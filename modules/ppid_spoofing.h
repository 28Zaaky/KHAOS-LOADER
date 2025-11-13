/*
 * PPID Spoofing Module
 * 
 * Makes created processes appear to have a legitimate parent (like explorer.exe)
 * instead of the actual loader process. Helps evade EDR process tree analysis.
 */

#ifndef PPID_SPOOFING_H
#define PPID_SPOOFING_H

#include <windows.h>

// Results from PPID spoofing operation
typedef struct _PPID_SPOOF_RESULT {
    BOOL success;
    DWORD processId;
    DWORD threadId;
    DWORD spoofedParentPid;
    HANDLE hProcess;
    HANDLE hThread;
    CHAR processName[MAX_PATH];
    CHAR parentName[MAX_PATH];
} PPID_SPOOF_RESULT, *PPPID_SPOOF_RESULT;

// Find PID of a process by name
DWORD FindProcessByName(const char* processName);

// Creates process with spoofed parent PID using PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
BOOL CreateProcessWithSpoofedPPID(
    const char* targetProcess,
    const char* parentProcess,
    BOOL suspended,
    PPPID_SPOOF_RESULT result
);

// Prints PPID spoofing result
VOID PrintPPIDSpoofResult(PPPID_SPOOF_RESULT result);

#endif // PPID_SPOOFING_H
