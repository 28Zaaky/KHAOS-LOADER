#ifndef ETW_BYPASS_H
#define ETW_BYPASS_H

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

/*
 * ETW Bypass Module
 * 
 * Disables Windows Event Tracing by patching ETW functions.
 * EDR/AV use ETW to monitor process activity - this prevents that.
 */

// Results from ETW bypass operation
typedef struct _ETW_RESULT {
    BOOL success;
    BOOL etwEventWritePatched;
    BOOL etwEventWriteExPatched;
} ETW_RESULT;

// Disable ETW event logging
BOOL DisableETW(ETW_RESULT* result);

// Patch specific ETW function
BOOL PatchETWFunction(const char* functionName);

void PrintETWResult(ETW_RESULT* result);

#endif // ETW_BYPASS_H
