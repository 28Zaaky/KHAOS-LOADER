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

// Results from ETW bypass operation
typedef struct _ETW_RESULT {
    BOOL success;
    BOOL etwEventWritePatched;
    BOOL etwEventWriteExPatched;
} ETW_RESULT;

BOOL DisableETW(ETW_RESULT* result);
void PrintETWResult(ETW_RESULT* result);

#endif // ETW_BYPASS_H