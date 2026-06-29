#ifndef AMSI_BYPASS_H
#define AMSI_BYPASS_H

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

// Results from AMSI bypass operation
typedef struct _AMSI_RESULT
{
    BOOL success;
    BOOL amsiScanBufferPatched;
} AMSI_RESULT;

// Disable AMSI scanning
BOOL DisableAMSI(AMSI_RESULT *result);

// Patch AmsiScanBuffer function
BOOL PatchAmsiScanBuffer();

void PrintAMSIResult(AMSI_RESULT *result);

#endif // AMSI_BYPASS_H
