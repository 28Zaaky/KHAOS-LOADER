#ifndef UNHOOKING_H
#define UNHOOKING_H

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
#ifndef PVOID
typedef void* PVOID;
#endif
#ifndef SIZE_T
typedef unsigned long long SIZE_T;
#endif

/*
 * NTDLL Unhooking Module
 * 
 * Removes EDR hooks from ntdll.dll by loading a fresh copy from disk
 * and restoring the .text section to its original state.
 */

// Results from unhooking operation
typedef struct _UNHOOK_RESULT {
    BOOL success;
    DWORD hooksFound;
    DWORD hooksRemoved;
    SIZE_T bytesRestored;
} UNHOOK_RESULT;

// Main unhooking function
BOOL UnhookNTDLL(UNHOOK_RESULT* result);

// Helper functions
PVOID LoadFreshNTDLL();
BOOL FindTextSection(PVOID moduleBase, PVOID* textStart, SIZE_T* textSize);
BOOL RestoreTextSection(PVOID hookedNtdll, PVOID freshNtdll);
void PrintUnhookResult(UNHOOK_RESULT* result);

#endif // UNHOOKING_H
