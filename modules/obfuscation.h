/*
 * Obfuscation Module
 * 
 * Provides runtime obfuscation for sensitive data and timing.
 * Random sleeps and XOR-based string/key protection.
 */

#ifndef OBFUSCATION_H
#define OBFUSCATION_H

#include <windows.h>

#ifdef PRODUCTION_MODE
    #define LOG(...)
    #define LOG_INFO(...)
    #define LOG_SUCCESS(...)
    #define LOG_WARNING(...)
    #define LOG_ERROR(...)
#else
    #define LOG(...) printf(__VA_ARGS__)
    #define LOG_INFO(msg) printf("[*] %s\n", msg)
    #define LOG_SUCCESS(msg) printf("[+] %s\n", msg)
    #define LOG_WARNING(msg) printf("[!] %s\n", msg)
    #define LOG_ERROR(msg) printf("[-] %s\n", msg)
#endif

VOID ObfuscateKey(BYTE* key, SIZE_T keySize, BYTE* output);
BOOL DeobfuscateKey(BYTE* obfuscatedKey, SIZE_T keySize, BYTE* output);
VOID RandomSleep(DWORD minMs, DWORD maxMs);
VOID AdaptiveSleep(DWORD baseMs);
VOID DeobfuscateString(BYTE* obfuscated, SIZE_T length, BYTE key, char* output);

BOOL IsRunningInSandbox(void);
BOOL IsDebuggerActive(void);

#endif
