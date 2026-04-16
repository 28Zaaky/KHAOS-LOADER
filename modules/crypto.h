#ifndef CRYPTO_H
#define CRYPTO_H

#include <windows.h>
#include <wincrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Lier avec les bibliothèques crypto de Windows
#pragma comment(lib, "Advapi32.lib") // Pour CryptAcquireContext, etc.
#pragma comment(lib, "Crypt32.lib")  // Pour certaines fonctions de hash

// Définir CALG_SHA_256 si non disponible
#ifndef CALG_SHA_256
#define CALG_SHA_256 (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256)
#define ALG_SID_SHA_256 12
#endif

// Tailles des éléments crypto
#define AES_256_KEY_SIZE 32 // 256 bits = 32 bytes
#define AES_BLOCK_SIZE 16   // Taille de bloc AES = 128 bits = 16 bytes
#define AES_IV_SIZE 16      // IV = taille du bloc

// Macro de logging conditionnelle
#ifdef DEBUG_CRYPTO
#define CRYPTO_LOG(fmt, ...) printf("[CRYPTO] " fmt, ##__VA_ARGS__)
#else
#define CRYPTO_LOG(fmt, ...) ((void)0)
#endif

BOOL EncryptPayload(
    BYTE *plainData,
    SIZE_T dataSize,
    BYTE iv[AES_IV_SIZE],
    BYTE key[AES_256_KEY_SIZE],
    BYTE **encryptedData,
    DWORD *outSize);

BOOL DecryptPayload(
    BYTE *encryptedData,
    SIZE_T dataSize,
    BYTE iv[AES_IV_SIZE],
    BYTE key[AES_256_KEY_SIZE],
    BYTE **decryptedData,
    DWORD *outSize);

BOOL GenerateRandomKey(BYTE key[AES_256_KEY_SIZE]);

BOOL GenerateRandomIV(BYTE iv[AES_IV_SIZE]);

void PrintHex(const char *label, BYTE *data, SIZE_T size);

BOOL HexStringToBytes(const char *hexStr, BYTE **outBytes, SIZE_T *outSize);

#endif // CRYPTO_H
