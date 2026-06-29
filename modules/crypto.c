#include "crypto.h"

BOOL EncryptPayload(
    BYTE *plainData,
    SIZE_T dataSize,
    BYTE iv[AES_IV_SIZE],
    BYTE key[AES_256_KEY_SIZE],
    BYTE **encryptedData,
    DWORD *outSize)
{
    BOOL result = FALSE;
    HCRYPTPROV hProv = 0; // Handle of the crypto provider
    HCRYPTKEY hKey = 0;   // Handle of the AES key
    HCRYPTHASH hHash = 0; // Handle of the SHA-256 hash
    DWORD encryptedSize = 0;
    DWORD dwMode = CRYPT_MODE_CBC;

    CRYPTO_LOG("[+] Starting payload encryption...\n");

    if (!plainData || dataSize == 0 || !iv || !key || !encryptedData || !outSize)
    {
        CRYPTO_LOG("[-] Invalid parameters in EncryptPayload\n");
        CRYPTO_LOG("    plainData=%p, dataSize=%zu, iv=%p, key=%p\n",
                   plainData, dataSize, iv, key);
        return FALSE;
    }

    encryptedSize = (DWORD)dataSize + AES_BLOCK_SIZE; // Max size with padding

    *encryptedData = (BYTE *)malloc(encryptedSize);
    if (*encryptedData == NULL)
    {
        CRYPTO_LOG("[-] Memory allocation failed for encrypted data (%lu bytes)\n",
                   encryptedSize);
        return FALSE;
    }

    // Copy plaintext data into the buffer
    memcpy(*encryptedData, plainData, dataSize);
    encryptedSize = (DWORD)dataSize; // Current size of the data

    CRYPTO_LOG("[*] Allocated %lu bytes for encrypted output\n", encryptedSize + AES_BLOCK_SIZE);

    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        CRYPTO_LOG("[-] CryptAcquireContext failed: 0x%08lX\n", GetLastError());
        CRYPTO_LOG("    Provider: PROV_RSA_AES\n");
        goto cleanup;
    }

    CRYPTO_LOG("[+] Crypto provider acquired successfully\n");

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        CRYPTO_LOG("[-] CryptCreateHash failed: 0x%08lX\n", GetLastError());
        CRYPTO_LOG("    Algorithm: CALG_SHA_256\n");
        goto cleanup;
    }

    // Hash the 32 bytes of the key
    if (!CryptHashData(hHash, key, AES_256_KEY_SIZE, 0))
    {
        CRYPTO_LOG("[-] CryptHashData failed: 0x%08lX\n", GetLastError());
        goto cleanup;
    }

    CRYPTO_LOG("[+] SHA-256 hash of key created\n");

    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey))
    {
        CRYPTO_LOG("[-] CryptDeriveKey failed: 0x%08lX\n", GetLastError());
        CRYPTO_LOG("    Algorithm: CALG_AES_256\n");
        goto cleanup;
    }

    CRYPTO_LOG("[+] AES-256 key derived from hash\n");

    if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE *)&dwMode, 0))
    {
        CRYPTO_LOG("[-] CryptSetKeyParam (MODE) failed: 0x%08lX\n", GetLastError());
        goto cleanup;
    }

    CRYPTO_LOG("[+] Cipher mode set to CBC\n");

    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0))
    {
        CRYPTO_LOG("[-] CryptSetKeyParam (IV) failed: 0x%08lX\n", GetLastError());
        goto cleanup;
    }

    CRYPTO_LOG("[+] IV applied to cipher\n");

    if (!CryptEncrypt(hKey, 0, TRUE, 0, *encryptedData, &encryptedSize,
                      (DWORD)dataSize + AES_BLOCK_SIZE))
    {
        CRYPTO_LOG("[-] CryptEncrypt failed: 0x%08lX\n", GetLastError());
        CRYPTO_LOG("    Input size: %zu bytes\n", dataSize);
        CRYPTO_LOG("    Buffer size: %lu bytes\n", (DWORD)dataSize + AES_BLOCK_SIZE);
        goto cleanup;
    }

    // encryptedSize now contains the final size with padding
    *outSize = encryptedSize;

    CRYPTO_LOG("[+] Encryption successful\n");
    CRYPTO_LOG("    Input size:  %zu bytes\n", dataSize);
    CRYPTO_LOG("    Output size: %lu bytes (including padding)\n", encryptedSize);
    CRYPTO_LOG("    Padding:     %lu bytes\n", encryptedSize - dataSize);

    result = TRUE;

cleanup:

    if (!result && *encryptedData)
    {
        // Clean the memory before freeing
        SecureZeroMemory(*encryptedData, encryptedSize);
        free(*encryptedData);
        *encryptedData = NULL;
        CRYPTO_LOG("[-] Encryption failed, buffer freed\n");
    }

    if (hKey)
        CryptDestroyKey(hKey);
    if (hHash)
        CryptDestroyHash(hHash);
    if (hProv)
        CryptReleaseContext(hProv, 0);

    return result;
}

BOOL DecryptPayload(
    BYTE *encryptedData,
    SIZE_T dataSize,
    BYTE iv[AES_IV_SIZE],
    BYTE key[AES_256_KEY_SIZE],
    BYTE **decryptedData,
    DWORD *outSize)
{
    BOOL result = FALSE;
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    HCRYPTHASH hHash = 0;
    DWORD decryptedSize = (DWORD)dataSize;
    DWORD dwMode = CRYPT_MODE_CBC;

    CRYPTO_LOG("[+] Starting payload decryption...\n");

    if (!encryptedData || dataSize == 0 || !iv || !key || !decryptedData || !outSize)
    {
        CRYPTO_LOG("[-] Invalid parameters in DecryptPayload\n");
        CRYPTO_LOG("    encryptedData=%p, dataSize=%zu, iv=%p, key=%p\n",
                   encryptedData, dataSize, iv, key);
        return FALSE;
    }

    // Check that the size is a multiple of 16 (AES blocks)
    if (dataSize % AES_BLOCK_SIZE != 0)
    {
        CRYPTO_LOG("[-] Invalid data size: %zu (not multiple of %d)\n",
                   dataSize, AES_BLOCK_SIZE);
        return FALSE;
    }

    CRYPTO_LOG("[*] Input size: %zu bytes (%zu blocks)\n",
               dataSize, dataSize / AES_BLOCK_SIZE);

    *decryptedData = (BYTE *)malloc(dataSize);
    if (*decryptedData == NULL)
    {
        CRYPTO_LOG("[-] Memory allocation failed for decrypted data (%zu bytes)\n",
                   dataSize);
        return FALSE;
    }

    // Copy encrypted data
    memcpy(*decryptedData, encryptedData, dataSize);

    CRYPTO_LOG("[+] Allocated %zu bytes for decrypted output\n", dataSize);

    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        CRYPTO_LOG("[-] CryptAcquireContext failed: 0x%08lX\n", GetLastError());
        goto cleanup;
    }

    CRYPTO_LOG("[+] Crypto provider acquired\n");

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        CRYPTO_LOG("[-] CryptCreateHash failed: 0x%08lX\n", GetLastError());
        goto cleanup;
    }

    if (!CryptHashData(hHash, key, AES_256_KEY_SIZE, 0))
    {
        CRYPTO_LOG("[-] CryptHashData failed: 0x%08lX\n", GetLastError());
        goto cleanup;
    }

    CRYPTO_LOG("[+] SHA-256 hash of key created\n");

    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey))
    {
        CRYPTO_LOG("[-] CryptDeriveKey failed: 0x%08lX\n", GetLastError());
        goto cleanup;
    }

    CRYPTO_LOG("[+] AES-256 key derived from hash\n");

    if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE *)&dwMode, 0))
    {
        CRYPTO_LOG("[-] CryptSetKeyParam (MODE) failed: 0x%08lX\n", GetLastError());
        goto cleanup;
    }

    CRYPTO_LOG("[+] Cipher mode set to CBC\n");

    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0))
    {
        CRYPTO_LOG("[-] CryptSetKeyParam (IV) failed: 0x%08lX\n", GetLastError());
        goto cleanup;
    }

    CRYPTO_LOG("[+] IV applied to cipher\n");

    if (!CryptDecrypt(hKey, 0, TRUE, 0, *decryptedData, &decryptedSize))
    {
        CRYPTO_LOG("[-] CryptDecrypt failed: 0x%08lX\n", GetLastError());
        CRYPTO_LOG("    This usually means:\n");
        CRYPTO_LOG("    - Wrong key used\n");
        CRYPTO_LOG("    - Wrong IV used\n");
        CRYPTO_LOG("    - Corrupted ciphertext\n");
        CRYPTO_LOG("    - Wrong padding\n");
        goto cleanup;
    }

    // decryptedSize contains now the actual size (without padding)
    *outSize = decryptedSize;

    CRYPTO_LOG("[+] Decryption successful\n");
    CRYPTO_LOG("    Input size:  %zu bytes\n", dataSize);
    CRYPTO_LOG("    Output size: %lu bytes (padding removed)\n", decryptedSize);
    CRYPTO_LOG("    Padding:     %zu bytes\n", dataSize - decryptedSize);

    result = TRUE;

cleanup:
    if (!result && *decryptedData)
    {
        // Erase sensitive data from memory
        SecureZeroMemory(*decryptedData, dataSize);
        free(*decryptedData);
        *decryptedData = NULL;
        CRYPTO_LOG("[-] Decryption failed, buffer freed\n");
    }

    if (hKey)
        CryptDestroyKey(hKey);
    if (hHash)
        CryptDestroyHash(hHash);
    if (hProv)
        CryptReleaseContext(hProv, 0);

    return result;
}

BOOL GenerateRandomKey(BYTE key[AES_256_KEY_SIZE])
{
    HCRYPTPROV hProv = 0;
    BOOL result = FALSE;

    CRYPTO_LOG("[+] Generating random 256-bit key...\n");

    // Validate parameter
    if (!key)
    {
        CRYPTO_LOG("[-] NULL key buffer provided\n");
        return FALSE;
    }

    // Acquire the crypto provider (CSPRNG)
    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        CRYPTO_LOG("[-] CryptAcquireContext failed: 0x%08lX\n", GetLastError());
        return FALSE;
    }

    // Generate 32 bytes of random data (256 bits)
    // CryptGenRandom guarantees that each bit has a 50% chance of being 0 or 1
    if (!CryptGenRandom(hProv, AES_256_KEY_SIZE, key))
    {
        CRYPTO_LOG("[-] CryptGenRandom failed: 0x%08lX\n", GetLastError());
        goto cleanup;
    }

    CRYPTO_LOG("[+] 256-bit key generated successfully\n");

// In debug mode, display the key
#ifdef DEBUG_CRYPTO
    PrintHex("Generated Key", key, AES_256_KEY_SIZE);
#endif

    result = TRUE;

cleanup:
    if (hProv)
        CryptReleaseContext(hProv, 0);

    return result;
}

BOOL GenerateRandomIV(BYTE iv[AES_IV_SIZE])
{
    HCRYPTPROV hProv = 0;
    BOOL result = FALSE;

    CRYPTO_LOG("[+] Generating random 128-bit IV...\n");

    // Validate parameter
    if (!iv)
    {
        CRYPTO_LOG("[-] NULL IV buffer provided\n");
        return FALSE;
    }

    // Acquire the crypto provider
    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        CRYPTO_LOG("[-] CryptAcquireContext failed: 0x%08lX\n", GetLastError());
        return FALSE;
    }

    // Generate 16 bytes of random data (128 bits = AES block size)
    if (!CryptGenRandom(hProv, AES_IV_SIZE, iv))
    {
        CRYPTO_LOG("[-] CryptGenRandom failed: 0x%08lX\n", GetLastError());
        goto cleanup;
    }

    CRYPTO_LOG("[+] 128-bit IV generated successfully\n");

// In debug mode, display the IV
#ifdef DEBUG_CRYPTO
    PrintHex("Generated IV", iv, AES_IV_SIZE);
#endif

    result = TRUE;

cleanup:
    if (hProv)
        CryptReleaseContext(hProv, 0);

    return result;
}

void PrintHex(const char *label, BYTE *data, SIZE_T size)
{
    if (!label || !data || size == 0)
        return;

    printf("[%s] ", label);

    // Display each byte in hexadecimal
    for (SIZE_T i = 0; i < size; i++)
    {
        printf("%02X ", data[i]);

        // New line every 16 bytes (for readability)
        if ((i + 1) % 16 == 0 && i + 1 < size)
            printf("\n%*s", (int)strlen(label) + 3, "");
    }

    printf("(%zu bytes)\n", size);
}

BOOL HexStringToBytes(const char *hexStr, BYTE **outBytes, SIZE_T *outSize)
{
    if (!hexStr || !outBytes || !outSize)
    {
        CRYPTO_LOG("[-] Invalid parameters in HexStringToBytes\n");
        return FALSE;
    }

    // Count valid hex characters (ignore spaces, 0x, etc.)
    SIZE_T hexLen = 0;
    for (const char *p = hexStr; *p; p++)
    {
        if ((*p >= '0' && *p <= '9') ||
            (*p >= 'A' && *p <= 'F') ||
            (*p >= 'a' && *p <= 'f'))
        {
            hexLen++;
        }
    }

    // Verify that the length is even (2 hex chars = 1 byte)
    if (hexLen % 2 != 0)
    {
        CRYPTO_LOG("[-] Invalid hex string length: %zu (must be even)\n", hexLen);
        return FALSE;
    }

    SIZE_T byteCount = hexLen / 2;

    // Allocate the output buffer
    *outBytes = (BYTE *)malloc(byteCount);
    if (*outBytes == NULL)
    {
        CRYPTO_LOG("[-] Memory allocation failed for %zu bytes\n", byteCount);
        return FALSE;
    }

    // Convert each pair of hex chars into 1 byte
    SIZE_T byteIndex = 0;
    for (const char *p = hexStr; *p && byteIndex < byteCount;)
    {
        // Ignore spaces, newlines, etc.
        if (!((*p >= '0' && *p <= '9') ||
              (*p >= 'A' && *p <= 'F') ||
              (*p >= 'a' && *p <= 'f')))
        {
            p++;
            continue;
        }

        // Lire 2 caractères hexa
        char highNibble = *p++;
        char lowNibble = *p++;

        // convert hex chars to byte values
        BYTE high = (highNibble >= '0' && highNibble <= '9') ? (highNibble - '0') : (highNibble >= 'A' && highNibble <= 'F') ? (highNibble - 'A' + 10)
                                                                                                                             : (highNibble - 'a' + 10);

        BYTE low = (lowNibble >= '0' && lowNibble <= '9') ? (lowNibble - '0') : (lowNibble >= 'A' && lowNibble <= 'F') ? (lowNibble - 'A' + 10)
                                                                                                                       : (lowNibble - 'a' + 10);

        // Combine high and low nibbles into a byte
        (*outBytes)[byteIndex++] = (high << 4) | low;
    }

    *outSize = byteCount;

    CRYPTO_LOG("[+] Converted %zu hex chars to %zu bytes\n", hexLen, byteCount);

    return TRUE;
}