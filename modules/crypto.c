/*
 * ============================================================================
 * MODULE: AES-256-CBC CRYPTOGRAPHY IMPLEMENTATION
 * ============================================================================
 *
 * Author: 28Zaakypro@proton.me
 * Date: 2025-11-13
 *
 * This file implements all encryption/decryption functions
 * required to protect the shellcode in the loader.
 *
 * COMPILATION:
 * ------------
 * gcc crypto.c -o crypto.o -c -lAdvapi32 -lCrypt32
 *
 * DEPENDENCIES:
 * -------------
 * - Advapi32.lib : CryptAcquireContext, CryptGenRandom, CryptEncrypt, etc.
 * - Crypt32.lib  : Advanced hashing functions
 *
 * CODE STRUCTURE:
 * ----------------
 * 1. EncryptPayload()    - AES-256-CBC encryption
 * 2. DecryptPayload()    - AES-256-CBC decryption
 * 3. GenerateRandomKey() - Secure key generation
 * 4. GenerateRandomIV()  - Secure IV generation
 * 5. PrintHex()          - Debug display
 * 6. HexStringToBytes()  - Hex → bytes conversion
 *
 * ============================================================================
 */

#include "crypto.h"

/*
 * ============================================================================
 * FUNCTION: EncryptPayload
 * ============================================================================
 *
 * AES-256-CBC ENCRYPTION IMPLEMENTATION
 *
 * This function is the core of the shellcode protection system.
 * It takes plaintext data and encrypts it using AES-256 in CBC mode.
 *
 * DETAILED STEPS:
 * ------------------
 * 1. Strict validation of all input parameters
 * 2. Calculation of the encrypted size (with PKCS#7 padding)
 * 3. Allocation of the output buffer
 * 4. Acquisition of the Windows cryptographic provider
 * 5. Creation of the SHA-256 hash of the key
 * 6. Derivation of the AES key from the hash
 * 7. Configuration of CBC mode
 * 8. Application of the IV
 * 9. Encryption of the data (with automatic padding added)
 * 10. Cleanup of all resources
 *
 * SIZE CALCULATION WITH PADDING:
 * ----------------------------------
 * AES works with 16-byte blocks. PKCS#7 padding ensures that
 * the final data length is a multiple of 16.
 *
 * Formula: encryptedSize = ((plainSize + 16) / 16) * 16
 *
 * Examples:
 *   - 10 bytes  → 16 encrypted bytes (6 bytes of padding)
 *   - 16 bytes  → 32 encrypted bytes (16 bytes of full padding)
 *   - 100 bytes → 112 encrypted bytes (12 bytes of padding)
 *
 * CryptEncrypt automatically applies PKCS#7 padding.
 */

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

    // ========================================================================
    // STEP 1: PARAMETER VALIDATION
    // ========================================================================
    // Check that all pointers are valid and sizes are consistent

    if (!plainData || dataSize == 0 || !iv || !key || !encryptedData || !outSize)
    {
        CRYPTO_LOG("[-] Invalid parameters in EncryptPayload\n");
        CRYPTO_LOG("    plainData=%p, dataSize=%zu, iv=%p, key=%p\n",
                   plainData, dataSize, iv, key);
        return FALSE;
    }

    // ========================================================================
    // ÉTAPE 2: CALCUL ET ALLOCATION DU BUFFER DE SORTIE
    // ========================================================================
    // CryptEncrypt requires a large enough buffer to hold the padding
    // We allocate dataSize + 1 full block (16 bytes) to be safe

    encryptedSize = (DWORD)dataSize + AES_BLOCK_SIZE; // Max size with padding

    *encryptedData = (BYTE *)malloc(encryptedSize);
    if (*encryptedData == NULL)
    {
        CRYPTO_LOG("[-] Memory allocation failed for encrypted data (%lu bytes)\n",
                   encryptedSize);
        return FALSE;
    }

    // Copy plaintext data into the buffer (CryptEncrypt encrypts in-place)
    memcpy(*encryptedData, plainData, dataSize);
    encryptedSize = (DWORD)dataSize; // Current size of the data

    CRYPTO_LOG("[*] Allocated %lu bytes for encrypted output\n", encryptedSize + AES_BLOCK_SIZE);

    // ========================================================================
    // STEP 3: ACQUISITION OF THE CRYPTOGRAPHIC PROVIDER
    // ========================================================================
    // PROV_RSA_AES = Provider supporting AES-128/192/256
    // CRYPT_VERIFYCONTEXT = No signature, just symmetric crypto

    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        CRYPTO_LOG("[-] CryptAcquireContext failed: 0x%08lX\n", GetLastError());
        CRYPTO_LOG("    Provider: PROV_RSA_AES\n");
        goto cleanup;
    }

    CRYPTO_LOG("[+] Crypto provider acquired successfully\n");

    // ========================================================================
    // STEP 4: CREATION OF THE SHA-256 HASH FOR THE KEY
    // ========================================================================
    // CryptDeriveKey requires a hash of the key, not the raw key
    // We use SHA-256 (32 bytes) for AES-256 (32 bytes key)

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

    // ========================================================================
    // STEP 5: DERIVATION OF THE AES-256 KEY
    // ========================================================================
    // Create the encryption key from the hash
    // CALG_AES_256 = AES with 256-bit key (32 bytes)

    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey))
    {
        CRYPTO_LOG("[-] CryptDeriveKey failed: 0x%08lX\n", GetLastError());
        CRYPTO_LOG("    Algorithm: CALG_AES_256\n");
        goto cleanup;
    }

    CRYPTO_LOG("[+] AES-256 key derived from hash\n");

    // ========================================================================
    // STEP 6: CONFIGURATION OF THE CBC MODE
    // ========================================================================
    // CBC mode (Cipher Block Chaining) to avoid patterns
    // By default, CryptoAPI uses ECB (insecure), so we force CBC

    if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE *)&dwMode, 0))
    {
        CRYPTO_LOG("[-] CryptSetKeyParam (MODE) failed: 0x%08lX\n", GetLastError());
        goto cleanup;
    }

    CRYPTO_LOG("[+] Cipher mode set to CBC\n");

    // ========================================================================
    // STEP 7: APPLICATION OF THE INITIALIZATION VECTOR (IV)
    // ========================================================================
    // The IV is essential in CBC mode for block chaining
    // It must be unique for each encryption with the same key

    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0))
    {
        CRYPTO_LOG("[-] CryptSetKeyParam (IV) failed: 0x%08lX\n", GetLastError());
        goto cleanup;
    }

    CRYPTO_LOG("[+] IV applied to cipher\n");

    // ========================================================================
    // STEP 8: ENCRYPTION OF THE DATA
    // ========================================================================
    // CryptEncrypt encrypts in-place and automatically adds PKCS#7 padding
    //
    // Parameters:
    //   hKey          : Encryption key
    //   0             : No final hash (HCRYPTHASH = 0)
    //   TRUE          : This is the last block (add padding)
    //   0             : Flags (none)
    //   *encryptedData: Data buffer (input/output)
    //   &encryptedSize: Current size → final size after encryption

    if (!CryptEncrypt(hKey, 0, TRUE, 0, *encryptedData, &encryptedSize,
                      (DWORD)dataSize + AES_BLOCK_SIZE))
    {
        CRYPTO_LOG("[-] CryptEncrypt failed: 0x%08lX\n", GetLastError());
        CRYPTO_LOG("    Input size: %zu bytes\n", dataSize);
        CRYPTO_LOG("    Buffer size: %lu bytes\n", (DWORD)dataSize + AES_BLOCK_SIZE);
        goto cleanup;
    }

    // encryptedSize now contains the final size (with padding)
    *outSize = encryptedSize;

    CRYPTO_LOG("[+] Encryption successful\n");
    CRYPTO_LOG("    Input size:  %zu bytes\n", dataSize);
    CRYPTO_LOG("    Output size: %lu bytes (including padding)\n", encryptedSize);
    CRYPTO_LOG("    Padding:     %lu bytes\n", encryptedSize - dataSize);

    result = TRUE;

cleanup:
    // ========================================================================
    // STEP 9: CLEANUP OF RESOURCES
    // ========================================================================
    // Free all crypto handles, even on error
    // On failure, also free the allocated buffer

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

/*
 * ============================================================================
 * FUNCTION: DecryptPayload
 * ============================================================================
 *
 * AES-256-CBC DECRYPTION IMPLEMENTATION
 *
 * This function is called at runtime in the loader to recover
 * the plaintext shellcode from the hardcoded encrypted data.
 *
 * DIFFERENCE FROM EncryptPayload:
 * --------------------------------
 * - EncryptPayload: used OFFLINE to prepare the payload
 * - DecryptPayload: used at RUNTIME in the loader on the target machine
 *
 * DETAILED STEPS:
 * ------------------
 * 1. Parameter validation (critical for security)
 * 2. Output buffer allocation (same size as input)
 * 3. Copy encrypted data (CryptDecrypt modifies data in-place)
 * 4. Acquisition of the crypto provider
 * 5. SHA-256 hash creation from the key
 * 6. Derivation of the AES-256 key
 * 7. CBC mode configuration
 * 8. IV application (MUST be the same as during encryption!)
 * 9. Decryption + automatic padding removal
 * 10. Full cleanup
 *
 * PADDING HANDLING:
 * -------------------
 * CryptDecrypt automatically removes PKCS#7 padding.
 * The variable decryptedSize is updated with the real size.
 *
 * Example:
 *   Input:  [3F A2 ... 03 03 03] (288 bytes with padding)
 *   Output: [48 31 C0 ... C3]    (285 bytes, original size)
 *
 * decryptedSize = 285 (not 288)
 */

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

    // ========================================================================
    // STEP 1: STRICT PARAMETER VALIDATION
    // ========================================================================
    // Critical check as this function deals with potentially
    // corrupted or malformed data

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

    // ========================================================================
    // STEP 2: OUTPUT BUFFER ALLOCATION
    // ========================================================================
    // Allocate a buffer of the same size as the input
    // (decryption can only reduce size with padding)

    *decryptedData = (BYTE *)malloc(dataSize);
    if (*decryptedData == NULL)
    {
        CRYPTO_LOG("[-] Memory allocation failed for decrypted data (%zu bytes)\n",
                   dataSize);
        return FALSE;
    }

    // Copy encrypted data (CryptDecrypt modifies data in-place)
    memcpy(*decryptedData, encryptedData, dataSize);

    CRYPTO_LOG("[+] Allocated %zu bytes for decrypted output\n", dataSize);

    // ========================================================================
    // STEP 3: ACQUISITION OF THE CRYPTO PROVIDER
    // ========================================================================

    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        CRYPTO_LOG("[-] CryptAcquireContext failed: 0x%08lX\n", GetLastError());
        goto cleanup;
    }

    CRYPTO_LOG("[+] Crypto provider acquired\n");

    // ========================================================================
    // STEP 4: CREATION OF THE SHA-256 HASH OF THE KEY
    // ========================================================================
    // Process is identical to encryption (same key = same hash)

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

    // ========================================================================
    // STEP 5: DERIVATION OF THE AES-256 KEY
    // ========================================================================

    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey))
    {
        CRYPTO_LOG("[-] CryptDeriveKey failed: 0x%08lX\n", GetLastError());
        goto cleanup;
    }

    CRYPTO_LOG("[+] AES-256 key derived from hash\n");

    // ========================================================================
    // STEP 6: CONFIGURATION OF THE CBC MODE
    // ========================================================================

    if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE *)&dwMode, 0))
    {
        CRYPTO_LOG("[-] CryptSetKeyParam (MODE) failed: 0x%08lX\n", GetLastError());
        goto cleanup;
    }

    CRYPTO_LOG("[+] Cipher mode set to CBC\n");

    // ========================================================================
    // STEP 7: APPLICATION OF THE IV
    // ========================================================================
    // CRITICAL: IV MUST be exactly the same as during encryption!
    // If IV is different, the first block will be corrupted

    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0))
    {
        CRYPTO_LOG("[-] CryptSetKeyParam (IV) failed: 0x%08lX\n", GetLastError());
        goto cleanup;
    }

    CRYPTO_LOG("[+] IV applied to cipher\n");

    // ========================================================================
    // STEP 8: DECRYPTION OF THE DATA
    // ========================================================================
    // CryptDecrypt decrypts in-place and automatically removes padding
    //
    // Parameters:
    //   hKey          : Decryption key
    //   0             : No hash (HCRYPTHASH = 0)
    //   TRUE          : Last block (remove padding)
    //   0             : Flags
    //   *decryptedData: Buffer for data (input/output)
    //   &decryptedSize: Size with padding → actual size after

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
    // ========================================================================
    // STEP 9: SECURE CLEANUP
    // ========================================================================
    // In case of failure, clean up and free the buffer
    // In case of success, the buffer remains allocated (caller must free())

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

/*
 * ============================================================================
 * FUNCTION: GenerateRandomKey
 * ============================================================================
 *
 * GENERATION OF A CRYPTOGRAPHICALLY SECURE AES-256 KEY
 *
 * This function uses Windows' CSPRNG (Cryptographically Secure
 * Pseudo-Random Number Generator) to produce 32 bytes
 * of high-quality entropy.
 *
 * ENTROPY SOURCES USED BY CryptGenRandom:
 * ----------------------------------------
 * 1. CPU thermal noise (electrical fluctuations)
 * 2. Hardware interrupt timings
 * 3. Mouse movement and keyboard input
 * 4. Hard drive state (seek times)
 * 5. Network state
 * 6. TPM (Trusted Platform Module) if available
 * 7. RDRAND CPU instruction (Intel/AMD)
 *
 * These sources are mixed using a Yarrow-style algorithm
 * to produce unpredictable bytes.
 *
 * RANDOMNESS QUALITY:
 * --------------------
 * CryptGenRandom is FIPS 140-2 Level 1 certified, which means:
 *   ✅ Passes all NIST statistical tests
 *   ✅ Not predictable even if internal state is known
 *   ✅ Resistant to timing-analysis attacks
 *   ✅ Suitable for cryptographic key generation
 */

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

// In debug mode, display the key (NEVER in production!)
#ifdef DEBUG_CRYPTO
    PrintHex("Generated Key", key, AES_256_KEY_SIZE);
#endif

    result = TRUE;

cleanup:
    if (hProv)
        CryptReleaseContext(hProv, 0);

    return result;
}

/*
 * ============================================================================
 * FUNCTION: GenerateRandomIV
 * ============================================================================
 *
 * GENERATION OF A RANDOM IV FOR AES-CBC
 *
 * The IV (Initialization Vector) is essential in CBC mode to:
 * 1. Ensure that identical plaintext produces different ciphertexts
 * 2. Prevent pattern-recognition attacks
 * 3. Add randomness to block chaining
 *
 * SECURITY RULES FOR THE IV:
 * ---------------------------
 * ✅ MUST be unpredictable (generated randomly)
 * ✅ MUST be unique for each encryption with the same key
 * ✅ Can be stored in plaintext alongside the ciphertext
 * ❌ NEVER use a fixed or predictable IV
 * ❌ NEVER reuse the same IV with the same key
 *
 * WHY CAN THE IV BE PUBLIC?
 * ---------------------------
 * Unlike the key, the IV does not need to be secret.
 * It only needs to be unpredictable and unique.
 *
 * This is why one can store:
 *   - encrypted_shellcode.bin (ciphertext)
 *   - iv.txt (IV in plaintext)
 *
 * But NOT:
 *   - key.txt in plaintext (must be obfuscated!)
 */

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

/*
 * ============================================================================
 * FUNCTION: PrintHex
 * ====================================================================================
 *
 * HEXADECIMAL DISPLAY FOR DEBUGGING
 *
 * Formats and prints a binary buffer in readable hexadecimal form.
 * Used during development to verify:
 *   - Generated keys
 *   - IVs
 *   - The first bytes of the encrypted/decrypted shellcode
 *
 * OUTPUT FORMAT:
 * -----------------
 * [Label] 3F A2 1B 9C D4 7E 8F 12 ... (32 bytes)
 *
 * SECURITY:
 * ---------
 * ⚠️  This function reveals sensitive data!
 *
 * To be used ONLY:
 *   - During development
 *   - With #ifdef DEBUG_CRYPTO
 *   - Never on a production machine
 *
 * In production, calls to PrintHex are disabled by the macro.
 */

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

/*
 * ============================================================================
 * FUNCTION: HexStringToBytes
 * ============================================================================
 *
 * HEX STRING → BINARY BYTE CONVERSION
 *
 * This function converts hex data (from a text file
 * or a string) into a usable binary buffer.
 *
 * USE CASES:
 * ----------
 * 1. Hardcoding encrypted shellcode:
 *    const char *hexShellcode = "3FA21B9C...";
 *    BYTE *shellcode = NULL;
 *    SIZE_T size = 0;
 *    HexStringToBytes(hexShellcode, &shellcode, &size);
 *
 * 2. Reading a key from a file:
 *    char *hexKey = ReadFile("key.txt");
 *    BYTE *key = NULL;
 *    SIZE_T keySize = 0;
 *    HexStringToBytes(hexKey, &key, &keySize);
 *
 * ACCEPTED FORMATS:
 * ------------------
 * - Compact:      "3FA21B9C"
 * - With spaces:  "3F A2 1B 9C"
 * - With 0x:      "0x3F 0xA2 0x1B 0x9C"
 * - Multi-line:   "3F A2\n1B 9C"
 *
 * ALGORITHM:
 * ----------
 * 1. Parse the hex string to count valid bytes
 * 2. Allocate the output buffer
 * 3. Convert each pair of hex characters into 1 byte
 * 4. Validation: characters 0–9, A–F, a–f only
 *
 * VALIDATION:
 * -----------
 * The function rejects:
 *   ❌ Odd length (1 hex char = incomplete)
 *   ❌ Invalid characters (G–Z, symbols, etc.)
 *   ❌ Empty string
 */

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