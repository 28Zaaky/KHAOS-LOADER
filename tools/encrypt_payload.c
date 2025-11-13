/*
 * ============================================================================
 * TOOL: PAYLOAD ENCRYPTION UTILITY
 * ============================================================================
 * 
 * Author: XvX Loader Project
 * Date: 2025-11-13
 * 
 * This tool encrypts a shellcode file using AES-256-CBC encryption.
 * It generates random key and IV, then outputs:
 *   1. Encrypted shellcode as C array
 *   2. Key as C array
 *   3. IV as C array
 * 
 * COMPILATION:
 * ------------
 * gcc encrypt_payload.c ../modules/crypto.c -o encrypt_payload.exe -lAdvapi32
 * 
 * USAGE:
 * ------
 * encrypt_payload.exe <input_file>
 * 
 * Example:
 * encrypt_payload.exe ../payload/shellcode.bin
 * 
 * OUTPUT:
 * -------
 * Creates 3 files in ../payload/:
 *   - shellcode_aes.bin (encrypted shellcode)
 *   - shellcode_aes.txt (C array format for copy/paste)
 *   - key_iv.txt (key and IV in C array format)
 * 
 * ============================================================================
 */

#include "../modules/crypto.h"
#include <stdio.h>
#include <stdlib.h>

void PrintUsage(const char *progName)
{
    printf("Usage: %s <shellcode_file>\n", progName);
    printf("\n");
    printf("Encrypts a shellcode file using AES-256-CBC.\n");
    printf("\n");
    printf("Example:\n");
    printf("  %s ../payload/shellcode.bin\n", progName);
    printf("\n");
    printf("Output files:\n");
    printf("  - ../payload/shellcode_aes.bin (encrypted binary)\n");
    printf("  - ../payload/shellcode_aes.txt (C array format)\n");
    printf("  - ../payload/key_iv.txt (key and IV)\n");
    printf("\n");
}

BOOL ReadFile_Custom(const char *filename, BYTE **data, SIZE_T *size)
{
    FILE *f = fopen(filename, "rb");
    if (!f)
    {
        printf("[-] Failed to open file: %s\n", filename);
        return FALSE;
    }

    // Get file size
    fseek(f, 0, SEEK_END);
    long fileSize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fileSize <= 0)
    {
        printf("[-] Invalid file size: %ld\n", fileSize);
        fclose(f);
        return FALSE;
    }

    // Allocate buffer
    *data = (BYTE *)malloc(fileSize);
    if (!*data)
    {
        printf("[-] Memory allocation failed\n");
        fclose(f);
        return FALSE;
    }

    // Read data
    size_t bytesRead = fread(*data, 1, fileSize, f);
    fclose(f);

    if (bytesRead != (size_t)fileSize)
    {
        printf("[-] Failed to read file completely\n");
        free(*data);
        return FALSE;
    }

    *size = (SIZE_T)fileSize;
    return TRUE;
}

BOOL WriteFile_Custom(const char *filename, const BYTE *data, SIZE_T size)
{
    FILE *f = fopen(filename, "wb");
    if (!f)
    {
        printf("[-] Failed to create file: %s\n", filename);
        return FALSE;
    }

    size_t bytesWritten = fwrite(data, 1, size, f);
    fclose(f);

    if (bytesWritten != size)
    {
        printf("[-] Failed to write file completely\n");
        return FALSE;
    }

    return TRUE;
}

void WriteCArrayToFile(const char *filename, const char *varName, const BYTE *data, SIZE_T size)
{
    FILE *f = fopen(filename, "w");
    if (!f)
    {
        printf("[-] Failed to create file: %s\n", filename);
        return;
    }

    fprintf(f, "// %s (%zu bytes)\n", varName, size);
    fprintf(f, "BYTE %s[] = {\n    ", varName);

    for (SIZE_T i = 0; i < size; i++)
    {
        fprintf(f, "0x%02X", data[i]);
        if (i < size - 1)
        {
            fprintf(f, ", ");
        }
        if ((i + 1) % 12 == 0 && i < size - 1)
        {
            fprintf(f, "\n    ");
        }
    }

    fprintf(f, "\n};\n");
    fclose(f);

    printf("[+] C array written to: %s\n", filename);
}

int main(int argc, char *argv[])
{
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║        XvX LOADER - AES-256 PAYLOAD ENCRYPTION TOOL          ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");
    printf("\n");

    if (argc != 2)
    {
        PrintUsage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *inputFile = argv[1];

    // ========================================================================
    // STEP 1: READ SHELLCODE
    // ========================================================================
    printf("[*] Reading shellcode from: %s\n", inputFile);

    BYTE *plainShellcode = NULL;
    SIZE_T shellcodeSize = 0;

    if (!ReadFile_Custom(inputFile, &plainShellcode, &shellcodeSize))
    {
        return EXIT_FAILURE;
    }

    printf("[+] Shellcode loaded: %zu bytes\n", shellcodeSize);
    printf("    First 16 bytes: ");
    for (SIZE_T i = 0; i < (shellcodeSize < 16 ? shellcodeSize : 16); i++)
    {
        printf("%02X ", plainShellcode[i]);
    }
    printf("\n\n");

    // ========================================================================
    // STEP 2: GENERATE RANDOM KEY AND IV
    // ========================================================================
    printf("[*] Generating random AES-256 key and IV...\n");

    BYTE key[AES_256_KEY_SIZE];
    BYTE iv[AES_IV_SIZE];

    if (!GenerateRandomKey(key))
    {
        printf("[-] Failed to generate key\n");
        free(plainShellcode);
        return EXIT_FAILURE;
    }

    if (!GenerateRandomIV(iv))
    {
        printf("[-] Failed to generate IV\n");
        free(plainShellcode);
        return EXIT_FAILURE;
    }

    printf("[+] Key generated (32 bytes):\n    ");
    for (int i = 0; i < AES_256_KEY_SIZE; i++)
    {
        printf("%02X ", key[i]);
        if ((i + 1) % 16 == 0)
            printf("\n    ");
    }
    printf("\n");

    printf("[+] IV generated (16 bytes):\n    ");
    for (int i = 0; i < AES_IV_SIZE; i++)
    {
        printf("%02X ", iv[i]);
    }
    printf("\n\n");

    // ========================================================================
    // STEP 3: ENCRYPT SHELLCODE
    // ========================================================================
    printf("[*] Encrypting shellcode with AES-256-CBC...\n");

    BYTE *encryptedShellcode = NULL;
    DWORD encryptedSize = 0;

    if (!EncryptPayload(plainShellcode, shellcodeSize, iv, key, &encryptedShellcode, &encryptedSize))
    {
        printf("[-] Encryption failed\n");
        free(plainShellcode);
        return EXIT_FAILURE;
    }

    printf("[+] Encryption successful!\n");
    printf("    Original size:  %zu bytes\n", shellcodeSize);
    printf("    Encrypted size: %lu bytes (including PKCS#7 padding)\n", encryptedSize);
    printf("    Padding added:  %lu bytes\n\n", encryptedSize - shellcodeSize);

    // ========================================================================
    // STEP 4: SAVE ENCRYPTED SHELLCODE
    // ========================================================================
    printf("[*] Saving encrypted shellcode...\n");

    // Binary file
    if (!WriteFile_Custom("payload/shellcode_aes.bin", encryptedShellcode, encryptedSize))
    {
        free(plainShellcode);
        free(encryptedShellcode);
        return EXIT_FAILURE;
    }
    printf("[+] Binary saved: payload/shellcode_aes.bin\n");

    // C array file (for easy copy/paste into loader.c)
    WriteCArrayToFile("payload/shellcode_aes.txt", "encryptedShellcode", encryptedShellcode, encryptedSize);

    // ========================================================================
    // STEP 5: SAVE KEY AND IV
    // ========================================================================
    printf("[*] Saving key and IV...\n");

    FILE *keyIvFile = fopen("payload/key_iv.txt", "w");
    if (keyIvFile)
    {
        fprintf(keyIvFile, "// AES-256 Key (32 bytes)\n");
        fprintf(keyIvFile, "BYTE aesKey[32] = {\n    ");
        for (int i = 0; i < AES_256_KEY_SIZE; i++)
        {
            fprintf(keyIvFile, "0x%02X", key[i]);
            if (i < AES_256_KEY_SIZE - 1)
                fprintf(keyIvFile, ", ");
            if ((i + 1) % 12 == 0 && i < AES_256_KEY_SIZE - 1)
                fprintf(keyIvFile, "\n    ");
        }
        fprintf(keyIvFile, "\n};\n\n");

        fprintf(keyIvFile, "// AES IV (16 bytes)\n");
        fprintf(keyIvFile, "BYTE aesIV[16] = {\n    ");
        for (int i = 0; i < AES_IV_SIZE; i++)
        {
            fprintf(keyIvFile, "0x%02X", iv[i]);
            if (i < AES_IV_SIZE - 1)
                fprintf(keyIvFile, ", ");
        }
        fprintf(keyIvFile, "\n};\n\n");

        fprintf(keyIvFile, "// Encrypted shellcode size: %lu bytes\n", encryptedSize);
        fprintf(keyIvFile, "// Original shellcode size: %zu bytes\n", shellcodeSize);

        fclose(keyIvFile);
        printf("[+] Key and IV saved: ../payload/key_iv.txt\n");
    }

    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                    ENCRYPTION COMPLETE                        ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("Next steps:\n");
    printf("  1. Copy contents of ../payload/shellcode_aes.txt into loader_v3.c\n");
    printf("  2. Copy key and IV from ../payload/key_iv.txt into loader_v3.c\n");
    printf("  3. Update DecryptAndInject() to use DecryptPayload() instead of XOR\n");
    printf("  4. Compile loader with: gcc -O0 loader_v3.c modules/*.c modules/dosyscall.o -o output/Loader_AES.exe -ladvapi32 -lntdll -luser32\n");
    printf("\n");

    // Cleanup
    SecureZeroMemory(plainShellcode, shellcodeSize);
    SecureZeroMemory(encryptedShellcode, encryptedSize);
    SecureZeroMemory(key, AES_256_KEY_SIZE);
    SecureZeroMemory(iv, AES_IV_SIZE);

    free(plainShellcode);
    free(encryptedShellcode);

    return EXIT_SUCCESS;
}
