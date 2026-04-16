/*
 * Author: 28zaakypro@proton.me
 * AES-256-CBC shellcode encryptor — outputs encrypted bin, C array, and key/IV files
 *
 * Compile: gcc encrypt_payload.c ../modules/crypto.c -o encrypt_payload.exe -lAdvapi32
 * Usage:   encrypt_payload.exe <shellcode.bin>
 * Output:  payload/shellcode_aes.bin, payload/shellcode_aes.txt, payload/key_iv.txt
 */

#include "../modules/crypto.h"
#include <stdio.h>
#include <stdlib.h>

void PrintUsage(const char *progName)
{
    printf("Usage: %s <shellcode_file>\n\n", progName);
    printf("Output: payload/shellcode_aes.bin, payload/shellcode_aes.txt, payload/key_iv.txt\n");
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
    if (argc != 2)
    {
        PrintUsage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *inputFile = argv[1];

    // Read shellcode
    printf("[*] Reading shellcode from: %s\n", inputFile);

    BYTE *plainShellcode = NULL;
    SIZE_T shellcodeSize = 0;

    if (!ReadFile_Custom(inputFile, &plainShellcode, &shellcodeSize))
    {
        return EXIT_FAILURE;
    }

    printf("[+] Shellcode loaded: %zu bytes\n", shellcodeSize);

    // Generate key and IV
    BYTE key[AES_256_KEY_SIZE];
    BYTE iv[AES_IV_SIZE];

    if (!GenerateRandomKey(key) || !GenerateRandomIV(iv))
    {
        printf("[-] Key/IV generation failed\n");
        free(plainShellcode);
        return EXIT_FAILURE;
    }

    // Encrypt
    BYTE *encryptedShellcode = NULL;
    DWORD encryptedSize = 0;

    if (!EncryptPayload(plainShellcode, shellcodeSize, iv, key, &encryptedShellcode, &encryptedSize))
    {
        printf("[-] Encryption failed\n");
        free(plainShellcode);
        return EXIT_FAILURE;
    }

    printf("[+] Encrypted: %zu -> %lu bytes (+%lu padding)\n",
           shellcodeSize, encryptedSize, encryptedSize - (DWORD)shellcodeSize);

    // Save encrypted binary
    if (!WriteFile_Custom("payload/shellcode_aes.bin", encryptedShellcode, encryptedSize))
    {
        free(plainShellcode);
        free(encryptedShellcode);
        return EXIT_FAILURE;
    }
    printf("[+] Binary saved: payload/shellcode_aes.bin\n");

    WriteCArrayToFile("payload/shellcode_aes.txt", "encryptedShellcode", encryptedShellcode, encryptedSize);

    // Save key and IV
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
        printf("[+] Key and IV saved: payload/key_iv.txt\n");
    }

    // Cleanup
    SecureZeroMemory(plainShellcode, shellcodeSize);
    SecureZeroMemory(encryptedShellcode, encryptedSize);
    SecureZeroMemory(key, AES_256_KEY_SIZE);
    SecureZeroMemory(iv, AES_IV_SIZE);

    free(plainShellcode);
    free(encryptedShellcode);

    return EXIT_SUCCESS;
}
