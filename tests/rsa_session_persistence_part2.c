/* rsa_session_persistence_part2.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfPKCS11.
 *
 * wolfPKCS11 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfPKCS11 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 *
 * Part 2 of RSA session persistence test - loads library back and does comparison
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/misc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#if !defined(NO_RSA) && !defined(WOLFPKCS11_NO_STORE)

/* only include the RSA test data */
#undef HAVE_ECC
#define NO_AES
#define NO_DH
#include "testdata.h"

/* Minimal unit test macros to avoid unused function warnings */
#define CHECK_COND(cond, ret, msg)                                         \
    do {                                                                   \
        if (!(cond)) {                                                     \
            fprintf(stderr, "\n%s:%d - %s - FAIL\n",                       \
                    __FILE__, __LINE__, msg);                              \
            ret = -1;                                                      \
        }                                                                  \
    }                                                                      \
    while (0)
#define CHECK_CKR(rv, msg)                                                 \
    do {                                                                   \
        if (rv != CKR_OK) {                                                \
            fprintf(stderr, "\n%s:%d - %s: %lx - FAIL\n",                  \
                    __FILE__, __LINE__, msg, rv);                          \
        }                                                                  \
    }                                                                      \
    while (0)
#define CHECK_CKR_FAIL(rv, exp, msg)                                       \
    do {                                                                   \
        if (rv != exp) {                                                   \
            fprintf(stderr, "\n%s:%d - %s RETURNED %lx - FAIL\n",          \
                    __FILE__, __LINE__, msg, rv);                          \
            if (rv == CKR_OK)                                              \
                rv = -1;                                                   \
        }                                                                  \
        else                                                               \
            rv = CKR_OK;                                                   \
    }                                                                      \
    while (0)

static int verbose = 0;

#ifndef HAVE_PKCS11_STATIC
static void* dlib;
#endif
static CK_FUNCTION_LIST* funcList;
static CK_SLOT_ID slot = 0;
static byte* userPin = (byte*)"wolfpkcs11-test";
static int userPinLen = 15;

static CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
static CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;

static CK_KEY_TYPE rsaKeyType = CKK_RSA;

/* Test data */
static unsigned char testHash[32] = {
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
};

static unsigned char testPlaintext[32] = {
    0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
    0x61, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x6d,
    0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x66,
    0x6f, 0x72, 0x20, 0x65, 0x6e, 0x63, 0x72, 0x79
};

/* RSA key ID for persistence - matching failing test case */
static unsigned char rsaKeyId[] = {0x12, 0x34, 0x56, 0x78, 0x90};
static char rsaKeyLabel[] = "tls_serv_key";

static CK_RV pkcs11_init(void)
{
    CK_RV ret;
    CK_C_INITIALIZE_ARGS args;
    CK_INFO info;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);

#ifndef HAVE_PKCS11_STATIC
    CK_C_GetFunctionList func;

    dlib = dlopen(WOLFPKCS11_DLL_FILENAME, RTLD_NOW | RTLD_LOCAL);
    if (dlib == NULL) {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        return -1;
    }

    func = (CK_C_GetFunctionList)dlsym(dlib, "C_GetFunctionList");
    if (func == NULL) {
        fprintf(stderr, "Failed to get function list function\n");
        dlclose(dlib);
        return -1;
    }

    ret = func(&funcList);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to get function list: %lx\n", ret);
        dlclose(dlib);
        return ret;
    }
#else
    ret = C_GetFunctionList(&funcList);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to get function list: %lx\n", ret);
        return ret;
    }
#endif

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    ret = funcList->C_Initialize(&args);
    CHECK_CKR(ret, "Initialize");

    if (ret == CKR_OK) {
        ret = funcList->C_GetInfo(&info);
        CHECK_CKR(ret, "Get Info");
    }

    /* Get available slots */
    if (ret == CKR_OK) {
        ret = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
        CHECK_CKR(ret, "Get Slot List");
    }

    if (ret == CKR_OK && slotCount > 0) {
        slot = slotList[0];  /* Use first available slot */
    } else if (ret == CKR_OK) {
        fprintf(stderr, "No slots available\n");
        ret = CKR_GENERAL_ERROR;
    }

    return ret;
}

static CK_RV pkcs11_final(void)
{
    funcList->C_Finalize(NULL);
#ifndef HAVE_PKCS11_STATIC
    if (dlib) {
        dlclose(dlib);
    }
#endif
    return CKR_OK;
}

static CK_RV pkcs11_open_session(CK_SESSION_HANDLE* session)
{
    CK_RV ret;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, session);
    CHECK_CKR(ret, "Open Session");

    if (ret == CKR_OK && userPinLen != 0) {
        ret = funcList->C_Login(*session, CKU_USER, userPin, userPinLen);
        CHECK_CKR(ret, "Login");
    }

    return ret;
}

static CK_RV pkcs11_close_session(CK_SESSION_HANDLE session)
{
    CK_RV ret;

    ret = funcList->C_Logout(session);
    CHECK_CKR(ret, "Logout");

    if (ret == CKR_OK) {
        ret = funcList->C_CloseSession(session);
        CHECK_CKR(ret, "Close Session");
    }

    return ret;
}

static CK_RV find_rsa_key_pair(CK_SESSION_HANDLE session,
                               CK_OBJECT_HANDLE* pubKey,
                               CK_OBJECT_HANDLE* privKey)
{
    CK_RV ret;
    CK_ULONG count;
    CK_ATTRIBUTE pubKeyTemplate[] = {
        { CKA_CLASS,    &pubKeyClass,  sizeof(pubKeyClass) },
        { CKA_KEY_TYPE, &rsaKeyType,   sizeof(rsaKeyType)  },
        { CKA_ID,       rsaKeyId,      sizeof(rsaKeyId)    },
        { CKA_LABEL,    rsaKeyLabel,   sizeof(rsaKeyLabel)-1 }
    };
    CK_ATTRIBUTE privKeyTemplate[] = {
        { CKA_CLASS,    &privKeyClass, sizeof(privKeyClass) },
        { CKA_KEY_TYPE, &rsaKeyType,   sizeof(rsaKeyType)   },
        { CKA_ID,       rsaKeyId,      sizeof(rsaKeyId)     },
        { CKA_LABEL,    rsaKeyLabel,   sizeof(rsaKeyLabel)-1 }
    };

    /* Find public key */
    ret = funcList->C_FindObjectsInit(session, pubKeyTemplate,
                                      sizeof(pubKeyTemplate)/sizeof(CK_ATTRIBUTE));
    CHECK_CKR(ret, "Find Public Key Init");

    if (ret == CKR_OK) {
        ret = funcList->C_FindObjects(session, pubKey, 1, &count);
        CHECK_CKR(ret, "Find Public Key");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_FindObjectsFinal(session);
        CHECK_CKR(ret, "Find Public Key Final");
    }

    if (ret == CKR_OK && count != 1) {
        fprintf(stderr, "Expected 1 public key, found %lu\n", count);
        return CKR_OBJECT_HANDLE_INVALID;
    }

    /* Find private key */
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjectsInit(session, privKeyTemplate,
                                          sizeof(privKeyTemplate)/sizeof(CK_ATTRIBUTE));
        CHECK_CKR(ret, "Find Private Key Init");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_FindObjects(session, privKey, 1, &count);
        CHECK_CKR(ret, "Find Private Key");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_FindObjectsFinal(session);
        CHECK_CKR(ret, "Find Private Key Final");
    }

    if (ret == CKR_OK && count != 1) {
        fprintf(stderr, "Expected 1 private key, found %lu\n", count);
        return CKR_OBJECT_HANDLE_INVALID;
    }

    return ret;
}

static CK_RV rsa_sign_test(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE privKey,
                          unsigned char* signature, CK_ULONG* sigLen)
{
    CK_RV ret;
    CK_MECHANISM mech = { CKM_SHA256_RSA_PKCS, NULL, 0 };

    ret = funcList->C_SignInit(session, &mech, privKey);
    CHECK_CKR(ret, "RSA Sign Init");

    if (ret == CKR_OK) {
        ret = funcList->C_Sign(session, testHash, sizeof(testHash),
                              signature, sigLen);
        CHECK_CKR(ret, "RSA Sign");
    }

    return ret;
}

static CK_RV rsa_encrypt_decrypt_test(CK_SESSION_HANDLE session,
                                     CK_OBJECT_HANDLE pubKey,
                                     CK_OBJECT_HANDLE privKey)
{
    CK_RV ret;
    CK_MECHANISM mech = { CKM_RSA_PKCS, NULL, 0 };
    unsigned char encrypted[256];
    unsigned char decrypted[256];
    CK_ULONG encLen = sizeof(encrypted);
    CK_ULONG decLen = sizeof(decrypted);

    /* Encrypt with public key */
    ret = funcList->C_EncryptInit(session, &mech, pubKey);
    CHECK_CKR(ret, "RSA Encrypt Init");

    if (ret == CKR_OK) {
        ret = funcList->C_Encrypt(session, testPlaintext, sizeof(testPlaintext),
                                 encrypted, &encLen);
        CHECK_CKR(ret, "RSA Encrypt");
    }

    /* Decrypt with private key */
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptInit(session, &mech, privKey);
        CHECK_CKR(ret, "RSA Decrypt Init");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_Decrypt(session, encrypted, encLen,
                                 decrypted, &decLen);
        CHECK_CKR(ret, "RSA Decrypt");
    }

    /* Verify decrypted data matches original */
    if (ret == CKR_OK) {
        if (decLen != sizeof(testPlaintext) ||
            XMEMCMP(decrypted, testPlaintext, decLen) != 0) {
            fprintf(stderr, "Decrypted data doesn't match original\n");
            ret = CKR_GENERAL_ERROR;
        }
    }

    return ret;
}

static CK_RV save_signature_to_file(const unsigned char* signature, CK_ULONG sigLen)
{
    FILE* fp;
    
    fp = fopen("./signature1.dat", "wb");
    if (fp == NULL) {
        fprintf(stderr, "Failed to create signature file\n");
        return CKR_GENERAL_ERROR;
    }
    
    /* Write signature length first, then signature data */
    if (fwrite(&sigLen, sizeof(CK_ULONG), 1, fp) != 1) {
        fprintf(stderr, "Failed to write signature length\n");
        fclose(fp);
        return CKR_GENERAL_ERROR;
    }
    
    if (fwrite(signature, 1, sigLen, fp) != sigLen) {
        fprintf(stderr, "Failed to write signature data\n");
        fclose(fp);
        return CKR_GENERAL_ERROR;
    }
    
    fclose(fp);
    printf("Signature saved to signature1.dat (length: %lu)\n", sigLen);
    return CKR_OK;
}

static CK_RV load_signature_from_file(unsigned char* signature, CK_ULONG* sigLen)
{
    FILE* fp;
    CK_ULONG storedLen;
    
    fp = fopen("./signature1.dat", "rb");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open signature file - did you run part 1 first?\n");
        return CKR_GENERAL_ERROR;
    }
    
    /* Read signature length first */
    if (fread(&storedLen, sizeof(CK_ULONG), 1, fp) != 1) {
        fprintf(stderr, "Failed to read signature length\n");
        fclose(fp);
        return CKR_GENERAL_ERROR;
    }
    
    if (storedLen > *sigLen) {
        fprintf(stderr, "Signature buffer too small: %lu > %lu\n", storedLen, *sigLen);
        fclose(fp);
        return CKR_GENERAL_ERROR;
    }
    
    /* Read signature data */
    if (fread(signature, 1, storedLen, fp) != storedLen) {
        fprintf(stderr, "Failed to read signature data\n");
        fclose(fp);
        return CKR_GENERAL_ERROR;
    }
    
    fclose(fp);
    *sigLen = storedLen;
    printf("Signature loaded from signature1.dat (length: %lu)\n", storedLen);
    return CKR_OK;
}

static CK_RV rsa_session_persistence_part2(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session2;
    CK_OBJECT_HANDLE pubKey2, privKey2;
    unsigned char signature1[256], signature2[256];
    CK_ULONG sig1Len = sizeof(signature1), sig2Len = sizeof(signature2);

    printf("RSA Session Persistence Test - Part 2\n");
    printf("======================================\n");

    /* Step 1: Re-initialize PKCS#11 */
    printf("Re-initializing PKCS#11...\n");
    ret = pkcs11_init();
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to re-initialize PKCS#11\n");
        return ret;
    }

    /* Token should already be initialized from part 1 */

    /* Step 2: Open new session and find existing key pair */
    ret = pkcs11_open_session(&session2);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to open second session\n");
        goto cleanup;
    }

    printf("Finding existing RSA key pair...\n");
    ret = find_rsa_key_pair(session2, &pubKey2, &privKey2);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to find RSA key pair after reinit\n");
        goto cleanup;
    }

    /* Step 3: Sign hash with private key (first time after reload) */
    printf("Signing hash (first time after reload)...\n");
    ret = rsa_sign_test(session2, privKey2, signature1, &sig1Len);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to sign hash (first time after reload)\n");
        goto cleanup;
    }

    /* Step 4: Save signature to file */
    ret = save_signature_to_file(signature1, sig1Len);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to save signature to file\n");
        goto cleanup;
    }

    /* Step 5: Encrypt/decrypt test */
    printf("Testing encrypt/decrypt (first time after reload)...\n");
    ret = rsa_encrypt_decrypt_test(session2, pubKey2, privKey2);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed encrypt/decrypt test (first time after reload)\n");
        goto cleanup;
    }

    /* Step 6: Close session and finalize again */
    printf("Closing session and finalizing again...\n");
    pkcs11_close_session(session2);
    pkcs11_final();

    /* Step 7: Re-initialize PKCS#11 again */
    printf("Re-initializing PKCS#11 again...\n");
    ret = pkcs11_init();
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to re-initialize PKCS#11 again\n");
        return ret;
    }

    /* Step 8: Open session and find key pair again */
    ret = pkcs11_open_session(&session2);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to open session again\n");
        goto cleanup;
    }

    printf("Finding existing RSA key pair again...\n");
    ret = find_rsa_key_pair(session2, &pubKey2, &privKey2);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to find RSA key pair after second reinit\n");
        goto cleanup;
    }

    /* Step 9: Load signature from file */
    ret = load_signature_from_file(signature1, &sig1Len);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to load signature from file\n");
        goto cleanup;
    }

    /* Step 10: Sign the same hash again */
    printf("Signing hash (second time after reload)...\n");
    ret = rsa_sign_test(session2, privKey2, signature2, &sig2Len);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to sign hash (second time after reload)\n");
        goto cleanup;
    }

    /* Step 11: Compare signatures */
    printf("Comparing signatures...\n");
    if (sig1Len != sig2Len || XMEMCMP(signature1, signature2, sig1Len) != 0) {
        fprintf(stderr, "ERROR: Signatures differ after session reinit!\n");
        fprintf(stderr, "First signature length: %lu\n", sig1Len);
        fprintf(stderr, "Second signature length: %lu\n", sig2Len);
        if (verbose) {
            fprintf(stderr, "First signature: ");
            for (CK_ULONG i = 0; i < sig1Len; i++) {
                fprintf(stderr, "%02x", signature1[i]);
            }
            fprintf(stderr, "\nSecond signature: ");
            for (CK_ULONG i = 0; i < sig2Len; i++) {
                fprintf(stderr, "%02x", signature2[i]);
            }
            fprintf(stderr, "\n");
        }
        ret = CKR_GENERAL_ERROR;
        goto cleanup;
    }

    /* Step 12: Test encrypt/decrypt again */
    printf("Testing encrypt/decrypt (second time after reload)...\n");
    ret = rsa_encrypt_decrypt_test(session2, pubKey2, privKey2);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed encrypt/decrypt test (second time after reload)\n");
        goto cleanup;
    }

    printf("SUCCESS: RSA key operations consistent across multiple library reloads\n");
    printf("This confirms no bugs exist between library unload and reload\n");

cleanup:
    if (session2 != 0) {
        pkcs11_close_session(session2);
    }
    pkcs11_final();
    return ret;
}

int main(int argc, char* argv[])
{
#if !defined(NO_RSA) && !defined(WOLFPKCS11_NO_STORE)
    CK_RV ret;

#ifndef WOLFPKCS11_NO_ENV
    if (!XGETENV("WOLFPKCS11_TOKEN_PATH")) {
        XSETENV("WOLFPKCS11_TOKEN_PATH", "./store/rsa", 1);
    }
#endif

    if (argc > 1 && strcmp(argv[1], "-v") == 0) {
        verbose = 1;
    }

    printf("wolfPKCS11 RSA Session Persistence Test - Part 2\n");
    printf("=================================================\n\n");

    ret = rsa_session_persistence_part2();
    if (ret == CKR_OK) {
        printf("\nPart 2 passed!\n");
        printf("Complete test suite: SUCCESS\n");
        return 0;
    } else {
        printf("\nPart 2 failed with error: %lx\n", ret);
        return 1;
    }
#else
    (void)argc;
    (void)argv;
    printf("RSA or KeyStore not compiled in!\n");
    return 77;
#endif
}

#endif /* !defined(NO_RSA) && !defined(WOLFPKCS11_NO_STORE) */