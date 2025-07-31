/* rsa_session_persistence_part1.c
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
 * Part 1 of RSA session persistence test - runs up to first finalize
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
static const char* tokenName = "wolfpkcs11";
static byte* soPin = (byte*)"password123456";
static int soPinLen = 14;
static byte* userPin = (byte*)"wolfpkcs11-test";
static int userPinLen = 15;

static CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
static CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;
static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;
static CK_KEY_TYPE rsaKeyType = CKK_RSA;



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

static CK_RV pkcs11_init_token(void)
{
    CK_RV ret;
    unsigned char label[32];

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenName, XSTRLEN(tokenName));

    ret = funcList->C_InitToken(slot, soPin, soPinLen, label);
    CHECK_CKR(ret, "Init Token");

    return ret;
}

static CK_RV pkcs11_set_user_pin(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &session);
    CHECK_CKR(ret, "Open Session for PIN setup");

    if (ret == CKR_OK) {
        ret = funcList->C_Login(session, CKU_SO, soPin, soPinLen);
        CHECK_CKR(ret, "Login as SO");

        if (ret == CKR_OK) {
            ret = funcList->C_InitPIN(session, userPin, userPinLen);
            CHECK_CKR(ret, "Set User PIN - Init PIN");
        }

        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }

    return ret;
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

static CK_RV create_rsa_key_pair(CK_SESSION_HANDLE session,
                                 CK_OBJECT_HANDLE* pubKey,
                                 CK_OBJECT_HANDLE* privKey)
{
    CK_RV ret;
    
    printf("  Using pre-defined RSA-2048 key material (no key generation)\n");
    CK_ATTRIBUTE pubKeyTemplate[] = {
        { CKA_CLASS,           &pubKeyClass,        sizeof(pubKeyClass)        },
        { CKA_KEY_TYPE,        &rsaKeyType,         sizeof(rsaKeyType)         },
        { CKA_ENCRYPT,         &ckTrue,             sizeof(ckTrue)             },
        { CKA_VERIFY,          &ckTrue,             sizeof(ckTrue)             },
        { CKA_MODULUS,         rsa_2048_modulus,    sizeof(rsa_2048_modulus)   },
        { CKA_PUBLIC_EXPONENT, rsa_2048_pub_exp,    sizeof(rsa_2048_pub_exp)   },
        { CKA_TOKEN,           &ckTrue,             sizeof(ckTrue)             },
        { CKA_ID,              rsaKeyId,            sizeof(rsaKeyId)           },
        { CKA_LABEL,           rsaKeyLabel,         sizeof(rsaKeyLabel)-1      }
    };

    CK_ATTRIBUTE privKeyTemplate[] = {
        { CKA_CLASS,             &privKeyClass,       sizeof(privKeyClass)       },
        { CKA_KEY_TYPE,          &rsaKeyType,         sizeof(rsaKeyType)         },
        { CKA_DECRYPT,           &ckTrue,             sizeof(ckTrue)             },
        { CKA_SIGN,              &ckTrue,             sizeof(ckTrue)             },
        { CKA_TOKEN,             &ckTrue,             sizeof(ckTrue)             },
        { CKA_PRIVATE,           &ckTrue,             sizeof(ckTrue)             },
        { CKA_SENSITIVE,         &ckTrue,             sizeof(ckTrue)             },
        { CKA_EXTRACTABLE,       &ckFalse,            sizeof(ckFalse)            },
        { CKA_ALWAYS_SENSITIVE,  &ckTrue,             sizeof(ckTrue)             },
        { CKA_NEVER_EXTRACTABLE, &ckTrue,             sizeof(ckTrue)             },
        { CKA_ID,                rsaKeyId,            sizeof(rsaKeyId)           },
        { CKA_LABEL,             rsaKeyLabel,         sizeof(rsaKeyLabel)-1      },
        { CKA_MODULUS,           rsa_2048_modulus,    sizeof(rsa_2048_modulus)   },
        { CKA_PUBLIC_EXPONENT,   rsa_2048_pub_exp,    sizeof(rsa_2048_pub_exp)   },
        { CKA_PRIVATE_EXPONENT,  rsa_2048_priv_exp,   sizeof(rsa_2048_priv_exp)  },
        { CKA_PRIME_1,           rsa_2048_p,          sizeof(rsa_2048_p)         },
        { CKA_PRIME_2,           rsa_2048_q,          sizeof(rsa_2048_q)         },
        { CKA_EXPONENT_1,        rsa_2048_dP,         sizeof(rsa_2048_dP)        },
        { CKA_EXPONENT_2,        rsa_2048_dQ,         sizeof(rsa_2048_dQ)        },
        { CKA_COEFFICIENT,       rsa_2048_u,          sizeof(rsa_2048_u)         }
    };

    ret = funcList->C_CreateObject(session, pubKeyTemplate,
                                   sizeof(pubKeyTemplate)/sizeof(CK_ATTRIBUTE),
                                   pubKey);
    CHECK_CKR(ret, "Create RSA Public Key");

    if (ret == CKR_OK) {
        ret = funcList->C_CreateObject(session, privKeyTemplate,
                                       sizeof(privKeyTemplate)/sizeof(CK_ATTRIBUTE),
                                       privKey);
        CHECK_CKR(ret, "Create RSA Private Key");
    }

    return ret;
}







static CK_RV rsa_session_persistence_part1(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session1;
    CK_OBJECT_HANDLE pubKey1, privKey1;

    printf("RSA Session Persistence Test - Part 1\n");
    printf("======================================\n");

    /* Step 1: Initialize PKCS#11 */
    ret = pkcs11_init();
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to initialize PKCS#11\n");
        return ret;
    }

    /* Step 1a: Initialize token */
    ret = pkcs11_init_token();
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to initialize token\n");
        goto cleanup;
    }

    /* Step 1b: Set user PIN */
    ret = pkcs11_set_user_pin();
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to set user PIN\n");
        goto cleanup;
    }

    /* Step 2: Open session and create RSA key pair */
    ret = pkcs11_open_session(&session1);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to open first session\n");
        goto cleanup;
    }

    printf("Creating RSA key pair using pre-defined key material...\n");
    ret = create_rsa_key_pair(session1, &pubKey1, &privKey1);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to create RSA key pair\n");
        goto cleanup;
    }

    /* Step 3: Close session and finalize */
    printf("Closing session and finalizing...\n");
    pkcs11_close_session(session1);
    pkcs11_final();

    printf("SUCCESS: Part 1 completed - keys created and library finalized\n");
    printf("Run rsa_session_persistence_part2 to test key persistence\n");

    return CKR_OK;

cleanup:
    pkcs11_close_session(session1);
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

    printf("wolfPKCS11 RSA Session Persistence Test - Part 1\n");
    printf("=================================================\n\n");

    ret = rsa_session_persistence_part1();
    if (ret == CKR_OK) {
        printf("\nPart 1 passed!\n");
        return 0;
    } else {
        printf("\nPart 1 failed with error: %lx\n", ret);
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