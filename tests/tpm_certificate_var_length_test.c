/* tpm_certificate_var_length_test.c
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
 * Test for TPM certificate variable length attributes persistence across 
 * session cycles. This test verifies that variable length certificate 
 * attributes are properly stored and retrieved after logout/login cycles.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/misc.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#if defined(WOLFPKCS11_TPM) && !defined(WOLFPKCS11_NO_STORE)

#include "testdata.h"

/* Minimal unit test macros */
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

static CK_OBJECT_CLASS certificateClass = CKO_CERTIFICATE;
static CK_CERTIFICATE_TYPE x509CertType = CKC_X_509;
static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;

/* Test certificate data - sample DER-encoded X.509 certificate */
static unsigned char testCertValue[] = {
    0x30, 0x82, 0x03, 0x21, 0x30, 0x82, 0x02, 0x09, 0x02, 0x09, 0x00, 0xF1, 0x02, 0x03, 0x04, 0x05,
    0x06, 0x07, 0x08, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
    0x05, 0x00, 0x30, 0x81, 0x87, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
    0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x0A, 0x57, 0x61, 0x73,
    0x68, 0x69, 0x6E, 0x67, 0x74, 0x6F, 0x6E, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07,
    0x0C, 0x07, 0x53, 0x65, 0x61, 0x74, 0x74, 0x6C, 0x65, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55,
    0x04, 0x0A, 0x0C, 0x07, 0x77, 0x6F, 0x6C, 0x66, 0x53, 0x53, 0x4C, 0x31, 0x14, 0x30, 0x12, 0x06,
    0x03, 0x55, 0x04, 0x0B, 0x0C, 0x0B, 0x45, 0x6E, 0x67, 0x69, 0x6E, 0x65, 0x65, 0x72, 0x69, 0x6E,
    0x67, 0x31, 0x29, 0x30, 0x27, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x20, 0x77, 0x6F, 0x6C, 0x66,
    0x50, 0x4B, 0x43, 0x53, 0x31, 0x31, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x65, 0x72, 0x74,
    0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6F, 0x72, 0x69, 0x74,
    0x79, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x34, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x5A, 0x17, 0x0D, 0x33, 0x34, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x5A, 0x30, 0x7E, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,
    0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x0A, 0x57, 0x61, 0x73, 0x68, 0x69,
    0x6E, 0x67, 0x74, 0x6F, 0x6E, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x07,
    0x53, 0x65, 0x61, 0x74, 0x74, 0x6C, 0x65, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x0A,
    0x0C, 0x07, 0x77, 0x6F, 0x6C, 0x66, 0x53, 0x53, 0x4C, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55,
    0x04, 0x0B, 0x0C, 0x0B, 0x45, 0x6E, 0x67, 0x69, 0x6E, 0x65, 0x65, 0x72, 0x69, 0x6E, 0x67, 0x31,
    0x20, 0x30, 0x1E, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x17, 0x77, 0x6F, 0x6C, 0x66, 0x50, 0x4B,
    0x43, 0x53, 0x31, 0x31, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66,
    0x69, 0x63, 0x61, 0x74, 0x65
};

/* Variable length test data - designed to test storage/retrieval of different sizes */
static char testLabel[] = "wolfPKCS11 Test Certificate with Very Long Label Name for Variable Length Testing";
static unsigned char testId[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
static unsigned char testSerialNumber[] = {0xF1, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

/* Text-based subject for testing variable length subject (like existing tests) */
static unsigned char testSubject[] = "C = US, ST = Washington, L = Seattle, O = wolfSSL, OU = Engineering, CN = wolfPKCS11 Test Certificate with Very Long Subject Name for Variable Length Testing";

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
    ret = funcList->C_InitToken(slot, soPin, soPinLen, 
                               (CK_UTF8CHAR_PTR)tokenName);
    CHECK_CKR(ret, "Init Token");

    return ret;
}

static CK_RV pkcs11_set_user_pin(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session;

    ret = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, &session);
    CHECK_CKR(ret, "Open Session");

    if (ret == CKR_OK) {
        ret = funcList->C_Login(session, CKU_SO, soPin, soPinLen);
        CHECK_CKR(ret, "Login SO");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_InitPIN(session, userPin, userPinLen);
        CHECK_CKR(ret, "Init PIN");
    }

    if (session != CK_INVALID_HANDLE) {
        funcList->C_CloseSession(session);
    }

    return ret;
}

static CK_RV pkcs11_open_session(CK_SESSION_HANDLE* session)
{
    CK_RV ret;

    ret = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, session);
    CHECK_CKR(ret, "Open Session");

    if (ret == CKR_OK) {
        ret = funcList->C_Login(*session, CKU_USER, userPin, userPinLen);
        CHECK_CKR(ret, "Login User");
    }

    return ret;
}

static CK_RV pkcs11_close_session(CK_SESSION_HANDLE session)
{
    CK_RV ret = CKR_OK;

    if (session != CK_INVALID_HANDLE) {
        ret = funcList->C_Logout(session);
        /* Logout may fail if not logged in, ignore error */
        
        ret = funcList->C_CloseSession(session);
        CHECK_CKR(ret, "Close Session");
    }

    return ret;
}

static CK_RV create_certificate_with_var_length_attrs(CK_SESSION_HANDLE session, 
                                                     CK_OBJECT_HANDLE* certHandle)
{
    CK_RV ret;
    CK_ATTRIBUTE certTemplate[] = {
        { CKA_CLASS,            &certificateClass, sizeof(certificateClass) },
        { CKA_CERTIFICATE_TYPE, &x509CertType,     sizeof(x509CertType) },
        { CKA_TOKEN,            &ckTrue,           sizeof(ckTrue) },
        { CKA_PRIVATE,          &ckFalse,          sizeof(ckFalse) },
        { CKA_LABEL,            testLabel,         sizeof(testLabel) - 1 },
        { CKA_ID,               testId,            sizeof(testId) },
        { CKA_SUBJECT,          testSubject,       sizeof(testSubject) - 1 },
        { CKA_SERIAL_NUMBER,    testSerialNumber,  sizeof(testSerialNumber) },
        { CKA_VALUE,            testCertValue,     sizeof(testCertValue) }
    };
    CK_ULONG templateCount = sizeof(certTemplate) / sizeof(CK_ATTRIBUTE);

    if (verbose) {
        fprintf(stderr, "Creating certificate with variable length attributes:\n");
        fprintf(stderr, "  Label length: %lu\n", (unsigned long)(sizeof(testLabel) - 1));
        fprintf(stderr, "  ID length: %lu\n", (unsigned long)sizeof(testId));
        fprintf(stderr, "  Subject length: %lu\n", (unsigned long)(sizeof(testSubject) - 1));
        fprintf(stderr, "  Serial number length: %lu\n", (unsigned long)sizeof(testSerialNumber));
        fprintf(stderr, "  Certificate value length: %lu\n", (unsigned long)sizeof(testCertValue));
    }

    ret = funcList->C_CreateObject(session, certTemplate, templateCount, certHandle);
    CHECK_CKR(ret, "Create Certificate Object");

    return ret;
}

static CK_RV find_certificate_by_label(CK_SESSION_HANDLE session, 
                                       CK_OBJECT_HANDLE* certHandle)
{
    CK_RV ret;
    CK_ATTRIBUTE findTemplate[] = {
        { CKA_CLASS, &certificateClass, sizeof(certificateClass) },
        { CKA_LABEL, testLabel,          sizeof(testLabel) - 1 }
    };
    CK_ULONG templateCount = sizeof(findTemplate) / sizeof(CK_ATTRIBUTE);
    CK_OBJECT_HANDLE objects[1];
    CK_ULONG objectCount;

    ret = funcList->C_FindObjectsInit(session, findTemplate, templateCount);
    CHECK_CKR(ret, "Find Objects Init");

    if (ret == CKR_OK) {
        ret = funcList->C_FindObjects(session, objects, 1, &objectCount);
        CHECK_CKR(ret, "Find Objects");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_FindObjectsFinal(session);
        CHECK_CKR(ret, "Find Objects Final");
    }

    if (ret == CKR_OK && objectCount == 1) {
        *certHandle = objects[0];
    } else if (ret == CKR_OK) {
        fprintf(stderr, "Certificate not found or multiple certificates found\n");
        ret = CKR_GENERAL_ERROR;
    }

    return ret;
}

static CK_RV verify_certificate_attributes(CK_SESSION_HANDLE session, 
                                          CK_OBJECT_HANDLE certHandle)
{
    CK_RV ret = CKR_OK;
    CK_ULONG labelLen, idLen, subjectLen, serialLen, valueLen;
    unsigned char* labelBuffer = NULL;
    unsigned char* idBuffer = NULL;
    unsigned char* subjectBuffer = NULL;
    unsigned char* serialBuffer = NULL;
    unsigned char* valueBuffer = NULL;

    /* First, get the sizes of all variable length attributes */
    CK_ATTRIBUTE sizeTemplate[] = {
        { CKA_LABEL,            NULL, 0 },
        { CKA_ID,               NULL, 0 },
        { CKA_SUBJECT,          NULL, 0 },
        { CKA_SERIAL_NUMBER,    NULL, 0 },
        { CKA_VALUE,            NULL, 0 }
    };
    CK_ULONG sizeTemplateCount = sizeof(sizeTemplate) / sizeof(CK_ATTRIBUTE);

    ret = funcList->C_GetAttributeValue(session, certHandle, sizeTemplate, sizeTemplateCount);
    CHECK_CKR(ret, "Get Attribute Sizes");

    if (ret != CKR_OK) {
        return ret;
    }

    /* Extract sizes */
    labelLen = sizeTemplate[0].ulValueLen;
    idLen = sizeTemplate[1].ulValueLen;
    subjectLen = sizeTemplate[2].ulValueLen;
    serialLen = sizeTemplate[3].ulValueLen;
    valueLen = sizeTemplate[4].ulValueLen;

    if (verbose) {
        fprintf(stderr, "Retrieved certificate attribute sizes:\n");
        fprintf(stderr, "  Label length: %lu\n", labelLen);
        fprintf(stderr, "  ID length: %lu\n", idLen);
        fprintf(stderr, "  Subject length: %lu\n", subjectLen);
        fprintf(stderr, "  Serial number length: %lu\n", serialLen);
        fprintf(stderr, "  Certificate value length: %lu\n", valueLen);
    }

    /* Allocate buffers for attribute values */
    labelBuffer = (unsigned char*)XMALLOC(labelLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    idBuffer = (unsigned char*)XMALLOC(idLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    subjectBuffer = (unsigned char*)XMALLOC(subjectLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    serialBuffer = (unsigned char*)XMALLOC(serialLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    valueBuffer = (unsigned char*)XMALLOC(valueLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!labelBuffer || !idBuffer || !subjectBuffer || 
        !serialBuffer || !valueBuffer) {
        fprintf(stderr, "Failed to allocate memory for attribute buffers\n");
        ret = CKR_HOST_MEMORY;
        goto cleanup;
    }

    /* Now get the actual attribute values */
    CK_ATTRIBUTE valueTemplate[] = {
        { CKA_LABEL,            labelBuffer,   labelLen },
        { CKA_ID,               idBuffer,      idLen },
        { CKA_SUBJECT,          subjectBuffer, subjectLen },
        { CKA_SERIAL_NUMBER,    serialBuffer,  serialLen },
        { CKA_VALUE,            valueBuffer,   valueLen }
    };
    CK_ULONG valueTemplateCount = sizeof(valueTemplate) / sizeof(CK_ATTRIBUTE);

    ret = funcList->C_GetAttributeValue(session, certHandle, valueTemplate, valueTemplateCount);
    CHECK_CKR(ret, "Get Attribute Values");

    if (ret != CKR_OK) {
        goto cleanup;
    }

    /* Verify all variable length attributes match what we stored */
    CHECK_COND(labelLen == (sizeof(testLabel) - 1), ret, "Label length mismatch");
    CHECK_COND(idLen == sizeof(testId), ret, "ID length mismatch");
    CHECK_COND(subjectLen == (sizeof(testSubject) - 1), ret, "Subject length mismatch");
    CHECK_COND(serialLen == sizeof(testSerialNumber), ret, "Serial number length mismatch");
    CHECK_COND(valueLen == sizeof(testCertValue), ret, "Certificate value length mismatch");

    if (ret == CKR_OK) {
        CHECK_COND(XMEMCMP(labelBuffer, testLabel, labelLen) == 0, ret, "Label content mismatch");
        CHECK_COND(XMEMCMP(idBuffer, testId, idLen) == 0, ret, "ID content mismatch");
        CHECK_COND(XMEMCMP(subjectBuffer, testSubject, subjectLen) == 0, ret, "Subject content mismatch");
        CHECK_COND(XMEMCMP(serialBuffer, testSerialNumber, serialLen) == 0, ret, "Serial number content mismatch");
        CHECK_COND(XMEMCMP(valueBuffer, testCertValue, valueLen) == 0, ret, "Certificate value content mismatch");
    }

cleanup:
    if (labelBuffer) XFREE(labelBuffer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (idBuffer) XFREE(idBuffer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (subjectBuffer) XFREE(subjectBuffer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (serialBuffer) XFREE(serialBuffer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (valueBuffer) XFREE(valueBuffer, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

static CK_RV tpm_certificate_var_length_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session1 = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE session2 = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE certHandle1 = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE certHandle2 = CK_INVALID_HANDLE;

    fprintf(stderr, "Starting TPM certificate variable length attributes test...\n");

    /* Step 1: Create certificate object with variable length attributes */
    ret = pkcs11_open_session(&session1);
    if (ret != CKR_OK) {
        return ret;
    }

    ret = create_certificate_with_var_length_attrs(session1, &certHandle1);
    if (ret != CKR_OK) {
        pkcs11_close_session(session1);
        return ret;
    }

    fprintf(stderr, "Step 1: Certificate created successfully\n");

    /* Step 2: Log out and close session */
    ret = pkcs11_close_session(session1);
    if (ret != CKR_OK) {
        return ret;
    }

    fprintf(stderr, "Step 2: Logged out and closed session\n");

    /* Step 3: Log back in and open new session */
    ret = pkcs11_open_session(&session2);
    if (ret != CKR_OK) {
        return ret;
    }

    fprintf(stderr, "Step 3: Logged back in with new session\n");

    /* Step 4: Find the certificate object */
    ret = find_certificate_by_label(session2, &certHandle2);
    if (ret != CKR_OK) {
        pkcs11_close_session(session2);
        return ret;
    }

    fprintf(stderr, "Step 4: Certificate found successfully\n");

    /* Step 5: Verify all variable length attributes are correct */
    ret = verify_certificate_attributes(session2, certHandle2);
    if (ret != CKR_OK) {
        pkcs11_close_session(session2);
        return ret;
    }

    fprintf(stderr, "Step 5: All variable length attributes verified successfully\n");

    /* Cleanup */
    pkcs11_close_session(session2);

    fprintf(stderr, "TPM certificate variable length attributes test PASSED\n");
    return CKR_OK;
}

int main(int argc, char* argv[])
{
    CK_RV ret;
    int i;

    /* Parse command line arguments */
    for (i = 1; i < argc; i++) {
        if (XSTRNCMP(argv[i], "-v", 2) == 0) {
            verbose = 1;
        }
    }

    /* Initialize PKCS11 */
    ret = pkcs11_init();
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to initialize PKCS11\n");
        return 1;
    }

    /* Initialize token */
    ret = pkcs11_init_token();
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to initialize token\n");
        pkcs11_final();
        return 1;
    }

    /* Set user PIN */
    ret = pkcs11_set_user_pin();
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to set user PIN\n");
        pkcs11_final();
        return 1;
    }

    /* Run the test */
    ret = tpm_certificate_var_length_test();

    /* Cleanup */
    pkcs11_final();

    if (ret == CKR_OK) {
        fprintf(stderr, "All tests PASSED\n");
        return 0;
    } else {
        fprintf(stderr, "Test FAILED with return code: %lx\n", ret);
        return 1;
    }
}

#else

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
    fprintf(stderr, "TPM certificate variable length test requires WOLFPKCS11_TPM and storage support\n");
    return 77; /* SKIP */
}

#endif /* WOLFPKCS11_TPM && !WOLFPKCS11_NO_STORE */
