/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include <openssl/x509.h>
#include "x509_lcl.h"
#include "e_os.h"

#if defined(OPENSSL_SYS_WINDOWS)

#include <wincrypt.h>

static int cert_usage_is_server_auth(PCCERT_CONTEXT cert_ctx, DWORD flags)
{
    DWORD err, i;
    DWORD size = 0;
    CERT_ENHKEY_USAGE* usage = NULL;
    int purpose_server_auth = 0;

    if (!CertGetEnhancedKeyUsage(cert_ctx, flags, NULL, &size)) {
        err = GetLastError();
        if (err == CRYPT_E_NOT_FOUND) {
            if (flags == CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG)
                return cert_usage_is_server_auth(cert_ctx, CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG);
            return 1;
        }
        return -1;
    }
    usage = (CERT_ENHKEY_USAGE*)malloc(size);
    if (!CertGetEnhancedKeyUsage(cert_ctx, flags, usage, &size)) {
        err = GetLastError();
        free(usage);
        if (err == CRYPT_E_NOT_FOUND)
            return 1;
        return -1;
    }
    for (i = 0; i < usage->cUsageIdentifier; ++i) {
        if (usage->rgpszUsageIdentifier[i]) {
            if (strcmp(usage->rgpszUsageIdentifier[i], "1.3.6.1.5.5.7.3.1") == 0) {
                purpose_server_auth = 1;
                break;
            }
        }
    }
    free(usage);
    return purpose_server_auth;
}

static int load_ca_certs_from_store(const char *storename, X509_LOOKUP *ctx)
{
    HCERTSTORE store = NULL;
    PCCERT_CONTEXT cert_ctx = NULL;
    int trust, r, err;
    int ret = 0;
    BIO *biobuf;
    X509 *x;

    store = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, (HCRYPTPROV)NULL, CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_LOCAL_MACHINE, storename);
    if (store == NULL) {
        X509err(X509_F_X509_LOAD_CERT_FILE, ERR_R_SYS_LIB);
        return 0;
    }

    while (cert_ctx = CertEnumCertificatesInStore(store, cert_ctx)) {
        if (cert_ctx->dwCertEncodingType != X509_ASN_ENCODING)
            continue;
        trust = cert_usage_is_server_auth(cert_ctx, CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG);
        if (trust < 0)
            goto done;
        if (trust) {
            biobuf = BIO_new_mem_buf(cert_ctx->pbCertEncoded, cert_ctx->cbCertEncoded);
            if (biobuf == NULL) {
                X509err(X509_F_X509_LOAD_CERT_FILE, ERR_R_SYS_LIB);
                goto done;
            }
            x = d2i_X509_bio(biobuf, NULL);
            BIO_free(biobuf);
            if (x == NULL) {
                X509err(X509_F_X509_LOAD_CERT_FILE, ERR_R_ASN1_LIB);
                goto done;
            }
            r = X509_STORE_add_cert(ctx->store_ctx, x);
            if (!r) {
                err = ERR_peek_last_error();
                if ((ERR_GET_LIB(err) == ERR_LIB_X509) && (ERR_GET_REASON(err) == X509_R_CERT_ALREADY_IN_HASH_TABLE)) {
                    /* cert already in hash table, not an error */
                    ERR_clear_error();
                } else {
                    X509_free(x);
                    goto done;
                }
            }
            X509_free(x);
        }
    }
    ret = 1;
done:
    if (cert_ctx)
        CertFreeCertificateContext(cert_ctx);
    CertCloseStore(store, 0);
    return ret;
}

int X509_load_platform_default_ca_certs(X509_LOOKUP *ctx)
{
    int ok = 1;
    ok = load_ca_certs_from_store("CA", ctx) && ok;
    ok = load_ca_certs_from_store("ROOT", ctx) && ok;
    return ok;
}

#elif defined(OPENSSL_SYS_MACOSX)

#include <Security/Security.h>

int X509_load_platform_default_ca_certs(X509_LOOKUP *ctx)
{
    CFArrayRef anchors;
    int i, count, ok, r, err;
    SecCertificateRef cr;
    CSSM_DATA cssm;
    BIO *biobuf;
    X509 *x;

    r = SecTrustCopyAnchorCertificates(&anchors);
    if (r == 0) {
        X509err(X509_F_X509_LOAD_CERT_FILE, ERR_R_SYS_LIB);
        return 0;
    }

    ok = 0;
    count = CFArrayGetCount(anchors);
    for (i = 0; i < count; ++i)
    {
        cr = (SecCertificateRef)CFArrayGetValueAtIndex(anchors, i);
        SecCertificateGetData(cr, &cssm);
        biobuf = BIO_new_mem_buf(cssm.Data, cssm.Length);
        if (biobuf == NULL) {
            X509err(X509_F_X509_LOAD_CERT_FILE, ERR_R_SYS_LIB);
            goto done;
        }
        x = d2i_X509_bio(biobuf, NULL);
        BIO_free(biobuf);
        if (x == NULL) {
            X509err(X509_F_X509_LOAD_CERT_FILE, ERR_R_ASN1_LIB);
            goto done;
        }
        r = X509_STORE_add_cert(ctx->store_ctx, x);
        if (!r) {
            err = ERR_peek_last_error();
            if ((ERR_GET_LIB(err) == ERR_LIB_X509) && (ERR_GET_REASON(err) == X509_R_CERT_ALREADY_IN_HASH_TABLE)) {
                /* cert already in hash table, not an error */
                ERR_clear_error();
            } else {
                X509_free(x);
                goto done;
            }
        }
        X509_free(x);
    }
    ok = 1;
done:
    CFRelease(anchors);
    return ok;
}

#else

int X509_load_platform_default_ca_certs(X509_LOOKUP *ctx)
{
    return 0;
}

#endif
