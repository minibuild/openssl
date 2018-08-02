/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/crypto.h>
#include <openssl/x509.h>

static const char EMPTY_PATH[] = "";

#if !defined(OPENSSL_SYS_WINDOWS) && !defined(OPENSSL_SYS_MACOSX) && !defined(OPENSSL_SYS_VMS)

#include <sys/stat.h>

/*
    This is where Go looks for public root certificates:
      - https://golang.org/src/crypto/x509/root_linux.go
      - https://golang.org/src/crypto/x509/root_bsd.go
      - https://golang.org/src/crypto/x509/root_unix.go
*/

static const char *X509_CERT_FILE_PROBE[] = {
#if defined(OPENSSL_SYS_LINUX)
    "/etc/ssl/certs/ca-certificates.crt",                   /* Debian/Ubuntu/Gentoo etc. */
    "/etc/pki/tls/certs/ca-bundle.crt",                     /* Fedora/RHEL 6 */
    "/etc/ssl/ca-bundle.pem",                               /* OpenSUSE */
    "/etc/pki/tls/cacert.pem",                              /* OpenELEC */
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",    /* CentOS/RHEL 7 */
#elif defined(OPENSSL_SYS_UNIX)
    "/usr/local/etc/ssl/cert.pem",                          /* FreeBSD */
    "/etc/ssl/cert.pem",                                    /* OpenBSD */
    "/usr/local/share/certs/ca-root-nss.crt",               /* DragonFly */
    "/etc/openssl/certs/ca-certificates.crt",               /* NetBSD */
#endif
    EMPTY_PATH
};

static const char *X509_CERT_DIR_PROBE[] = {
    "/etc/ssl/certs",                 /* SLES10/SLES11 */
    "/system/etc/security/cacerts",   /* Android */
    "/usr/local/share/certs",         /* FreeBSD */
    "/etc/pki/tls/certs",             /* Fedora/RHEL */
    "/etc/openssl/certs",             /* NetBSD */
    EMPTY_PATH
};

static int is_file(const char* filename)
{
    struct stat buf;
    if (stat(filename, &buf) != 0)
        return 0;
    if (!S_ISREG(buf.st_mode))
        return 0;
    return 1;
}

static int is_dir(const char* filename)
{
    struct stat buf;
    if (stat(filename, &buf) != 0)
        return 0;
    if (!S_ISDIR(buf.st_mode))
        return 0;
    return 1;
}

#endif

const char *X509_get_default_private_dir(void)
{
    return (X509_PRIVATE_DIR);
}

const char *X509_get_default_cert_area(void)
{
    return (X509_CERT_AREA);
}

const char *X509_get_default_cert_dir(void)
{
#if defined(OPENSSL_SYS_VMS)
    return (X509_CERT_DIR);
#elif !defined(OPENSSL_SYS_WINDOWS) && !defined(OPENSSL_SYS_MACOSX)
    const char* dirname = NULL;
    int i = 0;
    do {
        dirname = X509_CERT_DIR_PROBE[i];
        if (is_dir(dirname))
            break;
        ++i;
    } while (dirname[0]);
    return dirname;
#else
    return EMPTY_PATH;
#endif
}

const char *X509_get_default_cert_file(void)
{
#if defined(OPENSSL_SYS_VMS)
    return (X509_CERT_FILE);
#elif !defined(OPENSSL_SYS_WINDOWS) && !defined(OPENSSL_SYS_MACOSX)
    const char* filename = NULL;
    int i = 0;
    do {
        filename = X509_CERT_FILE_PROBE[i];
        if (is_file(filename))
            break;
        ++i;
    } while (filename[0]);
    return filename;
#else
    return EMPTY_PATH;
#endif
}

const char *X509_get_default_cert_dir_env(void)
{
    return (X509_CERT_DIR_EVP);
}

const char *X509_get_default_cert_file_env(void)
{
    return (X509_CERT_FILE_EVP);
}
