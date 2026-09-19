/* Copyright 2026 Cisco Systems, Inc. and its affiliates
 * SPDX-License-Identifier: Apache-2.0
 * Bounded pipe-only adapter to OpenSSL's RFC 5297 AES-256-SIV implementation.
 * No cryptographic primitive is implemented here. Never emit unauthenticated
 * plaintext, keys, request bytes, or OpenSSL diagnostics.
 */
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>

#define LIMIT (256U * 1024U)
static unsigned char key[64], aad[LIMIT], data[LIMIT], out[LIMIT + 16], tag[16];

static int read_exact(void *p, size_t n) { return fread(p, 1, n, stdin) == n; }
static uint32_t u32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

int main(int argc, char **argv) {
    unsigned char header[8];
    uint32_t alen = 0, dlen = 0;
    int enc, n = 0, final = 0, rc = 1;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core) != 0) return 1;
    if (argc != 2 || (strcmp(argv[1], "seal") && strcmp(argv[1], "open"))) return 1;
    enc = !strcmp(argv[1], "seal");
    /* No environment-supplied provider/configuration or legacy algorithms. */
    if (!OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL)) goto done;
    if (!read_exact(header, sizeof header)) goto done;
    alen = u32(header); dlen = u32(header + 4);
    if (!alen || alen > LIMIT || !dlen || dlen > LIMIT) goto done;
    if (!read_exact(key, sizeof key) || !read_exact(aad, alen) ||
        !read_exact(data, dlen) || (!enc && !read_exact(tag, sizeof tag)) ||
        fgetc(stdin) != EOF || ferror(stdin)) goto done;
    cipher = EVP_CIPHER_fetch(NULL, "AES-256-SIV", "provider=default");
    ctx = EVP_CIPHER_CTX_new();
    if (!cipher || !ctx || !EVP_CipherInit_ex2(ctx, cipher, key, NULL, enc, NULL)) goto done;
    if (!enc && !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, sizeof tag, tag)) goto done;
    if (!EVP_CipherUpdate(ctx, NULL, &n, aad, (int)alen) ||
        !EVP_CipherUpdate(ctx, out, &n, data, (int)dlen) ||
        !EVP_CipherFinal_ex(ctx, out + n, &final) || n + final != (int)dlen) goto done;
    if (enc && !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, sizeof tag, tag)) goto done;
    /* Only authenticated output crosses the pipe. */
    if (fwrite(out, 1, dlen, stdout) != dlen ||
        (enc && fwrite(tag, 1, sizeof tag, stdout) != sizeof tag) || fflush(stdout)) goto done;
    rc = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    OPENSSL_cleanse(key, sizeof key);
    OPENSSL_cleanse(data, sizeof data);
    OPENSSL_cleanse(out, sizeof out);
    return rc;
}
