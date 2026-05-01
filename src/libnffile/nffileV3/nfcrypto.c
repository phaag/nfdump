/*
 *  Copyright (c) 2026, Peter Haag
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   * Neither the name of the author nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * nfcrypto.c — encryption context and key management for libnffile.
 *
 * See nfcrypto.h for the full design description.
 *
 * KDF: Argon2id (crypto_pwhash) at OPSLIMIT_MODERATE / 64 MB memlimit.
 *   ~100 ms on a modern machine; acceptable for interactive use and per-file
 *   rotation in capture daemons (key derivation is off the hot path).
 *
 * Nonce layout (ChaCha20-Poly1305 IETF, 12-byte nonce):
 *   blockNonce[0..7]  = rootNonce[0..7] XOR le64(dstFileOffset)
 *   blockNonce[8..11] = rootNonce[8..11]   (high 4 bytes unchanged)
 *
 * Every block at a distinct file offset gets a unique nonce; parallel
 * pwrite() calls never collide as long as blocks land at distinct offsets.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "logging.h"
#include "nfcrypto.h"
#include "nffileV3.h"

/* -----------------------------------------------------------------------
 * ParsePassphrase — parse the optarg value from getopt's -K option.
 *
 * Forms:
 *   optarg == NULL  → -K alone: prompt via getpass()
 *   optarg[0] == '='→ -K=passphrase: use literal passphrase after '='
 *   optarg[0] == '@'→ -K@keyfile:   read first line from the named file
 *   anything else   → error (bare -Kpassword is rejected)
 *
 * Returns heap-allocated passphrase; caller must zero and free it.
 * Returns NULL on error (message written to stderr).
 * ----------------------------------------------------------------------- */
char *ParsePassphrase(const char *arg, const char *prompt) {
    if (arg == NULL) {
        // -K alone: interactive prompt
        char *passPhrase = getpass(prompt ? prompt : "Enter passphrase: ");
        if (!passPhrase) {
            LogError("-K: getpass() failed: %s", strerror(errno));
            return NULL;
        }
        char *result = strdup(passPhrase);
        memset(passPhrase, 0, strlen(passPhrase)); /* best-effort zero of getpass buffer */
        return result;
    } else if (arg[0] == '=') {
        // -K=passphrase
        if (arg[1] == '\0') {
            LogError("-K: empty passphrase after '='");
            return NULL;
        }
        return strdup(arg + 1);
    } else if (arg[0] == '@') {
        // -K@keyfile: read passphrase from first line of file
        const char *fname = arg + 1;
        if (fname[0] == '\0') {
            LogError("-K: missing filename after '@'");
            return NULL;
        }
        FILE *fp = fopen(fname, "r");
        if (!fp) {
            LogError("-K: cannot open key file '%s': %s", fname, strerror(errno));
            return NULL;
        }
        char buf[1024];
        char *line = fgets(buf, sizeof(buf), fp);
        fclose(fp);
        if (!line) {
            LogError("-K: cannot read passphrase from '%s'", fname);
            return NULL;
        }
        // strip trailing newline / carriage return
        size_t len = strlen(buf);
        while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) buf[--len] = '\0';
        if (len == 0) {
            memset(buf, 0, sizeof(buf));
            LogError("-K: empty passphrase in '%s'", fname);
            return NULL;
        }
        char *result = strdup(buf);
        memset(buf, 0, sizeof(buf)); /* zero local stack copy */
        return result;
    } else {
        LogError("-K: use -K=<passphrase> or -K@<keyfile>; bare -K<value> is not accepted");
        return NULL;
    }
}  // End of ParsePassphrase

#ifdef HAVE_LIBSODIUM

#include <sodium.h>

/* -----------------------------------------------------------------------
 * Module-level read-path context: set by RegisterReadCryptoCtx().
 * NULL → fall back to interactive getpass() in DeriveKeyFromFile().
 * This pointer is never freed here; the caller owns it.
 * ----------------------------------------------------------------------- */
static const crypto_ctx_t *g_readCtx = NULL;

/* -----------------------------------------------------------------------
 * Internal helper: run Argon2id KDF and write the 32-byte result into out.
 * ----------------------------------------------------------------------- */
static int deriveKey(const char *passphrase, const uint8_t *salt32, uint8_t out[32]) {
    if (sodium_init() < 0) {
        LogError("sodium_init() failed");
        return 0;
    }
    if (crypto_pwhash(out, 32, passphrase, strlen(passphrase), salt32, crypto_pwhash_OPSLIMIT_MODERATE, 64 * 1024 * 1024UL, /* 64 MB memlimit */
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        LogError("deriveKey: crypto_pwhash() failed (out of memory?)");
        sodium_memzero(out, 32);
        return 0;
    }
    return 1;
}  // End of deriveKey

/* -----------------------------------------------------------------------
 * NewCryptoCtx — allocate and populate a crypto_ctx_t.
 * Returns NULL if passphrase is empty or sodium is unavailable.
 * ----------------------------------------------------------------------- */
crypto_ctx_t *NewCryptoCtx(const char *passphrase) {
    if (!passphrase || passphrase[0] == '\0') {
        LogError("NewCryptoCtx: empty passphrase");
        return NULL;
    }
    if (strlen(passphrase) >= sizeof(((crypto_ctx_t *)0)->passphrase)) {
        LogError("NewCryptoCtx: passphrase too long (max %zu chars)", sizeof(((crypto_ctx_t *)0)->passphrase) - 1);
        return NULL;
    }
    if (sodium_init() < 0) {
        LogError("NewCryptoCtx: sodium_init() failed");
        return NULL;
    }
    crypto_ctx_t *ctx = calloc(1, sizeof(crypto_ctx_t));
    if (!ctx) {
        LogError("NewCryptoCtx: calloc() failed: %s", strerror(errno));
        return NULL;
    }
    ctx->algorithm = CRYPTO_ALGO_CHACHA20_POLY1305;
    ctx->kdf = CRYPTO_KDF_ARGON2ID;
    ctx->kdfIterations = 0; /* use algorithm default */
    strncpy(ctx->passphrase, passphrase, sizeof(ctx->passphrase) - 1);
    return ctx;
}  // End of NewCryptoCtx

/* -----------------------------------------------------------------------
 * FreeCryptoCtx — zero the passphrase and free.
 * ----------------------------------------------------------------------- */
void FreeCryptoCtx(crypto_ctx_t *ctx) {
    if (!ctx) return;
    sodium_memzero(ctx->passphrase, sizeof(ctx->passphrase));
    free(ctx);
}  // End of FreeCryptoCtx

/* -----------------------------------------------------------------------
 * RegisterReadCryptoCtx — set the module-level read ctx used by
 * DeriveKeyFromFile().  Pass NULL to revert to interactive prompting.
 * ----------------------------------------------------------------------- */
void RegisterReadCryptoCtx(const crypto_ctx_t *ctx) {
    //
    g_readCtx = ctx;
}  // End of RegisterReadCryptoCtx

/* -----------------------------------------------------------------------
 * DeriveKeyForNewFile — write path: generate fresh random salt, derive key,
 * generate fresh random rootNonce, and populate *out.
 * salt32_out[32] receives the salt for storage in cryptoHeaderBlock_t.
 * ----------------------------------------------------------------------- */
int DeriveKeyForNewFile(const crypto_ctx_t *ctx, nffile_crypto_t *out, uint8_t salt32_out[32]) {
    if (!ctx || !out || !salt32_out) {
        LogError("DeriveKeyForNewFile: NULL argument");
        return 0;
    }
    if (sodium_init() < 0) {
        LogError("sodium_init() failed");
        return 0;
    }
    /* Fresh random salt for this file */
    randombytes_buf(salt32_out, 32);

    if (!deriveKey(ctx->passphrase, salt32_out, out->encKey)) return 0;

    /* Fresh random rootNonce for this file */
    randombytes_buf(out->rootNonce, sizeof(out->rootNonce));
    out->algorithm = ctx->algorithm;
    return 1;
}  // End of DeriveKeyForNewFile

/* -----------------------------------------------------------------------
 * DeriveKeyFromFile — read path: derive key using the salt from the on-disk
 * cryptoHeaderBlock.  Uses the registered ctx or falls back to getpass().
 * ----------------------------------------------------------------------- */
int DeriveKeyFromFile(const cryptoHeaderBlock_t *cryptoHdr, nffile_crypto_t *out) {
    if (!cryptoHdr || !out) {
        LogError("DeriveKeyFromFile: NULL argument");
        return 0;
    }
    if (sodium_init() < 0) {
        LogError("sodium_init() failed");
        return 0;
    }

    const char *passphrase = NULL;
    char *prompted = NULL;

    if (g_readCtx) {
        passphrase = g_readCtx->passphrase;
    } else {
        prompted = getpass("Enter decryption passphrase: ");
        if (!prompted) {
            LogError("DeriveKeyFromFile: getpass() failed: %s", strerror(errno));
            return 0;
        }
        passphrase = prompted;
    }

    int ok = deriveKey(passphrase, cryptoHdr->salt, out->encKey);
    if (prompted) sodium_memzero(prompted, strlen(prompted));

    if (ok) {
        memcpy(out->rootNonce, cryptoHdr->rootNonce, sizeof(out->rootNonce));
        out->algorithm = (crypto_algo_t)cryptoHdr->algorithm;
    }
    return ok;
}  // End of DeriveKeyFromFile

/* -----------------------------------------------------------------------
 * VerifyEncryptionKey — test derived key against the on-disk keyCheck tag.
 *
 * keyCheck = AEAD tag of encrypting 16 zero bytes with nonce = rootNonce.
 * We replicate the operation and compare with sodium_memcmp.
 * Returns 1 if correct, 0 if wrong or error.
 * ----------------------------------------------------------------------- */
int VerifyEncryptionKey(const cryptoHeaderBlock_t *cryptoHdr, const nffile_crypto_t *crypto) {
    if (!cryptoHdr || !crypto) return 0;

    static const uint8_t plain[16] = {0};
    uint8_t out[16 + crypto_aead_chacha20poly1305_ietf_ABYTES];
    unsigned long long outlen = 0;

    int rc = crypto_aead_chacha20poly1305_ietf_encrypt(out, &outlen, plain, sizeof(plain), NULL, 0, NULL, cryptoHdr->rootNonce, crypto->encKey);
    if (rc != 0) {
        LogError("VerifyEncryptionKey: AEAD encrypt failed");
        return 0;
    }

    /* Tag is the last ABYTES bytes of the output */
    if (sodium_memcmp(out + 16, cryptoHdr->keyCheck, 16) != 0) {
        LogError("VerifyEncryptionKey: wrong passphrase or corrupt key check");
        return 0;
    }
    return 1;
}  // End of VerifyEncryptionKey

#else /* !HAVE_LIBSODIUM — dead stubs so callers need no #ifdef */

crypto_ctx_t *NewCryptoCtx(const char *passphrase) {
    (void)passphrase;
    LogError("NewCryptoCtx: encryption not compiled in (libsodium missing)");
    return NULL;
}  // End of NewCryptoCtx

void FreeCryptoCtx(crypto_ctx_t *ctx) {
    //
    (void)ctx;
}  // End of FreeCryptoCtx

void RegisterReadCryptoCtx(const crypto_ctx_t *ctx) {
    //
    (void)ctx;
}  // End of RegisterReadCryptoCtx

int DeriveKeyForNewFile(const crypto_ctx_t *ctx, nffile_crypto_t *out, uint8_t salt32_out[32]) {
    (void)ctx;
    (void)out;
    (void)salt32_out;
    return 0;
}

int DeriveKeyFromFile(const cryptoHeaderBlock_t *cryptoHdr, nffile_crypto_t *out) {
    (void)cryptoHdr;
    (void)out;
    return 0;
}  // End of DeriveKeyFromFile

int VerifyEncryptionKey(const cryptoHeaderBlock_t *cryptoHdr, const nffile_crypto_t *crypto) {
    LogError("VerifyEncryptionKey: encryption not compiled in (libsodium missing)");
    (void)cryptoHdr;
    (void)crypto;
    return 0;
}  // End of VerifyEncryptionKey

#endif /* HAVE_LIBSODIUM */
