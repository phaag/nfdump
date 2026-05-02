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
#include <termios.h>
#include <unistd.h>

#include "logging.h"
#include "nfcrypto.h"
#include "nffileV3.h"

#ifdef HAVE_LIBSODIUM
#include <sodium.h>
#endif

/* -----------------------------------------------------------------------
 * secure_prompt — termios-based password input, replaces deprecated getpass().
 *
 * Opens /dev/tty directly so it works even when stdin/stdout are redirected.
 * Disables echo, writes the prompt to stderr, reads one line, and restores
 * terminal state.  The internal stack buffer is zeroed before return.
 *
 * Returns a heap-allocated NUL-terminated string (strdup), or NULL on error.
 * Caller must zero and free the returned string when done.
 * ----------------------------------------------------------------------- */
static char *secure_prompt(const char *prompt) {
    FILE *tty = fopen("/dev/tty", "r+");
    int tty_opened = (tty != NULL);
    if (!tty) tty = stdin;  // last-resort fallback when no controlling terminal
    int fd = fileno(tty);

    /* Disable echo */
    struct termios old, noecho;
    int restore = (tcgetattr(fd, &old) == 0);
    if (restore) {
        noecho = old;
        noecho.c_lflag &= ~(tcflag_t)(ECHO | ECHOE | ECHOK | ECHONL);
        tcsetattr(fd, TCSAFLUSH, &noecho);
    }

    if (prompt) {
        fputs(prompt, stderr);
        fflush(stderr);
    }

    char buf[1024];
    char *line = fgets(buf, (int)sizeof(buf), tty);

    if (restore) tcsetattr(fd, TCSAFLUSH, &old);
    fputc('\n', stderr); /* restore cursor to next line after hidden input */

    if (tty_opened) fclose(tty);

    if (!line) {
        memset(buf, 0, sizeof(buf));
        return NULL;
    }

    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) buf[--len] = '\0';
    char *result = strdup(buf);
    memset(buf, 0, sizeof(buf));
    return result;
}  // End of secure_prompt

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
        char *result = secure_prompt(prompt ? prompt : "Enter passphrase: ");
        if (!result) {
            LogError("-K: failed to read passphrase interactively");
            return NULL;
        }
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

/* -----------------------------------------------------------------------
 * InitCrypto — one-time initialization of the libsodium library.
 * Called from Init_nffile().  Safe to call multiple times (libsodium
 * returns 1 on re-init), but only needs to run once.
 * Returns 1 on success, 0 on failure.
 * ----------------------------------------------------------------------- */
int InitCrypto(void) {
#ifdef HAVE_LIBSODIUM
    if (sodium_init() < 0) {
        LogError("InitCrypto: libsodium initialization failed");
        return 0;
    }
#endif
    return 1;
}  // End of InitCrypto

/* -----------------------------------------------------------------------
 * FreeFileCrypto — securely zero and free per-file crypto state.
 * Safe to call with NULL.
 * ----------------------------------------------------------------------- */
void FreeFileCrypto(nffile_crypto_t *crypto) {
    if (!crypto) return;
#ifdef HAVE_LIBSODIUM
    sodium_memzero(crypto->encKey, sizeof(crypto->encKey));
    sodium_memzero(crypto->rootNonce, sizeof(crypto->rootNonce));
#endif
    free(crypto);
}  // End of FreeFileCrypto

#ifdef HAVE_LIBSODIUM

/* sodium.h already included above the unconditional InitCrypto/FreeFileCrypto */

/* -----------------------------------------------------------------------
 * Module-level read-path context: set by RegisterReadCryptoCtx().
 * NULL → fall back to secure_prompt() in DeriveKeyFromFile().
 * This pointer is never freed here; the caller owns it.
 * ----------------------------------------------------------------------- */
static const crypto_ctx_t *g_readCtx = NULL;

/* -----------------------------------------------------------------------
 * Internal helper: run Argon2id KDF and write the 32-byte result into out.
 * Requires InitCrypto() to have been called first.
 * ----------------------------------------------------------------------- */
static int deriveKey(const char *passphrase, const uint8_t *salt32, uint8_t out[32]) {
    if (crypto_pwhash(out, 32, passphrase, strlen(passphrase), salt32, crypto_pwhash_OPSLIMIT_MODERATE, 64 * 1024 * 1024UL, /* 64 MB memlimit */
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        LogError("deriveKey: crypto_pwhash() failed (out of memory?)");
        sodium_memzero(out, 32);
        return 0;
    }
    return 1;
}  // End of deriveKey

/* -----------------------------------------------------------------------
 * findOrig — XOR-decode the obfuscated passphrase from ctx into a
 * freshly sodium_malloc()'d buffer.  The caller MUST:
 *   1. use the buffer immediately for KDF input,
 *   2. sodium_memzero(buf, ctx->passLen),
 *   3. sodium_free(buf).
 * Returns NULL on allocation failure.
 * ----------------------------------------------------------------------- */
static char *findOrig(const crypto_ctx_t *ctx) {
    /* +1 for NUL terminator */
    char *tmp = sodium_malloc(ctx->passLen + 1);
    if (!tmp) {
        LogError("findOrig: sodium_malloc failed");
        return NULL;
    }
    for (size_t i = 0; i < ctx->passLen; i++) {
        tmp[i] = (char)((uint8_t)ctx->maskedPass[i] ^ ctx->passPad[i]);
    }
    tmp[ctx->passLen] = '\0';
    return tmp;
}  // End of findOrig

/* -----------------------------------------------------------------------
 * NewCryptoCtx — allocate and populate a crypto_ctx_t.
 * Returns NULL if passphrase is empty or sodium is unavailable.
 * ----------------------------------------------------------------------- */
crypto_ctx_t *NewCryptoCtx(const char *passphrase) {
    if (!passphrase || passphrase[0] == '\0') {
        LogError("NewCryptoCtx: empty passphrase");
        return NULL;
    }
    const size_t plen = strlen(passphrase);
    if (plen > CRYPTO_CTX_MAX_PASSPHRASE) {
        LogError("NewCryptoCtx: passphrase too long (max %u chars)", CRYPTO_CTX_MAX_PASSPHRASE);
        return NULL;
    }
    // sodium_malloc requires sodium_init()
    // sodium_init() is safe to be called more than once and thread-safe
    if (sodium_init() < 0) {
        LogError("NewCryptoCtx: sodium_init() failed");
        return NULL;
    }
    /* sodium_malloc allocates mlock'd memory with guard pages */
    crypto_ctx_t *ctx = sodium_malloc(sizeof(crypto_ctx_t));
    if (!ctx) {
        LogError("NewCryptoCtx: sodium_malloc() failed");
        return NULL;
    }
    memset(ctx, 0, sizeof(crypto_ctx_t));
    ctx->algorithm = CRYPTO_ALGO_CHACHA20_POLY1305;
    ctx->kdf = CRYPTO_KDF_ARGON2ID;
    ctx->kdfIterations = 0;  // use algorithm default
    ctx->passLen = plen;

    /* XOR-mask the passphrase with a random pad so the cleartext bytes are
     * not directly visible in a process-memory dump. */
    randombytes_buf(ctx->passPad, plen);
    for (size_t i = 0; i < plen; i++) {
        ctx->maskedPass[i] = (uint8_t)passphrase[i] ^ ctx->passPad[i];
    }
    // Remainder of both arrays is already zero from the memset above
    return ctx;
}  // End of NewCryptoCtx

/* -----------------------------------------------------------------------
 * FreeCryptoCtx — zero the passphrase and free.
 * ----------------------------------------------------------------------- */
void FreeCryptoCtx(crypto_ctx_t *ctx) {
    if (!ctx) return;
    sodium_memzero(ctx->maskedPass, sizeof(ctx->maskedPass));
    sodium_memzero(ctx->passPad, sizeof(ctx->passPad));
    sodium_free(ctx);
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
    /* Fresh random salt for this file */
    /* (sodium_init already called by InitCrypto at startup) */
    randombytes_buf(salt32_out, 32);

    // Temporarily decode the XOR-masked passphrase into mlock'd memory
    char *tmp = findOrig(ctx);
    if (!tmp) return 0;
    int ok = deriveKey(tmp, salt32_out, out->encKey);
    sodium_memzero(tmp, ctx->passLen);
    sodium_free(tmp);
    if (!ok) return 0;

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

    char *unmasked = NULL; /* sodium_malloc'd plaintext copy; zeroed after use */
    const char *passphrase = NULL;
    char *prompted = NULL;

    if (g_readCtx) {
        /* Decode the XOR-masked passphrase into a temporary mlock'd buffer */
        unmasked = findOrig(g_readCtx);
        if (!unmasked) {
            LogError("DeriveKeyFromFile: failed to unmask passphrase");
            return 0;
        }
        passphrase = unmasked;
    } else {
        prompted = secure_prompt("Enter decryption passphrase: ");
        if (!prompted) {
            LogError("DeriveKeyFromFile: failed to read passphrase interactively");
            return 0;
        }
        passphrase = prompted;
    }

    int ok = deriveKey(passphrase, cryptoHdr->salt, out->encKey);

    /* Zero and free the cleartext copy immediately after KDF */
    if (unmasked) {
        sodium_memzero(unmasked, g_readCtx->passLen);
        sodium_free(unmasked);
    }
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

/* -----------------------------------------------------------------------
 * ComputeFileMac — derive a domain-separated MAC key and compute a
 * 32-byte BLAKE2b over the stable, plaintext file structure:
 *   1. Selected fileHeaderV3_t fields (nfdVersion, created, creator,
 *      flags, blockSize) — excludes offDirectory/dirSize known only at close
 *   2. cryptoHeaderBlock_t crypto-specific fields (algorithm, kdfType,
 *      kdfIterations, salt, rootNonce, keyCheck)
 *   3. All directoryEntryV3_t entries in order (type, size, offset)
 *
 * MAC key: crypto_kdf_derive_from_key(encKey, subkey_id=1, ctx="nfdmpMAC")
 * Hash   : crypto_generichash (BLAKE2b-256 with MAC key)
 * ----------------------------------------------------------------------- */
int ComputeFileMac(const nffile_crypto_t *crypto, const fileHeaderV3_t *hdr, const cryptoHeaderBlock_t *cryptoHdr, const directoryEntryV3_t *entries,
                   uint32_t numEntries, uint8_t mac_out[32]) {
    if (!crypto || !hdr || !cryptoHdr || (!entries && numEntries > 0) || !mac_out) {
        LogError("ComputeFileMac: NULL argument");
        return 0;
    }

    // Derive a 32-byte MAC key from the session key (domain-separated)
    uint8_t macKey[crypto_kdf_KEYBYTES]; /* = 32 bytes */
    if (crypto_kdf_derive_from_key(macKey, sizeof(macKey), /*subkey_id=*/1, "nfdmpMAC", crypto->encKey) != 0) {
        LogError("ComputeFileMac: crypto_kdf_derive_from_key() failed");
        sodium_memzero(macKey, sizeof(macKey));
        return 0;
    }

    // BLAKE2b-256 MAC keyed with macKey
    crypto_generichash_state st;
    crypto_generichash_init(&st, macKey, sizeof(macKey), 32);
    sodium_memzero(macKey, sizeof(macKey));

    // 1. selected fileHeaderV3_t fields
    crypto_generichash_update(&st, (const uint8_t *)&hdr->nfdVersion, sizeof(hdr->nfdVersion));
    crypto_generichash_update(&st, (const uint8_t *)&hdr->created, sizeof(hdr->created));
    crypto_generichash_update(&st, (const uint8_t *)&hdr->creator, sizeof(hdr->creator));
    crypto_generichash_update(&st, (const uint8_t *)&hdr->flags, sizeof(hdr->flags));
    crypto_generichash_update(&st, (const uint8_t *)&hdr->blockSize, sizeof(hdr->blockSize));

    // 2. cryptoHeaderBlock_t crypto-specific fields (beyond the common BLOCKHEADER)
    crypto_generichash_update(&st, (const uint8_t *)&cryptoHdr->version,       sizeof(cryptoHdr->version));
    crypto_generichash_update(&st, (const uint8_t *)&cryptoHdr->algorithm,     sizeof(cryptoHdr->algorithm));
    crypto_generichash_update(&st, (const uint8_t *)&cryptoHdr->kdfType,       sizeof(cryptoHdr->kdfType));
    crypto_generichash_update(&st, (const uint8_t *)&cryptoHdr->kdfIterations, sizeof(cryptoHdr->kdfIterations));
    crypto_generichash_update(&st, cryptoHdr->salt,                            sizeof(cryptoHdr->salt));
    crypto_generichash_update(&st, cryptoHdr->rootNonce,                       sizeof(cryptoHdr->rootNonce));
    crypto_generichash_update(&st, cryptoHdr->keyCheck,                        sizeof(cryptoHdr->keyCheck));

    // 3. directory entries in order
    for (uint32_t i = 0; i < numEntries; i++) {
        const directoryEntryV3_t *e = &entries[i];
        crypto_generichash_update(&st, (const uint8_t *)&e->type, sizeof(e->type));
        crypto_generichash_update(&st, (const uint8_t *)&e->size, sizeof(e->size));
        crypto_generichash_update(&st, (const uint8_t *)&e->offset, sizeof(e->offset));
    }

    crypto_generichash_final(&st, mac_out, 32);
    return 1;
}  // End of ComputeFileMac

/* -----------------------------------------------------------------------
 * VerifyFileMac — compute expected MAC and compare with stored value.
 * Uses constant-time sodium_memcmp.
 * Returns 1 if MAC matches, 0 on mismatch or computation error.
 * ----------------------------------------------------------------------- */
int VerifyFileMac(const nffile_crypto_t *crypto, const fileHeaderV3_t *hdr, const cryptoHeaderBlock_t *cryptoHdr, const directoryEntryV3_t *entries,
                  uint32_t numEntries, const uint8_t mac[32]) {
    if (!mac) return 0;
    uint8_t expected[32];
    if (!ComputeFileMac(crypto, hdr, cryptoHdr, entries, numEntries, expected)) return 0;
    int ok = (sodium_memcmp(expected, mac, 32) == 0);
    sodium_memzero(expected, sizeof(expected));
    return ok;
}  // End of VerifyFileMac

#else /* !HAVE_LIBSODIUM — dead stubs so callers need no #ifdef */

/* InitCrypto and FreeFileCrypto are defined unconditionally above the
 * HAVE_LIBSODIUM guard, since they compile without libsodium. */

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

int ComputeFileMac(const nffile_crypto_t *crypto, const fileHeaderV3_t *hdr, const cryptoHeaderBlock_t *cryptoHdr, const directoryEntryV3_t *entries,
                   uint32_t numEntries, uint8_t mac_out[32]) {
    (void)crypto;
    (void)hdr;
    (void)cryptoHdr;
    (void)entries;
    (void)numEntries;
    (void)mac_out;
    return 0;
}  // End of ComputeFileMac

int VerifyFileMac(const nffile_crypto_t *crypto, const fileHeaderV3_t *hdr, const cryptoHeaderBlock_t *cryptoHdr, const directoryEntryV3_t *entries,
                  uint32_t numEntries, const uint8_t mac[32]) {
    (void)crypto;
    (void)hdr;
    (void)cryptoHdr;
    (void)entries;
    (void)numEntries;
    (void)mac;
    return 0;
}  // End of VerifyFileMac

#endif /* HAVE_LIBSODIUM */
