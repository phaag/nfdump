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

#ifndef NFCRYPTO_H
#define NFCRYPTO_H 1

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>

/*
 * nfcrypto — encryption context and key management for libnffile.
 *
 * Design principles:
 *   - crypto_ctx_t is the application-lifetime, caller-owned, immutable
 *     configuration object created from the -K passphrase.  It is shared
 *     (read-only) across threads without locking.
 *   - Per-file runtime material (derived key, rootNonce) lives in
 *     nffile_crypto_t inside nffileV3_t and is generated fresh for each
 *     new file by InitNewFileV3().
 *   - All functions compile without HAVE_LIBSODIUM: when sodium is absent,
 *     NewCryptoCtx() returns NULL and all other entry points fail safely.
 *
 * Typical write path (capture daemons):
 *   crypto_ctx_t *ctx = NewCryptoCtx(passphrase);      // once at startup
 *   OpenNewFileTmpV3(..., ctx);                        // per file rotation
 *    -> InitNewFileV3 derives a fresh key + nonce for each file internally
 *   FreeCryptoCtx(ctx);                                // on exit
 *
 * Typical read path (nfdump):
 *   crypto_ctx_t *ctx = NewCryptoCtx(passphrase);      // once at startup
 *   RegisterReadCryptoCtx(ctx);                        // affects OpenFileV3
 *    -> mmapFileV3 auto-derives + verifies key per encrypted file
 *   RegisterReadCryptoCtx(NULL);
 *   FreeCryptoCtx(ctx);
 *
 * If no ctx is registered on the read path and an encrypted file is opened,
 * mmapFileV3 falls back to an interactive getpass() prompt.
 *
 * Algorithm / KDF identifiers (also stored on-disk in cryptoHeaderBlock_t):
 */
typedef enum {
    CRYPTO_ALGO_NONE = 0,               // not encrypted
    CRYPTO_ALGO_CHACHA20_POLY1305 = 1,  // ChaCha20-Poly1305 IETF, libsodium
    // CRYPTO_ALGO_AES256_GCM     = 2,  //   reserved for future use - implemented later
} crypto_algo_t;

typedef enum {
    CRYPTO_KDF_ARGON2ID = 1,  // libsodium crypto_pwhash Argon2id
    // CRYPTO_KDF_SCRYPT = 2, //   reserved for future use
} crypto_kdf_t;

/*
 * Application-lifetime crypto configuration.
 * Created once, immutable, shared read-only across threads.
 *
 * The passphrase is never stored in cleartext.  Instead it is XOR-obfuscated
 * with a random pad generated at NewCryptoCtx() time so that the raw
 * passphrase bytes are not directly visible in a process-memory dump.
 * Both arrays are zeroed by FreeCryptoCtx().
 *
 * To recover the plaintext temporarily, XOR maskedPass[0..passLen-1] with
 * passPad[0..passLen-1].  The scratch buffer must be sodium_free()'d after use.
 */
#define CRYPTO_CTX_MAX_PASSPHRASE 1023u  /* maximum passphrase length (bytes, excl. NUL) */
typedef struct crypto_ctx_s {
    crypto_algo_t algorithm;  // which AEAD cipher to use
    crypto_kdf_t kdf;         // which KDF to use for key derivation
    uint32_t kdfIterations;   // 0 = use algorithm default
    size_t passLen;           // strlen of original passphrase
    uint8_t passPad[CRYPTO_CTX_MAX_PASSPHRASE + 1];     /* random one-time XOR mask */
    uint8_t maskedPass[CRYPTO_CTX_MAX_PASSPHRASE + 1];  /* passphrase XOR passPad   */
} crypto_ctx_t;

/*
 * Parse the optarg value from getopt for the -K option.
 *
 * Accepted forms (optarg is the string immediately after -K, no space):
 *   NULL          -K alone              prompt interactively (echo off)
 *   "=passphrase" -K=passphrase         use the literal passphrase
 *   "@keyfile"    -K@/path/to/file      read the first line of keyfile
 *
 * Bare "-Kpassword" (optarg[0] not '=' or '@') is rejected with an error
 *
 * Returns a heap-allocated NUL-terminated passphrase string.
 * The caller must zero and free it after use.
 * Returns NULL on any error (message written via LogError).
 */
char *ParsePassphrase(const char *optarg, const char *prompt);

/* Forward declarations for MAC functions (full types in nffileV3.h) */
struct fileHeaderV3_s;
struct directoryEntryV3_s;

/* Forward declarations; full structs defined in nffileV3.h */
struct nffile_crypto_s;
struct cryptoHeaderBlock_s;

/*
 * One-time initialization of the libsodium library.  Must be called before
 * any other crypto function.  Invoked automatically by Init_nffile().
 * Returns 1 on success, 0 on failure.
 */
int InitCrypto(void);

/*
 * Securely zero and free per-file crypto state.  Safe to call with NULL.
 * Used by CloseFileV3() and DeleteFile().
 */
void FreeFileCrypto(struct nffile_crypto_s *crypto);

/*
 * Create a crypto_ctx_t with default algorithm (ChaCha20-Poly1305) and KDF
 * (Argon2id).  passphrase must be non-empty.
 * Returns NULL if libsodium is not compiled in, or on error.
 * Caller must call FreeCryptoCtx() when done.
 */
crypto_ctx_t *NewCryptoCtx(const char *passphrase);

/* Securely zero the passphrase and free.  Safe to call with NULL. */
void FreeCryptoCtx(crypto_ctx_t *ctx);

/*
 * Read path: register the ctx used by mmapFileV3() for all subsequently
 * opened encrypted files.  Pass NULL to revert to interactive prompting.
 * The ctx must remain valid until after all files are closed.
 */
void RegisterReadCryptoCtx(const crypto_ctx_t *ctx);

/*
 * -----------------------------------------------------------------------
 * Internal functions — called by nfwrite.c and nfread.c only.
 * Not intended for direct use by CLI tools.
 * -----------------------------------------------------------------------
 */

/* (Forward declarations moved above InitCrypto/FreeFileCrypto) */

/*
 * Write path: generate a fresh 32-byte random salt, derive the session key
 * from ctx->passphrase + salt via Argon2id, and fill *out with the
 * derived key and a fresh random rootNonce.
 * salt32_out[32] receives the generated salt for storage in the file header.
 * Returns 1 on success, 0 on error.
 */
int DeriveKeyForNewFile(const crypto_ctx_t *ctx, struct nffile_crypto_s *out, uint8_t salt32_out[32]);

/*
 * Read path: derive key from the registered ctx (or interactive getpass if
 * NULL) using the salt from the file's cryptoHeaderBlock, and fill *out.
 * Returns 1 on success, 0 on error.
 */
int DeriveKeyFromFile(const struct cryptoHeaderBlock_s *cryptoHdr, struct nffile_crypto_s *out);

/*
 * Verify the derived key in *crypto against the keyCheck in *cryptoHdr.
 * Returns 1 if correct, 0 if wrong or error.
 */
int VerifyEncryptionKey(const struct cryptoHeaderBlock_s *cryptoHdr, const struct nffile_crypto_s *crypto);

/*
 * Compute a 32-byte BLAKE2b file-structure MAC for encrypted files.
 *
 * A 32-byte MAC key is derived from crypto->encKey via crypto_kdf_derive_from_key
 * (subkey_id=1, ctx="nfdmpMAC"), domain-separating it from the encryption key.
 *
 * MAC input (fixed order):
 *   1. fileHeaderV3_t: nfdVersion, created, creator, flags, blockSize
 *   2. cryptoHeaderBlock_t: algorithm, kdfType, kdfIterations, salt,
 *                           rootNonce, keyCheck
 *   3. All directoryEntryV3_t in order: type, size, offset per entry
 *
 * Returns 1 on success, 0 on error.
 * Requires HAVE_LIBSODIUM; no-op stub returns 0 when libsodium absent.
 */
int ComputeFileMac(const struct nffile_crypto_s *crypto,
                   const struct fileHeaderV3_s *hdr,
                   const struct cryptoHeaderBlock_s *cryptoHdr,
                   const struct directoryEntryV3_s *entries,
                   uint32_t numEntries,
                   uint8_t mac_out[32]);

/*
 * Verify the 32-byte file MAC stored in mac[] against a freshly computed MAC.
 * Returns 1 if equal (via constant-time sodium_memcmp), 0 on mismatch or error.
 */
int VerifyFileMac(const struct nffile_crypto_s *crypto,
                  const struct fileHeaderV3_s *hdr,
                  const struct cryptoHeaderBlock_s *cryptoHdr,
                  const struct directoryEntryV3_s *entries,
                  uint32_t numEntries,
                  const uint8_t mac[32]);

/*
 * Additional Authenticated Data (AAD) for block-level AEAD.
 * Authenticates block header fields that are written in plaintext alongside
 * the ciphertext, preventing an attacker from silently altering block type,
 * size, compression, or position without detection.
 *
 * NOTE: files written with AAD are not compatible with files written without.
 * All new encrypted files use this structure.  The struct layout is fixed;
 * natural C alignment produces no padding (all uint32_t + uint64_t at 16).
 */
typedef struct {
    uint32_t type;        /* block type (from block header) */
    uint32_t rawSize;     /* uncompressed payload size (from block header) */
    uint32_t compression; /* compression algorithm (uint32 of uint16 field) */
    uint32_t pad;         /* reserved; must be zero */
    uint64_t offset;      /* block's file offset (dstOffset / entry->offset) */
} blockEncAAD_t;
_Static_assert(sizeof(blockEncAAD_t) == 24, "blockEncAAD_t size");

#endif /* NFCRYPTO_H */
