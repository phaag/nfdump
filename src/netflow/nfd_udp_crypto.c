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
 * nfd_udp_crypto.c — UDP transport encryption/decryption for nfpcapd→nfcapd.
 *
 * See nfd_udp_crypto.h for the full design description.
 *
 * Key derivation:
 *   Argon2id (crypto_pwhash) at OPSLIMIT_INTERACTIVE / 16 MB memlimit.
 *   16-byte domain-separation salt distinguishes the UDP transport key from
 *   per-file keys even when the same passphrase is passed to both nfpcapd
 *   and nfcapd via -K.  The salt defaults to "nfpcapd-udpkey1\0" and may be
 *   overridden via crypt.salt in nfdump.conf [common] before startup.
 *
 * Nonce:
 *   24-byte random nonce per packet (randombytes_buf).  XChaCha20 uses a
 *   192-bit nonce, so no counter management is needed; birthday collision
 *   probability is negligible at any realistic packet rate.
 *
 * Compression:
 *   LZ4 default compression applied before encryption when HAVE_LZ4 is
 *   defined, inner payload > NFD_COMP_THRESHOLD (512) bytes, and the
 *   compressed form is at least 10% smaller than the original.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "logging.h"
#include "nfd_udp_crypto.h"
#include "nffileV3/nfcrypto.h"

#ifdef HAVE_LIBSODIUM
#include <sodium.h>
#endif

#ifdef HAVE_LZ4
#include <lz4.h>
#else
#include "compress/lz4.h"
#endif

/* -----------------------------------------------------------------------
 * Module-private crypto state — one singleton per process.
 *
 * Bundled as a struct so all related fields are visible together and new
 * fields can be added in one place.  The public API (SetUdpSalt,
 * SetUdpRekeyInterval, DeriveUdpSessionKey, UdpEncrypt, UdpDecrypt)
 * is unchanged.
 *
 * salt:
 *   16-byte domain-separation salt for Argon2id KDF.  Must be exactly
 *   crypto_pwhash_SALTBYTES bytes.  Not secret; purpose is to produce a
 *   key distinct from any file-backend keys.  Default "nfpcapd-udpkey1\0".
 *   Override with SetUdpSalt() before DeriveUdpSessionKey().
 *
 * rekeyIntervalSecs:
 *   0 → rekeying disabled; session key used directly.  When non-zero both
 *   paths derive a per-epoch subkey via crypto_kdf_derive_from_key (BLAKE2b).
 *
 * encryptEpoch / decryptEpoch:
 *   Single-entry epoch-subkey caches.  Kept separate so encrypt and decrypt
 *   paths never share key material and recomputation is skipped for the
 *   common case where every packet in a burst carries the same epoch.
 *   UINT32_MAX is the sentinel meaning "not yet initialised".
 * ----------------------------------------------------------------------- */
typedef struct {
    uint8_t  salt[16];
    uint32_t rekeyIntervalSecs;
    uint32_t encryptEpoch;
    uint8_t  encryptKey[32];
    uint32_t decryptEpoch;
    uint8_t  decryptKey[32];
} udp_crypto_state_t;

static udp_crypto_state_t g_udpCrypto = {
    .salt              = {'n', 'f', 'p', 'c', 'a', 'p', 'd', '-', 'u', 'd', 'p', 'k', 'e', 'y', '1', '\0'},
    .rekeyIntervalSecs = 0,
    .encryptEpoch      = UINT32_MAX,
    .decryptEpoch      = UINT32_MAX,
};

/* -----------------------------------------------------------------------
 * DeriveUdpSessionKey
 * ----------------------------------------------------------------------- */
uint8_t *DeriveUdpSessionKey(const crypto_ctx_t *ctx) {
#ifndef HAVE_LIBSODIUM
    (void)ctx;
    LogError("DeriveUdpSessionKey: libsodium not available — UDP encryption disabled");
    return NULL;
#else
    if (!ctx) {
        LogError("DeriveUdpSessionKey: NULL crypto context");
        return NULL;
    }
    if (ctx->passLen == 0) {
        LogError("DeriveUdpSessionKey: empty passphrase");
        return NULL;
    }

    // Allocate output key in mlock()'d guarded memory
    uint8_t *key = sodium_malloc(32);
    if (!key) {
        LogError("DeriveUdpSessionKey: sodium_malloc(32) failed");
        return NULL;
    }

    /* Temporarily decode the XOR-masked passphrase into a fresh
     * sodium_malloc() scratch buffer, identical to the approach used
     * in nfcrypto.c findOrig().  Zero and free immediately after KDF. */
    char *tmp = sodium_malloc(ctx->passLen + 1);
    if (!tmp) {
        LogError("DeriveUdpSessionKey: sodium_malloc(passphrase scratch) failed");
        sodium_free(key);
        return NULL;
    }
    for (size_t i = 0; i < ctx->passLen; i++) {
        tmp[i] = (char)((uint8_t)ctx->maskedPass[i] ^ ctx->passPad[i]);
    }
    tmp[ctx->passLen] = '\0';

    int ok = (crypto_pwhash(key, 32, tmp, ctx->passLen, g_udpCrypto.salt, crypto_pwhash_OPSLIMIT_INTERACTIVE, 16 * 1024 * 1024UL,  // 16 MB memlimit
                            crypto_pwhash_ALG_ARGON2ID13) == 0);

    sodium_memzero(tmp, ctx->passLen);
    sodium_free(tmp);

    if (!ok) {
        LogError("DeriveUdpSessionKey: crypto_pwhash (Argon2id) failed");
        sodium_memzero(key, 32);
        sodium_free(key);
        return NULL;
    }

    return key;
#endif
}  // End of DeriveUdpSessionKey

/* -----------------------------------------------------------------------
 * FreeUdpSessionKey
 * ----------------------------------------------------------------------- */
void FreeUdpSessionKey(uint8_t *key) {
#ifdef HAVE_LIBSODIUM
    if (!key) return;
    sodium_memzero(key, 32);
    sodium_free(key);
#else
    (void)key;
#endif
}  // End of FreeUdpSessionKey

/* -----------------------------------------------------------------------
 * SetUdpRekeyInterval
 * ----------------------------------------------------------------------- */
void SetUdpRekeyInterval(uint32_t intervalSecs) {
    g_udpCrypto.rekeyIntervalSecs = intervalSecs;
    // Invalidate both epoch key caches so the next packet re-derives cleanly.
    g_udpCrypto.encryptEpoch = UINT32_MAX;
    g_udpCrypto.decryptEpoch = UINT32_MAX;
#ifdef HAVE_LIBSODIUM
    sodium_memzero(g_udpCrypto.encryptKey, sizeof(g_udpCrypto.encryptKey));
    sodium_memzero(g_udpCrypto.decryptKey, sizeof(g_udpCrypto.decryptKey));
#endif
    if (intervalSecs > 0)
        LogInfo("UdpCrypto: epoch rekeying enabled, interval=%u s (~%u min)", intervalSecs, intervalSecs / 60u);
    else
        LogInfo("UdpCrypto: epoch rekeying disabled (single session key)");
}  // End of SetUdpRekeyInterval

/* -----------------------------------------------------------------------
 * SetUdpSalt
 * ----------------------------------------------------------------------- */
void SetUdpSalt(const char *saltStr) {
    if (!saltStr || saltStr[0] == '\0') {
        LogError("SetUdpSalt: empty or NULL salt string — keeping default");
        return;
    }
    for (size_t i = 0; saltStr[i]; i++) {
        unsigned char c = (unsigned char)saltStr[i];
        if (c < 0x20 || c > 0x7e) {
            LogError("SetUdpSalt: non-printable character at offset %zu — keeping default", i);
            return;
        }
    }
    size_t n = strlen(saltStr);
    if (n > 16) {
        LogInfo("UdpCrypto: KDF salt truncated to first 16 bytes");
        n = 16;
    }
    memset(g_udpCrypto.salt, 0, sizeof(g_udpCrypto.salt));
    memcpy(g_udpCrypto.salt, saltStr, n);
    LogInfo("UdpCrypto: KDF salt configured (\"%.*s\")", (int)n, g_udpCrypto.salt);
}  // End of SetUdpSalt

/* -----------------------------------------------------------------------
 * anti_replay_check
 *
 * Implements a 256-bit sliding window using 32-bit sequence number
 * arithmetic with wrap-around via signed subtraction (RFC 6479 style).
 * ----------------------------------------------------------------------- */
int anti_replay_check(anti_replay_t *ar, uint32_t seq) {
    // Default window if somehow uninitialised (e.g. calloc'd by old code)
    if (ar->windowBits == 0) ar->windowBits = ANTI_REPLAY_WINDOW_DEFAULT;
    const uint32_t W = ar->windowBits;  // active window width (power of 2)
    const uint32_t mask = W - 1;        // bit-position mask

    if (!ar->initialized) {
        // Bootstrap: first packet sets the window position
        ar->top = seq;
        ar->initialized = 1;
        memset(ar->window, 0, W / 8);
        uint32_t bit = seq & mask;
        ar->window[bit >> 3] |= (uint8_t)(1u << (bit & 7u));
        return 1;
    }

    // Use signed 32-bit difference for correct wrap-around handling
    int32_t diff = (int32_t)(seq - ar->top);

    if (diff < 0) {
        // seq is behind top
        uint32_t behind = (uint32_t)(-diff);
        if (behind >= W) {
            // Too old — outside the window
            return 0;
        }
        uint32_t bit = seq & mask;
        uint8_t bmask = (uint8_t)(1u << (bit & 7u));
        if (ar->window[bit >> 3] & bmask) {
            // Already seen — replay
            return 0;
        }
        ar->window[bit >> 3] |= bmask;
        return 1;
    }

    if (diff == 0) {
        // Exact duplicate of top
        uint32_t bit = seq & mask;
        uint8_t bmask = (uint8_t)(1u << (bit & 7u));
        if (ar->window[bit >> 3] & bmask) return 0;  // replay
        ar->window[bit >> 3] |= bmask;
        return 1;
    }

    // diff > 0: seq is ahead of top — advance the window
    uint32_t advance = (uint32_t)diff;
    if (advance >= W) {
        // Large jump: clear entire active window
        memset(ar->window, 0, W / 8);
    } else {
        // Clear the slots that are being overtaken one by one
        for (uint32_t i = 1; i <= advance; i++) {
            uint32_t clearSeq = ar->top + i;
            uint32_t bit = clearSeq & mask;
            ar->window[bit >> 3] &= (uint8_t)~(1u << (bit & 7u));
        }
    }
    ar->top = seq;
    uint32_t bit = seq & mask;
    ar->window[bit >> 3] |= (uint8_t)(1u << (bit & 7u));
    return 1;
}  // End of anti_replay_check

/* -----------------------------------------------------------------------
 * UdpEncrypt
 * ----------------------------------------------------------------------- */
ssize_t UdpEncrypt(void *wireBuf, size_t wireBufMax, const void *inner, size_t innerLen, const uint8_t *sessionKey) {
#ifndef HAVE_LIBSODIUM
    (void)wireBuf;
    (void)wireBufMax;
    (void)inner;
    (void)innerLen;
    (void)sessionKey;
    LogError("UdpEncrypt: libsodium not available");
    return -1;
#else
    if (!sessionKey || !wireBuf || !inner || innerLen == 0) {
        LogError("UdpEncrypt: invalid arguments");
        return -1;
    }

    // Scratch buffer for LZ4 output.  Static: sendflow_thread is single-threaded.
    static uint8_t compScratch[65536 + 64];

    const uint8_t *plaintext = (const uint8_t *)inner;
    size_t plainLen = innerLen;
    uint8_t compAlgo = NFD_COMP_NONE;
    uint32_t origLen = 0;

    if (innerLen > NFD_COMP_THRESHOLD) {
        int compBound = LZ4_compressBound((int)innerLen);
        if (compBound > 0 && (size_t)compBound <= sizeof(compScratch)) {
            int compLen = LZ4_compress_default((const char *)inner, (char *)compScratch, (int)innerLen, compBound);
            // Use compression only when at least 10% smaller
            if (compLen > 0 && (size_t)compLen < innerLen * 9 / 10) {
                plaintext = compScratch;
                plainLen = (size_t)compLen;
                compAlgo = NFD_COMP_LZ4;
                origLen = (uint32_t)innerLen;
            }
        }
    }

    // Verify output buffer is large enough
    size_t wireNeeded = NFD_ENC_HDR_SIZE + plainLen + NFD_AEAD_TAG_SIZE;
    if (wireNeeded > wireBufMax) {
        LogError("UdpEncrypt: wireBuf too small (%zu needed, %zu available)", wireNeeded, wireBufMax);
        return -1;
    }

    // Determine the key to use and the epoch to write
    const uint8_t *useKey;
    uint32_t epoch = 0;

    if (g_udpCrypto.rekeyIntervalSecs > 0) {
        epoch = (uint32_t)((uint64_t)time(NULL) / g_udpCrypto.rekeyIntervalSecs);
        if (epoch != g_udpCrypto.encryptEpoch) {
            crypto_kdf_derive_from_key(g_udpCrypto.encryptKey, sizeof(g_udpCrypto.encryptKey), (uint64_t)epoch, "nfd-rkey", sessionKey);
            g_udpCrypto.encryptEpoch = epoch;
            LogInfo("UdpEncrypt: epoch key rotation — now epoch %u", epoch);
        }
        useKey = g_udpCrypto.encryptKey;
    } else {
        useKey = sessionKey;
    }

    // Fill the wire header
    nfd_enc_header_t *hdr = (nfd_enc_header_t *)wireBuf;
    hdr->version = htons(251u);  // VERSION_NFD_ENCRYPTED
    hdr->crypto = (uint8_t)NFD_CRYPTO_XCHACHA20_POLY1305;
    hdr->comp = (uint8_t)compAlgo;
    hdr->origLen = htonl(origLen);
    hdr->epoch = htonl(epoch);
    randombytes_buf(hdr->nonce, sizeof(hdr->nonce));

    // AAD: first NFD_AAD_SIZE bytes (version + crypto + comp + origLen + epoch).
    // These are authenticated but not encrypted — any tampering is detected.
    const uint8_t *aad = (const uint8_t *)wireBuf;

    unsigned long long cipherLen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt((uint8_t *)wireBuf + NFD_ENC_HDR_SIZE, &cipherLen, plaintext, plainLen, aad, NFD_AAD_SIZE, NULL,
                                                   hdr->nonce, useKey) != 0) {
        LogError("UdpEncrypt: crypto_aead_xchacha20poly1305_ietf_encrypt failed");
        return -1;
    }

    return (ssize_t)(NFD_ENC_HDR_SIZE + (size_t)cipherLen);
#endif
}  // End of UdpEncrypt

/* -----------------------------------------------------------------------
 * UdpDecrypt
 * ----------------------------------------------------------------------- */
ssize_t UdpDecrypt(void *outBuf, size_t outBufSize, const void *wireBuf, size_t wireBufLen, const uint8_t *sessionKey) {
#ifndef HAVE_LIBSODIUM
    (void)outBuf;
    (void)outBufSize;
    (void)wireBuf;
    (void)wireBufLen;
    (void)sessionKey;
    LogError("UdpDecrypt: libsodium not available");
    return -1;
#else
    if (!sessionKey || !wireBuf || !outBuf) {
        LogError("UdpDecrypt: invalid arguments");
        return -1;
    }

    // Minimum: header + 0 bytes plaintext + 16-byte MAC
    if (wireBufLen < NFD_ENC_HDR_SIZE + NFD_AEAD_TAG_SIZE) {
        LogError("UdpDecrypt: packet too short (%zu bytes)", wireBufLen);
        return -1;
    }

    const nfd_enc_header_t *hdr = (const nfd_enc_header_t *)wireBuf;

    // Validate algorithm selector bytes
    if (hdr->crypto != NFD_CRYPTO_XCHACHA20_POLY1305) {
        LogError("UdpDecrypt: unsupported crypto algorithm %u", (unsigned)hdr->crypto);
        return -1;
    }
    if (hdr->comp != NFD_COMP_NONE && hdr->comp != NFD_COMP_LZ4) {
        LogError("UdpDecrypt: unsupported comp algorithm %u", (unsigned)hdr->comp);
        return -1;
    }

    // Determine the key to use for this packet
    const uint8_t *useKey;
    uint32_t senderEpoch = ntohl(hdr->epoch);

    if (g_udpCrypto.rekeyIntervalSecs > 0) {
        /*
         * Receiver uses the sender's epoch number (from the wire header) to
         * derive the matching subkey.  No clock guessing needed.
         *
         * Skew check: reject epochs too far from the receiver's own current
         * epoch to prevent a distant epoch from forcing a spurious KDF call.
         * With the default interval of 3600 s and MAX_SKEW of 2, this
         * tolerates up to 2 hours of clock drift on either side.
         */
        uint32_t recvEpoch = (uint32_t)((uint64_t)time(NULL) / g_udpCrypto.rekeyIntervalSecs);
        int32_t skew = (int32_t)(senderEpoch - recvEpoch);
        if (skew < -(int32_t)NFD_MAX_EPOCH_SKEW || skew > (int32_t)NFD_MAX_EPOCH_SKEW) {
            LogError("UdpDecrypt: epoch skew too large — sender=%u receiver=%u diff=%d — drop", senderEpoch, recvEpoch, skew);
            return -1;
        }
        if (senderEpoch != g_udpCrypto.decryptEpoch) {
            crypto_kdf_derive_from_key(g_udpCrypto.decryptKey, sizeof(g_udpCrypto.decryptKey), (uint64_t)senderEpoch, "nfd-rkey", sessionKey);
            g_udpCrypto.decryptEpoch = senderEpoch;
        }
        useKey = g_udpCrypto.decryptKey;
    } else {
        if (senderEpoch != 0) {
            /* Receiver has rekeying disabled but the sender encoded a
             * non-zero epoch — likely a configuration mismatch.  Log once
             * (the auth failure that follows will also log an error). */
            LogError("UdpDecrypt: rekeying disabled here but sender epoch=%u — check -N config", senderEpoch);
        }
        useKey = sessionKey;
    }

    // AAD matches what the sender put in the first NFD_AAD_SIZE bytes
    const uint8_t *aad = (const uint8_t *)wireBuf;
    const uint8_t *ciphertext = (const uint8_t *)wireBuf + NFD_ENC_HDR_SIZE;
    size_t cipherLen = wireBufLen - NFD_ENC_HDR_SIZE;

    // When decompression follows, decrypt into a scratch buffer first;
    // otherwise decrypt directly into outBuf.
    static uint8_t decScratch[65536 + 64];
    uint8_t *decTarget;
    size_t decMax;

    if (hdr->comp == NFD_COMP_NONE) {
        decTarget = (uint8_t *)outBuf;
        decMax = outBufSize;
    } else {
        decTarget = decScratch;
        decMax = sizeof(decScratch);
    }

    if (decMax < cipherLen) {
        // cipherLen includes the 16-byte tag so plainLen < cipherLen
        LogError("UdpDecrypt: decrypt target buffer too small");
        return -1;
    }

    unsigned long long plainLen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(decTarget, &plainLen, NULL, ciphertext, cipherLen, aad, NFD_AAD_SIZE, hdr->nonce, useKey) != 0) {
        /* Authentication failure — log a brief message, avoid any oracle
         * info (do not print nonce, ciphertext, or expected MAC). */
        LogError("UdpDecrypt: authentication failed — packet dropped");
        return -1;
    }

    // Decompress if needed
    if (hdr->comp == NFD_COMP_LZ4) {
#ifndef HAVE_LZ4
        LogError("UdpDecrypt: received LZ4-compressed packet but LZ4 not compiled in");
        return -1;
#else
        uint32_t orig = ntohl(hdr->origLen);
        if (orig == 0 || orig > 65535) {
            LogError("UdpDecrypt: invalid origLen %u in LZ4 packet", orig);
            return -1;
        }
        if (outBufSize < orig) {
            LogError("UdpDecrypt: outBuf too small for decompressed data (%zu < %u)", outBufSize, orig);
            return -1;
        }
        int decompLen = LZ4_decompress_safe((const char *)decTarget, (char *)outBuf, (int)plainLen, (int)orig);
        if (decompLen != (int)orig) {
            LogError("UdpDecrypt: LZ4_decompress_safe failed (expected %u, got %d)", orig, decompLen);
            return -1;
        }
        return (ssize_t)orig;
#endif
    }

    return (ssize_t)plainLen;
#endif
}  // End of UdpDecrypt
