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
 * nfd_udp_crypto.c — universal wire encode/decode for nfpcapd/nfcapd/
 * sfcapd/nfreplay UDP forwarding (-H), covering both optional compression
 * and optional encryption.
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
 *   24-byte random nonce per packet (randombytes_buf), crypto=XCHACHA only.
 *   XChaCha20 uses a 192-bit nonce, so no counter management is needed;
 *   birthday collision probability is negligible at any realistic packet
 *   rate.
 *
 * Compression:
 *   Attempted independent of encryption, whenever the inner payload exceeds
 *   NFD_COMP_THRESHOLD (512) bytes: zstd first when this build has
 *   HAVE_ZSTD (better ratio at typical -H payload sizes), else LZ4 (system
 *   library or bundled fallback, always available). Kept only when the
 *   compressed form is at least 10% smaller than the input; otherwise sent
 *   uncompressed. Order is always compress-then-encrypt (the only safe
 *   order for AEAD).
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

#ifdef HAVE_ZSTD
#include <zstd.h>
#define NFD_ZSTD_LEVEL 1  // fast level; matches nffile's default zstd:1
#endif

/* -----------------------------------------------------------------------
 * Module-private crypto state — one singleton per process.
 *
 * Bundled as a struct so all related fields are visible together and new
 * fields can be added in one place.  The public API (SetUdpSalt,
 * SetUdpRekeyInterval, DeriveUdpSessionKey, NfdWireEncode, NfdWireDecode)
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
    uint8_t salt[16];
    uint32_t rekeyIntervalSecs;
    uint32_t encryptEpoch;
    uint8_t encryptKey[32];
    uint32_t decryptEpoch;
    uint8_t decryptKey[32];
} udp_crypto_state_t;

static udp_crypto_state_t g_udpCrypto = {
    .salt = {'n', 'f', 'p', 'c', 'a', 'p', 'd', '-', 'u', 'd', 'p', 'k', 'e', 'y', '1', '\0'},
    .rekeyIntervalSecs = 0,
    .encryptEpoch = UINT32_MAX,
    .decryptEpoch = UINT32_MAX,
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
 * TryCompress — compression step for NfdWireEncode, independent of
 * crypto mode. Tries zstd first (if HAVE_ZSTD), falls back to LZ4. Leaves
 * the out-params at their no-compression defaults (NFD_COMP_NONE, innerLen)
 * when compression isn't attempted or doesn't clear the 10%-smaller bar.
 *
 * ----------------------------------------------------------------------- */
static void TryCompress(const void *inner, size_t innerLen, uint8_t *scratch, size_t scratchSize, const uint8_t **outPtr, size_t *outLen,
                        uint8_t *outAlgo, uint32_t *outOrigLen) {
    *outPtr = (const uint8_t *)inner;
    *outLen = innerLen;
    *outAlgo = NFD_COMP_NONE;
    *outOrigLen = (uint32_t)innerLen;

    if (innerLen <= NFD_COMP_THRESHOLD) return;

#ifdef HAVE_ZSTD
    {
        size_t zBound = ZSTD_compressBound(innerLen);
        if (zBound <= scratchSize) {
            size_t zLen = ZSTD_compress(scratch, zBound, inner, innerLen, NFD_ZSTD_LEVEL);
            if (!ZSTD_isError(zLen) && zLen < innerLen * 9 / 10) {
                *outPtr = scratch;
                *outLen = zLen;
                *outAlgo = NFD_COMP_ZSTD;
                return;
            }
        }
    }
#endif

    int compBound = LZ4_compressBound((int)innerLen);
    if (compBound > 0 && (size_t)compBound <= scratchSize) {
        int compLen = LZ4_compress_default((const char *)inner, (char *)scratch, (int)innerLen, compBound);
        if (compLen > 0 && (size_t)compLen < innerLen * 9 / 10) {
            *outPtr = scratch;
            *outLen = (size_t)compLen;
            *outAlgo = NFD_COMP_LZ4;
        }
    }
}  // End of TryCompress

/* -----------------------------------------------------------------------
 * NfdWireEncode
 * ----------------------------------------------------------------------- */
ssize_t NfdWireEncode(void *wireBuf, size_t wireBufMax, const void *inner, size_t innerLen, const uint8_t *sessionKey) {
    if (!wireBuf || !inner || innerLen == 0) {
        LogError("NfdWireEncode: invalid arguments");
        return -1;
    }

    // Scratch buffer for compressor output.  Static: only one
    // udpsend_backend_thread ever runs per process (-H is restricted to a
    // single FlowSource); nfreplay is likewise single-threaded on this path.
    static uint8_t compScratch[65536 + 64];

    const uint8_t *plaintext;
    size_t plainLen;
    uint8_t compAlgo;
    uint32_t origLen;
    TryCompress(inner, innerLen, compScratch, sizeof(compScratch), &plaintext, &plainLen, &compAlgo, &origLen);

    if (!sessionKey) {
        // crypto=NONE: no libsodium needed, no AEAD tag appended.
        size_t wireNeeded = NFD_WIRE_HDR_SIZE + plainLen;
        if (wireNeeded > wireBufMax) {
            LogError("NfdWireEncode: wireBuf too small (%zu needed, %zu available)", wireNeeded, wireBufMax);
            return -1;
        }
        nfd_wire_header_t *hdr = (nfd_wire_header_t *)wireBuf;
        hdr->version = htons(NFD_WIRE_VERSION);
        hdr->crypto = (uint8_t)NFD_CRYPTO_NONE;
        hdr->comp = compAlgo;
        hdr->origLen = htonl(origLen);
        hdr->epoch = 0;
        memset(hdr->nonce, 0, sizeof(hdr->nonce));
        memcpy((uint8_t *)wireBuf + NFD_WIRE_HDR_SIZE, plaintext, plainLen);
        return (ssize_t)wireNeeded;
    }

#ifndef HAVE_LIBSODIUM
    (void)wireBufMax;
    LogError("NfdWireEncode: libsodium not available — cannot encrypt");
    return -1;
#else
    // Verify output buffer is large enough
    size_t wireNeeded = NFD_WIRE_HDR_SIZE + plainLen + NFD_AEAD_TAG_SIZE;
    if (wireNeeded > wireBufMax) {
        LogError("NfdWireEncode: wireBuf too small (%zu needed, %zu available)", wireNeeded, wireBufMax);
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
            LogInfo("NfdWireEncode: epoch key rotation — now epoch %u", epoch);
        }
        useKey = g_udpCrypto.encryptKey;
    } else {
        useKey = sessionKey;
    }

    // Fill the wire header
    nfd_wire_header_t *hdr = (nfd_wire_header_t *)wireBuf;
    hdr->version = htons(NFD_WIRE_VERSION);
    hdr->crypto = (uint8_t)NFD_CRYPTO_XCHACHA20_POLY1305;
    hdr->comp = compAlgo;
    hdr->origLen = htonl(origLen);
    hdr->epoch = htonl(epoch);
    randombytes_buf(hdr->nonce, sizeof(hdr->nonce));

    // AAD: first NFD_AAD_SIZE bytes (version + crypto + comp + origLen + epoch).
    // These are authenticated but not encrypted — any tampering is detected.
    const uint8_t *aad = (const uint8_t *)wireBuf;

    unsigned long long cipherLen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt((uint8_t *)wireBuf + NFD_WIRE_HDR_SIZE, &cipherLen, plaintext, plainLen, aad, NFD_AAD_SIZE, NULL,
                                                   hdr->nonce, useKey) != 0) {
        LogError("NfdWireEncode: crypto_aead_xchacha20poly1305_ietf_encrypt failed");
        return -1;
    }

    return (ssize_t)(NFD_WIRE_HDR_SIZE + (size_t)cipherLen);
#endif
}  // End of NfdWireEncode

/* -----------------------------------------------------------------------
 * Decompress — shared decompression step for NfdWireDecode, independent of
 * crypto mode. 'src'/'srcLen' is the (already-decrypted, if applicable)
 * payload; writes up to outBufSize bytes into outBuf.
 * Returns decompressed byte count on success, -1 on error.
 * ----------------------------------------------------------------------- */
static ssize_t Decompress(uint8_t comp, const uint8_t *src, size_t srcLen, uint32_t origLen, void *outBuf, size_t outBufSize) {
    if (comp == NFD_COMP_NONE) {
        // origLen is always populated
        if (origLen != (uint32_t)srcLen) {
            LogError("NfdWireDecode: origLen mismatch for uncompressed payload (declared %u, actual %zu)", origLen, srcLen);
            return -1;
        }
        if (outBufSize < srcLen) {
            LogError("NfdWireDecode: outBuf too small (%zu < %zu)", outBufSize, srcLen);
            return -1;
        }
        memmove(outBuf, src, srcLen);
        return (ssize_t)srcLen;
    }

    if (origLen == 0 || origLen > 65535 || outBufSize < origLen) {
        LogError("NfdWireDecode: invalid/oversized origLen %u", origLen);
        return -1;
    }

    if (comp == NFD_COMP_LZ4) {
        int decompLen = LZ4_decompress_safe((const char *)src, (char *)outBuf, (int)srcLen, (int)origLen);
        if (decompLen != (int)origLen) {
            LogError("NfdWireDecode: LZ4_decompress_safe failed (expected %u, got %d)", origLen, decompLen);
            return -1;
        }
        return (ssize_t)decompLen;
    }

#ifdef HAVE_ZSTD
    if (comp == NFD_COMP_ZSTD) {
        size_t decompLen = ZSTD_decompress(outBuf, outBufSize, src, srcLen);
        if (ZSTD_isError(decompLen) || decompLen != origLen) {
            LogError("NfdWireDecode: ZSTD_decompress failed (expected %u, got %zu%s%s)", origLen, decompLen, ZSTD_isError(decompLen) ? ": " : "",
                     ZSTD_isError(decompLen) ? ZSTD_getErrorName(decompLen) : "");
            return -1;
        }
        return (ssize_t)decompLen;
    }
#else
    if (comp == NFD_COMP_ZSTD) {
        LogError("NfdWireDecode: packet uses zstd compression but this build lacks libzstd");
        return -1;
    }
#endif

    LogError("NfdWireDecode: unsupported comp algorithm %u", (unsigned)comp);
    return -1;
}  // End of Decompress

/* -----------------------------------------------------------------------
 * NfdWireDecode
 * ----------------------------------------------------------------------- */
ssize_t NfdWireDecode(void *outBuf, size_t outBufSize, const void *wireBuf, size_t wireBufLen, const uint8_t *sessionKey) {
    if (!wireBuf || !outBuf) {
        LogError("NfdWireDecode: invalid arguments");
        return -1;
    }
    if (wireBufLen < NFD_WIRE_HDR_SIZE) {
        LogError("NfdWireDecode: packet too short for header (%zu bytes)", wireBufLen);
        return -1;
    }

    const nfd_wire_header_t *hdr = (const nfd_wire_header_t *)wireBuf;
    if (ntohs(hdr->version) != NFD_WIRE_VERSION) {
        LogError("NfdWireDecode: unsupported wire version %u", ntohs(hdr->version));
        return -1;
    }
    uint32_t origLen = ntohl(hdr->origLen);

    if (hdr->crypto == NFD_CRYPTO_NONE) {
        // No encryption, no key needed, no MAC to verify.
        const uint8_t *payload = (const uint8_t *)wireBuf + NFD_WIRE_HDR_SIZE;
        size_t payloadLen = wireBufLen - NFD_WIRE_HDR_SIZE;
        return Decompress(hdr->comp, payload, payloadLen, origLen, outBuf, outBufSize);
    }

    if (hdr->crypto != NFD_CRYPTO_XCHACHA20_POLY1305) {
        LogError("NfdWireDecode: unsupported crypto algorithm %u", (unsigned)hdr->crypto);
        return -1;
    }

#ifndef HAVE_LIBSODIUM
    (void)sessionKey;
    LogError("NfdWireDecode: libsodium not available — cannot decrypt");
    return -1;
#else
    if (!sessionKey) {
        LogError("NfdWireDecode: encrypted packet received but no session key configured");
        return -1;
    }

    // Minimum: header + 0 bytes plaintext + 16-byte MAC
    if (wireBufLen < NFD_WIRE_HDR_SIZE + NFD_AEAD_TAG_SIZE) {
        LogError("NfdWireDecode: encrypted packet too short (%zu bytes)", wireBufLen);
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
            LogError("NfdWireDecode: epoch skew too large — sender=%u receiver=%u diff=%d — drop", senderEpoch, recvEpoch, skew);
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
            LogError("NfdWireDecode: rekeying disabled here but sender epoch=%u — check -N config", senderEpoch);
        }
        useKey = sessionKey;
    }

    // AAD matches what the sender put in the first NFD_AAD_SIZE bytes
    const uint8_t *aad = (const uint8_t *)wireBuf;
    const uint8_t *ciphertext = (const uint8_t *)wireBuf + NFD_WIRE_HDR_SIZE;
    size_t cipherLen = wireBufLen - NFD_WIRE_HDR_SIZE;

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
        LogError("NfdWireDecode: decrypt target buffer too small");
        return -1;
    }

    unsigned long long plainLen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(decTarget, &plainLen, NULL, ciphertext, cipherLen, aad, NFD_AAD_SIZE, hdr->nonce, useKey) != 0) {
        /* Authentication failure — log a brief message, avoid any oracle
         * info (do not print nonce, ciphertext, or expected MAC). */
        LogError("NfdWireDecode: authentication failed — packet dropped");
        return -1;
    }

    return Decompress(hdr->comp, decTarget, (size_t)plainLen, origLen, outBuf, outBufSize);
#endif
}  // End of NfdWireDecode
