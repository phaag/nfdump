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
 * nfd_udp_crypto.h — wire format and crypto helpers for encrypted nfpcapd→nfcapd
 * UDP transport (version 251).
 *
 * Design summary (see doc/crypto-design-proposals.md for full rationale):
 *
 *   Algorithm: XChaCha20-Poly1305 IETF  (crypto_aead_xchacha20poly1305_ietf)
 *     • 256-bit key, 192-bit random nonce per packet, 128-bit Poly1305 MAC.
 *     • 192-bit nonce safely allows randombytes_buf() per packet with no
 *       counter state — birthday bound at 2^96, never reached in practice.
 *
 *   Key derivation: Argon2id at OPSLIMIT_INTERACTIVE / 16 MB, once at startup.
 *     • Fixed 16-byte domain-separation salt distinguishes the UDP transport
 *       key from the per-file backend key even when the same -K passphrase
 *       is used for both purposes.
 *     • Runs in ~1-5 ms; completely off the per-packet hot path.
 *
 *   Wire packet layout (total overhead: 32 B header + 16 B MAC = 48 bytes):
 *
 *     Offset  Size  Field
 *       0      2    version  = htons(VERSION_NFD_ENCRYPTED = 251)
 *       2      1    crypto   = nfd_crypto_algo_t  (algorithm selector)
 *       3      1    comp     = nfd_comp_algo_t    (compressor selector)
 *       4      4    origLen  = htonl(uncompressed inner len); 0 if comp==NONE
 *       8     24    nonce[24] = per-packet random XChaCha20 nonce
 *      32    var    ciphertext = AEAD-encrypt(inner) + 16-byte Poly1305 tag
 *
 *   AAD: wire[0..7] (version + crypto + comp + origLen) — authenticated,
 *   not encrypted.  Binds algorithm IDs to the ciphertext.
 *
 *   Replay protection: 256-bit sliding window on the inner nfd_header_t
 *   lastSequence field, checked after MAC verification succeeds.
 *
 *   Compression: LZ4 (HAVE_LZ4), attempted only when inner payload > 512 bytes,
 *   used only when compressed form is at least 10% smaller.
 *   Order: compress-then-encrypt (only safe order for AEAD).
 *
 * crypto/comp algorithm bytes use distinct uint8_t fields (not bit-flags):
 *   • Value 0 always means "none" for that dimension.
 *   • Each non-zero value selects a specific algorithm — no bit manipulation
 *     needed in the encoder or decoder; both switch() on the byte directly.
 *   • Adding a second cipher or compressor in the future requires only a new
 *     enum constant — no wire format change.
 *
 * All code is compiled only when HAVE_LIBSODIUM is defined.  Without libsodium,
 * DeriveUdpSessionKey() returns NULL and UdpEncrypt()/UdpDecrypt() return -1.
 */

#ifndef _NFD_UDP_CRYPTO_H
#define _NFD_UDP_CRYPTO_H 1

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* -----------------------------------------------------------------------
 * Algorithm identifier bytes stored in the wire header.
 * Using dedicated uint8_t fields (not bit-flags) means:
 *   - 0 is always "none / not applicable" for that dimension.
 *   - Decoder switches on the value to select an implementation.
 *   - Future algorithms only require a new enum constant.
 * ----------------------------------------------------------------------- */

/* Byte 2 of the wire header: encryption algorithm */
typedef enum {
    NFD_CRYPTO_NONE = 0,               // plaintext — invalid inside a v251 header
    NFD_CRYPTO_XCHACHA20_POLY1305 = 1, // crypto_aead_xchacha20poly1305_ietf (libsodium)
    // NFD_CRYPTO_AES256_GCM = 2,      reserved for future use
} nfd_crypto_algo_t;

/* Byte 3 of the wire header: compression algorithm */
typedef enum {
    NFD_COMP_NONE = 0, // uncompressed
    NFD_COMP_LZ4 = 1,  // LZ4 default compression (liblz4 or bundled lz4.h)
    // NFD_COMP_ZSTD = 2, reserved for future use
} nfd_comp_algo_t;

/* -----------------------------------------------------------------------
 * Wire header for version-251 encrypted nfpcapd UDP packets.
 * sizeof(nfd_enc_header_t) must equal NFD_ENC_HDR_SIZE (32).
 * ----------------------------------------------------------------------- */
#define NFD_ENC_HDR_SIZE 36u    // sizeof nfd_enc_header_t
#define NFD_AEAD_TAG_SIZE 16u   // Poly1305 MAC tag appended by AEAD
#define NFD_AAD_SIZE 12u        // authenticated prefix: version..epoch (bytes 0–11)
#define NFD_COMP_THRESHOLD 512u // only attempt LZ4 when inner payload > this

/*
 * Epoch skew tolerance on the receiver.  The receiver accepts sender epoch
 * numbers within ±NFD_MAX_EPOCH_SKEW of its own current epoch.  With the
 * default 60-minute rekey interval this allows ±2 hours of clock drift —
 * sufficient for any reasonably deployed host, including embedded senders
 * that lack reliable NTP.  The sender writes its epoch in the wire header;
 * the receiver never needs to guess it.
 */
#define NFD_MAX_EPOCH_SKEW 2u

typedef struct nfd_enc_header_s {
    uint16_t version;  // htons(VERSION_NFD_ENCRYPTED = 251)
    uint8_t crypto;    // nfd_crypto_algo_t — algorithm selector
    uint8_t comp;      // nfd_comp_algo_t   — compressor selector
    uint32_t origLen;  // htonl(uncompressed inner len); 0 when comp==NONE
    uint32_t epoch;    // htonl(rekey epoch counter); 0 when rekeying off
    uint8_t nonce[24]; // random XChaCha20-Poly1305 nonce
} __attribute__((packed)) nfd_enc_header_t;

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
_Static_assert(sizeof(nfd_enc_header_t) == NFD_ENC_HDR_SIZE, "nfd_enc_header_t must be 36 bytes");
#endif

/* -----------------------------------------------------------------------
 * Anti-replay sliding window.
 *
 * The active window width is runtime-configurable (windowBits field inside
 * anti_replay_t) so operators can tune for high-rate / high-reorder links.
 * Supported range: 64–1024 bits (must be a power of 2).
 * Default is ANTI_REPLAY_WINDOW_DEFAULT (256 bits).
 *
 * The bitmap always occupies ANTI_REPLAY_WINDOW_MAX/8 bytes inside the
 * struct regardless of the chosen width; only the first windowBits/8 bytes
 * are ever read or written.
 * ----------------------------------------------------------------------- */
#define ANTI_REPLAY_WINDOW_DEFAULT 256u // sensible default; covers typical UDP reordering
#define ANTI_REPLAY_WINDOW_MAX 1024u    // maximum supported; 128-byte bitmask

#define REKEY_INTERVALSECS_DEFAULT 3600u  // default rekey interval
typedef struct anti_replay_s {
    uint32_t top;                               // highest accepted sequence so far
    uint32_t windowBits;                        // active window width (power of 2, ≤ MAX)
    int initialized;                            // 0 until first valid packet
    uint8_t window[ANTI_REPLAY_WINDOW_MAX / 8]; // bitmask, 128 bytes
} anti_replay_t;

/*
 * anti_replay_check — validate seq against the sliding window.
 *
 * Returns 1 and updates state if seq is acceptable (new packet).
 * Returns 0 if seq is a replay or too far behind top (caller must DROP).
 * Thread-safety: not re-entrant; call from a single thread.
 */
int anti_replay_check(anti_replay_t *ar, uint32_t seq);

/* -----------------------------------------------------------------------
 * Session key lifecycle.
 *
 * DeriveUdpSessionKey() runs once at startup and takes ~1-5 ms (Argon2id
 * INTERACTIVE).  The returned pointer is sodium_malloc()'d and mlock()'d.
 * ----------------------------------------------------------------------- */

/* Forward declaration only — full definition in nffileV3/nfcrypto.h */
struct crypto_ctx_s;

/*
 * DeriveUdpSessionKey — derive a 32-byte session key from a crypto_ctx_t.
 * Returns a sodium_malloc()'d key, or NULL on error.
 * Caller must free with FreeUdpSessionKey().
 */
uint8_t *DeriveUdpSessionKey(const struct crypto_ctx_s *ctx);

// FreeUdpSessionKey — sodium_memzero + sodium_free.  Safe to call with NULL.
void FreeUdpSessionKey(uint8_t *key);

/*
 * SetUdpSalt — override the 16-byte Argon2id domain-separation salt.
 *
 * saltStr must be a non-empty printable ASCII string (characters 0x20–0x7e).
 * The first min(strlen(saltStr), 16) bytes are copied into the salt; any
 * remaining bytes are zeroed to pad to 16 bytes.
 * Strings longer than 16 characters are silently truncated.
 *
 * Must be called before DeriveUdpSessionKey().
 * Both sender (nfpcapd) and receiver (nfcapd) must use the same salt.
 * Configured via crypt.salt in nfdump.conf [common].
 */
void SetUdpSalt(const char *saltStr);

/*
 * SetUdpRekeyInterval — configure epoch-based key rotation.
 *
 * intervalSecs == 0  : rekeying disabled (default); the Argon2id-derived
 *                      key is used directly for the daemon's lifetime.
 * intervalSecs  > 0  : both UdpEncrypt and UdpDecrypt derive a per-epoch
 *                      subkey via crypto_kdf_derive_from_key (BLAKE2b).
 *                      The sender writes the epoch number into the wire
 *                      header; the receiver reads it back and accepts
 *                      epochs within ±NFD_MAX_EPOCH_SKEW of its own clock,
 *                      so clock differences up to
 *                      (NFD_MAX_EPOCH_SKEW × intervalSecs) are tolerated.
 *
 * Must be called before the first UdpEncrypt / UdpDecrypt call.
 * Safe to call on both the sender (nfpcapd) and receiver (nfcapd) side.
 */
void SetUdpRekeyInterval(uint32_t intervalSecs);

/* -----------------------------------------------------------------------
 * Packet-level encrypt / decrypt.
 * ----------------------------------------------------------------------- */

/*
 * UdpEncrypt — encrypt 'innerLen' bytes from 'inner' into 'wireBuf'.
 *
 * 'inner' is a complete v250 UDP payload (nfd_header_t + flow records).
 * 'wireBuf' must have at least NFD_ENC_HDR_SIZE + innerLen + NFD_AEAD_TAG_SIZE
 * bytes of space (extra room for LZ4 expansion is handled internally).
 *
 * Optionally LZ4-compresses the inner payload before encryption when
 * HAVE_LZ4 is defined, innerLen > NFD_COMP_THRESHOLD, and at least 10%
 * compression is achieved.
 *
 * Returns total wire byte count on success, -1 on error.
 */
ssize_t UdpEncrypt(void *wireBuf, size_t wireBufMax, const void *inner, size_t innerLen, const uint8_t *sessionKey);

/*
 * UdpDecrypt — decrypt and authenticate a version-251 wire packet.
 *
 * Writes the recovered inner v250 payload (nfd_header_t + records) into
 * 'outBuf'.  'outBuf' must be at least 65536 bytes.
 *
 * The caller is responsible for anti-replay checking the inner
 * nfd_header_t.lastSequence after a successful return.
 *
 * Returns inner payload byte count on success, -1 on auth or format error.
 */
ssize_t UdpDecrypt(void *outBuf, size_t outBufSize, const void *wireBuf, size_t wireBufLen, const uint8_t *sessionKey);

#endif /* _NFD_UDP_CRYPTO_H */
