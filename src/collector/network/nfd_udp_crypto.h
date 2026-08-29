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
 * nfd_udp_crypto.h — universal wire header, and optional compression/
 * encryption, for nfpcapd/nfcapd/sfcapd/nfreplay UDP forwarding (-H).
 *
 * Every -H/nfreplay UDP packet — encrypted or not, compressed or not — uses
 * the same 36-byte nfd_wire_header_t envelope, wire version VERSION_NFD_WIRE
 * (251). crypto and comp are independent fields, giving four combinations:
 *
 *   crypto=NONE,    comp=NONE        plain nfd_header_t + records, verbatim
 *   crypto=NONE,    comp=LZ4|ZSTD    plain, compressed
 *   crypto=XCHACHA, comp=NONE        AEAD-encrypted, uncompressed inner
 *   crypto=XCHACHA, comp=LZ4|ZSTD    compress-then-encrypt (only safe order)
 *
 * There is no separate unwrapped legacy format on the wire any more — a
 * pre-this-design sender or receiver will not interoperate (an old raw
 * payload's leading bytes won't match VERSION_NFD_WIRE and are cleanly
 * rejected, never misparsed).
 *
 *   Wire packet layout, crypto=NONE (total overhead: 36 bytes, no tag):
 *
 *     Offset  Size  Field
 *       0      2    version  = htons(VERSION_NFD_WIRE = 251)
 *       2      1    crypto   = NFD_CRYPTO_NONE
 *       3      1    comp     = nfd_comp_algo_t (NONE, LZ4, or ZSTD)
 *       4      4    origLen  = htonl(uncompressed inner len); 0 if comp==NONE
 *       8      4    epoch    = 0, unused
 *      12     24    nonce[24] = zeroed, unused
 *      36    var    payload  = inner, optionally compressed — no AEAD tag
 *
 *   Wire packet layout, crypto=XCHACHA20_POLY1305 (unchanged from the
 *   original v251 design; total overhead: 36 B header + 16 B MAC = 52 bytes):
 *
 *     Offset  Size  Field
 *       0      2    version  = htons(VERSION_NFD_WIRE = 251)
 *       2      1    crypto   = NFD_CRYPTO_XCHACHA20_POLY1305
 *       3      1    comp     = nfd_comp_algo_t
 *       4      4    origLen  = htonl(uncompressed inner len); 0 if comp==NONE
 *       8      4    epoch    = htonl(rekey epoch counter); 0 when rekeying off
 *      12     24    nonce[24] = per-packet random XChaCha20 nonce
 *      36    var    ciphertext = AEAD-encrypt(inner) + 16-byte Poly1305 tag
 *
 *   AAD (crypto=XCHACHA only): wire[0..11] (version + crypto + comp + origLen
 *   + epoch) — authenticated, not encrypted. Binds algorithm IDs to the
 *   ciphertext. Not applicable when crypto=NONE: there is no MAC, so header
 *   tampering is not detected at this layer (unauthenticated transport has no
 *   integrity guarantee regardless — this is unchanged from the old plain
 *   v250 format's properties, just carried in a structured header now).
 *
 *   Replay protection: 256-bit sliding window on the inner nfd_header_t
 *   lastSequence field, checked only when crypto=XCHACHA and MAC verification
 *   succeeded — replay protection without authentication is not meaningful
 *   (an unauthenticated sequence number is exactly as forgeable as the
 *   payload it would be "protecting"), so crypto=NONE packets never go
 *   through anti-replay, matching the old plain v250 path's properties.
 *
 *   Compression: tried opportunistically whenever the inner payload exceeds
 *   NFD_COMP_THRESHOLD (512) bytes, independent of crypto — zstd is
 *   preferred when this build has libzstd (better ratio at these payload
 *   sizes), falling back to LZ4 (always available: system library or
 *   bundled fallback) when zstd isn't compiled in or doesn't clear the
 *   savings bar. Compression is kept only when the result is at least 10%
 *   smaller than the input; otherwise the payload is sent uncompressed
 *   (comp=NONE). Order is always compress-then-encrypt (the only safe order
 *   for AEAD).
 *
 * crypto/comp algorithm bytes use distinct uint8_t fields (not bit-flags):
 *   • Value 0 always means "none" for that dimension.
 *   • Each non-zero value selects a specific algorithm — no bit manipulation
 *     needed in the encoder or decoder; both switch() on the byte directly.
 *   • Adding a second cipher or compressor in the future requires only a new
 *     enum constant — no wire format change.
 *
 * crypto=NONE packets need no libsodium and work in any build. crypto=XCHACHA
 * requires HAVE_LIBSODIUM (NfdWireEncode()/NfdWireDecode() return -1 for that
 * branch otherwise). comp=ZSTD requires HAVE_ZSTD; a decoder built without it
 * rejects a zstd-compressed packet cleanly rather than misdecoding it.
 *
 * -k on the receiving side means "authentication required": once a session
 * key is configured, a crypto=NONE packet is rejected (logged, dropped) —
 * see Process_nfd() in nfd_raw.c. A receiver without a session key accepts
 * crypto=NONE packets but rejects crypto=XCHACHA packets because it has no
 * key with which to authenticate and decrypt them.
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
    NFD_CRYPTO_NONE = 0,               // no encryption — plain, possibly compressed
    NFD_CRYPTO_XCHACHA20_POLY1305 = 1, // crypto_aead_xchacha20poly1305_ietf (libsodium)
    // NFD_CRYPTO_AES256_GCM = 2,      reserved for future use
} nfd_crypto_algo_t;

/* Byte 3 of the wire header: compression algorithm */
typedef enum {
    NFD_COMP_NONE = 0, // uncompressed
    NFD_COMP_LZ4 = 1,  // LZ4 default compression (liblz4 or bundled lz4.h)
    NFD_COMP_ZSTD = 2, // zstd default compression (requires HAVE_ZSTD)
} nfd_comp_algo_t;

/* -----------------------------------------------------------------------
 * Universal wire header for every -H/nfreplay UDP packet (version 251).
 * Fixed size regardless of crypto/comp mode — unused fields (nonce, epoch
 * under crypto=NONE) are simply zeroed, keeping parsing branch-free on the
 * header itself; 36 bytes is negligible next to real payload sizes.
 * sizeof(nfd_wire_header_t) must equal NFD_WIRE_HDR_SIZE (36).
 * ----------------------------------------------------------------------- */
#define NFD_WIRE_VERSION 251u   // outer nfd UDP transport version
#define NFD_WIRE_HDR_SIZE 36u   // sizeof nfd_wire_header_t
#define NFD_AEAD_TAG_SIZE 16u   // Poly1305 MAC tag appended by AEAD (crypto=XCHACHA only)
#define NFD_AAD_SIZE 12u        // authenticated prefix: version..epoch (bytes 0-11), crypto=XCHACHA only
#define NFD_COMP_THRESHOLD 512u // only attempt compression when inner payload > this

/*
 * Target wire packet size for every nfd sender (remote_backend.c's -H
 * backend, and nfreplay.c) — see udp.sendThreshold in nfdump.conf(5).
 * Shared here so every sender uses the same default and valid range;
 * out-of-range configured values are rejected (logged) rather than
 * clamped, falling back to the default. Each sender independently buffers
 * raw records up to 2x this value before compressing and flushing — see
 * the sender's own file for that accumulation logic.
 */
#define NFD_SEND_THRESHOLD_DEFAULT 1200u
#define NFD_SEND_THRESHOLD_MIN 512u
#define NFD_SEND_THRESHOLD_MAX 60000u

/*
 * Epoch skew tolerance on the receiver.  The receiver accepts sender epoch
 * numbers within ±NFD_MAX_EPOCH_SKEW of its own current epoch.  With the
 * default 60-minute rekey interval this allows ±2 hours of clock drift —
 * sufficient for any reasonably deployed host, including embedded senders
 * that lack reliable NTP.  The sender writes its epoch in the wire header;
 * the receiver never needs to guess it.  Not used when crypto=NONE.
 */
#define NFD_MAX_EPOCH_SKEW 2u

typedef struct nfd_wire_header_s {
    uint16_t version;  // htons(VERSION_NFD_WIRE = 251)
    uint8_t crypto;    // nfd_crypto_algo_t — algorithm selector
    uint8_t comp;      // nfd_comp_algo_t   — compressor selector
    uint32_t origLen;  // htonl(uncompressed inner len); 0 when comp==NONE
    uint32_t epoch;    // htonl(rekey epoch counter); 0 when rekeying off or crypto==NONE
    uint8_t nonce[24]; // random XChaCha20-Poly1305 nonce; zeroed when crypto==NONE
} __attribute__((packed)) nfd_wire_header_t;

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
_Static_assert(sizeof(nfd_wire_header_t) == NFD_WIRE_HDR_SIZE, "nfd_wire_header_t must be 36 bytes");
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
 * intervalSecs  > 0  : both NfdWireEncode and NfdWireDecode derive a
 *                      per-epoch subkey via crypto_kdf_derive_from_key
 *                      (BLAKE2b), for crypto=XCHACHA packets only.
 *                      The sender writes the epoch number into the wire
 *                      header; the receiver reads it back and accepts
 *                      epochs within ±NFD_MAX_EPOCH_SKEW of its own clock,
 *                      so clock differences up to
 *                      (NFD_MAX_EPOCH_SKEW × intervalSecs) are tolerated.
 *
 * Must be called before the first NfdWireEncode / NfdWireDecode call.
 * Safe to call on both the sender (nfpcapd) and receiver (nfcapd) side.
 */
void SetUdpRekeyInterval(uint32_t intervalSecs);

/* -----------------------------------------------------------------------
 * Packet-level encode / decode. Universal: handles all four crypto x comp
 * combinations described above.
 * ----------------------------------------------------------------------- */

/*
 * NfdWireEncode — wrap 'innerLen' bytes from 'inner' into a universal wire
 * packet in 'wireBuf'.
 *
 * 'inner' is a complete nfd_header_t + flow-records payload.
 * 'wireBuf' must have at least NFD_WIRE_HDR_SIZE + innerLen bytes of space
 * plus NFD_AEAD_TAG_SIZE when sessionKey is non-NULL (extra room for
 * compression expansion in the rare case it doesn't help is handled
 * internally — the wire packet only ever contains the smaller of the two).
 *
 * sessionKey == NULL: crypto=NONE. Works in any build, no libsodium needed.
 * sessionKey != NULL: crypto=XCHACHA20_POLY1305. Requires HAVE_LIBSODIUM.
 *
 * Either way, compression is attempted whenever innerLen > NFD_COMP_THRESHOLD:
 * zstd first (if this build has HAVE_ZSTD), else LZ4, kept only if the result
 * is at least 10% smaller than innerLen.
 *
 * Returns total wire byte count on success, -1 on error.
 */
ssize_t NfdWireEncode(void *wireBuf, size_t wireBufMax, const void *inner, size_t innerLen, const uint8_t *sessionKey);

/*
 * NfdWireDecode — unwrap and, if applicable, authenticate/decrypt/decompress
 * a universal wire packet.
 *
 * Writes the recovered inner payload (nfd_header_t + records) into 'outBuf'.
 * 'outBuf' must be at least 65536 bytes.
 *
 * sessionKey may be NULL: a crypto=NONE packet decodes regardless (no key
 * needed); a crypto=XCHACHA packet with sessionKey==NULL is rejected (this
 * receiver isn't configured to decrypt). Enforcing "sessionKey configured
 * means crypto=NONE is rejected" (authentication required) is the caller's
 * responsibility — see Process_nfd() in nfd_raw.c — not this function's,
 * since that policy depends on whether -k was given, which this function
 * has no notion of.
 *
 * The caller is responsible for anti-replay checking the inner
 * nfd_header_t.lastSequence after a successful return, and only when the
 * packet's crypto field was NFD_CRYPTO_XCHACHA20_POLY1305 — this function
 * does not report which branch was taken, but the caller can peek
 * wireBuf's crypto byte (offset 2) itself before calling.
 *
 * Returns inner payload byte count on success, -1 on auth, format, or
 * unsupported-algorithm error.
 */
ssize_t NfdWireDecode(void *outBuf, size_t outBufSize, const void *wireBuf, size_t wireBufLen, const uint8_t *sessionKey);

#endif /* _NFD_UDP_CRYPTO_H */
