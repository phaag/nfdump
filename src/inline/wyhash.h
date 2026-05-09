// wyhash_nfdump.h
// Minimal wyhash v4-style implementation adapted for nfdump flow aggregation.
// Public domain / CC0-equivalent: use freely.
//
// Usage:
//   #include "wyhash_nfdump.h"
//   uint64_t h = wyhash(key_ptr, key_len, seed);
//
// Notes:
//   - 64-bit non-cryptographic hash
//   - Good speed and quality for flow keys (5-tuple, etc.)
//   - C17 compatible

#ifndef WYHASH_NFDUMP_H
#define WYHASH_NFDUMP_H

#include <stddef.h>
#include <stdint.h>

static inline uint64_t wyrot(uint64_t x) { return (x >> 32) | (x << 32); }

static inline uint64_t wymum(uint64_t a, uint64_t b) {
    __uint128_t r = (__uint128_t)a * (__uint128_t)b;
    return (uint64_t)r ^ (uint64_t)(r >> 64);
}

// Fixed secret; you may randomize this at startup if you want ASLR-like behavior.
static const uint64_t wyhash_secret[4] = {0xa0761d6478bd642full, 0xe7037ed1a0b428dbull, 0x8ebc6af09c88c6e3ull, 0x589965cc75374cc3ull};

static inline uint64_t wyhash_read32(const uint8_t *p) {
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24);
}

static inline uint64_t wyhash_read64(const uint8_t *p) {
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static inline uint64_t wyhash_mix(uint64_t a, uint64_t b) { return wymum(a ^ wyhash_secret[1], b ^ wyhash_secret[2]); }

// Main wyhash function: 64-bit non-cryptographic hash.
static inline uint64_t wyhash(const void *key, size_t len, uint64_t seed) {
    const uint8_t *p = (const uint8_t *)key;
    uint64_t a, b;

    seed ^= wyhash_secret[0];
    uint64_t see1 = seed;

    if (len <= 16) {
        if (len >= 4) {
            a = (wyhash_read32(p) << 32) | wyhash_read32(p + ((len >> 3) << 2));
            b = (wyhash_read32(p + len - 4) << 32) | wyhash_read32(p + len - 4 - ((len >> 3) << 2));
        } else if (len > 0) {
            a = ((uint64_t)p[0] << 16) | ((uint64_t)p[len >> 1] << 8) | (uint64_t)p[len - 1];
            b = len;
        } else {
            a = wyhash_secret[1];
            b = wyhash_secret[2];
        }
        return wyhash_mix(a ^ seed, b ^ see1);
    }

    // len > 16
    size_t i = len;
    if (i > 48) {
        uint64_t see2 = seed;
        do {
            seed = wyhash_mix(wyhash_read64(p) ^ wyhash_secret[1], wyhash_read64(p + 8) ^ seed);
            see1 = wyhash_mix(wyhash_read64(p + 16) ^ wyhash_secret[2], wyhash_read64(p + 24) ^ see1);
            see2 = wyhash_mix(wyhash_read64(p + 32) ^ wyhash_secret[3], wyhash_read64(p + 40) ^ see2);
            p += 48;
            i -= 48;
        } while (i > 48);
        seed ^= see1 ^ see2;
    }

    while (i > 16) {
        seed = wyhash_mix(wyhash_read64(p) ^ wyhash_secret[1], wyhash_read64(p + 8) ^ seed);
        p += 16;
        i -= 16;
    }

    a = wyhash_read64(p + i - 16);
    b = wyhash_read64(p + i - 8);
    return wyhash_mix(a ^ wyhash_secret[1] ^ seed, b ^ wyhash_secret[2] ^ (len));
}

#endif  // WYHASH_NFDUMP_H
