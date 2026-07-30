/*
 * bloom.h
 *
 * Simple 512-bit bloom filter for IPv4/IPv6 addresses.
 *
 * Uses:
 *   - wyhash()
 *   - Kirsch-Mitzenmacher hash derivation
 *
 * False negatives: impossible
 * False positives: possible
 */

#ifndef _BLOOM_H
#define _BLOOM_H

#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

#include "wyhash.h"

#define BLOOM_BITS 65536
#define BLOOM_WORDS 1024
#define BLOOM_HASHES 7

typedef struct bloomFilter_s {
    uint64_t bits[BLOOM_WORDS];
} bloomFilter_t;

/*
 * Clear bloom filter.
 */
static inline void BloomInit(bloomFilter_t *bloom) { memset(bloom, 0, sizeof(*bloom)); }

/*
 * Internal generic add.
 */
static inline void BloomAdd(bloomFilter_t *bloom, const void *data, size_t len) {
    uint64_t h = wyhash(data, len, 0);

    uint32_t h1 = (uint32_t)h;
    uint32_t h2 = (uint32_t)(h >> 32);

    for (unsigned i = 0; i < BLOOM_HASHES; i++) {
        uint32_t x = h1 + i * h2;

        uint32_t bit = x & (BLOOM_BITS - 1);

        bloom->bits[bit >> 6] |= (1ULL << (bit & 63));
    }
}

/*
 * Internal generic lookup.
 *
 * Returns:
 *   0 -> definitely not present
 *   1 -> probably present
 */
static inline int BloomLookup(const bloomFilter_t *bloom, const void *data, size_t len) {
    uint64_t h = wyhash(data, len, 0);

    uint32_t h1 = (uint32_t)h;
    uint32_t h2 = (uint32_t)(h >> 32);

    for (unsigned i = 0; i < BLOOM_HASHES; i++) {
        uint32_t x = h1 + i * h2;

        uint32_t bit = x & (BLOOM_BITS - 1);

        if (!(bloom->bits[bit >> 6] & (1ULL << (bit & 63)))) {
            return 0;
        }
    }

    return 1;
}

/*
 * Add IPv4 address.
 *
 * IPv4 is expected in network byte order.
 */
static inline void BloomAddIPv4(bloomFilter_t *bloom, uint32_t ip) { BloomAdd(bloom, &ip, sizeof(ip)); }

/*
 * Lookup IPv4 address.
 */
static inline int BloomLookupIPv4(const bloomFilter_t *bloom, uint32_t ip) { return BloomLookup(bloom, &ip, sizeof(ip)); }

/*
 * Add IPv6 address.
 *
 * IPv6 is expected as struct in6_addr.
 */
static inline void BloomAddIPv6(bloomFilter_t *bloom, const uint8_t *ip) { BloomAdd(bloom, ip, 16); }

/*
 * Lookup IPv6 address.
 */
static inline int BloomLookupIPv6(const bloomFilter_t *bloom, const uint8_t *ip) { return BloomLookup(bloom, ip, 16); }

/*
 * Four bloom-filter pointers — one per direction × address family.
 *
 * Write side (nfmeta): pointers alias memory inside the current output block;
 * BloomAdd* calls write bloom bits directly into the block buffer.
 *
 * Read side (nfdump prepareThread): pointers alias the decompressed block in
 * RAM; BloomLookup* calls read bloom bits to decide whether to skip the block.
 *
 * A NULL pointer means no bloom is available for that direction/family.
 */
typedef struct bloomHandle_s {
    bloomFilter_t *srcIPv4bloom;
    bloomFilter_t *dstIPv4bloom;
    bloomFilter_t *srcIPv6bloom;
    bloomFilter_t *dstIPv6bloom;
} bloomHandle_t;

#endif