/*
 *  Copyright (c) 2025, Peter Haag
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

#ifndef _IP128_H
#define _IP128_H 1

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

// single IP addr for IPv4 and IPv6
// use ::FFFF:w.x.y.z notation for mapping IPv4 in IPv6
typedef struct ip128_s {
    _Alignas(16) uint8_t bytes[16];
} ip128_t;

// Fast 128-bit IP compare using 16-byte alignment; compilers will emit vector code at -O3 -march=native
static inline int ip128_equal(const ip128_t *a, const ip128_t *b) {
    uint64_t a0, a1, b0, b1;
    memcpy(&a0, a->bytes, sizeof(a0));
    memcpy(&a1, a->bytes + 8, sizeof(a1));
    memcpy(&b0, b->bytes, sizeof(b0));
    memcpy(&b1, b->bytes + 8, sizeof(b1));
    return (a0 == b0) && (a1 == b1);
}  // End of ip128_equal

// Fast 128-bit IP AND; compilers will emit vector code at -O3 -march=native
static inline void ip128_and(ip128_t *dst, const ip128_t *a, const ip128_t *b) {
    uint64_t a0, a1, b0, b1, d0, d1;
    memcpy(&a0, a->bytes, sizeof(a0));
    memcpy(&a1, a->bytes + 8, sizeof(a1));
    memcpy(&b0, b->bytes, sizeof(b0));
    memcpy(&b1, b->bytes + 8, sizeof(b1));
    d0 = a0 & b0;
    d1 = a1 & b1;
    memcpy(dst->bytes, &d0, sizeof(d0));
    memcpy(dst->bytes + 8, &d1, sizeof(d1));
}  // End of ip128_and

// Fast 128-bit IP compare with subnet; compilers will emit vector code at -O3 -march=native
static inline int ip_in_subnet(const ip128_t *ip, const ip128_t *network, const ip128_t *mask) {
    ip128_t tmp;
    ip128_and(&tmp, ip, mask);
    return ip128_equal(&tmp, network);
}

// Fast 128-bit IP compare to zero; compilers will emit vector code at -O3 -march=native
static inline int is_zero128(const ip128_t *a) {
    uint64_t a0, a1;
    memcpy(&a0, a->bytes, sizeof(a0));
    memcpy(&a1, a->bytes + 8, sizeof(a1));
    return (a0 == 0) && (a1 == 0);
}  // End of is_zero128

// Check, if IP is a mapped IPv4 in IPv6
static inline int is_ipv4_mapped(const ip128_t *a) {
    /* First 80 bits must be zero, next 16 bits must be 0xffff */
    const uint8_t prefix[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};
    return (memcmp(a->bytes, prefix, 12) == 0);
}

#define IP128HASH(ip)                                         \
    ({                                                        \
        const uint64_t *_w = (const uint64_t *)((ip)->bytes); \
        uint64_t _x = _w[0] ^ _w[1];                          \
        _x ^= _x >> 33;                                       \
        _x *= 0xff51afd7ed558ccdULL;                          \
        _x ^= _x >> 33;                                       \
        _x *= 0xc4ceb9fe1a85ec53ULL;                          \
        _x ^= _x >> 33;                                       \
        (uint32_t)_x;                                         \
    })

/*
// 32-bit version
#define IP128HASH(ip)                                         \
({                                                        \
const uint32_t *_w = (const uint32_t *)((ip)->bytes); \
uint32_t _h = _w[0] ^ _w[1] ^ _w[2] ^ _w[3];          \
_h ^= _h >> 16;                                       \
_h *= 0x7feb352du;                                    \
_h ^= _h >> 15;                                       \
_h *= 0x846ca68bu;                                    \
_h ^= _h >> 16;                                       \
_h;                                                   \
})
*/

char *ip128_2_str(const ip128_t *ip, char *ipstr);

ip128_t ip128_2_bin(const char *ipStr);

#endif