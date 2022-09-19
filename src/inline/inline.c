/*
 *  Copyright (c) 2009-2022, Peter Haag
 *  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
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

#include <stdint.h>

typedef struct type_mask_s {
    union {
        uint8_t val8[8];
        uint16_t val16[4];
        uint32_t val32[2];
        uint64_t val64;
    };
} type_mask_t;

static inline uint16_t Get_val16(const void *p);

static inline uint32_t Get_val24(const void *p);

static inline uint32_t Get_val32(const void *p);

static inline uint64_t Get_val40(const void *p);

static inline uint64_t Get_val48(const void *p);

static inline uint64_t Get_val56(const void *p);

static inline uint64_t Get_val64(const void *p);

static inline uint64_t Get_val(const void *p, uint32_t index, uint32_t length);

static inline void Put_val8(uint8_t v, void *p);

static inline void Put_val16(uint16_t v, void *p);

static inline void Put_val24(uint32_t v, void *p);

static inline void Put_val32(uint32_t v, void *p);

// static inline void	Put_val40(uint64_t v, const void *p);

static inline void Put_val48(uint64_t v, void *p);

// static inline void	Put_val56(uint64_t v, const void *p);

static inline void Put_val64(uint64_t v, void *p);

static inline uint16_t Get_val16(const void *p) {
    const uint16_t *in = (uint16_t *)p;

    return ntohs(*in);

}  // End of Get_val16

static inline uint32_t Get_val24(const void *p) {
    const uint8_t *in = (uint8_t *)p;

    uint64_t r = 0;
    for (size_t i = 0; i < 3; ++i) r = (r << 8) + *in++;
    return r;

}  // End of Get_val24

static inline uint32_t Get_val32(const void *p) {
    const uint32_t *in = (uint32_t *)p;

    return ntohl(*in);

}  // End of Get_val32

static inline uint64_t Get_val40(const void *p) {
    const uint8_t *in = (uint8_t *)p;

    uint64_t r = 0;
    for (size_t i = 0; i < 5; ++i) r = (r << 8) + *in++;
    return r;

}  // End of Get_val40

static inline uint64_t Get_val48(const void *p) {
    const uint8_t *in = (uint8_t *)p;

    uint64_t r = 0;
    for (size_t i = 0; i < 6; ++i) r = (r << 8) + *in++;

    return r;

}  // End of Get_val48

static inline uint64_t Get_val56(const void *p) {
    const uint8_t *in = (uint8_t *)p;

    uint64_t r = 0;
    for (size_t i = 0; i < 7; ++i) r = (r << 8) + *in++;
    return r;

}  // End of Get_val56

static inline uint64_t Get_val64(const void *p) {
    const uint64_t *in = (uint64_t *)p;

    return ntohll(*in);

}  // End of Get_val64

static inline uint64_t Get_val(const void *p, uint32_t index, uint32_t length) {
    switch (length) {
        case 1:
            return *((uint8_t *)(p + index));
            break;
        case 2:
            return Get_val16(p + index);
            break;
        case 3:
            return Get_val24(p + index);
            break;
        case 4:
            return Get_val32(p + index);
            break;
        case 5:
            return Get_val40(p + index);
            break;
        case 6:
            return Get_val48(p + index);
            break;
        case 7:
            return Get_val56(p + index);
            break;
        case 8:
            return Get_val64(p + index);
            break;
        default:
            return 0;
    }
    return 0;

}  // End of Get_val

static inline void Put_val8(uint8_t v, void *p) {
    uint8_t *out = (uint8_t *)p;

    out[0] = v;

}  // End of Put_val16

static inline void Put_val16(uint16_t v, void *p) {
    uint8_t *out = (uint8_t *)p;
    type_mask_t mask;

    mask.val16[0] = v;
    out[0] = mask.val8[0];
    out[1] = mask.val8[1];

}  // End of Put_val16

static inline void Put_val24(uint32_t v, void *p) {
    uint8_t *out = (uint8_t *)p;
    type_mask_t mask;

    mask.val32[0] = v;
    out[0] = mask.val8[1];
    out[1] = mask.val8[2];
    out[2] = mask.val8[3];

}  // End of Put_val24

static inline void Put_val32(uint32_t v, void *p) {
    uint8_t *out = (uint8_t *)p;
    type_mask_t mask;

    mask.val32[0] = v;
    out[0] = mask.val8[0];
    out[1] = mask.val8[1];
    out[2] = mask.val8[2];
    out[3] = mask.val8[3];

}  // End of Put_val32

/*
 * not yet used
 *
static inline void	Put_val40(uint64_t v, void *p) {
uint8_t		*out = (uint8_t *)p;
type_mask_t mask;

        mask.val64 = v;
        out[0] = mask.val8[3];
        out[1] = mask.val8[4];
        out[2] = mask.val8[5];
        out[3] = mask.val8[6];
        out[4] = mask.val8[7];

} // End of Put_val40
 *
 */

static inline void Put_val48(uint64_t v, void *p) {
    uint8_t *out = (uint8_t *)p;
    type_mask_t mask;

    mask.val64 = v;
    out[0] = mask.val8[2];
    out[1] = mask.val8[3];
    out[2] = mask.val8[4];
    out[3] = mask.val8[5];
    out[4] = mask.val8[6];
    out[5] = mask.val8[7];

}  // End of Put_val48

/*
 * not yet used
 *
static inline void	Put_val56(uint64_t v, void *p) {
uint8_t	*out = (uint8_t *)p;
type_mask_t mask;

        mask.val64 = v;
        out[0] = mask.val8[1];
        out[1] = mask.val8[2];
        out[2] = mask.val8[3];
        out[3] = mask.val8[4];
        out[4] = mask.val8[5];
        out[5] = mask.val8[6];
        out[6] = mask.val8[7];

} // End of Put_val56
 *
 */

static inline void Put_val64(uint64_t v, void *p) {
    uint8_t *out = (uint8_t *)p;
    type_mask_t mask;

    mask.val64 = v;
    out[0] = mask.val8[0];
    out[1] = mask.val8[1];
    out[2] = mask.val8[2];
    out[3] = mask.val8[3];
    out[4] = mask.val8[4];
    out[5] = mask.val8[5];
    out[6] = mask.val8[6];
    out[7] = mask.val8[7];

}  // End of Put_val64
