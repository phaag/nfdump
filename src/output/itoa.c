/*
 * Integer to ascii conversion (ANSI C)
 *
 * Description
 *     The itoa function converts an integer value to a character string in
 *     decimal and stores the result in the buffer. If value is negative, the
 *     resulting string is preceded with a minus sign (-).
 *
 * Parameters
 *     val: Value to be converted.
 *     buf: Buffer that holds the result of the conversion.
 *
 * Return Value
 *     A pointer to the end of resulting string.
 *
 * Notice
 *     The resulting string is not null-terminated.
 *     The buffer should be large enough to hold any possible result:
 *         uint32_t: 10 bytes
 *         uint64_t: 20 bytes
 *         int32_t: 11 bytes
 *         int64_t: 20 bytes
 *
 * Copyright (c) 2018 YaoYuan <ibireme@gmail.com>.
 * Released under the MIT license (MIT).
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#if !defined(force_inline)
#define force_inline __inline__
#endif

#if !defined(table_align)
#define table_align(x) __attribute__((aligned(x)))
#endif

table_align(2) static const char char_table[200] = {
    '0', '0', '0', '1', '0', '2', '0', '3', '0', '4', '0', '5', '0', '6', '0', '7', '0', '8', '0', '9', '1', '0', '1', '1', '1', '2', '1', '3', '1',
    '4', '1', '5', '1', '6', '1', '7', '1', '8', '1', '9', '2', '0', '2', '1', '2', '2', '2', '3', '2', '4', '2', '5', '2', '6', '2', '7', '2', '8',
    '2', '9', '3', '0', '3', '1', '3', '2', '3', '3', '3', '4', '3', '5', '3', '6', '3', '7', '3', '8', '3', '9', '4', '0', '4', '1', '4', '2', '4',
    '3', '4', '4', '4', '5', '4', '6', '4', '7', '4', '8', '4', '9', '5', '0', '5', '1', '5', '2', '5', '3', '5', '4', '5', '5', '5', '6', '5', '7',
    '5', '8', '5', '9', '6', '0', '6', '1', '6', '2', '6', '3', '6', '4', '6', '5', '6', '6', '6', '7', '6', '8', '6', '9', '7', '0', '7', '1', '7',
    '2', '7', '3', '7', '4', '7', '5', '7', '6', '7', '7', '7', '8', '7', '9', '8', '0', '8', '1', '8', '2', '8', '3', '8', '4', '8', '5', '8', '6',
    '8', '7', '8', '8', '8', '9', '9', '0', '9', '1', '9', '2', '9', '3', '9', '4', '9', '5', '9', '6', '9', '7', '9', '8', '9', '9'};

static inline char *itoa_i32(int32_t val, char *buf);
static inline char *itoa_i64(int64_t val, char *buf);
static inline char *itoa_u32(uint32_t val, char *buf);
static inline char *itoa_u64(uint64_t val, char *buf);

static inline char *itoa_u32(uint32_t val, char *buf) {
    /* This struct can help compiler generate 2-byte load/store */
    /* instructions on platforms that support unaligned access. */
    typedef struct {
        char c1, c2;
    } pair;

    /* The maximum value of uint32_t is 4294967295 (10 digits), */
    /* these digits are named as 'aabbccddee' here.             */
    uint32_t aa, bb, cc, dd, ee, aabb, bbcc, ccdd, ddee, aabbcc;

    /* Leading zero count in the first pair.                    */
    uint32_t lz;

    /* Although most compilers may convert the "division by     */
    /* constant value" into "multiply and shift", manual        */
    /* conversion can still help some compilers generate        */
    /* fewer and better instructions.                           */

    if (val < 100) { /* 1-2 digits: aa */
        lz = val < 10;
        ((pair *)buf)[0] = *(pair *)&(char_table[val * 2 + lz]);
        buf -= lz;
        return buf + 2;

    } else if (val < 10000) {    /* 3-4 digits: aabb */
        aa = (val * 5243) >> 19; /* (val / 100) */
        bb = val - aa * 100;     /* (val % 100) */
        lz = aa < 10;
        ((pair *)buf)[0] = *(pair *)&(char_table[aa * 2 + lz]);
        buf -= lz;
        ((pair *)buf)[1] = ((pair *)char_table)[bb];
        return buf + 4;

    } else if (val < 1000000) {                          /* 5-6 digits: aabbcc */
        aa = (uint32_t)(((uint64_t)val * 429497) >> 32); /* (val / 10000) */
        bbcc = val - aa * 10000;                         /* (val % 10000) */
        bb = (bbcc * 5243) >> 19;                        /* (bbcc / 100) */
        cc = bbcc - bb * 100;                            /* (bbcc % 100) */
        lz = aa < 10;
        ((pair *)buf)[0] = *(pair *)&(char_table[aa * 2 + lz]);
        buf -= lz;
        ((pair *)buf)[1] = ((pair *)char_table)[bb];
        ((pair *)buf)[2] = ((pair *)char_table)[cc];
        return buf + 6;

    } else if (val < 100000000) { /* 7~8 digits: aabbccdd */
        /* (val / 10000) */
        aabb = (uint32_t)(((uint64_t)val * 109951163) >> 40);
        ccdd = val - aabb * 10000; /* (val % 10000) */
        aa = (aabb * 5243) >> 19;  /* (aabb / 100) */
        cc = (ccdd * 5243) >> 19;  /* (ccdd / 100) */
        bb = aabb - aa * 100;      /* (aabb % 100) */
        dd = ccdd - cc * 100;      /* (ccdd % 100) */
        lz = aa < 10;
        ((pair *)buf)[0] = *(pair *)&(char_table[aa * 2 + lz]);
        buf -= lz;
        ((pair *)buf)[1] = ((pair *)char_table)[bb];
        ((pair *)buf)[2] = ((pair *)char_table)[cc];
        ((pair *)buf)[3] = ((pair *)char_table)[dd];
        return buf + 8;

    } else { /* 9~10 digits: aabbccddee */
        /* (val / 10000) */
        aabbcc = (uint32_t)(((uint64_t)val * 3518437209ul) >> 45);
        /* (aabbcc / 10000) */
        aa = (uint32_t)(((uint64_t)aabbcc * 429497) >> 32);
        ddee = val - aabbcc * 10000; /* (val % 10000) */
        bbcc = aabbcc - aa * 10000;  /* (aabbcc % 10000) */
        bb = (bbcc * 5243) >> 19;    /* (bbcc / 100) */
        dd = (ddee * 5243) >> 19;    /* (ddee / 100) */
        cc = bbcc - bb * 100;        /* (bbcc % 100) */
        ee = ddee - dd * 100;        /* (ddee % 100) */
        lz = aa < 10;
        ((pair *)buf)[0] = *(pair *)&(char_table[aa * 2 + lz]);
        buf -= lz;
        ((pair *)buf)[1] = ((pair *)char_table)[bb];
        ((pair *)buf)[2] = ((pair *)char_table)[cc];
        ((pair *)buf)[3] = ((pair *)char_table)[dd];
        ((pair *)buf)[4] = ((pair *)char_table)[ee];
        return buf + 10;
    }
}

static inline char *itoa_i32(int32_t val, char *buf) {
    uint32_t pos = (uint32_t)val;
    uint32_t neg = ~pos + 1;
    size_t sign = val < 0;
    *buf = '-';
    return itoa_u32(sign ? neg : pos, buf + sign);
}

static force_inline char *itoa_u64_len_8(uint32_t val, char *buf) {
    /* 8 digits: aabbccdd */
    typedef struct {
        char c1, c2;
    } pair;
    uint32_t aa, bb, cc, dd, aabb, ccdd;
    aabb = (uint32_t)(((uint64_t)val * 109951163) >> 40); /* (val / 10000) */
    ccdd = val - aabb * 10000;                            /* (val % 10000) */
    aa = (aabb * 5243) >> 19;                             /* (aabb / 100) */
    cc = (ccdd * 5243) >> 19;                             /* (ccdd / 100) */
    bb = aabb - aa * 100;                                 /* (aabb % 100) */
    dd = ccdd - cc * 100;                                 /* (ccdd % 100) */
    ((pair *)buf)[0] = ((pair *)char_table)[aa];
    ((pair *)buf)[1] = ((pair *)char_table)[bb];
    ((pair *)buf)[2] = ((pair *)char_table)[cc];
    ((pair *)buf)[3] = ((pair *)char_table)[dd];
    return buf + 8;
}

static force_inline char *itoa_u64_len_4(uint32_t val, char *buf) {
    /* 4 digits: aabb */
    typedef struct {
        char c1, c2;
    } pair;
    uint32_t aa, bb;
    aa = (val * 5243) >> 19; /* (val / 100) */
    bb = val - aa * 100;     /* (val % 100) */
    ((pair *)buf)[0] = ((pair *)char_table)[aa];
    ((pair *)buf)[1] = ((pair *)char_table)[bb];
    return buf + 4;
}

static force_inline char *itoa_u64_len_1_8(uint32_t val, char *buf) {
    typedef struct {
        char c1, c2;
    } pair;
    uint32_t aa, bb, cc, dd, aabb, bbcc, ccdd, lz;

    if (val < 100) { /* 1-2 digits: aa */
        lz = val < 10;
        ((pair *)buf)[0] = *(pair *)&(char_table[val * 2 + lz]);
        buf -= lz;
        return buf + 2;

    } else if (val < 10000) {    /* 3-4 digits: aabb */
        aa = (val * 5243) >> 19; /* (val / 100) */
        bb = val - aa * 100;     /* (val % 100) */
        lz = aa < 10;
        ((pair *)buf)[0] = *(pair *)&(char_table[aa * 2 + lz]);
        buf -= lz;
        ((pair *)buf)[1] = ((pair *)char_table)[bb];
        return buf + 4;

    } else if (val < 1000000) {                          /* 5-6 digits: aabbcc */
        aa = (uint32_t)(((uint64_t)val * 429497) >> 32); /* (val / 10000) */
        bbcc = val - aa * 10000;                         /* (val % 10000) */
        bb = (bbcc * 5243) >> 19;                        /* (bbcc / 100) */
        cc = bbcc - bb * 100;                            /* (bbcc % 100) */
        lz = aa < 10;
        ((pair *)buf)[0] = *(pair *)&(char_table[aa * 2 + lz]);
        buf -= lz;
        ((pair *)buf)[1] = ((pair *)char_table)[bb];
        ((pair *)buf)[2] = ((pair *)char_table)[cc];
        return buf + 6;

    } else { /* 7-8 digits: aabbccdd */
        /* (val / 10000) */
        aabb = (uint32_t)(((uint64_t)val * 109951163) >> 40);
        ccdd = val - aabb * 10000; /* (val % 10000) */
        aa = (aabb * 5243) >> 19;  /* (aabb / 100) */
        cc = (ccdd * 5243) >> 19;  /* (ccdd / 100) */
        bb = aabb - aa * 100;      /* (aabb % 100) */
        dd = ccdd - cc * 100;      /* (ccdd % 100) */
        lz = aa < 10;
        ((pair *)buf)[0] = *(pair *)&(char_table[aa * 2 + lz]);
        buf -= lz;
        ((pair *)buf)[1] = ((pair *)char_table)[bb];
        ((pair *)buf)[2] = ((pair *)char_table)[cc];
        ((pair *)buf)[3] = ((pair *)char_table)[dd];
        return buf + 8;
    }
}

static force_inline char *itoa_u64_len_5_8(uint32_t val, char *buf) {
    typedef struct {
        char c1, c2;
    } pair;
    uint32_t aa, bb, cc, dd, aabb, bbcc, ccdd, lz;

    if (val < 1000000) {                                 /* 5-6 digits: aabbcc */
        aa = (uint32_t)(((uint64_t)val * 429497) >> 32); /* (val / 10000) */
        bbcc = val - aa * 10000;                         /* (val % 10000) */
        bb = (bbcc * 5243) >> 19;                        /* (bbcc / 100) */
        cc = bbcc - bb * 100;                            /* (bbcc % 100) */
        lz = aa < 10;
        ((pair *)buf)[0] = *(pair *)&(char_table[aa * 2 + lz]);
        buf -= lz;
        ((pair *)buf)[1] = ((pair *)char_table)[bb];
        ((pair *)buf)[2] = ((pair *)char_table)[cc];
        return buf + 6;

    } else { /* 7-8 digits: aabbccdd */
        /* (val / 10000) */
        aabb = (uint32_t)(((uint64_t)val * 109951163) >> 40);
        ccdd = val - aabb * 10000; /* (val % 10000) */
        aa = (aabb * 5243) >> 19;  /* (aabb / 100) */
        cc = (ccdd * 5243) >> 19;  /* (ccdd / 100) */
        bb = aabb - aa * 100;      /* (aabb % 100) */
        dd = ccdd - cc * 100;      /* (ccdd % 100) */
        lz = aa < 10;
        ((pair *)buf)[0] = *(pair *)&(char_table[aa * 2 + lz]);
        buf -= lz;
        ((pair *)buf)[1] = ((pair *)char_table)[bb];
        ((pair *)buf)[2] = ((pair *)char_table)[cc];
        ((pair *)buf)[3] = ((pair *)char_table)[dd];
        return buf + 8;
    }
}

static inline char *itoa_u64(uint64_t val, char *buf) {
    uint64_t tmp, hgh;
    uint32_t mid, low;

    if (val < 100000000) { /* 1-8 digits */
        buf = itoa_u64_len_1_8((uint32_t)val, buf);
        return buf;

    } else if (val < (uint64_t)100000000 * 100000000) { /* 9-16 digits */
        hgh = val / 100000000;
        low = (uint32_t)(val - hgh * 100000000); /* (val % 100000000) */
        buf = itoa_u64_len_1_8((uint32_t)hgh, buf);
        buf = itoa_u64_len_8(low, buf);
        return buf;

    } else { /* 17-20 digits */
        tmp = val / 100000000;
        low = (uint32_t)(val - tmp * 100000000); /* (val % 100000000) */
        hgh = (uint32_t)(tmp / 10000);
        mid = (uint32_t)(tmp - hgh * 10000); /* (tmp % 10000) */
        buf = itoa_u64_len_5_8((uint32_t)hgh, buf);
        buf = itoa_u64_len_4(mid, buf);
        buf = itoa_u64_len_8(low, buf);
        return buf;
    }
}

static inline char *itoa_i64(int64_t val, char *buf) {
    uint64_t pos = (uint64_t)val;
    uint64_t neg = ~pos + 1;
    size_t sign = val < 0;
    *buf = '-';
    return itoa_u64(sign ? neg : pos, buf + sign);
}

/*
int main() {
    char buffer[64];

    for (uint32_t i = 0; i < 10000000; i++) {
        printf("%u %u %u %u\n", i, i + 1, i + 2, i + 3);
        char *s = itoa_u32(i, buffer);
        *s++ = ' ';
        s = itoa_u32(i, s);
        *s++ = ' ';
        s = itoa_u32(i, s);
        *s++ = ' ';
        s = itoa_u32(i, s);
        *s = '\0';
        puts(buffer);
}
return 0;
}
*/