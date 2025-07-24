/*************************************************************************
 *
 * Copyright 2010 by Sean Conner.  All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or (at your
 * option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, see <http://www.gnu.org/licenses/>.
 *
 **************************************************************************/

/**********************************************************************
 *
 *  dns_decode()
 *
 *       This function takes the wire representation of a response, decodes
 *       and returns a dns_query_t filled out with the various records.  You
 *       supply a block of memory sufficient enough to store the dns_query_t
 *       and any various strings/structures used in the dns_query_t (I've
 *       found 8K to be more than enough for decoding a UDP response but
 *       that's a very conservative value; 4K may be good enough).
 *       This code is written using C99.
 *
 *
 ****************************************************************************/

#include "config.h"

#define _GNU_SOURCE

#if defined(__NEWLIB__)
#include <machine/endian.h>
#define htons(_x) __htons(_x)
#define ntohs(_x) __ntohs(_x)
#elif defined(__BIONIC__)
#include <sys/endian.h>
#endif

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "codec.h"
#include "util.h"

#if defined(__clang__)
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#endif

/*----------------------------------------------------------------------------
; The folowing are used for memory allocation.  dns_decoded_t should be fine
; for alignment size, as it's good enough for alignment.  If some odd-ball
; system comes up that requires more strict alignment, then I'll change this
; to something like a long double or something silly like that.
;
; see the comment align_memory() for more details
;-----------------------------------------------------------------------------*/

#define MEM_ALIGN sizeof(dns_decoded_t)
#define MEM_MASK ~(sizeof(dns_decoded_t) - 1uL)

/*---------------------------------------------------------------------------
; This is the maximum number of domain labels to encode.  The domain
; "example.com" contains two domain labels.  "1.0.0.127.in-addr.arpa" has
; six domain labels.  This value is calculated was calculated by Tony Finch
; [1] based upon the maximum domain name length, and minimum segment length.
;
; [1] https://lobste.rs/s/tukocy/network_protocols_sans_i_o_2016#c_495uaz
;----------------------------------------------------------------------------*/

#define MAXSEG 128

/*---------------------------------------------------------------------------
; You really, no, I mean it, *REALLY* need to read RFC-1876 to understand
; all the crap that's going on for deciphering RR_LOC.
;----------------------------------------------------------------------------*/

#define LOC_BIAS (((unsigned long)INT32_MAX) + 1uL)
#define LOC_LAT_MAX ((unsigned long)(90uL * 3600000uL))
#define LOC_LNG_MAX ((unsigned long)(180uL * 3600000uL))
#define LOC_ALT_BIAS (10000000L)

/************************************************************************/

struct idns_header {
    uint16_t id;
    uint8_t opcode;
    uint8_t rcode;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed));

struct segment {
    char const *name;
    size_t offset;
};

typedef struct block {
    size_t size;
    uint8_t *ptr;
} block__s;

typedef struct segments {
    size_t idx;
    struct segment seg[MAXSEG];
} segments__s;

typedef struct edns_context {
    block__s packet;
    segments__s segments;
    bool edns;
    uint8_t *base;
    dns_rcode_t rcode;
} edns_context;

typedef struct ddns_context {
    block__s packet;
    block__s parse;
    block__s dest; /* see comments in align_memory() */
    dns_query_t *response;
    bool edns;
} ddns_context;

/***********************************************************************/

#ifdef DEVEL
static int pblock_okay(block__s const *block) {
    dbg_assert(block != NULL);
    dbg_assert(block->ptr != NULL);
    dbg_assert(block->size > 0);
    return 1;
}

static int block_okay(block__s const block) {
    dbg_assert(block.ptr != NULL);
    dbg_assert(block.size > 0);
    return 1;
}

static int dcontext_okay(ddns_context const *data) {
    dbg_assert(data != NULL);
    dbg_assert(data->response != NULL);
    dbg_assert(block_okay(data->packet));
    dbg_assert(block_okay(data->parse));
    dbg_assert(block_okay(data->dest));
    return 1;
}
#endif

/*************************************************************************
 *
 * Memory allocations are done quickly.  The dns_decode() routine is given a
 * block of memory to carve allocations out of (4k appears to be good eough;
 * 8k is more than enough for UDP packets) and there's no real intelligence
 * here---just a quick scheme.  String information is just allocated starting
 * at the next available location (referenced in context->dest) whereas the
 * few structures that do need allocating require the free pointer to be
 * adjusted to a proper memory alignment.  If you need alignments, call
 * alloc_struct(), otherwise for strings, use context->dest directly.  You
 * *can* use align_memory() directly, just be sure you know what you are
 * doing.
 *
 ******************************************************************************/

static bool align_memory(block__s *pool) {
    size_t newsize;
    size_t delta;

    dbg_assert(pblock_okay(pool));

    if (pool->size < MEM_ALIGN) return false;

    newsize = pool->size & MEM_MASK;
    if (newsize == pool->size) return true;

    dbg_assert(newsize < pool->size);
    delta = (newsize + MEM_ALIGN) - pool->size;
    dbg_assert(delta < pool->size);

    pool->ptr += delta;
    pool->size -= delta;

    return true;
}

/*************************************************************************/

static void *alloc_struct(block__s *pool, size_t size) {
    uint8_t *ptr;

    dbg_assert(pblock_okay(pool));

    if (size == 0 || pool->size == 0) return NULL;
    if (!align_memory(pool)) return NULL;
    if (pool->size < size) return NULL;

    ptr = pool->ptr;
    pool->ptr += size;
    pool->size -= size;
    return (void *)ptr;
}

/***********************************************************************/

static inline uint16_t read_uint16(block__s *parse) {
    uint16_t val;

    /*------------------------------------------------------------------------
    ; caller is reponsible for making sure there's at least two bytes to read
    ;------------------------------------------------------------------------*/

    dbg_assert(pblock_okay(parse));
    dbg_assert(parse->size >= 2);

    val = (parse->ptr[0] << 8) | (parse->ptr[1]);
    parse->ptr += 2;
    parse->size -= 2;
    return val;
}

/********************************************************************/

static inline uint32_t read_uint32(block__s *parse) {
    uint32_t val;

    /*------------------------------------------------------------------------
    ; caller is reponsible for making sure there's at least four bytes to read
    ;------------------------------------------------------------------------*/

    dbg_assert(pblock_okay(parse));
    dbg_assert(parse->size >= 4);

    val = (parse->ptr[0] << 24) | (parse->ptr[1] << 16) | (parse->ptr[2] << 8) | (parse->ptr[3]);
    parse->ptr += 4;
    parse->size -= 4;
    return val;
}

/********************************************************************/

static dns_rcode_t read_raw(ddns_context *data, uint8_t **result, size_t len) {
    dbg_assert(dcontext_okay(data));
    dbg_assert(result != NULL);

    if (len > 0) {
        if (len > data->parse.size) return RCODE_FORMAT_ERROR;

        /*--------------------------------------------------------------------
        ; Called when we don't know the contents of the data; it's aligned so
        ; that if the data is actually structured, it can probably be read
        ; directly by the clients of this code.
        ;--------------------------------------------------------------------*/

        if (!align_memory(&data->dest)) return RCODE_NO_MEMORY;

        if (len > data->dest.size) return RCODE_NO_MEMORY;

        *result = data->dest.ptr;
        memcpy(data->dest.ptr, data->parse.ptr, len);
        data->parse.ptr += len;
        data->parse.size -= len;
        data->dest.ptr += len;
        data->dest.size -= len;
    } else
        *result = NULL;

    return RCODE_OKAY;
}

/********************************************************************/

static dns_rcode_t read_string(ddns_context *data, const char **result) {
    size_t len;

    dbg_assert(dcontext_okay(data));
    dbg_assert(result != NULL);

    len = *data->parse.ptr;

    if (data->dest.size < len + 1) /* adjust for NUL byte */
        return RCODE_NO_MEMORY;

    if (data->parse.size < len + 1) /* adjust for length byte */
        return RCODE_FORMAT_ERROR;

    *result = (char *)data->dest.ptr;
    memcpy(data->dest.ptr, &data->parse.ptr[1], len);

    data->parse.ptr += (len + 1);
    data->parse.size -= (len + 1);
    data->dest.ptr += len;
    data->dest.size -= len;
    *data->dest.ptr++ = '\0';
    data->dest.size--;

    return RCODE_OKAY;
}

/********************************************************************/

static dns_rcode_t read_domain(ddns_context *data, const char **result) {
    block__s *parse = &data->parse;
    block__s tmp;
    size_t len;
    int loop; /* loop detection */

    dbg_assert(dcontext_okay(data));
    dbg_assert(result != NULL);

    *result = (char *)data->dest.ptr;
    loop = 0;

    do {
        /*----------------------------
        ; read in a domain segment
        ;-----------------------------*/

        if (*parse->ptr < 64) {
            len = *parse->ptr;

            if (parse->size < len + 1) return RCODE_FORMAT_ERROR;

            if (data->dest.size < len + 1) return RCODE_NO_MEMORY;

            if (len) {
                memcpy(data->dest.ptr, &parse->ptr[1], len);
                parse->ptr += (len + 1);
                parse->size -= (len + 1);
            }

            data->dest.size -= (len + 1);
            data->dest.ptr += len;
            *data->dest.ptr++ = '.';
        }

        /*------------------------------------------
        ; compressed segment---follow the pointer
        ;------------------------------------------*/

        else if (*parse->ptr >= 192) {
            if (++loop == 256) return RCODE_FORMAT_ERROR;

            if (parse->size < 2) return RCODE_FORMAT_ERROR;

            len = read_uint16(parse) & 0x3FFF;

            if (len >= data->packet.size) return RCODE_FORMAT_ERROR;

            tmp.ptr = &data->packet.ptr[len];
            tmp.size = data->packet.size - (size_t)(tmp.ptr - data->packet.ptr);
            parse = &tmp;
        }

        /*-----------------------------------------------------------------------
        ; EDNS0 extended labeles, RFC-2671; the only extension proposed so far,
        ; RFC-2673, was changed from Proposed to Experimental in RFC-3363, so
        ; I'm not including support for it at this time.
        ;-----------------------------------------------------------------------*/

        else if ((*parse->ptr >= 64) && (*parse->ptr <= 127))
            return RCODE_FORMAT_ERROR;

        /*------------------------------------
        ; reserved for future developments
        ;------------------------------------*/

        else
            return RCODE_FORMAT_ERROR;

        if (parse->size < 1) return RCODE_FORMAT_ERROR;
    } while (*parse->ptr);

    parse->ptr++;
    parse->size--;

    if (data->dest.size == 0) return RCODE_NO_MEMORY;
    *data->dest.ptr++ = '\0';
    data->dest.size--;

    return RCODE_OKAY;
}

/********************************************************************/

static inline dns_rcode_t decode_edns0rr_nsid(ddns_context *data, edns0_opt_t *opt) {
    static char const hexdigits[] = "0123456789ABCDEF";

    if (opt->len % 2 == 1) return RCODE_FORMAT_ERROR;

    if (data->dest.size < opt->len / 2) return RCODE_NO_MEMORY;

    for (size_t i = 0; i < opt->len; i += 2) {
        char const *phexh;
        char const *phexl;

        if (!isxdigit(data->parse.ptr[i])) return RCODE_FORMAT_ERROR;
        if (!isxdigit(data->parse.ptr[i + 1])) return RCODE_FORMAT_ERROR;

        phexh = memchr(hexdigits, toupper(data->parse.ptr[i]), 16);
        phexl = memchr(hexdigits, toupper(data->parse.ptr[i + 1]), 16);

        /*------------------------------------------------------------------
        ; phexh and phexl should not be NULL, unless isxdigit() is buggy, and
        ; that is something I'm not assuming.
        ;--------------------------------------------------------------------*/

        dbg_assert(phexh != NULL);
        dbg_assert(phexl != NULL);

        *data->dest.ptr = ((phexh - hexdigits) << 4) | ((phexl - hexdigits));
        data->dest.ptr++;
        data->dest.size--;
    }

    data->parse.ptr += opt->len;
    data->parse.size -= opt->len;
    opt->len /= 2;
    return RCODE_OKAY;
}

/***********************************************************************/

static inline dns_rcode_t decode_edns0rr_raw(ddns_context *data, edns0_opt_t *opt) {
    if (data->dest.size < opt->len) return RCODE_NO_MEMORY;

    memcpy(data->dest.ptr, data->parse.ptr, opt->len);
    data->parse.ptr += opt->len;
    data->parse.size -= opt->len;
    data->dest.ptr += opt->len;
    data->dest.size -= opt->len;
    return RCODE_OKAY;
}

/*************************************************************/

static dns_rcode_t decode_question(ddns_context *data, dns_question_t *pquest) {
    dns_rcode_t rc;

    dbg_assert(dcontext_okay(data));
    dbg_assert(pquest != NULL);

    rc = read_domain(data, &pquest->name);
    if (rc != RCODE_OKAY) return rc;

    if (data->parse.size < 4) return RCODE_FORMAT_ERROR;

    pquest->type = (dns_type_t)read_uint16(&data->parse);
    pquest->class = (dns_class_t)read_uint16(&data->parse);

    /*-------------------------------------------------------
    ; OPT RRs can never be the target of a question as it's
    ; more of a pseudo RR than a real live boy, um, RR.
    ;--------------------------------------------------------*/

    if (pquest->type == RR_OPT) return RCODE_FORMAT_ERROR;

    return RCODE_OKAY;
}

/************************************************************************/

static inline dns_rcode_t decode_rr_soa(ddns_context *data, dns_soa_t *psoa, size_t len) {
    dns_rcode_t rc;

    dbg_assert(dcontext_okay(data));
    dbg_assert(psoa != NULL);

    rc = read_domain(data, &psoa->mname);
    if (rc != RCODE_OKAY) return rc;
    rc = read_domain(data, &psoa->rname);
    if (rc != RCODE_OKAY) return rc;

    if (len < 20) return RCODE_FORMAT_ERROR;

    psoa->serial = read_uint32(&data->parse);
    psoa->refresh = read_uint32(&data->parse);
    psoa->retry = read_uint32(&data->parse);
    psoa->expire = read_uint32(&data->parse);
    psoa->minimum = read_uint32(&data->parse);

    return RCODE_OKAY;
}

/***********************************************************************/

static inline dns_rcode_t decode_rr_a(ddns_context *data, dns_a_t *pa, size_t len) {
    dbg_assert(dcontext_okay(data));
    dbg_assert(pa != NULL);

    if (len != 4) return RCODE_FORMAT_ERROR;
    memcpy(&pa->address, data->parse.ptr, 4);
    data->parse.ptr += 4;
    data->parse.size -= 4;
    return RCODE_OKAY;
}

/***********************************************************************/

static inline dns_rcode_t decode_rr_aaaa(ddns_context *data, dns_aaaa_t *pa, size_t len) {
    dbg_assert(dcontext_okay(data));
    dbg_assert(pa != NULL);

    if (len != 16) return RCODE_FORMAT_ERROR;
    memcpy(pa->address.s6_addr, data->parse.ptr, 16);
    data->parse.ptr += 16;
    data->parse.size -= 16;
    return RCODE_OKAY;
}

/**********************************************************************/

static inline dns_rcode_t decode_rr_wks(ddns_context *data, dns_wks_t *pwks, size_t len) {
    dbg_assert(dcontext_okay(data));
    dbg_assert(pwks != NULL);

    if (len < 6) return RCODE_FORMAT_ERROR;

    memcpy(&pwks->address, data->parse.ptr, 4);
    data->parse.ptr += 4;
    data->parse.size -= 4;
    pwks->protocol = read_uint16(&data->parse);

    pwks->numbits = len - 6;
    return read_raw(data, &pwks->bits, pwks->numbits);
}

/*********************************************************************/

static inline dns_rcode_t decode_rr_mx(ddns_context *data, dns_mx_t *pmx, size_t len) {
    dbg_assert(dcontext_okay(data));
    dbg_assert(pmx != NULL);

    if (len < 4) return RCODE_FORMAT_ERROR;

    pmx->preference = read_uint16(&data->parse);
    return read_domain(data, &pmx->exchange);
}

/**********************************************************************/

static inline dns_rcode_t decode_rr_txt(ddns_context *data, dns_txt_t *ptxt, size_t len) {
    size_t slen;

    dbg_assert(dcontext_okay(data));
    dbg_assert(ptxt != NULL);

    /*--------------------------------------------------------------------
    ; collapse multiple strings (which are allowed per the spec) into one
    ; large string.  Cache the length as well, as some records might prefer
    ; the length to be there (in case of binary data)
    ;---------------------------------------------------------------------*/

    ptxt->text = (char const *)data->dest.ptr;
    ptxt->len = 0;

    while (len) {
        if (data->parse.size < 1) return RCODE_FORMAT_ERROR;

        slen = *data->parse.ptr++;
        data->parse.size--;
        len--;

        if (slen > len) return RCODE_FORMAT_ERROR;

        if (data->parse.size < slen) return RCODE_FORMAT_ERROR;

        if (data->dest.size < slen) return RCODE_NO_MEMORY;

        memcpy(data->dest.ptr, data->parse.ptr, slen);
        dbg_assert(slen <= len);

        ptxt->len += slen;
        data->dest.ptr += slen;
        data->dest.size -= slen;
        data->parse.ptr += slen;
        data->parse.size -= slen;
        len -= slen;
    }

    if (data->dest.size == 0) return RCODE_NO_MEMORY;

    *data->dest.ptr++ = '\0';
    data->dest.size--;
    return RCODE_OKAY;
}

/**********************************************************************/

static inline dns_rcode_t decode_rr_hinfo(ddns_context *data, dns_hinfo_t *phinfo) {
    dns_rcode_t rc;

    dbg_assert(dcontext_okay(data));
    dbg_assert(phinfo != NULL);

    rc = read_string(data, &phinfo->cpu);
    if (rc != RCODE_OKAY) return rc;
    rc = read_string(data, &phinfo->os);
    return rc;
}

/**********************************************************************/

static inline dns_rcode_t decode_rr_srv(ddns_context *data, dns_srv_t *psrv, size_t len) {
    dbg_assert(dcontext_okay(data));
    dbg_assert(psrv != NULL);

    if (len < 7) return RCODE_FORMAT_ERROR;

    psrv->priority = read_uint16(&data->parse);
    psrv->weight = read_uint16(&data->parse);
    psrv->port = read_uint16(&data->parse);
    return read_domain(data, &psrv->target);
}

/**********************************************************************/

static inline dns_rcode_t decode_rr_naptr(ddns_context *data, dns_naptr_t *pnaptr, size_t len) {
    dns_rcode_t rc;

    dbg_assert(dcontext_okay(data));
    dbg_assert(pnaptr != NULL);

    if (len < 4) return RCODE_FORMAT_ERROR;

    pnaptr->order = read_uint16(&data->parse);
    pnaptr->preference = read_uint16(&data->parse);

    rc = read_string(data, &pnaptr->flags);
    if (rc != RCODE_OKAY) return rc;
    rc = read_string(data, &pnaptr->services);
    if (rc != RCODE_OKAY) return rc;
    rc = read_string(data, &pnaptr->regexp);
    if (rc != RCODE_OKAY) return rc;
    return read_domain(data, &pnaptr->replacement);
}

/********************************************************************/

static inline dns_rcode_t decode_rr_minfo(ddns_context *data, dns_minfo_t *pminfo) {
    dns_rcode_t rc;

    dbg_assert(dcontext_okay(data));
    dbg_assert(pminfo != NULL);

    rc = read_domain(data, &pminfo->rmailbx);
    if (rc != RCODE_OKAY) return rc;
    return read_domain(data, &pminfo->emailbx);
}

/*****************************************************************/

static dns_rcode_t dloc_double(ddns_context *data, double *pvalue) {
    size_t len;

    dbg_assert(dcontext_okay(data));
    dbg_assert(pvalue != NULL);

    len = *data->parse.ptr;
    if (len > data->parse.size - 1) return RCODE_FORMAT_ERROR;

    /*-----------------------------------------------------------------------
    ; Microsoft C compilers don't support VLAs.  So I'm picking an arbitrary
    ; limit that hopefully won't break things.  I'm not sure what the actual
    ; length limit is for a double value (as a string to be parsed), so I
    ; checked some C code, found a 36 digit double number, then doubled that.
    ; Hopefully this is good enough.
    ;------------------------------------------------------------------------*/

    char buffer[72];

    if (len >= sizeof(buffer)) return RCODE_FORMAT_ERROR;

    memcpy(buffer, &data->parse.ptr[1], len);
    buffer[len++] = '\0';

    data->parse.ptr += len;
    data->parse.size -= len;

    errno = 0;
    *pvalue = strtod(buffer, NULL);
    if (errno) return RCODE_FORMAT_ERROR;

    return RCODE_OKAY;
}

/****************************************************************/

static void dgpos_angle(dnsgpos_angle *pa, double v) {
    double ip;

    v = modf(v, &ip) * 60.0;
    pa->deg = ip;
    v = modf(v, &ip) * 60.0;
    pa->min = ip;
    v = modf(v, &ip) * 1000.0;
    pa->sec = ip;
    pa->frac = v;
}

/*****************************************************************/

static inline dns_rcode_t decode_rr_gpos(ddns_context *data, dns_gpos_t *pgpos) {
    dns_rcode_t rc;
    double lat;
    double lng;

    dbg_assert(dcontext_okay(data));
    dbg_assert(pgpos != NULL);

    rc = dloc_double(data, &lng);
    if (rc != RCODE_OKAY) return rc;
    rc = dloc_double(data, &lat);
    if (rc != RCODE_OKAY) return rc;

    if (lng < 0.0) {
        pgpos->longitude.nw = true;
        lng = fabs(lng);
    } else
        pgpos->longitude.nw = false;

    if (lat >= 0.0)
        pgpos->latitude.nw = true;
    else {
        pgpos->latitude.nw = false;
        lat = fabs(lat);
    }

    dgpos_angle(&pgpos->longitude, lng);
    dgpos_angle(&pgpos->latitude, lat);

    return dloc_double(data, &pgpos->altitude);
}

/**************************************************************************
 *
 * You really, no, I mean it, *REALLY* need to read RFC-1876 to understand
 * all the crap that's going on for deciphering RR_LOC.
 *
 **************************************************************************/

static int dloc_scale(unsigned long long *presult, const int scale) {
    int spow;
    int smul;

    dbg_assert(presult != NULL);

    smul = scale >> 4;
    spow = scale & 0x0F;

    if ((spow > 9) || (smul > 9)) return RCODE_FORMAT_ERROR;

    *presult = (unsigned long)(pow(10.0, spow) * smul);
    return RCODE_OKAY;
}

/**************************************************************/

static void dloc_angle(dnsgpos_angle *pa, const long v) {
    ldiv_t partial;

    dbg_assert(pa != NULL);

    partial = ldiv(v, 1000L);
    pa->frac = partial.rem;
    partial = ldiv(partial.quot, 60L);
    pa->sec = partial.rem;
    partial = ldiv(partial.quot, 60L);
    pa->min = partial.rem;
    pa->deg = partial.quot;
}

/*************************************************************/

static inline dns_rcode_t decode_rr_loc(ddns_context *data, dns_loc_t *ploc, size_t len) {
    dns_rcode_t rc;
    unsigned long lat;
    unsigned long lng;

    dbg_assert(dcontext_okay(data));
    dbg_assert(ploc != NULL);

    if (len < 16) return RCODE_FORMAT_ERROR;

    ploc->version = data->parse.ptr[0];

    if (ploc->version != 0) return RCODE_FORMAT_ERROR;

    rc = dloc_scale(&ploc->size, data->parse.ptr[1]);
    if (rc != RCODE_OKAY) return rc;
    rc = dloc_scale(&ploc->horiz_pre, data->parse.ptr[2]);
    if (rc != RCODE_OKAY) return rc;
    rc = dloc_scale(&ploc->vert_pre, data->parse.ptr[3]);
    if (rc != RCODE_OKAY) return rc;

    data->parse.ptr += 4;

    lat = read_uint32(&data->parse);
    lng = read_uint32(&data->parse);
    ploc->altitude = read_uint32(&data->parse) - LOC_ALT_BIAS;

    if (lat >= LOC_BIAS) /* north */
    {
        ploc->latitude.nw = true;
        lat -= LOC_BIAS;
    } else {
        ploc->latitude.nw = false;
        lat = LOC_BIAS - lat;
    }

    if (lng >= LOC_BIAS) /* east */
    {
        ploc->longitude.nw = false;
        lng -= LOC_BIAS;
    } else {
        ploc->longitude.nw = true;
        lng = LOC_BIAS - lng;
    }

    if (lat > LOC_LAT_MAX) return RCODE_FORMAT_ERROR;

    if (lng > LOC_LNG_MAX) return RCODE_FORMAT_ERROR;

    dloc_angle(&ploc->latitude, lat);
    dloc_angle(&ploc->longitude, lng);

    return RCODE_OKAY;
}

/***************************************************************/

static inline dns_rcode_t decode_rr_opt(ddns_context *data, dns_edns0opt_t *opt, size_t len) {
    dbg_assert(data != NULL);
    dbg_assert(opt != NULL);

    if (data->edns) /* there can be only one */
        return RCODE_FORMAT_ERROR;

    data->edns = true;
    opt->numopts = 0;
    opt->opts = NULL;
    opt->version = (opt->ttl >> 16) & 0xFF;
    opt->z = ntohs(opt->ttl & 0xFFFF);
    data->response->rcode |= (opt->ttl >> 20) & 0x0FF0;

    if (len) {
        uint8_t *scan;
        size_t length;

        dbg_assert(dcontext_okay(data));
        dbg_assert(len > 4);

        for (scan = data->parse.ptr, opt->numopts = 0, length = len; length > 0;) {
            size_t size;

            opt->numopts++;
            size = ((scan[2] << 8) | (scan[3])) + 4;
            scan += size;

            if (size > length) return RCODE_FORMAT_ERROR;

            length -= size;
        }

        opt->opts = alloc_struct(&data->dest, sizeof(edns0_opt_t) * opt->numopts);
        if (opt->opts == NULL) return RCODE_NO_MEMORY;

        for (size_t i = 0; i < opt->numopts; i++) {
            dns_rcode_t rc;

            opt->opts[i].code = read_uint16(&data->parse);
            opt->opts[i].len = read_uint16(&data->parse);

            /*-----------------------------------------------------------------
            ; much like in read_raw(), we don't necessarily know the data we're
            ; reading, so why not align it?
            ;------------------------------------------------------------------*/

            if (!align_memory(&data->dest)) return RCODE_NO_MEMORY;

            opt->opts[i].data = data->dest.ptr;

            switch (opt->opts[i].code) {
                case EDNS0RR_NSID:
                    rc = decode_edns0rr_nsid(data, &opt->opts[i]);
                    break;
                default:
                    rc = decode_edns0rr_raw(data, &opt->opts[i]);
                    break;
            }

            if (rc != RCODE_OKAY) return rc;
        }
    }

    return RCODE_OKAY;
}

/**********************************************************************/

static dns_rcode_t decode_answer(ddns_context *data, dns_answer_t *pans) {
    size_t len;
    size_t rest;
    dns_rcode_t rc;

    dbg_assert(dcontext_okay(data));
    dbg_assert(pans != NULL);

    rc = read_domain(data, &pans->generic.name);
    if (rc != RCODE_OKAY) return rc;

    if (data->parse.size < 10) return RCODE_FORMAT_ERROR;

    pans->generic.type = read_uint16(&data->parse);

    /*-----------------------------------------------------------------
    ; RR_OPT is annoying, since the defined class and ttl fields are
    ; interpreted completely differently.  Thanks a lot, Paul Vixie!  So we
    ; need to special case this stuff a bit.
    ;----------------------------------------------------------------*/

    if (pans->generic.type == RR_OPT) {
        pans->generic.class = CLASS_UNKNOWN;
        pans->generic.ttl = 0;
        pans->opt.udp_payload = read_uint16(&data->parse);
        data->response->rcode = (data->parse.ptr[0] << 4) | data->response->rcode;

        if (data->parse.ptr[1] != 0) /* version */
            return RCODE_FORMAT_ERROR;

        /*--------------------------------------------------------------------
        ; RFC-3225 states that of octets 2 and 3, only the left-most bit
        ; of byte 2 is defined (the DO bit)---the rest are supposed to be
        ; 0.  But of *course* Google is using these bits for their own
        ; "don't be evil" purposes, whatever that might be.
        ;
        ; Thanks Google.  Thanks for being like Microsoft---embrace, extend and
        ; then extinquish.  Way to be not evil!
        ;---------------------------------------------------------------------*/

        data->parse.ptr += 2;
        data->parse.size -= 2;

        pans->opt.fug = read_uint16(&data->parse);
        pans->opt.fdo = pans->opt.fug > 0x7FFF;
        pans->opt.fug &= 0x7FFF;
    } else {
        pans->generic.class = read_uint16(&data->parse);
        pans->generic.ttl = read_uint32(&data->parse);
    }

    len = read_uint16(&data->parse);
    rest = data->packet.size - (data->parse.ptr - data->packet.ptr);

    if (len > rest) return RCODE_FORMAT_ERROR;

    switch (pans->generic.type) {
        case RR_A:
            return decode_rr_a(data, &pans->a, len);
        case RR_SOA:
            return decode_rr_soa(data, &pans->soa, len);
        case RR_NAPTR:
            return decode_rr_naptr(data, &pans->naptr, len);
        case RR_AAAA:
            return decode_rr_aaaa(data, &pans->aaaa, len);
        case RR_SRV:
            return decode_rr_srv(data, &pans->srv, len);
        case RR_WKS:
            return decode_rr_wks(data, &pans->wks, len);
        case RR_GPOS:
            return decode_rr_gpos(data, &pans->gpos);
        case RR_LOC:
            return decode_rr_loc(data, &pans->loc, len);
        case RR_OPT:
            return decode_rr_opt(data, &pans->opt, len);

            /*----------------------------------------------------------------------
            ; The following record types all share the same structure (although the
            ; last field name is different, depending upon the record), so they can
            ; share the same call site.  It's enough to shave some space in the
            ; executable while being a cheap and non-obscure size optimization, or
            ; a gross hack, depending upon your view.
            ;----------------------------------------------------------------------*/

        case RR_PX:
        case RR_RP:
        case RR_MINFO:
            return decode_rr_minfo(data, &pans->minfo);

        case RR_AFSDB:
        case RR_RT:
        case RR_MX:
            return decode_rr_mx(data, &pans->mx, len);

        case RR_NSAP:
        case RR_ISDN:
        case RR_HINFO:
            return decode_rr_hinfo(data, &pans->hinfo);

        case RR_X25:
        case RR_SPF:
        case RR_TXT:
            return decode_rr_txt(data, &pans->txt, len);

        case RR_NSAP_PTR:
        case RR_MD:
        case RR_MF:
        case RR_MB:
        case RR_MG:
        case RR_MR:
        case RR_NS:
        case RR_PTR:
        case RR_CNAME:
            return read_domain(data, &pans->cname.cname);

        case RR_NULL:
        default:
            pans->x.size = len;
            return read_raw(data, &pans->x.rawdata, len);
    }

    dbg_assert(0);
    return RCODE_OKAY;
}

/***********************************************************************/

dns_rcode_t dns_decode(dns_decoded_t *presponse, size_t *prsize, dns_packet_t const *buffer, size_t len) {
    struct idns_header const *header;
    dns_query_t *response;
    ddns_context context;
    dns_rcode_t rc;

    dbg_assert(presponse != NULL);
    dbg_assert(prsize != NULL);
    dbg_assert(*prsize >= sizeof(dns_query_t));
    dbg_assert(buffer != NULL);

    if (len < sizeof(struct idns_header)) return RCODE_FORMAT_ERROR;

    context.packet.ptr = (uint8_t *)buffer;
    context.packet.size = len;
    context.parse.ptr = &context.packet.ptr[sizeof(struct idns_header)];
    context.parse.size = len - sizeof(struct idns_header);
    context.dest.ptr = (uint8_t *)presponse;
    context.dest.size = *prsize;
    context.edns = false;

    /*--------------------------------------------------------------------------
    ; we use the block of data given to store the results.  context.dest
    ; contains this block and allocations are doled out from this.  This odd
    ; bit here sets the structure to the start of the block we're using, and
    ; then "allocates" the size f the structure in the context variable.  I do
    ; this as a test of the allocation routines when the address is already
    ; aligned (an assumption I'm making)---the calls to dbg_assert() ensure this
    ; behavior.
    ;--------------------------------------------------------------------------*/

    response = (dns_query_t *)context.dest.ptr;
    context.response = alloc_struct(&context.dest, sizeof(dns_query_t));

    dbg_assert(context.response != NULL);
    dbg_assert(context.response == response);

    memset(response, 0, sizeof(dns_query_t));
    response->questions = NULL;
    response->answers = NULL;
    response->nameservers = NULL;
    response->additional = NULL;

    header = (struct idns_header *)buffer;

    response->id = ntohs(header->id);
    response->opcode = (header->opcode >> 3) & 0x0F;
    response->query = (header->opcode & 0x80) != 0x80;
    response->aa = (header->opcode & 0x04) == 0x04;
    response->tc = (header->opcode & 0x02) == 0x02;
    response->rd = (header->opcode & 0x01) == 0x01;
    response->ra = (header->rcode & 0x80) == 0x80;
    response->z = (header->rcode & 0x40) == 0x40;
    response->ad = (header->rcode & 0x20) == 0x20;
    response->cd = (header->rcode & 0x10) == 0x10;
    response->rcode = (header->rcode & 0x0F);
    response->qdcount = ntohs(header->qdcount);
    response->ancount = ntohs(header->ancount);
    response->nscount = ntohs(header->nscount);
    response->arcount = ntohs(header->arcount);

    response->questions = alloc_struct(&context.dest, response->qdcount * sizeof(dns_question_t));
    response->answers = alloc_struct(&context.dest, response->ancount * sizeof(dns_answer_t));
    response->nameservers = alloc_struct(&context.dest, response->nscount * sizeof(dns_answer_t));
    response->additional = alloc_struct(&context.dest, response->arcount * sizeof(dns_answer_t));

    if ((response->qdcount && (response->questions == NULL)) || (response->ancount && (response->answers == NULL)) ||
        (response->nscount && (response->nameservers == NULL)) || (response->arcount && (response->additional == NULL))) {
        return RCODE_NO_MEMORY;
    }

    for (size_t i = 0; i < response->qdcount; i++) {
        rc = decode_question(&context, &response->questions[i]);
        if (rc != RCODE_OKAY) return rc;
    }

    for (size_t i = 0; i < response->ancount; i++) {
        rc = decode_answer(&context, &response->answers[i]);
        if (rc != RCODE_OKAY) return rc;
    }

    for (size_t i = 0; i < response->nscount; i++) {
        rc = decode_answer(&context, &response->nameservers[i]);
        if (rc != RCODE_OKAY) return rc;
    }

    for (size_t i = 0; i < response->arcount; i++) {
        rc = decode_answer(&context, &response->additional[i]);
        if (rc != RCODE_OKAY) return rc;
    }

    *prsize = (size_t)(context.dest.ptr - (uint8_t *)presponse);
    return RCODE_OKAY;
}

/************************************************************************/
