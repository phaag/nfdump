/*
 *  Copyright (c) 2012-2022, Peter Haag
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

/* definitions common to netflow v9 fnf and ipfix */

#ifndef _FNF_H
#define _FNF_H 1

#include "config.h"
#include "nfxV3.h"

typedef struct templateList_s {
    // linked list
    struct templateList_s *next;

    // template information
    time_t updated;  // last update/refresh of template
    uint32_t id;     // template ID
#define UNUSED_TEMPLATE 0
#define DATA_TEMPLATE 1
#define SAMPLER_TEMPLATE 2
#define NBAR_TEMPLATE 4
#define IFNAME_TEMPLATE 8
#define VRFNAME_TEMPLATE 16
#define SYSUPTIME_TEMPLATE 32
    uint32_t type;  // template type
    void *data;     // template data
} templateList_t;

typedef struct dataTemplate_s {
    // extension elements
    sequencer_t sequencer;
    // extension vector
    uint16_t *extensionList;

} dataTemplate_t;

typedef struct optionTag_s {
    uint16_t offset;
    uint16_t length;
} optionTag_t;

struct nameOptionList_s {
    uint16_t scopeSize;
    optionTag_t ingress;
    optionTag_t name;
};

typedef struct optionTemplate_s {
    uint64_t flags;  // info about this option template
    struct samplerOption_s {
#define STDSAMPLING34 1
#define STDSAMPLING35 2
#define STDMASK 0x3
#define STDFLAGS 0x3

#define SAMPLER302 4
#define SAMPLER304 8
#define SAMPLER305 16
#define SAMPLERMASK 0x1C
#define SAMPLERFLAGS 0x1C

        // sampling offset/length values
        optionTag_t id;
        optionTag_t mode;
        optionTag_t interval;
    } samplerOption;

#define NBAROPTIONS 32
    // nbar option data
    struct nbarOptionList_s {
        uint16_t scopeSize;
        optionTag_t id;
        optionTag_t name;
        optionTag_t desc;
    } nbarOption;

// ifname option
#define IFNAMEOPTION 64
    struct nameOptionList_s ifnameOption;

// vrfname option
#define VRFNAMEOPTION 128
    struct nameOptionList_s vrfnameOption;

#define SYSUPOPTION 256
    optionTag_t SysUpOption;

} optionTemplate_t;

#define GET_FLOWSET_ID(p) (Get_val16(p))
#define GET_FLOWSET_LENGTH(p) (Get_val16((void *)((p) + 2)))

#define GET_TEMPLATE_ID(p) (Get_val16(p))
#define GET_TEMPLATE_COUNT(p) (Get_val16((void *)((p) + 2)))

#define GET_OPTION_TEMPLATE_ID(p) (Get_val16(p))
#define GET_OPTION_TEMPLATE_FIELD_COUNT(p) (Get_val16((void *)((p) + 2)))
#define GET_OPTION_TEMPLATE_SCOPE_FIELD_COUNT(p) (Get_val16((void *)((p) + 4)))

#define CHECK_OPTION_DATA(avail, tag) ((tag.offset + tag.length) <= avail)

#define DYN_FIELD_LENGTH 65535

#endif
