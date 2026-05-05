/*
 *  Copyright (c) 2024-2026, Peter Haag
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

#include "filter.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "dns/dns.h"
#include "filter.h"
#include "ja3/ja3.h"
#include "ja4/ja4.h"
#include "logging.h"
#include "maxmind/maxmind.h"
#include "nfxV4.h"
#include "sgregex.h"
#include "tor/tor.h"
#include "util.h"

#define MAXBLOCKS 1024

static uint32_t memblocks;
static uint32_t NumBlocks = 1; /* index 0 reserved */
static int Extended = 0;
uint32_t StartNode = 0;

typedef uint64_t (*flow_proc_t)(void *, uint32_t, data_t, recordHandle_t *);

typedef void *(*preprocess_proc_t)(uint32_t, data_t, recordHandle_t *, filterOption_t);

// ── Build-time tree node (freed after generateByteCode)
typedef struct filterElement {
    uint32_t extID;
    uint32_t offset;
    uint32_t length;
    uint64_t value;
    uint32_t superblock;
    uint32_t *blocklist;
    uint32_t geoLookup;
    uint32_t numblocks;
    uint32_t OnTrue, OnFalse;
    int16_t invert;
    uint16_t option;
    comparator_t comp;
    filterFunction_t function;
    data_t data;
} filterElement_t;

// ── Runtime bytecode opcodes
typedef enum {
    /* terminals (always prog[0] and prog[1]) */
    FOP_ACCEPT = 0,
    FOP_REJECT,
    /* unconditional */
    FOP_ANY,
    FOP_ISSET,
    /* width-specialised equality */
    FOP_EQ1,
    FOP_EQ2,
    FOP_EQ4,
    FOP_EQ8,
    /* relational – common widths */
    FOP_GT1,
    FOP_GT2,
    FOP_GT4,
    FOP_GT8,
    FOP_LT1,
    FOP_LT2,
    FOP_LT4,
    FOP_LT8,
    FOP_GE1,
    FOP_GE2,
    FOP_GE4,
    FOP_GE8,
    FOP_LE1,
    FOP_LE2,
    FOP_LE4,
    FOP_LE8,
    /* bitmask */
    FOP_FLAGS,
    /* network/prefix: (field & dataVal) == value */
    FOP_NET4,
    FOP_NET8,
    /* set membership (runtime IPSet_t / U64Set_t) */
    FOP_IPLIST,
    FOP_U64LIST,
    /* string comparisons */
    FOP_IDENT,
    FOP_STRING,
    FOP_SUBSTRING,
    FOP_BINARY,
    /* payload */
    FOP_PAYLOAD,
    FOP_REGEX,
    /* geo (dataVal = direction) */
    FOP_GEO,
    /* DNS */
    FOP_DNSNAME,
    FOP_DNSIP,
    /* function-derived value + compare (fnID selects function) */
    FOP_FUNC_EQ,
    FOP_FUNC_GT,
    FOP_FUNC_LT,
    FOP_FUNC_GE,
    FOP_FUNC_LE,
    /* preprocess-then-compare variants (for EXasInfoID / EXin|outPayloadHandle) */
    FOP_PREP_ISSET,
    FOP_PREP_EQ1,
    FOP_PREP_EQ2,
    FOP_PREP_EQ4,
    FOP_PREP_EQ8,
    FOP_PREP_GT8,
    FOP_PREP_LT8,
    FOP_PREP_GE8,
    FOP_PREP_LE8,
    FOP_PREP_FLAGS,
    FOP_PREP_STRING,
    FOP_PREP_SUBSTRING,
    FOP_PREP_BINARY,
    FOP_PREP_GEO,
    FOP_PREP_DNSNAME,
    FOP_PREP_DNSIP,
    FOP_PREP_PAYLOAD,
    FOP_PREP_REGEX,
    FOP__COUNT
} filterOp_t;

/*
 * Runtime instruction – 32 bytes on 64-bit systems, exactly 2 per cache line.
 *
 *  op        filterOp_t – selects computed-goto label
 *  extID     index into handle->extensionList[]
 *  fnID      filterFunction_t – index into flow_procs_map[] for FOP_FUNC_*
 *  length    field byte width (1/2/4/8); 0 = extension-present check
 *  option    filterOption_t – passed to preprocess for FOP_PREP_*
 *  offset    byte offset within the extension struct (fits in uint16_t)
 *  onTrue    program index to jump to when result == 1  (0 = ACCEPT)
 *  onFalse   program index to jump to when result == 0  (1 = REJECT)
 *  value     comparison value or pre-masked network address
 *  aux       data pointer: IPSet_t*, U64Set_t*, char*, srx_Context*, …
 *            – OR –
 *  dataVal   auxiliary integer: subnet mask, geo direction, fn data.dataVal
 *            (aux and dataVal are in a union; no op uses both)
 */
typedef struct filterInstr_s {
    const void *handler; /* direct-threaded label address – goto *inst->handler */
    uint16_t op;         /* opcode (kept for DumpEngine / DisposeFilter) */
    uint8_t extID;
    uint8_t fnID;
    uint8_t length;
    uint8_t option;
    uint16_t offset;
    uint16_t onTrue;
    uint16_t onFalse;
    uint32_t _pad; /* explicit padding – keeps value 8-byte aligned */
    uint64_t value;
    union {
        uintptr_t aux;   /* data pointer */
        int64_t dataVal; /* mask / direction / fnData.dataVal */
    };
} filterInstr_t;

_Static_assert(sizeof(filterInstr_t) == 40, "filterInstr_t must be 40 bytes");

/* Module-global dispatch table for direct threading.
 * Populated once by InitFilterDispatch() (via RunFilter in init mode)
 * before any CompileFilter() call.  Never modified after that. */
static const void *g_jt[FOP__COUNT];

/*
 * Runtime engine.  prog[] is immutable after CompileFilter() and shared
 * between the original and all FilterCloneEngine() copies (thread-safe).
 * Only ident is per-clone (strdup'd).
 */
typedef struct FilterEngine_s {
    filterInstr_t *prog; /* bytecode program – shared, read-only */
    uint32_t progLen;    /* number of instructions (includes terminals) */
    uint32_t startNode;
    int hasGeoDB;
    const char *ident;
} FilterEngine_t;

static filterElement_t *FilterTree = NULL;

static void UpdateList(uint32_t a, uint32_t b);

/* flow processing functions */
static uint64_t duration_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle);
static uint64_t pps_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle);
static uint64_t bps_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle);
static uint64_t bpp_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle);
static uint64_t mpls_label_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle);
static uint64_t mpls_eos_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle);
static uint64_t mpls_exp_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle);
static uint64_t mpls_any_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle);
static uint64_t pblock_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle);
static uint64_t mmASLookup_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle);
static uint64_t torLookup_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle);
static uint64_t ttlEqual_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle);

/* flow pre-processing functions */
static void *as_preproc(uint32_t length, data_t data, recordHandle_t *handle, filterOption_t option);
static void *inPayload_preproc(uint32_t length, data_t data, recordHandle_t *handle, filterOption_t option);
static void *outPayload_preproc(uint32_t length, data_t data, recordHandle_t *handle, filterOption_t option);

/*
 * flow processing function table:
 */

static struct flow_procs_map_s {
    char *name;
    flow_proc_t function;
} const flow_procs_map[] = {[FUNC_NONE] = {"none", NULL},
                            [FUNC_DURATION] = {"duration", duration_function},
                            [FUNC_PPS] = {"pps", pps_function},
                            [FUNC_BPS] = {"bps", bps_function},
                            [FUNC_BPP] = {"bpp", bpp_function},
                            [FUNC_MPLS_LABEL] = {"mpls label", mpls_label_function},
                            [FUNC_MPLS_EOS] = {"mpls eos", mpls_eos_function},
                            [FUNC_MPLS_EXP] = {"mpls exp", mpls_exp_function},
                            [FUNC_MPLS_ANY] = {"mpls any", mpls_any_function},
                            [FUNC_PBLOCK] = {"pblock", pblock_function},
                            [FUNC_MMAS_LOOKUP] = {"AS Lookup", mmASLookup_function},
                            [FUNC_TOR_LOOKUP] = {"TOR Lookup", torLookup_function},
                            [FUNC_JA3] = {"ja3", NULL},
                            [FUNC_TTL_EQUAL] = {"min/max TTL equal", ttlEqual_function},
                            {NULL, NULL}};

static struct preprocess_s {
    preprocess_proc_t function;
} const preprocess_map[MAXLISTSIZE] = {
    [EXasInfoID] = {as_preproc}, [EXinPayloadHandle] = {inPayload_preproc}, [EXoutPayloadHandle] = {outPayload_preproc}};

// 128bit compare for IPv6
static int IPNodeCMP(struct IPListNode *e1, struct IPListNode *e2) {
    uint64_t ip_e1[2], ip_e2[2];
    ip_e1[0] = e1->ip[0] & e2->mask[0];
    ip_e1[1] = e1->ip[1] & e2->mask[1];

    ip_e2[0] = e2->ip[0] & e1->mask[0];
    ip_e2[1] = e2->ip[1] & e1->mask[1];

    if (ip_e1[0] == ip_e2[0]) {
        if (ip_e1[1] == ip_e2[1])
            return 0;
        else
            return (ip_e1[1] < ip_e2[1] ? -1 : 1);
    } else {
        return (ip_e1[0] < ip_e2[0] ? -1 : 1);
    }

}  // End of IPNodeCMP

// 64bit uint64_t compare
static int U64NodeCMP(struct U64ListNode *e1, struct U64ListNode *e2) {
    if (e1->value == e2->value)
        return 0;
    else
        return (e1->value < e2->value ? -1 : 1);

}  // End of Uint64NodeCMP

RB_GENERATE(IPtree, IPListNode, entry, IPNodeCMP);
RB_GENERATE(U64tree, U64ListNode, entry, U64NodeCMP);

static uint64_t duration_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)handle->extensionList[EXgenericFlowID];

    // duration in msec
    return genericFlow->msecLast - genericFlow->msecFirst;
}  // End of duration_function

static uint64_t pps_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)handle->extensionList[EXgenericFlowID];

    /* duration in msec */
    uint64_t duration = genericFlow->msecLast - genericFlow->msecFirst;
    if (duration == 0)
        return 0;
    else
        return (1000LL * genericFlow->inPackets) / duration;

}  // End of pps_function

static uint64_t bps_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)handle->extensionList[EXgenericFlowID];

    /* duration in msec */
    uint64_t duration = genericFlow->msecLast - genericFlow->msecFirst;
    if (duration == 0)
        return 0;
    else
        // 8 bits per Octet - x 1000 for msec
        return (8000LL * genericFlow->inBytes) / duration;

}  // End of bps_function

static uint64_t bpp_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)handle->extensionList[EXgenericFlowID];

    return genericFlow->inPackets ? genericFlow->inBytes / genericFlow->inPackets : 0;

}  // End of bpp_function

static uint64_t mpls_label_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle) {
    EXmpls_t *mpls = (EXmpls_t *)handle->extensionList[EXmplsID];
    int64_t labelID = data.dataVal;

    return mpls->label[labelID] >> 4;

}  // End of mpls_label_function

static uint64_t mpls_eos_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle) {
    EXmpls_t *mpls = (EXmpls_t *)handle->extensionList[EXmplsID];

    // search for end of MPLS stack label
    for (int i = 0; i < 10; i++) {
        if (mpls->label[i] & 1) {
            // End of stack found -> return label
            return mpls->label[i] >> 4;
        }
    }

    // if no match above, trick filter to fail with an invalid mpls label value
    return 0xFF000000;

}  // End of mpls_eos_function

static uint64_t mpls_exp_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle) {
    EXmpls_t *mpls = (EXmpls_t *)handle->extensionList[EXmplsID];

    uint32_t offset = data.dataVal;
    return (mpls->label[offset] >> 1) & 0x7;

}  // End of mpls_exp_function

static uint64_t mpls_any_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle) {
    EXmpls_t *mpls = (EXmpls_t *)handle->extensionList[EXmplsID];
    int64_t labelValue = data.dataVal;

    // search for end of MPLS stack label
    for (int i = 0; i < 10; i++) {
        if ((mpls->label[i] >> 4) == labelValue) {
            // Found matching label
            return mpls->label[i] >> 4;
        }
    }

    // if no match above, trick filter to fail with an invalid mpls label value
    return 0xFF000000;

}  // End of mpls_any_function

static uint64_t pblock_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle) {
    EXnatPortBlock_t *natPortBlock = (EXnatPortBlock_t *)handle->extensionList[EXnatPortBlockID];

    if (!natPortBlock) return 0;

    uint16_t port = *((uint16_t *)dataPtr);

    return (port >= natPortBlock->blockStart && port <= natPortBlock->blockEnd);

}  // End of pblock_function

static uint64_t mmASLookup_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *recordHandle) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];
    uint32_t as = *((uint32_t *)dataPtr);
    if (as) return as;

    uint32_t direction = data.dataVal;
    if (ipv4Flow) {
        as = direction == OFFsrcAS ? LookupV4AS(ipv4Flow->srcAddr) : LookupV4AS(ipv4Flow->dstAddr);
    } else if (ipv6Flow) {
        as = direction == OFFsrcAS ? LookupV6AS(ipv6Flow->srcAddr) : LookupV6AS(ipv6Flow->dstAddr);
    }
    *((uint32_t *)dataPtr) = as;

    return as;
}  // End of mmASLookup_function

static uint64_t torLookup_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    if (!genericFlow) return 0;

    uint64_t isTor = 0;
    char info[4];
    if (length == 4) {  // IPv4
        uint32_t IPv4 = *((uint32_t *)dataPtr);
        isTor = LookupV4Tor(IPv4, genericFlow->msecFirst, genericFlow->msecLast, info);
    } else if (length == 16) {  // IPv6
        isTor = LookupV6Tor((uint64_t *)dataPtr, genericFlow->msecFirst, genericFlow->msecLast, info);
    }

    return isTor;
}  // End of torLookup_function

static uint64_t ttlEqual_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *recordHandle) {
    EXipInfo_t *ipInfo = (EXipInfo_t *)recordHandle->extensionList[EXipInfoID];
    if (ipInfo == NULL) return 0;

    return ipInfo->minTTL == ipInfo->maxTTL;
}  // End of ttlEqual_function

static void *dns_preproc(const EXPayload_t *payload, payloadHandle_t *payloadHandle, recordHandle_t *recordHandle) {
    uint32_t payloadLength = payload->size;
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)(recordHandle->extensionList[EXgenericFlowID]);
    if (!genericFlow) return NULL;
    if (genericFlow->srcPort != 53 && genericFlow->dstPort != 53) return NULL;

    void *dns = NULL;
    if (genericFlow->proto == IPPROTO_TCP)
        dns = dnsPayloadDecode(payload->payload + 2, payloadLength - 2);
    else
        dns = dnsPayloadDecode(payload->payload, payloadLength);
    payloadHandle->dns = dns;
    return dns;

}  // End of dns_preproc

static void *ssl_preproc(const EXPayload_t *payload, payloadHandle_t *payloadHandle, recordHandle_t *recordHandle) {
    uint32_t payloadLength = payload->size;
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)(recordHandle->extensionList[EXgenericFlowID]);
    if (!genericFlow) return NULL;

    ssl_t *ssl = NULL;
    if (genericFlow->proto == IPPROTO_TCP) ssl = sslProcess(payload->payload, payloadLength);
    payloadHandle->ssl = ssl;
    return ssl;

}  // End of ssl_preproc

static void *ja3_preproc(const EXPayload_t *payload, payloadHandle_t *payloadHandle, recordHandle_t *recordHandle) {
    ssl_t *ssl = (ssl_t *)payloadHandle->ssl;
    if (ssl == NULL) ssl = ssl_preproc(payload, payloadHandle, recordHandle);
    if (!ssl) return NULL;

    payloadHandle->ja3 = ja3Process(ssl, NULL);

    return payloadHandle->ja3;

}  // End of ja3_preproc

static void *ja4_preproc(const EXPayload_t *payload, payloadHandle_t *payloadHandle, recordHandle_t *recordHandle) {
    ssl_t *ssl = (ssl_t *)payloadHandle->ssl;
    if (ssl == NULL) ssl = ssl_preproc(payload, payloadHandle, recordHandle);
    if (!ssl) return NULL;

    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)(recordHandle->extensionList[EXgenericFlowID]);
    if (!genericFlow) return NULL;

    ja4_t *ja4 = NULL;
    if (ssl->type == CLIENTssl) {
        ja4 = ja4Process(ssl, genericFlow->proto);
    } else {
        ja4 = ja4sProcess(ssl, genericFlow->proto);
    }
    payloadHandle->ja4 = ja4;

    return ja4;

}  // End of ja4_preproc

static void *inPayload_preproc(uint32_t length, data_t data, recordHandle_t *recordHandle, filterOption_t option) {
    const EXPayload_t *payload = (EXPayload_t *)(recordHandle->extensionList[EXinPayloadID]);
    if (payload == NULL) return NULL;

    payloadHandle_t *payloadHandle = (void *)(recordHandle->extensionList[EXinPayloadHandle]);
    if (payloadHandle == NULL) {
        payloadHandle = calloc(1, sizeof(payloadHandle_t));
        if (!payloadHandle) {
            LogError("malloc() allocation error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return NULL;
        }
        recordHandle->extensionList[EXinPayloadHandle] = payloadHandle;
    }

    void *ptr = NULL;
    switch (option) {
        case OPT_NONE:
            return ptr;
            break;
        case OPT_DNS:
            if (payloadHandle->dns == NULL) dns_preproc(payload, payloadHandle, recordHandle);
            ptr = payloadHandle->dns;
            break;
        case OPT_SSL:
            if (payloadHandle->ssl == NULL) ssl_preproc(payload, payloadHandle, recordHandle);
            ptr = payloadHandle->ssl;
            break;
        case OPT_JA3:
            if (payloadHandle->ja3 == NULL) ja3_preproc(payload, payloadHandle, recordHandle);
            ptr = payloadHandle->ja3;
            break;
        case OPT_JA4:
            if (payloadHandle->ja4 == NULL) ja4_preproc(payload, payloadHandle, recordHandle);
            ptr = payloadHandle->ja4;
            break;
        default:
            return ptr;
    }

    return ptr;
}  // End of inPayload_preproc

static void *outPayload_preproc(uint32_t length, data_t data, recordHandle_t *recordHandle, filterOption_t option) {
    const EXPayload_t *payload = (EXPayload_t *)(recordHandle->extensionList[EXoutPayloadID]);
    if (payload == NULL) return NULL;

    payloadHandle_t *payloadHandle = (void *)(recordHandle->extensionList[EXoutPayloadHandle]);
    if (payloadHandle == NULL) {
        payloadHandle = calloc(1, sizeof(payloadHandle_t));
        if (!payloadHandle) {
            LogError("malloc() allocation error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return NULL;
        }
        recordHandle->extensionList[EXoutPayloadHandle] = payloadHandle;
    }

    void *ptr = NULL;
    switch (option) {
        case OPT_NONE:
            return ptr;
            break;
        case OPT_DNS:
            if (payloadHandle->dns == NULL) dns_preproc(payload, payloadHandle, recordHandle);
            ptr = payloadHandle->dns;
            break;
        case OPT_SSL:
            if (payloadHandle->ssl == NULL) ssl_preproc(payload, payloadHandle, recordHandle);
            ptr = payloadHandle->ssl;
            break;
        case OPT_JA3:
            if (payloadHandle->ja3 == NULL) ja3_preproc(payload, payloadHandle, recordHandle);
            ptr = payloadHandle->ja3;
            break;
        case OPT_JA4:
            if (payloadHandle->ja4 == NULL) ja4_preproc(payload, payloadHandle, recordHandle);
            ptr = payloadHandle->ja4;
            break;
        default:
            return ptr;
    }

    return ptr;
}  // End of outPayload_preproc

static void *as_preproc(uint32_t length, data_t data, recordHandle_t *handle, filterOption_t option) {
    // no AS field, map slack
    handle->extensionList[EXasInfoID] = handle->localStack;
    return (void *)handle->localStack;
}  // End of as_preproc

static int geoLookup(char *geoChar, uint64_t direction, recordHandle_t *recordHandle) {
    geoChar[0] = geoChar[1] = '.';
    switch (direction) {
        case DIR_SRC: {
            EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
            EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];
            if (ipv4Flow) {
                LookupV4Country(ipv4Flow->srcAddr, geoChar);
            } else if (ipv6Flow) {
                LookupV6Country(ipv6Flow->srcAddr, geoChar);
            }
        } break;
        case DIR_DST: {
            EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
            EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];
            if (ipv4Flow) {
                LookupV4Country(ipv4Flow->dstAddr, geoChar);
            } else if (ipv6Flow) {
                LookupV6Country(ipv6Flow->dstAddr, geoChar);
            }
        } break;
        case DIR_SRC_NAT: {
            EXnatXlateV4_t *natXlateV4 = (EXnatXlateV4_t *)recordHandle->extensionList[EXnatXlateV4ID];
            EXnatXlateV6_t *natXlateIPv6 = (EXnatXlateV6_t *)recordHandle->extensionList[EXnatXlateV6ID];
            if (natXlateV4) {
                LookupV4Country(natXlateV4->xlateSrcAddr, geoChar);
            } else if (natXlateIPv6) {
                LookupV6Country(natXlateIPv6->xlateSrcAddr, geoChar);
            }
        } break;
        case DIR_DST_NAT: {
            EXnatXlateV4_t *natXlateV4 = (EXnatXlateV4_t *)recordHandle->extensionList[EXnatXlateV4ID];
            EXnatXlateV6_t *natXlateV6 = (EXnatXlateV6_t *)recordHandle->extensionList[EXnatXlateV6ID];
            if (natXlateV4) {
                LookupV4Country(natXlateV4->xlateDstAddr, geoChar);
            } else if (natXlateV6) {
                LookupV6Country(natXlateV6->xlateDstAddr, geoChar);
            }
        } break;
        case DIR_SRC_TUN: {
            EXtunnelV4_t *tunV4 = (EXtunnelV4_t *)recordHandle->extensionList[EXtunnelV4ID];
            EXtunnelV6_t *tunV6 = (EXtunnelV6_t *)recordHandle->extensionList[EXtunnelV6ID];
            if (tunV4) {
                LookupV4Country(tunV4->srcAddr, geoChar);
            } else if (tunV6) {
                LookupV6Country(tunV6->srcAddr, geoChar);
            }
        } break;
        case DIR_DST_TUN: {
            EXtunnelV4_t *tunV4 = (EXtunnelV4_t *)recordHandle->extensionList[EXtunnelV4ID];
            EXtunnelV6_t *tunV6 = (EXtunnelV6_t *)recordHandle->extensionList[EXtunnelV6ID];
            if (tunV4) {
                LookupV4Country(tunV4->dstAddr, geoChar);
            } else if (tunV6) {
                LookupV6Country(tunV6->dstAddr, geoChar);
            }
        } break;
    }
    return *((uint16_t *)(geoChar));

}  // End of geoLookup

/*
 * Returns next free slot in blocklist
 */
uint32_t NewElement(uint32_t extID, uint32_t offset, uint32_t length, uint64_t value, comparator_t comp, filterFunction_t function, data_t data) {
    uint32_t n = NumBlocks;

    if (n >= (memblocks * MAXBLOCKS)) {
        memblocks++;
        FilterTree = realloc(FilterTree, memblocks * MAXBLOCKS * sizeof(filterElement_t));
        if (!FilterTree) {
            LogError("Memory allocation error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            exit(255);
        }
    }
    dbg_printf("New element: extID: %u, offset: %u, length: %u, value: %" PRIu64 " 0x%" PRIx64 "\n", extID, offset, length, value, value);

    FilterTree[n] = (filterElement_t){
        .extID = extID,
        .offset = offset,
        .length = length,
        .value = value,
        .invert = 0,
        .option = OPT_NONE,
        .OnTrue = 0,
        .OnFalse = 0,
        .comp = comp,
        .function = function,
        .data = data,
        .numblocks = 1,
        .blocklist = (uint32_t *)malloc(sizeof(uint32_t)),
        .superblock = n,
    };
    FilterTree[n].blocklist[0] = n;

    if (comp > 0 || function > 0 || extID > EXheader) Extended = 1;
    NumBlocks++;
    return n;

} /* End of NewElement */

void SetElementOption(uint32_t elementID, filterOption_t option) {
    // assigne option
    FilterTree[elementID].option = option;
}  // End of SetElementOption

/*
 * Inverts OnTrue and OnFalse
 */
uint32_t Invert(uint32_t a) {
    uint32_t i, j;

    for (i = 0; i < FilterTree[a].numblocks; i++) {
        j = FilterTree[a].blocklist[i];
        FilterTree[j].invert = FilterTree[j].invert ? 0 : 1;
    }
    return a;

} /* End of Invert */

/*
 * Connects the two blocks b1 and b2 ( AND ) and returns index of superblock
 */
uint32_t Connect_AND(uint32_t b1, uint32_t b2) {
    uint32_t a, b, i, j;

    // do not optimise blocks if block 'any' is appended
    if ((FilterTree[b2].data.dataVal == -1) || (FilterTree[b1].numblocks <= FilterTree[b2].numblocks)) {
        a = b1;
        b = b2;
    } else {
        a = b2;
        b = b1;
    }
    /* a points to block with less children and becomes the superblock
     * connect b to a
     */
    for (i = 0; i < FilterTree[a].numblocks; i++) {
        j = FilterTree[a].blocklist[i];
        if (FilterTree[j].invert) {
            if (FilterTree[j].OnFalse == 0) {
                FilterTree[j].OnFalse = b;
            }
        } else {
            if (FilterTree[j].OnTrue == 0) {
                FilterTree[j].OnTrue = b;
            }
        }
    }
    UpdateList(a, b);
    return a;

} /* End of Connect_AND */

/*
 * Connects the two blocks b1 and b2 ( OR ) and returns index of superblock
 */
uint32_t Connect_OR(uint32_t b1, uint32_t b2) {
    uint32_t a, b, i, j;

    // do not optimise block 'any' if appended as lastelement
    // for all prepending blocks to be evaluated.
    if ((FilterTree[b2].data.dataVal == -1) || (FilterTree[b1].numblocks <= FilterTree[b2].numblocks)) {
        a = b1;
        b = b2;
    } else {
        a = b2;
        b = b1;
    }
    /* a points to block with less children and becomes the superblock
     * connect b to a
     */
    for (i = 0; i < FilterTree[a].numblocks; i++) {
        j = FilterTree[a].blocklist[i];
        if (FilterTree[j].invert) {
            if (FilterTree[j].OnTrue == 0) {
                FilterTree[j].OnTrue = b;
            }
        } else {
            if (FilterTree[j].OnFalse == 0) {
                FilterTree[j].OnFalse = b;
            }
        }
    }
    UpdateList(a, b);
    return a;

} /* End of Connect_OR */

/*
 * Update supernode infos:
 * node 'b' was connected to 'a'. update node 'a' supernode data
 */
static void UpdateList(uint32_t a, uint32_t b) {
    /* numblocks contains the number of blocks in the superblock */
    uint32_t s = FilterTree[a].numblocks + FilterTree[b].numblocks;
    FilterTree[a].blocklist = (uint32_t *)realloc(FilterTree[a].blocklist, s * sizeof(uint32_t));
    if (!FilterTree[a].blocklist) {
        LogError("Memory allocation error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        exit(250);
    }

    /* connect list of node 'b' after list of node 'a' */
    uint32_t j = FilterTree[a].numblocks;
    for (int i = 0; i < (int)FilterTree[b].numblocks; i++) {
        FilterTree[a].blocklist[j + i] = FilterTree[b].blocklist[i];
    }
    FilterTree[a].numblocks = s;

    /* set superblock info of all children to new superblock */
    for (int i = 0; i < (int)FilterTree[a].numblocks; i++) {
        j = FilterTree[a].blocklist[i];
        FilterTree[j].superblock = a;
    }

    /* cleanup old node 'b' */
    FilterTree[b].numblocks = 0;
    free(FilterTree[b].blocklist);
    FilterTree[b].blocklist = NULL;

} /* End of UpdateList */

/*
 * Clear Filter
 */
static void ClearFilter(void) {
    NumBlocks = 1;
    Extended = 0;
    size_t total = memblocks * MAXBLOCKS;
    memset(FilterTree, 0, total * sizeof(filterElement_t));
}  // End of ClearFilter

static void InitFilter(void) {
    memblocks = 1;
    FilterTree = (filterElement_t *)malloc(MAXBLOCKS * sizeof(filterElement_t));
    if (!FilterTree) {
        LogError("Memory allocation error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        exit(255);
    }
    ClearFilter();
}  // End of InitFilter

/* ═══════════════════════════════════════════════════════════════════════════
 * Runtime IP/U64 set helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ── Runtime IP/U64 set types (internal to filter.c only) ────────────── */

/* One entry in the flat hash table or CIDR array.
 * 32 bytes = exactly one half cache line. */
typedef struct {
    uint64_t ip[2];   /* ip[0]=0 for IPv4 (uses only ip[1]) */
    uint64_t mask[2]; /* all-ones for exact entries */
} IPEntry_t;

/* Hybrid IP set: open-addressing hash table for exact IPs (O(1))
 * plus a flat array for CIDR prefixes (O(k), k≈0-5 in practice). */
typedef struct {
    uint32_t htSize;    /* hash table capacity (power-of-2), 0 = no exact entries */
    uint32_t cidrCount; /* number of CIDR prefix entries */
    IPEntry_t *ht;      /* flat hash table; slot is empty when ip[0]|ip[1]==0 */
    IPEntry_t cidr[];   /* flat CIDR array; stores (ip&mask, mask) */
} IPSet_t;

/* Sorted flat array for uint64 sets (ports, AS numbers, …).
 * Binary search is O(log n) with sequential memory access. */
typedef struct {
    uint32_t count;
    uint64_t values[]; /* flexible array, sorted ascending */
} U64Set_t;

static inline int isExactIP(const struct IPListNode *n) { return n->mask[0] == 0xffffffffffffffffULL && n->mask[1] == 0xffffffffffffffffULL; }

static uint32_t nextPow2_u32(uint32_t num) {
    if (num <= 1) return 1;
    if ((num & (num - 1)) == 0) return num;

    // __builtin_clz returns number of leading zeros
    return 1u << (32 - __builtin_clz(num - 1));
}  // End of ceil_power_of_2

/* Open-addressing insert into a calloc'd hash table (ip={0,0} = empty). */
static void ipHtInsert(IPEntry_t *ht, uint32_t htSize, uint64_t ip0, uint64_t ip1) {
    uint64_t h = ip0 * 0x9e3779b97f4a7c15ULL ^ ip1 * 0x6c62272e07bb0142ULL;
    uint32_t idx = (uint32_t)(h >> 32) & (htSize - 1);
    while (ht[idx].ip[0] | ht[idx].ip[1]) idx = (idx + 1) & (htSize - 1);
    ht[idx].ip[0] = ip0;
    ht[idx].ip[1] = ip1;
    ht[idx].mask[0] = ht[idx].mask[1] = 0xffffffffffffffffULL;
}

/*
 * Build a runtime IPSet_t from a build-time IPlist_t (RB-tree).
 * Exact entries go into a hash table (O(1) lookup).
 * CIDR entries go into a flat array (O(k) linear scan, k is usually tiny).
 * The RB-tree nodes are freed; the root is freed.
 */
static IPSet_t *buildIPSet(IPlist_t *root) {
    if (!root) return NULL;

    uint32_t exact_n = 0, cidr_n = 0;
    struct IPListNode *node;
    RB_FOREACH(node, IPtree, root) {
        if (isExactIP(node))
            exact_n++;
        else
            cidr_n++;
    }

    IPSet_t *set = calloc(1, sizeof(IPSet_t) + cidr_n * sizeof(IPEntry_t));
    if (!set) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    if (exact_n > 0) {
        set->htSize = nextPow2_u32(exact_n * 2 + 1);
        set->ht = calloc(set->htSize, sizeof(IPEntry_t));
        if (!set->ht) {
            free(set);
            return NULL;
        }
    }

    RB_FOREACH(node, IPtree, root) {
        if (isExactIP(node)) {
            ipHtInsert(set->ht, set->htSize, node->ip[0], node->ip[1]);
        } else {
            IPEntry_t *e = &set->cidr[set->cidrCount++];
            e->ip[0] = node->ip[0] & node->mask[0];
            e->ip[1] = node->ip[1] & node->mask[1];
            e->mask[0] = node->mask[0];
            e->mask[1] = node->mask[1];
        }
    }

    /* free RB-tree nodes */
    struct IPListNode *tmp;
    while ((tmp = RB_MIN(IPtree, root)) != NULL) {
        RB_REMOVE(IPtree, root, tmp);
        free(tmp);
    }
    free(root);
    return set;
}  // End of buildIPSet

static void freeIPSet(IPSet_t *set) {
    if (!set) return;
    free(set->ht);
    free(set);
}

/*
 * O(1) average IP membership test.
 * IPv4: ip0=0, ip1=addr32.  IPv6: ip0=high64, ip1=low64.
 */
static inline int IPSetContains(const IPSet_t *set, uint64_t ip0, uint64_t ip1) {
    /* 1 – exact hash table lookup */
    if (set->htSize > 0) {
        uint64_t h = ip0 * 0x9e3779b97f4a7c15ULL ^ ip1 * 0x6c62272e07bb0142ULL;
        uint32_t idx = (uint32_t)(h >> 32) & (set->htSize - 1);
        while (set->ht[idx].ip[0] | set->ht[idx].ip[1]) {
            if (set->ht[idx].ip[0] == ip0 && set->ht[idx].ip[1] == ip1) return 1;
            idx = (idx + 1) & (set->htSize - 1);
        }
    }
    /* 2 – CIDR linear scan (typically 0–few entries) */
    for (uint32_t i = 0; i < set->cidrCount; i++) {
        if ((ip0 & set->cidr[i].mask[0]) == set->cidr[i].ip[0] && (ip1 & set->cidr[i].mask[1]) == set->cidr[i].ip[1]) return 1;
    }
    return 0;
}  // End of IPSetContains

/* qsort comparator for uint64_t */
static int u64cmp(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

/*
 * Build a sorted flat U64Set_t from a U64List_t (RB-tree).
 * Binary search gives O(log n) with cache-friendly sequential access.
 * The RB-tree nodes are freed; the root is freed.
 */
static U64Set_t *buildU64Set(U64List_t *root) {
    if (!root) return NULL;

    uint32_t n = 0;
    struct U64ListNode *node;
    RB_FOREACH(node, U64tree, root) n++;

    U64Set_t *set = malloc(sizeof(U64Set_t) + n * sizeof(uint64_t));
    if (!set) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }
    set->count = n;

    uint32_t i = 0;
    RB_FOREACH(node, U64tree, root) set->values[i++] = node->value;

    qsort(set->values, n, sizeof(uint64_t), u64cmp);

    struct U64ListNode *tmp;
    while ((tmp = RB_MIN(U64tree, root)) != NULL) {
        RB_REMOVE(U64tree, root, tmp);
        free(tmp);
    }
    free(root);
    return set;
}  // End of buildU64Set

static void freeU64Set(U64Set_t *set) { free(set); }

/* Binary search on sorted flat array. */
static inline int U64SetContains(const U64Set_t *set, uint64_t val) {
    uint32_t lo = 0, hi = set->count;
    while (lo < hi) {
        uint32_t mid = (lo + hi) >> 1;
        if (set->values[mid] < val)
            lo = mid + 1;
        else if (set->values[mid] > val)
            hi = mid;
        else
            return 1;
    }
    return 0;
}  // End of U64SetContains

/* ═══════════════════════════════════════════════════════════════════════════
 * Bytecode emission: convert filterElement_t tree → filterInstr_t program
 * ═══════════════════════════════════════════════════════════════════════════ */

#define BC_ACCEPT 0 /* prog[0] = FOP_ACCEPT */
#define BC_REJECT 1 /* prog[1] = FOP_REJECT */
#define BC_UNSET 0xffff

/* Choose the filterOp_t for a tree node.
 * Encodes comp + length (+ preprocess / function) into a single opcode. */
static filterOp_t chooseOpcode(const filterElement_t *e) {
    bool has_func = (e->function != FUNC_NONE);
    bool has_prep = ((filterOption_t)e->option != OPT_NONE) || ((unsigned)e->extID < MAXLISTSIZE && preprocess_map[e->extID].function != NULL);

    if (has_func) {
        switch (e->comp) {
            case CMP_EQ:
                return FOP_FUNC_EQ;
            case CMP_GT:
                return FOP_FUNC_GT;
            case CMP_LT:
                return FOP_FUNC_LT;
            case CMP_GE:
                return FOP_FUNC_GE;
            case CMP_LE:
                return FOP_FUNC_LE;
            default:
                return FOP_REJECT;
        }
    }

    if (has_prep) {
        /* List/set comparisons use their own opcodes (they read the ext directly).
         * The preprocess path is not used for these. */
        if (e->comp == CMP_IPLIST) return FOP_IPLIST;
        if (e->comp == CMP_U64LIST) return FOP_U64LIST;
        /* CMP_EQ with value==0: just check preprocess returns non-NULL */
        if (e->comp == CMP_EQ && e->value == 0) return FOP_PREP_ISSET;
        switch (e->comp) {
            case CMP_EQ:
                switch (e->length) {
                    case 1:
                        return FOP_PREP_EQ1;
                    case 2:
                        return FOP_PREP_EQ2;
                    case 4:
                        return FOP_PREP_EQ4;
                    case 8:
                        return FOP_PREP_EQ8;
                    default:
                        return FOP_PREP_ISSET;
                }
            case CMP_GT:
                return FOP_PREP_GT8;
            case CMP_LT:
                return FOP_PREP_LT8;
            case CMP_GE:
                return FOP_PREP_GE8;
            case CMP_LE:
                return FOP_PREP_LE8;
            case CMP_FLAGS:
                return FOP_PREP_FLAGS;
            case CMP_STRING:
                return FOP_PREP_STRING;
            case CMP_SUBSTRING:
                return FOP_PREP_SUBSTRING;
            case CMP_BINARY:
                return FOP_PREP_BINARY;
            case CMP_DNSNAME:
                return FOP_PREP_DNSNAME;
            case CMP_DNSIP:
                return FOP_PREP_DNSIP;
            case CMP_PAYLOAD:
                return FOP_PREP_PAYLOAD;
            case CMP_REGEX:
                return FOP_PREP_REGEX;
            case CMP_GEO:
                return FOP_PREP_GEO;
            default:
                return FOP_PREP_ISSET;
        }
    }

    /* Regular (no preprocess, no function) */
    if (e->extID == EXheader && e->length == 0 && e->data.dataVal == 1) return FOP_ANY;

    /* These comparisons do not use e->length for dispatch — check before the length==0 guard. */
    switch (e->comp) {
        case CMP_IPLIST:
            return FOP_IPLIST;
        case CMP_U64LIST:
            return FOP_U64LIST;
        case CMP_IDENT:
            return FOP_IDENT;
        case CMP_STRING:
            return FOP_STRING;
        case CMP_SUBSTRING:
            return FOP_SUBSTRING;
        case CMP_BINARY:
            return FOP_BINARY;
        case CMP_PAYLOAD:
            return FOP_PAYLOAD;
        case CMP_REGEX:
            return FOP_REGEX;
        case CMP_GEO:
            return FOP_GEO;
        case CMP_DNSNAME:
            return FOP_DNSNAME;
        case CMP_DNSIP:
            return FOP_DNSIP;
        default:
            break;
    }

    if (e->length == 0) return FOP_ISSET;

    switch (e->comp) {
        case CMP_EQ:
            switch (e->length) {
                case 1:
                    return FOP_EQ1;
                case 2:
                    return FOP_EQ2;
                case 4:
                    return FOP_EQ4;
                case 8:
                    return FOP_EQ8;
            }
            break;
        case CMP_GT:
            switch (e->length) {
                case 1:
                    return FOP_GT1;
                case 2:
                    return FOP_GT2;
                case 4:
                    return FOP_GT4;
                case 8:
                    return FOP_GT8;
            }
            break;
        case CMP_LT:
            switch (e->length) {
                case 1:
                    return FOP_LT1;
                case 2:
                    return FOP_LT2;
                case 4:
                    return FOP_LT4;
                case 8:
                    return FOP_LT8;
            }
            break;
        case CMP_GE:
            switch (e->length) {
                case 1:
                    return FOP_GE1;
                case 2:
                    return FOP_GE2;
                case 4:
                    return FOP_GE4;
                case 8:
                    return FOP_GE8;
            }
            break;
        case CMP_LE:
            switch (e->length) {
                case 1:
                    return FOP_LE1;
                case 2:
                    return FOP_LE2;
                case 4:
                    return FOP_LE4;
                case 8:
                    return FOP_LE8;
            }
            break;
        case CMP_FLAGS:
            return FOP_FLAGS;
        case CMP_NET:
            switch (e->length) {
                case 4:
                    return FOP_NET4;
                case 8:
                    return FOP_NET8;
            }
            break;
        case CMP_IPLIST:
            return FOP_IPLIST;
        case CMP_U64LIST:
            return FOP_U64LIST;
        case CMP_IDENT:
            return FOP_IDENT;
        case CMP_STRING:
            return FOP_STRING;
        case CMP_SUBSTRING:
            return FOP_SUBSTRING;
        case CMP_BINARY:
            return FOP_BINARY;
        case CMP_PAYLOAD:
            return FOP_PAYLOAD;
        case CMP_REGEX:
            return FOP_REGEX;
        case CMP_GEO:
            return FOP_GEO;
        case CMP_DNSNAME:
            return FOP_DNSNAME;
        case CMP_DNSIP:
            return FOP_DNSIP;
        default:
            break;
    }
    return FOP_REJECT;
}  // End of chooseOpcode

static filterInstr_t buildInstr(const filterElement_t *e, uint16_t onTrue, uint16_t onFalse) {
    filterInstr_t inst = {
        .onTrue = onTrue,
        .onFalse = onFalse,
        .extID = (uint8_t)e->extID,
        .length = (uint8_t)e->length,
        .option = (uint8_t)e->option,
        .offset = (uint16_t)e->offset,
        .value = e->value,
        .op = (uint16_t)chooseOpcode(e),
    };

    if (e->function != FUNC_NONE) {
        inst.fnID = (uint8_t)e->function;
        inst.dataVal = e->data.dataVal;
    } else {
        switch (e->comp) {
            case CMP_NET:
                inst.dataVal = e->data.dataVal; /* subnet mask */
                break;
            case CMP_GEO:
                inst.dataVal = e->data.dataVal; /* direction enum */
                break;
            case CMP_IPLIST:
            case CMP_U64LIST:
            case CMP_IDENT:
            case CMP_STRING:
            case CMP_SUBSTRING:
            case CMP_BINARY:
            case CMP_DNSNAME:
            case CMP_DNSIP:
            case CMP_PAYLOAD:
            case CMP_REGEX:
                inst.aux = (uintptr_t)e->data.dataPtr;
                break;
            default:
                break;
        }
    }
    inst.handler = g_jt[inst.op];
    return inst;
}  // End of buildInstr

/*
 * Iterative DFS tree walk: emit each reachable node exactly once.
 * Uses an explicit stack instead of C recursion so arbitrarily deep filter
 * trees never exhaust the call stack.
 *
 * Pass 1 (pre-order): reserve a bc_idx slot for every reachable node.
 * Pass 2 (visit order): write each instruction now that all targets are known.
 *
 * Returns the bc_idx assigned to rootElem.
 */
static uint16_t emitNodes(uint32_t rootElem, const filterElement_t *filter, filterInstr_t *prog, uint16_t *progLen, uint16_t *indexMap,
                          uint32_t maxElems) {
    dbg_printf("Enter %s\n", __func__);

    // Both scratch arrays are bounded by the number of tree nodes
    uint32_t *dfsStack = malloc(maxElems * sizeof(uint32_t));
    uint32_t *visitOrder = malloc(maxElems * sizeof(uint32_t));
    if (!dfsStack || !visitOrder) {
        free(dfsStack);
        free(visitOrder);
        return BC_ACCEPT;
    }

    uint32_t top = 0, visitCount = 0;
    dfsStack[top++] = rootElem;

    // ── Pass 1: pre-order DFS — reserve bc_idx slots
    dbg_printf("pass 1: pre-order DFS. rootElem: %u\n", rootElem);
    while (top > 0) {
        uint32_t idx = dfsStack[--top];
        if (indexMap[idx] != BC_UNSET) continue;  // already reserved (DAG dedup)
        indexMap[idx] = (*progLen)++;
        visitOrder[visitCount++] = idx;

        const filterElement_t *e = &filter[idx];
        // Push OnFalse before OnTrue so OnTrue is popped and processed first
        if (e->OnFalse != 0) dfsStack[top++] = e->OnFalse;
        if (e->OnTrue != 0) dfsStack[top++] = e->OnTrue;
    }

    // ── Pass 2: write instructions (all indexMap entries now populated)
    for (uint32_t i = 0; i < visitCount; i++) {
        uint32_t idx = visitOrder[i];
        uint16_t bc_idx = indexMap[idx];
        const filterElement_t *e = &filter[idx];

        uint16_t trueTarget = (e->OnTrue != 0) ? indexMap[e->OnTrue] : (uint16_t)((e->invert == 0) ? BC_ACCEPT : BC_REJECT);
        uint16_t falseTarget = (e->OnFalse != 0) ? indexMap[e->OnFalse] : (uint16_t)((e->invert == 0) ? BC_REJECT : BC_ACCEPT);

        prog[bc_idx] = buildInstr(e, trueTarget, falseTarget);
    }

    free(dfsStack);
    free(visitOrder);
    return indexMap[rootElem];
}  // End of emitNodes

/*
 * Convert the build-time filterElement_t tree into a flat filterInstr_t program.
 * prog[0] = FOP_ACCEPT, prog[1] = FOP_REJECT.
 * Real instructions start at index 2.
 * After emission, converts all IPlist_t pointers to IPSet_t and
 * all U64List_t pointers to U64Set_t for fast runtime lookup.
 */
static filterInstr_t *generateByteCode(uint32_t rootElem, uint32_t numElems, uint16_t *startNodeOut, uint32_t *progLenOut) {
    /* Allocate program: 2 terminals + one slot per tree node */
    uint32_t maxProg = numElems + 2;
    filterInstr_t *prog = calloc(maxProg, sizeof(filterInstr_t));
    if (!prog) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    /* Fixed terminals */
    prog[BC_ACCEPT].op = FOP_ACCEPT;
    prog[BC_ACCEPT].handler = g_jt[FOP_ACCEPT];
    prog[BC_REJECT].op = FOP_REJECT;
    prog[BC_REJECT].handler = g_jt[FOP_REJECT];
    uint16_t progLen = 2;

    uint16_t *indexMap = malloc(maxProg * sizeof(uint16_t));
    if (!indexMap) {
        free(prog);
        return NULL;
    }
    for (uint32_t i = 0; i < maxProg; i++) indexMap[i] = BC_UNSET;

    uint16_t startNode = BC_ACCEPT; /* default: empty filter always accepts */
    if (rootElem != 0) startNode = emitNodes(rootElem, FilterTree, prog, &progLen, indexMap, maxProg);

    free(indexMap);

    /* Post-pass: convert list pointers to fast runtime structures.
     * A single IPlist_t* or U64List_t* may be shared by multiple instructions
     * (e.g. "ip in [...]" expands to src-v4/dst-v4/src-v6/dst-v6 nodes, all
     * pointing at the same list).  Use a small dedup table so each unique
     * list is converted exactly once. */

    /* dedup table: maps original build-time ptr → converted runtime ptr */
    typedef struct {
        uintptr_t orig;
        uintptr_t conv;
    } ptrpair_t;
    ptrpair_t *ipMap = calloc(progLen, sizeof(ptrpair_t));
    ptrpair_t *u64Map = calloc(progLen, sizeof(ptrpair_t));
    uint16_t ipMapLen = 0, u64MapLen = 0;

    for (uint16_t i = 2; i < progLen; i++) {
        filterInstr_t *inst = &prog[i];
        if (inst->op == FOP_IPLIST) {
            uintptr_t origPtr = inst->aux;
            IPSet_t *set = NULL;
            /* look up in dedup table */
            for (uint16_t k = 0; k < ipMapLen; k++) {
                if (ipMap[k].orig == origPtr) {
                    set = (IPSet_t *)ipMap[k].conv;
                    break;
                }
            }
            if (!set) {
                set = buildIPSet((IPlist_t *)origPtr);
                ipMap[ipMapLen++] = (ptrpair_t){origPtr, (uintptr_t)set};
            }
            inst->aux = (uintptr_t)set;
        }
        if (inst->op == FOP_U64LIST) {
            uintptr_t origPtr = inst->aux;
            U64Set_t *set = NULL;
            for (uint16_t k = 0; k < u64MapLen; k++) {
                if (u64Map[k].orig == origPtr) {
                    set = (U64Set_t *)u64Map[k].conv;
                    break;
                }
            }
            if (!set) {
                set = buildU64Set((U64List_t *)origPtr);
                u64Map[u64MapLen++] = (ptrpair_t){origPtr, (uintptr_t)set};
            }
            inst->aux = (uintptr_t)set;
        }
    }
    free(ipMap);
    free(u64Map);

    *startNodeOut = startNode;
    *progLenOut = progLen;
    return prog;
}  // End of generateByteCode

/* ═══════════════════════════════════════════════════════════════════════════
 * RunFilter – computed-goto bytecode interpreter (GCC/Clang extension).
 *
 * Each opcode has its own label; the branch-target buffer learns a separate
 * prediction per call site, giving O(1) dispatch with no switch overhead.
 *
 * NEXT(result) – branch to onTrue (result=1) or onFalse (result=0),
 *                load the instruction, and jump to its handler label.
 * PREP_ENTER   – shared preamble for FOP_PREP_* handlers: runs preprocess
 *                and sets inPtr to (base + offset) or fails to onFalse.
 * ═══════════════════════════════════════════════════════════════════════════ */
static int RunFilter(const FilterEngine_t *engine, recordHandle_t *handle) {
    /* Dispatch table – indices must match filterOp_t enum order. */
    static const void *const jt[FOP__COUNT] = {
        [FOP_ACCEPT] = &&L_ACCEPT,
        [FOP_REJECT] = &&L_REJECT,
        [FOP_ANY] = &&L_ANY,
        [FOP_ISSET] = &&L_ISSET,
        [FOP_EQ1] = &&L_EQ1,
        [FOP_EQ2] = &&L_EQ2,
        [FOP_EQ4] = &&L_EQ4,
        [FOP_EQ8] = &&L_EQ8,
        [FOP_GT1] = &&L_GT1,
        [FOP_GT2] = &&L_GT2,
        [FOP_GT4] = &&L_GT4,
        [FOP_GT8] = &&L_GT8,
        [FOP_LT1] = &&L_LT1,
        [FOP_LT2] = &&L_LT2,
        [FOP_LT4] = &&L_LT4,
        [FOP_LT8] = &&L_LT8,
        [FOP_GE1] = &&L_GE1,
        [FOP_GE2] = &&L_GE2,
        [FOP_GE4] = &&L_GE4,
        [FOP_GE8] = &&L_GE8,
        [FOP_LE1] = &&L_LE1,
        [FOP_LE2] = &&L_LE2,
        [FOP_LE4] = &&L_LE4,
        [FOP_LE8] = &&L_LE8,
        [FOP_FLAGS] = &&L_FLAGS,
        [FOP_NET4] = &&L_NET4,
        [FOP_NET8] = &&L_NET8,
        [FOP_IPLIST] = &&L_IPLIST,
        [FOP_U64LIST] = &&L_U64LIST,
        [FOP_IDENT] = &&L_IDENT,
        [FOP_STRING] = &&L_STRING,
        [FOP_SUBSTRING] = &&L_SUBSTRING,
        [FOP_BINARY] = &&L_BINARY,
        [FOP_PAYLOAD] = &&L_PAYLOAD,
        [FOP_REGEX] = &&L_REGEX,
        [FOP_GEO] = &&L_GEO,
        [FOP_DNSNAME] = &&L_DNSNAME,
        [FOP_DNSIP] = &&L_DNSIP,
        [FOP_FUNC_EQ] = &&L_FUNC_EQ,
        [FOP_FUNC_GT] = &&L_FUNC_GT,
        [FOP_FUNC_LT] = &&L_FUNC_LT,
        [FOP_FUNC_GE] = &&L_FUNC_GE,
        [FOP_FUNC_LE] = &&L_FUNC_LE,
        [FOP_PREP_ISSET] = &&L_PREP_ISSET,
        [FOP_PREP_EQ1] = &&L_PREP_EQ1,
        [FOP_PREP_EQ2] = &&L_PREP_EQ2,
        [FOP_PREP_EQ4] = &&L_PREP_EQ4,
        [FOP_PREP_EQ8] = &&L_PREP_EQ8,
        [FOP_PREP_GT8] = &&L_PREP_GT8,
        [FOP_PREP_LT8] = &&L_PREP_LT8,
        [FOP_PREP_GE8] = &&L_PREP_GE8,
        [FOP_PREP_LE8] = &&L_PREP_LE8,
        [FOP_PREP_FLAGS] = &&L_PREP_FLAGS,
        [FOP_PREP_STRING] = &&L_PREP_STRING,
        [FOP_PREP_SUBSTRING] = &&L_PREP_SUBSTRING,
        [FOP_PREP_BINARY] = &&L_PREP_BINARY,
        [FOP_PREP_GEO] = &&L_PREP_GEO,
        [FOP_PREP_DNSNAME] = &&L_PREP_DNSNAME,
        [FOP_PREP_DNSIP] = &&L_PREP_DNSIP,
        [FOP_PREP_PAYLOAD] = &&L_PREP_PAYLOAD,
        [FOP_PREP_REGEX] = &&L_PREP_REGEX,
    };

    /* Init mode: called once with engine == NULL from InitFilterDispatch().
     * Copies the local jt[] label addresses into g_jt so that buildInstr()
     * can embed them directly into each instruction's handler field. */
    if (__builtin_expect(engine == NULL, 0)) {
        memcpy(g_jt, jt, sizeof(jt));
        return 0;
    }

    /* Advance to the next instruction and dispatch.
     * Direct threading: inst->handler holds the label address so dispatch
     * is a single load + indirect branch – no jt[] table lookup needed. */
#define NEXT(result)                                           \
    do {                                                       \
        inst = &prog[(result) ? inst->onTrue : inst->onFalse]; \
        goto * inst->handler;                                  \
    } while (0)

    /* Preprocess preamble for FOP_PREP_* handlers.
     * Sets 'inPtr' to (base + inst->offset) or branches to onFalse. */
#define PREP_ENTER(inPtr)                                                                                        \
    do {                                                                                                         \
        void *_ext = handle->extensionList[inst->extID];                                                         \
        if (_ext == NULL || (filterOption_t)inst->option != OPT_NONE) {                                          \
            if ((unsigned)inst->extID >= MAXLISTSIZE || preprocess_map[inst->extID].function == NULL) {          \
                inst = &prog[inst->onFalse];                                                                     \
                goto * inst->handler;                                                                            \
            }                                                                                                    \
            data_t _d = {.dataVal = inst->dataVal};                                                              \
            _ext = preprocess_map[inst->extID].function(inst->length, _d, handle, (filterOption_t)inst->option); \
            if (!_ext) {                                                                                         \
                inst = &prog[inst->onFalse];                                                                     \
                goto * inst->handler;                                                                            \
            }                                                                                                    \
        }                                                                                                        \
        (inPtr) = (uint8_t *)_ext + inst->offset;                                                                \
    } while (0)

    const filterInstr_t *const restrict prog = engine->prog;
    const filterInstr_t *inst = &prog[engine->startNode];
    goto * inst->handler;

    /* ── terminals ──────────────────────────────────────────────────── */
L_ACCEPT:
    return 1;
L_REJECT:
    return 0;

    /* ── unconditional ───────────────────────────────────────────────── */
L_ANY:
    NEXT(1);
L_ISSET:
    NEXT(handle->extensionList[inst->extID] != NULL);

    /* ── width-specialised equality ──────────────────────────────────── */
L_EQ1: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    NEXT(*(const uint8_t *)(ext + inst->offset) == (uint8_t)inst->value);
}

L_EQ2: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    NEXT(*(const uint16_t *)(ext + inst->offset) == (uint16_t)inst->value);
}

L_EQ4: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    NEXT(*(const uint32_t *)(ext + inst->offset) == (uint32_t)inst->value);
}

L_EQ8: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    NEXT(*(const uint64_t *)(ext + inst->offset) == inst->value);
}

    /* ── relational ──────────────────────────────────────────────────── */
L_GT1: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    NEXT(*(const uint8_t *)(ext + inst->offset) > (uint8_t)inst->value);
}
L_GT2: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    NEXT(*(const uint16_t *)(ext + inst->offset) > (uint16_t)inst->value);
}
L_GT4: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    NEXT(*(const uint32_t *)(ext + inst->offset) > (uint32_t)inst->value);
}
L_GT8: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    NEXT(*(const uint64_t *)(ext + inst->offset) > inst->value);
}

L_LT1: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    NEXT(*(const uint8_t *)(ext + inst->offset) < (uint8_t)inst->value);
}
L_LT2: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    NEXT(*(const uint16_t *)(ext + inst->offset) < (uint16_t)inst->value);
}
L_LT4: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    NEXT(*(const uint32_t *)(ext + inst->offset) < (uint32_t)inst->value);
}
L_LT8: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    NEXT(*(const uint64_t *)(ext + inst->offset) < inst->value);
}

L_GE1: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    NEXT(*(const uint8_t *)(ext + inst->offset) >= (uint8_t)inst->value);
}
L_GE2: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    NEXT(*(const uint16_t *)(ext + inst->offset) >= (uint16_t)inst->value);
}
L_GE4: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    NEXT(*(const uint32_t *)(ext + inst->offset) >= (uint32_t)inst->value);
}
L_GE8: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    NEXT(*(const uint64_t *)(ext + inst->offset) >= inst->value);
}

L_LE1: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    NEXT(*(const uint8_t *)(ext + inst->offset) <= (uint8_t)inst->value);
}
L_LE2: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    NEXT(*(const uint16_t *)(ext + inst->offset) <= (uint16_t)inst->value);
}
L_LE4: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    NEXT(*(const uint32_t *)(ext + inst->offset) <= (uint32_t)inst->value);
}
L_LE8: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    NEXT(*(const uint64_t *)(ext + inst->offset) <= inst->value);
}

    /* ── bitmask ─────────────────────────────────────────────────────── */
L_FLAGS: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    uint64_t v = 0;
    switch (inst->length) {
        case 1:
            v = *(const uint8_t *)(ext + inst->offset);
            break;
        case 2:
            v = *(const uint16_t *)(ext + inst->offset);
            break;
        case 4:
            v = *(const uint32_t *)(ext + inst->offset);
            break;
        case 8:
            v = *(const uint64_t *)(ext + inst->offset);
            break;
    }
    NEXT((v & inst->value) == inst->value);
}

    /* ── network prefix ──────────────────────────────────────────────── */
L_NET4: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    uint64_t v = *(const uint32_t *)(ext + inst->offset);
    NEXT((v & (uint64_t)(uint32_t)inst->dataVal) == inst->value);
}

L_NET8: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    uint64_t v = *(const uint64_t *)(ext + inst->offset);
    NEXT((v & (uint64_t)inst->dataVal) == inst->value);
}

    /* ── IP set membership ───────────────────────────────────────────── */
L_IPLIST: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    const IPSet_t *set = (const IPSet_t *)(uintptr_t)inst->aux;
    uint64_t ip0 = 0, ip1;
    if (inst->length == 4) {
        ip1 = *(const uint32_t *)(ext + inst->offset);
    } else { /* IPv6: 16-byte field */
        ip0 = *(const uint64_t *)(ext + inst->offset);
        ip1 = *(const uint64_t *)(ext + inst->offset + 8);
    }
    NEXT(IPSetContains(set, ip0, ip1));
}

    /* ── uint64_t set membership ─────────────────────────────────────── */
L_U64LIST: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    uint64_t v = 0;
    switch (inst->length) {
        case 1:
            v = *(const uint8_t *)(ext + inst->offset);
            break;
        case 2:
            v = *(const uint16_t *)(ext + inst->offset);
            break;
        case 4:
            v = *(const uint32_t *)(ext + inst->offset);
            break;
        case 8:
            v = *(const uint64_t *)(ext + inst->offset);
            break;
    }
    NEXT(U64SetContains((const U64Set_t *)(uintptr_t)inst->aux, v));
}

    /* ── string comparisons ──────────────────────────────────────────── */
L_IDENT: {
    const char *str = (const char *)(uintptr_t)inst->aux;
    NEXT(str != NULL && strcmp(engine->ident, str) == 0);
}

L_STRING: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    const char *str = (const char *)(uintptr_t)inst->aux;
    NEXT(str != NULL && strcmp((const char *)(ext + inst->offset), str) == 0);
}

L_SUBSTRING: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    const char *str = (const char *)(uintptr_t)inst->aux;
    NEXT(str != NULL && strstr((const char *)(ext + inst->offset), str) != NULL);
}

L_BINARY: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    const void *bin = (const void *)(uintptr_t)inst->aux;
    NEXT(bin != NULL && memcmp(ext + inst->offset, bin, inst->length) == 0);
}

    /* ── payload ─────────────────────────────────────────────────────── */
L_PAYLOAD: {
    const EXPayload_t *payload = (const EXPayload_t *)(handle->extensionList[inst->extID]);
    if (__builtin_expect(!payload, 0)) NEXT(0);
    const char *needle = (const char *)(uintptr_t)inst->aux;
    if (__builtin_expect(!needle, 0)) NEXT(0);
    const char *hay = (const char *)payload->payload;
    const uint32_t len = payload->size;
    int m = 0;
    for (uint32_t i = 0; i < len; i++) {
        if (hay[i] == needle[m]) {
            m++;
            if (needle[m] == '\0') NEXT(1);
        } else
            m = 0;
    }
    NEXT(0);
}

L_REGEX: {
    const srx_Context *prog2 = (const srx_Context *)(uintptr_t)inst->aux;
    const EXPayload_t *payload = (const EXPayload_t *)(handle->extensionList[inst->extID]);
    if (__builtin_expect(!payload || !prog2, 0)) NEXT(0);
    NEXT(srx_MatchExt((srx_Context *)(uintptr_t)prog2, (rxChar *)payload->payload, payload->size, 0) != 0);
}

    /* ── geo lookup ──────────────────────────────────────────────────── */
L_GEO: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    char *geoChar = (char *)(ext + inst->offset);
    uint64_t geoVal;
    if (engine->hasGeoDB && geoChar[0] == '\0')
        geoVal = geoLookup(geoChar, (uint32_t)inst->dataVal, handle);
    else
        geoVal = *(const uint16_t *)geoChar;
    NEXT(geoVal == inst->value);
}

    /* ── DNS ─────────────────────────────────────────────────────────── */
L_DNSNAME: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    const char *str = (const char *)(uintptr_t)inst->aux;
    NEXT(str != NULL && dnsSearchName((void *)(ext + inst->offset), (char *)str) != 0);
}

L_DNSIP: {
    const uint8_t *ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!ext, 0)) NEXT(0);
    const char *str = (const char *)(uintptr_t)inst->aux;
    NEXT(str != NULL && dnsSearchIP((void *)(ext + inst->offset), (char *)str) != 0);
}

/* ── function-derived value ──────────────────────────────────────── */
/* The function reads from the extension struct and returns a uint64_t.
 * as_preproc is also called here when EXasInfoID ext is NULL. */
#define FUNC_BODY()                                                                                              \
    void *_ext = handle->extensionList[inst->extID];                                                             \
    if (__builtin_expect(_ext == NULL, 0)) {                                                                     \
        if ((unsigned)inst->extID < MAXLISTSIZE && preprocess_map[inst->extID].function != NULL) {               \
            data_t _d = {.dataVal = inst->dataVal};                                                              \
            _ext = preprocess_map[inst->extID].function(inst->length, _d, handle, (filterOption_t)inst->option); \
        }                                                                                                        \
        if (!_ext) NEXT(0);                                                                                      \
    }                                                                                                            \
    void *inPtr = (uint8_t *)_ext + inst->offset;                                                                \
    data_t _d2 = {.dataVal = inst->dataVal};                                                                     \
    uint64_t _v = flow_procs_map[inst->fnID].function(inPtr, inst->length, _d2, handle);

L_FUNC_EQ: {
    FUNC_BODY();
    NEXT(_v == inst->value);
}
L_FUNC_GT: {
    FUNC_BODY();
    NEXT(_v > inst->value);
}
L_FUNC_LT: {
    FUNC_BODY();
    NEXT(_v < inst->value);
}
L_FUNC_GE: {
    FUNC_BODY();
    NEXT(_v >= inst->value);
}
L_FUNC_LE: {
    FUNC_BODY();
    NEXT(_v <= inst->value);
}
#undef FUNC_BODY

    /* ── preprocess variants (EXasInfoID / EXin|outPayloadHandle) ────── */
L_PREP_ISSET: {
    uint8_t *inPtr;
    PREP_ENTER(inPtr);
    NEXT(inPtr != NULL);
}

L_PREP_EQ1: {
    uint8_t *inPtr;
    PREP_ENTER(inPtr);
    NEXT(*(const uint8_t *)inPtr == (uint8_t)inst->value);
}
L_PREP_EQ2: {
    uint8_t *inPtr;
    PREP_ENTER(inPtr);
    NEXT(*(const uint16_t *)inPtr == (uint16_t)inst->value);
}
L_PREP_EQ4: {
    uint8_t *inPtr;
    PREP_ENTER(inPtr);
    NEXT(*(const uint32_t *)inPtr == (uint32_t)inst->value);
}
L_PREP_EQ8: {
    uint8_t *inPtr;
    PREP_ENTER(inPtr);
    NEXT(*(const uint64_t *)inPtr == inst->value);
}

L_PREP_GT8: {
    uint8_t *inPtr;
    PREP_ENTER(inPtr);
    NEXT(*(const uint64_t *)inPtr > inst->value);
}
L_PREP_LT8: {
    uint8_t *inPtr;
    PREP_ENTER(inPtr);
    NEXT(*(const uint64_t *)inPtr < inst->value);
}
L_PREP_GE8: {
    uint8_t *inPtr;
    PREP_ENTER(inPtr);
    NEXT(*(const uint64_t *)inPtr >= inst->value);
}
L_PREP_LE8: {
    uint8_t *inPtr;
    PREP_ENTER(inPtr);
    NEXT(*(const uint64_t *)inPtr <= inst->value);
}

L_PREP_FLAGS: {
    uint8_t *inPtr;
    PREP_ENTER(inPtr);
    uint64_t v = 0;
    switch (inst->length) {
        case 1:
            v = *(const uint8_t *)inPtr;
            break;
        case 2:
            v = *(const uint16_t *)inPtr;
            break;
        case 4:
            v = *(const uint32_t *)inPtr;
            break;
        case 8:
            v = *(const uint64_t *)inPtr;
            break;
    }
    NEXT((v & inst->value) == inst->value);
}

L_PREP_STRING: {
    uint8_t *inPtr;
    PREP_ENTER(inPtr);
    const char *str = (const char *)(uintptr_t)inst->aux;
    NEXT(str != NULL && strcmp((const char *)inPtr, str) == 0);
}

L_PREP_SUBSTRING: {
    uint8_t *inPtr;
    PREP_ENTER(inPtr);
    const char *str = (const char *)(uintptr_t)inst->aux;
    NEXT(str != NULL && strstr((const char *)inPtr, str) != NULL);
}

L_PREP_BINARY: {
    uint8_t *inPtr;
    PREP_ENTER(inPtr);
    const void *bin = (const void *)(uintptr_t)inst->aux;
    NEXT(bin != NULL && memcmp(inPtr, bin, inst->length) == 0);
}

L_PREP_GEO: {
    uint8_t *inPtr;
    PREP_ENTER(inPtr);
    char *geoChar = (char *)inPtr;
    uint64_t geoVal;
    if (engine->hasGeoDB && geoChar[0] == '\0')
        geoVal = geoLookup(geoChar, (uint32_t)inst->dataVal, handle);
    else
        geoVal = *(const uint16_t *)geoChar;
    NEXT(geoVal == inst->value);
}

L_PREP_DNSNAME: {
    uint8_t *inPtr;
    PREP_ENTER(inPtr);
    const char *str = (const char *)(uintptr_t)inst->aux;
    NEXT(str != NULL && dnsSearchName((void *)inPtr, (char *)str) != 0);
}

L_PREP_DNSIP: {
    uint8_t *inPtr;
    PREP_ENTER(inPtr);
    const char *str = (const char *)(uintptr_t)inst->aux;
    NEXT(str != NULL && dnsSearchIP((void *)inPtr, (char *)str) != 0);
}

L_PREP_PAYLOAD: {
    /* For payload content search we work directly from the EXPayload extension,
     * not from the prepocessed payloadHandle. */
    uint8_t *_ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!_ext, 0)) {
        inst = &prog[inst->onFalse];
        goto * inst->handler;
    }
    if (preprocess_map[inst->extID].function) {
        data_t _d = {.dataVal = inst->dataVal};
        preprocess_map[inst->extID].function(inst->length, _d, handle, (filterOption_t)inst->option);
    }
    const EXPayload_t *payload = (const EXPayload_t *)_ext;
    const char *needle = (const char *)(uintptr_t)inst->aux;
    if (!needle) NEXT(0);
    const char *hay = (const char *)payload->payload;
    const uint32_t len = payload->size;
    int m = 0;
    for (uint32_t i = 0; i < len; i++) {
        if (hay[i] == needle[m]) {
            m++;
            if (needle[m] == '\0') NEXT(1);
        } else
            m = 0;
    }
    NEXT(0);
}

L_PREP_REGEX: {
    uint8_t *_ext = handle->extensionList[inst->extID];
    if (__builtin_expect(!_ext, 0)) {
        inst = &prog[inst->onFalse];
        goto * inst->handler;
    }
    if (preprocess_map[inst->extID].function) {
        data_t _d = {.dataVal = inst->dataVal};
        preprocess_map[inst->extID].function(inst->length, _d, handle, (filterOption_t)inst->option);
    }
    srx_Context *prog2 = (srx_Context *)(uintptr_t)inst->aux;
    const EXPayload_t *payload = (const EXPayload_t *)_ext;
    if (!prog2 || !payload) NEXT(0);
    NEXT(srx_MatchExt(prog2, (rxChar *)payload->payload, payload->size, 0) != 0);
}

#undef NEXT
#undef PREP_ENTER
}  // End of RunFilter

/* ═══════════════════════════════════════════════════════════════════════════
 * Public engine API
 * ═══════════════════════════════════════════════════════════════════════════ */

void FilterSetParam(void *engine, const char *ident, const unsigned hasGeoDB) {
    FilterEngine_t *filterEngine = (FilterEngine_t *)engine;
    filterEngine->hasGeoDB = hasGeoDB;
    filterEngine->ident = ident ? ident : "none";
}  // End of FilterSetParam

/*
 * Clone engine for a worker thread.  prog[] is shared (immutable after compile).
 * ident is strdup'd so each thread has its own copy.
 */
void *FilterCloneEngine(void *engine) {
    FilterEngine_t *filterEngine = malloc(sizeof(FilterEngine_t));
    if (!filterEngine) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }
    memcpy((void *)filterEngine, engine, sizeof(FilterEngine_t));
    if (filterEngine->ident) filterEngine->ident = strdup(filterEngine->ident);
    return (void *)filterEngine;
}  // End of FilterCloneEngine

int FilterRecord(const void *engine, recordHandle_t *handle) { return RunFilter((const FilterEngine_t *)engine, handle); }  // End of FilterRecord

char *ReadFilter(char *filename) {
    if (!CheckPath(filename, S_IFREG)) return NULL;

    int ffd = open(filename, O_RDONLY);
    if (ffd < 0) {
        LogError("Can't open filter file '%s': %s", filename, strerror(errno));
        return NULL;
    }

    struct stat stat_buff;
    if (fstat(ffd, &stat_buff)) {
        LogError("stat() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        close(ffd);
        return NULL;
    }

    char *filter = (char *)malloc(stat_buff.st_size + 1);
    if (!filter) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        close(ffd);
        return NULL;
    }

    ssize_t ret = read(ffd, (void *)filter, stat_buff.st_size);
    if (ret < 0) {
        LogError("Error reading filter file %s: %s", filename, strerror(errno));
        close(ffd);
        return NULL;
    }
    filter[stat_buff.st_size] = 0;
    close(ffd);

    return filter;

}  // End of ReadFilter

/* Populate g_jt by calling RunFilter in init mode (engine == NULL).
 * Must run before generateByteCode() so every buildInstr() call can
 * embed handler addresses directly into the instruction struct. */
static void InitFilterDispatch(void) {
    if (g_jt[FOP_ACCEPT] != NULL) return;
    RunFilter(NULL, NULL);
}  // End of InitFilterDispatch

void *CompileFilter(char *FilterSyntax) {
    if (!FilterSyntax) return NULL;

    InitFilterDispatch();
    InitFilter();
    lex_init(FilterSyntax);
    if (yyparse() != 0) {
        return NULL;
    }
    lex_cleanup();

    // Emit bytecode from the build-time tree
    uint16_t startNode = 0;
    uint32_t progLen = 0;
    filterInstr_t *prog = generateByteCode(StartNode, NumBlocks, &startNode, &progLen);
    if (!prog) return NULL;

    /* Free the build-time tree (blocklists were freed by UpdateList;
     * data pointers have been transferred to prog instructions). */
    for (uint32_t i = 1; i < NumBlocks; i++) {
        if (FilterTree[i].blocklist) free(FilterTree[i].blocklist);
    }
    free(FilterTree);
    FilterTree = NULL;

    FilterEngine_t *engine = malloc(sizeof(FilterEngine_t));
    if (!engine) {
        LogError("Memory allocation error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        free(prog);
        return NULL;
    }

    *engine = (FilterEngine_t){
        .prog = prog,
        .progLen = progLen,
        .startNode = startNode,
        .hasGeoDB = 0,
        .ident = "none",
    };

    dbg_printf("Engine: bytecode %u instructions, startNode %u\n", progLen, startNode);
    return (void *)engine;

}  // End of CompileFilter

void DisposeFilter(void *engine) {
    /* NOTE: prog is shared with all FilterCloneEngine() copies.
     * Free prog only from the owning (original) engine; clones call
     * DisposeFilter with their own shell only.  Since the current usage
     * never disposes clones while the original is still alive, and the
     * engine lives for the program lifetime, we free prog here.
     * A refcount can be added if dynamic filter reload is needed. */
    if (!engine) return;
    FilterEngine_t *fe = (FilterEngine_t *)engine;
    if (fe->prog) {
        /* Walk instructions and free auxiliary data owned by the prog.
         * IPSet_t* and U64Set_t* may be shared between instructions (when
         * grammar expanded a list into multiple nodes).  Null the aux after
         * freeing so later duplicates are skipped. */
        for (uint32_t i = 2; i < fe->progLen; i++) {
            filterInstr_t *inst = &fe->prog[i];
            switch ((filterOp_t)inst->op) {
                case FOP_IPLIST:
                    if (inst->aux) {
                        freeIPSet((IPSet_t *)(uintptr_t)inst->aux);
                        /* null duplicates */
                        uintptr_t p = inst->aux;
                        inst->aux = 0;
                        for (uint32_t j = i + 1; j < fe->progLen; j++)
                            if (fe->prog[j].op == FOP_IPLIST && fe->prog[j].aux == p) fe->prog[j].aux = 0;
                    }
                    break;
                case FOP_U64LIST:
                    if (inst->aux) {
                        freeU64Set((U64Set_t *)(uintptr_t)inst->aux);
                        uintptr_t p = inst->aux;
                        inst->aux = 0;
                        for (uint32_t j = i + 1; j < fe->progLen; j++)
                            if (fe->prog[j].op == FOP_U64LIST && fe->prog[j].aux == p) fe->prog[j].aux = 0;
                    }
                    break;
                case FOP_IDENT:
                case FOP_STRING:
                case FOP_PREP_STRING:
                case FOP_SUBSTRING:
                case FOP_PREP_SUBSTRING:
                case FOP_DNSNAME:
                case FOP_PREP_DNSNAME:
                case FOP_DNSIP:
                case FOP_PREP_DNSIP:
                case FOP_PAYLOAD:
                case FOP_PREP_PAYLOAD:
                case FOP_BINARY:
                case FOP_PREP_BINARY:
                    if (inst->aux) {
                        free((void *)(uintptr_t)inst->aux);
                        uintptr_t p = inst->aux;
                        inst->aux = 0;
                        for (uint32_t j = i + 1; j < fe->progLen; j++)
                            if (fe->prog[j].aux == p) fe->prog[j].aux = 0;
                    }
                    break;
                case FOP_REGEX:
                case FOP_PREP_REGEX:
                    if (inst->aux) {
                        srx_Destroy((srx_Context *)(uintptr_t)inst->aux);
                        uintptr_t p = inst->aux;
                        inst->aux = 0;
                        for (uint32_t j = i + 1; j < fe->progLen; j++)
                            if (fe->prog[j].aux == p) fe->prog[j].aux = 0;
                    }
                    break;
                default:
                    break;
            }
        }
        free(fe->prog);
    }
    free(engine);
}  // End of DisposeFilter

/*
 * Dump bytecode program for debugging.
 */
void DumpEngine(void *arg) {
    if (!arg) return;
    const FilterEngine_t *engine = (const FilterEngine_t *)arg;

    static const char *opname[] = {
        [FOP_ACCEPT] = "ACCEPT",
        [FOP_REJECT] = "REJECT",
        [FOP_ANY] = "ANY",
        [FOP_ISSET] = "ISSET",
        [FOP_EQ1] = "EQ1",
        [FOP_EQ2] = "EQ2",
        [FOP_EQ4] = "EQ4",
        [FOP_EQ8] = "EQ8",
        [FOP_GT1] = "GT1",
        [FOP_GT2] = "GT2",
        [FOP_GT4] = "GT4",
        [FOP_GT8] = "GT8",
        [FOP_LT1] = "LT1",
        [FOP_LT2] = "LT2",
        [FOP_LT4] = "LT4",
        [FOP_LT8] = "LT8",
        [FOP_GE1] = "GE1",
        [FOP_GE2] = "GE2",
        [FOP_GE4] = "GE4",
        [FOP_GE8] = "GE8",
        [FOP_LE1] = "LE1",
        [FOP_LE2] = "LE2",
        [FOP_LE4] = "LE4",
        [FOP_LE8] = "LE8",
        [FOP_FLAGS] = "FLAGS",
        [FOP_NET4] = "NET4",
        [FOP_NET8] = "NET8",
        [FOP_IPLIST] = "IPLIST",
        [FOP_U64LIST] = "U64LIST",
        [FOP_IDENT] = "IDENT",
        [FOP_STRING] = "STRING",
        [FOP_SUBSTRING] = "SUBSTRING",
        [FOP_BINARY] = "BINARY",
        [FOP_PAYLOAD] = "PAYLOAD",
        [FOP_REGEX] = "REGEX",
        [FOP_GEO] = "GEO",
        [FOP_DNSNAME] = "DNSNAME",
        [FOP_DNSIP] = "DNSIP",
        [FOP_FUNC_EQ] = "FUNC_EQ",
        [FOP_FUNC_GT] = "FUNC_GT",
        [FOP_FUNC_LT] = "FUNC_LT",
        [FOP_FUNC_GE] = "FUNC_GE",
        [FOP_FUNC_LE] = "FUNC_LE",
        [FOP_PREP_ISSET] = "PREP_ISSET",
        [FOP_PREP_EQ1] = "PREP_EQ1",
        [FOP_PREP_EQ2] = "PREP_EQ2",
        [FOP_PREP_EQ4] = "PREP_EQ4",
        [FOP_PREP_EQ8] = "PREP_EQ8",
        [FOP_PREP_GT8] = "PREP_GT8",
        [FOP_PREP_LT8] = "PREP_LT8",
        [FOP_PREP_GE8] = "PREP_GE8",
        [FOP_PREP_LE8] = "PREP_LE8",
        [FOP_PREP_FLAGS] = "PREP_FLAGS",
        [FOP_PREP_STRING] = "PREP_STRING",
        [FOP_PREP_SUBSTRING] = "PREP_SUBSTRING",
        [FOP_PREP_BINARY] = "PREP_BINARY",
        [FOP_PREP_GEO] = "PREP_GEO",
        [FOP_PREP_DNSNAME] = "PREP_DNSNAME",
        [FOP_PREP_DNSIP] = "PREP_DNSIP",
        [FOP_PREP_PAYLOAD] = "PREP_PAYLOAD",
        [FOP_PREP_REGEX] = "PREP_REGEX",
    };

    printf("Bytecode engine: startNode=%u progLen=%u\n", engine->startNode, engine->progLen);
    for (uint32_t i = 0; i < engine->progLen; i++) {
        const filterInstr_t *p = &engine->prog[i];
        const char *name = (p->op < FOP__COUNT && opname[p->op]) ? opname[p->op] : "?";
        printf(
            "  [%3u] %-16s extID=%-3u off=%-4u len=%-2u "
            "val=0x%016" PRIx64 " onT=%-3u onF=%-3u",
            i, name, p->extID, p->offset, p->length, p->value, p->onTrue, p->onFalse);
        if (p->op == FOP_IPLIST) {
            const IPSet_t *set = (const IPSet_t *)(uintptr_t)p->aux;
            if (set) printf(" [ht=%u cidr=%u]", set->htSize, set->cidrCount);
        } else if (p->op == FOP_U64LIST) {
            const U64Set_t *set = (const U64Set_t *)(uintptr_t)p->aux;
            if (set) printf(" [n=%u]", set->count);
        } else if (p->dataVal) {
            printf(" dataVal=0x%016" PRIx64, (uint64_t)p->dataVal);
        }
        printf("\n");
    }
}  // End of DumpEngine
