/*
 *  Copyright (c) 2024, Peter Haag
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

#include "filter.h"
#include "ja3/ja3.h"
#include "ja4/ja4.h"
#include "maxmind/maxmind.h"
#include "sgregex.h"
#include "util.h"

#define MAXBLOCKS 1024

static uint32_t memblocks;
static uint32_t NumBlocks = 1; /* index 0 reserved */
static int Extended = 0;
uint32_t StartNode = 0;

typedef uint64_t (*flow_proc_t)(void *, uint32_t, data_t, recordHandle_t *);

typedef void *(*preprocess_proc_t)(void *, uint32_t, data_t, recordHandle_t *);

typedef struct filterElement {
    /* Filter specific data */
    uint32_t extID;
    uint32_t offset;
    uint32_t length;
    uint64_t value;

    /* Internal block info for tree setup */
    uint32_t superblock; /* Index of superblock */
    uint32_t *blocklist; /* index array of blocks, belonging to
                                            this superblock */

    uint32_t geoLookup;       /* info on geoLookup */
    uint32_t numblocks;       /* number of blocks in blocklist */
    uint32_t OnTrue, OnFalse; /* Jump Index for tree */
    int16_t invert;           /* Invert result of test */
    comparator_t comp;        /* comperator */
    flow_proc_t function;     /* function for flow processing */
    char *fname;              /* ascii function name */
    char *label;              /* label, if any */
    data_t data;              /* any additional data for this block */
} filterElement_t;

typedef struct FilterEngine_s {
    filterElement_t *filter;
    uint32_t StartNode;
    uint16_t Extended;
    int hasGeoDB;
    const char *ident;
    char *label;
    int (*filterFunction)(const struct FilterEngine_s *, recordHandle_t *);
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

/* flow pre-processing functions */
static void *ssl_preproc(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle);
static void *ja3_preproc(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle);
static void *ja4_preproc(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle);

/*
 * flow processing function table:
 */

static struct flow_procs_map_s {
    filterFunction_t filterNum;
    char *name;
    flow_proc_t function;
} flow_procs_map[] = {{FUNC_NONE, "none", NULL},
                      {FUNC_DURATION, "duration", duration_function},
                      {FUNC_PPS, "pps", pps_function},
                      {FUNC_BPS, "bps", bps_function},
                      {FUNC_BPP, "bpp", bpp_function},
                      {FUNC_MPLS_LABEL, "mpls label", mpls_label_function},
                      {FUNC_MPLS_EOS, "mpls eos", mpls_eos_function},
                      {FUNC_MPLS_EXP, "mpls exp", mpls_exp_function},
                      {FUNC_MPLS_ANY, "mpls any", mpls_any_function},
                      {FUNC_PBLOCK, "pblock", pblock_function},
                      {FUNC_MMAS_LOOKUP, "AS Lockup", mmASLookup_function},
                      {0, NULL, NULL}};

static struct preprocess_s {
    preprocess_proc_t function;
} preprocess_map[] = {{ssl_preproc}, {ja3_preproc}, {ja4_preproc}, {NULL}};

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

// Insert the IP RB tree code here
RB_GENERATE(IPtree, IPListNode, entry, IPNodeCMP);

// Insert the uint64_t RB tree code here
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
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)handle->extensionList[EXmplsLabelID];
    int64_t labelID = data.dataVal;

    return mplsLabel->mplsLabel[labelID] >> 4;

}  // End of mpls_label_function

static uint64_t mpls_eos_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)handle->extensionList[EXmplsLabelID];

    // search for end of MPLS stack label
    for (int i = 0; i < 10; i++) {
        if (mplsLabel->mplsLabel[i] & 1) {
            // End of stack found -> return label
            return mplsLabel->mplsLabel[i] >> 4;
        }
    }

    // if no match above, trick filter to fail with an invalid mpls label value
    return 0xFF000000;

}  // End of mpls_eos_function

static uint64_t mpls_exp_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)handle->extensionList[EXmplsLabelID];

    uint32_t offset = data.dataVal;
    return (mplsLabel->mplsLabel[offset] >> 1) & 0x7;

}  // End of mpls_exp_function

static uint64_t mpls_any_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)handle->extensionList[EXmplsLabelID];
    int64_t labelValue = data.dataVal;

    // search for end of MPLS stack label
    for (int i = 0; i < 10; i++) {
        if ((mplsLabel->mplsLabel[i] >> 4) == labelValue) {
            // Found matching label
            return mplsLabel->mplsLabel[i] >> 4;
        }
    }

    // if no match above, trick filter to fail with an invalid mpls label value
    return 0xFF000000;

    uint32_t offset = data.dataVal;
    return mplsLabel->mplsLabel[offset] >> 4;

}  // End of mpls_any_function

static uint64_t pblock_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle) {
    EXnelXlatePort_t *nelXlatePort = (EXnelXlatePort_t *)handle->extensionList[EXnelXlatePortID];

    if (!nelXlatePort) return 0;

    uint16_t port = *((uint16_t *)dataPtr);

    return (port >= nelXlatePort->blockStart && port <= nelXlatePort->blockEnd);

}  // End of pblock_function

static uint64_t mmASLookup_function(void *dataPtr, uint32_t length, data_t data, recordHandle_t *recordHandle) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];
    uint32_t as = *((uint32_t *)dataPtr);
    if (as) return as;

    if (ipv4Flow) {
        as = LookupV4AS(ipv4Flow->srcAddr);
    } else if (ipv6Flow) {
        as = LookupV6AS(ipv6Flow->srcAddr);
    }
    *((uint32_t *)dataPtr) = as;
    return as;
}  // End of mmASLookup_function

static void *ssl_preproc(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle) {
    const uint8_t *payload = (uint8_t *)(handle->extensionList[EXinPayloadID]);
    if (payload == NULL) return NULL;

    ssl_t *ssl = handle->extensionList[SSLindex];
    if (ssl) return (void *)ssl;

    uint32_t payloadLength = ExtensionLength(payload);
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)(handle->extensionList[EXgenericFlowID]);
    if (genericFlow->proto == IPPROTO_TCP) ssl = sslProcess(payload, payloadLength);
    handle->extensionList[SSLindex] = ssl;
    return ssl;

}  // End of ssl_preproc

static void *ja3_preproc(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle) {
    const uint8_t *payload = (const uint8_t *)handle->extensionList[EXinPayloadID];
    if (payload == NULL) return NULL;

    // return ja3 string if it already exists
    if (handle->extensionList[JA3index]) return handle->extensionList[JA3index];

    ssl_t *ssl = ssl_preproc(dataPtr, length, data, handle);
    if (!ssl) return NULL;

    return ja3Process(ssl, NULL);

}  // End of ja3_preproc

static void *ja4_preproc(void *dataPtr, uint32_t length, data_t data, recordHandle_t *handle) {
    const uint8_t *payload = (uint8_t *)(handle->extensionList[EXinPayloadID]);
    if (payload == NULL) return NULL;

    // return ja4 struct if it already exists
    if (handle->extensionList[JA4index]) return handle->extensionList[JA4index];

    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)(handle->extensionList[EXgenericFlowID]);

    ssl_t *ssl = ssl_preproc(dataPtr, length, data, handle);
    if (ssl == NULL || ssl->type != CLIENTssl) return NULL;
    ja4_t *ja4 = malloc(sizeof(ja4_t) + SIZEja4String + 1);
    if (!ja4) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }
    ja4 = ja4Process(ssl, genericFlow->proto);
    if (ja4) {
        handle->extensionList[JA4index] = (void *)ja4;
        return (void *)ja4;
    }
    return NULL;
}  // End of ja4_preproc

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
            EXnselXlateIPv4_t *nselXlateIPv4 = (EXnselXlateIPv4_t *)recordHandle->extensionList[EXnselXlateIPv4ID];
            EXnselXlateIPv6_t *nselXlateIPv6 = (EXnselXlateIPv6_t *)recordHandle->extensionList[EXnselXlateIPv6ID];
            if (nselXlateIPv4) {
                LookupV4Country(nselXlateIPv4->xlateSrcAddr, geoChar);
            } else if (nselXlateIPv6) {
                LookupV6Country(nselXlateIPv6->xlateSrcAddr, geoChar);
            }
        } break;
        case DIR_DST_NAT: {
            EXnselXlateIPv4_t *nselXlateIPv4 = (EXnselXlateIPv4_t *)recordHandle->extensionList[EXnselXlateIPv4ID];
            EXnselXlateIPv6_t *nselXlateIPv6 = (EXnselXlateIPv6_t *)recordHandle->extensionList[EXnselXlateIPv6ID];
            if (nselXlateIPv4) {
                LookupV4Country(nselXlateIPv4->xlateDstAddr, geoChar);
            } else if (nselXlateIPv6) {
                LookupV6Country(nselXlateIPv6->xlateDstAddr, geoChar);
            }
        } break;
        case DIR_SRC_TUN: {
            EXtunIPv4_t *tunIPv4 = (EXtunIPv4_t *)recordHandle->extensionList[EXtunIPv4ID];
            EXtunIPv6_t *tunIPv6 = (EXtunIPv6_t *)recordHandle->extensionList[EXtunIPv6ID];
            if (tunIPv4) {
                LookupV4Country(tunIPv4->tunSrcAddr, geoChar);
            } else if (tunIPv6) {
                LookupV6Country(tunIPv6->tunSrcAddr, geoChar);
            }
        } break;
        case DIR_DST_TUN: {
            EXtunIPv4_t *tunIPv4 = (EXtunIPv4_t *)recordHandle->extensionList[EXtunIPv4ID];
            EXtunIPv6_t *tunIPv6 = (EXtunIPv6_t *)recordHandle->extensionList[EXtunIPv6ID];
            if (tunIPv4) {
                LookupV4Country(tunIPv4->tunDstAddr, geoChar);
            } else if (tunIPv6) {
                LookupV6Country(tunIPv6->tunDstAddr, geoChar);
            }
        } break;
    }
    return *((uint16_t *)(geoChar));

}  // ENd of geoLookup

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
    dbg_printf("New element: extID: %u, offset: %u, length: %u, value: %llu\n", extID, offset, length, value);

    // sanity check
    if (function && flow_procs_map[function].filterNum != function) {
        LogError("Software error in %s line %d", __FILE__, __LINE__);
        exit(255);
    }

    FilterTree[n] = (filterElement_t){
        .extID = extID,
        .offset = offset,
        .length = length,
        .value = value,
        .invert = 0,
        .OnTrue = 0,
        .OnFalse = 0,
        .comp = comp,
        .function = flow_procs_map[function].function,
        .fname = flow_procs_map[function].name,
        .label = NULL,
        .data = data,
        .numblocks = 1,
        .blocklist = (uint32_t *)malloc(sizeof(uint32_t)),
        .superblock = n,
    };
    FilterTree[n].blocklist[0] = n;

    if (comp > 0 || function > 0 || extID >= MAXEXTENSIONS) Extended = 1;
    NumBlocks++;
    return n;

} /* End of NewElement */

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
    for (int i = 0; i < FilterTree[b].numblocks; i++) {
        FilterTree[a].blocklist[j + i] = FilterTree[b].blocklist[i];
    }
    FilterTree[a].numblocks = s;

    /* set superblock info of all children to new superblock */
    for (int i = 0; i < FilterTree[a].numblocks; i++) {
        j = FilterTree[a].blocklist[i];
        FilterTree[j].superblock = a;
    }

    /* cleanup old node 'b' */
    FilterTree[b].numblocks = 0;
    if (FilterTree[b].blocklist) free(FilterTree[b].blocklist);

} /* End of UpdateList */

/*
 * Clear Filter
 */
static void ClearFilter(void) {
    NumBlocks = 1;
    Extended = 0;
    memset((void *)FilterTree, 0, MAXBLOCKS * sizeof(filterElement_t));
} /* End of ClearFilter */

static void InitFilter(void) {
    memblocks = 1;
    FilterTree = (filterElement_t *)malloc(MAXBLOCKS * sizeof(filterElement_t));
    if (!FilterTree) {
        LogError("Memory allocation error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        exit(255);
    }
    ClearFilter();
}  // End of InitFilter

void FilterSetParam(void *engine, const char *ident, const int hasGeoDB) {
    FilterEngine_t *filterEngine = (FilterEngine_t *)engine;
    filterEngine->hasGeoDB = hasGeoDB;
    filterEngine->ident = ident;
}  // End of FilterSetParam

int FilterRecord(const void *engine, recordHandle_t *handle) {
    FilterEngine_t *filterEngine = (FilterEngine_t *)engine;
    return filterEngine->filterFunction(filterEngine, handle);
}  // End of FilterRecord

static int RunFilterFast(const FilterEngine_t *engine, recordHandle_t *handle) {
    uint32_t index = engine->StartNode;
    int invert = 0;
    int evaluate = 0;
    while (index) {
        size_t offset = engine->filter[index].offset;
        uint32_t extID = engine->filter[index].extID;
        invert = engine->filter[index].invert;

        void *inPtr = handle->extensionList[extID];
        if (inPtr == NULL) {
            evaluate = 0;
            index = engine->filter[index].OnFalse;
            continue;
        }
        inPtr += offset;

        uint64_t inVal = 0;
        dbg_assert(engine->filter[index].length <= 8);
        switch (engine->filter[index].length) {
            case 0:
                break;
            case 1:
                inVal = *((uint8_t *)inPtr);
                break;
            case 2:
                inVal = *((uint16_t *)inPtr);
                break;
            case 4:
                inVal = *((uint32_t *)inPtr);
                break;
            case 8:
                inVal = *((uint64_t *)inPtr);
                break;
            default:
                memcpy((void *)&inVal, inPtr, engine->filter[index].length);
        }

        // printf("Value: %.16llx, : %.16llx\n", (long long unsigned)inVal, engine->filter[index].value);
        evaluate = inVal == engine->filter[index].value;
        index = evaluate ? engine->filter[index].OnTrue : engine->filter[index].OnFalse;
    }
    return invert ? !evaluate : evaluate;

}  // End of RunFilter

static int RunExtendedFilter(const FilterEngine_t *engine, recordHandle_t *handle) {
    uint32_t index = engine->StartNode;
    int evaluate = 0;
    int invert = 0;
    while (index) {
        uint32_t extID = engine->filter[index].extID;
        size_t offset = engine->filter[index].offset;
        invert = engine->filter[index].invert;

        void *inPtr = handle->extensionList[extID];
        if (inPtr == NULL) {
            evaluate = 0;
            if (extID <= MAXEXTENSIONS) {
                index = engine->filter[index].OnFalse;
                continue;
            }
            data_t data = engine->filter[index].data;
            uint32_t length = engine->filter[index].length;
            inPtr = preprocess_map[extID - MAXEXTENSIONS - 1].function(inPtr, length, data, handle);
            if (inPtr == NULL) {
                index = engine->filter[index].OnFalse;
                continue;
            }
        }
        inPtr += offset;

        data_t data = engine->filter[index].data;
        uint32_t length = engine->filter[index].length;
        uint64_t inVal = 0;
        if (engine->filter[index].function != NULL) {
            inVal = engine->filter[index].function(inPtr, length, data, handle);
        } else {
            switch (length) {
                case 0:
                    break;
                case 1:
                    inVal = *((uint8_t *)inPtr);
                    break;
                case 2:
                    inVal = *((uint16_t *)inPtr);
                    break;
                case 4:
                    inVal = *((uint32_t *)inPtr);
                    break;
                case 8:
                    inVal = *((uint64_t *)inPtr);
                case 3:
                case 5:
                case 7:
                    memcpy((void *)&inVal, inPtr, length);
                    break;
            }
        }

        switch (engine->filter[index].comp) {
            case CMP_EQ:
                evaluate = inVal == engine->filter[index].value;
                break;
            case CMP_GT:
                evaluate = inVal > engine->filter[index].value;
                break;
            case CMP_LT:
                evaluate = inVal < engine->filter[index].value;
                break;
            case CMP_GE:
                evaluate = inVal >= engine->filter[index].value;
                break;
            case CMP_LE:
                evaluate = inVal <= engine->filter[index].value;
                break;
            case CMP_FLAGS: {
                evaluate = (inVal & engine->filter[index].value) == engine->filter[index].value;
            } break;
            case CMP_IDENT: {
                char *str = (char *)data.dataPtr;
                evaluate = str != NULL && (strcmp(engine->ident, str) == 0 ? 1 : 0);
            } break;
            case CMP_STRING: {
                char *str = (char *)data.dataPtr;
                evaluate = str != NULL && (strcmp(inPtr, str) == 0 ? 1 : 0);
            } break;
            case CMP_SUBSTRING: {
                char *str = (char *)data.dataPtr;
                evaluate = str != NULL && (strstr(inPtr, str) != NULL ? 1 : 0);
            } break;
            case CMP_BINARY: {
                void *dataPtr = data.dataPtr;
                evaluate = dataPtr != NULL && memcmp(inPtr, dataPtr, length) == 0;
            } break;
            case CMP_NET: {
                uint64_t mask = data.dataVal;
                evaluate = (inVal & mask) == engine->filter[index].value;
            } break;
            case CMP_IPLIST: {
                if (length == 4) {
                    struct IPListNode find = {.ip[0] = 0, .ip[1] = inVal, .mask[0] = 0xffffffffffffffffLL, .mask[1] = 0xffffffffffffffffLL};
                    evaluate = RB_FIND(IPtree, data.dataPtr, &find) != NULL;
                } else if (length == 16) {
                    struct IPListNode find = {.ip[0] = *((uint64_t *)inPtr),
                                              .ip[1] = *((uint64_t *)(inPtr + 8)),
                                              .mask[0] = 0xffffffffffffffffLL,
                                              .mask[1] = 0xffffffffffffffffLL};
                    evaluate = RB_FIND(IPtree, data.dataPtr, &find) != NULL;
                } else {
                    evaluate = 0;
                }
            } break;
            case CMP_U64LIST: {
                struct U64ListNode find = {.value = inVal};
                evaluate = RB_FIND(U64tree, data.dataPtr, &find) != NULL;
            } break;
            case CMP_PAYLOAD: {
                char *payload = (char *)(handle->extensionList[extID]);
                char *string = (char *)engine->filter[index].data.dataPtr;
                uint32_t len = ExtensionLength(payload);
                evaluate = 0;
                if (string != NULL) {
                    // find any string str in payload data inPtr, even beyond '\0' bytes
                    int m = 0;
                    for (int i = 0; i < len; i++) {
                        if (payload[i] == string[m]) {
                            m++;
                            if (string[m] == '\0') {
                                evaluate = 1;
                                break;
                            }
                        } else {
                            m = 0;
                        }
                    }
                }
            } break;
            case CMP_REGEX: {
                srx_Context *program = (srx_Context *)data.dataPtr;
                char *payload = (char *)(handle->extensionList[extID]);
                uint32_t len = ExtensionLength(payload);

                evaluate = program != NULL && srx_MatchExt(program, payload, len, 0);
            } break;
            case CMP_GEO: {
                char *geoChar = (char *)inPtr;
                if (engine->hasGeoDB && geoChar[0] == '\0') inVal = geoLookup(geoChar, data.dataVal, handle);
                evaluate = inVal == engine->filter[index].value;
            } break;
        }
        index = evaluate ? engine->filter[index].OnTrue : engine->filter[index].OnFalse;
    }
    return invert ? !evaluate : evaluate;
}  // End of RunFilter

char *ReadFilter(char *filename) {
    struct stat stat_buff;
    if (stat(filename, &stat_buff)) {
        LogError("Can't stat filter file '%s': %s", filename, strerror(errno));
        exit(EXIT_FAILURE);
    }
    char *filter = (char *)malloc(stat_buff.st_size + 1);
    if (!filter) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        exit(EXIT_FAILURE);
    }
    int ffd = open(filename, O_RDONLY);
    if (ffd < 0) {
        LogError("Can't open filter file '%s': %s", filename, strerror(errno));
        exit(EXIT_FAILURE);
    }
    ssize_t ret = read(ffd, (void *)filter, stat_buff.st_size);
    if (ret < 0) {
        LogError("Error reading filter file %s: %s", filename, strerror(errno));
        close(ffd);
        exit(EXIT_FAILURE);
    }
    filter[stat_buff.st_size] = 0;
    close(ffd);

    return filter;

}  // End of ReadFilter

void *CompileFilter(char *FilterSyntax) {
    if (!FilterSyntax) return NULL;

    InitFilter();
    lex_init(FilterSyntax);
    if (yyparse() != 0) {
        return NULL;
    }
    lex_cleanup();

    FilterEngine_t *engine = malloc(sizeof(FilterEngine_t));
    if (!engine) {
        LogError("Memory allocation error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        exit(255);
    }
    *engine = (FilterEngine_t){
        .label = NULL,
        .StartNode = StartNode,
        .Extended = Extended,
        .filter = FilterTree,
        .hasGeoDB = 0,
        .filterFunction = Extended ? RunExtendedFilter : RunFilterFast,
    };
    FilterTree = NULL;

    dbg_printf("Engine: %s\n", engine->Extended ? "extended" : "fast");

    return (void *)engine;

}  // End of CompileFilter

void DisposeFilter(void *engine) { free(engine); }

/*
 * Dump Filterlist
 */
void DumpEngine(void *arg) {
    if (arg == NULL) return;
    FilterEngine_t *engine = (FilterEngine_t *)arg;

    printf("StartNode: %i Engine: %s\n", engine->StartNode, engine->Extended ? "Extended" : "Fast");
    for (int i = 1; i < NumBlocks; i++) {
        if (engine->filter[i].invert)
            printf(
                "Index: %u, ExtID: %u, Offset: %u, Length: %u, Value: %.16llx, Superblock: %u, Numblocks: %u, "
                "!OnTrue: %u, !OnFalse: %u Comp: %u Function: %s, Label: %s\n",
                i, engine->filter[i].extID, engine->filter[i].offset, engine->filter[i].length, (unsigned long long)engine->filter[i].value,
                engine->filter[i].superblock, engine->filter[i].numblocks, engine->filter[i].OnTrue, engine->filter[i].OnFalse,
                engine->filter[i].comp, engine->filter[i].fname, engine->filter[i].label ? engine->filter[i].label : "<none>");
        else
            printf(
                "Index: %u, ExtID: %u, Offset: %u, Length: %u, Value: %.16llx, Superblock: %u, Numblocks: %u, "
                "OnTrue: %u, OnFalse: %u Comp: %u Function: %s, Label: %s\n",
                i, engine->filter[i].extID, engine->filter[i].offset, engine->filter[i].length, (unsigned long long)engine->filter[i].value,
                engine->filter[i].superblock, engine->filter[i].numblocks, engine->filter[i].OnTrue, engine->filter[i].OnFalse,
                engine->filter[i].comp, engine->filter[i].fname, engine->filter[i].label ? engine->filter[i].label : "<none>");
        if (engine->filter[i].OnTrue > (memblocks * MAXBLOCKS) || engine->filter[i].OnFalse > (memblocks * MAXBLOCKS)) {
            fprintf(stderr, "Tree pointer out of range for index %u. *** ABORT ***\n", i);
            exit(255);
        }
        if (engine->filter[i].data.dataPtr) {
            if (engine->filter[i].comp == CMP_IPLIST) {
                struct IPListNode *node;
                RB_FOREACH(node, IPtree, engine->filter[i].data.dataPtr) {
                    printf("value: %.16" PRIx64 " %.16" PRIx64 " mask: %.16" PRIx64 " %.16" PRIx64 "\n", node->ip[0], node->ip[1], node->mask[0],
                           node->mask[1]);
                }
            } else if (engine->filter[i].comp == CMP_U64LIST) {
                struct U64ListNode *node;
                RB_FOREACH(node, U64tree, engine->filter[i].data.dataPtr) { printf("%.16llx \n", (unsigned long long)node->value); }
            } else
                printf("Data: %" PRIu64 " - %" PRIu64 "\n", engine->filter[i].data.dataVal, engine->filter[i].data.dataVal);
        }
        printf("\tBlocks: ");
        for (int j = 0; j < engine->filter[i].numblocks; j++) printf("%i ", engine->filter[i].blocklist[j]);
        printf("\n");
    }
    printf("NumBlocks: %i\n", NumBlocks - 1);
} /* End of DumpList */
