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

#include "ip_frag.h"

#include <errno.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "config.h"
#include "nfdump.h"
#include "util.h"

/*
 * defragmentation and reassembly follows RFC815
 *
 * - The max assembly size is 65636 bytes
 * - The hole list and the reassembled payload are stored in the same memory block
 * - Holes have a hole_t header at the beginning, marking first/last index of the hole
 *   as well as the index of the next hole in the memory block.
 * - The next index of the last hole is 0
 * - The first index of the hole list is stored in the fragement struct
 * - The total number of holes is stored in the fragment struct
 *
 */

// Hole header leading a free block in memory
typedef struct hole_s {
    uint16_t first;  // offset of hole start
    uint16_t last;   // offset of hole last
    uint16_t next;   // offset of next hole -> linked list
    uint16_t fill;   // empty - alignment 8 bytes
} hole_t;

// fragment record for each fragmented connection
typedef struct ip6Frag_s {
    ip_addr_t srcAddr;
    ip_addr_t dstAddr;
    void *payload;           // memory block to reassemble payload and hole list
    uint32_t fragID;         // fragment ID
    uint32_t numHoles;       // number of total holes
    uint16_t holeList;       // first index into hole list in payload RFC815
    uint16_t payloadLength;  // length of reassembled payload
} ipFrag_t;

#define MAXINDEX 0xFFFF

// fragment list
// use dynamic batches of NUMFRAGMENTS for the fragment array
#define NUMFRAGMENTS 32
static struct ipFragList_s {
    uint32_t numFrags;   // number of fragments in array
    ipFrag_t *fragList;  // dynamic array of fragments. Batches of NUMFRAGMENTS
} ipFragList = {.numFrags = 0, .fragList = NULL};

// init a new fragment in slot
static int initSlot(int slot, const ip_addr_t *srcAddr, const ip_addr_t *dstAddr, const uint32_t fragID) {
    dbg_printf("Init fragment slot %d\n", slot);

    void *payload = calloc(1, MAXINDEX + 1);
    if (!payload) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    // init hole list - one big hole - use first 8 bytes in payload as hole list info - RFC815
    hole_t *hole = (hole_t *)payload;
    *hole = (hole_t){.first = 0, .last = MAXINDEX, .next = 0, .fill = 0};

    ipFragList.fragList[slot] = (ipFrag_t){.payload = payload, .fragID = fragID, .holeList = 0, .numHoles = 1};
    memcpy(ipFragList.fragList[slot].srcAddr.V6, srcAddr->V6, 16);
    memcpy(ipFragList.fragList[slot].dstAddr.V6, dstAddr->V6, 16);

    return 1;
}  // End of initSlot

// get the existing or a new fragment struct for srcAddr/dstAddr/fragID
static ipFrag_t *getIPFragement(const ip_addr_t *srcAddr, const ip_addr_t *dstAddr, const uint32_t fragID) {
    int slot;
    int firstEmpty = -1;
    for (slot = 0; slot < ipFragList.numFrags; slot++) {
        if (ipFragList.fragList[slot].fragID == 0 && firstEmpty < 0) firstEmpty = slot;
        if (ipFragList.fragList[slot].fragID == fragID && (memcmp(ipFragList.fragList[slot].srcAddr.V6, srcAddr->ip_addr._v6, 16) == 0) &&
            (memcmp(ipFragList.fragList[slot].dstAddr.V6, dstAddr->ip_addr._v6, 16) == 0))
            break;
    }

    if (slot == ipFragList.numFrags) {
        // fragID not found
        if (firstEmpty < 0) {
            // no empty slot and all slots exhausted - extend fragment list by NUMFRAGMENTS
            ipFragList.fragList = realloc(ipFragList.fragList, (ipFragList.numFrags + NUMFRAGMENTS) * sizeof(ipFrag_t));
            if (!ipFragList.fragList) {
                LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                return NULL;
            }
            uint32_t max = ipFragList.numFrags + NUMFRAGMENTS;
            // init new empty slots
            for (int i = ipFragList.numFrags; i < max; i++) ipFragList.fragList[i].fragID = 0;
            ipFragList.numFrags = max;
            if (!initSlot(slot, srcAddr, dstAddr, fragID)) return NULL;
        } else {
            // assign first empty slot in list
            slot = firstEmpty;
            if (!initSlot(slot, srcAddr, dstAddr, fragID)) return NULL;
        }
    }  // else fragment in slot found

    dbg_printf("Return fragment slot %d\n", slot);
    ipFrag_t *fragment = &ipFragList.fragList[slot];
    return fragment;
}  // End of getIPFragement

static hole_t *findHole(ipFrag_t *fragment, uint16_t fragFirst, uint16_t fragLast, int moreFragments) {
    uint16_t *prefIndex = &fragment->holeList;
    uint8_t *payload = (uint8_t *)fragment->payload;

    // search for hole to map this fragment
    if (fragment->numHoles == 0) {
        // no more holes but still a packet to reassemble - possibly wrong
        LogError("ProcessIPFragment() reassembly error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    // search hole list for suitable hole in payload
    hole_t *hole = (hole_t *)(&payload[*prefIndex]);
    do {
        if (fragFirst > hole->last || fragLast < hole->first) {
            // fragment outside hole
            prefIndex = &hole->next;
        } else {
            // hole found
            // delete hole from list
            *prefIndex = hole->next;
            fragment->numHoles--;
            break;
        }

        // next hole
        if (hole->next == 0) {
            // end of hole list
            hole = NULL;
            break;
        } else {
            // next hole
            hole = (hole_t *)(&payload[hole->next]);
        }
    } while (1);

    if (hole == NULL) {
        return NULL;
    }

    // check if we need a new hole on the left of the fragment
    if (fragFirst > hole->first) {
        hole_t *newHole = (hole_t *)&payload[hole->first];
        *newHole = (hole_t){.first = hole->first, .last = fragFirst, .next = fragment->holeList};
        fragment->holeList = hole->first;
        fragment->numHoles++;
    }
    // check if we need a new hole on the right of the fragment
    if ((fragLast < hole->last) && moreFragments) {
        hole_t *newHole = (hole_t *)&payload[fragLast + 1];
        *newHole = (hole_t){.first = fragLast + 1, .last = hole->last, .next = fragment->holeList};
        fragment->holeList = fragLast + 1;
        fragment->numHoles++;
    }

    return hole;

}  // End of findHole

// Defragment IPv6 packets according RFC815
void *ProcessIP6Fragment(struct ip6_hdr *ip6, struct ip6_frag *ip6_frag, const void *eodata) {
    ip_addr_t srcAddr, dstAddr;
    memcpy(srcAddr.V6, ip6->ip6_src.s6_addr, 16);
    memcpy(dstAddr.V6, ip6->ip6_dst.s6_addr, 16);
    uint32_t fragID = ntohl(ip6_frag->ip6f_ident);

    ipFrag_t *fragment = getIPFragement(&srcAddr, &dstAddr, fragID);
    if (!fragment) return NULL;

    uint16_t offset = ntohs(ip6_frag->ip6f_offlg);
    int moreFragments = offset & 0x1;
    offset = offset & 0xFFF8;
    uint16_t ipPayloadLength = ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen) - sizeof(struct ip6_frag);
    void *ipPayload = (void *)ip6_frag + sizeof(struct ip6_frag);
    if (ipPayload > eodata) {
        LogError("ProcessIP6Fragment() data length error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    uint16_t fragFirst = offset;
    uint16_t fragLast = offset + ipPayloadLength - 1;

    hole_t *hole = findHole(fragment, fragFirst, fragLast, moreFragments);
    if (!hole) return NULL;

    // copy fragment into payload
    uint8_t *payload = (uint8_t *)fragment->payload;
    memcpy(payload + (ptrdiff_t)fragFirst, ipPayload, ipPayloadLength);

    // if it's the last fragment, copy length info
    if (moreFragments == 0) {
        // last fragment - copy length
        fragment->payloadLength = fragLast + 1;
        dbg_printf("Set fragment size: %u\n", fragment->payloadLength);
    }

    // if no more holes exist, we are done
    if (fragment->numHoles == 0) {
        dbg_printf("Complete fragment\n");
        fragment->fragID = 0;
        fragment->payload = NULL;
        ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(fragment->payloadLength + sizeof(struct ip6_frag));
        return payload;
    }

    return NULL;
}  // End of ProcessIP6Fragment

// Defragment IPv4 packets according RFC815
void *ProcessIP4Fragment(struct ip *ip4, const void *eodata) {
    ip_addr_t srcAddr = {0};
    ip_addr_t dstAddr = {0};
    srcAddr.V4 = ip4->ip_src.s_addr;
    dstAddr.V4 = ip4->ip_dst.s_addr;

    uint32_t fragID = ntohs(ip4->ip_id);
    ipFrag_t *fragment = getIPFragement(&srcAddr, &dstAddr, fragID);
    if (!fragment) return NULL;

    uint16_t ip_off = ntohs(ip4->ip_off);
    uint32_t offset = (ip_off & IP_OFFMASK) << 3;
    int moreFragments = ip_off & IP_MF;

    ptrdiff_t sizeIP = (ip4->ip_hl << 2);
    uint16_t ipPayloadLength = ntohs(ip4->ip_len) - sizeIP;
    void *ipPayload = (void *)ip4 + sizeIP;
    if (ipPayload > eodata) {
        LogError("ProcessIP4Fragment() data length error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    uint16_t fragFirst = offset;
    uint16_t fragLast = offset + ipPayloadLength - 1;

    hole_t *hole = findHole(fragment, fragFirst, fragLast, moreFragments);
    if (!hole) return NULL;

    // copy fragment into payload
    uint8_t *payload = (uint8_t *)fragment->payload;
    memcpy(payload + (ptrdiff_t)fragFirst, ipPayload, ipPayloadLength);

    // if it's the last fragment, copy length info
    if (moreFragments == 0) {
        // last fragment - copy length
        fragment->payloadLength = fragLast + 1;
        dbg_printf("Set fragment size: %u\n", fragment->payloadLength);
    }

    // if no more holes exist, we are done
    if (fragment->numHoles == 0) {
        dbg_printf("Complete fragment\n");
        fragment->fragID = 0;
        fragment->payload = NULL;
        ip4->ip_len = htons(fragment->payloadLength + sizeIP);
        return payload;
    }

    return NULL;
}  // End of ProcessIP4Fragment