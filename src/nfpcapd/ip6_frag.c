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

#include "ip6_frag.h"

#include <errno.h>
#include <netinet/ip6.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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
} ip6Frag_t;

#define MAXINDEX 0xFFFF

// fragment list
// use dynamic batches of NUMFRAGMENTS for the fragment array
#define NUMFRAGMENTS 32
static struct ip6FragList_s {
    uint32_t numFrags;    // number of fragments in array
    ip6Frag_t *fragList;  // dynamic array of fragments. Batches of NUMFRAGMENTS
} ip6FragList = {.numFrags = 0, .fragList = NULL};

// init a new fragment in slot
static int initSlot(int slot, uint32_t fragID) {
    void *payload = calloc(1, MAXINDEX + 1);
    if (!payload) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    // init hole list - one big hole - use first 8 bytes in payload as hole list info - RFC815
    hole_t *hole = (hole_t *)payload;
    *hole = (hole_t){.first = 0, .last = MAXINDEX, .next = 0, .fill = 0};

    ip6FragList.fragList[slot] = (ip6Frag_t){.payload = payload, .fragID = fragID, .holeList = 0, .numHoles = 1};

    return 1;
}  // End of initSlot

// get the existing or a new fragment struct for fragID
static ip6Frag_t *getIP6Fragement(struct ip6_hdr *ip6, uint32_t fragID) {
    int slot;
    int firstEmpty = -1;
    for (slot = 0; slot < ip6FragList.numFrags; slot++) {
        if (ip6FragList.fragList[slot].fragID == 0 && firstEmpty < 0) firstEmpty = slot;
        if (ip6FragList.fragList[slot].fragID == fragID) break;
    }

    if (slot == ip6FragList.numFrags) {
        // fragID not found
        if (firstEmpty < 0) {
            // no empty slot and all slots exhausted - extend fragment list by NUMFRAGMENTS
            ip6FragList.fragList = realloc(ip6FragList.fragList, (ip6FragList.numFrags + NUMFRAGMENTS) * sizeof(ip6Frag_t));
            if (!ip6FragList.fragList) {
                LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                return NULL;
            }
            uint32_t max = ip6FragList.numFrags + NUMFRAGMENTS;
            // init new empty slots
            for (int i = ip6FragList.numFrags; i < max; i++) ip6FragList.fragList[i].fragID = 0;
            ip6FragList.numFrags = max;
            if (!initSlot(slot, fragID)) return NULL;
        } else {
            // assign first empty slot in list
            slot = firstEmpty;
            if (!initSlot(slot, fragID)) return NULL;
        }
    }  // else fragment in slot found

    ip6Frag_t *fragment = &ip6FragList.fragList[slot];
    return fragment;
}  // End of getIP6Fragement

// Defragment packets according RFC815
void *ProcessIP6Fragment(struct ip6_hdr *ip6, struct ip6_frag *ip6_frag, void *eodata) {
    uint32_t fragID = ntohl(ip6_frag->ip6f_ident);
    ip6Frag_t *fragment = getIP6Fragement(ip6, fragID);
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

    ptrdiff_t fragFirst = offset;
    uint16_t fragLast = offset + ipPayloadLength - 1;

    // search for hole to map this fragment
    if (fragment->numHoles == 0) {
        // no more holes but still a packet to reassemble - possibly wrong
        LogError("ProcessIP6Fragment() reassembly error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    uint16_t *prefIndex = &fragment->holeList;
    uint8_t *payload = (uint8_t *)fragment->payload;

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
    // copy fragment into payload
    memcpy(payload + fragFirst, ipPayload, ipPayloadLength);

    // if it's the last fragment, copy length info
    if (moreFragments == 0) {
        // last fragment - copy length
        fragment->payloadLength = fragLast + 1;
    }

    // if no more holes exist, we are done
    if (fragment->numHoles == 0) {
        fragment->fragID = 0;
        fragment->payload = NULL;
        ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(fragment->payloadLength + sizeof(struct ip6_frag));
        return payload;
    }

    return NULL;
}  // End of ProcessIP6Fragment