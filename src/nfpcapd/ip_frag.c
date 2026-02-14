/*
 *  Copyright (c) 2026, Peter Haag
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
#include "ip128.h"
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
    ip128_t srcAddr;
    ip128_t dstAddr;
    time_t created;          // timestamp, when created, so we can expire old entries
    void *payload;           // memory block to reassemble payload and hole list
    uint32_t fragID;         // fragment ID
    uint32_t numHoles;       // number of total holes
    uint16_t holeList;       // first index into hole list in payload RFC815
    uint16_t payloadLength;  // length of reassembled payload
} ipFrag_t;

#define MAXINDEX 0xFFFF

#define FRAGMENT_TIMEOUT 10

// fragment list
// use dynamic batches of NUMFRAGMENTS for the fragment array
#define NUMFRAGMENTS 32
static struct ipFragList_s {
    uint32_t numFrags;   // number of fragments in array
    ipFrag_t *fragList;  // dynamic array of fragments. Batches of NUMFRAGMENTS
} ipFragList = {.numFrags = 0, .fragList = NULL};

// init a new fragment in slot
static int initSlot(int slot, const ip128_t *srcAddr, const ip128_t *dstAddr, const uint32_t fragID, time_t when) {
    dbg_printf("Init fragment slot %d\n", slot);

    void *payload = calloc(1, MAXINDEX + 1);
    if (!payload) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    // init hole list - one big hole - use first 8 bytes in payload as hole list info - RFC815
    hole_t *hole = (hole_t *)payload;
    *hole = (hole_t){.first = 0, .last = MAXINDEX, .next = 0xFFFF, .fill = 0};

    ipFragList.fragList[slot] = (ipFrag_t){.payload = payload, .fragID = fragID, .holeList = 0, .numHoles = 1, .created = when};
    memcpy(ipFragList.fragList[slot].srcAddr.bytes, srcAddr->bytes, 16);
    memcpy(ipFragList.fragList[slot].dstAddr.bytes, dstAddr->bytes, 16);

    return 1;
}  // End of initSlot

static void expireFragmentList(time_t now, time_t timeout) {
    uint32_t cnt = 0;
    for (int slot = 0; slot < ipFragList.numFrags; slot++) {
        // skip empty slots
        if (ipFragList.fragList[slot].created == 0) continue;

        // free up old entries not completed, since created + timeout
        if ((ipFragList.fragList[slot].created + timeout) < now) {
            free(ipFragList.fragList[slot].payload);
            ipFragList.fragList[slot].payload = NULL;
            ipFragList.fragList[slot].created = 0;
            ipFragList.fragList[slot].fragID = 0;
            cnt++;
        }
    }
    if (cnt) LogVerbose("Deleted %u incomplete IP fragments", cnt);

}  // End of expireFragmentList

// get the existing or a new fragment struct for srcAddr/dstAddr/fragID
static ipFrag_t *getIPFragement(const ip128_t *srcAddr, const ip128_t *dstAddr, const uint32_t fragID, time_t when) {
    // Periodically expire old fragments
    static time_t lastExpire = 0;
    if (when - lastExpire > 10) {
        expireFragmentList(when, FRAGMENT_TIMEOUT);
        lastExpire = when;
    }

    unsigned slot;
    int firstEmpty = -1;
    for (slot = 0; slot < ipFragList.numFrags; slot++) {
        if (ipFragList.fragList[slot].fragID == 0 && firstEmpty < 0) firstEmpty = slot;
        if (ipFragList.fragList[slot].fragID == fragID && (memcmp(ipFragList.fragList[slot].srcAddr.bytes, srcAddr->bytes, 16) == 0) &&
            (memcmp(ipFragList.fragList[slot].dstAddr.bytes, dstAddr->bytes, 16) == 0))
            break;
    }

    if (slot == ipFragList.numFrags) {
        // fragID not found
        if (firstEmpty < 0) {
            // no empty slot and all slots exhausted - extend fragment list by NUMFRAGMENTS
            void *tmp = realloc(ipFragList.fragList, (ipFragList.numFrags + NUMFRAGMENTS) * sizeof(ipFrag_t));
            if (!tmp) {
                LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                return NULL;
            }
            ipFragList.fragList = tmp;
            uint32_t max = ipFragList.numFrags + NUMFRAGMENTS;
            // init new empty slots
            for (unsigned i = ipFragList.numFrags; i < max; i++) ipFragList.fragList[i].fragID = 0;
            ipFragList.numFrags = max;
            if (!initSlot(slot, srcAddr, dstAddr, fragID, when)) return NULL;
        } else {
            // assign first empty slot in list
            slot = (unsigned)firstEmpty;
            if (!initSlot(slot, srcAddr, dstAddr, fragID, when)) return NULL;
        }
    }  // else fragment in slot found

    dbg_printf("Return fragment slot %d\n", slot);
    ipFrag_t *fragment = &ipFragList.fragList[slot];
    return fragment;
}  // End of getIPFragement

static int findHole(ipFrag_t *fragment, uint16_t fragFirst, uint16_t fragLast, int moreFragments) {
    uint16_t *prefIndex = &fragment->holeList;
    uint8_t *payload = (uint8_t *)fragment->payload;
    hole_t result = {0};

    dbg_printf("defrag - find hole for %u - %u\n", fragFirst, fragLast);

    // search for hole to map this fragment
    if (fragment->numHoles == 0) {
        // no more holes but still a packet to reassemble - possibly wrong
        LogError("ProcessIPFragment() reassembly error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    // search hole list for suitable hole in payload
    // 0xFFFF is our 'End of List' sentinel
    while (*prefIndex != 0xFFFF) {
        hole_t *hole = (hole_t *)(&payload[*prefIndex]);
        if (fragFirst > hole->last || fragLast < hole->first) {
            // fragment outside hole
            dbg_printf("defrag - hole %u - %u - no match\n", hole->first, hole->last);
            prefIndex = &hole->next;
            continue;
        }

        // Hole found! Delete it from the linked list
        // Copy the hole to the stack before we delete/modify it
        result = *hole;
        dbg_printf("defrag - hole %u - %u - found\n", hole->first, hole->last);

        // Delete the hole from the linked list
        *prefIndex = result.next;
        fragment->numHoles--;

        // Create hole to the left
        if (fragFirst > result.first) {
            uint16_t newOffset = result.first;
            hole_t *newHole = (hole_t *)&payload[newOffset];
            *newHole = (hole_t){.first = result.first, .last = fragFirst - 1, .next = fragment->holeList};
            dbg_printf("defrag - new hole left: %u - %u created\n", newHole->first, newHole->last);
            fragment->holeList = newOffset;
            fragment->numHoles++;
        }

        // Create hole to the right
        if (fragLast < result.last && moreFragments) {
            uint16_t newOffset = fragLast + 1;
            hole_t *newHole = (hole_t *)&payload[newOffset];
            *newHole = (hole_t){.first = fragLast + 1, .last = result.last, .next = fragment->holeList};
            dbg_printf("defrag - new hole right: %u - %u created\n", newHole->first, newHole->last);
            fragment->holeList = newOffset;
            fragment->numHoles++;
        }

        dbg_printf("defrag - fragment has %u holes\n", fragment->numHoles);

        return 1;
    }

    return 0;

}  // End of findHole

// Defragment IPv6 packets according RFC815
void *ProcessIP6Fragment(const struct ip6_hdr *ip6, const struct ip6_frag *ip6_frag, const void *eodata, uint32_t *payloadLength, time_t when) {
    ip128_t srcAddr, dstAddr;
    memcpy(srcAddr.bytes, ip6->ip6_src.s6_addr, 16);
    memcpy(dstAddr.bytes, ip6->ip6_dst.s6_addr, 16);
    uint32_t fragID = ntohl(ip6_frag->ip6f_ident);

    ipFrag_t *fragment = getIPFragement(&srcAddr, &dstAddr, fragID, when);
    if (!fragment) return NULL;

    uint16_t offset = ntohs(ip6_frag->ip6f_offlg);
    int moreFragments = offset & 0x1;
    offset = offset & 0xFFF8;
    uint16_t ipPayloadLength = ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen) - sizeof(struct ip6_frag);
    void *ipPayload = (void *)ip6_frag + sizeof(struct ip6_frag);

    if ((uint8_t *)ipPayload + ipPayloadLength > (uint8_t *)eodata) {
        LogError("IPv6 Fragment exceeds capture buffer");
        return NULL;
    }

    // Check for overflow: offset + payload must fit in 65535 bytes (max IP packet)
    if ((uint32_t)offset + ipPayloadLength > 65535) {
        LogError("IPv6 Fragment would exceed maximum IP packet size");
        return NULL;
    }

    uint16_t fragFirst = offset;
    uint16_t fragLast = offset + ipPayloadLength - 1;

    if (!findHole(fragment, fragFirst, fragLast, moreFragments)) {
        // This fragment is a duplicate or doesn't fit any current hole
        return NULL;
    }

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
        fragment->fragID = 0;
        fragment->created = 0;
        fragment->payload = NULL;
        *payloadLength = fragment->payloadLength;
        dbg_printf("Complete fragment. Size: %u\n", fragment->payloadLength);
        return payload;
    }

    return NULL;
}  // End of ProcessIP6Fragment

// Defragment IPv4 packets according RFC815
void *ProcessIP4Fragment(const struct ip *ip4, const void *eodata, uint32_t *payloadLength, time_t when) {
    static const uint8_t prefix[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};
    ip128_t srcAddr = {0};
    ip128_t dstAddr = {0};
    memcpy(srcAddr.bytes, prefix, 12);
    memcpy(dstAddr.bytes, prefix, 12);
    memcpy(srcAddr.bytes + 12, &ip4->ip_src.s_addr, 4);
    memcpy(dstAddr.bytes + 12, &ip4->ip_dst.s_addr, 4);

    uint32_t fragID = ntohs(ip4->ip_id);
    ipFrag_t *fragment = getIPFragement(&srcAddr, &dstAddr, fragID, when);
    if (!fragment) return NULL;

    uint16_t ip_off = ntohs(ip4->ip_off);
    uint32_t offset = (ip_off & IP_OFFMASK) << 3;
    int moreFragments = ip_off & IP_MF;

    ptrdiff_t sizeIP = (ip4->ip_hl << 2);
    uint16_t ipPayloadLength = ntohs(ip4->ip_len) - sizeIP;
    void *ipPayload = (void *)ip4 + sizeIP;
    if ((uint8_t *)ipPayload + ipPayloadLength > (uint8_t *)eodata) {
        LogError("IPv4 Fragment exceeds capture buffer");
        return NULL;
    }

    // Check for overflow: offset + payload must fit in 65535 bytes (max IP packet)
    if (offset + ipPayloadLength > 65535) {
        LogError("IPv4 Fragment would exceed maximum IP packet size");
        return NULL;
    }

    uint16_t fragFirst = offset;
    uint16_t fragLast = offset + ipPayloadLength - 1;

    if (!findHole(fragment, fragFirst, fragLast, moreFragments)) {
        // This fragment is a duplicate or doesn't fit any current hole
        return NULL;
    }

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
        fragment->fragID = 0;
        fragment->created = 0;
        fragment->payload = NULL;
        *payloadLength = fragment->payloadLength;
        dbg_printf("Complete fragment. Size: %u\n", fragment->payloadLength);
        return payload;
    }

    return NULL;
}  // End of ProcessIP4Fragment