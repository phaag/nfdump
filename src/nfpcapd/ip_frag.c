/*
 *  Copyright (c) 2025-2026, Peter Haag
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
#include "logging.h"
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
    time_t lastSeen;         // timestamp of last successfully accepted fragment
    void *payload;           // memory block to reassemble payload and hole list
    uint32_t fragID;         // fragment ID
    uint32_t numHoles;       // number of total holes
    uint16_t holeList;       // first index into hole list in payload RFC815
    uint16_t payloadLength;  // length of reassembled payload
    uint8_t proto;           // next-header protocol; prevents cross-protocol ID collisions
} ipFrag_t;

#define MAXINDEX 0xFFFF

#define FRAGMENT_TIMEOUT 10
#define FRAGMENT_MAINTENANCE_INTERVAL 5

// fragment list
// use dynamic batches of NUMFRAGMENTS for the fragment array
#define NUMFRAGMENTS 32
#define MAX_FRAGMENTS 256
static struct ipFragList_s {
    uint32_t numFrags;   // number of fragments in array
    ipFrag_t *fragList;  // dynamic array of fragments. Batches of NUMFRAGMENTS
} ipFragList = {.numFrags = 0, .fragList = NULL};
static time_t lastFragmentMaintenance = 0;

// init a new fragment in slot
static int initSlot(int slot, const ip128_t *srcAddr, const ip128_t *dstAddr, const uint32_t fragID, uint8_t proto, time_t when) {
    dbg_printf("Init fragment slot %d\n", slot);

    void *payload = calloc(1, MAXINDEX + 1);
    if (!payload) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    // init hole list - one big hole - use first 8 bytes in payload as hole list info - RFC815
    hole_t *hole = (hole_t *)payload;
    *hole = (hole_t){.first = 0, .last = MAXINDEX, .next = 0xFFFF, .fill = 0};

    ipFragList.fragList[slot] =
        (ipFrag_t){.payload = payload, .fragID = fragID, .proto = proto, .holeList = 0, .numHoles = 1, .lastSeen = when};
    memcpy(ipFragList.fragList[slot].srcAddr.bytes, srcAddr->bytes, 16);
    memcpy(ipFragList.fragList[slot].dstAddr.bytes, dstAddr->bytes, 16);

    return 1;
}  // End of initSlot

static uint32_t expireFragmentList(time_t now) {
    uint32_t cnt = 0;
    for (int slot = 0; slot < (int)ipFragList.numFrags; slot++) {
        // skip empty slots
        if (ipFragList.fragList[slot].lastSeen == 0) continue;

        // Expire incomplete assemblies after a period without accepted fragments.
        if (now >= ipFragList.fragList[slot].lastSeen &&
            (uint64_t)(now - ipFragList.fragList[slot].lastSeen) >= FRAGMENT_TIMEOUT) {
            free(ipFragList.fragList[slot].payload);
            memset(&ipFragList.fragList[slot], 0, sizeof(ipFrag_t));
            cnt++;
        }
    }
    if (cnt) LogVerbose("Deleted %u incomplete IP fragments", cnt);

    return cnt;
}  // End of expireFragmentList

void MaintainIPFragments(time_t now) {
    if (lastFragmentMaintenance != 0) {
        if (now < lastFragmentMaintenance) return;
        if ((uint64_t)(now - lastFragmentMaintenance) < FRAGMENT_MAINTENANCE_INTERVAL) return;
    }

    lastFragmentMaintenance = now;
    expireFragmentList(now);
}  // End of MaintainIPFragments

void DisposeIPFragments(void) {
    uint32_t cnt = 0;

    for (uint32_t slot = 0; slot < ipFragList.numFrags; slot++) {
        if (ipFragList.fragList[slot].lastSeen == 0) continue;
        free(ipFragList.fragList[slot].payload);
        cnt++;
    }
    free(ipFragList.fragList);
    ipFragList = (struct ipFragList_s){.numFrags = 0, .fragList = NULL};
    lastFragmentMaintenance = 0;

    if (cnt) LogVerbose("Disposed %u incomplete IP fragments", cnt);
}  // End of DisposeIPFragments

// get the existing or a new fragment struct for srcAddr/dstAddr/fragID
static ipFrag_t *getIPFragement(const ip128_t *srcAddr, const ip128_t *dstAddr, const uint32_t fragID, uint8_t proto, time_t when) {
    unsigned slot;
    int firstEmpty = -1;
    for (slot = 0; slot < ipFragList.numFrags; slot++) {
        if (ipFragList.fragList[slot].lastSeen == 0 && firstEmpty < 0) firstEmpty = slot;
        if (ipFragList.fragList[slot].fragID == fragID && ipFragList.fragList[slot].proto == proto &&
            (memcmp(ipFragList.fragList[slot].srcAddr.bytes, srcAddr->bytes, 16) == 0) &&
            (memcmp(ipFragList.fragList[slot].dstAddr.bytes, dstAddr->bytes, 16) == 0))
            break;
    }

    if (slot == ipFragList.numFrags) {
        // fragID not found
        if (firstEmpty < 0) {
            if (ipFragList.numFrags >= MAX_FRAGMENTS) {
                LogVerbose("Too many incomplete IP fragments; dropping fragment");
                return NULL;
            }
            // no empty slot  - no slots yet or all slots exhausted - extend fragment list by NUMFRAGMENTS
            void *tmp = realloc(ipFragList.fragList, (ipFragList.numFrags + NUMFRAGMENTS) * sizeof(ipFrag_t));
            if (!tmp) {
                LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                return NULL;
            }
            ipFragList.fragList = tmp;
            uint32_t max = ipFragList.numFrags + NUMFRAGMENTS;
            // init new empty slots
            for (unsigned i = ipFragList.numFrags; i < max; i++) {
                memset(&ipFragList.fragList[i], 0, sizeof(ipFrag_t));
            }
            ipFragList.numFrags = max;
        } else {
            // assign first empty slot in list
            slot = (unsigned)firstEmpty;
        }
        if (!initSlot(slot, srcAddr, dstAddr, fragID, proto, when)) return NULL;
    }  // else fragment in slot found

    dbg_printf("Return fragment slot %d\n", slot);
    ipFrag_t *fragment = &ipFragList.fragList[slot];
    return fragment;
}  // End of getIPFragement

static int findHole(ipFrag_t *fragment, uint16_t fragFirst, uint16_t fragLast, int moreFragments) {
    uint8_t *payload = (uint8_t *)fragment->payload;

    dbg_printf("defrag - find hole for %u - %u\n", fragFirst, fragLast);

    // search for hole to map this fragment
    if (fragment->numHoles == 0) {
        // no more holes but still a packet to reassemble - possibly wrong
        LogError("ProcessIPFragment() reassembly error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    // hole_t (2 byte alignment) is stored inline in `payload` at byte
    // offsets that come from prior fragments' lengths - only fragments
    // with moreFragments set are required to have an 8-byte-multiple
    // length, so the *last* fragment in a chain can be any length,
    // including odd, which can leave a hole starting at an odd offset.
    // holeOffset is the value that points at the hole currently under
    // examination; hasPrev/prevOffset track where that value is stored
    // (either fragment->holeList, a real aligned struct field, or a
    // previously-visited hole's `next` field inside payload) so it can be
    // patched in place once a match is found, without re-walking the list.
    uint16_t holeOffset = fragment->holeList;
    int hasPrev = 0;
    uint16_t prevOffset = 0;
    // Belt-and-suspenders bound on top of the containment check above: the
    // list can never legitimately have more than numHoles entries, so more
    // iterations than that means something (not necessarily this function)
    // left the list inconsistent - bail out instead of looping forever.
    uint32_t stepsLeft = fragment->numHoles;
    // 0xFFFF is our 'End of List' sentinel
    while (holeOffset != 0xFFFF) {
        if (unlikely(stepsLeft-- == 0)) {
            LogError("ProcessIPFragment() hole list inconsistent in %s line %d", __FILE__, __LINE__);
            return 0;
        }
        hole_t hole;
        memcpy(&hole, &payload[holeOffset], sizeof(hole));

        if (fragFirst > hole.last || fragLast < hole.first) {
            // fragment outside hole
            dbg_printf("defrag - hole %u - %u - no match\n", hole.first, hole.last);
            hasPrev = 1;
            prevOffset = holeOffset;
            holeOffset = hole.next;
            continue;
        }

        // The fragment overlaps this hole, but a well-formed, non-adversarial
        // fragment sequence never needs anything but full containment
        // (fragFirst >= hole.first && fragLast <= hole.last): every existing
        // hole was itself carved out to exactly cover an unfilled region, so
        // any earlier, correctly-received fragment already narrowed things
        // down to that. A fragment that only partially overlaps - crafted to
        // start before hole.first and/or end after hole.last - would have
        // its payload memcpy'd (by the caller) straight over bytes outside
        // this hole, which in this design also holds other holes' hole_t
        // bookkeeping and already-reassembled payload data. Overwriting that
        // corrupts the hole list
        if (fragFirst < hole.first || fragLast > hole.last) {
            dbg_printf("defrag - hole %u - %u - fragment %u - %u only partially overlaps, reject\n", hole.first, hole.last, fragFirst, fragLast);
            return 0;
        }

        // Hole found! Delete it from the linked list
        if (!hasPrev) {
            fragment->holeList = hole.next;
        } else {
            hole_t prevHole;
            memcpy(&prevHole, &payload[prevOffset], sizeof(prevHole));
            prevHole.next = hole.next;
            memcpy(&payload[prevOffset], &prevHole, sizeof(prevHole));
        }
        dbg_printf("defrag - hole %u - %u - found\n", hole.first, hole.last);
        fragment->numHoles--;

        // Create hole to the left
        if (fragFirst > hole.first) {
            uint16_t newOffset = hole.first;
            hole_t newHole = {.first = hole.first, .last = fragFirst - 1, .next = fragment->holeList};
            memcpy(&payload[newOffset], &newHole, sizeof(newHole));
            dbg_printf("defrag - new hole left: %u - %u created\n", newHole.first, newHole.last);
            fragment->holeList = newOffset;
            fragment->numHoles++;
        }

        // Create hole to the right
        if (fragLast < hole.last && moreFragments) {
            uint16_t newOffset = fragLast + 1;
            hole_t newHole = {.first = fragLast + 1, .last = hole.last, .next = fragment->holeList};
            memcpy(&payload[newOffset], &newHole, sizeof(newHole));
            dbg_printf("defrag - new hole right: %u - %u created\n", newHole.first, newHole.last);
            fragment->holeList = newOffset;
            fragment->numHoles++;
        }

        dbg_printf("defrag - fragment has %u holes\n", fragment->numHoles);

        return 1;
    }

    return 0;

}  // End of findHole

// Defragment IPv6 packets according RFC815
void *ProcessIP6Fragment(const struct ip6_hdr *ip6, const uint8_t *ip6_frag_in, const void *eodata, uint32_t *payloadLength, time_t when) {
    // ip6_frag_in points into the raw capture buffer at whatever offset the
    // preceding headers happened to land on - e.g. right after a 14-byte
    // Ethernet header, which is never 4-byte aligned. It is taken as a
    // byte pointer (not `const struct ip6_frag *`) precisely so the memcpy
    // below cannot be recognized/miscompiled by the optimizer as an
    // aligned typed load - that recognition is exactly what still tripped
    // UBSan even after switching to memcpy while the parameter was
    // struct-typed. Copy into a properly-aligned local struct first,
    // matching the safe pattern decode_ip.c already uses via
    // cursor_get()/cursor_read(). The payload pointer below still derives
    // from ip6_frag_in (the real buffer address), not the local copy.
    if ((const uint8_t *)eodata - ip6_frag_in < (ptrdiff_t)sizeof(struct ip6_frag)) return NULL;
    struct ip6_frag ip6_frag_copy;
    memcpy(&ip6_frag_copy, ip6_frag_in, sizeof(ip6_frag_copy));
    const struct ip6_frag *ip6_frag = &ip6_frag_copy;

    ip128_t srcAddr, dstAddr;
    memcpy(srcAddr.bytes, ip6->ip6_src.s6_addr, 16);
    memcpy(dstAddr.bytes, ip6->ip6_dst.s6_addr, 16);
    uint32_t fragID = ntohl(ip6_frag->ip6f_ident);

    uint16_t offset = ntohs(ip6_frag->ip6f_offlg);
    int moreFragments = offset & 0x1;
    offset = offset & 0xFFF8;
    uint16_t plen = ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen);
    if (plen < sizeof(struct ip6_frag)) return NULL;
    uint16_t ipPayloadLength = plen - sizeof(struct ip6_frag);
    const uint8_t *ipPayload = ip6_frag_in + sizeof(struct ip6_frag);

    if (ipPayloadLength == 0 || (moreFragments && (ipPayloadLength & 7))) return NULL;

    if (ipPayload > (const uint8_t *)eodata || ipPayloadLength > (size_t)((const uint8_t *)eodata - ipPayload)) {
        LogError("IPv6 Fragment exceeds capture buffer");
        return NULL;
    }

    // Check for overflow: offset + payload must fit in 65535 bytes (max IP packet)
    if ((uint32_t)offset + ipPayloadLength > 65535) {
        LogError("IPv6 Fragment would exceed maximum IP packet size");
        return NULL;
    }

    ipFrag_t *fragment = getIPFragement(&srcAddr, &dstAddr, fragID, ip6_frag->ip6f_nxt, when);
    if (!fragment) return NULL;

    uint16_t fragFirst = offset;
    uint16_t fragLast = offset + ipPayloadLength - 1;

    if (!findHole(fragment, fragFirst, fragLast, moreFragments)) {
        // This fragment is a duplicate or doesn't fit any current hole
        return NULL;
    }
    fragment->lastSeen = when;

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
        *payloadLength = fragment->payloadLength;
        dbg_printf("Complete fragment. Size: %u\n", fragment->payloadLength);
        memset(fragment, 0, sizeof(ipFrag_t));
        return payload;
    }

    return NULL;
}  // End of ProcessIP6Fragment

// Defragment IPv4 packets according RFC815
void *ProcessIP4Fragment(const uint8_t *ip4In, const void *eodata, uint32_t *payloadLength, time_t when) {
    // ip4In points into the raw capture buffer at whatever offset the
    // preceding headers happened to land on - e.g. right after a 14-byte
    // Ethernet header, which is never 4-byte aligned. It is taken as a
    // byte pointer
    if ((const uint8_t *)eodata - ip4In < (ptrdiff_t)sizeof(struct ip)) return NULL;
    struct ip ip4hdr;
    memcpy(&ip4hdr, ip4In, sizeof(ip4hdr));
    const struct ip *ip4 = &ip4hdr;

    static const uint8_t prefix[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};
    ip128_t srcAddr = {0};
    ip128_t dstAddr = {0};
    memcpy(srcAddr.bytes, prefix, 12);
    memcpy(dstAddr.bytes, prefix, 12);
    memcpy(srcAddr.bytes + 12, &ip4->ip_src.s_addr, 4);
    memcpy(dstAddr.bytes + 12, &ip4->ip_dst.s_addr, 4);

    uint32_t fragID = ntohs(ip4->ip_id);
    uint16_t ip_off = ntohs(ip4->ip_off);
    uint32_t offset = (ip_off & IP_OFFMASK) << 3;
    int moreFragments = ip_off & IP_MF;

    size_t sizeIP = (size_t)ip4->ip_hl << 2;
    uint16_t totalLength = ntohs(ip4->ip_len);
    if (sizeIP < sizeof(struct ip) || totalLength < sizeIP) return NULL;
    uint16_t ipPayloadLength = totalLength - sizeIP;
    const uint8_t *ipPayload = ip4In + sizeIP;
    if (ipPayloadLength == 0 || (moreFragments && (ipPayloadLength & 7))) return NULL;
    if (ipPayload > (const uint8_t *)eodata || ipPayloadLength > (size_t)((const uint8_t *)eodata - ipPayload)) {
        LogError("IPv4 Fragment exceeds capture buffer");
        return NULL;
    }

    // Check for overflow: offset + payload must fit in 65535 bytes (max IP packet)
    if (offset + ipPayloadLength > 65535) {
        LogError("IPv4 Fragment would exceed maximum IP packet size");
        return NULL;
    }

    ipFrag_t *fragment = getIPFragement(&srcAddr, &dstAddr, fragID, ip4->ip_p, when);
    if (!fragment) return NULL;

    uint16_t fragFirst = offset;
    uint16_t fragLast = offset + ipPayloadLength - 1;

    if (!findHole(fragment, fragFirst, fragLast, moreFragments)) {
        // This fragment is a duplicate or doesn't fit any current hole
        return NULL;
    }
    fragment->lastSeen = when;

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
        *payloadLength = fragment->payloadLength;
        dbg_printf("Complete fragment. Size: %u\n", fragment->payloadLength);
        memset(fragment, 0, sizeof(ipFrag_t));
        return payload;
    }

    return NULL;
}  // End of ProcessIP4Fragment
