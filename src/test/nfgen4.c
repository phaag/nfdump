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

/*
 * nfgen4 - generate dummy V4 flow records in nffileV3 format
 *
 * Creates ~40 V4 flow records with increasing complexity:
 *   - empty record (header only)
 *   - header with metadata fields
 *   - +EXgenericFlow
 *   - +EXipv4Flow / EXipv6Flow
 *   - +EXinterface, +EXflowMisc
 *   - +EXcntFlow, +EXvLan, +EXasInfo
 *   - +EXasRoutingV4 / EXasRoutingV6
 *   - +EXipReceivedV4 / V6
 *   - +EXmpls, +EXinMacAddr, +EXoutMacAddr
 *   - +EXasAdjacent, +EXlatency
 *   - +EXnatXlateV4, +EXnatXlatePort, +EXnselCommon, +EXnatPortBlock
 *   - +EXlayer2, +EXipInfo, +EXobservation, +EXvrf, +EXflowId
 *   - full record with many extensions
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "id.h"
#include "nfdump.h"
#include "nffileV3/nffileV3.h"
#include "nfxV4.h"
#include "util.h"

// record buffer — 4K is plenty for any single V4 record
#define RECBUF_SIZE 4096

static time_t baseTime;
static uint64_t timeOffset;  // incrementing msec offset for each record

/*
 * Build a V4 record into buf with the given extensions.
 *
 * extIDs: array of extension IDs to include (must be sorted ascending by ID)
 * numExt: number of extensions
 *
 * Returns the record size (h->size) on success, 0 on error.
 * The caller fills extension data via GetExtension() after this call.
 */
static uint16_t BuildV4Record(uint8_t *buf, const uint32_t *extIDs, uint32_t numExt) {
    memset(buf, 0, RECBUF_SIZE);
    recordHeaderV4_t *h = AddV4Header(buf);

    // set all bitmap bits first — AddV4Extension needs the full bitmap
    for (uint32_t i = 0; i < numExt; i++) {
        BitMapSet(h->extBitmap, extIDs[i]);
    }
    h->numExtensions = numExt;

    // compute offset past offset table (8-byte aligned)
    uint16_t nextOffset = (uint16_t)ALIGN8(sizeof(recordHeaderV4_t) + numExt * sizeof(uint16_t));
    h->size = nextOffset;  // AddV4Extension adds to h->size

    // add extensions in ascending ID order (matching bitmap rank order)
    for (uint32_t i = 0; i < numExt; i++) {
        uint32_t extID = extIDs[i];
        uint32_t extSize = extensionTable[extID].size;
        if (extSize == VARLENGTH) {
            fprintf(stderr, "BuildV4Record: variable-length extension %u not supported\n", extID);
            return 0;
        }

        // manually fill offset slot and data area (replicate AddV4Extension logic)
        uint32_t slot = __builtin_popcountll(h->extBitmap & ((1ULL << extID) - 1));
        uint16_t *offsets = V4OffsetTable(h);
        offsets[slot] = nextOffset;

        // zero the extension data area
        memset(buf + nextOffset, 0, extSize);

        nextOffset += (uint16_t)extSize;
        h->size += (uint16_t)extSize;
    }

    return h->size;
}

/*
 * Store the current record from buf into the flow block.
 * Flushes the block via the nffile writer queue when full.
 */
static flowBlockV3_t *StoreV4Record(uint8_t *buf, nffileV3_t *nffile, flowBlockV3_t *block) {
    recordHeaderV4_t *h = (recordHeaderV4_t *)buf;
    uint32_t required = h->size;

    if (!IsAvailable(block, BLOCK_SIZE_V3, required)) {
        PushBlockV3(nffile->processQueue, block);
        InitDataBlock(block, nffile->fileHeader->blockSize);
    }

    VerifyV4Record(h);
    void *cursor = GetCursor(block);
    memcpy(cursor, buf, required);
    block->numRecords++;
    block->rawSize += required;

    // update flow block bitmap
    block->extensionBitmap |= h->extBitmap;

    // update flow block timestamps from genericFlow if present
    EXgenericFlow_t *gf = GetExtension(h, EXgenericFlow);
    if (gf) {
        if (block->msecFirst == 0 || gf->msecFirst < block->msecFirst) block->msecFirst = gf->msecFirst;
        if (gf->msecLast > block->msecLast) block->msecLast = gf->msecLast;
    }

    return block;
}

/*
 * Update the stat_record in nffile based on the record in buf.
 */
static void UpdateStats(uint8_t *buf, stat_record_t *stat) {
    recordHeaderV4_t *h = (recordHeaderV4_t *)buf;
    EXgenericFlow_t *gf = GetExtension(h, EXgenericFlow);
    if (!gf) {
        stat->numflows++;
        return;
    }

    if (stat->msecFirstSeen == 0 || gf->msecFirst < stat->msecFirstSeen) stat->msecFirstSeen = gf->msecFirst;
    if (gf->msecLast > stat->msecLastSeen) stat->msecLastSeen = gf->msecLast;

    stat->numpackets += gf->inPackets;
    stat->numbytes += gf->inBytes;

    switch (gf->proto) {
        case IPPROTO_TCP:
            stat->numflows_tcp++;
            stat->numpackets_tcp += gf->inPackets;
            stat->numbytes_tcp += gf->inBytes;
            break;
        case IPPROTO_UDP:
            stat->numflows_udp++;
            stat->numpackets_udp += gf->inPackets;
            stat->numbytes_udp += gf->inBytes;
            break;
        case IPPROTO_ICMP:
            stat->numflows_icmp++;
            stat->numpackets_icmp += gf->inPackets;
            stat->numbytes_icmp += gf->inBytes;
            break;
        default:
            stat->numflows_other++;
            stat->numpackets_other += gf->inPackets;
            stat->numbytes_other += gf->inBytes;
    }

    EXcntFlow_t *cf = GetExtension(h, EXcntFlow);
    if (cf)
        stat->numflows += cf->flows;
    else
        stat->numflows++;
}

/*
 * Set IPv4 addresses via inet_pton
 */
static void SetIPv4(recordHeaderV4_t *h, const char *srcIP, const char *dstIP) {
    EXipv4Flow_t *ip = GetExtension(h, EXipv4Flow);
    if (!ip) return;
    inet_pton(AF_INET, srcIP, &ip->srcAddr);
    inet_pton(AF_INET, dstIP, &ip->dstAddr);
    ip->srcAddr = ntohl(ip->srcAddr);
    ip->dstAddr = ntohl(ip->dstAddr);
}

/*
 * Set IPv6 addresses via inet_pton
 */
static void SetIPv6(recordHeaderV4_t *h, const char *srcIP, const char *dstIP) {
    EXipv6Flow_t *ip = GetExtension(h, EXipv6Flow);
    if (!ip) return;
    inet_pton(AF_INET6, srcIP, ip->srcAddr);
    inet_pton(AF_INET6, dstIP, ip->dstAddr);
    ip->srcAddr[0] = ntohll(ip->srcAddr[0]);
    ip->srcAddr[1] = ntohll(ip->srcAddr[1]);
    ip->dstAddr[0] = ntohll(ip->dstAddr[0]);
    ip->dstAddr[1] = ntohll(ip->dstAddr[1]);
}

/*
 * Fill genericFlow with base values, advancing timestamps
 */
static void FillGenericFlow(recordHeaderV4_t *h, uint8_t proto, uint16_t srcPort, uint16_t dstPort, uint64_t packets, uint64_t bytes,
                            uint8_t tcpFlags) {
    EXgenericFlow_t *gf = GetExtension(h, EXgenericFlow);
    if (!gf) return;

    timeOffset += 1000;
    gf->msecFirst = 1000ULL * baseTime + timeOffset;
    gf->msecLast = gf->msecFirst + 2000;
    gf->msecReceived = gf->msecFirst + 1;
    gf->inPackets = packets;
    gf->inBytes = bytes;
    gf->srcPort = srcPort;
    gf->dstPort = dstPort;
    gf->proto = proto;
    gf->tcpFlags = tcpFlags;
    gf->fwdStatus = 1;
    gf->srcTos = 0;
}

#define EMIT_RECORD(buf, nffile, block, stat)      \
    do {                                           \
        UpdateStats(buf, stat);                    \
        block = StoreV4Record(buf, nffile, block); \
    } while (0)

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    baseTime = ISO2UNIX(strdup("201907111030"));
    timeOffset = 0;

    if (!Init_nffile(1, NULL)) exit(EXIT_FAILURE);

    nffileV3_t *nffile = OpenNewFileV3("dummy_flows.nf", CREATOR_UNKNOWN, NOT_COMPRESSED, LEVEL_0, NULL);
    if (!nffile) {
        fprintf(stderr, "Failed to create output file\n");
        exit(255);
    }
    nffile->ident = strdup("TestFlows-V4");

    // init stat record
    nffile->stat_record = calloc(1, sizeof(stat_record_t));
    if (!nffile->stat_record) {
        perror("calloc");
        exit(255);
    }
    nffile->stat_record->msecFirstSeen = 0x7fffffffffffffffLL;

    flowBlockV3_t *block = NULL;
    InitDataBlock(block, nffile->fileHeader->blockSize);

    uint8_t buf[RECBUF_SIZE];
    recordHeaderV4_t *h;

    // ================================================================
    // Record 1: Empty V4 record — header only, no extensions
    // ================================================================
    BuildV4Record(buf, NULL, 0);
    h = (recordHeaderV4_t *)buf;
    h->nfVersion = 10;
    EMIT_RECORD(buf, nffile, block, nffile->stat_record);

    // ================================================================
    // Record 2: Header with metadata, no extensions
    // ================================================================
    BuildV4Record(buf, NULL, 0);
    h = (recordHeaderV4_t *)buf;
    h->engineType = 1;
    h->engineID = 2;
    h->exporterID = 100;
    h->nfVersion = 10;
    EMIT_RECORD(buf, nffile, block, nffile->stat_record);

    // ================================================================
    // Record 3: EXgenericFlow only — TCP
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID};
        BuildV4Record(buf, ext, 1);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_TCP, 12345, 443, 5, 1500, 0x12);
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 4: EXgenericFlow + EXipv4Flow — TCP SYN
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID};
        BuildV4Record(buf, ext, 2);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_TCP, 12345, 443, 1, 60, 0x02);
        SetIPv4(h, "172.16.1.66", "192.168.170.100");
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 5: EXgenericFlow + EXipv4Flow — TCP SYN-ACK
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID};
        BuildV4Record(buf, ext, 2);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_TCP, 443, 12345, 1, 60, 0x12);
        SetIPv4(h, "192.168.170.100", "172.16.1.66");
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 6: EXgenericFlow + EXipv4Flow — TCP data
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID};
        BuildV4Record(buf, ext, 2);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_TCP, 12345, 443, 25, 33445, 0x18);
        SetIPv4(h, "172.16.1.66", "192.168.170.100");
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 7: EXgenericFlow + EXipv4Flow — UDP
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID};
        BuildV4Record(buf, ext, 2);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->nfVersion = 9;
        FillGenericFlow(h, IPPROTO_UDP, 33333, 53, 3, 256, 0);
        SetIPv4(h, "172.16.2.66", "8.8.8.8");
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 8: EXgenericFlow + EXipv4Flow — ICMP echo request
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID};
        BuildV4Record(buf, ext, 2);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_ICMP, 0, 0, 1, 64, 0);
        EXgenericFlow_t *gf = GetExtension(h, EXgenericFlow);
        gf->icmpType = 8;
        gf->icmpCode = 0;
        SetIPv4(h, "172.16.2.67", "192.168.170.102");
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 9: EXgenericFlow + EXipv4Flow — ICMP echo reply
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID};
        BuildV4Record(buf, ext, 2);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_ICMP, 0, 0, 1, 64, 0);
        EXgenericFlow_t *gf = GetExtension(h, EXgenericFlow);
        gf->icmpType = 0;
        gf->icmpCode = 0;
        SetIPv4(h, "192.168.170.102", "172.16.2.67");
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 10: EXgenericFlow + EXipv6Flow — IPv6 TCP
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv6FlowID};
        BuildV4Record(buf, ext, 2);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 101;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_TCP, 80, 54321, 10, 223344, 0x1b);
        SetIPv6(h, "fe80::2110:abcd:1234:0", "fe80::2110:abcd:1235:4321");
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 11: EXgenericFlow + EXipv6Flow — IPv6 UDP
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv6FlowID};
        BuildV4Record(buf, ext, 2);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 101;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_UDP, 5353, 5353, 2, 128, 0);
        SetIPv6(h, "2001:db8::1", "ff02::fb");
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 12: +EXinterface
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXinterfaceID};
        BuildV4Record(buf, ext, 3);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_TCP, 80, 22222, 15, 4096, 0x10);
        SetIPv4(h, "172.16.2.66", "192.168.170.101");
        EXinterface_t *iface = GetExtension(h, EXinterface);
        iface->input = 100;
        iface->output = 200;
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 13: +EXinterface + EXflowMisc
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXinterfaceID, EXflowMiscID};
        BuildV4Record(buf, ext, 4);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_TCP, 80, 22222, 20, 8192, 0x18);
        SetIPv4(h, "172.16.2.66", "192.168.170.101");
        EXinterface_t *iface = GetExtension(h, EXinterface);
        iface->input = 100;
        iface->output = 200;
        EXflowMisc_t *misc = GetExtension(h, EXflowMisc);
        misc->srcMask = 16;
        misc->dstMask = 24;
        misc->direction = 0;
        misc->dstTos = 4;
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 14: reverse direction flow
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXinterfaceID, EXflowMiscID};
        BuildV4Record(buf, ext, 4);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_TCP, 22222, 80, 18, 1024, 0x12);
        SetIPv4(h, "192.168.170.101", "172.16.2.66");
        EXinterface_t *iface = GetExtension(h, EXinterface);
        iface->input = 200;
        iface->output = 100;
        EXflowMisc_t *misc = GetExtension(h, EXflowMisc);
        misc->srcMask = 24;
        misc->dstMask = 16;
        misc->direction = 1;
        misc->biFlowDir = 1;
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 15: +EXcntFlow — counter extension
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXinterfaceID, EXflowMiscID, EXcntFlowID};
        BuildV4Record(buf, ext, 5);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_TCP, 443, 55667, 50, 102400, 0x1b);
        SetIPv4(h, "72.138.170.101", "42.16.32.6");
        EXinterface_t *iface = GetExtension(h, EXinterface);
        iface->input = 1;
        iface->output = 2;
        EXflowMisc_t *misc = GetExtension(h, EXflowMisc);
        misc->srcMask = 8;
        misc->dstMask = 16;
        EXcntFlow_t *cnt = GetExtension(h, EXcntFlow);
        cnt->outPackets = 203;
        cnt->outBytes = 44556677;
        cnt->flows = 7;
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 16: +EXvLan
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXinterfaceID, EXflowMiscID, EXcntFlowID, EXvLanID};
        BuildV4Record(buf, ext, 6);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_TCP, 443, 55667, 50, 102400, 0x1b);
        SetIPv4(h, "72.138.170.101", "42.16.32.6");
        EXinterface_t *iface = GetExtension(h, EXinterface);
        iface->input = 1;
        iface->output = 2;
        EXflowMisc_t *misc = GetExtension(h, EXflowMisc);
        misc->srcMask = 8;
        misc->dstMask = 16;
        EXcntFlow_t *cnt = GetExtension(h, EXcntFlow);
        cnt->outPackets = 100;
        cnt->outBytes = 50000;
        cnt->flows = 3;
        EXvLan_t *vlan = GetExtension(h, EXvLan);
        vlan->srcVlan = 45;
        vlan->dstVlan = 46;
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 17: +EXasInfo — AS numbers
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXinterfaceID, EXflowMiscID, EXvLanID, EXasInfoID};
        BuildV4Record(buf, ext, 6);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_TCP, 80, 44444, 30, 65000, 0x10);
        SetIPv4(h, "10.0.0.1", "203.0.113.50");
        EXinterface_t *iface = GetExtension(h, EXinterface);
        iface->input = 10;
        iface->output = 20;
        EXflowMisc_t *misc = GetExtension(h, EXflowMisc);
        misc->srcMask = 24;
        misc->dstMask = 24;
        EXvLan_t *vlan = GetExtension(h, EXvLan);
        vlan->srcVlan = 100;
        vlan->dstVlan = 200;
        EXasInfo_t *asInfo = GetExtension(h, EXasInfo);
        asInfo->srcAS = 775;
        asInfo->dstAS = 3303;
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 18: +EXasRoutingV4 — IPv4 next hop + BGP next hop
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXinterfaceID, EXflowMiscID, EXasInfoID, EXasRoutingV4ID};
        BuildV4Record(buf, ext, 6);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_TCP, 8080, 55555, 12, 3200, 0x10);
        SetIPv4(h, "10.0.1.1", "203.0.113.100");
        EXinterface_t *iface = GetExtension(h, EXinterface);
        iface->input = 5;
        iface->output = 6;
        EXflowMisc_t *misc = GetExtension(h, EXflowMisc);
        misc->srcMask = 24;
        misc->dstMask = 24;
        EXasInfo_t *asInfo = GetExtension(h, EXasInfo);
        asInfo->srcAS = 64501;
        asInfo->dstAS = 15169;
        EXasRoutingV4_t *rt = GetExtension(h, EXasRoutingV4);
        inet_pton(AF_INET, "172.72.1.2", &rt->nextHop);
        rt->nextHop = ntohl(rt->nextHop);
        inet_pton(AF_INET, "172.73.2.3", &rt->bgpNextHop);
        rt->bgpNextHop = ntohl(rt->bgpNextHop);
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 19: +EXasRoutingV6 — IPv6 routing with next hops
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv6FlowID, EXinterfaceID, EXflowMiscID, EXasInfoID, EXasRoutingV6ID};
        BuildV4Record(buf, ext, 6);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 101;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_TCP, 443, 60000, 100, 500000, 0x1b);
        SetIPv6(h, "2001:db8:1::1", "2001:db8:2::100");
        EXinterface_t *iface = GetExtension(h, EXinterface);
        iface->input = 3;
        iface->output = 4;
        EXflowMisc_t *misc = GetExtension(h, EXflowMisc);
        misc->srcMask = 48;
        misc->dstMask = 48;
        EXasInfo_t *asInfo = GetExtension(h, EXasInfo);
        asInfo->srcAS = 64502;
        asInfo->dstAS = 13335;
        EXasRoutingV6_t *rt = GetExtension(h, EXasRoutingV6);
        uint64_t v6[2];
        inet_pton(AF_INET6, "2001::1110:bcde:1234:4", v6);
        rt->nextHop[0] = ntohll(v6[0]);
        rt->nextHop[1] = ntohll(v6[1]);
        inet_pton(AF_INET6, "2002::1210:cdef:2346:5", v6);
        rt->bgpNextHop[0] = ntohll(v6[0]);
        rt->bgpNextHop[1] = ntohll(v6[1]);
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 20: +EXipReceivedV4 — collector/router IP
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXinterfaceID, EXflowMiscID, EXipReceivedV4ID};
        BuildV4Record(buf, ext, 5);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_UDP, 1234, 514, 5, 2048, 0);
        SetIPv4(h, "10.0.0.10", "10.0.0.20");
        EXinterface_t *iface = GetExtension(h, EXinterface);
        iface->input = 1;
        iface->output = 1;
        EXflowMisc_t *misc = GetExtension(h, EXflowMisc);
        misc->srcMask = 24;
        misc->dstMask = 24;
        EXipReceivedV4_t *rcv = GetExtension(h, EXipReceivedV4);
        inet_pton(AF_INET, "127.0.0.1", &rcv->ip);
        rcv->ip = ntohl(rcv->ip);
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 21: +EXipReceivedV6
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv6FlowID, EXinterfaceID, EXflowMiscID, EXipReceivedV6ID};
        BuildV4Record(buf, ext, 5);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 101;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_TCP, 22, 60001, 8, 4096, 0x10);
        SetIPv6(h, "2001:db8:3::10", "2001:db8:3::20");
        EXinterface_t *iface = GetExtension(h, EXinterface);
        iface->input = 7;
        iface->output = 8;
        EXflowMisc_t *misc = GetExtension(h, EXflowMisc);
        misc->srcMask = 64;
        misc->dstMask = 64;
        EXipReceivedV6_t *rcv = GetExtension(h, EXipReceivedV6);
        uint64_t v6[2];
        inet_pton(AF_INET6, "fe80::caffe:caffe:1234:1", v6);
        rcv->ip[0] = ntohll(v6[0]);
        rcv->ip[1] = ntohll(v6[1]);
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 22: +EXmpls — MPLS labels
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXinterfaceID, EXflowMiscID, EXmplsID};
        BuildV4Record(buf, ext, 5);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_TCP, 443, 44444, 100, 150000, 0x10);
        SetIPv4(h, "10.1.0.1", "10.2.0.1");
        EXinterface_t *iface = GetExtension(h, EXinterface);
        iface->input = 1;
        iface->output = 2;
        EXflowMisc_t *misc = GetExtension(h, EXflowMisc);
        misc->srcMask = 16;
        misc->dstMask = 16;
        EXmpls_t *mpls = GetExtension(h, EXmpls);
        mpls->label[0] = 1010 << 4;
        mpls->label[1] = 2020 << 4;
        mpls->label[2] = 3030 << 4;
        mpls->label[3] = 4040 << 4;
        mpls->label[4] = 5050 << 4;
        mpls->label[5] = 6060 << 4;
        mpls->label[6] = 7070 << 4;
        mpls->label[7] = 8080 << 4;
        mpls->label[8] = 9090 << 4;
        mpls->label[9] = (100100 << 4) + 1;
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 23: +EXinMacAddr — ingress MAC addresses
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXinterfaceID, EXflowMiscID, EXinMacAddrID};
        BuildV4Record(buf, ext, 5);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_TCP, 443, 55555, 30, 45000, 0x10);
        SetIPv4(h, "10.3.0.1", "10.4.0.1");
        EXinterface_t *iface = GetExtension(h, EXinterface);
        iface->input = 1;
        iface->output = 2;
        EXflowMisc_t *misc = GetExtension(h, EXflowMisc);
        misc->srcMask = 24;
        misc->dstMask = 24;
        EXinMacAddr_t *mac = GetExtension(h, EXinMacAddr);
        mac->inSrcMac = 0x1234567890aaULL;
        mac->outDstMac = 0x2feeddccbbabULL;
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 24: +EXoutMacAddr — egress MAC addresses
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXinterfaceID, EXflowMiscID, EXinMacAddrID, EXoutMacAddrID};
        BuildV4Record(buf, ext, 6);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_TCP, 443, 55556, 35, 50000, 0x10);
        SetIPv4(h, "10.3.0.2", "10.4.0.2");
        EXinterface_t *iface = GetExtension(h, EXinterface);
        iface->input = 1;
        iface->output = 2;
        EXflowMisc_t *misc = GetExtension(h, EXflowMisc);
        misc->srcMask = 24;
        misc->dstMask = 24;
        EXinMacAddr_t *inMac = GetExtension(h, EXinMacAddr);
        inMac->inSrcMac = 0x1234567890aaULL;
        inMac->outDstMac = 0x2feeddccbbabULL;
        EXoutMacAddr_t *outMac = GetExtension(h, EXoutMacAddr);
        outMac->inDstMac = 0x3aeeddccbbfcULL;
        outMac->outSrcMac = 0x4a345678900dULL;
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 25: +EXasAdjacent — adjacent AS
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXinterfaceID, EXflowMiscID, EXasInfoID, EXasAdjacentID};
        BuildV4Record(buf, ext, 6);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_TCP, 443, 33333, 42, 87000, 0x10);
        SetIPv4(h, "10.5.0.1", "10.6.0.1");
        EXinterface_t *iface = GetExtension(h, EXinterface);
        iface->input = 3;
        iface->output = 4;
        EXflowMisc_t *misc = GetExtension(h, EXflowMisc);
        misc->srcMask = 16;
        misc->dstMask = 16;
        EXasInfo_t *asInfo = GetExtension(h, EXasInfo);
        asInfo->srcAS = 64501;
        asInfo->dstAS = 15169;
        EXasAdjacent_t *adj = GetExtension(h, EXasAdjacent);
        adj->nextAdjacentAS = 7751;
        adj->prevAdjacentAS = 33032;
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 26: +EXlatency — nfpcapd latency
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXinterfaceID, EXflowMiscID, EXlatencyID};
        BuildV4Record(buf, ext, 5);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_TCP, 443, 22222, 50, 120000, 0x1b);
        SetIPv4(h, "10.7.0.1", "10.8.0.1");
        EXinterface_t *iface = GetExtension(h, EXinterface);
        iface->input = 5;
        iface->output = 6;
        EXflowMisc_t *misc = GetExtension(h, EXflowMisc);
        misc->srcMask = 24;
        misc->dstMask = 24;
        EXlatency_t *lat = GetExtension(h, EXlatency);
        lat->msecClientNwDelay = 2;
        lat->msecServerNwDelay = 22;
        lat->msecApplLatency = 222;
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 27: +EXnatXlateV4 + EXnatXlatePort — NAT translation
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXinterfaceID, EXflowMiscID, EXnatXlateV4ID, EXnatXlatePortID};
        BuildV4Record(buf, ext, 6);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->nfVersion = 10;
        h->flags = V4_FLAG_EVENT;
        FillGenericFlow(h, IPPROTO_TCP, 12345, 443, 10, 5000, 0x12);
        SetIPv4(h, "192.168.1.10", "203.0.113.50");
        EXinterface_t *iface = GetExtension(h, EXinterface);
        iface->input = 1;
        iface->output = 2;
        EXflowMisc_t *misc = GetExtension(h, EXflowMisc);
        misc->srcMask = 24;
        misc->dstMask = 24;
        EXnatXlateV4_t *xlate = GetExtension(h, EXnatXlateV4);
        inet_pton(AF_INET, "44.55.66.77", &xlate->xlateSrcAddr);
        xlate->xlateSrcAddr = ntohl(xlate->xlateSrcAddr);
        inet_pton(AF_INET, "8.8.8.8", &xlate->xlateDstAddr);
        xlate->xlateDstAddr = ntohl(xlate->xlateDstAddr);
        EXnatXlatePort_t *xport = GetExtension(h, EXnatXlatePort);
        xport->xlateSrcPort = 55667;
        xport->xlateDstPort = 443;
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 28: +EXnselCommon + EXnatPortBlock — NAT event + port block
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID,     EXinterfaceID,  EXflowMiscID,
                          EXnatXlateV4ID,  EXnatXlatePortID, EXnselCommonID, EXnatPortBlockID};
        BuildV4Record(buf, ext, 8);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->nfVersion = 10;
        h->flags = V4_FLAG_EVENT;
        FillGenericFlow(h, IPPROTO_TCP, 12345, 443, 15, 7500, 0x12);
        SetIPv4(h, "192.168.1.20", "203.0.113.60");
        EXinterface_t *iface = GetExtension(h, EXinterface);
        iface->input = 1;
        iface->output = 2;
        EXflowMisc_t *misc = GetExtension(h, EXflowMisc);
        misc->srcMask = 24;
        misc->dstMask = 24;
        EXnatXlateV4_t *xlate = GetExtension(h, EXnatXlateV4);
        inet_pton(AF_INET, "44.55.66.78", &xlate->xlateSrcAddr);
        xlate->xlateSrcAddr = ntohl(xlate->xlateSrcAddr);
        inet_pton(AF_INET, "9.9.9.9", &xlate->xlateDstAddr);
        xlate->xlateDstAddr = ntohl(xlate->xlateDstAddr);
        EXnatXlatePort_t *xport = GetExtension(h, EXnatXlatePort);
        xport->xlateSrcPort = 55668;
        xport->xlateDstPort = 443;
        EXnselCommon_t *nsel = GetExtension(h, EXnselCommon);
        nsel->type = NSEL_NAT;
        nsel->natEvent = 1;
        nsel->natPoolID = 5;
        EXgenericFlow_t *gf = GetExtension(h, EXgenericFlow);
        nsel->msecEvent = gf->msecFirst;
        EXnatPortBlock_t *pblock = GetExtension(h, EXnatPortBlock);
        pblock->blockStart = 1024;
        pblock->blockEnd = 16534;
        pblock->blockStep = 2;
        pblock->blockSize = 4096;
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 29: +EXlayer2 — layer 2 info
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXinterfaceID, EXflowMiscID, EXlayer2ID};
        BuildV4Record(buf, ext, 5);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_TCP, 443, 33333, 20, 30000, 0x10);
        SetIPv4(h, "10.10.0.1", "10.11.0.1");
        EXinterface_t *iface = GetExtension(h, EXinterface);
        iface->input = 10;
        iface->output = 11;
        EXflowMisc_t *misc = GetExtension(h, EXflowMisc);
        misc->srcMask = 16;
        misc->dstMask = 16;
        EXlayer2_t *l2 = GetExtension(h, EXlayer2);
        l2->vlanID = 47;
        l2->postVlanID = 48;
        l2->customerVlanId = 49;
        l2->postCustomerVlanId = 50;
        l2->ingress = 112233;
        l2->egress = 445566;
        l2->etherType = 0x0800;
        l2->ipVersion = 4;
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 30: +EXipInfo — IP header info
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXinterfaceID, EXflowMiscID, EXipInfoID};
        BuildV4Record(buf, ext, 5);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_TCP, 443, 44444, 60, 90000, 0x10);
        SetIPv4(h, "10.12.0.1", "10.13.0.1");
        EXinterface_t *iface = GetExtension(h, EXinterface);
        iface->input = 1;
        iface->output = 2;
        EXflowMisc_t *misc = GetExtension(h, EXflowMisc);
        misc->srcMask = 24;
        misc->dstMask = 24;
        EXipInfo_t *ipInfo = GetExtension(h, EXipInfo);
        ipInfo->fragmentFlags = flagDF;
        ipInfo->minTTL = 40;
        ipInfo->maxTTL = 255;
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 31: +EXobservation — observation domain
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXinterfaceID, EXobservationID};
        BuildV4Record(buf, ext, 4);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_UDP, 5060, 5060, 2, 800, 0);
        SetIPv4(h, "10.20.0.1", "10.20.0.2");
        EXinterface_t *iface = GetExtension(h, EXinterface);
        iface->input = 1;
        iface->output = 2;
        EXobservation_t *obs = GetExtension(h, EXobservation);
        obs->pointID = 1001;
        obs->domainID = 2002;
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 32: +EXvrf — VRF info
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXinterfaceID, EXflowMiscID, EXvrfID};
        BuildV4Record(buf, ext, 5);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_TCP, 22, 55555, 8, 4096, 0x10);
        SetIPv4(h, "10.30.0.1", "10.30.0.2");
        EXinterface_t *iface = GetExtension(h, EXinterface);
        iface->input = 1;
        iface->output = 2;
        EXflowMisc_t *misc = GetExtension(h, EXflowMisc);
        misc->srcMask = 24;
        misc->dstMask = 24;
        EXvrf_t *vrf = GetExtension(h, EXvrf);
        vrf->ingressVrf = 100;
        vrf->egressVrf = 200;
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 33: +EXflowId — flow identifier
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXinterfaceID, EXflowIdID};
        BuildV4Record(buf, ext, 4);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_TCP, 443, 11111, 5, 2048, 0x10);
        SetIPv4(h, "10.40.0.1", "10.40.0.2");
        EXinterface_t *iface = GetExtension(h, EXinterface);
        iface->input = 1;
        iface->output = 2;
        EXflowId_t *fid = GetExtension(h, EXflowId);
        fid->flowId = 0xDEADBEEF12345678ULL;
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 34: sampled flow
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXinterfaceID, EXflowMiscID};
        BuildV4Record(buf, ext, 4);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 102;
        h->nfVersion = 9;
        h->flags = V4_FLAG_SAMPLED;
        FillGenericFlow(h, IPPROTO_TCP, 80, 44444, 1000, 1500000, 0x10);
        SetIPv4(h, "172.20.1.1", "172.20.2.2");
        EXinterface_t *iface = GetExtension(h, EXinterface);
        iface->input = 1;
        iface->output = 2;
        EXflowMisc_t *misc = GetExtension(h, EXflowMisc);
        misc->srcMask = 16;
        misc->dstMask = 16;
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 35–38: Multiple UDP flows from same source (batch)
    // ================================================================
    for (int i = 0; i < 4; i++) {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXinterfaceID, EXflowMiscID};
        BuildV4Record(buf, ext, 4);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_UDP, (uint16_t)(40000 + i), 53, (uint64_t)(1 + i), (uint64_t)(64 + i * 32), 0);
        char src[32];
        snprintf(src, sizeof(src), "192.168.10.%d", 10 + i);
        SetIPv4(h, src, "8.8.4.4");
        EXinterface_t *iface = GetExtension(h, EXinterface);
        iface->input = 1;
        iface->output = 2;
        EXflowMisc_t *misc = GetExtension(h, EXflowMisc);
        misc->srcMask = 24;
        misc->dstMask = 0;
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 39: Full IPv4 record — many extensions combined
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID,  EXipv4FlowID, EXinterfaceID, EXflowMiscID,   EXcntFlowID,    EXvLanID,    EXasInfoID, EXasRoutingV4ID,
                          EXipReceivedV4ID, EXmplsID,     EXinMacAddrID, EXoutMacAddrID, EXasAdjacentID, EXlatencyID, EXlayer2ID, EXipInfoID};
        BuildV4Record(buf, ext, 16);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 100;
        h->engineType = 5;
        h->engineID = 10;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_TCP, 443, 12345, 200, 500000, 0x1b);
        SetIPv4(h, "10.100.0.1", "10.200.0.1");
        EXinterface_t *iface = GetExtension(h, EXinterface);
        iface->input = 100;
        iface->output = 200;
        EXflowMisc_t *misc = GetExtension(h, EXflowMisc);
        misc->srcMask = 16;
        misc->dstMask = 16;
        misc->direction = 0;
        misc->dstTos = 0;
        EXcntFlow_t *cnt = GetExtension(h, EXcntFlow);
        cnt->outPackets = 150;
        cnt->outBytes = 350000;
        cnt->flows = 1;
        EXvLan_t *vlan = GetExtension(h, EXvLan);
        vlan->srcVlan = 100;
        vlan->dstVlan = 200;
        EXasInfo_t *asInfo = GetExtension(h, EXasInfo);
        asInfo->srcAS = 64500;
        asInfo->dstAS = 13335;
        EXasRoutingV4_t *rt = GetExtension(h, EXasRoutingV4);
        inet_pton(AF_INET, "172.72.1.1", &rt->nextHop);
        rt->nextHop = ntohl(rt->nextHop);
        inet_pton(AF_INET, "172.73.2.2", &rt->bgpNextHop);
        rt->bgpNextHop = ntohl(rt->bgpNextHop);
        EXipReceivedV4_t *rcv = GetExtension(h, EXipReceivedV4);
        inet_pton(AF_INET, "127.0.0.1", &rcv->ip);
        rcv->ip = ntohl(rcv->ip);
        EXmpls_t *mpls = GetExtension(h, EXmpls);
        for (int i = 0; i < 10; i++) mpls->label[i] = (uint32_t)((1000 + i * 1000) << 4);
        EXinMacAddr_t *inMac = GetExtension(h, EXinMacAddr);
        inMac->inSrcMac = 0x1234567890aaULL;
        inMac->outDstMac = 0x2feeddccbbabULL;
        EXoutMacAddr_t *outMac = GetExtension(h, EXoutMacAddr);
        outMac->inDstMac = 0x3aeeddccbbfcULL;
        outMac->outSrcMac = 0x4a345678900dULL;
        EXasAdjacent_t *adj = GetExtension(h, EXasAdjacent);
        adj->nextAdjacentAS = 7751;
        adj->prevAdjacentAS = 33032;
        EXlatency_t *lat = GetExtension(h, EXlatency);
        lat->msecClientNwDelay = 5;
        lat->msecServerNwDelay = 15;
        lat->msecApplLatency = 150;
        EXlayer2_t *l2 = GetExtension(h, EXlayer2);
        l2->vlanID = 100;
        l2->postVlanID = 200;
        l2->customerVlanId = 300;
        l2->postCustomerVlanId = 400;
        l2->ingress = 1001;
        l2->egress = 1002;
        l2->etherType = 0x0800;
        l2->ipVersion = 4;
        EXipInfo_t *ipInfo = GetExtension(h, EXipInfo);
        ipInfo->fragmentFlags = flagDF;
        ipInfo->minTTL = 60;
        ipInfo->maxTTL = 128;
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 40: Full IPv6 record — many extensions combined
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID,  EXipv6FlowID,  EXinterfaceID,  EXflowMiscID,   EXcntFlowID, EXvLanID,   EXasInfoID, EXasRoutingV6ID,
                          EXipReceivedV6ID, EXinMacAddrID, EXoutMacAddrID, EXasAdjacentID, EXlatencyID, EXlayer2ID, EXipInfoID};
        BuildV4Record(buf, ext, 15);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 101;
        h->engineType = 6;
        h->engineID = 11;
        h->nfVersion = 10;
        FillGenericFlow(h, IPPROTO_TCP, 443, 54321, 300, 750000, 0x1b);
        SetIPv6(h, "2001:db8:100::1", "2001:db8:200::1");
        EXinterface_t *iface = GetExtension(h, EXinterface);
        iface->input = 10;
        iface->output = 20;
        EXflowMisc_t *misc = GetExtension(h, EXflowMisc);
        misc->srcMask = 48;
        misc->dstMask = 48;
        misc->direction = 0;
        EXcntFlow_t *cnt = GetExtension(h, EXcntFlow);
        cnt->outPackets = 250;
        cnt->outBytes = 600000;
        cnt->flows = 1;
        EXvLan_t *vlan = GetExtension(h, EXvLan);
        vlan->srcVlan = 500;
        vlan->dstVlan = 600;
        EXasInfo_t *asInfo = GetExtension(h, EXasInfo);
        asInfo->srcAS = 64503;
        asInfo->dstAS = 2906;
        EXasRoutingV6_t *rt = GetExtension(h, EXasRoutingV6);
        uint64_t v6[2];
        inet_pton(AF_INET6, "2001:db8:ff::1", v6);
        rt->nextHop[0] = ntohll(v6[0]);
        rt->nextHop[1] = ntohll(v6[1]);
        inet_pton(AF_INET6, "2001:db8:ff::2", v6);
        rt->bgpNextHop[0] = ntohll(v6[0]);
        rt->bgpNextHop[1] = ntohll(v6[1]);
        EXipReceivedV6_t *rcv = GetExtension(h, EXipReceivedV6);
        inet_pton(AF_INET6, "::1", v6);
        rcv->ip[0] = ntohll(v6[0]);
        rcv->ip[1] = ntohll(v6[1]);
        EXinMacAddr_t *inMac = GetExtension(h, EXinMacAddr);
        inMac->inSrcMac = 0xAABBCCDDEE01ULL;
        inMac->outDstMac = 0xAABBCCDDEE02ULL;
        EXoutMacAddr_t *outMac = GetExtension(h, EXoutMacAddr);
        outMac->inDstMac = 0xAABBCCDDEE03ULL;
        outMac->outSrcMac = 0xAABBCCDDEE04ULL;
        EXasAdjacent_t *adj = GetExtension(h, EXasAdjacent);
        adj->nextAdjacentAS = 64504;
        adj->prevAdjacentAS = 64505;
        EXlatency_t *lat = GetExtension(h, EXlatency);
        lat->msecClientNwDelay = 10;
        lat->msecServerNwDelay = 30;
        lat->msecApplLatency = 300;
        EXlayer2_t *l2 = GetExtension(h, EXlayer2);
        l2->vlanID = 500;
        l2->postVlanID = 600;
        l2->ingress = 2001;
        l2->egress = 2002;
        l2->etherType = 0x86DD;
        l2->ipVersion = 6;
        EXipInfo_t *ipInfo = GetExtension(h, EXipInfo);
        ipInfo->fragmentFlags = 0;
        ipInfo->minTTL = 55;
        ipInfo->maxTTL = 64;
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 41: NAT IPv6 translation
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv6FlowID, EXinterfaceID, EXflowMiscID, EXnatXlateV6ID, EXnatXlatePortID, EXnselCommonID};
        BuildV4Record(buf, ext, 7);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 101;
        h->nfVersion = 10;
        h->flags = V4_FLAG_EVENT;
        FillGenericFlow(h, IPPROTO_TCP, 12345, 443, 20, 10000, 0x12);
        SetIPv6(h, "fd00::1", "2001:db8::100");
        EXinterface_t *iface = GetExtension(h, EXinterface);
        iface->input = 1;
        iface->output = 2;
        EXflowMisc_t *misc = GetExtension(h, EXflowMisc);
        misc->srcMask = 64;
        misc->dstMask = 48;
        EXnatXlateV6_t *xlate = GetExtension(h, EXnatXlateV6);
        uint64_t v6[2];
        inet_pton(AF_INET6, "2001:db8:nat::1", v6);
        xlate->xlateSrcAddr[0] = ntohll(v6[0]);
        xlate->xlateSrcAddr[1] = ntohll(v6[1]);
        inet_pton(AF_INET6, "2001:db8::100", v6);
        xlate->xlateDstAddr[0] = ntohll(v6[0]);
        xlate->xlateDstAddr[1] = ntohll(v6[1]);
        EXnatXlatePort_t *xport = GetExtension(h, EXnatXlatePort);
        xport->xlateSrcPort = 60000;
        xport->xlateDstPort = 443;
        EXnselCommon_t *nsel = GetExtension(h, EXnselCommon);
        nsel->type = NSEL_NAT;
        nsel->natEvent = 1;
        nsel->natPoolID = 10;
        EXgenericFlow_t *gf = GetExtension(h, EXgenericFlow);
        nsel->msecEvent = gf->msecFirst;
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Record 42: NSEL ACL logging (Cisco ASA)
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXinterfaceID, EXflowMiscID, EXnselCommonID, EXnselAclID};
        BuildV4Record(buf, ext, 6);
        h = (recordHeaderV4_t *)buf;
        h->exporterID = 103;
        h->nfVersion = 10;
        h->flags = V4_FLAG_EVENT;
        FillGenericFlow(h, IPPROTO_TCP, 80, 55555, 5, 2000, 0x02);
        SetIPv4(h, "192.168.50.1", "203.0.113.200");
        EXinterface_t *iface = GetExtension(h, EXinterface);
        iface->input = 1;
        iface->output = 2;
        EXflowMisc_t *misc = GetExtension(h, EXflowMisc);
        misc->srcMask = 24;
        misc->dstMask = 24;
        EXnselCommon_t *nsel = GetExtension(h, EXnselCommon);
        nsel->type = NSEL_LOGGING;
        nsel->fwEvent = 2;
        nsel->fwXevent = 1001;
        nsel->connID = 12345678;
        EXgenericFlow_t *gf = GetExtension(h, EXgenericFlow);
        nsel->msecEvent = gf->msecFirst;
        EXnselAcl_t *acl = GetExtension(h, EXnselAcl);
        acl->ingressAcl[0] = 0x11111111;
        acl->ingressAcl[1] = 0x22222222;
        acl->ingressAcl[2] = 0x33333333;
        acl->egressAcl[0] = 0x44444444;
        acl->egressAcl[1] = 0x55555555;
        acl->egressAcl[2] = 0x66666666;
        EMIT_RECORD(buf, nffile, block, nffile->stat_record);
    }

    // ================================================================
    // Flush and close
    // ================================================================
    FlushBlockV3(nffile, block);
    FlushFileV3(nffile);
    CloseFileV3(nffile);

    printf("Generated 42 V4 flow records in dummy_flows.nf\n");

    return 0;
}
