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

#include "flowsend.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bookkeeper.h"
#include "collector.h"
#include "config.h"
#include "exporter.h"
#include "flowdump.h"
#include "id.h"
#include "logging.h"
#include "metric.h"
#include "nfd_raw.h"
#include "nfdump.h"
#include "nfnet.h"
#include "nfxV4.h"
#include "output_short.h"
#include "queue.h"
#include "util.h"

static int printRecord = 0;

static void *sendBuffer = NULL;
static uint32_t sequence = 0;

static int ProcessFlow(flowParam_t *flowParam, struct FlowNode *Node);

static int SendFlow(repeater_t *sendHost, nfd_header_t *pcapd_header) {
    dbg_printf("Sending %u records\n", pcapd_header->numRecord);
    uint32_t length = pcapd_header->length;
    pcapd_header->length = htons(pcapd_header->length);
    uint32_t seq = sequence++;
    pcapd_header->lastSequence = htonl(seq);
    pcapd_header->numRecord = htonl(pcapd_header->numRecord);
    // send buffer
    ssize_t len = sendto(sendHost->sockfd, pcapd_header, length, 0, (struct sockaddr *)&(sendHost->addr), sendHost->addrlen);
    if (len < 0) {
        LogError("ERROR: sendto() failed: %s", strerror(errno));
        return len;
    }

    // init new header
    pcapd_header->length = sizeof(nfd_header_t);
    pcapd_header->numRecord = 0;

    return 0;

}  // End of SendFlow

static int ProcessFlow(flowParam_t *flowParam, struct FlowNode *Node) {
    repeater_t *sendHost = flowParam->sendHost;

    dbg_printf("Send Flow node\n");

    nfd_header_t *pcapd_header = (nfd_header_t *)sendBuffer;

    // ── Phase 1: determine bitmap and total record size ──
    uint64_t bitMap = 0;
    uint32_t extensionSize = 0;
    uint16_t flags = 0;

    // always present
    BitMapSet(bitMap, EXgenericFlowID);
    extensionSize += EXgenericFlowSize;

    int isIPv6 = (Node->hotNode.flowKey.version == AF_INET6);
    if (isIPv6) {
        BitMapSet(bitMap, EXipv6FlowID);
        extensionSize += EXipv6FlowSize;
    } else {
        BitMapSet(bitMap, EXipv4FlowID);
        extensionSize += EXipv4FlowSize;
    }

    if (flowParam->extendedFlow) {
        if (Node->coldNode.vlanID) {
            BitMapSet(bitMap, EXvLanID);
            extensionSize += EXvLanSize;
        }
        if (Node->coldNode.mpls[0]) {
            BitMapSet(bitMap, EXmplsID);
            extensionSize += EXmplsSize;
        }
        if (Node->coldNode.srcMac) {
            BitMapSet(bitMap, EXinMacAddrID);
            extensionSize += EXinMacAddrSize;
        }
        if (Node->hotNode.flowKey.proto == IPPROTO_TCP && Node->coldNode.latency.application) {
            BitMapSet(bitMap, EXlatencyID);
            extensionSize += EXlatencySize;
        }
        if (Node->coldNode.pflog.has_pfinfo) {
            BitMapSet(bitMap, EXpfinfoID);
            extensionSize += EXpfinfoSize;
            SetFlag(flags, V4_FLAG_EVENT);
        }
        BitMapSet(bitMap, EXipInfoID);
        extensionSize += EXipInfoSize;
    }

    uint32_t payloadAligned = 0;
    if (flowParam->addPayload && Node->coldNode.payloadSize) {
        BitMapSet(bitMap, EXinPayloadID);
        payloadAligned = ALIGN8(sizeof(uint32_t) + Node->coldNode.payloadSize);
        extensionSize += payloadAligned;
    }

    int tunIsV6 = (Node->coldNode.tun_ip_version == AF_INET6);
    if (Node->coldNode.tun_ip_version) {
        if (tunIsV6) {
            BitMapSet(bitMap, EXtunnelV6ID);
            extensionSize += EXtunnelV6Size;
        } else {
            BitMapSet(bitMap, EXtunnelV4ID);
            extensionSize += EXtunnelV4Size;
        }
    }

    uint32_t numExtensions = __builtin_popcountll(bitMap);
    uint32_t tableSize = ALIGN8(numExtensions * sizeof(uint16_t));
    uint32_t baseOffset = sizeof(recordHeaderV4_t) + tableSize;
    uint32_t recordSize = baseOffset + extensionSize;

    // ── Buffer space check ──
    if (pcapd_header->length + recordSize > 65535) {
        if (SendFlow(sendHost, pcapd_header) < 0) return 0;
    }

    // ── Phase 2: write V4 record ──
    uint8_t *buffPtr = (uint8_t *)sendBuffer + pcapd_header->length;

    recordHeaderV4_t *recordHeader = (recordHeaderV4_t *)buffPtr;
    *recordHeader = (recordHeaderV4_t){
        .type = V4Record,
        .size = recordSize,
        .numExtensions = numExtensions,
        .flags = flags,
        .exporterID = 0,
        .engineType = 0x11,
        .engineID = 1,
        .nfVersion = 0x41,
        .extBitmap = bitMap,
    };

    uint16_t *offset = V4OffsetTable(recordHeader);
    memset(offset, 0, tableSize);
    uint32_t nextOffset = baseOffset;

    // Extensions in ascending extID order

    // EXgenericFlow (ID=1)
    *offset++ = nextOffset;
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)(buffPtr + nextOffset);
    nextOffset += EXgenericFlowSize;
    *genericFlow = (EXgenericFlow_t){
        .msecFirst = 1000LL * (uint64_t)Node->hotNode.t_first.tv_sec + (uint64_t)Node->hotNode.t_first.tv_usec / 1000LL,
        .msecLast = 1000LL * (uint64_t)Node->hotNode.t_last.tv_sec + (uint64_t)Node->hotNode.t_last.tv_usec / 1000LL,
        .msecReceived = 1000LL * (uint64_t)Node->hotNode.t_last.tv_sec + (uint64_t)Node->hotNode.t_last.tv_usec / 1000LL,
        .inPackets = Node->hotNode.packets,
        .inBytes = Node->hotNode.bytes,
        .srcPort = Node->hotNode.flowKey.src_port,
        .dstPort = Node->hotNode.flowKey.dst_port,
        .proto = Node->hotNode.flowKey.proto,
        .tcpFlags = Node->hotNode.flags,
    };

    // EXipv4Flow (ID=2) or EXipv6Flow (ID=3)
    if (isIPv6) {
        *offset++ = nextOffset;
        EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)(buffPtr + nextOffset);
        nextOffset += EXipv6FlowSize;
        uint64_t *src = (uint64_t *)Node->hotNode.flowKey.src_addr.bytes;
        uint64_t *dst = (uint64_t *)Node->hotNode.flowKey.dst_addr.bytes;
        ipv6Flow->srcAddr[0] = ntohll(src[0]);
        ipv6Flow->srcAddr[1] = ntohll(src[1]);
        ipv6Flow->dstAddr[0] = ntohll(dst[0]);
        ipv6Flow->dstAddr[1] = ntohll(dst[1]);
    } else {
        *offset++ = nextOffset;
        EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)(buffPtr + nextOffset);
        nextOffset += EXipv4FlowSize;
        uint32_t ipv4;
        memcpy(&ipv4, Node->hotNode.flowKey.src_addr.bytes + 12, 4);
        ipv4Flow->srcAddr = ntohl(ipv4);
        memcpy(&ipv4, Node->hotNode.flowKey.dst_addr.bytes + 12, 4);
        ipv4Flow->dstAddr = ntohl(ipv4);
    }

    // EXvLan (ID=7)
    if (bitMap & (1ULL << EXvLanID)) {
        *offset++ = nextOffset;
        EXvLan_t *vlan = (EXvLan_t *)(buffPtr + nextOffset);
        nextOffset += EXvLanSize;
        *vlan = (EXvLan_t){.srcVlan = Node->coldNode.vlanID};
    }

    // EXmpls (ID=13)
    if (bitMap & (1ULL << EXmplsID)) {
        *offset++ = nextOffset;
        EXmpls_t *mpls = (EXmpls_t *)(buffPtr + nextOffset);
        nextOffset += EXmplsSize;
        memset(mpls, 0, EXmplsSize);
        for (int i = 0; i < 10 && Node->coldNode.mpls[i] != 0; i++) {
            mpls->label[i] = ntohl(Node->coldNode.mpls[i]) >> 8;
        }
    }

    // EXinMacAddr (ID=14)
    if (bitMap & (1ULL << EXinMacAddrID)) {
        *offset++ = nextOffset;
        EXinMacAddr_t *macAddr = (EXinMacAddr_t *)(buffPtr + nextOffset);
        nextOffset += EXinMacAddrSize;
        *macAddr = (EXinMacAddr_t){
            .inSrcMac = ntohll(Node->coldNode.srcMac) >> 16,
            .outDstMac = ntohll(Node->coldNode.dstMac) >> 16,
        };
    }

    // EXlatency (ID=17)
    if (bitMap & (1ULL << EXlatencyID)) {
        *offset++ = nextOffset;
        EXlatency_t *latency = (EXlatency_t *)(buffPtr + nextOffset);
        nextOffset += EXlatencySize;
        *latency = (EXlatency_t){
            .msecClientNwDelay = Node->coldNode.latency.client,
            .msecServerNwDelay = Node->coldNode.latency.server,
            .msecApplLatency = Node->coldNode.latency.application,
        };
        dbg_printf("Node RTT: %u\n", Node->coldNode.latency.rtt);
    }

    // EXinPayload (ID=26, variable-length)
    if (bitMap & (1ULL << EXinPayloadID)) {
        *offset++ = nextOffset;
        EXinPayload_t *inPayload = (EXinPayload_t *)(buffPtr + nextOffset);
        inPayload->size = Node->coldNode.payloadSize;
        memcpy(inPayload->payload, Node->coldNode.payload, Node->coldNode.payloadSize);
        nextOffset += payloadAligned;
    }

    // EXtunnelV4 / EXtunnelV6 (split IPv4/IPv6)
    if (bitMap & (1ULL << EXtunnelV4ID)) {
        *offset++ = nextOffset;
        EXtunnelV4_t *tunnel = (EXtunnelV4_t *)(buffPtr + nextOffset);
        nextOffset += EXtunnelV4Size;
        uint32_t ipv4;
        memcpy(&ipv4, Node->coldNode.tun_src_addr.bytes + 12, 4);
        tunnel->srcAddr = ntohl(ipv4);
        memcpy(&ipv4, Node->coldNode.tun_dst_addr.bytes + 12, 4);
        tunnel->dstAddr = ntohl(ipv4);
        tunnel->proto = Node->coldNode.tun_proto;
        tunnel->align = 0;
    }
    if (bitMap & (1ULL << EXtunnelV6ID)) {
        *offset++ = nextOffset;
        EXtunnelV6_t *tunnel = (EXtunnelV6_t *)(buffPtr + nextOffset);
        nextOffset += EXtunnelV6Size;
        uint64_t ip6[2];
        memcpy(ip6, Node->coldNode.tun_src_addr.bytes, 16);
        tunnel->srcAddr[0] = ntohll(ip6[0]);
        tunnel->srcAddr[1] = ntohll(ip6[1]);
        memcpy(ip6, Node->coldNode.tun_dst_addr.bytes, 16);
        tunnel->dstAddr[0] = ntohll(ip6[0]);
        tunnel->dstAddr[1] = ntohll(ip6[1]);
        tunnel->proto = Node->coldNode.tun_proto;
        tunnel->align = 0;
    }

    // EXpfinfo (ID=33)
    if (bitMap & (1ULL << EXpfinfoID)) {
        *offset++ = nextOffset;
        EXpfinfo_t *pfinfo = (EXpfinfo_t *)(buffPtr + nextOffset);
        nextOffset += EXpfinfoSize;
        *pfinfo = (EXpfinfo_t){
            .action = Node->coldNode.pflog.action,
            .reason = Node->coldNode.pflog.reason,
            .dir = Node->coldNode.pflog.dir,
            .rewritten = Node->coldNode.pflog.rewritten,
            .rulenr = Node->coldNode.pflog.rulenr,
            .subrulenr = Node->coldNode.pflog.subrulenr,
            .uid = Node->coldNode.pflog.uid,
            .pid = Node->coldNode.pflog.pid,
        };
        strncpy(pfinfo->ifname, Node->coldNode.pflog.ifname, sizeof(pfinfo->ifname) - 1);
        pfinfo->ifname[sizeof(pfinfo->ifname) - 1] = '\0';
    }

    // EXipInfo (ID=38)
    if (bitMap & (1ULL << EXipInfoID)) {
        *offset++ = nextOffset;
        EXipInfo_t *ipInfo = (EXipInfo_t *)(buffPtr + nextOffset);
        nextOffset += EXipInfoSize;
        *ipInfo = (EXipInfo_t){
            .fragmentFlags = Node->coldNode.fragmentFlags,
            .minTTL = Node->coldNode.minTTL,
            .maxTTL = Node->coldNode.maxTTL,
        };
    }

    assert(nextOffset == recordSize);

    if (printRecord) {
        flow_record_short(stdout, recordHeader);
    }

    pcapd_header->numRecord++;
    pcapd_header->length += recordSize;

    dbg_printf("Record size: %u\n", recordSize);

    if (pcapd_header->length > 1200) {
        // send buffer - prevent fragmentation for next packet
        if (SendFlow(sendHost, pcapd_header) < 0) return 0;
    }

    return 1;

} /* End of ProcessFlow */

static inline int CloseSender(flowParam_t *flowParam) {
    repeater_t *sendHost = flowParam->sendHost;

    return close(sendHost->sockfd);

}  // end of CloseFlowFile

__attribute__((noreturn)) void *sendflow_thread(void *thread_data) {
    // argument dispatching
    flowParam_t *flowParam = (flowParam_t *)thread_data;

    sendBuffer = malloc(65535);
    nfd_header_t *pcapd_header = (nfd_header_t *)sendBuffer;
    memset((void *)pcapd_header, 0, sizeof(nfd_header_t));
    pcapd_header->version = htons(VERSION_NFDUMP);
    pcapd_header->length = sizeof(nfd_header_t);
    pcapd_header->lastSequence = 1;

    printRecord = flowParam->printRecord;
    int done = 0;
    while (!done) {
        struct FlowNode *Node = Pop_Node(flowParam->NodeList);
        switch (Node->nodeType) {
            case FLOW_NODE:
                ProcessFlow(flowParam, Node);
                break;
            case SIGNAL_NODE_SYNC:
                // skip
                break;
            case SIGNAL_NODE_DONE:
                CloseSender(flowParam);
                done = 1;
                break;
            default:
                LogError("Unknown node type: %u\n", Node->nodeType);
        }
        Free_Node(Node);
    }

    LogInfo("Terminating flow sending");
    dbg_printf("End flow sendthread[%lu]\n", (long unsigned)flowParam->tid);

    pthread_exit((void *)flowParam);
    /* NOTREACHED */

}  // End of p_flow_thread
