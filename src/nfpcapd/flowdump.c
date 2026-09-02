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

#include "flowdump.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "collector.h"
#include "config.h"
#include "exporter.h"
#include "flist.h"
#include "id.h"
#include "ip128.h"
#include "logging.h"
#include "metric.h"
#include "network/nfnet.h"
#include "nfcommon.h"
#include "nffileV3/nffileV3.h"
#include "nfxV4.h"
#include "output_short.h"
#include "pflog.h"
#include "queue.h"
#include "stat_record.h"
#include "util.h"

static int printRecord = 0;
#define MAX_FLOW_PAYLOAD 4096u
#include "nffile_inline.c"

static int AppendPcapFlowRecord(flowParam_t *flowParam, struct FlowNode *Node);
static int QueueFlowBlock(flowParam_t *flowParam);
static int AllocateFlowBlock(flowParam_t *flowParam);
static int EmitCycleMessage(flowParam_t *flowParam, time_t when, int done);

/*
 * The flow thread is deliberately backend-agnostic: it turns FlowNodes into
 * complete V4 records in V3 flow blocks and hands those blocks to the selected
 * collector backend through fs->blockQueue.  Both the nffile and UDP backends
 * therefore consume exactly the same stream.
 */
static int AppendPcapFlowRecord(flowParam_t *flowParam, struct FlowNode *Node) {
    FlowSource_t *fs = flowParam->fs;

    if (!fs->dataBlock) {
        LogError("AppendPcapFlowRecord(): no output block; dropping flow");
        return 0;
    }

    dbg_printf("Store Flow node\n");

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
        // EXvLanID = 7
        if (Node->coldNode.vlanID) {
            BitMapSet(bitMap, EXvLanID);
            extensionSize += EXvLanSize;
        }
        // EXmplsID = 13
        if (Node->coldNode.mpls[0]) {
            BitMapSet(bitMap, EXmplsID);
            extensionSize += EXmplsSize;
        }
        // EXinMacAddrID = 14
        if (Node->coldNode.srcMac) {
            BitMapSet(bitMap, EXinMacAddrID);
            extensionSize += EXinMacAddrSize;
        }
        // EXlatencyID = 17
        if (Node->hotNode.flowKey.proto == IPPROTO_TCP && Node->coldNode.latency.application) {
            BitMapSet(bitMap, EXlatencyID);
            extensionSize += EXlatencySize;
        }
        // EXpfinfoID = 33
        if (Node->coldNode.pflog.has_pfinfo) {
            BitMapSet(bitMap, EXpfinfoID);
            extensionSize += EXpfinfoSize;
            SetFlag(flags, V4_FLAG_EVENT);
        }
        // EXipInfoID = 38
        BitMapSet(bitMap, EXipInfoID);
        extensionSize += EXipInfoSize;
    }

    // EXinPayloadID = 26 (variable-length)
    uint32_t payloadAligned = 0;
    uint32_t payloadCopyLen = 0;
    if (flowParam->addPayload && Node->coldNode.payloadSize) {
        payloadCopyLen = Node->coldNode.payloadSize;
        if (payloadCopyLen > MAX_FLOW_PAYLOAD) payloadCopyLen = MAX_FLOW_PAYLOAD;
        BitMapSet(bitMap, EXinPayloadID);
        payloadAligned = ALIGN8(sizeof(uint32_t) + payloadCopyLen);
        extensionSize += payloadAligned;
    }

    // EXtunnelV4ID / EXtunnelV6ID (split IPv4/IPv6)
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

    // ── Buffer check — single check, no retry loop ──
    if (!IsAvailable(fs->dataBlock, flowParam->blockAllocSize, recordSize)) {
        if (!QueueFlowBlock(flowParam) || !AllocateFlowBlock(flowParam)) return 0;
    }
    uint32_t available = flowParam->blockAllocSize - fs->dataBlock->rawSize;
    if (available < recordSize) {
        LogError("AppendPcapFlowRecord(): output buffer size error. Skip record");
        return 0;
    }

    // ── Phase 2: write V4 record ──
    uint8_t *buffPtr = GetCursor(fs->dataBlock);
    memset(buffPtr, 0, recordSize);

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

    // zero the offset table
    uint16_t *offset = V4OffsetTable(recordHeader);
    memset(offset, 0, tableSize);
    uint32_t nextOffset = baseOffset;

    // Extensions must be written in ascending extID order
    // so that *offset++ fills the table in bitmap rank order

    // ── EXgenericFlow (ID=1, always present) ──
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

    // ── EXipv4Flow (ID=2) or EXipv6Flow (ID=3) ──
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

    // ── Conditional extensions in ascending ID order ──

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
        inPayload->size = payloadCopyLen;
        memcpy(inPayload->payload, Node->coldNode.payload, payloadCopyLen);
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
        // copy up to 3 chars + NUL into fixed ifname[4]
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

    // update first_seen, last_seen
    UpdateFirstLast(fs->dataBlock, genericFlow->msecFirst, genericFlow->msecLast);
    fs->dataBlock->extensionBitmap |= bitMap;

    if (fs->isNffileBackend) {
        UpdateRecordStat(&fs->stat_record, genericFlow, NULL);
        UpdateMetric(fs->Ident, MetricExpporterID(recordHeader), genericFlow);
    }

    if (printRecord) {
        flow_record_short(stdout, recordHeader);
    }

    // update file record size ( -> output buffer size )
    fs->dataBlock->numRecords += 1;
    fs->dataBlock->rawSize += recordSize;

    /* UDP delivery must not wait for a complete storage-sized (BLOCK_SIZE_V3) block. */
    if (flowParam->blockFlushThreshold && fs->dataBlock->rawSize >= flowParam->blockFlushThreshold) {
        if (!QueueFlowBlock(flowParam) || !AllocateFlowBlock(flowParam)) return 0;
    }

    return 1;

} /* End of AppendPcapFlowRecord */

static int AllocateFlowBlock(flowParam_t *flowParam) {
    FlowSource_t *fs = flowParam->fs;
    fs->dataBlock = NewFlowBlock(flowParam->blockAllocSize);
    if (!fs->dataBlock) {
        LogError("flow_thread: unable to allocate output block");
        return 0;
    }
    return 1;
}

static int QueueFlowBlock(flowParam_t *flowParam) {
    FlowSource_t *fs = flowParam->fs;
    if (!fs->dataBlock) return 1;

    if (fs->dataBlock->numRecords != 0) {
        if (queue_push(fs->blockQueue, fs->dataBlock) == QUEUE_CLOSED) {
            LogError("flow_thread: backend queue closed while queuing flow block");
            FreeDataBlock(fs->dataBlock);
            fs->dataBlock = NULL;
            return 0;
        }
    } else {
        FreeDataBlock(fs->dataBlock);
    }
    fs->dataBlock = NULL;
    return 1;
}

static int EmitCycleMessage(flowParam_t *flowParam, time_t when, int done) {
    FlowSource_t *fs = flowParam->fs;

    // Snapshot timestamps only for a file cycle. The UDP backend uses the
    // message solely as a flush/done marker; the receiver owns its stats.
    if (fs->isNffileBackend && fs->dataBlock && fs->dataBlock->numRecords) {
        if (fs->dataBlock->msecFirst < fs->stat_record.msecFirstSeen || fs->stat_record.msecFirstSeen == 0)
            fs->stat_record.msecFirstSeen = fs->dataBlock->msecFirst;
        if (fs->dataBlock->msecLast > fs->stat_record.msecLastSeen) fs->stat_record.msecLastSeen = fs->dataBlock->msecLast;
    }

    if (!QueueFlowBlock(flowParam)) return 0;

    msgBlockV3_t *msgBlock = NULL;
    InitDataBlock(msgBlock, BLOCK_SIZE_V3);
    if (!msgBlock) {
        LogError("flow_thread: unable to allocate cycle message block");
        return 0;
    }

    cycle_message_t message = {.type = MESSAGE_CYCLE, .length = sizeof(cycle_message_t), .when = when, .done = done};
    if (fs->isNffileBackend) memcpy(&message.stat_record, &fs->stat_record, sizeof(message.stat_record));
    memcpy(GetCursor(msgBlock), &message, sizeof(message));
    msgBlock->rawSize += sizeof(message);
    msgBlock->numMessages = 1;

    if (queue_push(fs->blockQueue, msgBlock) == QUEUE_CLOSED) {
        LogError("flow_thread: backend queue closed while queuing cycle message");
        FreeDataBlock(msgBlock);
        return 0;
    }

    if (fs->isNffileBackend)
        LogInfo("Ident: '%s' Flows: %llu, Packets: %llu, Bytes: %llu", fs->Ident, (unsigned long long)fs->stat_record.numflows,
                (unsigned long long)fs->stat_record.numpackets, (unsigned long long)fs->stat_record.numbytes);
    fs->bad_packets = 0;
    if (fs->isNffileBackend) memset(&fs->stat_record, 0, sizeof(fs->stat_record));

    if (done) {
        queue_close(fs->blockQueue);
        return 1;
    }
    return AllocateFlowBlock(flowParam);
}

__attribute__((noreturn)) void *flow_thread(void *thread_data) {
    flowParam_t *flowParam = (flowParam_t *)thread_data;
    FlowSource_t *fs = flowParam->fs;

    printRecord = flowParam->printRecord;
    if (!AllocateFlowBlock(flowParam)) {
        pthread_kill(flowParam->parent, SIGUSR1);
        pthread_exit((void *)flowParam);
    }

    fs->bad_packets = 0;
    int done = 0;
    while (!done) {
        struct FlowNode *Node = Pop_Node(flowParam->NodeList);
        if (!Node) {
            if (!EmitCycleMessage(flowParam, flowParam->NodeList->closeTimestamp, 1)) pthread_kill(flowParam->parent, SIGUSR1);
            break;
        }

        dbg_assert(Node->memflag == NODE_IN_USE);
        switch (Node->nodeType) {
            case FLOW_NODE:
                // A non-fatal "record dropped" (no block yet / record too large to
                // ever fit) never touches fs->dataBlock; only a broken pipeline
                // (OOM in AllocateFlowBlock, or the backend queue having closed
                // inside QueueFlowBlock) leaves it NULL. Escalate only that case.
                AppendPcapFlowRecord(flowParam, Node);
                if (!fs->dataBlock) {
                    pthread_kill(flowParam->parent, SIGUSR1);
                    done = 1;
                }
                break;
            case SIGNAL_NODE_SYNC:
                dbg_printf("Received signal_node_sync\n");
                if (!EmitCycleMessage(flowParam, Node->timestamp, 0)) {
                    Free_Node(Node);
                    pthread_kill(flowParam->parent, SIGUSR1);
                    done = 1;
                    continue;
                }
                break;
            case SIGNAL_NODE_DONE:
                dbg_printf("Received signal_node_done\n");
                if (!EmitCycleMessage(flowParam, Node->timestamp, 1)) pthread_kill(flowParam->parent, SIGUSR1);
                done = 1;
                break;
            default:
                LogError("Unknown node type: %u", Node->nodeType);
                break;
        }
        Free_Node(Node);
    }

    FreeDataBlock(fs->dataBlock);
    fs->dataBlock = NULL;
    LogInfo("Terminating flow processing");
    dbg_printf("End flow thread[%lu]\n", (long unsigned)flowParam->tid);
    pthread_exit((void *)flowParam);
}
