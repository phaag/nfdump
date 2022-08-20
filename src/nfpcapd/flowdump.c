/*
 *  Copyright (c) 2021, Peter Haag
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
#include "metric.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfnet.h"
#include "nfxV3.h"
#include "output_short.h"
#include "queue.h"
#include "util.h"

static int printRecord = 0;
#include "nffile_inline.c"

#define UpdateRecordSize(s) \
    recordSize += (s);      \
    if (recordSize > availableSize) continue;

static int StorePcapFlow(flowParam_t *flowParam, struct FlowNode *Node);

static int StorePcapFlow(flowParam_t *flowParam, struct FlowNode *Node) {
    FlowSource_t *fs = flowParam->fs;

    dbg_printf("Store Flow node\n");

    // output buffer size check for all expected records
    uint32_t recordSize = 0;
    do {
        int availableSize = CheckBufferSpace(fs->nffile, recordSize);
        if (availableSize == 0) {
            // fishy! - should never happen. maybe disk full?
            LogError("StorePcapFlow(): output buffer size error. Skip record");
            return 0;
        }
        recordSize = 0;

        // map output record to memory buffer
        UpdateRecordSize(V3HeaderRecordSize);
        AddV3Header(fs->nffile->buff_ptr, recordHeader);

        // header data
        recordHeader->nfversion = 0x41;
        recordHeader->engineType = 0x11;
        recordHeader->engineID = 1;
        recordHeader->exporterID = 0;

        // pack V3 record
        UpdateRecordSize(EXgenericFlowSize);
        PushExtension(recordHeader, EXgenericFlow, genericFlow);
        genericFlow->msecFirst = (1000LL * (uint64_t)Node->t_first.tv_sec) + (uint64_t)Node->t_first.tv_usec / 1000LL;
        genericFlow->msecLast = (1000LL * (uint64_t)Node->t_last.tv_sec) + (uint64_t)Node->t_last.tv_usec / 1000LL;

        struct timeval now;
        gettimeofday(&now, NULL);
        genericFlow->msecReceived = (uint64_t)now.tv_sec * 1000LL + (uint64_t)now.tv_usec / 1000LL;

        genericFlow->inPackets = Node->packets;
        genericFlow->inBytes = Node->bytes;

        genericFlow->proto = Node->proto;
        genericFlow->tcpFlags = Node->flags;
        genericFlow->srcPort = Node->src_port;
        genericFlow->dstPort = Node->dst_port;

        if (Node->version == AF_INET6) {
            UpdateRecordSize(EXipv6FlowSize);
            PushExtension(recordHeader, EXipv6Flow, ipv6Flow);
            ipv6Flow->srcAddr[0] = Node->src_addr.v6[0];
            ipv6Flow->srcAddr[1] = Node->src_addr.v6[1];
            ipv6Flow->dstAddr[0] = Node->dst_addr.v6[0];
            ipv6Flow->dstAddr[1] = Node->dst_addr.v6[1];
        } else {
            UpdateRecordSize(EXipv4FlowSize);
            PushExtension(recordHeader, EXipv4Flow, ipv4Flow);
            ipv4Flow->srcAddr = Node->src_addr.v4;
            ipv4Flow->dstAddr = Node->dst_addr.v4;
        }

        if (flowParam->extendedFlow) {
            if (Node->vlanID) {
                UpdateRecordSize(EXvLanSize);
                PushExtension(recordHeader, EXvLan, vlan);
                vlan->dstVlan = Node->vlanID;
            }

            UpdateRecordSize(EXmacAddrSize);
            PushExtension(recordHeader, EXmacAddr, macAddr);
            macAddr->inSrcMac = ntohll(Node->srcMac) >> 16;
            macAddr->outDstMac = ntohll(Node->dstMac) >> 16;
            macAddr->inDstMac = 0;
            macAddr->outSrcMac = 0;

            if (Node->mpls[0]) {
                UpdateRecordSize(EXmplsLabelSize);
                PushExtension(recordHeader, EXmplsLabel, mplsLabel);
                for (int i = 0; Node->mpls[i] != 0; i++) {
                    mplsLabel->mplsLabel[i] = ntohl(Node->mpls[i]) >> 8;
                }
            }

            if (Node->proto == IPPROTO_TCP) {
                UpdateRecordSize(EXlatencySize);
                PushExtension(recordHeader, EXlatency, latency);
                latency->usecClientNwDelay = Node->latency.client;
                latency->usecServerNwDelay = Node->latency.server;
                latency->usecApplLatency = Node->latency.application;
            }
        }

        if (flowParam->addPayload) {
            if (Node->payloadSize) {
                UpdateRecordSize(EXinPayloadSize + Node->payloadSize);
                PushVarLengthPointer(recordHeader, EXinPayload, inPayload, Node->payloadSize);
                memcpy(inPayload, Node->payload, Node->payloadSize);
            }
        }

        if (Node->tun_ip_version == AF_INET) {
            UpdateRecordSize(EXtunIPv4Size);
            PushExtension(recordHeader, EXtunIPv4, tunIPv4);
            tunIPv4->tunSrcAddr = Node->tun_src_addr.v4;
            tunIPv4->tunDstAddr = Node->tun_dst_addr.v4;
            tunIPv4->tunProto = Node->tun_proto;
        } else if (Node->tun_ip_version == AF_INET6) {
            UpdateRecordSize(EXtunIPv6Size);
            PushExtension(recordHeader, EXtunIPv6, tunIPv6);
            tunIPv6->tunSrcAddr[0] = Node->tun_src_addr.v6[0];
            tunIPv6->tunSrcAddr[1] = Node->tun_src_addr.v6[1];
            tunIPv6->tunDstAddr[0] = Node->tun_dst_addr.v6[0];
            tunIPv6->tunDstAddr[1] = Node->tun_dst_addr.v6[1];
            tunIPv6->tunProto = Node->tun_proto;
        }

        // update first_seen, last_seen
        if (genericFlow->msecFirst < fs->msecFirst) fs->msecFirst = genericFlow->msecFirst;
        if (genericFlow->msecLast > fs->msecLast) fs->msecLast = genericFlow->msecLast;

        // Update stats
        stat_record_t *stat_record = fs->nffile->stat_record;
        switch (genericFlow->proto) {
            case IPPROTO_ICMP:
                stat_record->numflows_icmp++;
                stat_record->numpackets_icmp += genericFlow->inPackets;
                stat_record->numbytes_icmp += genericFlow->inBytes;
                break;
            case IPPROTO_TCP:
                stat_record->numflows_tcp++;
                stat_record->numpackets_tcp += genericFlow->inPackets;
                stat_record->numbytes_tcp += genericFlow->inBytes;
                break;
            case IPPROTO_UDP:
                stat_record->numflows_udp++;
                stat_record->numpackets_udp += genericFlow->inPackets;
                stat_record->numbytes_udp += genericFlow->inBytes;
                break;
            default:
                stat_record->numflows_other++;
                stat_record->numpackets_other += genericFlow->inPackets;
                stat_record->numbytes_other += genericFlow->inBytes;
        }
        stat_record->numflows++;
        stat_record->numpackets += genericFlow->inPackets;
        stat_record->numbytes += genericFlow->inBytes;

        uint32_t exporterIdent = MetricExpporterID(recordHeader);
        UpdateMetric(fs->nffile->ident, exporterIdent, genericFlow);

        if (printRecord) {
            flow_record_short(stdout, recordHeader);
        }

        // update file record size ( -> output buffer size )
        fs->nffile->block_header->NumRecords += 1;
        fs->nffile->block_header->size += recordHeader->size;

        dbg_printf("Record size: %u, header size: %u\n", recordSize, recordHeader->size);

        assert(recordHeader->size == recordSize);
        fs->nffile->buff_ptr += recordHeader->size;
        break;

    } while (1);

    return 1;

} /* End of StorePcapFlow */

static inline int CloseFlowFile(flowParam_t *flowParam, time_t timestamp) {
    char FullName[MAXPATHLEN];

    struct tm *when = localtime(&timestamp);
    char fmt[24];
    strftime(fmt, sizeof(fmt), flowParam->extensionFormat, when);

    FlowSource_t *fs = flowParam->fs;
    nffile_t *nffile = fs->nffile;

    // prepare sub dir hierarchy
    char *subdir = NULL;
    char netflowFname[128];
    if (flowParam->subdir_index) {
        subdir = GetSubDir(when);
        if (!subdir) {
            // failed to generate subdir path - put flows into base directory
            LogError("Failed to create subdir path!");

            // failed to generate subdir path - put flows into base directory
            subdir = NULL;
            snprintf(netflowFname, 127, "nfcapd.%s", fmt);
        } else {
            snprintf(netflowFname, 127, "%s/nfcapd.%s", subdir, fmt);
        }

    } else {
        snprintf(netflowFname, 127, "nfcapd.%s", fmt);
    }
    netflowFname[127] = '\0';

    char error[256];
    if (subdir && !SetupSubDir(fs->datadir, subdir, error, 255)) {
        // in this case the flows get lost! - the rename will fail
        // but this should not happen anyway, unless i/o problems, inode problems etc.
        LogError("Ident: %s, Failed to create sub hier directories: %s", fs->Ident, error);
    }

    if (nffile->block_header->NumRecords) {
        // flush current buffer to disc
        if (WriteBlock(nffile) <= 0) LogError("Ident: %s, failed to write output buffer to disk: '%s'", fs->Ident, strerror(errno));
    }  // else - no new records in current block

    // prepare full filename
    snprintf(FullName, MAXPATHLEN - 1, "%s/%s", fs->datadir, netflowFname);
    FullName[MAXPATHLEN - 1] = '\0';

    // update stat record
    // if no flows were collected, fs->last_seen is still 0
    // set first_seen to start of this time slot, with twin window size.
    if (fs->msecLast == 0) {
        fs->msecFirst = 1000LL * (uint64_t)timestamp;
        fs->msecLast = 1000LL * (uint64_t)(timestamp + flowParam->t_win);
    }
    nffile->stat_record->firstseen = fs->msecFirst;
    nffile->stat_record->lastseen = fs->msecLast;

    // Flush Exporter Stat to file
    FlushExporterStats(fs);
    // Close file
    CloseUpdateFile(nffile);

    // if rename fails, we are in big trouble, as we need to get rid of the old .current file
    // otherwise, we will loose flows and can not continue collecting new flows
    if (RenameAppend(fs->current, FullName) < 0) {
        LogError("Ident: %s, Can't rename dump file: %s", fs->Ident, strerror(errno));
        LogError("Ident: %s, Serious Problem! Fix manually", fs->Ident);
        // we do not update the books here, as the file failed to rename properly
        // otherwise the books may be wrong
    } else {
        struct stat fstat;
        // Update books
        stat(FullName, &fstat);
        UpdateBooks(fs->bookkeeper, timestamp, 512 * fstat.st_blocks);
    }

    LogInfo("Ident: '%s' Flows: %llu, Packets: %llu, Bytes: %llu", fs->Ident, (unsigned long long)nffile->stat_record->numflows,
            (unsigned long long)nffile->stat_record->numpackets, (unsigned long long)nffile->stat_record->numbytes);

    // reset stats
    fs->bad_packets = 0;
    fs->msecFirst = 0xffffffffffffLL;
    fs->msecLast = 0;

    // Dump all exporters to the buffer
    FlushStdRecords(fs);

    return 0;
}  // end of CloseFlowFile

__attribute__((noreturn)) void *flow_thread(void *thread_data) {
    // argument dispatching
    flowParam_t *flowParam = (flowParam_t *)thread_data;
    int compress = flowParam->compress;
    FlowSource_t *fs = flowParam->fs;

    printRecord = flowParam->printRecord;
    // prepare file
    fs->nffile = OpenNewFile(fs->current, NULL, compress, NOT_ENCRYPTED);
    if (!fs->nffile) {
        pthread_kill(flowParam->parent, SIGUSR1);
        pthread_exit((void *)flowParam);
    }
    SetIdent(fs->nffile, fs->Ident);

    // init vars
    fs->bad_packets = 0;
    fs->msecFirst = 0xffffffffffffLL;
    fs->msecLast = 0;
    while (1) {
        struct FlowNode *Node = Pop_Node(flowParam->NodeList);
        if (Node->fin == SIGNAL_SYNC) {
            CloseFlowFile(flowParam, Node->timestamp);
            fs->nffile = OpenNewFile(fs->current, fs->nffile, compress, NOT_ENCRYPTED);
            if (!fs->nffile) {
                LogError("Fatal: OpenNewFile() failed for ident: %s", fs->Ident);
                pthread_kill(flowParam->parent, SIGUSR1);
                break;
            }
            SetIdent(fs->nffile, fs->Ident);

            // Dump all exporters to the buffer
            FlushStdRecords(fs);

        } else if (Node->fin == SIGNAL_DONE) {
            CloseFlowFile(flowParam, Node->timestamp);
            break;
        } else {
            StorePcapFlow(flowParam, Node);
        }
        Free_Node(Node);
    }

    DisposeFile(fs->nffile);

    LogInfo("Terminating flow processng");
    dbg_printf("End flow thread[%lu]\n", (long unsigned)flowParam->tid);

    pthread_exit((void *)flowParam);
    /* NOTREACHED */

}  // End of p_flow_thread
