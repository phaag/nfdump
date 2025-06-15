/*
 *  Copyright (c) 2009-2025, Peter Haag
 *  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
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
 * sfcapd makes use of code originated from sflowtool by InMon Corp.
 * Those parts of the code are distributed under the InMon Public License below.
 * All other/additional code is pubblished under BSD license.
 */

#include "sflow_nfdump.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "metric.h"
#include "nfdump.h"
#include "nfxV3.h"
#include "output_short.h"
#include "sflow.h" /* sFlow v5 */
#include "sflow_process.h"
#include "sflow_v2v4.h" /* sFlow v2/4 */
#include "util.h"

#define MAX_SFLOW_EXTENSIONS 8

typedef struct exporter_sflow_s {
    // link chain
    struct exporter_sflow_s *next;

    // exporter information
    exporter_info_record_t info;

    uint64_t packets;           // number of packets sent by this exporter
    uint64_t flows;             // number of flow records sent by this exporter
    uint32_t sequence_failure;  // number of sequence failures

    sampler_t *sampler;

} exporter_sflow_t;

static int PrintRecord = 0;

static int ExtensionsEnabled[MAXEXTENSIONS];
uint32_t BaseRecordSize = EXgenericFlowSize;

static exporter_sflow_t *GetExporter(FlowSource_t *fs, uint32_t agentSubId, uint32_t meanSkipCount);

#include "inline.c"
#include "nffile_inline.c"

int Init_sflow(int verbose, char *extensionList) {
    PrintRecord = verbose;

    if (extensionList) {
        // Disable all extensions
        for (int i = 0; i < MAXEXTENSIONS; i++) {
            ExtensionsEnabled[i] = 0;
        }

        // get enabled extensions from string
        int extID = ScanExtension(extensionList);
        while (extID > 0) {
            dbg_printf("Enable extension %d\n", extID);
            ExtensionsEnabled[extID] = 1;
            extID = ScanExtension(NULL);
        }

        if (extID == -1) {
            LogError("Failed to scan extension list.");
            return 0;
        }

        // make sure extension 1 is enabled
        if (ExtensionsEnabled[1] == 0) {
            LogError("Force EXgeneric extension");
        }
        ExtensionsEnabled[1] = 1;

    } else {
        // Enable all extensions
        dbg_printf("Enable all extensions\n");
        for (int i = 0; i < MAXEXTENSIONS; i++) {
            ExtensionsEnabled[i] = 1;
        }
    }

    // extension available in all flows
    if (ExtensionsEnabled[EXflowMiscID]) {
        BaseRecordSize += EXflowMiscSize;
    }
    if (ExtensionsEnabled[EXvLanID]) {
        BaseRecordSize += EXvLanSize;
    }
    if (ExtensionsEnabled[EXasRoutingID]) {
        BaseRecordSize += EXasRoutingSize;
    }
    if (ExtensionsEnabled[EXmacAddrID]) {
        BaseRecordSize += EXmacAddrSize;
    }
    if (ExtensionsEnabled[EXmplsLabelID]) {
        BaseRecordSize += EXmplsLabelSize;
    }

    return 1;
}  // End of Init_sflow

// called by sfcapd for each packet
void Process_sflow(void *in_buff, ssize_t in_buff_cnt, FlowSource_t *fs, int parse_tun) {
    SFSample sample = {.rawSample = in_buff,
                       .rawSampleLen = in_buff_cnt,
                       .sourceIP.s_addr = fs->sa_family == PF_INET ? htonl(fs->ip.V4) : 0,
                       .parse_tun = parse_tun};

    dbg_printf("startDatagram =================================\n");
    // catch SFABORT in sflow code
    int exceptionVal;
    if ((exceptionVal = setjmp(sample.env)) == 0) {
        // TRY
        sample.datap = (uint32_t *)sample.rawSample;
        sample.endp = (u_char *)sample.rawSample + sample.rawSampleLen;
        readSFlowDatagram(&sample, fs, PrintRecord);
    } else {
        // CATCH
        dbg_printf("SFLOW: caught exception: %d\n", exceptionVal);
        LogError("SFLOW: caught exception: %d", exceptionVal);
    }
    dbg_printf("endDatagram	 =================================\n");

}  // End of Process_sflow

static exporter_sflow_t *GetExporter(FlowSource_t *fs, uint32_t agentSubId, uint32_t meanSkipCount) {
    // search the appropriate exporter engine
    exporter_sflow_t **e = (exporter_sflow_t **)&(fs->exporter_data);
    while (*e) {
        if ((*e)->info.id == agentSubId && (*e)->info.version == SFLOW_VERSION && (*e)->info.ip.V6[0] == fs->ip.V6[0] &&
            (*e)->info.ip.V6[1] == fs->ip.V6[1])
            return *e;
        e = &((*e)->next);
    }

#define IP_STRING_LEN 40
    char ipstr[IP_STRING_LEN];
    if (fs->sa_family == AF_INET) {
        uint32_t _ip = htonl(fs->ip.V4);
        inet_ntop(AF_INET, &_ip, ipstr, sizeof(ipstr));
    } else if (fs->sa_family == AF_INET6) {
        uint64_t _ip[2] = {htonll(fs->ip.V6[0]), htonll(fs->ip.V6[1])};
        inet_ntop(AF_INET6, &_ip, ipstr, sizeof(ipstr));
    } else {
        strncpy(ipstr, "<unknown>", IP_STRING_LEN);
    }

    // nothing found
    LogInfo("SFLOW: New exporter");

    *e = (exporter_sflow_t *)malloc(sizeof(exporter_sflow_t));
    if (!(*e)) {
        LogError("SFLOW: malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    **e = (exporter_sflow_t){
        .next = NULL,
        .info.header.type = ExporterInfoRecordType,
        .info.header.size = sizeof(exporter_info_record_t),
        .info.version = SFLOW_VERSION,
        .info.id = agentSubId,
        .info.ip = fs->ip,
        .info.sa_family = fs->sa_family,
        .sequence_failure = 0,
        .packets = 0,
        .flows = 0,
    };

    sampler_t *sampler = (sampler_t *)malloc(sizeof(sampler_t));
    if (!sampler) {
        LogError("SFLOW: malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }
    (*e)->sampler = sampler;
    *sampler = (sampler_t){.record.type = SamplerRecordType,
                           .record.size = sizeof(sampler_record_t),
                           .record.id = -1,
                           .record.algorithm = 0,
                           .record.packetInterval = 1,
                           .record.spaceInterval = meanSkipCount - 1,
                           .next = NULL};

    FlushInfoExporter(fs, &((*e)->info));
    sampler->record.exporter_sysid = (*e)->info.sysid;
    fs->dataBlock = AppendToBuffer(fs->nffile, fs->dataBlock, &(sampler->record), sampler->record.size);

    dbg_printf("SFLOW: New exporter: SysID: %u, agentSubId: %u, MeanSkipCount: %u, IP: %s\n", (*e)->info.sysid, agentSubId, meanSkipCount, ipstr);
    LogInfo("SFLOW: New exporter: SysID: %u, agentSubId: %u, MeanSkipCount: %u, IP: %s", (*e)->info.sysid, agentSubId, meanSkipCount, ipstr);

    return (*e);

}  // End of GetExporter

// store sflow in nfdump format
void StoreSflowRecord(SFSample *sample, FlowSource_t *fs) {
    dbg_printf("StoreSflowRecord\n");

    struct timeval now;
    gettimeofday(&now, NULL);

    exporter_sflow_t *exporter = GetExporter(fs, sample->agentSubId, sample->meanSkipCount);
    if (!exporter) {
        LogError("SFLOW: Exporter NULL: Abort sflow record processing");
        return;
    }
    exporter->packets++;

    if (sample->ip_fragmentOffset > 0) {
        sample->dcd_sport = 0;
        sample->dcd_dport = 0;
    }

    uint32_t recordSize = BaseRecordSize;

    int isV4 = sample->ipsrc.type == SFLADDRESSTYPE_IP_V4;
    if (isV4 && ExtensionsEnabled[EXipv4FlowID]) {
        recordSize += EXipv4FlowSize;
    }

    int isV6 = sample->ipsrc.type == SFLADDRESSTYPE_IP_V6;
    if (isV6 && ExtensionsEnabled[EXipv6FlowID]) {
        recordSize += EXipv6FlowSize;
    }
    dbg_printf("IPv4: %u, IPv6: %u\n", isV4, isV6);

    if (sample->nextHop.type == SFLADDRESSTYPE_IP_V4 && ExtensionsEnabled[EXipNextHopV4ID]) {
        recordSize += EXipNextHopV4Size;
    }
    if (sample->nextHop.type == SFLADDRESSTYPE_IP_V6 && ExtensionsEnabled[EXipNextHopV6ID]) {
        recordSize += EXipNextHopV6Size;
    }

    if (sample->bgp_nextHop.type == SFLADDRESSTYPE_IP_V4 && ExtensionsEnabled[EXbgpNextHopV4ID]) {
        recordSize += EXbgpNextHopV4Size;
    }
    if (sample->bgp_nextHop.type == SFLADDRESSTYPE_IP_V6 && ExtensionsEnabled[EXbgpNextHopV6ID]) {
        recordSize += EXbgpNextHopV6Size;
    }

    if ((sample->extended_data_tag & SASAMPLE_EXTENDED_DATA_NAT) != 0) {
        if (sample->nat_src.type == SFLADDRESSTYPE_IP_V4 && ExtensionsEnabled[EXnatXlateIPv4ID]) {
            recordSize += EXnatXlateIPv4Size;
        }
        if (sample->nat_src.type == SFLADDRESSTYPE_IP_V6 && ExtensionsEnabled[EXnatXlateIPv6ID]) {
            recordSize += EXnatXlateIPv6Size;
        }
        if (ExtensionsEnabled[EXnatXlatePortID]) {
            recordSize += EXnatXlatePortSize;
        }
    }

    if (fs->sa_family == AF_INET && ExtensionsEnabled[EXipReceivedV4ID]) {
        recordSize += EXipReceivedV4Size;
    }
    if (fs->sa_family == AF_INET6 && ExtensionsEnabled[EXipReceivedV6ID]) {
        recordSize += EXipReceivedV6Size;
    }

    // Tunnels
    int tun_isV4 = sample->tun_ipsrc.type == SFLADDRESSTYPE_IP_V4;
    if (tun_isV4 && ExtensionsEnabled[EXtunIPv4ID]) {
        recordSize += EXtunIPv4Size;
    }

    int tun_isV6 = sample->tun_ipsrc.type == SFLADDRESSTYPE_IP_V6;
    if (isV6 && ExtensionsEnabled[EXtunIPv6ID]) {
        recordSize += EXtunIPv6Size;
    }
    dbg_printf("Tunnel: IPv4: %u, IPv6: %u\n", tun_isV4, tun_isV6);

    recordSize += sizeof(recordHeaderV3_t);
    if (!IsAvailable(fs->dataBlock, recordSize)) {
        // flush block - get an empty one
        fs->dataBlock = WriteBlock(fs->nffile, fs->dataBlock);
    }

    void *buffPtr = GetCurrentCursor(fs->dataBlock);
    dbg_printf("Fill Record\n");
    AddV3Header(buffPtr, recordHeader);

    recordHeader->exporterID = exporter->info.sysid;
    recordHeader->flags = V3_FLAG_SAMPLED;
    recordHeader->nfversion = 0x80 | sample->datagramVersion;

    // pack V3 record
    PushExtension(recordHeader, EXgenericFlow, genericFlow);
    uint64_t msec = now.tv_sec * 1000L + now.tv_usec / 1000;
    *genericFlow = (EXgenericFlow_t){
        .msecFirst = msec,
        .msecLast = msec,
        .proto = sample->dcd_ipProtocol,
        .tcpFlags = sample->dcd_tcpFlags,
        .srcPort = (uint16_t)sample->dcd_sport,
        .dstPort = (uint16_t)sample->dcd_dport,
        .msecReceived = (uint64_t)((uint64_t)fs->received.tv_sec * 1000LL) + (uint64_t)((uint64_t)fs->received.tv_usec / 1000LL),
        .inPackets = sample->meanSkipCount,
        .inBytes = sample->meanSkipCount * sample->sampledPacketSize,
        .srcTos = sample->dcd_ipTos,
    };

    if (isV4 && ExtensionsEnabled[EXipv4FlowID]) {
        PushExtension(recordHeader, EXipv4Flow, ipv4Flow);
        ipv4Flow->srcAddr = ntohl(sample->ipsrc.address.ip_v4.addr);
        ipv4Flow->dstAddr = ntohl(sample->ipdst.address.ip_v4.addr);
    }

    if (isV6 && ExtensionsEnabled[EXipv6FlowID]) {
        PushExtension(recordHeader, EXipv6Flow, ipv6Flow);

        u_char *b = sample->ipsrc.address.ip_v6.addr;
        uint64_t *u = (uint64_t *)b;
        ipv6Flow->srcAddr[0] = ntohll(*u);
        u = (uint64_t *)&(b[8]);
        ipv6Flow->srcAddr[1] = ntohll(*u);

        b = sample->ipdst.address.ip_v6.addr;
        u = (uint64_t *)b;
        ipv6Flow->dstAddr[0] = ntohll(*u);
        u = (uint64_t *)&(b[8]);
        ipv6Flow->dstAddr[1] = ntohll(*u);
    }

    if (ExtensionsEnabled[EXflowMiscID]) {
        PushExtension(recordHeader, EXflowMisc, flowMisc);
        flowMisc->input = sample->inputPort;
        flowMisc->output = sample->outputPort;
        flowMisc->srcMask = sample->srcMask;
        flowMisc->dstMask = sample->dstMask;
    }

    if (ExtensionsEnabled[EXvLanID]) {
        PushExtension(recordHeader, EXvLan, vLan);
        vLan->srcVlan = sample->in_vlan;
        vLan->dstVlan = sample->out_vlan;
    }

    if (ExtensionsEnabled[EXasRoutingID]) {
        PushExtension(recordHeader, EXasRouting, asRouting);
        asRouting->srcAS = sample->src_as;
        asRouting->dstAS = sample->dst_as;
    }

    if (sample->nextHop.type == SFLADDRESSTYPE_IP_V4 && ExtensionsEnabled[EXipNextHopV4ID]) {
        PushExtension(recordHeader, EXipNextHopV4, ipNextHopV4);
        ipNextHopV4->ip = ntohl(sample->nextHop.address.ip_v4.addr);
    }
    if (sample->nextHop.type == SFLADDRESSTYPE_IP_V6 && ExtensionsEnabled[EXipNextHopV6ID]) {
        uint64_t *addr = (uint64_t *)sample->nextHop.address.ip_v6.addr;
        PushExtension(recordHeader, EXipNextHopV6, ipNextHopV6);
        ipNextHopV6->ip[0] = ntohll(addr[0]);
        ipNextHopV6->ip[1] = ntohll(addr[1]);
    }

    if (sample->bgp_nextHop.type == SFLADDRESSTYPE_IP_V4 && ExtensionsEnabled[EXbgpNextHopV4ID]) {
        PushExtension(recordHeader, EXbgpNextHopV4, bgpNextHopV4);
        bgpNextHopV4->ip = ntohl(sample->bgp_nextHop.address.ip_v4.addr);
    }
    if (sample->bgp_nextHop.type == SFLADDRESSTYPE_IP_V6 && ExtensionsEnabled[EXbgpNextHopV6ID]) {
        uint64_t *addr = (void *)sample->bgp_nextHop.address.ip_v6.addr;
        PushExtension(recordHeader, EXbgpNextHopV6, bgpNextHopV6);
        bgpNextHopV6->ip[0] = ntohll(addr[0]);
        bgpNextHopV6->ip[1] = ntohll(addr[1]);
    }

    if (ExtensionsEnabled[EXmacAddrID]) {
        PushExtension(recordHeader, EXmacAddr, macAddr);
        macAddr->inSrcMac = Get_val48((void *)&sample->eth_src);
        macAddr->outDstMac = Get_val48((void *)&sample->eth_dst);
        macAddr->inDstMac = 0;
        macAddr->outSrcMac = 0;
    }

    if (ExtensionsEnabled[EXmplsLabelID]) {
        if (sample->mpls_num_labels > 0) {
            PushExtension(recordHeader, EXmplsLabel, mplsLabel);
            for (int i = 0; i < sample->mpls_num_labels; i++) {
                mplsLabel->mplsLabel[i] = sample->mpls_label[i];
            }
        }
    }

    if ((sample->extended_data_tag & SASAMPLE_EXTENDED_DATA_NAT) != 0) {
        switch (sample->nat_src.type) {
            case SFLADDRESSTYPE_IP_V4:
                if (ExtensionsEnabled[EXnatXlateIPv4ID]) {
                    dbg_printf("NAT v4 addr\n");
                    PushExtension(recordHeader, EXnatXlateIPv4, natXlateIPv4);
                    natXlateIPv4->xlateSrcAddr = ntohl(sample->nat_src.address.ip_v4.addr);
                    natXlateIPv4->xlateDstAddr = ntohl(sample->nat_dst.address.ip_v4.addr);
                }
                break;
            case SFLADDRESSTYPE_IP_V6: {
                if (ExtensionsEnabled[EXnatXlateIPv6ID]) {
                    dbg_printf("NAT v6 addr\n");
                    PushExtension(recordHeader, EXnatXlateIPv6, natXlateIPv6);
                    uint64_t *addr = (void *)sample->nat_src.address.ip_v6.addr;
                    natXlateIPv6->xlateSrcAddr[0] = ntohll(addr[0]);
                    natXlateIPv6->xlateSrcAddr[1] = ntohll(addr[1]);
                    addr = (void *)sample->nat_dst.address.ip_v6.addr;
                    natXlateIPv6->xlateDstAddr[0] = ntohll(addr[0]);
                    natXlateIPv6->xlateDstAddr[1] = ntohll(addr[1]);
                }
            } break;
            default:
                /* undefined address type - bail out */
                LogError("SFLOW: getAddress() unknown address type = %d\n", sample->nat_src.type);
        }
        if (ExtensionsEnabled[EXnatXlatePortID]) {
            PushExtension(recordHeader, EXnatXlatePort, natXlatePort);
            natXlatePort->xlateSrcPort = sample->nat_src_port;
            natXlatePort->xlateDstPort = sample->nat_dst_port;
        }
    }

    // add router IP
    if (fs->sa_family == PF_INET && ExtensionsEnabled[EXipReceivedV4ID]) {
        PushExtension(recordHeader, EXipReceivedV4, ipReceivedV4);
        ipReceivedV4->ip = fs->ip.V4;
        dbg_printf("Add IPv4 route IP extension\n");
    }
    if (fs->sa_family == PF_INET6 && ExtensionsEnabled[EXipReceivedV6ID]) {
        PushExtension(recordHeader, EXipReceivedV6, ipReceivedV6);
        ipReceivedV6->ip[0] = fs->ip.V6[0];
        ipReceivedV6->ip[1] = fs->ip.V6[1];
        dbg_printf("Add IPv6 route IP extension\n");
    }

    // Tunnels
    if (tun_isV4 && ExtensionsEnabled[EXtunIPv4ID]) {
        PushExtension(recordHeader, EXtunIPv4, tunIPv4);
        tunIPv4->tunSrcAddr = ntohl(sample->tun_ipsrc.address.ip_v4.addr);
        tunIPv4->tunDstAddr = ntohl(sample->tun_ipdst.address.ip_v4.addr);
        tunIPv4->tunProto = sample->tun_proto;
        dbg_printf("Add IPv4 tunnel extension\n");
    }

    if (tun_isV6 && ExtensionsEnabled[EXtunIPv6ID]) {
        PushExtension(recordHeader, EXtunIPv6, tunIPv6);

        u_char *b = sample->tun_ipsrc.address.ip_v6.addr;
        uint64_t *u = (uint64_t *)b;
        tunIPv6->tunSrcAddr[0] = ntohll(*u);
        u = (uint64_t *)&(b[8]);
        tunIPv6->tunSrcAddr[1] = ntohll(*u);

        b = sample->tun_ipdst.address.ip_v6.addr;
        u = (uint64_t *)b;
        tunIPv6->tunDstAddr[0] = ntohll(*u);
        u = (uint64_t *)&(b[8]);
        tunIPv6->tunDstAddr[1] = ntohll(*u);

        tunIPv6->tunProto = sample->tun_proto;
        dbg_printf("Add IPv6 tunnel extension\n");
    }

    // update first_seen, last_seen
    if (genericFlow->msecFirst < fs->nffile->stat_record->msecFirstSeen)  // the very first time stamp need to be set
        fs->nffile->stat_record->msecFirstSeen = genericFlow->msecFirst;
    fs->nffile->stat_record->msecLastSeen = genericFlow->msecFirst;

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
    exporter->flows++;
    stat_record->numflows++;
    stat_record->numpackets += genericFlow->inPackets;
    stat_record->numbytes += genericFlow->inBytes;

    uint32_t exporterIdent = MetricExpporterID(recordHeader);
    UpdateMetric(fs->nffile->ident, exporterIdent, genericFlow);

    if (PrintRecord) {
        flow_record_short(stdout, recordHeader);
    }
#ifdef DEVEL
    printf("OffsetToPayload %d\n", sample->offsetToPayload);
    void *p = (void *)sample->header + sample->offsetToPayload;
    ssize_t len = sample->headerLen - sample->offsetToPayload;
    dbg_printf("Payload length: %zd\n", len);
    if (len > 0) {
        dbg_printf("Payload length: %zd\n", len);
        DumpHex(stdout, p, len);
    }
#endif
    // update file record size ( -> output buffer size )
    fs->dataBlock->NumRecords++;
    fs->dataBlock->size += recordHeader->size;

    dbg_printf("Record size: Header: %u, calc: %u\n", recordHeader->size, recordSize);
    dbg_assert(recordHeader->size <= recordSize);

}  // End of StoreSflowRecord
