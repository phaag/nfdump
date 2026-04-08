/*
 *  Copyright (c) 2009-2026, Peter Haag
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

#include "logging.h"
#include "metric.h"
#include "nfdump.h"
#include "nfxV4.h"
#include "output_short.h"
// sFlow v5
#include "sflow.h"
#include "sflow_process.h"
// sFlow v2/4
#include "id.h"
#include "sflow_v2v4.h"
#include "util.h"

#define MAX_SFLOW_EXTENSIONS 8

static int PrintRecord = 0;

static int ExtensionsEnabled[MAXEXTENSIONS];

// extension size of all basic enabled extensions
// Init_sflow() adds more basic extension StoreSFlow() adds more dynamic extensions
static uint32_t baseExtensionSize = EXgenericFlowSize;

// corresponding bitmap
static uint64_t baseBitMap = 1LL << EXgenericFlowID;

static exporter_entry_t *GetExporter(FlowSource_t *fs, uint32_t agentSubId, uint32_t meanSkipCount);

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
    if (ExtensionsEnabled[EXinterfaceID]) {
        BitMapSet(baseBitMap, EXinterfaceID);
        baseExtensionSize += EXinterfaceSize;
    }
    if (ExtensionsEnabled[EXflowMiscID]) {
        BitMapSet(baseBitMap, EXflowMiscID);
        baseExtensionSize += EXflowMiscSize;
    }
    if (ExtensionsEnabled[EXvLanID]) {
        BitMapSet(baseBitMap, EXvLanID);
        baseExtensionSize += EXvLanSize;
    }
    if (ExtensionsEnabled[EXasInfoID]) {
        BitMapSet(baseBitMap, EXasInfoID);
        baseExtensionSize += EXasInfoSize;
    }
    if (ExtensionsEnabled[EXinMacAddrID]) {
        BitMapSet(baseBitMap, EXinMacAddrID);
        baseExtensionSize += EXinMacAddrSize;
    }

    return 1;
}  // End of Init_sflow

// called by sfcapd for each packet
void Process_sflow(void *in_buff, ssize_t in_buff_cnt, FlowSource_t *fs, int parse_tun) {
    SFSample sample = {.rawSample = in_buff, .rawSampleLen = in_buff_cnt, .parse_tun = parse_tun};

    memcpy(sample.sourceIP.bytes, fs->ipAddr.bytes, 16);
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

static exporter_entry_t *GetExporter(FlowSource_t *fs, uint32_t agentSubId, uint32_t meanSkipCount) {
    const exporter_key_t key = {.version = SFLOW_VERSION, .id = agentSubId};

    // fast cache
    if (fs->last_exp && fs->last_key.version == key.version && fs->last_key.id == key.id) return fs->last_exp;

    // not found - search in hash table
    exporter_table_t *tab = &fs->exporters;
    // Check load factor in case we need a new slot
    if ((tab->count * 4) >= (tab->capacity * 3)) {
        // expand exporter index
        expand_exporter_table(tab);
        tab = &fs->exporters;
    }

    uint32_t hash = EXPORTERHASH(key);
    uint32_t mask = tab->capacity - 1;
    uint32_t i = hash & mask;

    for (;;) {
        exporter_entry_t *e = &tab->entries[i];
        // key does not exists - create new exporter
        if (!e->in_use) {
            // create new exporter
            size_t recordSize = sizeof(exporter_info_record_v4_t) + sizeof(sampler_record_v4_t);
            void *info = calloc(1, recordSize);
            if (info == NULL) {
                LogError("Process_sflow: malloc(): %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                return NULL;
            }

            // create new exporter
            *e = (exporter_entry_t){.key = key, .sequence = UINT32_MAX, .sysID = AssignExporterID(), .in_use = 1, .info = info};
            tab->count++;

            *(e->info) = (exporter_info_record_v4_t){
                .type = ExporterInfoRecordV4Type,
                .size = recordSize,
                .version = key.version,
                .id = key.id,
                .sysID = e->sysID,
                .sampler_capacity = 1,
            };
            memcpy(e->info->ip, fs->ipAddr.bytes, 16);

            e->sflow = (exporter_sflow_t){0};

            // attach sampler
            sampler_record_v4_t *sampler = &e->info->samplers[0];
            *sampler = (sampler_record_v4_t){
                .inUse = 1, .selectorID = SAMPLER_GENERIC, .algorithm = 0, .packetInterval = 1, .spaceInterval = meanSkipCount - 1};

            e->sampler_cache[0].ptr = &e->info->samplers[0];
            e->sampler_count++;

            char ipstr[INET6_ADDRSTRLEN];
            ip128_2_str(&fs->ipAddr, ipstr);

            e->sflow.bitMap = baseBitMap;
            if (fs->sa_family == PF_INET6) {
                BitMapSet(e->sflow.bitMap, EXipReceivedV6ID);
                // max proposed output record size
                e->sflow.extensionSize = baseExtensionSize + EXipReceivedV6Size;
                dbg_printf("Process_v5: New IPv6 exporter %s - add EXipReceivedV6\n", ipstr);
            } else {
                BitMapSet(e->sflow.bitMap, EXipReceivedV4ID);
                // max proposed output record size
                e->sflow.extensionSize = baseExtensionSize + EXipReceivedV4Size;
                dbg_printf("Process_v5: New IPv4 exporter %s - add EXipReceivedV4\n", ipstr);
            }

            LogInfo("Process_sflow: New exporter: SysID: %u, agentSubId: %u, MeanSkipCount: %u, IP: %s", e->info->sysID, agentSubId, meanSkipCount,
                    ip128_2_str(&fs->ipAddr, ipstr));

            fs->last_key = key;
            fs->last_exp = e;
            return e;
        }
        if (EXPORTER_KEY_EQUAL(e->key, key)) {
            fs->last_key = key;
            fs->last_exp = e;
            return e;
        }

        dbg_assert(tab->count < tab->capacity);
        i = (i + 1) & mask;
    }

    // unreached
    return NULL;

}  // End of GetExporter

// store sflow in nfdump format
void StoreSflowRecord(SFSample *sample, FlowSource_t *fs) {
    dbg_printf("StoreSflowRecord\n");

    struct timeval now = fs->received;

    exporter_entry_t *exporter = GetExporter(fs, sample->agentSubId, sample->meanSkipCount);
    if (!exporter) {
        LogError("SFLOW: Exporter NULL: Abort sflow record processing");
        return;
    }
    exporter->packets++;

    if (sample->ip_fragmentOffset > 0) {
        sample->dcd_sport = 0;
        sample->dcd_dport = 0;
    }

    // build up record and extensions
    uint32_t extensionSize = exporter->sflow.extensionSize;
    uint64_t bitMap = exporter->sflow.bitMap;

    int isV4 = sample->ipsrc.type == SFLADDRESSTYPE_IP_V4;
    if (isV4 && ExtensionsEnabled[EXipv4FlowID]) {
        BitMapSet(bitMap, EXipv4FlowID);
        extensionSize += EXipv4FlowSize;
    }

    int isV6 = sample->ipsrc.type == SFLADDRESSTYPE_IP_V6;
    if (isV6 && ExtensionsEnabled[EXipv6FlowID]) {
        BitMapSet(bitMap, EXipv6FlowID);
        extensionSize += EXipv6FlowSize;
    }
    dbg_printf("IPv4: %u, IPv6: %u\n", isV4, isV6);

    if ((sample->nextHop.type == SFLADDRESSTYPE_IP_V4 || sample->bgp_nextHop.type == SFLADDRESSTYPE_IP_V4) && ExtensionsEnabled[EXasRoutingV4ID]) {
        BitMapSet(bitMap, EXasRoutingV4ID);
        extensionSize += EXasRoutingV4Size;
    }
    if ((sample->nextHop.type == SFLADDRESSTYPE_IP_V6 || sample->bgp_nextHop.type == SFLADDRESSTYPE_IP_V6) && ExtensionsEnabled[EXasRoutingV6ID]) {
        BitMapSet(bitMap, EXasRoutingV6ID);
        extensionSize += EXasRoutingV6Size;
    }

    if (sample->mpls_num_labels > 0 && ExtensionsEnabled[EXmplsID]) {
        BitMapSet(bitMap, EXmplsID);
        extensionSize += EXmplsSize;
    }

    if ((sample->extended_data_tag & SASAMPLE_EXTENDED_DATA_NAT) != 0) {
        if (sample->nat_src.type == SFLADDRESSTYPE_IP_V4 && ExtensionsEnabled[EXnatXlateV4ID]) {
            BitMapSet(bitMap, EXnatXlateV4ID);
            extensionSize += EXnatXlateV4Size;
        }
        if (sample->nat_src.type == SFLADDRESSTYPE_IP_V6 && ExtensionsEnabled[EXnatXlateV6ID]) {
            BitMapSet(bitMap, EXnatXlateV6ID);
            extensionSize += EXnatXlateV6Size;
        }
        if (ExtensionsEnabled[EXnatXlatePortID]) {
            BitMapSet(bitMap, EXnatXlatePortID);
            extensionSize += EXnatXlatePortSize;
        }
    }

    // Tunnels
    int tun_isV4 = sample->tun_ipsrc.type == SFLADDRESSTYPE_IP_V4;
    int tun_isV6 = sample->tun_ipsrc.type == SFLADDRESSTYPE_IP_V6;
    if ((tun_isV4 || tun_isV6) && ExtensionsEnabled[EXtunnelID]) {
        BitMapSet(bitMap, EXtunnelID);
        extensionSize += EXtunnelSize;
    }

    dbg_printf("Tunnel: IPv4: %u, IPv6: %u\n", tun_isV4, tun_isV6);

    uint32_t numExtensions = __builtin_popcountll(bitMap);
    size_t tableSize = ALIGN8(numExtensions * sizeof(uint16_t));
    uint32_t baseOffset = sizeof(recordHeaderV4_t) + tableSize;
    uint32_t recordSize = baseOffset + extensionSize;

    if (!IsAvailable(fs->dataBlock, BLOCK_SIZE_V3, recordSize)) {
        // flush block - get an empty one
        PushBlockV3(fs->blockQueue, fs->dataBlock);
        fs->dataBlock = NULL;
        InitDataBlock(fs->dataBlock, BLOCK_SIZE_V3);
    }

    uint8_t *buffPtr = GetCursor(fs->dataBlock);
    dbg_printf("Fill Record\n");

    // zero entire record at once
    recordHeaderV4_t *recordHeader = (recordHeaderV4_t *)buffPtr;
    *recordHeader = (recordHeaderV4_t){.type = V4Record,
                                       .exporterID = exporter->sysID,
                                       .nfVersion = 0x80 | sample->datagramVersion,
                                       .flags = V4_FLAG_SAMPLED,
                                       .extBitmap = bitMap,
                                       .numExtensions = numExtensions};

    EXgenericFlow_t *genericFlow = NULL;
    // fill the record based on the bitMap
    uint8_t *recordBase = buffPtr;
    uint16_t *offset = (uint16_t *)(buffPtr + sizeof(recordHeaderV4_t));
    memset(offset, 0, tableSize);
    uint32_t nextOffset = baseOffset;
    while (bitMap) {
        uint64_t t = bitMap & -bitMap;
        uint32_t extID = __builtin_ctzll(bitMap);
        bitMap ^= t;

        *offset++ = nextOffset;
        uint32_t extSize = extensionTable[extID].size;
        uint8_t *extension = recordBase + nextOffset;
        nextOffset += extSize;

        switch (extID) {
            case EXgenericFlowID: {
                genericFlow = (EXgenericFlow_t *)extension;
                uint64_t msec = (uint64_t)(now.tv_sec * 1000L + now.tv_usec / 1000);
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
            } break;
            case EXipv4FlowID: {
                EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)extension;
                ipv4Flow->srcAddr = ntohl(sample->ipsrc.address.ip_v4.addr);
                ipv4Flow->dstAddr = ntohl(sample->ipdst.address.ip_v4.addr);
            } break;
            case EXipv6FlowID: {
                EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)extension;
                uint64_t ip6[2];
                memcpy(ip6, sample->ipsrc.address.ip_v6.addr, 16);
                ipv6Flow->srcAddr[0] = ntohll(ip6[0]);
                ipv6Flow->srcAddr[1] = ntohll(ip6[1]);

                memcpy(ip6, sample->ipdst.address.ip_v6.addr, 16);
                ipv6Flow->dstAddr[0] = ntohll(ip6[0]);
                ipv6Flow->dstAddr[1] = ntohll(ip6[1]);
            } break;
            case EXinterfaceID: {
                EXinterface_t *interface = (EXinterface_t *)extension;
                interface->input = sample->inputPort;
                interface->output = sample->outputPort;
            } break;
            case EXflowMiscID: {
                EXflowMisc_t *flowMisc = (EXflowMisc_t *)extension;
                *flowMisc = (EXflowMisc_t){.srcMask = sample->srcMask, .dstMask = sample->dstMask};
            } break;
            case EXvLanID: {
                EXvLan_t *vLan = (EXvLan_t *)extension;
                vLan->srcVlan = sample->in_vlan;
                vLan->dstVlan = sample->out_vlan;
            } break;
            case EXasInfoID: {
                EXasInfo_t *asInfo = (EXasInfo_t *)extension;
                asInfo->srcAS = sample->src_as;
                asInfo->dstAS = sample->dst_as;
            } break;
            case EXasRoutingV4ID: {
                EXasRoutingV4_t *asRouting = (EXasRoutingV4_t *)extension;
                asRouting->nextHop = ntohl(sample->nextHop.address.ip_v4.addr);
                asRouting->bgpNextHop = ntohl(sample->bgp_nextHop.address.ip_v4.addr);
            } break;
            case EXasRoutingV6ID: {
                EXasRoutingV6_t *asRouting = (EXasRoutingV6_t *)extension;
                uint64_t ip6[2];
                memcpy(ip6, sample->nextHop.address.ip_v6.addr, 16);
                asRouting->nextHop[0] = ntohll(ip6[0]);
                asRouting->nextHop[1] = ntohll(ip6[1]);

                memcpy(ip6, sample->bgp_nextHop.address.ip_v6.addr, 16);
                asRouting->bgpNextHop[0] = ntohll(ip6[0]);
                asRouting->bgpNextHop[1] = ntohll(ip6[1]);
            } break;
            case EXinMacAddrID: {
                EXinMacAddr_t *macAddr = (EXinMacAddr_t *)extension;
                macAddr->inSrcMac = Get_val48((void *)&sample->eth_src);
                macAddr->outDstMac = Get_val48((void *)&sample->eth_dst);
            } break;
            case EXmplsID: {
                EXmpls_t *mpls = (EXmpls_t *)extension;
                if (sample->mpls_num_labels > 0) {
                    for (int i = 0; i < sample->mpls_num_labels; i++) {
                        mpls->label[i] = sample->mpls_label[i];
                    }
                    for (int i = sample->mpls_num_labels; i < 10; i++) {
                        mpls->label[i] = 0;
                    }
                }
            } break;
            case EXnatXlateV4ID: {
                EXnatXlateV4_t *natXlateIPv4 = (EXnatXlateV4_t *)extension;
                natXlateIPv4->xlateSrcAddr = ntohl(sample->nat_src.address.ip_v4.addr);
                natXlateIPv4->xlateDstAddr = ntohl(sample->nat_dst.address.ip_v4.addr);
            } break;
            case EXnatXlateV6ID: {
                EXnatXlateV6_t *natXlateIPv6 = (EXnatXlateV6_t *)extension;
                uint64_t ip6[2];
                memcpy(ip6, sample->nat_src.address.ip_v6.addr, 16);
                natXlateIPv6->xlateSrcAddr[0] = ntohll(ip6[0]);
                natXlateIPv6->xlateSrcAddr[1] = ntohll(ip6[1]);
                memcpy(ip6, sample->nat_dst.address.ip_v6.addr, 16);
                natXlateIPv6->xlateDstAddr[0] = ntohll(ip6[0]);
                natXlateIPv6->xlateDstAddr[1] = ntohll(ip6[1]);
            } break;
            case EXnatXlatePortID: {
                EXnatXlatePort_t *natXlatePort = (EXnatXlatePort_t *)extension;
                natXlatePort->xlateSrcPort = sample->nat_src_port;
                natXlatePort->xlateDstPort = sample->nat_dst_port;
            } break;
            case EXipReceivedV4ID: {
                EXipReceivedV4_t *ipReceived = (EXipReceivedV4_t *)extension;
                uint32_t ipv4;
                memcpy(&ipv4, fs->ipAddr.bytes + 12, 4);
                ipReceived->ip = ntohl(ipv4);
                dbg_printf("Add IPv4 router IP extension\n");
            } break;
            case EXipReceivedV6ID: {
                EXipReceivedV6_t *ipReceived = (EXipReceivedV6_t *)extension;
                uint64_t ip6[2];
                memcpy(ip6, fs->ipAddr.bytes, 16);
                ipReceived->ip[0] = ntohll(ip6[0]);
                ipReceived->ip[1] = ntohll(ip6[1]);
                dbg_printf("Add IPv6 router IP extension\n");
            } break;
            case EXtunnelID: {
                EXtunnel_t *tunnel = (EXtunnel_t *)extension;
                if (tun_isV4) {
                    dbg_printf("Add IPv4 tunnel extension\n");
                    memset(tunnel->tunSrcAddr, 0, 10);
                    memset(tunnel->tunDstAddr, 0, 10);
                    tunnel->tunSrcAddr[10] = 0xff;
                    tunnel->tunSrcAddr[11] = 0xff;
                    tunnel->tunDstAddr[10] = 0xff;
                    tunnel->tunDstAddr[11] = 0xff;
                    memcpy(tunnel->tunSrcAddr + 12, &sample->tun_ipsrc.address.ip_v4.addr, 4);
                    memcpy(tunnel->tunDstAddr + 12, &sample->tun_ipdst.address.ip_v4.addr, 4);
                } else if (tun_isV6) {
                    memcpy(tunnel->tunSrcAddr, sample->tun_ipsrc.address.ip_v6.addr, 16);
                    memcpy(tunnel->tunDstAddr, sample->tun_ipdst.address.ip_v6.addr, 16);
                }
                tunnel->tunProto = sample->tun_proto;
            } break;
        }
    }

    recordHeader->size = nextOffset;

    // update first_seen, last_seen
    if (!genericFlow) {
        LogError("SFLOW: genericFlow extension missing - skip stats update");
        return;
    }
    if (genericFlow->msecFirst < fs->stat_record.msecFirstSeen)  // the very first time stamp need to be set
        fs->stat_record.msecFirstSeen = genericFlow->msecFirst;
    fs->stat_record.msecLastSeen = genericFlow->msecFirst;

    // Update stats
    stat_record_t *stat_record = &fs->stat_record;
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
    UpdateMetric(fs->Ident, exporterIdent, genericFlow);

    if (PrintRecord) {
        flow_record_short(stdout, recordHeader);
    }
#ifdef DEVEL
    printf("OffsetToPayload %d\n", sample->offsetToPayload);
    void *p = (void *)sample->header + sample->offsetToPayload;
    ssize_t len = (int)sample->headerLen - sample->offsetToPayload;
    dbg_printf("Payload length: %zd\n", len);
    if (len > 0) {
        dbg_printf("Payload length: %zd\n", len);
        DumpHex(stdout, p, (unsigned)len);
    }
#endif
    // update file record size ( -> output buffer size )
    fs->dataBlock->numRecords++;
    fs->dataBlock->rawSize += recordHeader->size;

    dbg_printf("Record size: Header: %u, calc: %u\n", recordHeader->size, recordSize);
    dbg_assert(recordHeader->size <= recordSize);

}  // End of StoreSflowRecord
