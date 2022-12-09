/*
 *  Copyright (c) 2009-2022, Peter Haag
 *  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *	 this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice,
 *	 this list of conditions and the following disclaimer in the documentation
 *	 and/or other materials provided with the distribution.
 *   * Neither the name of the author nor the names of its contributors may be
 *	 used to endorse or promote products derived from this software without
 *	 specific prior written permission.
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

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "nfdump.h"
#include "nffile.h"
#include "nfnet.h"
#include "nfxV3.h"
#include "util.h"

static time_t when;
time_t offset = 10;
uint64_t msecs = 10;

#include "nffile_inline.c"

void *GenRecord(int af, void *buff_ptr, char *src_ip, char *dst_ip, int src_port, int dst_port, int proto, int tcp_flags, int tos, uint64_t packets,
                uint64_t bytes, int src_as, int dst_as);

static void SetIPaddress(master_record_t *record, int af, char *src_ip, char *dst_ip);

static void SetNextIPaddress(master_record_t *record, int af, char *next_ip);

static void SetRouterIPaddress(master_record_t *record, int af, char *next_ip);

static void SetBGPNextIPaddress(master_record_t *record, int af, char *next_ip);

static void UpdateRecord(master_record_t *record);

static void PackRecordV3(master_record_t *master_record, nffile_t *nffile);

static void SetIPaddress(master_record_t *record, int af, char *src_ip, char *dst_ip) {
    if (af == PF_INET6) {
        SetFlag(record->mflags, V3_FLAG_IPV6_ADDR);
        inet_pton(PF_INET6, src_ip, &(record->V6.srcaddr[0]));
        inet_pton(PF_INET6, dst_ip, &(record->V6.dstaddr[0]));
        record->V6.srcaddr[0] = ntohll(record->V6.srcaddr[0]);
        record->V6.srcaddr[1] = ntohll(record->V6.srcaddr[1]);
        record->V6.dstaddr[0] = ntohll(record->V6.dstaddr[0]);
        record->V6.dstaddr[1] = ntohll(record->V6.dstaddr[1]);
    } else {
        ClearFlag(record->mflags, V3_FLAG_IPV6_ADDR);
        inet_pton(PF_INET, src_ip, &record->V4.srcaddr);
        inet_pton(PF_INET, dst_ip, &record->V4.dstaddr);
        record->V4.srcaddr = ntohl(record->V4.srcaddr);
        record->V4.dstaddr = ntohl(record->V4.dstaddr);
    }

}  // End of SetIPaddress

static void SetNextIPaddress(master_record_t *record, int af, char *next_ip) {
    if (af == PF_INET6) {
        SetFlag(record->mflags, V3_FLAG_IPV6_NH);
        inet_pton(PF_INET6, next_ip, &(record->ip_nexthop.V6[0]));
        record->ip_nexthop.V6[0] = ntohll(record->ip_nexthop.V6[0]);
        record->ip_nexthop.V6[1] = ntohll(record->ip_nexthop.V6[1]);
    } else {
        ClearFlag(record->mflags, V3_FLAG_IPV6_NH);
        inet_pton(PF_INET, next_ip, &record->ip_nexthop.V4);
        record->ip_nexthop.V4 = ntohl(record->ip_nexthop.V4);
    }

}  // End of SetNextIPaddress

static void SetRouterIPaddress(master_record_t *record, int af, char *next_ip) {
    if (af == PF_INET6) {
        SetFlag(record->mflags, V3_FLAG_IPV6_NH);
        inet_pton(PF_INET6, next_ip, &(record->ip_router.V6[0]));
        record->ip_router.V6[0] = ntohll(record->ip_router.V6[0]);
        record->ip_router.V6[1] = ntohll(record->ip_router.V6[1]);
    } else {
        ClearFlag(record->mflags, V3_FLAG_IPV6_NH);
        inet_pton(PF_INET, next_ip, &record->ip_router.V4);
        record->ip_router.V4 = ntohl(record->ip_router.V4);
    }

}  // End of SetRouterIPaddress

static void SetBGPNextIPaddress(master_record_t *record, int af, char *next_ip) {
    if (af == PF_INET6) {
        SetFlag(record->mflags, V3_FLAG_IPV6_NHB);
        inet_pton(PF_INET6, next_ip, &(record->bgp_nexthop.V6[0]));
        record->bgp_nexthop.V6[0] = ntohll(record->bgp_nexthop.V6[0]);
        record->bgp_nexthop.V6[1] = ntohll(record->bgp_nexthop.V6[1]);
    } else {
        ClearFlag(record->mflags, V3_FLAG_IPV6_NHB);
        inet_pton(PF_INET, next_ip, &record->bgp_nexthop.V4);
        record->bgp_nexthop.V4 = ntohl(record->bgp_nexthop.V4);
    }

}  // End of SetBGPNextIPaddress

static void UpdateRecord(master_record_t *record) {
    record->msecFirst = 1000LL * when + msecs;
    record->msecLast = 1000LL * when + offset + msecs + 10LL;
    record->msecReceived = record->msecLast - 1000LL + 1LL;

    record->srcPort += 10;
    record->dstPort += 11;

    record->inPackets += 1;
    record->inBytes += 1024;

    when += 10LL;
    offset += 10LL;

    msecs += 100LL;
    if (msecs > 1000LL) msecs = msecs - 1000LL;

    record->engine_id++;
    record->engine_type = offset;

}  // End of UpdateRecord

static void PackRecordV3(master_record_t *master_record, nffile_t *nffile) {
    uint32_t required;

    required = master_record->size;

    // flush current buffer to disc if not enough space
    if (!CheckBufferSpace(nffile, required)) {
        return;
    }

    // enough buffer space available at this point
    AddV3Header(nffile->buff_ptr, v3Record);
    v3Record->flags = master_record->flags;
    v3Record->engineType = master_record->engine_type;
    v3Record->engineID = master_record->engine_id;

    // first record header
    for (int i = 0; i < master_record->numElements; i++) {
        dbg_printf("Pack extension %u\n", master_record->exElementList[i]);
        switch (master_record->exElementList[i]) {
            case EXnull:
                fprintf(stderr, "PackRecordV3(): Found unexpected NULL extension\n");
                break;
            case EXgenericFlowID: {
                PushExtension(v3Record, EXgenericFlow, genericFlow);
                genericFlow->msecFirst = master_record->msecFirst;
                genericFlow->msecLast = master_record->msecLast;
                genericFlow->msecReceived = master_record->msecReceived;
                genericFlow->inPackets = master_record->inPackets;
                genericFlow->inBytes = master_record->inBytes;
                genericFlow->srcPort = master_record->srcPort;
                genericFlow->dstPort = master_record->dstPort;
                genericFlow->proto = master_record->proto;
                genericFlow->tcpFlags = master_record->tcp_flags;
                genericFlow->fwdStatus = master_record->fwd_status;
                genericFlow->srcTos = master_record->tos;
            } break;
            case EXipv4FlowID: {
                PushExtension(v3Record, EXipv4Flow, ipv4Flow);
                ipv4Flow->srcAddr = master_record->V4.srcaddr;
                ipv4Flow->dstAddr = master_record->V4.dstaddr;
            } break;
            case EXipv6FlowID: {
                PushExtension(v3Record, EXipv6Flow, ipv6Flow);
                ipv6Flow->srcAddr[0] = master_record->V6.srcaddr[0];
                ipv6Flow->srcAddr[1] = master_record->V6.srcaddr[1];
                ipv6Flow->dstAddr[0] = master_record->V6.dstaddr[0];
                ipv6Flow->dstAddr[1] = master_record->V6.dstaddr[1];
            } break;
            case EXflowMiscID: {
                PushExtension(v3Record, EXflowMisc, flowMisc);
                flowMisc->input = master_record->input;
                flowMisc->output = master_record->output;
                flowMisc->dir = master_record->dir;
                flowMisc->dstTos = master_record->dst_tos;
                flowMisc->srcMask = master_record->src_mask;
                flowMisc->dstMask = master_record->dst_mask;
                flowMisc->biFlowDir = master_record->biFlowDir;
                flowMisc->flowEndReason = master_record->flowEndReason;
            } break;
            case EXcntFlowID: {
                PushExtension(v3Record, EXcntFlow, cntFlow);
                cntFlow->outPackets = master_record->out_pkts;
                cntFlow->outBytes = master_record->out_bytes;
                cntFlow->flows = master_record->aggr_flows;
            } break;
            case EXvLanID: {
                PushExtension(v3Record, EXvLan, vLan);
                vLan->srcVlan = master_record->src_vlan;
                vLan->dstVlan = master_record->dst_vlan;
            } break;
            case EXasRoutingID: {
                PushExtension(v3Record, EXasRouting, asRouting);
                asRouting->srcAS = master_record->srcas;
                asRouting->dstAS = master_record->dstas;
            } break;
            case EXbgpNextHopV4ID: {
                PushExtension(v3Record, EXbgpNextHopV4, bgpNextHopV4);
                bgpNextHopV4->ip = master_record->bgp_nexthop.V4;
            } break;
            case EXbgpNextHopV6ID: {
                PushExtension(v3Record, EXbgpNextHopV6, bgpNextHopV6);
                bgpNextHopV6->ip[0] = master_record->bgp_nexthop.V6[0];
                bgpNextHopV6->ip[1] = master_record->bgp_nexthop.V6[1];
            } break;
            case EXipNextHopV4ID: {
                PushExtension(v3Record, EXipNextHopV4, ipNextHopV4);
                ipNextHopV4->ip = master_record->ip_nexthop.V4;
            } break;
            case EXipNextHopV6ID: {
                PushExtension(v3Record, EXipNextHopV6, ipNextHopV6);
                ipNextHopV6->ip[0] = master_record->ip_nexthop.V6[0];
                ipNextHopV6->ip[1] = master_record->ip_nexthop.V6[1];
            } break;
            case EXipReceivedV4ID: {
                PushExtension(v3Record, EXipReceivedV4, ipNextHopV4);
                ipNextHopV4->ip = master_record->ip_router.V4;
            } break;
            case EXipReceivedV6ID: {
                PushExtension(v3Record, EXipReceivedV6, ipNextHopV6);
                ipNextHopV6->ip[0] = master_record->ip_router.V6[0];
                ipNextHopV6->ip[1] = master_record->ip_router.V6[1];
            } break;
            case EXmplsLabelID: {
                PushExtension(v3Record, EXmplsLabel, mplsLabel);
                for (int j = 0; j < 10; j++) {
                    mplsLabel->mplsLabel[j] = master_record->mpls_label[j];
                }
            } break;
            case EXmacAddrID: {
                PushExtension(v3Record, EXmacAddr, macAddr);
                macAddr->inSrcMac = master_record->in_src_mac;
                macAddr->outDstMac = master_record->out_dst_mac;
                macAddr->inDstMac = master_record->in_dst_mac;
                macAddr->outSrcMac = master_record->out_src_mac;
            } break;
            case EXasAdjacentID: {
                PushExtension(v3Record, EXasAdjacent, asAdjacent);
                asAdjacent->nextAdjacentAS = master_record->bgpNextAdjacentAS;
                asAdjacent->prevAdjacentAS = master_record->bgpPrevAdjacentAS;
            } break;
            case EXlatencyID: {
                PushExtension(v3Record, EXlatency, latency);
                latency->usecClientNwDelay = master_record->client_nw_delay_usec;
                latency->usecServerNwDelay = master_record->server_nw_delay_usec;
                latency->usecApplLatency = master_record->appl_latency_usec;
            } break;
            case EXvrfID: {
                PushExtension(v3Record, EXvrf, vrf);
                vrf->egressVrf = master_record->egressVrf;
                vrf->ingressVrf = master_record->ingressVrf;
            } break;
#ifdef NSEL
            case EXnselCommonID: {
                PushExtension(v3Record, EXnselCommon, nselCommon);
                nselCommon->msecEvent = master_record->msecEvent;
                nselCommon->connID = master_record->connID;
                nselCommon->fwXevent = master_record->fwXevent;
                nselCommon->fwEvent = master_record->event;
            } break;
            case EXnselXlateIPv4ID: {
                PushExtension(v3Record, EXnselXlateIPv4, nselXlateIPv4);
                nselXlateIPv4->xlateSrcAddr = master_record->xlate_src_ip.V4;
                nselXlateIPv4->xlateDstAddr = master_record->xlate_dst_ip.V4;
            } break;
            case EXnselXlateIPv6ID: {
                PushExtension(v3Record, EXnselXlateIPv6, nselXlateIPv6);
                memcpy(nselXlateIPv6->xlateSrcAddr, master_record->xlate_src_ip.V6, 16);
                memcpy(nselXlateIPv6->xlateDstAddr, master_record->xlate_dst_ip.V6, 16);
            } break;
            case EXnselXlatePortID: {
                PushExtension(v3Record, EXnselXlatePort, nselXlatePort);
                nselXlatePort->xlateSrcPort = master_record->xlate_src_port;
                nselXlatePort->xlateDstPort = master_record->xlate_dst_port;
            } break;
            case EXnselAclID: {
                PushExtension(v3Record, EXnselAcl, nselAcl);
                nselAcl->ingressAcl[0] = htonl(master_record->ingressAcl[0]);
                nselAcl->ingressAcl[1] = htonl(master_record->ingressAcl[1]);
                nselAcl->ingressAcl[2] = htonl(master_record->ingressAcl[2]);
                nselAcl->egressAcl[0] = htonl(master_record->egressAcl[0]);
                nselAcl->egressAcl[1] = htonl(master_record->egressAcl[1]);
                nselAcl->egressAcl[2] = htonl(master_record->egressAcl[2]);
            } break;
            case EXnselUserID: {
                PushExtension(v3Record, EXnselUser, nselUser);
                memcpy(nselUser->username, master_record->username, 65);
                nselUser->username[65] = '\0';
            } break;
            case EXnelCommonID: {
                PushExtension(v3Record, EXnelCommon, nelCommon);
                nelCommon->msecEvent = master_record->msecEvent;
                nelCommon->natEvent = master_record->event;
            } break;
            case EXnelXlatePortID: {
                PushExtension(v3Record, EXnelXlatePort, nelXlatePort);
                nelXlatePort->blockStart = master_record->block_start;
                nelXlatePort->blockEnd = master_record->block_end;
                nelXlatePort->blockStep = master_record->block_step;
                nelXlatePort->blockSize = master_record->block_size;
            } break;
#endif
            case EXnbarAppID: {
                PushVarLengthExtension(v3Record, EXnbarApp, nbarApp, 4);
                memcpy(nbarApp->id, master_record->nbarAppID, 4);
            } break;
            default:
                fprintf(stderr, "PackRecordV3(): Unknown extension '%u'\n", master_record->exElementList[i]);
        }
        if (v3Record->size > required) {
            fprintf(stderr, "PackRecordV3(): record size(%u) > expected(%u)'\n", v3Record->size, required);
        }
    }

    if (v3Record->size != required) {
        fprintf(stderr, "PackRecordV3(): record size(%u) != expected(%u)'\n", v3Record->size, required);
    }
    nffile->block_header->NumRecords++;
    nffile->block_header->size += v3Record->size;
    nffile->buff_ptr += v3Record->size;
    dbg_assert(v3Record->size == required);

}  // End of PackRecordV3

int main(int argc, char **argv) {
    int i, c;
    master_record_t record;
    nffile_t *nffile;

    when = ISO2UNIX(strdup("201907111030"));
    while ((c = getopt(argc, argv, "h")) != EOF) {
        switch (c) {
            case 'h':
                break;
            default:
                fprintf(stderr, "ERROR: Unsupported option: '%c'\n", c);
                exit(255);
        }
    }

    memset((void *)&record, 0, sizeof(record));

    if (!Init_nffile(NULL)) exit(254);

    nffile = OpenNewFile("test.flows.nf", NULL, NOT_COMPRESSED, 0);
    if (!nffile) {
        exit(255);
    }

    i = 0;

    // Start with empty record
    record.size = V3HeaderRecordSize;
    record.numElements = i;
    UpdateRecord(&record);
    PackRecordV3(&record, nffile);

    record.exElementList[i++] = EXgenericFlowID;
    record.size += EXgenericFlowSize;
    record.numElements = i;
    record.fwd_status = 1;
    record.tcp_flags = 2;
    record.tos = 3;
    record.dst_tos = 4;
    UpdateRecord(&record);
    PackRecordV3(&record, nffile);

    record.exElementList[i++] = EXipv4FlowID;
    record.size += EXipv4FlowSize;
    SetIPaddress(&record, PF_INET, "172.16.1.66", "192.168.170.100");
    record.numElements = i;
    UpdateRecord(&record);
    PackRecordV3(&record, nffile);

    record.exElementList[i - 1] = EXipv6FlowID;
    record.size -= EXipv4FlowSize;
    record.size += EXipv6FlowSize;
    SetIPaddress(&record, PF_INET6, "fe80::2110:abcd:1234:0", "fe80::2110:abcd:1235:4321");
    UpdateRecord(&record);
    PackRecordV3(&record, nffile);

    record.exElementList[i - 1] = EXipv4FlowID;
    record.size += EXipv4FlowSize;
    record.size -= EXipv6FlowSize;
    SetIPaddress(&record, PF_INET, "172.16.2.66", "192.168.170.101");
    record.exElementList[i++] = EXflowMiscID;
    record.size += EXflowMiscSize;
    record.numElements = i;
    record.srcPort = 80;
    record.dstPort = 22222;
    record.input = 100;
    record.output = 200;
    record.src_mask = 16;
    record.dst_mask = 24;
    record.tcp_flags = 2;
    record.proto = IPPROTO_TCP;
    record.dir = 1;
    PackRecordV3(&record, nffile);

    record.msecFirst += 1000;
    record.msecLast += 1000;
    record.inPackets += 10;
    record.inBytes += 1024;
    record.tcp_flags = 16;
    PackRecordV3(&record, nffile);

    record.msecFirst += 1000LL;
    record.msecLast += 1000LL;
    record.inPackets += 10;
    record.inBytes += 1024;
    record.tcp_flags = 1;
    PackRecordV3(&record, nffile);

    SetIPaddress(&record, PF_INET, "192.168.170.101", "172.16.2.66");
    record.msecFirst += 1;
    record.msecLast += 1;
    record.dstPort = 80;
    record.srcPort = 22222;
    record.input = 200;
    record.output = 100;
    record.src_mask = 24;
    record.dst_mask = 16;
    record.tcp_flags = 18;
    record.proto = IPPROTO_TCP;
    record.dir = 2;
    record.inPackets = 10;
    record.inBytes = 1024;
    PackRecordV3(&record, nffile);

    record.msecFirst += 1000LL;
    record.msecLast += 1000LL;
    record.inPackets += 10;
    record.inBytes += 1024;
    record.tcp_flags = 16;
    PackRecordV3(&record, nffile);

    record.msecFirst += 1000LL;
    record.msecLast += 1000;
    record.inPackets += 10;
    record.inBytes += 1024;
    record.tcp_flags = 1;
    PackRecordV3(&record, nffile);

    SetIPaddress(&record, PF_INET, "72.138.170.101", "42.16.32.6");
    record.exElementList[i++] = EXcntFlowID;
    record.size += EXcntFlowSize;
    record.numElements = i;
    record.tcp_flags++;
    record.out_pkts = 203;
    record.out_bytes = 204;
    record.aggr_flows = 7;
    UpdateRecord(&record);
    PackRecordV3(&record, nffile);

    record.exElementList[i++] = EXvLanID;
    record.size += EXvLanSize;
    record.numElements = i;
    record.tcp_flags++;
    record.src_vlan = 45;
    record.dst_vlan = 46;
    UpdateRecord(&record);
    PackRecordV3(&record, nffile);

    record.exElementList[i++] = EXasRoutingID;
    record.size += EXasRoutingSize;
    record.numElements = i;
    record.tcp_flags++;
    record.srcas = 775;
    record.dstas = 3303;
    UpdateRecord(&record);
    PackRecordV3(&record, nffile);

    record.exElementList[i++] = EXipNextHopV4ID;
    record.size += EXipNextHopV4Size;
    record.numElements = i;
    record.tcp_flags++;
    SetNextIPaddress(&record, PF_INET, "172.72.1.2");
    UpdateRecord(&record);
    PackRecordV3(&record, nffile);

    record.exElementList[i++] = EXbgpNextHopV4ID;
    record.size += EXbgpNextHopV4Size;  // 7
    record.numElements = i;
    record.tcp_flags++;
    SetBGPNextIPaddress(&record, PF_INET, "172.73.2.3");
    UpdateRecord(&record);
    PackRecordV3(&record, nffile);

    record.exElementList[i++] = EXipReceivedV4ID;
    record.size += EXipReceivedV4Size;  // 9
    record.numElements = i;
    record.tcp_flags++;
    SetRouterIPaddress(&record, PF_INET, "127.0.0.1");
    UpdateRecord(&record);
    PackRecordV3(&record, nffile);

    record.exElementList[i++] = EXmplsLabelID;
    record.size += EXmplsLabelSize;
    record.numElements = i;
    record.tcp_flags++;
    record.mpls_label[0] = 1010 << 4;
    record.mpls_label[1] = 2020 << 4;
    record.mpls_label[2] = 3030 << 4;
    record.mpls_label[3] = 4040 << 4;
    record.mpls_label[4] = 5050 << 4;
    record.mpls_label[5] = 6060 << 4;
    record.mpls_label[6] = 7070 << 4;
    record.mpls_label[7] = 8080 << 4;
    record.mpls_label[8] = 9090 << 4;
    record.mpls_label[9] = (100100 << 4) + 1;
    UpdateRecord(&record);
    PackRecordV3(&record, nffile);

    record.exElementList[i++] = EXmacAddrID;
    record.size += EXmacAddrSize;
    record.numElements = i;
    record.tcp_flags++;
    record.in_src_mac = 0x1234567890aaLL;
    record.out_dst_mac = 0x2feeddccbbabLL;
    record.in_dst_mac = 0x3aeeddccbbfcLL;
    record.out_src_mac = 0x4a345678900dLL;
    UpdateRecord(&record);
    PackRecordV3(&record, nffile);

    record.exElementList[i++] = EXasAdjacentID;
    record.size += EXasAdjacentSize;
    record.numElements = i;
    record.tcp_flags++;
    record.bgpNextAdjacentAS = 7751;
    record.bgpPrevAdjacentAS = 33032;
    UpdateRecord(&record);
    PackRecordV3(&record, nffile);

    record.exElementList[i++] = EXlatencyID;
    record.size += EXlatencySize;
    record.numElements = i;
    record.tcp_flags++;
    record.client_nw_delay_usec = 2;
    record.server_nw_delay_usec = 22;
    record.appl_latency_usec = 222;
    UpdateRecord(&record);
    PackRecordV3(&record, nffile);

    /*
            record.exElementList[i] = 0;
            record.numElements = i;

            record.map_ref = 0;
            record.type	= CommonRecordType;

            record.flags   		= 0;
            record.exporter_sysid = 1;

            UpdateRecord(&record);
            PackRecordV3(&record, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.2.66", "192.168.170.101");
            UpdateRecord(&record);
            PackRecordV3(&record, nffile);

            record.inPackets 	 	= 101;
            record.inByytes 	 	= 102;
            UpdateRecord(&record);
            PackRecordV3(&record, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.3.66", "192.168.170.102");
            UpdateRecord(&record);
            PackRecordV3(&record, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.4.66", "192.168.170.103");
            record.srcPort 	 = 2024;
            record.proto 	 = IPPROTO_UDP;
            record.tcp_flags = 1;
            record.tos 		 = 1;
            record.inPackets 	 = 1001;
            record.inByytes 	 = 1002;
            UpdateRecord(&record);
            PackRecordV3(&record, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.5.66", "192.168.170.104");
            record.srcPort 	 	= 3024;
            record.proto 	 	= 51;
            record.tcp_flags 	= 2;
            record.tos 		 	= 2;
            record.inPackets 	 	= 10001;
            record.inByytes 	 	= 10002;
            UpdateRecord(&record);
            PackRecordV3(&record, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.6.66", "192.168.170.105");
            record.srcPort 	 	= 4024;
            record.proto 	 	= IPPROTO_TCP;
            record.tcp_flags 	= 4;
            record.tos 		 	= 3;
            record.inPackets 	 	= 100001;
            record.inByytes 	 	= 100002;
            UpdateRecord(&record);
            PackRecordV3(&record, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.7.66", "192.168.170.106");
            record.srcPort 	 	= 5024;
            record.tcp_flags 	= 8;
            record.tos 		 	= 4;
            record.inPackets 	 	= 1000001;
            record.inByytes 	 	= 1000002;
            UpdateRecord(&record);
            PackRecordV3(&record, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.8.66", "192.168.170.107");
            record.tcp_flags 	= 1;
            record.tos 		 	= 4;
            record.inPackets 	 	= 10000001;
            record.inByytes 	 	= 1001;
            UpdateRecord(&record);
            PackRecordV3(&record, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.9.66", "192.168.170.108");
            record.srcPort 	 	= 6024;
            record.tcp_flags 	= 16;
            record.tos 		 	= 5;
            record.inPackets 	 	= 500;
            record.inByytes 	 	= 10000001;
            UpdateRecord(&record);
            PackRecordV3(&record, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.10.66", "192.168.170.109");
            UpdateRecord(&record);
            PackRecordV3(&record, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.11.66", "192.168.170.110");
            record.srcPort 		= 7024;
            record.tcp_flags 	= 32;
            record.tos 		 	= 255;
            record.inPackets 	 	= 5000;
            record.inByytes 	 	= 100000001;
            UpdateRecord(&record);
            PackRecordV3(&record, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.12.66", "192.168.170.111");
            record.srcPort 	 	= 8024;
            record.tcp_flags 	= 63;
            record.tos 		 	= 0;
            record.inByytes 	 	= 1000000001;
            UpdateRecord(&record);
            PackRecordV3(&record, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.13.66", "192.168.170.112");
            record.srcPort 	 	= 0;
            record.dstPort 	 	= 8;
            record.proto 	 	= 1;
            record.tcp_flags 	= 0;
            record.tos 		 	= 0;
            record.inPackets 	 	= 50002;
            record.inByytes 	 	= 50000;
            UpdateRecord(&record);
            PackRecordV3(&record, nffile);

            SetIPaddress(&record,  PF_INET, "172.160.160.166", "172.160.160.180");
            record.srcPort 	 = 10024;
            record.dstPort 	 = 25000;
            record.proto 	 = IPPROTO_TCP;
            record.inPackets 	 = 500001;
            record.inByytes 	 = 500000;
            UpdateRecord(&record);
            PackRecordV3(&record, nffile);

            SetIPaddress(&record,  PF_INET6, "fe80::2110:abcd:1234:0", "fe80::2110:abcd:1235:4321");
            SetNextIPaddress(&record,  PF_INET6, "2003:234:aabb::211:24ff:fe80:d01e");
            SetBGPNextIPaddress(&record,  PF_INET6, "2004:234:aabb::211:24ff:fe80:d01e");
            record.srcPort 	 = 1024;
            record.dstPort 	 = 25;
            record.tcp_flags = 27;
            record.inPackets 	 = 10;
            record.inByytes 	 = 15100;
            UpdateRecord(&record);
            PackRecordV3(&record, nffile);

            SetIPaddress(&record,  PF_INET6, "2001:234:aabb::211:24ff:fe80:d01e", "2001:620::8:203:baff:fe52:38e5");
            record.srcPort 	 = 10240;
            record.dstPort 	 = 52345;
            record.inPackets 	 = 10100;
            record.inByytes 	 = 15000000;
            UpdateRecord(&record);
            PackRecordV3(&record, nffile);

            record.inPackets 	 = 10100000;
            record.inByytes 	 = 0x100000000LL;
            UpdateRecord(&record);
            PackRecordV3(&record, nffile);

            record.inPackets 	 = 0x100000000LL;
            record.inByytes 	 = 15000000;
            UpdateRecord(&record);
            PackRecordV3(&record, nffile);

            record.inByytes 	 = 0x200000000LL;
            UpdateRecord(&record);
            PackRecordV3(&record, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.14.18", "192.168.170.113");
            SetNextIPaddress(&record,  PF_INET, "172.72.1.2");
            SetBGPNextIPaddress(&record,  PF_INET, "172.73.2.3");
            record.srcPort 	 = 10240;
            record.dstPort 	 = 52345;
            record.inPackets 	 = 10100000;
            record.inByytes 	 = 0x100000000LL;
            UpdateRecord(&record);
            PackRecordV3(&record, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.15.18", "192.168.170.114");
            record.inPackets 	 = 0x100000000LL;
            record.inByytes 	 = 15000000;
            UpdateRecord(&record);
            PackRecordV3(&record, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.16.18", "192.168.170.115");
            record.inByytes 	 = 0x200000000LL;
            UpdateRecord(&record);
            PackRecordV3(&record, nffile);
    */
    if (nffile->block_header->NumRecords) {
        if (WriteBlock(nffile) <= 0) {
            fprintf(stderr, "Failed to write output buffer to disk: '%s'", strerror(errno));
        }
    }
    CloseUpdateFile(nffile);
    return 0;
}
