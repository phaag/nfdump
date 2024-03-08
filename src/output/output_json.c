/*
 *  Copyright (c) 2019-2024, Peter Haag
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

#include "config.h"

// for asprintf prototype
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include "ja3/ja3.h"
#include "maxmind.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfxV3.h"
#include "output_json.h"
#include "output_util.h"
#include "userio.h"
#include "util.h"

#define IP_STRING_LEN (INET6_ADDRSTRLEN)

// record counter
static uint32_t recordCount;

static void stringEXgenericFlow(FILE *stream, void *extensionRecord) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)extensionRecord;

    char datebuff1[64], datebuff2[64], dateBuff3[64];

    time_t when = genericFlow->msecFirst / 1000LL;
    struct tm *ts = localtime(&when);
    strftime(datebuff1, 63, "%Y-%m-%dT%H:%M:%S", ts);

    when = genericFlow->msecLast / 1000LL;
    ts = localtime(&when);
    strftime(datebuff2, 63, "%Y-%m-%dT%H:%M:%S", ts);

    when = genericFlow->msecReceived / 1000LL;
    ts = localtime(&when);
    strftime(dateBuff3, 63, "%Y-%m-%dT%H:%M:%S", ts);

    fprintf(stream,
            "	\"first\" : \"%s.%03u\",\n"
            "	\"last\" : \"%s.%03u\",\n"
            "	\"received\" : \"%s.%03u\",\n"
            "	\"in_packets\" : %llu,\n"
            "	\"in_bytes\" : %llu,\n",
            datebuff1, (unsigned)(genericFlow->msecFirst % 1000LL), datebuff2, (unsigned)(genericFlow->msecLast % 1000LL), dateBuff3,
            (unsigned)(genericFlow->msecReceived % 1000LL), (unsigned long long)genericFlow->inPackets, (unsigned long long)genericFlow->inBytes);

    if (genericFlow->proto == IPPROTO_ICMP || genericFlow->proto == IPPROTO_ICMPV6) {  // ICMP
        fprintf(stream,
                "	\"proto\" : %u,\n"
                "	\"icmp_type\" : %u,\n"
                "	\"icmp_code\" : %u,\n"
                "	\"src_tos\" : %u,\n",
                genericFlow->proto, genericFlow->icmpType, genericFlow->icmpCode, genericFlow->srcTos);
    } else {
        fprintf(stream,
                "	\"proto\" : %u,\n"
                "	\"tcp_flags\" : \"%s\",\n"
                "	\"src_port\" : %u,\n"
                "	\"dst_port\" : %u,\n"
                "	\"fwd_status\" : %u,\n"
                "	\"src_tos\" : %u,\n",
                genericFlow->proto, FlagsString(genericFlow->tcpFlags), genericFlow->srcPort, genericFlow->dstPort, genericFlow->fwdStatus,
                genericFlow->srcTos);
    }

}  // End of stringEXgenericFlow

static void stringEXipv4Flow(FILE *stream, void *extensionRecord) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)extensionRecord;

    uint32_t src = htonl(ipv4Flow->srcAddr);
    uint32_t dst = htonl(ipv4Flow->dstAddr);
    char as[IP_STRING_LEN], ds[IP_STRING_LEN];
    inet_ntop(AF_INET, &src, as, sizeof(as));
    inet_ntop(AF_INET, &dst, ds, sizeof(ds));

    char sloc[128], dloc[128];
    LookupV4Location(ipv4Flow->srcAddr, sloc, 128);
    LookupV4Location(ipv4Flow->dstAddr, dloc, 128);

    fprintf(stream,
            "	\"src4_addr\" : \"%s\",\n"
            "	\"dst4_addr\" : \"%s\",\n"
            "	\"src_geo\" : \"%s\",\n"
            "	\"dst_geo\" : \"%s\",\n",
            as, ds, sloc, dloc);

}  // End of stringEXipv4Flow

static void stringEXipv6Flow(FILE *stream, void *extensionRecord) {
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)extensionRecord;

    uint64_t src[2], dst[2];
    src[0] = htonll(ipv6Flow->srcAddr[0]);
    src[1] = htonll(ipv6Flow->srcAddr[1]);
    dst[0] = htonll(ipv6Flow->dstAddr[0]);
    dst[1] = htonll(ipv6Flow->dstAddr[1]);
    char as[IP_STRING_LEN], ds[IP_STRING_LEN];
    inet_ntop(AF_INET6, &src, as, sizeof(as));
    inet_ntop(AF_INET6, &dst, ds, sizeof(ds));

    char sloc[128], dloc[128];
    LookupV6Location(ipv6Flow->srcAddr, sloc, 128);
    LookupV6Location(ipv6Flow->dstAddr, dloc, 128);

    fprintf(stream,
            "	\"src6_addr\" : \"%s\",\n"
            "	\"dst6_addr\" : \"%s\",\n"
            "	\"src_geo\" : \"%s\",\n"
            "	\"dst_geo\" : \"%s\",\n",
            as, ds, sloc, dloc);

}  // End of stringEXipv6Flow

static void stringEXflowMisc(FILE *stream, recordHandle_t *recordHandle, void *extensionRecord) {
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)extensionRecord;
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    char snet[IP_STRING_LEN], dnet[IP_STRING_LEN];

    if (ipv6Flow) {
        // IPv6
        if (flowMisc->srcMask || flowMisc->dstMask) {
            uint64_t src[2];
            uint64_t dst[2];
            if (flowMisc->srcMask >= 64) {
                src[0] = ipv6Flow->srcAddr[0] & (0xffffffffffffffffLL << (flowMisc->srcMask - 64));
                src[1] = 0;
            } else {
                src[0] = ipv6Flow->srcAddr[0];
                src[1] = ipv6Flow->srcAddr[1] & (0xffffffffffffffffLL << flowMisc->srcMask);
            }
            src[0] = htonll(src[0]);
            src[1] = htonll(src[1]);
            inet_ntop(AF_INET6, &src, snet, sizeof(snet));

            if (flowMisc->dstMask >= 64) {
                dst[0] = ipv6Flow->dstAddr[0] & (0xffffffffffffffffLL << (flowMisc->dstMask - 64));
                dst[1] = 0;
            } else {
                dst[0] = ipv6Flow->dstAddr[0];
                dst[1] = ipv6Flow->dstAddr[1] & (0xffffffffffffffffLL << flowMisc->dstMask);
            }
            dst[0] = htonll(dst[0]);
            dst[1] = htonll(dst[1]);
            inet_ntop(AF_INET6, &dst, dnet, sizeof(dnet));

        } else {
            snet[0] = '\0';
            dnet[0] = '\0';
        }

    } else {
        // IPv4
        if (flowMisc->srcMask || flowMisc->dstMask) {
            uint32_t src = ipv4Flow->srcAddr & (0xffffffffL << (32 - flowMisc->srcMask));
            src = htonl(src);
            inet_ntop(AF_INET, &src, snet, sizeof(snet));

            uint32_t dst = ipv4Flow->dstAddr & (0xffffffffL << (32 - flowMisc->dstMask));
            dst = htonl(dst);
            inet_ntop(AF_INET, &dst, dnet, sizeof(dnet));
        } else {
            snet[0] = '\0';
            dnet[0] = '\0';
        }
    }

    fprintf(stream,
            "	\"input_snmp\" : %u,\n"
            "	\"output_snmp\" : %u,\n"
            "	\"src_mask\" : %u,\n"
            "	\"dst_mask\" : %u,\n"
            "	\"src_net\" : \"%s\",\n"
            "	\"dst_net\" : \"%s\",\n"
            "	\"direction\" : %u,\n"
            "	\"dst_tos\" : %u,\n",
            flowMisc->input, flowMisc->output, flowMisc->srcMask, flowMisc->dstMask, snet, dnet, flowMisc->dir, flowMisc->dstTos);

}  // End of stringEXflowMisc

static void stringEXcntFlow(FILE *stream, void *extensionRecord) {
    EXcntFlow_t *cntFlow = (EXcntFlow_t *)extensionRecord;
    fprintf(stream,
            "	\"out_packets\" : %llu,\n"
            "	\"out_bytes\" : %llu,\n"
            "	\"aggr_flows\" : %llu,\n",
            (long long unsigned)cntFlow->outPackets, (long long unsigned)cntFlow->outBytes, (long long unsigned)cntFlow->flows);

}  // End of stringEXcntFlow

static void stringEXvLan(FILE *stream, void *extensionRecord) {
    EXvLan_t *vLan = (EXvLan_t *)extensionRecord;
    fprintf(stream,
            "	\"src_vlan\" : %u,\n"
            "	\"dst_vlan\" : %u,\n",
            vLan->srcVlan, vLan->dstVlan);

}  // End of stringEXvLan

static void stringEXasRouting(FILE *stream, recordHandle_t *recordHandle, void *extensionRecord) {
    EXasRouting_t *asRouting = (EXasRouting_t *)extensionRecord;
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    if (asRouting->srcAS == 0) asRouting->srcAS = ipv4Flow ? LookupV4AS(ipv4Flow->srcAddr) : LookupV6AS(ipv6Flow->srcAddr);
    if (asRouting->dstAS == 0) asRouting->dstAS = ipv4Flow ? LookupV4AS(ipv4Flow->dstAddr) : LookupV6AS(ipv6Flow->dstAddr);

    fprintf(stream,
            "	\"src_as\" : %u,\n"
            "	\"dst_as\" : %u,\n",
            asRouting->srcAS, asRouting->dstAS);

}  // End of stringEXasRouting

static void stringEXbgpNextHopV4(FILE *stream, void *extensionRecord) {
    EXbgpNextHopV4_t *bgpNextHopV4 = (EXbgpNextHopV4_t *)extensionRecord;

    uint32_t i = htonl(bgpNextHopV4->ip);
    char ip[IP_STRING_LEN];
    ip[0] = 0;
    inet_ntop(AF_INET, &i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    fprintf(stream, "	\"bgp4_next_hop\" : \"%s\",\n", ip);

}  // End of stringEXbgpNextHopV4

static void stringEXbgpNextHopV6(FILE *stream, void *extensionRecord) {
    EXbgpNextHopV6_t *bgpNextHopV6 = (EXbgpNextHopV6_t *)extensionRecord;

    uint64_t i[2];
    i[0] = htonll(bgpNextHopV6->ip[0]);
    i[1] = htonll(bgpNextHopV6->ip[1]);

    char ip[IP_STRING_LEN];
    ip[0] = 0;
    inet_ntop(AF_INET6, i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    fprintf(stream, "	\"bgp6_next_hop\" : \"%s\",\n", ip);

}  // End of stringEXbgpNextHopV6

static void stringEXipNextHopV4(FILE *stream, void *extensionRecord) {
    EXipNextHopV4_t *ipNextHopV4 = (EXipNextHopV4_t *)extensionRecord;

    uint32_t i = htonl(ipNextHopV4->ip);
    char ip[IP_STRING_LEN];
    ip[0] = 0;
    inet_ntop(AF_INET, &i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    fprintf(stream, "	\"ip4_next_hop\" : \"%s\",\n", ip);

}  // End of stringEXipNextHopV4

static void stringEXipNextHopV6(FILE *stream, void *extensionRecord) {
    EXipNextHopV6_t *ipNextHopV6 = (EXipNextHopV6_t *)extensionRecord;

    uint64_t i[2];
    i[0] = htonll(ipNextHopV6->ip[0]);
    i[1] = htonll(ipNextHopV6->ip[1]);

    char ip[IP_STRING_LEN];
    ip[0] = 0;
    inet_ntop(AF_INET6, i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    fprintf(stream, "	\"ip6_next_hop\" : \"%s\",\n", ip);

}  // End of stringEXipNextHopV6

static void stringEXipReceivedV4(FILE *stream, void *extensionRecord) {
    EXipReceivedV4_t *ipReceivedV4 = (EXipReceivedV4_t *)extensionRecord;

    uint32_t i = htonl(ipReceivedV4->ip);
    char ip[IP_STRING_LEN];
    ip[0] = 0;
    inet_ntop(AF_INET, &i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    fprintf(stream, "	\"ip4_router\" : \"%s\",\n", ip);

}  // End of stringEXipReceivedV4

static void stringEXipReceivedV6(FILE *stream, void *extensionRecord) {
    EXipReceivedV6_t *ipReceivedV6 = (EXipReceivedV6_t *)extensionRecord;

    uint64_t i[2];
    i[0] = htonll(ipReceivedV6->ip[0]);
    i[1] = htonll(ipReceivedV6->ip[1]);
    char ip[IP_STRING_LEN];
    ip[0] = 0;
    inet_ntop(AF_INET6, i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    fprintf(stream, "	\"ip6_router\" : \"%s\",\n", ip);

}  // End of stringEXipReceivedV6

static void stringEXmplsLabel(FILE *stream, void *extensionRecord) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)extensionRecord;
    for (int i = 0; i < 10; i++) {
        fprintf(stream, "	\"mpls_%u\" : \"%u-%u-%u\",\n", i + 1, mplsLabel->mplsLabel[i] >> 4, (mplsLabel->mplsLabel[i] & 0xF) >> 1,
                mplsLabel->mplsLabel[i] & 1);
    }

}  // End of stringEXmplsLabel

static void stringEXmacAddr(FILE *stream, void *extensionRecord) {
    EXmacAddr_t *macAddr = (EXmacAddr_t *)extensionRecord;

    uint8_t mac1[6], mac2[6], mac3[6], mac4[6];
    for (int i = 0; i < 6; i++) {
        mac1[i] = (macAddr->inSrcMac >> (i * 8)) & 0xFF;
        mac2[i] = (macAddr->outDstMac >> (i * 8)) & 0xFF;
        mac3[i] = (macAddr->inDstMac >> (i * 8)) & 0xFF;
        mac4[i] = (macAddr->outSrcMac >> (i * 8)) & 0xFF;
    }

    fprintf(stream,
            "	\"in_src_mac\" : \"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\",\n"
            "	\"out_dst_mac\" : \"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\",\n"
            "	\"in_dst_mac\" : \"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\",\n"
            "	\"out_src_mac\" : \"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\",\n",
            mac1[5], mac1[4], mac1[3], mac1[2], mac1[1], mac1[0], mac2[5], mac2[4], mac2[3], mac2[2], mac2[1], mac2[0], mac3[5], mac3[4], mac3[3],
            mac3[2], mac3[1], mac3[0], mac4[5], mac4[4], mac4[3], mac4[2], mac4[1], mac4[0]);

}  // End of stringEXmacAddr

static void stringEXasAdjacent(FILE *stream, void *extensionRecord) {
    EXasAdjacent_t *asAdjacent = (EXasAdjacent_t *)extensionRecord;
    fprintf(stream,
            "	\"next_as\" : %u,\n"
            "	\"prev_as\" : %u,\n",
            asAdjacent->nextAdjacentAS, asAdjacent->prevAdjacentAS);

}  // End of stringEXasAdjacent

static void stringEXlatency(FILE *stream, void *extensionRecord) {
    EXlatency_t *latency = (EXlatency_t *)extensionRecord;

    double f1, f2, f3;
    f1 = (double)latency->usecClientNwDelay / 1000.0;
    f2 = (double)latency->usecServerNwDelay / 1000.0;
    f3 = (double)latency->usecApplLatency / 1000.0;

    fprintf(stream,
            "	\"cli_latency\" : %f,\n"
            "	\"srv_latency\" : %f,\n"
            "	\"app_latency\" : %f,\n",
            f1, f2, f3);

}  // End of stringEXlatency

static void String_ja3(FILE *stream, recordHandle_t *recordHandle, void *extensionRecord) {
    EXinPayload_t *payload = (EXinPayload_t *)extensionRecord;
    uint32_t payloadLength = ExtensionLength(payload);

    if (payloadLength == 0) {
        return;
    }

    ssl_t *ssl = (ssl_t *)recordHandle->sslInfo;
    if (*((uint64_t *)(recordHandle->ja3)) == 0) {
        if (ssl == NULL) {
            ssl = sslProcess((const uint8_t *)payload, payloadLength);
            recordHandle->sslInfo = (void *)ssl;
        }
        ja3Process(ssl, recordHandle->ja3);
    }

    if (ssl && ssl->sniName[0]) {
        fprintf(stream, "	\"sni\" : %s,\n", ssl->sniName);
    }
    if (*((uint64_t *)(recordHandle->ja3)) == 0) {
        fprintf(stream, "	\"ja3 hash\" : %s,\n", ja3String(recordHandle->ja3));
    }

}  // End of String_ja3

static void stringEXtunIPv4(FILE *stream, void *extensionRecord) {
    EXtunIPv4_t *tunIPv4 = (EXtunIPv4_t *)extensionRecord;

    uint32_t src = htonl(tunIPv4->tunSrcAddr);
    uint32_t dst = htonl(tunIPv4->tunDstAddr);
    char as[IP_STRING_LEN], ds[IP_STRING_LEN];
    inet_ntop(AF_INET, &src, as, sizeof(as));
    inet_ntop(AF_INET, &dst, ds, sizeof(ds));

    fprintf(stream,
            "	\"tun proto\" : %u,\n"
            "	\"src4_tun_ip\" : \"%s\",\n"
            "	\"dst4_tun_ip\" : \"%s\",\n",
            tunIPv4->tunProto, as, ds);

}  // End of stringEXtunIPv4

static void stringEXtunIPv6(FILE *stream, void *extensionRecord) {
    EXtunIPv6_t *tunIPv6 = (EXtunIPv6_t *)extensionRecord;

    uint64_t src[2];
    uint64_t dst[2];
    src[0] = htonll(tunIPv6->tunSrcAddr[0]);
    src[1] = htonll(tunIPv6->tunSrcAddr[1]);
    dst[0] = htonll(tunIPv6->tunDstAddr[0]);
    dst[1] = htonll(tunIPv6->tunDstAddr[1]);
    char as[IP_STRING_LEN], ds[IP_STRING_LEN];
    inet_ntop(AF_INET6, &src, as, sizeof(as));
    inet_ntop(AF_INET6, &dst, ds, sizeof(ds));

    fprintf(stream,
            "	\"tun proto\" : %u,\n"
            "	\"src6_tun_ip\" : \"%s\",\n"
            "	\"dst6_tun_ip\" : \"%s\",\n",
            tunIPv6->tunProto, as, ds);

}  // End of stringEXtunIPv6

static void stringEXobservation(FILE *stream, void *extensionRecord) {
    EXobservation_t *observation = (EXobservation_t *)extensionRecord;
    fprintf(stream,
            "	\"observationDoaminID\" : %u,\n"
            "	\"observationPointID\" : %llu,\n",
            observation->domainID, (long long unsigned)observation->pointID);

}  // End of stringEXobservation

static void stringEXvrf(FILE *stream, void *extensionRecord) {
    EXvrf_t *vrf = (EXvrf_t *)extensionRecord;
    fprintf(stream,
            "	\"ingress_vrf\" : \"%u\",\n"
            "	\"egress_vrf\" : \"%u\",\n",
            vrf->ingressVrf, vrf->egressVrf);

}  // End of stringEXvrf

static void stringEXnselCommon(FILE *stream, void *extensionRecord) {
    EXnselCommon_t *nselCommon = (EXnselCommon_t *)extensionRecord;

    char datestr[64];
    time_t when = nselCommon->msecEvent / 1000LL;
    if (when == 0) {
        strncpy(datestr, "<unknown>", 63);
    } else {
        struct tm *ts = localtime(&when);
        strftime(datestr, 63, "%Y-%m-%dT%H:%M:%S", ts);
    }
    fprintf(stream,
            "	\"connect_id\" : \"%u\",\n"
            "	\"event_id\" : \"%u\",\n"
            "	\"event\" : \"%s\",\n"
            "	\"xevent_id\" : \"%u\",\n"
            "	\"t_event\" : \"%s.%llu\",\n",
            nselCommon->connID, nselCommon->fwEvent, fwEventString(nselCommon->fwEvent), nselCommon->fwXevent, datestr,
            nselCommon->msecEvent % 1000LL);

}  // End of stringEXnselCommon

static void stringEXnselXlateIPv4(FILE *stream, void *extensionRecord) {
    EXnselXlateIPv4_t *nselXlateIPv4 = (EXnselXlateIPv4_t *)extensionRecord;

    uint32_t src = htonl(nselXlateIPv4->xlateSrcAddr);
    uint32_t dst = htonl(nselXlateIPv4->xlateDstAddr);
    char as[IP_STRING_LEN], ds[IP_STRING_LEN];
    inet_ntop(AF_INET, &src, as, sizeof(as));
    inet_ntop(AF_INET, &dst, ds, sizeof(ds));

    fprintf(stream,
            "	\"src4_xlt_ip\" : \"%s\",\n"
            "	\"dst4_xlt_ip\" : \"%s\",\n",
            as, ds);

}  // End of stringEXnselXlateIPv4

static void stringEXnselXlateIPv6(FILE *stream, void *extensionRecord) {
    EXnselXlateIPv6_t *nselXlateIPv6 = (EXnselXlateIPv6_t *)extensionRecord;

    uint64_t src[2];
    uint64_t dst[2];
    src[0] = htonll(nselXlateIPv6->xlateSrcAddr[0]);
    src[1] = htonll(nselXlateIPv6->xlateSrcAddr[1]);
    dst[0] = htonll(nselXlateIPv6->xlateDstAddr[0]);
    dst[1] = htonll(nselXlateIPv6->xlateDstAddr[1]);
    char as[IP_STRING_LEN], ds[IP_STRING_LEN];
    inet_ntop(AF_INET6, &src, as, sizeof(as));
    inet_ntop(AF_INET6, &dst, ds, sizeof(ds));

    fprintf(stream,
            "	\"src6_xlt_ip\" : \"%s\",\n"
            "	\"dst6_xlt_ip\" : \"%s\",\n",
            as, ds);

}  // End of stringEXnselXlateIPv4

static void stringEXnselXlatePort(FILE *stream, void *extensionRecord) {
    EXnselXlatePort_t *nselXlatePort = (EXnselXlatePort_t *)extensionRecord;
    fprintf(stream,
            "	\"src_xlt_port\" : \"%u\",\n"
            "	\"dst_xlt_port\" : \"%u\",\n",
            nselXlatePort->xlateSrcPort, nselXlatePort->xlateDstPort);

}  // End of stringEXnselXlatePort

static void stringEXnselAcl(FILE *stream, void *extensionRecord) {
    EXnselAcl_t *nselAcl = (EXnselAcl_t *)extensionRecord;
    fprintf(stream,
            "	\"ingress_acl\" : \"0x%x/0x%x/0x%x\",\n"
            "	\"egress_acl\" : \"0x%x/0x%x/0x%x\",\n",
            nselAcl->ingressAcl[0], nselAcl->ingressAcl[1], nselAcl->ingressAcl[2], nselAcl->egressAcl[0], nselAcl->egressAcl[1],
            nselAcl->egressAcl[2]);

}  // End of stringEXnselAcl

static void stringEXnselUserID(FILE *stream, void *extensionRecord) {
    EXnselUser_t *nselUser = (EXnselUser_t *)extensionRecord;
    fprintf(stream, "	\"user_name\" : \"%s\",\n", nselUser->username[0] ? nselUser->username : "<empty>");

}  // End of stringEXnselUserID

static void stringEXnelCommon(FILE *stream, void *extensionRecord) {
    EXnelCommon_t *nelCommon = (EXnelCommon_t *)extensionRecord;

    time_t when = nelCommon->msecEvent / 1000LL;
    char datestr[64];
    if (when == 0) {
        strncpy(datestr, "<unknown>", 63);
    } else {
        struct tm *ts = localtime(&when);
        strftime(datestr, 63, "%Y-%m-%dT%H:%M:%S", ts);
    }

    fprintf(stream,
            "	\"nat_event_id\" : \"%u\",\n"
            "	\"nat_event\" : \"%s\",\n"
            "	\"nat_pool_id\" : \"%u\",\n"
            "	\"t_event\" : \"%s.%llu\",\n",
            nelCommon->natEvent, natEventString(nelCommon->natEvent, LONGNAME), nelCommon->natPoolID, datestr, nelCommon->msecEvent % 1000LL);

}  // End of stringEXnelCommon

static void stringEXnelXlatePort(FILE *stream, void *extensionRecord) {
    EXnelXlatePort_t *nelXlatePort = (EXnelXlatePort_t *)extensionRecord;
    fprintf(stream,
            "	\"pblock_start\" : \"%u\",\n"
            "	\"pblock_end\" : \"%u\",\n"
            "	\"pblock_step\" : \"%u\",\n"
            "	\"pblock_size\" : \"%u\",\n",
            nelXlatePort->blockStart, nelXlatePort->blockEnd, nelXlatePort->blockStep, nelXlatePort->blockSize);

}  // End of stringEXnelXlatePort

void json_prolog(void) {
    recordCount = 0;
    // open json
    printf("[\n");
}  // End of json_prolog

void json_epilog(void) {
    // close json
    printf("]\n");
}  // End of json_epilog

void flow_record_to_json(FILE *stream, recordHandle_t *recordHandle, int tag) {
    recordHeaderV3_t *recordHeaderV3 = recordHandle->recordHeaderV3;

    if (recordCount) {
        fprintf(stream, ",\n");
    }
    recordCount++;

    fprintf(stream,
            "{\n"
            "	\"type\" : \"%s\",\n"
            "	\"sampled\" : %u,\n"
            "	\"export_sysid\" : %u,\n",
            TestFlag(recordHeaderV3->flags, V3_FLAG_EVENT) ? "EVENT" : "FLOW", TestFlag(recordHeaderV3->flags, V3_FLAG_SAMPLED) ? 1 : 0,
            recordHeaderV3->exporterID);

    int processed = 0;
    for (int i = 0; i < MAXEXTENSIONS; i++) {
        if (processed == recordHeaderV3->numElements) break;
        if (recordHandle->extensionList[i] == NULL) continue;
        void *ptr = recordHandle->extensionList[i];

        switch (i) {
            case EXnull:
                if (ptr != recordHeaderV3) fprintf(stderr, "Found unexpected NULL extension \n");
                break;
            case EXgenericFlowID:
                stringEXgenericFlow(stream, ptr);
                break;
            case EXipv4FlowID:
                stringEXipv4Flow(stream, ptr);
                break;
            case EXipv6FlowID:
                stringEXipv6Flow(stream, ptr);
                break;
            case EXflowMiscID:
                stringEXflowMisc(stream, recordHandle, ptr);
                break;
            case EXcntFlowID:
                stringEXcntFlow(stream, ptr);
                break;
            case EXvLanID:
                stringEXvLan(stream, ptr);
                break;
            case EXasRoutingID:
                stringEXasRouting(stream, recordHandle, ptr);
                break;
            case EXbgpNextHopV4ID:
                stringEXbgpNextHopV4(stream, ptr);
                break;
            case EXbgpNextHopV6ID:
                stringEXbgpNextHopV6(stream, ptr);
                break;
            case EXipNextHopV4ID:
                stringEXipNextHopV4(stream, ptr);
                break;
            case EXipNextHopV6ID:
                stringEXipNextHopV6(stream, ptr);
                break;
            case EXipReceivedV4ID:
                stringEXipReceivedV4(stream, ptr);
                break;
            case EXipReceivedV6ID:
                stringEXipReceivedV6(stream, ptr);
                break;
            case EXmplsLabelID:
                stringEXmplsLabel(stream, ptr);
                break;
            case EXmacAddrID:
                stringEXmacAddr(stream, ptr);
                break;
            case EXasAdjacentID:
                stringEXasAdjacent(stream, ptr);
                break;
            case EXlatencyID:
                stringEXlatency(stream, ptr);
                break;
            case EXinPayloadID:
                String_ja3(stream, recordHandle, ptr);
                break;
            case EXoutPayloadID:
                String_ja3(stream, recordHandle, ptr);
                break;
            case EXtunIPv4ID:
                stringEXtunIPv4(stream, ptr);
                break;
            case EXtunIPv6ID:
                stringEXtunIPv6(stream, ptr);
                break;
            case EXobservationID:
                stringEXobservation(stream, ptr);
                break;
            case EXvrfID:
                stringEXvrf(stream, ptr);
                break;
            case EXnselCommonID:
                stringEXnselCommon(stream, ptr);
                break;
            case EXnselXlateIPv4ID:
                stringEXnselXlateIPv4(stream, ptr);
                break;
            case EXnselXlateIPv6ID:
                stringEXnselXlateIPv6(stream, ptr);
                break;
            case EXnselXlatePortID:
                stringEXnselXlatePort(stream, ptr);
                break;
            case EXnselAclID:
                stringEXnselAcl(stream, ptr);
                break;
            case EXnselUserID:
                stringEXnselUserID(stream, ptr);
                break;
            case EXnelCommonID:
                stringEXnelCommon(stream, ptr);
                break;
            case EXnelXlatePortID:
                stringEXnelXlatePort(stream, ptr);
                break;
            default:
                dbg_printf("Extension %i not yet implemented\n", r->exElementList[i]);
        }
        i++;
    }

    // add label and close json object
    /* XXX
    fprintf(stream,
            "	\"label\" : \"%s\"\n"
            "}",
            r->label ? r->label : "<none>");
    */

}  // End of flow_record_to_json
