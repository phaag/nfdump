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
#include "ja4/ja4.h"
#include "maxmind/maxmind.h"
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

static void stringEXgenericFlow(FILE *stream, void *extensionRecord, const char *indent, const char *fs) {
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
            "%s\"first\" : \"%s.%03u\"%s"
            "%s\"last\" : \"%s.%03u\"%s"
            "%s\"received\" : \"%s.%03u\"%s"
            "%s\"in_packets\" : %llu%s"
            "%s\"in_bytes\" : %llu%s",
            indent, datebuff1, (unsigned)(genericFlow->msecFirst % 1000LL), fs, indent, datebuff2, (unsigned)(genericFlow->msecLast % 1000LL), fs,
            indent, dateBuff3, (unsigned)(genericFlow->msecReceived % 1000LL), fs, indent, (unsigned long long)genericFlow->inPackets, fs, indent,
            (unsigned long long)genericFlow->inBytes, fs);

    if (genericFlow->proto == IPPROTO_ICMP || genericFlow->proto == IPPROTO_ICMPV6) {  // ICMP
        fprintf(stream,
                "%s\"proto\" : %u%s"
                "%s\"icmp_type\" : %u%s"
                "%s\"icmp_code\" : %u%s"
                "%s\"src_tos\" : %u%s",
                indent, genericFlow->proto, fs, indent, genericFlow->icmpType, fs, indent, genericFlow->icmpCode, fs, indent, genericFlow->srcTos,
                fs);
    } else {
        fprintf(stream,
                "%s\"proto\" : %u%s"
                "%s\"tcp_flags\" : \"%s\"%s"
                "%s\"src_port\" : %u%s"
                "%s\"dst_port\" : %u%s"
                "%s\"fwd_status\" : %u%s"
                "%s\"src_tos\" : %u%s",
                indent, genericFlow->proto, fs, indent, FlagsString(genericFlow->tcpFlags), fs, indent, genericFlow->srcPort, fs, indent,
                genericFlow->dstPort, fs, indent, genericFlow->fwdStatus, fs, indent, genericFlow->srcTos, fs);
    }

}  // End of stringEXgenericFlow

static void stringEXipv4Flow(FILE *stream, void *extensionRecord, const char *indent, const char *fs) {
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
            "%s\"src4_addr\" : \"%s\"%s"
            "%s\"dst4_addr\" : \"%s\"%s"
            "%s\"src_geo\" : \"%s\"%s"
            "%s\"dst_geo\" : \"%s\"%s",
            indent, as, fs, indent, ds, fs, indent, sloc, fs, indent, dloc, fs);

}  // End of stringEXipv4Flow

static void stringEXipv6Flow(FILE *stream, void *extensionRecord, const char *indent, const char *fs) {
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
            "%s\"src6_addr\" : \"%s\"%s"
            "%s\"dst6_addr\" : \"%s\"%s"
            "%s\"src_geo\" : \"%s\"%s"
            "%s\"dst_geo\" : \"%s\"%s",
            indent, as, fs, indent, ds, fs, indent, sloc, fs, indent, dloc, fs);

}  // End of stringEXipv6Flow

static void stringEXflowMisc(FILE *stream, recordHandle_t *recordHandle, void *extensionRecord, const char *indent, const char *fs) {
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
            "%s\"input_snmp\" : %u%s"
            "%s\"output_snmp\" : %u%s"
            "%s\"src_mask\" : %u%s"
            "%s\"dst_mask\" : %u%s"
            "%s\"src_net\" : \"%s\"%s"
            "%s\"dst_net\" : \"%s\"%s"
            "%s\"direction\" : %u%s"
            "%s\"dst_tos\" : %u%s",
            indent, flowMisc->input, fs, indent, flowMisc->output, fs, indent, flowMisc->srcMask, fs, indent, flowMisc->dstMask, fs, indent, snet, fs,
            indent, dnet, fs, indent, flowMisc->dir, fs, indent, flowMisc->dstTos, fs);

}  // End of stringEXflowMisc

static void stringEXcntFlow(FILE *stream, void *extensionRecord, const char *indent, const char *fs) {
    EXcntFlow_t *cntFlow = (EXcntFlow_t *)extensionRecord;
    fprintf(stream,
            "%s\"out_packets\" : %llu%s"
            "%s\"out_bytes\" : %llu%s"
            "%s\"aggr_flows\" : %llu%s",
            indent, (long long unsigned)cntFlow->outPackets, fs, indent, (long long unsigned)cntFlow->outBytes, fs, indent,
            (long long unsigned)cntFlow->flows, fs);

}  // End of stringEXcntFlow

static void stringEXvLan(FILE *stream, void *extensionRecord, const char *indent, const char *fs) {
    EXvLan_t *vLan = (EXvLan_t *)extensionRecord;
    fprintf(stream,
            "%s\"src_vlan\" : %u%s"
            "%s\"dst_vlan\" : %u%s",
            indent, vLan->srcVlan, fs, indent, vLan->dstVlan, fs);

}  // End of stringEXvLan

static void stringEXasRouting(FILE *stream, recordHandle_t *recordHandle, void *extensionRecord, const char *indent, const char *fs) {
    EXasRouting_t *asRouting = (EXasRouting_t *)extensionRecord;
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    if (asRouting->srcAS == 0) asRouting->srcAS = ipv4Flow ? LookupV4AS(ipv4Flow->srcAddr) : LookupV6AS(ipv6Flow->srcAddr);
    if (asRouting->dstAS == 0) asRouting->dstAS = ipv4Flow ? LookupV4AS(ipv4Flow->dstAddr) : LookupV6AS(ipv6Flow->dstAddr);

    fprintf(stream,
            "%s\"src_as\" : %u%s"
            "%s\"dst_as\" : %u%s",
            indent, asRouting->srcAS, fs, indent, asRouting->dstAS, fs);

}  // End of stringEXasRouting

static void stringEXbgpNextHopV4(FILE *stream, void *extensionRecord, const char *indent, const char *fs) {
    EXbgpNextHopV4_t *bgpNextHopV4 = (EXbgpNextHopV4_t *)extensionRecord;

    uint32_t i = htonl(bgpNextHopV4->ip);
    char ip[IP_STRING_LEN];
    ip[0] = 0;
    inet_ntop(AF_INET, &i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    fprintf(stream, "%s\"bgp4_next_hop\" : \"%s\"%s", indent, ip, fs);

}  // End of stringEXbgpNextHopV4

static void stringEXbgpNextHopV6(FILE *stream, void *extensionRecord, const char *indent, const char *fs) {
    EXbgpNextHopV6_t *bgpNextHopV6 = (EXbgpNextHopV6_t *)extensionRecord;

    uint64_t i[2];
    i[0] = htonll(bgpNextHopV6->ip[0]);
    i[1] = htonll(bgpNextHopV6->ip[1]);

    char ip[IP_STRING_LEN];
    ip[0] = 0;
    inet_ntop(AF_INET6, i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    fprintf(stream, "%s\"bgp6_next_hop\" : \"%s\"%s", indent, ip, fs);

}  // End of stringEXbgpNextHopV6

static void stringEXipNextHopV4(FILE *stream, void *extensionRecord, const char *indent, const char *fs) {
    EXipNextHopV4_t *ipNextHopV4 = (EXipNextHopV4_t *)extensionRecord;

    uint32_t i = htonl(ipNextHopV4->ip);
    char ip[IP_STRING_LEN];
    ip[0] = 0;
    inet_ntop(AF_INET, &i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    fprintf(stream, "%s\"ip4_next_hop\" : \"%s\"%s", indent, ip, fs);

}  // End of stringEXipNextHopV4

static void stringEXipNextHopV6(FILE *stream, void *extensionRecord, const char *indent, const char *fs) {
    EXipNextHopV6_t *ipNextHopV6 = (EXipNextHopV6_t *)extensionRecord;

    uint64_t i[2];
    i[0] = htonll(ipNextHopV6->ip[0]);
    i[1] = htonll(ipNextHopV6->ip[1]);

    char ip[IP_STRING_LEN];
    ip[0] = 0;
    inet_ntop(AF_INET6, i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    fprintf(stream, "%s\"ip6_next_hop\" : \"%s\"%s", indent, ip, fs);

}  // End of stringEXipNextHopV6

static void stringEXipReceivedV4(FILE *stream, void *extensionRecord, const char *indent, const char *fs) {
    EXipReceivedV4_t *ipReceivedV4 = (EXipReceivedV4_t *)extensionRecord;

    uint32_t i = htonl(ipReceivedV4->ip);
    char ip[IP_STRING_LEN];
    ip[0] = 0;
    inet_ntop(AF_INET, &i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    fprintf(stream, "%s\"ip4_router\" : \"%s\"%s", indent, ip, fs);

}  // End of stringEXipReceivedV4

static void stringEXipReceivedV6(FILE *stream, void *extensionRecord, const char *indent, const char *fs) {
    EXipReceivedV6_t *ipReceivedV6 = (EXipReceivedV6_t *)extensionRecord;

    uint64_t i[2];
    i[0] = htonll(ipReceivedV6->ip[0]);
    i[1] = htonll(ipReceivedV6->ip[1]);
    char ip[IP_STRING_LEN];
    ip[0] = 0;
    inet_ntop(AF_INET6, i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    fprintf(stream, "%s\"ip6_router\" : \"%s\"%s", indent, ip, fs);

}  // End of stringEXipReceivedV6

static void stringEXmplsLabel(FILE *stream, void *extensionRecord, const char *indent, const char *fs) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)extensionRecord;
    for (int i = 0; i < 10; i++) {
        fprintf(stream, "%s\"mpls_%u\" : \"%u-%u-%u\"%s", indent, i + 1, mplsLabel->mplsLabel[i] >> 4, (mplsLabel->mplsLabel[i] & 0xF) >> 1,
                mplsLabel->mplsLabel[i] & 1, fs);
    }

}  // End of stringEXmplsLabel

static void stringEXmacAddr(FILE *stream, void *extensionRecord, const char *indent, const char *fs) {
    EXmacAddr_t *macAddr = (EXmacAddr_t *)extensionRecord;

    uint8_t mac1[6], mac2[6], mac3[6], mac4[6];
    for (int i = 0; i < 6; i++) {
        mac1[i] = (macAddr->inSrcMac >> (i * 8)) & 0xFF;
        mac2[i] = (macAddr->outDstMac >> (i * 8)) & 0xFF;
        mac3[i] = (macAddr->inDstMac >> (i * 8)) & 0xFF;
        mac4[i] = (macAddr->outSrcMac >> (i * 8)) & 0xFF;
    }

    fprintf(stream,
            "%s\"in_src_mac\" : \"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\"%s"
            "%s\"out_dst_mac\" : \"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\"%s"
            "%s\"in_dst_mac\" : \"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\"%s"
            "%s\"out_src_mac\" : \"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\"%s",
            indent, mac1[5], mac1[4], mac1[3], mac1[2], mac1[1], mac1[0], fs, indent, mac2[5], mac2[4], mac2[3], mac2[2], mac2[1], mac2[0], fs,
            indent, mac3[5], mac3[4], mac3[3], mac3[2], mac3[1], mac3[0], fs, indent, mac4[5], mac4[4], mac4[3], mac4[2], mac4[1], mac4[0], fs);

}  // End of stringEXmacAddr

static void stringEXasAdjacent(FILE *stream, void *extensionRecord, const char *indent, const char *fs) {
    EXasAdjacent_t *asAdjacent = (EXasAdjacent_t *)extensionRecord;
    fprintf(stream,
            "%s\"next_as\" : %u%s"
            "%s\"prev_as\" : %u%s",
            indent, asAdjacent->nextAdjacentAS, fs, indent, asAdjacent->prevAdjacentAS, fs);

}  // End of stringEXasAdjacent

static void stringEXlatency(FILE *stream, void *extensionRecord, const char *indent, const char *fs) {
    EXlatency_t *latency = (EXlatency_t *)extensionRecord;

    double f1, f2, f3;
    f1 = (double)latency->usecClientNwDelay / 1000.0;
    f2 = (double)latency->usecServerNwDelay / 1000.0;
    f3 = (double)latency->usecApplLatency / 1000.0;

    fprintf(stream,
            "%s\"cli_latency\" : %f%s"
            "%s\"srv_latency\" : %f%s"
            "%s\"app_latency\" : %f%s",
            indent, f1, fs, indent, f2, fs, indent, f3, fs);

}  // End of stringEXlatency

static void String_payload(FILE *stream, recordHandle_t *recordHandle, void *extensionRecord, const char *indent, const char *fs) {
    const uint8_t *payload = (const uint8_t *)extensionRecord;
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];

    // payload handled in output json:
    // ssl, ja3, ja4

    if (payload == NULL || genericFlow->proto != IPPROTO_TCP) {
        return;
    }

    ssl_t *ssl = recordHandle->extensionList[SSLindex];
    if (ssl == NULL) {
        uint32_t payloadLength = ExtensionLength(payload);
        ssl = sslProcess(payload, payloadLength);
        recordHandle->extensionList[SSLindex] = ssl;
        if (ssl == NULL) {
            return;
        }
    }

    // ssl is defined

    if (ssl) {
        switch (ssl->tlsCharVersion[0]) {
            case 's':
                fprintf(stream, "%s\"tls\" : SSL%c%s", indent, ssl->tlsCharVersion[1], fs);
                break;
            case '1':
                fprintf(stream, "%s\"tls\" : TLS1.%c%s", indent, ssl->tlsCharVersion[1], fs);
                break;
            default:
                fprintf(stream, "%s\"tls\" : 0x%4x%s", indent, ssl->tlsVersion, fs);
                break;
        }

        if (ssl->sniName[0]) {
            fprintf(stream, "%s\"sni\" : %s%s\n", indent, ssl->sniName, fs);
        }
    }

    char *ja3 = recordHandle->extensionList[JA3index];
    if (ja3 == NULL) {
        ja3 = ja3Process(ssl, NULL);
        recordHandle->extensionList[JA3index] = ja3;
    }
    if (ja3) {
        fprintf(stream, "%s\"ja3 hash\" : %s%s\n", indent, ja3, fs);
    }

    ja4_t *ja4 = recordHandle->extensionList[JA4index];
    if (ja4 == NULL) {
        if (ssl->type == CLIENTssl) {
            ja4 = ja4Process(ssl, genericFlow->proto);
        } else {
            ja4 = ja4sProcess(ssl, genericFlow->proto);
        }
        recordHandle->extensionList[JA4index] = ja4;
    }
    if (ja4 == NULL) return;

    // ja4 is defined
    if (ja4->type == TYPE_JA4)
        fprintf(stream, "%s\"ja4 hash\" : %s%s\n", indent, ja4->string, fs);
    else
        fprintf(stream, "%s\"ja4s hash\" : %s%s\n", indent, ja4->string, fs);

}  // End of String_payload

static void stringEXtunIPv4(FILE *stream, void *extensionRecord, const char *indent, const char *fs) {
    EXtunIPv4_t *tunIPv4 = (EXtunIPv4_t *)extensionRecord;

    uint32_t src = htonl(tunIPv4->tunSrcAddr);
    uint32_t dst = htonl(tunIPv4->tunDstAddr);
    char as[IP_STRING_LEN], ds[IP_STRING_LEN];
    inet_ntop(AF_INET, &src, as, sizeof(as));
    inet_ntop(AF_INET, &dst, ds, sizeof(ds));

    fprintf(stream,
            "%s\"tun proto\" : %u%s"
            "%s\"src4_tun_ip\" : \"%s\"%s"
            "%s\"dst4_tun_ip\" : \"%s\"%s",
            indent, tunIPv4->tunProto, fs, indent, as, fs, indent, ds, fs);

}  // End of stringEXtunIPv4

static void stringEXtunIPv6(FILE *stream, void *extensionRecord, const char *indent, const char *fs) {
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
            "%s\"tun proto\" : %u%s"
            "%s\"src6_tun_ip\" : \"%s\"%s"
            "%s\"dst6_tun_ip\" : \"%s\"%s",
            indent, tunIPv6->tunProto, fs, indent, as, fs, indent, ds, fs);

}  // End of stringEXtunIPv6

static void stringEXobservation(FILE *stream, void *extensionRecord, const char *indent, const char *fs) {
    EXobservation_t *observation = (EXobservation_t *)extensionRecord;
    fprintf(stream,
            "%s\"observationDoaminID\" : %u%s"
            "%s\"observationPointID\" : %llu%s",
            indent, observation->domainID, fs, indent, (long long unsigned)observation->pointID, fs);

}  // End of stringEXobservation

static void stringEXvrf(FILE *stream, void *extensionRecord, const char *indent, const char *fs) {
    EXvrf_t *vrf = (EXvrf_t *)extensionRecord;
    fprintf(stream,
            "%s\"ingress_vrf\" : \"%u\"%s"
            "%s\"egress_vrf\" : \"%u\"%s",
            indent, vrf->ingressVrf, fs, indent, vrf->egressVrf, fs);

}  // End of stringEXvrf

static void stringEXnselCommon(FILE *stream, void *extensionRecord, const char *indent, const char *fs) {
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
            "%s\"connect_id\" : \"%u\"%s"
            "%s\"event_id\" : \"%u\"%s"
            "%s\"event\" : \"%s\"%s"
            "%s\"xevent_id\" : \"%u\"%s"
            "%s\"t_event\" : \"%s.%llu\"%s",
            indent, nselCommon->connID, fs, indent, nselCommon->fwEvent, fs, indent, fwEventString(nselCommon->fwEvent), fs, indent,
            nselCommon->fwXevent, fs, indent, datestr, nselCommon->msecEvent % 1000LL, fs);

}  // End of stringEXnselCommon

static void stringEXnselXlateIPv4(FILE *stream, void *extensionRecord, const char *indent, const char *fs) {
    EXnselXlateIPv4_t *nselXlateIPv4 = (EXnselXlateIPv4_t *)extensionRecord;

    uint32_t src = htonl(nselXlateIPv4->xlateSrcAddr);
    uint32_t dst = htonl(nselXlateIPv4->xlateDstAddr);
    char as[IP_STRING_LEN], ds[IP_STRING_LEN];
    inet_ntop(AF_INET, &src, as, sizeof(as));
    inet_ntop(AF_INET, &dst, ds, sizeof(ds));

    fprintf(stream,
            "%s\"src4_xlt_ip\" : \"%s\"%s"
            "%s\"dst4_xlt_ip\" : \"%s\"%s",
            indent, as, fs, indent, ds, fs);

}  // End of stringEXnselXlateIPv4

static void stringEXnselXlateIPv6(FILE *stream, void *extensionRecord, const char *indent, const char *fs) {
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
            "%s\"src6_xlt_ip\" : \"%s\"%s"
            "%s\"dst6_xlt_ip\" : \"%s\"%s",
            indent, as, fs, indent, ds, fs);

}  // End of stringEXnselXlateIPv4

static void stringEXnselXlatePort(FILE *stream, void *extensionRecord, const char *indent, const char *fs) {
    EXnselXlatePort_t *nselXlatePort = (EXnselXlatePort_t *)extensionRecord;
    fprintf(stream,
            "%s\"src_xlt_port\" : \"%u\"%s"
            "%s\"dst_xlt_port\" : \"%u\"%s",
            indent, nselXlatePort->xlateSrcPort, fs, indent, nselXlatePort->xlateDstPort, fs);

}  // End of stringEXnselXlatePort

static void stringEXnselAcl(FILE *stream, void *extensionRecord, const char *indent, const char *fs) {
    EXnselAcl_t *nselAcl = (EXnselAcl_t *)extensionRecord;
    fprintf(stream,
            "%s\"ingress_acl\" : \"0x%x/0x%x/0x%x\"%s"
            "%s\"egress_acl\" : \"0x%x/0x%x/0x%x\"%s",
            indent, nselAcl->ingressAcl[0], nselAcl->ingressAcl[1], nselAcl->ingressAcl[2], fs, indent, nselAcl->egressAcl[0], nselAcl->egressAcl[1],
            nselAcl->egressAcl[2], fs);

}  // End of stringEXnselAcl

static void stringEXnselUserID(FILE *stream, void *extensionRecord, const char *indent, const char *fs) {
    EXnselUser_t *nselUser = (EXnselUser_t *)extensionRecord;
    fprintf(stream, "%s\"user_name\" : \"%s\"%s", indent, nselUser->username[0] ? nselUser->username : "<empty>", fs);

}  // End of stringEXnselUserID

static void stringEXnelCommon(FILE *stream, void *extensionRecord, const char *indent, const char *fs) {
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
            "%s\"nat_event_id\" : \"%u\"%s"
            "%s\"nat_event\" : \"%s\"%s"
            "%s\"nat_pool_id\" : \"%u\"%s"
            "%s\"t_event\" : \"%s.%llu\"%s",
            indent, nelCommon->natEvent, fs, indent, natEventString(nelCommon->natEvent, LONGNAME), fs, indent, nelCommon->natPoolID, fs, indent,
            datestr, nelCommon->msecEvent % 1000LL, fs);

}  // End of stringEXnelCommon

static void stringEXnelXlatePort(FILE *stream, void *extensionRecord, const char *indent, const char *fs) {
    EXnelXlatePort_t *nelXlatePort = (EXnelXlatePort_t *)extensionRecord;
    fprintf(stream,
            "%s\"pblock_start\" : \"%u\"%s"
            "%s\"pblock_end\" : \"%u\"%s"
            "%s\"pblock_step\" : \"%u\"%s"
            "%s\"pblock_size\" : \"%u\"%s",
            indent, nelXlatePort->blockStart, fs, indent, nelXlatePort->blockEnd, fs, indent, nelXlatePort->blockStep, fs, indent,
            nelXlatePort->blockSize, fs);

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

static void flow_record_to_json(FILE *stream, recordHandle_t *recordHandle, int tag, const char *ws, const char *indent, const char *fs,
                                const char *rs) {
    // ws is whitespace after object opening and before object closing {WS  WS}
    // indent is printed before each record for clarity if needed
    // fs is Field Separator
    // rs is Record Separator
    recordHeaderV3_t *recordHeaderV3 = recordHandle->recordHeaderV3;

    if (recordCount) {
        fprintf(stream, "%s", rs);
    }
    recordCount++;

    fprintf(stream,
            "{%s"
            "%s\"type\" : \"%s\"%s"
            "%s\"export_sysid\" : %u%s",
            ws, indent, TestFlag(recordHeaderV3->flags, V3_FLAG_EVENT) ? "EVENT" : "FLOW", fs, indent, recordHeaderV3->exporterID, fs);

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
                stringEXgenericFlow(stream, ptr, indent, fs);
                break;
            case EXipv4FlowID:
                stringEXipv4Flow(stream, ptr, indent, fs);
                break;
            case EXipv6FlowID:
                stringEXipv6Flow(stream, ptr, indent, fs);
                break;
            case EXflowMiscID:
                stringEXflowMisc(stream, recordHandle, ptr, indent, fs);
                break;
            case EXcntFlowID:
                stringEXcntFlow(stream, ptr, indent, fs);
                break;
            case EXvLanID:
                stringEXvLan(stream, ptr, indent, fs);
                break;
            case EXasRoutingID:
                stringEXasRouting(stream, recordHandle, ptr, indent, fs);
                break;
            case EXbgpNextHopV4ID:
                stringEXbgpNextHopV4(stream, ptr, indent, fs);
                break;
            case EXbgpNextHopV6ID:
                stringEXbgpNextHopV6(stream, ptr, indent, fs);
                break;
            case EXipNextHopV4ID:
                stringEXipNextHopV4(stream, ptr, indent, fs);
                break;
            case EXipNextHopV6ID:
                stringEXipNextHopV6(stream, ptr, indent, fs);
                break;
            case EXipReceivedV4ID:
                stringEXipReceivedV4(stream, ptr, indent, fs);
                break;
            case EXipReceivedV6ID:
                stringEXipReceivedV6(stream, ptr, indent, fs);
                break;
            case EXmplsLabelID:
                stringEXmplsLabel(stream, ptr, indent, fs);
                break;
            case EXmacAddrID:
                stringEXmacAddr(stream, ptr, indent, fs);
                break;
            case EXasAdjacentID:
                stringEXasAdjacent(stream, ptr, indent, fs);
                break;
            case EXlatencyID:
                stringEXlatency(stream, ptr, indent, fs);
                break;
            case EXinPayloadID:
                String_payload(stream, recordHandle, ptr, indent, fs);
                break;
            case EXoutPayloadID:
                String_payload(stream, recordHandle, ptr, indent, fs);
                break;
            case EXtunIPv4ID:
                stringEXtunIPv4(stream, ptr, indent, fs);
                break;
            case EXtunIPv6ID:
                stringEXtunIPv6(stream, ptr, indent, fs);
                break;
            case EXobservationID:
                stringEXobservation(stream, ptr, indent, fs);
                break;
            case EXvrfID:
                stringEXvrf(stream, ptr, indent, fs);
                break;
            case EXnselCommonID:
                stringEXnselCommon(stream, ptr, indent, fs);
                break;
            case EXnselXlateIPv4ID:
                stringEXnselXlateIPv4(stream, ptr, indent, fs);
                break;
            case EXnselXlateIPv6ID:
                stringEXnselXlateIPv6(stream, ptr, indent, fs);
                break;
            case EXnselXlatePortID:
                stringEXnselXlatePort(stream, ptr, indent, fs);
                break;
            case EXnselAclID:
                stringEXnselAcl(stream, ptr, indent, fs);
                break;
            case EXnselUserID:
                stringEXnselUserID(stream, ptr, indent, fs);
                break;
            case EXnelCommonID:
                stringEXnelCommon(stream, ptr, indent, fs);
                break;
            case EXnelXlatePortID:
                stringEXnelXlatePort(stream, ptr, indent, fs);
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
            r->label ? r->label : "<none>");
    */

    // Close out JSON record
    fprintf(stream, "%s\"sampled\" : %u%s}", indent, TestFlag(recordHeaderV3->flags, V3_FLAG_SAMPLED) ? 1 : 0, ws);

}  // End of flow_record_to_json

void flow_record_to_json_human(FILE *stream, recordHandle_t *recordHandle, int tag) {
    flow_record_to_json(stream, recordHandle, tag, "\n", "\t", ",\n", ",\n");

}  // End of flow_record_to_json_human

void flow_record_to_json_log(FILE *stream, recordHandle_t *recordHandle, int tag) {
    flow_record_to_json(stream, recordHandle, tag, "", "", ",", "\n");
}  // End of flow_record_to_json_log
