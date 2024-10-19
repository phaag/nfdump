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
 *     and/or other materials provided with the distributson.
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

#include "output_ndjson.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include "config.h"
#include "ja3/ja3.h"
#include "ja4/ja4.h"
#include "maxmind/maxmind.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfxV3.h"
#include "output_util.h"
#include "userio.h"
#include "util.h"

#define IP_STRING_LEN (INET6_ADDRSTRLEN)

// record counter
static uint32_t recordCount = 0;

#include "itoa.c"

#define AddElementString(e, s)     \
    do {                           \
        *streamPtr++ = '"';        \
        size_t len = strlen(e);    \
        memcpy(streamPtr, e, len); \
        streamPtr += len;          \
        *streamPtr++ = '"';        \
        *streamPtr++ = ':';        \
        *streamPtr++ = '"';        \
        len = strlen(s);           \
        memcpy(streamPtr, s, len); \
        streamPtr += len;          \
        *streamPtr++ = '"';        \
        *streamPtr++ = ',';        \
    } while (0)

#define AddElementU64(e, u64)                             \
    do {                                                  \
        *streamPtr++ = '"';                               \
        size_t len = strlen(e);                           \
        memcpy(streamPtr, e, len);                        \
        streamPtr += len;                                 \
        *streamPtr++ = '"';                               \
        *streamPtr++ = ':';                               \
        streamPtr = itoa_u64((uint64_t)(u64), streamPtr); \
        *streamPtr++ = ',';                               \
    } while (0)

#define AddElementU32(e, u32)                             \
    do {                                                  \
        *streamPtr++ = '"';                               \
        size_t len = strlen(e);                           \
        memcpy(streamPtr, e, len);                        \
        streamPtr += len;                                 \
        *streamPtr++ = '"';                               \
        *streamPtr++ = ':';                               \
        streamPtr = itoa_u32((uint32_t)(u32), streamPtr); \
        *streamPtr++ = ',';                               \
    } while (0)

#define STREAMBUFFSIZE 4096
#define STREAMLEN(ptr)                                \
    ((ptrdiff_t)STREAMBUFFSIZE - (ptr - streamBuff)); \
    assert((ptr - streamBuff) < STREAMBUFFSIZE)
static char *streamBuff = NULL;

static char *stringEXgenericFlow(char *streamPtr, void *extensionRecord) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)extensionRecord;

    time_t when = (genericFlow->msecFirst / 1000LL);
    struct tm ts = {0};
    localtime_r(&when, &ts);
    char dateBuff1[64];
    strftime(dateBuff1, 63, "%Y-%m-%dT%H:%M:%S", &ts);

    when = (genericFlow->msecLast / 1000LL);
    localtime_r(&when, &ts);
    char dateBuff2[64];
    strftime(dateBuff2, 63, "%Y-%m-%dT%H:%M:%S", &ts);

    when = (genericFlow->msecReceived / 1000LL);
    localtime_r(&when, &ts);
    char dateBuff3[64];
    strftime(dateBuff3, 63, "%Y-%m-%dT%H:%M:%S", &ts);

    ptrdiff_t lenStream = STREAMLEN(streamPtr);
    int len = snprintf(streamPtr, lenStream,
                       "\"first\":\"%s.%03u\","
                       "\"last\":\"%s.%03u\","
                       "\"received\":\"%s.%03u\",",
                       dateBuff1, (unsigned)(genericFlow->msecFirst % 1000LL), dateBuff2, (unsigned)(genericFlow->msecLast % 1000LL), dateBuff3,
                       (unsigned)(genericFlow->msecReceived % 1000LL));
    streamPtr += len;

    AddElementU64("in_packets", genericFlow->inPackets);
    AddElementU64("in_bytes", genericFlow->inBytes);

    if (genericFlow->proto == IPPROTO_ICMP || genericFlow->proto == IPPROTO_ICMPV6) {  // ICMP
        AddElementU32("proto", (uint32_t)genericFlow->proto);
        AddElementU32("icmp_type", (uint32_t)genericFlow->icmpType);
        AddElementU32("icmp_code", (uint32_t)genericFlow->icmpCode);
        AddElementU32("src_tos", (uint32_t)genericFlow->srcTos);
    } else {
        AddElementU32("proto", (uint32_t)genericFlow->proto);
        AddElementString("tcp_flags", FlagsString(genericFlow->tcpFlags));
        AddElementU32("src_port", (uint32_t)genericFlow->srcPort);
        AddElementU32("dst_port", (uint32_t)genericFlow->dstPort);
        AddElementU32("fwd_status", (uint32_t)genericFlow->fwdStatus);
        AddElementU32("src_tos", (uint32_t)genericFlow->srcTos);
    }

    return streamPtr;

}  // End of stringEXgenericFlow

static char *stringEXipv4Flow(char *streamPtr, void *extensionRecord) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)extensionRecord;

    uint32_t src = htonl(ipv4Flow->srcAddr);
    uint32_t dst = htonl(ipv4Flow->dstAddr);
    char sa[IP_STRING_LEN], da[IP_STRING_LEN];
    inet_ntop(AF_INET, &src, sa, sizeof(sa));
    inet_ntop(AF_INET, &dst, da, sizeof(da));

    char sloc[128], dloc[128];
    LookupV4Location(ipv4Flow->srcAddr, sloc, 128);
    LookupV4Location(ipv4Flow->dstAddr, dloc, 128);

    AddElementString("src4_addr", sa);
    AddElementString("dst4_addr", da);
    AddElementString("src4_geo", sloc);
    AddElementString("dst4_geo", dloc);

    return streamPtr;
}  // End of stringEXipv4Flow

static char *stringEXipv6Flow(char *streamPtr, void *extensionRecord) {
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)extensionRecord;

    uint64_t src[2], dst[2];
    src[0] = htonll(ipv6Flow->srcAddr[0]);
    src[1] = htonll(ipv6Flow->srcAddr[1]);
    dst[0] = htonll(ipv6Flow->dstAddr[0]);
    dst[1] = htonll(ipv6Flow->dstAddr[1]);
    char sa[IP_STRING_LEN], da[IP_STRING_LEN];
    inet_ntop(AF_INET6, &src, sa, sizeof(sa));
    inet_ntop(AF_INET6, &dst, da, sizeof(da));

    char sloc[128], dloc[128];
    LookupV6Location(ipv6Flow->srcAddr, sloc, 128);
    LookupV6Location(ipv6Flow->dstAddr, dloc, 128);

    AddElementString("src6_addr", sa);
    AddElementString("dst6_addr", da);
    AddElementString("src6_geo", sloc);
    AddElementString("dst6_geo", dloc);

    return streamPtr;
}  // End of stringEXipv6Flow

static char *stringEXflowMisc(char *streamPtr, recordHandle_t *recordHandle, void *extensionRecord) {
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

    AddElementU32("input_snmp", flowMisc->input);
    AddElementU32("output_snmp", flowMisc->output);
    AddElementU32("src_mask", flowMisc->srcMask);
    AddElementU32("dst_mask", flowMisc->dstMask);
    AddElementString("src_net", snet);
    AddElementString("dst_net", dnet);
    AddElementU32("direction", flowMisc->dir);
    AddElementU32("dst_tos", flowMisc->dstTos);

    return streamPtr;

}  // End of stringEXflowMisc

static char *stringEXipInfo(char *streamPtr, void *extensionRecord) {
    EXipInfo_t *ipInfo = (EXipInfo_t *)extensionRecord;

    char flags[4] = "--\0";
    if (ipInfo->fragmentFlags & flagDF) {
        flags[0] = 'D';
        flags[1] = 'F';
    }
    if (ipInfo->fragmentFlags & flagMF) {
        flags[2] = 'M';
        flags[3] = 'F';
    }

    AddElementString("ip_fragment", flags);
    AddElementU32("ip_ttl", (uint32_t)ipInfo->ttl);

    return streamPtr;
}  // End of stringEXipInfo

static char *stringEXcntFlow(char *streamPtr, void *extensionRecord) {
    EXcntFlow_t *cntFlow = (EXcntFlow_t *)extensionRecord;

    AddElementU64("out_packets", cntFlow->outPackets);
    AddElementU64("out_bytes", cntFlow->outBytes);
    AddElementU64("aggr_flows", cntFlow->flows);

    return streamPtr;
}  // End of stringEXcntFlow

static char *stringEXvLan(char *streamPtr, void *extensionRecord) {
    EXvLan_t *vLan = (EXvLan_t *)extensionRecord;

    AddElementU32("src_vlan", vLan->srcVlan);
    AddElementU32("dst_vlan", vLan->dstVlan);

    return streamPtr;
}  // End of stringEXvLan

static char *stringEXasRouting(char *streamPtr, recordHandle_t *recordHandle, void *extensionRecord) {
    EXasRouting_t *asRouting = (EXasRouting_t *)extensionRecord;
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    if (asRouting->srcAS == 0) asRouting->srcAS = ipv4Flow ? LookupV4AS(ipv4Flow->srcAddr) : LookupV6AS(ipv6Flow->srcAddr);
    if (asRouting->dstAS == 0) asRouting->dstAS = ipv4Flow ? LookupV4AS(ipv4Flow->dstAddr) : LookupV6AS(ipv6Flow->dstAddr);

    AddElementU32("src_as", asRouting->srcAS);
    AddElementU32("dst_as", asRouting->dstAS);

    return streamPtr;
}  // End of stringEXasRouting

static char *stringEXbgpNextHopV4(char *streamPtr, void *extensionRecord) {
    EXbgpNextHopV4_t *bgpNextHopV4 = (EXbgpNextHopV4_t *)extensionRecord;

    uint32_t i = htonl(bgpNextHopV4->ip);
    char ip[IP_STRING_LEN];
    ip[0] = 0;
    inet_ntop(AF_INET, &i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    AddElementString("bgp4_next_hop", ip);

    return streamPtr;
}  // End of stringEXbgpNextHopV4

static char *stringEXbgpNextHopV6(char *streamPtr, void *extensionRecord) {
    EXbgpNextHopV6_t *bgpNextHopV6 = (EXbgpNextHopV6_t *)extensionRecord;

    uint64_t i[2];
    i[0] = htonll(bgpNextHopV6->ip[0]);
    i[1] = htonll(bgpNextHopV6->ip[1]);

    char ip[IP_STRING_LEN];
    ip[0] = 0;
    inet_ntop(AF_INET6, i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    AddElementString("bgp6_next_hop", ip);

    return streamPtr;
}  // End of stringEXbgpNextHopV6

static char *stringEXipNextHopV4(char *streamPtr, void *extensionRecord) {
    EXipNextHopV4_t *ipNextHopV4 = (EXipNextHopV4_t *)extensionRecord;

    uint32_t i = htonl(ipNextHopV4->ip);
    char ip[IP_STRING_LEN];
    ip[0] = 0;
    inet_ntop(AF_INET, &i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    AddElementString("ip4_next_hop", ip);

    return streamPtr;
}  // End of stringEXipNextHopV4

static char *stringEXipNextHopV6(char *streamPtr, void *extensionRecord) {
    EXipNextHopV6_t *ipNextHopV6 = (EXipNextHopV6_t *)extensionRecord;

    uint64_t i[2];
    i[0] = htonll(ipNextHopV6->ip[0]);
    i[1] = htonll(ipNextHopV6->ip[1]);

    char ip[IP_STRING_LEN];
    ip[0] = 0;
    inet_ntop(AF_INET6, i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    AddElementString("ip6_next_hop", ip);

    return streamPtr;
}  // End of stringEXipNextHopV6

static char *stringEXipReceivedV4(char *streamPtr, void *extensionRecord) {
    EXipReceivedV4_t *ipReceivedV4 = (EXipReceivedV4_t *)extensionRecord;

    uint32_t i = htonl(ipReceivedV4->ip);
    char ip[IP_STRING_LEN];
    ip[0] = 0;
    inet_ntop(AF_INET, &i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    AddElementString("ip4_router", ip);

    return streamPtr;
}  // End of stringEXipReceivedV4

static char *stringEXipReceivedV6(char *streamPtr, void *extensionRecord) {
    EXipReceivedV6_t *ipReceivedV6 = (EXipReceivedV6_t *)extensionRecord;

    uint64_t i[2];
    i[0] = htonll(ipReceivedV6->ip[0]);
    i[1] = htonll(ipReceivedV6->ip[1]);
    char ip[IP_STRING_LEN];
    ip[0] = 0;
    inet_ntop(AF_INET6, i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    AddElementString("ip6_router", ip);

    return streamPtr;
}  // End of stringEXipReceivedV6

static char *stringEXmplsLabel(char *streamPtr, void *extensionRecord) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)extensionRecord;
    for (int i = 0; i < 10; i++) {
        ptrdiff_t lenStream = STREAMLEN(streamPtr);
        int len = snprintf(streamPtr, lenStream, "\"mpls_%u\":\"%u-%u-%u\",", i + 1, mplsLabel->mplsLabel[i] >> 4,
                           (mplsLabel->mplsLabel[i] & 0xF) >> 1, mplsLabel->mplsLabel[i] & 1);
        streamPtr += len;
    }

    return streamPtr;
}  // End of stringEXmplsLabel

static char *stringEXmacAddr(char *streamPtr, void *extensionRecord) {
    EXmacAddr_t *macAddr = (EXmacAddr_t *)extensionRecord;

    uint8_t mac1[6], mac2[6], mac3[6], mac4[6];
    for (int i = 0; i < 6; i++) {
        mac1[i] = (macAddr->inSrcMac >> (i * 8)) & 0xFF;
        mac2[i] = (macAddr->outDstMac >> (i * 8)) & 0xFF;
        mac3[i] = (macAddr->inDstMac >> (i * 8)) & 0xFF;
        mac4[i] = (macAddr->outSrcMac >> (i * 8)) & 0xFF;
    }

    ptrdiff_t lenStream = STREAMLEN(streamPtr);
    int len = snprintf(streamPtr, lenStream,
                       "\"in_src_mac\":\"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\","
                       "\"out_dst_mac\":\"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\","
                       "\"in_dst_mac\":\"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\","
                       "\"out_src_mac\":\"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\",",
                       mac1[5], mac1[4], mac1[3], mac1[2], mac1[1], mac1[0], mac2[5], mac2[4], mac2[3], mac2[2], mac2[1], mac2[0], mac3[5], mac3[4],
                       mac3[3], mac3[2], mac3[1], mac3[0], mac4[5], mac4[4], mac4[3], mac4[2], mac4[1], mac4[0]);
    streamPtr += len;

    return streamPtr;
}  // End of stringEXmacAddr

static char *stringEXasAdjacent(char *streamPtr, void *extensionRecord) {
    EXasAdjacent_t *asAdjacent = (EXasAdjacent_t *)extensionRecord;

    AddElementU32("next_as", asAdjacent->nextAdjacentAS);
    AddElementU32("prev_as", asAdjacent->prevAdjacentAS);

    return streamPtr;
}  // End of stringEXasAdjacent

static char *stringEXlatency(char *streamPtr, void *extensionRecord) {
    EXlatency_t *latency = (EXlatency_t *)extensionRecord;

    double f1, f2, f3;
    f1 = (double)latency->usecClientNwDelay / 1000.0;
    f2 = (double)latency->usecServerNwDelay / 1000.0;
    f3 = (double)latency->usecApplLatency / 1000.0;

    ptrdiff_t lenStream = STREAMLEN(streamPtr);
    int len = snprintf(streamPtr, lenStream,
                       "\"cli_latency\":%f,"
                       "\"srv_latency\":%f,"
                       "\"app_latency\":%f,",
                       f1, f2, f3);
    streamPtr += len;

    return streamPtr;
}  // End of stringEXlatency

static char *string_payload(char *streamPtr, recordHandle_t *recordHandle, void *extensionRecord) {
    const uint8_t *payload = (const uint8_t *)extensionRecord;
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];

    // payload handled in output json:
    // ssl, ja3, ja4

    if (payload == NULL || genericFlow->proto != IPPROTO_TCP) {
        return streamPtr;
    }

    ssl_t *ssl = recordHandle->extensionList[SSLindex];
    if (ssl == NULL) {
        uint32_t payloadLength = ExtensionLength(payload);
        ssl = sslProcess(payload, payloadLength);
        recordHandle->extensionList[SSLindex] = ssl;
        if (ssl == NULL) {
            return streamPtr;
        }
    }

    // ssl is defined

    ptrdiff_t lenStream = STREAMLEN(streamPtr);
    int len = 0;
    if (ssl) {
        switch (ssl->tlsCharVersion[0]) {
            case 's':
                len = snprintf(streamPtr, lenStream, "\"tls\":\"SSL%c\",", ssl->tlsCharVersion[1]);
                break;
            case '1':
                len = snprintf(streamPtr, lenStream, "\"tls\":\"TLS1.%c\",", ssl->tlsCharVersion[1]);
                break;
            default:
                len = snprintf(streamPtr, lenStream, "\"tls\":0x%4x,", ssl->tlsVersion);
                break;
        }
        streamPtr += len;

        if (ssl->sniName[0]) {
            AddElementString("sni", ssl->sniName);
        }
    }

    char *ja3 = recordHandle->extensionList[JA3index];
    if (ja3 == NULL) {
        ja3 = ja3Process(ssl, NULL);
        recordHandle->extensionList[JA3index] = ja3;
    }
    if (ja3) {
        AddElementString("ja3 hash", ja3);
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
    if (ja4 == NULL) return streamPtr;

    // ja4 is defined
    if (ja4->type == TYPE_JA4)
        AddElementString("ja4 hash", ja4->string);
    else
        AddElementString("ja4s hash", ja4->string);

    return streamPtr;
}  // End of string_payload

static char *stringEXtunIPv4(char *streamPtr, void *extensionRecord) {
    EXtunIPv4_t *tunIPv4 = (EXtunIPv4_t *)extensionRecord;

    uint32_t src = htonl(tunIPv4->tunSrcAddr);
    uint32_t dst = htonl(tunIPv4->tunDstAddr);
    char as[IP_STRING_LEN], ds[IP_STRING_LEN];
    inet_ntop(AF_INET, &src, as, sizeof(as));
    inet_ntop(AF_INET, &dst, ds, sizeof(ds));

    AddElementU32("tun_proto", tunIPv4->tunProto);
    AddElementString("src4_tun_ip", as);
    AddElementString("dst4_tun_ip", ds);

    return streamPtr;
}  // End of stringEXtunIPv4

static char *stringEXtunIPv6(char *streamPtr, void *extensionRecord) {
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

    AddElementU32("tun_proto", tunIPv6->tunProto);
    AddElementString("src6_tun_ip", as);
    AddElementString("dst6_tun_ip", ds);

    return streamPtr;
}  // End of stringEXtunIPv6

static char *stringEXobservation(char *streamPtr, void *extensionRecord) {
    EXobservation_t *observation = (EXobservation_t *)extensionRecord;

    AddElementU32("observationDomainID", observation->domainID);
    AddElementU32("observationPointID", observation->pointID);

    return streamPtr;
}  // End of stringEXobservation

static char *stringEXvrf(char *streamPtr, void *extensionRecord) {
    EXvrf_t *vrf = (EXvrf_t *)extensionRecord;

    AddElementU32("ingress_vrf", vrf->ingressVrf);
    AddElementU32("egress_vrf", vrf->egressVrf);

    return streamPtr;
}  // End of stringEXvrf

static char *stringEXlayer2(char *streamPtr, void *extensionRecord) {
    EXlayer2_t *layer2 = (EXlayer2_t *)extensionRecord;

    AddElementU32("vlanID", layer2->vlanID);
    AddElementU32("post_vlanID", layer2->postVlanID);
    AddElementU32("cust_vlanID", layer2->customerVlanId);
    AddElementU32("post_cust_vlanID", layer2->postCustomerVlanId);
    AddElementU32("phys_ingress", layer2->ingress);
    AddElementU32("phys_egress", layer2->egress);
    AddElementU32("ethertype", layer2->etherType);
    AddElementU32("ip_version", layer2->ipVersion);

    return streamPtr;
}  // End of stringEXlayer2

static char *stringEXnselCommon(char *streamPtr, void *extensionRecord) {
    EXnselCommon_t *nselCommon = (EXnselCommon_t *)extensionRecord;

    char datestr[64];
    time_t when = nselCommon->msecEvent / 1000LL;
    if (when == 0) {
        strncpy(datestr, "<unknown>", 63);
    } else {
        struct tm *ts = localtime(&when);
        strftime(datestr, 63, "%Y-%m-%dT%H:%M:%S", ts);
    }

    AddElementU32("connect_id", nselCommon->connID);
    AddElementU32("event_id", nselCommon->fwEvent);
    AddElementString("event", fwEventString(nselCommon->fwEvent));
    AddElementU32("xevent_id", nselCommon->fwXevent);

    ptrdiff_t lenStream = STREAMLEN(streamPtr);
    int len = snprintf(streamPtr, lenStream, "\"t_event\":\"%s.%llu\",", datestr, nselCommon->msecEvent % 1000LL);
    streamPtr += len;

    return streamPtr;
}  // End of stringEXnselCommon

static char *stringEXnatXlateIPv4(char *streamPtr, void *extensionRecord) {
    EXnatXlateIPv4_t *natXlateIPv4 = (EXnatXlateIPv4_t *)extensionRecord;

    uint32_t src = htonl(natXlateIPv4->xlateSrcAddr);
    uint32_t dst = htonl(natXlateIPv4->xlateDstAddr);
    char as[IP_STRING_LEN], ds[IP_STRING_LEN];
    inet_ntop(AF_INET, &src, as, sizeof(as));
    inet_ntop(AF_INET, &dst, ds, sizeof(ds));

    AddElementString("src4_xlt_ip", as);
    AddElementString("dst4_xlt_ip", ds);

    return streamPtr;
}  // End of stringEXnatXlateIPv4

static char *stringEXnatXlateIPv6(char *streamPtr, void *extensionRecord) {
    EXnatXlateIPv6_t *natXlateIPv6 = (EXnatXlateIPv6_t *)extensionRecord;

    uint64_t src[2];
    uint64_t dst[2];
    src[0] = htonll(natXlateIPv6->xlateSrcAddr[0]);
    src[1] = htonll(natXlateIPv6->xlateSrcAddr[1]);
    dst[0] = htonll(natXlateIPv6->xlateDstAddr[0]);
    dst[1] = htonll(natXlateIPv6->xlateDstAddr[1]);
    char as[IP_STRING_LEN], ds[IP_STRING_LEN];
    inet_ntop(AF_INET6, &src, as, sizeof(as));
    inet_ntop(AF_INET6, &dst, ds, sizeof(ds));

    AddElementString("src6_xlt_ip", as);
    AddElementString("dst6_xlt_ip", ds);

    return streamPtr;
}  // End of stringEXnatXlateIPv4

static char *stringEXnatXlatePort(char *streamPtr, void *extensionRecord) {
    EXnatXlatePort_t *natXlatePort = (EXnatXlatePort_t *)extensionRecord;

    AddElementU32("src_xlt_port", natXlatePort->xlateSrcPort);
    AddElementU32("dst_xlt_port", natXlatePort->xlateDstPort);

    return streamPtr;
}  // End of stringEXnatXlatePort

static char *stringEXnselAcl(char *streamPtr, void *extensionRecord) {
    EXnselAcl_t *nselAcl = (EXnselAcl_t *)extensionRecord;
    ptrdiff_t lenStream = STREAMLEN(streamPtr);
    int len = snprintf(streamPtr, lenStream,
                       "\"ingress_acl\":\"0x%x/0x%x/0x%x\","
                       "\"egress_acl\":\"0x%x/0x%x/0x%x\",",
                       nselAcl->ingressAcl[0], nselAcl->ingressAcl[1], nselAcl->ingressAcl[2], nselAcl->egressAcl[0], nselAcl->egressAcl[1],
                       nselAcl->egressAcl[2]);
    streamPtr += len;

    return streamPtr;
}  // End of stringEXnselAcl

static char *stringEXnselUserID(char *streamPtr, void *extensionRecord) {
    EXnselUser_t *nselUser = (EXnselUser_t *)extensionRecord;

    char *name = nselUser->username[0] ? nselUser->username : "<empty>";
    AddElementString("user_name", name);

    return streamPtr;
}  // End of stringEXnselUserID

static char *stringEXnatCommon(char *streamPtr, void *extensionRecord) {
    EXnatCommon_t *natCommon = (EXnatCommon_t *)extensionRecord;

    time_t when = natCommon->msecEvent / 1000LL;
    char datestr[64];
    if (when == 0) {
        strncpy(datestr, "<unknown>", 63);
    } else {
        struct tm *ts = localtime(&when);
        strftime(datestr, 63, "%Y-%m-%dT%H:%M:%S", ts);
    }

    AddElementU32("nat_event_id", natCommon->natEvent);
    AddElementString("nat_event", natEventString(natCommon->natEvent, LONGNAME));
    AddElementU32("nat_pool_id", natCommon->natPoolID);

    ptrdiff_t lenStream = STREAMLEN(streamPtr);
    int len = snprintf(streamPtr, lenStream, "\"t_event\":\"%s.%llu\",", datestr, natCommon->msecEvent % 1000LL);

    streamPtr += len;

    return streamPtr;
}  // End of stringEXnatCommon

static char *stringEXnatPortBlock(char *streamPtr, void *extensionRecord) {
    EXnatPortBlock_t *natPortBlock = (EXnatPortBlock_t *)extensionRecord;

    AddElementU32("pblock_start", natPortBlock->blockStart);
    AddElementU32("pblock_end", natPortBlock->blockEnd);
    AddElementU32("pblock_step", natPortBlock->blockStep);
    AddElementU32("pblock_size", natPortBlock->blockSize);

    return streamPtr;
}  // End of stringEXnatPortBlock

static char *stringEXflowId(char *streamPtr, void *extensionRecord) {
    EXflowId_t *flowId = (EXflowId_t *)extensionRecord;

    AddElementU64("flowID", flowId->flowId);

    return streamPtr;
}  // End of stringEXflowId

static char *stringEXnokiaNat(char *streamPtr, void *extensionRecord) {
    EXnokiaNat_t *nokiaNat = (EXnokiaNat_t *)extensionRecord;

    AddElementU32("inServiceID", nokiaNat->inServiceID);
    AddElementU32("inServiceID", nokiaNat->outServiceID);

    return streamPtr;
}  // End of String_inServiceID

static char *stringEXnokiaNatString(char *streamPtr, void *extensionRecord) {
    char *natString = (char *)extensionRecord;

    AddElementString("natString", natString);

    return streamPtr;
}  // End of String_natString

void ndjson_prolog(outputParams_t *outputParam) {
    streamBuff = malloc(STREAMBUFFSIZE);
    if (!streamBuff) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        exit(EXIT_FAILURE);
    }
    streamBuff[0] = '\0';

}  // End of ndjson_prolog

void ndjson_epilog(outputParams_t *outputParam) {
    free(streamBuff);
    streamBuff = NULL;
}  // End of ndjson_epilog

enum { FORMAT_NDJSON = 0, FORMAT_JSON };

void flow_record_to_ndjson(FILE *stream, recordHandle_t *recordHandle, int tag) {
    // ws is whitespace after object opening and before object closing {WS  WS}
    // indent is printed before each record for clarity if needed
    // fs is Field Separator
    // rs is Record Separator

    recordHeaderV3_t *recordHeaderV3 = recordHandle->recordHeaderV3;

    streamBuff[0] = '\0';
    char *streamPtr = streamBuff;

    *streamPtr++ = '{';

    char *typeString = TestFlag(recordHeaderV3->flags, V3_FLAG_EVENT) ? "EVENT" : "FLOW";
    AddElementU32("cnt", ++recordCount);
    AddElementString("type", typeString);
    AddElementU32("export_sysid", recordHeaderV3->exporterID);

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
                streamPtr = stringEXgenericFlow(streamPtr, ptr);
                break;
            case EXipv4FlowID:
                streamPtr = stringEXipv4Flow(streamPtr, ptr);
                break;
            case EXipv6FlowID:
                streamPtr = stringEXipv6Flow(streamPtr, ptr);
                break;
            case EXflowMiscID:
                streamPtr = stringEXflowMisc(streamPtr, recordHandle, ptr);
                break;
            case EXcntFlowID:
                streamPtr = stringEXcntFlow(streamPtr, ptr);
                break;
            case EXvLanID:
                streamPtr = stringEXvLan(streamPtr, ptr);
                break;
            case EXasRoutingID:
                streamPtr = stringEXasRouting(streamPtr, recordHandle, ptr);
                break;
            case EXbgpNextHopV4ID:
                streamPtr = stringEXbgpNextHopV4(streamPtr, ptr);
                break;
            case EXbgpNextHopV6ID:
                streamPtr = stringEXbgpNextHopV6(streamPtr, ptr);
                break;
            case EXipNextHopV4ID:
                streamPtr = stringEXipNextHopV4(streamPtr, ptr);
                break;
            case EXipNextHopV6ID:
                streamPtr = stringEXipNextHopV6(streamPtr, ptr);
                break;
            case EXipReceivedV4ID:
                streamPtr = stringEXipReceivedV4(streamPtr, ptr);
                break;
            case EXipReceivedV6ID:
                streamPtr = stringEXipReceivedV6(streamPtr, ptr);
                break;
            case EXmplsLabelID:
                streamPtr = stringEXmplsLabel(streamPtr, ptr);
                break;
            case EXmacAddrID:
                streamPtr = stringEXmacAddr(streamPtr, ptr);
                break;
            case EXasAdjacentID:
                streamPtr = stringEXasAdjacent(streamPtr, ptr);
                break;
            case EXlatencyID:
                streamPtr = stringEXlatency(streamPtr, ptr);
                break;
            case EXinPayloadID:
                streamPtr = string_payload(streamPtr, recordHandle, ptr);
                break;
            case EXoutPayloadID:
                streamPtr = string_payload(streamPtr, recordHandle, ptr);
                break;
            case EXtunIPv4ID:
                streamPtr = stringEXtunIPv4(streamPtr, ptr);
                break;
            case EXtunIPv6ID:
                streamPtr = stringEXtunIPv6(streamPtr, ptr);
                break;
            case EXobservationID:
                streamPtr = stringEXobservation(streamPtr, ptr);
                break;
            case EXvrfID:
                streamPtr = stringEXvrf(streamPtr, ptr);
                break;
            case EXlayer2ID:
                streamPtr = stringEXlayer2(streamPtr, ptr);
                break;
            case EXnselCommonID:
                streamPtr = stringEXnselCommon(streamPtr, ptr);
                break;
            case EXnatXlateIPv4ID:
                streamPtr = stringEXnatXlateIPv4(streamPtr, ptr);
                break;
            case EXnatXlateIPv6ID:
                streamPtr = stringEXnatXlateIPv6(streamPtr, ptr);
                break;
            case EXnatXlatePortID:
                streamPtr = stringEXnatXlatePort(streamPtr, ptr);
                break;
            case EXnselAclID:
                streamPtr = stringEXnselAcl(streamPtr, ptr);
                break;
            case EXnselUserID:
                streamPtr = stringEXnselUserID(streamPtr, ptr);
                break;
            case EXnatCommonID:
                streamPtr = stringEXnatCommon(streamPtr, ptr);
                break;
            case EXnatPortBlockID:
                streamPtr = stringEXnatPortBlock(streamPtr, ptr);
                break;
            case EXflowIdID:
                streamPtr = stringEXflowId(streamPtr, ptr);
                break;
            case EXnokiaNatID:
                streamPtr = stringEXnokiaNat(streamPtr, ptr);
                break;
            case EXnokiaNatStringID:
                streamPtr = stringEXnokiaNatString(streamPtr, ptr);
                break;
            case EXipInfoID:
                streamPtr = stringEXipInfo(streamPtr, ptr);
                break;
            default:
                dbg_printf("Extension %i not yet implemented\n", i);
        }
    }

    // Close out JSON record
    AddElementU32("sampled", TestFlag(recordHeaderV3->flags, V3_FLAG_SAMPLED) ? 1 : 0);

    streamPtr--;
    *streamPtr++ = '}';
    *streamPtr++ = '\n';
    *streamPtr++ = '\0';

    if (unlikely((streamBuff + STREAMBUFFSIZE - streamPtr) < 512)) {
        LogError("json_record() error in %s line %d: %s", __FILE__, __LINE__, "buffer error");
        exit(EXIT_FAILURE);
    }

    fputs(streamBuff, stream);

}  // End of flow_record_to_ndjson
