/*
 *  Copyright (c) 2019-2026, Peter Haag
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
#include "logging.h"
#include "maxmind/maxmind.h"
#include "nfdump.h"
#include "nffileV3/nffileV3.h"
#include "nfxV4.h"
#include "output_util.h"
#include "userio.h"
#include "util.h"

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

static char *stringEXgenericFlow(char *streamPtr, uint8_t *extensionRecord) {
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

static char *stringEXipv4Flow(char *streamPtr, uint8_t *extensionRecord) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)extensionRecord;

    uint32_t src = htonl(ipv4Flow->srcAddr);
    uint32_t dst = htonl(ipv4Flow->dstAddr);
    char sa[INET6_ADDRSTRLEN], da[INET6_ADDRSTRLEN];
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

static char *stringEXipv6Flow(char *streamPtr, uint8_t *extensionRecord) {
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)extensionRecord;

    uint64_t src[2], dst[2];
    src[0] = htonll(ipv6Flow->srcAddr[0]);
    src[1] = htonll(ipv6Flow->srcAddr[1]);
    dst[0] = htonll(ipv6Flow->dstAddr[0]);
    dst[1] = htonll(ipv6Flow->dstAddr[1]);
    char sa[INET6_ADDRSTRLEN], da[INET6_ADDRSTRLEN];
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

static char *stringEXinterface(char *streamPtr, uint8_t *extensionRecord) {
    EXinterface_t *interface = (EXinterface_t *)extensionRecord;

    AddElementU32("input_snmp", interface->input);
    AddElementU32("output_snmp", interface->output);

    return streamPtr;
}  // End of stringEXinterface

static char *stringEXflowMisc(char *streamPtr, recordHandle_t *recordHandle, uint8_t *extensionRecord) {
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)extensionRecord;
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    char snet[INET6_ADDRSTRLEN], dnet[INET6_ADDRSTRLEN];

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

    AddElementU32("src_mask", flowMisc->srcMask);
    AddElementU32("dst_mask", flowMisc->dstMask);
    AddElementString("src_net", snet);
    AddElementString("dst_net", dnet);
    AddElementU32("direction", flowMisc->direction);
    AddElementU32("dst_tos", flowMisc->dstTos);

    return streamPtr;

}  // End of stringEXflowMisc

static char *stringEXipInfo(char *streamPtr, uint8_t *extensionRecord) {
    EXipInfo_t *ipInfo = (EXipInfo_t *)extensionRecord;

    if (ipInfo->fragmentFlags) {
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
    }
    if (ipInfo->minTTL || ipInfo->maxTTL) {
        AddElementU32("ip_minttl", (uint32_t)ipInfo->minTTL);
        AddElementU32("ip_maxttl", (uint32_t)ipInfo->maxTTL);
    }

    return streamPtr;
}  // End of stringEXipInfo

static char *stringEXcntFlow(char *streamPtr, uint8_t *extensionRecord) {
    EXcntFlow_t *cntFlow = (EXcntFlow_t *)extensionRecord;

    AddElementU64("out_packets", cntFlow->outPackets);
    AddElementU64("out_bytes", cntFlow->outBytes);
    AddElementU64("aggr_flows", cntFlow->flows);

    return streamPtr;
}  // End of stringEXcntFlow

static char *stringEXvLan(char *streamPtr, uint8_t *extensionRecord) {
    EXvLan_t *vLan = (EXvLan_t *)extensionRecord;

    AddElementU32("src_vlan", vLan->srcVlan);
    AddElementU32("dst_vlan", vLan->dstVlan);

    return streamPtr;
}  // End of stringEXvLan

static char *stringEXasInfo(char *streamPtr, recordHandle_t *recordHandle, uint8_t *extensionRecord) {
    EXasInfo_t *asInfo = (EXasInfo_t *)extensionRecord;
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    if (asInfo->srcAS == 0) asInfo->srcAS = ipv4Flow ? LookupV4AS(ipv4Flow->srcAddr) : LookupV6AS(ipv6Flow->srcAddr);
    if (asInfo->dstAS == 0) asInfo->dstAS = ipv4Flow ? LookupV4AS(ipv4Flow->dstAddr) : LookupV6AS(ipv6Flow->dstAddr);

    AddElementU32("src_as", asInfo->srcAS);
    AddElementU32("dst_as", asInfo->dstAS);

    return streamPtr;
}  // End of stringEXasInfo

static char *stringEXasRoutingV4(char *streamPtr, uint8_t *extensionRecord) {
    EXasRoutingV4_t *asRouting = (EXasRoutingV4_t *)extensionRecord;

    char ipStr[INET_ADDRSTRLEN];
    uint32_t ip = htonl(asRouting->nextHop);
    inet_ntop(AF_INET, &ip, ipStr, sizeof(ipStr));
    AddElementString("ip4_next_hop", ipStr);

    ip = htonl(asRouting->bgpNextHop);
    inet_ntop(AF_INET, &ip, ipStr, sizeof(ipStr));
    AddElementString("bgp4_next_hop", ipStr);

    return streamPtr;
}  // End of stringEXasRoutingV4

static char *stringEXasRoutingV6(char *streamPtr, uint8_t *extensionRecord) {
    EXasRoutingV6_t *asRouting = (EXasRoutingV6_t *)extensionRecord;

    char ipStr[INET6_ADDRSTRLEN];
    uint64_t ip[2];
    ip[0] = htonll(asRouting->nextHop[0]);
    ip[1] = htonll(asRouting->nextHop[1]);
    inet_ntop(AF_INET6, ip, ipStr, sizeof(ipStr));
    AddElementString("ip6_next_hop", ipStr);

    ip[0] = htonll(asRouting->bgpNextHop[0]);
    ip[1] = htonll(asRouting->bgpNextHop[1]);
    inet_ntop(AF_INET6, ip, ipStr, sizeof(ipStr));
    AddElementString("bgp6_next_hop", ipStr);

    return streamPtr;
}  // End of stringEXasRoutingV6

static char *stringEXipReceivedV4(char *streamPtr, uint8_t *extensionRecord) {
    EXipReceivedV4_t *ipReceivedV4 = (EXipReceivedV4_t *)extensionRecord;

    uint32_t i = htonl(ipReceivedV4->ip);
    char ip[INET6_ADDRSTRLEN];
    ip[0] = 0;
    inet_ntop(AF_INET, &i, ip, sizeof(ip));
    ip[INET6_ADDRSTRLEN - 1] = 0;

    AddElementString("ip4_router", ip);

    return streamPtr;
}  // End of stringEXipReceivedV4

static char *stringEXipReceivedV6(char *streamPtr, uint8_t *extensionRecord) {
    EXipReceivedV6_t *ipReceivedV6 = (EXipReceivedV6_t *)extensionRecord;

    uint64_t i[2];
    i[0] = htonll(ipReceivedV6->ip[0]);
    i[1] = htonll(ipReceivedV6->ip[1]);
    char ip[INET6_ADDRSTRLEN];
    ip[0] = 0;
    inet_ntop(AF_INET6, i, ip, sizeof(ip));
    ip[INET6_ADDRSTRLEN - 1] = 0;

    AddElementString("ip6_router", ip);

    return streamPtr;
}  // End of stringEXipReceivedV6

static char *stringEXmpls(char *streamPtr, uint8_t *extensionRecord) {
    EXmpls_t *mpls = (EXmpls_t *)extensionRecord;
    for (int i = 0; i < 10; i++) {
        ptrdiff_t lenStream = STREAMLEN(streamPtr);
        int len = snprintf(streamPtr, (size_t)lenStream, "  \"mpls_%u\" : \"%u-%u-%u\",\n", i + 1, mpls->label[i] >> 4, (mpls->label[i] & 0xF) >> 1,
                           mpls->label[i] & 1);
        streamPtr += len;
    }

    return streamPtr;
}  // End of stringEXmpls

static char *stringEXinMacAddr(char *streamPtr, uint8_t *extensionRecord) {
    EXinMacAddr_t *macAddr = (EXinMacAddr_t *)extensionRecord;

    uint8_t mac1[6], mac2[6];
    for (int i = 0; i < 6; i++) {
        mac1[i] = (macAddr->inSrcMac >> (i * 8)) & 0xFF;
        mac2[i] = (macAddr->outDstMac >> (i * 8)) & 0xFF;
    }

    ptrdiff_t lenStream = STREAMLEN(streamPtr);
    int len = snprintf(streamPtr, lenStream,
                       "  \"in_src_mac\" : \"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\",\n"
                       "  \"out_dst_mac\" : \"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\",\n",
                       mac1[5], mac1[4], mac1[3], mac1[2], mac1[1], mac1[0], mac2[5], mac2[4], mac2[3], mac2[2], mac2[1], mac2[0]);
    streamPtr += len;

    return streamPtr;
}  // End of stringEXinMacAddr

static char *stringEXoutMacAddr(char *streamPtr, uint8_t *extensionRecord) {
    EXoutMacAddr_t *macAddr = (EXoutMacAddr_t *)extensionRecord;

    uint8_t mac1[6], mac2[6];
    for (int i = 0; i < 6; i++) {
        mac1[i] = (macAddr->inDstMac >> (i * 8)) & 0xFF;
        mac2[i] = (macAddr->outSrcMac >> (i * 8)) & 0xFF;
    }

    ptrdiff_t lenStream = STREAMLEN(streamPtr);
    int len = snprintf(streamPtr, lenStream,
                       "  \"in_dst_mac\" : \"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\",\n"
                       "  \"out_src_mac\" : \"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\",\n",
                       mac1[5], mac1[4], mac1[3], mac1[2], mac1[1], mac1[0], mac2[5], mac2[4], mac2[3], mac2[2], mac2[1], mac2[0]);
    streamPtr += len;

    return streamPtr;
}  // End of stringEXoutMacAddr

static char *stringEXasAdjacent(char *streamPtr, uint8_t *extensionRecord) {
    EXasAdjacent_t *asAdjacent = (EXasAdjacent_t *)extensionRecord;

    AddElementU32("next_as", asAdjacent->nextAdjacentAS);
    AddElementU32("prev_as", asAdjacent->prevAdjacentAS);

    return streamPtr;
}  // End of stringEXasAdjacent

static char *stringEXlatency(char *streamPtr, uint8_t *extensionRecord) {
    EXlatency_t *latency = (EXlatency_t *)extensionRecord;

    ptrdiff_t lenStream = STREAMLEN(streamPtr);
    int len = snprintf(streamPtr, lenStream,
                       "\"cli_latency\":%llu,"
                       "\"srv_latency\":%llu,"
                       "\"app_latency\":%llu,",
                       latency->msecClientNwDelay, latency->msecServerNwDelay, latency->msecApplLatency);
    streamPtr += len;

    return streamPtr;
}  // End of stringEXlatency

static char *string_payload(char *streamPtr, payloadHandle_t *payloadHandle, const void *payload, uint32_t payloadSize, const char *prefix) {
    // payload handled in output json:
    // ssl, ja3, ja4

    ssl_t *ssl = payloadHandle->ssl;
    if (ssl == NULL) {
        ssl = sslProcess(payload, payloadSize);
        payloadHandle->ssl = ssl;
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
                len = snprintf(streamPtr, lenStream, "  \"%s_tls\" : SSL%c,\n", prefix, ssl->tlsCharVersion[1]);
                break;
            case '1':
                len = snprintf(streamPtr, lenStream, "  \"%s_tls\" : TLS1.%c,\n", prefix, ssl->tlsCharVersion[1]);
                break;
            default:
                len = snprintf(streamPtr, lenStream, "  \"%s_tls\" : 0x%4x,\n", prefix, ssl->tlsVersion);
                break;
        }
        streamPtr += len;

        if (ssl->sniName[0]) {
            char token[64];
            snprintf(token, 64, "%s_sni", prefix);
            AddElementString(token, ssl->sniName);
        }
    }

    char *ja3 = payloadHandle->ja3;
    if (ja3) {
        free(ja3);
        ja3 = NULL;
    }
    if (ja3 == NULL) {
        ja3 = ja3Process(ssl, NULL);
        payloadHandle->ja3 = ja3;
    }
    if (ja3) {
        char token[64];
        snprintf(token, 64, "%s_ja3 hash", prefix);
        AddElementString(token, ja3);
    }

    ja4_t *ja4 = payloadHandle->ja4;
    if (ja4) {
        free(ja4);
        ja4 = NULL;
    }
    if (ja4 == NULL) {
        if (ssl->type == CLIENTssl) {
            ja4 = ja4Process(ssl, IPPROTO_TCP);
        } else {
            ja4 = ja4sProcess(ssl, IPPROTO_TCP);
        }
        payloadHandle->ja4 = ja4;
    }
    if (ja4 == NULL) return streamPtr;

    // ja4 is defined
    if (ja4->type == TYPE_JA4) {
        char token[64];
        snprintf(token, 64, "%s_ja4 hash", prefix);
        AddElementString(token, ja4->string);
    } else {
        char token[64];
        snprintf(token, 64, "%s_ja4s hash", prefix);
        AddElementString("ja4s hash", ja4->string);
    }

    return streamPtr;
}  // End of string_payload

static char *string_Payload(char *streamPtr, recordHandle_t *recordHandle, uint8_t *extensionRecord, const char *prefix) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    EXPayload_t *payload = (EXPayload_t *)extensionRecord;
    uint32_t payloadSize = payload->size;

    if (genericFlow->proto != IPPROTO_TCP) {
        return streamPtr;
    }

    int slot = EXinPayloadHandle;
    if (prefix[0] == 'o') slot = EXoutPayloadHandle;

    payloadHandle_t *payloadHandle = NULL;
    payloadHandle = (payloadHandle_t *)recordHandle->extensionList[slot];
    if (payloadHandle == NULL) {
        payloadHandle = calloc(1, sizeof(payloadHandle_t));
        if (!payloadHandle) {
            LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            exit(EXIT_FAILURE);
        } else {
            recordHandle->extensionList[slot] = payloadHandle;
        }
    }
    return string_payload(streamPtr, payloadHandle, payload->payload, payloadSize, prefix);
}  // End of string_Payload

static char *stringEXtunnel(char *streamPtr, uint8_t *extensionRecord) {
    EXtunnel_t *tunnel = (EXtunnel_t *)extensionRecord;

    AddElementU32("tun_proto", tunnel->tunProto);

    char ipStr[INET_ADDRSTRLEN];
    const uint8_t prefix[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};
    if (memcmp(tunnel->tunSrcAddr, prefix, 12) == 0) {
        uint32_t ip;
        memcpy(&ip, tunnel->tunSrcAddr + 12, sizeof(uint32_t));
        ip = htonl(ip);
        inet_ntop(AF_INET, &ip, ipStr, sizeof(ipStr));
        AddElementString("src_tun_ip", ipStr);

        memcpy(&ip, tunnel->tunDstAddr + 12, sizeof(uint32_t));
        ip = htonl(ip);
        inet_ntop(AF_INET, &ip, ipStr, sizeof(ipStr));
        AddElementString("dst_tun_ip", ipStr);
    } else {
        uint64_t ip[2];
        ip[0] = htonll(tunnel->tunSrcAddr[0]);
        ip[1] = htonll(tunnel->tunSrcAddr[1]);
        inet_ntop(AF_INET6, ip, ipStr, sizeof(ipStr));
        AddElementString("src_tun_ip", ipStr);

        ip[0] = htonll(tunnel->tunDstAddr[0]);
        ip[1] = htonll(tunnel->tunDstAddr[1]);
        inet_ntop(AF_INET6, ip, ipStr, sizeof(ipStr));
        AddElementString("dst_tun_ip", ipStr);
    }

    return streamPtr;
}  // End of stringEXtunnel

static char *stringEXobservation(char *streamPtr, uint8_t *extensionRecord) {
    EXobservation_t *observation = (EXobservation_t *)extensionRecord;

    AddElementU32("observationDomainID", observation->domainID);
    AddElementU32("observationPointID", observation->pointID);

    return streamPtr;
}  // End of stringEXobservation

static char *stringEXvrf(char *streamPtr, uint8_t *extensionRecord) {
    EXvrf_t *vrf = (EXvrf_t *)extensionRecord;

    AddElementU32("ingress_vrf", vrf->ingressVrf);
    AddElementU32("egress_vrf", vrf->egressVrf);

    return streamPtr;
}  // End of stringEXvrf

static char *stringEXlayer2(char *streamPtr, uint8_t *extensionRecord) {
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

static char *stringEXnselCommon(char *streamPtr, uint8_t *extensionRecord) {
    EXnselCommon_t *nselCommon = (EXnselCommon_t *)extensionRecord;

    char datestr[64];
    time_t when = nselCommon->msecEvent / 1000LL;
    if (when == 0) {
        strncpy(datestr, "0000-00-00T00:00:00", 64);
    } else {
        struct tm ts_buf;
        struct tm *ts = localtime_r(&when, &ts_buf);
        strftime(datestr, 64, "%Y-%m-%dT%H:%M:%S", ts);
    }

    if (nselCommon->fwEvent) {
        AddElementU32("connect_id", nselCommon->connID);
        AddElementU32("event_id", nselCommon->fwEvent);
        AddElementString("event", fwEventString(nselCommon->fwEvent));
        AddElementU32("xevent_id", nselCommon->fwXevent);
    }

    if (nselCommon->natEvent) {
        AddElementU32("nat_event_id", nselCommon->natEvent);
        AddElementString("nat_event", natEventString(nselCommon->natEvent, LONGNAME));
        AddElementU32("nat_pool_id", nselCommon->natPoolID);
    }
    ptrdiff_t lenStream = STREAMLEN(streamPtr);
    int len = snprintf(streamPtr, lenStream, "  \"t_event\" : \"%s.%llu\",\n", datestr, nselCommon->msecEvent % 1000LL);
    streamPtr += len;

    return streamPtr;
}  // End of stringEXnselCommon

static char *stringEXnatXlateV4(char *streamPtr, uint8_t *extensionRecord) {
    EXnatXlateV4_t *natXlate = (EXnatXlateV4_t *)extensionRecord;

    char ipStr[INET_ADDRSTRLEN];
    uint32_t ip = natXlate->xlateSrcAddr;
    ip = htonl(ip);
    inet_ntop(AF_INET, &ip, ipStr, sizeof(ipStr));
    AddElementString("src_xlate_ip", ipStr);

    ip = natXlate->xlateDstAddr;
    ip = htonl(ip);
    inet_ntop(AF_INET, &ip, ipStr, sizeof(ipStr));
    AddElementString("dst_xlate_ip", ipStr);

    return streamPtr;
}  // End of stringEXnatXlateV4

static char *stringEXnatXlateV6(char *streamPtr, uint8_t *extensionRecord) {
    EXnatXlateV6_t *natXlate = (EXnatXlateV6_t *)extensionRecord;

    char ipStr[INET6_ADDRSTRLEN];

    uint64_t ip[2];
    ip[0] = htonll(natXlate->xlateSrcAddr[0]);
    ip[1] = htonll(natXlate->xlateSrcAddr[1]);
    inet_ntop(AF_INET6, ip, ipStr, sizeof(ipStr));
    AddElementString("src_xlate_ip", ipStr);

    ip[0] = htonll(natXlate->xlateDstAddr[0]);
    ip[1] = htonll(natXlate->xlateDstAddr[1]);
    inet_ntop(AF_INET6, ip, ipStr, sizeof(ipStr));
    AddElementString("dst_xlate_ip", ipStr);

    return streamPtr;
}  // End of stringEXnatXlateV6

static char *stringEXnatXlatePort(char *streamPtr, uint8_t *extensionRecord) {
    EXnatXlatePort_t *natXlate = (EXnatXlatePort_t *)extensionRecord;

    AddElementU32("src_xlt_port", natXlate->xlateSrcPort);
    AddElementU32("dst_xlt_port", natXlate->xlateDstPort);

    return streamPtr;
}  // End of stringEXnatXlatePort

static char *stringEXnselAcl(char *streamPtr, uint8_t *extensionRecord) {
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

static char *stringEXnselUserID(char *streamPtr, uint8_t *extensionRecord) {
    EXnselUser_t *nselUser = (EXnselUser_t *)extensionRecord;

    char *name = nselUser->username[0] ? nselUser->username : "<empty>";
    AddElementString("user_name", name);

    return streamPtr;
}  // End of stringEXnselUserID

static char *stringEXnatPortBlock(char *streamPtr, uint8_t *extensionRecord) {
    EXnatPortBlock_t *natPortBlock = (EXnatPortBlock_t *)extensionRecord;

    AddElementU32("pblock_start", natPortBlock->blockStart);
    AddElementU32("pblock_end", natPortBlock->blockEnd);
    AddElementU32("pblock_step", natPortBlock->blockStep);
    AddElementU32("pblock_size", natPortBlock->blockSize);

    return streamPtr;
}  // End of stringEXnatPortBlock

static char *stringEXflowId(char *streamPtr, uint8_t *extensionRecord) {
    EXflowId_t *flowId = (EXflowId_t *)extensionRecord;

    AddElementU64("flowID", flowId->flowId);

    return streamPtr;
}  // End of stringEXflowId

static char *stringEXnokiaNat(char *streamPtr, uint8_t *extensionRecord) {
    EXnokiaNat_t *nokiaNat = (EXnokiaNat_t *)extensionRecord;

    AddElementU32("inServiceID", nokiaNat->inServiceID);
    AddElementU32("inServiceID", nokiaNat->outServiceID);

    return streamPtr;
}  // End of String_inServiceID

static char *stringEXnokiaNatString(char *streamPtr, uint8_t *extensionRecord) {
    char *natString = (char *)extensionRecord;

    AddElementString("natString", natString);

    return streamPtr;
}  // End of String_natString

void ndjson_prolog(outputParams_t *outputParam) {
    (void)outputParam;
    streamBuff = malloc(STREAMBUFFSIZE);
    if (!streamBuff) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        exit(EXIT_FAILURE);
    }
    streamBuff[0] = '\0';

}  // End of ndjson_prolog

void ndjson_epilog(outputParams_t *outputParam) {
    (void)outputParam;
    free(streamBuff);
    streamBuff = NULL;
}  // End of ndjson_epilog

enum { FORMAT_NDJSON = 0, FORMAT_JSON };

void flow_record_to_ndjson(FILE *stream, recordHandle_t *recordHandle, outputParams_t *outputParam) {
    // ws is whitespace after object opening and before object closing {WS  WS}
    // indent is printed before each record for clarity if needed
    // fs is Field Separator
    // rs is Record Separator

    recordHeaderV4_t *recordHeaderV4 = recordHandle->recordHeaderV4;

    streamBuff[0] = '\0';
    char *streamPtr = streamBuff;

    *streamPtr++ = '{';

    char *typeString = TestFlag(recordHeaderV4->flags, V4_FLAG_EVENT) ? "EVENT" : "FLOW";
    AddElementU32("cnt", ++recordCount);
    AddElementString("type", typeString);
    if (outputParam->ident != NULL) AddElementString("ident", outputParam->ident);

    AddElementU32("export_sysid", recordHeaderV4->exporterID);

    // all based on recordBase
    uint8_t *recordBase = (uint8_t *)recordHeaderV4;

    // offset table
    uint16_t *offsetTable = (uint16_t *)(recordBase + sizeof(recordHeaderV4_t));

    // print extensions
    uint32_t slot = 0;
    uint32_t bitMap = recordHeaderV4->extBitmap;
    while (bitMap) {
        // find lowest set bit (ctz) in bitMap
        uint32_t type = __builtin_ctzll(bitMap);
        bitMap &= bitMap - 1;

        ptrdiff_t offset = offsetTable[slot];
        uint8_t *extension = recordBase + offset;

        switch (type) {
            case EXnull:
                break;
            case EXgenericFlowID:
                streamPtr = stringEXgenericFlow(streamPtr, extension);
                break;
            case EXipv4FlowID:
                streamPtr = stringEXipv4Flow(streamPtr, extension);
                break;
            case EXipv6FlowID:
                streamPtr = stringEXipv6Flow(streamPtr, extension);
                break;
            case EXinterfaceID:
                streamPtr = stringEXinterface(streamPtr, extension);
                break;
            case EXflowMiscID:
                streamPtr = stringEXflowMisc(streamPtr, recordHandle, extension);
                break;
            case EXcntFlowID:
                streamPtr = stringEXcntFlow(streamPtr, extension);
                break;
            case EXvLanID:
                streamPtr = stringEXvLan(streamPtr, extension);
                break;
            case EXasInfoID:
                streamPtr = stringEXasInfo(streamPtr, recordHandle, extension);
                break;
            case EXasRoutingV4ID:
                streamPtr = stringEXasRoutingV4(streamPtr, extension);
                break;
            case EXasRoutingV6ID:
                streamPtr = stringEXasRoutingV6(streamPtr, extension);
                break;
            case EXipReceivedV4ID:
                streamPtr = stringEXipReceivedV4(streamPtr, extension);
                break;
            case EXipReceivedV6ID:
                streamPtr = stringEXipReceivedV6(streamPtr, extension);
                break;
            case EXmplsID:
                streamPtr = stringEXmpls(streamPtr, extension);
                break;
            case EXinMacAddrID:
                streamPtr = stringEXinMacAddr(streamPtr, extension);
                break;
            case EXoutMacAddrID:
                streamPtr = stringEXoutMacAddr(streamPtr, extension);
                break;
            case EXasAdjacentID:
                streamPtr = stringEXasAdjacent(streamPtr, extension);
                break;
            case EXlatencyID:
                streamPtr = stringEXlatency(streamPtr, extension);
                break;
            case EXinPayloadID:
                streamPtr = string_Payload(streamPtr, recordHandle, extension, "in");
                break;
            case EXoutPayloadID:
                streamPtr = string_Payload(streamPtr, recordHandle, extension, "out");
                break;
            case EXtunnelID:
                streamPtr = stringEXtunnel(streamPtr, extension);
                break;
            case EXobservationID:
                streamPtr = stringEXobservation(streamPtr, extension);
                break;
            case EXvrfID:
                streamPtr = stringEXvrf(streamPtr, extension);
                break;
            case EXlayer2ID:
                streamPtr = stringEXlayer2(streamPtr, extension);
                break;
            case EXnselCommonID:
                streamPtr = stringEXnselCommon(streamPtr, extension);
                break;
            case EXnatXlateV4ID:
                streamPtr = stringEXnatXlateV4(streamPtr, extension);
                break;
            case EXnatXlateV6ID:
                streamPtr = stringEXnatXlateV6(streamPtr, extension);
                break;
            case EXnatXlatePortID:
                streamPtr = stringEXnatXlatePort(streamPtr, extension);
                break;
            case EXnselAclID:
                streamPtr = stringEXnselAcl(streamPtr, extension);
                break;
            case EXnselUserID:
                streamPtr = stringEXnselUserID(streamPtr, extension);
                break;
            case EXnatPortBlockID:
                streamPtr = stringEXnatPortBlock(streamPtr, extension);
                break;
            case EXflowIdID:
                streamPtr = stringEXflowId(streamPtr, extension);
                break;
            case EXnokiaNatID:
                streamPtr = stringEXnokiaNat(streamPtr, extension);
                break;
            case EXnokiaNatStringID:
                streamPtr = stringEXnokiaNatString(streamPtr, extension);
                break;
            case EXipInfoID:
                streamPtr = stringEXipInfo(streamPtr, extension);
                break;
            default:
                dbg_printf("Extension %i not yet implemented\n", type);
        }
    }

    // Close out JSON record
    AddElementU32("sampled", TestFlag(recordHeaderV4->flags, V4_FLAG_SAMPLED) ? 1 : 0);

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
