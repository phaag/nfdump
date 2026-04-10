/*
 *  Copyright (c) 2019-2025, Peter Haag
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

#include "output_raw.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include "config.h"
#include "dns/codec.h"
#include "dns/dns.h"
#include "exporter.h"
#include "ifvrf.h"
#include "ja3/ja3.h"
#include "ja4/ja4.h"
#include "logging.h"
#include "maxmind/maxmind.h"
#include "nbar.h"
#include "nfdump.h"
#include "nffileV3/nffileV3.h"
#include "nfxV4.h"
#include "output_util.h"
#include "payload/dns/output_dns.h"
#include "ssl/ssl.h"
#include "tor/tor.h"
#include "userio.h"
#include "util.h"

// record counter
static uint32_t recordCount;

static void stringEXgenericFlow(FILE *stream, recordHandle_t *recordHandle, uint8_t *extensionRecord) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)extensionRecord;

    char datestr1[64], datestr2[64], datestr3[64];

    if (TestFlag(recordHandle->recordHeaderV4->flags, V4_FLAG_EVENT)) {
        EXnselCommon_t *nselCommon = (EXnselCommon_t *)recordHandle->extensionList[EXnselCommonID];
        uint64_t eventTime = genericFlow->msecFirst;
        if (nselCommon && nselCommon->msecEvent) eventTime = nselCommon->msecEvent;
        time_t when = eventTime / 1000LL;
        if (when == 0) {
            strncpy(datestr1, "0000-00-00 00:00:00", 63);
        } else {
            struct tm ts_buf;
            struct tm *ts = localtime_r(&when, &ts_buf);
            strftime(datestr1, 63, "%Y-%m-%d %H:%M:%S", ts);
        }
        fprintf(stream, "  Event time   =      %13llu [%s.%03llu]\n", (long long unsigned)eventTime, datestr1, eventTime % 1000LL);

    } else {
        time_t when = genericFlow->msecFirst / 1000LL;
        if (when == 0) {
            strncpy(datestr1, "0000-00-00 00:00:00", 63);
        } else {
            struct tm ts_buf;
            struct tm *ts = localtime_r(&when, &ts_buf);
            strftime(datestr1, 63, "%Y-%m-%d %H:%M:%S", ts);
        }

        when = genericFlow->msecLast / 1000LL;
        if (when == 0) {
            strncpy(datestr2, "0000-00-00 00:00:00", 63);
        } else {
            struct tm ts_buf;
            struct tm *ts = localtime_r(&when, &ts_buf);
            strftime(datestr2, 63, "%Y-%m-%d %H:%M:%S", ts);
        }

        fprintf(stream,
                "  first        =      %13llu [%s.%03llu]\n"
                "  last         =      %13llu [%s.%03llu]\n",
                (long long unsigned)genericFlow->msecFirst, datestr1, genericFlow->msecFirst % 1000LL, (long long unsigned)genericFlow->msecLast,
                datestr2, genericFlow->msecLast % 1000LL);
    }

    if (genericFlow->msecReceived) {
        time_t when = genericFlow->msecReceived / 1000LL;
        struct tm ts_buf;
        struct tm *ts = localtime_r(&when, &ts_buf);
        strftime(datestr3, 63, "%Y-%m-%d %H:%M:%S", ts);
    } else {
        datestr3[0] = '0';
        datestr3[1] = '\0';
    }

    fprintf(stream,
            "  received at  =      %13llu [%s.%03llu]\n"
            "  proto        =                %3u %s\n"
            "  tcp flags    =               0x%.2x %s\n",
            (long long unsigned)genericFlow->msecReceived, datestr3, (long long unsigned)genericFlow->msecReceived % 1000L, genericFlow->proto,
            ProtoString(genericFlow->proto, 0), genericFlow->proto == IPPROTO_TCP ? genericFlow->tcpFlags : 0,
            FlagsString(genericFlow->proto == IPPROTO_TCP ? genericFlow->tcpFlags : 0));

    if (genericFlow->proto == IPPROTO_ICMP || genericFlow->proto == IPPROTO_ICMPV6) {  // ICMP
        fprintf(stream, "  ICMP         =               %2u.%-2u type.code\n", genericFlow->icmpType, genericFlow->icmpCode);
    } else {
        fprintf(stream,
                "  src port     =              %5u\n"
                "  dst port     =              %5u\n"
                "  src tos      =                %3u\n"
                "  fwd status   =                %3u\n",
                genericFlow->srcPort, genericFlow->dstPort, genericFlow->srcTos, genericFlow->fwdStatus);
    }

    fprintf(stream,
            "  in packets   =         %10llu\n"
            "  in bytes     =         %10llu\n",
            (unsigned long long)genericFlow->inPackets, (unsigned long long)genericFlow->inBytes);

}  // End of EXgenericFlowID

static void stringEXtunIPv4(FILE *stream, EXtunnelV4_t *tunnel, EXgenericFlow_t *genericFlow) {
    char srcIPstr[INET_ADDRSTRLEN], dstIPstr[INET_ADDRSTRLEN];

    uint32_t ip;
    ip = htonl(tunnel->srcAddr);
    inet_ntop(AF_INET, &ip, srcIPstr, sizeof(srcIPstr));

    ip = htonl(tunnel->dstAddr);
    inet_ntop(AF_INET, &ip, dstIPstr, sizeof(dstIPstr));

    char sloc[128], dloc[128], stor[4], dtor[4];
    stor[0] = dtor[0] = '\0';
    if (genericFlow) {
        if (LookupV4Tor(tunnel->srcAddr, genericFlow->msecFirst, genericFlow->msecLast, stor + 1)) stor[0] = ' ';
        if (LookupV4Tor(tunnel->dstAddr, genericFlow->msecFirst, genericFlow->msecLast, dtor + 1)) dtor[0] = ' ';
    }
    LookupV4Location(tunnel->srcAddr, sloc, 128);
    LookupV4Location(tunnel->dstAddr, dloc, 128);
    fprintf(stream,
            "  tun proto    =                %3u %s\n"
            "  tun src addr =   %16s%s%s%s\n"
            "  tun dst addr =   %16s%s%s%s\n",
            tunnel->proto, ProtoString(tunnel->proto, 0), srcIPstr, strlen(sloc) ? ": " : "", sloc, stor, dstIPstr, strlen(dloc) ? ": " : "", dloc,
            dtor);

}  // End of stringEXtunIPv4

static void stringEXtunIPv6(FILE *stream, EXtunnelV6_t *tunnel, EXgenericFlow_t *genericFlow) {
    char srcIPstr[INET6_ADDRSTRLEN], dstIPstr[INET6_ADDRSTRLEN];

    uint64_t srcIP[2], dstIP[2];
    srcIP[0] = htonll(tunnel->srcAddr[0]);
    srcIP[1] = htonll(tunnel->srcAddr[1]);
    dstIP[0] = htonll(tunnel->dstAddr[0]);
    dstIP[1] = htonll(tunnel->dstAddr[1]);
    inet_ntop(AF_INET6, &srcIP, srcIPstr, sizeof(srcIPstr));
    inet_ntop(AF_INET6, &dstIP, dstIPstr, sizeof(dstIPstr));

    char sloc[128], dloc[128], stor[4], dtor[4];
    stor[0] = dtor[0] = '\0';
    if (genericFlow) {
        if (LookupV6Tor((uint64_t *)tunnel->srcAddr, genericFlow->msecFirst, genericFlow->msecLast, stor + 1)) stor[0] = ' ';
        if (LookupV6Tor((uint64_t *)tunnel->dstAddr, genericFlow->msecFirst, genericFlow->msecLast, dtor + 1)) dtor[0] = ' ';
    }
    LookupV6Location((uint64_t *)tunnel->srcAddr, sloc, 128);
    LookupV6Location((uint64_t *)tunnel->dstAddr, dloc, 128);
    fprintf(stream,
            "  tun proto    =                %3u %s\n"
            "  tun src addr =   %16s%s%s%s\n"
            "  tun dst addr =   %16s%s%s%s\n",
            tunnel->proto, ProtoString(tunnel->proto, 0), srcIPstr, strlen(sloc) ? ": " : "", sloc, stor, dstIPstr, strlen(dloc) ? ": " : "", dloc,
            dtor);

}  // End of stringEXtunIPv6

static void stringsEXipv4Flow(FILE *stream, recordHandle_t *recordHandle, uint8_t *extensionRecord) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)extensionRecord;
    EXtunnelV4_t *tunV4 = (EXtunnelV4_t *)recordHandle->extensionList[EXtunnelV4ID];
    EXtunnelV6_t *tunV6 = (EXtunnelV6_t *)recordHandle->extensionList[EXtunnelV6ID];
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];

    if (tunV4) {
        stringEXtunIPv4(stream, tunV4, genericFlow);
    } else if (tunV6) {
        stringEXtunIPv6(stream, tunV6, genericFlow);
    }

    uint32_t src = htonl(ipv4Flow->srcAddr);
    uint32_t dst = htonl(ipv4Flow->dstAddr);

    char as[INET6_ADDRSTRLEN], ds[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &src, as, sizeof(as));
    inet_ntop(AF_INET, &dst, ds, sizeof(ds));

    char sloc[128], dloc[128], stor[4], dtor[4];
    stor[0] = dtor[0] = '\0';
    if (genericFlow) {
        if (LookupV4Tor(ipv4Flow->srcAddr, genericFlow->msecFirst, genericFlow->msecLast, stor + 1)) stor[0] = ' ';
        if (LookupV4Tor(ipv4Flow->dstAddr, genericFlow->msecFirst, genericFlow->msecLast, dtor + 1)) dtor[0] = ' ';
    }
    LookupV4Location(ipv4Flow->srcAddr, sloc, 128);
    LookupV4Location(ipv4Flow->dstAddr, dloc, 128);
    fprintf(stream,
            "  src addr     =   %16s%s%s%s%s\n"
            "  dst addr     =   %16s%s%s%s%s\n",
            as, strlen(sloc) ? ": " : "", sloc, strlen(stor) ? " - " : "", stor, ds, strlen(dloc) ? ": " : "", dloc, strlen(dtor) ? " - " : "", dtor);

}  // End of stringsEXipv4Flow

static void stringsEXipv6Flow(FILE *stream, recordHandle_t *recordHandle, uint8_t *extensionRecord) {
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)extensionRecord;
    EXtunnelV4_t *tunV4 = (EXtunnelV4_t *)recordHandle->extensionList[EXtunnelV4ID];
    EXtunnelV6_t *tunV6 = (EXtunnelV6_t *)recordHandle->extensionList[EXtunnelV6ID];
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];

    if (tunV4) {
        stringEXtunIPv4(stream, tunV4, genericFlow);
    } else if (tunV6) {
        stringEXtunIPv6(stream, tunV6, genericFlow);
    }

    uint64_t src[2], dst[2];
    src[0] = htonll(ipv6Flow->srcAddr[0]);
    src[1] = htonll(ipv6Flow->srcAddr[1]);
    dst[0] = htonll(ipv6Flow->dstAddr[0]);
    dst[1] = htonll(ipv6Flow->dstAddr[1]);

    char as[INET6_ADDRSTRLEN], ds[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &src, as, sizeof(as));
    inet_ntop(AF_INET6, &dst, ds, sizeof(ds));

    char sloc[128], dloc[128], stor[4], dtor[4];
    stor[0] = dtor[0] = '\0';
    if (genericFlow) {
        if (LookupV6Tor(ipv6Flow->srcAddr, genericFlow->msecFirst, genericFlow->msecLast, stor + 1)) stor[0] = ' ';
        if (LookupV6Tor(ipv6Flow->dstAddr, genericFlow->msecFirst, genericFlow->msecLast, dtor + 1)) dtor[0] = ' ';
    }
    LookupV6Location(ipv6Flow->srcAddr, sloc, 128);
    LookupV6Location(ipv6Flow->dstAddr, dloc, 128);
    fprintf(stream,
            "  src addr     =   %16s%s%s%s\n"
            "  dst addr     =   %16s%s%s%s\n",
            as, strlen(sloc) ? ": " : "", sloc, stor, ds, strlen(dloc) ? ": " : "", dloc, dtor);

}  // End of stringsEXipv6Flow

static void stringsEXinterface(FILE *stream, recordHandle_t *recordHandle, uint8_t *extensionRecord) {
    (void)recordHandle;
    EXinterface_t *interface = (EXinterface_t *)extensionRecord;

    char ifInName[128];
    GetIfName(interface->input, ifInName, sizeof(ifInName));

    char ifOutName[128];
    GetIfName(interface->output, ifOutName, sizeof(ifOutName));

    fprintf(stream,
            "  input        =       %12u%s\n"
            "  output       =       %12u%s\n",
            interface->input, ifInName, interface->output, ifOutName);

}  // End of stringsEXinterface

static void stringsEXflowMisc(FILE *stream, recordHandle_t *recordHandle, uint8_t *extensionRecord) {
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)extensionRecord;
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    char snet[INET6_ADDRSTRLEN], dnet[INET6_ADDRSTRLEN];
    if (ipv4Flow) {
        // IPv4
        inet_ntop_mask(ipv4Flow->srcAddr, flowMisc->srcMask, snet, sizeof(snet));
        inet_ntop_mask(ipv4Flow->dstAddr, flowMisc->dstMask, dnet, sizeof(dnet));
    } else if (ipv6Flow) {
        // IPv6
        inet6_ntop_mask(ipv6Flow->srcAddr, flowMisc->srcMask, snet, sizeof(snet));
        inet6_ntop_mask(ipv6Flow->dstAddr, flowMisc->dstMask, dnet, sizeof(dnet));
    } else {
        snet[0] = '\0';
        dnet[0] = '\0';
    }

    fprintf(stream,
            "  src mask     =              %5u %s/%u\n"
            "  dst mask     =              %5u %s/%u\n"
            "  dst tos      =                %3u\n"
            "  direction    =                %3u\n"
            "  biFlow Dir   =               0x%.2x %s\n"
            "  end reason   =               0x%.2x %s\n",
            flowMisc->srcMask, snet, flowMisc->srcMask, flowMisc->dstMask, dnet, flowMisc->dstMask, flowMisc->dstTos, flowMisc->direction,
            flowMisc->biFlowDir, biFlowString(flowMisc->biFlowDir), flowMisc->flowEndReason, FlowEndString(flowMisc->flowEndReason));

}  // End of stringsEXflowMisc

static void stringEXipInfo(FILE *stream, uint8_t *extensionRecord) {
    EXipInfo_t *ipInfo = (EXipInfo_t *)extensionRecord;

    if (ipInfo->fragmentFlags) {
        char *DF = ipInfo->fragmentFlags & flagDF ? "DF" : "  ";
        char *MF = ipInfo->fragmentFlags & flagMF ? "MF" : "  ";
        fprintf(stream, "  ip fragment  =               0x%.2x %s %s\n", ipInfo->fragmentFlags, DF, MF);
    }
    if (ipInfo->minTTL || ipInfo->maxTTL) {
        fprintf(stream,
                "  ip minTTL    =              %5u\n"
                "  ip minTTL    =              %5u\n",
                ipInfo->minTTL, ipInfo->maxTTL);
    }
}  // End of stringEXcntFlow

static void stringsEXcntFlow(FILE *stream, uint8_t *extensionRecord) {
    EXcntFlow_t *cntFlow = (EXcntFlow_t *)extensionRecord;
    fprintf(stream,
            "  out packets  =         %10llu\n"
            "  out bytes    =         %10llu\n"
            "  aggr flows   =         %10llu\n",
            (long long unsigned)cntFlow->outPackets, (long long unsigned)cntFlow->outBytes, (long long unsigned)cntFlow->flows);

}  // End of stringEXcntFlow

static void stringsEXvLan(FILE *stream, uint8_t *extensionRecord) {
    EXvLan_t *vLan = (EXvLan_t *)extensionRecord;
    fprintf(stream,
            "  src vlan     =         %10u\n"
            "  dst vlan     =         %10u\n",
            vLan->srcVlan, vLan->dstVlan);

}  // End of stringsEXvLan

static void stringsEXasInfo(FILE *stream, recordHandle_t *recordHandle, uint8_t *extensionRecord) {
    EXasInfo_t *asInfo = (EXasInfo_t *)extensionRecord;
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    if (asInfo->srcAS == 0) asInfo->srcAS = ipv4Flow ? LookupV4AS(ipv4Flow->srcAddr) : LookupV6AS(ipv6Flow->srcAddr);
    if (asInfo->dstAS == 0) asInfo->dstAS = ipv4Flow ? LookupV4AS(ipv4Flow->dstAddr) : LookupV6AS(ipv6Flow->dstAddr);
    fprintf(stream,
            "  src as       =             %6u\n"
            "  dst as       =             %6u\n",
            asInfo->srcAS, asInfo->dstAS);

}  // End of stringsEXasInfo

static void stringsEXasRoutingV4(FILE *stream, uint8_t *extensionRecord) {
    EXasRoutingV4_t *asRoutingV4 = (EXasRoutingV4_t *)extensionRecord;

    uint32_t ip;
    ip = htonl(asRoutingV4->nextHop);
    char next_ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, next_ipStr, sizeof(next_ipStr));

    ip = htonl(asRoutingV4->bgpNextHop);
    char bgp_ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, bgp_ipStr, sizeof(bgp_ipStr));

    fprintf(stream,
            "  ip next hop  =   %16s\n"
            "  bgp next hop =   %16s\n",
            next_ipStr, bgp_ipStr);

}  // End of stringsEXbgpNextHopV4

static void stringsEXasRoutingV6(FILE *stream, uint8_t *extensionRecord) {
    EXasRoutingV6_t *asRoutingV6 = (EXasRoutingV6_t *)extensionRecord;

    uint64_t ip[2];
    ip[0] = htonll(asRoutingV6->nextHop[0]);
    ip[1] = htonll(asRoutingV6->nextHop[1]);
    char next_ipStr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ip, next_ipStr, sizeof(next_ipStr));

    ip[0] = htonll(asRoutingV6->bgpNextHop[0]);
    ip[1] = htonll(asRoutingV6->bgpNextHop[1]);
    char bgp_ipStr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ip, bgp_ipStr, sizeof(bgp_ipStr));

    fprintf(stream,
            "  ip next hop  =   %16s\n"
            "  bgp next hop =   %16s\n",
            next_ipStr, bgp_ipStr);

}  // End of stringsEXasRoutingV6

static void stringsEXipReceivedV4(FILE *stream, uint8_t *extensionRecord) {
    EXipReceivedV4_t *ipReceivedV4 = (EXipReceivedV4_t *)extensionRecord;

    uint32_t i = htonl(ipReceivedV4->ip);

    char ip[INET6_ADDRSTRLEN];
    ip[0] = 0;
    inet_ntop(AF_INET, &i, ip, sizeof(ip));
    ip[INET6_ADDRSTRLEN - 1] = 0;

    fprintf(stream, "  ip exporter  =   %16s\n", ip);

}  // End of stringsEXipReceivedV4

static void stringsEXipReceivedV6(FILE *stream, uint8_t *extensionRecord) {
    EXipReceivedV6_t *ipReceivedV6 = (EXipReceivedV6_t *)extensionRecord;

    uint64_t i[2];
    i[0] = htonll(ipReceivedV6->ip[0]);
    i[1] = htonll(ipReceivedV6->ip[1]);

    char ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, i, ip, sizeof(ip));
    ip[INET6_ADDRSTRLEN - 1] = 0;

    fprintf(stream, "  ip exporter  =   %16s\n", ip);

}  // End of stringsEXipReceivedV6

static void stringsEXmpls(FILE *stream, uint8_t *extensionRecord) {
    EXmpls_t *mpls = (EXmpls_t *)extensionRecord;
    for (int i = 0; i < 10; i++) {
        if (mpls->label[i] != 0) {
            fprintf(stream, "  MPLS Lbl %2u  =       %8u-%1u-%1u\n", i + 1, mpls->label[i] >> 4, (mpls->label[i] & 0xF) >> 1, mpls->label[i] & 1);
        }
    }

}  // End of stringsEXmplsLabel

static void stringsEXinMacAddr(FILE *stream, uint8_t *extensionRecord) {
    EXinMacAddr_t *macAddr = (EXinMacAddr_t *)extensionRecord;
    uint8_t mac1[6], mac2[6];

    for (int i = 0; i < 6; i++) {
        mac1[i] = (macAddr->inSrcMac >> (i * 8)) & 0xFF;
        mac2[i] = (macAddr->outDstMac >> (i * 8)) & 0xFF;
    }

    fprintf(stream,
            "  in src mac   =  %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n"
            "  out dst mac  =  %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
            mac1[5], mac1[4], mac1[3], mac1[2], mac1[1], mac1[0], mac2[5], mac2[4], mac2[3], mac2[2], mac2[1], mac2[0]);

}  // End of stringsEXinMacAddr

static void stringsEXoutMacAddr(FILE *stream, uint8_t *extensionRecord) {
    EXoutMacAddr_t *macAddr = (EXoutMacAddr_t *)extensionRecord;
    uint8_t mac1[6], mac2[6];

    for (int i = 0; i < 6; i++) {
        mac1[i] = (macAddr->inDstMac >> (i * 8)) & 0xFF;
        mac2[i] = (macAddr->outSrcMac >> (i * 8)) & 0xFF;
    }

    fprintf(stream,
            "  in dst mac   =  %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n"
            "  out src mac  =  %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
            mac1[5], mac1[4], mac1[3], mac1[2], mac1[1], mac1[0], mac2[5], mac2[4], mac2[3], mac2[2], mac2[1], mac2[0]);

}  // End of stringsEXoutMacAddr

static void stringsEXasAdjacent(FILE *stream, uint8_t *extensionRecord) {
    EXasAdjacent_t *asAdjacent = (EXasAdjacent_t *)extensionRecord;
    fprintf(stream,
            "  bgp next as  =              %5u\n"
            "  bgp prev as  =              %5u\n",
            asAdjacent->nextAdjacentAS, asAdjacent->prevAdjacentAS);

}  // End of stringsEXasAdjacent

static void stringsEXlatency(FILE *stream, uint8_t *extensionRecord) {
    EXlatency_t *latency = (EXlatency_t *)extensionRecord;

    double f1, f2, f3;
    f1 = (double)latency->msecClientNwDelay;
    f2 = (double)latency->msecServerNwDelay;
    f3 = (double)latency->msecApplLatency;

    fprintf(stream,
            "  cli latency  =          %9.3f ms\n"
            "  srv latency  =          %9.3f ms\n"
            "  app latency  =          %9.3f ms\n",
            f1, f2, f3);

}  // End of stringsEXlatency

static void stringsEXobservation(FILE *stream, uint8_t *extensionRecord) {
    EXobservation_t *observation = (EXobservation_t *)extensionRecord;
    fprintf(stream,
            "  obs domainID =            0x%05llx\n"
            "  obs pointID  =       0x%010llx\n",
            (long long unsigned)observation->domainID, (long long unsigned)observation->pointID);

}  // End of stringsEXobservation

static void stringsEXvrf(FILE *stream, uint8_t *extensionRecord) {
    EXvrf_t *vrf = (EXvrf_t *)extensionRecord;

    char vrfIngressName[128];
    GetVrfName(vrf->ingressVrf, vrfIngressName, sizeof(vrfIngressName));

    char vrfEgressName[128];
    GetVrfName(vrf->egressVrf, vrfEgressName, sizeof(vrfEgressName));

    fprintf(stream,
            "  ingress VRF  =         %10u%s\n"
            "  egress VRF   =         %10u%s\n",
            vrf->ingressVrf, vrfIngressName, vrf->egressVrf, vrfEgressName);

}  // End of stringsEXvrf

static void stringEXlayer2(FILE *stream, uint8_t *extensionRecord) {
    EXlayer2_t *layer2 = (EXlayer2_t *)extensionRecord;
    fprintf(stream,
            "  vlanID       =              %5u\n"
            "  post vlanID  =              %5u\n"
            "  custID       =              %5u\n"
            "  post custID  =              %5u\n"
            "  ingress IfID =         %10u\n"
            "  egress IfID  =         %10u\n"
            "  ethertype    =             0x%04x\n",
            layer2->vlanID, layer2->postVlanID, layer2->customerVlanId, layer2->postCustomerVlanId, layer2->ingress, layer2->egress,
            layer2->etherType);

    if (layer2->ipVersion) {
        fprintf(stream, "  IP version   =              %5u\n", layer2->ipVersion);
    }
}  // End of stringEXlayer2

static void stringsEXnselCommon(FILE *stream, uint8_t *extensionRecord) {
    EXnselCommon_t *nselCommon = (EXnselCommon_t *)extensionRecord;

    char datestr[64];
    time_t when = nselCommon->msecEvent / 1000LL;
    if (when == 0) {
        strncpy(datestr, "0000-00-00 00:00:00", 63);
    } else {
        struct tm ts_buf;
        struct tm *ts = localtime_r(&when, &ts_buf);
        strftime(datestr, 63, "%Y-%m-%d %H:%M:%S", ts);
    }
    if (nselCommon->fwEvent) {
        fprintf(stream,
                "  connect ID   =         %10u\n"
                "  fw event     =              %5u: %s\n"
                "  fw ext event =              %5u: %s\n"
                "  Event time   =      %13llu [%s.%03llu]\n",
                nselCommon->connID, nselCommon->fwEvent, fwEventString(nselCommon->fwEvent), nselCommon->fwXevent,
                fwXEventString(nselCommon->fwXevent), (long long unsigned)nselCommon->msecEvent, datestr,
                (long long unsigned)(nselCommon->msecEvent % 1000L));
    } else {
        fprintf(stream,
                "  Event time   =      %13llu [%s.%03llu]\n"
                "  nat event    =              %5u: %s\n"
                "  nat pool ID  =              %5u\n",
                (long long unsigned)nselCommon->msecEvent, datestr, (long long unsigned)(nselCommon->msecEvent % 1000L), nselCommon->natEvent,
                natEventString(nselCommon->natEvent, LONGNAME), nselCommon->natPoolID);
    }

}  // End of stringsEXnselCommon

static void stringsEXnatXlateV4(FILE *stream, uint8_t *extensionRecord) {
    EXnatXlateV4_t *natXlate = (EXnatXlateV4_t *)extensionRecord;

    char srcStr[INET_ADDRSTRLEN], dstStr[INET_ADDRSTRLEN];
    uint32_t src = natXlate->xlateSrcAddr;
    uint32_t dst = natXlate->xlateDstAddr;
    src = htonl(src);
    dst = htonl(dst);
    inet_ntop(AF_INET, &src, srcStr, sizeof(srcStr));
    inet_ntop(AF_INET, &dst, dstStr, sizeof(dstStr));

    fprintf(stream,
            "  src xlt ip   =   %16s\n"
            "  dst xlt ip   =   %16s\n",
            srcStr, dstStr);

}  // End of stringsEXnatXlateV4

static void stringsEXnatXlateV6(FILE *stream, uint8_t *extensionRecord) {
    EXnatXlateV6_t *natXlate = (EXnatXlateV6_t *)extensionRecord;

    char srcStr[INET6_ADDRSTRLEN], dstStr[INET6_ADDRSTRLEN];
    uint64_t src[2];
    uint64_t dst[2];
    src[0] = htonll(natXlate->xlateSrcAddr[0]);
    src[1] = htonll(natXlate->xlateSrcAddr[1]);
    dst[0] = htonll(natXlate->xlateDstAddr[0]);
    dst[1] = htonll(natXlate->xlateDstAddr[1]);
    inet_ntop(AF_INET6, src, srcStr, sizeof(srcStr));
    inet_ntop(AF_INET6, dst, dstStr, sizeof(dstStr));

    fprintf(stream,
            "  src xlt ip   =   %16s\n"
            "  dst xlt ip   =   %16s\n",
            srcStr, dstStr);

}  // End of stringsEXnatXlateV6

static void stringsEXnatXlatePort(FILE *stream, uint8_t *extensionRecord) {
    EXnatXlatePort_t *natXlate = (EXnatXlatePort_t *)extensionRecord;

    fprintf(stream,
            "  src xlt port =              %5u\n"
            "  dst xlt port =              %5u\n",
            natXlate->xlateSrcPort, natXlate->xlateDstPort);

}  // End of stringsEXnatXlatePort

static void stringsEXnselAcl(FILE *stream, uint8_t *extensionRecord) {
    EXnselAcl_t *nselAcl = (EXnselAcl_t *)extensionRecord;
    fprintf(stream,
            "  Ingress ACL  =        0x%x/0x%x/0x%x\n"
            "  Egress ACL   =        0x%x/0x%x/0x%x\n",
            nselAcl->ingressAcl[0], nselAcl->ingressAcl[1], nselAcl->ingressAcl[2], nselAcl->egressAcl[0], nselAcl->egressAcl[1],
            nselAcl->egressAcl[2]);

}  // End of stringsEXnselAcl

static void stringsEXnselUserID(FILE *stream, uint8_t *extensionRecord) {
    EXnselUser_t *nselUser = (EXnselUser_t *)extensionRecord;
    fprintf(stream, "  username     =        %s\n", nselUser->username);

}  // End of stringsEXnselUserID

static void stringsEXnatPortBlock(FILE *stream, uint8_t *extensionRecord) {
    EXnatPortBlock_t *natPortBlock = (EXnatPortBlock_t *)extensionRecord;
    fprintf(stream,
            "  pblock start =              %5u\n"
            "  pblock end   =              %5u\n"
            "  pblock step  =              %5u\n"
            "  pblock size  =              %5u\n",
            natPortBlock->blockStart, natPortBlock->blockEnd, natPortBlock->blockStep, natPortBlock->blockSize);

}  // End of stringsEXnatPortBlock

static void stringsEXnbarApp(FILE *stream, uint8_t *extensionRecord) {
    EXnbarApp_t *nbar = (EXnbarApp_t *)extensionRecord;
    uint32_t nbarAppIDlen = nbar->length;

    union {
        uint8_t val8[4];
        uint32_t val32;
    } pen;

    char nameBuff[256];
    char *name = GetNbarInfo(nbar->id, nbarAppIDlen, nameBuff);
    if (name == NULL) {
        name = "<no info>";
    }

    if (nbar->id[0] == 20) {  // PEN - private enterprise number
        pen.val8[0] = nbar->id[4];
        pen.val8[1] = nbar->id[3];
        pen.val8[2] = nbar->id[2];
        pen.val8[3] = nbar->id[1];

        unsigned selector = 0;
        unsigned index = 5;
        while (index < nbarAppIDlen) {
            selector = (selector << 8) | nbar->id[index];
            index++;
        }
        fprintf(stream, "  app ID       =              %2u..%u..%u: %s\n", nbar->id[0], pen.val32, selector, name);
    } else {
        unsigned selector = 0;
        unsigned index = 1;
        while (index < nbarAppIDlen) {
            selector = (selector << 8) | nbar->id[index];
            index++;
        }
        fprintf(stream, "  app ID       =              %2u..%u: %s\n", nbar->id[0], selector, name);
    }

}  // End of stringsEXnbarApp

static void inoutPayload(FILE *stream, recordHandle_t *recordHandle, payloadHandle_t *payloadHandle, uint8_t *payload, uint32_t length, char *prefix);

static void stringsEXinPayload(FILE *stream, recordHandle_t *recordHandle, uint8_t *extensionRecord) {
    EXinPayload_t *inPayload = (EXinPayload_t *)recordHandle->extensionList[EXinPayloadID];
    uint32_t payloadLength = inPayload->size;

    fprintf(stream, "  in payload   =         %10u\n", payloadLength);

    payloadHandle_t *payloadHandle = (payloadHandle_t *)recordHandle->extensionList[EXinPayloadHandle];
    if (!payloadHandle) {
        payloadHandle = calloc(1, sizeof(payloadHandle_t));
        if (!payloadHandle) {
            LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            exit(EXIT_FAILURE);
        } else {
            recordHandle->extensionList[EXinPayloadHandle] = payloadHandle;
        }
    }
    inoutPayload(stream, recordHandle, payloadHandle, inPayload->payload, payloadLength, "in");
}  // End of stringsEXinPayload

static void stringsEXoutPayload(FILE *stream, recordHandle_t *recordHandle, uint8_t *extensionRecord) {
    EXoutPayload_t *outPayload = (EXoutPayload_t *)recordHandle->extensionList[EXoutPayloadID];
    uint32_t payloadLength = outPayload->size;

    fprintf(stream, "  out payload  =         %10u\n", payloadLength);

    payloadHandle_t *payloadHandle = (payloadHandle_t *)recordHandle->extensionList[EXoutPayloadHandle];
    if (!payloadHandle) {
        payloadHandle = calloc(1, sizeof(payloadHandle_t));
        if (!payloadHandle) {
            LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            exit(EXIT_FAILURE);
        } else {
            recordHandle->extensionList[EXoutPayloadHandle] = payloadHandle;
        }
    }
    inoutPayload(stream, recordHandle, payloadHandle, outPayload->payload, payloadLength, "out");
}  // end of stringsExoutPayload

static void inoutPayload(FILE *stream, recordHandle_t *recordHandle, payloadHandle_t *payloadHandle, uint8_t *payload, uint32_t payloadLength,
                         char *prefix) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];

    if (genericFlow && (genericFlow->srcPort == 53 || genericFlow->dstPort == 53)) {
        void *dnsDecoded = payloadHandle->dns;
        if (dnsDecoded == NULL) {
            if (genericFlow->proto == IPPROTO_TCP) {
                dnsDecoded = dnsPayloadDecode(payload + 2, payloadLength - 2);
            } else {
                dnsDecoded = dnsPayloadDecode(payload, payloadLength);
            }
            payloadHandle->dns = dnsDecoded;
            dns_print_result(stream, (dns_query_t *)dnsDecoded);
        }
        return;
    }

    // ascii text can be printed as string incl. \n \r etc. nullBytes at the End of the string are allowed
    // otherwise DumpHex() the payload.
    int ascii = 1;
    unsigned nullBytes = 0;
    for (int i = 0; i < (int)payloadLength; i++) {
        if ((payload[i] < ' ' || payload[i] > '~') && payload[i] != '\n' && payload[i] != '\r' && payload[i] != 0x09) {
            if (payload[i] == '\0') {
                nullBytes++;
            } else {
                ascii = 0;
                break;
            }
        } else if (nullBytes) {
            ascii = 0;
            break;
        }
    }

    if (ascii) {
        fprintf(stream, "%.*s\n", payloadLength, payload);
    } else if (genericFlow->proto == IPPROTO_TCP) {
        ssl_t *ssl = payloadHandle->ssl;
        if (ssl == NULL) {
            ssl = sslProcess(payload, payloadLength);
            payloadHandle->ssl = ssl;
            if (ssl == NULL) {
                DumpHex(stream, payload, payloadLength);
                return;
            }
        }

        // ssl is defined
        switch (ssl->tlsCharVersion[0]) {
            case 's':
                fprintf(stream, "    TLS vers   =              SSL %c  \n", ssl->tlsCharVersion[1]);
                break;
            case '1':
                fprintf(stream, "    TLS vers   =            TLS 1.%c\n", ssl->tlsCharVersion[1]);
                break;
            default:
                fprintf(stream, "    TLS vers   =              0x%4x\n", ssl->tlsVersion);
                break;
        }

        if (ssl->sniName[0]) fprintf(stream, "    sni name   =  %s\n", ssl->sniName);

        char *ja3 = payloadHandle->ja3;
        if (ja3 == NULL) {
            ja3 = ja3Process(ssl, NULL);
            payloadHandle->ja3 = ja3;
        }
        if (ja3) {
            if (ssl->type == CLIENTssl) {
                fprintf(stream, "    ja3 hash   =  %s\n", ja3);
            } else {
                fprintf(stream, "    ja3s hash  =  %s\n", ja3);
            }
        }

        ja4_t *ja4 = payloadHandle->ja4;
        if (ja4 == NULL) {
            if (ssl->type == CLIENTssl) {
                ja4 = ja4Process(ssl, genericFlow->proto);
            } else {
                ja4 = ja4sProcess(ssl, genericFlow->proto);
            }
            payloadHandle->ja4 = ja4;
        }

        if (ja4) {
            if (ja4->type == TYPE_JA4)
                fprintf(stream, "    ja4 hash   =  %s\n", ja4->string);
            else
                fprintf(stream, "    ja4s hash  =  %s\n", ja4->string);
        }
    }

    DumpHex(stream, payload, payloadLength);
}  // End of inoutPayload

static void stringsEXpfinfo(FILE *stream, uint8_t *extensionRecord) {
    EXpfinfo_t *pfinfo = (EXpfinfo_t *)extensionRecord;

    fprintf(stream,
            "  pflog ifname =           %8s\n"
            "  pflog action =              %5s/%u\n"
            "  pflog reason =              %5s/%u\n"
            "  pflog direct =              %5s\n"
            "  pflog rulenr =              %5u\n",
            pfinfo->ifname, pfAction(pfinfo->action), pfinfo->action, pfReason(pfinfo->reason), pfinfo->reason, pfinfo->dir ? "in" : "out",
            pfinfo->rulenr);

}  // End of stringsEXpfinfo

static void stringsEXinmonMeta(FILE *stream, uint8_t *extensionRecord) {
    EXinmonMeta_t *inmon = (EXinmonMeta_t *)extensionRecord;
    fprintf(stream,
            "  inmon size   =              %5u\n"
            "  inmon type   =              %5u\n",
            inmon->frameSize, inmon->linkType);
}  // End of stringsEXinmonMeta

static void stringsEXinmonFrame(FILE *stream, uint8_t *extensionRecord) {
    EXinmonFrame_t *inmon = (EXinmonFrame_t *)extensionRecord;
    fprintf(stream, "  inmon frame  =              %5u\n", inmon->length);
}  // End of stringsEXinmonFrame

static void stringsEXflowId(FILE *stream, uint8_t *extensionRecord) {
    EXflowId_t *flowId = (EXflowId_t *)extensionRecord;
    fprintf(stream, "  flow ID      = %#18" PRIx64 "\n", flowId->flowId);
}  // End of stringsEXflowId

static void stringsEXnokiaNat(FILE *stream, uint8_t *extensionRecord) {
    EXnokiaNat_t *nokiaNat = (EXnokiaNat_t *)extensionRecord;
    fprintf(stream,
            "  inServiceID  =              %5u\n"
            "  outServiceID =              %5u\n",
            nokiaNat->inServiceID, nokiaNat->outServiceID);
}  // End of stringsEXnokiaNat

static void stringsEXnokiaNatString(FILE *stream, uint8_t *extensionRecord) {
    char *natString = (char *)extensionRecord;
    fprintf(stream, "  nat String   = %-19s\n", natString);
}  // End of stringsEXnokiaNatString

void raw_prolog(outputParams_t *outputParam) {
    // empty prolog
    recordCount = 0;
}  // End of raw_prolog

void raw_epilog(outputParams_t *outputParam) {
    // empty epilog
}  // End of raw_epilog

void raw_record(FILE *stream, recordHandle_t *recordHandle, outputParams_t *outputParam) {
    recordHeaderV4_t *recordHeaderV4 = recordHandle->recordHeaderV4;

    // all based on recordBase
    uint8_t *recordBase = (uint8_t *)recordHeaderV4;

    // offset table
    uint16_t *offsetTable = (uint16_t *)(recordBase + sizeof(recordHeaderV4_t));

    // Generate extension string
    uint64_t bitMap = recordHeaderV4->extBitmap;
    char elementString[recordHeaderV4->numExtensions * 5 + 1];  // if numExtensions == 0 -> '\0'
    elementString[0] = '\0';
    while (bitMap) {
        // find lowest set bit (ctz) in bitMap
        uint32_t type = __builtin_ctzll(bitMap);
        bitMap &= bitMap - 1;
        snprintf(elementString + strlen(elementString), sizeof(elementString) - strlen(elementString), "%u ", type);
    }

    char *type;
    char version[8];
    if (TestFlag(recordHeaderV4->flags, V4_FLAG_EVENT)) {
        type = "EVENT";
        version[0] = '\0';
    } else {
        uint8_t nfversion = recordHeaderV4->nfVersion;
        if (nfversion != 0) {
            snprintf(version, 8, " v%u", nfversion & 0x0F);
            if (nfversion & 0x80) {
                type = "SFLOW";
            } else if (nfversion & 0x40) {
                type = "PCAP";
            } else {
                type = "NETFLOW";
            }
        } else {
            // compat with previous versions
            type = "FLOW";
            version[0] = '\0';
        }
    }

    fprintf(stream,
            "\n"
            "Flow Record: \n"
            "  RecordCount  =              %5" PRIu64 "\n",
            recordHandle->flowCount);

    if (outputParam->ident) {
        fprintf(stream, "  Ident        =       %12s\n", outputParam->ident);
    }

    fprintf(stream,
            "  Flags        =               0x%.2x %s%s%s, %s\n"
            "  Elements     =            %5u/%u: %s\n"
            "  size         =              %5u\n"
            "  engine type  =              %5u\n"
            "  engine ID    =              %5u\n"
            "  export sysid =              %5u\n",
            recordHeaderV4->flags, type, version, TestFlag(recordHeaderV4->flags, V4_FLAG_ANON) ? " Anonymized" : "",
            TestFlag(recordHeaderV4->flags, V4_FLAG_SAMPLED) ? "Sampled" : "Unsampled", recordHeaderV4->numExtensions, recordHandle->slackElements,
            elementString, recordHeaderV4->size, recordHeaderV4->engineType, recordHeaderV4->engineID, recordHeaderV4->exporterID);

    if (recordHandle->extensionList[EXasInfoID] == NULL && outputParam->hasGeoDB) recordHandle->extensionList[EXasInfoID] = recordHandle->localStack;

    int doInputPayload = 0;
    int doOutputPayload = 0;
    // print extensions
    bitMap = recordHeaderV4->extBitmap;
    uint32_t slot = 0;
    while (bitMap) {
        // find lowest set bit (ctz) in bitMap
        uint32_t type = __builtin_ctzll(bitMap);
        bitMap &= bitMap - 1;

        ptrdiff_t offset = offsetTable[slot++];
        uint8_t *extension = recordBase + offset;

        switch (type) {
            case EXnull:
                break;
            case EXgenericFlowID:
                stringEXgenericFlow(stream, recordHandle, extension);
                break;
            case EXipv4FlowID:
                stringsEXipv4Flow(stream, recordHandle, extension);
                break;
            case EXipv6FlowID:
                stringsEXipv6Flow(stream, recordHandle, extension);
                break;
            case EXinterfaceID:
                stringsEXinterface(stream, recordHandle, extension);
                break;
            case EXflowMiscID:
                stringsEXflowMisc(stream, recordHandle, extension);
                break;
            case EXcntFlowID:
                stringsEXcntFlow(stream, extension);
                break;
            case EXvLanID:
                stringsEXvLan(stream, extension);
                break;
            case EXasInfoID:
                stringsEXasInfo(stream, recordHandle, extension);
                break;
            case EXasRoutingV4ID:
                stringsEXasRoutingV4(stream, extension);
                break;
            case EXasRoutingV6ID:
                stringsEXasRoutingV6(stream, extension);
                break;
            case EXipReceivedV4ID:
                stringsEXipReceivedV4(stream, extension);
                break;
            case EXipReceivedV6ID:
                stringsEXipReceivedV6(stream, extension);
                break;
            case EXmplsID:
                stringsEXmpls(stream, extension);
                break;
            case EXinMacAddrID:
                stringsEXinMacAddr(stream, extension);
                break;
            case EXoutMacAddrID:
                stringsEXoutMacAddr(stream, extension);
                break;
            case EXasAdjacentID:
                stringsEXasAdjacent(stream, extension);
                break;
            case EXlatencyID:
                stringsEXlatency(stream, extension);
                break;
            case EXobservationID:
                stringsEXobservation(stream, extension);
                break;
            case EXvrfID:
                stringsEXvrf(stream, extension);
                break;
            case EXlayer2ID:
                stringEXlayer2(stream, extension);
                break;
            case EXnselCommonID:
                stringsEXnselCommon(stream, extension);
                break;
            case EXnatXlateV4ID:
                stringsEXnatXlateV4(stream, extension);
                break;
            case EXnatXlateV6ID:
                stringsEXnatXlateV6(stream, extension);
                break;
            case EXnatXlatePortID:
                stringsEXnatXlatePort(stream, extension);
                break;
            case EXnselAclID:
                stringsEXnselAcl(stream, extension);
                break;
            case EXnselUserID:
                stringsEXnselUserID(stream, extension);
                break;
            case EXnatPortBlockID:
                stringsEXnatPortBlock(stream, extension);
                break;
            case EXnbarAppID:
                stringsEXnbarApp(stream, extension);
                break;
            case EXinPayloadID:
                doInputPayload = 1;
                break;
            case EXoutPayloadID:
                doOutputPayload = 1;
                break;
            case EXtunnelV4ID:
            case EXtunnelV6ID:
                break;
            case EXpfinfoID:
                stringsEXpfinfo(stream, extension);
                break;
            case EXinmonMetaID:
                stringsEXinmonMeta(stream, extension);
                break;
            case EXinmonFrameID:
                stringsEXinmonFrame(stream, extension);
                break;
            case EXflowIdID:
                stringsEXflowId(stream, extension);
                break;
            case EXnokiaNatID:
                stringsEXnokiaNat(stream, extension);
                break;
            case EXnokiaNatStringID:
                stringsEXnokiaNatString(stream, extension);
                break;
            case EXipInfoID:
                stringEXipInfo(stream, extension);
                break;
            default:
                dbg_printf("Extension %i not decoded\n", type);
        }
    }
    if (doInputPayload) stringsEXinPayload(stream, recordHandle, NULL);
    if (doOutputPayload) stringsEXoutPayload(stream, recordHandle, NULL);

}  // raw_record
