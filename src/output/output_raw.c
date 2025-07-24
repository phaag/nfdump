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
#include "maxmind/maxmind.h"
#include "nbar.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfxV3.h"
#include "output_util.h"
#include "payload/dns/output_dns.h"
#include "ssl/ssl.h"
#include "tor/tor.h"
#include "userio.h"
#include "util.h"

#define IP_STRING_LEN (INET6_ADDRSTRLEN)

// record counter
static uint32_t recordCount;

static void stringEXgenericFlow(FILE *stream, recordHandle_t *recordHandle, void *extensionRecord) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)extensionRecord;

    char datestr1[64], datestr2[64], datestr3[64];

    if (TestFlag(recordHandle->recordHeaderV3->flags, V3_FLAG_EVENT)) {
        EXnselCommon_t *nselCommon = (EXnselCommon_t *)recordHandle->extensionList[EXnselCommonID];
        EXnatCommon_t *natCommon = (EXnatCommon_t *)recordHandle->extensionList[EXnatCommonID];
        uint64_t eventTime = genericFlow->msecFirst;
        if (nselCommon && nselCommon->msecEvent) eventTime = nselCommon->msecEvent;
        if (natCommon && natCommon->msecEvent) eventTime = natCommon->msecEvent;
        time_t when = eventTime / 1000LL;
        if (when == 0) {
            strncpy(datestr1, "0000-00-00 00:00:00", 63);
        } else {
            struct tm *ts = localtime(&when);
            strftime(datestr1, 63, "%Y-%m-%d %H:%M:%S", ts);
        }
        fprintf(stream, "  Event time   =      %13llu [%s.%03llu]\n", (long long unsigned)eventTime, datestr1, eventTime % 1000LL);

    } else {
        time_t when = genericFlow->msecFirst / 1000LL;
        if (when == 0) {
            strncpy(datestr1, "0000-00-00 00:00:00", 63);
        } else {
            struct tm *ts = localtime(&when);
            strftime(datestr1, 63, "%Y-%m-%d %H:%M:%S", ts);
        }

        when = genericFlow->msecLast / 1000LL;
        if (when == 0) {
            strncpy(datestr2, "0000-00-00 00:00:00", 63);
        } else {
            struct tm *ts = localtime(&when);
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
        struct tm *ts = localtime(&when);
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

static void stringEXtunIPv4(FILE *stream, EXtunIPv4_t *tunIPv4, EXgenericFlow_t *genericFlow) {
    char as[IP_STRING_LEN], ds[IP_STRING_LEN];

    uint32_t src = htonl(tunIPv4->tunSrcAddr);
    uint32_t dst = htonl(tunIPv4->tunDstAddr);
    inet_ntop(AF_INET, &src, as, sizeof(as));
    inet_ntop(AF_INET, &dst, ds, sizeof(ds));

    char sloc[128], dloc[128], stor[4], dtor[4];
    stor[0] = dtor[0] = '\0';
    if (genericFlow) {
        if (LookupV4Tor(tunIPv4->tunSrcAddr, genericFlow->msecFirst, genericFlow->msecLast, stor + 1)) stor[0] = ' ';
        if (LookupV4Tor(tunIPv4->tunDstAddr, genericFlow->msecFirst, genericFlow->msecLast, dtor + 1)) dtor[0] = ' ';
    }
    LookupV4Location(tunIPv4->tunSrcAddr, sloc, 128);
    LookupV4Location(tunIPv4->tunDstAddr, dloc, 128);
    fprintf(stream,
            "  tun proto    =                %3u %s\n"
            "  tun src addr =   %16s%s%s%s\n"
            "  tun dst addr =   %16s%s%s%s\n",
            tunIPv4->tunProto, ProtoString(tunIPv4->tunProto, 0), as, strlen(sloc) ? ": " : "", sloc, stor, ds, strlen(dloc) ? ": " : "", dloc, dtor);

}  // End of stringEXtunIPv4

static void stringEXtunIPv6(FILE *stream, EXtunIPv6_t *tunIPv6, EXgenericFlow_t *genericFlow) {
    char as[IP_STRING_LEN], ds[IP_STRING_LEN];

    uint64_t src[2], dst[2];
    src[0] = htonll(tunIPv6->tunSrcAddr[0]);
    src[1] = htonll(tunIPv6->tunSrcAddr[1]);
    dst[0] = htonll(tunIPv6->tunDstAddr[0]);
    dst[1] = htonll(tunIPv6->tunDstAddr[1]);
    inet_ntop(AF_INET6, &src, as, sizeof(as));
    inet_ntop(AF_INET6, &dst, ds, sizeof(ds));

    char sloc[128], dloc[128], stor[4], dtor[4];
    stor[0] = dtor[0] = '\0';
    if (genericFlow) {
        if (LookupV6Tor(tunIPv6->tunSrcAddr, genericFlow->msecFirst, genericFlow->msecLast, stor + 1)) stor[0] = ' ';
        if (LookupV6Tor(tunIPv6->tunDstAddr, genericFlow->msecFirst, genericFlow->msecLast, dtor + 1)) dtor[0] = ' ';
    }
    LookupV6Location(tunIPv6->tunSrcAddr, sloc, 128);
    LookupV6Location(tunIPv6->tunDstAddr, dloc, 128);
    fprintf(stream,
            "  tun proto    =                %3u %s\n"
            "  tun src addr =   %16s%s%s%s\n"
            "  tun dst addr =   %16s%s%s%s\n",
            tunIPv6->tunProto, ProtoString(tunIPv6->tunProto, 0), as, strlen(sloc) ? ": " : "", sloc, stor, ds, strlen(dloc) ? ": " : "", dloc, dtor);

}  // End of stringEXtunIPv6

static void stringsEXipv4Flow(FILE *stream, recordHandle_t *recordHandle, void *extensionRecord) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)extensionRecord;
    EXtunIPv4_t *tunIPv4 = (EXtunIPv4_t *)recordHandle->extensionList[EXtunIPv4ID];
    EXtunIPv6_t *tunIPv6 = (EXtunIPv6_t *)recordHandle->extensionList[EXtunIPv6ID];
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];

    if (tunIPv4)
        stringEXtunIPv4(stream, tunIPv4, genericFlow);
    else if (tunIPv6)
        stringEXtunIPv6(stream, tunIPv6, genericFlow);

    uint32_t src = htonl(ipv4Flow->srcAddr);
    uint32_t dst = htonl(ipv4Flow->dstAddr);

    char as[IP_STRING_LEN], ds[IP_STRING_LEN];
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

static void stringsEXipv6Flow(FILE *stream, recordHandle_t *recordHandle, void *extensionRecord) {
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)extensionRecord;
    EXtunIPv4_t *tunIPv4 = (EXtunIPv4_t *)recordHandle->extensionList[EXtunIPv4ID];
    EXtunIPv6_t *tunIPv6 = (EXtunIPv6_t *)recordHandle->extensionList[EXtunIPv6ID];
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];

    if (tunIPv4)
        stringEXtunIPv4(stream, tunIPv4, genericFlow);
    else if (tunIPv4)
        stringEXtunIPv6(stream, tunIPv6, genericFlow);

    uint64_t src[2], dst[2];
    src[0] = htonll(ipv6Flow->srcAddr[0]);
    src[1] = htonll(ipv6Flow->srcAddr[1]);
    dst[0] = htonll(ipv6Flow->dstAddr[0]);
    dst[1] = htonll(ipv6Flow->dstAddr[1]);

    char as[IP_STRING_LEN], ds[IP_STRING_LEN];
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

static void stringsEXflowMisc(FILE *stream, recordHandle_t *recordHandle, void *extensionRecord) {
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)extensionRecord;
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    char snet[IP_STRING_LEN], dnet[IP_STRING_LEN];
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

    char ifInName[128];
    GetIfName(flowMisc->input, ifInName, sizeof(ifInName));

    char ifOutName[128];
    GetIfName(flowMisc->output, ifOutName, sizeof(ifOutName));

    fprintf(stream,
            "  input        =       %12u%s\n"
            "  output       =       %12u%s\n"
            "  src mask     =              %5u %s/%u\n"
            "  dst mask     =              %5u %s/%u\n"
            "  dst tos      =                %3u\n"
            "  direction    =                %3u\n"
            "  biFlow Dir   =               0x%.2x %s\n"
            "  end reason   =               0x%.2x %s\n",
            flowMisc->input, ifInName, flowMisc->output, ifOutName, flowMisc->srcMask, snet, flowMisc->srcMask, flowMisc->dstMask, dnet,
            flowMisc->dstMask, flowMisc->dstTos, flowMisc->dir, flowMisc->biFlowDir, biFlowString(flowMisc->biFlowDir), flowMisc->flowEndReason,
            FlowEndString(flowMisc->flowEndReason));

}  // End of stringsEXflowMisc

static void stringEXipInfo(FILE *stream, void *extensionRecord) {
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

static void stringsEXcntFlow(FILE *stream, void *extensionRecord) {
    EXcntFlow_t *cntFlow = (EXcntFlow_t *)extensionRecord;
    fprintf(stream,
            "  out packets  =         %10llu\n"
            "  out bytes    =         %10llu\n"
            "  aggr flows   =         %10llu\n",
            (long long unsigned)cntFlow->outPackets, (long long unsigned)cntFlow->outBytes, (long long unsigned)cntFlow->flows);

}  // End of stringEXcntFlow

static void stringsEXvLan(FILE *stream, void *extensionRecord) {
    EXvLan_t *vLan = (EXvLan_t *)extensionRecord;
    fprintf(stream,
            "  src vlan     =         %10u\n"
            "  dst vlan     =         %10u\n",
            vLan->srcVlan, vLan->dstVlan);

}  // End of stringsEXvLan

static void stringsEXasRouting(FILE *stream, recordHandle_t *recordHandle, void *extensionRecord) {
    EXasRouting_t *asRouting = (EXasRouting_t *)extensionRecord;
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    if (asRouting->srcAS == 0) asRouting->srcAS = ipv4Flow ? LookupV4AS(ipv4Flow->srcAddr) : LookupV6AS(ipv6Flow->srcAddr);
    if (asRouting->dstAS == 0) asRouting->dstAS = ipv4Flow ? LookupV4AS(ipv4Flow->dstAddr) : LookupV6AS(ipv6Flow->dstAddr);
    fprintf(stream,
            "  src as       =              %5u\n"
            "  dst as       =              %5u\n",
            asRouting->srcAS, asRouting->dstAS);

}  // End of stringsEXasRouting

static void stringsEXbgpNextHopV4(FILE *stream, void *extensionRecord) {
    EXbgpNextHopV4_t *bgpNextHopV4 = (EXbgpNextHopV4_t *)extensionRecord;

    uint32_t i = htonl(bgpNextHopV4->ip);
    char ip[IP_STRING_LEN];
    ip[0] = 0;
    inet_ntop(AF_INET, &i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    fprintf(stream, "  bgp next hop =   %16s\n", ip);

}  // End of stringsEXbgpNextHopV4

static void stringsEXbgpNextHopV6(FILE *stream, void *extensionRecord) {
    EXbgpNextHopV6_t *bgpNextHopV6 = (EXbgpNextHopV6_t *)extensionRecord;

    uint64_t i[2];
    i[0] = htonll(bgpNextHopV6->ip[0]);
    i[1] = htonll(bgpNextHopV6->ip[1]);

    char ip[IP_STRING_LEN];
    ip[0] = 0;
    inet_ntop(AF_INET6, i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    fprintf(stream, "  bgp next hop =   %16s\n", ip);

}  // End of stringsEXbgpNextHopV6

static void stringsEXipNextHopV4(FILE *stream, void *extensionRecord) {
    EXipNextHopV4_t *ipNextHopV4 = (EXipNextHopV4_t *)extensionRecord;

    uint32_t i = htonl(ipNextHopV4->ip);

    char ip[IP_STRING_LEN];
    ip[0] = 0;
    inet_ntop(AF_INET, &i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    fprintf(stream, "  ip next hop  =   %16s\n", ip);

}  // End of stringsEXipNextHopV4

static void stringsEXipNextHopV6(FILE *stream, void *extensionRecord) {
    EXipNextHopV6_t *ipNextHopV6 = (EXipNextHopV6_t *)extensionRecord;

    uint64_t i[2];
    i[0] = htonll(ipNextHopV6->ip[0]);
    i[1] = htonll(ipNextHopV6->ip[1]);

    char ip[IP_STRING_LEN];
    inet_ntop(AF_INET6, i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    fprintf(stream, "  ip next hop  =   %16s\n", ip);

}  // End of stringsEXipNextHopV6

static void stringsEXipReceivedV4(FILE *stream, void *extensionRecord) {
    EXipReceivedV4_t *ipReceivedV4 = (EXipReceivedV4_t *)extensionRecord;

    uint32_t i = htonl(ipReceivedV4->ip);

    char ip[IP_STRING_LEN];
    ip[0] = 0;
    inet_ntop(AF_INET, &i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    fprintf(stream, "  ip exporter  =   %16s\n", ip);

}  // End of stringsEXipReceivedV4

static void stringsEXipReceivedV6(FILE *stream, void *extensionRecord) {
    EXipReceivedV6_t *ipReceivedV6 = (EXipReceivedV6_t *)extensionRecord;

    uint64_t i[2];
    i[0] = htonll(ipReceivedV6->ip[0]);
    i[1] = htonll(ipReceivedV6->ip[1]);

    char ip[IP_STRING_LEN];
    inet_ntop(AF_INET6, i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    fprintf(stream, "  ip exporter  =   %16s\n", ip);

}  // End of stringsEXipReceivedV6

static void stringsEXmplsLabel(FILE *stream, void *extensionRecord) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)extensionRecord;
    for (int i = 0; i < 10; i++) {
        if (mplsLabel->mplsLabel[i] != 0) {
            fprintf(stream, "  MPLS Lbl %2u  =       %8u-%1u-%1u\n", i + 1, mplsLabel->mplsLabel[i] >> 4, (mplsLabel->mplsLabel[i] & 0xF) >> 1,
                    mplsLabel->mplsLabel[i] & 1);
        }
    }

}  // End of stringsEXmplsLabel

static void stringsEXmacAddr(FILE *stream, void *extensionRecord) {
    EXmacAddr_t *macAddr = (EXmacAddr_t *)extensionRecord;
    uint8_t mac1[6], mac2[6], mac3[6], mac4[6];

    for (int i = 0; i < 6; i++) {
        mac1[i] = (macAddr->inSrcMac >> (i * 8)) & 0xFF;
        mac2[i] = (macAddr->outDstMac >> (i * 8)) & 0xFF;
        mac3[i] = (macAddr->inDstMac >> (i * 8)) & 0xFF;
        mac4[i] = (macAddr->outSrcMac >> (i * 8)) & 0xFF;
    }

    fprintf(stream,
            "  in src mac   =  %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n"
            "  out dst mac  =  %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n"
            "  in dst mac   =  %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n"
            "  out src mac  =  %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
            mac1[5], mac1[4], mac1[3], mac1[2], mac1[1], mac1[0], mac2[5], mac2[4], mac2[3], mac2[2], mac2[1], mac2[0], mac3[5], mac3[4], mac3[3],
            mac3[2], mac3[1], mac3[0], mac4[5], mac4[4], mac4[3], mac4[2], mac4[1], mac4[0]);

}  // End of stringsEXmacAddr

static void stringsEXasAdjacent(FILE *stream, void *extensionRecord) {
    EXasAdjacent_t *asAdjacent = (EXasAdjacent_t *)extensionRecord;
    fprintf(stream,
            "  bgp next as  =              %5u\n"
            "  bgp prev as  =              %5u\n",
            asAdjacent->nextAdjacentAS, asAdjacent->prevAdjacentAS);

}  // End of stringsEXasAdjacent

static void stringsEXlatency(FILE *stream, void *extensionRecord) {
    EXlatency_t *latency = (EXlatency_t *)extensionRecord;

    double f1, f2, f3;
    f1 = (double)latency->usecClientNwDelay / 1000.0;
    f2 = (double)latency->usecServerNwDelay / 1000.0;
    f3 = (double)latency->usecApplLatency / 1000.0;

    fprintf(stream,
            "  cli latency  =          %9.3f ms\n"
            "  srv latency  =          %9.3f ms\n"
            "  app latency  =          %9.3f ms\n",
            f1, f2, f3);

}  // End of stringsEXlatency

static void stringsEXsampler(FILE *stream, void *extensionRecord) {
    EXsamplerInfo_t *samplerInfo = (EXsamplerInfo_t *)extensionRecord;

    uint16_t exporterID = samplerInfo->exporter_sysid;

    exporter_t *exporter = GetExporterInfo(exporterID);
    if (exporter != NULL) {
        sampler_t *sampler = exporter->sampler;
        while (sampler) {
            if (sampler->record.id == samplerInfo->selectorID) break;
            sampler = sampler->next;
        }
        if (sampler != NULL) {
            fprintf(stream,
                    "  samplingID   =              %5llu\n"
                    "  pk Interval  =              %5u\n"
                    "  sp Interval  =              %5u\n",
                    (unsigned long long)samplerInfo->selectorID, sampler->record.packetInterval, sampler->record.spaceInterval);
        } else {
            fprintf(stream, "  samplingID   =              %5llu\n", (unsigned long long)samplerInfo->selectorID);
        }
    } else {
        fprintf(stream, "  samplingID   =              %5llu\n", (unsigned long long)samplerInfo->selectorID);
    }
}  // End of stringsEXsampler

static void stringsEXobservation(FILE *stream, void *extensionRecord) {
    EXobservation_t *observation = (EXobservation_t *)extensionRecord;
    fprintf(stream,
            "  obs domainID =          0x%05x\n"
            "  obs pointID  =       0x%010llx\n",
            observation->domainID, (long long unsigned)observation->pointID);

}  // End of stringsEXobservation

static void stringsEXvrf(FILE *stream, void *extensionRecord) {
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

static void stringEXlayer2(FILE *stream, void *extensionRecord) {
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

static void stringsEXnselCommon(FILE *stream, void *extensionRecord) {
    EXnselCommon_t *nselCommon = (EXnselCommon_t *)extensionRecord;

    char datestr[64];
    time_t when = nselCommon->msecEvent / 1000LL;
    if (when == 0) {
        strncpy(datestr, "0000-00-00 00:00:00", 63);
    } else {
        struct tm *ts = localtime(&when);
        strftime(datestr, 63, "%Y-%m-%d %H:%M:%S", ts);
    }
    fprintf(stream,
            "  connect ID   =         %10u\n"
            "  fw event     =              %5u: %s\n"
            "  fw ext event =              %5u: %s\n"
            "  Event time   =      %13llu [%s.%03llu]\n",
            nselCommon->connID, nselCommon->fwEvent, fwEventString(nselCommon->fwEvent), nselCommon->fwXevent, fwXEventString(nselCommon->fwXevent),
            (long long unsigned)nselCommon->msecEvent, datestr, (long long unsigned)(nselCommon->msecEvent % 1000L));

}  // End of stringsEXnselCommon

static void stringsEXnatXlateIPv4(FILE *stream, void *extensionRecord) {
    EXnatXlateIPv4_t *natXlateIPv4 = (EXnatXlateIPv4_t *)extensionRecord;

    uint32_t src = htonl(natXlateIPv4->xlateSrcAddr);
    uint32_t dst = htonl(natXlateIPv4->xlateDstAddr);
    char as[IP_STRING_LEN], ds[IP_STRING_LEN];
    inet_ntop(AF_INET, &src, as, sizeof(as));
    inet_ntop(AF_INET, &dst, ds, sizeof(ds));

    fprintf(stream,
            "  src xlt ip   =   %16s\n"
            "  dst xlt ip   =   %16s\n",
            as, ds);

}  // End of stringsEXnatXlateIPv4

static void stringsEXnatXlateIPv6(FILE *stream, void *extensionRecord) {
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

    fprintf(stream,
            "  src xlt ip   =   %16s\n"
            "  dst xlt ip   =   %16s\n",
            as, ds);

}  // End of stringsEXnatXlateIPv6

static void stringsEXnatXlatePort(FILE *stream, void *extensionRecord) {
    EXnatXlatePort_t *natXlatePort = (EXnatXlatePort_t *)extensionRecord;
    fprintf(stream,
            "  src xlt port =              %5u\n"
            "  dst xlt port =              %5u\n",
            natXlatePort->xlateSrcPort, natXlatePort->xlateDstPort);

}  // End of stringsEXnatXlatePort

static void stringsEXnselAcl(FILE *stream, void *extensionRecord) {
    EXnselAcl_t *nselAcl = (EXnselAcl_t *)extensionRecord;
    fprintf(stream,
            "  Ingress ACL  =        0x%x/0x%x/0x%x\n"
            "  Egress ACL   =        0x%x/0x%x/0x%x\n",
            nselAcl->ingressAcl[0], nselAcl->ingressAcl[1], nselAcl->ingressAcl[2], nselAcl->egressAcl[0], nselAcl->egressAcl[1],
            nselAcl->egressAcl[2]);

}  // End of stringsEXnselAcl

static void stringsEXnselUserID(FILE *stream, void *extensionRecord) {
    EXnselUser_t *nselUser = (EXnselUser_t *)extensionRecord;
    fprintf(stream, "  username     =        %s\n", nselUser->username);

}  // End of stringsEXnselUserID

static void stringsEXnatCommon(FILE *stream, void *extensionRecord) {
    EXnatCommon_t *natCommon = (EXnatCommon_t *)extensionRecord;
    fprintf(stream,
            "  nat event    =              %5u: %s\n"
            "  nat pool ID  =              %5u\n",
            natCommon->natEvent, natEventString(natCommon->natEvent, LONGNAME), natCommon->natPoolID);

}  // End of stringsEXnatCommon

static void stringsEXnatPortBlock(FILE *stream, void *extensionRecord) {
    EXnatPortBlock_t *natPortBlock = (EXnatPortBlock_t *)extensionRecord;
    fprintf(stream,
            "  pblock start =              %5u\n"
            "  pblock end   =              %5u\n"
            "  pblock step  =              %5u\n"
            "  pblock size  =              %5u\n",
            natPortBlock->blockStart, natPortBlock->blockEnd, natPortBlock->blockStep, natPortBlock->blockSize);

}  // End of stringsEXnatPortBlock

static void stringsEXnbarApp(FILE *stream, void *extensionRecord) {
    uint8_t *nbar = (uint8_t *)extensionRecord;
    uint32_t nbarAppIDlen = ExtensionLength(nbar);

    union {
        uint8_t val8[4];
        uint32_t val32;
    } pen;

    char *name = GetNbarInfo(nbar, nbarAppIDlen);
    if (name == NULL) {
        name = "<no info>";
    }

    if (nbar[0] == 20) {  // PEN - private enterprise number
        pen.val8[0] = nbar[4];
        pen.val8[1] = nbar[3];
        pen.val8[2] = nbar[2];
        pen.val8[3] = nbar[1];

        int selector = 0;
        int index = 5;
        while (index < nbarAppIDlen) {
            selector = (selector << 8) | nbar[index];
            index++;
        }
        fprintf(stream, "  app ID       =              %2u..%u..%u: %s\n", nbar[0], pen.val32, selector, name);
    } else {
        int selector = 0;
        int index = 1;
        while (index < nbarAppIDlen) {
            selector = (selector << 8) | nbar[index];
            index++;
        }
        fprintf(stream, "  app ID       =              %2u..%u: %s\n", nbar[0], selector, name);
    }

}  // End of stringsEXnbarApp

static void inoutPayload(FILE *stream, recordHandle_t *recordHandle, payloadHandle_t *payloadHandle, uint8_t *payload, uint32_t length, char *prefix);

static void stringsEXinPayload(FILE *stream, recordHandle_t *recordHandle, void *extensionRecord) {
    EXinPayload_t *inPayload = (EXinPayload_t *)recordHandle->extensionList[EXinPayloadID];
    uint32_t payloadLength = ExtensionLength(inPayload);

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
    inoutPayload(stream, recordHandle, payloadHandle, inPayload, payloadLength, "in");
}  // End of stringsEXinPayload

static void stringsEXoutPayload(FILE *stream, recordHandle_t *recordHandle, void *extensionRecord) {
    EXoutPayload_t *outPayload = (EXoutPayload_t *)recordHandle->extensionList[EXoutPayloadID];
    uint32_t payloadLength = ExtensionLength(outPayload);

    fprintf(stream, "  out payload  =         %10u\n", payloadLength);

    payloadHandle_t *payloadHandle = (payloadHandle_t *)recordHandle->extensionList[EXoutPayloadHandle];
    if (!payloadHandle) {
        payloadHandle = calloc(1, sizeof(payloadHandle_t));
        if (!payloadHandle) {
            LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            exit(EXIT_FAILURE);
        } else {
            recordHandle->extensionList[EXinPayloadHandle] = payloadHandle;
        }
    }
    inoutPayload(stream, recordHandle, payloadHandle, outPayload, payloadLength, "out");
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

    int ascii = 1;
    for (int i = 0; i < payloadLength; i++) {
        if ((payload[i] < ' ' || payload[i] > '~') && payload[i] != '\n' && payload[i] != '\r' && payload[i] != 0x09) {
            ascii = 0;
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

static void stringsEXpfinfo(FILE *stream, void *extensionRecord) {
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

static void stringsEXinmon(FILE *stream, void *extensionRecord) {
    EXinmonMeta_t *inmonMeta = (EXinmonMeta_t *)extensionRecord;
    fprintf(stream,
            "  inmon size   =              %5u\n"
            "  inmon type   =              %5u\n",
            inmonMeta->frameSize, inmonMeta->linkType);
}  // End of stringsEXinmon

static void stringsEXflowId(FILE *stream, void *extensionRecord) {
    EXflowId_t *flowId = (EXflowId_t *)extensionRecord;
    fprintf(stream, "  flow ID      = %#18" PRIx64 "\n", flowId->flowId);
}  // End of stringsEXflowId

static void stringsEXnokiaNat(FILE *stream, void *extensionRecord) {
    EXnokiaNat_t *nokiaNat = (EXnokiaNat_t *)extensionRecord;
    fprintf(stream,
            "  inServiceID  =              %5u\n"
            "  outServiceID =              %5u\n",
            nokiaNat->inServiceID, nokiaNat->outServiceID);
}  // End of stringsEXnokiaNat

static void stringsEXnokiaNatString(FILE *stream, void *extensionRecord) {
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
    recordHeaderV3_t *recordHeaderV3 = recordHandle->recordHeaderV3;

    char elementString[MAXEXTENSIONS * 5];

    elementString[0] = '\0';
    for (int i = 1; i < MAXEXTENSIONS; i++) {
        if (recordHandle->extensionList[i]) snprintf(elementString + strlen(elementString), sizeof(elementString) - strlen(elementString), "%u ", i);
    }

    char *type;
    char version[8];
    if (TestFlag(recordHeaderV3->flags, V3_FLAG_EVENT)) {
        type = "EVENT";
        version[0] = '\0';
    } else {
        uint8_t nfversion = recordHeaderV3->nfversion;
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
            "  Elements     =              %5u: %s\n"
            "  size         =              %5u\n"
            "  engine type  =              %5u\n"
            "  engine ID    =              %5u\n"
            "  export sysid =              %5u\n",
            recordHeaderV3->flags, type, version, TestFlag(recordHeaderV3->flags, V3_FLAG_ANON) ? " Anonymized" : "",
            TestFlag(recordHeaderV3->flags, V3_FLAG_SAMPLED) ? "Sampled" : "Unsampled", recordHeaderV3->numElements, elementString,
            recordHeaderV3->size, recordHeaderV3->engineType, recordHeaderV3->engineID, recordHeaderV3->exporterID);

    /* XXX
        if (r->label) {
            fprintf(stream, "  Label        =   %16s\n", r->label);
        }
    */

    int processed = 0;
    int doInputPayload = 0;
    int doOutputPayload = 0;
    for (int i = 0; i < MAXEXTENSIONS; i++) {
        if (processed == recordHeaderV3->numElements) break;
        if (recordHandle->extensionList[i] == NULL) continue;
        void *ptr = recordHandle->extensionList[i];
        switch (i) {
            case EXnull:
                if (ptr != recordHeaderV3) fprintf(stderr, "Found unexpected NULL extension \n");
                break;
            case EXgenericFlowID:
                stringEXgenericFlow(stream, recordHandle, ptr);
                break;
            case EXipv4FlowID:
                stringsEXipv4Flow(stream, recordHandle, ptr);
                break;
            case EXipv6FlowID:
                stringsEXipv6Flow(stream, recordHandle, ptr);
                break;
            case EXflowMiscID:
                stringsEXflowMisc(stream, recordHandle, ptr);
                break;
            case EXcntFlowID:
                stringsEXcntFlow(stream, ptr);
                break;
            case EXvLanID:
                stringsEXvLan(stream, ptr);
                break;
            case EXasRoutingID:
                stringsEXasRouting(stream, recordHandle, ptr);
                break;
            case EXbgpNextHopV4ID:
                stringsEXbgpNextHopV4(stream, ptr);
                break;
            case EXbgpNextHopV6ID:
                stringsEXbgpNextHopV6(stream, ptr);
                break;
            case EXipNextHopV4ID:
                stringsEXipNextHopV4(stream, ptr);
                break;
            case EXipNextHopV6ID:
                stringsEXipNextHopV6(stream, ptr);
                break;
            case EXipReceivedV4ID:
                stringsEXipReceivedV4(stream, ptr);
                break;
            case EXipReceivedV6ID:
                stringsEXipReceivedV6(stream, ptr);
                break;
            case EXmplsLabelID:
                stringsEXmplsLabel(stream, ptr);
                break;
            case EXmacAddrID:
                stringsEXmacAddr(stream, ptr);
                break;
            case EXasAdjacentID:
                stringsEXasAdjacent(stream, ptr);
                break;
            case EXlatencyID:
                stringsEXlatency(stream, ptr);
                break;
            case EXsamplerInfoID:
                stringsEXsampler(stream, ptr);
                break;
            case EXobservationID:
                stringsEXobservation(stream, ptr);
                break;
            case EXvrfID:
                stringsEXvrf(stream, ptr);
                break;
            case EXlayer2ID:
                stringEXlayer2(stream, ptr);
                break;
            case EXnselCommonID:
                stringsEXnselCommon(stream, ptr);
                break;
            case EXnatXlateIPv4ID:
                stringsEXnatXlateIPv4(stream, ptr);
                break;
            case EXnatXlateIPv6ID:
                stringsEXnatXlateIPv6(stream, ptr);
                break;
            case EXnatXlatePortID:
                stringsEXnatXlatePort(stream, ptr);
                break;
            case EXnselAclID:
                stringsEXnselAcl(stream, ptr);
                break;
            case EXnselUserID:
                stringsEXnselUserID(stream, ptr);
                break;
            case EXnatCommonID:
                stringsEXnatCommon(stream, ptr);
                break;
            case EXnatPortBlockID:
                stringsEXnatPortBlock(stream, ptr);
                break;
            case EXnbarAppID:
                stringsEXnbarApp(stream, ptr);
                break;
            case EXinPayloadID:
                doInputPayload = 1;
                break;
            case EXoutPayloadID:
                doOutputPayload = 1;
                break;
            case EXtunIPv4ID:
                break;
            case EXtunIPv6ID:
                break;
            case EXpfinfoID:
                stringsEXpfinfo(stream, ptr);
                break;
            case EXinmonMetaID:
                stringsEXinmon(stream, ptr);
                break;
            case EXflowIdID:
                stringsEXflowId(stream, ptr);
                break;
            case EXnokiaNatID:
                stringsEXnokiaNat(stream, ptr);
                break;
            case EXnokiaNatStringID:
                stringsEXnokiaNatString(stream, ptr);
                break;
            case EXipInfoID:
                stringEXipInfo(stream, ptr);
                break;
            default:
                dbg_printf("Extension %i not decoded\n", i);
        }
    }
    if (doInputPayload) stringsEXinPayload(stream, recordHandle, NULL);
    if (doOutputPayload) stringsEXoutPayload(stream, recordHandle, NULL);

}  // raw_record
