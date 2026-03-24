/*
 *  Copyright (c) 2024-2026, Peter Haag
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

#include "output_short.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include "config.h"
#include "logging.h"
#include "nfdump.h"
#include "nfxV4.h"
#include "userio.h"
#include "util.h"

typedef void (*funcPrintRecord_t)(FILE *, uint8_t *);

static char *FlagsString(uint16_t flags) {
    static char string[16];

    string[0] = flags & 128 ? 'C' : '.';  // Congestion window reduced -  CWR
    string[1] = flags & 64 ? 'E' : '.';   // ECN-Echo
    string[2] = flags & 32 ? 'U' : '.';   // Urgent
    string[3] = flags & 16 ? 'A' : '.';   // Ack
    string[4] = flags & 8 ? 'P' : '.';    // Push
    string[5] = flags & 4 ? 'R' : '.';    // Reset
    string[6] = flags & 2 ? 'S' : '.';    // Syn
    string[7] = flags & 1 ? 'F' : '.';    // Fin
    string[8] = '\0';

    return string;
}  // End of FlagsString

static void stringEXgenericFlow(FILE *stream, uint8_t *extension) {
    if (!extension) return;

    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)extension;
    char datestr1[64], datestr2[64], datestr3[64];
    struct tm ts_buf;
    struct tm *ts;
    time_t when = genericFlow->msecFirst / 1000LL;
    if (when == 0) {
        strncpy(datestr1, "<unknown>", 63);
    } else {
        ts = localtime_r(&when, &ts_buf);
        strftime(datestr1, 63, "%Y-%m-%d %H:%M:%S", ts);
    }

    when = genericFlow->msecLast / 1000LL;
    if (when == 0) {
        strncpy(datestr2, "<unknown>", 63);
    } else {
        ts = localtime_r(&when, &ts_buf);
        strftime(datestr2, 63, "%Y-%m-%d %H:%M:%S", ts);
    }

    if (genericFlow->msecReceived) {
        when = genericFlow->msecReceived / 1000LL;
        ts = localtime_r(&when, &ts_buf);
        strftime(datestr3, 63, "%Y-%m-%d %H:%M:%S", ts);
    } else {
        datestr3[0] = '0';
        datestr3[1] = '\0';
    }

    fprintf(stream,
            "  first        =     %13llu [%s.%03llu]\n"
            "  last         =     %13llu [%s.%03llu]\n"
            "  received at  =     %13llu [%s.%03llu]\n"
            "  proto        =               %3u %s\n"
            "  tcp flags    =              0x%.2x %s\n",
            (long long unsigned)genericFlow->msecFirst, datestr1, genericFlow->msecFirst % 1000LL, (long long unsigned)genericFlow->msecLast,
            datestr2, genericFlow->msecLast % 1000LL, (long long unsigned)genericFlow->msecReceived, datestr3,
            (long long unsigned)genericFlow->msecReceived % 1000L, genericFlow->proto, ProtoString(genericFlow->proto, 0),
            genericFlow->proto == IPPROTO_TCP ? genericFlow->tcpFlags : 0,
            FlagsString(genericFlow->proto == IPPROTO_TCP ? genericFlow->tcpFlags : 0));

    if (genericFlow->proto == IPPROTO_ICMP || genericFlow->proto == IPPROTO_ICMPV6) {  // ICMP
        fprintf(stream, "  ICMP         =              %2u.%-2u type.code\n", genericFlow->icmpType, genericFlow->icmpCode);
    } else {
        fprintf(stream,
                "  src port     =             %5u\n"
                "  dst port     =             %5u\n"
                "  src tos      =               %3u\n",
                genericFlow->srcPort, genericFlow->dstPort, genericFlow->srcTos);
    }

    fprintf(stream,
            "  in packets   =        %10llu\n"
            "  in bytes     =        %10llu\n",
            (unsigned long long)genericFlow->inPackets, (unsigned long long)genericFlow->inBytes);

}  // End of EXgenericFlowID

static void stringsEXipv4Flow(FILE *stream, uint8_t *extension) {
    if (!extension) return;

    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)extension;

    char as[INET_ADDRSTRLEN], ds[INET_ADDRSTRLEN];
    uint32_t src = htonl(ipv4Flow->srcAddr);
    uint32_t dst = htonl(ipv4Flow->dstAddr);
    inet_ntop(AF_INET, &src, as, sizeof(as));
    inet_ntop(AF_INET, &dst, ds, sizeof(ds));

    fprintf(stream,
            "  src addr     =  %16s\n"
            "  dst addr     =  %16s\n",
            as, ds);

}  // End of stringsEXipv4Flow

static void stringsEXipv6Flow(FILE *stream, uint8_t *extension) {
    if (!extension) return;

    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)extension;

    char as[INET6_ADDRSTRLEN], ds[INET6_ADDRSTRLEN];
    uint64_t src[2], dst[2];
    src[0] = htonll(ipv6Flow->srcAddr[0]);
    src[1] = htonll(ipv6Flow->srcAddr[1]);
    dst[0] = htonll(ipv6Flow->dstAddr[0]);
    dst[1] = htonll(ipv6Flow->dstAddr[1]);
    inet_ntop(AF_INET6, &src, as, sizeof(as));
    inet_ntop(AF_INET6, &dst, ds, sizeof(ds));

    fprintf(stream,
            "  src addr     =  %16s\n"
            "  dst addr     =  %16s\n",
            as, ds);

}  // End of stringsEXipv6Flow

static void stringsEXinterface(FILE *stream, uint8_t *extension) {
    if (!extension) return;

    EXinterface_t *interface = (EXinterface_t *)extension;
    fprintf(stream,
            "  input        =          %8u\n"
            "  output       =          %8u\n",
            interface->input, interface->output);

}  // End of stringsEXinterface

static void stringsEXflowMisc(FILE *stream, uint8_t *extension) {
    if (!extension) return;

    EXflowMisc_t *flowMisc = (EXflowMisc_t *)extension;
    fprintf(stream,
            "  src mask     =             %5u\n"
            "  dst mask     =             %5u\n"
            "  dst tos      =               %3u\n"
            "  direction    =               %3u\n"
            "  biFlow Dir   =              0x%.2x\n"
            "  end reason   =              0x%.2x\n",
            flowMisc->srcMask, flowMisc->dstMask, flowMisc->dstTos, flowMisc->direction, flowMisc->biFlowDir, flowMisc->flowEndReason);

}  // End of stringsEXflowMisc

static void stringsEXcntFlow(FILE *stream, uint8_t *extension) {
    if (!extension) return;

    EXcntFlow_t *cntFlow = (EXcntFlow_t *)extension;
    fprintf(stream,
            "  out packets  =        %10llu\n"
            "  out bytes    =        %10llu\n"
            "  aggr flows   =        %10llu\n",
            (long long unsigned)cntFlow->outPackets, (long long unsigned)cntFlow->outBytes, (long long unsigned)cntFlow->flows);

}  // End of stringEXcntFlow

static void stringsEXvLan(FILE *stream, uint8_t *extension) {
    if (!extension) return;

    EXvLan_t *vLan = (EXvLan_t *)extension;
    fprintf(stream,
            "  src vlan     =             %5u\n"
            "  dst vlan     =             %5u\n",
            vLan->srcVlan, vLan->dstVlan);

}  // End of stringsEXvLan

static void stringsEXasInfo(FILE *stream, uint8_t *extension) {
    if (!extension) return;

    EXasInfo_t *asInfo = (EXasInfo_t *)extension;
    fprintf(stream,
            "  src as       =             %5u\n"
            "  dst as       =             %5u\n",
            asInfo->srcAS, asInfo->dstAS);

}  // End of stringsEXasInfo

static void stringsEXasRoutingV4(FILE *stream, uint8_t *extension) {
    if (!extension) return;

    EXasRoutingV4_t *nextHopV4 = (EXasRoutingV4_t *)extension;
    char nextIP[INET_ADDRSTRLEN];
    char bgpNextIP[INET_ADDRSTRLEN];
    uint32_t ip = htonl(nextHopV4->nextHop);
    inet_ntop(AF_INET, &ip, nextIP, sizeof(nextIP));
    ip = htonl(nextHopV4->bgpNextHop);
    inet_ntop(AF_INET, &ip, bgpNextIP, sizeof(bgpNextIP));

    fprintf(stream,
            "  ip next hop  =  %16s\n"
            "  bgp next hop =  %16s\n",
            nextIP, bgpNextIP);

}  // End of stringsEXasRoutingV4

static void stringsEXasRoutingV6(FILE *stream, uint8_t *extension) {
    if (!extension) return;

    EXasRoutingV6_t *routingV6 = (EXasRoutingV6_t *)extension;
    char nextIP[INET6_ADDRSTRLEN];
    char bgpNextIP[INET6_ADDRSTRLEN];
    uint64_t ip[2];
    ip[0] = htonll(routingV6->nextHop[0]);
    ip[1] = htonll(routingV6->nextHop[1]);
    inet_ntop(AF_INET6, ip, nextIP, sizeof(nextIP));
    ip[0] = htonll(routingV6->bgpNextHop[0]);
    ip[1] = htonll(routingV6->bgpNextHop[1]);
    inet_ntop(AF_INET6, ip, bgpNextIP, sizeof(bgpNextIP));

    fprintf(stream,
            "  ip next hop  =  %16s\n"
            "  bgp next hop =  %16s\n",
            nextIP, bgpNextIP);

}  // End of stringsEXasRoutingV6

static void stringsEXipReceivedV4(FILE *stream, uint8_t *extension) {
    if (!extension) return;

    EXipReceivedV4_t *ipReceivedV4 = (EXipReceivedV4_t *)extension;
    char ipStr[INET_ADDRSTRLEN];
    uint32_t ip = htonl(ipReceivedV4->ip);
    inet_ntop(AF_INET, &ip, ipStr, sizeof(ipStr));

    fprintf(stream, "  ip exporter  =  %16s\n", ipStr);

}  // End of stringsEXipReceivedV4

static void stringsEXipReceivedV6(FILE *stream, uint8_t *extension) {
    if (!extension) return;

    EXipReceivedV6_t *ipReceivedV6 = (EXipReceivedV6_t *)extension;
    char ipStr[INET6_ADDRSTRLEN];
    uint64_t ip[2];
    ip[0] = htonll(ipReceivedV6->ip[0]);
    ip[1] = htonll(ipReceivedV6->ip[1]);
    inet_ntop(AF_INET6, ip, ipStr, sizeof(ipStr));

    fprintf(stream, "  ip exporter  =  %16s\n", ipStr);

}  // End of stringsEXipReceivedV6

static void stringsEXinPayload(FILE *stream, uint8_t *extension) {
    if (!extension) return;

    uint32_t length = *((uint32_t *)extension);
    uint8_t *payload = (uint8_t *)extension + sizeof(uint32_t);
    fprintf(stream, "i-payload-len  =             %5u\n", length);
    DumpHex(stream, payload, length);

}  // End of stringsEXinPayload

static void stringsEXoutPayload(FILE *stream, uint8_t *extension) {
    if (!extension) return;

    uint32_t length = *((uint32_t *)extension);
    uint8_t *payload = (uint8_t *)extension + sizeof(uint32_t);
    fprintf(stream, "o-payload-len  =             %5u\n", length);
    DumpHex(stream, payload, length);

}  // End of stringsEXinPayload

static const funcPrintRecord_t funcPrintRecord[MAXEXTENSIONS] = {
    [EXgenericFlowID] = stringEXgenericFlow,
    [EXipv4FlowID] = stringsEXipv4Flow,
    [EXipv6FlowID] = stringsEXipv6Flow,
    [EXinterfaceID] = stringsEXinterface,
    [EXflowMiscID] = stringsEXflowMisc,
    [EXcntFlowID] = stringsEXcntFlow,
    [EXvLanID] = stringsEXvLan,
    [EXasInfoID] = stringsEXasInfo,
    [EXasRoutingV4ID] = stringsEXasRoutingV4,
    [EXasRoutingV6ID] = stringsEXasRoutingV6,
    [EXipReceivedV4ID] = stringsEXipReceivedV4,
    [EXipReceivedV6ID] = stringsEXipReceivedV6,
    [EXinPayloadID] = stringsEXinPayload,
    [EXoutPayloadID] = stringsEXoutPayload,
};

void flow_record_short(FILE *stream, recordHeaderV4_t *recordHeaderV4) {
    if (!recordHeaderV4) {
        LogError("flow_recordv4_short() NULL pointer");
        return;
    }
    if (recordHeaderV4->extBitmap == 0) {
        LogError("flow_recordv4_short() zero bitmap");
        return;
    }

    // all based on recordBase
    uint8_t *recordBase = (uint8_t *)recordHeaderV4;

    // offset table
    uint16_t *offsetTable = (uint16_t *)(recordBase + sizeof(recordHeaderV4_t));

    // Generate extension string
    uint64_t bitMap = recordHeaderV4->extBitmap;
    char elementString[recordHeaderV4->numExtensions * 5];
    elementString[0] = '\0';
    while (bitMap) {
        // find lowest set bit (ctz) in bitMap
        uint32_t type = __builtin_ctzll(bitMap);
        bitMap &= bitMap - 1;
        snprintf(elementString + strlen(elementString), sizeof(elementString) - strlen(elementString), "%u ", type);
    }

    // Print flow header
    char *type = "";
    char version[8];
    if (TestFlag(recordHeaderV4->flags, V4_FLAG_EVENT)) {
        type = "EVENT";
        version[0] = '\0';
    } else {
        if (recordHeaderV4->nfVersion != 0) {
            snprintf(version, sizeof(version), " v%u", recordHeaderV4->nfVersion & 0x0F);
            if (recordHeaderV4->nfVersion & 0x80) {
                type = "SFLOW";
            } else if (recordHeaderV4->nfVersion & 0x40) {
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
            "  Flags        =              0x%.2x %s%s%s, %s\n"
            "  Elements     =             %5u: %s\n"
            "  size         =             %5u\n"
            "  engine type  =             %5u\n"
            "  engine ID    =             %5u\n"
            "  export sysid =             %5u\n",
            recordHeaderV4->flags, type, version, TestFlag(recordHeaderV4->flags, V4_FLAG_ANON) ? " Anonymized" : "",
            TestFlag(recordHeaderV4->flags, V4_FLAG_SAMPLED) ? "Sampled" : "Unsampled", recordHeaderV4->numExtensions, elementString,
            recordHeaderV4->size, recordHeaderV4->engineType, recordHeaderV4->engineID, recordHeaderV4->exporterID);

    // print extensions
    bitMap = recordHeaderV4->extBitmap;
    uint32_t slot = 0;
    while (bitMap) {
        // find lowest set bit (ctz) in bitMap
        uint32_t type = __builtin_ctzll(bitMap);
        bitMap &= bitMap - 1;

        // uint32_t slot = __builtin_popcountll(recordHeaderV4->extBitmap & ((1ULL << type) - 1));

        ptrdiff_t offset = offsetTable[slot++];
        dbg_printf("Extension: %u at offset: %u\n", type, offset);
        uint8_t *extension = recordBase + offset;
        if (funcPrintRecord[type]) funcPrintRecord[type](stream, extension);
    }

}  // flow_record_short
