/*
 *  Copyright (c) 2019-2023, Peter Haag
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

#include "maxmind.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfxV3.h"
#include "output_json.h"
#include "output_util.h"
#include "util.h"

#define IP_STRING_LEN (INET6_ADDRSTRLEN)

// record counter
static uint32_t recordCount;

static void stringEXgenericFlow(FILE *stream, master_record_t *r) {
    char datebuff1[64], datebuff2[64], dateBuff3[64];

    time_t when = r->msecFirst / 1000LL;
    struct tm *ts = localtime(&when);
    strftime(datebuff1, 63, "%Y-%m-%dT%H:%M:%S", ts);

    when = r->msecLast / 1000LL;
    ts = localtime(&when);
    strftime(datebuff2, 63, "%Y-%m-%dT%H:%M:%S", ts);

    when = r->msecReceived / 1000LL;
    ts = localtime(&when);
    strftime(dateBuff3, 63, "%Y-%m-%dT%H:%M:%S", ts);

    fprintf(stream,
            "	\"first\" : \"%s.%03u\",\n"
            "	\"last\" : \"%s.%03u\",\n"
            "	\"received\" : \"%s.%03u\",\n"
            "	\"in_packets\" : %llu,\n"
            "	\"in_bytes\" : %llu,\n",
            datebuff1, (unsigned)(r->msecFirst % 1000LL), datebuff2, (unsigned)(r->msecLast % 1000LL), dateBuff3,
            (unsigned)(r->msecReceived % 1000LL), (unsigned long long)r->inPackets, (unsigned long long)r->inBytes);

    if (r->proto == IPPROTO_ICMP || r->proto == IPPROTO_ICMPV6) {  // ICMP
        fprintf(stream,
                "	\"proto\" : %u,\n"
                "	\"icmp_type\" : %u,\n"
                "	\"icmp_code\" : %u,\n"
                "	\"src_tos\" : %u,\n",
                r->proto, r->icmpType, r->icmpCode, r->tos);
    } else {
        fprintf(stream,
                "	\"proto\" : %u,\n"
                "	\"tcp_flags\" : \"%s\",\n"
                "	\"src_port\" : %u,\n"
                "	\"dst_port\" : %u,\n"
                "	\"src_tos\" : %u,\n",
                r->proto, FlagsString(r->tcp_flags), r->srcPort, r->dstPort, r->tos);
    }

}  // End of stringEXgenericFlow

static void stringEXipv4Flow(FILE *stream, master_record_t *r) {
    char as[IP_STRING_LEN], ds[IP_STRING_LEN];
    char sloc[128], dloc[128];

    uint32_t src = htonl(r->V4.srcaddr);
    uint32_t dst = htonl(r->V4.dstaddr);
    inet_ntop(AF_INET, &src, as, sizeof(as));
    inet_ntop(AF_INET, &dst, ds, sizeof(ds));

    LookupLocation(r->V6.srcaddr, sloc, 128);
    LookupLocation(r->V6.dstaddr, dloc, 128);

    fprintf(stream,
            "	\"src4_addr\" : \"%s\",\n"
            "	\"dst4_addr\" : \"%s\",\n"
            "	\"src_geo\" : \"%s\",\n"
            "	\"dst_geo\" : \"%s\",\n",
            as, ds, sloc, dloc);

}  // End of stringEXipv4Flow

static void stringEXipv6Flow(FILE *stream, master_record_t *r) {
    char as[IP_STRING_LEN], ds[IP_STRING_LEN];
    char sloc[128], dloc[128];
    uint64_t src[2], dst[2];

    src[0] = htonll(r->V6.srcaddr[0]);
    src[1] = htonll(r->V6.srcaddr[1]);
    dst[0] = htonll(r->V6.dstaddr[0]);
    dst[1] = htonll(r->V6.dstaddr[1]);
    inet_ntop(AF_INET6, &src, as, sizeof(as));
    inet_ntop(AF_INET6, &dst, ds, sizeof(ds));

    LookupLocation(r->V6.srcaddr, sloc, 128);
    LookupLocation(r->V6.dstaddr, dloc, 128);

    fprintf(stream,
            "	\"src6_addr\" : \"%s\",\n"
            "	\"dst6_addr\" : \"%s\",\n"
            "	\"src_geo\" : \"%s\",\n"
            "	\"dst_geo\" : \"%s\",\n",
            as, ds, sloc, dloc);

}  // End of stringEXipv6Flow

static void stringEXflowMisc(FILE *stream, master_record_t *r) {
    char snet[IP_STRING_LEN], dnet[IP_STRING_LEN];

    if (TestFlag(r->mflags, V3_FLAG_IPV6_ADDR) != 0) {
        // IPv6
        if (r->src_mask || r->dst_mask) {
            uint64_t src[2];
            uint64_t dst[2];
            if (r->src_mask >= 64) {
                src[0] = r->V6.srcaddr[0] & (0xffffffffffffffffLL << (r->src_mask - 64));
                src[1] = 0;
            } else {
                src[0] = r->V6.srcaddr[0];
                src[1] = r->V6.srcaddr[1] & (0xffffffffffffffffLL << r->src_mask);
            }
            src[0] = htonll(src[0]);
            src[1] = htonll(src[1]);
            inet_ntop(AF_INET6, &src, snet, sizeof(snet));

            if (r->dst_mask >= 64) {
                dst[0] = r->V6.dstaddr[0] & (0xffffffffffffffffLL << (r->dst_mask - 64));
                dst[1] = 0;
            } else {
                dst[0] = r->V6.dstaddr[0];
                dst[1] = r->V6.dstaddr[1] & (0xffffffffffffffffLL << r->dst_mask);
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
        if (r->src_mask || r->dst_mask) {
            uint32_t src, dst;
            src = r->V4.srcaddr & (0xffffffffL << (32 - r->src_mask));
            src = htonl(src);
            inet_ntop(AF_INET, &src, snet, sizeof(snet));

            dst = r->V4.dstaddr & (0xffffffffL << (32 - r->dst_mask));
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
            "	\"fwd_status\" : %u,\n"
            "	\"direction\" : %u,\n"
            "	\"dst_tos\" : %u,\n",
            r->input, r->output, r->src_mask, r->dst_mask, snet, dnet, r->fwd_status, r->dir, r->dst_tos);

}  // End of stringEXflowMisc

static void stringEXcntFlow(FILE *stream, master_record_t *r) {
    fprintf(stream,
            "	\"out_packets\" : %llu,\n"
            "	\"out_bytes\" : %llu,\n"
            "	\"aggr_flows\" : %llu,\n",
            (long long unsigned)r->out_pkts, (long long unsigned)r->out_bytes, (long long unsigned)r->aggr_flows);

}  // End of stringEXcntFlow

static void stringEXvLan(FILE *stream, master_record_t *r) {
    fprintf(stream,
            "	\"src_vlan\" : %u,\n"
            "	\"dst_vlan\" : %u,\n",
            r->src_vlan, r->dst_vlan);

}  // End of stringEXvLan

static void stringEXasRouting(FILE *stream, master_record_t *r) {
    if (r->srcas == 0) r->srcas = LookupAS(r->V6.srcaddr);
    if (r->dstas == 0) r->dstas = LookupAS(r->V6.dstaddr);
    fprintf(stream,
            "	\"src_as\" : %u,\n"
            "	\"dst_as\" : %u,\n",
            r->srcas, r->dstas);

}  // End of stringEXasRouting

static void stringEXbgpNextHopV4(FILE *stream, master_record_t *r) {
    char ip[IP_STRING_LEN];

    ip[0] = 0;
    uint32_t i = htonl(r->bgp_nexthop.V4);
    inet_ntop(AF_INET, &i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    fprintf(stream, "	\"bgp4_next_hop\" : \"%s\",\n", ip);

}  // End of stringEXbgpNextHopV4

static void stringEXbgpNextHopV6(FILE *stream, master_record_t *r) {
    char ip[IP_STRING_LEN];
    uint64_t i[2];

    i[0] = htonll(r->bgp_nexthop.V6[0]);
    i[1] = htonll(r->bgp_nexthop.V6[1]);
    inet_ntop(AF_INET6, i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    fprintf(stream, "	\"bgp6_next_hop\" : \"%s\",\n", ip);

}  // End of stringEXbgpNextHopV6

static void stringEXipNextHopV4(FILE *stream, master_record_t *r) {
    char ip[IP_STRING_LEN];

    ip[0] = 0;
    uint32_t i = htonl(r->ip_nexthop.V4);
    inet_ntop(AF_INET, &i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    fprintf(stream, "	\"ip4_next_hop\" : \"%s\",\n", ip);

}  // End of stringEXipNextHopV4

static void stringEXipNextHopV6(FILE *stream, master_record_t *r) {
    char ip[IP_STRING_LEN];
    uint64_t i[2];

    i[0] = htonll(r->ip_nexthop.V6[0]);
    i[1] = htonll(r->ip_nexthop.V6[1]);
    inet_ntop(AF_INET6, i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    fprintf(stream, "	\"ip6_next_hop\" : \"%s\",\n", ip);

}  // End of stringEXipNextHopV6

static void stringEXipReceivedV4(FILE *stream, master_record_t *r) {
    char ip[IP_STRING_LEN];

    ip[0] = 0;
    uint32_t i = htonl(r->ip_router.V4);
    inet_ntop(AF_INET, &i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    fprintf(stream, "	\"ip4_router\" : \"%s\",\n", ip);

}  // End of stringEXipReceivedV4

static void stringEXipReceivedV6(FILE *stream, master_record_t *r) {
    char ip[IP_STRING_LEN];
    uint64_t i[2];

    i[0] = htonll(r->ip_router.V6[0]);
    i[1] = htonll(r->ip_router.V6[1]);
    inet_ntop(AF_INET6, i, ip, sizeof(ip));
    ip[IP_STRING_LEN - 1] = 0;

    fprintf(stream, "	\"ip6_router\" : \"%s\",\n", ip);

}  // End of stringEXipReceivedV6

static void stringEXmplsLabel(FILE *stream, master_record_t *r) {
    for (int i = 0; i < 10; i++) {
        fprintf(stream, "	\"mpls_%u\" : \"%u-%u-%u\",\n", i + 1, r->mpls_label[i] >> 4, (r->mpls_label[i] & 0xF) >> 1, r->mpls_label[i] & 1);
    }

}  // End of stringEXipReceivedV6

static void stringEXmacAddr(FILE *stream, master_record_t *r) {
    uint8_t mac1[6], mac2[6], mac3[6], mac4[6];

    for (int i = 0; i < 6; i++) {
        mac1[i] = (r->in_src_mac >> (i * 8)) & 0xFF;
        mac2[i] = (r->out_dst_mac >> (i * 8)) & 0xFF;
        mac3[i] = (r->in_dst_mac >> (i * 8)) & 0xFF;
        mac4[i] = (r->out_src_mac >> (i * 8)) & 0xFF;
    }

    fprintf(stream,
            "	\"in_src_mac\" : \"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\",\n"
            "	\"out_dst_mac\" : \"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\",\n"
            "	\"in_dst_mac\" : \"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\",\n"
            "	\"out_src_mac\" : \"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\",\n",
            mac1[5], mac1[4], mac1[3], mac1[2], mac1[1], mac1[0], mac2[5], mac2[4], mac2[3], mac2[2], mac2[1], mac2[0], mac3[5], mac3[4], mac3[3],
            mac3[2], mac3[1], mac3[0], mac4[5], mac4[4], mac4[3], mac4[2], mac4[1], mac4[0]);

}  // End of stringEXmacAddr

static void stringEXasAdjacent(FILE *stream, master_record_t *r) {
    fprintf(stream,
            "	\"next_as\" : %u,\n"
            "	\"prev_as\" : %u,\n",
            r->bgpNextAdjacentAS, r->bgpPrevAdjacentAS);

}  // End of stringEXasAdjacent

static void stringEXlatency(FILE *stream, master_record_t *r) {
    double f1, f2, f3;

    f1 = (double)r->client_nw_delay_usec / 1000.0;
    f2 = (double)r->server_nw_delay_usec / 1000.0;
    f3 = (double)r->appl_latency_usec / 1000.0;

    fprintf(stream,
            "	\"cli_latency\" : %f,\n"
            "	\"srv_latency\" : %f,\n"
            "	\"app_latency\" : %f,\n",
            f1, f2, f3);

}  // End of stringEXlatency

static void String_ja3(FILE *stream, master_record_t *r) {
    uint8_t zero[16] = {0};
    if (r->inPayloadLength == 0 || memcmp(r->ja3, zero, 16) == 0) {
        return;
    }

    char out[33];
    int i, j;
    for (i = 0, j = 0; i < 16; i++, j += 2) {
        uint8_t ln = r->ja3[i] & 0xF;
        uint8_t hn = (r->ja3[i] >> 4) & 0xF;
        out[j + 1] = ln <= 9 ? ln + '0' : ln + 'a' - 10;
        out[j] = hn <= 9 ? hn + '0' : hn + 'a' - 10;
    }
    out[32] = '\0';
    fprintf(stream, "	\"ja3\" : %s,\n", out);

}  // End of String_ja3

static void stringEXtunIPv4(FILE *stream, master_record_t *r) {
    char as[IP_STRING_LEN], ds[IP_STRING_LEN];

    uint32_t src = htonl(r->tun_src_ip.V4);
    uint32_t dst = htonl(r->tun_dst_ip.V4);
    inet_ntop(AF_INET, &src, as, sizeof(as));
    inet_ntop(AF_INET, &dst, ds, sizeof(ds));

    fprintf(stream,
            "	\"tun proto\" : %u,\n"
            "	\"src4_tun_ip\" : \"%s\",\n"
            "	\"dst4_tun_ip\" : \"%s\",\n",
            r->tun_proto, as, ds);

}  // End of stringEXtunIPv4

static void stringEXtunIPv6(FILE *stream, master_record_t *r) {
    char as[IP_STRING_LEN], ds[IP_STRING_LEN];
    uint64_t src[2];
    uint64_t dst[2];

    src[0] = htonll(r->tun_src_ip.V6[0]);
    src[1] = htonll(r->tun_src_ip.V6[1]);
    dst[0] = htonll(r->tun_dst_ip.V6[0]);
    dst[1] = htonll(r->tun_dst_ip.V6[1]);
    inet_ntop(AF_INET6, &src, as, sizeof(as));
    inet_ntop(AF_INET6, &dst, ds, sizeof(ds));

    fprintf(stream,
            "	\"tun proto\" : %u,\n"
            "	\"src6_tun_ip\" : \"%s\",\n"
            "	\"dst6_tun_ip\" : \"%s\",\n",
            r->tun_proto, as, ds);

}  // End of stringEXtunIPv6

static void stringEXobservation(FILE *stream, master_record_t *r) {
    fprintf(stream,
            "	\"observationDoaminID\" : %u,\n"
            "	\"observationPointID\" : %llu,\n",
            r->observationDomainID, (long long unsigned)r->observationPointID);

}  // End of stringEXobservation

static void stringEXvrf(FILE *stream, master_record_t *r) {
    fprintf(stream,
            "	\"ingress_vrf\" : \"%u\",\n"
            "	\"egress_vrf\" : \"%u\",\n",
            r->ingressVrf, r->egressVrf);

}  // End of stringEXvrf

#ifdef NSEL
static void stringEXnselCommon(FILE *stream, master_record_t *r) {
    char datestr[64];

    time_t when = r->msecEvent / 1000LL;
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
            r->connID, r->event, r->event_flag == FW_EVENT ? FwEventString(r->event) : EventString(r->event, LONGNAME), r->fwXevent, datestr,
            r->msecEvent % 1000LL);

}  // End of stringEXnselCommon

static void stringEXnselXlateIPv4(FILE *stream, master_record_t *r) {
    char as[IP_STRING_LEN], ds[IP_STRING_LEN];

    uint32_t src = htonl(r->xlate_src_ip.V4);
    uint32_t dst = htonl(r->xlate_dst_ip.V4);
    inet_ntop(AF_INET, &src, as, sizeof(as));
    inet_ntop(AF_INET, &dst, ds, sizeof(ds));

    fprintf(stream,
            "	\"src4_xlt_ip\" : \"%s\",\n"
            "	\"dst4_xlt_ip\" : \"%s\",\n",
            as, ds);

}  // End of stringEXnselXlateIPv4

static void stringEXnselXlateIPv6(FILE *stream, master_record_t *r) {
    char as[IP_STRING_LEN], ds[IP_STRING_LEN];
    uint64_t src[2];
    uint64_t dst[2];

    src[0] = htonll(r->xlate_src_ip.V6[0]);
    src[1] = htonll(r->xlate_src_ip.V6[1]);
    dst[0] = htonll(r->xlate_dst_ip.V6[0]);
    dst[1] = htonll(r->xlate_dst_ip.V6[1]);
    inet_ntop(AF_INET6, &src, as, sizeof(as));
    inet_ntop(AF_INET6, &dst, ds, sizeof(ds));

    fprintf(stream,
            "	\"src6_xlt_ip\" : \"%s\",\n"
            "	\"dst6_xlt_ip\" : \"%s\",\n",
            as, ds);

}  // End of stringEXnselXlateIPv4

static void stringEXnselXlatePort(FILE *stream, master_record_t *r) {
    fprintf(stream,
            "	\"src_xlt_port\" : \"%u\",\n"
            "	\"dst_xlt_port\" : \"%u\",\n",
            r->xlate_src_port, r->xlate_dst_port);

}  // End of stringEXnselXlatePort

static void stringEXnselAcl(FILE *stream, master_record_t *r) {
    fprintf(stream,
            "	\"ingress_acl\" : \"0x%x/0x%x/0x%x\",\n"
            "	\"egress_acl\" : \"0x%x/0x%x/0x%x\",\n",
            r->ingressAcl[0], r->ingressAcl[1], r->ingressAcl[2], r->egressAcl[0], r->egressAcl[1], r->egressAcl[2]);

}  // End of stringEXnselAcl

static void stringEXnselUserID(FILE *stream, master_record_t *r) {
    fprintf(stream, "	\"user_name\" : \"%s\",\n", r->username[0] ? r->username : "<empty>");

}  // End of stringEXnselUserID

static void stringEXnelCommon(FILE *stream, master_record_t *r) {
    char datestr[64];
    char *event;

    switch (r->event) {
        case 0:
            event = "Reserved";
            break;
        case 1:
            event = "NAT translation create";
            break;
        case 2:
            event = "NAT translation delete";
            break;
        case 3:
            event = "NAT Addresses exhausted";
            break;
        case 4:
            event = "NAT44 session create";
            break;
        case 5:
            event = "NAT44 session delete";
            break;
        case 6:
            event = "NAT64 session create";
            break;
        case 7:
            event = "NAT64 session delete";
            break;
        case 8:
            event = "NAT44 BIB create";
            break;
        case 9:
            event = "NAT44 BIB delete";
            break;
        case 10:
            event = "NAT64 BIB create";
            break;
        case 11:
            event = "NAT64 BIB delete";
            break;
        case 12:
            event = "NAT ports exhausted";
            break;
        case 13:
            event = "Quota Exceeded";
            break;
        case 14:
            event = "Address binding create";
            break;
        case 15:
            event = "Address binding delete";
            break;
        case 16:
            event = "Port block allocation";
            break;
        case 17:
            event = "Port block de-allocation";
            break;
        case 18:
            event = "Threshold Reached";
            break;
        default:
            event = "";
            break;
    }

    time_t when = r->msecEvent / 1000LL;
    if (when == 0) {
        strncpy(datestr, "<unknown>", 63);
    } else {
        struct tm *ts = localtime(&when);
        strftime(datestr, 63, "%Y-%m-%dT%H:%M:%S", ts);
    }
    fprintf(stream,
            "	\"nat_event_id\" : \"%u\",\n"
            "	\"nat_event\" : \"%s\",\n"
            "	\"ingress_vrf\" : \"%u\",\n"
            "	\"egress_vrf\" : \"%u\",\n"
            "	\"t_event\" : \"%s.%llu\",\n",
            r->event, event, r->ingressVrf, r->egressVrf, datestr, r->msecEvent % 1000LL);

}  // End of stringEXnelCommon

static void stringEXnelXlatePort(FILE *stream, master_record_t *r) {
    fprintf(stream,
            "	\"pblock_start\" : \"%u\",\n"
            "	\"pblock_end\" : \"%u\",\n"
            "	\"pblock_step\" : \"%u\",\n"
            "	\"pblock_size\" : \"%u\",\n",
            r->block_start, r->block_end, r->block_step, r->block_size);

}  // End of stringEXnelXlatePort
#endif

void json_prolog(void) {
    recordCount = 0;
    // open json
    printf("[\n");
}  // End of json_prolog

void json_epilog(void) {
    // close json
    printf("]\n");
}  // End of json_epilog

void flow_record_to_json(FILE *stream, void *record, int tag) {
    master_record_t *r = (master_record_t *)record;

    if (recordCount) {
        fprintf(stream, ",\n");
    }
    recordCount++;

    fprintf(stream,
            "{\n"
            "	\"type\" : \"%s\",\n"
            "	\"sampled\" : %u,\n"
            "	\"export_sysid\" : %u,\n",
            TestFlag(r->flags, V3_FLAG_EVENT) ? "EVENT" : "FLOW", TestFlag(r->flags, V3_FLAG_SAMPLED) ? 1 : 0, r->exporter_sysid);

    int i = 0;
    while (r->exElementList[i]) {
        switch (r->exElementList[i]) {
            case EXnull:
                fprintf(stderr, "Found unexpected NULL extension \n");
                break;
            case EXgenericFlowID:
                stringEXgenericFlow(stream, r);
                break;
            case EXipv4FlowID:
                stringEXipv4Flow(stream, r);
                break;
            case EXipv6FlowID:
                stringEXipv6Flow(stream, r);
                break;
            case EXflowMiscID:
                stringEXflowMisc(stream, r);
                break;
            case EXcntFlowID:
                stringEXcntFlow(stream, r);
                break;
            case EXvLanID:
                stringEXvLan(stream, r);
                break;
            case EXasRoutingID:
                stringEXasRouting(stream, r);
                break;
            case EXbgpNextHopV4ID:
                stringEXbgpNextHopV4(stream, r);
                break;
            case EXbgpNextHopV6ID:
                stringEXbgpNextHopV6(stream, r);
                break;
            case EXipNextHopV4ID:
                stringEXipNextHopV4(stream, r);
                break;
            case EXipNextHopV6ID:
                stringEXipNextHopV6(stream, r);
                break;
            case EXipReceivedV4ID:
                stringEXipReceivedV4(stream, r);
                break;
            case EXipReceivedV6ID:
                stringEXipReceivedV6(stream, r);
                break;
            case EXmplsLabelID:
                stringEXmplsLabel(stream, r);
                break;
            case EXmacAddrID:
                stringEXmacAddr(stream, r);
                break;
            case EXasAdjacentID:
                stringEXasAdjacent(stream, r);
                break;
            case EXlatencyID:
                stringEXlatency(stream, r);
                break;
            case EXinPayloadID:
                String_ja3(stream, r);
                break;
            case EXoutPayloadID:
                String_ja3(stream, r);
                break;
            case EXtunIPv4ID:
                stringEXtunIPv4(stream, r);
                break;
            case EXtunIPv6ID:
                stringEXtunIPv6(stream, r);
                break;
            case EXobservationID:
                stringEXobservation(stream, r);
                break;
            case EXvrfID:
                stringEXvrf(stream, r);
                break;
#ifdef NSEL
            case EXnselCommonID:
                stringEXnselCommon(stream, r);
                break;
            case EXnselXlateIPv4ID:
                stringEXnselXlateIPv4(stream, r);
                break;
            case EXnselXlateIPv6ID:
                stringEXnselXlateIPv6(stream, r);
                break;
            case EXnselXlatePortID:
                stringEXnselXlatePort(stream, r);
                break;
            case EXnselAclID:
                stringEXnselAcl(stream, r);
                break;
            case EXnselUserID:
                stringEXnselUserID(stream, r);
                break;
            case EXnelCommonID:
                stringEXnelCommon(stream, r);
                break;
            case EXnelXlatePortID:
                stringEXnelXlatePort(stream, r);
                break;
#endif
            default:
                dbg_printf("Extension %i not yet implemented\n", r->exElementList[i]);
        }
        i++;
    }

    // add label and close json object
    fprintf(stream,
            "	\"label\" : \"%s\"\n"
            "}",
            r->label ? r->label : "<none>");

}  // End of flow_record_to_json
