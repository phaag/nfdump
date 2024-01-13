/*
 *  Copyright (c) 2019-2022, Peter Haag
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

#include "output_csv.h"

#include <arpa/inet.h>
#include <errno.h>
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
#include "nfdump.h"
#include "nffile.h"
#include "output_csv.h"
#include "output_util.h"
#include "userio.h"
#include "util.h"

#define IP_STRING_LEN (INET6_ADDRSTRLEN)

void csv_prolog(void) {
    printf(
        "ts,te,td,sa,da,sp,dp,pr,flg,fwd,stos,ipkt,ibyt,opkt,obyt,in,out,sas,das,smk,dmk,dtos,dir,nh,nhb,svln,dvln,ismc,odmc,idmc,osmc,mpls1,mpls2,"
        "mpls3,mpls4,mpls5,mpls6,mpls7,mpls8,mpls9,mpls10,cl,sl,al,ra,eng,exid,tr\n");

}  // End of csv_prolog

void csv_epilog(void) {}  // End of csv_epilog

void csv_record(FILE *stream, void *record, int tag) {
    recordHandle_t *recordHandle = (recordHandle_t *)record;

    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    if (!genericFlow) return;

    // if this flow is a tunnel, add a flow line with the tunnel IPs
    EXtunIPv4_t *tunIPv4 = (EXtunIPv4_t *)recordHandle->extensionList[EXtunIPv4ID];
    EXtunIPv6_t *tunIPv6 = (EXtunIPv6_t *)recordHandle->extensionList[EXtunIPv6ID];
    if (tunIPv4 || tunIPv6) {
        size_t len = V3HeaderRecordSize + EXgenericFlowSize + EXipv6FlowSize;
        void *p = malloc(len);
        if (!p) {
            LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            exit(EXIT_FAILURE);
        }
        AddV3Header(p, v3TunHeader);
        PushExtension(v3TunHeader, EXgenericFlow, tunGenericFlow);
        memcpy((void *)tunGenericFlow, (void *)genericFlow, sizeof(EXgenericFlow_t));
        if (tunIPv4) {
            tunGenericFlow->proto = tunIPv4->tunProto;
            PushExtension(v3TunHeader, EXipv4Flow, tunIPv4Flow);
            tunIPv4Flow->srcAddr = tunIPv4->tunSrcAddr;
            tunIPv4Flow->dstAddr = tunIPv4->tunDstAddr;
        } else {
            tunGenericFlow->proto = tunIPv6->tunProto;
            PushExtension(v3TunHeader, EXipv6Flow, tunIPv6Flow);
            tunIPv6Flow->srcAddr[0] = tunIPv6->tunSrcAddr[0];
            tunIPv6Flow->srcAddr[1] = tunIPv6->tunSrcAddr[1];
            tunIPv6Flow->dstAddr[0] = tunIPv6->tunDstAddr[0];
            tunIPv6Flow->dstAddr[1] = tunIPv6->tunDstAddr[1];
        }
        csv_record(stream, p, tag);
        free(p);
    }

    char as[IP_STRING_LEN], ds[IP_STRING_LEN];
    as[0] = 0;
    ds[0] = 0;
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];
    if (ipv4Flow) {
        // IPv4
        uint32_t snet, dnet;
        snet = htonl(ipv4Flow->srcAddr);
        dnet = htonl(ipv4Flow->dstAddr);
        inet_ntop(AF_INET, &snet, as, sizeof(as));
        inet_ntop(AF_INET, &dnet, ds, sizeof(ds));
    }

    if (ipv6Flow) {
        uint64_t snet[2];
        uint64_t dnet[2];

        snet[0] = htonll(ipv6Flow->srcAddr[0]);
        snet[1] = htonll(ipv6Flow->srcAddr[1]);
        dnet[0] = htonll(ipv6Flow->dstAddr[0]);
        dnet[1] = htonll(ipv6Flow->dstAddr[1]);
        inet_ntop(AF_INET6, snet, as, sizeof(as));
        inet_ntop(AF_INET6, dnet, ds, sizeof(ds));
    }

    as[IP_STRING_LEN - 1] = 0;
    ds[IP_STRING_LEN - 1] = 0;

    char datestr1[64], datestr2[64], datestr3[64];
    time_t when = genericFlow->msecFirst / 1000LL;
    struct tm *ts = localtime(&when);
    strftime(datestr1, 63, "%Y-%m-%d %H:%M:%S", ts);

    when = genericFlow->msecLast / 1000LL;
    ts = localtime(&when);
    strftime(datestr2, 63, "%Y-%m-%d %H:%M:%S", ts);

    double duration = (double)(genericFlow->msecLast - genericFlow->msecFirst) / 1000.0;

    EXcntFlow_t *cntFlow = (EXcntFlow_t *)recordHandle->extensionList[EXcntFlowID];
    uint64_t outPackets = 0;
    uint64_t outBytes = 0;
    if (cntFlow) {
        outPackets = cntFlow->outPackets;
        outBytes = cntFlow->outBytes;
    }

    fprintf(stream, "%s,%s,%.3f,%s,%s,%u,%u,%s,%s,%u,%u,%llu,%llu,%llu,%llu", datestr1, datestr2, duration, as, ds, genericFlow->srcPort,
            genericFlow->dstPort, ProtoString(genericFlow->proto, 0), FlagsString(genericFlow->tcpFlags), genericFlow->fwdStatus, genericFlow->srcTos,
            (unsigned long long)genericFlow->inPackets, (unsigned long long)genericFlow->inBytes, (long long unsigned)outPackets,
            (long long unsigned)outBytes);

    EXflowMisc_t *flowMisc = (EXflowMisc_t *)recordHandle->extensionList[EXflowMiscID];
    uint32_t input = 0;
    uint32_t output = 0;
    uint32_t srcMask = 0;
    uint32_t dstMask = 0;
    uint8_t dir = 0;
    uint8_t dstTos = 0;
    if (flowMisc) {
        input = flowMisc->input;
        output = flowMisc->output;
        srcMask = flowMisc->srcMask;
        dstMask = flowMisc->dstMask;
        dir = flowMisc->dir;
        dstTos = flowMisc->dstTos;
    }

    EXasRouting_t *asRouting = (EXasRouting_t *)recordHandle->extensionList[EXasRoutingID];
    uint32_t srcAS = 0;
    uint32_t dstAS = 0;
    if (asRouting) {
        srcAS = asRouting->srcAS;
        dstAS = asRouting->dstAS;
    }

    fprintf(stream, ",%u,%u,%u,%u,%u,%u,%u,%u", input, output, srcAS, dstAS, srcMask, dstMask, dstTos, dir);

    as[0] = 0;
    uint32_t ipv4 = 0;
    uint64_t ipv6[2];

    EXipNextHopV4_t *ipNextHopV4 = (EXipNextHopV4_t *)recordHandle->extensionList[EXipNextHopV4ID];
    EXipNextHopV6_t *ipNextHopV6 = (EXipNextHopV6_t *)recordHandle->extensionList[EXipNextHopV6ID];
    if (ipNextHopV4) {
        ipv4 = htonl(ipNextHopV4->ip);
        inet_ntop(AF_INET, &ipv4, as, sizeof(as));
    } else if (ipNextHopV6) {
        ipv6[0] = htonll(ipNextHopV6->ip[0]);
        ipv6[1] = htonll(ipNextHopV6->ip[1]);
        inet_ntop(AF_INET6, ipv6, as, sizeof(as));
    } else {
        ipv4 = 0;
        inet_ntop(AF_INET, &ipv4, as, sizeof(as));
    }
    as[IP_STRING_LEN - 1] = 0;
    fprintf(stream, ",%s", as);

    as[0] = 0;
    EXbgpNextHopV4_t *bgpNextHopV4 = (EXbgpNextHopV4_t *)recordHandle->extensionList[EXbgpNextHopV4ID];
    EXbgpNextHopV6_t *bgpNextHopV6 = (EXbgpNextHopV6_t *)recordHandle->extensionList[EXbgpNextHopV6ID];
    if (bgpNextHopV4) {
        ipv4 = htonl(bgpNextHopV4->ip);
        inet_ntop(AF_INET, &ipv4, as, sizeof(as));
    } else if (bgpNextHopV6) {
        ipv6[0] = htonll(bgpNextHopV6->ip[0]);
        ipv6[1] = htonll(bgpNextHopV6->ip[1]);
        inet_ntop(AF_INET6, ipv6, as, sizeof(as));
    } else {
        ipv4 = 0;
        inet_ntop(AF_INET, &ipv4, as, sizeof(as));
    }
    as[IP_STRING_LEN - 1] = 0;
    fprintf(stream, ",%s", as);

    master_record_t *r = (master_record_t *)record;

    // EX_VLAN:
    fprintf(stream, ",%u,%u", r->src_vlan, r->dst_vlan);

    // case EX_MAC_1:
    uint8_t mac1[6], mac2[6];
    for (int i = 0; i < 6; i++) {
        mac1[i] = (r->in_src_mac >> (i * 8)) & 0xFF;
    }
    for (int i = 0; i < 6; i++) {
        mac2[i] = (r->out_dst_mac >> (i * 8)) & 0xFF;
    }

    fprintf(stream, ",%.2x:%.2x:%.2x:%.2x:%.2x:%.2x,%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac1[5], mac1[4], mac1[3], mac1[2], mac1[1], mac1[0], mac2[5],
            mac2[4], mac2[3], mac2[2], mac2[1], mac2[0]);

    // EX_MAC_2:
    for (int i = 0; i < 6; i++) {
        mac1[i] = (r->in_dst_mac >> (i * 8)) & 0xFF;
    }
    for (int i = 0; i < 6; i++) {
        mac2[i] = (r->out_src_mac >> (i * 8)) & 0xFF;
    }

    fprintf(stream, ",%.2x:%.2x:%.2x:%.2x:%.2x:%.2x,%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac1[5], mac1[4], mac1[3], mac1[2], mac1[1], mac1[0], mac2[5],
            mac2[4], mac2[3], mac2[2], mac2[1], mac2[0]);

    // EX_MPLS:
    for (int i = 0; i < 10; i++) {
        fprintf(stream, ",%u-%1u-%1u", r->mpls_label[i] >> 4, (r->mpls_label[i] & 0xF) >> 1, r->mpls_label[i] & 1);
    }

    double f1, f2, f3;
    f1 = (double)r->client_nw_delay_usec / 1000.0;
    f2 = (double)r->server_nw_delay_usec / 1000.0;
    f3 = (double)r->appl_latency_usec / 1000.0;

    fprintf(stream, ",%9.3f,%9.3f,%9.3f", f1, f2, f3);

    // EX_ROUTER_IP_v4:
    if (TestFlag(r->mflags, V3_FLAG_IPV6_EXP) != 0) {
        // EX_NEXT_HOP_v6:
        as[0] = 0;
        r->ip_router.V6[0] = htonll(r->ip_router.V6[0]);
        r->ip_router.V6[1] = htonll(r->ip_router.V6[1]);
        inet_ntop(AF_INET6, r->ip_router.V6, as, sizeof(as));
        as[IP_STRING_LEN - 1] = 0;
        fprintf(stream, ",%s", as);
    } else {
        // EX_NEXT_HOP_v4:
        as[0] = 0;
        r->ip_router.V4 = htonl(r->ip_router.V4);
        inet_ntop(AF_INET, &r->ip_router.V4, as, sizeof(as));
        as[IP_STRING_LEN - 1] = 0;
        fprintf(stream, ",%s", as);
    }

    // EX_ROUTER_ID
    fprintf(stream, ",%u/%u", r->engine_type, r->engine_id);

    // Exporter SysID
    fprintf(stream, ",%u", r->exporter_sysid);

    // Date flow received
    when = r->msecReceived / 1000LL;
    ts = localtime(&when);
    strftime(datestr3, 63, ",%Y-%m-%d %H:%M:%S", ts);

    fprintf(stream, "%s.%03llu\n", datestr3, (long long unsigned)r->msecReceived % 1000LL);

}  // End of csv_record
