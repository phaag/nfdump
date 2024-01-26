/*
 *  Copyright (c) 2024, Peter Haag
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

static void SetIPaddress(recordHandle_t *recordHandle, int af, char *src_ip, char *dst_ip);

static void SetNextIPaddress(recordHandle_t *recordHandle, int af, char *next_ip);

static void SetRouterIPaddress(recordHandle_t *recordHandle, int af, char *next_ip);

static void SetBGPNextIPaddress(recordHandle_t *recordHandle, int af, char *next_ip);

static void UpdateRecord(recordHandle_t *recordHandle);

static void StoreRecord(recordHandle_t *recordHandle, nffile_t *nffile);

static void SetIPaddress(recordHandle_t *recordHandle, int af, char *src_ip, char *dst_ip) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];
    recordHeaderV3_t *v3Record = recordHandle->recordHeaderV3;
    if (af == PF_INET && ipv4Flow) {
        ClearFlag(v3Record->flags, V3_FLAG_IPV6_ADDR);
        inet_pton(PF_INET, src_ip, &ipv4Flow->srcAddr);
        inet_pton(PF_INET, dst_ip, &ipv4Flow->dstAddr);
        ipv4Flow->srcAddr = ntohl(ipv4Flow->srcAddr);
        ipv4Flow->dstAddr = ntohl(ipv4Flow->dstAddr);
    }
    if (af == PF_INET6 && ipv6Flow) {
        SetFlag(v3Record->flags, V3_FLAG_IPV6_ADDR);
        inet_pton(PF_INET6, src_ip, ipv6Flow->srcAddr);
        inet_pton(PF_INET6, dst_ip, ipv6Flow->dstAddr);
        ipv6Flow->srcAddr[0] = ntohll(ipv6Flow->srcAddr[0]);
        ipv6Flow->srcAddr[1] = ntohll(ipv6Flow->srcAddr[1]);
        ipv6Flow->dstAddr[0] = ntohll(ipv6Flow->dstAddr[0]);
        ipv6Flow->dstAddr[1] = ntohll(ipv6Flow->dstAddr[1]);
    }

}  // End of SetIPaddress

static void SetNextIPaddress(recordHandle_t *recordHandle, int af, char *next_ip) {
    EXipNextHopV4_t *ipNextHopV4 = (EXipNextHopV4_t *)recordHandle->extensionList[EXipNextHopV4ID];
    EXipNextHopV6_t *ipNextHopV6 = (EXipNextHopV6_t *)recordHandle->extensionList[EXipNextHopV6ID];
    recordHeaderV3_t *v3Record = recordHandle->recordHeaderV3;
    if (af == PF_INET && ipNextHopV4) {
        ClearFlag(v3Record->flags, V3_FLAG_IPV6_NH);
        inet_pton(PF_INET, next_ip, &ipNextHopV4->ip);
        ipNextHopV4->ip = ntohl(ipNextHopV4->ip);
    }
    if (af == PF_INET6 && ipNextHopV6) {
        SetFlag(v3Record->flags, V3_FLAG_IPV6_NH);
        inet_pton(PF_INET6, next_ip, ipNextHopV6->ip);
        ipNextHopV6->ip[0] = ntohll(ipNextHopV6->ip[0]);
        ipNextHopV6->ip[1] = ntohll(ipNextHopV6->ip[1]);
    }

}  // End of SetNextIPaddress

static void SetRouterIPaddress(recordHandle_t *recordHandle, int af, char *router_ip) {
    EXipReceivedV4_t *ipReceivedV4 = (EXipReceivedV4_t *)recordHandle->extensionList[EXipReceivedV4ID];
    EXipReceivedV6_t *ipReceivedV6 = (EXipReceivedV6_t *)recordHandle->extensionList[EXipReceivedV6ID];
    recordHeaderV3_t *v3Record = recordHandle->recordHeaderV3;
    if (af == PF_INET && ipReceivedV4) {
        ClearFlag(v3Record->flags, V3_FLAG_IPV6_EXP);
        inet_pton(PF_INET, router_ip, &ipReceivedV4->ip);
        ipReceivedV4->ip = ntohl(ipReceivedV4->ip);
    }
    if (af == PF_INET6 && ipReceivedV6) {
        SetFlag(v3Record->flags, V3_FLAG_IPV6_EXP);
        inet_pton(PF_INET6, router_ip, ipReceivedV6->ip);
        ipReceivedV6->ip[0] = ntohll(ipReceivedV6->ip[0]);
        ipReceivedV6->ip[1] = ntohll(ipReceivedV6->ip[1]);
    }

}  // End of SetRouterIPaddress

static void SetBGPNextIPaddress(recordHandle_t *recordHandle, int af, char *next_ip) {
    EXbgpNextHopV4_t *bgpNextHopV4 = (EXbgpNextHopV4_t *)recordHandle->extensionList[EXbgpNextHopV4ID];
    EXbgpNextHopV6_t *bgpNextHopV6 = (EXbgpNextHopV6_t *)recordHandle->extensionList[EXbgpNextHopV6ID];
    recordHeaderV3_t *v3Record = recordHandle->recordHeaderV3;
    if (af == PF_INET && bgpNextHopV4) {
        ClearFlag(v3Record->flags, V3_FLAG_IPV6_NHB);
        inet_pton(PF_INET, next_ip, &bgpNextHopV4->ip);
        bgpNextHopV4->ip = ntohl(bgpNextHopV4->ip);
    }
    if (af == PF_INET6 && bgpNextHopV6) {
        SetFlag(v3Record->flags, V3_FLAG_IPV6_NHB);
        inet_pton(PF_INET6, next_ip, bgpNextHopV6->ip);
        bgpNextHopV6->ip[0] = ntohll(bgpNextHopV6->ip[0]);
        bgpNextHopV6->ip[1] = ntohll(bgpNextHopV6->ip[1]);
    }

}  // End of SetBGPNextIPaddress

static void UpdateRecord(recordHandle_t *recordHandle) {
    recordHeaderV3_t *v3Record = recordHandle->recordHeaderV3;
    // remap record
    MapRecordHandle(recordHandle, v3Record, ++recordHandle->flowCount);
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    if (!genericFlow) return;

    genericFlow->msecFirst = 1000LL * when + msecs;
    genericFlow->msecLast = 1000LL * when + offset + msecs + 10LL;
    genericFlow->msecReceived = genericFlow->msecLast - 1000LL + 1LL;

    genericFlow->srcPort += 10;
    genericFlow->dstPort += 11;

    genericFlow->inPackets += 1;
    genericFlow->inBytes += 1024;

    when += 10LL;
    offset += 10LL;

    msecs += 100LL;
    if (msecs > 1000LL) msecs = msecs - 1000LL;

    v3Record->engineID++;
    v3Record->engineType = offset;

}  // End of UpdateRecord

static void StoreRecord(recordHandle_t *recordHandle, nffile_t *nffile) {
    recordHeaderV3_t *v3Record = recordHandle->recordHeaderV3;

    uint32_t required = v3Record->size;

    // flush current buffer to disc if not enough space
    if (!CheckBufferSpace(nffile, required)) {
        return;
    }

    memcpy(nffile->buff_ptr, (void *)v3Record, required);
    nffile->block_header->NumRecords++;
    nffile->block_header->size += v3Record->size;
    nffile->buff_ptr += v3Record->size;

}  // End of StoreRecord

static void RemoveExtension(recordHandle_t *recordHandle, int extID) {
    recordHeaderV3_t *v3Record = recordHandle->recordHeaderV3;

    void *startPtr = NULL;
    void *endPtr = NULL;
    uint32_t size = v3Record->size - sizeof(recordHeaderV3_t);
    elementHeader_t *elementHeader = (elementHeader_t *)((void *)v3Record + sizeof(recordHeaderV3_t));
    for (int i = 0; i < v3Record->numElements; i++) {
        size -= elementHeader->length;
        if (elementHeader->type == extID) {
            startPtr = (void *)elementHeader;
            endPtr = startPtr + elementHeader->length;
        }
    }
    if (startPtr != NULL) {
        memmove(startPtr, endPtr, size);
    }
}  // end of RemoveExtension

int main(int argc, char **argv) {
    when = ISO2UNIX(strdup("201907111030"));

    if (!Init_nffile(1, NULL)) exit(254);

    nffile_t *nffile = OpenNewFile("test.flows.nf", NULL, CREATOR_UNKNOWN, NOT_COMPRESSED, 0);
    if (!nffile) {
        exit(255);
    }

    recordHeaderV3_t *record = calloc(1, 4096);
    recordHandle_t *recordHandle = calloc(1, sizeof(recordHandle_t));
    if (!record || !recordHandle) {
        perror("malloc() failed:");
        exit(255);
    }

    // add v3 header
    AddV3Header(record, v3Record);
    MapRecordHandle(recordHandle, v3Record, 1);

    // Start with empty record
    StoreRecord(recordHandle, nffile);

    // EXgenericFlowID
    PushExtension(v3Record, EXgenericFlow, genericFlow);
    genericFlow->fwdStatus = 1;
    genericFlow->tcpFlags = 2;
    genericFlow->srcTos = 3;
    genericFlow->srcPort = 12335;
    genericFlow->dstPort = 432;
    genericFlow->inPackets = 1;
    genericFlow->inBytes = 222;
    genericFlow->proto = IPPROTO_TCP;
    UpdateRecord(recordHandle);
    StoreRecord(recordHandle, nffile);

    // EXipv4FlowID
    PushExtension(v3Record, EXipv4Flow, ipv4Flow);
    UpdateRecord(recordHandle);
    SetIPaddress(recordHandle, PF_INET, "172.16.1.66", "192.168.170.100");
    StoreRecord(recordHandle, nffile);

    // EXipv6FlowID
    PushExtension(v3Record, EXipv6Flow, ipv6Flow);
    UpdateRecord(recordHandle);
    SetIPaddress(recordHandle, PF_INET6, "fe80::2110:abcd:1234:0", "fe80::2110:abcd:1235:4321");
    StoreRecord(recordHandle, nffile);

    RemoveExtension(recordHandle, EXipv6FlowID);

    // EXflowMiscID
    PushExtension(v3Record, EXflowMisc, flowMisc);
    UpdateRecord(recordHandle);
    SetIPaddress(recordHandle, PF_INET, "172.16.2.66", "192.168.170.101");

    genericFlow->srcPort = 80;
    genericFlow->dstPort = 22222;
    flowMisc->input = 100;
    flowMisc->output = 200;
    flowMisc->srcMask = 16;
    flowMisc->dstMask = 24;
    flowMisc->dir = 1;
    genericFlow->tcpFlags = 2;
    genericFlow->proto = IPPROTO_TCP;
    UpdateRecord(recordHandle);
    StoreRecord(recordHandle, nffile);

    genericFlow->msecFirst += 1000LL;
    genericFlow->msecLast += 1000LL;
    genericFlow->inPackets += 10;
    genericFlow->inBytes += 1024;
    genericFlow->tcpFlags = 16;
    StoreRecord(recordHandle, nffile);

    genericFlow->msecFirst += 1000LL;
    genericFlow->msecLast += 1000LL;
    genericFlow->inPackets += 10;
    genericFlow->inBytes += 1024;
    genericFlow->tcpFlags = 16;
    genericFlow->tcpFlags = 1;
    StoreRecord(recordHandle, nffile);

    SetIPaddress(recordHandle, PF_INET, "192.168.170.101", "172.16.2.66");
    genericFlow->msecFirst += 1;
    genericFlow->msecLast += 1;
    genericFlow->dstPort = 80;
    genericFlow->srcPort = 22222;
    flowMisc->input = 200;
    flowMisc->output = 100;
    flowMisc->srcMask = 24;
    flowMisc->dstMask = 16;
    genericFlow->tcpFlags = 18;
    genericFlow->proto = IPPROTO_TCP;
    flowMisc->dir = 2;
    genericFlow->inPackets = 10;
    genericFlow->inBytes = 1024;
    StoreRecord(recordHandle, nffile);

    genericFlow->msecFirst += 1000LL;
    genericFlow->msecLast += 1000LL;
    genericFlow->inPackets += 10;
    genericFlow->inBytes += 1024;
    genericFlow->tcpFlags = 16;
    StoreRecord(recordHandle, nffile);

    genericFlow->msecFirst += 1000LL;
    genericFlow->msecLast += 1000;
    genericFlow->inPackets += 10;
    genericFlow->inBytes += 1024;
    genericFlow->tcpFlags = 1;
    StoreRecord(recordHandle, nffile);

    // EXcntFlowID
    PushExtension(v3Record, EXcntFlow, cntFlow);
    UpdateRecord(recordHandle);
    SetIPaddress(recordHandle, PF_INET, "72.138.170.101", "42.16.32.6");

    genericFlow->tcpFlags++;
    cntFlow->outPackets = 203;
    cntFlow->outBytes = 204;
    cntFlow->flows = 7;
    UpdateRecord(recordHandle);
    StoreRecord(recordHandle, nffile);

    // EXvLanID
    PushExtension(v3Record, EXvLan, vLan);
    genericFlow->tcpFlags++;
    vLan->srcVlan = 45;
    vLan->dstVlan = 46;
    UpdateRecord(recordHandle);
    StoreRecord(recordHandle, nffile);

    // EXasRoutingID
    PushExtension(v3Record, EXasRouting, asRouting);
    genericFlow->tcpFlags++;
    asRouting->srcAS = 775;
    asRouting->dstAS = 3303;
    UpdateRecord(recordHandle);
    StoreRecord(recordHandle, nffile);

    // EXipNextHopV4ID
    PushExtension(v3Record, EXipNextHopV4, ipNextHopV4);
    genericFlow->tcpFlags++;
    SetNextIPaddress(recordHandle, PF_INET, "172.72.1.2");
    UpdateRecord(recordHandle);
    StoreRecord(recordHandle, nffile);

    // EXbgpNextHopV4ID
    PushExtension(v3Record, EXbgpNextHopV4, bgpNextHopV4);
    genericFlow->tcpFlags++;
    SetBGPNextIPaddress(recordHandle, PF_INET, "172.73.2.3");
    UpdateRecord(recordHandle);
    StoreRecord(recordHandle, nffile);

    // EXipReceivedV4ID
    PushExtension(v3Record, EXipReceivedV4, ipReceivedV4);
    genericFlow->tcpFlags++;
    SetRouterIPaddress(recordHandle, PF_INET, "127.0.0.1");
    UpdateRecord(recordHandle);
    StoreRecord(recordHandle, nffile);

    // EXmplsLabelID
    PushExtension(v3Record, EXmplsLabel, mplsLabel);
    genericFlow->tcpFlags++;
    mplsLabel->mplsLabel[0] = 1010 << 4;
    mplsLabel->mplsLabel[1] = 2020 << 4;
    mplsLabel->mplsLabel[2] = 3030 << 4;
    mplsLabel->mplsLabel[3] = 4040 << 4;
    mplsLabel->mplsLabel[4] = 5050 << 4;
    mplsLabel->mplsLabel[5] = 6060 << 4;
    mplsLabel->mplsLabel[6] = 7070 << 4;
    mplsLabel->mplsLabel[7] = 8080 << 4;
    mplsLabel->mplsLabel[8] = 9090 << 4;
    mplsLabel->mplsLabel[9] = (100100 << 4) + 1;
    UpdateRecord(recordHandle);
    StoreRecord(recordHandle, nffile);

    // EXmacAddrID
    PushExtension(v3Record, EXmacAddr, macAddr);
    genericFlow->tcpFlags++;
    macAddr->inSrcMac = 0x1234567890aaLL;
    macAddr->outDstMac = 0x2feeddccbbabLL;
    macAddr->inDstMac = 0x3aeeddccbbfcLL;
    macAddr->outSrcMac = 0x4a345678900dLL;
    UpdateRecord(recordHandle);
    StoreRecord(recordHandle, nffile);

    // EXasAdjacentID
    PushExtension(v3Record, EXasAdjacent, asAdjacent);
    genericFlow->tcpFlags++;
    asAdjacent->nextAdjacentAS = 7751;
    asAdjacent->prevAdjacentAS = 33032;
    UpdateRecord(recordHandle);
    StoreRecord(recordHandle, nffile);

    // EXlatencyID
    PushExtension(v3Record, EXlatency, latency);
    genericFlow->tcpFlags++;
    latency->usecClientNwDelay = 2;
    latency->usecServerNwDelay = 22;
    latency->usecApplLatency = 222;
    UpdateRecord(recordHandle);
    StoreRecord(recordHandle, nffile);

    /*
            record.exElementList[i] = 0;
            record.numElements = i;

            record.map_ref = 0;
            record.type	= CommonRecordType;

            record.flags   		= 0;
            record.exporter_sysid = 1;

            UpdateRecord(recordHandle);
            StoreRecord(recordHandle, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.2.66", "192.168.170.101");
            UpdateRecord(recordHandle);
            StoreRecord(recordHandle, nffile);

            genericFlow->inPackets 	 	= 101;
            record.inByytes 	 	= 102;
            UpdateRecord(recordHandle);
            StoreRecord(recordHandle, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.3.66", "192.168.170.102");
            UpdateRecord(recordHandle);
            StoreRecord(recordHandle, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.4.66", "192.168.170.103");
            record.srcPort 	 = 2024;
            record.proto 	 = IPPROTO_UDP;
            genericFlow->tcpFlags = 1;
            record.tos 		 = 1;
            genericFlow->inPackets 	 = 1001;
            record.inByytes 	 = 1002;
            UpdateRecord(recordHandle);
            StoreRecord(recordHandle, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.5.66", "192.168.170.104");
            record.srcPort 	 	= 3024;
            record.proto 	 	= 51;
            genericFlow->tcpFlags 	= 2;
            record.tos 		 	= 2;
            genericFlow->inPackets 	 	= 10001;
            record.inByytes 	 	= 10002;
            UpdateRecord(recordHandle);
            StoreRecord(recordHandle, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.6.66", "192.168.170.105");
            record.srcPort 	 	= 4024;
            record.proto 	 	= IPPROTO_TCP;
            genericFlow->tcpFlags 	= 4;
            record.tos 		 	= 3;
            genericFlow->inPackets 	 	= 100001;
            record.inByytes 	 	= 100002;
            UpdateRecord(recordHandle);
            StoreRecord(recordHandle, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.7.66", "192.168.170.106");
            record.srcPort 	 	= 5024;
            genericFlow->tcpFlags 	= 8;
            record.tos 		 	= 4;
            genericFlow->inPackets 	 	= 1000001;
            record.inByytes 	 	= 1000002;
            UpdateRecord(recordHandle);
            StoreRecord(recordHandle, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.8.66", "192.168.170.107");
            genericFlow->tcpFlags 	= 1;
            record.tos 		 	= 4;
            genericFlow->inPackets 	 	= 10000001;
            record.inByytes 	 	= 1001;
            UpdateRecord(recordHandle);
            StoreRecord(recordHandle, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.9.66", "192.168.170.108");
            record.srcPort 	 	= 6024;
            genericFlow->tcpFlags 	= 16;
            record.tos 		 	= 5;
            genericFlow->inPackets 	 	= 500;
            record.inByytes 	 	= 10000001;
            UpdateRecord(recordHandle);
            StoreRecord(recordHandle, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.10.66", "192.168.170.109");
            UpdateRecord(recordHandle);
            StoreRecord(recordHandle, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.11.66", "192.168.170.110");
            record.srcPort 		= 7024;
            genericFlow->tcpFlags 	= 32;
            record.tos 		 	= 255;
            genericFlow->inPackets 	 	= 5000;
            record.inByytes 	 	= 100000001;
            UpdateRecord(recordHandle);
            StoreRecord(recordHandle, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.12.66", "192.168.170.111");
            record.srcPort 	 	= 8024;
            genericFlow->tcpFlags 	= 63;
            record.tos 		 	= 0;
            record.inByytes 	 	= 1000000001;
            UpdateRecord(recordHandle);
            StoreRecord(recordHandle, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.13.66", "192.168.170.112");
            record.srcPort 	 	= 0;
            record.dstPort 	 	= 8;
            record.proto 	 	= 1;
            genericFlow->tcpFlags 	= 0;
            record.tos 		 	= 0;
            genericFlow->inPackets 	 	= 50002;
            record.inByytes 	 	= 50000;
            UpdateRecord(recordHandle);
            StoreRecord(recordHandle, nffile);

            SetIPaddress(&record,  PF_INET, "172.160.160.166", "172.160.160.180");
            record.srcPort 	 = 10024;
            record.dstPort 	 = 25000;
            record.proto 	 = IPPROTO_TCP;
            genericFlow->inPackets 	 = 500001;
            record.inByytes 	 = 500000;
            UpdateRecord(recordHandle);
            StoreRecord(recordHandle, nffile);

            SetIPaddress(&record,  PF_INET6, "fe80::2110:abcd:1234:0", "fe80::2110:abcd:1235:4321");
            SetNextIPaddress(&record,  PF_INET6, "2003:234:aabb::211:24ff:fe80:d01e");
            SetBGPNextIPaddress(&record,  PF_INET6, "2004:234:aabb::211:24ff:fe80:d01e");
            record.srcPort 	 = 1024;
            record.dstPort 	 = 25;
            genericFlow->tcpFlags = 27;
            genericFlow->inPackets 	 = 10;
            record.inByytes 	 = 15100;
            UpdateRecord(recordHandle);
            StoreRecord(recordHandle, nffile);

            SetIPaddress(&record,  PF_INET6, "2001:234:aabb::211:24ff:fe80:d01e", "2001:620::8:203:baff:fe52:38e5");
            record.srcPort 	 = 10240;
            record.dstPort 	 = 52345;
            genericFlow->inPackets 	 = 10100;
            record.inByytes 	 = 15000000;
            UpdateRecord(recordHandle);
            StoreRecord(recordHandle, nffile);

            genericFlow->inPackets 	 = 10100000;
            record.inByytes 	 = 0x100000000LL;
            UpdateRecord(recordHandle);
            StoreRecord(recordHandle, nffile);

            genericFlow->inPackets 	 = 0x100000000LL;
            record.inByytes 	 = 15000000;
            UpdateRecord(recordHandle);
            StoreRecord(recordHandle, nffile);

            record.inByytes 	 = 0x200000000LL;
            UpdateRecord(recordHandle);
            StoreRecord(recordHandle, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.14.18", "192.168.170.113");
            SetNextIPaddress(&record,  PF_INET, "172.72.1.2");
            SetBGPNextIPaddress(&record,  PF_INET, "172.73.2.3");
            record.srcPort 	 = 10240;
            record.dstPort 	 = 52345;
            genericFlow->inPackets 	 = 10100000;
            record.inByytes 	 = 0x100000000LL;
            UpdateRecord(recordHandle);
            StoreRecord(recordHandle, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.15.18", "192.168.170.114");
            genericFlow->inPackets 	 = 0x100000000LL;
            record.inByytes 	 = 15000000;
            UpdateRecord(recordHandle);
            StoreRecord(recordHandle, nffile);

            SetIPaddress(&record,  PF_INET, "172.16.16.18", "192.168.170.115");
            record.inByytes 	 = 0x200000000LL;
            UpdateRecord(recordHandle);
            StoreRecord(recordHandle, nffile);
    */
    if (nffile->block_header->NumRecords) {
        if (WriteBlock(nffile) <= 0) {
            fprintf(stderr, "Failed to write output buffer to disk: '%s'", strerror(errno));
        }
    }
    CloseUpdateFile(nffile);
    return 0;
}
