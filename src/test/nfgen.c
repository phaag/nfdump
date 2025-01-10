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

static void DumpRecord(recordHeaderV3_t *recordHeaderV3);

#define AssertMapRecordHandle(a, b, c)   \
    if (MapRecordHandle(a, b, c) == 0) { \
        DumpHex(stdout, b, 256);         \
        DumpRecord(b);                   \
        exit(255);                       \
    }

static void SetIPaddress(recordHandle_t *recordHandle, int af, char *src_ip, char *dst_ip);

static void SetNextIPaddress(recordHandle_t *recordHandle, int af, char *next_ip);

static void SetRouterIPaddress(recordHandle_t *recordHandle, int af, char *next_ip);

static void SetBGPNextIPaddress(recordHandle_t *recordHandle, int af, char *next_ip);

static void UpdateRecord(recordHandle_t *recordHandle);

static dataBlock_t *StoreRecord(recordHandle_t *recordHandle, nffile_t *nffile, dataBlock_t *dataBlock);

static void DumpRecord(recordHeaderV3_t *recordHeaderV3) {
    printf("V3Record: %u size: %u\n", recordHeaderV3->type, recordHeaderV3->size);
    printf(" Elements    : %u\n", recordHeaderV3->numElements);
    printf(" Element Type: %u\n", recordHeaderV3->engineType);
    printf(" Element ID  : %u\n", recordHeaderV3->engineID);
    printf(" Exporter ID : %u\n", recordHeaderV3->exporterID);
    printf(" Flags       : %u\n", recordHeaderV3->flags);
    elementHeader_t *elementHeader = (elementHeader_t *)((void *)recordHeaderV3 + sizeof(recordHeaderV3_t));
    for (int i = 0; i < recordHeaderV3->numElements; i++) {
        printf(" ExtID : %u, Length: %u\n", elementHeader->type, elementHeader->length);
        if (elementHeader->type <= 0 || elementHeader->type >= MAXEXTENSIONS) {
            LogError("Invalid extension '%u'", elementHeader->type);
            return;
        }
        elementHeader = (elementHeader_t *)((void *)elementHeader + elementHeader->length);
    }
}

static void SetIPaddress(recordHandle_t *recordHandle, int af, char *src_ip, char *dst_ip) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];
    if (af == PF_INET && ipv4Flow) {
        inet_pton(PF_INET, src_ip, &ipv4Flow->srcAddr);
        inet_pton(PF_INET, dst_ip, &ipv4Flow->dstAddr);
        ipv4Flow->srcAddr = ntohl(ipv4Flow->srcAddr);
        ipv4Flow->dstAddr = ntohl(ipv4Flow->dstAddr);
    }
    if (af == PF_INET6 && ipv6Flow) {
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
    if (af == PF_INET && ipNextHopV4) {
        inet_pton(PF_INET, next_ip, &ipNextHopV4->ip);
        ipNextHopV4->ip = ntohl(ipNextHopV4->ip);
    }
    if (af == PF_INET6 && ipNextHopV6) {
        // XXX SetFlag(v3Record->flags, V3_FLAG_IPV6_NH);
        inet_pton(PF_INET6, next_ip, ipNextHopV6->ip);
        ipNextHopV6->ip[0] = ntohll(ipNextHopV6->ip[0]);
        ipNextHopV6->ip[1] = ntohll(ipNextHopV6->ip[1]);
    }

}  // End of SetNextIPaddress

static void SetRouterIPaddress(recordHandle_t *recordHandle, int af, char *router_ip) {
    EXipReceivedV4_t *ipReceivedV4 = (EXipReceivedV4_t *)recordHandle->extensionList[EXipReceivedV4ID];
    EXipReceivedV6_t *ipReceivedV6 = (EXipReceivedV6_t *)recordHandle->extensionList[EXipReceivedV6ID];
    if (af == PF_INET && ipReceivedV4) {
        inet_pton(PF_INET, router_ip, &ipReceivedV4->ip);
        ipReceivedV4->ip = ntohl(ipReceivedV4->ip);
    }
    if (af == PF_INET6 && ipReceivedV6) {
        inet_pton(PF_INET6, router_ip, ipReceivedV6->ip);
        ipReceivedV6->ip[0] = ntohll(ipReceivedV6->ip[0]);
        ipReceivedV6->ip[1] = ntohll(ipReceivedV6->ip[1]);
    }

}  // End of SetRouterIPaddress

static void SetBGPNextIPaddress(recordHandle_t *recordHandle, int af, char *next_ip) {
    EXbgpNextHopV4_t *bgpNextHopV4 = (EXbgpNextHopV4_t *)recordHandle->extensionList[EXbgpNextHopV4ID];
    EXbgpNextHopV6_t *bgpNextHopV6 = (EXbgpNextHopV6_t *)recordHandle->extensionList[EXbgpNextHopV6ID];
    if (af == PF_INET && bgpNextHopV4) {
        inet_pton(PF_INET, next_ip, &bgpNextHopV4->ip);
        bgpNextHopV4->ip = ntohl(bgpNextHopV4->ip);
    }
    if (af == PF_INET6 && bgpNextHopV6) {
        inet_pton(PF_INET6, next_ip, bgpNextHopV6->ip);
        bgpNextHopV6->ip[0] = ntohll(bgpNextHopV6->ip[0]);
        bgpNextHopV6->ip[1] = ntohll(bgpNextHopV6->ip[1]);
    }

}  // End of SetBGPNextIPaddress

static void UpdateRecord(recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    if (!genericFlow) return;

    genericFlow->msecFirst = genericFlow->msecLast + offset;
    genericFlow->msecLast += 2002LL;
    genericFlow->inPackets += 10;
    genericFlow->inBytes += 223344;

    offset += 10LL;

}  // End of UpdateRecord

static dataBlock_t *StoreRecord(recordHandle_t *recordHandle, nffile_t *nffile, dataBlock_t *dataBlock) {
    static uint32_t recordCount = 1;
    recordHandle->flowCount = recordCount++;
    recordHeaderV3_t *v3Record = recordHandle->recordHeaderV3;

    v3Record->engineID++;
    v3Record->engineType++;

    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    if (genericFlow) {
        genericFlow->msecFirst++;
        if (nffile->stat_record->firstseen == 0 || genericFlow->msecFirst < nffile->stat_record->firstseen) {
            nffile->stat_record->firstseen = genericFlow->msecFirst;
        }
        if (nffile->stat_record->lastseen == 0 || genericFlow->msecLast > nffile->stat_record->lastseen) {
            nffile->stat_record->lastseen = genericFlow->msecLast;
        }
        // Update stats
        switch (genericFlow->proto) {
            case IPPROTO_ICMP:
                nffile->stat_record->numflows_icmp++;
                nffile->stat_record->numpackets_icmp += genericFlow->inPackets;
                nffile->stat_record->numbytes_icmp += genericFlow->inBytes;
                break;
            case IPPROTO_TCP:
                nffile->stat_record->numflows_tcp++;
                nffile->stat_record->numpackets_tcp += genericFlow->inPackets;
                nffile->stat_record->numbytes_tcp += genericFlow->inBytes;
                break;
            case IPPROTO_UDP:
                nffile->stat_record->numflows_udp++;
                nffile->stat_record->numpackets_udp += genericFlow->inPackets;
                nffile->stat_record->numbytes_udp += genericFlow->inBytes;
                break;
            default:
                nffile->stat_record->numflows_other++;
                nffile->stat_record->numpackets_other += genericFlow->inPackets;
                nffile->stat_record->numbytes_other += genericFlow->inBytes;
        }
        nffile->stat_record->numpackets += genericFlow->inPackets;
        nffile->stat_record->numbytes += genericFlow->inBytes;
    }
    EXcntFlow_t *cntFlow = (EXcntFlow_t *)recordHandle->extensionList[EXcntFlowID];
    if (cntFlow)
        nffile->stat_record->numflows += cntFlow->flows;
    else
        nffile->stat_record->numflows++;

    uint32_t required = v3Record->size;

    if (!IsAvailable(dataBlock, required)) {
        // flush block - get an empty one
        dataBlock = WriteBlock(nffile, dataBlock);
    }

    void *buffPtr = GetCurrentCursor(dataBlock);
    memcpy(buffPtr, (void *)v3Record, required);
    dataBlock->NumRecords++;
    dataBlock->size += v3Record->size;

    return dataBlock;
}  // End of StoreRecord

static void RemoveExtension(recordHandle_t *recordHandle, int extID) {
    recordHeaderV3_t *v3Record = recordHandle->recordHeaderV3;

    void *startPtr = NULL;
    void *endPtr = NULL;
    uint32_t size = v3Record->size - sizeof(recordHeaderV3_t);
    uint32_t elementSize = 0;
    elementHeader_t *elementHeader = (elementHeader_t *)((void *)v3Record + sizeof(recordHeaderV3_t));
    for (int i = 0; i < v3Record->numElements; i++) {
        size -= elementHeader->length;
        if (elementHeader->type == extID) {
            startPtr = (void *)elementHeader;
            endPtr = startPtr + elementHeader->length;
            elementSize = elementHeader->length;
            break;
        }
        elementHeader = (elementHeader_t *)((void *)elementHeader + elementHeader->length);
    }
    if (startPtr != NULL) {
        memmove(startPtr, endPtr, size);
        v3Record->numElements--;
        v3Record->size -= elementSize;
    }
    AssertMapRecordHandle(recordHandle, v3Record, recordHandle->flowCount);

}  // end of RemoveExtension

int main(int argc, char **argv) {
    when = ISO2UNIX(strdup("201907111030"));

    if (!Init_nffile(1, NULL)) exit(254);

    nffile_t *nffile = OpenNewFile("dummy_flows.nf", NULL, CREATOR_UNKNOWN, NOT_COMPRESSED, 0);
    if (!nffile) {
        exit(255);
    }
    SetIdent(nffile, "TestFlows");
    dataBlock_t *dataBlock = WriteBlock(nffile, NULL);

    recordHeaderV3_t *record = (recordHeaderV3_t *)calloc(1, 4096);
    recordHandle_t *recordHandle = (recordHandle_t *)calloc(1, sizeof(recordHandle_t));
    if (!record || !recordHandle) {
        perror("calloc() failed:");
        exit(255);
    }

    // add v3 header
    AddV3Header(record, v3Record);
    AssertMapRecordHandle(recordHandle, v3Record, 0);
    // Start with empty record
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    // fill record Header
    v3Record->engineType = 0;
    v3Record->engineID = 1;
    v3Record->exporterID = 3;
    v3Record->nfversion = 10;
    recordHandle->flowCount++;
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    // EXgenericFlowID
    PushExtension(v3Record, EXgenericFlow, genericFlow);
    AssertMapRecordHandle(recordHandle, v3Record, 0);
    genericFlow->msecFirst = 1000LL * when + 234LL;
    genericFlow->msecLast = genericFlow->msecFirst + 2000LL;
    genericFlow->msecReceived = 1000LL * when + 1;
    genericFlow->inPackets = 1;
    genericFlow->inBytes = 222;
    genericFlow->srcPort = 12345;
    genericFlow->dstPort = 433;
    genericFlow->proto = IPPROTO_TCP;
    genericFlow->tcpFlags = 2;
    genericFlow->fwdStatus = 1;
    genericFlow->srcTos = 3;
    recordHandle->flowCount++;
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    // as we remove ipv4flow below, we need a local context
    do {
        // EXipv4FlowID
        PushExtension(v3Record, EXipv4Flow, ipv4Flow);
        AssertMapRecordHandle(recordHandle, v3Record, 0);
        SetIPaddress(recordHandle, PF_INET, "172.16.1.66", "192.168.170.100");
        dataBlock = StoreRecord(recordHandle, nffile, dataBlock);
    } while (0);

    // EXipv6FlowID
    RemoveExtension(recordHandle, EXipv4FlowID);
    PushExtension(v3Record, EXipv6Flow, ipv6Flow);
    AssertMapRecordHandle(recordHandle, v3Record, 0);
    SetIPaddress(recordHandle, PF_INET6, "fe80::2110:abcd:1234:0", "fe80::2110:abcd:1235:4321");
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    // multiple IPv6 flows
    genericFlow->msecFirst = genericFlow->msecLast + 100LL;
    genericFlow->msecLast += 2002LL;
    genericFlow->inPackets = 10;
    genericFlow->inBytes = 223344;
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);
    genericFlow->msecFirst = genericFlow->msecLast + 200LL;
    genericFlow->msecLast += 3003LL;
    genericFlow->inPackets = 25;
    genericFlow->inBytes = 33445566LL;
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    // bring back ipv4
    PushExtension(v3Record, EXipv4Flow, ipv4Flow);
    AssertMapRecordHandle(recordHandle, v3Record, 0);
    SetIPaddress(recordHandle, PF_INET, "172.16.1.68", "192.168.170.104");
    // this record has ipv4 and ipv6 records
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    // remove v6 extension
    RemoveExtension(recordHandle, EXipv6FlowID);

    // EXflowMiscID
    PushExtension(v3Record, EXflowMisc, flowMisc);
    AssertMapRecordHandle(recordHandle, v3Record, 0);
    SetIPaddress(recordHandle, PF_INET, "172.16.2.66", "192.168.170.101");

    flowMisc->input = 100;
    flowMisc->output = 200;
    flowMisc->srcMask = 16;
    flowMisc->dstMask = 24;
    flowMisc->dir = 1;
    flowMisc->dstTos = 4;
    flowMisc->biFlowDir = 0;
    genericFlow->srcPort = 80;
    genericFlow->dstPort = 22222;
    genericFlow->tcpFlags = 3;
    genericFlow->proto = IPPROTO_TCP;
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    // next flow
    UpdateRecord(recordHandle);
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    genericFlow->srcPort = 33333;
    genericFlow->dstPort = 5353;
    genericFlow->tcpFlags = 0;
    genericFlow->proto = IPPROTO_UDP;
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    SetIPaddress(recordHandle, PF_INET, "192.168.170.101", "172.16.2.66");
    UpdateRecord(recordHandle);
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);
    UpdateRecord(recordHandle);
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    SetIPaddress(recordHandle, PF_INET, "172.16.2.67", "192.168.170.102");
    genericFlow->srcPort = 0;
    genericFlow->icmpType = 1;
    genericFlow->icmpCode = 8;
    genericFlow->tcpFlags = 0;
    genericFlow->inPackets = 1;
    genericFlow->inBytes = 22;
    genericFlow->proto = IPPROTO_ICMP;
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    SetIPaddress(recordHandle, PF_INET, "192.168.170.102", "172.16.2.67");
    genericFlow->icmpType = 0;
    genericFlow->icmpCode = 3;
    genericFlow->tcpFlags = 0;
    genericFlow->inPackets = 1;
    genericFlow->inBytes = 35;
    genericFlow->msecFirst = genericFlow->msecLast + 200LL;
    genericFlow->msecLast += 3003LL;
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    SetIPaddress(recordHandle, PF_INET, "192.168.170.101", "172.16.2.66");
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
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    UpdateRecord(recordHandle);
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    UpdateRecord(recordHandle);
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    UpdateRecord(recordHandle);
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    // EXcntFlowID
    PushExtension(v3Record, EXcntFlow, cntFlow);
    AssertMapRecordHandle(recordHandle, v3Record, 0);
    UpdateRecord(recordHandle);
    SetIPaddress(recordHandle, PF_INET, "72.138.170.101", "42.16.32.6");

    cntFlow->outPackets = 203;
    cntFlow->outBytes = 44556677LL;
    cntFlow->flows = 7;
    UpdateRecord(recordHandle);
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    // EXvLanID
    PushExtension(v3Record, EXvLan, vLan);
    AssertMapRecordHandle(recordHandle, v3Record, 0);
    vLan->srcVlan = 45;
    vLan->dstVlan = 46;
    UpdateRecord(recordHandle);
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    // EXasRoutingID
    PushExtension(v3Record, EXasRouting, asRouting);
    AssertMapRecordHandle(recordHandle, v3Record, 0);
    asRouting->srcAS = 775;
    asRouting->dstAS = 3303;
    UpdateRecord(recordHandle);
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    // EXipNextHopV6ID
    PushExtension(v3Record, EXipNextHopV6, ipNextHopV6);
    AssertMapRecordHandle(recordHandle, v3Record, 0);
    SetNextIPaddress(recordHandle, PF_INET6, "2001::1110:bcde:1234:4");
    UpdateRecord(recordHandle);
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    // EXipNextHopV4ID
    RemoveExtension(recordHandle, EXipNextHopV6ID);
    PushExtension(v3Record, EXipNextHopV4, ipNextHopV4);
    AssertMapRecordHandle(recordHandle, v3Record, 0);
    SetNextIPaddress(recordHandle, PF_INET, "172.72.1.2");
    UpdateRecord(recordHandle);
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    // EXbgpNextHopV6ID
    PushExtension(v3Record, EXbgpNextHopV6, bgpNextHopV6);
    AssertMapRecordHandle(recordHandle, v3Record, 0);
    SetBGPNextIPaddress(recordHandle, PF_INET6, "2002::1210:cdef:2346:5");
    UpdateRecord(recordHandle);
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    // EXbgpNextHopV4ID
    RemoveExtension(recordHandle, EXbgpNextHopV6ID);
    PushExtension(v3Record, EXbgpNextHopV4, bgpNextHopV4);
    AssertMapRecordHandle(recordHandle, v3Record, 0);
    SetBGPNextIPaddress(recordHandle, PF_INET, "172.73.2.3");
    UpdateRecord(recordHandle);
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    // EXipReceivedV6ID
    PushExtension(v3Record, EXipReceivedV6, ipReceivedV6);
    AssertMapRecordHandle(recordHandle, v3Record, 0);
    SetRouterIPaddress(recordHandle, PF_INET6, "fe80::caffe:caffe:1234:1");
    UpdateRecord(recordHandle);
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    // EXipReceivedV4ID
    RemoveExtension(recordHandle, EXipReceivedV6ID);
    PushExtension(v3Record, EXipReceivedV4, ipReceivedV4);
    AssertMapRecordHandle(recordHandle, v3Record, 0);
    SetRouterIPaddress(recordHandle, PF_INET, "127.0.0.1");
    UpdateRecord(recordHandle);
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    // EXmplsLabelID
    PushExtension(v3Record, EXmplsLabel, mplsLabel);
    AssertMapRecordHandle(recordHandle, v3Record, 0);
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
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    // EXmacAddrID
    PushExtension(v3Record, EXmacAddr, macAddr);
    AssertMapRecordHandle(recordHandle, v3Record, 0);
    macAddr->inSrcMac = 0x1234567890aaLL;
    macAddr->outDstMac = 0x2feeddccbbabLL;
    macAddr->inDstMac = 0x3aeeddccbbfcLL;
    macAddr->outSrcMac = 0x4a345678900dLL;
    UpdateRecord(recordHandle);
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    // EXasAdjacentID
    PushExtension(v3Record, EXasAdjacent, asAdjacent);
    AssertMapRecordHandle(recordHandle, v3Record, 0);
    asAdjacent->nextAdjacentAS = 7751;
    asAdjacent->prevAdjacentAS = 33032;
    UpdateRecord(recordHandle);
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    // EXlatencyID
    PushExtension(v3Record, EXlatency, latency);
    AssertMapRecordHandle(recordHandle, v3Record, 0);
    latency->usecClientNwDelay = 2;
    latency->usecServerNwDelay = 22;
    latency->usecApplLatency = 222;
    UpdateRecord(recordHandle);
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    // remove extension
    RemoveExtension(recordHandle, EXvLanID);

    // EXlayer2
    PushExtension(v3Record, EXlayer2, layer2);
    AssertMapRecordHandle(recordHandle, v3Record, 0);
    layer2->vlanID = 47;
    layer2->postVlanID = 48;
    layer2->customerVlanId = 49;
    layer2->postCustomerVlanId = 50;
    layer2->ingress = 112233;
    layer2->egress = 445566;
    UpdateRecord(recordHandle);
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    // EXnatCommon
    PushExtension(v3Record, EXnatCommon, natCommon);
    AssertMapRecordHandle(recordHandle, v3Record, 0);
    natCommon->natEvent = 1;
    natCommon->msecEvent = genericFlow->msecFirst;
    natCommon->natPoolID = 5;

    // EXnatPortBlock
    PushExtension(v3Record, EXnatPortBlock, natPortBlock);
    AssertMapRecordHandle(recordHandle, v3Record, 0);
    natPortBlock->blockStart = 1024;
    natPortBlock->blockEnd = 16534;
    natPortBlock->blockStep = 2;
    natPortBlock->blockSize = 4096;

    // EXnatXlateIPv4
    PushExtension(v3Record, EXnatXlatePort, natXlatePort);
    AssertMapRecordHandle(recordHandle, v3Record, 0);
    natXlatePort->xlateSrcPort = 55667;
    natXlatePort->xlateDstPort = 443;

    PushExtension(v3Record, EXnatXlateIPv4, natXlateIPv4);
    AssertMapRecordHandle(recordHandle, v3Record, 0);
    inet_pton(PF_INET, "44.55.66.77", &natXlateIPv4->xlateSrcAddr);
    inet_pton(PF_INET, "8.8.8.8", &natXlateIPv4->xlateDstAddr);
    natXlateIPv4->xlateSrcAddr = ntohl(natXlateIPv4->xlateSrcAddr);
    natXlateIPv4->xlateDstAddr = ntohl(natXlateIPv4->xlateDstAddr);
    UpdateRecord(recordHandle);
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    PushExtension(v3Record, EXipInfo, ipInfo);
    AssertMapRecordHandle(recordHandle, v3Record, 0);
    ipInfo->minTTL = 40;
    ipInfo->maxTTL = 255;
    ipInfo->fragmentFlags = flagDF;

    UpdateRecord(recordHandle);
    dataBlock = StoreRecord(recordHandle, nffile, dataBlock);

    FlushBlock(nffile, dataBlock);
    CloseUpdateFile(nffile);
    return 0;
}
