/*
 *  Copyright (c) 2024, Peter Haag
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

#include <arpa/inet.h>
#include <ctype.h>
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

#include "filter.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfxV3.h"
#include "output_short.h"
#include "userio.h"
#include "util.h"

/* global MapReord function */
#include "nffile_inline.c"

/* Functions */

static void DumpRecord(recordHandle_t *recordHandle) {
    printf("V3 Record:\n");
    DumpHex(stdout, (void *)recordHandle, sizeof(recordHeaderV3_t));
    for (int i = 0; i < MAXEXTENSIONS; i++) {
        void *element = (void *)recordHandle->extensionList[i];
        if (element) {
            elementHeader_t *elementHeader = (elementHeader_t *)(element - sizeof(elementHeader_t));
            printf("Element: %u\n", elementHeader->type);
            DumpHex(stdout, (void *)elementHeader, elementHeader->length);
        }
    }

    printf("Count: %u\n", recordHandle->flowCount);
    printf("Ja3: ");
    DumpHex(stdout, (void *)recordHandle->ja3, sizeof(recordHandle->ja3));

    printf("Geo: ");
    DumpHex(stdout, (void *)recordHandle->geo, sizeof(recordHandle->geo));
}

static void CheckFilter(char *filter, recordHandle_t *recordHandle, int expect) {
    void *engine = CompileFilter(filter);
    if (!engine) {
        printf("*** Compile %s failed\n", filter);
        if (expect != -1)
            exit(255);
        else
            return;
    } else {
        printf("Compiled ok: %s\n", filter);
    }
    int ret = FilterRecord(engine, recordHandle, NULL);
    if (ret != expect) {
        printf("*** Filter failed for %s\n", filter);
        printf("*** Expected %d, result: %d\n", expect, ret);
        DumpEngine(engine);
        DumpRecord(recordHandle);
        exit(255);
    }
    DisposeFilter(engine);
}

static void runTest(void) {
    void *p = malloc(4192);
    AddV3Header(p, recordHeaderV3);
    recordHandle_t *recordHandle = calloc(1, sizeof(recordHandle_t));
    if (!recordHandle) {
        perror("malloc() failed:");
        exit(255);
    }
    MapRecordHandle(recordHandle, recordHeaderV3, 1);
    CheckFilter("count 1", recordHandle, 1);
    CheckFilter("count 2", recordHandle, 0);
    CheckFilter("count > 2", recordHandle, 0);

    // no extension
    CheckFilter("any", recordHandle, 1);

    // Record header
    recordHeaderV3->engineType = 3;
    recordHeaderV3->engineID = 8;
    CheckFilter("engine-type 4", recordHandle, 0);
    CheckFilter("engine-type 3", recordHandle, 1);
    CheckFilter("engine type 3", recordHandle, 1);
    CheckFilter("engine-id 9", recordHandle, 0);
    CheckFilter("engine-id 8", recordHandle, 1);
    CheckFilter("engine id 8", recordHandle, 1);
    recordHeaderV3->exporterID = 12345;
    CheckFilter("exporter id 12345", recordHandle, 1);
    CheckFilter("exporter id 8", recordHandle, 0);

    // non existing extension
    CheckFilter("src port 80", recordHandle, 0);

    // EXgenericFlowID
    PushExtension(recordHeaderV3, EXgenericFlow, genericFlow);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);

    genericFlow->srcPort = 80;
    CheckFilter("src port 80", recordHandle, 1);
    CheckFilter("not src port 80", recordHandle, 0);
    CheckFilter("src port 81", recordHandle, 0);
    CheckFilter("src port 79", recordHandle, 0);

    genericFlow->srcPort = 0x1122;
    genericFlow->dstPort = 80;
    CheckFilter("src port 0x1122", recordHandle, 1);
    CheckFilter("not src port 80", recordHandle, 1);
    CheckFilter("dst port 80", recordHandle, 1);
    CheckFilter("dst port > 79", recordHandle, 1);
    CheckFilter("dst port > 80", recordHandle, 0);
    CheckFilter("dst port < 80", recordHandle, 0);
    CheckFilter("port > 79 and port < 81", recordHandle, 1);

    genericFlow->proto = 17;
    CheckFilter("proto 17", recordHandle, 1);
    CheckFilter("proto tcp", recordHandle, 0);
    CheckFilter("proto udp", recordHandle, 1);
    CheckFilter("proto foobar", recordHandle, -1);

    genericFlow->proto = 1;
    CheckFilter("icmp-type 3", recordHandle, 0);
    genericFlow->icmpType = 3;
    CheckFilter("icmp-type 3", recordHandle, 1);
    CheckFilter("icmp type 3", recordHandle, 1);
    CheckFilter("icmp-code 8", recordHandle, 0);
    genericFlow->icmpCode = 8;
    CheckFilter("icmp-code 8", recordHandle, 1);
    CheckFilter("icmp code 8", recordHandle, 1);

    genericFlow->inPackets = 100;
    CheckFilter("packets 100", recordHandle, 1);
    CheckFilter("packets 1", recordHandle, 0);
    CheckFilter("packets > 1", recordHandle, 1);
    CheckFilter("packets < 101", recordHandle, 1);

    CheckFilter("bytes 200", recordHandle, 0);
    genericFlow->inBytes = 200;
    CheckFilter("bytes 200", recordHandle, 1);
    CheckFilter("bytes 2", recordHandle, 0);
    CheckFilter("bytes > 2", recordHandle, 1);
    CheckFilter("bytes < 201", recordHandle, 1);

    CheckFilter("duration > 0", recordHandle, 0);
    genericFlow->msecLast = time(0) * 1000;
    genericFlow->msecFirst = genericFlow->msecLast - (10 * 1000);
    CheckFilter("duration > 1", recordHandle, 1);
    CheckFilter("duration >= 10000", recordHandle, 1);
    CheckFilter("duration >= 10001", recordHandle, 0);

    genericFlow->inPackets = 100;
    CheckFilter("pps > 1", recordHandle, 1);
    CheckFilter("pps 10", recordHandle, 1);
    CheckFilter("pps > 10", recordHandle, 0);

    genericFlow->inBytes = 200;
    CheckFilter("bps > 2", recordHandle, 1);
    CheckFilter("bps 160", recordHandle, 1);
    CheckFilter("bps > 160", recordHandle, 0);

    CheckFilter("bpp 2", recordHandle, 1);
    CheckFilter("bpp > 2", recordHandle, 0);

    genericFlow->proto = IPPROTO_TCP;
    genericFlow->tcpFlags = 1;  // FIN
    CheckFilter("flags F", recordHandle, 1);
    CheckFilter("flags S", recordHandle, 0);
    CheckFilter("flags R", recordHandle, 0);
    CheckFilter("flags P", recordHandle, 0);
    CheckFilter("flags A", recordHandle, 0);
    CheckFilter("flags U", recordHandle, 0);
    CheckFilter("flags X", recordHandle, 0);

    genericFlow->tcpFlags = 2;  // SYN
    CheckFilter("flags S", recordHandle, 1);
    genericFlow->tcpFlags = 4;  // RST
    CheckFilter("flags R", recordHandle, 1);
    genericFlow->tcpFlags = 8;  // PUSH
    CheckFilter("flags P", recordHandle, 1);
    genericFlow->tcpFlags = 16;  // ACK
    CheckFilter("flags A", recordHandle, 1);
    genericFlow->tcpFlags = 32;  // URG
    CheckFilter("flags U", recordHandle, 1);
    genericFlow->tcpFlags = 63;  // Xmas
    CheckFilter("flags X", recordHandle, 1);

    CheckFilter("flags S", recordHandle, 1);
    CheckFilter("flags RF", recordHandle, 1);
    genericFlow->tcpFlags = 16;
    CheckFilter("not flags RF", recordHandle, 1);

    genericFlow->tcpFlags = 63;
    CheckFilter("flags =S", recordHandle, 0);
    genericFlow->tcpFlags = 2;
    CheckFilter("flags =S", recordHandle, 1);
    genericFlow->tcpFlags = 18;
    CheckFilter("flags =SA", recordHandle, 1);

    genericFlow->tcpFlags = 3;  // flags SF
    CheckFilter("flags SF", recordHandle, 1);
    CheckFilter("flags 3", recordHandle, 1);
    CheckFilter("flags SF and not flags AR", recordHandle, 1);
    CheckFilter("flags SF", recordHandle, 1);
    genericFlow->tcpFlags = 7;
    CheckFilter("flags R", recordHandle, 1);
    CheckFilter("flags P", recordHandle, 0);
    CheckFilter("flags A", recordHandle, 0);

    CheckFilter("flags = 7", recordHandle, 1);
    CheckFilter("flags > 7", recordHandle, 0);
    CheckFilter("flags > 6", recordHandle, 1);
    CheckFilter("flags < 7", recordHandle, 0);
    CheckFilter("flags < 8", recordHandle, 1);

    genericFlow->srcTos = 10;
    CheckFilter("src tos 10", recordHandle, 1);
    CheckFilter("src tos 11", recordHandle, 0);
    CheckFilter("src tos 9", recordHandle, 0);
    CheckFilter("src tos > 9", recordHandle, 1);
    CheckFilter("src tos < 11", recordHandle, 1);

    genericFlow->fwdStatus = 25;
    CheckFilter("fwdstat 25", recordHandle, 1);
    CheckFilter("fwdstat DbadTTL", recordHandle, 1);
    CheckFilter("fwdstat 24", recordHandle, 0);
    CheckFilter("fwdstat 26", recordHandle, 0);

    // EXipv4FlowID
    CheckFilter("ipv4", recordHandle, 0);
    CheckFilter("ipv6", recordHandle, 0);
    CheckFilter("src ip 4.4.4.4", recordHandle, 0);
    CheckFilter("src ip 2001:620:0:ff::5c", recordHandle, 0);
    PushExtension(recordHeaderV3, EXipv4Flow, ipv4);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);
    CheckFilter("ipv4", recordHandle, 1);
    CheckFilter("ipv6", recordHandle, 0);
    PushExtension(recordHeaderV3, EXipv6Flow, ipv6);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);
    CheckFilter("ipv6", recordHandle, 1);
    uint32_t v4 = 0;
    inet_pton(PF_INET, "1.2.3.4", &v4);
    ipv4->srcAddr = ntohl(v4);
    CheckFilter("src ip 1.2.3.4", recordHandle, 1);
    CheckFilter("dst ip 1.2.3.4", recordHandle, 0);
    CheckFilter("ip 1.2.3.4", recordHandle, 1);
    ipv4->dstAddr = ipv4->srcAddr;
    ipv4->srcAddr = 0;
    CheckFilter("src ip 1.2.3.4", recordHandle, 0);
    CheckFilter("dst ip 1.2.3.4", recordHandle, 1);
    CheckFilter("ip 1.2.3.4", recordHandle, 1);

    // EXipv6FlowID
    uint64_t v6[2];
    inet_pton(PF_INET6, "2001:620:0:ff::5c", v6);
    ipv6->srcAddr[0] = ntohll(v6[0]);
    ipv6->srcAddr[1] = ntohll(v6[1]);
    CheckFilter("src ip 2001:620:0:ff::5c", recordHandle, 1);
    CheckFilter("ip 2001:620:0:ff::5c", recordHandle, 1);
    CheckFilter("dst ip 2001:620:0:ff::5c", recordHandle, 0);
    ipv6->dstAddr[0] = ipv6->srcAddr[0];
    ipv6->dstAddr[1] = ipv6->srcAddr[1];
    CheckFilter("dst ip 2001:620:0:ff::5c", recordHandle, 1);
    ipv6->srcAddr[0] = 0;
    ipv6->srcAddr[1] = 0;
    CheckFilter("ip 2001:620:0:ff::5c", recordHandle, 1);
    CheckFilter("src ip 2001:620:0:ff::5c", recordHandle, 0);

    // CheckFilter("ip cnn.com", recordHandle, 0);

    // EXasRoutingID
    CheckFilter("src as 65535", recordHandle, 0);
    PushExtension(recordHeaderV3, EXasRouting, asRouting);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);
    asRouting->srcAS = 65535;
    CheckFilter("src as 65535", recordHandle, 1);
    CheckFilter("as 65535", recordHandle, 1);
    CheckFilter("dst as 65535", recordHandle, 0);
    asRouting->dstAS = 65535;
    asRouting->srcAS = 0;
    CheckFilter("dst as 65535", recordHandle, 1);
    CheckFilter("as 65535", recordHandle, 1);
    CheckFilter("src as 65535", recordHandle, 0);
    CheckFilter("as > 65000", recordHandle, 1);

    // EXflowMiscID
    PushExtension(recordHeaderV3, EXflowMisc, flowMisc);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);
    flowMisc->input = 5;
    CheckFilter("in if 5", recordHandle, 1);
    CheckFilter("in if 6", recordHandle, 0);
    CheckFilter("out if 6", recordHandle, 0);
    flowMisc->output = 6;
    CheckFilter("out if 6", recordHandle, 1);

    flowMisc->srcMask = 11;
    flowMisc->dstMask = 13;
    CheckFilter("src mask 11", recordHandle, 1);
    CheckFilter("src mask 12", recordHandle, 0);
    CheckFilter("mask 11", recordHandle, 1);
    CheckFilter("dst mask 13", recordHandle, 1);
    CheckFilter("dst mask 14", recordHandle, 0);
    CheckFilter("mask 13", recordHandle, 1);
    CheckFilter("mask 11", recordHandle, 1);

    flowMisc->dir = 1;
    CheckFilter("flowdir 1", recordHandle, 1);
    CheckFilter("flowdir 0", recordHandle, 0);
    CheckFilter("flowdir egress", recordHandle, 1);
    CheckFilter("flowdir ingress", recordHandle, 0);

    // EXvLan
    PushExtension(recordHeaderV3, EXvLan, vlan);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);
    vlan->srcVlan = 1001;
    vlan->dstVlan = 2002;
    CheckFilter("src vlan 2002", recordHandle, 0);
    CheckFilter("dst vlan 2002", recordHandle, 1);
    CheckFilter("vlan 2002", recordHandle, 1);
    CheckFilter("vlan 1001", recordHandle, 1);
    CheckFilter("dst vlan 1001", recordHandle, 0);
    CheckFilter("src vlan 1001", recordHandle, 1);

    // EXipNextHopV4ID
    PushExtension(recordHeaderV3, EXipNextHopV4, nextHopV4);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);
    inet_pton(PF_INET, "1.2.3.4", &v4);
    nextHopV4->ip = ntohl(v4);
    CheckFilter("next ip 1.1.1.1", recordHandle, 0);
    CheckFilter("next ip 1.2.3.4", recordHandle, 1);

    // EXipNextHopV6ID
    PushExtension(recordHeaderV3, EXipNextHopV6, nextHopV6);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);
    inet_pton(PF_INET6, "2002:620:0:ff::52", v6);
    nextHopV6->ip[0] = ntohll(v6[0]);
    nextHopV6->ip[1] = ntohll(v6[1]);
    CheckFilter("next ip 2001:620:0:ff::5c", recordHandle, 0);
    CheckFilter("next ip 2002:620:0:ff::52", recordHandle, 1);

    // EXbgpNextHopV4ID
    PushExtension(recordHeaderV3, EXbgpNextHopV4, bgpNextHopV4);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);
    inet_pton(PF_INET, "22.33.44.55", &v4);
    bgpNextHopV4->ip = ntohl(v4);
    CheckFilter("bgp next ip 1.2.3.4", recordHandle, 0);
    CheckFilter("bgp next ip 22.33.44.55", recordHandle, 1);

    // EXbgpNextHopV6ID
    PushExtension(recordHeaderV3, EXbgpNextHopV6, bgpNextHopV6);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);
    inet_pton(PF_INET6, "fe80::2110:abcd:1235:ffff", v6);
    bgpNextHopV6->ip[0] = ntohll(v6[0]);
    bgpNextHopV6->ip[1] = ntohll(v6[1]);
    CheckFilter("bgp next ip 2002:620:0:ff::52", recordHandle, 0);
    CheckFilter("bgp next ip fe80::2110:abcd:1235:ffff", recordHandle, 1);

    // EXipReceivedV4ID
    PushExtension(recordHeaderV3, EXipReceivedV4, receivedV4);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);
    inet_pton(PF_INET, "192.168.100.1", &v4);
    receivedV4->ip = ntohl(v4);
    CheckFilter("router ip 22.33.44.55", recordHandle, 0);
    CheckFilter("router ip 192.168.100.1", recordHandle, 1);
    CheckFilter("exporter ip 192.168.100.1", recordHandle, 1);

    // EXipReceivedV6ID
    PushExtension(recordHeaderV3, EXipReceivedV6, receivedV6);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);
    inet_pton(PF_INET6, "fe80::2110:abcd:1235:1234", v6);
    receivedV6->ip[0] = ntohll(v6[0]);
    receivedV6->ip[1] = ntohll(v6[1]);
    CheckFilter("router ip fe80::2110:abcd:1235:ffff", recordHandle, 0);
    CheckFilter("router ip fe80::2110:abcd:1235:1234", recordHandle, 1);
    CheckFilter("exporter ip fe80::2110:abcd:1235:1234", recordHandle, 1);

    // IP lists
    inet_pton(PF_INET, "192.168.169.170", &v4);
    ipv4->srcAddr = ntohl(v4);
    inet_pton(PF_INET, "172.16.17.18", &v4);
    ipv4->dstAddr = ntohl(v4);
    CheckFilter("src ip in [8.8.8.8 2.2.2.2 192.168.169.170]", recordHandle, 1);
    CheckFilter("ip in [8.8.8.8 2.2.2.2 192.168.169.170]", recordHandle, 1);
    CheckFilter("dst ip 172.16.17.18", recordHandle, 1);
    CheckFilter("dst ip in [8.8.8.8 2.2.2.2 192.168.169.170]", recordHandle, 0);
    CheckFilter("dst ip in [8.8.8.8 2.2.2.2 192.168.169.171 172.16.17.18]", recordHandle, 1);

    inet_pton(PF_INET6, "fe80::2110:abcd:1234:5678", v6);
    ipv6->srcAddr[0] = ntohll(v6[0]);
    ipv6->srcAddr[1] = ntohll(v6[1]);
    ipv6->dstAddr[0] = 0;
    ipv6->dstAddr[1] = 0;
    CheckFilter("src ip in [8.8.8.8 2.2.2.2 192.168.169.171]", recordHandle, 0);
    CheckFilter("src ip in [192.168.169.0/24]", recordHandle, 1);
    CheckFilter("src ip in [8.8.8.8 192.168.169.0/24]", recordHandle, 1);
    CheckFilter("ip in [8.8.8.8 2.2.2.2 192.168.169.171]", recordHandle, 0);
    CheckFilter("dst ip in [8.8.8.8 2.2.2.2 192.168.169.171]", recordHandle, 0);
    CheckFilter("src ip in [8.8.8.8 2.2.2.2 192.168.169.171 fe80::2110:abcd:1234:5678]", recordHandle, 1);
    inet_pton(PF_INET6, "2001:620:0:ff::5c", v6);
    ipv6->dstAddr[0] = ntohll(v6[0]);
    ipv6->dstAddr[1] = ntohll(v6[1]);
    CheckFilter("src ip in [fe80::/16]", recordHandle, 1);
    CheckFilter("src ip in [1.1.1.1 fe80::/16]", recordHandle, 1);
    CheckFilter("ip in [8.8.8.8 2.2.2.2 192.168.169.171 fe80::2110:abcd:1234:5678]", recordHandle, 1);
    CheckFilter("dst ip in [8.8.8.8 2.2.2.2 192.168.169.171 fe80::2110:abcd:1234:5678]", recordHandle, 0);
    CheckFilter("dst ip in [8.8.8.8 2.2.2.2 192.168.169.171 fe80::2110:abcd:1234:5678 2001:620:0:ff::5c]", recordHandle, 1);

    // port lists
    genericFlow->srcPort = 44331;
    genericFlow->dstPort = 80;
    CheckFilter("src port in [80 443 143 25]", recordHandle, 0);
    CheckFilter("dst port in [80 443 143 25]", recordHandle, 1);
    CheckFilter("port in [80 443 143 25]", recordHandle, 1);
    CheckFilter("port in [44331, 443 143 25]", recordHandle, 1);
    CheckFilter("src port in [44331 443 143 25]", recordHandle, 1);
    CheckFilter("dst port in [44331 443 143 25]", recordHandle, 0);

    // AS lists
    asRouting->srcAS = 65535;
    asRouting->dstAS = 330;
    CheckFilter("src as in [330 55443 44332]", recordHandle, 0);
    CheckFilter("dst as in [330 55443 44332]", recordHandle, 1);
    CheckFilter("as in [330 55443 44332]", recordHandle, 1);
    CheckFilter("as in [65535, 55443 44332]", recordHandle, 1);
    CheckFilter("src as in [65535, 55443 44332]", recordHandle, 1);
    CheckFilter("dst as in [65535, 55443 44332]", recordHandle, 0);

    // EXmplsLabelID
    PushExtension(recordHeaderV3, EXmplsLabel, mplsLabel);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);
    for (int i = 0; i < 10; i++) {
        mplsLabel->mplsLabel[i] = (30 + i) << 4;  // init label
    }
    // simulate an end of stack label
    mplsLabel->mplsLabel[4] = (34 << 4) + 1;

    CheckFilter("mpls label2 32", recordHandle, 1);
    CheckFilter("mpls label2 > 31", recordHandle, 1);
    CheckFilter("mpls label2 > 32", recordHandle, 0);
    CheckFilter("mpls label4 > 33", recordHandle, 1);
    CheckFilter("mpls label4 34", recordHandle, 1);

    CheckFilter("mpls eos 34", recordHandle, 1);
    CheckFilter("mpls eos 33", recordHandle, 0);

    for (int i = 0; i < 10; i++) {
        mplsLabel->mplsLabel[i] = mplsLabel->mplsLabel[i] | ((i & 0x7) << 1);  // init exp bits
    }

    CheckFilter("mpls exp3 3", recordHandle, 1);
    CheckFilter("mpls exp3 > 2", recordHandle, 1);
    CheckFilter("mpls exp3 > 4", recordHandle, 0);
    CheckFilter("mpls exp7 > 6", recordHandle, 1);
    CheckFilter("mpls exp7 7", recordHandle, 1);

    CheckFilter("mpls any 34", recordHandle, 1);
    CheckFilter("mpls any 33", recordHandle, 1);
    CheckFilter("mpls any 330", recordHandle, 0);

    PushExtension(recordHeaderV3, EXmacAddr, macAddr);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);
    macAddr->inSrcMac = 0x0a5056c00001LL;
    macAddr->inDstMac = 0x0b5056c00001LL;
    macAddr->outSrcMac = 0x0c5056c00001LL;
    macAddr->outDstMac = 0x0d5056c00001LL;

    // EXmacAddrID
    CheckFilter("in src mac 0a:50:56:c0:00:01", recordHandle, 1);
    CheckFilter("in src mac 0a:50:56:c0:00:02", recordHandle, 0);
    CheckFilter("in dst mac 0b:50:56:c0:00:01", recordHandle, 1);
    CheckFilter("in dst mac 0b:50:56:c0:00:02", recordHandle, 0);
    CheckFilter("out src mac 0c:50:56:c0:00:01", recordHandle, 1);
    CheckFilter("out src mac 0c:50:56:c0:00:02", recordHandle, 0);
    CheckFilter("out dst mac 0d:50:56:c0:00:01", recordHandle, 1);
    CheckFilter("out dst mac 0d:50:56:c0:00:02", recordHandle, 0);

    CheckFilter("in mac 0a:50:56:c0:00:01", recordHandle, 1);
    CheckFilter("in mac 0b:50:56:c0:00:01", recordHandle, 1);
    CheckFilter("in mac 0c:50:56:c0:00:01", recordHandle, 0);
    CheckFilter("in mac 0d:50:56:c0:00:01", recordHandle, 0);

    CheckFilter("out mac 0c:50:56:c0:00:01", recordHandle, 1);
    CheckFilter("out mac 0d:50:56:c0:00:01", recordHandle, 1);
    CheckFilter("out mac 0a:50:56:c0:00:01", recordHandle, 0);
    CheckFilter("out mac 0b:50:56:c0:00:01", recordHandle, 0);

    CheckFilter("mac 0a:50:56:c0:00:01", recordHandle, 1);
    CheckFilter("mac 0b:50:56:c0:00:01", recordHandle, 1);
    CheckFilter("mac 0c:50:56:c0:00:01", recordHandle, 1);
    CheckFilter("mac 0d:50:56:c0:00:01", recordHandle, 1);
    CheckFilter("mac 0a:50:56:c0:00:01", recordHandle, 1);
    CheckFilter("mac 0c:50:56:c0:00:01", recordHandle, 1);
    CheckFilter("mac 0b:50:56:c0:00:01", recordHandle, 1);
    CheckFilter("mac 0d:50:56:c0:00:01", recordHandle, 1);

    // EXlatencyID
    PushExtension(recordHeaderV3, EXlatency, latency);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);
    latency->usecClientNwDelay = 11;
    latency->usecServerNwDelay = 22;
    latency->usecApplLatency = 33;

    CheckFilter("client latency 11", recordHandle, 1);
    CheckFilter("server latency 22", recordHandle, 1);
    CheckFilter("app latency 33", recordHandle, 1);
    CheckFilter("client latency 12", recordHandle, 0);
    CheckFilter("server latency 23", recordHandle, 0);
    CheckFilter("app latency 34", recordHandle, 0);
    CheckFilter("client latency < 11", recordHandle, 0);
    CheckFilter("client latency > 11", recordHandle, 0);

    PushExtension(recordHeaderV3, EXnselCommon, nselCommon);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);
    nselCommon->fwEvent = NSEL_EVENT_IGNORE;
    CheckFilter("asa event ignore", recordHandle, 1);
    CheckFilter("asa event create", recordHandle, 0);
    nselCommon->fwEvent = NSEL_EVENT_CREATE;
    CheckFilter("asa event create", recordHandle, 1);
    nselCommon->fwEvent = NSEL_EVENT_DELETE;
    CheckFilter("asa event delete", recordHandle, 1);
    nselCommon->fwEvent = NSEL_EVENT_DENIED;
    CheckFilter("asa event denied", recordHandle, 1);
    CheckFilter("asa event create", recordHandle, 0);
    CheckFilter("asa event 3", recordHandle, 1);
    CheckFilter("asa event > 2", recordHandle, 1);
    CheckFilter("asa event > 3", recordHandle, 0);

    // EXnselCommonID
    nselCommon->fwXevent = NSEL_XEVENT_IACL;
    CheckFilter("asa denied ingress", recordHandle, 1);
    CheckFilter("asa denied egress", recordHandle, 0);
    nselCommon->fwXevent = NSEL_XEVENT_EACL;
    CheckFilter("asa denied egress", recordHandle, 1);
    nselCommon->fwXevent = NSEL_XEVENT_DENIED;
    CheckFilter("asa denied access", recordHandle, 1);
    nselCommon->fwXevent = NSEL_XEVENT_NOSYN;
    CheckFilter("asa denied nosyn", recordHandle, 1);
    CheckFilter("asa denied ingress", recordHandle, 0);

    CheckFilter("asa xevent 1004", recordHandle, 1);
    CheckFilter("asa xevent < 1004", recordHandle, 0);
    CheckFilter("asa xevent > 1004", recordHandle, 0);

    PushExtension(recordHeaderV3, EXnselXlateIPv4, nselXlateIPv4);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);
    inet_pton(PF_INET, "172.32.7.16", &v4);
    nselXlateIPv4->xlateSrcAddr = ntohl(v4);
    inet_pton(PF_INET, "10.10.10.11", &v4);
    nselXlateIPv4->xlateDstAddr = ntohl(v4);

    // EXnselXlateIPv4ID
    CheckFilter("src nat ip 172.32.7.16", recordHandle, 1);
    CheckFilter("src nat ip 172.32.7.15", recordHandle, 0);
    CheckFilter("dst nat ip 10.10.10.11", recordHandle, 1);
    CheckFilter("dst nat ip 10.10.10.12", recordHandle, 0);
    CheckFilter("nat ip 172.32.7.16", recordHandle, 1);
    CheckFilter("nat ip 10.10.10.11", recordHandle, 1);
    CheckFilter("nat ip 172.32.7.15", recordHandle, 0);
    CheckFilter("nat ip 10.10.10.12", recordHandle, 0);
    CheckFilter("src nat net 172.32.7.0/24", recordHandle, 1);
    CheckFilter("src nat net 172.32.8.0/24", recordHandle, 0);
    CheckFilter("dst nat net 10.10.10.0/24", recordHandle, 1);
    CheckFilter("dst nat net 10.10.11.0/24", recordHandle, 0);
    CheckFilter("nat net 172.32.7.0/24", recordHandle, 1);
    CheckFilter("nat net 10.10.10.0/24", recordHandle, 1);

    CheckFilter("nat ip in [172.32.7.16]", recordHandle, 1);
    CheckFilter("nat ip in [10.10.10.11]", recordHandle, 1);
    CheckFilter("nat ip in [172.32.7.15]", recordHandle, 0);
    CheckFilter("nat ip in [10.10.10.10]", recordHandle, 0);

    // EXnselXlateIPv6ID
    PushExtension(recordHeaderV3, EXnselXlateIPv6, nselXlateIPv6);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);
    inet_pton(PF_INET6, "fe80::2110:abcd:1235:ffff", v6);
    nselXlateIPv6->xlateSrcAddr[0] = ntohll(v6[0]);
    nselXlateIPv6->xlateSrcAddr[1] = ntohll(v6[1]);

    CheckFilter("src nat ip fe80::2110:abcd:1235:ffff", recordHandle, 1);
    CheckFilter("src nat ip fe80::2110:abcd:1235:fffe", recordHandle, 0);

    // net/prefix notation
    inet_pton(PF_INET, "192.168.169.170", &v4);
    ipv4->srcAddr = ntohl(v4);
    inet_pton(PF_INET, "172.16.18.19", &v4);
    ipv4->dstAddr = ntohl(v4);
    CheckFilter("src net 192.168.169.0 255.255.255.0", recordHandle, 1);
    CheckFilter("src net 192.168.168.0 255.255.255.0", recordHandle, 0);
    CheckFilter("src net 192.168.169.0/24", recordHandle, 1);
    CheckFilter("src net 192.168.168.0/24", recordHandle, 0);
    CheckFilter("dst net 172.16.18.0/24", recordHandle, 1);
    CheckFilter("net 192.168.169.0/24", recordHandle, 1);
    CheckFilter("net 172.16.18.0/24", recordHandle, 1);

    inet_pton(PF_INET6, "2001:620:0:ff::5c", v6);
    ipv6->srcAddr[0] = ntohll(v6[0]);
    ipv6->srcAddr[1] = ntohll(v6[1]);
    CheckFilter("src net 2001::/16", recordHandle, 1);
    CheckFilter("net 2001::/16", recordHandle, 1);

    // EXnselXlatePortID
    PushExtension(recordHeaderV3, EXnselXlatePort, nselXlatePort);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);
    nselXlatePort->xlateSrcPort = 45123;
    nselXlatePort->xlateDstPort = 59321;
    CheckFilter("src nat port 45123", recordHandle, 1);
    CheckFilter("dst nat port 59321", recordHandle, 1);
    CheckFilter("nat port 45123", recordHandle, 1);
    CheckFilter("nat port 59321", recordHandle, 1);
    CheckFilter("nat port > 59321", recordHandle, 0);

    CheckFilter("nat port in [59321 80 443]", recordHandle, 1);
    CheckFilter("nat port in [45123 80 443]", recordHandle, 1);
    CheckFilter("nat port in [143 80 443]", recordHandle, 0);

    // EXnselAclID
    PushExtension(recordHeaderV3, EXnselAcl, nselAcl);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);
    nselAcl->ingressAcl[0] = 100;
    nselAcl->ingressAcl[1] = 110;
    nselAcl->ingressAcl[2] = 120;
    nselAcl->egressAcl[0] = 200;
    nselAcl->egressAcl[1] = 210;
    nselAcl->egressAcl[2] = 220;

    CheckFilter("ingress acl 100", recordHandle, 1);
    CheckFilter("ingress acl 110", recordHandle, 1);
    CheckFilter("ingress acl 120", recordHandle, 1);
    CheckFilter("egress acl 200", recordHandle, 1);
    CheckFilter("egress acl 210", recordHandle, 1);
    CheckFilter("egress acl 220", recordHandle, 1);
    CheckFilter("ingress acl 200", recordHandle, 0);
    CheckFilter("egress acl 100", recordHandle, 0);

    CheckFilter("ingress acl > 100", recordHandle, 1);
    CheckFilter("ingress acl > 200", recordHandle, 0);
    CheckFilter("egress acl < 300", recordHandle, 1);
    CheckFilter("egress acl < 100", recordHandle, 0);

    // EXnselUserID
    PushExtension(recordHeaderV3, EXnselUser, nselUser);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);
    strcpy(nselUser->username, "The nsel user");
    CheckFilter("asa user invalid", recordHandle, 0);
    CheckFilter("asa user 'The nsel user'", recordHandle, 1);

    // EXnelCommonID
    PushExtension(recordHeaderV3, EXnelCommon, nelCommon);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);
    nelCommon->natEvent = 0;
    CheckFilter("nat event invalid", recordHandle, 1);
    CheckFilter("nat event add", recordHandle, 0);

    nelCommon->natEvent = 10;
    CheckFilter("nat event add64bib", recordHandle, 1);
    CheckFilter("nat event add", recordHandle, 0);
    CheckFilter("nat event 10", recordHandle, 1);
    CheckFilter("nat event > 9", recordHandle, 1);
    CheckFilter("nat event > 10", recordHandle, 0);

    // EXnelXlatePortID
    PushExtension(recordHeaderV3, EXnelXlatePort, nelXlatePort);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);
    nelXlatePort->blockStart = 1111;
    nelXlatePort->blockEnd = 2222;
    nelXlatePort->blockStep = 3333;
    nelXlatePort->blockSize = 4444;

    CheckFilter("nat pblock start 1111", recordHandle, 1);
    CheckFilter("nat pblock start 2222", recordHandle, 0);

    CheckFilter("nat pblock end 2222", recordHandle, 1);
    CheckFilter("nat pblock end 3333", recordHandle, 0);

    CheckFilter("nat pblock step 3333", recordHandle, 1);
    CheckFilter("nat pblock step 4444", recordHandle, 0);

    CheckFilter("nat pblock size 4444", recordHandle, 1);
    CheckFilter("nat pblock size 5555", recordHandle, 0);

    genericFlow->srcPort = 1234;
    genericFlow->dstPort = 80;
    CheckFilter("src port in nat pblock", recordHandle, 1);
    genericFlow->srcPort = 1024;
    CheckFilter("src port in nat pblock", recordHandle, 0);
    CheckFilter("dst port in nat pblock", recordHandle, 0);
    genericFlow->srcPort = 1234;
    CheckFilter("port in nat pblock", recordHandle, 1);
    genericFlow->dstPort = 2121;
    CheckFilter("dst port in nat pblock", recordHandle, 1);
    CheckFilter("port in nat pblock", recordHandle, 1);

    // EXinPayloadID
    char *payloadString = "GET /index.html HTTP/1.1\r\n";
    PushVarLengthPointer(recordHeaderV3, EXinPayload, payload, strlen(payloadString) + 1);
    strcpy(payload, payloadString);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);

    CheckFilter("payload content 'GET /index'", recordHandle, 1);
    CheckFilter("payload content index", recordHandle, 1);
    CheckFilter("payload content 'POST'", recordHandle, 0);

    CheckFilter("payload regex 'GET'", recordHandle, 1);
    CheckFilter("payload regex '(GET|POST)'", recordHandle, 1);
    CheckFilter("payload regex 'HT{1,3}P/[0-9].[0-9]'", recordHandle, 1);
    CheckFilter("payload regex \"HT{1,3}P/[0-9].[0-9]\"", recordHandle, 1);
    CheckFilter("payload regex 'QT{1,3}P/[0-9].[0-9]'", recordHandle, 0);
    CheckFilter("payload regex 'gET' i and exporter sysid 12345", recordHandle, 1);

    // EXtunIPv4ID
    PushExtension(recordHeaderV3, EXtunIPv4, tunIPv4);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);
    inet_pton(PF_INET, "192.168.170.170", &v4);
    tunIPv4->tunSrcAddr = ntohl(v4);
    inet_pton(PF_INET, "172.16.19.20", &v4);
    tunIPv4->tunDstAddr = ntohl(v4);

    CheckFilter("src tun ip 192.168.170.170", recordHandle, 1);
    CheckFilter("src tun ip 192.168.170.169", recordHandle, 0);
    CheckFilter("dst tun ip 172.16.19.20", recordHandle, 1);
    CheckFilter("dst tun ip 172.16.19.19", recordHandle, 0);
    CheckFilter("tun ip 172.16.19.20", recordHandle, 1);
    CheckFilter("tun ip 192.168.170.170", recordHandle, 1);
    CheckFilter("tun ip 192.168.170.169", recordHandle, 0);
    CheckFilter("tun ip 172.16.19.19", recordHandle, 0);

    CheckFilter("tun ip in [172.16.19.20]", recordHandle, 1);
    CheckFilter("tun ip in [192.168.170.170]", recordHandle, 1);

    // EXtunIPv6ID
    PushExtension(recordHeaderV3, EXtunIPv6, tunIPv6);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);

    tunIPv4->tunProto = IPPROTO_IPIP;
    CheckFilter("tun proto ipip", recordHandle, 1);
    CheckFilter("tun proto 4", recordHandle, 1);
    CheckFilter("tun proto 5", recordHandle, 0);

    tunIPv4->tunProto = 0;
    tunIPv6->tunProto = IPPROTO_IPIP;
    CheckFilter("tun proto ipip", recordHandle, 1);
    CheckFilter("tun proto 4", recordHandle, 1);
    CheckFilter("tun proto 5", recordHandle, 0);

    inet_pton(PF_INET6, "fe80::2110:abcd:1235:ffff", v6);
    tunIPv6->tunSrcAddr[0] = ntohll(v6[0]);
    tunIPv6->tunSrcAddr[1] = ntohll(v6[1]);
    inet_pton(PF_INET6, "fe80::2110:abcd:1235:fffe", v6);
    tunIPv6->tunDstAddr[0] = ntohll(v6[0]);
    tunIPv6->tunDstAddr[1] = ntohll(v6[1]);

    CheckFilter("src tun ip fe80::2110:abcd:1235:ffff", recordHandle, 1);
    CheckFilter("src tun ip fe80::2110:abcd:1235:fffe", recordHandle, 0);
    CheckFilter("tun ip fe80::2110:abcd:1235:ffff", recordHandle, 1);

    CheckFilter("dst tun ip fe80::2110:abcd:1235:fffe", recordHandle, 1);
    CheckFilter("dst tun ip fe80::2110:abcd:1235:fffc", recordHandle, 0);
    CheckFilter("tun ip fe80::2110:abcd:1235:fffe", recordHandle, 1);

    // local (processed) extension
    char *ja3s = "123456789abcdef0123456789abcdef0";
    char *pos = ja3s;
    for (int count = 0; count < 16; count++) {
        sscanf(pos, "%2hhx", &recordHandle->ja3[count]);
        pos += 2;
    }
    CheckFilter("payload ja3 123456789abcdef0123456789abcdef0", recordHandle, 1);
    CheckFilter("payload ja3 123456789abcdef0123456789abcdef1", recordHandle, 0);
    CheckFilter("payload ja3 023456789abcdef0123456789abcdef0", recordHandle, 0);
    CheckFilter("payload ja3 defined", recordHandle, 1);
    memset((void *)recordHandle->ja3, 0, 16);
    CheckFilter("payload ja3 defined", recordHandle, 0);

    // geo location
    // src
    recordHandle->geo[0] = 'C';
    recordHandle->geo[1] = 'H';
    // dst
    recordHandle->geo[2] = 'D';
    recordHandle->geo[3] = 'E';
    // src nat
    recordHandle->geo[4] = 'U';
    recordHandle->geo[5] = 'S';
    // dst nat
    recordHandle->geo[6] = 'A';
    recordHandle->geo[7] = 'T';

    CheckFilter("src geo CH", recordHandle, 1);
    CheckFilter("src geo CD", recordHandle, 0);
    CheckFilter("geo CH", recordHandle, 1);
    CheckFilter("geo DE", recordHandle, 1);
    CheckFilter("geo CD", recordHandle, 0);

    CheckFilter("dst geo AB", recordHandle, 0);
    CheckFilter("dst geo DE", recordHandle, 1);
    CheckFilter("dst geo de", recordHandle, 1);

    CheckFilter("src nat geo US", recordHandle, 1);
    CheckFilter("dst nat geo AT", recordHandle, 1);
    CheckFilter("dst nat geo DE", recordHandle, 0);
    CheckFilter("nat geo US", recordHandle, 1);
    CheckFilter("nat geo AT", recordHandle, 1);

    // EXobservationID
    PushExtension(recordHeaderV3, EXobservation, observation);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);
    observation->pointID = 0xabcabcabc;
    observation->domainID = 0xcabc;

    CheckFilter("observation domain id 0xcabc", recordHandle, 1);
    CheckFilter("observation domain id 12345", recordHandle, 0);

    CheckFilter("observation point id 0xabcabcabc", recordHandle, 1);
    CheckFilter("observation point id 12345", recordHandle, 0);

    // EXvrfID
    PushExtension(recordHeaderV3, EXvrf, vrf);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);
    vrf->ingressVrf = 0xAAAA;
    vrf->egressVrf = 0xBBBB;
    CheckFilter("ingress vrf 0xAAAA", recordHandle, 1);
    CheckFilter("ingress vrf 100", recordHandle, 0);

    CheckFilter("egress vrf 0xBBBB", recordHandle, 1);
    CheckFilter("egress vrf 0xAAAA", recordHandle, 0);

    // EXpfinfoID
    char *ifName = "longinterface";
    PushVarLengthExtension(recordHeaderV3, EXpfinfo, pfinfo, strlen(ifName) + 1);
    MapRecordHandle(recordHandle, recordHeaderV3, 1);
    pfinfo->action = 1;
    CheckFilter("pf action block", recordHandle, 1);
    CheckFilter("pf action pass", recordHandle, 0);
    pfinfo->action = 0;
    CheckFilter("pf action pass", recordHandle, 1);
    pfinfo->action = 4;
    CheckFilter("pf action pass", recordHandle, 0);
    CheckFilter("pf action nat", recordHandle, 1);

    pfinfo->reason = 0;
    CheckFilter("pf reason match", recordHandle, 1);
    CheckFilter("pf reason short", recordHandle, 0);
    pfinfo->reason = 3;
    CheckFilter("pf reason short", recordHandle, 1);

    pfinfo->rulenr = 22;
    CheckFilter("pf rule 22", recordHandle, 1);
    CheckFilter("pf rule 23", recordHandle, 0);
    pfinfo->rulenr = 23;
    CheckFilter("pf rule 23", recordHandle, 1);

    pfinfo->dir = 1;
    CheckFilter("pf dir in", recordHandle, 1);
    CheckFilter("pf dir out", recordHandle, 0);
    pfinfo->dir = 0;
    CheckFilter("pf dir out", recordHandle, 1);

    ifName = "vether0";
    strcpy(pfinfo->ifname, ifName);
    CheckFilter("pf interface vether0", recordHandle, 1);
    CheckFilter("pf interface vmx0", recordHandle, 0);

    ifName = "longinterface";
    strcpy(pfinfo->ifname, ifName);
    CheckFilter("pf interface longinterface", recordHandle, 1);
    CheckFilter("pf interface vether0", recordHandle, 0);

    printf("DONE.\n");
}  // End of runTest

int main(int argc, char **argv) {
    runTest();
    return 0;
}
