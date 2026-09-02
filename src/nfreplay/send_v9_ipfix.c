/*
 *  Copyright (c) 2022-2026, Peter Haag
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

#include "send_v9_ipfix.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

// #include "exporter.h"
#include "logging.h"
#include "nfcommon.h"
#include "nfxV4.h"
#include "send_net.h"
#include "util.h"

#define NF9_TEMPLATE_FLOWSET_ID 0
#define NF9_MIN_RECORD_FLOWSET_ID 256

/* IPFIX v10 message header (RFC 7011 §3.1) — 16 bytes.
 * Differs from the 20-byte NetFlow v9 header: no SysUptime, 'count' is
 * replaced by total message 'length' in bytes, and version = 10. */
typedef struct ipfixHeader_s {
    uint16_t version;              /* = 10                                   */
    uint16_t length;               /* total message length in bytes          */
    uint32_t exportTime;           /* seconds since epoch when packet is sent */
    uint32_t sequenceNumber;       /* cumulative data records before this pkt */
    uint32_t observationDomainID;  /* exporter observation domain            */
} ipfixHeader_t;

typedef struct v9Header_s {
    uint16_t version;
    uint16_t count;
    uint32_t SysUptime;
    uint32_t unix_secs;
    uint32_t sequence;
    uint32_t source_id;
} v9Header_t;

typedef struct template_flowset_s {
    uint16_t flowset_id;
    uint16_t length;
    uint16_t template_id;
    uint16_t count;
    struct {
        uint16_t type;
        uint16_t length;
    } field[1];
} template_flowset_t;

typedef struct data_flowset_s {
    uint16_t flowset_id;
    uint16_t length;
    uint8_t data[4];
} data_flowset_t;

typedef struct outTemplates_s {
    struct outTemplates_s *next;
    time_t time_sent;         // time, last sent
    uint16_t template_id;     // id assigned to this template
    uint16_t needs_refresh;   // tagged for refreshing
    uint16_t numExtensions;   // number of extension in record
    uint16_t align;           // not used - memory alignment
    uint64_t elementBits;     // active element in record
    uint64_t record_count;    // number of data records sent with this template
    uint32_t data_length;     // length of the data record resulting from this template
    uint32_t flowset_length;  // length of the flowset record

    template_flowset_t *template_flowset;  // full template in network byte order for sending
} outTemplate_t;

typedef struct sender_data_s {
    struct header_s {
        v9Header_t *v9_header;      // start of packet — NetFlow v9 view
        ipfixHeader_t *ipfix_header; // start of packet — IPFIX v10 view (same address)
        uint32_t record_count;    // number of data records in send buffer
        uint32_t template_count;  // number of templates in send buffer
        uint32_t sequence;
    } header;

    data_flowset_t *data_flowset;  // full data template in network byte order for sending
    uint32_t data_flowset_id;      // id of current data flowset

} sender_data_t;

#define MAX_LIFETIME 60

static outTemplate_t *outTemplates = NULL;
static sender_data_t *sender_data = NULL;
static int use_ipfix = 0;  /* 0 = NetFlow v9, 1 = IPFIX v10 */

// Fires once per run, the first time a record carries an extension this
// output path has no field mapping for (e.g. DNS/SSL/JA3/JA4/payload/NBAR) -
// that extension is silently left out of the NetFlow v9/IPFIX template and
// every record using it, unlike -v 250 (nfdump native), which forwards the
// raw record - and therefore every extension - verbatim.
static int dropNoticeShown = 0;
static void NoticeExtensionDropped(void) {
    if (dropNoticeShown) return;
    dropNoticeShown = 1;
    LogInfo(
        "nfreplay: one or more record extensions have no NetFlow v9/IPFIX field mapping and are dropped from the output "
        "(this is logged once per run). Use -v 250 (nfdump native protocol) to forward every record verbatim instead.");
}  // End of NoticeExtensionDropped

// Get_valxx, a  macros
#include "inline.c"

/*
 * functions for sending netflow v9 records
 */

static outTemplate_t *GetOutputTemplate(recordHandle_t *recordHandle);

static void Append_Record(send_peer_t *peer, recordHandle_t *recordHandle);

static int Add_template_flowset(outTemplate_t *outTemplate, send_peer_t *peer);

static void CloseDataFlowset(send_peer_t *peer);

static void FinalizePacket(send_peer_t *peer);

static int CheckSendBufferSpace(size_t size, send_peer_t *peer);

/*
 * Table-driven extension -> NetFlow v9/IPFIX field mapping.
 *
 * One BuildTemplate_* function (emits (type,length) pairs into the template)
 * and one WriteRecord_* function (emits the actual field values into the
 * data flowset) per supported extension, both reached only via extMap[]
 * below, indexed directly by extension ID. This is the single authoritative
 * list of what this output path understands - GetOutputTemplate() and
 * Append_Record() no longer each carry their own independent switch that
 * has to be kept in sync by hand; a template and its data can no longer
 * silently drift apart.
 *
 * v9Length/ipfixLength are 0 when an extension has no field mapping for that
 * particular protocol (see the per-extension comments below for why - some
 * fields are protocol-exclusive, e.g. IPFIX's flowId(148) collides on the
 * wire with NetFlow v9's connectionId(148)); FindExtMap() below treats
 * either "no builder at all" and "zero length for this protocol" the same
 * way: report the one-time drop notice and skip the extension.
 */
typedef int (*buildTemplateFn_t)(template_flowset_t *flowset, int count, const recordHandle_t *recordHandle);
typedef void (*writeRecordFn_t)(const void *elementPtr, send_peer_t *peer);

typedef struct extMapEntry_s {
    buildTemplateFn_t buildTemplate;
    writeRecordFn_t writeRecord;
    uint16_t v9Length;     // wire bytes this extension adds under NetFlow v9, 0 if not available
    uint16_t ipfixLength;  // wire bytes this extension adds under IPFIX, 0 if not available
} extMapEntry_t;

// ---------------------------------------------------------------------
// Original extension set - present since NetFlow v9/IPFIX output existed.
// Identical field mapping and byte width for both protocols.
// ---------------------------------------------------------------------

static int BuildTemplate_GenericFlow(template_flowset_t *flowset, int count, const recordHandle_t *recordHandle) {
    (void)recordHandle;
    flowset->field[count].type = htons(NF_F_FLOW_CREATE_TIME_MSEC);
    flowset->field[count].length = htons(8);
    count++;
    flowset->field[count].type = htons(NF_F_FLOW_END_TIME_MSEC);
    flowset->field[count].length = htons(8);
    count++;
    flowset->field[count].type = htons(NF9_IN_PACKETS);
    flowset->field[count].length = htons(8);
    count++;
    flowset->field[count].type = htons(NF9_IN_BYTES);
    flowset->field[count].length = htons(8);
    count++;
    flowset->field[count].type = htons(NF9_L4_SRC_PORT);
    flowset->field[count].length = htons(2);
    count++;
    flowset->field[count].type = htons(NF9_L4_DST_PORT);
    flowset->field[count].length = htons(2);
    count++;
    flowset->field[count].type = htons(NF9_ICMP);
    flowset->field[count].length = htons(2);
    count++;
    flowset->field[count].type = htons(NF9_IN_PROTOCOL);
    flowset->field[count].length = htons(1);
    count++;
    flowset->field[count].type = htons(NF9_TCP_FLAGS);
    flowset->field[count].length = htons(1);
    count++;
    flowset->field[count].type = htons(NF9_FORWARDING_STATUS);
    flowset->field[count].length = htons(1);
    count++;
    flowset->field[count].type = htons(NF9_SRC_TOS);
    flowset->field[count].length = htons(1);
    count++;
    return count;
}  // End of BuildTemplate_GenericFlow

static void WriteRecord_GenericFlow(const void *elementPtr, send_peer_t *peer) {
    const EXgenericFlow_t *genericFlow = (const EXgenericFlow_t *)elementPtr;
    Put_val64(htonll(genericFlow->msecFirst), peer->buff_ptr);
    peer->buff_ptr += 8;
    Put_val64(htonll(genericFlow->msecLast), peer->buff_ptr);
    peer->buff_ptr += 8;
    Put_val64(htonll(genericFlow->inPackets), peer->buff_ptr);
    peer->buff_ptr += 8;
    Put_val64(htonll(genericFlow->inBytes), peer->buff_ptr);
    peer->buff_ptr += 8;
    Put_val16(htons(genericFlow->srcPort), peer->buff_ptr);
    peer->buff_ptr += 2;
    if (genericFlow->proto == IPPROTO_ICMP || genericFlow->proto == IPPROTO_ICMPV6) {
        Put_val16(0, peer->buff_ptr);
        peer->buff_ptr += 2;
        Put_val16(htons(genericFlow->dstPort), peer->buff_ptr);
        peer->buff_ptr += 2;
    } else {
        Put_val16(htons(genericFlow->dstPort), peer->buff_ptr);
        peer->buff_ptr += 2;
        Put_val16(0, peer->buff_ptr);
        peer->buff_ptr += 2;
    }
    Put_val8(genericFlow->proto, peer->buff_ptr);
    peer->buff_ptr += 1;
    Put_val8(genericFlow->tcpFlags, peer->buff_ptr);
    peer->buff_ptr += 1;
    Put_val8(genericFlow->fwdStatus, peer->buff_ptr);
    peer->buff_ptr += 1;
    Put_val8(genericFlow->srcTos, peer->buff_ptr);
    peer->buff_ptr += 1;
}  // End of WriteRecord_GenericFlow

static int BuildTemplate_Ipv4Flow(template_flowset_t *flowset, int count, const recordHandle_t *recordHandle) {
    (void)recordHandle;
    flowset->field[count].type = htons(NF9_IPV4_SRC_ADDR);
    flowset->field[count].length = htons(4);
    count++;
    flowset->field[count].type = htons(NF9_IPV4_DST_ADDR);
    flowset->field[count].length = htons(4);
    count++;
    return count;
}  // End of BuildTemplate_Ipv4Flow

static void WriteRecord_Ipv4Flow(const void *elementPtr, send_peer_t *peer) {
    const EXipv4Flow_t *ipv4Flow = (const EXipv4Flow_t *)elementPtr;
    Put_val32(htonl(ipv4Flow->srcAddr), peer->buff_ptr);
    peer->buff_ptr += 4;
    Put_val32(htonl(ipv4Flow->dstAddr), peer->buff_ptr);
    peer->buff_ptr += 4;
}  // End of WriteRecord_Ipv4Flow

static int BuildTemplate_Ipv6Flow(template_flowset_t *flowset, int count, const recordHandle_t *recordHandle) {
    (void)recordHandle;
    flowset->field[count].type = htons(NF9_IPV6_SRC_ADDR);
    flowset->field[count].length = htons(16);
    count++;
    flowset->field[count].type = htons(NF9_IPV6_DST_ADDR);
    flowset->field[count].length = htons(16);
    count++;
    return count;
}  // End of BuildTemplate_Ipv6Flow

static void WriteRecord_Ipv6Flow(const void *elementPtr, send_peer_t *peer) {
    const EXipv6Flow_t *ipv6Flow = (const EXipv6Flow_t *)elementPtr;
    Put_val64(htonll(ipv6Flow->srcAddr[0]), peer->buff_ptr);
    peer->buff_ptr += 8;
    Put_val64(htonll(ipv6Flow->srcAddr[1]), peer->buff_ptr);
    peer->buff_ptr += 8;
    Put_val64(htonll(ipv6Flow->dstAddr[0]), peer->buff_ptr);
    peer->buff_ptr += 8;
    Put_val64(htonll(ipv6Flow->dstAddr[1]), peer->buff_ptr);
    peer->buff_ptr += 8;
}  // End of WriteRecord_Ipv6Flow

static int BuildTemplate_Interface(template_flowset_t *flowset, int count, const recordHandle_t *recordHandle) {
    (void)recordHandle;
    flowset->field[count].type = htons(NF9_INPUT_SNMP);
    flowset->field[count].length = htons(4);
    count++;
    flowset->field[count].type = htons(NF9_OUTPUT_SNMP);
    flowset->field[count].length = htons(4);
    count++;
    return count;
}  // End of BuildTemplate_Interface

static void WriteRecord_Interface(const void *elementPtr, send_peer_t *peer) {
    const EXinterface_t *interface = (const EXinterface_t *)elementPtr;
    Put_val32(htonl(interface->input), peer->buff_ptr);
    peer->buff_ptr += 4;
    Put_val32(htonl(interface->output), peer->buff_ptr);
    peer->buff_ptr += 4;
}  // End of WriteRecord_Interface

// The src/dst mask field type depends on whether this record is IPv4 or
// IPv6 - looked up directly from the record rather than relying on
// EXipv4Flow/EXipv6Flow having already run earlier in the same iteration
// (true today since their extension IDs are numerically smaller, but that
// is no longer something this function needs to assume).
static int BuildTemplate_FlowMisc(template_flowset_t *flowset, int count, const recordHandle_t *recordHandle) {
    uint16_t srcMaskType = NF9_SRC_MASK;
    uint16_t dstMaskType = NF9_DST_MASK;
    if (recordHandle->extensionList[EXipv6FlowID]) {
        srcMaskType = NF9_IPV6_SRC_MASK;
        dstMaskType = NF9_IPV6_DST_MASK;
    }
    flowset->field[count].type = htons(srcMaskType);
    flowset->field[count].length = htons(1);
    count++;
    flowset->field[count].type = htons(dstMaskType);
    flowset->field[count].length = htons(1);
    count++;
    flowset->field[count].type = htons(NF9_DIRECTION);
    flowset->field[count].length = htons(1);
    count++;
    flowset->field[count].type = htons(NF9_DST_TOS);
    flowset->field[count].length = htons(1);
    count++;
    return count;
}  // End of BuildTemplate_FlowMisc

static void WriteRecord_FlowMisc(const void *elementPtr, send_peer_t *peer) {
    const EXflowMisc_t *flowMisc = (const EXflowMisc_t *)elementPtr;
    Put_val8(flowMisc->srcMask, peer->buff_ptr);
    peer->buff_ptr += 1;
    Put_val8(flowMisc->dstMask, peer->buff_ptr);
    peer->buff_ptr += 1;
    Put_val8(flowMisc->direction, peer->buff_ptr);
    peer->buff_ptr += 1;
    Put_val8(flowMisc->dstTos, peer->buff_ptr);
    peer->buff_ptr += 1;
}  // End of WriteRecord_FlowMisc

static int BuildTemplate_CntFlow(template_flowset_t *flowset, int count, const recordHandle_t *recordHandle) {
    (void)recordHandle;
    flowset->field[count].type = htons(NF9_FLOWS_AGGR);
    flowset->field[count].length = htons(8);
    count++;
    flowset->field[count].type = htons(NF9_OUT_PKTS);
    flowset->field[count].length = htons(8);
    count++;
    flowset->field[count].type = htons(NF9_OUT_BYTES);
    flowset->field[count].length = htons(8);
    count++;
    return count;
}  // End of BuildTemplate_CntFlow

static void WriteRecord_CntFlow(const void *elementPtr, send_peer_t *peer) {
    const EXcntFlow_t *cntFlow = (const EXcntFlow_t *)elementPtr;
    Put_val64(htonll(cntFlow->flows), peer->buff_ptr);
    peer->buff_ptr += 8;
    Put_val64(htonll(cntFlow->outPackets), peer->buff_ptr);
    peer->buff_ptr += 8;
    Put_val64(htonll(cntFlow->outBytes), peer->buff_ptr);
    peer->buff_ptr += 8;
}  // End of WriteRecord_CntFlow

static int BuildTemplate_VLan(template_flowset_t *flowset, int count, const recordHandle_t *recordHandle) {
    (void)recordHandle;
    flowset->field[count].type = htons(NF9_SRC_VLAN);
    flowset->field[count].length = htons(2);
    count++;
    flowset->field[count].type = htons(NF9_DST_VLAN);
    flowset->field[count].length = htons(2);
    count++;
    return count;
}  // End of BuildTemplate_VLan

static void WriteRecord_VLan(const void *elementPtr, send_peer_t *peer) {
    const EXvLan_t *vLan = (const EXvLan_t *)elementPtr;
    Put_val16(htons(vLan->srcVlan), peer->buff_ptr);
    peer->buff_ptr += 2;
    Put_val16(htons(vLan->dstVlan), peer->buff_ptr);
    peer->buff_ptr += 2;
}  // End of WriteRecord_VLan

static int BuildTemplate_AsInfo(template_flowset_t *flowset, int count, const recordHandle_t *recordHandle) {
    (void)recordHandle;
    flowset->field[count].type = htons(NF9_SRC_AS);
    flowset->field[count].length = htons(4);
    count++;
    flowset->field[count].type = htons(NF9_DST_AS);
    flowset->field[count].length = htons(4);
    count++;
    return count;
}  // End of BuildTemplate_AsInfo

static void WriteRecord_AsInfo(const void *elementPtr, send_peer_t *peer) {
    const EXasInfo_t *asInfo = (const EXasInfo_t *)elementPtr;
    Put_val32(htonl(asInfo->srcAS), peer->buff_ptr);
    peer->buff_ptr += 4;
    Put_val32(htonl(asInfo->dstAS), peer->buff_ptr);
    peer->buff_ptr += 4;
}  // End of WriteRecord_AsInfo

static int BuildTemplate_AsRoutingV4(template_flowset_t *flowset, int count, const recordHandle_t *recordHandle) {
    (void)recordHandle;
    flowset->field[count].type = htons(NF9_V4_NEXT_HOP);
    flowset->field[count].length = htons(4);
    count++;
    flowset->field[count].type = htons(NF9_BGP_V4_NEXT_HOP);
    flowset->field[count].length = htons(4);
    count++;
    return count;
}  // End of BuildTemplate_AsRoutingV4

static void WriteRecord_AsRoutingV4(const void *elementPtr, send_peer_t *peer) {
    const EXasRoutingV4_t *asRouting = (const EXasRoutingV4_t *)elementPtr;
    Put_val32(htonl(asRouting->nextHop), peer->buff_ptr);
    peer->buff_ptr += 4;
    Put_val32(htonl(asRouting->bgpNextHop), peer->buff_ptr);
    peer->buff_ptr += 4;
}  // End of WriteRecord_AsRoutingV4

static int BuildTemplate_AsRoutingV6(template_flowset_t *flowset, int count, const recordHandle_t *recordHandle) {
    (void)recordHandle;
    flowset->field[count].type = htons(NF9_V6_NEXT_HOP);
    flowset->field[count].length = htons(16);
    count++;
    flowset->field[count].type = htons(NF9_BPG_V6_NEXT_HOP);
    flowset->field[count].length = htons(16);
    count++;
    return count;
}  // End of BuildTemplate_AsRoutingV6

static void WriteRecord_AsRoutingV6(const void *elementPtr, send_peer_t *peer) {
    const EXasRoutingV6_t *asRouting = (const EXasRoutingV6_t *)elementPtr;
    Put_val64(htonll(asRouting->nextHop[0]), peer->buff_ptr);
    peer->buff_ptr += 8;
    Put_val64(htonll(asRouting->nextHop[1]), peer->buff_ptr);
    peer->buff_ptr += 8;
    Put_val64(htonll(asRouting->bgpNextHop[0]), peer->buff_ptr);
    peer->buff_ptr += 8;
    Put_val64(htonll(asRouting->bgpNextHop[1]), peer->buff_ptr);
    peer->buff_ptr += 8;
}  // End of WriteRecord_AsRoutingV6

static int BuildTemplate_Mpls(template_flowset_t *flowset, int count, const recordHandle_t *recordHandle) {
    (void)recordHandle;
    static const uint16_t mplsLabelType[10] = {NF9_MPLS_LABEL_1, NF9_MPLS_LABEL_2, NF9_MPLS_LABEL_3, NF9_MPLS_LABEL_4, NF9_MPLS_LABEL_5,
                                               NF9_MPLS_LABEL_6, NF9_MPLS_LABEL_7, NF9_MPLS_LABEL_8, NF9_MPLS_LABEL_9, NF9_MPLS_LABEL_10};
    for (int i = 0; i < 10; i++) {
        flowset->field[count].type = htons(mplsLabelType[i]);
        flowset->field[count].length = htons(3);
        count++;
    }
    return count;
}  // End of BuildTemplate_Mpls

static void WriteRecord_Mpls(const void *elementPtr, send_peer_t *peer) {
    const EXmpls_t *mpls = (const EXmpls_t *)elementPtr;
    for (int i = 0; i < 10; i++) {
        uint32_t val32 = htonl(mpls->label[i]);
        Put_val24(val32, peer->buff_ptr);
        peer->buff_ptr += 3;
    }
}  // End of WriteRecord_Mpls

static int BuildTemplate_InMacAddr(template_flowset_t *flowset, int count, const recordHandle_t *recordHandle) {
    (void)recordHandle;
    flowset->field[count].type = htons(NF9_IN_SRC_MAC);
    flowset->field[count].length = htons(6);
    count++;
    flowset->field[count].type = htons(NF9_OUT_DST_MAC);
    flowset->field[count].length = htons(6);
    count++;
    return count;
}  // End of BuildTemplate_InMacAddr

static void WriteRecord_InMacAddr(const void *elementPtr, send_peer_t *peer) {
    const EXinMacAddr_t *macAddr = (const EXinMacAddr_t *)elementPtr;
    uint64_t val64 = htonll(macAddr->inSrcMac);
    Put_val48(val64, peer->buff_ptr);
    peer->buff_ptr += 6;
    val64 = htonll(macAddr->outDstMac);
    Put_val48(val64, peer->buff_ptr);
    peer->buff_ptr += 6;
}  // End of WriteRecord_InMacAddr

static int BuildTemplate_OutMacAddr(template_flowset_t *flowset, int count, const recordHandle_t *recordHandle) {
    (void)recordHandle;
    flowset->field[count].type = htons(NF9_IN_DST_MAC);
    flowset->field[count].length = htons(6);
    count++;
    flowset->field[count].type = htons(NF9_OUT_SRC_MAC);
    flowset->field[count].length = htons(6);
    count++;
    return count;
}  // End of BuildTemplate_OutMacAddr

static void WriteRecord_OutMacAddr(const void *elementPtr, send_peer_t *peer) {
    const EXoutMacAddr_t *macAddr = (const EXoutMacAddr_t *)elementPtr;
    uint64_t val64 = htonll(macAddr->inDstMac);
    Put_val48(val64, peer->buff_ptr);
    peer->buff_ptr += 6;
    val64 = htonll(macAddr->outSrcMac);
    Put_val48(val64, peer->buff_ptr);
    peer->buff_ptr += 6;
}  // End of WriteRecord_OutMacAddr

static int BuildTemplate_AsAdjacent(template_flowset_t *flowset, int count, const recordHandle_t *recordHandle) {
    (void)recordHandle;
    flowset->field[count].type = htons(NF_F_BGP_ADJ_NEXT_AS);
    flowset->field[count].length = htons(4);
    count++;
    flowset->field[count].type = htons(NF_F_BGP_ADJ_PREV_AS);
    flowset->field[count].length = htons(4);
    count++;
    return count;
}  // End of BuildTemplate_AsAdjacent

static void WriteRecord_AsAdjacent(const void *elementPtr, send_peer_t *peer) {
    const EXasAdjacent_t *asAdjacent = (const EXasAdjacent_t *)elementPtr;
    Put_val32(htonl(asAdjacent->nextAdjacentAS), peer->buff_ptr);
    peer->buff_ptr += 4;
    Put_val32(htonl(asAdjacent->prevAdjacentAS), peer->buff_ptr);
    peer->buff_ptr += 4;
}  // End of WriteRecord_AsAdjacent

static int BuildTemplate_Layer2(template_flowset_t *flowset, int count, const recordHandle_t *recordHandle) {
    (void)recordHandle;
    flowset->field[count].type = htons(NF_F_dot1qVlanId);
    flowset->field[count].length = htons(2);
    count++;
    flowset->field[count].type = htons(NF_F_postDot1qVlanId);
    flowset->field[count].length = htons(2);
    count++;
    flowset->field[count].type = htons(NF_F_dot1qCustomerVlanId);
    flowset->field[count].length = htons(2);
    count++;
    flowset->field[count].type = htons(NF_F_postDot1qCustomerVlanId);
    flowset->field[count].length = htons(2);
    count++;
    flowset->field[count].type = htons(NF_9_IP_PROTOCOL_VERSION);
    flowset->field[count].length = htons(1);
    count++;
    return count;
}  // End of BuildTemplate_Layer2

static void WriteRecord_Layer2(const void *elementPtr, send_peer_t *peer) {
    const EXlayer2_t *layer2 = (const EXlayer2_t *)elementPtr;
    Put_val16(htons(layer2->vlanID), peer->buff_ptr);
    peer->buff_ptr += 2;
    Put_val16(htons(layer2->postVlanID), peer->buff_ptr);
    peer->buff_ptr += 2;
    Put_val16(htons(layer2->customerVlanId), peer->buff_ptr);
    peer->buff_ptr += 2;
    Put_val16(htons(layer2->postCustomerVlanId), peer->buff_ptr);
    peer->buff_ptr += 2;
    Put_val8(layer2->ipVersion, peer->buff_ptr);
    peer->buff_ptr += 1;
}  // End of WriteRecord_Layer2

// ---------------------------------------------------------------------
// Extensions added after auditing this codebase's own NetFlow v9/IPFIX
// *decoder* (src/netflow/netflow_v9.c, ipfix.c) for which wire element
// numbers it already treats as authoritative for each field - the same
// numbers a real collector receiving from a real exporter would send, not
// numbers picked from a spec reading alone. Extensions whose decoder-side
// mapping turned out to be a receiver-local synthesized value (LOCAL_*: no
// real wire field exists to encode, e.g. "which IP sent us this packet" or
// nfpcapd's own DPI payload capture) or that have no decoder mapping at all
// anywhere in this codebase (EXlatency, EXpfinfo, EXtunnelV4/V6 - nfpcapd or
// BSD pf specific, no known standard IE) are deliberately not in this table;
// they fall through to the generic drop notice like any other unmapped
// extension. Cisco ASA ACL/username fields and Nokia NAT fields are also
// deliberately excluded: real, documented numbers, but enterprise-specific -
// only a Cisco- or Nokia-aware collector understands them, not "any"
// v9/IPFIX collector. Variable-length fields (EXnbarAppID, the
// EXpacketMeta/EXpacketFrame pair) are excluded too: this table only
// supports fixed-length fields today.
// ---------------------------------------------------------------------

// minimumTTL(52)/maximumTTL(53)/fragmentFlags(197) - RFC 5102 base IPFIX
// information model; numerically identical under NetFlow v9.
static int BuildTemplate_IpInfo(template_flowset_t *flowset, int count, const recordHandle_t *recordHandle) {
    (void)recordHandle;
    flowset->field[count].type = htons(NF9_MIN_TTL);
    flowset->field[count].length = htons(1);
    count++;
    flowset->field[count].type = htons(NF9_MAX_TTL);
    flowset->field[count].length = htons(1);
    count++;
    flowset->field[count].type = htons(NF9_FRAGMENT_FLAGS);
    flowset->field[count].length = htons(1);
    count++;
    return count;
}  // End of BuildTemplate_IpInfo

static void WriteRecord_IpInfo(const void *elementPtr, send_peer_t *peer) {
    const EXipInfo_t *ipInfo = (const EXipInfo_t *)elementPtr;
    Put_val8(ipInfo->minTTL, peer->buff_ptr);
    peer->buff_ptr += 1;
    Put_val8(ipInfo->maxTTL, peer->buff_ptr);
    peer->buff_ptr += 1;
    Put_val8(ipInfo->fragmentFlags, peer->buff_ptr);
    peer->buff_ptr += 1;
}  // End of WriteRecord_IpInfo

// ingressVRFID(234)/egressVRFID(235) - RFC 6759 "Export of Logging
// Information using IPFIX"; identical under NetFlow v9.
static int BuildTemplate_Vrf(template_flowset_t *flowset, int count, const recordHandle_t *recordHandle) {
    (void)recordHandle;
    flowset->field[count].type = htons(NF_N_INGRESS_VRFID);
    flowset->field[count].length = htons(4);
    count++;
    flowset->field[count].type = htons(NF_N_EGRESS_VRFID);
    flowset->field[count].length = htons(4);
    count++;
    return count;
}  // End of BuildTemplate_Vrf

static void WriteRecord_Vrf(const void *elementPtr, send_peer_t *peer) {
    const EXvrf_t *vrf = (const EXvrf_t *)elementPtr;
    Put_val32(htonl(vrf->ingressVrf), peer->buff_ptr);
    peer->buff_ptr += 4;
    Put_val32(htonl(vrf->egressVrf), peer->buff_ptr);
    peer->buff_ptr += 4;
}  // End of WriteRecord_Vrf

// postNATSourceIPv4Address(225)/postNATDestinationIPv4Address(226) - RFC 6759.
static int BuildTemplate_NatXlateV4(template_flowset_t *flowset, int count, const recordHandle_t *recordHandle) {
    (void)recordHandle;
    flowset->field[count].type = htons(NF_F_XLATE_SRC_ADDR_IPV4);
    flowset->field[count].length = htons(4);
    count++;
    flowset->field[count].type = htons(NF_F_XLATE_DST_ADDR_IPV4);
    flowset->field[count].length = htons(4);
    count++;
    return count;
}  // End of BuildTemplate_NatXlateV4

static void WriteRecord_NatXlateV4(const void *elementPtr, send_peer_t *peer) {
    const EXnatXlateV4_t *nat = (const EXnatXlateV4_t *)elementPtr;
    Put_val32(htonl(nat->xlateSrcAddr), peer->buff_ptr);
    peer->buff_ptr += 4;
    Put_val32(htonl(nat->xlateDstAddr), peer->buff_ptr);
    peer->buff_ptr += 4;
}  // End of WriteRecord_NatXlateV4

// postNATSourceIPv6Address(281)/postNATDestinationIPv6Address(282) - RFC 6759.
static int BuildTemplate_NatXlateV6(template_flowset_t *flowset, int count, const recordHandle_t *recordHandle) {
    (void)recordHandle;
    flowset->field[count].type = htons(NF_F_XLATE_SRC_ADDR_IPV6);
    flowset->field[count].length = htons(16);
    count++;
    flowset->field[count].type = htons(NF_F_XLATE_DST_ADDR_IPV6);
    flowset->field[count].length = htons(16);
    count++;
    return count;
}  // End of BuildTemplate_NatXlateV6

static void WriteRecord_NatXlateV6(const void *elementPtr, send_peer_t *peer) {
    const EXnatXlateV6_t *nat = (const EXnatXlateV6_t *)elementPtr;
    Put_val64(htonll(nat->xlateSrcAddr[0]), peer->buff_ptr);
    peer->buff_ptr += 8;
    Put_val64(htonll(nat->xlateSrcAddr[1]), peer->buff_ptr);
    peer->buff_ptr += 8;
    Put_val64(htonll(nat->xlateDstAddr[0]), peer->buff_ptr);
    peer->buff_ptr += 8;
    Put_val64(htonll(nat->xlateDstAddr[1]), peer->buff_ptr);
    peer->buff_ptr += 8;
}  // End of WriteRecord_NatXlateV6

// postNAPTSourceTransportPort(227)/postNAPTDestinationTransportPort(228) - RFC 6759.
static int BuildTemplate_NatXlatePort(template_flowset_t *flowset, int count, const recordHandle_t *recordHandle) {
    (void)recordHandle;
    flowset->field[count].type = htons(NF_F_XLATE_SRC_PORT);
    flowset->field[count].length = htons(2);
    count++;
    flowset->field[count].type = htons(NF_F_XLATE_DST_PORT);
    flowset->field[count].length = htons(2);
    count++;
    return count;
}  // End of BuildTemplate_NatXlatePort

static void WriteRecord_NatXlatePort(const void *elementPtr, send_peer_t *peer) {
    const EXnatXlatePort_t *nat = (const EXnatXlatePort_t *)elementPtr;
    Put_val16(htons(nat->xlateSrcPort), peer->buff_ptr);
    peer->buff_ptr += 2;
    Put_val16(htons(nat->xlateDstPort), peer->buff_ptr);
    peer->buff_ptr += 2;
}  // End of WriteRecord_NatXlatePort

// natPortBlockStart/End/Step/Size(361-364) - decoded identically under both
// NetFlow v9 and IPFIX by this codebase's own decoder.
static int BuildTemplate_NatPortBlock(template_flowset_t *flowset, int count, const recordHandle_t *recordHandle) {
    (void)recordHandle;
    flowset->field[count].type = htons(NF_F_XLATE_PORT_BLOCK_START);
    flowset->field[count].length = htons(2);
    count++;
    flowset->field[count].type = htons(NF_F_XLATE_PORT_BLOCK_END);
    flowset->field[count].length = htons(2);
    count++;
    flowset->field[count].type = htons(NF_F_XLATE_PORT_BLOCK_STEP);
    flowset->field[count].length = htons(2);
    count++;
    flowset->field[count].type = htons(NF_F_XLATE_PORT_BLOCK_SIZE);
    flowset->field[count].length = htons(2);
    count++;
    return count;
}  // End of BuildTemplate_NatPortBlock

static void WriteRecord_NatPortBlock(const void *elementPtr, send_peer_t *peer) {
    const EXnatPortBlock_t *block = (const EXnatPortBlock_t *)elementPtr;
    Put_val16(htons(block->blockStart), peer->buff_ptr);
    peer->buff_ptr += 2;
    Put_val16(htons(block->blockEnd), peer->buff_ptr);
    peer->buff_ptr += 2;
    Put_val16(htons(block->blockStep), peer->buff_ptr);
    peer->buff_ptr += 2;
    Put_val16(htons(block->blockSize), peer->buff_ptr);
    peer->buff_ptr += 2;
}  // End of WriteRecord_NatPortBlock

// NSEL common (Cisco ASA event logging, standardised by RFC 6759):
// eventTimeMilliseconds(323), connectionId(148), firewallEvent(233),
// natEvent(230) are only ever decoded by this codebase under NetFlow v9;
// natPoolId(283) is decoded under both. Mirror that split on encode: a v9
// receiver gets the full set, an IPFIX receiver only natPoolId. connID uses
// wire number 148, the same number IPFIX assigns to flowId - encoding it
// under IPFIX would collide with EXflowId below, which is why it is v9-only.
static int BuildTemplate_NselCommon(template_flowset_t *flowset, int count, const recordHandle_t *recordHandle) {
    (void)recordHandle;
    if (!use_ipfix) {
        flowset->field[count].type = htons(NF_F_EVENT_TIME_MSEC);
        flowset->field[count].length = htons(8);
        count++;
        flowset->field[count].type = htons(NF_F_CONN_ID);
        flowset->field[count].length = htons(4);
        count++;
        flowset->field[count].type = htons(NF_F_FW_EVENT);
        flowset->field[count].length = htons(1);
        count++;
        flowset->field[count].type = htons(NF_N_NAT_EVENT);
        flowset->field[count].length = htons(2);
        count++;
    }
    flowset->field[count].type = htons(NF_N_NATPOOL_ID);
    flowset->field[count].length = htons(4);
    count++;
    return count;
}  // End of BuildTemplate_NselCommon

static void WriteRecord_NselCommon(const void *elementPtr, send_peer_t *peer) {
    const EXnselCommon_t *nsel = (const EXnselCommon_t *)elementPtr;
    if (!use_ipfix) {
        Put_val64(htonll(nsel->msecEvent), peer->buff_ptr);
        peer->buff_ptr += 8;
        Put_val32(htonl(nsel->connID), peer->buff_ptr);
        peer->buff_ptr += 4;
        Put_val8(nsel->fwEvent, peer->buff_ptr);
        peer->buff_ptr += 1;
        Put_val16(htons(nsel->natEvent), peer->buff_ptr);
        peer->buff_ptr += 2;
    }
    Put_val32(htonl(nsel->natPoolID), peer->buff_ptr);
    peer->buff_ptr += 4;
}  // End of WriteRecord_NselCommon

// flowId(148) - RFC 7011 base IPFIX information model. IPFIX-only: this
// codebase's own NetFlow v9 decoder already assigns wire number 148 to
// connectionId (see EXnselCommon above), so a v9 collector receiving 148
// here would misinterpret it.
static int BuildTemplate_FlowId(template_flowset_t *flowset, int count, const recordHandle_t *recordHandle) {
    (void)recordHandle;
    flowset->field[count].type = htons(IPFIX_FLOW_ID);
    flowset->field[count].length = htons(8);
    count++;
    return count;
}  // End of BuildTemplate_FlowId

static void WriteRecord_FlowId(const void *elementPtr, send_peer_t *peer) {
    const EXflowId_t *flowId = (const EXflowId_t *)elementPtr;
    Put_val64(htonll(flowId->flowId), peer->buff_ptr);
    peer->buff_ptr += 8;
}  // End of WriteRecord_FlowId

// observationPointId(138)/observationDomainId(149) - RFC 7011. IPFIX-only:
// this codebase's decoder never maps these under NetFlow v9, which already
// carries a per-message source_id serving the same purpose in its header.
static int BuildTemplate_Observation(template_flowset_t *flowset, int count, const recordHandle_t *recordHandle) {
    (void)recordHandle;
    flowset->field[count].type = htons(IPFIX_OBSERVATION_POINT_ID);
    flowset->field[count].length = htons(8);
    count++;
    flowset->field[count].type = htons(IPFIX_OBSERVATION_DOMAIN_ID);
    flowset->field[count].length = htons(8);
    count++;
    return count;
}  // End of BuildTemplate_Observation

static void WriteRecord_Observation(const void *elementPtr, send_peer_t *peer) {
    const EXobservation_t *obs = (const EXobservation_t *)elementPtr;
    Put_val64(htonll(obs->pointID), peer->buff_ptr);
    peer->buff_ptr += 8;
    Put_val64(htonll(obs->domainID), peer->buff_ptr);
    peer->buff_ptr += 8;
}  // End of WriteRecord_Observation

// O(1) direct-indexed lookup, designated initializers so an unlisted
// extension ID is guaranteed zero-initialized (buildTemplate/writeRecord
// NULL, both lengths 0) without having to list it explicitly.
static const extMapEntry_t extMap[MAXEXTENSIONS] = {
    [EXgenericFlowID] = {BuildTemplate_GenericFlow, WriteRecord_GenericFlow, 42, 42},
    [EXipv4FlowID] = {BuildTemplate_Ipv4Flow, WriteRecord_Ipv4Flow, 8, 8},
    [EXipv6FlowID] = {BuildTemplate_Ipv6Flow, WriteRecord_Ipv6Flow, 32, 32},
    [EXinterfaceID] = {BuildTemplate_Interface, WriteRecord_Interface, 8, 8},
    [EXflowMiscID] = {BuildTemplate_FlowMisc, WriteRecord_FlowMisc, 4, 4},
    [EXcntFlowID] = {BuildTemplate_CntFlow, WriteRecord_CntFlow, 24, 24},
    [EXvLanID] = {BuildTemplate_VLan, WriteRecord_VLan, 4, 4},
    [EXasInfoID] = {BuildTemplate_AsInfo, WriteRecord_AsInfo, 8, 8},
    [EXasRoutingV4ID] = {BuildTemplate_AsRoutingV4, WriteRecord_AsRoutingV4, 8, 8},
    [EXasRoutingV6ID] = {BuildTemplate_AsRoutingV6, WriteRecord_AsRoutingV6, 32, 32},
    [EXmplsID] = {BuildTemplate_Mpls, WriteRecord_Mpls, 30, 30},
    [EXinMacAddrID] = {BuildTemplate_InMacAddr, WriteRecord_InMacAddr, 12, 12},
    [EXoutMacAddrID] = {BuildTemplate_OutMacAddr, WriteRecord_OutMacAddr, 12, 12},
    [EXasAdjacentID] = {BuildTemplate_AsAdjacent, WriteRecord_AsAdjacent, 8, 8},
    [EXlayer2ID] = {BuildTemplate_Layer2, WriteRecord_Layer2, 9, 9},
    [EXipInfoID] = {BuildTemplate_IpInfo, WriteRecord_IpInfo, 3, 3},
    [EXvrfID] = {BuildTemplate_Vrf, WriteRecord_Vrf, 8, 8},
    [EXnatXlateV4ID] = {BuildTemplate_NatXlateV4, WriteRecord_NatXlateV4, 8, 8},
    [EXnatXlateV6ID] = {BuildTemplate_NatXlateV6, WriteRecord_NatXlateV6, 32, 32},
    [EXnatXlatePortID] = {BuildTemplate_NatXlatePort, WriteRecord_NatXlatePort, 4, 4},
    [EXnatPortBlockID] = {BuildTemplate_NatPortBlock, WriteRecord_NatPortBlock, 8, 8},
    [EXnselCommonID] = {BuildTemplate_NselCommon, WriteRecord_NselCommon, 19, 4},
    [EXflowIdID] = {BuildTemplate_FlowId, WriteRecord_FlowId, 0, 8},
    [EXobservationID] = {BuildTemplate_Observation, WriteRecord_Observation, 0, 16},
};

// Resolve ext to its mapping for the protocol currently in use. Returns NULL
// (and reports the drop notice) both when the extension has no mapping at
// all and when it has one but not for this particular protocol - either way
// the caller must treat it exactly like an unmapped extension.
static const extMapEntry_t *FindExtMap(int ext, uint16_t *length) {
    const extMapEntry_t *m = &extMap[ext];
    uint16_t len = use_ipfix ? m->ipfixLength : m->v9Length;
    if (!m->buildTemplate || len == 0) {
        NoticeExtensionDropped();
        return NULL;
    }
    *length = len;
    return m;
}  // End of FindExtMap

int Init_v9_output(send_peer_t *peer) {
    use_ipfix = 0;
    sender_data = calloc(1, sizeof(sender_data_t));
    if (!sender_data) {
        LogError("calloc() %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }
    sender_data->header.v9_header = (v9Header_t *)peer->send_buffer;
    sender_data->header.ipfix_header = (ipfixHeader_t *)peer->send_buffer;
    peer->buff_ptr = (void *)((void *)sender_data->header.v9_header + sizeof(v9Header_t));

    sender_data->header.v9_header->version = htons(9);
    sender_data->header.v9_header->SysUptime = 0;
    sender_data->header.v9_header->unix_secs = 0;
    sender_data->header.v9_header->count = 0;
    sender_data->header.v9_header->source_id = htonl(1);
    sender_data->header.record_count = 0;
    sender_data->header.template_count = 0;
    sender_data->header.sequence = 0;

    sender_data->data_flowset = NULL;
    sender_data->data_flowset_id = 0;

    return 1;

}  // End of Init_v9_output

int Init_ipfix_output(send_peer_t *peer) {
    use_ipfix = 1;
    sender_data = calloc(1, sizeof(sender_data_t));
    if (!sender_data) {
        LogError("calloc() %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }
    sender_data->header.v9_header = (v9Header_t *)peer->send_buffer;
    sender_data->header.ipfix_header = (ipfixHeader_t *)peer->send_buffer;
    /* IPFIX header is 16 bytes (4 bytes shorter than v9 due to no SysUptime) */
    peer->buff_ptr = (void *)((void *)peer->send_buffer + sizeof(ipfixHeader_t));

    sender_data->header.ipfix_header->version = htons(10);
    sender_data->header.ipfix_header->length = 0;
    sender_data->header.ipfix_header->exportTime = htonl((uint32_t)time(NULL));
    sender_data->header.ipfix_header->sequenceNumber = 0;
    sender_data->header.ipfix_header->observationDomainID = htonl(1);
    sender_data->header.record_count = 0;
    sender_data->header.template_count = 0;
    sender_data->header.sequence = 0;

    sender_data->data_flowset = NULL;
    sender_data->data_flowset_id = 0;

    return 1;

}  // End of Init_ipfix_output

int Close_v9_output(send_peer_t *peer) {
    if ((sender_data->header.record_count + sender_data->header.template_count) > 0) {
        dbg_printf("Close output\n");
        peer->flush = 1;
        FinalizePacket(peer);
        sender_data->header.record_count = 0;
        sender_data->header.template_count = 0;
        return 1;
    }

    return 0;

}  // End of Close_v9_output

int Close_ipfix_output(send_peer_t *peer) { return Close_v9_output(peer); }  // End of Close_ipfix_output

static outTemplate_t *GetOutputTemplate(recordHandle_t *recordHandle) {
    uint32_t template_id = 0;

    uint64_t elementBits = recordHandle->recordHeaderV4->extBitmap;

    outTemplate_t **t = &outTemplates;
    // search for the template, which corresponds to our flags and extension map
    while (*t) {
        if (((*t)->elementBits == elementBits) && ((*t)->numExtensions == recordHandle->numElements)) {
            return *t;
        }
        template_id = (*t)->template_id;
        t = &((*t)->next);
    }

    // nothing found, otherwise we would not get here
    *t = (outTemplate_t *)calloc(1, sizeof(outTemplate_t));
    if (!(*t)) {
        LogError("calloc() %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        exit(255);
    }
    (*t)->next = NULL;

    (*t)->elementBits = elementBits;
    (*t)->numExtensions = recordHandle->numElements;

    if (template_id == 0)
        (*t)->template_id = NF9_MIN_RECORD_FLOWSET_ID;
    else
        (*t)->template_id = template_id + 1;

    dbg_printf("No output template found. Create new template: %d\n", (*t)->template_id);

    (*t)->time_sent = 0;
    (*t)->record_count = 0;

    // add flowset array - includes one potential padding
    int32_t numV9Elements = 40;  // assume, this may be enough, otherwise expand table
    (*t)->template_flowset = calloc(1, sizeof(template_flowset_t) + (size_t)(numV9Elements * 4));
    if (!(*t)->template_flowset) {
        LogError("calloc() %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        exit(255);
    }
    template_flowset_t *flowset = (*t)->template_flowset;

    // add two default elements
    int32_t count = 0;
    flowset->field[count].type = htons(NF9_ENGINE_TYPE);
    flowset->field[count].length = htons(1);
    count++;
    flowset->field[count].type = htons(NF9_ENGINE_ID);
    flowset->field[count].length = htons(1);
    count++;
    uint32_t data_length = 2;

    dbg_printf("Generate template for %u extensions\n", recordHandle->numElements);
    // iterate over all extensions
    int added = 0;
    for (int ext = 1; ext < MAXEXTENSIONS; ext++) {
        if (added == recordHandle->numElements) break;
        if (recordHandle->extensionList[ext] == 0) continue;
        added++;

        uint16_t length = 0;
        const extMapEntry_t *m = FindExtMap(ext, &length);
        if (!m) continue;

        // dynamically increase flowset table, if too little slots are left
        if ((numV9Elements - count) < 15) {
            dbg_printf("Expand flowset table\n");
            numV9Elements += 20;
            size_t newSize = sizeof(template_flowset_t) + (numV9Elements * 4);
            (*t)->template_flowset = realloc((*t)->template_flowset, newSize);
            if (!(*t)->template_flowset) {
                LogError("realloc() %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                exit(255);
            }
            // remap flowset
            flowset = (*t)->template_flowset;
        }
        dbg_printf("Add extension: %d\n", ext);
        count = m->buildTemplate(flowset, count, recordHandle);
        data_length += length;
    }

    // one potential padding field
    flowset->field[count].type = 0;
    flowset->field[count].length = 0;

    (*t)->template_flowset->flowset_id = htons(use_ipfix ? IPFIX_TEMPLATE_SET_ID : NF9_TEMPLATE_FLOWSET_ID);
    (*t)->flowset_length = 4 * (2 + count);  // + 2 for the header

    // add proper padding for 32bit boundary
    if (((*t)->flowset_length & 0x3) != 0) (*t)->flowset_length += (4 - ((*t)->flowset_length & 0x3));
    (*t)->template_flowset->length = htons((*t)->flowset_length);

    (*t)->data_length = data_length;

    dbg_printf("Created new template with id: %u, count: %u, record length: %u\n", (*t)->template_id, count, data_length);
    flowset->template_id = htons((*t)->template_id);
    flowset->count = htons(count);

    // canity check
    if ((*t)->flowset_length > UDP_PACKET_SIZE) {
        LogError("Error: flowset length: %u > UDP packet size: %u", (*t)->flowset_length, UDP_PACKET_SIZE);
        LogError("Panic in %s line %d", __FILE__, __LINE__);
        exit(255);
    }
    return *t;

}  // End of GetOutputTemplate

static void Append_Record(send_peer_t *peer, recordHandle_t *recordHandle) {
    uint8_t *p = (uint8_t *)peer->buff_ptr;
    *p++ = recordHandle->recordHeaderV4->engineType;
    *p++ = recordHandle->recordHeaderV4->engineID;
    peer->buff_ptr = (void *)p;

    int added = 0;
    for (int ext = 1; ext < MAXEXTENSIONS; ext++) {
        if (added == recordHandle->numElements) break;
        void *elementPtr = recordHandle->extensionList[ext];
        if (elementPtr == NULL) continue;
        added++;

        // Same resolution as GetOutputTemplate() above, so the two always
        // agree on exactly which extensions this record actually carries in
        // its wire encoding - already reported once by GetOutputTemplate()
        // if unmapped, nothing more to do here for that case.
        uint16_t length;
        const extMapEntry_t *m = FindExtMap(ext, &length);
        if (!m) continue;
        m->writeRecord(elementPtr, peer);
    }

    sender_data->header.record_count++;

}  // End of Append_Record

static int Add_template_flowset(outTemplate_t *outTemplate, send_peer_t *peer) {
    dbg_printf("Add template %u, bytes: %u\n", outTemplate->template_id, outTemplate->flowset_length);
    memcpy(peer->buff_ptr, (void *)outTemplate->template_flowset, outTemplate->flowset_length);
    peer->buff_ptr = (void *)((ptrdiff_t)peer->buff_ptr + outTemplate->flowset_length);

    sender_data->header.template_count++;

    return 1;
}  // End of Add_template_flowset

static void CloseDataFlowset(send_peer_t *peer) {
    if (sender_data->data_flowset) {
        uint32_t length = (void *)peer->buff_ptr - (void *)sender_data->data_flowset;
        uint32_t bits = length & 0x3;
        if (bits != 0) {
            uint32_t align = 4 - bits;
            length += align;
            // fill padding with 0
            for (int i = 0; i < (int)align; i++) {
                *((char *)peer->buff_ptr) = '\0';
                peer->buff_ptr++;
            }
        }
        dbg_printf("Close flowset: Length: %u, align: %u\n", length, 4 - bits);
        sender_data->data_flowset->length = htons(length);
        sender_data->data_flowset = NULL;
        sender_data->data_flowset_id = 0;
    }
}  // End of CloseDataFlowset

/* FinalizePacket — close the current data flowset (adds 32-bit padding) and
 * stamp the protocol-specific header fields before FlushBuffer sends it.
 *
 * NetFlow v9: increment the per-packet sequence counter, write record count.
 * IPFIX v10:  write total message length in bytes, exportTime, and the
 *             cumulative data-record sequence number (RFC 7011 §3.1). */
static void FinalizePacket(send_peer_t *peer) {
    CloseDataFlowset(peer);
    if (use_ipfix) {
        uint16_t pkt_len = (uint16_t)((uint8_t *)peer->buff_ptr - (uint8_t *)peer->send_buffer);
        sender_data->header.ipfix_header->length = htons(pkt_len);
        sender_data->header.ipfix_header->exportTime = htonl((uint32_t)time(NULL));
        /* sequenceNumber = count of data records exported before this message */
        sender_data->header.ipfix_header->sequenceNumber = htonl(sender_data->header.sequence);
        sender_data->header.sequence += sender_data->header.record_count;
    } else {
        sender_data->header.sequence++;
        sender_data->header.v9_header->sequence = htonl(sender_data->header.sequence);
        sender_data->header.v9_header->count =
            htons(sender_data->header.record_count + sender_data->header.template_count);
    }
    dbg_printf("Prepare buffer: sequence: %u, records: %u, templates: %u\n", sender_data->header.sequence,
               sender_data->header.record_count, sender_data->header.template_count);
}  // End of FinalizePacket

static int CheckSendBufferSpace(size_t size, send_peer_t *peer) {
    dbg_printf("CheckSendBufferSpace for %zu bytes: ", size);
    if ((peer->buff_ptr + size) > peer->endp) {
        // request buffer flush
        dbg_printf("Check for %zu bytes in send buffer. Flush first.\n", size);
        peer->flush = 1;
        FinalizePacket(peer);
        sender_data->header.record_count = 0;
        sender_data->header.template_count = 0;
        return 0;
    }
    dbg_printf("ok.\n");

    return 1;

}  // End of CheckBufferSpace

int Add_v9_output_record(recordHandle_t *recordHandle, send_peer_t *peer) {
#ifdef DEVEL
    static unsigned count = 1;
    printf("\nNext record: %u\n", count++);
#endif
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    if (recordHandle->numElements == 0 || !genericFlow) {
        dbg_printf("Skip record with 0 extensions\n");
        return 0;
    }

    if (!sender_data->header.v9_header->unix_secs) {  // first time a record is added
        dbg_printf("First time setup\n");
        if (!use_ipfix) {
            // v9: set SysUptime base one day back so per-record relative timestamps fit
            uint64_t boot_time = genericFlow->msecFirst - 86400LL * 1000LL;
            uint32_t unix_secs = boot_time / 1000LL;
            sender_data->header.v9_header->unix_secs = htonl(unix_secs);
        } else {
            // IPFIX: mark as initialised; exportTime is set fresh on every FinalizePacket
            sender_data->header.v9_header->unix_secs = htonl(1);
        }
    }

    // check, if Buffer was flushed
    if (peer->buff_ptr == peer->send_buffer) {
        size_t hdr_size = use_ipfix ? sizeof(ipfixHeader_t) : sizeof(v9Header_t);
        peer->buff_ptr = (void *)((void *)peer->send_buffer + hdr_size);
    }

    time_t now = time(NULL);
    outTemplate_t *template = GetOutputTemplate(recordHandle);
    if ((sender_data->data_flowset_id != template->template_id) || template->needs_refresh) {
        // Different flowset ID - End data flowset and open new data flowset
        CloseDataFlowset(peer);

        if (!CheckSendBufferSpace(template->data_length + sizeof(data_flowset_t) + template->flowset_length, peer)) {
            // request buffer flush first
            dbg_printf("Flush Buffer #1\n");
            return 1;
        }

        // if never sent or needs refresh
        if (template->record_count == 0 || template->needs_refresh) {
            Add_template_flowset(template, peer);
            template->time_sent = now;
            // Consume the refresh request - leaving this set would resend
            // the template flowset with every subsequent record for the
            // rest of the run instead of only once every MAX_LIFETIME
            // seconds or 4096 records.
            template->needs_refresh = 0;
        }

        // Add data flowset
        dbg_printf("Add new data flowset\n");
        sender_data->data_flowset = peer->buff_ptr;
        sender_data->data_flowset->flowset_id = template->template_flowset->template_id;
        sender_data->data_flowset_id = template->template_id;
        peer->buff_ptr = (void *)sender_data->data_flowset->data;
    }

    // same data flowset ID - add Record
    if (!CheckSendBufferSpace(template->data_length, peer)) {
        // request buffer flush first
        dbg_printf("Flush Buffer #2\n");
        return 1;
    }

    dbg_printf("Add record %u, bytes: %u\n", template->template_id, template->data_length);
    Append_Record(peer, recordHandle);

    // template record counter
    template->record_count++;

    // need refresh?
    if (((template->record_count & 0xFFF) == 0) || (now - template->time_sent > MAX_LIFETIME)) {
        template->needs_refresh = 1;
        dbg_printf("Schedule template refresh\n");
    }

    dbg_printf("Done Add_v9_output_record\n\n");

    return 0;
}  // End of Add_v9_output_record

/* Add_ipfix_output_record — IPFIX v10 entry point.
 * All data-record encoding is identical to NetFlow v9 (same IANA IE numbers
 * and byte widths for all fields used here); only the message header and
 * template set ID differ, which are driven by the use_ipfix flag. */
int Add_ipfix_output_record(recordHandle_t *recordHandle, send_peer_t *peer) {
    return Add_v9_output_record(recordHandle, peer);
}  // End of Add_ipfix_output_record
