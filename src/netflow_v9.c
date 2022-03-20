/*
 *  Copyright (c) 2009-2021, Peter Haag
 *  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
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
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "bookkeeper.h"
#include "collector.h"
#include "exporter.h"
#include "fnf.h"
#include "metric.h"
#include "nbar.h"
#include "netflow_v9.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfnet.h"
#include "nfxV3.h"
#include "output_short.h"
#include "util.h"

// a few handy macros
#include "inline.c"

static int printRecord;
static uint32_t default_sampling;
static uint32_t overwrite_sampling;

// define stack slots
#define STACK_NONE 0
#define STACK_ICMP 1
#define STACK_ICMP_TYPE 2
#define STACK_ICMP_CODE 3
#define STACK_FIRST22 4
#define STACK_LAST21 5
#define STACK_SAMPLER 6
#define STACK_MSEC 7
#define STACK_CLIENT_USEC 8
#define STACK_SERVER_USEC 9
#define STACK_APPL_USEC 10
#define STACK_ENGINE_TYPE 11
#define STACK_ENGINE_ID 12
#define STACK_MAX 13

typedef struct exporterDomain_s {
    // identical to generic_exporter_t
    struct exporterDomain_s *next;

    // generic exporter information
    exporter_info_record_t info;

    uint64_t packets;           // number of packets sent by this exporter
    uint64_t flows;             // number of flow records sent by this exporter
    uint32_t sequence_failure;  // number of sequence failues
    uint32_t padding_errors;    // number of padding errors

    // sampling information:
    // each flow source may have several sampler applied
    // tags #48, #49, #50
    // each sampler is assinged a sampler struct

    // global sampling information #34 #35
    // stored in a sampler with id = -1;
    sampler_t *sampler;  // sampler info

    // exporter parameters
    uint64_t boot_time;
    // sequence
    int64_t last_sequence;
    int64_t sequence;
    int first;

    // statistics
    uint64_t TemplateRecords;  // stat counter
    uint64_t DataRecords;      // stat counter

    // in order to prevent search through all lists keep
    // the last template we processed as a cache
    templateList_t *currentTemplate;

    // list of all templates of this exporter
    templateList_t *template;

} exporterDomain_t;

static const struct v9TranslationMap_s {
    uint16_t id;  // v9 element id
#define Stack_ONLY 0
    uint16_t outputLength;  // output length in extension ID
    uint16_t copyMode;      // extension ID
    uint16_t extensionID;   // extension ID
    uint32_t offsetRel;     // offset rel. to extension start of struct
    uint32_t stackID;       // save value in stack slot, if needed
    char *name;             // name of element as string
} v9TranslationMap[] = {
    {NF9_IN_BYTES, SIZEinBytes, NumberCopy, EXgenericFlowID, OFFinBytes, STACK_NONE, "inBytesDeltaCount"},
    {NF9_IN_PACKETS, SIZEinPackets, NumberCopy, EXgenericFlowID, OFFinPackets, STACK_NONE, "inPacketsDeltaCount"},
    {NF9_FLOWS_AGGR, SIZEflows, NumberCopy, EXcntFlowID, OFFflows, STACK_NONE, "FlowCount"},
    {NF9_IN_PROTOCOL, SIZEproto, NumberCopy, EXgenericFlowID, OFFproto, STACK_NONE, "proto"},
    {NF9_SRC_TOS, SIZEsrcTos, NumberCopy, EXgenericFlowID, OFFsrcTos, STACK_NONE, "src tos"},
    {NF9_FORWARDING_STATUS, SIZEfwdStatus, NumberCopy, EXgenericFlowID, OFFfwdStatus, STACK_NONE, "forwarding status"},
    {NF9_TCP_FLAGS, SIZEtcpFlags, NumberCopy, EXgenericFlowID, OFFtcpFlags, STACK_NONE, "TCP flags"},
    {NF9_L4_SRC_PORT, SIZEsrcPort, NumberCopy, EXgenericFlowID, OFFsrcPort, STACK_NONE, "src port"},
    {NF9_IPV4_SRC_ADDR, SIZEsrc4Addr, NumberCopy, EXipv4FlowID, OFFsrc4Addr, STACK_NONE, "src IPv4"},
    {NF9_SRC_MASK, SIZEsrcMask, NumberCopy, EXflowMiscID, OFFsrcMask, STACK_NONE, "src mask IPv4"},
    {NF9_INPUT_SNMP, SIZEinput, NumberCopy, EXflowMiscID, OFFinput, STACK_NONE, "input interface"},
    {NF9_L4_DST_PORT, SIZEdstPort, NumberCopy, EXgenericFlowID, OFFdstPort, STACK_NONE, "dst port"},
    {NF_F_ICMP_TYPE, Stack_ONLY, NumberCopy, EXgenericFlowID, OFFicmpType, STACK_ICMP_TYPE, "icmp type"},
    {NF_F_ICMP_TYPE_IPV6, Stack_ONLY, NumberCopy, EXgenericFlowID, OFFicmpType, STACK_ICMP_TYPE, "icmp type"},
    {NF_F_ICMP_CODE, Stack_ONLY, NumberCopy, EXgenericFlowID, OFFicmpCode, STACK_ICMP_CODE, "icmp code"},
    {NF_F_ICMP_CODE_IPV6, Stack_ONLY, NumberCopy, EXgenericFlowID, OFFicmpCode, STACK_ICMP_CODE, "icmp code"},
    {NF9_IPV4_DST_ADDR, SIZEdst4Addr, NumberCopy, EXipv4FlowID, OFFdst4Addr, STACK_NONE, "dst IPv4"},
    {NF9_DST_MASK, SIZEdstMask, NumberCopy, EXflowMiscID, OFFdstMask, STACK_NONE, "dst mask IPv4"},
    {NF9_OUTPUT_SNMP, SIZEoutput, NumberCopy, EXflowMiscID, OFFoutput, STACK_NONE, "output interface"},
    {NF9_V4_NEXT_HOP, SIZENext4HopIP, NumberCopy, EXipNextHopV4ID, OFFNext4HopIP, STACK_NONE, "IPv4 next hop"},
    {NF9_SRC_AS, SIZEsrcAS, NumberCopy, EXasRoutingID, OFFsrcAS, STACK_NONE, "src AS"},
    {NF9_DST_AS, SIZEdstAS, NumberCopy, EXasRoutingID, OFFdstAS, STACK_NONE, "dst AS"},
    {NF9_BGP_V4_NEXT_HOP, SIZEbgp4NextIP, NumberCopy, EXbgpNextHopV4ID, OFFbgp4NextIP, STACK_NONE, "IPv4 bgp next hop"},
    {NF9_LAST_SWITCHED, Stack_ONLY, NumberCopy, EXgenericFlowID, OFFmsecLast, STACK_LAST21, "msec last SysupTime"},
    {NF9_FIRST_SWITCHED, Stack_ONLY, NumberCopy, EXgenericFlowID, OFFmsecFirst, STACK_FIRST22, "msec first SysupTime"},
    {NF9_OUT_BYTES, SIZEoutBytes, NumberCopy, EXcntFlowID, OFFoutBytes, STACK_NONE, "output bytes delta counter"},
    {NF9_OUT_PKTS, SIZEoutPackets, NumberCopy, EXcntFlowID, OFFoutPackets, STACK_NONE, "output packet delta counter"},
    {NF9_IPV6_SRC_ADDR, SIZEsrc6Addr, NumberCopy, EXipv6FlowID, OFFsrc6Addr, STACK_NONE, "IPv6 src addr"},
    {NF9_IPV6_DST_ADDR, SIZEdst6Addr, NumberCopy, EXipv6FlowID, OFFdst6Addr, STACK_NONE, "IPv6 dst addr"},
    {NF9_IPV6_SRC_MASK, SIZEsrcMask, NumberCopy, EXflowMiscID, OFFsrcMask, STACK_NONE, "src mask bits"},
    {NF9_IPV6_DST_MASK, SIZEdstMask, NumberCopy, EXflowMiscID, OFFdstMask, STACK_NONE, "dst mask bits"},
    {NF9_ICMP, Stack_ONLY, NumberCopy, EXgenericFlowID, OFFdstPort, STACK_ICMP, "icmp type/code"},
    {NF9_DST_TOS, SIZEdstTos, NumberCopy, EXflowMiscID, OFFdstTos, STACK_NONE, "post IP class of Service"},
    {NF9_IN_SRC_MAC, SIZEinSrcMac, NumberCopy, EXmacAddrID, OFFinSrcMac, STACK_NONE, "in src MAC addr"},
    {NF9_OUT_DST_MAC, SIZEoutDstMac, NumberCopy, EXmacAddrID, OFFoutDstMac, STACK_NONE, "out dst MAC addr"},
    {NF9_SRC_VLAN, SIZEsrcVlan, NumberCopy, EXvLanID, OFFsrcVlan, STACK_NONE, "src VLAN ID"},
    {NF9_DST_VLAN, SIZEdstVlan, NumberCopy, EXvLanID, OFFdstVlan, STACK_NONE, "dst VLAN ID"},
    {NF_F_dot1qVlanId, SIZEsrcVlan, NumberCopy, EXvLanID, OFFsrcVlan, STACK_NONE, "src VLAN ID"},
    {NF_F_postDot1qVlanId, SIZEdstVlan, NumberCopy, EXvLanID, OFFdstVlan, STACK_NONE, "dst VLAN ID"},
    {NF9_DIRECTION, SIZEdir, NumberCopy, EXflowMiscID, OFFdir, STACK_NONE, "flow direction"},
    {NF9_V6_NEXT_HOP, SIZENext6HopIP, NumberCopy, EXipNextHopV6ID, OFFNext6HopIP, STACK_NONE, "IPv6 next hop IP"},
    {NF9_BPG_V6_NEXT_HOP, SIZEbgp6NextIP, NumberCopy, EXbgpNextHopV6ID, OFFbgp6NextIP, STACK_NONE, "IPv6 bgp next hop IP"},
    {NF_F_BGP_ADJ_NEXT_AS, SIZEnextAdjacentAS, NumberCopy, EXasAdjacentID, OFFnextAdjacentAS, STACK_NONE, "bgb adj next AS"},
    {NF_F_BGP_ADJ_PREV_AS, SIZEprevAdjacentAS, NumberCopy, EXasAdjacentID, OFFprevAdjacentAS, STACK_NONE, "bgb adj prev AS"},
    {NF9_MPLS_LABEL_1, SIZEmplsLabel1, NumberCopy, EXmplsLabelID, OFFmplsLabel1, STACK_NONE, "mpls label 1"},
    {NF9_MPLS_LABEL_2, SIZEmplsLabel2, NumberCopy, EXmplsLabelID, OFFmplsLabel2, STACK_NONE, "mpls label 2"},
    {NF9_MPLS_LABEL_3, SIZEmplsLabel3, NumberCopy, EXmplsLabelID, OFFmplsLabel3, STACK_NONE, "mpls label 3"},
    {NF9_MPLS_LABEL_4, SIZEmplsLabel4, NumberCopy, EXmplsLabelID, OFFmplsLabel4, STACK_NONE, "mpls label 4"},
    {NF9_MPLS_LABEL_5, SIZEmplsLabel5, NumberCopy, EXmplsLabelID, OFFmplsLabel5, STACK_NONE, "mpls label 5"},
    {NF9_MPLS_LABEL_6, SIZEmplsLabel6, NumberCopy, EXmplsLabelID, OFFmplsLabel6, STACK_NONE, "mpls label 6"},
    {NF9_MPLS_LABEL_7, SIZEmplsLabel7, NumberCopy, EXmplsLabelID, OFFmplsLabel7, STACK_NONE, "mpls label 7"},
    {NF9_MPLS_LABEL_8, SIZEmplsLabel8, NumberCopy, EXmplsLabelID, OFFmplsLabel8, STACK_NONE, "mpls label 8"},
    {NF9_MPLS_LABEL_9, SIZEmplsLabel9, NumberCopy, EXmplsLabelID, OFFmplsLabel9, STACK_NONE, "mpls label 9"},
    {NF9_MPLS_LABEL_10, SIZEmplsLabel10, NumberCopy, EXmplsLabelID, OFFmplsLabel10, STACK_NONE, "mpls label 10"},
    {NF9_IN_DST_MAC, SIZEinDstMac, NumberCopy, EXmacAddrID, OFFinDstMac, STACK_NONE, "in dst MAC addr"},
    {NF9_OUT_SRC_MAC, SIZEoutSrcMac, NumberCopy, EXmacAddrID, OFFoutSrcMac, STACK_NONE, "out src MAC addr"},
    {NF_F_FLOW_CREATE_TIME_MSEC, SIZEmsecFirst, NumberCopy, EXgenericFlowID, OFFmsecFirst, STACK_NONE, "msec first"},
    {NF_F_FLOW_END_TIME_MSEC, SIZEmsecLast, NumberCopy, EXgenericFlowID, OFFmsecLast, STACK_NONE, "msec last"},
    {NF9_ENGINE_TYPE, Stack_ONLY, NumberCopy, EXnull, 0, STACK_ENGINE_TYPE, "engine type"},
    {NF9_ENGINE_ID, Stack_ONLY, NumberCopy, EXnull, 0, STACK_ENGINE_ID, "engine ID"},
    {LOCAL_IPv4Received, SIZEReceived4IP, NumberCopy, EXipReceivedV4ID, OFFReceived4IP, STACK_NONE, "IPv4 exporter"},
    {LOCAL_IPv6Received, SIZEReceived6IP, NumberCopy, EXipReceivedV6ID, OFFReceived6IP, STACK_NONE, "IPv6 exporter"},
    {LOCAL_msecTimeReceived, SIZEmsecReceived, NumberCopy, EXgenericFlowID, OFFmsecReceived, STACK_NONE, "msec time received"},

    // NSEL extensions
    {NF_F_FLOW_BYTES, SIZEinBytes, NumberCopy, EXgenericFlowID, OFFinBytes, STACK_NONE, "ASA inBytes total"},
    {NF_F_FLOW_PACKETS, SIZEinPackets, NumberCopy, EXgenericFlowID, OFFinPackets, STACK_NONE, "ASA inPackets total"},
    {NF_F_FWD_FLOW_DELTA_BYTES, SIZEinBytes, NumberCopy, EXgenericFlowID, OFFinBytes, STACK_NONE, "ASA fwd bytes"},
    {NF_F_REV_FLOW_DELTA_BYTES, SIZEoutBytes, NumberCopy, EXcntFlowID, OFFoutBytes, STACK_NONE, "ASA rew bytes"},
    {NF_F_INITIATORPACKETS, SIZEinPackets, NumberCopy, EXgenericFlowID, OFFinPackets, STACK_NONE, "ASA initiator pkackets"},
    {NF_F_RESPONDERPACKETS, SIZEoutPackets, NumberCopy, EXcntFlowID, OFFoutPackets, STACK_NONE, "ASA responder packets"},
    {NF_F_EVENT_TIME_MSEC, Stack_ONLY, NumberCopy, EXnull, 0, STACK_MSEC, "msec time event"},
    {NF_F_CONN_ID, SIZEconnID, NumberCopy, EXnselCommonID, OFFconnID, STACK_NONE, "connection ID"},
    {NF_F_FW_EVENT, SIZEfwEvent, NumberCopy, EXnselCommonID, OFFfwEvent, STACK_NONE, "fw event ID"},
    {NF_F_FW_EVENT_84, SIZEfwEvent, NumberCopy, EXnselCommonID, OFFfwEvent, STACK_NONE, "fw event ID"},
    {NF_F_FW_EXT_EVENT, SIZEfwXevent, NumberCopy, EXnselCommonID, OFFfwXevent, STACK_NONE, "fw ext event ID"},
    {NF_F_XLATE_SRC_ADDR_IPV4, SIZExlateSrc4Addr, NumberCopy, EXnselXlateIPv4ID, OFFxlateSrc4Addr, STACK_NONE, "xlate src addr"},
    {NF_F_XLATE_SRC_ADDR_84, SIZExlateSrc4Addr, NumberCopy, EXnselXlateIPv4ID, OFFxlateSrc4Addr, STACK_NONE, "xlate src addr"},
    {NF_F_XLATE_DST_ADDR_IPV4, SIZExlateDst4Addr, NumberCopy, EXnselXlateIPv4ID, OFFxlateDst4Addr, STACK_NONE, "xlate dst addr"},
    {NF_F_XLATE_DST_ADDR_84, SIZExlateDst4Addr, NumberCopy, EXnselXlateIPv4ID, OFFxlateDst4Addr, STACK_NONE, "xlate dst addr"},
    {NF_F_XLATE_SRC_ADDR_IPV6, SIZExlateSrc6Addr, NumberCopy, EXnselXlateIPv6ID, OFFxlateSrc6Addr, STACK_NONE, "xlate src addr"},
    {NF_F_XLATE_DST_ADDR_IPV6, SIZExlateDst6Addr, NumberCopy, EXnselXlateIPv6ID, OFFxlateDst6Addr, STACK_NONE, "xlate dst addr"},
    {NF_F_XLATE_SRC_PORT, SIZExlateSrcPort, NumberCopy, EXnselXlatePortID, OFFxlateSrcPort, STACK_NONE, "xlate src port"},
    {NF_F_XLATE_DST_PORT, SIZExlateDstPort, NumberCopy, EXnselXlatePortID, OFFxlateDstPort, STACK_NONE, "xlate dst port"},
    {NF_F_XLATE_SRC_PORT_84, SIZExlateSrcPort, NumberCopy, EXnselXlatePortID, OFFxlateSrcPort, STACK_NONE, "xlate src port"},
    {NF_F_XLATE_DST_PORT_84, SIZExlateDstPort, NumberCopy, EXnselXlatePortID, OFFxlateDstPort, STACK_NONE, "xlate dst port"},
    {NF_F_INGRESS_ACL_ID, SIZEingressAcl, NumberCopy, EXnselAclID, OFFingressAcl, STACK_NONE, "ingress ACL ID"},
    {NF_F_EGRESS_ACL_ID, SIZEegressAcl, NumberCopy, EXnselAclID, OFFegressAcl, STACK_NONE, "egress ACL ID"},
    {NF_F_USERNAME, SIZEusername, NumberCopy, EXnselUserID, OFFusername, STACK_NONE, "AAA username"},
    // NEL

    {NF_N_NAT_EVENT, SIZEnatEvent, NumberCopy, EXnelCommonID, OFFnatEvent, STACK_NONE, "NAT event"},
    {NF_N_INGRESS_VRFID, SIZEingressVrf, NumberCopy, EXnelCommonID, OFFingressVrf, STACK_NONE, "ingress VRF ID"},
    {NF_N_EGRESS_VRFID, SIZEegressVrf, NumberCopy, EXnelCommonID, OFFegressVrf, STACK_NONE, "egress VRF ID"},
    {NF_N_NATPOOL_ID, SIZEnatPoolID, NumberCopy, EXnelCommonID, OFFnatPoolID, STACK_NONE, "nat pool ID"},
    {NF_F_XLATE_PORT_BLOCK_START, SIZEnelblockStart, NumberCopy, EXnelXlatePortID, OFFnelblockStart, STACK_NONE, "NAT block start"},
    {NF_F_XLATE_PORT_BLOCK_END, SIZEnelblockEnd, NumberCopy, EXnelXlatePortID, OFFnelblockEnd, STACK_NONE, "NAT block end"},
    {NF_F_XLATE_PORT_BLOCK_STEP, SIZEnelblockStep, NumberCopy, EXnelXlatePortID, OFFnelblockStep, STACK_NONE, "NAT block step"},
    {NF_F_XLATE_PORT_BLOCK_SIZE, SIZEnelblockSize, NumberCopy, EXnelXlatePortID, OFFnelblockSize, STACK_NONE, "NAT block size"},

    // Nprobe latency
    {NF_NPROBE_CLIENT_NW_DELAY_USEC, SIZEusecClientNwDelay, NumberCopy, EXlatencyID, OFFusecClientNwDelay, STACK_NONE, "nprobe client latency usec"},
    {NF_NPROBE_SERVER_NW_DELAY_USEC, SIZEusecServerNwDelay, NumberCopy, EXlatencyID, OFFusecServerNwDelay, STACK_NONE, "nprobe client latency usec"},
    {NF_NPROBE_APPL_LATENCY_USEC, SIZEusecApplLatency, NumberCopy, EXlatencyID, OFFusecApplLatency, STACK_NONE, "nprobe application latency usec"},
    {NF_NPROBE_CLIENT_NW_DELAY_SEC, Stack_ONLY, NumberCopy, EXlatencyID, 0, STACK_CLIENT_USEC, "nprobe client latency sec"},
    {NF_NPROBE_SERVER_NW_DELAY_SEC, Stack_ONLY, NumberCopy, EXlatencyID, 0, STACK_SERVER_USEC, "nprobe server latency sec"},
    {NF_NPROBE_APPL_LATENCY_SEC, Stack_ONLY, NumberCopy, EXlatencyID, 0, STACK_APPL_USEC, "nprobe application latency sec"},

    // nbar
    {NBAR_APPLICATION_ID, SIZEnbarAppID, ByteCopy, EXnbarAppID, OFFnbarAppID, STACK_NONE, "nbar application ID"},

    // sampling
    {NF9_FLOW_SAMPLER_ID, Stack_ONLY, NumberCopy, EXnull, 0, STACK_SAMPLER, "sampler ID"},
    {NF_SELECTOR_ID, Stack_ONLY, NumberCopy, EXnull, 0, STACK_SAMPLER, "sampler ID"},

    // End of table
    {0, 0, 0, 0, 0, STACK_NONE, NULL},
};

// netflow v9 does not officially support enterprise IDs and reverse elements
// some exporters export tem though
// map for corresponding reverse element, if enterprise ID = IPFIX_ReverseInformationElement
static const struct v9ReverseMap_s {
    uint16_t ID;         // v9 element id
    uint16_t reverseID;  // reverse v9 element id
} v9ReverseMap[] = {
    {NF9_IN_BYTES, NF9_OUT_BYTES},
    {NF9_IN_PACKETS, NF9_OUT_PKTS},
    {0, 0},
};

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
    // match template with mater record
    uint32_t size;
    uint16_t numExtensions;
    uint16_t exElementList[MAXELEMENTS];

    //
    time_t time_sent;
    uint64_t record_count;  // number of data records sent with this template

    uint32_t record_length;   // length of the data record resulting from this template
    uint32_t flowset_length;  // length of the flowset record
    uint16_t template_id;     // id assigned to this template
    uint16_t needs_refresh;   // tagged for refreshing

    // template flowset
    template_flowset_t *template_flowset;
} outTemplate_t;

typedef struct sender_data_s {
    struct header_s {
        v9Header_t *v9_header;    // start of v9 packet
        uint32_t record_count;    // number of records in send buffer
        uint32_t template_count;  // number of templates in send buffer
        uint32_t sequence;
    } header;

    data_flowset_t *data_flowset;  // start of data_flowset in buffer
    uint32_t data_flowset_id;      // id of current data flowset

} sender_data_t;

#define MAX_LIFETIME 60

static outTemplate_t *outTemplates = NULL;
static sender_data_t *sender_data = NULL;
static uint32_t processed_records;
static uint32_t numV9Elements;

/* local function prototypes */
static void ProcessOptionFlowset(exporterDomain_t *exporter, FlowSource_t *fs, templateList_t *templateList, void *data_flowset);

static void InsertSampler(FlowSource_t *fs, exporterDomain_t *exporter, int32_t id, uint16_t mode, uint32_t interval);

static inline void Process_v9_templates(exporterDomain_t *exporter, void *template_flowset, FlowSource_t *fs);

static inline void Process_v9_option_templates(exporterDomain_t *exporter, void *option_template_flowset, FlowSource_t *fs);

static inline void Process_v9_data(exporterDomain_t *exporter, void *data_flowset, FlowSource_t *fs, dataTemplate_t *template);

static void Process_v9_sampler_option_data(exporterDomain_t *exporter, FlowSource_t *fs, templateList_t *template, void *data_flowset);

static void Process_v9_nbar_option_data(exporterDomain_t *exporter, FlowSource_t *fs, templateList_t *template, void *data_flowset);

static inline exporterDomain_t *getExporter(FlowSource_t *fs, uint32_t exporter_id);

static outTemplate_t *GetOutputTemplate(master_record_t *master_record);

static void Append_Record(send_peer_t *peer, master_record_t *master_record);

static int Add_template_flowset(outTemplate_t *outTemplate, send_peer_t *peer);

static void CloseDataFlowset(send_peer_t *peer);

static int CheckSendBufferSpace(size_t size, send_peer_t *peer);

/* functions */

#include "nffile_inline.c"
int Init_v9(int verbose, uint32_t sampling, uint32_t overwrite) {
    int i;

    printRecord = verbose > 2;
    default_sampling = sampling;
    overwrite_sampling = overwrite;
    outTemplates = NULL;

    for (i = 0; v9TranslationMap[i].name != NULL; i++) {
    }
    LogInfo("Init v9: Max number of v9 tags: %u", i);

    return 1;

}  // End of Init_v9

static void ProcessOptionFlowset(exporterDomain_t *exporter, FlowSource_t *fs, templateList_t *template, void *data_flowset) {
    if (TestFlag(template->type, SAMPLER_TEMPLATE)) {
        dbg_printf("Found sampler option table\n");
        Process_v9_sampler_option_data(exporter, fs, template, data_flowset);
    }
    if (TestFlag(template->type, NBAR_TEMPLATE)) {
        dbg_printf("Found nbar option table\n");
        Process_v9_nbar_option_data(exporter, fs, template, data_flowset);
    }

}  // End of ProcessOptionFlowset

static int LookupElement(uint16_t type, int EnterpriseNumber) {
    switch (EnterpriseNumber) {
        case 0:  // no Enterprise value
            break;
        case IPFIX_ReverseInformationElement:
            for (int i = 0; v9ReverseMap[i].ID != 0; i++) {
                if (v9ReverseMap[i].ID == type) {
                    type = v9ReverseMap[i].reverseID;
                    dbg_printf(" Reverse mapped element type: %u\n", type);
                    break;
                }
            }
            break;
        default:
            dbg_printf(" Skip enterprise id: %u\n", EnterpriseNumber);
            return -1;
    }

    int i = 0;
    while (v9TranslationMap[i].name != NULL) {
        if (v9TranslationMap[i].id == type) return i;
        i++;
    }

    return -1;

}  // End of LookupElement

static inline exporterDomain_t *getExporter(FlowSource_t *fs, uint32_t exporter_id) {
#define IP_STRING_LEN 40
    char ipstr[IP_STRING_LEN];
    exporterDomain_t **e = (exporterDomain_t **)&(fs->exporter_data);

    while (*e) {
        if ((*e)->info.id == exporter_id && (*e)->info.version == 9 && (*e)->info.ip.V6[0] == fs->ip.V6[0] && (*e)->info.ip.V6[1] == fs->ip.V6[1])
            return *e;
        e = &((*e)->next);
    }

    if (fs->sa_family == AF_INET) {
        uint32_t _ip = htonl(fs->ip.V4);
        inet_ntop(AF_INET, &_ip, ipstr, sizeof(ipstr));
    } else if (fs->sa_family == AF_INET6) {
        uint64_t _ip[2];
        _ip[0] = htonll(fs->ip.V6[0]);
        _ip[1] = htonll(fs->ip.V6[1]);
        inet_ntop(AF_INET6, &_ip, ipstr, sizeof(ipstr));
    } else {
        strncpy(ipstr, "<unknown>", IP_STRING_LEN);
    }

    // nothing found
    *e = (exporterDomain_t *)calloc(1, sizeof(exporterDomain_t));
    if (!(*e)) {
        LogError("Process_v9: Panic! malloc() %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }
    (*e)->info.header.type = ExporterInfoRecordType;
    (*e)->info.header.size = sizeof(exporter_info_record_t);
    (*e)->info.version = 9;
    (*e)->info.id = exporter_id;
    (*e)->info.ip = fs->ip;
    (*e)->info.sa_family = fs->sa_family;
    (*e)->info.sysid = 0;

    (*e)->first = 1;
    (*e)->sequence_failure = 0;
    (*e)->padding_errors = 0;
    (*e)->TemplateRecords = 0;
    (*e)->DataRecords = 0;

    (*e)->sampler = NULL;
    (*e)->next = NULL;

    FlushInfoExporter(fs, &((*e)->info));

    dbg_printf("Process_v9: New exporter: SysID: %u, Domain: %u, IP: %s\n", (*e)->info.sysid, exporter_id, ipstr);
    LogInfo("Process_v9: New exporter: SysID: %u, Domain: %u, IP: %s\n", (*e)->info.sysid, exporter_id, ipstr);

    return (*e);

}  // End of getExporter

static templateList_t *getTemplate(exporterDomain_t *exporter, uint16_t id) {
    templateList_t *template;

#ifdef DEVEL
    if (exporter->currentTemplate) {
        printf("Get template - current template: %u\n", exporter->currentTemplate->id);
    }
    printf("Get template - available templates for exporter: %u\n", exporter->info.id);
    template = exporter->template;
    while (template) {
        printf(" ID: %u, type:, %u\n", template->id, template->type);
        template = template->next;
    }
#endif

    if (exporter->currentTemplate && (exporter->currentTemplate->id == id)) return exporter->currentTemplate;

    template = exporter->template;
    while (template) {
        if (template->id == id) {
            exporter->currentTemplate = template;
            return template;
        }
        template = template->next;
    }

    dbg_printf("[%u] Get template %u: not found\n", exporter->info.id, id);
    exporter->currentTemplate = NULL;

    return NULL;

}  // End of getTemplate

static templateList_t *newTemplate(exporterDomain_t *exporter, uint16_t id) {
    templateList_t *template;

    template = calloc(1, sizeof(templateList_t));
    if (!template) {
        LogError("Process_v9: Panic! calloc() %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    // init the new template
    template->next = exporter->template;
    template->updated = time(NULL);
    template->id = id;
    template->data = NULL;

    exporter->template = template;
    dbg_printf("[%u] Add new template ID %u\n", exporter->info.id, id);

    return template;

}  // End of newTemplate

static void removeTemplate(exporterDomain_t *exporter, uint16_t id) {
    templateList_t *template, *parent;

    parent = NULL;
    template = exporter->template;
    while (template && (template->id != id)) {
        parent = template;
        template = template->next;
    }

    if (template == NULL) {
        dbg_printf("[%u] Remove template id: %i - template not found\n", exporter->info.id, id);
        return;
    } else {
        dbg_printf("[%u] Remove template ID: %u\n", exporter->info.id, id);
    }

    // clear table cache, if this is the table to delete
    if (exporter->currentTemplate == template) exporter->currentTemplate = NULL;

    if (parent) {
        // remove temeplate from list
        parent->next = template->next;
    } else {
        // last temeplate removed
        exporter->template = template->next;
    }

    if (TestFlag(template->type, DATA_TEMPLATE)) {
        dataTemplate_t *dataTemplate = (dataTemplate_t *)template->data;
        ClearSequencer(&(dataTemplate->sequencer));
    }
    free(template->data);
    free(template);

}  // End of removeTemplate

static inline void Process_v9_templates(exporterDomain_t *exporter, void *DataPtr, FlowSource_t *fs) {
    void *template;
    uint32_t size_left, size_required, num_v9tags;
    int i;

    size_left = GET_FLOWSET_LENGTH(DataPtr);
    size_left -= 4;          // -4 for flowset header -> id and length
    template = DataPtr + 4;  // the template description begins at offset 4

    // process all templates in flowset, as long as any bytes are left
    size_required = 0;
    while (size_left) {
        uint16_t id, count;
        void *p;
        template = template + size_required;

        if (size_left < 4) {
            LogError("Process_v9: [%u] buffer size error: flowset length error in %s:%u", exporter->info.id, __FILE__, __LINE__);
            return;
        }

        id = GET_TEMPLATE_ID(template);
        count = GET_TEMPLATE_COUNT(template);
        size_required = 4 + 4 * count;  // id + count = 4 bytes, and 2 x 2 bytes for each entry

        dbg_printf("\n[%u] Template ID: %u, field count: %u\n", exporter->info.id, id, count);
        dbg_printf("template size: %u buffersize: %u\n", size_required, size_left);

        if (size_left < size_required) {
            LogError("Process_v9: [%u] buffer size error: expected %u available %u", exporter->info.id, size_required, size_left);
            return;
        }

        num_v9tags = 0;  // number of optional v9 tags

        sequence_t *sequenceTable = malloc((count + 4) * sizeof(sequence_t));  // + 2 for IP and time received
        if (!sequenceTable) {
            LogError("Process_v9: malloc(): %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return;
        }
        uint32_t numSequences = 0;

        p = template + 4;  // type/length pairs start at template offset 4
        int commonFound = 0;
        for (i = 0; i < count; i++) {
            uint16_t Type, Length;
            uint32_t EnterpriseNumber = 0;

            Type = Get_val16(p);
            p = p + 2;
            Length = Get_val16(p);
            p = p + 2;
            num_v9tags++;

            int index = LookupElement(Type, EnterpriseNumber);
            if (index < 0) {  // not found - enter skip seqence
                sequenceTable[numSequences].inputType = Type;
                sequenceTable[numSequences].inputLength = Length;
                sequenceTable[numSequences].extensionID = EXnull;
                sequenceTable[numSequences].outputLength = 0;
                sequenceTable[numSequences].copyMode = 0;
                sequenceTable[numSequences].offsetRel = 0;
                sequenceTable[numSequences].stackID = STACK_NONE;
                dbg_printf("Skip sequence for unknown type: %u, length: %u\n", Type, Length);
            } else {
                sequenceTable[numSequences].inputType = Type;
                sequenceTable[numSequences].inputLength = Length;
                sequenceTable[numSequences].copyMode = v9TranslationMap[index].copyMode;
                sequenceTable[numSequences].extensionID = v9TranslationMap[index].extensionID;
                sequenceTable[numSequences].outputLength = v9TranslationMap[index].outputLength;
                sequenceTable[numSequences].offsetRel = v9TranslationMap[index].offsetRel;
                sequenceTable[numSequences].stackID = v9TranslationMap[index].stackID;
                dbg_printf("Map type: %u, length: %u to Extension %u - '%s' - output length: %u\n", Type, Length, v9TranslationMap[index].extensionID,
                           v9TranslationMap[index].name, v9TranslationMap[index].outputLength);
                commonFound++;
            }
            numSequences++;
        }
        dbg_printf("Processed: %u, common elements: %u\n", size_required, commonFound);

        if (commonFound == 0) {
            size_left -= size_required;
            DataPtr = DataPtr + size_required + 4;  // +4 for header
            dbg_printf("Template does not contain common elements - skip\n");
            free(sequenceTable);
            sequenceTable = NULL;
            continue;
        }

        int index = LookupElement(LOCAL_msecTimeReceived, 0);
        sequenceTable[numSequences].inputType = LOCAL_msecTimeReceived;
        sequenceTable[numSequences].inputLength = 0;
        sequenceTable[numSequences].extensionID = v9TranslationMap[index].extensionID;
        sequenceTable[numSequences].outputLength = v9TranslationMap[index].outputLength;
        sequenceTable[numSequences].offsetRel = v9TranslationMap[index].offsetRel;
        sequenceTable[numSequences].stackID = v9TranslationMap[index].stackID;
        numSequences++;
        dbg_printf("Map type: %u, length: %u to Extension %u - '%s' - output length: %u\n", LOCAL_msecTimeReceived, 8,
                   v9TranslationMap[index].extensionID, v9TranslationMap[index].name, v9TranslationMap[index].outputLength);

        // if it exitsts - remove old template on exporter with same ID
        removeTemplate(exporter, id);
        templateList_t *template = newTemplate(exporter, id);
        if (!template) {
            LogError("Process_v9: abort template add: %s line %d", __FILE__, __LINE__);
            return;
        }
        dataTemplate_t *dataTemplate = calloc(1, sizeof(dataTemplate_t));
        if (!dataTemplate) {
            LogError("Error calloc(): %s in %s:%d", strerror(errno), __FILE__, __LINE__);
            return;
        }
        template->data = dataTemplate;
        dataTemplate->extensionList = SetupSequencer(&(dataTemplate->sequencer), sequenceTable, numSequences);
        dataTemplate->sequencer.templateID = id;
        SetFlag(template->type, DATA_TEMPLATE);

#ifdef DEVEL
        printf("Added/Updated Sequencer to template\n");
        PrintSequencer(&(dataTemplate->sequencer));
#endif

        // update size left of this flowset
        size_left -= size_required;
        if (size_left < 4) {
            // pading
            dbg_printf("Skip %u bytes padding\n", size_left);
            return;
        }
        DataPtr = DataPtr + size_required + 4;  // +4 for header

    }  // End of while size_left

}  // End of Process_v9_templates

static inline void Process_v9_option_templates(exporterDomain_t *exporter, void *option_template_flowset, FlowSource_t *fs) {
    uint8_t *option_template, *p;
    uint32_t size_left, nr_scopes, nr_options;
    uint16_t tableID, scope_length, option_length;

    size_left = GET_FLOWSET_LENGTH(option_template_flowset) - 4;  // -4 for flowset header -> id and length
    option_template = option_template_flowset + 4;
    tableID = GET_OPTION_TEMPLATE_ID(option_template);
    scope_length = GET_OPTION_TEMPLATE_FIELD_COUNT(option_template);
    option_length = GET_OPTION_TEMPLATE_SCOPE_FIELD_COUNT(option_template);

    if (scope_length & 0x3) {
        LogError("Process_v9: [%u] scope length error: length %u not multiple of 4", exporter->info.id, scope_length);
        return;
    }

    if (option_length & 0x3) {
        LogError("Process_v9: [%u] option length error: length %u not multiple of 4", exporter->info.id, option_length);
        return;
    }

    if ((scope_length + option_length) > size_left) {
        LogError(
            "Process_v9: [%u] option template length error: size left %u too small for %u scopes "
            "length and %u options length",
            exporter->info.id, size_left, scope_length, option_length);
        return;
    }

    nr_scopes = scope_length >> 2;
    nr_options = option_length >> 2;

    dbg_printf("\n[%u] Option Template ID: %u\n", exporter->info.id, tableID);
    dbg_printf("Scope length: %u Option length: %u\n", scope_length, option_length);

    removeTemplate(exporter, tableID);
    optionTemplate_t *optionTemplate = (optionTemplate_t *)calloc(1, sizeof(optionTemplate_t));
    if (!optionTemplate) {
        LogError("Error calloc(): %s in %s:%d", strerror(errno), __FILE__, __LINE__);
        return;
    }

    int i;
    uint16_t offset = 0;
    p = option_template + 6;  // start of length/type data
    for (i = 0; i < nr_scopes; i++) {
#ifdef DEVEL
        uint16_t type = Get_val16(p);
#endif
        p = p + 2;

        uint16_t length = Get_val16(p);
        p = p + 2;
        offset += length;
#ifdef DEVEL
        printf("Scope field: Type ");
        switch (type) {
            case 1:
                printf("(1) - System");
                break;
            case 2:
                printf("(2) - Interface");
                break;
            case 3:
                printf("(3) - Line Card");
                break;
            case 4:
                printf("(4) - NetFlow Cache");
                break;
            case 5:
                printf("(5) - Template");
                break;
            default:
                printf("(%u) - Unknown", type);
                break;
        }
        printf(", length %u\n", length);
#endif
    }
    uint16_t scopeSize = offset;

    struct samplerOption_s *samplerOption = &(optionTemplate->samplerOption);
    struct nbarOptionList_s *nbarOption = &(optionTemplate->nbarOption);

    for (; i < (nr_scopes + nr_options); i++) {
        uint16_t type = Get_val16(p);
        p = p + 2;
        uint16_t length = Get_val16(p);
        p = p + 2;
        dbg_printf("Option field Type: %u, length %u\n", type, length);

        switch (type) {
            // general sampling
            case NF9_SAMPLING_INTERVAL:  // #34
                samplerOption->interval.length = length;
                samplerOption->interval.offset = offset;
                SetFlag(optionTemplate->flags, STDSAMPLING34);
                dbg_printf(" Sampling option found\n");
                break;
            case NF9_SAMPLING_ALGORITHM:  // #35
                samplerOption->mode.length = length;
                samplerOption->mode.offset = offset;
                SetFlag(optionTemplate->flags, STDSAMPLING35);
                dbg_printf(" Sampling option found\n");
                break;

            // individual samplers
            case NF9_FLOW_SAMPLER_ID:  // #48 depricated - fall through
            case NF_SELECTOR_ID:       // #302
                samplerOption->id.length = length;
                samplerOption->id.offset = offset;
                SetFlag(optionTemplate->flags, SAMPLER302);
                dbg_printf(" Sampling option found\n");
                break;
            case FLOW_SAMPLER_MODE:      // #49 depricated - fall through
            case NF_SELECTOR_ALGORITHM:  // #304
                samplerOption->mode.length = length;
                samplerOption->mode.offset = offset;
                SetFlag(optionTemplate->flags, SAMPLER304);
                dbg_printf(" Sampling option found\n");
                break;
            case NF9_FLOW_SAMPLER_RANDOM_INTERVAL:  // #50 depricated - fall through
            case NF_SAMPLING_INTERVAL:              // #305
                samplerOption->interval.length = length;
                samplerOption->interval.offset = offset;
                SetFlag(optionTemplate->flags, SAMPLER305);
                dbg_printf(" Sampling option found\n");
                break;

            // nbar application information
            case NBAR_APPLICATION_DESC:
                nbarOption->desc.length = length;
                nbarOption->desc.offset = offset;
                SetFlag(optionTemplate->flags, NBAROPTIONS);
                dbg_printf(" Nbar option found\n");
                break;
            case NBAR_APPLICATION_ID:
                nbarOption->id.length = length;
                nbarOption->id.offset = offset;
                SetFlag(optionTemplate->flags, NBAROPTIONS);
                dbg_printf(" Nbar option found\n");
                break;
            case NBAR_APPLICATION_NAME:
                nbarOption->name.length = length;
                nbarOption->name.offset = offset;
                SetFlag(optionTemplate->flags, NBAROPTIONS);
                dbg_printf(" Nbar option found\n");
                break;
            default:
                dbg_printf(" Skip this type: %u, length %u\n", type, length);
        }
        offset += length;
    }

    dbg_printf("\n");

    if (optionTemplate->flags) {
        // if it exitsts - remove old template on exporter with same ID
        templateList_t *template = newTemplate(exporter, tableID);
        if (!template) {
            LogError("Process_v9: abort template add: %s line %d", __FILE__, __LINE__);
            return;
        }
        template->data = optionTemplate;

        if ((optionTemplate->flags & SAMPLERMASK) == SAMPLERFLAGS) {
            dbg_printf("[%u] Sampler information found\n", exporter->info.id);
            SetFlag(template->type, SAMPLER_TEMPLATE);
        } else if ((optionTemplate->flags & STDMASK) == STDFLAGS) {
            dbg_printf("[%u] Std sampling information found\n", exporter->info.id);
            SetFlag(template->type, SAMPLER_TEMPLATE);
        } else {
            dbg_printf("[%u] No Sampling information found\n", exporter->info.id);
        }

        if (TestFlag(optionTemplate->flags, NBAROPTIONS)) {
            dbg_printf("[%u] found nbar options\n", exporter->info.id);
            dbg_printf("[%u] id   length: %u\n", exporter->info.id, optionTemplate->nbarOption.id.length);
            dbg_printf("[%u] name length: %u\n", exporter->info.id, optionTemplate->nbarOption.name.length);
            dbg_printf("[%u] desc length: %u\n", exporter->info.id, optionTemplate->nbarOption.desc.length);
            optionTemplate->nbarOption.scopeSize = scopeSize;
            SetFlag(template->type, NBAR_TEMPLATE);
        } else {
            dbg_printf("[%u] No nbar information found\n", exporter->info.id);
        }

    } else {
        free(optionTemplate);
        dbg_printf("[%u] Skip option template\n", exporter->info.id);
    }

    processed_records++;

}  // End of Process_v9_option_templates

static void InsertSampler(FlowSource_t *fs, exporterDomain_t *exporter, int32_t id, uint16_t mode, uint32_t interval) {
    sampler_t *sampler;

    dbg_printf("[%u] Insert Sampler: Exporter is 0x%llu\n", exporter->info.id, (long long unsigned)exporter);
    if (!exporter->sampler) {
        // no samplers so far
        sampler = (sampler_t *)malloc(sizeof(sampler_t));
        if (!sampler) {
            LogError("Process_v9: Panic! malloc(): %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return;
        }

        sampler->info.header.type = SamplerInfoRecordType;
        sampler->info.header.size = sizeof(sampler_info_record_t);
        sampler->info.exporter_sysid = exporter->info.sysid;
        sampler->info.id = id;
        sampler->info.mode = mode;
        sampler->info.interval = interval;
        sampler->next = NULL;
        exporter->sampler = sampler;

        AppendToBuffer(fs->nffile, &(sampler->info.header), sampler->info.header.size);
        LogInfo("Add new sampler: ID: %i, mode: %u, interval: %u\n", id, mode, interval);
        dbg_printf("Add new sampler: ID: %i, mode: %u, interval: %u\n", id, mode, interval);

    } else {
        sampler = exporter->sampler;
        while (sampler) {
            // test for update of existing sampler
            if (sampler->info.id == id) {
                // found same sampler id - update record
                dbg_printf("Update existing sampler id: %i, mode: %u, interval: %u\n", id, mode, interval);

                // we update only on changes
                if (mode != sampler->info.mode || interval != sampler->info.interval) {
                    AppendToBuffer(fs->nffile, &(sampler->info.header), sampler->info.header.size);
                    sampler->info.mode = mode;
                    sampler->info.interval = interval;
                    LogInfo("Update existing sampler id: %i, mode: %u, interval: %u\n", id, mode, interval);
                } else {
                    dbg_printf("Sampler unchanged!\n");
                }

                break;
            }

            // test for end of chain
            if (sampler->next == NULL) {
                // end of sampler chain - insert new sampler
                sampler->next = (sampler_t *)malloc(sizeof(sampler_t));
                if (!sampler->next) {
                    LogError("Process_v9: Panic! malloc(): %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                    return;
                }
                sampler = sampler->next;

                sampler->info.header.type = SamplerInfoRecordType;
                sampler->info.header.size = sizeof(sampler_info_record_t);
                sampler->info.exporter_sysid = exporter->info.sysid;
                sampler->info.id = id;
                sampler->info.mode = mode;
                sampler->info.interval = interval;
                sampler->next = NULL;

                AppendToBuffer(fs->nffile, &(sampler->info.header), sampler->info.header.size);
                LogInfo("Append new sampler: ID: %u, mode: %u, interval: %u\n", id, mode, interval);
                dbg_printf("Append new sampler: ID: %u, mode: %u, interval: %u\n", id, mode, interval);
                break;
            }

            // advance
            sampler = sampler->next;
        }
    }

}  // End of InsertSampler

static inline void Process_v9_data(exporterDomain_t *exporter, void *data_flowset, FlowSource_t *fs, dataTemplate_t *template) {
    uint64_t sampling_rate;
    int32_t size_left;
    uint8_t *inBuff;

    size_left = GET_FLOWSET_LENGTH(data_flowset) - 4;  // -4 for data flowset header -> id and length

    // map input buffer as a byte array
    inBuff = (uint8_t *)(data_flowset + 4);  // skip flowset header

    sequencer_t *sequencer = &(template->sequencer);

    dbg_printf("[%u] Process data flowset size: %u\n", exporter->info.id, size_left);

    sampling_rate = 1;

    // reserve space in output stream for EXipReceivedVx
    uint32_t receivedSize = 0;
    if (fs->sa_family == PF_INET6)
        receivedSize = EXipReceivedV6Size;
    else
        receivedSize = EXipReceivedV4Size;

    while (size_left > 0) {
        void *outBuff;

        if (size_left < 4) {  // rounding pads
            size_left = 0;
            continue;
        }

        // check for enough space in output buffer
        uint32_t outRecordSize = CalcOutRecordSize(sequencer, inBuff, size_left);
        int buffAvail = CheckBufferSpace(fs->nffile, sizeof(recordHeaderV3_t) + outRecordSize + receivedSize);
        if (buffAvail == 0) {
            // this should really never occur, because the buffer gets flushed ealier
            LogError("Process_v9: output buffer size error. Skip ipfix record processing");
            dbg_printf("Process_v9: output buffer size error. Skip ipfix record processing");
            return;
        }

    REDO:
        // map file record to output buffer
        outBuff = fs->nffile->buff_ptr;

        dbg_printf("[%u] Process data record: %u addr: %llu, size_left: %u buff_avail: %u\n", exporter->info.id, processed_records,
                   (long long unsigned)((ptrdiff_t)inBuff - (ptrdiff_t)data_flowset), size_left, buffAvail);

        // process record
        AddV3Header(outBuff, recordHeaderV3);

        // header data
        recordHeaderV3->engineType = (exporter->info.id >> 8) & 0xFF;
        recordHeaderV3->engineID = exporter->info.id & 0xFF;
        recordHeaderV3->nfversion = 9;
        recordHeaderV3->exporterID = exporter->info.sysid;

        uint64_t stack[STACK_MAX];
        memset((void *)stack, 0, sizeof(stack));
        // copy record data
        int ret = SequencerRun(sequencer, inBuff, size_left, outBuff, buffAvail, stack);
        switch (ret) {
            case SEQ_OK:
                break;
            case SEQ_ERROR:
                LogError("Process v9: Sequencer run error. Skip record processing");
                return;
                break;
            case SEQ_MEM_ERR:
                if (buffAvail == WRITE_BUFFSIZE) {
                    LogError("Process v9: Sequencer run error. buffer size too small");
                    return;
                }

                // request new and empty buffer
                LogInfo("Process v9: Sequencer run - resize output buffer");
                buffAvail = CheckBufferSpace(fs->nffile, buffAvail + 1);
                if (buffAvail == 0) {
                    // this should really never occur, because the buffer gets flushed ealier
                    LogError("Process_v9: output buffer size error. Skip ipfix record processing");
                    dbg_printf("Process_v9: output buffer size error. Skip ipfix record processing");
                    return;
                }
                goto REDO;
                break;
        }

        dbg_printf(
            "New record added with %u elements and size: %u, sequencer inLength: %lu, outLength: "
            "%lu\n",
            recordHeaderV3->numElements, recordHeaderV3->size, sequencer->inLength, sequencer->outLength);

        // add router IP
        if (fs->sa_family == PF_INET6) {
            PushExtension(recordHeaderV3, EXipReceivedV6, ipReceivedV6);
            ipReceivedV6->ip[0] = fs->ip.V6[0];
            ipReceivedV6->ip[1] = fs->ip.V6[1];
            dbg_printf("Add IPv6 route IP extension\n");
        } else {
            PushExtension(recordHeaderV3, EXipReceivedV4, ipReceivedV4);
            ipReceivedV4->ip = fs->ip.V4;
            dbg_printf("Add IPv4 route IP extension\n");
        }

        dbg_printf("Record: %u elements, size: %u\n", recordHeaderV3->numElements, recordHeaderV3->size);

        outBuff += recordHeaderV3->size;
        inBuff += sequencer->inLength;
        size_left -= sequencer->inLength;

        processed_records++;

        if (stack[STACK_ENGINE_TYPE]) recordHeaderV3->engineType = stack[STACK_ENGINE_TYPE];
        if (stack[STACK_ENGINE_ID]) recordHeaderV3->engineID = stack[STACK_ENGINE_ID];

        // handle sampling
        if (overwrite_sampling > 0) {
            // force overwrite sampling
            sampling_rate = overwrite_sampling;
            dbg_printf("[%u] Hard overwrite sampling rate: %llu\n", exporter->info.id, (long long unsigned)sampling_rate);
        } else {
            // check sampler ID
            sampler_t *sampler = exporter->sampler;
            if (stack[STACK_SAMPLER]) {
                uint32_t sampler_id = stack[STACK_SAMPLER];
                dbg_printf("[%u] Sampling ID %u exported\n", exporter->info.id, sampler_id);
                // individual sampler ID
                while (sampler && sampler->info.id != sampler_id) sampler = sampler->next;

                if (sampler) {
                    sampling_rate = sampler->info.interval;
                    dbg_printf("Found sampler ID %u - sampling rate: %llu\n", sampler_id, (long long unsigned)sampling_rate);
                } else {
                    sampling_rate = default_sampling;
                    dbg_printf("No sampler ID %u found\n", sampler_id);
                }

            } else if (exporter->sampler) {
                // check for generic sampler ID -1
                while (sampler && sampler->info.id != -1) sampler = sampler->next;

                if (sampler) {
                    // found
                    sampling_rate = sampler->info.interval;
                    dbg_printf("[%u] Std sampling available for this flow source: Rate: %llu\n", exporter->info.id,
                               (long long unsigned)sampling_rate);
                } else {
                    sampling_rate = default_sampling;
                    dbg_printf("[%u] No Sampling record found\n", exporter->info.id);
                }
            } else {
                dbg_printf("[%u] No Sampling record found\n", exporter->info.id);
            }
        }
        if (sampling_rate != 1) SetFlag(recordHeaderV3->flags, V3_FLAG_SAMPLED);

        // add time received
        EXgenericFlow_t *genericFlow = sequencer->offsetCache[EXgenericFlowID];
        if (genericFlow) {
            genericFlow->msecReceived = ((uint64_t)fs->received.tv_sec * 1000LL) + (uint64_t)((uint64_t)fs->received.tv_usec / 1000LL);

            // update first_seen, last_seen
            // tags #152, #153 are expected otherwise
            // process tags #21, #22
            if (stack[STACK_LAST21] != 0) {
                uint64_t First = stack[STACK_FIRST22];
                uint64_t Last = stack[STACK_LAST21];

                if (First > Last) /* First in msec, in case of msec overflow, between start and end */
                    genericFlow->msecFirst = exporter->boot_time - 0x100000000LL + First;
                else
                    genericFlow->msecFirst = First + exporter->boot_time;

                // end time in msecs
                genericFlow->msecLast = (uint64_t)Last + exporter->boot_time;
            }

            if (genericFlow->msecFirst < fs->msecFirst) fs->msecFirst = genericFlow->msecFirst;
            if (genericFlow->msecLast > fs->msecLast) fs->msecLast = genericFlow->msecLast;
            dbg_printf("msecFrist: %llu\n", (long long unsigned)genericFlow->msecFirst);
            dbg_printf("msecLast : %llu\n", (long long unsigned)genericFlow->msecLast);

            if (sampling_rate > 1) {
                genericFlow->inPackets *= (uint64_t)sampling_rate;
                genericFlow->inBytes *= (uint64_t)sampling_rate;
                SetFlag(recordHeaderV3->flags, V3_FLAG_SAMPLED);
            }

            switch (genericFlow->proto) {
                case IPPROTO_ICMPV6:
                case IPPROTO_ICMP:
                    fs->nffile->stat_record->numflows_icmp++;
                    fs->nffile->stat_record->numpackets_icmp += genericFlow->inPackets;
                    fs->nffile->stat_record->numbytes_icmp += genericFlow->inBytes;
                    // fix odd CISCO behaviour for ICMP port/type in src port
                    if (genericFlow->srcPort != 0) {
                        uint8_t *s1 = (uint8_t *)&(genericFlow->srcPort);
                        uint8_t *s2 = (uint8_t *)&(genericFlow->dstPort);
                        s2[0] = s1[1];
                        s2[1] = s1[0];
                    }
                    // srcPort is always 0
                    genericFlow->srcPort = 0;
                    if (stack[STACK_ICMP] != 0) {
                        // icmp type/code element #32
                        genericFlow->dstPort = stack[STACK_ICMP];
                    } else if (stack[STACK_ICMP_TYPE] || stack[STACK_ICMP_CODE]) {
                        // icmp type and code elements #176 #177 #178 #179
                        genericFlow->dstPort = 256 * stack[STACK_ICMP_TYPE] + stack[STACK_ICMP_CODE];
                    } else {
                        genericFlow->dstPort = 0;
                    }
                    break;
                case IPPROTO_TCP:
                    fs->nffile->stat_record->numflows_tcp++;
                    fs->nffile->stat_record->numpackets_tcp += genericFlow->inPackets;
                    fs->nffile->stat_record->numbytes_tcp += genericFlow->inBytes;
                    break;
                case IPPROTO_UDP:
                    fs->nffile->stat_record->numflows_udp++;
                    fs->nffile->stat_record->numpackets_udp += genericFlow->inPackets;
                    fs->nffile->stat_record->numbytes_udp += genericFlow->inBytes;
                    break;
                default:
                    fs->nffile->stat_record->numflows_other++;
                    fs->nffile->stat_record->numpackets_other += genericFlow->inPackets;
                    fs->nffile->stat_record->numbytes_other += genericFlow->inBytes;
            }

            exporter->flows++;
            fs->nffile->stat_record->numflows++;
            fs->nffile->stat_record->numpackets += genericFlow->inPackets;
            fs->nffile->stat_record->numbytes += genericFlow->inBytes;

            uint32_t exporterIdent = MetricExpporterID(recordHeaderV3);
            UpdateMetric(fs->nffile->ident, exporterIdent, genericFlow);
        }

        EXcntFlow_t *cntFlow = sequencer->offsetCache[EXcntFlowID];
        if (cntFlow) {
            if (cntFlow->flows == 0) cntFlow->flows++;
            fs->nffile->stat_record->numpackets += cntFlow->outPackets;
            fs->nffile->stat_record->numbytes += cntFlow->outBytes;
        }

        // handle event time for NSEL/ASA and NAT
        EXnselCommon_t *nselCommon = sequencer->offsetCache[EXnselCommonID];
        if (nselCommon) {
            nselCommon->msecEvent = stack[STACK_MSEC];
        }
        EXnelCommon_t *nelCommon = sequencer->offsetCache[EXnelCommonID];
        if (nelCommon) {
            nelCommon->msecEvent = stack[STACK_MSEC];
        }

        // nprobe latency
        EXlatency_t *latency = sequencer->offsetCache[EXlatencyID];
        if (latency) {
            latency->usecClientNwDelay += 1000000LL * stack[STACK_CLIENT_USEC];
            latency->usecServerNwDelay += 1000000LL * stack[STACK_SERVER_USEC];
            latency->usecApplLatency += 1000000LL * stack[STACK_APPL_USEC];
        }

        if (printRecord) {
            flow_record_short(stdout, recordHeaderV3);
        }

        fs->nffile->block_header->size += recordHeaderV3->size;
        fs->nffile->block_header->NumRecords++;
        fs->nffile->buff_ptr = outBuff;

        // buffer size sanity check
        if (fs->nffile->block_header->size > WRITE_BUFFSIZE) {
            // should never happen
            LogError("### Software error ###: %s line %d", __FILE__, __LINE__);
            LogError("Process v9: Output buffer overflow! Flush buffer and skip records.");
            LogError("Buffer size: %u > %u", fs->nffile->block_header->size, WRITE_BUFFSIZE);

            // reset buffer
            fs->nffile->block_header->size = 0;
            fs->nffile->block_header->NumRecords = 0;
            fs->nffile->buff_ptr = (void *)((pointer_addr_t)fs->nffile->block_header + sizeof(dataBlock_t));
            return;
        }
    }

}  // End of Process_v9_data

static inline void Process_v9_sampler_option_data(exporterDomain_t *exporter, FlowSource_t *fs, templateList_t *template, void *data_flowset) {
    uint32_t size_left = GET_FLOWSET_LENGTH(data_flowset) - 4;  // -4 for data flowset header -> id and length
    dbg_printf("[%u] Process sampler option data flowset size: %u\n", exporter->info.id, size_left);

    // map input buffer as a byte array
    uint8_t *in = (uint8_t *)(data_flowset + 4);  // skip flowset header

    optionTemplate_t *optionTemplate = (optionTemplate_t *)template->data;
    struct samplerOption_s *samplerOption = &(optionTemplate->samplerOption);

    if ((optionTemplate->flags & SAMPLERMASK) != 0) {
        int32_t id;
        uint16_t mode;
        uint32_t interval;

        if (CHECK_OPTION_DATA(size_left, samplerOption->id) && CHECK_OPTION_DATA(size_left, samplerOption->mode) &&
            CHECK_OPTION_DATA(size_left, samplerOption->interval)) {
            id = Get_val(in, samplerOption->id.offset, samplerOption->id.length);
            mode = Get_val(in, samplerOption->mode.offset, samplerOption->mode.length);
            interval = Get_val(in, samplerOption->interval.offset, samplerOption->interval.length);
        } else {
            LogError("Process_ipfix_option: %s line %d: Not enough data for option data", __FILE__, __LINE__);
            return;
        }

        dbg_printf("Extracted Sampler data:\n");
        dbg_printf("Sampler ID      : %u\n", id);
        dbg_printf("Sampler mode    : %u\n", mode);
        dbg_printf("Sampler interval: %u\n", interval);

        InsertSampler(fs, exporter, id, mode, interval);
    }

    if ((optionTemplate->flags & STDMASK) != 0) {
        int32_t id;
        uint16_t mode;
        uint32_t interval;

        id = -1;
        if (CHECK_OPTION_DATA(size_left, samplerOption->mode) && CHECK_OPTION_DATA(size_left, samplerOption->interval)) {
            mode = Get_val(in, samplerOption->mode.offset, samplerOption->mode.length);
            interval = Get_val(in, samplerOption->interval.offset, samplerOption->interval.length);
        } else {
            LogError("Process_ipfix_option: %s line %d: Not enough data for option data", __FILE__, __LINE__);
            return;
        }

        InsertSampler(fs, exporter, id, mode, interval);

        dbg_printf("Extracted Std Sampler data:\n");
        dbg_printf("Sampler ID       : %i\n", id);
        dbg_printf("Sampler algorithm: %u\n", mode);
        dbg_printf("Sampler interval : %u\n", interval);

        dbg_printf("Set std sampler: algorithm: %u, interval: %u\n", mode, interval);
    }
    processed_records++;

}  // End of Process_v9_sampler_option_data

static void Process_v9_nbar_option_data(exporterDomain_t *exporter, FlowSource_t *fs, templateList_t *template, void *data_flowset) {
    uint32_t size_left = GET_FLOWSET_LENGTH(data_flowset) - 4;  // -4 for data flowset header -> id and length
    dbg_printf("[%u] Process nbar option data flowset size: %u\n", exporter->info.id, size_left);

    optionTemplate_t *optionTemplate = (optionTemplate_t *)template->data;
    struct nbarOptionList_s *nbarOption = &(optionTemplate->nbarOption);

    // map input buffer as a byte array
    uint8_t *inBuff = (uint8_t *)(data_flowset + 4);  // skip flowset header
    // data size
    size_t nbar_data_size = nbarOption->id.length + nbarOption->name.length + nbarOption->desc.length;
    // size of record
    size_t nbar_option_size = nbarOption->scopeSize + nbar_data_size;
    // number of records in data
    int numRecords = size_left / nbar_option_size;
    dbg_printf("[%u] nbar option data - records: %u, size: %zu\n", exporter->info.id, numRecords, nbar_option_size);

    if (numRecords == 0 || nbar_option_size == 0 || nbar_option_size > size_left) {
        LogError("Process_nbar_option: nbar option size error: option size: %u, size left: %u", nbar_option_size, size_left);
        return;
    }

    size_t nbar_total_size = numRecords * (sizeof(nbarRecordHeader_t) + sizeof(NbarAppInfo_t) + nbar_data_size);
    size_t align = nbar_total_size & 0x3;
    if (align) {
        nbar_total_size += 4 - align;
    }

    // output buffer size check for all expected records
    if (!CheckBufferSpace(fs->nffile, nbar_total_size)) {
        // fishy! - should never happen. maybe disk full?
        LogError("Process_nbar_option: output buffer size error. Abort nbar record processing");
        return;
    }

    void *outBuff = fs->nffile->buff_ptr;

    int cnt = 0;
    while (size_left >= nbar_option_size) {
        // push nbar header
        AddNbarHeader(outBuff, nbarHeader);

        // push nbar app info record
        PushNbarVarLengthExtension(nbarHeader, NbarAppInfo, nbar_record, sizeof(NbarAppInfo_t) + nbar_data_size);

        nbar_record->app_id_length = nbarOption->id.length;
        nbar_record->app_name_length = nbarOption->name.length;
        nbar_record->app_desc_length = nbarOption->desc.length;
        uint8_t *p = nbar_record->data;
        int err = 0;

        // copy data
        //  id octet array
        memcpy(p, inBuff + nbarOption->id.offset, nbarOption->id.length);
        p += nbarOption->id.length;

        // name string
        memcpy(p, inBuff + nbarOption->name.offset, nbarOption->name.length);
        uint32_t state = UTF8_ACCEPT;
        if (validate_utf8(&state, (char *)p, nbarOption->name.length) == UTF8_REJECT) {
            LogError("Process_nbar_option: validate_utf8() %s line %d: %s", __FILE__, __LINE__, "invalid utf8 nbar name");
            err = 1;
        }
        p[nbarOption->name.length - 1] = '\0';
        p += nbarOption->name.length;

        // description string
        memcpy(p, inBuff + nbarOption->desc.offset, nbarOption->desc.length);
        state = UTF8_ACCEPT;
        if (validate_utf8(&state, (char *)p, nbarOption->name.length) == UTF8_REJECT) {
            LogError("Process_nbar_option: validate_utf8() %s line %d: %s", __FILE__, __LINE__, "invalid utf8 nbar description");
            err = 1;
        }
        p[nbarOption->desc.length - 1] = '\0';

        cnt++;
#ifdef DEVEL
        if (err == 0) {
            printf("nbar record: %d: \n", cnt);
            // PrintNbarRecord(nbarHeader);
        } else {
            printf("Invalid nbar information - skip record\n");
        }
#endif

        // in case of an err we do no store this record
        if (err == 0) {
            outBuff += nbarHeader->size;
            fs->nffile->block_header->NumRecords++;
        }
        inBuff += nbar_option_size;
        size_left -= nbar_option_size;
    }

    // update file record size ( -> output buffer size )
    fs->nffile->block_header->size += (void *)outBuff - fs->nffile->buff_ptr;
    fs->nffile->buff_ptr = (void *)outBuff;

    if (size_left > 7) {
        LogInfo("Proces nbar data record - %u extra bytes", size_left);
    }
    processed_records++;

}  // End of Process_v9_nbar_option_data

void Process_v9(void *in_buff, ssize_t in_buff_cnt, FlowSource_t *fs) {
    exporterDomain_t *exporter;
    void *flowset_header;
    v9Header_t *v9_header;
    int64_t distance;
    uint32_t flowset_length, exporter_id;
    ssize_t size_left;

#ifdef DEVEL
    static int pkg_num = 1;
    dbg_printf("\nProcess_v9: Next packet: %i\n", pkg_num++);
#endif

    size_left = in_buff_cnt;
    if (size_left < V9_HEADER_LENGTH) {
        LogError("Process_v9: Too little data for v9 packet: '%lli'", (long long)size_left);
        return;
    }

    // map v9 data structure to input buffer
    v9_header = (v9Header_t *)in_buff;
    exporter_id = ntohl(v9_header->source_id);

    exporter = getExporter(fs, exporter_id);
    if (!exporter) {
        LogError("Process_v9: Exporter NULL: Abort v9 record processing");
        return;
    }
    exporter->packets++;

    /* calculate boot time in msec */
    v9_header->SysUptime = ntohl(v9_header->SysUptime);
    v9_header->unix_secs = ntohl(v9_header->unix_secs);
    exporter->boot_time = (uint64_t)1000 * (uint64_t)(v9_header->unix_secs) - (uint64_t)v9_header->SysUptime;

    flowset_header = (void *)v9_header + V9_HEADER_LENGTH;
    size_left -= V9_HEADER_LENGTH;

#ifdef DEVEL
    uint32_t expected_records = ntohs(v9_header->count);
    printf("[%u] records: %u, buffer: %li \n", exporter_id, expected_records, size_left);
    printf("SourceID: %u, Sysuptime: %u.%u\n", v9_header->source_id, v9_header->SysUptime, v9_header->unix_secs);
#endif

    // sequence check
    if (exporter->first) {
        exporter->last_sequence = ntohl(v9_header->sequence);
        exporter->sequence = exporter->last_sequence;
        exporter->first = 0;
    } else {
        exporter->last_sequence = exporter->sequence;
        exporter->sequence = ntohl(v9_header->sequence);
        distance = exporter->sequence - exporter->last_sequence;
        // handle overflow
        if (distance < 0) {
            distance = 0xffffffff + distance + 1;
        }
        if (distance != 1) {
            exporter->sequence_failure++;
            fs->nffile->stat_record->sequence_failure++;
            dbg_printf("[%u] Sequence error: last seq: %lli, seq %lli dist %lli\n", exporter->info.id, (long long)exporter->last_sequence,
                       (long long)exporter->sequence, (long long)distance);
        }
    }
    dbg_printf("Sequence: %llu\n", exporter->sequence);

    processed_records = 0;

    // iterate over all flowsets in export packet, while there are bytes left
    flowset_length = 0;
    while (size_left) {
        uint16_t flowset_id;
        if (size_left < 4) {
            return;
        }

        flowset_header = flowset_header + flowset_length;
        flowset_id = GET_FLOWSET_ID(flowset_header);
        flowset_length = GET_FLOWSET_LENGTH(flowset_header);

        dbg_printf("[%u] Next flowset id: %u, length: %u, buffersize: %zu\n", exporter->info.id, flowset_id, flowset_length, size_left);

        if (flowset_length == 0) {
            /* 	this should never happen, as 4 is an empty flowset
                    and smaller is an illegal flowset anyway ...
                    if it happends, we can't determine the next flowset, so skip the entire export
               packet
             */
            LogError("Process_v9: flowset zero length error.");
            dbg_printf("Process_v9: flowset zero length error.\n");
            return;
        }

        // possible padding
        if (flowset_length <= 4) {
            return;
        }

        if (flowset_length > size_left) {
            LogError("Process_v9: flowset length error. Expected bytes: %u > buffersize: %lli", flowset_length, (long long)size_left);
            return;
        }

        switch (flowset_id) {
            case NF9_TEMPLATE_FLOWSET_ID:
                exporter->TemplateRecords++;
                Process_v9_templates(exporter, flowset_header, fs);
                break;
            case NF9_OPTIONS_FLOWSET_ID: {
                exporter->TemplateRecords++;
                dbg_printf("Process option template flowset, length: %u\n", flowset_length);
                Process_v9_option_templates(exporter, flowset_header, fs);
            } break;
            default: {
                if (flowset_id < NF9_MIN_RECORD_FLOWSET_ID) {
                    dbg_printf("Invalid flowset id: %u\n", flowset_id);
                    LogError("Process_v9: Invalid flowset id: %u", flowset_id);
                } else {
                    dbg_printf("[%u] ID %u Data flowset\n", exporter->info.id, flowset_id);
                    templateList_t *template = getTemplate(exporter, flowset_id);
                    if (template) {
                        if (TestFlag(template->type, DATA_TEMPLATE)) {
                            Process_v9_data(exporter, flowset_header, fs, (dataTemplate_t *)template->data);
                            exporter->DataRecords++;
                        } else {
                            ProcessOptionFlowset(exporter, fs, template, flowset_header);
                        }
                    }
                }
            }
        }

        // next flowset
        size_left -= flowset_length;

    }  // End of while

    return;

} /* End of Process_v9 */

/*
 * functions for sending netflow v9 records
 */

int Init_v9_output(send_peer_t *peer) {
    int i;

    for (i = 0; v9TranslationMap[i].name != NULL; i++) {
    }
    LogInfo("Init v9 out: Max number of v9 tags: %u\n", i);
    numV9Elements = i;

    sender_data = calloc(1, sizeof(sender_data_t));
    if (!sender_data) {
        LogError("calloc() %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }
    sender_data->header.v9_header = (v9Header_t *)peer->send_buffer;
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

int Close_v9_output(send_peer_t *peer) {
    if ((sender_data->header.record_count + sender_data->header.template_count) > 0) {
        dbg_printf("Close v9 output\n");
        peer->flush = 1;
        sender_data->header.sequence++;
        sender_data->header.v9_header->sequence = htonl(sender_data->header.sequence);
        sender_data->header.v9_header->count = htons(sender_data->header.record_count + sender_data->header.template_count);
        CloseDataFlowset(peer);
        dbg_printf("Prepare buffer: sequence: %u, records: %u, templates: %u\n", sender_data->header.sequence, sender_data->header.record_count,
                   sender_data->header.template_count);
        sender_data->header.record_count = 0;
        sender_data->header.template_count = 0;
        return 1;
    }

    return 0;

}  // End of Close_v9_output

static outTemplate_t *GetOutputTemplate(master_record_t *master_record) {
    outTemplate_t **t;
    template_flowset_t *flowset;
    uint32_t template_id, count, record_length;

    template_id = 0;

    t = &outTemplates;
    // search for the template, which corresponds to our flags and extension map
    while (*t) {
        if ((*t)->size == master_record->size && (*t)->numExtensions == master_record->numElements) {
            if (memcmp((void *)(*t)->exElementList, (void *)master_record->exElementList, 2 * master_record->numElements) == 0)
                dbg_printf("Found existing output template id: %u\n", (*t)->template_id);
            return *t;
        }
        template_id = (*t)->template_id;
        t = &((*t)->next);
    }

    dbg_printf("No output template found. Create new template\n");
    // nothing found, otherwise we would not get here
    *t = (outTemplate_t *)calloc(1, sizeof(outTemplate_t));
    if (!(*t)) {
        LogError("malloc() %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        exit(255);
    }
    (*t)->next = NULL;

    (*t)->size = master_record->size;
    (*t)->numExtensions = master_record->numElements;
    memcpy((*t)->exElementList, (void *)master_record->exElementList, 2 * master_record->numElements);

    if (template_id == 0)
        (*t)->template_id = NF9_MIN_RECORD_FLOWSET_ID;
    else
        (*t)->template_id = template_id + 1;

    (*t)->time_sent = 0;
    (*t)->record_count = 0;
    // add flowset array - includes one potential padding
    (*t)->template_flowset = calloc(1, sizeof(template_flowset_t) + ((numV9Elements * 4)));

    count = 0;
    record_length = 0;
    flowset = (*t)->template_flowset;

    flowset->field[count].type = htons(NF9_ENGINE_TYPE);
    flowset->field[count].length = htons(1);
    count++;
    flowset->field[count].type = htons(NF9_ENGINE_ID);
    flowset->field[count].length = htons(1);
    count++;
    record_length += 2;

    dbg_printf("Generate template for %u extensions\n", master_record->numElements);
    // iterate over all extensions
    uint16_t srcMaskType = 0;
    uint16_t dstMaskType = 0;
    for (int i = 0; i < master_record->numElements; i++) {
        if (count >= numV9Elements) {
            LogError("Panic! %s line %d: %s", __FILE__, __LINE__, "Numer of elements too big");
            exit(255);
        }
        dbg_printf("extension %i: %u\n", i, master_record->exElementList[i]);
        switch (master_record->exElementList[i]) {
            case EXgenericFlowID:
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
                record_length += 42;
                break;
            case EXipv4FlowID:
                flowset->field[count].type = htons(NF9_IPV4_SRC_ADDR);
                flowset->field[count].length = htons(4);
                count++;
                flowset->field[count].type = htons(NF9_IPV4_DST_ADDR);
                flowset->field[count].length = htons(4);
                count++;
                record_length += 8;
                srcMaskType = NF9_SRC_MASK;
                dstMaskType = NF9_DST_MASK;
                break;
            case EXipv6FlowID:
                flowset->field[count].type = htons(NF9_IPV6_SRC_ADDR);
                flowset->field[count].length = htons(16);
                count++;
                flowset->field[count].type = htons(NF9_IPV6_DST_ADDR);
                flowset->field[count].length = htons(16);
                count++;
                record_length += 32;
                srcMaskType = NF9_IPV6_SRC_MASK;
                dstMaskType = NF9_IPV6_DST_MASK;
                break;
            case EXflowMiscID:
                flowset->field[count].type = htons(NF9_INPUT_SNMP);
                flowset->field[count].length = htons(4);
                count++;
                flowset->field[count].type = htons(NF9_OUTPUT_SNMP);
                flowset->field[count].length = htons(4);
                count++;
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
                record_length += 12;
                break;
            case EXcntFlowID:
                flowset->field[count].type = htons(NF9_FLOWS_AGGR);
                flowset->field[count].length = htons(8);
                count++;
                flowset->field[count].type = htons(NF9_OUT_PKTS);
                flowset->field[count].length = htons(8);
                count++;
                flowset->field[count].type = htons(NF9_OUT_BYTES);
                flowset->field[count].length = htons(8);
                count++;
                record_length += 24;
                break;
            case EXvLanID:
                flowset->field[count].type = htons(NF9_SRC_VLAN);
                flowset->field[count].length = htons(2);
                count++;
                flowset->field[count].type = htons(NF9_DST_VLAN);
                flowset->field[count].length = htons(2);
                count++;
                record_length += 4;
                break;
            case EXasRoutingID:
                flowset->field[count].type = htons(NF9_SRC_AS);
                flowset->field[count].length = htons(4);
                count++;
                flowset->field[count].type = htons(NF9_DST_AS);
                flowset->field[count].length = htons(4);
                count++;
                record_length += 8;
                break;
            case EXbgpNextHopV4ID:
                flowset->field[count].type = htons(NF9_BGP_V4_NEXT_HOP);
                flowset->field[count].length = htons(4);
                count++;
                record_length += 4;
                break;
            case EXbgpNextHopV6ID:
                flowset->field[count].type = htons(NF9_BPG_V6_NEXT_HOP);
                flowset->field[count].length = htons(16);
                count++;
                record_length += 16;
                break;
            case EXipNextHopV4ID:
                flowset->field[count].type = htons(NF9_V4_NEXT_HOP);
                flowset->field[count].length = htons(4);
                count++;
                record_length += 4;
                break;
            case EXipNextHopV6ID:
                flowset->field[count].type = htons(NF9_V6_NEXT_HOP);
                flowset->field[count].length = htons(16);
                count++;
                record_length += 16;
                break;
            case EXmplsLabelID:
                flowset->field[count].type = htons(NF9_MPLS_LABEL_1);
                flowset->field[count].length = htons(3);
                count++;
                flowset->field[count].type = htons(NF9_MPLS_LABEL_2);
                flowset->field[count].length = htons(3);
                count++;
                flowset->field[count].type = htons(NF9_MPLS_LABEL_3);
                flowset->field[count].length = htons(3);
                count++;
                flowset->field[count].type = htons(NF9_MPLS_LABEL_4);
                flowset->field[count].length = htons(3);
                count++;
                flowset->field[count].type = htons(NF9_MPLS_LABEL_5);
                flowset->field[count].length = htons(3);
                count++;
                flowset->field[count].type = htons(NF9_MPLS_LABEL_6);
                flowset->field[count].length = htons(3);
                count++;
                flowset->field[count].type = htons(NF9_MPLS_LABEL_7);
                flowset->field[count].length = htons(3);
                count++;
                flowset->field[count].type = htons(NF9_MPLS_LABEL_8);
                flowset->field[count].length = htons(3);
                count++;
                flowset->field[count].type = htons(NF9_MPLS_LABEL_9);
                flowset->field[count].length = htons(3);
                count++;
                flowset->field[count].type = htons(NF9_MPLS_LABEL_10);
                flowset->field[count].length = htons(3);
                count++;
                record_length += 30;
                break;
            case EXmacAddrID:
                flowset->field[count].type = htons(NF9_IN_SRC_MAC);
                flowset->field[count].length = htons(6);
                count++;
                flowset->field[count].type = htons(NF9_OUT_DST_MAC);
                flowset->field[count].length = htons(6);
                count++;
                flowset->field[count].type = htons(NF9_IN_DST_MAC);
                flowset->field[count].length = htons(6);
                count++;
                flowset->field[count].type = htons(NF9_OUT_SRC_MAC);
                flowset->field[count].length = htons(6);
                count++;
                record_length += 24;
                break;
            case EXasAdjacentID:
                flowset->field[count].type = htons(NF_F_BGP_ADJ_NEXT_AS);
                flowset->field[count].length = htons(4);
                count++;
                flowset->field[count].type = htons(NF_F_BGP_ADJ_PREV_AS);
                flowset->field[count].length = htons(4);
                count++;
                record_length += 8;
                break;
        }
    }

    // one potential padding field
    flowset->field[count].type = 0;
    flowset->field[count].length = 0;

    (*t)->template_flowset->flowset_id = htons(NF9_TEMPLATE_FLOWSET_ID);
    (*t)->flowset_length = 4 * (2 + count);  // + 2 for the header

    // add proper padding for 32bit boundary
    if (((*t)->flowset_length & 0x3) != 0) (*t)->flowset_length += (4 - ((*t)->flowset_length & 0x3));
    (*t)->template_flowset->length = htons((*t)->flowset_length);

    (*t)->record_length = record_length;

    dbg_printf("Created new template with id: %u, count: %u, record length: %u\n", (*t)->template_id, count, record_length);
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

static void Append_Record(send_peer_t *peer, master_record_t *master_record) {
    uint8_t *p = (uint8_t *)peer->buff_ptr;
    *p++ = master_record->engine_type;
    *p++ = master_record->engine_id;
    peer->buff_ptr = (void *)p;

    for (int i = 0; i < master_record->numElements; i++) {
        switch (master_record->exElementList[i]) {
            case EXgenericFlowID:
                Put_val64(htonll(master_record->msecFirst), peer->buff_ptr);
                peer->buff_ptr += 8;
                Put_val64(htonll(master_record->msecLast), peer->buff_ptr);
                peer->buff_ptr += 8;
                Put_val64(htonll(master_record->inPackets), peer->buff_ptr);
                peer->buff_ptr += 8;
                Put_val64(htonll(master_record->inBytes), peer->buff_ptr);
                peer->buff_ptr += 8;
                Put_val16(htons(master_record->srcPort), peer->buff_ptr);
                peer->buff_ptr += 2;
                if (master_record->proto == IPPROTO_ICMP || master_record->proto == IPPROTO_ICMPV6) {
                    Put_val16(0, peer->buff_ptr);
                    peer->buff_ptr += 2;
                    Put_val16(htons(master_record->dstPort), peer->buff_ptr);
                    peer->buff_ptr += 2;
                } else {
                    Put_val16(htons(master_record->dstPort), peer->buff_ptr);
                    peer->buff_ptr += 2;
                    Put_val16(0, peer->buff_ptr);
                    peer->buff_ptr += 2;
                }
                Put_val8(master_record->proto, peer->buff_ptr);
                peer->buff_ptr += 1;
                Put_val8(master_record->tcp_flags, peer->buff_ptr);
                peer->buff_ptr += 1;
                Put_val8(master_record->fwd_status, peer->buff_ptr);
                peer->buff_ptr += 1;
                Put_val8(master_record->tos, peer->buff_ptr);
                peer->buff_ptr += 1;
                break;
            case EXipv4FlowID:
                Put_val32(htonl(master_record->V4.srcaddr), peer->buff_ptr);
                peer->buff_ptr += 4;
                Put_val32(htonl(master_record->V4.dstaddr), peer->buff_ptr);
                peer->buff_ptr += 4;
                break;
            case EXipv6FlowID:
                Put_val64(htonll(master_record->V6.srcaddr[0]), peer->buff_ptr);
                peer->buff_ptr += 8;
                Put_val64(htonll(master_record->V6.srcaddr[1]), peer->buff_ptr);
                peer->buff_ptr += 8;
                Put_val64(htonll(master_record->V6.dstaddr[0]), peer->buff_ptr);
                peer->buff_ptr += 8;
                Put_val64(htonll(master_record->V6.dstaddr[1]), peer->buff_ptr);
                peer->buff_ptr += 8;
                break;
            case EXflowMiscID:
                Put_val32(htonl(master_record->input), peer->buff_ptr);
                peer->buff_ptr += 4;
                Put_val32(htonl(master_record->output), peer->buff_ptr);
                peer->buff_ptr += 4;
                Put_val8(master_record->src_mask, peer->buff_ptr);
                peer->buff_ptr += 1;
                Put_val8(master_record->dst_mask, peer->buff_ptr);
                peer->buff_ptr += 1;
                Put_val8(master_record->dir, peer->buff_ptr);
                peer->buff_ptr += 1;
                Put_val8(master_record->dst_tos, peer->buff_ptr);
                peer->buff_ptr += 1;
                break;
            case EXcntFlowID:
                Put_val64(htonll(master_record->aggr_flows), peer->buff_ptr);
                peer->buff_ptr += 8;
                Put_val64(htonll(master_record->out_pkts), peer->buff_ptr);
                peer->buff_ptr += 8;
                Put_val64(htonll(master_record->out_bytes), peer->buff_ptr);
                peer->buff_ptr += 8;
                break;
            case EXvLanID:
                Put_val16(htons(master_record->src_vlan), peer->buff_ptr);
                peer->buff_ptr += 2;
                Put_val16(htons(master_record->dst_vlan), peer->buff_ptr);
                peer->buff_ptr += 2;
                break;
            case EXasRoutingID:
                Put_val32(htonl(master_record->srcas), peer->buff_ptr);
                peer->buff_ptr += 4;
                Put_val32(htonl(master_record->dstas), peer->buff_ptr);
                peer->buff_ptr += 4;
                break;
            case EXbgpNextHopV4ID:
                Put_val32(htonl(master_record->bgp_nexthop.V4), peer->buff_ptr);
                peer->buff_ptr += 4;
                break;
            case EXbgpNextHopV6ID:
                Put_val64(htonll(master_record->bgp_nexthop.V6[0]), peer->buff_ptr);
                peer->buff_ptr += 8;
                Put_val64(htonll(master_record->bgp_nexthop.V6[1]), peer->buff_ptr);
                peer->buff_ptr += 8;
                break;
            case EXipNextHopV4ID:
                Put_val32(htonl(master_record->ip_nexthop.V4), peer->buff_ptr);
                peer->buff_ptr += 4;
                break;
            case EXipNextHopV6ID:
                Put_val64(htonll(master_record->ip_nexthop.V6[0]), peer->buff_ptr);
                peer->buff_ptr += 8;
                Put_val64(htonll(master_record->ip_nexthop.V6[1]), peer->buff_ptr);
                peer->buff_ptr += 8;
                break;
            case EXmplsLabelID:
                for (int i = 0; i < 10; i++) {
                    uint32_t val32 = htonl(master_record->mpls_label[i]);
                    Put_val24(val32, peer->buff_ptr);
                    peer->buff_ptr += 3;
                }
                break;
            case EXmacAddrID: {
                uint64_t val64 = htonll(master_record->in_src_mac);
                Put_val48(val64, peer->buff_ptr);
                peer->buff_ptr += 6;

                val64 = htonll(master_record->out_dst_mac);
                Put_val48(val64, peer->buff_ptr);
                peer->buff_ptr += 6;

                val64 = htonll(master_record->in_dst_mac);
                Put_val48(val64, peer->buff_ptr);
                peer->buff_ptr += 6;

                val64 = htonll(master_record->out_src_mac);
                Put_val48(val64, peer->buff_ptr);
                peer->buff_ptr += 6;
            } break;
            case EXasAdjacentID:
                Put_val32(htonl(master_record->bgpNextAdjacentAS), peer->buff_ptr);
                peer->buff_ptr += 4;
                Put_val32(htonl(master_record->bgpPrevAdjacentAS), peer->buff_ptr);
                peer->buff_ptr += 4;
                break;
        }
    }

    sender_data->header.record_count++;

}  // End of Append_Record

static int Add_template_flowset(outTemplate_t *outTemplate, send_peer_t *peer) {
    dbg_printf("Add template %u, bytes: %u\n", outTemplate->template_id, outTemplate->flowset_length);
    memcpy(peer->buff_ptr, (void *)outTemplate->template_flowset, outTemplate->flowset_length);
    peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + outTemplate->flowset_length);

    sender_data->header.template_count++;

    return 1;
}  // End of Add_template_flowset

static void CloseDataFlowset(send_peer_t *peer) {
    if (sender_data->data_flowset) {
        uint32_t length = (void *)peer->buff_ptr - (void *)sender_data->data_flowset;
        uint32_t align = length & 0x3;
        if (align != 0) {
            length += (4 - align);
            // fill padding with 0
            for (int i = 0; i < align; i++) {
                *((char *)peer->buff_ptr) = '\0';
                peer->buff_ptr++;
            }
        }
        sender_data->data_flowset->length = htons(length);
        sender_data->data_flowset = NULL;
        sender_data->data_flowset_id = 0;
        dbg_printf("Close flowset: Length: %u, align: %u\n", length, align);
    }
}  // End of CloseDataFlowset

static int CheckSendBufferSpace(size_t size, send_peer_t *peer) {
    dbg_printf("CheckSendBufferSpace for %lu bytes: ", size);
    if ((peer->buff_ptr + size) > peer->endp) {
        // request buffer flush
        dbg_printf("failed. Flush first.\n");
        peer->flush = 1;
        sender_data->header.sequence++;
        sender_data->header.v9_header->sequence = htonl(sender_data->header.sequence);
        sender_data->header.v9_header->count = htons(sender_data->header.record_count + sender_data->header.template_count);
        CloseDataFlowset(peer);
        dbg_printf("Prepare buffer: sequence: %u, records: %u, templates: %u\n", sender_data->header.sequence, sender_data->header.record_count,
                   sender_data->header.template_count);
        sender_data->header.record_count = 0;
        sender_data->header.template_count = 0;
        return 0;
    }
    dbg_printf("ok.\n");

    return 1;

}  // End of CheckBufferSpace

int Add_v9_output_record(master_record_t *master_record, send_peer_t *peer) {
    time_t now = time(NULL);

    dbg_printf("\nNext packet\n");
    if (master_record->numElements == 0) {
        dbg_printf("Skip record with 0 extensions\n\n");
        return 0;
    }

    if (!sender_data->header.v9_header->unix_secs) {  // first time a record is added
        dbg_printf("First time setup\n");
        // boot time is set one day back - assuming that the start time of every flow does not start
        // ealier
        uint64_t boot_time = master_record->msecFirst - 86400LL * 1000LL;
        uint32_t unix_secs = boot_time / 1000LL;
        sender_data->header.v9_header->unix_secs = htonl(unix_secs);
    }

    // check, if Buffer was flushed
    if (peer->buff_ptr == peer->send_buffer) {
        peer->buff_ptr = (void *)((void *)sender_data->header.v9_header + sizeof(v9Header_t));
    }

    outTemplate_t *template = GetOutputTemplate(master_record);
    if ((sender_data->data_flowset_id != template->template_id) || template->needs_refresh) {
        // Different flowset ID - End data flowset and open new data flowset
        CloseDataFlowset(peer);

        if (!CheckSendBufferSpace(template->record_length + sizeof(data_flowset_t) + template->flowset_length, peer)) {
            // request buffer flush first
            dbg_printf("Flush Buffer #1\n");
            return 1;
        }

        // add first time this template
        Add_template_flowset(template, peer);
        template->time_sent = now;

        // Add data flowset
        dbg_printf("Add new data flowset\n");
        sender_data->data_flowset = peer->buff_ptr;
        sender_data->data_flowset->flowset_id = template->template_flowset->template_id;
        sender_data->data_flowset_id = template->template_id;
        peer->buff_ptr = (void *)sender_data->data_flowset->data;
    }

    // same data flowset ID - add Record
    if (!CheckSendBufferSpace(template->record_length, peer)) {
        // request buffer flush first
        dbg_printf("Flush Buffer #2\n");
        return 1;
    }

    dbg_printf("Add record %u, bytes: %u\n", template->template_id, template->record_length);
    Append_Record(peer, master_record);

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
