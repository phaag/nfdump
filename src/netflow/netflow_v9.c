/*
 *  Copyright (c) 2009-2025, Peter Haag
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

#include "netflow_v9.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "bookkeeper.h"
#include "collector.h"
#include "config.h"
#include "exporter.h"
#include "fnf.h"
#include "metric.h"
#include "nbar.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfnet.h"
#include "nfxV3.h"
#include "output_short.h"
#include "record_callback.h"
#include "util.h"

// Get_valxx, a  macros
#include "inline.c"

// define stack slots
enum {
    STACK_NONE = 0,
    STACK_ICMP,
    STACK_ICMP_TYPE,
    STACK_ICMP_CODE,
    STACK_MSECFIRST,
    STACK_MSECLAST,
    STACK_SAMPLER,
    STACK_SECFIRST,
    STACK_SECLAST,
    STACK_MSEC,
    STACK_SYSUPTIME,
    STACK_CLIENT_USEC,
    STACK_SERVER_USEC,
    STACK_APPL_USEC,
    STACK_ENGINE_TYPE,
    STACK_ENGINE_ID,
    STACK_MAX
};

static int ExtensionsEnabled[MAXEXTENSIONS];

static const struct v9TranslationMap_s {
    uint16_t id;  // v9 element id
#define Stack_ONLY 0
    uint16_t outputLength;  // output length in extension ID
    uint16_t copyMode;      // number or byte copy
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
    {NF9_V4_NEXT_HOP, SIZENextHopV4IP, NumberCopy, EXipNextHopV4ID, OFFNextHopV4IP, STACK_NONE, "IPv4 next hop"},
    {NF9_SRC_AS, SIZEsrcAS, NumberCopy, EXasRoutingID, OFFsrcAS, STACK_NONE, "src AS"},
    {NF9_DST_AS, SIZEdstAS, NumberCopy, EXasRoutingID, OFFdstAS, STACK_NONE, "dst AS"},
    {NF9_BGP_V4_NEXT_HOP, SIZEbgp4NextIP, NumberCopy, EXbgpNextHopV4ID, OFFbgp4NextIP, STACK_NONE, "IPv4 bgp next hop"},
    {NF9_LAST_SWITCHED, Stack_ONLY, NumberCopy, EXgenericFlowID, OFFmsecLast, STACK_MSECLAST, "msec last SysupTime"},
    {NF9_FIRST_SWITCHED, Stack_ONLY, NumberCopy, EXgenericFlowID, OFFmsecFirst, STACK_MSECFIRST, "msec first SysupTime"},
    {NF_F_flowStartSeconds, Stack_ONLY, NumberCopy, EXnull, 0, STACK_SECFIRST, "sec first seen"},
    {NF_F_flowEndSeconds, Stack_ONLY, NumberCopy, EXnull, 0, STACK_SECLAST, "sec last seen"},
    {NF9_OUT_BYTES, SIZEoutBytes, NumberCopy, EXcntFlowID, OFFoutBytes, STACK_NONE, "output bytes delta counter"},
    {NF9_OUT_PKTS, SIZEoutPackets, NumberCopy, EXcntFlowID, OFFoutPackets, STACK_NONE, "output packet delta counter"},
    {NF9_IPV6_SRC_ADDR, SIZEsrc6Addr, NumberCopy, EXipv6FlowID, OFFsrc6Addr, STACK_NONE, "IPv6 src addr"},
    {NF9_IPV6_DST_ADDR, SIZEdst6Addr, NumberCopy, EXipv6FlowID, OFFdst6Addr, STACK_NONE, "IPv6 dst addr"},
    {NF9_IPV6_SRC_MASK, SIZEsrcMask, NumberCopy, EXflowMiscID, OFFsrcMask, STACK_NONE, "src mask bits"},
    {NF9_IPV6_DST_MASK, SIZEdstMask, NumberCopy, EXflowMiscID, OFFdstMask, STACK_NONE, "dst mask bits"},
    {NF9_ICMP, Stack_ONLY, NumberCopy, EXgenericFlowID, OFFdstPort, STACK_ICMP, "icmp type/code"},
    {NF9_MIN_TTL, SIZEminTTL, NumberCopy, EXipInfoID, OFFminTTL, STACK_NONE, "flow min TTL"},
    {NF9_MAX_TTL, SIZEmaxTTL, NumberCopy, EXipInfoID, OFFmaxTTL, STACK_NONE, "flow max TTL"},
    {NF9_DST_TOS, SIZEdstTos, NumberCopy, EXflowMiscID, OFFdstTos, STACK_NONE, "post IP class of Service"},
    {NF9_MIN_TTL, SIZEminTTL, NumberCopy, EXipInfoID, OFFminTTL, STACK_NONE, "flow min TTL"},
    {NF9_MAX_TTL, SIZEmaxTTL, NumberCopy, EXipInfoID, OFFmaxTTL, STACK_NONE, "flow max TTL"},
    {NF_F_flowEndReason, SIZEflowEndReason, NumberCopy, EXflowMiscID, OFFflowEndReason, STACK_NONE, "Flow end reason"},
    {NF_F_ipTTL, SIZEminTTL, NumberCopy, EXipInfoID, OFFminTTL, STACK_NONE, "flow min TTL"},
    {NF_F_fragmentFlags, SIZEfragmentFlags, NumberCopy, EXipInfoID, OFFfragmentFlags, STACK_NONE, "IP fragment flags"},
    {NF9_IN_SRC_MAC, SIZEinSrcMac, NumberCopy, EXmacAddrID, OFFinSrcMac, STACK_NONE, "in src MAC addr"},
    {NF9_OUT_DST_MAC, SIZEoutDstMac, NumberCopy, EXmacAddrID, OFFoutDstMac, STACK_NONE, "out dst MAC addr"},
    {NF9_SRC_VLAN, SIZEvlanID, NumberCopy, EXvLanID, OFFvlanID, STACK_NONE, "src VLAN ID"},
    {NF9_DST_VLAN, SIZEvlanID, NumberCopy, EXvLanID, OFFvlanID, STACK_NONE, "dst VLAN ID"},
    {NF_F_dot1qVlanId, SIZEvlanID, NumberCopy, EXlayer2ID, OFFvlanID, STACK_NONE, "dot1q VLAN ID"},
    {NF_F_postDot1qVlanId, SIZEvlanID, NumberCopy, EXlayer2ID, OFFvlanID, STACK_NONE, "dot1q post VLAN ID"},
    {NF_F_dot1qCustomerVlanId, SIZEcustomerVlanId, NumberCopy, EXlayer2ID, OFFcustomerVlanId, STACK_NONE, "dot1q customer VLAN ID"},
    {NF_F_postDot1qCustomerVlanId, SIZEpostCustomerVlanId, NumberCopy, EXlayer2ID, OFFpostCustomerVlanId, STACK_NONE, "dot1q post customer VLAN ID"},
    {NF_F_ingressPhysicalInterface, SIZEphysIngress, NumberCopy, EXlayer2ID, OFFphysIngress, STACK_NONE, "ingress physical interface ID"},
    {NF_F_egressPhysicalInterface, SIZEphysEgress, NumberCopy, EXlayer2ID, OFFphysEgress, STACK_NONE, "egress physical interface ID"},
    {NF_9_IP_PROTOCOL_VERSION, SIZEipVersion, NumberCopy, EXlayer2ID, OFFipVersion, STACK_NONE, "ip version"},
    {NF9_DIRECTION, SIZEdir, NumberCopy, EXflowMiscID, OFFdir, STACK_NONE, "flow direction"},
    {NF9_V6_NEXT_HOP, SIZENextHopV6IP, NumberCopy, EXipNextHopV6ID, OFFNextHopV6IP, STACK_NONE, "IPv6 next hop IP"},
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
    {SystemInitTimeMiliseconds, Stack_ONLY, NumberCopy, EXnull, 0, STACK_SYSUPTIME, "SysupTime msec"},
    {NF9_ENGINE_TYPE, Stack_ONLY, NumberCopy, EXnull, 0, STACK_ENGINE_TYPE, "engine type"},
    {NF9_ENGINE_ID, Stack_ONLY, NumberCopy, EXnull, 0, STACK_ENGINE_ID, "engine ID"},
    {LOCAL_IPv4Received, SIZEReceived4IP, NumberCopy, EXipReceivedV4ID, OFFReceived4IP, STACK_NONE, "IPv4 exporter"},
    {LOCAL_IPv6Received, SIZEReceived6IP, NumberCopy, EXipReceivedV6ID, OFFReceived6IP, STACK_NONE, "IPv6 exporter"},
    {LOCAL_msecTimeReceived, SIZEmsecReceived, NumberCopy, EXgenericFlowID, OFFmsecReceived, STACK_NONE, "msec time received"},
    {NF9_ETHERTYPE, SIZEetherType, NumberCopy, EXlayer2ID, OFFetherType, STACK_NONE, "ethertype"},

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
    {NF_F_XLATE_SRC_ADDR_IPV4, SIZExlateSrc4Addr, NumberCopy, EXnatXlateIPv4ID, OFFxlateSrc4Addr, STACK_NONE, "xlate src addr"},
    {NF_F_XLATE_SRC_ADDR_84, SIZExlateSrc4Addr, NumberCopy, EXnatXlateIPv4ID, OFFxlateSrc4Addr, STACK_NONE, "xlate src addr"},
    {NF_F_XLATE_DST_ADDR_IPV4, SIZExlateDst4Addr, NumberCopy, EXnatXlateIPv4ID, OFFxlateDst4Addr, STACK_NONE, "xlate dst addr"},
    {NF_F_XLATE_DST_ADDR_84, SIZExlateDst4Addr, NumberCopy, EXnatXlateIPv4ID, OFFxlateDst4Addr, STACK_NONE, "xlate dst addr"},
    {NF_F_XLATE_SRC_ADDR_IPV6, SIZExlateSrc6Addr, NumberCopy, EXnatXlateIPv6ID, OFFxlateSrc6Addr, STACK_NONE, "xlate src addr"},
    {NF_F_XLATE_DST_ADDR_IPV6, SIZExlateDst6Addr, NumberCopy, EXnatXlateIPv6ID, OFFxlateDst6Addr, STACK_NONE, "xlate dst addr"},
    {NF_F_XLATE_SRC_PORT, SIZExlateSrcPort, NumberCopy, EXnatXlatePortID, OFFxlateSrcPort, STACK_NONE, "xlate src port"},
    {NF_F_XLATE_DST_PORT, SIZExlateDstPort, NumberCopy, EXnatXlatePortID, OFFxlateDstPort, STACK_NONE, "xlate dst port"},
    {NF_F_XLATE_SRC_PORT_84, SIZExlateSrcPort, NumberCopy, EXnatXlatePortID, OFFxlateSrcPort, STACK_NONE, "xlate src port"},
    {NF_F_XLATE_DST_PORT_84, SIZExlateDstPort, NumberCopy, EXnatXlatePortID, OFFxlateDstPort, STACK_NONE, "xlate dst port"},
    {NF_F_INGRESS_ACL_ID, SIZEingressAcl, NumberCopy, EXnselAclID, OFFingressAcl, STACK_NONE, "ingress ACL ID"},
    {NF_F_EGRESS_ACL_ID, SIZEegressAcl, NumberCopy, EXnselAclID, OFFegressAcl, STACK_NONE, "egress ACL ID"},
    {NF_F_USERNAME, SIZEusername, NumberCopy, EXnselUserID, OFFusername, STACK_NONE, "AAA username"},
    {NF_N_INGRESS_VRFID, SIZEingressVrf, NumberCopy, EXvrfID, OFFingressVrf, STACK_NONE, "ingress VRF ID"},
    {NF_N_EGRESS_VRFID, SIZEegressVrf, NumberCopy, EXvrfID, OFFegressVrf, STACK_NONE, "egress VRF ID"},

    // NEL
    {NF_N_NAT_EVENT, SIZEnatEvent, NumberCopy, EXnatCommonID, OFFnatEvent, STACK_NONE, "NAT event"},
    {NF_N_NATPOOL_ID, SIZEnatPoolID, NumberCopy, EXnatCommonID, OFFnatPoolID, STACK_NONE, "nat pool ID"},
    {NF_F_XLATE_PORT_BLOCK_START, SIZEnelblockStart, NumberCopy, EXnatPortBlockID, OFFnelblockStart, STACK_NONE, "NAT block start"},
    {NF_F_XLATE_PORT_BLOCK_END, SIZEnelblockEnd, NumberCopy, EXnatPortBlockID, OFFnelblockEnd, STACK_NONE, "NAT block end"},
    {NF_F_XLATE_PORT_BLOCK_STEP, SIZEnelblockStep, NumberCopy, EXnatPortBlockID, OFFnelblockStep, STACK_NONE, "NAT block step"},
    {NF_F_XLATE_PORT_BLOCK_SIZE, SIZEnelblockSize, NumberCopy, EXnatPortBlockID, OFFnelblockSize, STACK_NONE, "NAT block size"},

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
    {NF9_FLOW_SAMPLER_ID, SIZEsampID, NumberCopy, EXsamplerInfoID, OFFsampID, STACK_SAMPLER, "sampler ID"},
    {SELECTOR_ID, SIZEsampID, NumberCopy, EXsamplerInfoID, OFFsampID, STACK_SAMPLER, "sampler ID"},

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

// module limited globals
static uint32_t processed_records;
static int printRecord;
static int32_t defaultSampling;

/* local function prototypes */
static void InsertSampler(FlowSource_t *fs, exporter_entry_t *exporter_entry, sampler_record_t *sampler_record);

static inline void Process_v9_templates(exporter_entry_t *exporter_entry, void *template_flowset, FlowSource_t *fs);

static inline void Process_v9_option_templates(exporter_entry_t *exporter_entry, void *option_template_flowset, FlowSource_t *fs);

static inline void Process_v9_data(exporter_entry_t *exporter_entry, void *data_flowset, FlowSource_t *fs, dataTemplate_t *template);

static void Process_v9_sampler_option_data(exporter_entry_t *exporter_entry, FlowSource_t *fs, templateList_t *template, void *data_flowset);

static void Process_v9_nbar_option_data(exporter_entry_t *exporter_entry, FlowSource_t *fs, templateList_t *template, void *data_flowset);

static void Process_v9_ifvrf_option_data(exporter_entry_t *exporter_entry, FlowSource_t *fs, int type, templateList_t *template, void *data_flowset);

static void Process_v9_SysUpTime_option_data(exporter_entry_t *exporter_entry, templateList_t *template, void *data_flowset);

static inline exporter_entry_t *getExporter(FlowSource_t *fs, uint32_t exporter_id);

/* functions */

#include "nffile_inline.c"

int Init_v9(int verbose, int32_t sampling, char *extensionList) {
    printRecord = verbose > 2;

    defaultSampling = sampling;

    if (extensionList) {
        // Disable all extensions
        for (int i = 0; i < MAXEXTENSIONS; i++) {
            ExtensionsEnabled[i] = 0;
        }

        // get enabled extensions from string
        int extID = ScanExtension(extensionList);
        while (extID > 0) {
            dbg_printf("Enable extension %d\n", extID);
            ExtensionsEnabled[extID] = 1;
            extID = ScanExtension(NULL);
        }

        if (extID == -1) {
            LogError("Failed to scan extension list.");
            return 0;
        }

        // make sure extension 1 is enabled
        ExtensionsEnabled[1] = 1;

    } else {
        // Enable all extensions
        dbg_printf("Enable all extensions\n");
        for (int i = 0; i < MAXEXTENSIONS; i++) {
            ExtensionsEnabled[i] = 1;
        }
    }

    int tagsEnabled = 0;
    for (int i = 0; v9TranslationMap[i].name != NULL; i++) {
        int extID = v9TranslationMap[i].extensionID;
        if (ExtensionsEnabled[extID]) tagsEnabled++;
    }

    if (sampling < 0) {
        LogInfo("Init v9: Max number of v9 tags enabled: %u, overwrite sampling: %d", tagsEnabled, -defaultSampling);
    } else {
        LogInfo("Init v9: Max number of v9 tags enabled: %u, default sampling: %d", tagsEnabled, defaultSampling);
    }

    return 1;

}  // End of Init_v9

static int LookupElement(uint16_t type, uint32_t EnterpriseNumber) {
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
        if (v9TranslationMap[i].id == type) {
            int extID = v9TranslationMap[i].extensionID;
            if (ExtensionsEnabled[extID]) {
                return i;
            } else {
                dbg_printf("Extension %d not enabled\n", extID);
                return -1;
            }
        }

        i++;
    }

    return -1;

}  // End of LookupElement

static inline exporter_entry_t *getExporter(FlowSource_t *fs, uint32_t exporter_id) {
    const exporter_key_t key = {.version = VERSION_NETFLOW_V9, .id = exporter_id, .ip = fs->ipAddr};

    // fast cache
    if (fs->last_exp && EXPORTER_KEY_EQUAL(fs->last_key, key)) {
        return fs->last_exp;
    }

    exporter_table_t *tab = &fs->exporters;
    // Check load factor in case we need a new slot
    if ((tab->count * 4) >= (tab->capacity * 3)) {
        // expand exporter index
        expand_exporter_table(tab);
        tab = &fs->exporters;
    }

    // not identical of last exporter
    uint32_t hash = EXPORTERHASH(key);
    uint32_t mask = tab->capacity - 1;
    uint32_t i = hash & mask;

    for (;;) {
        exporter_entry_t *e = &tab->entries[i];
        // key does not exists - create new exporter
        if (!e->in_use) {
            // create new exporter
            e->key = key;
            e->packets = 0;
            e->flows = 0;
            e->sequence_failure = 0;
            e->sequence = UINT32_MAX;
            e->in_use = 1;
            tab->count++;

            e->info = (exporter_info_record_t){.header = (record_header_t){.type = ExporterInfoRecordType, .size = sizeof(exporter_info_record_t)},
                                               .version = key.version,
                                               .id = key.id,
                                               .fill = 0,
                                               .sysid = 0};
            memcpy(e->info.ip, fs->ipAddr.bytes, 16);

            e->version.v9 = (exporter_v9_t){0};
            FlushInfoExporter(fs, &e->info);

            if (defaultSampling < 0) {
                // map hard overwrite sampling into a static sampler
                sampler_record_t sampler_record;
                sampler_record.id = SAMPLER_OVERWRITE;
                sampler_record.packetInterval = 1;
                sampler_record.algorithm = 0;
                sampler_record.spaceInterval = (-defaultSampling) - 1;
                InsertSampler(fs, e, &sampler_record);
                dbg_printf("Add static sampler for overwrite sampling: %d\n", -defaultSampling);
            } else if (defaultSampling > 1) {
                // map default sampling > 1 into a static sampler
                sampler_record_t sampler_record;
                sampler_record.id = SAMPLER_DEFAULT;
                sampler_record.packetInterval = 1;
                sampler_record.algorithm = 0;
                sampler_record.spaceInterval = defaultSampling - 1;
                InsertSampler(fs, e, &sampler_record);
                dbg_printf("Add static sampler for default sampling: %u\n", defaultSampling);
            }

            char ipstr[INET6_ADDRSTRLEN];
            LogInfo("Process_v9: New v9 exporter: SysID: %u, Domain: %u, IP: %s", e->info.sysid, exporter_id, ip128_2_str(&fs->ipAddr, ipstr));

            fs->last_key = key;
            fs->last_exp = e;
            return e;
        }
        if (EXPORTER_KEY_EQUAL(e->key, key)) {
            fs->last_key = key;
            fs->last_exp = e;
            return e;
        }

        dbg_assert(tab->count < tab->capacity);
        // next slot
        i = (i + 1) & mask;
    }

    // unreached
    return NULL;

}  // End of getExporter

static void InsertSampler(FlowSource_t *fs, exporter_entry_t *exporter_entry, sampler_record_t *sampler_record) {
    sampler_t *sampler;

    dbg_printf("[%u] Insert Sampler: Exporter is 0x%p\n", exporter_entry->info.id, (void *)exporter_entry);

    if (!exporter_entry->sampler) {
        // no samplers so far
        sampler = (sampler_t *)malloc(sizeof(sampler_t));
        if (!sampler) {
            LogError("Process_v9: Panic! malloc(): %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return;
        }

        sampler->record = *sampler_record;
        sampler->record.type = SamplerRecordType;
        sampler->record.size = sizeof(sampler_record_t);
        sampler->record.exporter_sysid = exporter_entry->info.sysid;
        sampler->next = NULL;
        exporter_entry->sampler = sampler;

        fs->dataBlock = AppendToBuffer(fs->nffile, fs->dataBlock, &(sampler->record), sampler->record.size);
        LogInfo("Add new sampler id: %lli, algorithm: %u, packet interval: %u, packet space: %u", sampler_record->id, sampler_record->algorithm,
                sampler_record->packetInterval, sampler_record->spaceInterval);

    } else {
        sampler = exporter_entry->sampler;
        while (sampler) {
            // test for update of existing sampler
            if (sampler->record.id == sampler_record->id) {
                // found same sampler id - update record if changed
                if (sampler_record->algorithm != sampler->record.algorithm || sampler_record->packetInterval != sampler->record.packetInterval ||
                    sampler_record->spaceInterval != sampler->record.spaceInterval) {
                    sampler->record.algorithm = sampler_record->algorithm;
                    sampler->record.packetInterval = sampler_record->packetInterval;
                    sampler->record.spaceInterval = sampler_record->spaceInterval;
                    fs->dataBlock = AppendToBuffer(fs->nffile, fs->dataBlock, &(sampler->record), sampler->record.size);
                    LogInfo("Update existing sampler id: %lli, algorithm: %u, packet interval: %u, packet space: %u", sampler_record->id,
                            sampler_record->algorithm, sampler_record->packetInterval, sampler_record->spaceInterval);
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
                sampler->record = *sampler_record;
                sampler->record.type = SamplerRecordType;
                sampler->record.size = sizeof(sampler_record_t);
                sampler->record.exporter_sysid = exporter_entry->info.sysid;
                sampler->next = NULL;

                fs->dataBlock = AppendToBuffer(fs->nffile, fs->dataBlock, &(sampler->record), sampler->record.size);
                LogInfo("Append new sampler id: %lli, algorithm: %u, packet interval: %u, packet space: %u", sampler_record->id,
                        sampler_record->algorithm, sampler_record->packetInterval, sampler_record->spaceInterval);
                break;
            }

            // advance
            sampler = sampler->next;
        }
    }

}  // End of InsertSampler

static templateList_t *getTemplate(exporter_entry_t *exporter_entry, uint16_t id) {
    exporter_v9_t *exporter_v9 = &exporter_entry->version.v9;

#ifdef DEVEL
    {
        if (exporter_v9->currentTemplate) {
            printf("Get template - current template: %u\n", exporter_v9->currentTemplate->id);
        }
        printf("Get template - available templates for exporter: %u\n", exporter_entry->info.id);
        templateList_t *template = exporter_v9->template;
        while (template) {
            printf(" ID: %u, type:, %u\n", template->id, template->type);
            template = template->next;
        }
    }
#endif

    if (exporter_v9->currentTemplate && (exporter_v9->currentTemplate->id == id)) return exporter_v9->currentTemplate;

    templateList_t *template = exporter_v9->template;
    while (template) {
        if (template->id == id) {
            exporter_v9->currentTemplate = template;
            dbg_printf("[%u] Get template - found %u\n", exporter_entry->info.id, id);
            return template;
        }
        template = template->next;
    }

    dbg_printf("[%u] Get template %u: not found\n", exporter_entry->info.id, id);
    exporter_v9->currentTemplate = NULL;

    return NULL;

}  // End of getTemplate

static templateList_t *newTemplate(exporter_entry_t *exporter_entry, uint16_t id) {
    templateList_t *template = (templateList_t *)calloc(1, sizeof(templateList_t));
    if (!template) {
        LogError("Process_v9: Panic! calloc() %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    // init the new template
    exporter_v9_t *exporter_v9 = &exporter_entry->version.v9;
    template->next = exporter_v9->template;
    template->updated = time(NULL);
    template->id = id;
    template->data = NULL;

    exporter_v9->template = template;
    dbg_printf("[%u] Add new template ID %u\n", exporter_entry->info.id, id);

    return template;

}  // End of newTemplate

static void removeTemplate(exporter_entry_t *exporter_entry, uint16_t id) {
    exporter_v9_t *exporter_v9 = &exporter_entry->version.v9;

    templateList_t *parent = NULL;
    templateList_t *template = exporter_v9->template;
    while (template && (template->id != id)) {
        parent = template;
        template = template->next;
    }

    if (template == NULL) {
        dbg_printf("[%u] Remove template id: %i - template not found\n", exporter_entry->info.id, id);
        return;
    } else {
        dbg_printf("[%u] Remove template ID: %u\n", exporter_entry->info.id, id);
    }

    // clear table cache, if this is the table to delete
    if (exporter_v9->currentTemplate == template) exporter_v9->currentTemplate = NULL;

    if (parent) {
        // remove template from list
        parent->next = template->next;
    } else {
        // last template removed
        exporter_v9->template = template->next;
    }

    if (TestFlag(template->type, DATA_TEMPLATE)) {
        dataTemplate_t *dataTemplate = (dataTemplate_t *)template->data;
        ClearSequencer(&(dataTemplate->sequencer));
        if (dataTemplate->extensionList) free(dataTemplate->extensionList);
    }
    free(template->data);
    free(template);

}  // End of removeTemplate

static inline void Process_v9_templates(exporter_entry_t *exporter_entry, void *DataPtr, FlowSource_t *fs) {
    uint32_t size_left = GET_FLOWSET_LENGTH(DataPtr);
    size_left -= 4;                // -4 for flowset header -> id and length
    void *template = DataPtr + 4;  // the template description begins at offset 4

    // process all templates in flowset, as long as any bytes are left
    uint32_t size_required = 0;
    while (size_left) {
        template = template + size_required;

        if (size_left < 4) {
            LogError("Process_v9: [%u] buffer size error: flowset length error in %s:%u", exporter_entry->info.id, __FILE__, __LINE__);
            return;
        }

        uint16_t id = GET_TEMPLATE_ID(template);
        uint16_t count = GET_TEMPLATE_COUNT(template);
        size_required = 4 + 4 * count;  // id + count = 4 bytes, and 2 x 2 bytes for each entry

        dbg_printf("\n[%u] Template ID: %u, field count: %u\n", exporter_entry->info.id, id, count);
        dbg_printf("template size: %u buffersize: %u\n", size_required, size_left);

        if (size_left < size_required) {
            LogError("Process_v9: [%u] buffer size error: expected %u available %u", exporter_entry->info.id, size_required, size_left);
            return;
        }

        sequence_t *sequenceTable = (sequence_t *)malloc((count + 4) * sizeof(sequence_t));  // + 2 for IP and time received
        if (!sequenceTable) {
            LogError("Process_v9: malloc(): %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return;
        }
        uint32_t numSequences = 0;

        void *p = template + 4;  // type/length pairs start at template offset 4
        int commonFound = 0;
        for (int i = 0; i < count; i++) {
            uint16_t Type, Length;
            uint32_t EnterpriseNumber = 0;

            Type = Get_val16(p);
            p = p + 2;
            Length = Get_val16(p);
            p = p + 2;

            int index = LookupElement(Type, EnterpriseNumber);
            if (index < 0) {  // not found - enter skip sequence
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

        // if it exists - remove old template on exporter with same ID
        removeTemplate(exporter_entry, id);
        templateList_t *template = newTemplate(exporter_entry, id);
        if (!template) {
            LogError("Process_v9: abort template add: %s line %d", __FILE__, __LINE__);
            return;
        }
        dataTemplate_t *dataTemplate = (dataTemplate_t *)calloc(1, sizeof(dataTemplate_t));
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
            // padding
            dbg_printf("Skip %u bytes padding\n", size_left);
            return;
        }
        DataPtr = DataPtr + size_required + 4;  // +4 for header

    }  // End of while size_left

}  // End of Process_v9_templates

static inline void Process_v9_option_templates(exporter_entry_t *exporter_entry, void *option_template_flowset, FlowSource_t *fs) {
    uint32_t size_left = GET_FLOWSET_LENGTH(option_template_flowset) - 4;  // -4 for flowset header -> id and length
    uint8_t *option_template = option_template_flowset + 4;
    uint16_t tableID = GET_OPTION_TEMPLATE_ID(option_template);
    uint16_t scope_length = GET_OPTION_TEMPLATE_FIELD_COUNT(option_template);
    uint16_t option_length = GET_OPTION_TEMPLATE_SCOPE_FIELD_COUNT(option_template);

    if (scope_length & 0x3) {
        LogError("Process_v9: [%u] scope length error: length %u not multiple of 4", exporter_entry->info.id, scope_length);
        return;
    }

    if (option_length & 0x3) {
        LogError("Process_v9: [%u] option length error: length %u not multiple of 4", exporter_entry->info.id, option_length);
        return;
    }

    if ((scope_length + option_length) > size_left) {
        LogError(
            "Process_v9: [%u] option template length error: size left %u too small for %u scopes "
            "length and %u options length",
            exporter_entry->info.id, size_left, scope_length, option_length);
        return;
    }

    uint32_t nr_scopes = scope_length >> 2;
    uint32_t nr_options = option_length >> 2;

    dbg_printf("\n[%u] Option Template ID: %u\n", exporter_entry->info.id, tableID);
    dbg_printf("Scope length: %u Option length: %u\n", scope_length, option_length);

    removeTemplate(exporter_entry, tableID);
    optionTemplate_t *optionTemplate = (optionTemplate_t *)calloc(1, sizeof(optionTemplate_t));
    if (!optionTemplate) {
        LogError("Error calloc(): %s in %s:%d", strerror(errno), __FILE__, __LINE__);
        return;
    }

    uint8_t *p = option_template + 6;  // start of length/type data

    struct samplerOption_s *samplerOption = &(optionTemplate->samplerOption);
    struct nbarOptionList_s *nbarOption = &(optionTemplate->nbarOption);
    struct nameOptionList_s *ifnameOptionList = &(optionTemplate->ifnameOption);
    struct nameOptionList_s *vrfnameOptionList = &(optionTemplate->vrfnameOption);

    uint16_t scopeSize = 0;
    uint16_t offset = 0;
    for (int i = 0; i < (nr_scopes + nr_options); i++) {
        uint16_t type = Get_val16(p);
        p = p + 2;
        uint16_t length = Get_val16(p);
        p = p + 2;
        if (i < nr_scopes) {
            scopeSize += length;
            dbg_printf("Scope field Type: %u, offset: %u, length %u\n", type, offset, length);
        } else {
            dbg_printf("Option field Type: %u, offset: %u, length %u\n", type, offset, length);
        }

        switch (type) {
            // Old std sampling tags
            case NF9_SAMPLING_INTERVAL:  // #34
                samplerOption->spaceInterval.length = length;
                samplerOption->spaceInterval.offset = offset;
                SetFlag(optionTemplate->flags, STDSAMPLING34);
                dbg_printf(" Sampling tag #34 option found\n");
                break;
            case NF9_SAMPLING_ALGORITHM:  // #35
                samplerOption->algorithm.length = length;
                samplerOption->algorithm.offset = offset;
                SetFlag(optionTemplate->flags, STDSAMPLING35);
                dbg_printf(" Sampling #35 found\n");
                break;

            // New std sampling, individual sammplers (sampling ID)
            // Map old individual samplers
            case NF9_FLOW_SAMPLER_ID:  // #48 deprecated - fall through
                dbg_printf(" Sampling #48 found\n");
            case SELECTOR_ID:  // #302
                samplerOption->id.length = length;
                samplerOption->id.offset = offset;
                SetFlag(optionTemplate->flags, SAMPLER302);
                dbg_printf(" Sampling #302 found\n");
                break;
            case NF9_FLOW_SAMPLER_MODE:  // #49 deprecated - fall through
                dbg_printf(" Sampling #49 found\n");
            case SELECTOR_ALGORITHM:  // #304
                samplerOption->algorithm.length = length;
                samplerOption->algorithm.offset = offset;
                SetFlag(optionTemplate->flags, SAMPLER304);
                dbg_printf(" Sampling #304 found\n");
                break;
            case SAMPLING_PACKET_INTERVAL:  // #305
                samplerOption->packetInterval.length = length;
                samplerOption->packetInterval.offset = offset;
                SetFlag(optionTemplate->flags, SAMPLER305);
                dbg_printf(" Sampling #305 found\n");
                break;
            case NF9_FLOW_SAMPLER_RANDOM_INTERVAL:  // #50 deprecated - fall through
                dbg_printf(" Sampling #50 found\n");
            case SAMPLING_SPACE_INTERVAL:  // #306
                samplerOption->spaceInterval.length = length;
                samplerOption->spaceInterval.offset = offset;
                SetFlag(optionTemplate->flags, SAMPLER306);
                dbg_printf(" Sampling #306 found\n");
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

            // ifname
            case NF9_INPUT_SNMP:
                ifnameOptionList->ingress.length = length;
                ifnameOptionList->ingress.offset = offset;
                SetFlag(optionTemplate->flags, IFNAMEOPTION);
                dbg_printf(" Ifname ingress option found\n");
                break;
            case NF9_INTERFACEDESCRIPTION:
                ifnameOptionList->name.length = length;
                ifnameOptionList->name.offset = offset;
                SetFlag(optionTemplate->flags, IFNAMEOPTION);
                dbg_printf(" Ifname name option found\n");
                break;

            // vrfname
            case NF_N_INGRESS_VRFID:
                vrfnameOptionList->ingress.length = length;
                vrfnameOptionList->ingress.offset = offset;
                SetFlag(optionTemplate->flags, VRFNAMEOPTION);
                dbg_printf(" Vrfname ingress option found\n");
                break;
            case NF_N_VRFNAME:
                vrfnameOptionList->name.length = length;
                vrfnameOptionList->name.offset = offset;
                SetFlag(optionTemplate->flags, VRFNAMEOPTION);
                dbg_printf(" Vrfname name option found\n");
                break;

            // SysUpTime information
            case SystemInitTimeMiliseconds:
                optionTemplate->SysUpOption.length = length;
                optionTemplate->SysUpOption.offset = offset;
                SetFlag(optionTemplate->flags, SYSUPOPTION);
                dbg_printf(" SysUpTime option found\n");
                break;

            default:
                dbg_printf(" Skip this type: %u, length %u\n", type, length);
        }
        offset += length;
    }
    optionTemplate->optionSize = offset;

    dbg_printf("\n[%u] Option size: %" PRIu64 ", flags: %" PRIx64 "\n", exporter_entry->info.id, optionTemplate->optionSize, optionTemplate->flags);
    if (optionTemplate->flags) {
        // if it exists - remove old template on exporter with same ID
        templateList_t *template = newTemplate(exporter_entry, tableID);
        if (!template) {
            LogError("Process_v9: abort template add: %s line %d", __FILE__, __LINE__);
            return;
        }
        template->data = optionTemplate;

        if ((optionTemplate->flags & SAMPLERFLAGS) == SAMPLERFLAGS) {
            dbg_printf("[%u] New Sampler information found\n", exporter_entry->info.id);
            SetFlag(template->type, SAMPLER_TEMPLATE);
        } else if ((optionTemplate->flags & SAMPLERSTDFLAGS) == SAMPLERSTDFLAGS) {
            dbg_printf("[%u] New std sampling information found\n", exporter_entry->info.id);
            SetFlag(template->type, SAMPLER_TEMPLATE);
        } else if ((optionTemplate->flags & STDMASK) == STDFLAGS) {
            dbg_printf("[%u] Old std sampling information found\n", exporter_entry->info.id);
            SetFlag(template->type, SAMPLER_TEMPLATE);
        } else {
            dbg_printf("[%u] No Sampling information found\n", exporter_entry->info.id);
        }

        if (TestFlag(optionTemplate->flags, NBAROPTIONS)) {
            dbg_printf("[%u] found nbar option\n", exporter_entry->info.id);
            dbg_printf("[%u] id   length: %u\n", exporter_entry->info.id, optionTemplate->nbarOption.id.length);
            dbg_printf("[%u] name length: %u\n", exporter_entry->info.id, optionTemplate->nbarOption.name.length);
            dbg_printf("[%u] desc length: %u\n", exporter_entry->info.id, optionTemplate->nbarOption.desc.length);
            optionTemplate->nbarOption.scopeSize = scopeSize;
            SetFlag(template->type, NBAR_TEMPLATE);
        } else {
            dbg_printf("[%u] No nbar information found\n", exporter_entry->info.id);
        }

        if (TestFlag(optionTemplate->flags, IFNAMEOPTION)) {
            dbg_printf("[%u] found ifname option\n", exporter_entry->info.id);
            dbg_printf("[%u] ingess length: %u\n", exporter_entry->info.id, optionTemplate->ifnameOption.ingress.length);
            dbg_printf("[%u] name length  : %u\n", exporter_entry->info.id, optionTemplate->ifnameOption.name.length);
            optionTemplate->ifnameOption.scopeSize = scopeSize;
            SetFlag(template->type, IFNAME_TEMPLATE);
        } else {
            dbg_printf("[%u] No ifname information found\n", exporter_entry->info.id);
        }

        if (TestFlag(optionTemplate->flags, VRFNAMEOPTION)) {
            dbg_printf("[%u] found vrfname option\n", exporter_entry->info.id);
            dbg_printf("[%u] ingess length: %u\n", exporter_entry->info.id, optionTemplate->vrfnameOption.ingress.length);
            dbg_printf("[%u] name length  : %u\n", exporter_entry->info.id, optionTemplate->vrfnameOption.name.length);
            optionTemplate->vrfnameOption.scopeSize = scopeSize;
            SetFlag(template->type, VRFNAME_TEMPLATE);
        } else {
            dbg_printf("[%u] No vrfname information found\n", exporter_entry->info.id);
        }

        if (TestFlag(optionTemplate->flags, SYSUPOPTION)) {
            dbg_printf("[%u] SysUp information found. length: %u\n", exporter_entry->info.id, optionTemplate->SysUpOption.length);
            SetFlag(template->type, SYSUPTIME_TEMPLATE);
        } else {
            dbg_printf("[%u] No SysUp information found\n", exporter_entry->info.id);
        }

    } else {
        free(optionTemplate);
        dbg_printf("[%u] Skip option template\n", exporter_entry->info.id);
    }

    processed_records++;

}  // End of Process_v9_option_templates

static inline void Process_v9_data(exporter_entry_t *exporter_entry, void *data_flowset, FlowSource_t *fs, dataTemplate_t *template) {
    exporter_v9_t *exporter_v9 = &exporter_entry->version.v9;

    int32_t size_left = GET_FLOWSET_LENGTH(data_flowset) - 4;  // -4 for data flowset header -> id and length

    // map input buffer as a byte array
    uint8_t *inBuff = (uint8_t *)(data_flowset + 4);  // skip flowset header

    sequencer_t *sequencer = &(template->sequencer);

    dbg_printf("[%u] Process data flowset size: %u\n", exporter_entry->info.id, size_left);

    // reserve space in output stream for EXipReceivedVx
    uint32_t receivedSize = 0;
    if (fs->sa_family == PF_INET6)
        receivedSize = ExtensionsEnabled[EXipReceivedV6ID] ? EXipReceivedV6Size : 0;
    else
        receivedSize = ExtensionsEnabled[EXipReceivedV4ID] ? EXipReceivedV4Size : 0;

    while (size_left > 0) {
        if (size_left < 4) {  // rounding pads
            size_left = 0;
            continue;
        }

        // check for enough space in output buffer
        uint32_t outRecordSize = CalcOutRecordSize(sequencer, inBuff, size_left);
        if (!IsAvailable(fs->dataBlock, sizeof(recordHeaderV3_t) + outRecordSize + receivedSize)) {
            // flush block - get an empty one
            fs->dataBlock = WriteBlock(fs->nffile, fs->dataBlock);
        }

        int buffAvail = BlockAvailable(fs->dataBlock);
        if (buffAvail == 0) {
            // this should really never occur, because the buffer gets flushed earlier
            LogError("Process_v9: output buffer size error. Skip v9 record processing");
            dbg_printf("Process_v9: output buffer size error. Skip v9 record processing");
            return;
        }

        void *outBuff;
    REDO:
        // map file record to output buffer
        outBuff = GetCurrentCursor(fs->dataBlock);

        dbg_printf("[%u] Process data record: %u addr: %p, size_left: %u buff_avail: %u\n", exporter_entry->info.id, processed_records,
                   (void *)((ptrdiff_t)inBuff - (ptrdiff_t)data_flowset), size_left, buffAvail);

        // process record
        AddV3Header(outBuff, recordHeaderV3);

        // header data
        recordHeaderV3->engineType = (exporter_entry->info.id >> 8) & 0xFF;
        recordHeaderV3->engineID = exporter_entry->info.id & 0xFF;
        recordHeaderV3->nfversion = 9;
        recordHeaderV3->exporterID = exporter_entry->info.sysid;

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

                LogVerbose("Process v9: Sequencer run - resize output buffer");
                // request new and empty buffer
                fs->dataBlock = WriteBlock(fs->nffile, fs->dataBlock);
                if (fs->dataBlock == NULL) {
                    return;
                }

                int buffAvail = BlockAvailable(fs->dataBlock);
                if (buffAvail == 0) {
                    // this should really never happen, because the buffer got flushed
                    LogError("Process_v9: output buffer size error. Skip v9 record processing");
                    dbg_printf("Process_v9: output buffer size error. Skip v9 record processing");
                    return;
                }
                goto REDO;
                break;
        }

        dbg_printf("New record added with %u elements and size: %u, sequencer inLength: %zu, outLength: %zu\n", recordHeaderV3->numElements,
                   recordHeaderV3->size, sequencer->inLength, sequencer->outLength);

        // add router IP
        if (fs->sa_family == PF_INET6) {
            if (ExtensionsEnabled[EXipReceivedV6ID]) {
                PushExtension(recordHeaderV3, EXipReceivedV6, ipReceivedV6);
                uint64_t *ipv6 = (uint64_t *)fs->ipAddr.bytes;
                ipReceivedV6->ip[0] = ntohll(ipv6[0]);
                ipReceivedV6->ip[1] = ntohll(ipv6[1]);
                dbg_printf("Add IPv6 route IP extension\n");
            } else {
                dbg_printf("IPv6 route IP extension not enabled\n");
            }
        } else {
            if (ExtensionsEnabled[EXipReceivedV4ID]) {
                PushExtension(recordHeaderV3, EXipReceivedV4, ipReceivedV4);
                uint32_t ipv4;
                memcpy(&ipv4, fs->ipAddr.bytes + 12, 4);
                ipReceivedV4->ip = ntohl(ipv4);
                dbg_printf("Add IPv4 route IP extension\n");
            } else {
                dbg_printf("IPv4 route IP extension not enabled\n");
            }
        }

        dbg_printf("Record: %u elements, size: %u\n", recordHeaderV3->numElements, recordHeaderV3->size);

        outBuff += recordHeaderV3->size;
        inBuff += sequencer->inLength;
        size_left -= sequencer->inLength;

        processed_records++;

        if (stack[STACK_ENGINE_TYPE]) recordHeaderV3->engineType = stack[STACK_ENGINE_TYPE];
        if (stack[STACK_ENGINE_ID]) recordHeaderV3->engineID = stack[STACK_ENGINE_ID];

        // handle sampling
        uint64_t packetInterval = 1;
        uint64_t spaceInterval = 0;
        uint64_t intervalTotal = 0;
        // either 0 for no sampler or announced samplerID
        uint32_t sampler_id = stack[STACK_SAMPLER];
        sampler_t *sampler = exporter_entry->sampler;
        sampler_t *overwriteSampler = NULL;
        sampler_t *defaultSampler = NULL;
        sampler_t *genericSampler = NULL;
        while (sampler) {
            if (sampler->record.id == sampler_id) break;
            if (sampler->record.id == SAMPLER_OVERWRITE) overwriteSampler = sampler;
            if (sampler->record.id == SAMPLER_DEFAULT) defaultSampler = sampler;
            if (sampler->record.id == SAMPLER_GENERIC) genericSampler = sampler;
            sampler = sampler->next;
        }

        EXsamplerInfo_t *samplerInfo = (EXsamplerInfo_t *)sequencer->offsetCache[EXsamplerInfoID];
        if (samplerInfo) {
            samplerInfo->exporter_sysid = exporter_entry->info.sysid;
        }

        if (overwriteSampler) {
            // hard overwrite sampling
            packetInterval = overwriteSampler->record.packetInterval;
            spaceInterval = overwriteSampler->record.spaceInterval;
            SetFlag(recordHeaderV3->flags, V3_FLAG_SAMPLED);
            dbg_printf("[%u] Overwrite sampling - packet interval: %" PRIu64 ", packet space: %" PRIu64 "\n", exporter_entry->info.id, packetInterval,
                       spaceInterval);
        } else if (sampler) {
            // individual assigned sampler ID
            packetInterval = sampler->record.packetInterval;
            spaceInterval = sampler->record.spaceInterval;
            SetFlag(recordHeaderV3->flags, V3_FLAG_SAMPLED);
            dbg_printf("[%u] Found assigned sampler ID %u - packet interval: %" PRIu64 ", packet space: %" PRIu64 "\n", exporter_entry->info.id,
                       sampler_id, packetInterval, spaceInterval);
        } else if (genericSampler) {
            // global sampler ID
            packetInterval = genericSampler->record.packetInterval;
            spaceInterval = genericSampler->record.spaceInterval;
            SetFlag(recordHeaderV3->flags, V3_FLAG_SAMPLED);
            dbg_printf("[%u] Found generic sampler - packet interval: %" PRIu64 ", packet space: %" PRIu64 "\n", exporter_entry->info.id,
                       packetInterval, spaceInterval);
        } else if (defaultSampler) {
            // static default sampler
            packetInterval = defaultSampler->record.packetInterval;
            spaceInterval = defaultSampler->record.spaceInterval;
            SetFlag(recordHeaderV3->flags, V3_FLAG_SAMPLED);
            dbg_printf("[%u] Found static default sampler - packet interval: %" PRIu64 ", packet space: %" PRIu64 "\n", exporter_entry->info.id,
                       packetInterval, spaceInterval);
        }
        intervalTotal = packetInterval + spaceInterval;

        // add time received
        EXgenericFlow_t *genericFlow = sequencer->offsetCache[EXgenericFlowID];
        if (genericFlow) {
            genericFlow->msecReceived = ((uint64_t)fs->received.tv_sec * 1000LL) + (uint64_t)((uint64_t)fs->received.tv_usec / 1000LL);

            // update first_seen, last_seen
            // tags #152, #153 are expected otherwise
            // process tags #21, #22
            if (stack[STACK_MSECLAST] != 0) {
                uint64_t First = stack[STACK_MSECFIRST];
                uint64_t Last = stack[STACK_MSECLAST];

                if (First > Last) /* First in msec, in case of msec overflow, between start and end */
                    genericFlow->msecFirst = exporter_v9->boot_time - 0x100000000LL + First;
                else
                    genericFlow->msecFirst = First + exporter_v9->boot_time;

                // end time in msecs
                genericFlow->msecLast = (uint64_t)Last + exporter_v9->boot_time;
            } else if (stack[STACK_SECFIRST]) {
                genericFlow->msecFirst = stack[STACK_SECFIRST] * (uint64_t)1000;
                genericFlow->msecLast = stack[STACK_SECLAST] * (uint64_t)1000;
            }

            UpdateFirstLast(fs->nffile, genericFlow->msecFirst, genericFlow->msecLast);
            dbg_printf("msecFrist: %" PRIu64 "\n", genericFlow->msecFirst);
            dbg_printf("msecLast : %" PRIu64 "\n", genericFlow->msecLast);
            dbg_printf("packets : %" PRIu64 "\n", genericFlow->inPackets);
            dbg_printf("bytes : %" PRIu64 "\n", genericFlow->inBytes);

            if (spaceInterval > 0) {
                genericFlow->inPackets = genericFlow->inPackets * intervalTotal / (uint64_t)packetInterval;
                genericFlow->inBytes = genericFlow->inBytes * intervalTotal / (uint64_t)packetInterval;
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
                    } else if (stack[STACK_ICMP_TYPE] != 0 || stack[STACK_ICMP_CODE] != 0) {
                        // icmp type and code elements #176 #177 #178 #179
                        genericFlow->dstPort = (stack[STACK_ICMP_TYPE] << 8) + stack[STACK_ICMP_CODE];
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

            exporter_entry->flows++;
            fs->nffile->stat_record->numflows++;
            fs->nffile->stat_record->numpackets += genericFlow->inPackets;
            fs->nffile->stat_record->numbytes += genericFlow->inBytes;

            uint32_t exporterIdent = MetricExpporterID(recordHeaderV3);
            UpdateMetric(fs->nffile->ident, exporterIdent, genericFlow);
        }

        EXcntFlow_t *cntFlow = sequencer->offsetCache[EXcntFlowID];
        if (cntFlow) {
            if (spaceInterval > 0) {
                cntFlow->outPackets = cntFlow->outPackets * intervalTotal / (uint64_t)packetInterval;
                cntFlow->outBytes = cntFlow->outBytes * intervalTotal / (uint64_t)packetInterval;
            }
            if (cntFlow->flows == 0) cntFlow->flows++;
            fs->nffile->stat_record->numpackets += cntFlow->outPackets;
            fs->nffile->stat_record->numbytes += cntFlow->outBytes;
        }

        // handle event time for NSEL/ASA and NAT
        EXnselCommon_t *nselCommon = sequencer->offsetCache[EXnselCommonID];
        if (nselCommon) {
            nselCommon->msecEvent = stack[STACK_MSEC];
            if (nselCommon->msecEvent) {
                if (genericFlow) {
                    dbg_printf("Copy nsel Event time: %" PRIu64 " overwriting %" PRIu64 "\n", nselCommon->msecEvent, genericFlow->msecFirst);
                    genericFlow->msecFirst = stack[STACK_MSEC];
                    genericFlow->msecLast = stack[STACK_MSEC];
                }
            } else {
                if (genericFlow) {
                    dbg_printf("Copy msecFirst to nsel Event time: %" PRIu64 "\n", genericFlow->msecFirst);
                    nselCommon->msecEvent = genericFlow->msecFirst;
                }
            }
            SetFlag(recordHeaderV3->flags, V3_FLAG_EVENT);
            dbg_printf("Nsel event time: %" PRIu64 "\n", nselCommon->msecEvent);
        }
        EXnatCommon_t *natCommon = sequencer->offsetCache[EXnatCommonID];
        if (natCommon) {
            natCommon->msecEvent = stack[STACK_MSEC];
            if (natCommon->msecEvent) {
                if (genericFlow) {
                    dbg_printf("Copy nat Event time: %" PRIu64 " overwriting %" PRIu64 "\n", natCommon->msecEvent, genericFlow->msecFirst);
                    genericFlow->msecFirst = stack[STACK_MSEC];
                    genericFlow->msecLast = stack[STACK_MSEC];
                }
            } else {
                if (genericFlow) {
                    dbg_printf("Copy msecFirst to nat Event time: %" PRIu64 "\n", genericFlow->msecFirst);
                    natCommon->msecEvent = genericFlow->msecFirst;
                }
            }
            SetFlag(recordHeaderV3->flags, V3_FLAG_EVENT);
            dbg_printf("Nat event time: %" PRIu64 "\n", natCommon->msecEvent);
        }
        dbg_printf("Final msecFrist: %" PRIu64 "\n", genericFlow->msecFirst);
        dbg_printf("Final msecLast : %" PRIu64 "\n", genericFlow->msecLast);

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

        // Call the record callback for filtered repeaters
        CALL_RECORD_CALLBACK(recordHeaderV3);

        fs->dataBlock->size += recordHeaderV3->size;
        fs->dataBlock->NumRecords++;

        // buffer size sanity check
        if (fs->dataBlock->size > WRITE_BUFFSIZE) {
            // should never happen
            LogError("### Software error ###: %s line %d", __FILE__, __LINE__);
            LogError("Process v9: Output buffer overflow! Flush buffer and skip records.");
            LogError("Buffer size: %u > %u", fs->dataBlock->size, WRITE_BUFFSIZE);

            // reset buffer
            fs->dataBlock->size = 0;
            fs->dataBlock->NumRecords = 0;
            return;
        }
    }

}  // End of Process_v9_data

static inline void Process_v9_sampler_option_data(exporter_entry_t *exporter_entry, FlowSource_t *fs, templateList_t *template, void *data_flowset) {
    uint32_t size_left = GET_FLOWSET_LENGTH(data_flowset) - 4;  // -4 for data flowset header -> id and length
    dbg_printf("[%u] Process sampler option data flowset size: %u\n", exporter_entry->info.id, size_left);

    // map input buffer as a byte array
    uint8_t *in = (uint8_t *)(data_flowset + 4);  // skip flowset header

    optionTemplate_t *optionTemplate = (optionTemplate_t *)template->data;
    struct samplerOption_s *samplerOption = &(optionTemplate->samplerOption);

    if ((optionTemplate->flags & SAMPLERSTDFLAGS) != 0) {
        sampler_record_t sampler_record = {0};

        if (CHECK_OPTION_DATA(size_left, samplerOption->id)) {
            sampler_record.id = Get_val(in, samplerOption->id.offset, samplerOption->id.length);
        }
        sampler_record.algorithm = 0;
        if (CHECK_OPTION_DATA(size_left, samplerOption->algorithm)) {
            sampler_record.algorithm = Get_val(in, samplerOption->algorithm.offset, samplerOption->algorithm.length);
        }
        sampler_record.packetInterval = 0;
        if (CHECK_OPTION_DATA(size_left, samplerOption->packetInterval)) {
            sampler_record.packetInterval = Get_val(in, samplerOption->packetInterval.offset, samplerOption->packetInterval.length);
        }
        sampler_record.spaceInterval = 0;
        if (CHECK_OPTION_DATA(size_left, samplerOption->spaceInterval)) {
            sampler_record.spaceInterval = Get_val(in, samplerOption->spaceInterval.offset, samplerOption->spaceInterval.length);
        }

        if (sampler_record.packetInterval == 0) {
            // map plain interval data into packet space/interval
            sampler_record.packetInterval = 1;
            if (sampler_record.spaceInterval) {
                sampler_record.spaceInterval--;
            } else {
                LogError("Process_v9_option: Zero sampling interval -> sampling == 1", __FILE__, __LINE__);
            }
        }

        dbg_printf("Extracted Sampler data:\n");
        if (sampler_record.id == 0) {
            sampler_record.id = SAMPLER_GENERIC;
            dbg_printf("New std sampler: algorithm : %u, packet interval: %u, packet space: %u\n", sampler_record.algorithm,
                       sampler_record.packetInterval, sampler_record.spaceInterval);
        } else {
            dbg_printf("ID : %" PRId64 ", algorithm : %u, packet interval: %u, packet space: %u\n", sampler_record.id, sampler_record.algorithm,
                       sampler_record.packetInterval, sampler_record.spaceInterval);
        }

        InsertSampler(fs, exporter_entry, &sampler_record);
        return;
    }

    if ((optionTemplate->flags & STDMASK) != 0) {
        sampler_record_t sampler_record = {0};

        // map plain interval data into packet space/interval
        sampler_record.id = SAMPLER_GENERIC;
        sampler_record.packetInterval = 1;
        if (CHECK_OPTION_DATA(size_left, samplerOption->algorithm)) {
            sampler_record.algorithm = Get_val(in, samplerOption->algorithm.offset, samplerOption->algorithm.length);
        }
        if (CHECK_OPTION_DATA(size_left, samplerOption->spaceInterval)) {
            sampler_record.spaceInterval = Get_val(in, samplerOption->spaceInterval.offset, samplerOption->spaceInterval.length);
            if (sampler_record.spaceInterval) {
                sampler_record.spaceInterval--;
            } else {
                LogError("Process_v9_option: Zero sampling interval -> sampling == 1", __FILE__, __LINE__);
            }
        }
        dbg_printf("ID : %" PRId64 ", algorithm : %u, packet interval: %u, packet space: %u\n", sampler_record.id, sampler_record.algorithm,
                   sampler_record.packetInterval, sampler_record.spaceInterval);

        InsertSampler(fs, exporter_entry, &sampler_record);
    }
    processed_records++;

}  // End of Process_v9_sampler_option_data

static void Process_v9_nbar_option_data(exporter_entry_t *exporter_entry, FlowSource_t *fs, templateList_t *template, void *data_flowset) {
    uint32_t size_left = GET_FLOWSET_LENGTH(data_flowset) - 4;  // -4 for data flowset header -> id and length
    dbg_printf("[%u] Process nbar option data flowset size: %u\n", exporter_entry->info.id, size_left);

    optionTemplate_t *optionTemplate = (optionTemplate_t *)template->data;
    struct nbarOptionList_s *nbarOption = &(optionTemplate->nbarOption);

    // map input buffer as a byte array
    uint8_t *inBuff = (uint8_t *)(data_flowset + 4);  // skip flowset header
    // data size
    size_t data_size = nbarOption->id.length + nbarOption->name.length + nbarOption->desc.length;
    // size of record
    size_t option_size = optionTemplate->optionSize;
    // number of records in data
    int numRecords = size_left / option_size;
    dbg_printf("[%u] nbar option data - records: %u, size: %zu\n", exporter_entry->info.id, numRecords, option_size);

    if (numRecords == 0 || option_size == 0 || option_size > size_left) {
        LogError("Process_nbar_option: nbar option size error: option size: %zu, size left: %u", option_size, size_left);
        return;
    }

    size_t elementSize = data_size;
    size_t align = elementSize & 0x3;
    if (align) {
        elementSize += 4 - align;
    }
    size_t total_size = sizeof(arrayRecordHeader_t) + sizeof(NbarAppInfo_t) + numRecords * elementSize;
    dbg_printf("nbar elementSize: %zu, totalSize: %zu\n", elementSize, total_size);

    // output buffer size check for all expected records
    if (!IsAvailable(fs->dataBlock, total_size)) {
        // flush block - get an empty one
        fs->dataBlock = WriteBlock(fs->nffile, fs->dataBlock);
    }

    void *outBuff = GetCurrentCursor(fs->dataBlock);
    // push nbar header
    AddArrayHeader(outBuff, nbarHeader, NbarRecordType, elementSize);

    // put array info descriptor next
    NbarAppInfo_t *NbarInfo = (NbarAppInfo_t *)(outBuff + sizeof(arrayRecordHeader_t));
    nbarHeader->size += sizeof(NbarAppInfo_t);

    // info record for each element in array
    NbarInfo->app_id_length = nbarOption->id.length;
    NbarInfo->app_name_length = nbarOption->name.length;
    NbarInfo->app_desc_length = nbarOption->desc.length;

    dbg(int cnt = 0);
    while (size_left >= option_size) {
        // push nbar app info record
        uint8_t *p;
        PushArrayNextElement(nbarHeader, p, uint8_t);

        // copy data
        // id octet array
        memcpy(p, inBuff + nbarOption->id.offset, nbarOption->id.length);
        p += nbarOption->id.length;

        // name string
        memcpy(p, inBuff + nbarOption->name.offset, nbarOption->name.length);
        uint32_t state = UTF8_ACCEPT;
        int err = 0;
        if (validate_utf8(&state, (char *)p, nbarOption->name.length) == UTF8_REJECT) {
            LogError("Process_nbar_option: validate_utf8() %s line %d: %s", __FILE__, __LINE__, "invalid utf8 nbar name");
            err = 1;
        }
        p[nbarOption->name.length - 1] = '\0';
        p += nbarOption->name.length;

        // description string
        memcpy(p, inBuff + nbarOption->desc.offset, nbarOption->desc.length);
        state = UTF8_ACCEPT;
        if (validate_utf8(&state, (char *)p, nbarOption->desc.length) == UTF8_REJECT) {
            LogError("Process_nbar_option: validate_utf8() %s line %d: %s", __FILE__, __LINE__, "invalid utf8 nbar description");
            err = 1;
        }
        p[nbarOption->desc.length - 1] = '\0';

#ifdef DEVEL
        cnt++;
        if (err == 0) {
            printf("nbar record: %d, name: %s, desc: %s\n", cnt, p - nbarOption->name.length, p);
        } else {
            printf("Invalid nbar information - skip record\n");
        }
#endif

        // in case of an err we do no store this record
        if (err != 0) {
            nbarHeader->numElements--;
            nbarHeader->size -= elementSize;
        }
        inBuff += option_size;
        size_left -= option_size;
    }

    // update data block header
    fs->dataBlock->size += nbarHeader->size;
    fs->dataBlock->NumRecords++;

    if (size_left > 7) {
        LogVerbose("Process nbar data record - %u extra bytes", size_left);
    }
    processed_records++;

    dbg_printf("nbar processed: %u records - header: size: %u, type: %u, numelements: %u, elementSize: %u\n", numRecords, nbarHeader->size,
               nbarHeader->type, nbarHeader->numElements, nbarHeader->elementSize);

}  // End of Process_v9_nbar_option_data

static void Process_v9_ifvrf_option_data(exporter_entry_t *exporter_entry, FlowSource_t *fs, int type, templateList_t *template, void *data_flowset) {
    uint32_t size_left = GET_FLOWSET_LENGTH(data_flowset) - 4;  // -4 for data flowset header -> id and length
    dbg_printf("[%u] Process ifvrf option data flowset size: %u\n", exporter_entry->info.id, size_left);

    uint32_t recordType = 0;
    optionTemplate_t *optionTemplate = (optionTemplate_t *)template->data;
    struct nameOptionList_s *nameOption = NULL;
    switch (type) {
        case IFNAME_TEMPLATE:
            nameOption = &(optionTemplate->ifnameOption);
            recordType = IfNameRecordType;
            dbg_printf("[%u] Process if name option data flowset size: %u\n", exporter_entry->info.id, size_left);
            break;
        case VRFNAME_TEMPLATE:
            nameOption = &(optionTemplate->vrfnameOption);
            recordType = VrfNameRecordType;
            dbg_printf("[%u] Process vrf name option data flowset size: %u\n", exporter_entry->info.id, size_left);
            break;
        default:
            LogError("Unknown array record type: %d", type);
            return;

            // unreached
            break;
    }

    // map input buffer as a byte array
    uint8_t *inBuff = (uint8_t *)(data_flowset + 4);  // skip flowset header
    // data size
    size_t data_size = nameOption->name.length + sizeof(uint32_t);
    // size of record
    size_t option_size = optionTemplate->optionSize;
    // number of records in data
    int numRecords = size_left / option_size;
    dbg_printf("[%u] name option data - records: %u, size: %zu\n", exporter_entry->info.id, numRecords, option_size);

    if (numRecords == 0 || option_size == 0 || option_size > size_left) {
        LogError("Process_ifvrf_option: nbar option size error: option size: %zu, size left: %u", option_size, size_left);
        return;
    }

    size_t elementSize = data_size;
    size_t align = elementSize & 0x3;
    if (align) {
        elementSize += 4 - align;
    }
    size_t total_size = sizeof(arrayRecordHeader_t) + sizeof(uint32_t) + numRecords * elementSize;
    dbg_printf("name elementSize: %zu, totalSize: %zu\n", elementSize, total_size);

    // output buffer size check for all expected records
    if (!IsAvailable(fs->dataBlock, total_size)) {
        // flush block - get an empty one
        fs->dataBlock = WriteBlock(fs->nffile, fs->dataBlock);
    }

    void *outBuff = GetCurrentCursor(fs->dataBlock);

    // push nbar header
    AddArrayHeader(outBuff, nameHeader, recordType, elementSize);

    // put array info descriptor next
    uint32_t *nameSize = (uint32_t *)(outBuff + sizeof(arrayRecordHeader_t));
    nameHeader->size += sizeof(uint32_t);

    // info record for each element in array
    *nameSize = nameOption->name.length;

    dbg(int cnt = 0);
    while (size_left >= option_size) {
        // push nbar app info record
        uint8_t *p;
        PushArrayNextElement(nameHeader, p, uint8_t);

        // copy data
        // ingress ID
        uint32_t val = 0;
        for (int i = 0; i < nameOption->ingress.length; i++) val = (val << 8) + *((uint8_t *)(inBuff + nameOption->ingress.offset + i));

        uint32_t *ingress = (uint32_t *)p;
        *ingress = val;
        p += sizeof(uint32_t);

        // name string
        memcpy(p, inBuff + nameOption->name.offset, nameOption->name.length);
        uint32_t state = UTF8_ACCEPT;
        int err = 0;
        if (validate_utf8(&state, (char *)p, nameOption->name.length) == UTF8_REJECT) {
            LogError("Process_name_option: validate_utf8() %s line %d: %s", __FILE__, __LINE__, "invalid utf8 if/vrf name");
            err = 1;
        }
        p[nameOption->name.length - 1] = '\0';
#ifdef DEVEL
        if (err == 0) {
            printf("name record: %d: ingress: %d, %s\n", cnt, val, p);
        } else {
            printf("Invalid name information - skip record\n");
        }
        cnt++;
#endif
        p += nameOption->name.length;

        // in case of an err we do no store this record
        if (err != 0) {
            nameHeader->numElements--;
            nameHeader->size -= elementSize;
        }
        inBuff += option_size;
        size_left -= option_size;
    }

    // update data block header
    fs->dataBlock->size += nameHeader->size;
    fs->dataBlock->NumRecords++;

    if (size_left > 7) {
        LogVerbose("Process ifvrf data record - %u extra bytes", size_left);
    }
    processed_records++;

    dbg_printf("if/vrf name processed: %u records - header: size: %u, type: %u, numelements: %u, elementSize: %u\n", numRecords, nameHeader->size,
               nameHeader->type, nameHeader->numElements, nameHeader->elementSize);

}  // End of Process_v9_ifvrf_option_data

static void Process_v9_SysUpTime_option_data(exporter_entry_t *exporter_entry, templateList_t *template, void *data_flowset) {
    exporter_v9_t *exporter_v9 = &exporter_entry->version.v9;

    uint32_t size_left = GET_FLOWSET_LENGTH(data_flowset) - 4;  // -4 for data flowset header -> id and length
    dbg_printf("[%u] Process sysup option data flowset size: %u\n", exporter_entry->info.id, size_left);

    optionTemplate_t *optionTemplate = (optionTemplate_t *)template->data;

    // map input buffer as a byte array
    uint8_t *in = (uint8_t *)(data_flowset + 4);  // skip flowset header
    if (CHECK_OPTION_DATA(size_left, optionTemplate->SysUpOption)) {
        exporter_v9->SysUpTime = Get_val(in, optionTemplate->SysUpOption.offset, optionTemplate->SysUpOption.length);
        dbg_printf("Extracted SysUpTime : %" PRIu64 "\n", exporter_v9->SysUpTime);
    } else {
        LogError("Process_v9_option: %s line %d: Not enough data for option data", __FILE__, __LINE__);
        return;
    }

}  // End of Process_v9_SysUpTime_option_data

static void ProcessOptionFlowset(exporter_entry_t *exporter_entry, FlowSource_t *fs, templateList_t *template, void *data_flowset) {
    if (TestFlag(template->type, SAMPLER_TEMPLATE)) {
        dbg_printf("Found sampler option data\n");
        Process_v9_sampler_option_data(exporter_entry, fs, template, data_flowset);
    }
    if (TestFlag(template->type, NBAR_TEMPLATE)) {
        dbg_printf("Found nbar option data\n");
        Process_v9_nbar_option_data(exporter_entry, fs, template, data_flowset);
    }

    if (TestFlag(template->type, IFNAME_TEMPLATE)) {
        dbg_printf("Found ifname option data\n");
        Process_v9_ifvrf_option_data(exporter_entry, fs, IFNAME_TEMPLATE, template, data_flowset);
    }

    if (TestFlag(template->type, VRFNAME_TEMPLATE)) {
        dbg_printf("Found vrfname option data\n");
        Process_v9_ifvrf_option_data(exporter_entry, fs, VRFNAME_TEMPLATE, template, data_flowset);
    }

    if (TestFlag(template->type, SYSUPTIME_TEMPLATE)) {
        dbg_printf("Found SysUpTime option data\n");
        Process_v9_SysUpTime_option_data(exporter_entry, template, data_flowset);
    }
}  // End of ProcessOptionFlowset

void Process_v9(void *in_buff, ssize_t in_buff_cnt, FlowSource_t *fs) {
#ifdef DEVEL
    static int pkg_num = 1;
    dbg_printf("\nProcess_v9: Next packet: %i\n", pkg_num++);
#endif

    ssize_t size_left = in_buff_cnt;
    if (size_left < V9_HEADER_LENGTH) {
        LogError("Process_v9: Too little data for v9 packet: '%lli'", (long long)size_left);
        return;
    }

    // map v9 data structure to input buffer
    v9Header_t *v9_header = (v9Header_t *)in_buff;
    uint32_t exporter_id = ntohl(v9_header->source_id);

    exporter_entry_t *exporter_entry = getExporter(fs, exporter_id);
    if (!exporter_entry) {
        LogError("Process_v9: No exporter template: Skip v9 record processing");
        return;
    }
    exporter_entry->packets++;
    exporter_v9_t *exporter_v9 = &exporter_entry->version.v9;

    /* calculate boot time in msec */
    v9_header->SysUptime = ntohl(v9_header->SysUptime);
    v9_header->unix_secs = ntohl(v9_header->unix_secs);
    exporter_v9->boot_time = (uint64_t)1000 * (uint64_t)(v9_header->unix_secs) - (uint64_t)v9_header->SysUptime;

    void *flowset_header = (void *)v9_header + V9_HEADER_LENGTH;
    size_left -= V9_HEADER_LENGTH;

#ifdef DEVEL
    uint32_t expected_records = ntohs(v9_header->count);
    printf("[%u] records: %u, buffer: %zd \n", exporter_id, expected_records, size_left);
    printf("SourceID: %u, Sysuptime: %u.%u\n", v9_header->source_id, v9_header->SysUptime, v9_header->unix_secs);
#endif

    // sequence check
    uint32_t seq = ntohl(v9_header->sequence);

    /*
     * sequence == UINT32_MAX means "uninitialized"
     * this is false exactly once, then always true
     */
    if (exporter_entry->sequence != UINT32_MAX) {
        uint32_t distance = seq - exporter_entry->sequence; /* wrap-safe */

        if (distance != 1) {
            exporter_entry->sequence_failure++;
            fs->nffile->stat_record->sequence_failure++;

            dbg_printf("[%u] Sequence error: last seq: %u, seq %u, dist %u\n", exporter_entry->info.id, exporter_entry->sequence, seq, distance);
        }
    }
    exporter_entry->sequence = seq;

    dbg_printf("Sequence: %u\n", exporter_entry->sequence);

    processed_records = 0;

    // iterate over all flowsets in export packet, while there are bytes left
    uint32_t flowset_length = 0;
    while (size_left) {
        uint16_t flowset_id;
        if (size_left < 4) {
            return;
        }

        flowset_header = flowset_header + flowset_length;
        flowset_id = GET_FLOWSET_ID(flowset_header);
        flowset_length = GET_FLOWSET_LENGTH(flowset_header);

        dbg_printf("[%u] Next flowset id: %u, length: %u, buffersize: %zu\n", exporter_entry->info.id, flowset_id, flowset_length, size_left);

        if (flowset_length == 0) {
            /* 	this should never happen, as 4 is an empty flowset
                    and smaller is an illegal flowset anyway ...
                    if it happens, we can't determine the next flowset, so skip the entire export
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
                exporter_v9->TemplateRecords++;
                Process_v9_templates(exporter_entry, flowset_header, fs);
                break;
            case NF9_OPTIONS_FLOWSET_ID: {
                exporter_v9->TemplateRecords++;
                dbg_printf("Process option template flowset, length: %u\n", flowset_length);
                Process_v9_option_templates(exporter_entry, flowset_header, fs);
            } break;
            default: {
                if (flowset_id < NF9_MIN_RECORD_FLOWSET_ID) {
                    dbg_printf("Invalid flowset id: %u\n", flowset_id);
                    LogError("Process_v9: Invalid flowset id: %u", flowset_id);
                } else {
                    dbg_printf("[%u] ID %u Data flowset\n", exporter_entry->info.id, flowset_id);
                    templateList_t *template = getTemplate(exporter_entry, flowset_id);
                    if (template) {
                        if (TestFlag(template->type, DATA_TEMPLATE)) {
                            Process_v9_data(exporter_entry, flowset_header, fs, (dataTemplate_t *)template->data);
                            exporter_v9->DataRecords++;
                        } else {
                            ProcessOptionFlowset(exporter_entry, fs, template, flowset_header);
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
