/*
 *  Copyright (c) 2009-2026, Peter Haag
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
#include "id.h"
#include "logging.h"
#include "metric.h"
#include "nbar.h"
#include "nfdump.h"
#include "nffileV3/nffileV3.h"
#include "nfnet.h"
#include "nfxV4.h"
#include "output_short.h"
#include "util.h"

#define LINEAR_MARKER 512

// Get_valxx, a  macros
#include "inline.c"

static int ExtensionsEnabled[MAXEXTENSIONS];

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

// add each element with id elementID at index elementID in the translation table
#define AddElement(elementID, elementSize, translate, extID, offset, name) [elementID] = {elementID, elementSize, translate, extID, offset, name}

#define AppendElement(elementID, elementSize, translate, extID, offset, name) {elementID, elementSize, translate, extID, offset, name}

static const struct v9TranslationMap_s {
    uint16_t id;            // v9 element id
    uint16_t outputLength;  // output length in extension ID
    transform_t transform;  // transform encoding
    uint16_t extensionID;   // extension ID
    uint16_t offsetRel;     // offset in extension
    char *name;             // name of element as string
} v9TranslationMap[] = {
    AddElement(NF9_IN_BYTES, SIZEinBytes, MOVE_NUMBER, EXgenericFlowID, OFFinBytes, "inBytesDeltaCount"),
    AddElement(NF9_IN_PACKETS, SIZEinPackets, MOVE_NUMBER, EXgenericFlowID, OFFinPackets, "inPacketsDeltaCount"),
    AddElement(NF9_FLOWS_AGGR, SIZEflows, MOVE_NUMBER, EXcntFlowID, OFFflows, "FlowCount"),
    AddElement(NF9_IN_PROTOCOL, SIZEproto, MOVE_NUMBER, EXgenericFlowID, OFFproto, "proto"),
    AddElement(NF9_SRC_TOS, SIZEsrcTos, MOVE_NUMBER, EXgenericFlowID, OFFsrcTos, "src tos"),
    AddElement(NF9_FORWARDING_STATUS, SIZEfwdStatus, MOVE_NUMBER, EXgenericFlowID, OFFfwdStatus, "forwarding status"),
    AddElement(NF9_TCP_FLAGS, SIZEtcpFlags, MOVE_NUMBER, EXgenericFlowID, OFFtcpFlags, "TCP flags"),
    AddElement(NF9_L4_SRC_PORT, SIZEsrcPort, MOVE_NUMBER, EXgenericFlowID, OFFsrcPort, "src port"),
    AddElement(NF9_IPV4_SRC_ADDR, SIZEsrc4Addr, MOVE_NUMBER, EXipv4FlowID, OFFsrc4Addr, "src IPv4"),
    AddElement(NF9_SRC_MASK, SIZEsrcMask, MOVE_NUMBER, EXflowMiscID, OFFsrcMask, "src mask IPv4"),
    AddElement(NF9_INPUT_SNMP, SIZEinput, MOVE_NUMBER, EXinterfaceID, OFFinput, "input interface"),
    AddElement(NF9_L4_DST_PORT, SIZEdstPort, MOVE_NUMBER, EXgenericFlowID, OFFdstPort, "dst port"),
    AddElement(NF_F_ICMP_TYPE, SIZEicmpType, REGISTER_0, EXgenericFlowID, OFFicmpType, "icmp type"),
    AddElement(NF_F_ICMP_TYPE_IPV6, SIZEicmpType, REGISTER_0, EXgenericFlowID, OFFicmpType, "icmp type"),
    AddElement(NF_F_ICMP_CODE, SIZEicmpCode, REGISTER_1, EXgenericFlowID, OFFicmpCode, "icmp code"),
    AddElement(NF_F_ICMP_CODE_IPV6, SIZEicmpCode, REGISTER_1, EXgenericFlowID, OFFicmpCode, "icmp code"),
    AddElement(NF9_IPV4_DST_ADDR, SIZEdst4Addr, MOVE_NUMBER, EXipv4FlowID, OFFdst4Addr, "dst IPv4"),
    AddElement(NF9_DST_MASK, SIZEdstMask, MOVE_NUMBER, EXflowMiscID, OFFdstMask, "dst mask IPv4"),
    AddElement(NF9_OUTPUT_SNMP, SIZEoutput, MOVE_NUMBER, EXinterfaceID, OFFoutput, "output interface"),
    AddElement(NF9_V4_NEXT_HOP, SIZEnextHopIPV4, MOVE_NUMBER, EXasRoutingV4ID, OFFnextHopIPV4, "IPv4 next hop"),
    AddElement(NF9_SRC_AS, SIZEsrcAS, MOVE_NUMBER, EXasInfoID, OFFsrcAS, "src AS"),
    AddElement(NF9_DST_AS, SIZEdstAS, MOVE_NUMBER, EXasInfoID, OFFdstAS, "dst AS"),
    AddElement(NF9_BGP_V4_NEXT_HOP, SIZEbgpNextHopV4, MOVE_NUMBER, EXasRoutingV4ID, OFFbgpNextHopV4, "IPv4 bgp next hop"),
    AddElement(NF9_LAST_SWITCHED, SIZEmsecLast, MOVE_V9_TIME, EXgenericFlowID, OFFmsecLast, "msec last SysupTime"),
    AddElement(NF9_FIRST_SWITCHED, SIZEmsecFirst, MOVE_V9_TIME, EXgenericFlowID, OFFmsecFirst, "msec first SysupTime"),
    AddElement(NF_F_flowStartSeconds, SIZEmsecFirst, MOVE_TIMESEC, EXgenericFlowID, OFFmsecFirst, "sec first seen"),
    AddElement(NF_F_flowEndSeconds, SIZEmsecLast, MOVE_TIMESEC, EXgenericFlowID, OFFmsecLast, "sec last seen"),
    AddElement(NF9_OUT_BYTES, SIZEoutBytes, MOVE_NUMBER, EXcntFlowID, OFFoutBytes, "output bytes delta counter"),
    AddElement(NF9_OUT_PKTS, SIZEoutPackets, MOVE_NUMBER, EXcntFlowID, OFFoutPackets, "output packet delta counter"),
    AddElement(NF9_IPV6_SRC_ADDR, SIZEsrc6Addr, MOVE_IPV6, EXipv6FlowID, OFFsrc6Addr, "IPv6 src addr"),
    AddElement(NF9_IPV6_DST_ADDR, SIZEdst6Addr, MOVE_IPV6, EXipv6FlowID, OFFdst6Addr, "IPv6 dst addr"),
    AddElement(NF9_IPV6_SRC_MASK, SIZEsrcMask, MOVE_NUMBER, EXflowMiscID, OFFsrcMask, "src mask bits"),
    AddElement(NF9_IPV6_DST_MASK, SIZEdstMask, MOVE_NUMBER, EXflowMiscID, OFFdstMask, "dst mask bits"),
    AddElement(NF9_ICMP_TYPECODE_V4, SIZEdstPort, REGISTER_1, EXgenericFlowID, OFFdstPort, "icmp type/code V4"),
    AddElement(NF9_ICMP_TYPECODE_V6, SIZEdstPort, REGISTER_1, EXgenericFlowID, OFFdstPort, "icmp type/code V6"),
    AddElement(NF9_MIN_TTL, SIZEminTTL, MOVE_NUMBER, EXipInfoID, OFFminTTL, "flow min TTL"),
    AddElement(NF9_MAX_TTL, SIZEmaxTTL, MOVE_NUMBER, EXipInfoID, OFFmaxTTL, "flow max TTL"),
    AddElement(NF9_DST_TOS, SIZEdstTos, MOVE_NUMBER, EXflowMiscID, OFFdstTos, "post IP class of Service"),
    AddElement(NF_F_flowEndReason, SIZEflowEndReason, MOVE_NUMBER, EXflowMiscID, OFFflowEndReason, "Flow end reason"),
    AddElement(NF_F_ipTTL, SIZEminTTL, MOVE_NUMBER, EXipInfoID, OFFminTTL, "flow min TTL"),
    AddElement(NF_F_fragmentFlags, SIZEfragmentFlags, MOVE_NUMBER, EXipInfoID, OFFfragmentFlags, "IP fragment flags"),
    AddElement(NF9_IN_SRC_MAC, SIZEinSrcMac, MOVE_NUMBER, EXinMacAddrID, OFFinSrcMac, "in src MAC addr"),
    AddElement(NF9_OUT_DST_MAC, SIZEoutDstMac, MOVE_NUMBER, EXinMacAddrID, OFFoutDstMac, "out dst MAC addr"),
    AddElement(NF9_SRC_VLAN, SIZEvlanID, MOVE_NUMBER, EXvLanID, OFFvlanID, "src VLAN ID"),
    AddElement(NF9_DST_VLAN, SIZEvlanID, MOVE_NUMBER, EXvLanID, OFFvlanID, "dst VLAN ID"),
    AddElement(NF_F_dot1qVlanId, SIZEvlanID, MOVE_NUMBER, EXlayer2ID, OFFvlanID, "dot1q VLAN ID"),
    AddElement(NF_F_postDot1qVlanId, SIZEvlanID, MOVE_NUMBER, EXlayer2ID, OFFvlanID, "dot1q post VLAN ID"),
    AddElement(NF_F_dot1qCustomerVlanId, SIZEcustomerVlanId, MOVE_NUMBER, EXlayer2ID, OFFcustomerVlanId, "dot1q customer VLAN ID"),
    AddElement(NF_F_postDot1qCustomerVlanId, SIZEpostCustomerVlanId, MOVE_NUMBER, EXlayer2ID, OFFpostCustomerVlanId, "dot1q post customer VLAN ID"),
    AddElement(NF_F_ingressPhysicalInterface, SIZEphysIngress, MOVE_NUMBER, EXlayer2ID, OFFphysIngress, "ingress physical interface ID"),
    AddElement(NF_F_egressPhysicalInterface, SIZEphysEgress, MOVE_NUMBER, EXlayer2ID, OFFphysEgress, "egress physical interface ID"),
    AddElement(NF_9_IP_PROTOCOL_VERSION, SIZEipVersion, MOVE_NUMBER, EXlayer2ID, OFFipVersion, "ip version"),
    AddElement(NF9_DIRECTION, SIZEdir, MOVE_NUMBER, EXflowMiscID, OFFdir, "flow direction"),
    AddElement(NF9_V6_NEXT_HOP, SIZEnextHopIPV6, MOVE_IPV6, EXasRoutingV6ID, OFFnextHopIPV6, "IPv6 next hop IP"),
    AddElement(NF9_BPG_V6_NEXT_HOP, SIZEbgpNextHopV6, MOVE_IPV6, EXasRoutingV6ID, OFFbgpNextHopV6, "IPv6 bgp next hop IP"),
    AddElement(NF_F_BGP_ADJ_NEXT_AS, SIZEnextAdjacentAS, MOVE_NUMBER, EXasAdjacentID, OFFnextAdjacentAS, "bgb adj next AS"),
    AddElement(NF_F_BGP_ADJ_PREV_AS, SIZEprevAdjacentAS, MOVE_NUMBER, EXasAdjacentID, OFFprevAdjacentAS, "bgb adj prev AS"),
    AddElement(NF9_MPLS_LABEL_1, SIZEmplsLabel1, MOVE_NUMBER, EXmplsID, OFFmplsLabel1, "mpls label 1"),
    AddElement(NF9_MPLS_LABEL_2, SIZEmplsLabel2, MOVE_NUMBER, EXmplsID, OFFmplsLabel2, "mpls label 2"),
    AddElement(NF9_MPLS_LABEL_3, SIZEmplsLabel3, MOVE_NUMBER, EXmplsID, OFFmplsLabel3, "mpls label 3"),
    AddElement(NF9_MPLS_LABEL_4, SIZEmplsLabel4, MOVE_NUMBER, EXmplsID, OFFmplsLabel4, "mpls label 4"),
    AddElement(NF9_MPLS_LABEL_5, SIZEmplsLabel5, MOVE_NUMBER, EXmplsID, OFFmplsLabel5, "mpls label 5"),
    AddElement(NF9_MPLS_LABEL_6, SIZEmplsLabel6, MOVE_NUMBER, EXmplsID, OFFmplsLabel6, "mpls label 6"),
    AddElement(NF9_MPLS_LABEL_7, SIZEmplsLabel7, MOVE_NUMBER, EXmplsID, OFFmplsLabel7, "mpls label 7"),
    AddElement(NF9_MPLS_LABEL_8, SIZEmplsLabel8, MOVE_NUMBER, EXmplsID, OFFmplsLabel8, "mpls label 8"),
    AddElement(NF9_MPLS_LABEL_9, SIZEmplsLabel9, MOVE_NUMBER, EXmplsID, OFFmplsLabel9, "mpls label 9"),
    AddElement(NF9_MPLS_LABEL_10, SIZEmplsLabel10, MOVE_NUMBER, EXmplsID, OFFmplsLabel10, "mpls label 10"),
    AddElement(NF9_IN_DST_MAC, SIZEinDstMac, MOVE_NUMBER, EXoutMacAddrID, OFFinDstMac, "in dst MAC addr"),
    AddElement(NF9_OUT_SRC_MAC, SIZEoutSrcMac, MOVE_NUMBER, EXoutMacAddrID, OFFoutSrcMac, "out src MAC addr"),
    AddElement(NF_F_FLOW_CREATE_TIME_MSEC, SIZEmsecFirst, MOVE_NUMBER, EXgenericFlowID, OFFmsecFirst, "msec first"),
    AddElement(NF_F_FLOW_END_TIME_MSEC, SIZEmsecLast, MOVE_NUMBER, EXgenericFlowID, OFFmsecLast, "msec last"),
    AddElement(SystemInitTimeMiliseconds, 0, MOVE_SYSUP, EXnull, 0, "SysupTime msec"),
    AddElement(NF9_ENGINE_TYPE, 0, NOP, EXnull, 0, "engine type"),
    AddElement(NF9_ENGINE_ID, 0, NOP, EXnull, 0, "engine ID"),
    AddElement(NF9_ETHERTYPE, SIZEetherType, MOVE_NUMBER, EXlayer2ID, OFFetherType, "ethertype"),

    // NSEL extensions
    AddElement(NF_F_FLOW_BYTES, SIZEinBytes, MOVE_NUMBER, EXgenericFlowID, OFFinBytes, "ASA inBytes total"),
    AddElement(NF_F_FLOW_PACKETS, SIZEinPackets, MOVE_NUMBER, EXgenericFlowID, OFFinPackets, "ASA inPackets total"),
    AddElement(NF_F_FWD_FLOW_DELTA_BYTES, SIZEinBytes, MOVE_NUMBER, EXgenericFlowID, OFFinBytes, "ASA fwd bytes"),
    AddElement(NF_F_REV_FLOW_DELTA_BYTES, SIZEoutBytes, MOVE_NUMBER, EXcntFlowID, OFFoutBytes, "ASA rew bytes"),
    AddElement(NF_F_INITIATORPACKETS, SIZEinPackets, MOVE_NUMBER, EXgenericFlowID, OFFinPackets, "ASA initiator pkackets"),
    AddElement(NF_F_RESPONDERPACKETS, SIZEoutPackets, MOVE_NUMBER, EXcntFlowID, OFFoutPackets, "ASA responder packets"),
    AddElement(NF_F_EVENT_TIME_MSEC, SIZEmsecEvent, MOVE_NUMBER, EXnselCommonID, OFFmsecEvent, "msec time event"),
    AddElement(NF_F_CONN_ID, SIZEconnID, MOVE_NUMBER, EXnselCommonID, OFFconnID, "connection ID"),
    AddElement(NF_F_FW_EVENT, SIZEfwEvent, MOVE_NUMBER, EXnselCommonID, OFFfwEvent, "fw event ID"),
    AddElement(NF_F_XLATE_SRC_ADDR_IPV4, SIZExlateSrcAddrV4, MOVE_NUMBER, EXnatXlateV4ID, OFFxlateSrcAddrV4, "xlate src addr"),
    AddElement(NF_F_XLATE_DST_ADDR_IPV4, SIZExlateDstAddrV4, MOVE_NUMBER, EXnatXlateV4ID, OFFxlateDstAddrV4, "xlate dst addr"),
    AddElement(NF_F_XLATE_SRC_ADDR_IPV6, SIZExlateSrcAddrV6, MOVE_IPV6, EXnatXlateV6ID, OFFxlateDstAddrV6, "xlate src addr"),
    AddElement(NF_F_XLATE_DST_ADDR_IPV6, SIZExlateDstAddrV6, MOVE_IPV6, EXnatXlateV6ID, OFFxlateDstAddrV6, "xlate dst addr"),
    AddElement(NF_F_XLATE_SRC_PORT, SIZExlateSrcPort, MOVE_NUMBER, EXnatXlatePortID, OFFxlateSrcPort, "xlate src port"),
    AddElement(NF_F_XLATE_DST_PORT, SIZExlateDstPort, MOVE_NUMBER, EXnatXlatePortID, OFFxlateDstPort, "xlate dst port"),
    AddElement(NF_N_INGRESS_VRFID, SIZEingressVrf, MOVE_NUMBER, EXvrfID, OFFingressVrf, "ingress VRF ID"),
    AddElement(NF_N_EGRESS_VRFID, SIZEegressVrf, MOVE_NUMBER, EXvrfID, OFFegressVrf, "egress VRF ID"),

    // NEL
    AddElement(NF_N_NAT_EVENT, SIZEnatEvent, MOVE_NUMBER, EXnselCommonID, OFFnatEvent, "NAT event"),
    AddElement(NF_N_NATPOOL_ID, SIZEnatPoolID, MOVE_NUMBER, EXnselCommonID, OFFnatPoolID, "nat pool ID"),
    AddElement(NF_F_XLATE_PORT_BLOCK_START, SIZEnelblockStart, MOVE_NUMBER, EXnatPortBlockID, OFFnelblockStart, "NAT block start"),
    AddElement(NF_F_XLATE_PORT_BLOCK_END, SIZEnelblockEnd, MOVE_NUMBER, EXnatPortBlockID, OFFnelblockEnd, "NAT block end"),
    AddElement(NF_F_XLATE_PORT_BLOCK_STEP, SIZEnelblockStep, MOVE_NUMBER, EXnatPortBlockID, OFFnelblockStep, "NAT block step"),
    AddElement(NF_F_XLATE_PORT_BLOCK_SIZE, SIZEnelblockSize, MOVE_NUMBER, EXnatPortBlockID, OFFnelblockSize, "NAT block size"),

    // nbar
    AddElement(NBAR_APPLICATION_ID, SIZEnbarAppID, MOVE_BYTES, EXnbarAppID, OFFnbarAppID, "nbar application ID"),

    // sampling
    AddElement(NF9_FLOW_SAMPLER_ID, sizeof(uint8_t), REGISTER_2, EXnull, 0, "sampler ID"),
    AddElement(SELECTOR_ID, sizeof(uint64_t), REGISTER_2, EXnull, 0, "sampler ID"),

    // for memory efficiency:
    // element ID below LINEAR_MARKER are stored at it's proper index
    // element ID above LINEAR_MARKER are stored linearly at LINEAR_MARKER and above
    // once, element #LINEAR_MARKER-1 gets implemented, this marker shifts
    AddElement(LINEAR_MARKER - 1, 0, NOP, 0, 0, "compiler marker"),

    // privat IDs
    AppendElement(LOCAL_IPv4Received, SIZEReceived4IP, MOVE_NUMBER, EXipReceivedV4ID, OFFReceived4IP, "IPv4 exporter"),
    AppendElement(LOCAL_IPv6Received, SIZEReceived6IP, MOVE_NUMBER, EXipReceivedV6ID, OFFReceived6IP, "IPv6 exporter"),
    AppendElement(LOCAL_msecTimeReceived, SIZEmsecReceived, MOVE_TIME_RVD, EXgenericFlowID, OFFmsecReceived, "msec time received"),

    // large Element IDs
    AppendElement(NF_F_XLATE_SRC_ADDR_84, SIZExlateSrcAddrV4, MOVE_NUMBER, EXnatXlateV4ID, OFFxlateSrcAddrV4, "xlate src addr"),
    AppendElement(NF_F_XLATE_DST_ADDR_84, SIZExlateDstAddrV4, MOVE_NUMBER, EXnatXlateV4ID, OFFxlateDstAddrV4, "xlate dst addr"),
    AppendElement(NF_F_XLATE_SRC_PORT_84, SIZExlateSrcPort, MOVE_NUMBER, EXnatXlatePortID, OFFxlateSrcPort, "xlate src port"),
    AppendElement(NF_F_XLATE_DST_PORT_84, SIZExlateDstPort, MOVE_NUMBER, EXnatXlatePortID, OFFxlateDstPort, "xlate dst port"),
    AppendElement(NF_F_FW_EVENT_84, SIZEfwEvent, MOVE_NUMBER, EXnselCommonID, OFFfwEvent, "fw event ID"),
    AppendElement(NF_F_FW_EXT_EVENT, SIZEfwXevent, MOVE_NUMBER, EXnselCommonID, OFFfwXevent, "fw ext event ID"),
    AppendElement(NF_F_INGRESS_ACL_ID, SIZEingressAcl, MOVE_BYTES, EXnselAclID, OFFingressAcl, "ingress ACL ID"),
    AppendElement(NF_F_EGRESS_ACL_ID, SIZEegressAcl, MOVE_BYTES, EXnselAclID, OFFegressAcl, "egress ACL ID"),
    AppendElement(NF_F_USERNAME, SIZEusername, MOVE_NUMBER, EXnselUserID, OFFusername, "AAA username"),

    // last element in v9 translation map
    AppendElement(0, 0, NOP, 0, 0, NULL),

};

static const int maxMapEntries = ARRAY_SIZE(v9TranslationMap);

// netflow v9 does not officially support enterprise IDs and reverse elements
// some exporters export them though
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
static void InsertSampler(exporter_entry_t *exporter_entry, sampler_record_v4_t *sampler_record_v4);

static void expand_template_table(exporter_v9_t *exporter_v9);

static inline exporter_entry_t *getExporter(FlowSource_t *fs, uint32_t exporter_id);

static inline void Process_v9_templates(exporter_entry_t *exporter_entry, const uint8_t *template_flowset, FlowSource_t *fs);

static inline void Process_v9_option_templates(exporter_entry_t *exporter_entry, const uint8_t *option_template_flowset, FlowSource_t *fs);

static inline void Process_v9_data(exporter_entry_t *exporter_entry, const uint8_t *data_flowset, FlowSource_t *fs, const pipeline_t *pipeline);

static void Process_v9_sampler_option_data(exporter_entry_t *exporter_entry, FlowSource_t *fs, template_t *template, const uint8_t *data_flowset);

static void Process_v9_nbar_option_data(exporter_entry_t *exporter_entry, FlowSource_t *fs, template_t *template, const uint8_t *data_flowset);

static void Process_v9_ifvrf_option_data(exporter_entry_t *exporter_entry, FlowSource_t *fs, int type, template_t *template,
                                         const uint8_t *data_flowset);

static void Process_v9_SysUpTime_option_data(exporter_entry_t *exporter_entry, template_t *template, const uint8_t *data_flowset);

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
    for (int i = 0; i < maxMapEntries; i++) {
        if (v9TranslationMap[i].name != NULL) {
            int extID = v9TranslationMap[i].extensionID;
            if (ExtensionsEnabled[extID]) tagsEnabled++;
        }
    }

    if (sampling < 0) {
        LogInfo("Init v9: Max number of v9 tags enabled: %u, overwrite sampling: %d", tagsEnabled, -defaultSampling);
    } else {
        LogInfo("Init v9: Max number of v9 tags enabled: %u, default sampling: %d", tagsEnabled, defaultSampling);
    }

#ifdef DEVEL
    printf("Extension table:\n");
    for (int i = 0; i < MAXEXTENSIONS; i++) {
        printf("[%2d] id: %u, size: %u, name: %s\n", i, extensionTable[i].id, extensionTable[i].size, extensionTable[i].name);
    }
    printf("\nv9TranslationMap\n");
    for (int i = 0; i < maxMapEntries; i++) {
        printf("[%d] ID: %u, name: %s\n", i, v9TranslationMap[i].id, v9TranslationMap[i].name ? v9TranslationMap[i].name : "NULL");
    }
#endif

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

    // index search
    if (type < LINEAR_MARKER) {
        if (v9TranslationMap[type].name != NULL) {
            int extID = v9TranslationMap[type].extensionID;
            if (ExtensionsEnabled[extID]) {
                return type;
            } else {
                dbg_printf("Extension %d not enabled\n", extID);
                return -1;
            }
        } else {
            return -1;
        }
    }

    // linear search
    int i = LINEAR_MARKER;
    while (v9TranslationMap[i].name != NULL && i < maxMapEntries) {
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
        __builtin_prefetch(&tab->entries[(i + 1) & mask]);
        exporter_entry_t *e = &tab->entries[i];
        // key does not exists - create new exporter
        if (!e->in_use) {
            // create new exporter
            size_t recordSize = sizeof(exporter_info_record_v4_t);
            uint32_t numSamplers = 0;
            if (defaultSampling < 0 || defaultSampling > 1) {
                numSamplers = 4;
                // expect sampling for flow records - we start with 4 samplers.
            }
            recordSize += (numSamplers * sizeof(sampler_record_v4_t));

            void *info = calloc(1, recordSize);
            if (info == NULL) {
                LogError("Process_v9: malloc(): %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                return NULL;
            }

            *e = (exporter_entry_t){
                .key = key, .sequence = UINT32_MAX, .in_use = 1, .sysID = AssignExporterID(), .sampler_count = numSamplers, .info = info};
            tab->count++;

            *(e->info) = (exporter_info_record_v4_t){.type = ExporterInfoRecordV4Type,
                                                     .size = recordSize,
                                                     .version = key.version,
                                                     .id = key.id,
                                                     .sysID = e->sysID,
                                                     .sampler_capacity = numSamplers};
            memcpy(e->info->ip, fs->ipAddr.bytes, 16);

            e->v9 = (exporter_v9_t){0};
            expand_template_table(&e->v9);

            if (defaultSampling < 0) {
                // map hard overwrite sampling into a static sampler
                sampler_record_v4_t sampler_record_v4 = {
                    .inUse = 1, .selectorID = SAMPLER_OVERWRITE, .algorithm = 0, .packetInterval = 1, .spaceInterval = (-defaultSampling) - 1};
                InsertSampler(e, &sampler_record_v4);
                dbg_printf("Add static sampler for overwrite sampling: %d\n", -defaultSampling);
            } else if (defaultSampling > 1) {
                // map default sampling > 1 into a static sampler
                sampler_record_v4_t sampler_record_v4 = {
                    .inUse = 1, .selectorID = SAMPLER_DEFAULT, .algorithm = 0, .packetInterval = 1, .spaceInterval = defaultSampling - 1};
                InsertSampler(e, &sampler_record_v4);
                dbg_printf("Add static sampler for default sampling: %u\n", defaultSampling);
            }

            char ipstr[INET6_ADDRSTRLEN];
            LogInfo("Process_v9: New v9 exporter: SysID: %u, Domain: %u, IP: %s", e->info->sysID, exporter_id, ip128_2_str(&fs->ipAddr, ipstr));

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

static sampler_record_v4_t *CacheSampler(exporter_entry_t *exporter, sampler_record_v4_t *sampler) {
    dbg_printf("Cache sampler with ID: %lld\n", sampler->selectorID);

    // already in cache? → move to front
    for (int i = 0; i < SAMPLER_CACHE_SIZE; i++) {
        if (exporter->sampler_cache[i].ptr == sampler) {
            dbg_printf("Sampler already in cache slot %d - move to front\n", i);

            for (int j = i; j > 0; j--) {
                exporter->sampler_cache[j] = exporter->sampler_cache[j - 1];
            }

            exporter->sampler_cache[0].ptr = sampler;
            return sampler;
        }
    }

    // shift right (evict last)
    for (int i = SAMPLER_CACHE_SIZE - 1; i > 0; i--) {
        exporter->sampler_cache[i] = exporter->sampler_cache[i - 1];
    }

    exporter->sampler_cache[0].ptr = sampler;

    dbg_printf("Cache sampler in slot 0 (MRU)\n");

    return sampler;

}  // End of CacheSampler

static void InsertSampler(exporter_entry_t *exporter_entry, sampler_record_v4_t *sampler_record_v4) {
    dbg_printf("[%u] Insert Sampler: Exporter ID: %u\n", exporter_entry->sysID, exporter_entry->sysID);

    exporter_info_record_v4_t *info_record = exporter_entry->info;

    // grow array if needed
    if (info_record->sampler_count == info_record->sampler_capacity) {
        uint32_t numSamplers = info_record->sampler_capacity ? 2 * info_record->sampler_capacity : 4;
        size_t newSize = sizeof(exporter_info_record_v4_t) + numSamplers * sizeof(sampler_record_v4_t);

        dbg_printf("Expand sampler array: %u -> %u\n", info_record->sampler_capacity, numSamplers);

        exporter_info_record_v4_t *new_record = realloc(info_record, newSize);
        if (!new_record) {
            LogError("InsertSampler: realloc(): %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return;
        }

        if (new_record != info_record) {
            // invalidate cache
            for (int i = 0; i < SAMPLER_CACHE_SIZE; i++) {
                exporter_entry->sampler_cache[i].ptr = NULL;
            }
            dbg_printf("Sampler cache invalidated due to realloc\n");
        }

        exporter_entry->info = new_record;
        info_record = new_record;

        // init new slots
        for (uint32_t i = info_record->sampler_capacity; i < numSamplers; i++) {
            info_record->samplers[i].inUse = 0;
        }

        info_record->sampler_capacity = numSamplers;
        info_record->size = newSize;
    }

    sampler_record_v4_t *samplers = info_record->samplers;
    sampler_record_v4_t *slot = NULL;

    // find existing or free slot
    for (uint32_t i = 0; i < info_record->sampler_capacity; i++) {
        if (samplers[i].inUse) {
            if (samplers[i].selectorID == sampler_record_v4->selectorID) {
                dbg_printf("Update existing sampler in slot %u\n", i);
                slot = &samplers[i];

                break;
            }
        } else if (!slot) {
            // remember first free slot
            slot = &samplers[i];
        }
    }

    if (!slot) {
        dbg_printf("No slot found - should not happen\n");
        return;
    }

    if (slot->inUse == 0) {
        info_record->sampler_count++;
        exporter_entry->sampler_count = info_record->sampler_count;
    }

    // write sampler
    *slot = *sampler_record_v4;
    slot->inUse = 1;
    slot->lru = 0xFFFF;  // kept for compatibility (unused now)

    dbg_printf("Sampler stored: algorithm: %u, packetInterval: %u, spaceInterval: %u\n", slot->algorithm, slot->packetInterval, slot->spaceInterval);

    // CLI samplers go directly into cache (MRU front)
    if (sampler_record_v4->selectorID == SAMPLER_OVERWRITE || sampler_record_v4->selectorID == SAMPLER_DEFAULT) {
        dbg_printf("Cache %s sampler\n", sampler_record_v4->selectorID == SAMPLER_OVERWRITE ? "overwrite" : "default");

        CacheSampler(exporter_entry, slot);
    }

}  // End of InsertSampler

static sampler_record_v4_t *LookupSampler(exporter_entry_t *exporter, int64_t sampler_id) {
    sampler_record_v4_t *assigned = NULL;
    sampler_record_v4_t *generic = NULL;
    sampler_record_v4_t *deflt = NULL;

    dbg_printf("Lookup sampler: count: %u, samplerID: %lld, exporter id: %u, sysID: %u\n", exporter->sampler_count, sampler_id, exporter->info->id,
               exporter->sysID);

    if (exporter->sampler_count == 0) return NULL;

    // HOT PATH: cache only
    for (int i = 0; i < SAMPLER_CACHE_SIZE; i++) {
        sampler_record_v4_t *sampler = exporter->sampler_cache[i].ptr;
        if (!sampler) continue;

        switch (sampler->selectorID) {
            case SAMPLER_OVERWRITE:
                dbg_printf("Return found overwrite sampler\n");
                return sampler;

            case SAMPLER_DEFAULT:
                dbg_printf("Found default sampler\n");
                deflt = sampler;
                break;

            case SAMPLER_GENERIC:
                dbg_printf("Found generic sampler\n");
                generic = sampler;
                break;

            default:
                if (sampler->selectorID == sampler_id) {
                    dbg_printf("Return found assigned sampler ID\n");
                    return sampler;
                }
                break;
        }
    }

    if (generic && sampler_id == 0) return generic;

    // SLOW PATH: backend lookup
    dbg_printf("Search backend for sampler ID: %lld\n", sampler_id);

    sampler_record_v4_t *sampler = exporter->info->samplers;

    for (uint32_t i = 0; i < exporter->info->sampler_capacity; i++, sampler++) {
        if (!sampler->inUse) continue;

        if (!generic && sampler->selectorID == SAMPLER_GENERIC) {
            dbg_printf("Found generic sampler in backend slot %u\n", i);
            return CacheSampler(exporter, sampler);
        }

        if (sampler->selectorID == SAMPLER_OVERWRITE) {
            dbg_printf("Found overwrite sampler in backend slot %u\n", i);
            generic = CacheSampler(exporter, sampler);
        }

        if (sampler->selectorID == sampler_id) {
            dbg_printf("Found assigned sampler in backend slot %u\n", i);
            assigned = CacheSampler(exporter, sampler);
            break;
        }
    }

#ifdef DEVEL
    printf("Found assigned sampler: %s\n", assigned ? "true" : "false");
    printf("Found generic sampler : %s\n", generic ? "true" : "false");
    printf("Found default sampler : %s\n", deflt ? "true" : "false");
#endif

    // precedence
    if (assigned) return assigned;
    if (generic) return generic;
    // maybe NULL
    return deflt;

}  // End of LookupSampler

static template_t *getTemplate(exporter_entry_t *exporter_entry, uint16_t id) {
    exporter_v9_t *exporter_v9 = &exporter_entry->v9;

#ifdef DEVEL
    {
        printf("[%u] Get template - last template ID: %u\n", exporter_entry->info->id, exporter_v9->lastTemplateID);
        printf("[%u] Get template - available templates for exporter sysID: %u\n", exporter_entry->info->id, exporter_entry->sysID);
        template_t *template = exporter_v9->template;
        for (int i = 0; i < (int)exporter_v9->templateCapacity; i++) {
            if (template->id != 0) {
                printf(" [%d] ID: %u, type:, %u\n", i, template->id, template->type);
            }
            template++;
        }
    }
#endif

    // return lastTemplate, if id matches
    if (likely(exporter_v9->lastTemplateID == id)) return exporter_v9->lastTemplate;

    // search template
    uint32_t mask = exporter_v9->templateCapacity - 1;
    uint32_t idx = id & mask;
    template_t *template = exporter_v9->template;
    for (;;) {
        __builtin_prefetch(&template[(idx + 1) & mask]);
        if (template[idx].id == EMPTY_SLOT) {
            exporter_v9->lastTemplateID = 0;
            exporter_v9->lastTemplate = NULL;
            dbg_printf("[%u] Get template %u: not found\n", exporter_entry->info->id, id);
            return NULL;
        }
        if (template[idx].id == id) {
            exporter_v9->lastTemplateID = id;
            exporter_v9->lastTemplate = template + idx;
            dbg_printf("[%u] Get template %u: found at index %u\n", exporter_entry->info->id, id, idx);
            return exporter_v9->lastTemplate;
        }
        idx = (idx + 1) & mask;
    }

    // unreached
    return NULL;

}  // End of getTemplate

static void expand_template_table(exporter_v9_t *exporter_v9) {
    uint32_t old_cap = exporter_v9->templateCapacity;
    template_t *old_template = exporter_v9->template;

    uint32_t new_cap = exporter_v9->templateCapacity != 0 ? exporter_v9->templateCapacity * 2 : NUMTEMPLATES;
    template_t *new_template = calloc(new_cap, sizeof(template_t));
    if (!new_template) {
        LogError("expand_template_table() error calloc(): %s in %s:%d", strerror(errno), __FILE__, __LINE__);
        return;
    }
    dbg_printf("Expand exporter table: %u -> %u\n", old_cap, new_cap);

    exporter_v9->template = new_template;
    exporter_v9->templateCapacity = new_cap;
    exporter_v9->templateCount = 0;

    uint32_t mask = exporter_v9->templateCapacity - 1;
    for (int i = 0; i < (int)old_cap; i++) {
        template_t *t = &old_template[i];
        if (t->id == EMPTY_SLOT || t->id == DELETED_SLOT) continue;

        uint32_t idx = t->id & mask;
        while (new_template[idx].id > 0) idx = (idx + 1) & mask;

        new_template[idx] = *t;
        exporter_v9->templateCount++;
    }

    dbg_printf("Expand exporter table count: %u\n", exporter_v9->templateCount);

    if (old_template) free(old_template);
}  // End of expand_template_table

static template_t *newTemplate(exporter_v9_t *exporter_v9, uint16_t id) {
    if (((exporter_v9->templateCount + exporter_v9->templateDeleted) * 4) >= (exporter_v9->templateCapacity * 3)) {
        // expand exporter index
        expand_template_table(exporter_v9);
    }

    int firstDeleted = -1;
    template_t *template = exporter_v9->template;
    uint32_t mask = exporter_v9->templateCapacity - 1;
    uint32_t idx = id & mask;
    for (;;) {
        __builtin_prefetch(&template[(idx + 1) & mask]);
        if (template[idx].id == EMPTY_SLOT) {
            if (firstDeleted != -1) idx = firstDeleted;
            template[idx] = (template_t){.id = id, .updated = time(NULL), .data = NULL};

            exporter_v9->templateCount++;
            exporter_v9->lastTemplateID = id;
            exporter_v9->lastTemplate = template + idx;
            dbg_printf("New template %u at %u\n", id, idx);
            return exporter_v9->lastTemplate;
        }

        if (template[idx].id == DELETED_SLOT && firstDeleted == -1) firstDeleted = idx;
        idx = (idx + 1) & mask;
    }

    return template;

}  // End of newTemplate

static int removeTemplate(exporter_v9_t *exporter_v9, uint16_t id) {
    if (exporter_v9->templateCapacity == 0) return 0;

    uint32_t mask = exporter_v9->templateCapacity - 1;
    uint32_t idx = id & mask;
    template_t *table = exporter_v9->template;

    for (;;) {
        if (table[idx].id == EMPTY_SLOT) {
            // not found
            return 0;
        }

        if (table[idx].id == id) {
            // free attached data if needed
            if (table[idx].data) {
                free(table[idx].data);
                table[idx].data = NULL;
            }

            // mark as deleted
            table[idx].id = DELETED_SLOT;

            exporter_v9->templateCount--;
            exporter_v9->templateDeleted++;

            // invalidate cache
            if (exporter_v9->lastTemplateID == id) {
                exporter_v9->lastTemplateID = 0;
                exporter_v9->lastTemplate = NULL;
            }

            return 1;
        }

        idx = (idx + 1) & mask;
    }
}  // End of removeTemplate

static inline void Process_v9_templates(exporter_entry_t *exporter_entry, const uint8_t *DataPtr, FlowSource_t *fs) {
    uint32_t size_left = GET_FLOWSET_LENGTH(DataPtr);
    size_left -= 4;                            // -4 for flowset header -> id and length
    const uint8_t *templatePtr = DataPtr + 4;  // the template description begins at offset 4

    // process all templates in flowset, as long as any bytes are left
    uint32_t size_required = 0;
    while (size_left) {
        templatePtr = templatePtr + size_required;

        if (size_left < 4) {
            LogError("Process_v9: [%u] buffer size error: flowset length error in %s:%u", exporter_entry->info->id, __FILE__, __LINE__);
            return;
        }

        uint16_t id = GET_TEMPLATE_ID(templatePtr);
        uint16_t count = GET_TEMPLATE_COUNT(templatePtr);
        size_required = 4 + 4 * count;  // id + count = 4 bytes, and 2 x 2 bytes for each entry

        dbg_printf("\n[%u] Template ID: %u, field count: %u\n", exporter_entry->info->id, id, count);
        dbg_printf("template size: %u buffersize: %u\n", size_required, size_left);

        if (size_left < size_required) {
            LogError("Process_v9: [%u] buffer size error: expected %u available %u", exporter_entry->info->id, size_required, size_left);
            return;
        }

        // temp instruction array
        pipelineInstr_t instruction[count + 2];  // +2 for IP received, time received
        memset(instruction, 0, sizeof(instruction));
        pipelineInstr_t *instr = instruction;
        pipelineInstr_t *prev = NULL;

        // instruction counter
        const uint8_t *p = templatePtr + 4;  // type/length pairs start at template offset 4
        int commonFound = 0;
        for (int i = 0; i < (int)count; i++) {
            uint32_t EnterpriseNumber = 0;

            uint16_t type = getVal16(p);
            uint16_t inLength = getVal16(p);

            int index = LookupElement(type, EnterpriseNumber);
            if (index < 0) {
                // not found - add skip sequence
                // var length skip cannot be stacked
                if (inLength != VARLENGTH && prev && prev->transform == SKIP_INPUT) {
                    // compact multiple skip instructions
                    prev->inLength += inLength;
                    dbg_printf("Add %u bytes to previous skip instruction\n", inLength);
                    continue;
                }
                *instr = (pipelineInstr_t){
                    .transform = SKIP_INPUT,
                    .type = type,
                    .inLength = inLength,
                };
                dbg_printf("Skip unknown element type: %u, length: %u\n", type, inLength);
            } else {
                *instr = (pipelineInstr_t){
                    .type = type,
                    .inLength = inLength,
                    .extID = v9TranslationMap[index].extensionID,
                    .dstOffset = v9TranslationMap[index].offsetRel,
                    .transform = v9TranslationMap[index].transform,
                    .outLength = v9TranslationMap[index].outputLength,
                };

                dbg_printf("Map type: %u, length: %u to Extension %u - '%s' - output length: %u\n", type, inLength,
                           v9TranslationMap[index].extensionID, v9TranslationMap[index].name, v9TranslationMap[index].outputLength);
                commonFound++;
            }
            prev = instr;
            instr++;
        }
        dbg_printf("Processed: %u, common elements: %u\n", size_required, commonFound);

        if (commonFound == 0) {
            size_left -= size_required;
            DataPtr = DataPtr + size_required + 4;  // +4 for header
            dbg_printf("Template does not contain common elements - skip\n");
            continue;
        }

        // reserve space for IP received
        if (fs->sa_family == PF_INET6 && ExtensionsEnabled[EXipReceivedV6ID]) {
            *instr++ = (pipelineInstr_t){
                .transform = MOVE_IPV6_RVD,
                .extID = EXipReceivedV6ID,
                .dstOffset = OFFReceived6IP,
                .outLength = SIZEReceived6IP,
            };
            dbg_printf("Map type: receivedV6, length: 16 to Extension %u - '%s' - output length: %lu\n", EXipReceivedV6ID,
                       extensionTable[EXipReceivedV6ID].name, SIZEReceived6IP);
        }
        if (fs->sa_family == PF_INET && ExtensionsEnabled[EXipReceivedV4ID]) {
            *instr++ = (pipelineInstr_t){
                .transform = MOVE_IPV4_RVD,
                .extID = EXipReceivedV4ID,
                .dstOffset = OFFReceived4IP,
                .outLength = SIZEReceived4IP,
            };
            dbg_printf("Map type: receivedV4, length: 4 to Extension %u - '%s' - output length: %lu\n", EXipReceivedV4ID,
                       extensionTable[EXipReceivedV4ID].name, SIZEReceived4IP);
        }

        int index = LookupElement(LOCAL_msecTimeReceived, 0);
        *instr++ = (pipelineInstr_t){
            .type = v9TranslationMap[index].id,
            .inLength = 0,
            .extID = v9TranslationMap[index].extensionID,
            .dstOffset = v9TranslationMap[index].offsetRel,
            .transform = v9TranslationMap[index].transform,
            .outLength = v9TranslationMap[index].outputLength,
        };
        dbg_printf("Map type: %u, length: %u to Extension %u - '%s' - output length: %u\n", LOCAL_msecTimeReceived, 8,
                   v9TranslationMap[index].extensionID, v9TranslationMap[index].name, v9TranslationMap[index].outputLength);

        uint32_t cnt = (instr - instruction);
        pipeline_t *pipeline = PipelineCompile(instruction, id, cnt);
        if (!pipeline) {
            LogError("Process_v9: PipelineCompile() failed");
            return;
        }
        dbg(PrintPipeline(pipeline));

        // if it exists - remove old template on exporter with same ID
        template_t *template = getTemplate(exporter_entry, id);
        if (template) {
            // clean existing template
            if (template->data) free(template->data);
            template->updated = time(NULL);
            dbg_printf("Update/refresh template ID: %u\n", id);
        } else {
            template = newTemplate(&(exporter_entry->v9), id);
            dbg_printf("New template ID: %u\n", id);
        }

        if (!template) {
            LogError("Process_v9: abort template add: %s line %d", __FILE__, __LINE__);
            free(pipeline);
            return;
        }
        template->type = DATA_TEMPLATE;
        template->data = pipeline;
        SetFlag(template->type, DATA_TEMPLATE);

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

static inline void Process_v9_option_templates(exporter_entry_t *exporter_entry, const uint8_t *option_template_flowset, FlowSource_t *fs) {
    uint32_t size_left = GET_FLOWSET_LENGTH(option_template_flowset) - 4;  // -4 for flowset header -> id and length
    const uint8_t *option_template = option_template_flowset + 4;

    // process all option templates in flowset
    while (size_left >= 6) {  // minimum option template header: id(2) + scope_length(2) + option_length(2)
        uint16_t tableID = GET_OPTION_TEMPLATE_ID(option_template);
        uint16_t scope_length = GET_OPTION_TEMPLATE_FIELD_COUNT(option_template);
        uint16_t option_length = GET_OPTION_TEMPLATE_SCOPE_FIELD_COUNT(option_template);

        // size consumed by this option template: 6 byte header + scope fields + option fields
        uint32_t template_size = 6 + scope_length + option_length;

        if (scope_length & 0x3) {
            LogError("Process_v9: [%u] scope length error: length %u not multiple of 4", exporter_entry->info->id, scope_length);
            return;
        }

        if (option_length & 0x3) {
            LogError("Process_v9: [%u] option length error: length %u not multiple of 4", exporter_entry->info->id, option_length);
            return;
        }

        if (template_size > size_left) {
            LogError(
                "Process_v9: [%u] option template length error: size left %u too small for %u scopes "
                "length and %u options length",
                exporter_entry->info->id, size_left, scope_length, option_length);
            return;
        }

        uint32_t nr_scopes = scope_length >> 2;
        uint32_t nr_options = option_length >> 2;

        dbg_printf("\n[%u] Option Template ID: %u\n", exporter_entry->info->id, tableID);
        dbg_printf("Scope length: %u Option length: %u\n", scope_length, option_length);

        optionTemplate_t *optionTemplate = (optionTemplate_t *)calloc(1, sizeof(optionTemplate_t));
        if (!optionTemplate) {
            LogError("Error calloc(): %s in %s:%d", strerror(errno), __FILE__, __LINE__);
            return;
        }

        const uint8_t *p = option_template + 6;  // start of length/type data

        struct samplerOption_s *samplerOption = &(optionTemplate->samplerOption);
        struct nbarOptionList_s *nbarOption = &(optionTemplate->nbarOption);
        struct nameOptionList_s *ifnameOptionList = &(optionTemplate->ifnameOption);
        struct nameOptionList_s *vrfnameOptionList = &(optionTemplate->vrfnameOption);

        uint16_t scopeSize = 0;
        uint16_t offset = 0;
        for (int i = 0; i < (int)(nr_scopes + nr_options); i++) {
            uint16_t type = Get_val16(p);
            p = p + 2;
            uint16_t length = Get_val16(p);
            p = p + 2;
            if (i < (int)nr_scopes) {
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

        dbg_printf("\n[%u] Option size: %" PRIu64 ", flags: %" PRIx64 "\n", exporter_entry->info->id, optionTemplate->optionSize,
                   optionTemplate->flags);
        if (optionTemplate->flags) {
            template_t *template = getTemplate(exporter_entry, tableID);
            if (template) {
                // clean existing template
                if (template->data) free(template->data);
                dbg_printf("Update/refresh option template ID: %u\n", tableID);
            } else {
                template = newTemplate(&(exporter_entry->v9), tableID);
                dbg_printf("New template ID: %u\n", tableID);
            }

            if (!template) {
                LogError("Process_ipfix: Failed option template add: %s line %d", __FILE__, __LINE__);
                free(optionTemplate);
                return;
            }
            template->updated = time(NULL);
            template->data = optionTemplate;

            if ((optionTemplate->flags & SAMPLERFLAGS) == SAMPLERFLAGS) {
                dbg_printf("[%u] New Sampler information found\n", exporter_entry->info->id);
                SetFlag(template->type, SAMPLER_TEMPLATE);
            } else if ((optionTemplate->flags & SAMPLERSTDFLAGS) == SAMPLERSTDFLAGS) {
                dbg_printf("[%u] New std sampling information found\n", exporter_entry->info->id);
                SetFlag(template->type, SAMPLER_TEMPLATE);
            } else if ((optionTemplate->flags & STDMASK) == STDFLAGS) {
                dbg_printf("[%u] Old std sampling information found\n", exporter_entry->info->id);
                SetFlag(template->type, SAMPLER_TEMPLATE);
            } else if ((optionTemplate->flags & STDSAMPLING34) == STDSAMPLING34) {
                dbg_printf("[%u] Old std sampling information found - missing algorithm\n", exporter_entry->info->id);
                samplerOption->algorithm.length = 0;
                samplerOption->algorithm.offset = 0;
                SetFlag(template->type, SAMPLER_TEMPLATE);
            } else {
                dbg_printf("[%u] No Sampling information found\n", exporter_entry->info->id);
            }

            if (TestFlag(optionTemplate->flags, NBAROPTIONS)) {
                if (nbarOption->id.length == 0) {
                    LogError("Process_v9: [%u] nbar option missing mandatory ID field - skip", exporter_entry->info->id);
                    ClearFlag(optionTemplate->flags, NBAROPTIONS);
                } else {
                    dbg_printf("[%u] found nbar option\n", exporter_entry->info->id);
                    dbg_printf("[%u] id   length: %u\n", exporter_entry->info->id, optionTemplate->nbarOption.id.length);
                    dbg_printf("[%u] name length: %u\n", exporter_entry->info->id, optionTemplate->nbarOption.name.length);
                    dbg_printf("[%u] desc length: %u\n", exporter_entry->info->id, optionTemplate->nbarOption.desc.length);
                    optionTemplate->nbarOption.scopeSize = scopeSize;
                    SetFlag(template->type, NBAR_TEMPLATE);
                }
            } else {
                dbg_printf("[%u] No nbar information found\n", exporter_entry->info->id);
            }

            if (TestFlag(optionTemplate->flags, IFNAMEOPTION)) {
                dbg_printf("[%u] found ifname option\n", exporter_entry->info->id);
                dbg_printf("[%u] ingress length: %u\n", exporter_entry->info->id, optionTemplate->ifnameOption.ingress.length);
                dbg_printf("[%u] name length  : %u\n", exporter_entry->info->id, optionTemplate->ifnameOption.name.length);
                optionTemplate->ifnameOption.scopeSize = scopeSize;
                SetFlag(template->type, IFNAME_TEMPLATE);
            } else {
                dbg_printf("[%u] No ifname information found\n", exporter_entry->info->id);
            }

            if (TestFlag(optionTemplate->flags, VRFNAMEOPTION)) {
                dbg_printf("[%u] found vrfname option\n", exporter_entry->info->id);
                dbg_printf("[%u] ingress length: %u\n", exporter_entry->info->id, optionTemplate->vrfnameOption.ingress.length);
                dbg_printf("[%u] name length  : %u\n", exporter_entry->info->id, optionTemplate->vrfnameOption.name.length);
                optionTemplate->vrfnameOption.scopeSize = scopeSize;
                SetFlag(template->type, VRFNAME_TEMPLATE);
            } else {
                dbg_printf("[%u] No vrfname information found\n", exporter_entry->info->id);
            }

            if (TestFlag(optionTemplate->flags, SYSUPOPTION)) {
                dbg_printf("[%u] SysUp information found. length: %u\n", exporter_entry->info->id, optionTemplate->SysUpOption.length);
                SetFlag(template->type, SYSUPTIME_TEMPLATE);
            } else {
                dbg_printf("[%u] No SysUp information found\n", exporter_entry->info->id);
            }

        } else {
            free(optionTemplate);
            dbg_printf("[%u] Skip option template\n", exporter_entry->info->id);
        }

        processed_records++;

        // advance to next option template in flowset
        size_left -= template_size;
        option_template += template_size;
    }  // End of while size_left

}  // End of Process_v9_option_templates

static inline void Process_v9_data(exporter_entry_t *exporter_entry, const uint8_t *data_flowset, FlowSource_t *fs, const pipeline_t *pipeline) {
    exporter_v9_t *exporter_v9 = &exporter_entry->v9;

    int32_t size_left = GET_FLOWSET_LENGTH(data_flowset) - 4;  // -4 for data flowset header -> id and length

    // map input buffer as a byte array
    const uint8_t *inBuff = data_flowset + 4;  // skip flowset header

    dbg_printf("[%u] Process data flowset size: %u\n", exporter_entry->info->id, size_left);
    dbg_printf("Datablock type: %u, size: %u\n", fs->dataBlock->type, fs->dataBlock->rawSize);

    // general runtime parameters for pipiling processor, common for all flows
    pipelineRuntime_t runtime = {.SysUptime = exporter_v9->sysUptime,
                                 .unix_secs = exporter_v9->unix_secs,
                                 .secExported = 0,
                                 .ipReceived = fs->ipAddr,
                                 .msecReceived = ((uint64_t)fs->received.tv_sec * 1000LL) + (uint64_t)((uint64_t)fs->received.tv_usec / 1000LL)};

    while (size_left > 0) {
        if (size_left < 4) {  // rounding pads
            size_left = 0;
            continue;
        }

        // check for enough space in output buffer
        uint32_t outRecordSize = pipeline->recordSize == VARLENGTH ? 1024 : pipeline->recordSize;
        if (!IsAvailable(fs->dataBlock, BLOCK_SIZE_V3, sizeof(recordHeaderV4_t) + outRecordSize)) {
            // flush block - get an empty one
            PushBlockV3(fs->blockQueue, fs->dataBlock);
            fs->dataBlock = NULL;
            InitDataBlock(fs->dataBlock, BLOCK_SIZE_V3);
        }

        int buffAvail = BLOCK_SIZE_V3 - fs->dataBlock->rawSize;
        if (buffAvail == 0) {
            // this should really never occur, because the buffer gets flushed earlier
            LogError("Process_v9: output buffer size error. Skip v9 record processing");
            return;
        }

        recordHeaderV4_t *recordHeaderV4 = NULL;
        void *outBuff;
        int redone = 0;
        ssize_t processed = 0;
        do {
            // map file record to output buffer
            outBuff = GetCursor(fs->dataBlock);
            dbg_printf("Redone: %u\n", redone);
            dbg_printf("[%u] Process data record: %u offset: %ld, size_left: %u buff_avail: %u\n", exporter_entry->info->id, processed_records,
                       (inBuff - data_flowset), size_left, buffAvail);

            // process record
            recordHeaderV4 = AddV4Header(outBuff);

            // header data
            recordHeaderV4->engineType = (exporter_entry->info->id >> 8) & 0xFF;
            recordHeaderV4->engineID = exporter_entry->info->id & 0xFF;
            recordHeaderV4->nfVersion = 9;
            recordHeaderV4->exporterID = exporter_entry->info->sysID;

            // copy record data
            memset(runtime.rtRegister, 0, sizeof(runtime.rtRegister));
            runtime.genericRecord = NULL;
            runtime.cntRecord = NULL;
            processed = PipelineRun(pipeline, inBuff, size_left, outBuff, buffAvail, &runtime);
            switch (processed) {
                case PIP_ERR_SHORT_INPUT:
                    LogError("Process v9: PipelineRun() short input. Skip record processing");
                    processed = size_left;
                    break;
                case PIP_ERR_SHORT_OUTPUT:
                    if (buffAvail == BLOCK_SIZE_V3) {
                        LogError("Process v9: PipelineRun() short output. Skip record processing");
                        return;
                    }

                    LogVerbose("Process v9: PipelinRun() resize output buffer");
                    // request new and empty buffer
                    PushBlockV3(fs->blockQueue, fs->dataBlock);
                    fs->dataBlock = NULL;
                    InitDataBlock(fs->dataBlock, BLOCK_SIZE_V3);
                    if (fs->dataBlock == NULL) {
                        return;
                    }

                    buffAvail = BLOCK_SIZE_V3 - fs->dataBlock->rawSize;
                    if (buffAvail == 0 || redone) {
                        // this should really never happen, because the buffer got flushed
                        LogError("Process_v9: output buffer size error. Skip v9 record processing");
                        return;
                    }
                    redone++;
                    break;
                case PIP_ERR_RUNTIME_INPUT:
                    LogError("Process_v9: runtime buffer error. Skip v9 record processing");
                    return;
                    break;
                case PIP_ERR_RUNTIME_ERROR:
                    LogError("Process_v9: pipeline runtime error. Skip v9 record processing");
                    break;
                default:
                    dbg_printf("New record added with %u elements and size: %u, processed inLength: %zu\n", recordHeaderV4->numExtensions,
                               recordHeaderV4->size, processed);
            }
            // process < 0 means error pipeline processing
        } while (processed < 0 && redone < 2);

        if (processed <= 0) {
            LogError("Process_v9: pipeline processing error: %zd. Skip v9 record processing", processed);
            return;
        }

        dbg_printf("Record: %u elements, size: %u\n", recordHeaderV4->numExtensions, recordHeaderV4->size);

        outBuff += recordHeaderV4->size;
        inBuff += processed;
        size_left -= processed;

        processed_records++;

        /* XXX FIX!
        if (stack[STACK_ENGINE_TYPE]) recordHeaderV4->engineType = stack[STACK_ENGINE_TYPE];
        if (stack[STACK_ENGINE_ID]) recordHeaderV4->engineID = stack[STACK_ENGINE_ID];
        */

        // handle sampling
        // either 0 for no sampler or announced samplerID
        uint64_t packetInterval = 1;
        uint64_t spaceInterval = 0;
        uint64_t intervalTotal = 0;
        sampler_record_v4_t *sampler = NULL;
        uint32_t sampler_id = runtime.rtRegister[2];
        if (exporter_entry->info->sampler_count > 0) {
            sampler = LookupSampler(exporter_entry, sampler_id);
        }
        if (sampler) {
            packetInterval = sampler->packetInterval;
            spaceInterval = sampler->spaceInterval;
            intervalTotal = packetInterval + spaceInterval;

            SetFlag(recordHeaderV4->flags, V4_FLAG_SAMPLED);
#ifdef DEVEL
            char *samplerType;
            switch (sampler->selectorID) {
                case SAMPLER_OVERWRITE:
                    samplerType = "Overwrite sampler";
                    break;
                case SAMPLER_DEFAULT:
                    samplerType = "Default sampler";
                    break;
                case SAMPLER_GENERIC:
                    samplerType = "Generic sampler";
                    break;
                default:
                    samplerType = "Assigned sampler";
            }
            printf("[%u] %s - packet interval: %u, packet space: %u\n", exporter_entry->info->id, samplerType, sampler->packetInterval,
                   sampler->spaceInterval);
        } else {
            printf("[%u] No sampler\n", exporter_entry->info->id);
#endif
        }

        EXgenericFlow_t *genericFlow = runtime.genericRecord;
        if (likely(genericFlow != NULL)) {
            //    genericFlow->msecReceived = ((uint64_t)fs->received.tv_sec * 1000LL) + (uint64_t)((uint64_t)fs->received.tv_usec / 1000LL);

            // update first_seen, last_seen
            UpdateFirstLast(fs->dataBlock, genericFlow->msecFirst, genericFlow->msecLast);
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
                    fs->stat_record.numflows_icmp++;
                    fs->stat_record.numpackets_icmp += genericFlow->inPackets;
                    fs->stat_record.numbytes_icmp += genericFlow->inBytes;
                    // fix odd CISCO behaviour for ICMP port/type in src port
                    if (genericFlow->srcPort != 0) {
                        uint8_t *s1 = (uint8_t *)&(genericFlow->srcPort);
                        uint8_t *s2 = (uint8_t *)&(genericFlow->dstPort);
                        s2[0] = s1[1];
                        s2[1] = s1[0];
                    }
                    // srcPort is always 0
                    genericFlow->srcPort = 0;
                    if (runtime.rtRegister[0] != 0 || runtime.rtRegister[1] != 0) {
                        if (runtime.rtRegister[1] > 256) {
                            // icmp #032 #139
                            genericFlow->dstPort = runtime.rtRegister[1];
                        } else {
                            // icmp type and code elements #176 #177 #178 #179
                            genericFlow->dstPort = (runtime.rtRegister[0] << 8) + runtime.rtRegister[1];
                        }
                    }
                    break;
                case IPPROTO_TCP:
                    fs->stat_record.numflows_tcp++;
                    fs->stat_record.numpackets_tcp += genericFlow->inPackets;
                    fs->stat_record.numbytes_tcp += genericFlow->inBytes;
                    break;
                case IPPROTO_UDP:
                    fs->stat_record.numflows_udp++;
                    fs->stat_record.numpackets_udp += genericFlow->inPackets;
                    fs->stat_record.numbytes_udp += genericFlow->inBytes;
                    break;
                default:
                    fs->stat_record.numflows_other++;
                    fs->stat_record.numpackets_other += genericFlow->inPackets;
                    fs->stat_record.numbytes_other += genericFlow->inBytes;
            }

            exporter_entry->flows++;
            fs->stat_record.numflows++;
            fs->stat_record.numpackets += genericFlow->inPackets;
            fs->stat_record.numbytes += genericFlow->inBytes;

            uint32_t exporterIdent = MetricExpporterID(recordHeaderV4);
            UpdateMetric(fs->Ident, exporterIdent, genericFlow);
        }

        EXcntFlow_t *cntFlow = runtime.cntRecord;
        if (cntFlow) {
            if (spaceInterval > 0) {
                cntFlow->outPackets = cntFlow->outPackets * intervalTotal / (uint64_t)packetInterval;
                cntFlow->outBytes = cntFlow->outBytes * intervalTotal / (uint64_t)packetInterval;
            }
            if (cntFlow->flows == 0) cntFlow->flows++;
            fs->stat_record.numpackets += cntFlow->outPackets;
            fs->stat_record.numbytes += cntFlow->outBytes;
        }

        // handle event time for NSEL/ASA and NAT
        EXnselCommon_t *nselCommon = GetExtension(recordHeaderV4, EXnselCommon);
        if (unlikely(nselCommon != NULL && genericFlow != NULL)) {
            dbg_printf("Entry msecFrist: %" PRIu64 "\n", genericFlow->msecFirst);
            dbg_printf("Entry msecLast : %" PRIu64 "\n", genericFlow->msecLast);
            dbg_printf("Entry Nsel time: %" PRIu64 "\n", nselCommon->msecEvent);
            if (nselCommon->msecEvent) {
                if (genericFlow->msecFirst == 0) {
                    dbg_printf("Copy nsel Event time: %" PRIu64 " overwriting %" PRIu64 "\n", nselCommon->msecEvent, genericFlow->msecFirst);
                    genericFlow->msecFirst = nselCommon->msecEvent;
                }
            } else {
                dbg_printf("Copy msecFirst to nsel Event time: %" PRIu64 "\n", genericFlow->msecFirst);
                nselCommon->msecEvent = genericFlow->msecFirst;
            }
            genericFlow->msecLast = genericFlow->msecFirst;
            SetFlag(recordHeaderV4->flags, V4_FLAG_EVENT);
            dbg_printf("Nsel event time: %" PRIu64 "\n", nselCommon->msecEvent);
        }
        dbg_printf("Final msecFrist: %" PRIu64 "\n", genericFlow ? genericFlow->msecFirst : 0);
        dbg_printf("Final msecLast : %" PRIu64 "\n", genericFlow ? genericFlow->msecLast : 0);

        if (printRecord) {
            flow_record_short(stdout, recordHeaderV4);
        }

        fs->dataBlock->rawSize += recordHeaderV4->size;
        fs->dataBlock->numRecords++;

        // buffer size sanity check
        if (fs->dataBlock->rawSize >= BLOCK_SIZE_V3) {
            // should never happen
            LogError("Process v9: Output buffer overflow! Flush buffer and skip records.");
            LogError("Buffer size: %u > %u", fs->dataBlock->rawSize, BLOCK_SIZE_V3);

            // reset buffer
            *fs->dataBlock = (flowBlockV3_t){.type = BLOCK_TYPE_FLOW, .rawSize = sizeof(flowBlockV3_t)};
            fs->dataBlock->numRecords = 0;
            return;
        }
    }

}  // End of Process_v9_data

static inline void Process_v9_sampler_option_data(exporter_entry_t *exporter_entry, FlowSource_t *fs, template_t *template,
                                                  const uint8_t *data_flowset) {
    uint32_t size_left = GET_FLOWSET_LENGTH(data_flowset) - 4;  // -4 for data flowset header -> id and length
    dbg_printf("[%u] Process sampler option data flowset size: %u\n", exporter_entry->info->id, size_left);

    // map input buffer as a byte array
    uint8_t *in = (uint8_t *)(data_flowset + 4);  // skip flowset header

    optionTemplate_t *optionTemplate = (optionTemplate_t *)template->data;
    struct samplerOption_s *samplerOption = &(optionTemplate->samplerOption);

    sampler_record_v4_t sampler_record = {0};
    if ((optionTemplate->flags & SAMPLERSTDFLAGS) != 0) {
        sampler_record.inUse = 1;
        if (CHECK_OPTION_DATA(size_left, samplerOption->id)) {
            sampler_record.selectorID = Get_val(in, samplerOption->id.offset, samplerOption->id.length);
        }

        if (CHECK_OPTION_DATA(size_left, samplerOption->algorithm)) {
            sampler_record.algorithm = Get_val(in, samplerOption->algorithm.offset, samplerOption->algorithm.length);
        }

        if (CHECK_OPTION_DATA(size_left, samplerOption->packetInterval)) {
            sampler_record.packetInterval = Get_val(in, samplerOption->packetInterval.offset, samplerOption->packetInterval.length);
        }

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
                sampler_record.inUse = 0;
            }
        }

        dbg_printf("Extracted Sampler data:\n");
        if (sampler_record.selectorID == 0) {
            sampler_record.selectorID = SAMPLER_GENERIC;
            dbg_printf("New std sampler: algorithm : %u, packet interval: %u, packet space: %u\n", sampler_record.algorithm,
                       sampler_record.packetInterval, sampler_record.spaceInterval);
        } else {
            dbg_printf("ID : %" PRId64 ", algorithm : %u, packet interval: %u, packet space: %u\n", sampler_record.selectorID,
                       sampler_record.algorithm, sampler_record.packetInterval, sampler_record.spaceInterval);
        }
    }

    if ((optionTemplate->flags & STDMASK) != 0) {
        // map plain interval data into packet space/interval
        sampler_record.inUse = 1;
        sampler_record.selectorID = SAMPLER_GENERIC;
        sampler_record.packetInterval = 1;
        if (CHECK_OPTION_DATA(size_left, samplerOption->algorithm)) {
            sampler_record.algorithm = Get_val(in, samplerOption->algorithm.offset, samplerOption->algorithm.length);
        }
        if (CHECK_OPTION_DATA(size_left, samplerOption->spaceInterval)) {
            sampler_record.spaceInterval = Get_val(in, samplerOption->spaceInterval.offset, samplerOption->spaceInterval.length);
            if (sampler_record.spaceInterval) {
                sampler_record.spaceInterval--;
            } else {
                sampler_record.inUse = 0;
                LogError("Process_v9_option: Zero sampling interval -> sampling == 1", __FILE__, __LINE__);
            }
        }
        dbg_printf("ID : %" PRId64 ", algorithm : %u, packet interval: %u, packet space: %u\n", sampler_record.selectorID, sampler_record.algorithm,
                   sampler_record.packetInterval, sampler_record.spaceInterval);
    }

    if (sampler_record.inUse) InsertSampler(exporter_entry, &sampler_record);
    processed_records++;

}  // End of Process_v9_sampler_option_data

static void Process_v9_nbar_option_data(exporter_entry_t *exporter_entry, FlowSource_t *fs, template_t *template, const uint8_t *data_flowset) {
    uint32_t size_left = GET_FLOWSET_LENGTH(data_flowset) - 4;  // -4 for data flowset header -> id and length
    dbg_printf("[%u] Process nbar option data flowset size: %u\n", exporter_entry->info->id, size_left);

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
    dbg_printf("[%u] nbar option data - records: %u, size: %zu\n", exporter_entry->info->id, numRecords, option_size);

    if (numRecords == 0 || option_size == 0 || option_size > size_left) {
        LogError("Process_nbar_option: nbar option size error: option size: %zu, size left: %u", option_size, size_left);
        return;
    }

    // validate field offsets/lengths fit within option record
    if (!CHECK_OPTION_DATA(option_size, nbarOption->id) || !CHECK_OPTION_DATA(option_size, nbarOption->name) ||
        !CHECK_OPTION_DATA(option_size, nbarOption->desc)) {
        LogError("Process_nbar_option: field offset/length exceeds option record size");
        return;
    }

    if (data_size == 0) {
        LogError("Process_nbar_option: all nbar field lengths are 0");
        return;
    }

    // final element size in array block
    size_t elementSize = ALIGN8(data_size + 3);  // add 3 length bytes
    // number of elements per block
    uint32_t numElements = (BLOCK_SIZE_V3 - sizeof(arrayBlockV3_t)) / elementSize;
    if (numElements == 0) {
        LogError("Process_nbar_option: nbar element too large for block");
        return;
    }
    // number of blocks needed
    uint32_t numBlocks = (numRecords / numElements) + 1;

    dbg_printf("Nbar dump: numRecords: %u, numElements: %u, elementSize: %zu, numBLocks: %u\n", numRecords, numElements, elementSize, numBlocks);

    // write these number of array blocks
    arrayBlockV3_t *arrayBlock = NULL;
    for (int nb = 0; nb < (int)numBlocks; nb++) {
        arrayBlock = (arrayBlockV3_t *)NewDataBlock(BLOCK_SIZE_V3);
        *arrayBlock = (arrayBlockV3_t){
            .type = BLOCK_TYPE_ARRAY,
            .rawSize = sizeof(arrayBlockV3_t),
            .elementType = NbarRecordType,
            .elementSize = elementSize,
        };

        int cnt = 0;
        uint8_t *outBuff = GetCursor(arrayBlock);
        while ((cnt++ < (int)numElements) && (size_left >= option_size)) {
            uint8_t *p = outBuff;
            p[0] = nbarOption->id.length;
            p[1] = nbarOption->name.length;
            p[2] = nbarOption->desc.length;
            p += 3;

            // copy data
            // id octet array
            if (nbarOption->id.length) {
                memcpy(p, inBuff + nbarOption->id.offset, nbarOption->id.length);
                p += nbarOption->id.length;
            }

            // name string
            int err = 0;
            if (nbarOption->name.length) {
                memcpy(p, inBuff + nbarOption->name.offset, nbarOption->name.length);
                uint32_t state = UTF8_ACCEPT;
                if (validate_utf8(&state, (char *)p, nbarOption->name.length) == UTF8_REJECT) {
                    LogError("Process_nbar_option: validate_utf8() %s line %d: %s", __FILE__, __LINE__, "invalid utf8 nbar name");
                    err++;
                }
                p[nbarOption->name.length - 1] = '\0';
                p += nbarOption->name.length;
            }

            // description string
            if (nbarOption->desc.length) {
                memcpy(p, inBuff + nbarOption->desc.offset, nbarOption->desc.length);
                uint32_t state = UTF8_ACCEPT;
                if (validate_utf8(&state, (char *)p, nbarOption->desc.length) == UTF8_REJECT) {
                    LogError("Process_nbar_option: validate_utf8() %s line %d: %s", __FILE__, __LINE__, "invalid utf8 nbar description");
                    err++;
                }
                p[nbarOption->desc.length - 1] = '\0';
            }

#ifdef DEVEL
            if (err == 0) {
                printf("nbar record: %d, idLen: %u, nameLen: %u, descLen: %u\n", cnt, outBuff[0], outBuff[1], outBuff[2]);
                printf("nbar record: %d, name: %s, desc: %s\n", cnt, nbarOption->name.length ? (char *)(p - nbarOption->name.length) : "NULL",
                       nbarOption->desc.length ? (char *)p : "NULL");
            } else {
                printf("Invalid nbar information - skip record\n");
            }
#endif

            // in case of an err we do not store this record
            if (err == 0) {
                // valid record - advance output
                outBuff += elementSize;
                arrayBlock->numElements++;
                arrayBlock->rawSize += elementSize;
            }
            inBuff += option_size;
            size_left -= option_size;
        }

        // write array block only if it contains elements
        if (arrayBlock->numElements > 0) {
            dbg_printf("Push ARRAYBLOCK: %u elements\n", arrayBlock->numElements);
            PushBlockV3(fs->blockQueue, arrayBlock);
            arrayBlock = NULL;
        }
    }
    FreeDataBlock(arrayBlock);

    if (size_left > 7) {
        LogVerbose("Process nbar data record - %u extra bytes", size_left);
    }
    processed_records++;

}  // End of Process_v9_nbar_option_data

static void Process_v9_ifvrf_option_data(exporter_entry_t *exporter_entry, FlowSource_t *fs, int type, template_t *template,
                                         const uint8_t *data_flowset) {
    uint32_t size_left = GET_FLOWSET_LENGTH(data_flowset) - 4;  // -4 for data flowset header -> id and length
    dbg_printf("[%u] Process ifvrf option data flowset size: %u\n", exporter_entry->info->id, size_left);

    uint32_t recordType = 0;
    optionTemplate_t *optionTemplate = (optionTemplate_t *)template->data;
    struct nameOptionList_s *nameOption = NULL;
    switch (type) {
        case IFNAME_TEMPLATE:
            nameOption = &(optionTemplate->ifnameOption);
            recordType = IfNameRecordType;
            dbg_printf("[%u] Process if name option data flowset size: %u\n", exporter_entry->info->id, size_left);
            break;
        case VRFNAME_TEMPLATE:
            nameOption = &(optionTemplate->vrfnameOption);
            recordType = VrfNameRecordType;
            dbg_printf("[%u] Process vrf name option data flowset size: %u\n", exporter_entry->info->id, size_left);
            break;
        default:
            LogError("Unknown array record type: %d", type);
            return;

            // unreached
            break;
    }

    // map input buffer as a byte array
    uint8_t *inBuff = (uint8_t *)(data_flowset + 4);  // skip flowset header
    // size of record
    size_t option_size = optionTemplate->optionSize;
    // number of records in data
    int numRecords = size_left / option_size;
    dbg_printf("[%u] name option data - records: %u, size: %zu\n", exporter_entry->info->id, numRecords, option_size);

    if (numRecords == 0 || option_size == 0 || option_size > size_left) {
        LogError("Process_ifvrf_option: option size error: option size: %zu, size left: %u", option_size, size_left);
        return;
    }

    // validate field offsets/lengths fit within option record
    if (!CHECK_OPTION_DATA(option_size, nameOption->ingress) || !CHECK_OPTION_DATA(option_size, nameOption->name)) {
        LogError("Process_ifvrf_option: field offset/length exceeds option record size");
        return;
    }

    if (nameOption->name.length == 0) {
        LogError("Process_ifvrf_option: name field length is 0");
        return;
    }

    // element: uint32_t id + char name[name.length]
    size_t data_size = sizeof(uint32_t) + nameOption->name.length;
    size_t elementSize = ALIGN8(data_size);
    // number of elements per block
    uint32_t numElements = (BLOCK_SIZE_V3 - sizeof(arrayBlockV3_t)) / elementSize;
    if (numElements == 0) {
        LogError("Process_ifvrf_option: element too large for block");
        return;
    }
    // number of blocks needed
    uint32_t numBlocks = (numRecords / numElements) + 1;

    dbg_printf("ifvrf dump: numRecords: %u, numElements: %u, elementSize: %zu, numBlocks: %u\n", numRecords, numElements, elementSize, numBlocks);

    // write array blocks
    arrayBlockV3_t *arrayBlock = NULL;
    for (int nb = 0; nb < (int)numBlocks; nb++) {
        arrayBlock = NewArrayBlock(recordType, elementSize);
        if (!arrayBlock) {
            LogError("Process_ifvrf_option: NewArrayBlock() failed");
            return;
        }

        int cnt = 0;
        uint8_t *outBuff = GetCursor(arrayBlock);
        while ((cnt++ < (int)numElements) && (size_left >= option_size)) {
            uint8_t *p = outBuff;

            // ingress/vrf ID - variable length input -> uint32_t
            uint32_t val = 0;
            memcpy(&val, inBuff + nameOption->ingress.offset, sizeof(uint32_t));
            *((uint32_t *)p) = ntohl(val);
            p += sizeof(uint32_t);

            // name string
            int err = 0;
            memcpy(p, inBuff + nameOption->name.offset, nameOption->name.length);
            uint32_t state = UTF8_ACCEPT;
            if (validate_utf8(&state, (char *)p, nameOption->name.length) == UTF8_REJECT) {
                LogError("Process_ifvrf_option: validate_utf8() %s line %d: %s", __FILE__, __LINE__, "invalid utf8 if/vrf name");
                err = 1;
            }
            p[nameOption->name.length - 1] = '\0';

#ifdef DEVEL
            if (err == 0) {
                printf("name record: %d: ingress: %u, %s\n", cnt, val, (char *)(outBuff + sizeof(uint32_t)));
            } else {
                printf("Invalid name information - skip record\n");
            }
#endif

            // in case of an err we do not store this record
            if (err == 0) {
                outBuff += elementSize;
                arrayBlock->numElements++;
                arrayBlock->rawSize += elementSize;
            }
            inBuff += option_size;
            size_left -= option_size;
        }

        // write array block only if it contains elements
        if (arrayBlock->numElements > 0) {
            dbg_printf("Push ifvrf ARRAYBLOCK: %u elements\n", arrayBlock->numElements);
            PushBlockV3(fs->blockQueue, arrayBlock);
            arrayBlock = NULL;
        }
    }
    FreeDataBlock(arrayBlock);

    if (size_left > 7) {
        LogVerbose("Process ifvrf data record - %u extra bytes", size_left);
    }
    processed_records++;

}  // End of Process_v9_ifvrf_option_data

static void Process_v9_SysUpTime_option_data(exporter_entry_t *exporter_entry, template_t *template, const uint8_t *data_flowset) {
    exporter_v9_t *exporter_v9 = &exporter_entry->v9;

    uint32_t size_left = GET_FLOWSET_LENGTH(data_flowset) - 4;  // -4 for data flowset header -> id and length
    dbg_printf("[%u] Process sysup option data flowset size: %u\n", exporter_entry->info->id, size_left);

    optionTemplate_t *optionTemplate = (optionTemplate_t *)template->data;

    // map input buffer as a byte array
    uint8_t *in = (uint8_t *)(data_flowset + 4);  // skip flowset header
    if (CHECK_OPTION_DATA(size_left, optionTemplate->SysUpOption)) {
        exporter_v9->msecSysUpTime = Get_val(in, optionTemplate->SysUpOption.offset, optionTemplate->SysUpOption.length);
        dbg_printf("Extracted SysUpTime : %" PRIu64 "\n", exporter_v9->msecSysUpTime);
    } else {
        LogError("Process_v9_option: %s line %d: Not enough data for option data", __FILE__, __LINE__);
        return;
    }

}  // End of Process_v9_SysUpTime_option_data

static void ProcessOptionFlowset(exporter_entry_t *exporter_entry, FlowSource_t *fs, template_t *template, const uint8_t *data_flowset) {
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

void Process_v9(uint8_t *in_buff, size_t in_buff_cnt, FlowSource_t *fs) {
#ifdef DEVEL
    static int pkg_num = 1;
    dbg_printf("\nProcess_v9: Next packet: %i\n", pkg_num++);
#endif

    size_t size_left = (size_t)in_buff_cnt;
    if (size_left < V9_HEADER_LENGTH) {
        LogError("Process_v9: Too little data for v9 packet: '%lli'", (long long)size_left);
        return;
    }

    // map v9 data structure to input buffer
    v9Header_t *v9_header = (v9Header_t *)in_buff;
    uint32_t exporter_id = ntohl(v9_header->source_id);

    exporter_entry_t *exporter_entry = getExporter(fs, exporter_id);
    if (!exporter_entry) {
        LogVerbose("Process_v9: No exporter template: Skip v9 record processing");
        return;
    }
    exporter_entry->packets++;
    exporter_v9_t *exporter_v9 = &exporter_entry->v9;

    exporter_v9->sysUptime = ntohl(v9_header->SysUptime);
    exporter_v9->unix_secs = ntohl(v9_header->unix_secs);

    size_left -= V9_HEADER_LENGTH;

#ifdef DEVEL
    uint32_t expected_records = ntohs(v9_header->count);
    printf("[%u] records: %u, buffer: %zd \n", exporter_id, expected_records, size_left);
    printf("SourceID: %u, Sysuptime: %u.%u\n", exporter_id, exporter_v9->sysUptime, exporter_v9->unix_secs);
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
            fs->stat_record.sequence_failure++;

            dbg_printf("[%u] Sequence error: last seq: %u, seq %u, dist %u\n", exporter_entry->info->id, exporter_entry->sequence, seq, distance);
        }
    }
    exporter_entry->sequence = seq;

    dbg_printf("Sequence: %u\n", exporter_entry->sequence);

    processed_records = 0;

    // iterate over all flowsets in export packet, while there are bytes left
    const uint8_t *flowset_header = in_buff + V9_HEADER_LENGTH;
    while (size_left) {
        if (size_left < 4) {
            return;
        }

        uint16_t flowset_id = GET_FLOWSET_ID(flowset_header);
        uint32_t flowset_length = GET_FLOWSET_LENGTH(flowset_header);

        dbg_printf("[%u] Next flowset id: %u, length: %u, buffersize: %zu\n", exporter_entry->info->id, flowset_id, flowset_length, size_left);

        if (flowset_length == 0) {
            LogError("Process_v9: flowset zero length error.");
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
                    dbg_printf("[%u] ID %u Data flowset\n", exporter_entry->info->id, flowset_id);
                    template_t *template = getTemplate(exporter_entry, flowset_id);
                    if (template) {
                        if (TestFlag(template->type, DATA_TEMPLATE)) {
                            Process_v9_data(exporter_entry, flowset_header, fs, template->data);
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
        flowset_header = flowset_header + flowset_length;

    }  // End of while

    return;

} /* End of Process_v9 */
