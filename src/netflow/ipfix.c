/*
 *  Copyright (c) 2012-2026, Peter Haag
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

#include "ipfix.h"

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

static const struct ipfixTranslationMap_s {
    uint16_t id;            // IPFIX element id
    uint16_t outputLength;  // output length in extension ID
    transform_t transform;  // transform encoding
    uint16_t extensionID;   // extension ID
    uint32_t offsetRel;     // offset rel. to extension start of struct
    char *name;             // name of element as string
} ipfixTranslationMap[] = {
    AddElement(IPFIX_octetDeltaCount, SIZEinBytes, MOVE_NUMBER, EXgenericFlowID, OFFinBytes, "octetDeltaCount"),
    AddElement(IPFIX_packetDeltaCount, SIZEinPackets, MOVE_NUMBER, EXgenericFlowID, OFFinPackets, "packetDeltaCount"),
    AddElement(IPFIX_initiatorPackets, SIZEinPackets, MOVE_NUMBER, EXgenericFlowID, OFFinPackets, "initiator packets"),
    AddElement(IPFIX_deltaFlowCount, SIZEflows, MOVE_NUMBER, EXcntFlowID, OFFflows, "deltaFlowCount"),
    AddElement(IPFIX_protocolIdentifier, SIZEproto, MOVE_NUMBER, EXgenericFlowID, OFFproto, "proto"),
    AddElement(IPFIX_ipClassOfService, SIZEsrcTos, MOVE_NUMBER, EXgenericFlowID, OFFsrcTos, "src tos"),
    AddElement(IPFIX_forwardingStatus, SIZEfwdStatus, MOVE_NUMBER, EXgenericFlowID, OFFfwdStatus, "forwarding status"),
    AddElement(IPFIX_tcpControlBits, SIZEtcpFlags, MOVE_NUMBER, EXgenericFlowID, OFFtcpFlags, "TCP flags"),
    AddElement(IPFIX_SourceTransportPort, SIZEsrcPort, MOVE_NUMBER, EXgenericFlowID, OFFsrcPort, "src port"),
    AddElement(IPFIX_udpSourcePort, SIZEsrcPort, MOVE_NUMBER, EXgenericFlowID, OFFsrcPort, "src port"),
    AddElement(IPFIX_tcpSourcePort, SIZEsrcPort, MOVE_NUMBER, EXgenericFlowID, OFFsrcPort, "src port"),
    AddElement(IPFIX_SourceIPv4Address, SIZEsrc4Addr, MOVE_NUMBER, EXipv4FlowID, OFFsrc4Addr, "src IPv4"),
    AddElement(IPFIX_SourceIPv4PrefixLength, SIZEsrcMask, MOVE_NUMBER, EXflowMiscID, OFFsrcMask, "src mask IPv4"),
    AddElement(IPFIX_ingressInterface, SIZEinput, MOVE_NUMBER, EXinterfaceID, OFFinput, "input interface"),
    AddElement(IPFIX_DestinationTransportPort, SIZEdstPort, MOVE_NUMBER, EXgenericFlowID, OFFdstPort, "dst port"),
    AddElement(IPFIX_udpDestinationPort, SIZEdstPort, MOVE_NUMBER, EXgenericFlowID, OFFdstPort, "dst port"),
    AddElement(IPFIX_tcpDestinationPort, SIZEdstPort, MOVE_NUMBER, EXgenericFlowID, OFFdstPort, "dst port"),
    AddElement(IPFIX_DestinationIPv4Address, SIZEdst4Addr, MOVE_NUMBER, EXipv4FlowID, OFFdst4Addr, "dst IPv4"),
    AddElement(IPFIX_DestinationIPv4PrefixLength, SIZEdstMask, MOVE_NUMBER, EXflowMiscID, OFFdstMask, "dst mask IPv4"),
    AddElement(IPFIX_egressInterface, SIZEoutput, MOVE_NUMBER, EXinterfaceID, OFFoutput, "output interface"),
    AddElement(IPFIX_ipNextHopIPv4Address, SIZEnextHopIPV4, MOVE_NUMBER, EXasRoutingV4ID, OFFnextHopIPV4, "IPv4 next hop"),
    AddElement(IPFIX_bgpSourceAsNumber, SIZEsrcAS, MOVE_NUMBER, EXasInfoID, OFFsrcAS, "src AS"),
    AddElement(IPFIX_bgpDestinationAsNumber, SIZEdstAS, MOVE_NUMBER, EXasInfoID, OFFdstAS, "dst AS"),
    AddElement(IPFIX_bgpNextHopIPv4Address, SIZEbgpNextHopV4, MOVE_NUMBER, EXasRoutingV4ID, OFFbgpNextHopV4, "IPv4 bgp next hop"),
    AddElement(IPFIX_flowStartSeconds, SIZEmsecFirst, MOVE_TIMESEC, EXgenericFlowID, OFFmsecFirst, "sec first seen"),
    AddElement(IPFIX_flowEndSeconds, SIZEmsecLast, MOVE_TIMESEC, EXgenericFlowID, OFFmsecLast, "sec last seen"),
    AddElement(IPFIX_flowEndSysUpTime, SIZEmsecLast, MOVE_IPFIX_TIME, EXgenericFlowID, OFFmsecLast, "msec last SysupTime"),
    AddElement(IPFIX_flowStartSysUpTime, SIZEmsecFirst, MOVE_IPFIX_TIME, EXgenericFlowID, OFFmsecFirst, "msec first SysupTime"),
    AddElement(IPFIX_SystemInitTimeMiliseconds, 0, MOVE_SYSUP, EXnull, 0, "SysupTime msec"),
    AddElement(IPFIX_postOctetDeltaCount, SIZEoutBytes, MOVE_NUMBER, EXcntFlowID, OFFoutBytes, "output bytes delta counter"),
    AddElement(IPFIX_postPacketDeltaCount, SIZEoutPackets, MOVE_NUMBER, EXcntFlowID, OFFoutPackets, "output packet delta counter"),
    AddElement(IPFIX_responderPackets, SIZEoutPackets, MOVE_NUMBER, EXcntFlowID, OFFoutPackets, "responder packets"),
    AddElement(IPFIX_newconnections, SIZEflows, MOVE_NUMBER, EXcntFlowID, OFFflows, "connections"),
    AddElement(IPFIX_SourceIPv6Address, SIZEsrc6Addr, MOVE_IPV6, EXipv6FlowID, OFFsrc6Addr, "IPv6 src addr"),
    AddElement(IPFIX_DestinationIPv6Address, SIZEdst6Addr, MOVE_IPV6, EXipv6FlowID, OFFdst6Addr, "IPv6 dst addr"),
    AddElement(IPFIX_SourceIPv6PrefixLength, SIZEsrcMask, MOVE_NUMBER, EXflowMiscID, OFFsrcMask, "src mask bits"),
    AddElement(IPFIX_DestinationIPv6PrefixLength, SIZEdstMask, MOVE_NUMBER, EXflowMiscID, OFFdstMask, "dst mask bits"),
    AddElement(IPFIX_icmpTypeCodeIPv4, SIZEdstPort, MOVE_NUMBER, EXgenericFlowID, OFFdstPort, "icmp type/code"),
    AddElement(IPFIX_icmpTypeCodeIPv6, SIZEdstPort, MOVE_NUMBER, EXgenericFlowID, OFFdstPort, "icmp v6 type/code"),
    AddElement(IPFIX_icmpTypeV4, SIZEicmpType, REGISTER_0, EXgenericFlowID, OFFicmpType, "icmp type"),
    AddElement(IPFIX_icmpCodeV4, SIZEicmpCode, REGISTER_1, EXgenericFlowID, OFFicmpCode, "icmp code"),
    AddElement(IPFIX_icmpTypeV6, SIZEicmpType, REGISTER_0, EXgenericFlowID, OFFicmpType, "icmp type"),
    AddElement(IPFIX_icmpCodeV6, SIZEicmpCode, REGISTER_1, EXgenericFlowID, OFFicmpCode, "icmp code"),
    AddElement(IPFIX_MIN_TTL, SIZEminTTL, MOVE_NUMBER, EXipInfoID, OFFminTTL, "flow min TTL"),
    AddElement(IPFIX_MAX_TTL, SIZEmaxTTL, MOVE_NUMBER, EXipInfoID, OFFmaxTTL, "flow max TTL"),
    AddElement(IPFIX_postIpClassOfService, SIZEdstTos, MOVE_NUMBER, EXflowMiscID, OFFdstTos, "post IP class of Service"),
    AddElement(IPFIX_SourceMacAddress, SIZEinSrcMac, MOVE_NUMBER, EXinMacAddrID, OFFinSrcMac, "in src MAC addr"),
    AddElement(IPFIX_postDestinationMacAddress, SIZEoutDstMac, MOVE_NUMBER, EXinMacAddrID, OFFoutDstMac, "out dst MAC addr"),
    AddElement(IPFIX_vlanId, SIZEvlanID, MOVE_NUMBER, EXvLanID, OFFvlanID, "src VLAN ID"),
    AddElement(IPFIX_postVlanId, SIZEpostVlanID, MOVE_NUMBER, EXvLanID, OFFpostVlanID, "dst VLAN ID"),
    AddElement(IPFIX_dot1qVlanId, SIZEvlanID, MOVE_NUMBER, EXlayer2ID, OFFvlanID, "dot1q VLAN ID"),
    AddElement(IPFIX_postDot1qVlanId, SIZEpostVlanID, MOVE_NUMBER, EXlayer2ID, OFFpostVlanID, "dot1q post VLAN ID"),
    AddElement(IPFIX_dot1qCustomerVlanId, SIZEcustomerVlanId, MOVE_NUMBER, EXlayer2ID, OFFcustomerVlanId, "dot1q customer VLAN ID"),
    AddElement(IPFIX_postDot1qCustomerVlanId, SIZEpostCustomerVlanId, MOVE_NUMBER, EXlayer2ID, OFFpostCustomerVlanId, "dot1q post customer VLAN ID"),
    AddElement(IPFIX_ingressPhysicalInterface, SIZEphysIngress, MOVE_NUMBER, EXlayer2ID, OFFphysIngress, "ingress physical interface ID"),
    AddElement(IPFIX_egressPhysicalInterface, SIZEphysEgress, MOVE_NUMBER, EXlayer2ID, OFFphysEgress, "egress physical interface ID"),
    AddElement(IPFIX_ipVersion, SIZEipVersion, MOVE_NUMBER, EXlayer2ID, OFFipVersion, "ip version"),
    AddElement(IPFIX_flowDirection, SIZEdir, MOVE_NUMBER, EXflowMiscID, OFFdir, "flow direction"),
    AddElement(IPFIX_biflowDirection, SIZEbiFlowDir, MOVE_NUMBER, EXflowMiscID, OFFbiFlowDir, "biFlow direction"),
    AddElement(IPFIX_flowEndReason, SIZEflowEndReason, MOVE_NUMBER, EXflowMiscID, OFFflowEndReason, "Flow end reason"),
    AddElement(IPFIX_ipTTL, SIZEminTTL, MOVE_NUMBER, EXipInfoID, OFFminTTL, "flow min TTL"),
    AddElement(IPFIX_fragmentFlags, SIZEfragmentFlags, MOVE_NUMBER, EXipInfoID, OFFfragmentFlags, "IP fragment flags"),
    AddElement(IPFIX_ipNextHopIPv6Address, SIZEnextHopIPV6, MOVE_IPV6, EXasRoutingV6ID, OFFnextHopIPV6, "IPv6 next hop IP"),
    AddElement(IPFIX_bgpNextHopIPv6Address, SIZEbgpNextHopV6, MOVE_IPV6, EXasRoutingV6ID, OFFbgpNextHopV6, "IPv6 bgp next hop IP"),
    AddElement(IPFIX_mplsTopLabelStackSection, SIZEmplsLabel1, MOVE_NUMBER, EXmplsID, OFFmplsLabel1, "mpls label 1"),
    AddElement(IPFIX_mplsLabelStackSection2, SIZEmplsLabel2, MOVE_NUMBER, EXmplsID, OFFmplsLabel2, "mpls label 2"),
    AddElement(IPFIX_mplsLabelStackSection3, SIZEmplsLabel3, MOVE_NUMBER, EXmplsID, OFFmplsLabel3, "mpls label 3"),
    AddElement(IPFIX_mplsLabelStackSection4, SIZEmplsLabel4, MOVE_NUMBER, EXmplsID, OFFmplsLabel4, "mpls label 4"),
    AddElement(IPFIX_mplsLabelStackSection5, SIZEmplsLabel5, MOVE_NUMBER, EXmplsID, OFFmplsLabel5, "mpls label 5"),
    AddElement(IPFIX_mplsLabelStackSection6, SIZEmplsLabel6, MOVE_NUMBER, EXmplsID, OFFmplsLabel6, "mpls label 6"),
    AddElement(IPFIX_mplsLabelStackSection7, SIZEmplsLabel7, MOVE_NUMBER, EXmplsID, OFFmplsLabel7, "mpls label 7"),
    AddElement(IPFIX_mplsLabelStackSection8, SIZEmplsLabel8, MOVE_NUMBER, EXmplsID, OFFmplsLabel8, "mpls label 8"),
    AddElement(IPFIX_mplsLabelStackSection9, SIZEmplsLabel9, MOVE_NUMBER, EXmplsID, OFFmplsLabel9, "mpls label 9"),
    AddElement(IPFIX_mplsLabelStackSection10, SIZEmplsLabel10, MOVE_NUMBER, EXmplsID, OFFmplsLabel10, "mpls label 10"),
    AddElement(IPFIX_DestinationMacAddress, SIZEinDstMac, MOVE_NUMBER, EXoutMacAddrID, OFFinDstMac, "in dst MAC addr"),
    AddElement(IPFIX_postSourceMacAddress, SIZEoutSrcMac, MOVE_NUMBER, EXoutMacAddrID, OFFoutSrcMac, "out src MAC addr"),
    AddElement(IPFIX_octetTotalCount, SIZEinBytes, MOVE_NUMBER, EXgenericFlowID, OFFinBytes, "input octetTotalCount"),
    AddElement(IPFIX_packetTotalCount, SIZEinPackets, MOVE_NUMBER, EXgenericFlowID, OFFinPackets, "input packetTotalCount"),
    AddElement(IPFIX_flowStartMilliseconds, SIZEmsecFirst, MOVE_NUMBER, EXgenericFlowID, OFFmsecFirst, "msec first"),
    AddElement(IPFIX_flowEndMilliseconds, SIZEmsecLast, MOVE_NUMBER, EXgenericFlowID, OFFmsecLast, "msec last"),
    AddElement(IPFIX_flowStartDeltaMicroseconds, SIZEmsecFirst, MOVE_IPFIX_USEC, EXgenericFlowID, OFFmsecFirst, "delta usec first"),
    AddElement(IPFIX_flowEndDeltaMicroseconds, SIZEmsecLast, MOVE_IPFIX_USEC, EXgenericFlowID, OFFmsecLast, "delta usec last"),
    AddElement(IPFIX_flowDurationMilliseconds, 0, NOP, EXnull, 0, "duration msec"),
    AddElement(IPFIX_postOctetTotalCount, SIZEoutBytes, MOVE_NUMBER, EXcntFlowID, OFFoutBytes, "output octetTotalCount"),
    AddElement(IPFIX_postPacketTotalCount, SIZEoutPackets, MOVE_NUMBER, EXcntFlowID, OFFoutPackets, "output packetTotalCount"),
    AddElement(IPFIX_engineType, 0, NOP, EXnull, 0, "engine type"),
    AddElement(IPFIX_engineId, 0, NOP, EXnull, 0, "engine ID"),
    AddElement(NBAR_APPLICATION_ID, SIZEnbarAppID, MOVE_BYTES, EXnbarAppID, OFFnbarAppID, "nbar application ID"),
    AddElement(IPFIX_observationDomainId, SIZEdomainID, MOVE_NUMBER, EXobservationID, OFFdomainID, "observation domainID"),
    AddElement(IPFIX_observationPointId, SIZEpointID, MOVE_NUMBER, EXobservationID, OFFpointID, "observation pointID"),
    AddElement(IPFIX_INGRESS_VRFID, SIZEingressVrf, MOVE_NUMBER, EXvrfID, OFFingressVrf, "ingress VRF ID"),
    AddElement(IPFIX_EGRESS_VRFID, SIZEegressVrf, MOVE_NUMBER, EXvrfID, OFFegressVrf, "egress VRF ID"),

    // sampling
    AddElement(IPFIX_samplerId, sizeof(uint8_t), REGISTER_2, EXnull, 0, "sampler ID"),
    AddElement(IPFIX_selectorId, sizeof(uint64_t), REGISTER_2, EXnull, 0, "sampler ID"),

    // NAT
    AddElement(IPFIX_observationTimeMilliseconds, SIZEmsecEvent, MOVE_NUMBER, EXnselCommonID, OFFmsecEvent, "msec time event"),
    AddElement(IPFIX_natEvent, SIZEnatEvent, MOVE_NUMBER, EXnselCommonID, OFFnatEvent, "NAT event"),
    AddElement(IPFIX_postNATSourceIPv4Address, SIZExlateSrcAddrV4, MOVE_NUMBER, EXnatXlateV4ID, OFFxlateSrcAddrV4, "xlate src addr"),
    AddElement(IPFIX_postNATDestinationIPv4Address, SIZExlateDstAddrV4, MOVE_NUMBER, EXnatXlateV4ID, OFFxlateDstAddrV4, "xlate dst addr"),
    AddElement(IPFIX_postNAPTSourceTransportPort, SIZExlateSrcPort, MOVE_NUMBER, EXnatXlatePortID, OFFxlateSrcPort, "xlate src port"),
    AddElement(IPFIX_postNAPTDestinationTransportPort, SIZExlateDstPort, MOVE_NUMBER, EXnatXlatePortID, OFFxlateDstPort, "xlate dst port"),
    AddElement(IPFIX_flowId, SIZEflowId, MOVE_NUMBER, EXflowIdID, OFFflowId, "flow ID"),
    // cgNAT
    AddElement(IPFIX_NATPOOL_ID, SIZEnatPoolID, MOVE_NUMBER, EXnselCommonID, OFFnatPoolID, "nat pool ID"),
    AddElement(IPFIX_PORT_BLOCK_START, SIZEnelblockStart, MOVE_NUMBER, EXnatPortBlockID, OFFnelblockStart, "NAT block start"),
    AddElement(IPFIX_PORT_BLOCK_END, SIZEnelblockEnd, MOVE_NUMBER, EXnatPortBlockID, OFFnelblockEnd, "NAT block end"),
    AddElement(IPFIX_PORT_BLOCK_STEP, SIZEnelblockStep, MOVE_NUMBER, EXnatPortBlockID, OFFnelblockStep, "NAT block step"),
    AddElement(IPFIX_PORT_BLOCK_SIZE, SIZEnelblockSize, MOVE_NUMBER, EXnatPortBlockID, OFFnelblockSize, "NAT block size"),
    // inline-monitoring inmon
    AddElement(IPFIX_dataLinkFrameSize, SIZEinmonFrameSize, MOVE_NUMBER, EXinmonMetaID, OFFinmonFrameSize, "inmon frame size"),
    AddElement(IPFIX_dataLinkFrameType, SIZEinmonLinkType, MOVE_NUMBER, EXinmonMetaID, OFFinmonLinkType, "inmon link type"),
    AddElement(IPFIX_dataLinkFrameSection, SIZEinmonFrameSize, MOVE_BYTES, EXinmonFrameID, OFFinmonFrameSize, "inmon packet content"),

    // for memory efficiency:
    // element ID below LINEAR_MARKER are stored at it's proper index
    // element ID above LINEAR_MARKER are stored linearly at LINEAR_MARKER and above
    // once, element #LINEAR_MARKER-1 gets implemented, this marker shifts
    AddElement(LINEAR_MARKER - 1, 0, NOP, 0, 0, "compiler marker"),

    // privat IDs
    AppendElement(LOCAL_IPv4Received, SIZEReceived4IP, MOVE_NUMBER, EXipReceivedV4ID, OFFReceived4IP, "IPv4 exporter"),
    AppendElement(LOCAL_IPv6Received, SIZEReceived6IP, MOVE_NUMBER, EXipReceivedV6ID, OFFReceived6IP, "IPv6 exporter"),
    AppendElement(LOCAL_msecTimeReceived, SIZEmsecReceived, MOVE_TIME_RVD, EXgenericFlowID, OFFmsecReceived, "msec time received"),

    // payload
    AppendElement(LOCAL_inPayload, VARLENGTH, MOVE_BYTES, EXinPayloadID, 0, "in payload"),
    AppendElement(LOCAL_outPayload, VARLENGTH, MOVE_BYTES, EXoutPayloadID, 0, "out payload"),

    // large Element IDs
    // Nokia
    AppendElement(NOKIA_InsideServiceId, SIZEinServiceID, MOVE_NUMBER, EXnokiaNatID, OFFinServiceID, "Nokia inside service ID"),
    AppendElement(NOKIA_OutsideServiceId, SIZEoutServiceID, MOVE_NUMBER, EXnokiaNatID, OFFoutServiceID, "Nokia outside service ID"),
    AppendElement(NOKIA_NatSubString, SIZEnatSubString, MOVE_BYTES, EXnokiaNatStringID, OFFnatSubString, "Nokia nat substring"),

    // last element in ipfix translation map
    AppendElement(0, 0, NOP, 0, 0, NULL),

};

static const int maxMapEntries = ARRAY_SIZE(ipfixTranslationMap);

// map for corresponding reverse element, if enterprise ID = IPFIX_ReverseInformationElement
static const struct ipfixReverseMap_s {
    uint16_t ID;         // IPFIX element id
    uint16_t reverseID;  // reverse IPFIX element id
} ipfixReverseMap[] = {
    {IPFIX_octetTotalCount, IPFIX_postOctetTotalCount},
    {IPFIX_packetTotalCount, IPFIX_postPacketTotalCount},
    {IPFIX_octetDeltaCount, IPFIX_postOctetDeltaCount},
    {IPFIX_packetDeltaCount, IPFIX_postPacketDeltaCount},
    {LOCAL_inPayload, LOCAL_outPayload},
    {0, 0},
};

// module limited globals
static uint32_t processed_records;
static int printRecord;
int32_t defaultSampling;

// prototypes
static void InsertSampler(exporter_entry_t *exporter_entry, sampler_record_v4_t *sampler_record_v4);

static void expand_template_table(exporter_ipfix_t *exporter_ipfix);

static exporter_entry_t *getExporter(FlowSource_t *fs, uint32_t ObservationDomain);

static void Process_ipfix_templates(exporter_entry_t *exporter_entry, void *flowset_header, uint32_t size_left, FlowSource_t *f);

static void Process_ipfix_template_add(exporter_entry_t *exporter_entry, const uint8_t *DataPtr, uint32_t size_left, FlowSource_t *f);

static void Process_ipfix_template_withdraw(exporter_entry_t *exporter_entry, const uint8_t *DataPtr, uint32_t size_left);

static void Process_ipfix_option_templates(exporter_entry_t *exporter_entry, const uint8_t *option_template_flowset);

static void ProcessOptionFlowset(exporter_entry_t *exporter_entry, FlowSource_t *fs, template_t *template, const uint8_t *data_flowset);

static void Process_ifvrf_option_data(exporter_entry_t *exporter_entry, FlowSource_t *fs, int type, template_t *template,
                                      const uint8_t *data_flowset);

static void Process_ipfix_data(exporter_entry_t *exporter_entry, uint32_t ExportTime, const uint8_t *data_flowset, FlowSource_t *fs,
                               const pipeline_t *pipeline);

static int LookupElement(uint16_t type, uint32_t EnterpriseNumber);

int Init_IPFIX(int verbose, int32_t sampling, char *extensionList) {
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
        if (ipfixTranslationMap[i].name) {
            int extID = ipfixTranslationMap[i].extensionID;
            if (ExtensionsEnabled[extID]) tagsEnabled++;
        }
    }

    if (sampling < 0) {
        LogInfo("Init IPFIX: Max number of ipfix tags enabled: %u, overwrite sampling: %d", tagsEnabled, -defaultSampling);
        dbg_printf("Init ipfix: Overwrite sampling: %d\n", -defaultSampling);
    } else {
        LogInfo("Init IPFIX: Max number of ipfix tags enabled: %u, default sampling: %d", tagsEnabled, defaultSampling);
        dbg_printf("Init ipfix: Default sampling: %d\n", defaultSampling);
    }

    return 1;

}  // End of Init_IPFIX

static int LookupElement(uint16_t type, uint32_t EnterpriseNumber) {
    switch (EnterpriseNumber) {
        case 0:  // no Enterprise value
            break;
        case 9:  // CiscoSystem
            switch (type) {
                case 12236:  // client ipv4 address
                    dbg_printf(" CISCO enterprise client IP type: %u\n", type);
                    type = IPFIX_SourceIPv4Address;
                    break;
                case 12237:  // server ipv4 address
                    dbg_printf(" CISCO enterprise server IP type: %u\n", type);
                    type = IPFIX_DestinationIPv4Address;
                    break;
                case 12241:  // server transport port
                    dbg_printf(" CISCO enterprise server port type: %u\n", type);
                    type = IPFIX_DestinationTransportPort;
                    break;
                case 8337:  //  server counter bytes network
                    dbg_printf(" CISCO enterprise server bytes type: %u\n", type);
                    type = IPFIX_octetDeltaCount;
                    break;
                case 8338:  //  client counter bytes network
                    dbg_printf(" CISCO enterprise client bytes type: %u\n", type);
                    type = IPFIX_postOctetDeltaCount;
                    break;
            }
            break;
        case 637:  // Nokia
            switch (type) {
                case 91:  // InsideServiceId
                    dbg_printf(" NOKIA enterprise InsideServiceId: %u\n", type);
                    type = NOKIA_InsideServiceId;
                    break;
                case 92:  // OutsideServiceId
                    dbg_printf(" NOKIA enterprise OutsideServiceId: %u\n", type);
                    type = NOKIA_OutsideServiceId;
                    break;
                case 93:  // NatSubString
                    dbg_printf(" NOKIA enterprise NatSubString: %u\n", type);
                    type = NOKIA_NatSubString;
                    break;
            }
            break;
        case 6871:  // yaf CERT Coordination Centre
            // map yaf types here
            switch (type) {
                case YAF_payload:
                    type = LOCAL_inPayload;
                    break;
                case 16402:  // VENDOR_BIT_REVERSE | 18
                    type = LOCAL_outPayload;
                    break;
                default:
                    dbg_printf(" Skip yaf CERT Coordination Centre\n");
                    return -1;
            }
            break;
        case IPFIX_ReverseInformationElement:
            for (int i = 0; ipfixReverseMap[i].ID != 0; i++) {
                if (ipfixReverseMap[i].ID == type) {
                    type = ipfixReverseMap[i].reverseID;
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
        if (ipfixTranslationMap[type].name != NULL) {
            int extID = ipfixTranslationMap[type].extensionID;
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
    while (ipfixTranslationMap[i].name != NULL && i < maxMapEntries) {
        if (ipfixTranslationMap[i].id == type) {
            int extID = ipfixTranslationMap[i].extensionID;
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

static exporter_entry_t *getExporter(FlowSource_t *fs, uint32_t ObservationDomain) {
    const exporter_key_t key = {.version = VERSION_IPFIX, .id = ObservationDomain, .ip = fs->ipAddr};

    // Fast cache
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

    // not found - search in hash table
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
                LogError("Process_ipfix: malloc(): %s line %d: %s", __FILE__, __LINE__, strerror(errno));
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

            e->ipfix = (exporter_ipfix_t){0};
            expand_template_table(&e->ipfix);

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
            LogInfo("Process_ipfix: New ipfix exporter: SysID: %u, Observation domain %u from: %s", e->info->sysID, ObservationDomain,
                    ip128_2_str(&fs->ipAddr, ipstr));

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
    exporter_ipfix_t *exporter_ipfix = &exporter_entry->ipfix;

#ifdef DEVEL
    {
        printf("[%u] Get template - last template ID: %u\n", exporter_entry->info->id, exporter_ipfix->lastTemplateID);
        printf("[%u] Get template - available templates for exporter sysID: %u\n", exporter_entry->info->id, exporter_entry->sysID);
        template_t *template = exporter_ipfix->template;
        for (int i = 0; i < (int)exporter_ipfix->templateCapacity; i++) {
            if (template->id != 0) {
                printf(" [%d] ID: %u, type:, %u\n", i, template->id, template->type);
            }
            template++;
        }
    }
#endif

    // return lastTemplate, if id matches
    if (exporter_ipfix->lastTemplateID == id) return exporter_ipfix->lastTemplate;

    // search template
    uint32_t mask = exporter_ipfix->templateCapacity - 1;
    uint32_t idx = id & mask;
    template_t *template = exporter_ipfix->template;
    for (;;) {
        __builtin_prefetch(&template[(idx + 1) & mask]);
        if (template[idx].id == EMPTY_SLOT) {
            exporter_ipfix->lastTemplateID = 0;
            exporter_ipfix->lastTemplate = NULL;
            dbg_printf("[%u] Get template %u: not found\n", exporter_entry->info->id, id);
            return NULL;
        }
        if (template[idx].id == id) {
            exporter_ipfix->lastTemplateID = id;
            exporter_ipfix->lastTemplate = template + idx;
            dbg_printf("[%u] Get template %u: found\n", exporter_entry->info->id, id);
            return exporter_ipfix->lastTemplate;
        }
        idx = (idx + 1) & mask;
    }

    // unreached
    return NULL;

}  // End of getTemplate

static void expand_template_table(exporter_ipfix_t *exporter_ipfix) {
    uint32_t old_cap = exporter_ipfix->templateCapacity;
    template_t *old_template = exporter_ipfix->template;

    uint32_t new_cap = exporter_ipfix->templateCapacity != 0 ? exporter_ipfix->templateCapacity * 2 : NUMTEMPLATES;
    template_t *new_template = calloc(new_cap, sizeof(template_t));
    if (!new_template) {
        LogError("expand_template_table() error calloc(): %s in %s:%d", strerror(errno), __FILE__, __LINE__);
        return;
    }
    dbg_printf("Expand exporter table: %u -> %u\n", old_cap, new_cap);

    exporter_ipfix->template = new_template;
    exporter_ipfix->templateCapacity = new_cap;
    exporter_ipfix->templateCount = 0;

    uint32_t mask = exporter_ipfix->templateCapacity - 1;
    for (int i = 0; i < (int)old_cap; i++) {
        template_t *t = &old_template[i];
        if (t->id == EMPTY_SLOT || t->id == DELETED_SLOT) continue;

        uint32_t idx = t->id & mask;
        while (new_template[idx].id > 0) idx = (idx + 1) & mask;

        new_template[idx] = *t;
        exporter_ipfix->templateCount++;
    }

    dbg_printf("Expand exporter table count: %u\n", exporter_ipfix->templateCount);

    if (old_template) free(old_template);
}  // End of expand_template_table

static template_t *newTemplate(exporter_ipfix_t *exporter_ipfix, uint16_t id) {
    if ((exporter_ipfix->templateCount * 4) >= (exporter_ipfix->templateCapacity * 3)) {
        // expand exporter index
        expand_template_table(exporter_ipfix);
    }

    int firstDeleted = -1;
    template_t *template = exporter_ipfix->template;
    uint32_t mask = exporter_ipfix->templateCapacity - 1;
    uint32_t idx = id & mask;
    for (;;) {
        __builtin_prefetch(&template[(idx + 1) & mask]);
        if (template[idx].id == EMPTY_SLOT) {
            if (firstDeleted != -1) idx = firstDeleted;
            template[idx] = (template_t){.id = id, .updated = time(NULL), .data = NULL};

            exporter_ipfix->templateCount++;
            exporter_ipfix->lastTemplateID = id;
            exporter_ipfix->lastTemplate = template + idx;
            dbg_printf("New template %u at %u\n", id, idx);
            return exporter_ipfix->lastTemplate;
        }

        if (template[idx].id == DELETED_SLOT && firstDeleted == -1) firstDeleted = idx;
        idx = (idx + 1) & mask;
    }

    return template;

}  // End of newTemplate

static int removeTemplate(exporter_entry_t *exporter_entry, uint16_t id) {
    exporter_ipfix_t *exporter_ipfix = &(exporter_entry->ipfix);
    if (exporter_ipfix->templateCapacity == 0) return 0;

    uint32_t mask = exporter_ipfix->templateCapacity - 1;
    uint32_t idx = id & mask;
    template_t *table = exporter_ipfix->template;

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

            exporter_ipfix->templateCount--;
            exporter_ipfix->templateDeleted++;

            // invalidate cache
            if (exporter_ipfix->lastTemplateID == id) {
                exporter_ipfix->lastTemplateID = 0;
                exporter_ipfix->lastTemplate = NULL;
            }

            return 1;
        }

        idx = (idx + 1) & mask;
    }
}  // End of removeTemplate

static void removeAllTemplates(exporter_entry_t *exporter_entry) {
    exporter_ipfix_t *exporter_ipfix = &(exporter_entry->ipfix);

    LogInfo("Process_ipfix: Withdraw all templates from observation domain %u\n", exporter_entry->info->id);

    template_t *template = exporter_ipfix->template;
    for (int i = 0; i < (int)exporter_ipfix->templateCapacity; i++) {
        if (template->data) free(template->data);
        *template = (template_t){0};
        template++;
    }
    exporter_ipfix->templateCount = 0;

    // invalidate cache
    exporter_ipfix->lastTemplateID = 0;
    exporter_ipfix->lastTemplate = NULL;

}  // End of removeAllTemplates

static void Process_ipfix_templates(exporter_entry_t *exporter_entry, void *flowset_header, uint32_t size_left, FlowSource_t *fs) {
    size_left -= 4;  // subtract message header
    void *DataPtr = flowset_header + 4;

    ipfix_template_record_t *ipfix_template_record = (ipfix_template_record_t *)DataPtr;

    // uint32_t	id 	  = ntohs(ipfix_template_record->TemplateID);
    uint32_t count = ntohs(ipfix_template_record->FieldCount);

    if (count == 0) {
        // withdraw template
        Process_ipfix_template_withdraw(exporter_entry, DataPtr, size_left);
    } else {
        // refresh/add templates
        Process_ipfix_template_add(exporter_entry, DataPtr, size_left, fs);
    }

}  // End of Process_ipfix_templates

static void Process_ipfix_template_add(exporter_entry_t *exporter_entry, const uint8_t *DataPtr, uint32_t size_left, FlowSource_t *fs) {
    ipfix_template_record_t *ipfix_template_record;
    ipfix_template_elements_std_t *NextElement;

    // a template flowset can contain multiple records ( templates )
    while (size_left) {
        uint32_t id, count, size_required;
        if (size_left < 4) {
            LogError("Process_ipfix [%u] Template size error at %s line %u", exporter_entry->info->id, __FILE__, __LINE__, strerror(errno));
            size_left = 0;
            continue;
        }

        // map next record.
        ipfix_template_record = (ipfix_template_record_t *)DataPtr;
        size_left -= 4;

        id = ntohs(ipfix_template_record->TemplateID);
        count = ntohs(ipfix_template_record->FieldCount);

        dbg_printf("\n[%u] Template ID: %u\n", exporter_entry->info->id, id);
        dbg_printf("FieldCount: %u buffersize: %u\n", count, size_left);

        // assume all elements in template are std elements. correct this value, if we find an
        // enterprise element
        size_required = 4 * count;
        if (size_left < size_required) {
            LogError("Process_ipfix: [%u] Not enough data for template elements! required: %i, left: %u", exporter_entry->info->id, size_required,
                     size_left);
            return;
        }

        // temp instruction array
        pipelineInstr_t instruction[2 * count + 2];
        memset(instruction, 0, sizeof(instruction));
        pipelineInstr_t *instr = instruction;
        pipelineInstr_t *prev = NULL;

        uint32_t commonFound = 0;
        // process all elements in this record
        NextElement = (ipfix_template_elements_std_t *)ipfix_template_record->elements;
        for (int i = 0; i < (int)count; i++) {
            dbg_assert((instr - instruction) < (count + 2));
            uint16_t type = ntohs(NextElement->Type);
            uint16_t inLength = ntohs(NextElement->Length);
            int Enterprise = type & 0x8000 ? 1 : 0;
            type = type & 0x7FFF;

            uint32_t EnterpriseNumber = 0;
            if (Enterprise) {
                ipfix_template_elements_e_t *e = (ipfix_template_elements_e_t *)NextElement;
                size_required += 4;  // ad 4 for enterprise value
                if (size_left < size_required) {
                    LogError(
                        "Process_ipfix: [%u] Not enough data for template elements! required: %i, "
                        "left: %u",
                        exporter_entry->info->id, size_required, size_left);
                    return;
                }
                EnterpriseNumber = ntohl(e->EnterpriseNumber);
                if (EnterpriseNumber == IPFIX_ReverseInformationElement) {
                    dbg_printf("[%i] Enterprise: 1, Type: %u, Length %u Reverse Information Element: %u\n", i, type, inLength, EnterpriseNumber);
                } else {
                    dbg_printf("[%i] Enterprise: 1, Type: %u, Length %u EnterpriseNumber: %u\n", i, type, inLength, EnterpriseNumber);
                }
                e++;
                NextElement = (ipfix_template_elements_std_t *)e;
            } else {
                dbg_printf("[%i] Enterprise: 0, Type: %u, Length %u\n", i, type, inLength);
                NextElement++;
            }

            int index = LookupElement(type, EnterpriseNumber);
            if (index < 0) {  // not found - enter skip sequence
                if ((EnterpriseNumber == 0) && (type == IPFIX_subTemplateList || type == IPFIX_subTemplateMultiList)) {
                    // Sub-template IEs (RFC 6313) — skip content at runtime
                    *instr = (pipelineInstr_t){.transform = SUBTEMPLATE, .type = type, .inLength = inLength};
                    dbg_printf(" Skip sub template type: %u, enterprise: %u, length: %u\n", type, EnterpriseNumber, inLength);
                } else {
                    // not found - add skip sequence
                    // var length skip cannot be stacked
                    if (inLength != VARLENGTH && prev && prev->transform == SKIP_INPUT) {
                        // compact multiple skip instructions
                        prev->inLength += inLength;
                        dbg_printf("Add %u bytes to previous skip instruction\n", inLength);
                        continue;
                    } else {
                        *instr = (pipelineInstr_t){
                            .transform = SKIP_INPUT,
                            .type = type,
                            .inLength = inLength,
                        };
                        dbg_printf("Skip unknown element type: %u, length: %u\n", type, inLength);
                    }
                }

            } else {
                *instr = (pipelineInstr_t){
                    .type = type,
                    .inLength = inLength,
                    .extID = ipfixTranslationMap[index].extensionID,
                    .dstOffset = ipfixTranslationMap[index].offsetRel,
                    .transform = ipfixTranslationMap[index].transform,
                    .outLength = ipfixTranslationMap[index].outputLength,
                };

                dbg_printf(" Map type: %s(%u), inLen: %u, Ext: %s(%u), outLen: %u, transform: %s\n", ipfixTranslationMap[index].name,
                           ipfixTranslationMap[index].id, inLength, extensionTable[ipfixTranslationMap[index].extensionID].name,
                           ipfixTranslationMap[index].extensionID, ipfixTranslationMap[index].outputLength,
                           trTable[ipfixTranslationMap[index].transform].trName);
                commonFound++;
            }

            prev = instr;
            instr++;
        }

        dbg_printf("Processed bytes: %u, common found: %u\n", size_required, commonFound);
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

        dbg_assert((instr - instruction) < (count + 2));
        int index = LookupElement(LOCAL_msecTimeReceived, 0);
        *instr++ = (pipelineInstr_t){
            .type = ipfixTranslationMap[index].id,
            .inLength = 0,
            .extID = ipfixTranslationMap[index].extensionID,
            .dstOffset = ipfixTranslationMap[index].offsetRel,
            .transform = ipfixTranslationMap[index].transform,
            .outLength = ipfixTranslationMap[index].outputLength,
        };
        dbg_printf("Map type: %u, length: %u to Extension %u - '%s' - output length: %u\n", LOCAL_msecTimeReceived, 8,
                   ipfixTranslationMap[index].extensionID, ipfixTranslationMap[index].name, ipfixTranslationMap[index].outputLength);

        uint32_t cnt = instr - instruction;
        dbg_printf("Total instructions: %u, template count: %u\n", cnt, count);

        pipeline_t *pipeline = PipelineCompile(instruction, id, cnt);
        if (!pipeline) {
            LogError("Process_ipfix: PipelineCompile() failed");
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
            template = newTemplate(&(exporter_entry->ipfix), id);
            dbg_printf("New template ID: %u\n", id);
        }

        if (!template) {
            LogError("Process_ipfix: abort template add: %s line %d", __FILE__, __LINE__);
            free(pipeline);
            return;
        }

        template->type = DATA_TEMPLATE;
        template->data = pipeline;
        SetFlag(template->type, DATA_TEMPLATE);

        // update size left of this flowset
        size_left -= size_required;
        DataPtr = DataPtr + size_required + 4;  // +4 for header
        if (size_left < 4) {
            // padding
            dbg_printf("Skip %u bytes padding\n", size_left);
            size_left = 0;
        }
    }

}  // End of Process_ipfix_template_add

static void Process_ipfix_template_withdraw(exporter_entry_t *exporter_entry, const uint8_t *DataPtr, uint32_t size_left) {
    // a template flowset can contain multiple records ( templates )
    if (size_left < 4) {
        return;
    }
    while (size_left) {
        // map next record.
        ipfix_template_record_t *ipfix_template_record = (ipfix_template_record_t *)DataPtr;
        size_left -= 4;

        uint32_t id = ntohs(ipfix_template_record->TemplateID);
        // count = ntohs(ipfix_template_record->FieldCount);

        if (id == IPFIX_TEMPLATE_FLOWSET_ID) {
            // withdraw all templates
            removeAllTemplates(exporter_entry);
        } else {
            removeTemplate(exporter_entry, id);
        }

        DataPtr = DataPtr + 4;
        if (size_left < 4) {
            // padding
            dbg_printf("Skip %u bytes padding\n", size_left);
            size_left = 0;
        }
    }

}  // End of Process_ipfix_template_withdraw

static void Process_ipfix_option_templates(exporter_entry_t *exporter_entry, const uint8_t *option_template_flowset) {
    uint32_t size_left = GET_FLOWSET_LENGTH(option_template_flowset) - 4;  // -4 for flowset header -> id and length
    if (size_left < 6) {
        LogError(
            "Process_ipfix: [%u] option template length error: size left %u too small for an "
            "options template",
            exporter_entry->info->id, size_left);
        return;
    }

    const uint8_t *option_template = option_template_flowset + 4;
    uint16_t tableID = GET_OPTION_TEMPLATE_ID(option_template);
    uint16_t field_count = GET_OPTION_TEMPLATE_FIELD_COUNT(option_template);
    uint16_t scope_field_count = GET_OPTION_TEMPLATE_SCOPE_FIELD_COUNT(option_template);
    option_template += 6;
    size_left -= 6;

    dbg_printf("Decode Option Template. tableID: %u, field count: %u, scope field count: %u\n", tableID, field_count, scope_field_count);

    if (scope_field_count == 0) {
        LogError("Process_ipfx: [%u] scope field count error: length must not be zero", exporter_entry->info->id);
        dbg_printf("scope field count error: length must not be zero\n");
        return;
    }

    uint32_t size_required = 2 * field_count * sizeof(uint16_t);
    dbg_printf("Size left: %u, size required: %u\n", size_left, size_required);
    if (size_left < size_required) {
        LogError(
            "Process_ipfix: [%u] option template length error: size left %u too small for %u "
            "scopes length and %u options length",
            exporter_entry->info->id, size_left, field_count, scope_field_count);
        dbg_printf("option template length error: size left %u too small for field_count %u\n", size_left, field_count);
        return;
    }

    if (scope_field_count == 0) {
        LogError("Process_ipfxi: [%u] scope field count error: length must not be zero", exporter_entry->info->id);
        return;
    }

    optionTemplate_t *optionTemplate = (optionTemplate_t *)calloc(1, sizeof(optionTemplate_t));
    if (!optionTemplate) {
        LogError("Error calloc(): %s in %s:%d", strerror(errno), __FILE__, __LINE__);
        return;
    }

    struct samplerOption_s *samplerOption = &(optionTemplate->samplerOption);
    struct nbarOptionList_s *nbarOption = &(optionTemplate->nbarOption);
    struct nameOptionList_s *ifnameOptionList = &(optionTemplate->ifnameOption);
    struct nameOptionList_s *vrfnameOptionList = &(optionTemplate->vrfnameOption);

    uint16_t scopeSize = 0;
    uint16_t offset = 0;
    for (int i = 0; i < field_count; i++) {
        uint32_t enterprise_value;
        uint16_t type, length;
        unsigned Enterprise;

        // keep compiler happy
        UNUSED(enterprise_value);
        type = Get_val16(option_template);
        option_template += 2;
        length = Get_val16(option_template);
        option_template += 2;
        size_left -= 4;
        if (i < scope_field_count) {
            scopeSize += length;
            dbg_printf("Scope field Type: %u, offset: %u, length %u\n", type, offset, length);
        } else {
            dbg_printf("Option field Type: %u, offset: %u, length %u\n", type, offset, length);
        }

        Enterprise = type & 0x8000 ? 1 : 0;
        if (Enterprise) {
            size_required += 4;
            if (size_left < 4) {
                LogError("Process_ipfix: [%u] option template length error: size left %u too", exporter_entry->info->id, size_left);
                dbg_printf("option template length error: size left %u too small\n", size_left);
                return;
            }
            type &= 0x7FFF;
            enterprise_value = Get_val32(option_template);
            option_template += 4;
            size_left -= 4;
            dbg_printf(" [%i] Enterprise: 1, offset: %u, option type: %u, option length %u enterprise value: %u\n", i, offset, type, length,
                       enterprise_value);
        } else {
            dbg_printf(" [%i] Enterprise: 0, offset: %u, option type: %u, option length %u\n", i, offset, type, length);
        }

        switch (type) {
            // Old std sampling tags
            case IPFIX_samplingInterval:  // #34
                samplerOption->spaceInterval.length = length;
                samplerOption->spaceInterval.offset = offset;
                SetFlag(optionTemplate->flags, STDSAMPLING34);
                dbg_printf(" Sampling tag #34 option found\n");
                break;
            case IPFIX_samplingAlgorithm:  // #35
                samplerOption->algorithm.length = length;
                samplerOption->algorithm.offset = offset;
                SetFlag(optionTemplate->flags, STDSAMPLING35);
                dbg_printf(" Sampling #35 found\n");
                break;

            // New std sampling, individual sammplers (sampling ID)
            // Map old individual samplers
            case IPFIX_samplerId:  // #48 deprecated - fall through
                dbg_printf(" Sampling #48 map to #302\n");
            case IPFIX_selectorId:  // #302
                samplerOption->id.length = length;
                samplerOption->id.offset = offset;
                SetFlag(optionTemplate->flags, SAMPLER302);
                dbg_printf(" Sampling #302 found\n");
                break;
            case IPFIX_samplerMode:  // #49 deprecated - fall through
                dbg_printf(" Sampling #49 found\n");
            case IPFIX_selectorAlgorithm:  // #304
                samplerOption->algorithm.length = length;
                samplerOption->algorithm.offset = offset;
                SetFlag(optionTemplate->flags, SAMPLER304);
                dbg_printf(" Sampling #304 found\n");
                break;
            case IPFIX_samplingPacketInterval:  // #305
                samplerOption->packetInterval.length = length;
                samplerOption->packetInterval.offset = offset;
                SetFlag(optionTemplate->flags, SAMPLER305);
                dbg_printf(" Sampling #305 found\n");
                break;
            case IPFIX_samplerRandomInterval:  // #50 deprecated - fall through
                dbg_printf(" Sampling #50 found\n");
            case IPFIX_samplingPacketSpace:  // #306
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
            case IPFIX_ingressInterface:
                ifnameOptionList->ingress.length = length;
                ifnameOptionList->ingress.offset = offset;
                SetFlag(optionTemplate->flags, IFNAMEOPTION);
                dbg_printf(" Ifname ingress option found\n");
                break;
            case IPFIX_interfaceDescription:
                ifnameOptionList->name.length = length;
                ifnameOptionList->name.offset = offset;
                SetFlag(optionTemplate->flags, IFNAMEOPTION);
                dbg_printf(" Ifname name option found\n");
                break;

            // vrfname
            case IPFIX_INGRESS_VRFID:
                vrfnameOptionList->ingress.length = length;
                vrfnameOptionList->ingress.offset = offset;
                SetFlag(optionTemplate->flags, VRFNAMEOPTION);
                dbg_printf(" Vrfname ingress option found\n");
                break;
            case IPFIX_VRFname:
                vrfnameOptionList->name.length = length;
                vrfnameOptionList->name.offset = offset;
                SetFlag(optionTemplate->flags, VRFNAMEOPTION);
                dbg_printf(" Vrfname name option found\n");
                break;

            // SysUpTime information
            case IPFIX_SystemInitTimeMiliseconds:
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

    dbg_printf("\n[%u] Option size: %" PRIu64 ", flags: %" PRIx64 "\n", exporter_entry->info->id, optionTemplate->optionSize, optionTemplate->flags);
    if (optionTemplate->flags) {
        // if it exists - remove old template on exporter with same ID
        template_t *template = getTemplate(exporter_entry, tableID);
        if (template) {
            // clean existing template
            if (template->data) free(template->data);
            dbg_printf("Update/refresh option template ID: %u\n", tableID);
        } else {
            template = newTemplate(&(exporter_entry->ipfix), tableID);
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
            dbg_printf("[%u] found nbar options\n", exporter_entry->info->id);
            dbg_printf("[%u] id   length: %u, offset: %u\n", exporter_entry->info->id, nbarOption->id.length, nbarOption->id.offset);
            dbg_printf("[%u] name length: %u, offset: %u\n", exporter_entry->info->id, nbarOption->name.length, nbarOption->name.offset);
            dbg_printf("[%u] desc length: %u, offset: %u\n", exporter_entry->info->id, nbarOption->desc.length, nbarOption->desc.offset);
            optionTemplate->nbarOption.scopeSize = scopeSize;
            SetFlag(template->type, NBAR_TEMPLATE);
        } else {
            dbg_printf("[%u] No nbar information found\n", exporter_entry->info->id);
        }

        if (TestFlag(optionTemplate->flags, IFNAMEOPTION)) {
            dbg_printf("[%u] found ifname option\n", exporter_entry->info->id);
            dbg_printf("[%u] ingess length: %u\n", exporter_entry->info->id, optionTemplate->ifnameOption.ingress.length);
            dbg_printf("[%u] name length  : %u\n", exporter_entry->info->id, optionTemplate->ifnameOption.name.length);
            optionTemplate->ifnameOption.scopeSize = scopeSize;
            SetFlag(template->type, IFNAME_TEMPLATE);
        } else {
            dbg_printf("[%u] No ifname information found\n", exporter_entry->info->id);
        }

        if (TestFlag(optionTemplate->flags, VRFNAMEOPTION)) {
            dbg_printf("[%u] found vrfname option\n", exporter_entry->info->id);
            dbg_printf("[%u] ingess length: %u\n", exporter_entry->info->id, optionTemplate->vrfnameOption.ingress.length);
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
        dbg_printf("\n[%u] template type: %x\n", exporter_entry->info->id, template->type);

    } else {
        free(optionTemplate);
    }

    processed_records++;
    dbg_printf("\n");

}  // End of Process_ipfix_option_templates

static void Process_ipfix_data(exporter_entry_t *exporter_entry, uint32_t ExportTime, const uint8_t *data_flowset, FlowSource_t *fs,
                               const pipeline_t *pipeline) {
    int32_t size_left = GET_FLOWSET_LENGTH(data_flowset) - 4;  // -4 for data flowset header -> id and length
    exporter_ipfix_t *exporter_ipfix = &(exporter_entry->ipfix);

    // map input buffer as a byte array
    const uint8_t *inBuff = data_flowset + 4;  // skip flowset header

    dbg_printf("[%u] Process data flowset size: %d\n", exporter_entry->info->id, size_left);

    // general runtime parameters for pipiling processor, common for all flows
    pipelineRuntime_t runtime = {.SysUptime = exporter_ipfix->SysUpTime,
                                 .unix_secs = 0,
                                 .secExported = ExportTime,
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
            fs->dataBlock = PushBlockV3(fs->blockQueue, fs->dataBlock);
        }

        unsigned buffAvail = BLOCK_SIZE_V3 - fs->dataBlock->rawSize;
        if (buffAvail == 0) {
            // this should really never occur, because the buffer gets flushed earlier
            LogError("Process_ipfix: output buffer size error. Skip ipfix record processing");
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
            recordHeaderV4->nfVersion = 10;
            recordHeaderV4->exporterID = exporter_entry->info->sysID;

            // copy record data
            memset(runtime.rtRegister, 0, sizeof(runtime.rtRegister));
            runtime.genericRecord = NULL;
            runtime.cntRecord = NULL;
            processed = PipelineRun(pipeline, inBuff, size_left, outBuff, buffAvail, &runtime);
            switch (processed) {
                case PIP_ERR_SHORT_INPUT:
                    LogError("Process ipfix: PipelineRun() short input. Skip record processing");
                    processed = size_left;
                    break;
                case PIP_ERR_SHORT_OUTPUT:
                    if (buffAvail == BLOCK_SIZE_V3) {
                        LogError("Process ipfix: PipelineRun() short output. Skip record processing");
                        return;
                    }

                    LogVerbose("Process ipfix: PipelinRun() resize output buffer");
                    // request new and empty buffer
                    fs->dataBlock = PushBlockV3(fs->blockQueue, fs->dataBlock);
                    if (fs->dataBlock == NULL) {
                        return;
                    }

                    buffAvail = BLOCK_SIZE_V3 - fs->dataBlock->rawSize;
                    if (buffAvail == 0 || redone) {
                        // this should really never happen, because the buffer got flushed
                        LogError("Process_ipfix: output buffer size error. Skip ipfix record processing");
                        return;
                    }
                    redone++;
                    break;
                case PIP_ERR_RUNTIME_INPUT:
                    LogError("Process_ipfix: runtime buffer error. Skip ipfix record processing");
                    return;
                    break;
                case PIP_ERR_RUNTIME_ERROR:
                    LogError("Process_ipfix: pipeline runtime error. Skip v9 record processing");
                    break;
                default:
                    dbg_printf("New record added with %u elements and size: %u, processed inLength: %zu\n", recordHeaderV4->numExtensions,
                               recordHeaderV4->size, processed);
            }

        } while (processed < 0 && redone < 2);

        if (processed <= 0) {
            LogError("Process_ipfix: pipeline processing error: %zd. Skip ipfix record processing", processed);
            return;
        }

        dbg_printf("Record: %u elements, size: %u\n", recordHeaderV4->numExtensions, recordHeaderV4->size);

        outBuff += recordHeaderV4->size;
        inBuff += processed;
        size_left -= processed;

        processed_records++;
        exporter_ipfix->PacketSequence++;

        /* XXX FIX!
        if (stack[STACK_ENGINE_TYPE]) recordHeaderV4->engineType = stack[STACK_ENGINE_TYPE];
        if (stack[STACK_ENGINE_ID]) recordHeaderV4->engineID = stack[STACK_ENGINE_ID];
        */

        // handle sampling
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

        // update first_seen, last_seen
        EXgenericFlow_t *genericFlow = runtime.genericRecord;
        if (likely(genericFlow != NULL)) {
            //    genericFlow->msecReceived = ((uint64_t)fs->received.tv_sec * 1000LL) + (uint64_t)((uint64_t)fs->received.tv_usec / 1000LL);

            // update first_seen, last_seen
            UpdateFirstLast(fs, genericFlow->msecFirst, genericFlow->msecLast);
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
                    if (runtime.rtRegister[0] != 0 || runtime.rtRegister[1] != 0) {
                        // icmp type and code elements #176 #177 #178 #179
                        genericFlow->dstPort = (runtime.rtRegister[0] << 8) + runtime.rtRegister[1];
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
            // sampling > 1
            if (spaceInterval > 0) {
                cntFlow->outPackets = cntFlow->outPackets * intervalTotal / (uint64_t)packetInterval;
                cntFlow->outBytes = cntFlow->outBytes * intervalTotal / (uint64_t)packetInterval;
            }
            if (cntFlow->flows == 0) cntFlow->flows++;
            fs->stat_record.numpackets += cntFlow->outPackets;
            fs->stat_record.numbytes += cntFlow->outBytes;
        }

        /*
         XXX maybe implemented later
        // if observation extension is used but no domainID, take it from the ipfix header
        EXobservation_t *observation = GetExtension(recordHeaderV4, EXobservation);
        if (observation) {
            if (observation->domainID == 0) observation->domainID = exporter_entry->info->id;
        }

        // XXX decode packet content
        EXinmonFrame_t *inmonFrame = GetExtension(recordHeaderV4, EXinmonFrame);
        if (inmonFrame) {
            // XXX FIX! todo
            // decode packet
        }
        */

        if (printRecord) {
            flow_record_short(stdout, recordHeaderV4);
        }

        fs->dataBlock->rawSize += recordHeaderV4->size;
        fs->dataBlock->numRecords++;

        // buffer size sanity check
        if (fs->dataBlock->rawSize > BLOCK_SIZE_V3) {
            // should never happen
            LogError("Process ipfix: Output buffer overflow! Flush buffer and skip records.");
            LogError("Buffer size: %u > %u", fs->dataBlock->rawSize, BLOCK_SIZE_V3);

            // reset buffer
            *fs->dataBlock = (flowBlockV3_t){.type = BLOCK_TYPE_FLOW, .rawSize = sizeof(flowBlockV3_t)};
            return;
        }
    }

}  // End of Process_ipfix_data

static inline void Process_ipfix_sampler_option_data(exporter_entry_t *exporter_entry, FlowSource_t *fs, template_t *template,
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
                LogError("Process_ipfix_option: Zero sampling interval -> sampling == 1", __FILE__, __LINE__);
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
        sampler_record.inUse = 1;

        // map plain interval data into packet space/interval
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
                LogError("Process_ipfix_option: Zero sampling interval -> sampling == 1", __FILE__, __LINE__);
            }
        }
        dbg_printf("ID : %" PRId64 ", algorithm : %u, packet interval: %u, packet space: %u\n", sampler_record.selectorID, sampler_record.algorithm,
                   sampler_record.packetInterval, sampler_record.spaceInterval);
    }

    if (sampler_record.inUse) InsertSampler(exporter_entry, &sampler_record);
    processed_records++;

}  // End of Process_ipfix_sampler_option_data

// XXX FIX!

static void Process_ipfix_nbar_option_data(exporter_entry_t *exporter_entry, FlowSource_t *fs, template_t *template, const uint8_t *data_flowset) {
    /*
    uint32_t size_left = GET_FLOWSET_LENGTH(data_flowset) - 4;  // -4 for data flowset header -> id and length
    dbg_printf("[%u] Process nbar option data flowset size: %u\n", exporter_entry->info->id, size_left);

    optionTemplate_t *optionTemplate = (optionTemplate_t *)template->data;
    struct nbarOptionList_s *nbarOption = &(optionTemplate->nbarOption);

    // map input buffer as a byte array
    const uint8_t *inBuff = (uint8_t *)(data_flowset + 4);  // skip flowset header
    // data size
    size_t data_size = nbarOption->id.length + nbarOption->name.length + nbarOption->desc.length;
    // size of record
    size_t option_size = optionTemplate->optionSize;
    // number of records in data
    unsigned numRecords = size_left / option_size;
    dbg_printf("[%u] nbar option data - records: %u, size: %zu\n", exporter_entry->info->id, numRecords, option_size);

    if (numRecords == 0 || option_size == 0 || option_size > size_left) {
        LogError("Process_nbar_option: nbar option size error: option size: %zu, size left: %u", option_size, size_left);
        return;
    }
    if (nbarOption->name.length == 0 && nbarOption->desc.length == 0) {
        LogInfo("Process_nbar_option: nbar name and description length 0 - skip data");
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
        fs->dataBlock = PushBlockV3(fs->blockQueue, fs->dataBlock);
    }

    void *outBuff = GetCursor(fs->dataBlock);
    // push nbar header
    AddArrayHeader(outBuff, nbarHeader, NbarRecordType, elementSize);

    // put array info descriptor next
    NbarAppInfo_t *NbarInfo = (NbarAppInfo_t *)(outBuff + sizeof(arrayRecordHeader_t));
    nbarHeader->size += sizeof(NbarAppInfo_t);

    // info record for each element in array
    NbarInfo->app_id_length = nbarOption->id.length;
    NbarInfo->app_name_length = nbarOption->name.length;
    NbarInfo->app_desc_length = nbarOption->desc.length;
    dbg_printf("NBAR idLength: %u, nameLength: %u, descLength: %u\n", nbarOption->id.length, nbarOption->name.length, nbarOption->desc.length);

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
        if (nbarOption->name.length) p[nbarOption->name.length - 1] = '\0';
        p += nbarOption->name.length;

        // description string
        memcpy(p, inBuff + nbarOption->desc.offset, nbarOption->desc.length);
        state = UTF8_ACCEPT;
        if (validate_utf8(&state, (char *)p, nbarOption->desc.length) == UTF8_REJECT) {
            LogError("Process_nbar_option: validate_utf8() %s line %d: %s", __FILE__, __LINE__, "invalid utf8 nbar description");
            err = 1;
        }
        if (nbarOption->desc.length) p[nbarOption->desc.length - 1] = '\0';
#ifdef DEVEL
        cnt++;
        if (err == 0) {
            printf("nbar record: %d, ", cnt);
            uint8_t *u = (uint8_t *)(p - nbarOption->name.length - nbarOption->id.length);
            for (int i = 0; i < nbarOption->id.length; i++) printf("%02X ", *((uint8_t *)u++));

            printf("nbar record: %d, ", cnt);
            if (nbarOption->name.length)
                printf("name: %s, ", p - nbarOption->name.length);
            else
                printf("name: <empty>");
            if (nbarOption->desc.length)
                printf("desc: %s\n", p);
            else
                printf("desc: <empty>\n");
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
        LogInfo("Process nbar data record - %u extra bytes", size_left);
    }
    processed_records++;

    dbg_printf("nbar processed: %u records - header: size: %u, type: %u, numelements: %u, elementSize: %u\n", numRecords, nbarHeader->size,
               nbarHeader->type, nbarHeader->numElements, nbarHeader->elementSize);
    */
}  // End of Process_ipfix_nbar_option_data

static void Process_ifvrf_option_data(exporter_entry_t *exporter_entry, FlowSource_t *fs, int type, template_t *template,
                                      const uint8_t *data_flowset) {
    /*
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
        const uint8_t *inBuff = (uint8_t *)(data_flowset + 4);  // skip flowset header
        // data size
        size_t data_size = nameOption->name.length + sizeof(uint32_t);
        // size of record
        size_t option_size = optionTemplate->optionSize;
        // number of records in data
        unsigned numRecords = size_left / option_size;
        dbg_printf("[%u] name option data - records: %u, size: %zu\n", exporter_entry->info->id, numRecords, option_size);

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
            fs->dataBlock = PushBlockV3(fs->blockQueue, fs->dataBlock);
        }

        void *outBuff = GetCursor(fs->dataBlock);
        // push nbar header
        AddArrayHeader(outBuff, nameHeader, recordType, elementSize);

        // put array info descriptor next
        uint32_t *nameSize = (uint32_t *)(outBuff + sizeof(arrayRecordHeader_t));
        nameHeader->size += sizeof(uint32_t);

        // info record for each element in array
        *nameSize = nameOption->name.length;

        dbg(unsigned cnt = 0);
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
                printf("name record: %u: ingress: %d, %s\n", cnt, val, p);
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
            LogInfo("Process ifvrf data record - %u extra bytes", size_left);
        }
        processed_records++;

        dbg_printf("if/vrf name processed: %u records - header: size: %u, type: %u, numelements: %u, elementSize: %u\n", numRecords, nameHeader->size,
                   nameHeader->type, nameHeader->numElements, nameHeader->elementSize);
        */

}  // End of Process_ifvrf_option_data

static void Process_ipfix_SysUpTime_option_data(exporter_entry_t *exporter_entry, template_t *template, const uint8_t *data_flowset) {
    exporter_ipfix_t *exporter_ipfix = &(exporter_entry->ipfix);
    uint32_t size_left = GET_FLOWSET_LENGTH(data_flowset) - 4;  // -4 for data flowset header -> id and length
    dbg_printf("[%u] Process sysup option data flowset size: %u\n", exporter_entry->info->id, size_left);

    optionTemplate_t *optionTemplate = (optionTemplate_t *)template->data;

    // map input buffer as a byte array
    const uint8_t *in = (uint8_t *)(data_flowset + 4);  // skip flowset header
    if (CHECK_OPTION_DATA(size_left, optionTemplate->SysUpOption)) {
        exporter_ipfix->SysUpTime = Get_val(in, optionTemplate->SysUpOption.offset, optionTemplate->SysUpOption.length);
        dbg_printf("Extracted SysUpTime : %" PRIu64 "\n", exporter_ipfix->SysUpTime);
    } else {
        LogError("Process_ipfix_option: %s line %d: Not enough data for option data", __FILE__, __LINE__);
        return;
    }

}  // End of Process_ipfix_SysUpTime_option_data

static void ProcessOptionFlowset(exporter_entry_t *exporter_entry, FlowSource_t *fs, template_t *template, const uint8_t *data_flowset) {
    if (TestFlag(template->type, SAMPLER_TEMPLATE)) {
        dbg_printf("Found sampler option table\n");
        Process_ipfix_sampler_option_data(exporter_entry, fs, template, data_flowset);
    }
    if (TestFlag(template->type, NBAR_TEMPLATE)) {
        dbg_printf("Found nbar option table\n");
        Process_ipfix_nbar_option_data(exporter_entry, fs, template, data_flowset);
    }
    if (TestFlag(template->type, IFNAME_TEMPLATE)) {
        dbg_printf("Found ifname option data\n");
        Process_ifvrf_option_data(exporter_entry, fs, IFNAME_TEMPLATE, template, data_flowset);
    }

    if (TestFlag(template->type, VRFNAME_TEMPLATE)) {
        dbg_printf("Found vrfname option data\n");
        Process_ifvrf_option_data(exporter_entry, fs, VRFNAME_TEMPLATE, template, data_flowset);
    }
    if (TestFlag(template->type, SYSUPTIME_TEMPLATE)) {
        dbg_printf("Found SysUpTime option data\n");
        Process_ipfix_SysUpTime_option_data(exporter_entry, template, data_flowset);
    }

    processed_records++;

}  // End of ProcessOptionFlowset

void Process_IPFIX(void *in_buff, ssize_t in_buff_cnt, FlowSource_t *fs) {
#ifdef DEVEL
    static uint32_t pkg_num = 1;
    printf("Process_ipfix: Next packet: %i\n", pkg_num);
#endif

    ssize_t size_left = in_buff_cnt;
    if (size_left < (ssize_t)IPFIX_HEADER_LENGTH) {
        LogError("Process_ipfix: Too little data for ipfix packet: '%lli'", (long long)size_left);
        return;
    }

    ipfix_header_t *ipfix_header = (ipfix_header_t *)in_buff;
    uint32_t ExportTime = ntohl(ipfix_header->ExportTime);
    uint32_t Sequence = ntohl(ipfix_header->LastSequence);

    uint32_t ObservationDomain = ntohl(ipfix_header->ObservationDomain);
    exporter_entry_t *exporter_entry = getExporter(fs, ObservationDomain);
    if (!exporter_entry) {
        LogError("Process_ipfix: Exporter NULL: Abort ipfix record processing");
        return;
    }
    exporter_entry->packets++;
    exporter_ipfix_t *exporter_ipfix = &(exporter_entry->ipfix);

    // exporter->PacketSequence = Sequence;
    void *flowset_header = (void *)ipfix_header + IPFIX_HEADER_LENGTH;
    size_left -= IPFIX_HEADER_LENGTH;

    dbg_printf("\n[%u] process packet: %u, export time: %s, TemplateRecords: %u, DataRecords: %" PRIu64 ", buffer: %zd \n", ObservationDomain,
               pkg_num++, UNIX2ISO(ExportTime), exporter_ipfix->TemplateRecords, exporter_ipfix->DataRecords, size_left);
    dbg_printf("[%u] Sequence: %u\n", ObservationDomain, Sequence);

    // sequence check - difficult for ipfix, as *all* data records count
    // 2^32 wrap is handled automatically as both counters overflow
    if (Sequence != exporter_ipfix->PacketSequence) {
        if (exporter_ipfix->DataRecords != 0) {
            // sync sequence on first data record without error report
            fs->stat_record.sequence_failure++;
            exporter_entry->sequence_failure++;
            dbg_printf("[%u] Sequence check failed: last seq: %u, seq %u\n", exporter_entry->info->id, Sequence, exporter_ipfix->PacketSequence);
        } else {
            dbg_printf("[%u] Sync Sequence: %u\n", exporter_entry->info->id, Sequence);
        }
        exporter_ipfix->PacketSequence = Sequence;
    } else {
        dbg_printf("[%u] Sequence check ok\n", exporter_entry->info->id);
    }

    // iterate over all set
    uint32_t flowset_length = 0;
    while (size_left) {
        uint16_t flowset_id;
        if (size_left < 4) {
            return;
        }

        // grab flowset header
        flowset_header = flowset_header + flowset_length;
        flowset_id = GET_FLOWSET_ID(flowset_header);
        flowset_length = GET_FLOWSET_LENGTH(flowset_header);

        dbg_printf("Process_ipfix: Next flowset id %u, length %u, buffersize: %zi\n", flowset_id, flowset_length, size_left);

        if (flowset_length == 0) {
            /* 	this should never happen, as 4 is an empty flowset
                    and smaller is an illegal flowset anyway ...
                    if it happens, we can't determine the next flowset, so skip the entire export
               packet
             */
            LogError("Process_ipfix: flowset zero length error.");
            dbg_printf("Process_ipfix: flowset zero length error.\n");
            return;
        }

        // possible padding
        if (flowset_length <= 4) {
            return;
        }

        if (flowset_length > size_left) {
            LogError("Process_ipfix: flowset length error. Expected bytes: %u > buffersize: %lli", flowset_length, (long long)size_left);
            return;
        }

        switch (flowset_id) {
            case IPFIX_TEMPLATE_FLOWSET_ID:
                exporter_ipfix->TemplateRecords++;
                dbg_printf("Process template flowset, length: %u\n", flowset_length);
                Process_ipfix_templates(exporter_entry, flowset_header, flowset_length, fs);
                break;
            case IPFIX_OPTIONS_FLOWSET_ID:
                // option_flowset = (option_template_flowset_t *)flowset_header;
                exporter_ipfix->TemplateRecords++;
                dbg_printf("Process option template flowset, length: %u\n", flowset_length);
                Process_ipfix_option_templates(exporter_entry, flowset_header);
                break;
            default: {
                if (flowset_id < IPFIX_MIN_RECORD_FLOWSET_ID) {
                    dbg_printf("Invalid flowset id: %u. Skip flowset\n", flowset_id);
                    LogError("Process_ipfix: Invalid flowset id: %u. Skip flowset", flowset_id);
                } else {
                    dbg_printf("Process data flowset, length: %u\n", flowset_length);
                    template_t *template = getTemplate(exporter_entry, flowset_id);
                    if (template) {
                        if (TestFlag(template->type, DATA_TEMPLATE)) {
                            dbg_printf("Process ipfix data\n");
                            Process_ipfix_data(exporter_entry, ExportTime, flowset_header, fs, (pipeline_t *)template->data);
                            exporter_ipfix->DataRecords++;
                        } else {
                            dbg_printf("Process ipfix option\n");
                            ProcessOptionFlowset(exporter_entry, fs, template, flowset_header);
                        }
                    } else {
                        dbg_printf("No template with id: %u, Skip length: %u\n", flowset_id, flowset_length);
                    }
                }
            }
        }  // End of switch

        // next record
        size_left -= flowset_length;

    }  // End of while

}  // End of Process_IPFIX
