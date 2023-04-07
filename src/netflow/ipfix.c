/*
 *  Copyright (c) 2012-2023, Peter Haag
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
#include "util.h"

// define stack slots
enum {
    STACK_NONE = 0,
    STACK_ICMP,
    STACK_ICMPTYPE,
    STACK_ICMPCODE,
    STACK_DSTPORT,
    STACK_SAMPLER,
    STACK_MSECFIRST,
    STACK_MSECLAST,
    STACK_DURATION,
    STACK_MSEC,
    STACK_SYSUPTIME,
    STACK_ENGINETYPE,
    STACK_ENGINEID,
    STACK_MAX
};

/*
 * 	All Observation Domains from all exporter are stored in a linked list
 *	which uniquely can identify each exporter/Observation Domain
 */
typedef struct exporterDomain_s {
    struct exporterDomain_s *next;  // linkes list to next exporter

    // exporter information
    exporter_info_record_t info;

    uint64_t packets;           // number of packets sent by this exporter
    uint64_t flows;             // number of flow records sent by this exporter
    uint32_t sequence_failure;  // number of sequence failures

    // sampling information:
    // each flow source may have several sampler applied:
    // SAMPLER_OVERWRITE - supplied on cmd line -s -interval
    // SAMPLER_DEFAULT   - supplied on cmd line -s interval
    // SAMPLER_GENERIC   - sampling information tags #34 #35
    // samplerID         - sampling information tags #48, #49, #50 - mapped to
    // samplerID         - sampling information tags #302, #304, #305, #306
    sampler_t *sampler;  // sampler info

    // exporter parameters
    uint32_t ExportTime;

    // Current sequence number
    uint32_t PacketSequence;

    // statistics
    uint64_t TemplateRecords;  // stat counter
    uint64_t DataRecords;      // stat counter

    // SysUptime if sent with #160
    uint64_t SysUpTime;  // in msec

    // in order to prevent search through all lists keep
    // the last template we processed as a cache
    templateList_t *currentTemplate;

    // list of all templates of this exporter
    templateList_t *template;

} exporterDomain_t;

static int ExtensionsEnabled[MAXEXTENSIONS];

static const struct ipfixTranslationMap_s {
    uint16_t id;  // IPFIX element id
#define Stack_ONLY 0
    uint16_t outputLength;  // output length in extension ID
    uint16_t copyMode;      // number or byte copy
    uint16_t extensionID;   // extension ID
    uint32_t offsetRel;     // offset rel. to extension start of struct
    uint32_t stackID;       // save value in stack slot, if needed
    char *name;             // name of element as string
} ipfixTranslationMap[] = {
    {IPFIX_octetDeltaCount, SIZEinBytes, NumberCopy, EXgenericFlowID, OFFinBytes, STACK_NONE, "octetDeltaCount"},
    {IPFIX_packetDeltaCount, SIZEinPackets, NumberCopy, EXgenericFlowID, OFFinPackets, STACK_NONE, "packetDeltaCount"},
    {IPFIX_initiatorPackets, SIZEinPackets, NumberCopy, EXgenericFlowID, OFFinPackets, STACK_NONE, "initiator packets"},
    {IPFIX_deltaFlowCount, SIZEflows, NumberCopy, EXcntFlowID, OFFflows, STACK_NONE, "deltaFlowCount"},
    {IPFIX_protocolIdentifier, SIZEproto, NumberCopy, EXgenericFlowID, OFFproto, STACK_NONE, "proto"},
    {IPFIX_ipClassOfService, SIZEsrcTos, NumberCopy, EXgenericFlowID, OFFsrcTos, STACK_NONE, "src tos"},
    {IPFIX_forwardingStatus, SIZEfwdStatus, NumberCopy, EXgenericFlowID, OFFfwdStatus, STACK_NONE, "forwarding status"},
    {IPFIX_tcpControlBits, SIZEtcpFlags, NumberCopy, EXgenericFlowID, OFFtcpFlags, STACK_NONE, "TCP flags"},
    {IPFIX_SourceTransportPort, SIZEsrcPort, NumberCopy, EXgenericFlowID, OFFsrcPort, STACK_NONE, "src port"},
    {IPFIX_SourceIPv4Address, SIZEsrc4Addr, NumberCopy, EXipv4FlowID, OFFsrc4Addr, STACK_NONE, "src IPv4"},
    {IPFIX_SourceIPv4PrefixLength, SIZEsrcMask, NumberCopy, EXflowMiscID, OFFsrcMask, STACK_NONE, "src mask IPv4"},
    {IPFIX_ingressInterface, SIZEinput, NumberCopy, EXflowMiscID, OFFinput, STACK_NONE, "input interface"},
    {IPFIX_DestinationTransportPort, SIZEdstPort, NumberCopy, EXgenericFlowID, OFFdstPort, STACK_DSTPORT, "dst port"},
    {IPFIX_DestinationIPv4Address, SIZEdst4Addr, NumberCopy, EXipv4FlowID, OFFdst4Addr, STACK_NONE, "dst IPv4"},
    {IPFIX_DestinationIPv4PrefixLength, SIZEdstMask, NumberCopy, EXflowMiscID, OFFdstMask, STACK_NONE, "dst mask IPv4"},
    {IPFIX_egressInterface, SIZEoutput, NumberCopy, EXflowMiscID, OFFoutput, STACK_NONE, "output interface"},
    {IPFIX_ipNextHopIPv4Address, SIZENext4HopIP, NumberCopy, EXipNextHopV4ID, OFFNext4HopIP, STACK_NONE, "IPv4 next hop"},
    {IPFIX_bgpSourceAsNumber, SIZEsrcAS, NumberCopy, EXasRoutingID, OFFsrcAS, STACK_NONE, "src AS"},
    {IPFIX_bgpDestinationAsNumber, SIZEdstAS, NumberCopy, EXasRoutingID, OFFdstAS, STACK_NONE, "dst AS"},
    {IPFIX_bgpNextHopIPv4Address, SIZEbgp4NextIP, NumberCopy, EXbgpNextHopV4ID, OFFbgp4NextIP, STACK_NONE, "IPv4 bgp next hop"},
    {IPFIX_flowEndSysUpTime, Stack_ONLY, NumberCopy, EXnull, 0, STACK_MSECLAST, "msec last SysupTime"},
    {IPFIX_flowStartSysUpTime, Stack_ONLY, NumberCopy, EXnull, 0, STACK_MSECFIRST, "msec first SysupTime"},
    {IPFIX_SystemInitTimeMiliseconds, Stack_ONLY, NumberCopy, EXnull, 0, STACK_SYSUPTIME, "SysupTime msec"},
    {IPFIX_postOctetDeltaCount, SIZEoutBytes, NumberCopy, EXcntFlowID, OFFoutBytes, STACK_NONE, "output bytes delta counter"},
    {IPFIX_postPacketDeltaCount, SIZEoutPackets, NumberCopy, EXcntFlowID, OFFoutPackets, STACK_NONE, "output packet delta counter"},
    {IPFIX_responderPackets, SIZEoutPackets, NumberCopy, EXcntFlowID, OFFoutPackets, STACK_NONE, "responder packets"},
    {IPFIX_newconnections, SIZEflows, NumberCopy, EXcntFlowID, OFFflows, STACK_NONE, "connections"},
    {IPFIX_SourceIPv6Address, SIZEsrc6Addr, NumberCopy, EXipv6FlowID, OFFsrc6Addr, STACK_NONE, "IPv6 src addr"},
    {IPFIX_DestinationIPv6Address, SIZEdst6Addr, NumberCopy, EXipv6FlowID, OFFdst6Addr, STACK_NONE, "IPv6 dst addr"},
    {IPFIX_SourceIPv6PrefixLength, SIZEsrcMask, NumberCopy, EXflowMiscID, OFFsrcMask, STACK_NONE, "src mask bits"},
    {IPFIX_DestinationIPv6PrefixLength, SIZEdstMask, NumberCopy, EXflowMiscID, OFFdstMask, STACK_NONE, "dst mask bits"},
    {IPFIX_icmpTypeCodeIPv4, SIZEdstPort, NumberCopy, EXgenericFlowID, OFFdstPort, STACK_ICMP, "icmp v4 type/code"},
    {IPFIX_icmpTypeCodeIPv6, SIZEdstPort, NumberCopy, EXgenericFlowID, OFFdstPort, STACK_ICMP, "icmp v6 type/code"},
    {IPFIX_icmpTypeV4, SIZEicmpCode, Stack_ONLY, EXgenericFlowID, OFFicmpType, STACK_ICMPTYPE, "icmp v4 type"},
    {IPFIX_icmpCodeV4, SIZEicmpType, Stack_ONLY, EXgenericFlowID, OFFicmpCode, STACK_ICMPCODE, "icmp v4 code"},
    {IPFIX_icmpTypeV6, SIZEicmpCode, Stack_ONLY, EXgenericFlowID, OFFicmpType, STACK_ICMPTYPE, "icmp v6 type"},
    {IPFIX_icmpCodeV6, SIZEicmpType, Stack_ONLY, EXgenericFlowID, OFFicmpCode, STACK_ICMPCODE, "icmp v6 code"},
    {IPFIX_postIpClassOfService, SIZEdstTos, NumberCopy, EXflowMiscID, OFFdstTos, STACK_NONE, "post IP class of Service"},
    {IPFIX_SourceMacAddress, SIZEinSrcMac, NumberCopy, EXmacAddrID, OFFinSrcMac, STACK_NONE, "in src MAC addr"},
    {IPFIX_postDestinationMacAddress, SIZEoutDstMac, NumberCopy, EXmacAddrID, OFFoutDstMac, STACK_NONE, "out dst MAC addr"},
    {IPFIX_vlanId, SIZEsrcVlan, NumberCopy, EXvLanID, OFFsrcVlan, STACK_NONE, "src VLAN ID"},
    {IPFIX_postVlanId, SIZEdstAS, NumberCopy, EXvLanID, OFFdstAS, STACK_NONE, "dst VLAN ID"},
    {IPFIX_flowDirection, SIZEdir, NumberCopy, EXflowMiscID, OFFdir, STACK_NONE, "flow direction"},
    {IPFIX_biflowDirection, SIZEbiFlowDir, NumberCopy, EXflowMiscID, OFFbiFlowDir, STACK_NONE, "biFlow direction"},
    {IPFIX_flowEndReason, SIZEflowEndReason, NumberCopy, EXflowMiscID, OFFflowEndReason, STACK_NONE, "Flow end reason"},
    {IPFIX_ipNextHopIPv6Address, SIZENext6HopIP, NumberCopy, EXipNextHopV6ID, OFFNext6HopIP, STACK_NONE, "IPv6 next hop IP"},
    {IPFIX_bgpNextHopIPv6Address, SIZEbgp6NextIP, NumberCopy, EXbgpNextHopV6ID, OFFbgp6NextIP, STACK_NONE, "IPv6 bgp next hop IP"},
    {IPFIX_mplsTopLabelStackSection, SIZEmplsLabel1, NumberCopy, EXmplsLabelID, OFFmplsLabel1, STACK_NONE, "mpls label 1"},
    {IPFIX_mplsLabelStackSection2, SIZEmplsLabel2, NumberCopy, EXmplsLabelID, OFFmplsLabel2, STACK_NONE, "mpls label 2"},
    {IPFIX_mplsLabelStackSection3, SIZEmplsLabel3, NumberCopy, EXmplsLabelID, OFFmplsLabel3, STACK_NONE, "mpls label 3"},
    {IPFIX_mplsLabelStackSection4, SIZEmplsLabel4, NumberCopy, EXmplsLabelID, OFFmplsLabel4, STACK_NONE, "mpls label 4"},
    {IPFIX_mplsLabelStackSection5, SIZEmplsLabel5, NumberCopy, EXmplsLabelID, OFFmplsLabel5, STACK_NONE, "mpls label 5"},
    {IPFIX_mplsLabelStackSection6, SIZEmplsLabel6, NumberCopy, EXmplsLabelID, OFFmplsLabel6, STACK_NONE, "mpls label 6"},
    {IPFIX_mplsLabelStackSection7, SIZEmplsLabel7, NumberCopy, EXmplsLabelID, OFFmplsLabel7, STACK_NONE, "mpls label 7"},
    {IPFIX_mplsLabelStackSection8, SIZEmplsLabel8, NumberCopy, EXmplsLabelID, OFFmplsLabel8, STACK_NONE, "mpls label 8"},
    {IPFIX_mplsLabelStackSection9, SIZEmplsLabel9, NumberCopy, EXmplsLabelID, OFFmplsLabel9, STACK_NONE, "mpls label 9"},
    {IPFIX_mplsLabelStackSection10, SIZEmplsLabel10, NumberCopy, EXmplsLabelID, OFFmplsLabel10, STACK_NONE, "mpls label 10"},
    {IPFIX_DestinationMacAddress, SIZEinDstMac, NumberCopy, EXmacAddrID, OFFinDstMac, STACK_NONE, "in dst MAC addr"},
    {IPFIX_postSourceMacAddress, SIZEoutSrcMac, NumberCopy, EXmacAddrID, OFFoutSrcMac, STACK_NONE, "out src MAC addr"},
    {IPFIX_octetTotalCount, SIZEinBytes, NumberCopy, EXgenericFlowID, OFFinBytes, STACK_NONE, "input octetTotalCount"},
    {IPFIX_packetTotalCount, SIZEinPackets, NumberCopy, EXgenericFlowID, OFFinPackets, STACK_NONE, "input packetTotalCount"},
    {IPFIX_flowStartMilliseconds, SIZEmsecFirst, NumberCopy, EXgenericFlowID, OFFmsecFirst, STACK_NONE, "msec first"},
    {IPFIX_flowEndMilliseconds, SIZEmsecLast, NumberCopy, EXgenericFlowID, OFFmsecLast, STACK_NONE, "msec last"},
    {IPFIX_flowStartDeltaMicroseconds, SIZEmsecFirst, NumberCopy, EXgenericFlowID, OFFmsecFirst, STACK_NONE, "msec first"},
    {IPFIX_flowEndDeltaMicroseconds, SIZEmsecLast, NumberCopy, EXgenericFlowID, OFFmsecLast, STACK_NONE, "msec last"},
    {IPFIX_flowDurationMilliseconds, Stack_ONLY, NumberCopy, EXnull, 0, STACK_DURATION, "duration msec"},
    {LOCAL_IPv4Received, SIZEReceived4IP, NumberCopy, EXipReceivedV4ID, OFFReceived4IP, STACK_NONE, "IPv4 exporter"},
    {LOCAL_IPv6Received, SIZEReceived6IP, NumberCopy, EXipReceivedV6ID, OFFReceived6IP, STACK_NONE, "IPv6 exporter"},
    {LOCAL_msecTimeReceived, SIZEmsecReceived, NumberCopy, EXgenericFlowID, OFFmsecReceived, STACK_NONE, "msec time received"},
    {IPFIX_postOctetTotalCount, SIZEoutBytes, NumberCopy, EXcntFlowID, OFFoutBytes, STACK_NONE, "output octetTotalCount"},
    {IPFIX_postPacketTotalCount, SIZEoutPackets, NumberCopy, EXcntFlowID, OFFoutPackets, STACK_NONE, "output packetTotalCount"},
    {IPFIX_engineType, Stack_ONLY, NumberCopy, EXnull, 0, STACK_ENGINETYPE, "engine type"},
    {IPFIX_engineId, Stack_ONLY, NumberCopy, EXnull, 0, STACK_ENGINEID, "engine ID"},
    {NBAR_APPLICATION_ID, SIZEnbarAppID, NumberCopy, EXnbarAppID, OFFnbarAppID, STACK_NONE, "nbar application ID"},
    {IPFIX_observationDomainId, SIZEdomainID, NumberCopy, EXobservationID, OFFdomainID, STACK_NONE, "observation domainID"},
    {IPFIX_observationPointId, SIZEpointID, NumberCopy, EXobservationID, OFFpointID, STACK_NONE, "observation pointID"},
    // sampling
    {IPFIX_samplerId, SIZEsampID, NumberCopy, EXsamplerInfoID, OFFsampID, STACK_SAMPLER, "sampler ID"},
    {IPFIX_selectorId, SIZEsampID, NumberCopy, EXsamplerInfoID, OFFsampID, STACK_SAMPLER, "sampler ID"},
    {IPFIX_INGRESS_VRFID, SIZEingressVrf, NumberCopy, EXvrfID, OFFingressVrf, STACK_NONE, "ingress VRF ID"},
    {IPFIX_EGRESS_VRFID, SIZEegressVrf, NumberCopy, EXvrfID, OFFegressVrf, STACK_NONE, "egress VRF ID"},
    // NAT
    {IPFIX_observationTimeMilliseconds, SIZEmsecEvent, NumberCopy, EXnelCommonID, OFFmsecEvent, STACK_MSEC, "msec time event"},
    {IPFIX_natEvent, SIZEnatEvent, NumberCopy, EXnelCommonID, OFFnatEvent, STACK_NONE, "NAT event"},
    {IPFIX_postNATSourceIPv4Address, SIZExlateSrc4Addr, NumberCopy, EXnselXlateIPv4ID, OFFxlateSrc4Addr, STACK_NONE, "xlate src addr"},
    {IPFIX_postNATDestinationIPv4Address, SIZExlateDst4Addr, NumberCopy, EXnselXlateIPv4ID, OFFxlateDst4Addr, STACK_NONE, "xlate dst addr"},
    {IPFIX_postNAPTSourceTransportPort, SIZExlateSrcPort, NumberCopy, EXnselXlatePortID, OFFxlateSrcPort, STACK_NONE, "xlate src port"},
    {IPFIX_postNAPTDestinationTransportPort, SIZExlateDstPort, NumberCopy, EXnselXlatePortID, OFFxlateDstPort, STACK_NONE, "xlate dst port"},

    // payload
    {LOCAL_inPayload, VARLENGTH, NumberCopy, EXinPayloadID, 0, STACK_NONE, "in payload"},
    {LOCAL_outPayload, VARLENGTH, NumberCopy, EXoutPayloadID, 0, STACK_NONE, "out payload"},

    // End of table
    {0, 0, 0, 0, 0, STACK_NONE, NULL},

};

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
uint32_t defaultSampling;

// prototypes
static void InsertSampler(FlowSource_t *fs, exporterDomain_t *exporter, sampler_record_t *sampler_record);

static exporterDomain_t *getExporter(FlowSource_t *fs, uint32_t ObservationDomain);

static void Process_ipfix_templates(exporterDomain_t *exporter, void *flowset_header, uint32_t size_left, FlowSource_t *fs);

static void Process_ipfix_template_add(exporterDomain_t *exporter, void *DataPtr, uint32_t size_left, FlowSource_t *fs);

static void Process_ipfix_template_withdraw(exporterDomain_t *exporter, void *DataPtr, uint32_t size_left, FlowSource_t *fs);

static void Process_ipfix_option_templates(exporterDomain_t *exporter, void *option_template_flowset, FlowSource_t *fs);

static void ProcessOptionFlowset(exporterDomain_t *exporter, FlowSource_t *fs, templateList_t *template, void *data_flowset);

static void Process_ifvrf_option_data(exporterDomain_t *exporter, FlowSource_t *fs, int type, templateList_t *template, void *data_flowset);

static void Process_ipfix_data(exporterDomain_t *exporter, uint32_t ExportTime, void *data_flowset, FlowSource_t *fs, dataTemplate_t *template);

static int LookupElement(uint16_t type, uint32_t EnterpriseNumber);

#include "inline.c"
#include "nffile_inline.c"

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
    for (int i = 0; ipfixTranslationMap[i].name != NULL; i++) {
        int extID = ipfixTranslationMap[i].extensionID;
        if (ExtensionsEnabled[extID]) tagsEnabled++;
    }

    if (sampling < 0) {
        LogInfo("Init IPFIX: Max number of ipfix tags enabled: %u, overwrite sampling: %d", tagsEnabled, -defaultSampling);
        dbg_printf("Initv9: Overwrite sampling: %d\n", -defaultSampling);
    } else {
        LogInfo("Init IPFIX: Max number of ipfix tags enabled: %u, default sampling: %d", tagsEnabled, defaultSampling);
        dbg_printf("Initv9: Default sampling: %d\n", defaultSampling);
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

    int i = 0;
    while (ipfixTranslationMap[i].name != NULL) {
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

    dbg_printf(" No mapping for enterprise: %u, type: %u\n", EnterpriseNumber, type);
    return -1;

}  // End of LookupElement

static exporterDomain_t *getExporter(FlowSource_t *fs, uint32_t ObservationDomain) {
#define IP_STRING_LEN 40
    char ipstr[IP_STRING_LEN];
    exporterDomain_t **e = (exporterDomain_t **)&(fs->exporter_data);

    while (*e) {
        if ((*e)->info.id == ObservationDomain && (*e)->info.version == 10 && (*e)->info.ip.V6[0] == fs->ip.V6[0] &&
            (*e)->info.ip.V6[1] == fs->ip.V6[1])
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
        LogError("Process_ipfix: Panic! malloc() %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }
    (*e)->info.header.type = ExporterInfoRecordType;
    (*e)->info.header.size = sizeof(exporter_info_record_t);
    (*e)->info.id = ObservationDomain;
    (*e)->info.ip = fs->ip;
    (*e)->info.sa_family = fs->sa_family;
    (*e)->info.version = 10;
    (*e)->info.sysid = 0;

    (*e)->TemplateRecords = 0;
    (*e)->DataRecords = 0;
    (*e)->sequence_failure = 0;
    (*e)->next = NULL;
    (*e)->sampler = NULL;

    FlushInfoExporter(fs, &((*e)->info));

    if (defaultSampling < 0) {
        // map hard overwrite sampling into a static sampler
        sampler_record_t sampler_record;
        sampler_record.id = SAMPLER_OVERWRITE;
        sampler_record.packetInterval = 1;
        sampler_record.algorithm = 0;
        sampler_record.spaceInterval = (-defaultSampling) - 1;
        InsertSampler(fs, (*e), &sampler_record);
        dbg_printf("Add static sampler for overwrite sampling: %d\n", -defaultSampling);
    } else if (defaultSampling > 1) {
        // map default sampling > 1 into a static sampler
        sampler_record_t sampler_record;
        sampler_record.id = SAMPLER_DEFAULT;
        sampler_record.packetInterval = 1;
        sampler_record.algorithm = 0;
        sampler_record.spaceInterval = defaultSampling - 1;
        InsertSampler(fs, (*e), &sampler_record);
        dbg_printf("Add static sampler for default sampling: %u\n", defaultSampling);
    }

    dbg_printf("[%u] New ipfix exporter: SysID: %u, Observation domain %u from: %s:%u\n", ObservationDomain, (*e)->info.sysid, ObservationDomain,
               ipstr, fs->port);
    LogInfo("Process_ipfix: New ipfix exporter: SysID: %u, Observation domain %u from: %s", (*e)->info.sysid, ObservationDomain, ipstr);

    return (*e);

}  // End of getExporter

static void InsertSampler(FlowSource_t *fs, exporterDomain_t *exporter, sampler_record_t *sampler_record) {
    sampler_t *sampler;

    dbg_printf("[%u] Insert Sampler: Exporter is 0x%llu\n", exporter->info.id, (long long unsigned)exporter);
    if (!exporter->sampler) {
        // no samplers so far
        sampler = (sampler_t *)malloc(sizeof(sampler_t));
        if (!sampler) {
            LogError("Process_ipfix: Panic! malloc(): %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return;
        }

        sampler->record = *sampler_record;
        sampler->record.type = SamplerRecordType;
        sampler->record.size = sizeof(sampler_record_t);
        sampler->record.exporter_sysid = exporter->info.sysid;
        sampler->next = NULL;
        exporter->sampler = sampler;

        AppendToBuffer(fs->nffile, &(sampler->record), sampler->record.size);
        LogInfo("Add new sampler id: %lli, algorithm: %u, packet interval: %u, packet space: %u", sampler_record->id, sampler_record->algorithm,
                sampler_record->packetInterval, sampler_record->spaceInterval);
        dbg_printf("Add new sampler id: %lli, algorithm: %u, packet interval: %u, packet space: %u\n", sampler_record->id, sampler_record->algorithm,
                   sampler_record->packetInterval, sampler_record->spaceInterval);

    } else {
        sampler = exporter->sampler;
        while (sampler) {
            // test for update of existing sampler
            if (sampler->record.id == sampler_record->id) {
                // found same sampler id - update record if changed
                if (sampler_record->algorithm != sampler->record.algorithm || sampler_record->packetInterval != sampler->record.packetInterval ||
                    sampler_record->spaceInterval != sampler->record.spaceInterval) {
                    AppendToBuffer(fs->nffile, &(sampler->record), sampler->record.size);
                    sampler->record.algorithm = sampler_record->algorithm;
                    sampler->record.packetInterval = sampler_record->packetInterval;
                    sampler->record.spaceInterval = sampler_record->spaceInterval;
                    LogInfo("Update existing sampler id: %lli, algorithm: %u, packet interval: %u, packet space: %u", sampler_record->id,
                            sampler_record->algorithm, sampler_record->packetInterval, sampler_record->spaceInterval);
                    dbg_printf("Update existing sampler id: %lli, algorithm: %u, packet interval: %u, packet space: %u\n", sampler_record->id,
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
                sampler->record.exporter_sysid = exporter->info.sysid;
                sampler->next = NULL;

                AppendToBuffer(fs->nffile, &(sampler->record), sampler->record.size);
                LogInfo("Append new sampler id: %lli, algorithm: %u, packet interval: %u, packet space: %u", sampler_record->id,
                        sampler_record->algorithm, sampler_record->packetInterval, sampler_record->spaceInterval);
                dbg_printf("Append new sampler id: %lli, algorithm: %u, packet interval: %u, packet space: %u\n", sampler_record->id,
                           sampler_record->algorithm, sampler_record->packetInterval, sampler_record->spaceInterval);
                break;
            }

            // advance
            sampler = sampler->next;
        }
    }

}  // End of InsertSampler

static templateList_t *getTemplate(exporterDomain_t *exporter, uint16_t id) {
    templateList_t *template;

#ifdef DEVEL
    if (exporter->currentTemplate) {
        printf("Get template - current template: %u\n", exporter->currentTemplate->id);
    }
    printf("Get template - available templates for exporter: %u\n", exporter->info.id);
    template = exporter->template;
    while (template) {
        printf(" ID: %u, type: %u\n", template->id, template->type);
        template = template->next;
    }
    if (exporter->currentTemplate && (exporter->currentTemplate->id == id))
        printf("Get template - current template match: %u\n", exporter->currentTemplate->id);
#endif

    if (exporter->currentTemplate && (exporter->currentTemplate->id == id)) return exporter->currentTemplate;

    template = exporter->template;
    while (template) {
        if (template->id == id) {
            exporter->currentTemplate = template;
            dbg_printf("[%u] Get template - found %u\n", exporter->info.id, id);
            return template;
        }
        template = template->next;
    }

    dbg_printf("[%u] Get template - not found %u\n", exporter->info.id, id);

    exporter->currentTemplate = NULL;
    return NULL;

}  // End of getTemplate

static templateList_t *newTemplate(exporterDomain_t *exporter, uint16_t id) {
    templateList_t *template;

    template = calloc(1, sizeof(templateList_t));
    if (!template) {
        LogError("Process_ipfix: Panic! calloc() %s line %d: %s", __FILE__, __LINE__, strerror(errno));
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

    if (template->type == DATA_TEMPLATE) {
        dataTemplate_t *dataTemplate = (dataTemplate_t *)template->data;
        ClearSequencer(&(dataTemplate->sequencer));
        if (dataTemplate->extensionList) free(dataTemplate->extensionList);
    }
    free(template->data);
    free(template);

}  // End of removeTemplate

static void removeAllTemplates(exporterDomain_t *exporter) {
    templateList_t *template;

    LogInfo("Process_ipfix: Withdraw all templates from observation domain %u\n", exporter->info.id);

    template = exporter->template;
    while (template) {
        templateList_t *next;
        next = template->next;

        dbg_printf("\n[%u] Withdraw template ID: %u\n", exporter->info.id, template->id);

        if (template->type == DATA_TEMPLATE) {
            dataTemplate_t *dataTemplate = (dataTemplate_t *)template->data;
            ClearSequencer(&(dataTemplate->sequencer));
            if (dataTemplate->extensionList) free(dataTemplate->extensionList);
        }
        free(template->data);
        free(template);

        template = next;
    }

}  // End of removeAllTemplates

static void relinkSequencerList(exporterDomain_t *exporter) {
    templateList_t *template;

    template = exporter->template;
    while (template && template->type != DATA_TEMPLATE) template = template->next;

    if (!template) return;

    dataTemplate_t *dataTemplate = (dataTemplate_t *)template->data;
    sequencer_t *sequencer = &(dataTemplate->sequencer);
    sequencer_t *loop = sequencer;
    dbg_printf("Chain seqencer list\n");

    do {
        template = template->next;
        while (template && template->type != DATA_TEMPLATE) template = template->next;

        if (!template) break;

        dataTemplate_t *dataTemplate = (dataTemplate_t *)template->data;
        sequencer->next = &(dataTemplate->sequencer);
        sequencer = sequencer->next;
    } while (1);

    sequencer->next = loop;

#ifdef DEVEL
    template = exporter->template;
    while (template && template->type != DATA_TEMPLATE) template = template->next;

    dataTemplate = (dataTemplate_t *)template->data;
    sequencer = &(dataTemplate->sequencer);
    loop = sequencer;
    do {
        dbg_printf(" sequencer id: %u\n", sequencer->templateID);
        sequencer = sequencer->next;
    } while (sequencer != loop);
#endif

}  // End of relinkSequencerList

static void Process_ipfix_templates(exporterDomain_t *exporter, void *flowset_header, uint32_t size_left, FlowSource_t *fs) {
    ipfix_template_record_t *ipfix_template_record;
    void *DataPtr;
    uint32_t count;

    size_left -= 4;  // subtract message header
    DataPtr = flowset_header + 4;

    ipfix_template_record = (ipfix_template_record_t *)DataPtr;

    // uint32_t	id 	  = ntohs(ipfix_template_record->TemplateID);
    count = ntohs(ipfix_template_record->FieldCount);

    if (count == 0) {
        // withdraw template
        Process_ipfix_template_withdraw(exporter, DataPtr, size_left, fs);
    } else {
        // refresh/add templates
        Process_ipfix_template_add(exporter, DataPtr, size_left, fs);
    }

}  // End of Process_ipfix_templates

static inline int SetSequence(sequence_t *sequenceTable, uint32_t numSequences, uint16_t Type, uint16_t Length, uint16_t EnterpriseNumber) {
    int found = 0;
    int index = LookupElement(Type, EnterpriseNumber);
    if (index < 0) {  // not found - enter skip sequence
        if ((EnterpriseNumber == 0) && (Type == IPFIX_subTemplateList || Type == IPFIX_subTemplateMultiList)) {
            sequenceTable[numSequences].inputType = Type;
            dbg_printf(" Add sequence for sub template type: %u, enterprise: %u, length: %u\n", Type, EnterpriseNumber, Length);
            found = 1;
        } else {
            sequenceTable[numSequences].inputType = 0;
            dbg_printf(" Skip sequence for unknown type: %u, enterprise: %u, length: %u\n", Type, EnterpriseNumber, Length);
        }

        sequenceTable[numSequences].inputLength = Length;
        sequenceTable[numSequences].extensionID = EXnull;
        sequenceTable[numSequences].outputLength = 0;
        sequenceTable[numSequences].copyMode = 0;
        sequenceTable[numSequences].offsetRel = 0;
        sequenceTable[numSequences].stackID = STACK_NONE;
    } else {
        found = 1;
        sequenceTable[numSequences].inputType = ipfixTranslationMap[index].id;
        sequenceTable[numSequences].inputLength = Length;
        sequenceTable[numSequences].extensionID = ipfixTranslationMap[index].extensionID;
        sequenceTable[numSequences].outputLength = ipfixTranslationMap[index].outputLength;
        sequenceTable[numSequences].copyMode = ipfixTranslationMap[index].copyMode;
        sequenceTable[numSequences].offsetRel = ipfixTranslationMap[index].offsetRel;
        sequenceTable[numSequences].stackID = ipfixTranslationMap[index].stackID;
        dbg_printf(" Map type: %u, length: %u to Extension %u - '%s' - output length: %u\n", ipfixTranslationMap[index].id, Length,
                   ipfixTranslationMap[index].extensionID, ipfixTranslationMap[index].name, ipfixTranslationMap[index].outputLength);
    }
    return found;

}  // End of SetSequence

static void Process_ipfix_template_add(exporterDomain_t *exporter, void *DataPtr, uint32_t size_left, FlowSource_t *fs) {
    ipfix_template_record_t *ipfix_template_record;
    ipfix_template_elements_std_t *NextElement;
    int i;

    // a template flowset can contain multiple records ( templates )
    while (size_left) {
        uint32_t id, count, size_required;
        if (size_left < 4) {
            LogError("Process_ipfix [%u] Template size error at %s line %u", exporter->info.id, __FILE__, __LINE__, strerror(errno));
            size_left = 0;
            continue;
        }

        // map next record.
        ipfix_template_record = (ipfix_template_record_t *)DataPtr;
        size_left -= 4;

        id = ntohs(ipfix_template_record->TemplateID);
        count = ntohs(ipfix_template_record->FieldCount);

        dbg_printf("\n[%u] Template ID: %u\n", exporter->info.id, id);
        dbg_printf("FieldCount: %u buffersize: %u\n", count, size_left);

        // assume all elements in template are std elements. correct this value, if we find an
        // enterprise element
        size_required = 4 * count;
        if (size_left < size_required) {
            // if we fail this check, this flowset must be skipped.
            LogError("Process_ipfix: [%u] Not enough data for template elements! required: %i, left: %u", exporter->info.id, size_required,
                     size_left);
            dbg_printf("ERROR: Not enough data for template elements! required: %i, left: %u", size_required, size_left);
            return;
        }

        sequence_t *sequenceTable = malloc((count + 4) * sizeof(sequence_t));  // + 2 for IP and time received
        if (!sequenceTable) {
            LogError("Process_ipfix: malloc(): %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return;
        }

        uint32_t numSequences = 0;
        uint32_t commonFound = 0;
        // process all elements in this record
        NextElement = (ipfix_template_elements_std_t *)ipfix_template_record->elements;
        for (i = 0; i < count; i++) {
            uint16_t Type = ntohs(NextElement->Type);
            uint16_t Length = ntohs(NextElement->Length);
            int Enterprise = Type & 0x8000 ? 1 : 0;
            Type = Type & 0x7FFF;

            uint32_t EnterpriseNumber = 0;
            if (Enterprise) {
                ipfix_template_elements_e_t *e = (ipfix_template_elements_e_t *)NextElement;
                size_required += 4;  // ad 4 for enterprise value
                if (size_left < size_required) {
                    LogError(
                        "Process_ipfix: [%u] Not enough data for template elements! required: %i, "
                        "left: %u",
                        exporter->info.id, size_required, size_left);
                    dbg_printf("ERROR: Not enough data for template elements! required: %i, left: %u", size_required, size_left);
                    return;
                }
                EnterpriseNumber = ntohl(e->EnterpriseNumber);
                if (EnterpriseNumber == IPFIX_ReverseInformationElement) {
                    dbg_printf("[%i] Enterprise: 1, Type: %u, Length %u Reverse Information Element: %u\n", i, Type, Length, EnterpriseNumber);
                } else {
                    dbg_printf("[%i] Enterprise: 1, Type: %u, Length %u EnterpriseNumber: %u\n", i, Type, Length, EnterpriseNumber);
                }
                e++;
                NextElement = (ipfix_template_elements_std_t *)e;
            } else {
                dbg_printf("[%i] Enterprise: 0, Type: %u, Length %u\n", i, Type, Length);
                NextElement++;
            }

            commonFound += SetSequence(sequenceTable, numSequences, Type, Length, EnterpriseNumber);
            numSequences++;
        }

        dbg_printf("Processed: %u, common found: %u\n", size_required, commonFound);
        if (commonFound == 0) {
            size_left -= size_required;
            DataPtr = DataPtr + size_required + 4;  // +4 for header
            dbg_printf("Template does not contain common elements - skip\n");
            free(sequenceTable);
            sequenceTable = NULL;
            continue;
        }

        removeTemplate(exporter, id);
        templateList_t *template = newTemplate(exporter, id);
        if (!template) {
            LogError("Process_ipfix: abort template add: %s line %d", __FILE__, __LINE__);
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

        relinkSequencerList(exporter);
#ifdef DEVEL
        printf("Added/Updated Sequencer to template\n");
        PrintSequencer(&(dataTemplate->sequencer));
#endif

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

static void Process_ipfix_template_withdraw(exporterDomain_t *exporter, void *DataPtr, uint32_t size_left, FlowSource_t *fs) {
    ipfix_template_record_t *ipfix_template_record;

    // a template flowset can contain multiple records ( templates )
    if (size_left < 4) {
        return;
    }
    while (size_left) {
        uint32_t id;

        // map next record.
        ipfix_template_record = (ipfix_template_record_t *)DataPtr;
        size_left -= 4;

        id = ntohs(ipfix_template_record->TemplateID);
        // count = ntohs(ipfix_template_record->FieldCount);

        if (id == IPFIX_TEMPLATE_FLOWSET_ID) {
            // withdraw all templates
            removeAllTemplates(exporter);
        } else {
            removeTemplate(exporter, id);
        }
        relinkSequencerList(exporter);

        DataPtr = DataPtr + 4;
        if (size_left < 4) {
            // padding
            dbg_printf("Skip %u bytes padding\n", size_left);
            size_left = 0;
        }
    }

}  // End of Process_ipfix_template_withdraw

static void Process_ipfix_option_templates(exporterDomain_t *exporter, void *option_template_flowset, FlowSource_t *fs) {
    uint8_t *option_template;
    uint32_t size_left, size_required;
    // uint32_t nr_scopes, nr_options;
    uint16_t tableID, field_count, scope_field_count, offset;

    size_left = GET_FLOWSET_LENGTH(option_template_flowset) - 4;  // -4 for flowset header -> id and length
    if (size_left < 6) {
        LogError(
            "Process_ipfix: [%u] option template length error: size left %u too small for an "
            "options template",
            exporter->info.id, size_left);
        return;
    }

    option_template = option_template_flowset + 4;
    tableID = GET_OPTION_TEMPLATE_ID(option_template);
    field_count = GET_OPTION_TEMPLATE_FIELD_COUNT(option_template);
    scope_field_count = GET_OPTION_TEMPLATE_SCOPE_FIELD_COUNT(option_template);
    option_template += 6;
    size_left -= 6;

    dbg_printf("Decode Option Template. tableID: %u, field count: %u, scope field count: %u\n", tableID, field_count, scope_field_count);

    if (scope_field_count == 0) {
        LogError("Process_ipfx: [%u] scope field count error: length must not be zero", exporter->info.id);
        dbg_printf("scope field count error: length must not be zero\n");
        return;
    }

    size_required = 2 * field_count * sizeof(uint16_t);
    dbg_printf("Size left: %u, size required: %u\n", size_left, size_required);
    if (size_left < size_required) {
        LogError(
            "Process_ipfix: [%u] option template length error: size left %u too small for %u "
            "scopes length and %u options length",
            exporter->info.id, size_left, field_count, scope_field_count);
        dbg_printf("option template length error: size left %u too small for field_count %u\n", size_left, field_count);
        return;
    }

    if (scope_field_count == 0) {
        LogError("Process_ipfxi: [%u] scope field count error: length must not be zero", exporter->info.id);
        return;
    }

    int i;
    offset = 0;
    for (i = 0; i < scope_field_count; i++) {
        uint16_t id, length;
        int Enterprise;

        if (size_left && size_left < 4) {
            LogError("Process_ipfix [%u] Template size error at %s line %u", exporter->info.id, __FILE__, __LINE__, strerror(errno));
            return;
        }
        id = Get_val16(option_template);
        option_template += 2;
        length = Get_val16(option_template);
        option_template += 2;
        size_left -= 4;
        Enterprise = id & 0x8000 ? 1 : 0;
        if (Enterprise) {
            size_required += 4;
            if (size_left < 4) {
                dbg_printf("option template length error: size left %u too small\n", size_left);
                return;
            }
            option_template += 4;
            size_left -= 4;
            dbg_printf(" [%i] Enterprise: 1, scope id: %u, scope length %u enterprise value: %u\n", i, id, length, Get_val32(option_template));
        } else {
            dbg_printf(" [%i] Enterprise: 0, scope id: %u, scope length %u\n", i, id, length);
        }
        offset += length;
    }

    removeTemplate(exporter, tableID);
    optionTemplate_t *optionTemplate = (optionTemplate_t *)calloc(1, sizeof(optionTemplate_t));
    if (!optionTemplate) {
        LogError("Error calloc(): %s in %s:%d", strerror(errno), __FILE__, __LINE__);
        return;
    }

    uint16_t scopeSize = offset;
    dbg_printf("Scope size: %u\n", scopeSize);

    struct samplerOption_s *samplerOption = &(optionTemplate->samplerOption);
    struct nbarOptionList_s *nbarOption = &(optionTemplate->nbarOption);
    struct nameOptionList_s *ifnameOptionList = &(optionTemplate->ifnameOption);
    struct nameOptionList_s *vrfnameOptionList = &(optionTemplate->vrfnameOption);

    for (; i < field_count; i++) {
        uint32_t enterprise_value;
        uint16_t type, length;
        int Enterprise;

        // keep compiler happy
        UNUSED(enterprise_value);
        type = Get_val16(option_template);
        option_template += 2;
        length = Get_val16(option_template);
        option_template += 2;
        size_left -= 4;
        Enterprise = type & 0x8000 ? 1 : 0;
        if (Enterprise) {
            size_required += 4;
            if (size_left < 4) {
                LogError("Process_ipfix: [%u] option template length error: size left %u too", exporter->info.id, size_left);
                dbg_printf("option template length error: size left %u too small\n", size_left);
                return;
            }
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

    dbg_printf("\n[%u] Option size: %llu, flags: %llx\n", exporter->info.id, optionTemplate->optionSize, optionTemplate->flags);
    if (optionTemplate->flags) {
        // if it exitsts - remove old template on exporter with same ID
        templateList_t *template = newTemplate(exporter, tableID);
        if (!template) {
            LogError("Process_ipfix: abort template add: %s line %d", __FILE__, __LINE__);
            return;
        }
        template->data = optionTemplate;

        if ((optionTemplate->flags & SAMPLERFLAGS) == SAMPLERFLAGS) {
            dbg_printf("[%u] New Sampler information found\n", exporter->info.id);
            SetFlag(template->type, SAMPLER_TEMPLATE);
        } else if ((optionTemplate->flags & SAMPLERSTDFLAGS) == SAMPLERSTDFLAGS) {
            dbg_printf("[%u] New std sampling information found\n", exporter->info.id);
            SetFlag(template->type, SAMPLER_TEMPLATE);
        } else if ((optionTemplate->flags & STDMASK) == STDFLAGS) {
            dbg_printf("[%u] Old std sampling information found\n", exporter->info.id);
            SetFlag(template->type, SAMPLER_TEMPLATE);
        } else if ((optionTemplate->flags & STDSAMPLING34) == STDSAMPLING34) {
            dbg_printf("[%u] Old std sampling information found - missing algorithm\n", exporter->info.id);
            samplerOption->algorithm.length = 0;
            samplerOption->algorithm.offset = 0;
            SetFlag(template->type, SAMPLER_TEMPLATE);
        } else {
            dbg_printf("[%u] No Sampling information found\n", exporter->info.id);
        }

        if (TestFlag(optionTemplate->flags, NBAROPTIONS)) {
            dbg_printf("[%u] found nbar options\n", exporter->info.id);
            dbg_printf("[%u] id   length: %u, offset: %u\n", exporter->info.id, nbarOption->id.length, nbarOption->id.offset);
            dbg_printf("[%u] name length: %u, offset: %u\n", exporter->info.id, nbarOption->name.length, nbarOption->name.offset);
            dbg_printf("[%u] desc length: %u, offset: %u\n", exporter->info.id, nbarOption->desc.length, nbarOption->desc.offset);
            optionTemplate->nbarOption.scopeSize = scopeSize;
            SetFlag(template->type, NBAR_TEMPLATE);
        } else {
            dbg_printf("[%u] No nbar information found\n", exporter->info.id);
        }

        if (TestFlag(optionTemplate->flags, IFNAMEOPTION)) {
            dbg_printf("[%u] found ifname option\n", exporter->info.id);
            dbg_printf("[%u] ingess length: %u\n", exporter->info.id, optionTemplate->ifnameOption.ingress.length);
            dbg_printf("[%u] name length  : %u\n", exporter->info.id, optionTemplate->ifnameOption.name.length);
            optionTemplate->ifnameOption.scopeSize = scopeSize;
            SetFlag(template->type, IFNAME_TEMPLATE);
        } else {
            dbg_printf("[%u] No ifname information found\n", exporter->info.id);
        }

        if (TestFlag(optionTemplate->flags, VRFNAMEOPTION)) {
            dbg_printf("[%u] found vrfname option\n", exporter->info.id);
            dbg_printf("[%u] ingess length: %u\n", exporter->info.id, optionTemplate->vrfnameOption.ingress.length);
            dbg_printf("[%u] name length  : %u\n", exporter->info.id, optionTemplate->vrfnameOption.name.length);
            optionTemplate->vrfnameOption.scopeSize = scopeSize;
            SetFlag(template->type, VRFNAME_TEMPLATE);
        } else {
            dbg_printf("[%u] No vrfname information found\n", exporter->info.id);
        }

        if (TestFlag(optionTemplate->flags, SYSUPOPTION)) {
            dbg_printf("[%u] SysUp information found. length: %u\n", exporter->info.id, optionTemplate->SysUpOption.length);
            SetFlag(template->type, SYSUPTIME_TEMPLATE);
        } else {
            dbg_printf("[%u] No SysUp information found\n", exporter->info.id);
        }
        dbg_printf("\n[%u] template type: %x\n", exporter->info.id, template->type);

    } else {
        free(optionTemplate);
    }

    processed_records++;
    dbg_printf("\n");

}  // End of Process_ipfix_option_templates

static void Process_ipfix_data(exporterDomain_t *exporter, uint32_t ExportTime, void *data_flowset, FlowSource_t *fs, dataTemplate_t *template) {
    uint32_t size_left = GET_FLOWSET_LENGTH(data_flowset) - 4;  // -4 for data flowset header -> id and length

    // map input buffer as a byte array
    uint8_t *inBuff = (uint8_t *)(data_flowset + 4);  // skip flowset header

    sequencer_t *sequencer = &(template->sequencer);

    dbg_printf("[%u] Process data flowset size: %u\n", exporter->info.id, size_left);

    // reserve space in output stream for EXipReceivedVx
    uint32_t receivedSize = 0;
    if (fs->sa_family == PF_INET6)
        receivedSize = ExtensionsEnabled[EXipReceivedV6ID] ? EXipReceivedV6Size : 0;
    else
        receivedSize = ExtensionsEnabled[EXipReceivedV4ID] ? EXipReceivedV4Size : 0;

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
            // this should really never occur, because the buffer gets flushed earlier
            LogError("Process_ipfix: output buffer size error. Skip ipfix record processing");
            dbg_printf("Process_ipfix: output buffer size error. Skip ipfix record processing");
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
        recordHeaderV3->nfversion = 10;
        recordHeaderV3->exporterID = exporter->info.sysid;

        uint64_t stack[STACK_MAX];
        memset((void *)stack, 0, sizeof(stack));
        // copy record data
        int ret = SequencerRun(sequencer, inBuff, size_left, outBuff, buffAvail, stack);
        switch (ret) {
            case SEQ_OK:
                break;
            case SEQ_ERROR:
                LogError("Process ipfix: Sequencer run error. Skip record processing");
                return;
                break;
            case SEQ_MEM_ERR:
                if (buffAvail == WRITE_BUFFSIZE) {
                    LogError("Process ipfix: Sequencer run error. buffer size too small");
                    return;
                }

                // request new and empty buffer
                LogInfo("Process ipfix: Sequencer run - resize output buffer");
                buffAvail = CheckBufferSpace(fs->nffile, buffAvail + 1);
                if (buffAvail == 0) {
                    // this should really never occur, because the buffer gets flushed earlier
                    LogError("Process_ipfix: output buffer size error. Skip ipfix record processing");
                    dbg_printf("Process_ipfix: output buffer size error. Skip ipfix record processing");
                    return;
                }
                goto REDO;
                break;
        }

        dbg_printf(
            "New record added with %u elements and size: %u, sequencer inLength: %lu, outLength: "
            "%lu\n",
            recordHeaderV3->numElements, recordHeaderV3->size, sequencer->inLength, sequencer->outLength);

        recordHeaderV3->engineType = stack[STACK_ENGINETYPE];
        recordHeaderV3->engineID = stack[STACK_ENGINEID];

        // add router IP
        if (fs->sa_family == PF_INET6) {
            if (ExtensionsEnabled[EXipReceivedV6ID]) {
                PushExtension(recordHeaderV3, EXipReceivedV6, ipReceivedV6);
                ipReceivedV6->ip[0] = fs->ip.V6[0];
                ipReceivedV6->ip[1] = fs->ip.V6[1];
                dbg_printf("Add IPv6 route IP extension\n");
            } else {
                dbg_printf("IPv6 route IP extension not enabled\n");
            }
        } else {
            if (ExtensionsEnabled[EXipReceivedV4ID]) {
                PushExtension(recordHeaderV3, EXipReceivedV4, ipReceivedV4);
                ipReceivedV4->ip = fs->ip.V4;
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
        exporter->PacketSequence++;

        // handle sampling
        uint64_t packetInterval = 1;
        uint64_t spaceInterval = 0;
        uint64_t intervalTotal = 0;
        // either 0 for no sampler or announced samplerID
        uint32_t sampler_id = stack[STACK_SAMPLER];
        sampler_t *sampler = exporter->sampler;
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
            samplerInfo->exporter_sysid = exporter->info.sysid;
        }

        if (overwriteSampler) {
            // hard overwrite sampling
            packetInterval = overwriteSampler->record.packetInterval;
            spaceInterval = overwriteSampler->record.spaceInterval;
            SetFlag(recordHeaderV3->flags, V3_FLAG_SAMPLED);
            dbg_printf("[%u] Overwrite sampling - packet interval: %llu, packet space: %llu\n", exporter->info.id, packetInterval, spaceInterval);
        } else if (sampler) {
            // individual assigned sampler ID
            packetInterval = sampler->record.packetInterval;
            spaceInterval = sampler->record.spaceInterval;
            SetFlag(recordHeaderV3->flags, V3_FLAG_SAMPLED);
            dbg_printf("[%u] Found assigned sampler ID %u - packet interval: %llu, packet space: %llu\n", exporter->info.id, sampler_id,
                       packetInterval, spaceInterval);
        } else if (genericSampler) {
            // global sampler ID
            packetInterval = genericSampler->record.packetInterval;
            spaceInterval = genericSampler->record.spaceInterval;
            SetFlag(recordHeaderV3->flags, V3_FLAG_SAMPLED);
            dbg_printf("[%u] Found generic sampler - packet interval: %llu, packet space: %llu\n", exporter->info.id, packetInterval, spaceInterval);
        } else if (defaultSampler) {
            // static default sampler
            packetInterval = defaultSampler->record.packetInterval;
            spaceInterval = defaultSampler->record.spaceInterval;
            SetFlag(recordHeaderV3->flags, V3_FLAG_SAMPLED);
            dbg_printf("[%u] Found static default sampler - packet interval: %llu, packet space: %llu\n", exporter->info.id, packetInterval,
                       spaceInterval);
        }
        intervalTotal = packetInterval + spaceInterval;

        // update first_seen, last_seen
        EXgenericFlow_t *genericFlow = sequencer->offsetCache[EXgenericFlowID];
        if (genericFlow) {
            // add time received
            genericFlow->msecReceived = ((uint64_t)fs->received.tv_sec * 1000LL) + (uint64_t)((uint64_t)fs->received.tv_usec / 1000LL);

            // map duration to msecLast
            if (genericFlow->msecFirst && genericFlow->msecLast == 0 && stack[STACK_DURATION])
                genericFlow->msecLast = genericFlow->msecFirst + stack[STACK_DURATION];

            // if timestamps relative to sysupTime
            // record sysuptime overwrites option template sysuptime
            if (stack[STACK_SYSUPTIME] && stack[STACK_MSECFIRST]) {
                dbg_printf("Calculate first/last from record SysUpTime\n");
                genericFlow->msecFirst = stack[STACK_SYSUPTIME] + stack[STACK_MSECFIRST];
                genericFlow->msecLast = stack[STACK_SYSUPTIME] + stack[STACK_MSECLAST];
            } else if (exporter->SysUpTime && stack[STACK_MSECFIRST]) {
                dbg_printf("Calculate first/last from option SysUpTime\n");
                genericFlow->msecFirst = exporter->SysUpTime + stack[STACK_MSECFIRST];
                genericFlow->msecLast = exporter->SysUpTime + stack[STACK_MSECLAST];
            }

            if (genericFlow->msecFirst < fs->msecFirst) fs->msecFirst = genericFlow->msecFirst;
            if (genericFlow->msecLast > fs->msecLast) fs->msecLast = genericFlow->msecLast;
            dbg_printf("msecFrist: %llu\n", genericFlow->msecFirst);
            dbg_printf("msecLast : %llu\n", genericFlow->msecLast);
            dbg_printf("packets : %llu\n", (long long unsigned)genericFlow->inPackets);
            dbg_printf("bytes : %llu\n", (long long unsigned)genericFlow->inBytes);

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
                        genericFlow->srcPort = 0;
                    }
                    if (stack[STACK_ICMP] != 0) {
                        genericFlow->dstPort = stack[STACK_ICMP];
                    } else if (stack[STACK_ICMPTYPE] != 0 || stack[STACK_ICMPCODE] != 0) {
                        genericFlow->dstPort = (stack[STACK_ICMPTYPE] << 8) + stack[STACK_ICMPCODE];
                    }
                    break;
                case IPPROTO_TCP:
                    fs->nffile->stat_record->numflows_tcp++;
                    fs->nffile->stat_record->numpackets_tcp += genericFlow->inPackets;
                    fs->nffile->stat_record->numbytes_tcp += genericFlow->inBytes;
                    genericFlow->dstPort = stack[STACK_DSTPORT];
                    break;
                case IPPROTO_UDP:
                    fs->nffile->stat_record->numflows_udp++;
                    fs->nffile->stat_record->numpackets_udp += genericFlow->inPackets;
                    fs->nffile->stat_record->numbytes_udp += genericFlow->inBytes;
                    genericFlow->dstPort = stack[STACK_DSTPORT];
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
            // sampling > 1
            if (spaceInterval > 0) {
                cntFlow->outPackets = cntFlow->outPackets * intervalTotal / (uint64_t)packetInterval;
                cntFlow->outBytes = cntFlow->outBytes * intervalTotal / (uint64_t)packetInterval;
            }
            if (cntFlow->flows == 0) cntFlow->flows++;
            fs->nffile->stat_record->numpackets += cntFlow->outPackets;
            fs->nffile->stat_record->numbytes += cntFlow->outBytes;
        }

        // if observation extension is used but no domainID, take it from the ipfix header
        EXobservation_t *observation = sequencer->offsetCache[EXobservationID];
        if (observation) {
            if (observation->domainID == 0) observation->domainID = exporter->info.id;
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
            LogError("Process ipfix: Output buffer overflow! Flush buffer and skip records.");
            LogError("Buffer size: %u > %u", fs->nffile->block_header->size, WRITE_BUFFSIZE);

            // reset buffer
            fs->nffile->block_header->size = 0;
            fs->nffile->block_header->NumRecords = 0;
            fs->nffile->buff_ptr = (void *)((void *)fs->nffile->block_header + sizeof(dataBlock_t));
            return;
        }
    }

}  // End of Process_ipfix_data

static inline void Process_ipfix_sampler_option_data(exporterDomain_t *exporter, FlowSource_t *fs, templateList_t *template, void *data_flowset) {
    uint32_t size_left = GET_FLOWSET_LENGTH(data_flowset) - 4;  // -4 for data flowset header -> id and length
    dbg_printf("[%u] Process sampler option data flowset size: %u\n", exporter->info.id, size_left);

    // map input buffer as a byte array
    uint8_t *in = (uint8_t *)(data_flowset + 4);  // skip flowset header

    optionTemplate_t *optionTemplate = (optionTemplate_t *)template->data;
    struct samplerOption_s *samplerOption = &(optionTemplate->samplerOption);

    if ((optionTemplate->flags & SAMPLERSTDFLAGS) != 0) {
        sampler_record_t sampler_record = {0};

        if (CHECK_OPTION_DATA(size_left, samplerOption->id)) {
            sampler_record.id = Get_val(in, samplerOption->id.offset, samplerOption->id.length);
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
            }
        }

        dbg_printf("Extracted Sampler data:\n");
        if (sampler_record.id == 0) {
            sampler_record.id = SAMPLER_GENERIC;
            dbg_printf("New std sampler: algorithm : %u, packet interval: %u, packet space: %u\n", sampler_record.algorithm,
                       sampler_record.packetInterval, sampler_record.spaceInterval);
        } else {
            dbg_printf("ID : %lld, algorithm : %u, packet interval: %u, packet space: %u\n", sampler_record.id, sampler_record.algorithm,
                       sampler_record.packetInterval, sampler_record.spaceInterval);
        }

        InsertSampler(fs, exporter, &sampler_record);
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
                LogError("Process_ipfix_option: Zero sampling interval -> sampling == 1", __FILE__, __LINE__);
            }
        }
        dbg_printf("ID : %lld, algorithm : %u, packet interval: %u, packet space: %u\n", sampler_record.id, sampler_record.algorithm,
                   sampler_record.packetInterval, sampler_record.spaceInterval);

        InsertSampler(fs, exporter, &sampler_record);
    }
    processed_records++;

}  // End of Process_ipfix_sampler_option_data

static void Process_ipfix_nbar_option_data(exporterDomain_t *exporter, FlowSource_t *fs, templateList_t *template, void *data_flowset) {
    uint32_t size_left = GET_FLOWSET_LENGTH(data_flowset) - 4;  // -4 for data flowset header -> id and length
    dbg_printf("[%u] Process nbar option data flowset size: %u\n", exporter->info.id, size_left);

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
    dbg_printf("[%u] nbar option data - records: %u, size: %zu\n", exporter->info.id, numRecords, option_size);

    if (numRecords == 0 || option_size == 0 || option_size > size_left) {
        LogError("Process_nbar_option: nbar option size error: option size: %u, size left: %u", option_size, size_left);
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
    if (!CheckBufferSpace(fs->nffile, total_size)) {
        // fishy! - should never happen. maybe disk full?
        LogError("Process_nbar_option: output buffer size error. Abort nbar record processing");
        return;
    }

    void *outBuff = fs->nffile->buff_ptr;
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
    fs->nffile->block_header->size += nbarHeader->size;
    fs->nffile->block_header->NumRecords++;
    fs->nffile->buff_ptr += nbarHeader->size;

    if (size_left > 7) {
        LogInfo("Process nbar data record - %u extra bytes", size_left);
    }
    processed_records++;

    dbg_printf("nbar processed: %u records - header: size: %u, type: %u, numelements: %u, elementSize: %u\n", numRecords, nbarHeader->size,
               nbarHeader->type, nbarHeader->numElements, nbarHeader->elementSize);
}  // End of Process_ipfix_nbar_option_data

static void Process_ifvrf_option_data(exporterDomain_t *exporter, FlowSource_t *fs, int type, templateList_t *template, void *data_flowset) {
    uint32_t size_left = GET_FLOWSET_LENGTH(data_flowset) - 4;  // -4 for data flowset header -> id and length
    dbg_printf("[%u] Process ifvrf option data flowset size: %u\n", exporter->info.id, size_left);

    uint32_t recordType = 0;
    optionTemplate_t *optionTemplate = (optionTemplate_t *)template->data;
    struct nameOptionList_s *nameOption = NULL;
    switch (type) {
        case IFNAME_TEMPLATE:
            nameOption = &(optionTemplate->ifnameOption);
            recordType = IfNameRecordType;
            dbg_printf("[%u] Process if name option data flowset size: %u\n", exporter->info.id, size_left);
            break;
        case VRFNAME_TEMPLATE:
            nameOption = &(optionTemplate->vrfnameOption);
            recordType = VrfNameRecordType;
            dbg_printf("[%u] Process vrf name option data flowset size: %u\n", exporter->info.id, size_left);
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
    dbg_printf("[%u] name option data - records: %u, size: %zu\n", exporter->info.id, numRecords, option_size);

    if (numRecords == 0 || option_size == 0 || option_size > size_left) {
        LogError("Process_ifvrf_option: nbar option size error: option size: %u, size left: %u", option_size, size_left);
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
    if (!CheckBufferSpace(fs->nffile, total_size)) {
        // fishy! - should never happen. maybe disk full?
        LogError("Process_ifvrf_option: output buffer size error. Abort nbar record processing");
        return;
    }

    void *outBuff = fs->nffile->buff_ptr;
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
    fs->nffile->block_header->size += nameHeader->size;
    fs->nffile->block_header->NumRecords++;
    fs->nffile->buff_ptr += nameHeader->size;

    if (size_left > 7) {
        LogInfo("Process ifvrf data record - %u extra bytes", size_left);
    }
    processed_records++;

    dbg_printf("if/vrf name processed: %u records - header: size: %u, type: %u, numelements: %u, elementSize: %u\n", numRecords, nameHeader->size,
               nameHeader->type, nameHeader->numElements, nameHeader->elementSize);

}  // End of Process_v9_ifvrf_option_data

static void Process_ipfix_SysUpTime_option_data(exporterDomain_t *exporter, templateList_t *template, void *data_flowset) {
    uint32_t size_left = GET_FLOWSET_LENGTH(data_flowset) - 4;  // -4 for data flowset header -> id and length
    dbg_printf("[%u] Process sysup option data flowset size: %u\n", exporter->info.id, size_left);

    optionTemplate_t *optionTemplate = (optionTemplate_t *)template->data;

    // map input buffer as a byte array
    uint8_t *in = (uint8_t *)(data_flowset + 4);  // skip flowset header
    if (CHECK_OPTION_DATA(size_left, optionTemplate->SysUpOption)) {
        exporter->SysUpTime = Get_val(in, optionTemplate->SysUpOption.offset, optionTemplate->SysUpOption.length);
        dbg_printf("Extracted SysUpTime : %llu\n", exporter->SysUpTime);
    } else {
        LogError("Process_ipfix_option: %s line %d: Not enough data for option data", __FILE__, __LINE__);
        return;
    }

}  // End of Process_ipfix_SysUpTime_option_data

static void ProcessOptionFlowset(exporterDomain_t *exporter, FlowSource_t *fs, templateList_t *template, void *data_flowset) {
    if (TestFlag(template->type, SAMPLER_TEMPLATE)) {
        dbg_printf("Found sampler option table\n");
        Process_ipfix_sampler_option_data(exporter, fs, template, data_flowset);
    }
    if (TestFlag(template->type, NBAR_TEMPLATE)) {
        dbg_printf("Found nbar option table\n");
        Process_ipfix_nbar_option_data(exporter, fs, template, data_flowset);
    }
    if (TestFlag(template->type, IFNAME_TEMPLATE)) {
        dbg_printf("Found ifname option data\n");
        Process_ifvrf_option_data(exporter, fs, IFNAME_TEMPLATE, template, data_flowset);
    }

    if (TestFlag(template->type, VRFNAME_TEMPLATE)) {
        dbg_printf("Found vrfname option data\n");
        Process_ifvrf_option_data(exporter, fs, VRFNAME_TEMPLATE, template, data_flowset);
    }
    if (TestFlag(template->type, SYSUPTIME_TEMPLATE)) {
        dbg_printf("Found SysUpTime option data\n");
        Process_ipfix_SysUpTime_option_data(exporter, template, data_flowset);
    }

    processed_records++;

}  // End of ProcessOptionFlowset

void Process_IPFIX(void *in_buff, ssize_t in_buff_cnt, FlowSource_t *fs) {
    exporterDomain_t *exporter;
    ssize_t size_left;
    uint32_t ExportTime, Sequence;
    ipfix_header_t *ipfix_header;
    void *flowset_header;

#ifdef DEVEL
    static uint32_t pkg_num = 1;
    printf("Process_ipfix: Next packet: %i\n", pkg_num);
#endif

    size_left = in_buff_cnt;
    if (size_left < IPFIX_HEADER_LENGTH) {
        LogError("Process_ipfix: Too little data for ipfix packet: '%lli'", (long long)size_left);
        return;
    }

    ipfix_header = (ipfix_header_t *)in_buff;
    ExportTime = ntohl(ipfix_header->ExportTime);
    Sequence = ntohl(ipfix_header->LastSequence);

    uint32_t ObservationDomain = ntohl(ipfix_header->ObservationDomain);
    exporter = getExporter(fs, ObservationDomain);
    if (!exporter) {
        LogError("Process_ipfix: Exporter NULL: Abort ipfix record processing");
        return;
    }
    exporter->packets++;

    // exporter->PacketSequence = Sequence;
    flowset_header = (void *)ipfix_header + IPFIX_HEADER_LENGTH;
    size_left -= IPFIX_HEADER_LENGTH;

    dbg_printf("\n[%u] process packet: %u, export time: %s, TemplateRecords: %llu, DataRecords: %llu, buffer: %li \n", ObservationDomain, pkg_num++,
               UNIX2ISO(ExportTime), (long long unsigned)exporter->TemplateRecords, (long long unsigned)exporter->DataRecords, size_left);
    dbg_printf("[%u] Sequence: %u\n", ObservationDomain, Sequence);

    // sequence check
    // 2^32 wrap is handled automatically as both counters overflow
    if (Sequence != exporter->PacketSequence) {
        if (exporter->DataRecords != 0) {
            // sync sequence on first data record without error report
            fs->nffile->stat_record->sequence_failure++;
            exporter->sequence_failure++;
            dbg_printf("[%u] Sequence check failed: last seq: %u, seq %u\n", exporter->info.id, Sequence, exporter->PacketSequence);
        } else {
            dbg_printf("[%u] Sync Sequence: %u\n", exporter->info.id, Sequence);
        }
        exporter->PacketSequence = Sequence;
    } else {
        dbg_printf("[%u] Sequence check ok\n", exporter->info.id);
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
                    if it happends, we can't determine the next flowset, so skip the entire export
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
                exporter->TemplateRecords++;
                dbg_printf("Process template flowset, length: %u\n", flowset_length);
                Process_ipfix_templates(exporter, flowset_header, flowset_length, fs);
                break;
            case IPFIX_OPTIONS_FLOWSET_ID:
                // option_flowset = (option_template_flowset_t *)flowset_header;
                exporter->TemplateRecords++;
                dbg_printf("Process option template flowset, length: %u\n", flowset_length);
                Process_ipfix_option_templates(exporter, flowset_header, fs);
                break;
            default: {
                if (flowset_id < IPFIX_MIN_RECORD_FLOWSET_ID) {
                    dbg_printf("Invalid flowset id: %u. Skip flowset\n", flowset_id);
                    LogError("Process_ipfix: Invalid flowset id: %u. Skip flowset", flowset_id);
                } else {
                    dbg_printf("Process data flowset, length: %u\n", flowset_length);
                    templateList_t *template = getTemplate(exporter, flowset_id);
                    if (template) {
                        if (TestFlag(template->type, DATA_TEMPLATE)) {
                            dbg_printf("Process ipfix data\n");
                            Process_ipfix_data(exporter, ExportTime, flowset_header, fs, (dataTemplate_t *)template->data);
                            exporter->DataRecords++;
                        } else {
                            dbg_printf("Process ipfix option\n");
                            ProcessOptionFlowset(exporter, fs, template, flowset_header);
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
