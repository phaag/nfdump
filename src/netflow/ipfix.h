/*
 *  Copyright (c) 2009-2023, Peter Haag
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

#ifndef _IPFIX_H
#define _IPFIX_H 1

#include <sys/types.h>

#include "config.h"
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "collector.h"

/* reference: http://tools.ietf.org/html/draft-ietf-ipfix-protocol-rfc5101bis-00 */

typedef struct ipfix_header {
    uint16_t Version;            // set to 10 for IPFIX
    uint16_t Length;             // Total length incl. this header. up to 65535 bytes
    uint32_t ExportTime;         // UNIC epoch export Time of flow.
    uint32_t LastSequence;       // Incremental sequence counter modulo 2^32 of all IPFIX Data Records
    uint32_t ObservationDomain;  // identifier , unique to the exporter
} ipfix_header_t;

#define IPFIX_HEADER_LENGTH sizeof(ipfix_header_t)

/*
   Message Header Field Descriptions:

   Version

      Version of Flow Record format exported in this message.  The value
      of this field is 0x000a for the current version, incrementing by
      one the version used in the NetFlow services export version 9
      [RFC3954].

   Length

      Total length of the IPFIX Message, measured in octets, including
      Message Header and Set(s).

   Export Time

      Time at which the IPFIX Message Header leaves the Exporter,
      expressed in seconds since the UNIX epoch of 1 January 1970 at
      00:00 UTC, encoded as an unsigned 32-bit integer.

   Sequence Number

      Incremental sequence counter modulo 2^32 of all IPFIX Data Records
      sent on this PR-SCTP stream from the current Observation Domain by
      the Exporting Process.  Check the specific meaning of this field
      in the subsections of Section 10 when UDP or TCP is selected as
      the transport protocol.  This value SHOULD be used by the
      Collecting Process to identify whether any IPFIX Data Records have
      been missed.  Template and Options Template Records do not
      increase the Sequence Number.

   Observation Domain ID

      A 32-bit identifier of the Observation Domain that is locally
      unique to the Exporting Process.  The Exporting Process uses the
      Observation Domain ID to uniquely identify to the Collecting
      Process the Observation Domain that metered the Flows.  It is
      RECOMMENDED that this identifier also be unique per IPFIX Device.

      Collecting Processes SHOULD use the Transport Session and the
      Observation Domain ID field to separate different export streams
      originating from the same Exporter.  The Observation Domain ID
      SHOULD be 0 when no specific Observation Domain ID is relevant for
      the entire IPFIX Message, for example, when exporting the
      Exporting Process Statistics, or in case of a hierarchy of
      Collectors when aggregated Data Records are exported.

*/

/* set format:
   A Set has the format shown in Figure H.  The record types can be
   either Template Records, Options Template Records, or Data Records.
   The record types MUST NOT be mixed within a Set.

   +--------------------------------------------------+
   | Set Header                                       |
   +--------------------------------------------------+
   | record                                           |
   +--------------------------------------------------+
   | record                                           |
   +--------------------------------------------------+
    ...
   +--------------------------------------------------+
   | record                                           |
   +--------------------------------------------------+
   | Padding (opt.)                                   |
   +--------------------------------------------------+
*/

typedef struct set_header_s {
    uint16_t SetID;  // SetIDs:
                     // 0, 1: not used
                     // 2: Template Set
                     // 3: Options Template Set
#define IPFIX_TEMPLATE_FLOWSET_ID 2
#define IPFIX_OPTIONS_FLOWSET_ID 3
#define IPFIX_MIN_RECORD_FLOWSET_ID 256
    uint16_t Length;      // Length of bytes incl. this header
    uint32_t records[1];  // pointer to records
} set_header_t;

/* Template Record Format
   The format of the Template Record is shown in Figure J.  It consists
   of a Template Record Header and one or more Field Specifiers.  The
   definition of the Field Specifiers is given in Figure G above.

   +--------------------------------------------------+
   | Template Record Header                           |
   +--------------------------------------------------+
   | Field Specifier                                  |
   +--------------------------------------------------+
   | Field Specifier                                  |
   +--------------------------------------------------+
    ...
   +--------------------------------------------------+
   | Field Specifier                                  |
   +--------------------------------------------------+
*/

typedef struct ipfix_template_record_s {
    uint16_t TemplateID;  // Template ID:
                          // 0-255 reserved for Template Sets, Options Template Sets,
                          // and other reserved Sets yet to be created.
                          // 256-65535 Template IDs of Data Sets
    uint16_t FieldCount;
    uint32_t elements[1];
} ipfix_template_record_t;

/* Standard Information Elements
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|  Information Element ident. |        Field Length           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
typedef struct ipfix_template_elements_std_s {
    uint16_t Type;
    uint16_t Length;
} ipfix_template_elements_std_t;

/* enterprise-specific Information Elements
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |1|  Information Element ident. |        Field Length           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Enterprise Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
typedef struct ipfix_template_elements_e_s {
    uint16_t Type;
    uint16_t Length;
    uint32_t EnterpriseNumber;
} ipfix_template_elements_e_t;

#define _1byte 1
#define _2bytes 2
#define _3bytes 3
#define _4bytes 4
#define _6bytes 6
#define _8bytes 8
#define _16bytes 16

#define SKIP_ELEMENT 0
// IPFIX std element definitions
// Flowset record types
#define IPFIX_octetDeltaCount 1
#define IPFIX_packetDeltaCount 2
#define IPFIX_deltaFlowCount 3
#define IPFIX_protocolIdentifier 4
#define IPFIX_ipClassOfService 5
#define IPFIX_tcpControlBits 6
#define IPFIX_SourceTransportPort 7
#define IPFIX_SourceIPv4Address 8
#define IPFIX_SourceIPv4PrefixLength 9
#define IPFIX_ingressInterface 10
#define IPFIX_DestinationTransportPort 11
#define IPFIX_DestinationIPv4Address 12
#define IPFIX_DestinationIPv4PrefixLength 13
#define IPFIX_egressInterface 14
#define IPFIX_ipNextHopIPv4Address 15
#define IPFIX_bgpSourceAsNumber 16
#define IPFIX_bgpDestinationAsNumber 17
#define IPFIX_bgpNextHopIPv4Address 18

#define IPFIX_flowEndSysUpTime 21
#define IPFIX_flowStartSysUpTime 22
#define IPFIX_postOctetDeltaCount 23
#define IPFIX_postPacketDeltaCount 24
#define IPFIX_SourceIPv6Address 27
#define IPFIX_DestinationIPv6Address 28
#define IPFIX_SourceIPv6PrefixLength 29
#define IPFIX_DestinationIPv6PrefixLength 30
#define IPFIX_flowLabelIPv6 31
#define IPFIX_icmpTypeCodeIPv4 32

// deprecated elements for sampling
#define IPFIX_samplingInterval 34
#define IPFIX_samplingAlgorithm 35

// deprecated, but for compatibility
#define IPFIX_engineType 38
#define IPFIX_engineId 39

#define IPFIX_samplerId 48
#define IPFIX_samplerMode 49
#define IPFIX_samplerRandomInterval 50

// #define IPFIX_MIN_TTL			52
// #define IPFIX_MAX_TTL			53
// #define IPFIX_IPV4_IDENT			54

#define IPFIX_postIpClassOfService 55
#define IPFIX_SourceMacAddress 56
#define IPFIX_postDestinationMacAddress 57
#define IPFIX_vlanId 58
#define IPFIX_postVlanId 59
#define IPFIX_ipVersion 60
#define IPFIX_flowDirection 61
#define IPFIX_ipNextHopIPv6Address 62
#define IPFIX_bgpNextHopIPv6Address 63

#define IPFIX_mplsTopLabelStackSection 70
#define IPFIX_mplsLabelStackSection2 71
#define IPFIX_mplsLabelStackSection3 72
#define IPFIX_mplsLabelStackSection4 73
#define IPFIX_mplsLabelStackSection5 74
#define IPFIX_mplsLabelStackSection6 75
#define IPFIX_mplsLabelStackSection7 76
#define IPFIX_mplsLabelStackSection8 77
#define IPFIX_mplsLabelStackSection9 78
#define IPFIX_mplsLabelStackSection10 79
#define IPFIX_DestinationMacAddress 80
#define IPFIX_postSourceMacAddress 81
#define IPFIX_interfaceDescription 83
#define IPFIX_octetTotalCount 85
#define IPFIX_packetTotalCount 86
#define IPFIX_forwardingStatus 89

#define NBAR_APPLICATION_DESC 94
#define NBAR_APPLICATION_ID 95
#define NBAR_APPLICATION_NAME 96

#define IPFIX_flowEndReason 136
#define IPFIX_observationPointId 138
#define IPFIX_icmpTypeCodeIPv6 139
#define IPFIX_flowId 148
#define IPFIX_observationDomainId 149
#define IPFIX_flowStartSeconds 150
#define IPFIX_flowEndSeconds 151
#define IPFIX_flowStartMilliseconds 152
#define IPFIX_flowEndMilliseconds 153
#define IPFIX_flowStartDeltaMicroseconds 158
#define IPFIX_flowEndDeltaMicroseconds 159
#define IPFIX_SystemInitTimeMiliseconds 160
#define IPFIX_flowDurationMilliseconds 161
#define IPFIX_postOctetTotalCount 171
#define IPFIX_postPacketTotalCount 172
#define IPFIX_icmpTypeV4 176
#define IPFIX_icmpCodeV4 177
#define IPFIX_icmpTypeV6 178
#define IPFIX_icmpCodeV6 179

#define IPFIX_ipTTL 192
#define IPFIX_fragmentFlags 197

#define IPFIX_postNATSourceIPv4Address 225
#define IPFIX_postNATDestinationIPv4Address 226
#define IPFIX_postNAPTSourceTransportPort 227
#define IPFIX_postNAPTDestinationTransportPort 228
#define IPFIX_natEvent 230
#define IPFIX_INGRESS_VRFID 234
#define IPFIX_EGRESS_VRFID 235
#define IPFIX_VRFname 236

#define IPFIX_biflowDirection 239

#define IPFIX_dot1qVlanId 243
#define IPFIX_postDot1qVlanId 254

#define IPFIX_dot1qCustomerVlanId 245
#define IPFIX_postDot1qCustomerVlanId 255

#define IPFIX_ingressPhysicalInterface 252
#define IPFIX_egressPhysicalInterface 253

// sub template IDs
#define IPFIX_newconnections 278
#define IPFIX_subTemplateList 292
#define IPFIX_subTemplateMultiList 293

// bidir flows
#define IPFIX_initiatorPackets 298
#define IPFIX_responderPackets 299

// sampling
#define IPFIX_selectorId 302
#define IPFIX_selectorAlgorithm 304
#define IPFIX_samplingPacketInterval 305
#define IPFIX_samplingPacketSpace 306

// cgNAT
#define IPFIX_NATPOOL_ID 283
#define IPFIX_PORT_BLOCK_START 361
#define IPFIX_PORT_BLOCK_END 362
#define IPFIX_PORT_BLOCK_STEP 363
#define IPFIX_PORT_BLOCK_SIZE 364

// Juniper inline-monitoring
#define IPFIX_dataLinkFrameSize 312
#define IPFIX_dataLinkFrameSection 315
#define IPFIX_dataLinkFrameType 408

#define IPFIX_observationTimeMilliseconds 323

// Private Enterprise Numbers
#define IPFIX_ReverseInformationElement 29305

#define YAF_payload 18
#define YAF_dnsQueryResponse 174
#define YAF_dnsQRType 175
#define YAF_dnsAuthoritative 176
#define YAF_dnsNXDomain 177
#define YAF_dnsRRSection 178
#define YAF_dnsQName 179
#define YAF_dnsTTL 199
#define YAF_dnsID 226

#define LOCAL_IPv4Received 32764
#define LOCAL_IPv6Received 32765
#define LOCAL_msecTimeReceived 32766
#define LOCAL_inPayload 32767
#define LOCAL_outPayload 32768

#define NOKIA_InsideServiceId 32769
#define NOKIA_OutsideServiceId 32770
#define NOKIA_NatSubString 32771

#define VENDOR_BIT_REVERSE 0x4000

/* prototypes */
int Init_IPFIX(int verbose, int32_t sampling, char *extensionList);

void Process_IPFIX(void *in_buff, ssize_t in_buff_cnt, FlowSource_t *fs);

#endif  //_IPFIX_H 1
