/*
 *  Copyright (c) 2014, Peter Haag
 *  Copyright (c) 2009, Peter Haag
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
 *  $Author:$
 *
 *  $Id:$
 *
 *  $LastChangedRevision:$
 *	
 */

#ifndef _IPFIX_H
#define _IPFIX_H 1

/* reference: http://tools.ietf.org/html/draft-ietf-ipfix-protocol-rfc5101bis-00 */

typedef struct ipfix_header {
	uint16_t  Version;				// set to 10 for IPFIX
	uint16_t  Length;				// Total length incl. this header. up to 65535 bytes
	uint32_t  ExportTime;			// UNIC epoch export Time of flow. 
	uint32_t  LastSequence;			// Incremental sequence counter modulo 2^32 of all IPFIX Data Records
	uint32_t  ObservationDomain;	// identifier , unique to the exporter
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
	uint16_t  	SetID; 			// SetIDs:
								// 0, 1: not used
								// 2: Template Set
								// 3: Options Template Set
#define IPFIX_TEMPLATE_FLOWSET_ID     2
#define IPFIX_OPTIONS_FLOWSET_ID      3
#define IPFIX_MIN_RECORD_FLOWSET_ID   256
	uint16_t  	Length;			// Length of bytes incl. this header
	uint32_t	records[1];		// pointer to records
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
	uint16_t	TemplateID;	// Template ID:
							// 0-255 reserved for Template Sets, Options Template Sets,
      						// and other reserved Sets yet to be created.
							// 256-65535 Template IDs of Data Sets
	uint16_t	FieldCount;
	uint32_t	elements[1];
} ipfix_template_record_t;

/* Standard Information Elements
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|  Information Element ident. |        Field Length           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
typedef struct ipfix_template_elements_std_s {
		uint16_t	Type;
		uint16_t	Length;
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
		uint16_t	Type;
		uint16_t	Length;
		uint32_t	EnterpriseNumber;
} ipfix_template_elements_e_t;

#define _1byte    1
#define _2bytes   2
#define _3bytes   3
#define _4bytes   4
#define _6bytes   6
#define _8bytes   8
#define _16bytes  16

// IPFIX std element definitios
// Flowset record types
#define IPFIX_octetDeltaCount	 			  1
#define IPFIX_packetDeltaCount	 			  2
// reserved 3
#define IPFIX_FLOWS_AGGR		 			  3
#define IPFIX_protocolIdentifier 			  4
#define IPFIX_ipClassOfService			 	  5
#define IPFIX_tcpControlBits			 	  6
#define IPFIX_SourceTransportPort		 	  7
#define IPFIX_SourceIPv4Address		 		  8
#define IPFIX_SourceIPv4PrefixLength		  9
#define IPFIX_ingressInterface		 		 10
#define IPFIX_DestinationTransportPort		 11
#define IPFIX_DestinationIPv4Address		 12
#define IPFIX_DestinationIPv4PrefixLength	 13
#define IPFIX_egressInterface		 		 14
#define IPFIX_ipNextHopIPv4Address		 	 15
#define IPFIX_bgpSourceAsNumber			 	 16
#define IPFIX_bgpDestinationAsNumber		 17
#define IPFIX_bgpNextHopIPv4Address	 		 18

#define IPFIX_flowEndSysUpTime		 		 21
#define IPFIX_flowStartSysUpTime	 		 22
#define IPFIX_postOctetDeltaCount			 23
#define IPFIX_postPacketDeltaCount			 24
#define IPFIX_SourceIPv6Address		 		 27
#define IPFIX_DestinationIPv6Address		 28
#define IPFIX_SourceIPv6PrefixLength		 29
#define IPFIX_DestinationIPv6PrefixLength	 30
#define IPFIX_flowLabelIPv6					 31
#define IPFIX_icmpTypeCodeIPv4			 	 32
// reserved 34, 35
// reserved 38, 39
// reserved 48, 49, 50, 51

// #define IPFIX_MIN_TTL			52
// #define IPFIX_MAX_TTL			53
// #define IPFIX_IPV4_IDENT			54

#define IPFIX_postIpClassOfService			 55
#define IPFIX_SourceMacAddress		 56
#define IPFIX_postDestinationMacAddress		 57
#define IPFIX_vlanId			 			 58
#define IPFIX_postVlanId			 		 59

#define IPFIX_flowDirection			 		 61
#define IPFIX_ipNextHopIPv6Address		 	 62 
#define IPFIX_bgpNextHopIPv6Address	 		 63 

#define IPFIX_mplsTopLabelStackSection		 70
#define IPFIX_mplsLabelStackSection2		 71
#define IPFIX_mplsLabelStackSection3		 72
#define IPFIX_mplsLabelStackSection4	 	 73
#define IPFIX_mplsLabelStackSection5		 74
#define IPFIX_mplsLabelStackSection6		 75
#define IPFIX_mplsLabelStackSection7		 76
#define IPFIX_mplsLabelStackSection8		 77
#define IPFIX_mplsLabelStackSection9		 78
#define IPFIX_mplsLabelStackSection10		 79
#define IPFIX_DestinationMacAddress		 	 80
#define IPFIX_postSourceMacAddress		 	 81
#define IPFIX_octetTotalCount		 	 	 85
#define IPFIX_packetTotalCount		 	 	 86
#define IPFIX_flowStartMilliseconds			152
#define IPFIX_flowEndMilliseconds			153
// reserved 89

/* prototypes */
int Init_IPFIX(void);

void Process_IPFIX(void *in_buff, ssize_t in_buff_cnt, FlowSource_t *fs);

#endif //_IPFIX_H 1
