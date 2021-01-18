/*  
 *  Copyright (c) 2012-2020, Peter Haag
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

#include "config.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "util.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfxV3.h"
#include "nfnet.h"
#include "output_raw.h"
#include "bookkeeper.h"
#include "collector.h"
#include "fnf.h"
#include "exporter.h"
#include "nbar.h"
#include "ipfix.h"


// define stack slots
#define STACK_NONE		0
#define STACK_ICMP		1
#define STACK_DSTPORT	2
#define STACK_SAMPLER	3
#define STACK_MSECFIRST	4
#define STACK_MSECLAST	5
#define STACK_SYSUPTIME	6
#define STACK_MAX		7

/* module limited globals */

typedef struct templateList_s {
	// linked list
	struct templateList_s *next;

	// template information
	time_t		updated;			// last update/refresh of template
	uint32_t	id;					// template ID

	// extension elements
	sequencer_t sequencer;

	// extension vector
	uint16_t	*extensionList;

} templateList_t;

/*
 * 	All Obervation Domains from all exporter are stored in a linked list
 *	which uniquely can identify each exporter/Observation Domain
 */
typedef struct exporterDomain_s {
	struct exporterDomain_s *next;	// linkes list to next exporter

	// exporter information
	exporter_info_record_t info;

	uint64_t	packets;			// number of packets sent by this exporter
	uint64_t	flows;				// number of flow records sent by this exporter
	uint32_t	sequence_failure;	// number of sequence failues

	//  sampler
	sampler_t		*sampler;		// sampler info
	samplerOption_t *samplerOption; // sampler options table info

	// nbar application info
	nbarOptionList_t	*nbarOptionList;	// nbar options table info

	// exporter parameters
	uint32_t	ExportTime;

	// Current sequence number
	uint32_t	PacketSequence;

	// statistics
	uint64_t	TemplateRecords;	// stat counter
	uint64_t	DataRecords;		// stat counter

	// SysUptime if sent with #160
	uint64_t	SysUpTime;			// in msec
	optionTag_t SysUpOption;

	// in order to prevent search through all lists keep
	// the last template we processed as a cache
	templateList_t *currentTemplate;

	// list of all templates of this exporter
	templateList_t *template;

} exporterDomain_t;

static const struct ipfixTranslationMap_s {
	uint16_t	id;				// IPFIX element id 
#define Stack_ONLY 0
	uint16_t	outputLength;	// output length in extension ID
	uint32_t	extensionID;	// extension ID
	uint32_t	offsetRel;		// offset rel. to extension start of struct
	uint32_t	stackID;		// save value in stack slot, if needed
	char		*name;			// name of element as string
} ipfixTranslationMap[] = {
	{ IPFIX_octetDeltaCount,             SIZEinBytes,      EXgenericFlowID,   OFFinBytes, STACK_NONE, "octetDeltaCount" },
	{ IPFIX_packetDeltaCount,            SIZEinPackets,    EXgenericFlowID,   OFFinPackets, STACK_NONE, "packetDeltaCount" },
	{ IPFIX_deltaFlowCount,              SIZEflows,        EXcntFlowID,       OFFflows, STACK_NONE, "deltaFlowCount" },
	{ IPFIX_protocolIdentifier,          SIZEproto,        EXgenericFlowID,   OFFproto, STACK_NONE, "proto" },
	{ IPFIX_ipClassOfService,            SIZEsrcTos,       EXgenericFlowID,   OFFsrcTos, STACK_NONE, "src tos" },
	{ IPFIX_tcpControlBits,              SIZEtcpFlags,     EXgenericFlowID,   OFFtcpFlags, STACK_NONE, "TCP flags" },
	{ IPFIX_SourceTransportPort,         SIZEsrcPort,      EXgenericFlowID,   OFFsrcPort, STACK_NONE, "src port" },
	{ IPFIX_SourceIPv4Address,           SIZEsrc4Addr,     EXipv4FlowID,      OFFsrc4Addr, STACK_NONE, "src IPv4" },
	{ IPFIX_SourceIPv4PrefixLength,      SIZEsrcMask,      EXflowMiscID,      OFFsrcMask, STACK_NONE, "src mask IPv4" },
	{ IPFIX_ingressInterface,            SIZEinput,        EXflowMiscID,	  OFFinput, STACK_NONE, "input interface" },
	{ IPFIX_DestinationTransportPort,    SIZEdstPort,      EXgenericFlowID,   OFFdstPort, STACK_DSTPORT, "dst port" },
	{ IPFIX_DestinationIPv4Address,      SIZEdst4Addr,     EXipv4FlowID,      OFFdst4Addr, STACK_NONE, "dst IPv4" },
	{ IPFIX_DestinationIPv4PrefixLength, SIZEdstMask,      EXflowMiscID,      OFFdstMask, STACK_NONE, "dst mask IPv4" },
	{ IPFIX_egressInterface,             SIZEoutput,       EXflowMiscID,	  OFFoutput, STACK_NONE, "output interface" },
	{ IPFIX_ipNextHopIPv4Address,        SIZENext4HopIP,   EXipNextHopV4ID,   OFFNext4HopIP, STACK_NONE, "IPv4 next hop" },
	{ IPFIX_bgpSourceAsNumber,           SIZEsrcAS,        EXasRoutingID,     OFFsrcAS, STACK_NONE, "src AS" },
	{ IPFIX_bgpDestinationAsNumber,      SIZEdstAS,        EXasRoutingID,     OFFdstAS, STACK_NONE, "dst AS" },
	{ IPFIX_bgpNextHopIPv4Address,       SIZEbgp4NextIP,   EXbgpNextHopV4ID,  OFFbgp4NextIP, STACK_NONE, "IPv4 bgp next hop" },
	{ IPFIX_flowEndSysUpTime,            Stack_ONLY,	   EXnull,			  0, STACK_MSECFIRST, "msec last SysupTime" },
	{ IPFIX_flowStartSysUpTime,          Stack_ONLY,	   EXnull,			  0, STACK_MSECLAST, "msec first SysupTime" },
	{ IPFIX_SystemInitTimeMiliseconds,   Stack_ONLY,	   EXnull,			  0, STACK_SYSUPTIME, "SysupTime msec" },
	{ IPFIX_postOctetDeltaCount,         SIZEoutBytes,     EXcntFlowID,       OFFoutBytes, STACK_NONE, "output bytes delta counter" },
	{ IPFIX_postPacketDeltaCount,        SIZEoutPackets,   EXcntFlowID,       OFFoutPackets, STACK_NONE, "output packet delta counter" },
	{ IPFIX_SourceIPv6Address,           SIZEsrc6Addr,     EXipv6FlowID,      OFFsrc6Addr, STACK_NONE, 	"IPv6 src addr" },
	{ IPFIX_DestinationIPv6Address,      SIZEdst6Addr,     EXipv6FlowID,      OFFdst6Addr, STACK_NONE, 	"IPv6 dst addr" },
	{ IPFIX_SourceIPv6PrefixLength,      SIZEsrcMask,      EXflowMiscID,      OFFsrcMask, STACK_NONE, 	"src mask bits" },
	{ IPFIX_DestinationIPv6PrefixLength, SIZEdstMask,      EXflowMiscID,      OFFdstMask, STACK_NONE, 	"dst mask bits" },
	{ IPFIX_icmpTypeCodeIPv4,            SIZEdstPort,      EXgenericFlowID,   OFFdstPort, STACK_ICMP, "icmp v4 type/code" },
	{ IPFIX_icmpTypeCodeIPv6,            SIZEdstPort,      EXgenericFlowID,   OFFdstPort, STACK_ICMP, "icmp v6 type/code" },
	{ IPFIX_postIpClassOfService,        SIZEdstTos,       EXflowMiscID,      OFFdstTos, STACK_NONE, 	"post IP class of Service" },
	{ IPFIX_SourceMacAddress,            SIZEinSrcMac,     EXmacAddrID,       OFFinSrcMac,STACK_NONE, 	"in src MAC addr" },
	{ IPFIX_postDestinationMacAddress,   SIZEoutDstMac,    EXmacAddrID,       OFFoutDstMac,	STACK_NONE, "out dst MAC addr" },
	{ IPFIX_vlanId,                      SIZEsrcVlan,      EXvLanID,          OFFsrcVlan,	STACK_NONE, "src VLAN ID" },
	{ IPFIX_postVlanId,                  SIZEdstAS,        EXvLanID,          OFFdstAS,	STACK_NONE, "dst VLAN ID" },
	{ IPFIX_flowDirection,               SIZEdir,          EXflowMiscID,      OFFdir, 	STACK_NONE, "flow direction" },
	{ IPFIX_biflowDirection,             SIZEbiFlowDir,    EXflowMiscID,      OFFbiFlowDir,  STACK_NONE, "biFlow direction" },
	{ IPFIX_flowEndReason,				 SIZEflowEndReason,EXflowMiscID,      OFFflowEndReason,  STACK_NONE, "Flow end reason" },
	{ IPFIX_ipNextHopIPv6Address,        SIZENext6HopIP,   EXipNextHopV6ID,   OFFNext6HopIP, STACK_NONE, "IPv6 next hop IP" },
	{ IPFIX_bgpNextHopIPv6Address,       SIZEbgp6NextIP,   EXbgpNextHopV6ID,  OFFbgp6NextIP, STACK_NONE, "IPv6 bgp next hop IP" },
	{ IPFIX_mplsTopLabelStackSection,    SIZEmplsLabel1,   EXmplsLabelID,     OFFmplsLabel1, STACK_NONE, "mpls label 1" },
	{ IPFIX_mplsLabelStackSection2,      SIZEmplsLabel2,   EXmplsLabelID,     OFFmplsLabel2, STACK_NONE, "mpls label 2" },
	{ IPFIX_mplsLabelStackSection3,      SIZEmplsLabel3,   EXmplsLabelID,     OFFmplsLabel3, STACK_NONE, "mpls label 3" },
	{ IPFIX_mplsLabelStackSection4,      SIZEmplsLabel4,   EXmplsLabelID,     OFFmplsLabel4, STACK_NONE, "mpls label 4" },
	{ IPFIX_mplsLabelStackSection5,      SIZEmplsLabel5,   EXmplsLabelID,     OFFmplsLabel5, STACK_NONE, "mpls label 5" },
	{ IPFIX_mplsLabelStackSection6,      SIZEmplsLabel6,   EXmplsLabelID,     OFFmplsLabel6, STACK_NONE, "mpls label 6" },
	{ IPFIX_mplsLabelStackSection7,      SIZEmplsLabel7,   EXmplsLabelID,     OFFmplsLabel7, STACK_NONE, "mpls label 7" },
	{ IPFIX_mplsLabelStackSection8,      SIZEmplsLabel8,   EXmplsLabelID,     OFFmplsLabel8, STACK_NONE, "mpls label 8" },
	{ IPFIX_mplsLabelStackSection9,      SIZEmplsLabel9,   EXmplsLabelID,     OFFmplsLabel9, STACK_NONE, "mpls label 9" },
	{ IPFIX_mplsLabelStackSection10,     SIZEmplsLabel10,  EXmplsLabelID,     OFFmplsLabel10, STACK_NONE, "mpls label 10" },
	{ IPFIX_DestinationMacAddress,       SIZEinDstMac,     EXmacAddrID,	      OFFinDstMac,	STACK_NONE, "in dst MAC addr" },
	{ IPFIX_postSourceMacAddress,        SIZEoutSrcMac,    EXmacAddrID,	      OFFoutSrcMac,	STACK_NONE, "out src MAC addr" },
	{ IPFIX_octetTotalCount,             SIZEinBytes,      EXgenericFlowID,       OFFinBytes, STACK_NONE, "input octetTotalCount" },
	{ IPFIX_packetTotalCount,            SIZEinPackets,    EXgenericFlowID,       OFFinPackets, STACK_NONE, "input packetTotalCount" },
	{ IPFIX_flowStartMilliseconds,       SIZEmsecFirst,    EXgenericFlowID,  OFFmsecFirst, STACK_NONE, "msec first" },
	{ IPFIX_flowEndMilliseconds,         SIZEmsecLast,     EXgenericFlowID,  OFFmsecLast, 	STACK_NONE, "msec last" },
	{ IPFIX_flowStartDeltaMicroseconds,  SIZEmsecFirst,    EXgenericFlowID,  OFFmsecFirst, STACK_NONE, "msec first" },
	{ IPFIX_flowEndDeltaMicroseconds,    SIZEmsecLast,     EXgenericFlowID,  OFFmsecLast, 	STACK_NONE, "msec last" },
	{ LOCAL_IPv4Received,                SIZEReceived4IP,  EXipReceivedV4ID,  OFFReceived4IP, STACK_NONE, "IPv4 exporter" },
	{ LOCAL_IPv6Received,                SIZEReceived6IP,  EXipReceivedV6ID,  OFFReceived6IP, STACK_NONE, "IPv6 exporter" },
	{ LOCAL_msecTimeReceived,            SIZEmsecReceived, EXgenericFlowID,  OFFmsecReceived, STACK_NONE, "msec time received"},
	{ IPFIX_postOctetTotalCount,         SIZEoutBytes,     EXcntFlowID,       OFFoutBytes, STACK_NONE, "output octetTotalCount" },
	{ IPFIX_postPacketTotalCount,        SIZEoutPackets,   EXcntFlowID,       OFFoutPackets, STACK_NONE, "output packetTotalCount" },
	{ NBAR_APPLICATION_ID,        		 SIZEnbarAppID,    EXnbarAppID,       OFFnbarAppID, STACK_NONE, "nbar application ID" },
	// sampling
	{ IPFIX_samplerId,					 Stack_ONLY,       EXnull,			  0,				STACK_SAMPLER, "sampler ID" },
	{ IPFIX_selectorId,					 Stack_ONLY,       EXnull,			  0,				STACK_SAMPLER, "sampler ID" },
	// payload
	{ LOCAL_payload,					 SIZEdata,       EXpayloadID,		  OFFdata,			STACK_NONE, "payload" },
	
	// End of table
	{ 0,            0, 0,  0, STACK_NONE, NULL },

};

// map for corresponding reverse element, if enterprise ID = IPFIX_ReverseInformationElement
static const struct ipfixReverseMap_s {
	uint16_t ID;		// IPFIX element id 
	uint16_t reverseID;	// reverse IPFIX element id
} ipfixReverseMap[] = {
	{ IPFIX_octetTotalCount, IPFIX_postOctetTotalCount},
	{ IPFIX_packetTotalCount, IPFIX_postPacketTotalCount},
	{ IPFIX_octetDeltaCount, IPFIX_postOctetDeltaCount},
	{ IPFIX_packetDeltaCount, IPFIX_postPacketDeltaCount},
	{ 0, 0},
};

// module limited globals
static uint32_t	processed_records;
static int printRecord;

uint32_t default_sampling;
uint32_t overwrite_sampling;

// prototypes
static int HasOptionTable(exporterDomain_t *exporter, uint16_t tableID );

static void InsertSamplerOption(exporterDomain_t *exporter, samplerOption_t *samplerOption);

static void InsertSampler(FlowSource_t *fs, exporterDomain_t *exporter, int32_t id, uint16_t mode, uint32_t interval);

static exporterDomain_t *getExporter(FlowSource_t *fs, ipfix_header_t *ipfix_header);

static void Process_ipfix_templates(exporterDomain_t *exporter, void *flowset_header, uint32_t size_left, FlowSource_t *fs);

static void Process_ipfix_template_add(exporterDomain_t *exporter, void *DataPtr, uint32_t size_left, FlowSource_t *fs);

static void Process_ipfix_template_withdraw(exporterDomain_t *exporter, void *DataPtr, uint32_t size_left, FlowSource_t *fs);

static void  Process_ipfix_option_data(exporterDomain_t *exporter, void *data_flowset, FlowSource_t *fs);

static void Process_ipfix_data(exporterDomain_t *exporter, uint32_t ExportTime, void *data_flowset, FlowSource_t *fs, templateList_t *template );

static int LookupElement(uint16_t type, uint32_t EnterpriseNumber);

#include "inline.c"
#include "nffile_inline.c"

int Init_IPFIX(int verbose, uint32_t sampling, uint32_t overwrite) {
int i;

	printRecord = verbose;
	default_sampling   = sampling;
	overwrite_sampling = overwrite;

	for (i=0; ipfixTranslationMap[i].name != NULL; i++ ) {}
	LogInfo("Init IPFIX: Max number of IPFIX tags: %i", i);

	return 1;

} // End of Init_IPFIX

static int HasOptionTable(exporterDomain_t *exporter, uint16_t tableID ) {
samplerOption_t *s;

	s = exporter->samplerOption;
	while ( s && s->tableID != tableID )
		s = s->next;

	dbg_printf("Has option table: %s\n", s == NULL ? "not found" : "found");

	return s != NULL;

} // End of HasOptionTable

static int LookupElement(uint16_t type, uint32_t EnterpriseNumber) {

	switch ( EnterpriseNumber ) {
		case 0:		// no Enterprise value
			break;
		case 6871:	// yaf CERT Coordination Centre
			// map yaf types here
			if ( type == 18 ) 
				type = LOCAL_payload;
			else {
				dbg_printf(" Skip yaf CERT Coordination Centre\n");
				return -1;
			}
			break;
		case IPFIX_ReverseInformationElement:
			for (int i=0; ipfixReverseMap[i].ID != 0; i++ ) {
				if ( ipfixReverseMap[i].ID == type ) {
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
	while ( ipfixTranslationMap[i].name != NULL ) {
		if ( ipfixTranslationMap[i].id == type ) 
			return i;
		i++;
	}

	dbg_printf(" No mapping for enterprise: %u, type: %u\n", EnterpriseNumber, type);
	return -1;

} // End of LookupElement

static exporterDomain_t *getExporter(FlowSource_t *fs, ipfix_header_t *ipfix_header) {
#define IP_STRING_LEN   40
char ipstr[IP_STRING_LEN];
exporterDomain_t **e = (exporterDomain_t **)&(fs->exporter_data);
uint32_t ObservationDomain = ntohl(ipfix_header->ObservationDomain);

	while ( *e ) {
		if ( (*e)->info.id == ObservationDomain && (*e)->info.version == 10 && 
			 (*e)->info.ip.V6[0] == fs->ip.V6[0] && (*e)->info.ip.V6[1] == fs->ip.V6[1]) 
			return *e;
		e = &((*e)->next);
	}

	if ( fs->sa_family == AF_INET ) {
		uint32_t _ip = htonl(fs->ip.V4);
		inet_ntop(AF_INET, &_ip, ipstr, sizeof(ipstr));
	} else if ( fs->sa_family == AF_INET6 ) {
		uint64_t _ip[2];
		_ip[0] = htonll(fs->ip.V6[0]);
		_ip[1] = htonll(fs->ip.V6[1]);
		inet_ntop(AF_INET6, &_ip, ipstr, sizeof(ipstr));
	} else {
		strncpy(ipstr, "<unknown>", IP_STRING_LEN);
	}

	// nothing found
	*e = (exporterDomain_t *)calloc(1, sizeof(exporterDomain_t));
	if ( !(*e)) {
		LogError("Process_ipfix: Panic! malloc() %s line %d: %s", __FILE__, __LINE__, strerror (errno));
		return NULL;
	}
	(*e)->info.header.type  = ExporterInfoRecordType;
	(*e)->info.header.size  = sizeof(exporter_info_record_t);
	(*e)->info.id 			= ObservationDomain;
	(*e)->info.ip			= fs->ip;
	(*e)->info.sa_family	= fs->sa_family;
	(*e)->info.version 		= 10;
	(*e)->info.sysid	 	= 0;

	(*e)->TemplateRecords 	= 0;
	(*e)->DataRecords 	 	= 0;
	(*e)->sequence_failure 	= 0;
	(*e)->next	 			= NULL;
	(*e)->sampler 			= NULL;
	(*e)->nbarOptionList	= NULL;

	FlushInfoExporter(fs, &((*e)->info));

	dbg_printf("[%u] New exporter: SysID: %u, Observation domain %u from: %s:%u\n", 
		ObservationDomain, (*e)->info.sysid, ObservationDomain, ipstr, fs->port);
	LogInfo("Process_ipfix: New exporter: SysID: %u, Observation domain %u from: %s\n", 
		(*e)->info.sysid, ObservationDomain, ipstr);


	return (*e);

} // End of getExporter

static void InsertSampler(FlowSource_t *fs, exporterDomain_t *exporter, int32_t id, uint16_t mode, uint32_t interval) {
sampler_t *sampler;

	dbg_printf("[%u] Insert Sampler: Exporter is 0x%llu\n", exporter->info.id, (long long unsigned)exporter);
	if ( !exporter->sampler ) {
		// no samplers so far 
		sampler = (sampler_t *)malloc(sizeof(sampler_t));
		if ( !sampler ) {
			LogError( "Process_v9: Panic! malloc(): %s line %d: %s", __FILE__, __LINE__, strerror (errno));
			return;
		}

		sampler->info.header.type = SamplerInfoRecordType;
		sampler->info.header.size = sizeof(sampler_info_record_t);
		sampler->info.exporter_sysid = exporter->info.sysid;
		sampler->info.id	   = id;
		sampler->info.mode	 = mode;
		sampler->info.interval = interval;
		sampler->next		  = NULL;
		exporter->sampler = sampler;

		AppendToBuffer(fs->nffile, &(sampler->info.header), sampler->info.header.size);
		LogInfo( "Add new sampler: ID: %i, mode: %u, interval: %u\n", 
			id, mode, interval);
		dbg_printf("Add new sampler: ID: %i, mode: %u, interval: %u\n", 
			id, mode, interval);

	} else {
		sampler = exporter->sampler;
		while ( sampler ) {
			// test for update of existing sampler
			if ( sampler->info.id == id ) {
				// found same sampler id - update record
				dbg_printf("Update existing sampler id: %i, mode: %u, interval: %u\n", 
					id, mode, interval);

				// we update only on changes
				if ( mode != sampler->info.mode || interval != sampler->info.interval ) {
					AppendToBuffer(fs->nffile, &(sampler->info.header), sampler->info.header.size);
					sampler->info.mode	 = mode;
					sampler->info.interval = interval;
					LogInfo( "Update existing sampler id: %i, mode: %u, interval: %u\n", 
						id, mode, interval);
				} else {
					dbg_printf("Sampler unchanged!\n");
				}

				break;
			}

			// test for end of chain
			if ( sampler->next == NULL ) {
				// end of sampler chain - insert new sampler
				sampler->next = (sampler_t *)malloc(sizeof(sampler_t));
				if ( !sampler->next ) {
					LogError( "Process_v9: Panic! malloc(): %s line %d: %s", __FILE__, __LINE__, strerror (errno));
					return;
				}
				sampler = sampler->next;

				sampler->info.header.type	 = SamplerInfoRecordType;
				sampler->info.header.size	 = sizeof(sampler_info_record_t);
				sampler->info.exporter_sysid = exporter->info.sysid;
				sampler->info.id	   	= id;
				sampler->info.mode		= mode;
				sampler->info.interval	= interval;
				sampler->next			= NULL;

				AppendToBuffer(fs->nffile, &(sampler->info.header), sampler->info.header.size);
				LogInfo( "Append new sampler: ID: %u, mode: %u, interval: %u\n", 
					id, mode, interval);
				dbg_printf("Append new sampler: ID: %u, mode: %u, interval: %u\n", 
					id, mode, interval);
				break;
			}

			// advance
			sampler = sampler->next;
		}
	} 
	
} // End of InsertSampler

static void InsertSamplerOption(exporterDomain_t *exporter, samplerOption_t *samplerOption) {
samplerOption_t *s, *parent;

	parent = NULL;
	s = exporter->samplerOption;
	while (s) {
		if ( s->tableID == samplerOption->tableID ) { // table already known to us - update data
			dbg_printf("Found existing sampling info in template %i\n", samplerOption->tableID);
			break;
		}
		parent = s;
		s = s->next;
	}

	if ( s != NULL ) { // existing entry
		// replace existing table
		dbg_printf("Replace existing sampler table ID %i\n", samplerOption->tableID);
		if ( parent ) {
			parent->next = samplerOption;
		} else {
			exporter->samplerOption = samplerOption;
		}
		samplerOption->next = s->next;
		free(s);
		s = NULL;
	} else { // new entry
		dbg_printf("New sampling table ID %i\n", samplerOption->tableID);
		// push new sampling table
		samplerOption->next = exporter->samplerOption;
		exporter->samplerOption = samplerOption;
	}

	dbg_printf("Update/Insert sampler table id: %u flags: 0x%x - sampler ID: %u/%u, mode: %u/%u, interval: %u/%u\n",
		samplerOption->tableID, samplerOption->flags, 
		samplerOption->id.offset, samplerOption->id.length,
		samplerOption->mode.offset, samplerOption->mode.length,
		samplerOption->interval.offset, samplerOption->interval.length);

} // End of InsertSamplerOption

static void InsertNbarOption(exporterDomain_t *exporter, nbarOptionList_t *nbarOptionList) {
nbarOptionList_t *s, *parent;

	parent = NULL;
	s = exporter->nbarOptionList;
	while (s) {
		if ( s->tableID == nbarOptionList->tableID ) { // table already known to us - update data
			dbg_printf("Found existing nbar info in template %i\n", nbarOptionList->tableID);
			break;
		}
		parent = s;
		s = s->next;
	}

	if ( s != NULL ) { // existing entry
		// replace existing table
		dbg_printf("Replace existing nbar table ID %i\n", nbarOptionList->tableID);
		if ( parent ) {
			parent->next = nbarOptionList;
		} else {
			exporter->nbarOptionList = nbarOptionList;
		}
		nbarOptionList->next = s->next;
		free(s);
		s = NULL;
	} else { // new entry
		dbg_printf("New nbar table ID %i\n", nbarOptionList->tableID);
		// push new nbar table
		nbarOptionList->next = exporter->nbarOptionList;
		exporter->nbarOptionList = nbarOptionList;
	}

	dbg_printf("Update/Insert nbar table id: %u nbar ID: %u/%u, name: %u/%u, desc: %u/%u\n",
		nbarOptionList->tableID,
		nbarOptionList->id.offset, nbarOptionList->id.length,
		nbarOptionList->name.offset, nbarOptionList->name.length,
		nbarOptionList->desc.offset, nbarOptionList->desc.length);

} // End of InsertNbarOption

static templateList_t *getTemplate(exporterDomain_t *exporter, uint16_t id) {
templateList_t *template;

	if ( exporter->currentTemplate && ( exporter->currentTemplate->id == id ) )
		return exporter->currentTemplate;

	template = exporter->template;
	while ( template ) {
		if ( template->id == id ) {
			exporter->currentTemplate = template;
			return template;
		}
		template = template->next;
	}

	dbg_printf("[%u] Get template %u: %s\n", exporter->info.id, id, template == NULL ? "not found" : "found");

	exporter->currentTemplate = NULL;
	return NULL;

} // End of getTemplate

static templateList_t *newTemplate(exporterDomain_t *exporter, uint16_t id) {
templateList_t *template;

	template = calloc(1, sizeof(templateList_t));
	if ( !template ) {
			LogError("Process_ipfix: Panic! calloc() %s line %d: %s", __FILE__, __LINE__, strerror (errno));
			return NULL;
	}

	// init the new template
	template->next	  = exporter->template;
	template->updated = time(NULL);
	template->id	  = id;
	template->extensionList = 0;

	exporter->template = template;
	dbg_printf("[%u] Add new template ID %u\n", exporter->info.id, id);

	return template;

} // End of newTemplate

static void removeTemplate(FlowSource_t *fs, exporterDomain_t *exporter, uint16_t id) {
templateList_t *template, *parent;

	LogInfo("Process_ipfix: [%u] Withdraw template id: %i", 
			exporter->info.id, id);

	parent = NULL;
	template = exporter->template;
	while ( template && ( template->id != id ) ) {
		parent = template;
		template = template->next;
	}

	if ( template == NULL ) {
		LogError("Process_ipfix: [%u] Withdraw template id: %i - template not found", 
				exporter->info.id, id);
		return;
	}

	dbg_printf("\n[%u] Withdraw template ID: %u\n", exporter->info.id, id);

	// clear table cache, if this is the table to delete
	if (exporter->currentTemplate == template)
		exporter->currentTemplate = NULL;

	if ( parent ) {
		// remove temeplate from list
		parent->next = template->next;
	} else {
		// last temeplate removed
		exporter->template = NULL;
	}

	ClearSequencer(&(template->sequencer));
	free(template);

} // End of removeTemplate

static void removeAllTemplates(exporterDomain_t *exporter) {
templateList_t *template;

	LogInfo("Process_ipfix: Withdraw all templates from observation domain %u\n", 
		exporter->info.id);

	template = exporter->template;
	while ( template ) {
		templateList_t *next;
		next = template->next;

		dbg_printf("\n[%u] Withdraw template ID: %u\n", exporter->info.id, template->id);

		ClearSequencer(&(template->sequencer));
		free(template);

		template = next;
	}

} // End of removeAllTemplates

static templateList_t *clearOrNewTemplate(exporterDomain_t *exporter, uint16_t id) {

	dbg_printf("clearOrNewTemplate()\n");
	templateList_t *template = getTemplate(exporter, id);

	if ( !template ) {
		dbg_printf("Process_ipfix: [%u] Add template %u\n", exporter->info.id, id);
		LogInfo("Process_ipfix: [%u] Add template %u", exporter->info.id, id);
		template = newTemplate(exporter, id);
	} else {
		dbg_printf("[%u] Refresh template %u\n", exporter->info.id, id);
		ClearSequencer(&(template->sequencer));
	}
	return template;

} // End of clearOrNewTemplate

static void relinkSequencerList(exporterDomain_t *exporter) {
templateList_t *template;

	template = exporter->template;
	if ( !template )
		return;

	sequencer_t *sequencer = &(template->sequencer);
	sequencer_t *loop = sequencer;
	dbg_printf("Chain seqencer list\n");
	template = template->next;

	while ( template ) {
		sequencer->next = &(template->sequencer);
		sequencer = sequencer->next;
		template = template->next;
	}
	sequencer->next = loop;

#ifdef DEVEL
	template = exporter->template;
	sequencer = &(template->sequencer);
	while ( template ) {
		dbg_printf(" id: %u, ID: %u\n", template->id, template->sequencer.templateID);
		// sequencer->next = &(template->sequencer);
		template = template->next;
	}
	while (1) {
		dbg_printf(" sequencer id: %u\n", sequencer->templateID);
		sequencer = sequencer->next;
		if ( sequencer == loop )
			break;
	}
#endif

} // End of relinkSequencerList



static void Process_ipfix_templates(exporterDomain_t *exporter, void *flowset_header, uint32_t size_left, FlowSource_t *fs) {
ipfix_template_record_t *ipfix_template_record;
void *DataPtr;
uint32_t count;

	size_left 	   -= 4;	// subtract message header
	DataPtr = flowset_header + 4;

	ipfix_template_record = (ipfix_template_record_t *)DataPtr;

	// uint32_t	id 	  = ntohs(ipfix_template_record->TemplateID);
	count = ntohs(ipfix_template_record->FieldCount);

	if ( count == 0 ) {
		// withdraw template
		Process_ipfix_template_withdraw(exporter, DataPtr, size_left, fs);
	} else {
		// refresh/add templates
		Process_ipfix_template_add(exporter, DataPtr, size_left, fs);
	}

} // End of Process_ipfix_templates

static inline int SetSequence(sequence_t *sequenceTable, uint32_t numSequences, 
		uint16_t Type, uint16_t Length, uint16_t  EnterpriseNumber) {

	int found = 0;
	int index = LookupElement(Type, EnterpriseNumber);
	if ( index < 0 ) {	// not found - enter skip seqence
		if ( (EnterpriseNumber == 0) && 
			 (Type == IPFIX_subTemplateList || Type == IPFIX_subTemplateMultiList)) {
			sequenceTable[numSequences].inputType = Type;
			dbg_printf(" Add skip sequence for sub template type: %u, enterprise: %u, length: %u\n",
				Type, EnterpriseNumber, Length);
			found = 1;
		} else {
			sequenceTable[numSequences].inputType = 0;
		}

		sequenceTable[numSequences].inputLength	 = Length;
		sequenceTable[numSequences].extensionID	 = EXnull;
		sequenceTable[numSequences].outputLength = 0;
		sequenceTable[numSequences].offsetRel	 = 0;
		sequenceTable[numSequences].stackID		 = STACK_NONE;
		dbg_printf(" Skip sequence for unknown type: %u, enterprise: %u, length: %u\n",
			Type, EnterpriseNumber, Length);
	} else {
		found = 1;
		sequenceTable[numSequences].inputType	 = ipfixTranslationMap[index].id;
		sequenceTable[numSequences].inputLength	 = Length;
		sequenceTable[numSequences].extensionID	 = ipfixTranslationMap[index].extensionID;
		sequenceTable[numSequences].outputLength = ipfixTranslationMap[index].outputLength;
		sequenceTable[numSequences].offsetRel	 = ipfixTranslationMap[index].offsetRel;
		sequenceTable[numSequences].stackID      = ipfixTranslationMap[index].stackID;
		dbg_printf(" Map type: %u, length: %u to Extension %u - '%s' - output length: %u\n",
			ipfixTranslationMap[index].id, Length, 
			ipfixTranslationMap[index].extensionID, ipfixTranslationMap[index].name,
			ipfixTranslationMap[index].outputLength);
	}
	return found;

} // End of SetSequence

static void Process_ipfix_template_add(exporterDomain_t *exporter, void *DataPtr, uint32_t size_left, FlowSource_t *fs) {
ipfix_template_record_t *ipfix_template_record;
ipfix_template_elements_std_t *NextElement;
int i;

	// a template flowset can contain multiple records ( templates )
	while ( size_left ) {
		uint32_t id, count, size_required;
		if ( size_left < 4 ) {
			LogError("Process_ipfix [%u] Template size error at %s line %u" , 
				exporter->info.id, __FILE__, __LINE__, strerror (errno));
			size_left = 0;
			continue;
		}

		// map next record.
		ipfix_template_record = (ipfix_template_record_t *)DataPtr;
		size_left 		-= 4;

		id    = ntohs(ipfix_template_record->TemplateID);
		count = ntohs(ipfix_template_record->FieldCount);

		dbg_printf("\n[%u] Template ID: %u\n", exporter->info.id, id);
		dbg_printf("FieldCount: %u buffersize: %u\n", count, size_left);

		// assume all elements in template are std elements. correct this value, if we find an enterprise element
		size_required   = 4*count;
		if ( size_left < size_required ) {
			// if we fail this check, this flowset must be skipped.
			LogError("Process_ipfix: [%u] Not enough data for template elements! required: %i, left: %u", 
					exporter->info.id, size_required, size_left);
			dbg_printf("ERROR: Not enough data for template elements! required: %i, left: %u", size_required, size_left);
			return;
		}

		sequence_t *sequenceTable = malloc((count + 4)*sizeof(sequence_t));	// + 2 for IP and time received
		if ( !sequenceTable ) {
			LogError("Process_ipfix: malloc(): %s line %d: %s", __FILE__, __LINE__, strerror (errno));
			return;
		}

		uint32_t numSequences = 0;
		uint32_t commonFound  = 0;
		// process all elements in this record
		NextElement 	 = (ipfix_template_elements_std_t *)ipfix_template_record->elements;
		for ( i=0; i<count; i++ ) {
			uint16_t Type, Length;
			int Enterprise;
			uint32_t EnterpriseNumber;

			Type   = ntohs(NextElement->Type);
			Length = ntohs(NextElement->Length);
			Enterprise = Type & 0x8000 ? 1 : 0;
			Type = Type & 0x7FFF;

			if ( Enterprise ) {
				ipfix_template_elements_e_t *e = (ipfix_template_elements_e_t *)NextElement;
				size_required += 4;	// ad 4 for enterprise value
				if ( size_left < size_required ) {
					LogError("Process_ipfix: [%u] Not enough data for template elements! required: %i, left: %u", 
							exporter->info.id, size_required, size_left);
					dbg_printf("ERROR: Not enough data for template elements! required: %i, left: %u",
						size_required, size_left);
					return;
				}
				EnterpriseNumber = ntohl(e->EnterpriseNumber);
				if ( EnterpriseNumber == IPFIX_ReverseInformationElement ) {
					dbg_printf("[%i] Enterprise: 1, Type: %u, Length %u Reverse Information Element: %u\n",
						i, Type, Length, EnterpriseNumber);
				} else {
					dbg_printf("[%i] Enterprise: 1, Type: %u, Length %u EnterpriseNumber: %u\n",
						i, Type, Length, EnterpriseNumber);
				}
				e++;
				NextElement = (ipfix_template_elements_std_t *)e;
			} else {
				dbg_printf("[%i] Enterprise: 0, Type: %u, Length %u\n", i, Type, Length);
				EnterpriseNumber = 0;
				NextElement++;
			}
			
			commonFound += SetSequence(sequenceTable, numSequences, Type, Length, EnterpriseNumber);
			numSequences++;
		}

		dbg_printf("Processed: %u, common found: %u\n", size_required, commonFound);
		if ( commonFound == 0 ) {
			size_left -= size_required;
			DataPtr = DataPtr + size_required+4;	// +4 for header
			dbg_printf("Template does not contain common elements - skip\n");
			free(sequenceTable);
			sequenceTable = NULL;
			continue;
		}

		templateList_t *template = clearOrNewTemplate(exporter, id);
		if ( !template ) {
			LogError("Process_ipfix: abort template add: %s line %d", __FILE__, __LINE__);
			return;
		}
		template->extensionList = SetupSequencer(&(template->sequencer), sequenceTable, numSequences);
		template->updated = time(NULL);
		template->sequencer.templateID = id;
		dbg_printf("Added/Updated Sequencer to template\n");
		relinkSequencerList(exporter);
		PrintSequencer(&(template->sequencer));

		// update size left of this flowset
		size_left -= size_required;
		DataPtr = DataPtr + size_required+4;	// +4 for header
		if ( size_left < 4 ) {
			// pading
			dbg_printf("Skip %u bytes padding\n", size_left);
			size_left = 0;
		}
	}

} // End of Process_ipfix_template_add

static void Process_ipfix_template_withdraw(exporterDomain_t *exporter, void *DataPtr, uint32_t size_left, FlowSource_t *fs) {
ipfix_template_record_t *ipfix_template_record;

	// a template flowset can contain multiple records ( templates )
	if ( size_left < 4 ) {
		return;
	}
	while ( size_left ) {
		uint32_t id;

		// map next record.
		ipfix_template_record = (ipfix_template_record_t *)DataPtr;
		size_left 		-= 4;

		id 	  = ntohs(ipfix_template_record->TemplateID);
		// count = ntohs(ipfix_template_record->FieldCount);

		if ( id == IPFIX_TEMPLATE_FLOWSET_ID ) {
			// withdraw all templates
			removeAllTemplates(exporter);
		} else {
			removeTemplate(fs, exporter, id);
		}

		DataPtr = DataPtr + 4;
		if ( size_left < 4 ) {
			// pading
			dbg_printf("Skip %u bytes padding\n", size_left);
			size_left = 0;
		}
	}
 
} // End of Process_ipfix_template_withdraw

static void Process_ipfix_option_templates(exporterDomain_t *exporter, void *option_template_flowset, FlowSource_t *fs) {
uint8_t		*option_template;
uint32_t	size_left, size_required;
// uint32_t nr_scopes, nr_options;
uint16_t	tableID, field_count, scope_field_count, offset;

	size_left = GET_FLOWSET_LENGTH(option_template_flowset) - 4; // -4 for flowset header -> id and length
	if ( size_left < 6 ) {
		LogError("Process_ipfix: [%u] option template length error: size left %u too small for an options template", 
			exporter->info.id, size_left);
		return;
	}

	option_template	  = option_template_flowset + 4;
	tableID 		  = GET_OPTION_TEMPLATE_ID(option_template); 
	field_count 	  = GET_OPTION_TEMPLATE_FIELD_COUNT(option_template);
	scope_field_count = GET_OPTION_TEMPLATE_SCOPE_FIELD_COUNT(option_template);
	option_template   += 6;
	size_left -= 6;

	dbg_printf("Decode Option Template. tableID: %u, field count: %u, scope field count: %u\n",
		tableID, field_count, scope_field_count);

	if ( scope_field_count == 0  ) {
		LogError("Process_ipfx: [%u] scope field count error: length must not be zero", 
			exporter->info.id);
		dbg_printf("scope field count error: length must not be zero\n");
		return;
	}

	size_required = 2 * field_count * sizeof(uint16_t);
	dbg_printf("Size left: %u, size required: %u\n", size_left, size_required);
	if ( size_left < size_required ) {
		LogError("Process_ipfix: [%u] option template length error: size left %u too small for %u scopes length and %u options length", 
			exporter->info.id, size_left, field_count, scope_field_count);
		dbg_printf("option template length error: size left %u too small for field_count %u\n", 
			size_left, field_count);
		return;
	}

	if ( scope_field_count == 0  ) {
		LogError("Process_ipfxi: [%u] scope field count error: length must not be zero", 
			exporter->info.id);
		return;
	}

	samplerOption_t *samplerOption = (samplerOption_t *)calloc(1, sizeof(samplerOption_t));
	if ( !samplerOption ) {
		LogError("Error malloc(): %s in %s:%d", strerror (errno), __FILE__, __LINE__);
		return;
	}
	samplerOption->tableID = tableID;

	nbarOptionList_t *nbarOptionList = (nbarOptionList_t *)calloc(1, sizeof(nbarOptionList_t));
	if ( !nbarOptionList ) {
		LogError("Error malloc(): %s in %s:%d", strerror (errno), __FILE__, __LINE__);
		return;
	}

	int i;
	offset = 0;
	for ( i=0; i<scope_field_count; i++ ) {
		uint16_t id, length;
		int Enterprise;

		if ( size_left && size_left < 4 ) {
			LogError("Process_ipfix [%u] Template size error at %s line %u" , 
				exporter->info.id, __FILE__, __LINE__, strerror (errno));
			return;
		}
		id 	   = Get_val16(option_template); option_template += 2;
		length = Get_val16(option_template); option_template += 2;
		size_left -= 4;
		Enterprise = id & 0x8000 ? 1 : 0;
		if ( Enterprise ) {
			size_required += 4;
			if ( size_left < 4 ) {
//				LogError("Process_ipfix: [%u] option template length error: size left %u too small", 
//					exporter->info.id, size_left);
				dbg_printf("option template length error: size left %u too small\n", size_left);
				return;
			}
			option_template += 4;
			size_left -= 4;
			dbg_printf(" [%i] Enterprise: 1, scope id: %u, scope length %u enterprise value: %u\n", 
				i, id, length, Get_val32(option_template));
		} else {
			dbg_printf(" [%i] Enterprise: 0, scope id: %u, scope length %u\n", i, id, length);
		}
		offset += length;
	}

	for ( ;i<field_count; i++ ) {
		uint32_t enterprise_value;
		uint16_t type, length;
		int Enterprise;

		// keep compiler happy
		UNUSED(enterprise_value);
		type   = Get_val16(option_template); option_template += 2;
		length = Get_val16(option_template); option_template += 2;
		size_left -= 4;
		Enterprise = type & 0x8000 ? 1 : 0;
		if ( Enterprise ) {
			size_required += 4;
			if ( size_left < 4 ) {
				LogError("Process_ipfix: [%u] option template length error: size left %u too", 
					exporter->info.id, size_left);
				dbg_printf("option template length error: size left %u too small\n", size_left);
				return;
			}
			enterprise_value = Get_val32(option_template);
			option_template += 4;
			size_left -= 4;
			dbg_printf(" [%i] Enterprise: 1, option type: %u, option length %u enterprise value: %u\n", 
				i, type, length, enterprise_value);
		} else {
			dbg_printf(" [%i] Enterprise: 0, option type: %u, option length %u\n", i, type, length);
		}

		switch (type) {
			// general sampling
			case IPFIX_samplingInterval: // #34
				samplerOption->interval.length = length;
				samplerOption->interval.offset = offset;
				SetFlag(samplerOption->flags, STDSAMPLING34);
				break;
			case IPFIX_samplingAlgorithm: // #35
				samplerOption->mode.length = length;
				samplerOption->mode.offset = offset;
				SetFlag(samplerOption->flags, STDSAMPLING35);
				break;

			// individual samplers
			case IPFIX_samplerId:	// #48 depricated - fall through
			case IPFIX_selectorId:	// #302
				samplerOption->id.length = length;
				samplerOption->id.offset = offset;
				SetFlag(samplerOption->flags, SAMPLER302);
				break;
			case IPFIX_samplerMode:		  // #49 depricated - fall through
			case IPFIX_selectorAlgorithm: // #304
				samplerOption->mode.length = length;
				samplerOption->mode.offset = offset;
				SetFlag(samplerOption->flags, SAMPLER304);
				break;
			case IPFIX_samplerRandomInterval:  // #50 depricated - fall through
			case IPFIX_samplingPacketInterval: // #305
				samplerOption->interval.length = length;
				samplerOption->interval.offset = offset;
				SetFlag(samplerOption->flags, SAMPLER305);
				break;

			// nbar application information
			case NBAR_APPLICATION_DESC:
				nbarOptionList->desc.length = length;
				nbarOptionList->desc.offset = offset;
				nbarOptionList->tableID = tableID;
				break;
			case NBAR_APPLICATION_ID:
				nbarOptionList->id.length = length;
				nbarOptionList->id.offset = offset;
				nbarOptionList->tableID = tableID;
				break;
			case NBAR_APPLICATION_NAME:
				nbarOptionList->name.length = length;
				nbarOptionList->name.offset = offset;
				nbarOptionList->tableID = tableID;
				break;

			// SysUpTime information
			case IPFIX_SystemInitTimeMiliseconds:
				exporter->SysUpOption.length = length;
				exporter->SysUpOption.offset = offset;
				break;
		}
		offset += length;
	}

	if ( (samplerOption->flags & SAMPLERMASK ) != 0) {
		dbg_printf("[%u] Sampler information found\n", exporter->info.id);
		InsertSamplerOption(exporter, samplerOption);
	} else if ( (samplerOption->flags & STDMASK ) != 0) {
		dbg_printf("[%u] Std sampling information found\n", exporter->info.id);
		InsertSamplerOption(exporter, samplerOption);
	} else {
		free(samplerOption);
		dbg_printf("[%u] No Sampling information found\n", exporter->info.id);
	}

	if ( nbarOptionList->tableID ) {
		dbg_printf("[%u] found nbar options\n", exporter->info.id);
		dbg_printf("[%u] id   length: %u\n", exporter->info.id, nbarOptionList->id.length);
		dbg_printf("[%u] name length: %u\n", exporter->info.id, nbarOptionList->name.length);
		dbg_printf("[%u] desc length: %u\n", exporter->info.id, nbarOptionList->desc.length);
		InsertNbarOption(exporter, nbarOptionList);
	} else {
		free(nbarOptionList);
		dbg_printf("[%u] No nbar information found\n", exporter->info.id);
	}

	if ( exporter->SysUpOption.length ) {
		dbg_printf("[%u] SysUp information found. length: %u\n", exporter->info.id, exporter->SysUpOption.length);
	} else {
		dbg_printf("[%u] No SysUp information found\n", exporter->info.id);
	}

	processed_records++;
	dbg_printf("\n");

} // End of Process_ipfix_option_templates

static void Process_ipfix_data(exporterDomain_t *exporter, uint32_t ExportTime, void *data_flowset, FlowSource_t *fs, templateList_t *template ){
uint64_t			sampling_rate;
uint32_t			size_left;
uint8_t				*inBuff;

	size_left = GET_FLOWSET_LENGTH(data_flowset) - 4; // -4 for data flowset header -> id and length

	// map input buffer as a byte array
	inBuff = (uint8_t *)(data_flowset + 4);	// skip flowset header

	sequencer_t *sequencer = &(template->sequencer);

	dbg_printf("[%u] Process data flowset size: %u\n", exporter->info.id, size_left);

	// Check if sampling is announced
	sampling_rate = 1;

	uint32_t receivedSize = 0;
	if ( fs->sa_family == PF_INET6 )
		receivedSize = EXipReceivedV6Size;
	else
		receivedSize = EXipReceivedV4Size;

	while (size_left) {
		void *outBuff;

		if ( size_left < 4 ) {	// rounding pads
			size_left = 0;
			continue;
		}

		// check for enough space in output buffer
		uint32_t outRecordSize = CalcOutRecordSize(sequencer, inBuff, size_left);
		if ( outRecordSize == 0 ) {
			dbg_printf("Process_ipfix: output record size zero. Skip record processing");
			return;
		}
		if ( sequencer->hasVarOutLength)
			outRecordSize = 2 * size_left;

		int buffAvail = CheckBufferSpace(fs->nffile, sizeof(recordHeaderV3_t) + outRecordSize + receivedSize);
		if ( buffAvail == 0 ) {
			// this should really never occur, because the buffer gets flushed ealier
			LogError("Process_ipfix: output buffer size error. Skip ipfix record processing");
			dbg_printf("Process_ipfix: output buffer size error. Skip ipfix record processing");
			return;
		}

		// map file record to output buffer
		outBuff	= fs->nffile->buff_ptr;

		dbg_printf("[%u] Process data record: %u addr: %llu, buffer size_left: %u\n", 
			exporter->info.id, processed_records, (long long unsigned)((ptrdiff_t)inBuff - (ptrdiff_t)data_flowset), 
			size_left);

		// process record
		AddV3Header(outBuff, recordHeaderV3);

		// header data
		recordHeaderV3->engineType	= 0; // XXX fix
		recordHeaderV3->engineID	= 0; // XXX fix
		recordHeaderV3->nfversion	= 10;
		if ( sampling_rate != 1 )
			SetFlag(recordHeaderV3->flags, V3_FLAG_SAMPLED);
		recordHeaderV3->exporterID	= exporter->info.sysid;

		if ( sequencer->inLength > size_left ) {
			// overrun
			dbg_printf("Process ipfix: buffer check error: required size %zu > left buffer size: %u\n", 
				sequencer->inLength, size_left);
			LogError("Process ipfix: buffer check error: required size %i > left buffer size: %u", 
				sequencer->inLength, size_left);
			return;
		} 

		uint64_t stack[STACK_MAX];
		memset((void *)stack, 0, sizeof(stack));
		// copy record data
		int ret = SequencerRun(sequencer, inBuff, size_left, outBuff, sizeof(recordHeaderV3_t) + outRecordSize, stack);
		switch (ret) {
			case SEQ_ERROR:
				LogError("Process ipfix: Sequencer run error. Skip record processing");
				break;
			case SEQ_MEM_ERR:
				if ( buffAvail == WRITE_BUFFSIZE ) {
					LogError("Process ipfix: Sequencer run error. buffer size too small");
					return;
				}
				// XXX fix low buffer condition
				LogError("Process ipfix: Sequencer run error. fix buffer size");
				return;
				break;
		}

		dbg_printf("New record added with %u elements and size: %u\n", 
			recordHeaderV3->numElements, recordHeaderV3->size);
		// outBuff += sequencer->outLength;
		outBuff += recordHeaderV3->size;
		inBuff += sequencer->inLength;
		size_left -= sequencer->inLength;

		processed_records++;
		exporter->PacketSequence++;

		// handle sampling
		if ( overwrite_sampling > 0 ) {
			// force overwrite sampling
			sampling_rate = overwrite_sampling;
			dbg_printf("[%u] Hard overwrite sampling rate: %llu\n",
				exporter->info.id, (long long unsigned)sampling_rate);
		} else {
			// chck sampler ID
			sampler_t *sampler = exporter->sampler;
			if ( stack[STACK_SAMPLER] ) {
				uint32_t sampler_id = stack[STACK_SAMPLER];
				dbg_printf("[%u] Sampling ID %u exported\n", exporter->info.id, sampler_id);
				// individual sampler ID
				while ( sampler && sampler->info.id != sampler_id ) 
					sampler = sampler->next;

				if ( sampler ) {
					sampling_rate = sampler->info.interval;
					dbg_printf("Found sampler ID %u - sampling rate: %llu\n", 
						sampler_id, (long long unsigned)sampling_rate);
				} else {
					sampling_rate = default_sampling;
					dbg_printf("No sampler ID %u found\n", sampler_id);
				}

			} else if ( exporter->sampler ) {
				// check for sampler ID -1
				while ( sampler && sampler->info.id != -1 ) 
					sampler = sampler->next;

				if ( sampler ) {
					// found
					sampling_rate = sampler->info.interval;
					dbg_printf("[%u] Std sampling available for this flow source: Rate: %llu\n",
						exporter->info.id, (long long unsigned)sampling_rate);
				} else {
					sampling_rate = default_sampling;
					dbg_printf("[%u] No Sampling record found\n", exporter->info.id);
				}
			} else {
				dbg_printf("[%u] No Sampling record found\n", exporter->info.id);
			}
		}
		if ( sampling_rate != 1 )
			SetFlag(recordHeaderV3->flags, V3_FLAG_SAMPLED);

		// add router IP
		if ( fs->sa_family == PF_INET6 ) {
	   		PushExtension(recordHeaderV3, EXipReceivedV6, ipReceivedV6);
			ipReceivedV6->ip[0] = fs->ip.V6[0];
			ipReceivedV6->ip[1] = fs->ip.V6[1];
			dbg_printf("Add IPv6 route IP extension\n");
		} else {
	   		PushExtension(recordHeaderV3, EXipReceivedV4, ipReceivedV4);
			ipReceivedV4->ip = fs->ip.V4;
			dbg_printf("Add IPv4 route IP extension\n");
		}

		// update first_seen, last_seen
		EXgenericFlow_t *genericFlow = sequencer->offsetCache[EXgenericFlowID];
		if ( genericFlow ) {
			// add time received
			genericFlow->msecReceived = ((uint64_t)fs->received.tv_sec * 1000LL) + 
								  (uint64_t)((uint64_t)fs->received.tv_usec / 1000LL);

			// if timestamps relative to sysupTime
			// record sysuptime overwrites option template sysuptime
			if ( stack[STACK_SYSUPTIME] && stack[STACK_MSECFIRST]) {
				dbg_printf("Calculate first/last from record SysUpTime\n");
				genericFlow->msecFirst = stack[STACK_SYSUPTIME] + stack[STACK_MSECFIRST];
				genericFlow->msecLast  = stack[STACK_SYSUPTIME] + stack[STACK_MSECLAST];
			} else if ( exporter->SysUpTime && stack[STACK_MSECFIRST]) {
				dbg_printf("Calculate first/last from option SysUpTime\n");
				genericFlow->msecFirst = exporter->SysUpTime + stack[STACK_MSECFIRST];
				genericFlow->msecLast  = exporter->SysUpTime + stack[STACK_MSECLAST];
			}

			if ( genericFlow->msecFirst < fs->msecFirst )
				fs->msecFirst = genericFlow->msecFirst;
			if ( genericFlow->msecLast > fs->msecLast )
				fs->msecLast = genericFlow->msecLast;
			dbg_printf("msecFrist: %llu\n", genericFlow->msecFirst);
			dbg_printf("msecLast : %llu\n", genericFlow->msecLast);

			// sampling
			if ( sampling_rate > 1 ) {
  				genericFlow->inPackets *= (uint64_t)sampling_rate;
  				genericFlow->inBytes   *= (uint64_t)sampling_rate;
				SetFlag(recordHeaderV3->flags, V3_FLAG_SAMPLED);
			}

			switch (genericFlow->proto) {
				case IPPROTO_ICMPV6:
				case IPPROTO_ICMP:
					fs->nffile->stat_record->numflows_icmp++;
					fs->nffile->stat_record->numpackets_icmp += genericFlow->inPackets;
					fs->nffile->stat_record->numbytes_icmp   += genericFlow->inBytes;
					// fix odd CISCO behaviour for ICMP port/type in src port
					if ( genericFlow->srcPort != 0 ) {
						uint8_t *s1 = (uint8_t *)&(genericFlow->srcPort);
						uint8_t *s2 = (uint8_t *)&(genericFlow->dstPort);
						s2[0] = s1[1];
						s2[1] = s1[0];
						genericFlow->srcPort = 0;
					}
					if ( stack[STACK_ICMP] != 0 ) {
						genericFlow->dstPort = stack[STACK_ICMP];
					}
					break;
				case IPPROTO_TCP:
					fs->nffile->stat_record->numflows_tcp++;
					fs->nffile->stat_record->numpackets_tcp += genericFlow->inPackets;
					fs->nffile->stat_record->numbytes_tcp   += genericFlow->inBytes;
					genericFlow->dstPort = stack[STACK_DSTPORT];
					break;
				case IPPROTO_UDP:
					fs->nffile->stat_record->numflows_udp++;
					fs->nffile->stat_record->numpackets_udp += genericFlow->inPackets;
					fs->nffile->stat_record->numbytes_udp   += genericFlow->inBytes;
					genericFlow->dstPort = stack[STACK_DSTPORT];
					break;
				default:
					fs->nffile->stat_record->numflows_other++;
					fs->nffile->stat_record->numpackets_other += genericFlow->inPackets;
					fs->nffile->stat_record->numbytes_other   += genericFlow->inBytes;
			}
	
			exporter->flows++;
        	fs->nffile->stat_record->numflows++;
        	fs->nffile->stat_record->numpackets += genericFlow->inPackets;
        	fs->nffile->stat_record->numbytes   += genericFlow->inBytes;

		}

		EXcntFlow_t *cntFlow = sequencer->offsetCache[EXcntFlowID];
		if ( cntFlow ) {
			if ( cntFlow->flows == 0 ) {
				cntFlow->flows++;
       			fs->nffile->stat_record->numpackets += cntFlow->outPackets;
       			fs->nffile->stat_record->numbytes   += cntFlow->outBytes;
			}
		}

		if ( printRecord ) {
			char *string;
			master_record_t master_record;
			memset((void *)&master_record, 0, sizeof(master_record_t));
			ExpandRecord_v3(recordHeaderV3, &master_record);
		 	flow_record_to_raw(&master_record, &string, 0);
			printf("%s\n", string);
		}

		fs->nffile->block_header->size  += recordHeaderV3->size;
		fs->nffile->block_header->NumRecords++;
		fs->nffile->buff_ptr	= outBuff;

		// buffer size sanity check
		if ( fs->nffile->block_header->size  > WRITE_BUFFSIZE ) {
			// should never happen
			LogError("### Software error ###: %s line %d", __FILE__, __LINE__);
			LogError("Process ipfix: Output buffer overflow! Flush buffer and skip records.");
			LogError("Buffer size: %u > %u", fs->nffile->block_header->size, WRITE_BUFFSIZE);

			// reset buffer
			fs->nffile->block_header->size 		= 0;
			fs->nffile->block_header->NumRecords = 0;
			fs->nffile->buff_ptr = (void *)((void *)fs->nffile->block_header + sizeof(dataBlock_t) );
			return;
		}
	}

} // End of Process_ipfix_data

static inline void Process_ipfix_sampler_option_data(exporterDomain_t *exporter, FlowSource_t *fs, samplerOption_t *samplerOption, void *data_flowset) {

	uint32_t size_left = GET_FLOWSET_LENGTH(data_flowset) - 4; // -4 for data flowset header -> id and length
	dbg_printf("[%u] Process option data flowset size: %u\n", exporter->info.id, size_left);

	if ( (samplerOption->id.offset + samplerOption->id.length) > size_left ) {
		LogError( "Process_sampler_option size error: not enought data. Have: %u, want: %u:", 
			size_left, (samplerOption->id.offset + samplerOption->id.length));
		return;
	}

	// map input buffer as a byte array
	uint8_t *in	= (uint8_t *)(data_flowset + 4);  // skip flowset header

	if ( (samplerOption->flags & SAMPLERMASK ) != 0) {
		int32_t  id;
		uint16_t mode;
		uint32_t interval;

		if ( CHECK_OPTION_DATA(size_left, samplerOption->id) && 
			 CHECK_OPTION_DATA(size_left, samplerOption->mode) &&
			 CHECK_OPTION_DATA(size_left, samplerOption->interval)) {
			id	 = Get_val(in, samplerOption->id.offset, samplerOption->id.length);
			mode = Get_val(in, samplerOption->mode.offset, samplerOption->mode.length);
			interval = Get_val(in, samplerOption->interval.offset, samplerOption->interval.length);
		} else {
			LogError("Process_ipfix_option: %s line %d: Not enough data for option data", __FILE__, __LINE__);
			return;
		}

		InsertSampler(fs, exporter, id, mode, interval);

		dbg_printf("Extracted Sampler data:\n");
		dbg_printf("Sampler ID	    : %u\n", id);
		dbg_printf("Sampler mode	: %u\n", mode);
		dbg_printf("Sampler interval: %u\n", interval);
	}

	if ( (samplerOption->flags & STDMASK ) != 0) {
		int32_t  id;
		uint16_t mode;
		uint32_t interval;

		id		 = -1;
		if ( CHECK_OPTION_DATA(size_left, samplerOption->mode) &&
			 CHECK_OPTION_DATA(size_left, samplerOption->interval)) {
			mode	 = Get_val(in, samplerOption->mode.offset, samplerOption->mode.length);
			interval = Get_val(in, samplerOption->interval.offset, samplerOption->interval.length);
		} else {
			LogError("Process_ipfix_option: %s line %d: Not enough data for option data", __FILE__, __LINE__);
			return;
		}

 		InsertSampler(fs, exporter, id, mode, interval);

		dbg_printf("Extracted Std Sampler data:\n");
		dbg_printf("Sampler ID	     : %i\n", id);
		dbg_printf("Sampler algorithm: %u\n", mode);
		dbg_printf("Sampler interval : %u\n", interval);

		dbg_printf("Set std sampler: algorithm: %u, interval: %u\n", 
				mode, interval);
	}

} // End of Process_ipfix_sampler_option_data

static void Process_ipfix_nbar_option_data(exporterDomain_t *exporter, FlowSource_t *fs, nbarOptionList_t *nbarOptionList, void *data_flowset) {

	uint32_t size_left = GET_FLOWSET_LENGTH(data_flowset) - 4; // -4 for data flowset header -> id and length
	dbg_printf("[%u] Process nbar option data flowset size: %u\n", exporter->info.id, size_left);

	// map input buffer as a byte array
	uint8_t *inBuff = (uint8_t *)(data_flowset + 4);	// skip flowset header
	// data size
	size_t nbar_data_size = nbarOptionList->id.length + nbarOptionList->name.length + nbarOptionList->desc.length;
	// size of record
	size_t nbar_option_size = nbarOptionList->scopeSize + nbar_data_size;
	// number of records in data
	int numRecords = size_left / nbar_option_size;
	dbg_printf("[%u] nbar option data - records: %u, size: %zu\n", exporter->info.id, numRecords, nbar_option_size);

	if ( numRecords == 0 || nbar_option_size == 0 || nbar_option_size > size_left ) {
		LogError( "Process_nbar_option: nbar option size error: option size: %u, size left: %u", nbar_option_size, size_left);
		return;
	}

	size_t nbar_total_size = numRecords * ( sizeof(nbarRecordHeader_t) + sizeof(NbarAppInfo_t) + nbar_data_size );
	size_t align = nbar_total_size & 0x3;
	if ( align ) {
		nbar_total_size += 4 - align;
	}

	// output buffer size check for all expected records
	if ( !CheckBufferSpace(fs->nffile, nbar_total_size)) {
		// fishy! - should never happen. maybe disk full?
		LogError("Process_nbar_option: output buffer size error. Abort nbar record processing");
		return;
	}

	void *outBuff = fs->nffile->buff_ptr;

	int cnt = 0;
	while ( size_left >= nbar_option_size ) {
		// push nbar header
		AddNbarHeader(outBuff, nbarHeader);

		// push nbar app info record
		PushNbarVarLengthExtension(nbarHeader, NbarAppInfo, nbar_record, sizeof(NbarAppInfo_t) + nbar_data_size);
		
		nbar_record->app_id_length	 = nbarOptionList->id.length;
		nbar_record->app_name_length = nbarOptionList->name.length;
		nbar_record->app_desc_length = nbarOptionList->desc.length;
		uint8_t *p = nbar_record->data;
		int err = 0;

		//copy data
		// id octet array
		memcpy(p, inBuff + nbarOptionList->id.offset, nbarOptionList->id.length);
		p += nbarOptionList->id.length;

		// name string
		memcpy(p, inBuff + nbarOptionList->name.offset, nbarOptionList->name.length);
		uint32_t state = UTF8_ACCEPT;
		if (validate_utf8(&state, (char *)p, nbarOptionList->name.length) == UTF8_REJECT) {
			LogError("Process_nbar_option: validate_utf8() %s line %d: %s", __FILE__, __LINE__, "invalid utf8 nbar name");
   			err = 1;
    	}
		p[nbarOptionList->name.length-1] = '\0';
		p += nbarOptionList->name.length;

		// description string
		memcpy(p, inBuff + nbarOptionList->desc.offset, nbarOptionList->desc.length);
		state = UTF8_ACCEPT;
		if (validate_utf8(&state, (char *)p, nbarOptionList->name.length) == UTF8_REJECT) {
			LogError("Process_nbar_option: validate_utf8() %s line %d: %s", __FILE__, __LINE__, "invalid utf8 nbar description");
   			err = 1;
    	}
		p[nbarOptionList->desc.length-1] = '\0';

		cnt++;
#ifdef DEVEL
		if ( err == 0 ) {
			printf("nbar record: %d: \n", cnt);
			PrintNbarRecord(nbarHeader);
		} else {
			printf("Invalid nbar information - skip record\n");
		}
#endif


		// in case of an err we do no store this record
		if ( err == 0 ) {
			outBuff += nbarHeader->size;
			fs->nffile->block_header->NumRecords++;
		} 
		inBuff  += nbar_option_size;
		size_left -= nbar_option_size;
	}

	// update file record size ( -> output buffer size )
	fs->nffile->block_header->size 		 += (void *)outBuff - fs->nffile->buff_ptr;
	fs->nffile->buff_ptr 				  = (void *)outBuff;

	if ( size_left > 7 ) {
		LogInfo("Proces nbar data record - %u extra bytes", size_left);
	}
	processed_records++;

} // End of Process_ipfix_nbar_option_data

static void Process_ipfix_SysUpTime_option_data(exporterDomain_t *exporter, void *data_flowset) {

	uint32_t size_left = GET_FLOWSET_LENGTH(data_flowset) - 4; // -4 for data flowset header -> id and length
	dbg_printf("[%u] Process option data flowset size: %u\n", exporter->info.id, size_left);

	// map input buffer as a byte array
	uint8_t *in	= (uint8_t *)(data_flowset + 4);  // skip flowset header
	if ( CHECK_OPTION_DATA(size_left, exporter->SysUpOption)) {
		exporter->SysUpTime = Get_val(in, exporter->SysUpOption.offset, exporter->SysUpOption.length);
		dbg_printf("Extracted SysUpTime : %llu\n", exporter->SysUpTime);
	} else {
		LogError("Process_ipfix_option: %s line %d: Not enough data for option data", __FILE__, __LINE__);
		return;
	}

} // End of Process_ipfix_SysUpTime_option_data

static void  Process_ipfix_option_data(exporterDomain_t *exporter, void *data_flowset, FlowSource_t *fs) {

	uint16_t tableID  = GET_FLOWSET_ID(data_flowset);

	samplerOption_t *s = exporter->samplerOption;
	while ( s && s->tableID != tableID )
		s = s->next;

	if (s) {
		dbg_printf("Found sampler option table\n");
		Process_ipfix_sampler_option_data(exporter, fs, s, data_flowset);
	} else {
		dbg_printf("No sampler option table found\n");
	}

	nbarOptionList_t *n = exporter->nbarOptionList;
	while ( n && n->tableID != tableID )
		n = n->next;

	if (n) {
		dbg_printf("Found nbar option table\n");
		Process_ipfix_nbar_option_data(exporter, fs, n, data_flowset);
	} else {
		dbg_printf("No nbar option table found\n");
	}

	if ( exporter->SysUpOption.length ) {
		dbg_printf("Found SysUpTime option data\n");
		Process_ipfix_SysUpTime_option_data(exporter, data_flowset);
	} else {
		dbg_printf("No SysUpTime option data found\n");
	}

	processed_records++;

} // End of Process_ipfix_option_data

void Process_IPFIX(void *in_buff, ssize_t in_buff_cnt, FlowSource_t *fs) {
exporterDomain_t	*exporter;
ssize_t				size_left;
uint32_t			ExportTime, Sequence;
ipfix_header_t		*ipfix_header;
void				*flowset_header;

#ifdef DEVEL
static uint32_t		packet_cntr = 1;
uint32_t 			ObservationDomain;
	printf("Process_ipfix: Next packet: %i\n", packet_cntr);
#endif

	size_left 	 = in_buff_cnt;
	if ( size_left < IPFIX_HEADER_LENGTH ) {
		LogError("Process_ipfix: Too little data for ipfix packet: '%lli'", (long long)size_left);
		return;
	}

	ipfix_header = (ipfix_header_t *)in_buff;
	ExportTime   = ntohl(ipfix_header->ExportTime);
	Sequence     = ntohl(ipfix_header->LastSequence);

#ifdef DEVEL
	ObservationDomain = ntohl(ipfix_header->ObservationDomain);
#endif

	exporter = getExporter(fs, ipfix_header);
	if ( !exporter ) {
		LogError("Process_ipfix: Exporter NULL: Abort ipfix record processing");
		return;
	}
	exporter->packets++;

	//exporter->PacketSequence = Sequence;
	flowset_header	= (void *)ipfix_header + IPFIX_HEADER_LENGTH;
	size_left 	   -= IPFIX_HEADER_LENGTH;

	dbg_printf("\n[%u] process packet: %u, exported: %s, TemplateRecords: %llu, DataRecords: %llu, buffer: %li \n", 
		ObservationDomain, packet_cntr++, UNIX2ISO(ExportTime), (long long unsigned)exporter->TemplateRecords, 
		(long long unsigned)exporter->DataRecords, size_left);
	dbg_printf("[%u] Sequence: %u\n", ObservationDomain, Sequence);

	// sequence check
	// 2^32 wrap is handled automatically as both counters overflow
	if ( Sequence != exporter->PacketSequence ) {
		if ( exporter->DataRecords != 0 ) {
			// sync sequence on first data record without error report
			fs->nffile->stat_record->sequence_failure++;
			exporter->sequence_failure++;
			dbg_printf("[%u] Sequence check failed: last seq: %u, seq %u\n", 
				exporter->info.id, Sequence, exporter->PacketSequence);
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
		if ( size_left < 4 ) {
			return;
		}

		// grab flowset header
		flowset_header = flowset_header + flowset_length;
		flowset_id 		= GET_FLOWSET_ID(flowset_header);
		flowset_length 	= GET_FLOWSET_LENGTH(flowset_header);

		dbg_printf("Process_ipfix: Next flowset id %u, length %u, buffersize: %zi\n", 
			flowset_id, flowset_length, size_left);

		if ( flowset_length == 0 ) {
			/* 	this should never happen, as 4 is an empty flowset 
				and smaller is an illegal flowset anyway ...
				if it happends, we can't determine the next flowset, so skip the entire export packet
			 */
			LogError("Process_ipfix: flowset zero length error.");
			dbg_printf("Process_ipfix: flowset zero length error.\n");
			return;
		}

		// possible padding
		if ( flowset_length <= 4 ) {
			return;
		}

		if ( flowset_length > size_left ) {
			LogError("Process_ipfix: flowset length error. Expected bytes: %u > buffersize: %lli", 
				flowset_length, (long long)size_left);
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
				if ( flowset_id < IPFIX_MIN_RECORD_FLOWSET_ID ) {
					dbg_printf("Invalid flowset id: %u. Skip flowset\n", flowset_id);
					LogError("Process_ipfix: Invalid flowset id: %u. Skip flowset", flowset_id);
				} else {
					dbg_printf("Process data flowset, length: %u\n", flowset_length);
					templateList_t *template = getTemplate(exporter, flowset_id);
					if ( template ) {
						Process_ipfix_data(exporter, ExportTime, flowset_header, fs, template);
						exporter->DataRecords++;
					} else if ( HasOptionTable(exporter, flowset_id) ) {
						Process_ipfix_option_data(exporter, flowset_header, fs);
					} else {
						// maybe a flowset with option data
						dbg_printf("Process ipfix: [%u] No template for id %u -> Skip record\n", 
							exporter->info.id, flowset_id);
					}
				}
			}
		} // End of switch

		// next record
		size_left -= flowset_length;

	} // End of while

} // End of Process_IPFIX
