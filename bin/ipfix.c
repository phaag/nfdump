/*  
 *  Copyright (c) 2014, Peter Haag
 *  Copyright (c) 2012, Peter Haag
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

#include "config.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nffile.h"
#include "nfx.h"
#include "nfnet.h"
#include "nf_common.h"
#include "util.h"
#include "bookkeeper.h"
#include "nfxstat.h"
#include "collector.h"
#include "exporter.h"
#include "ipfix.h"

#ifndef DEVEL
#   define dbg_printf(...) /* printf(__VA_ARGS__) */
#else
#   define dbg_printf(...) printf(__VA_ARGS__)
#endif

// a few handy macros
#define GET_FLOWSET_ID(p) 	  (Get_val16(p))
#define GET_FLOWSET_LENGTH(p) (Get_val16((void *)((p) + 2)))

#define GET_TEMPLATE_ID(p) 	  (Get_val16(p))
#define GET_TEMPLATE_COUNT(p) (Get_val16((void *)((p) + 2)))

#define GET_OPTION_TEMPLATE_ID(p) 	  		  		 (Get_val16(p))
#define GET_OPTION_TEMPLATE_FIELD_COUNT(p)   (Get_val16((void *)((p) + 2)))
#define GET_OPTION_TEMPLATE_SCOPE_FIELD_COUNT(p)   		 (Get_val16((void *)((p) + 4)))

/* module limited globals */

/* 
 * sequence element to move data from data input to output
 * a sequence exists for each IPFIX element
 */
typedef struct sequence_map_s {
/* sequence definition:
   just move a certain number of bytes          -> moveXX
   set a certain number of output bytes to zero -> zeroXX
   process input data into appropriate output   -> AnyName
 */
#define nop     		0
#define move8   		1
#define move16  		2
#define move32  		3
#define move40  		4
#define move48  		5
#define move56  		6
#define move64  		7
#define move128 		8
#define move32_sampling 9
#define move64_sampling 10
#define move_mac		11
#define move_mpls 		12
#define Time64Mili 		13
#define saveICMP 		14
#define zero8			15
#define zero16			16
#define zero32			17
#define zero64			18
#define zero128			19

	uint32_t	id;				// sequence ID as defined above
	uint16_t	input_offset;	// copy/process data at this input offset
	uint16_t	output_offset;	// copy final data to this output offset
	void		*stack;			// optionally copy data onto this stack
} sequence_map_t;

/*
 * the IPFIX template records are processed and
 * for each template we create a a translation table, which contains
 * all information required, to transform the data records from
 * the exporter into nfdump internal data structurs.
 * All templates are chained in a linked list
 */ 
typedef struct input_translation_s {
	struct input_translation_s	*next;	// linked list
	uint32_t	flags;					// flags for output record
	time_t		updated;				// timestamp of last update/refresh
	uint32_t	id;						// template ID of exporter domains
	uint32_t	input_record_size;		// size of the input record
	uint32_t	output_record_size;		// required size in nfdump format

	// tmp vars needed while processing the data record
	uint64_t	flow_start;				// start time in msec
	uint64_t	flow_end;				// end time in msec
	uint32_t	ICMP_offset;			// offset of ICMP type/code in data stream
	uint64_t    packets;				// total (in)packets - sampling corrected
	uint64_t    bytes;					// total (in)bytes - sampling corrected
	uint64_t    out_packets;			// total out packets - sampling corrected
	uint64_t    out_bytes;				// total out bytes - sampling corrected
//	uint32_t	src_as_offset;
//	uint32_t	dst_as_offset;
//	uint32_t	sampler_offset;
//	uint32_t	sampler_size;
//	uint32_t	engine_offset;
	uint32_t	router_ip_offset;
	uint32_t	received_offset;

	// etension map infos
	uint32_t	extension_map_changed;	// map changed while refreshing?
	extension_info_t 	 extension_info; // the extension map reflecting this template

	// sequence map information
	uint32_t	number_of_sequences;	// number of sequences for the translate 
	sequence_map_t *sequence;			// sequence map
} input_translation_t;

/*
 * 	All Obervation Domains from all exporter are stored in a linked list
 *	which uniquely can identify each exporter/Observation Domain
 */
typedef struct exporter_ipfix_domain_s {
	struct exporter_ipfix_domain_s	*next;	// linkes list to next exporter

	// generic exporter information
	exporter_info_record_t info;

	uint64_t	packets;			// number of packets sent by this exporter
	uint64_t	flows;				// number of flow records sent by this exporter
	uint32_t	sequence_failure;	// number of sequence failues

	// generic sampler
	generic_sampler_t		*sampler;

	// exporter parameters
	uint32_t	ExportTime;

	// Current sequence number
	uint32_t	PacketSequence;

	// statistics
	uint64_t	TemplateRecords;	// stat counter
	uint64_t	DataRecords;		// stat counter

	// linked list of all templates sent by this exporter
	input_translation_t	*input_translation_table; 

	// in order to prevent search through all lists keep
	// the last template we processed as a cache
	input_translation_t *current_table;

} exporter_ipfix_domain_t;


static struct ipfix_element_map_s {
	uint16_t	id;			// IPFIX element id 
	uint16_t	length;		// type of this element ( input length )
	uint16_t	out_length;	// type of this element ( output length )
	uint32_t	sequence;	// 
	uint32_t	zero_sequence;	// 
	uint16_t	extension;	// maps into nfdump extension ID
} ipfix_element_map[] = {
	{0, 0, 0},
	{ IPFIX_octetDeltaCount, 			 _8bytes, 	_8bytes,  move64_sampling, zero64, COMMON_BLOCK },
	{ IPFIX_octetDeltaCount, 			 _4bytes, 	_8bytes,  move32_sampling, zero64, COMMON_BLOCK },
	{ IPFIX_packetDeltaCount, 			 _8bytes, 	_8bytes,  move64_sampling, zero64, COMMON_BLOCK },
	{ IPFIX_packetDeltaCount, 			 _4bytes, 	_8bytes,  move32_sampling, zero64, COMMON_BLOCK },
	{ IPFIX_octetTotalCount, 			 _8bytes, 	_8bytes,  move64_sampling, zero64, COMMON_BLOCK },
	{ IPFIX_octetTotalCount, 			 _4bytes, 	_8bytes,  move32_sampling, zero64, COMMON_BLOCK },
	{ IPFIX_packetTotalCount, 			 _8bytes, 	_8bytes,  move64_sampling, zero64, COMMON_BLOCK },
	{ IPFIX_packetTotalCount, 			 _4bytes, 	_8bytes,  move32_sampling, zero64, COMMON_BLOCK },
	{ IPFIX_protocolIdentifier, 		 _1byte, 	_1byte,   move8,  zero8, COMMON_BLOCK },
	{ IPFIX_ipClassOfService, 			 _1byte, 	_1byte,   move8, zero8, COMMON_BLOCK },
	{ IPFIX_tcpControlBits, 			 _1byte, 	_1byte,   move8, zero8, COMMON_BLOCK },
	{ IPFIX_SourceTransportPort, 		 _2bytes, 	_2bytes,  move16, zero16, COMMON_BLOCK },
	{ IPFIX_SourceIPv4Address, 			 _4bytes, 	_4bytes,  move32, zero32, COMMON_BLOCK },
	{ IPFIX_SourceIPv4PrefixLength, 	 _1byte, 	_1byte,   move8, zero8, EX_MULIPLE },
	{ IPFIX_ingressInterface, 			 _4bytes, 	_4bytes,  move32, zero32, EX_IO_SNMP_4 },
	{ IPFIX_ingressInterface, 			 _2bytes, 	_2bytes,  move16, zero16, EX_IO_SNMP_2 },
	{ IPFIX_DestinationTransportPort,	 _2bytes, 	_2bytes,  move16, zero16, COMMON_BLOCK },
	{ IPFIX_DestinationIPv4Address, 	 _4bytes, 	_4bytes,  move32, zero32, COMMON_BLOCK },
	{ IPFIX_DestinationIPv4PrefixLength, _1byte, 	_1byte,   move8, zero8, EX_MULIPLE },
	{ IPFIX_egressInterface, 			 _4bytes, 	_4bytes,  move32, zero32, EX_IO_SNMP_4 },
	{ IPFIX_egressInterface, 			 _2bytes, 	_2bytes,  move16, zero16, EX_IO_SNMP_2 },
	{ IPFIX_ipNextHopIPv4Address, 		 _4bytes, 	_4bytes,  move32, zero32, EX_NEXT_HOP_v4 },
	{ IPFIX_bgpSourceAsNumber, 			 _4bytes, 	_4bytes,  move32, zero32, EX_AS_4 },
	{ IPFIX_bgpSourceAsNumber, 			 _2bytes, 	_2bytes,  move16, zero16, EX_AS_2 },
	{ IPFIX_bgpDestinationAsNumber, 	 _4bytes, 	_4bytes,  move32, zero32, EX_AS_4 },
	{ IPFIX_bgpDestinationAsNumber, 	 _2bytes, 	_2bytes,  move16, zero16, EX_AS_2 },
	{ IPFIX_bgpNextHopIPv4Address, 		 _4bytes, 	_4bytes,  move32, zero32, EX_NEXT_HOP_BGP_v4},
	{ IPFIX_flowEndSysUpTime, 			 _4bytes, 	_4bytes,  nop, nop,  COMMON_BLOCK },
	{ IPFIX_flowStartSysUpTime, 		 _4bytes, 	_4bytes,  nop, nop, COMMON_BLOCK },
	{ IPFIX_postOctetDeltaCount, 		 _8bytes, 	_8bytes,  move64, zero64, EX_OUT_BYTES_8 },
	{ IPFIX_postOctetDeltaCount, 		 _4bytes, 	_4bytes,  move32, zero32, EX_OUT_BYTES_4 },
	{ IPFIX_postPacketDeltaCount, 		 _8bytes, 	_8bytes,  move64, zero64, EX_OUT_PKG_8 },
	{ IPFIX_postPacketDeltaCount, 		 _4bytes, 	_4bytes,  move32, zero32, EX_OUT_PKG_4 },
	{ IPFIX_SourceIPv6Address, 			 _16bytes, 	_16bytes, move128, zero128, COMMON_BLOCK },
	{ IPFIX_DestinationIPv6Address, 	 _16bytes, 	_16bytes, move128, zero128, COMMON_BLOCK },
	{ IPFIX_SourceIPv6PrefixLength, 	 _1byte, 	_1byte,   move8, zero8, EX_MULIPLE },
	{ IPFIX_DestinationIPv6PrefixLength, _1byte, 	_1byte,   move8, zero8, EX_MULIPLE },
	{ IPFIX_flowLabelIPv6, 				 _4bytes, 	_4bytes,  nop, nop, COMMON_BLOCK },
	{ IPFIX_icmpTypeCodeIPv4, 			 _2bytes, 	_2bytes,  nop, nop, COMMON_BLOCK },
	{ IPFIX_postIpClassOfService, 		 _1byte, 	_1byte,   move8, zero8, EX_MULIPLE },
	{ IPFIX_SourceMacAddress, 			 _6bytes, 	_8bytes,  move_mac, zero64, EX_MAC_1},
	{ IPFIX_postDestinationMacAddress, 	 _6bytes,	_8bytes,  move_mac, zero64, EX_MAC_1},
	{ IPFIX_vlanId, 					 _2bytes, 	_2bytes,  move16, zero16, EX_VLAN}, 
	{ IPFIX_postVlanId, 				 _2bytes, 	_2bytes,  move16, zero16, EX_VLAN},
	{ IPFIX_flowDirection, 				 _1byte, 	_1byte,   move8, zero8, EX_MULIPLE },
	{ IPFIX_ipNextHopIPv6Address, 		 _16bytes, 	_16bytes, move128, zero128, EX_NEXT_HOP_v6},
	{ IPFIX_bgpNextHopIPv6Address, 		 _16bytes, 	_16bytes, move128, zero128, EX_NEXT_HOP_BGP_v6},
	{ IPFIX_mplsTopLabelStackSection, 	 _3bytes,   _4bytes,  move_mpls, zero32, EX_MPLS},
	{ IPFIX_mplsLabelStackSection2, 	 _3bytes,   _4bytes,  move_mpls, zero32, EX_MPLS},
	{ IPFIX_mplsLabelStackSection3, 	 _3bytes,   _4bytes,  move_mpls, zero32, EX_MPLS},
	{ IPFIX_mplsLabelStackSection4, 	 _3bytes,   _4bytes,  move_mpls, zero32, EX_MPLS},
	{ IPFIX_mplsLabelStackSection5, 	 _3bytes,   _4bytes,  move_mpls, zero32, EX_MPLS},
	{ IPFIX_mplsLabelStackSection6, 	 _3bytes,   _4bytes,  move_mpls, zero32, EX_MPLS},
	{ IPFIX_mplsLabelStackSection7, 	 _3bytes,   _4bytes,  move_mpls, zero32, EX_MPLS},
	{ IPFIX_mplsLabelStackSection8, 	 _3bytes,   _4bytes,  move_mpls, zero32, EX_MPLS},
	{ IPFIX_mplsLabelStackSection9, 	 _3bytes,   _4bytes,  move_mpls, zero32, EX_MPLS},
	{ IPFIX_mplsLabelStackSection10, 	 _3bytes,   _4bytes,  move_mpls, zero32, EX_MPLS},
	{ IPFIX_DestinationMacAddress, 		 _6bytes,   _8bytes,  move_mac, zero64, EX_MAC_2},
	{ IPFIX_postSourceMacAddress, 		 _6bytes,   _8bytes,  move_mac, zero64, EX_MAC_2},
	{ IPFIX_flowStartMilliseconds, 		 _8bytes,   _8bytes,  Time64Mili, zero32, COMMON_BLOCK},
	{ IPFIX_flowEndMilliseconds, 		 _8bytes,   _8bytes,  Time64Mili, zero32, COMMON_BLOCK},
	{0, 0, 0}
};

// cache to be used while parsing a template
static struct cache_s {
	struct element_param_s {
		uint16_t index;
		uint16_t found;
		uint16_t offset;
		uint16_t length;
	}			*lookup_info;
	uint32_t	max_ipfix_elements;
	uint32_t	*common_extensions;

} cache;

// module limited globals
static uint32_t	processed_records;

// externals
extern int verbose;
extern uint32_t Max_num_extensions;
extern extension_descriptor_t extension_descriptor[];
extern uint32_t overwrite_sampling;
extern uint32_t	exporter_sysid;

// prototypes
static input_translation_t *add_translation_table(exporter_ipfix_domain_t *exporter, uint16_t id);

static void remove_translation_table(FlowSource_t *fs, exporter_ipfix_domain_t *exporter, uint16_t id);

static void remove_all_translation_tables(exporter_ipfix_domain_t *exporter);

static inline exporter_ipfix_domain_t *GetExporter(FlowSource_t *fs, ipfix_header_t *ipfix_header);

static inline uint32_t MapElement(uint16_t Type, uint16_t Length, uint16_t Offset);

static inline void PushSequence(input_translation_t *table, uint16_t Type, uint32_t *offset, void *stack);

static inline void Process_ipfix_templates(exporter_ipfix_domain_t *exporter, void *flowset_header, uint32_t size_left, FlowSource_t *fs);

static inline void Process_ipfix_template_add(exporter_ipfix_domain_t *exporter, void *DataPtr, uint32_t size_left, FlowSource_t *fs);

static inline void Process_ipfix_template_withdraw(exporter_ipfix_domain_t *exporter, void *DataPtr, uint32_t size_left, FlowSource_t *fs);


#include "inline.c"
#include "nffile_inline.c"

int Init_IPFIX(void) {
int i;

	cache.lookup_info	    = (struct element_param_s *)calloc(65536, sizeof(struct element_param_s));
	cache.common_extensions = (uint32_t *)malloc((Max_num_extensions+1)*sizeof(uint32_t));
	if ( !cache.common_extensions || !cache.lookup_info ) {
		syslog(LOG_ERR, "Process_ipfix: Panic! malloc(): %s line %d: %s", __FILE__, __LINE__, strerror (errno));
		return 0;
	}

	// init the helper element table
	for (i=1; ipfix_element_map[i].id != 0; i++ ) {
		uint32_t Type = ipfix_element_map[i].id;
		// multiple same type - save first index only
		// iterate through same Types afterwards
		if ( cache.lookup_info[Type].index == 0 ) 
			cache.lookup_info[Type].index  = i;
	}
	cache.max_ipfix_elements = i;

	syslog(LOG_DEBUG,"Init IPFIX: Max number of IPFIX tags: %u", cache.max_ipfix_elements);

	return 1;

} // End of Init_IPFIX

static inline exporter_ipfix_domain_t *GetExporter(FlowSource_t *fs, ipfix_header_t *ipfix_header) {
#define IP_STRING_LEN   40
char ipstr[IP_STRING_LEN];
exporter_ipfix_domain_t **e = (exporter_ipfix_domain_t **)&(fs->exporter_data);
uint32_t ObservationDomain = ntohl(ipfix_header->ObservationDomain);

	while ( *e ) {
		if ( (*e)->info.id == ObservationDomain && (*e)->info.version == 10 && 
			 (*e)->info.ip.v6[0] == fs->ip.v6[0] && (*e)->info.ip.v6[1] == fs->ip.v6[1]) 
			return *e;
		e = &((*e)->next);
	}

	if ( fs->sa_family == AF_INET ) {
		uint32_t _ip = htonl(fs->ip.v4);
		inet_ntop(AF_INET, &_ip, ipstr, sizeof(ipstr));
	} else if ( fs->sa_family == AF_INET6 ) {
		uint64_t _ip[2];
		_ip[0] = htonll(fs->ip.v6[0]);
		_ip[1] = htonll(fs->ip.v6[1]);
		inet_ntop(AF_INET6, &_ip, ipstr, sizeof(ipstr));
	} else {
		strncpy(ipstr, "<unknown>", IP_STRING_LEN);
	}

	// nothing found
	*e = (exporter_ipfix_domain_t *)malloc(sizeof(exporter_ipfix_domain_t));
	if ( !(*e)) {
		syslog(LOG_ERR, "Process_ipfix: Panic! malloc() %s line %d: %s", __FILE__, __LINE__, strerror (errno));
		return NULL;
	}
	memset((void *)(*e), 0, sizeof(exporter_ipfix_domain_t));
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

	FlushInfoExporter(fs, &((*e)->info));

	dbg_printf("[%u] New exporter: SysID: %u, Observation domain %u from: %s\n", 
		ObservationDomain, (*e)->info.sysid, ObservationDomain, ipstr);
	syslog(LOG_INFO, "Process_ipfix: New exporter: SysID: %u, Observation domain %u from: %s\n", 
		(*e)->info.sysid, ObservationDomain, ipstr);


	return (*e);

} // End of GetExporter

static inline uint32_t MapElement(uint16_t Type, uint16_t Length, uint16_t Offset) {
int	index;

	index = cache.lookup_info[Type].index;
	if ( index ) {
		while ( index && ipfix_element_map[index].id == Type ) {
			if ( Length == ipfix_element_map[index].length ) {
				cache.lookup_info[Type].found  = 1;
				cache.lookup_info[Type].offset = Offset;
				cache.lookup_info[Type].length = Length;
				cache.lookup_info[Type].index  = index;
				dbg_printf("found extension %u for type: %u, input length: %u output length: %u Extension: %u\n", 
					ipfix_element_map[index].extension, ipfix_element_map[index].id, 
					ipfix_element_map[index].length, ipfix_element_map[index].out_length, ipfix_element_map[index].extension);
				return ipfix_element_map[index].extension;
			}
			index++;
		}
	}
	dbg_printf("Skip unknown element type: %u, Length: %u\n", Type, Length);

	return 0;

} // End of MapElement

static inline input_translation_t *GetTranslationTable(exporter_ipfix_domain_t *exporter, uint16_t id) {
input_translation_t *table;

	if ( exporter->current_table && ( exporter->current_table->id == id ) )
		return exporter->current_table;

	table = exporter->input_translation_table;
	while ( table ) {
		if ( table->id == id ) {
			exporter->current_table = table;
			return table;
		}

		table = table->next;
	}

	dbg_printf("[%u] Get translation table %u: %s\n", exporter->info.id, id, table == NULL ? "not found" : "found");

	exporter->current_table = table;
	return table;

} // End of GetTranslationTable

static input_translation_t *add_translation_table(exporter_ipfix_domain_t *exporter, uint16_t id) {
input_translation_t **table;

	table = &(exporter->input_translation_table);
	while ( *table ) {
		table = &((*table)->next);
	}

	// Allocate enough space for all potential ipfix tags, which we support
	// so template refreshing may change the table size without danger of overflowing 
	*table = calloc(1, sizeof(input_translation_t));
	if ( !(*table) ) {
			syslog(LOG_ERR, "Process_ipfix: Panic! calloc() %s line %d: %s", __FILE__, __LINE__, strerror (errno));
			return NULL;
	}
	(*table)->sequence = calloc(cache.max_ipfix_elements, sizeof(sequence_map_t));
	if ( !(*table)->sequence ) {
			syslog(LOG_ERR, "Process_ipfix: Panic! malloc() %s line %d: %s", __FILE__, __LINE__, strerror (errno));
			return NULL;
	}

	(*table)->id   = id;
	(*table)->next = NULL;

	dbg_printf("[%u] Get new translation table %u\n", exporter->info.id, id);

	return *table;

} // End of add_translation_table

static void remove_translation_table(FlowSource_t *fs, exporter_ipfix_domain_t *exporter, uint16_t id) {
input_translation_t *table, *parent;

	syslog(LOG_INFO, "Process_ipfix: [%u] Withdraw template id: %i", 
			exporter->info.id, id);

	parent = NULL;
	table = exporter->input_translation_table;
	while ( table && ( table->id != id ) ) {
		parent = table;
		table = table->next;
	}

	if ( table == NULL ) {
		syslog(LOG_ERR, "Process_ipfix: [%u] Withdraw template id: %i. translation table not found", 
				exporter->info.id, id);
		return;
	}

	dbg_printf("\n[%u] Withdraw template ID: %u\n", exporter->info.id, table->id);

	// clear table cache, if this is the table to delete
	if (exporter->current_table == table)
		exporter->current_table = NULL;

	if ( parent ) {
		// remove table from list
		parent->next = table->next;
	} else {
		// last table removed
		exporter->input_translation_table = NULL;
	}

	RemoveExtensionMap(fs, table->extension_info.map);
	free(table->sequence);
	free(table->extension_info.map);
	free(table);

} // End of remove_translation_table

static void remove_all_translation_tables(exporter_ipfix_domain_t *exporter) {
input_translation_t *table, *next;

	syslog(LOG_INFO, "Process_ipfix: Withdraw all templates from observation domain %u\n", 
		exporter->info.id);

	table = exporter->input_translation_table;
	while ( table ) {
		next = table->next;

		dbg_printf("\n[%u] Withdraw template ID: %u\n", exporter->info.id, table->id);

		free(table->sequence);
		free(table->extension_info.map);
		free(table);

		table = next;
	}

	// clear references
	exporter->input_translation_table = NULL;
	exporter->current_table = NULL;

} // End of remove_all_translation_tables

static inline void PushSequence(input_translation_t *table, uint16_t Type, uint32_t *offset, void *stack) {
uint32_t i = table->number_of_sequences;
uint32_t index = cache.lookup_info[Type].index;

	if ( table->number_of_sequences >= cache.max_ipfix_elements ) {
		syslog(LOG_ERR, "Process_ipfix: Software bug! Sequence table full. at %s line %d", 
			__FILE__, __LINE__);
		dbg_printf("Software bug! Sequence table full. at %s line %d", 
			__FILE__, __LINE__);
		return;
	}

	if ( cache.lookup_info[Type].found ) {
			table->sequence[i].id = ipfix_element_map[index].sequence;
			table->sequence[i].input_offset  = cache.lookup_info[Type].offset;
			table->sequence[i].output_offset = *offset;
			table->sequence[i].stack = stack;
	} else {
			table->sequence[i].id = ipfix_element_map[index].zero_sequence;
			table->sequence[i].input_offset  = 0;
			table->sequence[i].output_offset = *offset;
			table->sequence[i].stack = NULL;
	}
	dbg_printf("Push: sequence: %u, Type: %u, length: %u, out length: %u, id: %u, in offset: %u, out offset: %u\n",
		i, Type, ipfix_element_map[index].length, ipfix_element_map[index].out_length, table->sequence[i].id, 
		table->sequence[i].input_offset, table->sequence[i].output_offset);
	table->number_of_sequences++;
	(*offset) += ipfix_element_map[index].out_length;

} // End of PushSequence

static input_translation_t *setup_translation_table (exporter_ipfix_domain_t *exporter, uint16_t id, uint16_t input_record_size) {
input_translation_t *table;
extension_map_t 	*extension_map;
uint32_t			i, ipv6, offset, next_extension;
size_t				size_required;

	ipv6 = 0;

	table = GetTranslationTable(exporter, id);
	if ( !table ) {
		syslog(LOG_INFO, "Process_ipfix: [%u] Add template %u", exporter->info.id, id);
		table = add_translation_table(exporter, id);
		if ( !table ) {
			return NULL;
		}
		// Add an extension map
		// The number of extensions for this template is currently unknown
		// Allocate enough space for all configured extensions - some may be unused later
		// make sure memory is 4byte alligned
		size_required = Max_num_extensions * sizeof(uint16_t) + sizeof(extension_map_t);
		size_required = (size_required + 3) &~(size_t)3;
		extension_map = malloc(size_required);
		if ( !extension_map ) {
			syslog(LOG_ERR, "Process_ipfix: Panic! malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror (errno));
			return  NULL;
		}
		extension_map->type 	   = ExtensionMapType;
		// Set size to an empty table - will be adapted later
		extension_map->size 	   = sizeof(extension_map_t);
		extension_map->map_id 	   = INIT_ID;
		// packed record size still unknown at this point - will be added later
		extension_map->extension_size = 0;

		table->extension_info.map 	 = extension_map;
		table->extension_map_changed = 1;
		table->number_of_sequences 	 = 0;
 	} else {
		extension_map = table->extension_info.map;

		// reset size/extension size - it's refreshed automatically
		extension_map->size 	   	  = sizeof(extension_map_t);
		extension_map->extension_size = 0;

		dbg_printf("[%u] Refresh template %u\n", exporter->info.id, id);

		// very noisy with somee exporters
		dbg_printf("[%u] Refresh template %u\n", exporter->info.id, id);
	}
	// clear current table
	memset((void *)table->sequence, 0, cache.max_ipfix_elements * sizeof(sequence_map_t));
	table->number_of_sequences = 0;

	table->updated  	= time(NULL);
	// IPFIX only has 64bit counters
	table->flags			= 0;
	SetFlag(table->flags, FLAG_PKG_64);
	SetFlag(table->flags, FLAG_BYTES_64);
	table->ICMP_offset	= 0;
//	table->sampler_offset 	= 0;
//	table->sampler_size		= 0;
//	table->engine_offset 	= 0;
	table->router_ip_offset = 0;
	table->received_offset  = 0;

	dbg_printf("[%u] Build sequence table %u\n", exporter->info.id, id);

	// fill table
	table->id 			= id;

	/* 
	 * common data block: The common record is expected in the output stream. If not available
	 * in the template, fill values with 0
	 */

	// All required extensions
	// The order we Push all ipfix elements, must corresponde to the structure of the common record
	// followed by all available extension in the extension map
	offset = BYTE_OFFSET_first;
	PushSequence( table, IPFIX_flowStartMilliseconds, &offset, &table->flow_start);
	offset = BYTE_OFFSET_first + 4;
	PushSequence( table, IPFIX_flowEndMilliseconds, &offset, &table->flow_end);
	offset = BYTE_OFFSET_first + 8;
	offset +=1;	// Skip netflow v9 fwd status
	PushSequence( table, IPFIX_tcpControlBits, &offset, NULL);
	PushSequence( table, IPFIX_protocolIdentifier, &offset, NULL);
	PushSequence( table, IPFIX_ipClassOfService, &offset, NULL);

	PushSequence( table, IPFIX_SourceTransportPort, &offset, NULL);
	PushSequence( table, IPFIX_DestinationTransportPort, &offset, NULL);

	// skip exporter_sysid and reserved
	offset += 4;

	/* IP addresss record
	 * This record is expected in the output stream. If not available
	 * in the template, assume empty v4 address.
	 */
	if ( cache.lookup_info[IPFIX_SourceIPv4Address].found ) {
		// IPv4 addresses 
		PushSequence( table, IPFIX_SourceIPv4Address, &offset, NULL);
		PushSequence( table, IPFIX_DestinationIPv4Address, &offset, NULL);
	} else if ( cache.lookup_info[IPFIX_SourceIPv6Address].found ) {
		// IPv6 addresses 
		PushSequence( table, IPFIX_SourceIPv6Address, &offset, NULL);
		PushSequence( table, IPFIX_DestinationIPv6Address, &offset, NULL);
		// mark IPv6 
		SetFlag(table->flags, FLAG_IPV6_ADDR);
		ipv6 = 1;
	} else {
		// should not happen, assume empty IPv4 addresses, zero
		PushSequence( table, IPFIX_SourceIPv4Address, &offset, NULL);
		PushSequence( table, IPFIX_DestinationIPv4Address, &offset, NULL);
	}

	// decide between Delta or Total  counters - prefer Total if available
	if ( cache.lookup_info[IPFIX_packetTotalCount].found )
		PushSequence( table, IPFIX_packetTotalCount, &offset, &table->packets);
	else
		PushSequence( table, IPFIX_packetDeltaCount, &offset, &table->packets);
	SetFlag(table->flags, FLAG_PKG_64);

	if ( cache.lookup_info[IPFIX_octetTotalCount].found )
		PushSequence( table, IPFIX_octetTotalCount, &offset, &table->bytes);
	else
		PushSequence( table, IPFIX_octetDeltaCount, &offset, &table->bytes);
	SetFlag(table->flags, FLAG_BYTES_64);


	// Optional extensions
	next_extension = 0;
	for (i=4; extension_descriptor[i].id; i++ ) {
		uint32_t map_index = i;

		if ( cache.common_extensions[i] == 0 )
			continue;

		switch(i) {
			case EX_IO_SNMP_2:
				PushSequence( table, IPFIX_ingressInterface, &offset, NULL);
				PushSequence( table, IPFIX_egressInterface, &offset, NULL);
				break;
			case EX_IO_SNMP_4:
				PushSequence( table, IPFIX_ingressInterface, &offset, NULL);
				PushSequence( table, IPFIX_egressInterface, &offset, NULL);
				break;
			case EX_AS_2:
				PushSequence( table, IPFIX_bgpSourceAsNumber, &offset, NULL);
				PushSequence( table, IPFIX_bgpDestinationAsNumber, &offset, NULL);
				break;
			case EX_AS_4:
				PushSequence( table, IPFIX_bgpSourceAsNumber, &offset, NULL);
				PushSequence( table, IPFIX_bgpDestinationAsNumber, &offset, NULL);
				break;
			case EX_MULIPLE:
				PushSequence( table, IPFIX_postIpClassOfService, &offset, NULL);
				PushSequence( table, IPFIX_flowDirection, &offset, NULL);
				if ( ipv6 ) {
					// IPv6
					PushSequence( table, IPFIX_SourceIPv6PrefixLength, &offset, NULL);
					PushSequence( table, IPFIX_DestinationIPv6PrefixLength, &offset, NULL);
				} else {
					// IPv4
					PushSequence( table, IPFIX_SourceIPv4PrefixLength, &offset, NULL);
					PushSequence( table, IPFIX_DestinationIPv4PrefixLength, &offset, NULL);
				}
				break;
			case EX_NEXT_HOP_v4:
				PushSequence( table, IPFIX_ipNextHopIPv4Address, &offset, NULL);
				break;
			case EX_NEXT_HOP_v6:
				PushSequence( table, IPFIX_ipNextHopIPv6Address, &offset, NULL);
				SetFlag(table->flags, FLAG_IPV6_NH);
				break;
			case EX_NEXT_HOP_BGP_v4:
				PushSequence( table, IPFIX_bgpNextHopIPv4Address, &offset, NULL);
				break;
			case EX_NEXT_HOP_BGP_v6:
				PushSequence( table, IPFIX_bgpNextHopIPv6Address, &offset, NULL);
				SetFlag(table->flags, FLAG_IPV6_NHB);
				break;
			case EX_VLAN:
				PushSequence( table, IPFIX_vlanId, &offset, NULL);
				PushSequence( table, IPFIX_postVlanId, &offset, NULL);
				break;
			case EX_OUT_PKG_4:
				PushSequence( table, IPFIX_postPacketDeltaCount, &offset, NULL);
				break;
			case EX_OUT_PKG_8:
				PushSequence( table, IPFIX_postPacketDeltaCount, &offset, NULL);
				break;
			case EX_OUT_BYTES_4:
				PushSequence( table, IPFIX_postOctetDeltaCount, &offset, NULL);
				break;
			case EX_OUT_BYTES_8:
				PushSequence( table, IPFIX_postOctetDeltaCount, &offset, NULL);
				break;
			case EX_AGGR_FLOWS_8:
				break;
			case EX_MAC_1:
				PushSequence( table, IPFIX_SourceMacAddress, &offset, NULL);
				PushSequence( table, IPFIX_postDestinationMacAddress, &offset, NULL);
				break;
			case EX_MAC_2:
				PushSequence( table, IPFIX_DestinationMacAddress, &offset, NULL);
				PushSequence( table, IPFIX_postSourceMacAddress, &offset, NULL);
				break;
			case EX_MPLS:
				PushSequence( table, IPFIX_mplsTopLabelStackSection, &offset, NULL);
				PushSequence( table, IPFIX_mplsLabelStackSection2, &offset, NULL);
				PushSequence( table, IPFIX_mplsLabelStackSection3, &offset, NULL);
				PushSequence( table, IPFIX_mplsLabelStackSection4, &offset, NULL);
				PushSequence( table, IPFIX_mplsLabelStackSection5, &offset, NULL);
				PushSequence( table, IPFIX_mplsLabelStackSection6, &offset, NULL);
				PushSequence( table, IPFIX_mplsLabelStackSection7, &offset, NULL);
				PushSequence( table, IPFIX_mplsLabelStackSection8, &offset, NULL);
				PushSequence( table, IPFIX_mplsLabelStackSection9, &offset, NULL);
				PushSequence( table, IPFIX_mplsLabelStackSection10, &offset, NULL);
				break;
			case EX_ROUTER_IP_v4:
			case EX_ROUTER_IP_v6:
				if ( exporter->info.sa_family == PF_INET6 ) {
					table->router_ip_offset = offset;
					dbg_printf("Router IPv6: offset: %u, olen: %u\n", offset, 16 );
					// not an entry for the translateion table.
					// but reserve space in the output record for IPv6
					offset			 	   += 16;
					SetFlag(table->flags, FLAG_IPV6_EXP);
					map_index = EX_ROUTER_IP_v6;
				} else {
					table->router_ip_offset = offset;
					dbg_printf("Router IPv4: offset: %u, olen: %u\n", offset, 4 );
					// not an entry for the translateion table.
					// but reserve space in the output record for IPv4
					offset				   += 4;
					ClearFlag(table->flags, FLAG_IPV6_EXP);
					map_index = EX_ROUTER_IP_v4;
				}
				break;
			case EX_ROUTER_ID:
				// no value in ipfix 
				break;
			case EX_RECEIVED:
				table->received_offset = offset;
				dbg_printf("Received offset: %u\n", offset);
				offset				   += 8;
				break;

		}
		extension_map->size += sizeof(uint16_t);
		extension_map->extension_size += extension_descriptor[map_index].size;


		// found extension in map_index must be the same as in map - otherwise map is dirty
		if ( extension_map->ex_id[next_extension] != map_index ) {
			// dirty map - needs to be refreshed in output stream
			extension_map->ex_id[next_extension] = map_index;
			table->extension_map_changed = 1;

		}
		next_extension++;

	}
	extension_map->ex_id[next_extension++] = 0;

	// make sure map is aligned
	if ( extension_map->size & 0x3 ) {
		extension_map->ex_id[next_extension] = 0;
		extension_map->size = ( extension_map->size + 3 ) &~ 0x3;
	}
 
	table->output_record_size = offset;
	table->input_record_size  = input_record_size;

	// for netflow historical reason, ICMP type/code goes into dst port field
	// remember offset, for decoding
	if ( cache.lookup_info[IPFIX_icmpTypeCodeIPv4].found && cache.lookup_info[IPFIX_icmpTypeCodeIPv4].length == 2 ) {
		table->ICMP_offset = cache.lookup_info[IPFIX_icmpTypeCodeIPv4].offset;
	}

#ifdef DEVEL
	if ( table->extension_map_changed ) {
		printf("Extension Map id=%u changed!\n", extension_map->map_id);
	} else {
		printf("[%u] template %u unchanged\n", exporter->info.id, id);
	}

	printf("Process_ipfix: Check extension map: id: %d, size: %u, extension_size: %u\n", 
		extension_map->map_id, extension_map->size, extension_map->extension_size);
	{ int i;
	for (i=0; i<table->number_of_sequences; i++ ) {
		printf("Sequence %i: id: %u, in offset: %u, out offset: %u, stack: %llu\n",
			i, table->sequence[i].id, table->sequence[i].input_offset, table->sequence[i].output_offset, 
			(unsigned long long)table->sequence[i].stack);
	}
	printf("Flags: 0x%x\n", table->flags); 
	printf("Input record size: %u, output record size: %u\n", 
		table->input_record_size, table->output_record_size);
	}
	PrintExtensionMap(extension_map);
#endif

	return table;

} // End of setup_translation_table

static inline void Process_ipfix_templates(exporter_ipfix_domain_t *exporter, void *flowset_header, uint32_t size_left, FlowSource_t *fs) {
ipfix_template_record_t *ipfix_template_record;
void *DataPtr;
uint32_t id, count;

	size_left 	   -= 4;	// subtract message header
	DataPtr = flowset_header + 4;

	ipfix_template_record = (ipfix_template_record_t *)DataPtr;

	id 	  = ntohs(ipfix_template_record->TemplateID);
	count = ntohs(ipfix_template_record->FieldCount);

	if ( count == 0 ) {
		// withdraw template
		Process_ipfix_template_withdraw(exporter, DataPtr, size_left, fs);
	} else {
		// refresh/add templates
		Process_ipfix_template_add(exporter, DataPtr, size_left, fs);
	}

} // End of Process_ipfix_templates

static inline void Process_ipfix_template_add(exporter_ipfix_domain_t *exporter, void *DataPtr, uint32_t size_left, FlowSource_t *fs) {
input_translation_t *translation_table;
ipfix_template_record_t *ipfix_template_record;
ipfix_template_elements_std_t *NextElement;
int i;
uint16_t Offset = 0;

	// a template flowset can contain multiple records ( templates )
	while ( size_left ) {

		// clear helper tables
		memset((void *)cache.common_extensions, 0,  (Max_num_extensions+1)*sizeof(uint32_t));
		memset((void *)cache.lookup_info, 0, 65536 * sizeof(struct element_param_s));
		for (i=1; ipfix_element_map[i].id != 0; i++ ) {
			uint32_t Type = ipfix_element_map[i].id;
			if ( ipfix_element_map[i].id == ipfix_element_map[i-1].id )
				continue;
			cache.lookup_info[Type].index   = i;
			// other elements cleard be memset
		}

		uint32_t id, count, size_required;
		uint32_t num_extensions = 0;

		// map next record.
		ipfix_template_record = (ipfix_template_record_t *)DataPtr;
		size_left 		-= 4;

		id 	  = ntohs(ipfix_template_record->TemplateID);
		count = ntohs(ipfix_template_record->FieldCount);

		dbg_printf("\n[%u] Template ID: %u\n", exporter->info.id, id);
		dbg_printf("FieldCount: %u buffersize: %u\n", count, size_left);

		// assume all elements in template are std elements. correct this value, if we find an enterprise element
		size_required   = 4*count;
		if ( size_left < size_required ) {
			// if we fail this check, this flowset must be skipped.
			syslog(LOG_ERR, "Process_ipfix: [%u] Not enough data for template elements! required: %i, left: %u", 
					exporter->info.id, size_required, size_left);
			dbg_printf("ERROR: Not enough data for template elements! required: %i, left: %u", size_required, size_left);
			return;
		}

		Offset = 0;
		// process all elements in this record
		NextElement 	 = (ipfix_template_elements_std_t *)ipfix_template_record->elements;
		for ( i=0; i<count; i++ ) {
			uint16_t Type, Length;
			uint32_t ext_id;
			int Enterprise;
	
			Type   = ntohs(NextElement->Type);
			Length = ntohs(NextElement->Length);
			Enterprise = Type & 0x8000 ? 1 : 0;

			ext_id = MapElement(Type, Length, Offset);

			// do we store this extension? enabled != 0
			// more than 1 v9 tag may map to an extension - so count this extension once only
			if ( ext_id && extension_descriptor[ext_id].enabled ) {
				if ( cache.common_extensions[ext_id] == 0 ) {
					cache.common_extensions[ext_id] = 1;
					num_extensions++;
				}
			} 
			Offset += Length;
	
			if ( Enterprise ) {
				ipfix_template_elements_e_t *e = (ipfix_template_elements_e_t *)NextElement;
				size_required += 4;	// ad 4 for enterprise value
				if ( size_left < size_required ) {
					syslog(LOG_ERR, "Process_ipfix: [%u] Not enough data for template elements! required: %i, left: %u", 
							exporter->info.id, size_required, size_left);
					dbg_printf("ERROR: Not enough data for template elements! required: %i, left: %u", size_required, size_left);
					return;
				}
				dbg_printf(" [%i] Enterprise: 1, Type: %u, Length %u EnterpriseNumber: %u\n", i, Type, Length, ntohl(e->EnterpriseNumber));
				e++;
				NextElement = (ipfix_template_elements_std_t *)e;
			} else {
				dbg_printf(" [%i] Enterprise: 0, Type: %u, Length %u\n", i, Type, Length);
				NextElement++;
			}
		}

		dbg_printf("Processed: %u\n", size_required);

		// as the router IP address extension is not part announced in a template, we need to deal with it here
		if ( extension_descriptor[EX_ROUTER_IP_v4].enabled ) {
			if ( cache.common_extensions[EX_ROUTER_IP_v4] == 0 ) {
				cache.common_extensions[EX_ROUTER_IP_v4] = 1;
				num_extensions++;
			}
			dbg_printf("Add sending router IP address (%s) => Extension: %u\n", 
				fs->sa_family == PF_INET6 ? "ipv6" : "ipv4", EX_ROUTER_IP_v4);
		}

		// XXX for now, we do not stre router ID in IPFIX
		extension_descriptor[EX_ROUTER_ID].enabled = 0;

/*	
		// as the router IP address extension is not part announced in a template, we need to deal with it here
		if ( extension_descriptor[EX_ROUTER_ID].enabled ) {
			if ( cache.common_extensions[EX_ROUTER_ID] == 0 ) {
				cache.common_extensions[EX_ROUTER_ID] = 1;
				num_extensions++;
			}
			dbg_printf("Force add router ID (engine type/ID), Extension: %u\n", EX_ROUTER_ID);
		}
*/
		// as the received time is not announced in a template, we need to deal with it here
		if ( extension_descriptor[EX_RECEIVED].enabled ) {
			if ( cache.common_extensions[EX_RECEIVED] == 0 ) {
				cache.common_extensions[EX_RECEIVED] = 1;
				num_extensions++;
			}
			dbg_printf("Force add packet received time, Extension: %u\n", EX_RECEIVED);
		}

#ifdef DEVEL
		{
			int i;
			for (i=4; extension_descriptor[i].id; i++ ) {
				if ( cache.common_extensions[i] ) {
					printf("Enabled extension: %i\n", i);
				}
			}
		}
#endif
	
		translation_table = setup_translation_table(exporter, id, Offset);
		if (translation_table->extension_map_changed ) {
			translation_table->extension_map_changed = 0;
			// refresh he map in the ouput buffer
			dbg_printf("Translation Table changed! Add extension map ID: %i\n", translation_table->extension_info.map->map_id);
			AddExtensionMap(fs, translation_table->extension_info.map);
			dbg_printf("Translation Table added! map ID: %i\n", translation_table->extension_info.map->map_id);
		}

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

static inline void Process_ipfix_template_withdraw(exporter_ipfix_domain_t *exporter, void *DataPtr, uint32_t size_left, FlowSource_t *fs) {
ipfix_template_record_t *ipfix_template_record;

	// a template flowset can contain multiple records ( templates )
	while ( size_left ) {
		uint32_t id, count;

		// map next record.
		ipfix_template_record = (ipfix_template_record_t *)DataPtr;
		size_left 		-= 4;

		id 	  = ntohs(ipfix_template_record->TemplateID);
		count = ntohs(ipfix_template_record->FieldCount);

		if ( id == IPFIX_TEMPLATE_FLOWSET_ID ) {
			// withdraw all templates
			remove_all_translation_tables(exporter);
			ReInitExtensionMapList(fs);
		} else {
			remove_translation_table(fs, exporter, id);
		}

		DataPtr = DataPtr + 4;
		if ( size_left < 4 ) {
			// pading
			dbg_printf("Skip %u bytes padding\n", size_left);
			size_left = 0;
		}
	}
 
} // End of Process_ipfix_template_withdraw

static inline void Process_ipfix_option_templates(exporter_ipfix_domain_t *exporter, void *option_template_flowset, FlowSource_t *fs) {
void		*DataPtr;
uint32_t	size_left, size_required, i;
// uint32_t nr_scopes, nr_options;
uint16_t	id, field_count, scope_field_count, offset, sampler_id_length;
uint16_t	offset_sampler_id, offset_sampler_mode, offset_sampler_interval, found_sampler;
uint16_t	offset_std_sampler_interval, offset_std_sampler_algorithm, found_std_sampling;

	i = 0;	// keep compiler happy
	size_left 		  = GET_FLOWSET_LENGTH(option_template_flowset) - 4; // -4 for flowset header -> id and length
	if ( size_left < 6 ) {
		syslog(LOG_ERR, "Process_ipfix: [%u] option template length error: size left %u too small for an options template", 
			exporter->info.id, size_left);
		return;
	}

	DataPtr   		  = option_template_flowset + 4;
	id 	  			  = GET_OPTION_TEMPLATE_ID(DataPtr); 
	field_count 	  = GET_OPTION_TEMPLATE_FIELD_COUNT(DataPtr);
	scope_field_count = GET_OPTION_TEMPLATE_SCOPE_FIELD_COUNT(DataPtr);
	DataPtr   += 6;
	size_left -= 6;

	if ( scope_field_count == 0  ) {
		syslog(LOG_ERR, "Process_ipfx: [%u] scope field count error: length must not be zero", 
			exporter->info.id);
		dbg_printf("scope field count error: length must not be zero\n");
		return;
	}

	size_required = field_count * 2 * sizeof(uint16_t);
	dbg_printf("Size left: %u, size required: %u\n", size_left, size_required);
	if ( size_left < size_required ) {
		syslog(LOG_ERR, "Process_ipfix: [%u] option template length error: size left %u too small for %u scopes length and %u options length", 
			exporter->info.id, size_left, field_count, scope_field_count);
		dbg_printf("option template length error: size left %u too small for field_count %u\n", 
			size_left, field_count);
		return;
	}

	dbg_printf("Decode Option Template. id: %u, field count: %u, scope field count: %u\n",
		id, field_count, scope_field_count);

	if ( scope_field_count == 0  ) {
		syslog(LOG_ERR, "Process_ipfxi: [%u] scope field count error: length must not be zero", 
			exporter->info.id);
		return;
	}

	for ( i=0; i<scope_field_count; i++ ) {
		uint32_t enterprise_value;
		uint16_t id, length;
		int Enterprise;

		id 	   = Get_val16(DataPtr); DataPtr += 2;
		length = Get_val16(DataPtr); DataPtr += 2;
		Enterprise = id & 0x8000 ? 1 : 0;
		if ( Enterprise ) {
			size_required += 4;
			dbg_printf("Adjusted: Size left: %u, size required: %u\n", size_left, size_required);
			if ( size_left < size_required ) {
				syslog(LOG_ERR, "Process_ipfix: [%u] option template length error: size left %u too small for %u scopes length and %u options length", 
					exporter->info.id, size_left, field_count, scope_field_count);
				dbg_printf("option template length error: size left %u too small for field_count %u\n", 
					size_left, field_count);
				return;
			}
			enterprise_value = Get_val32(DataPtr);
			DataPtr += 4;
			dbg_printf(" [%i] Enterprise: 1, scope id: %u, scope length %u enterprise value: %u\n", 
				i, id, length, enterprise_value);
		} else {
			dbg_printf(" [%i] Enterprise: 0, scope id: %u, scope length %u\n", i, id, length);
		}
	}
	for ( ;i<field_count; i++ ) {
		uint32_t enterprise_value;
		uint16_t id, length;
		int Enterprise;

		id 	   = Get_val16(DataPtr); DataPtr += 2;
		length = Get_val16(DataPtr); DataPtr += 2;
		Enterprise = id & 0x8000 ? 1 : 0;
		if ( Enterprise ) {
			size_required += 4;
			dbg_printf("Adjusted: Size left: %u, size required: %u\n", size_left, size_required);
			if ( size_left < size_required ) {
				syslog(LOG_ERR, "Process_ipfix: [%u] option template length error: size left %u too small for %u scopes length and %u options length", 
					exporter->info.id, size_left, field_count, scope_field_count);
				dbg_printf("option template length error: size left %u too small for field_count %u\n", 
					size_left, field_count);
				return;
			}
			enterprise_value = Get_val32(DataPtr);
			DataPtr += 4;
			dbg_printf(" [%i] Enterprise: 1, option id: %u, option length %u enterprise value: %u\n", 
				i, id, length, enterprise_value);
		} else {
			dbg_printf(" [%i] Enterprise: 0, option id: %u, option length %u\n", i, id, length);
		}
	}

	sampler_id_length			 = 0;
	offset_sampler_id 			 = 0;
	offset_sampler_mode 		 = 0;
	offset_sampler_interval 	 = 0;
	offset_std_sampler_interval  = 0;
	offset_std_sampler_algorithm = 0;
	found_sampler				 = 0;
	found_std_sampling			 = 0;
	offset = 0;

/* XXX
   XXX Sampling for IPFIX not yet implemented due to lack of data and information
		switch (type) {
			// general sampling
			case NF9_SAMPLING_INTERVAL:
				offset_std_sampler_interval = offset;
				found_std_sampling++;
				break;
			case NF9_SAMPLING_ALGORITHM:
				offset_std_sampler_algorithm = offset;
				found_std_sampling++;
				break;

			// individual samplers
			case NF9_FLOW_SAMPLER_ID:
				offset_sampler_id = offset;
				sampler_id_length = length;
				found_sampler++;
				break;
			case FLOW_SAMPLER_MODE:
				offset_sampler_mode = offset;
				found_sampler++;
				break;
			case NF9_FLOW_SAMPLER_RANDOM_INTERVAL:
				offset_sampler_interval = offset;
				found_sampler++;
				break;
		}
		offset += length;
	if ( found_sampler == 3 ) { // need all three tags
		dbg_printf("[%u] Sampling information found\n", exporter->info.id);
		InsertSamplerOffset(fs, id, offset_sampler_id, sampler_id_length, offset_sampler_mode, offset_sampler_interval);
	} else if ( found_std_sampling == 2 ) { // need all two tags
		dbg_printf("[%u] Std sampling information found\n", exporter->info.id);
		InsertStdSamplerOffset(fs, id, offset_std_sampler_interval, offset_std_sampler_algorithm);
	} else {
		dbg_printf("[%u] No Sampling information found\n", exporter->info.id);
	}
*/
	dbg_printf("\n");
	processed_records++;

} // End of Process_ipfix_option_templates


static inline void Process_ipfix_data(exporter_ipfix_domain_t *exporter, void *data_flowset, FlowSource_t *fs, input_translation_t *table ){
uint64_t			sampling_rate;
uint32_t			size_left;
uint8_t				*in, *out;
int					i;
char				*string;

	size_left = GET_FLOWSET_LENGTH(data_flowset) - 4; // -4 for data flowset header -> id and length

	// map input buffer as a byte array
	in  	  = (uint8_t *)(data_flowset + 4);	// skip flowset header

	dbg_printf("[%u] Process data flowset size: %u\n", exporter->info.id, size_left);


	// Check if sampling is announced
	sampling_rate = 1;
/* ### 
	if ( table->sampler_offset && fs->sampler  ) {
		uint32_t sampler_id;
		if ( table->sampler_size == 2 ) {
			sampler_id = Get_val16((void *)&in[table->sampler_offset]);
		} else {
			sampler_id = in[table->sampler_offset];
		}
		if ( fs->sampler[sampler_id] ) {
			sampling_rate = fs->sampler[sampler_id]->interval;
			dbg_printf("[%u] Sampling ID %u available\n", exporter->info.id, sampler_id);
			dbg_printf("[%u] Sampler_offset : %u\n", exporter->info.id, table->sampler_offset);
			dbg_printf("[%u] Sampler Data : %s\n", exporter->info.id, fs->sampler == NULL ? "not available" : "available");
			dbg_printf("[%u] Sampling rate: %llu\n", exporter->info.id, (long long unsigned)sampling_rate);
		} else {
			sampling_rate = default_sampling;
			dbg_printf("[%u] Sampling ID %u not (yet) available\n", exporter->info.id, sampler_id);
		}

	} else if ( fs->std_sampling.interval > 0 ) {
		sampling_rate = fs->std_sampling.interval;
		dbg_printf("[%u] Std sampling available for this flow source: Rate: %llu\n", exporter->info.id, (long long unsigned)sampling_rate);
	} else {
		sampling_rate = default_sampling;
		dbg_printf("[%u] No Sampling record found\n", exporter->info.id);
	}
### */
	if ( overwrite_sampling > 0 )  {
		sampling_rate = overwrite_sampling;
		dbg_printf("[%u] Hard overwrite sampling rate: %llu\n", exporter->info.id, (long long unsigned)sampling_rate);
	} 

	if ( sampling_rate != 1 )
		SetFlag(table->flags, FLAG_SAMPLED);

	while (size_left) {
		common_record_t		*data_record;

		if ( (size_left < table->input_record_size) ) {
			if ( size_left > 3 ) {
				syslog(LOG_WARNING,"Process_ipfix: Corrupt data flowset? Pad bytes: %u", size_left);
				dbg_printf("Process_ipfix: Corrupt data flowset? Pad bytes: %u, table record_size: %u\n", 
					size_left, table->input_record_size);
			}
			size_left = 0;
			continue;
		}

		// check for enough space in output buffer
		if ( !CheckBufferSpace(fs->nffile, table->output_record_size) ) {
			// this should really never occur, because the buffer gets flushed ealier
			syslog(LOG_ERR,"Process_ipfix: output buffer size error. Abort ipfix record processing");
			dbg_printf("Process_ipfix: output buffer size error. Abort ipfix record processing");
			return;
		}
		processed_records++;
		exporter->PacketSequence++;

		// map file record to output buffer
		data_record	= (common_record_t *)fs->nffile->buff_ptr;
		// map output buffer as a byte array
		out 	  = (uint8_t *)data_record;

		dbg_printf("[%u] Process data record: %u addr: %llu, in record size: %u, buffer size_left: %u\n", 
			exporter->info.id, processed_records, (long long unsigned)((ptrdiff_t)in - (ptrdiff_t)data_flowset), 
			table->input_record_size, size_left);

		// fill the data record
		data_record->flags 		    = table->flags;
		data_record->size  		    = table->output_record_size;
		data_record->type  		    = CommonRecordType;
	  	data_record->ext_map	    = table->extension_info.map->map_id;
		data_record->exporter_sysid = exporter->info.sysid;
		data_record->reserved 		= 0;

		table->flow_start 		    = 0;
		table->flow_end 		    = 0;
		table->packets 		  	    = 0;
		table->bytes 		  	    = 0;
		table->out_packets 	  	    = 0;
		table->out_bytes 	  	    = 0;

		// apply copy and processing sequence
		for ( i=0; i<table->number_of_sequences; i++ ) {
			int input_offset  = table->sequence[i].input_offset;
			int output_offset = table->sequence[i].output_offset;
			void *stack = table->sequence[i].stack;
			switch (table->sequence[i].id) {
				case nop:
					break;
				case move8:
					out[output_offset] = in[input_offset];
					break;
				case move16:
					*((uint16_t *)&out[output_offset]) = Get_val16((void *)&in[input_offset]);
					break;
				case move32:
					*((uint32_t *)&out[output_offset]) = Get_val32((void *)&in[input_offset]);
					break;
				case move40:
					/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
					{ type_mask_t t;

						t.val.val64 = Get_val40((void *)&in[input_offset]);
						*((uint32_t *)&out[output_offset]) 	 = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4]) = t.val.val32[1];
					}
					break;
				case move48:
					/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
					{ type_mask_t t;
						t.val.val64 = Get_val48((void *)&in[input_offset]);
						*((uint32_t *)&out[output_offset]) 	 = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4]) = t.val.val32[1];
					}
					break;
				case move56:
					/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
					{ type_mask_t t;

						t.val.val64 = Get_val56((void *)&in[input_offset]);
						*((uint32_t *)&out[output_offset]) 	 = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4]) = t.val.val32[1];
					}
					break;
				case move64: 
					{ type_mask_t t;
						t.val.val64 = Get_val64((void *)&in[input_offset]);

						*((uint32_t *)&out[output_offset]) 	 = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4]) = t.val.val32[1];
					} break;
				case move128: 
					/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
					{ type_mask_t t;
					  
						t.val.val64 = Get_val64((void *)&in[input_offset]);
						*((uint32_t *)&out[output_offset]) 	  = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4])  = t.val.val32[1];

						t.val.val64 = Get_val64((void *)&in[input_offset+8]);
						*((uint32_t *)&out[output_offset+8])  = t.val.val32[0];
						*((uint32_t *)&out[output_offset+12]) = t.val.val32[1];
					} break;
				case move32_sampling:
					/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
					{ type_mask_t t;
						t.val.val64 = Get_val32((void *)&in[input_offset]);
						t.val.val64 *= sampling_rate;
						*((uint32_t *)&out[output_offset]) 	 = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4]) = t.val.val32[1];
					  	*(uint64_t *)stack = t.val.val64;
					} break;
				case move64_sampling:
					/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
					{ type_mask_t t;
						t.val.val64 = Get_val64((void *)&in[input_offset]);

						t.val.val64 *= sampling_rate;
						*((uint32_t *)&out[output_offset]) 	 = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4]) = t.val.val32[1];
					  	*(uint64_t *)stack = t.val.val64;
					} break;
				case Time64Mili:
					{ uint64_t DateMiliseconds = Get_val64((void *)&in[input_offset]);
					  *(uint64_t *)stack = DateMiliseconds;

					} break;
				case move_mac:
					/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
					{ type_mask_t t;

						t.val.val64 = Get_val48((void *)&in[input_offset]);
						*((uint32_t *)&out[output_offset])   = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4]) = t.val.val32[1];
					}
					break;
				case zero8:
					out[output_offset] = 0;
					break;
				case zero16:
					*((uint16_t *)&out[output_offset]) = 0;
					break;
				case zero32:
					*((uint32_t *)&out[output_offset]) = 0;
					break;
				case zero64: 
						*((uint64_t *)&out[output_offset]) = 0;
					 break;
				case zero128: 
						*((uint64_t *)&out[output_offset]) = 0;
						*((uint64_t *)&out[output_offset+8]) = 0;
					break;
				
				default:
					syslog(LOG_ERR, "Process_ipfix: Software bug! Unknown Sequence: %u. at %s line %d", 
						table->sequence[i].id, __FILE__, __LINE__);
					dbg_printf("Software bug! Unknown Sequence: %u. at %s line %d\n", 
						table->sequence[i].id, __FILE__, __LINE__);
			}
		}

		// for netflow historical reason, ICMP type/code goes into dst port field
		if ( data_record->prot == IPPROTO_ICMP || data_record->prot == IPPROTO_ICMPV6 ) {
			if ( table->ICMP_offset ) {
				data_record->srcport = 0;
				data_record->dstport = Get_val16((void *)&in[table->ICMP_offset]);
			}
		}

		// check, if we need to store the packet received time
		if ( table->received_offset ) {
			type_mask_t t;
			t.val.val64 = (uint64_t)((uint64_t)fs->received.tv_sec * 1000LL) + (uint64_t)((uint64_t)fs->received.tv_usec / 1000LL);
				*((uint32_t *)&out[table->received_offset])   = t.val.val32[0];
				*((uint32_t *)&out[table->received_offset+4]) = t.val.val32[1];
		}

		// split first/last time into epoch/msec values
		data_record->first 		= table->flow_start / 1000;
		data_record->msec_first = table->flow_start % 1000;

		data_record->last 		= table->flow_end / 1000;
		data_record->msec_last	= table->flow_end % 1000;

		// update first_seen, last_seen
		if ( table->flow_start < fs->first_seen )
			fs->first_seen = table->flow_start;
		if ( table->flow_end > fs->last_seen )
			fs->last_seen = table->flow_end;

		// check if we need to record the router IP address
		if ( table->router_ip_offset ) {
			int output_offset = table->router_ip_offset;
			if ( exporter->info.sa_family == PF_INET6 ) {
				// 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs 
				type_mask_t t;
					  
				t.val.val64 = exporter->info.ip.v6[0];
				*((uint32_t *)&out[output_offset]) 	  = t.val.val32[0];
				*((uint32_t *)&out[output_offset+4])  = t.val.val32[1];

				t.val.val64 = exporter->info.ip.v6[1];
				*((uint32_t *)&out[output_offset+8])  = t.val.val32[0];
				*((uint32_t *)&out[output_offset+12]) = t.val.val32[1];
			} else {
				*((uint32_t *)&out[output_offset]) = exporter->info.ip.v4;
			}
		}

		switch (data_record->prot ) { // switch protocol of
			case IPPROTO_ICMP:
				fs->nffile->stat_record->numflows_icmp++;
				fs->nffile->stat_record->numpackets_icmp  += table->packets;
				fs->nffile->stat_record->numbytes_icmp    += table->bytes;
				fs->nffile->stat_record->numpackets_icmp  += table->out_packets;
				fs->nffile->stat_record->numbytes_icmp    += table->out_bytes;
				break;
			case IPPROTO_TCP:
				fs->nffile->stat_record->numflows_tcp++;
				fs->nffile->stat_record->numpackets_tcp   += table->packets;
				fs->nffile->stat_record->numbytes_tcp     += table->bytes;
				fs->nffile->stat_record->numpackets_tcp   += table->out_packets;
				fs->nffile->stat_record->numbytes_tcp     += table->out_bytes;
				break;
			case IPPROTO_UDP:
				fs->nffile->stat_record->numflows_udp++;
				fs->nffile->stat_record->numpackets_udp   += table->packets;
				fs->nffile->stat_record->numbytes_udp     += table->bytes;
				fs->nffile->stat_record->numpackets_udp   += table->out_packets;
				fs->nffile->stat_record->numbytes_udp     += table->out_bytes;
				break;
			default:
				fs->nffile->stat_record->numflows_other++;
				fs->nffile->stat_record->numpackets_other += table->packets;
				fs->nffile->stat_record->numbytes_other   += table->bytes;
				fs->nffile->stat_record->numpackets_other += table->out_packets;
				fs->nffile->stat_record->numbytes_other   += table->out_bytes;
		}
		exporter->flows++;
		fs->nffile->stat_record->numflows++;
		fs->nffile->stat_record->numpackets	+= table->packets;
		fs->nffile->stat_record->numbytes	+= table->bytes;
		fs->nffile->stat_record->numpackets	+= table->out_packets;
		fs->nffile->stat_record->numbytes	+= table->out_bytes;
	
		if ( fs->xstat ) {
			uint32_t bpp = table->packets ? table->bytes/table->packets : 0;
			if ( bpp > MAX_BPP ) 
				bpp = MAX_BPP;
			if ( data_record->prot == IPPROTO_TCP ) {
				fs->xstat->bpp_histogram->tcp.bpp[bpp]++;
				fs->xstat->bpp_histogram->tcp.count++;

				fs->xstat->port_histogram->src_tcp.port[data_record->srcport]++;
				fs->xstat->port_histogram->dst_tcp.port[data_record->dstport]++;
				fs->xstat->port_histogram->src_tcp.count++;
				fs->xstat->port_histogram->dst_tcp.count++;
			} else if ( data_record->prot == IPPROTO_UDP ) {
				fs->xstat->bpp_histogram->udp.bpp[bpp]++;
				fs->xstat->bpp_histogram->udp.count++;

				fs->xstat->port_histogram->src_udp.port[data_record->srcport]++;
				fs->xstat->port_histogram->dst_udp.port[data_record->dstport]++;
				fs->xstat->port_histogram->src_udp.count++;
				fs->xstat->port_histogram->dst_udp.count++;
			}
		}

		if ( verbose ) {
			master_record_t master_record;
			ExpandRecord_v2((common_record_t *)data_record, &(table->extension_info), &(exporter->info), &master_record);
		 	format_file_block_record(&master_record, &string, 0);
			printf("%s\n", string);
		}

		fs->nffile->block_header->size  += data_record->size;
		fs->nffile->block_header->NumRecords++;
		fs->nffile->buff_ptr	= (common_record_t *)((pointer_addr_t)data_record + data_record->size);

		// advance input
		size_left 		   -= table->input_record_size;
		in  	  		   += table->input_record_size;

		// buffer size sanity check
		if ( fs->nffile->block_header->size  > BUFFSIZE ) {
			// should never happen
			syslog(LOG_ERR,"### Software error ###: %s line %d", __FILE__, __LINE__);
			syslog(LOG_ERR,"Process ipfix: Output buffer overflow! Flush buffer and skip records.");
			syslog(LOG_ERR,"Buffer size: %u > %u", fs->nffile->block_header->size, BUFFSIZE);

			// reset buffer
			fs->nffile->block_header->size 		= 0;
			fs->nffile->block_header->NumRecords = 0;
			fs->nffile->buff_ptr = (void *)((pointer_addr_t)fs->nffile->block_header + sizeof(data_block_header_t) );
			return;
		}

	}

} // End of Process_ipfix_data

void Process_IPFIX(void *in_buff, ssize_t in_buff_cnt, FlowSource_t *fs) {
exporter_ipfix_domain_t	*exporter;
ssize_t				size_left;
uint32_t			ExportTime, ObservationDomain, Sequence, flowset_length;
ipfix_header_t		*ipfix_header;
void				*flowset_header;
#ifdef DEVEL
static uint32_t		packet_cntr = 0;
#endif

	size_left 	 = in_buff_cnt;
	if ( size_left < IPFIX_HEADER_LENGTH ) {
		syslog(LOG_ERR, "Process_ipfix: Too little data for ipfix packet: '%lli'", (long long)size_left);
		return;
	}

	ipfix_header = (ipfix_header_t *)in_buff;
	ObservationDomain 	 = ntohl(ipfix_header->ObservationDomain);
	ExportTime 			 = ntohl(ipfix_header->ExportTime);
	Sequence 			 = ntohl(ipfix_header->LastSequence);

	exporter	= GetExporter(fs, ipfix_header);
	if ( !exporter ) {
		syslog(LOG_ERR,"Process_ipfix: Exporter NULL: Abort ipfix record processing");
		return;
	}
	exporter->packets++;
	//exporter->PacketSequence = Sequence;
	flowset_header	= (void *)ipfix_header + IPFIX_HEADER_LENGTH;
	size_left 	   -= IPFIX_HEADER_LENGTH;

	dbg_printf("\n[%u] Next packet: %u, exported: %s, TemplateRecords: %llu, DataRecords: %llu, buffer: %li \n", 
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
			/* maybee to noise onbuggy exporters
			syslog(LOG_ERR, "Process_ipfix [%u] Sequence error: last seq: %u, seq %u\n", 
				info.id, exporter->LastSequence, Sequence);
			*/
		} else {
			dbg_printf("[%u] Sync Sequence: %u\n", exporter->info.id, Sequence);
		}
		exporter->PacketSequence = Sequence;
	} else {
		dbg_printf("[%u] Sequence check ok\n", exporter->info.id);
	}

	// iterate over all set
	flowset_length = 0;
	while (size_left) {
		uint16_t	flowset_id;

		flowset_header = flowset_header + flowset_length;

		flowset_id 		= GET_FLOWSET_ID(flowset_header);
		flowset_length 	= GET_FLOWSET_LENGTH(flowset_header);

		dbg_printf("Process_ipfix: Next flowset %u, length %u.\n", flowset_id, flowset_length);

		if ( flowset_length == 0 ) {
			/* 	this should never happen, as 4 is an empty flowset 
				and smaller is an illegal flowset anyway ...
				if it happends, we can't determine the next flowset, so skip the entire export packet
			 */
			syslog(LOG_ERR,"Process_ipfix: flowset zero length error.");
			dbg_printf("Process_ipfix: flowset zero length error.\n");
			return;

		}

		// possible padding
		if ( flowset_length <= 4 ) {
			size_left = 0;
			continue;
		}

		if ( flowset_length > size_left ) {
			syslog(LOG_ERR,"Process_ipfix: flowset length error. Expected bytes: %u > buffersize: %lli", 
				flowset_length, (long long)size_left);
			size_left = 0;
			continue;
		}


		switch (flowset_id) {
			case IPFIX_TEMPLATE_FLOWSET_ID:
				// Process_ipfix_templates(exporter, flowset_header, fs);
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
					syslog(LOG_ERR,"Process_ipfix: Invalid flowset id: %u. Skip flowset", flowset_id);
				} else {
					input_translation_t *table;
					dbg_printf("Process data flowset, length: %u\n", flowset_length);
					table = GetTranslationTable(exporter, flowset_id);
					if ( table ) {
						Process_ipfix_data(exporter, flowset_header, fs, table);
						exporter->DataRecords++;
					} else if ( HasOptionTable(fs, flowset_id) ) {
						// Process_ipfix_option_data(exporter, flowset_header, fs);
					} else {
						// maybe a flowset with option data
						dbg_printf("Process ipfix: [%u] No table for id %u -> Skip record\n", 
							exporter->info.id, flowset_id);
					}

				}
			}
		} // End of switch

		// next record
		size_left -= flowset_length;

	} // End of while

} // End of Process_IPFIX

