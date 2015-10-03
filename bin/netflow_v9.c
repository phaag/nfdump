/*
 *  Copyright (c) 2014, Peter Haag
 *  Copyright (c) 2009, Peter Haag
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
 *  $Author: haag $
 *
 *  $Id: netflow_v9.c 55 2010-02-02 16:02:58Z haag $
 *
 *  $LastChangedRevision: 55 $
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
#include "netflow_v9.h"

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
#define GET_OPTION_TEMPLATE_OPTION_SCOPE_LENGTH(p)   (Get_val16((void *)((p) + 2)))
#define GET_OPTION_TEMPLATE_OPTION_LENGTH(p)   		 (Get_val16((void *)((p) + 4)))

#include "inline.c"

extern int verbose;
extern extension_descriptor_t extension_descriptor[];
extern uint32_t Max_num_extensions;
extern uint32_t default_sampling;
extern uint32_t overwrite_sampling;

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
#define move96  		8
#define move128 		9
#define move32_sampling 10
#define move64_sampling 11
#define move_mac		12
#define move_mpls 		13
#define move_ulatency	14
#define move_slatency 	15
#define move_user_20	16
#define move_user_65	17
#define TimeMsec 		18
#define PushTimeMsec 	19
#define saveICMP 		20
#define zero8			21
#define zero16			22
#define zero32			23
#define zero64			24
#define zero96			25
#define zero128			26

	uint32_t	id;				// sequence ID as defined above
	uint16_t	input_offset;	// copy/process data at this input offset
	uint16_t	output_offset;	// copy final data to this output offset
	void		*stack;			// optionally copy data onto this stack
} sequence_map_t;


typedef struct input_translation_s {
	struct input_translation_s	*next;
	uint32_t	flags;
	time_t		updated;
	uint32_t	id;
	uint32_t	input_record_size;
	uint32_t	output_record_size;

	// tmp vars needed while processing the data record
	uint32_t	ICMP_offset;			// offset of ICMP type/code in data stream
	uint64_t	flow_start;				// start time in msec
	uint64_t	flow_end;				// end time in msec
	uint64_t    EventTimeMsec;			// Event time in msec for NSEL/NEL
	uint64_t    packets;				// total packets - sampling corrected
	uint64_t    bytes;					// total bytes - sampling corrected
	uint64_t    out_packets;			// total out packets - sampling corrected
	uint64_t    out_bytes;				// total out bytes - sampling corrected
	uint32_t	sampler_offset;
	uint32_t	sampler_size;
	uint32_t	engine_offset;
	uint32_t	received_offset;
	uint32_t	router_ip_offset;

	// extension map infos
	uint32_t	extension_map_changed;		// map changed while refreshing
	extension_info_t 	 extension_info;	// the nfcap extension map, reflecting this template

	// sequence map information
	uint32_t	number_of_sequences;	// number of sequences for the translate 
	sequence_map_t *sequence;			// sequence map

} input_translation_t;

typedef struct exporter_v9_domain_s {
	// identical to generic_exporter_t
	struct exporter_v9_domain_s	*next;

	// generic exporter information
	exporter_info_record_t info;

	uint64_t	packets;			// number of packets sent by this exporter
	uint64_t	flows;				// number of flow records sent by this exporter
	uint32_t	sequence_failure;	// number of sequence failues

	// generic sampler
	generic_sampler_t		*sampler;
	// end of generic_exporter_t

	// exporter parameters
	uint64_t	boot_time;
	// sequence
	int64_t		last_sequence;
	int64_t		sequence;
	int			first;

	// sampling information: 
	// each flow source may have several sampler applied
	// tags #48, #49, #50
	// each sampler is assinged a sampler struct

	// global sampling information #34 #35
	// stored in a sampler with id = -1;

	// translation table
	input_translation_t	*input_translation_table; 
	input_translation_t *current_table;
} exporter_v9_domain_t;


/* module limited globals */
static struct v9_element_map_s {
	uint16_t	id;			// v9 element id 
	char		*name;		// name string
	uint16_t	length;		// type of this element ( input length )
	uint16_t	out_length;	// type of this element ( output length )
	uint32_t	sequence;	// output length
	uint32_t	zero_sequence;	// 
	uint16_t	extension;	// maps into nfdump extension ID
} v9_element_map[] = {
	{0, 0, 0},
	// packets and bytes are always stored in 64bits
	{ NF9_IN_BYTES, 			 "bytes",			_4bytes,  _8bytes, move32_sampling, zero64, COMMON_BLOCK },
	{ NF9_IN_BYTES, 			 "bytes",			_8bytes,  _8bytes, move64_sampling, zero64, COMMON_BLOCK },
	{ NF9_IN_PACKETS, 			 "packets",			_4bytes,  _8bytes, move32_sampling, zero64, COMMON_BLOCK },
	{ NF9_IN_PACKETS, 			 "packets",			_8bytes,  _8bytes, move64_sampling, zero64, COMMON_BLOCK },

	{ NF9_FLOWS_AGGR, 			 "flows",			_4bytes,  _4bytes, move32, zero32, EX_AGGR_FLOWS_4 },
	{ NF9_FLOWS_AGGR, 			 "flows",			_8bytes,  _8bytes, move64, zero64, EX_AGGR_FLOWS_8 },
	{ NF9_IN_PROTOCOL, 		 	 "proto",			_1byte,   _1byte,  move8,  zero8, COMMON_BLOCK },
	{ NF9_SRC_TOS, 		 	 	 "tos",				_1byte,   _1byte,  move8,  zero8, COMMON_BLOCK },
	{ NF9_TCP_FLAGS, 		  	 "flags",			_1byte,   _1byte,  move8,  zero8, COMMON_BLOCK },
	{ NF9_L4_SRC_PORT, 		 	 "src port",		_2bytes,  _2bytes, move16, zero16, COMMON_BLOCK },
	{ NF9_IPV4_SRC_ADDR,		 "V4 src addr",		_4bytes,  _4bytes, move32, zero32, COMMON_BLOCK },
	{ NF9_SRC_MASK, 	 		 "V4 src mask",		_1byte,   _1byte,  move8, zero8, EX_MULIPLE },
	{ NF9_INPUT_SNMP, 			 "input SNMP",		_2bytes,  _2bytes, move16, zero16, EX_IO_SNMP_2 },
	{ NF9_INPUT_SNMP, 			 "input SNMP",		_4bytes,  _4bytes, move32, zero32, EX_IO_SNMP_4 },
	{ NF9_L4_DST_PORT, 		 	 "dst port",		_2bytes,  _2bytes, move16, zero16, COMMON_BLOCK },
	{ NF9_IPV4_DST_ADDR,		 "V4 dst addr",		_4bytes,  _4bytes, move32, zero32, COMMON_BLOCK },
	{ NF9_DST_MASK, 	 		 "V4 dst mask",		_1byte,   _1byte,  move8, zero8, EX_MULIPLE },
	{ NF9_OUTPUT_SNMP, 			 "output SNMP",		_2bytes,  _2bytes, move16, zero16, EX_IO_SNMP_2 },
	{ NF9_OUTPUT_SNMP, 			 "output SNMP",		_4bytes,  _4bytes, move32, zero32, EX_IO_SNMP_4 },
	{ NF9_V4_NEXT_HOP,		 	 "V4 next hop IP",	_4bytes,  _4bytes, move32, zero32, EX_NEXT_HOP_v4 },
	{ NF9_SRC_AS, 			 	 "src AS",			_2bytes,  _2bytes, move16, zero16, EX_AS_2 },
	{ NF9_SRC_AS, 			 	 "src AS",			_4bytes,  _4bytes, move32, zero32, EX_AS_4 },
	{ NF9_DST_AS, 			 	 "dst AS",			_2bytes,  _2bytes, move16, zero16, EX_AS_2 },
	{ NF9_DST_AS, 			 	 "dst AS",			_4bytes,  _4bytes, move32, zero32, EX_AS_4 },
	{ NF9_BGP_V4_NEXT_HOP,		 "V4 BGP next hop",	_4bytes,  _4bytes, move32, zero32, EX_NEXT_HOP_BGP_v4 },
	{ NF9_LAST_SWITCHED, 		 "time sec end",	_4bytes,  _4bytes, move32, zero32, COMMON_BLOCK },
	{ NF9_FIRST_SWITCHED, 		 "time sec create",	_4bytes,  _4bytes, move32, zero32, COMMON_BLOCK },
	{ NF_F_FLOW_CREATE_TIME_MSEC, "time msec start",_8bytes,  _8bytes, TimeMsec, nop, COMMON_BLOCK },
	{ NF_F_FLOW_END_TIME_MSEC, 	"time msec end",	_8bytes,  _8bytes, TimeMsec, nop, COMMON_BLOCK },
	{ NF9_OUT_BYTES, 			 "out bytes",		_4bytes,  _8bytes, move32_sampling, zero64, EX_OUT_BYTES_8 },
	{ NF9_OUT_BYTES, 			 "out bytes",		_8bytes,  _8bytes, move64_sampling, zero64, EX_OUT_BYTES_8 },
	{ NF9_OUT_PKTS, 			 "out packets",		_4bytes,  _8bytes, move32_sampling, zero64, EX_OUT_PKG_8 },
	{ NF9_OUT_PKTS, 			 "out packets",		_8bytes,  _8bytes, move64_sampling, zero64, EX_OUT_PKG_8 },
	{ NF9_IPV6_SRC_ADDR,		 "V6 src addr",		_16bytes, _16bytes, move128, zero128, COMMON_BLOCK },
	{ NF9_IPV6_DST_ADDR,		 "V6 dst addr",		_16bytes, _16bytes, move128, zero128, COMMON_BLOCK },
	{ NF9_IPV6_SRC_MASK, 	 	 "V6 src mask",		_1byte,   _1byte,  move8, zero8, EX_MULIPLE },
	{ NF9_IPV6_DST_MASK, 	 	 "V6 dst mask",		_1byte,   _1byte,  move8, zero8, EX_MULIPLE },
	/* XXX fix */
	{ NF9_IPV6_FLOW_LABEL, 		 "V6 flow label",	_4bytes,  _4bytes, nop, nop, COMMON_BLOCK },

	{ NF9_ICMP_TYPE, 			 "ICMP type",		_2bytes,  _2bytes, nop, nop, COMMON_BLOCK },
	// sampling
	{ NF9_SAMPLING_INTERVAL, 	 "sampling interval",	_4bytes,  _4bytes, move32, zero32, COMMON_BLOCK },
	{ NF9_SAMPLING_ALGORITHM,  	 "sampling algorithm",	_1byte,   _1byte, move8, zero8, COMMON_BLOCK },

	{ NF9_ENGINE_TYPE,  	 	 "engine type",		_1byte,   _1byte, move8, zero8, EX_ROUTER_ID },
	{ NF9_ENGINE_ID,  	 	 	 "engine ID",		_1byte,   _1byte, move8, zero8, EX_ROUTER_ID },

	// sampling
	{ NF9_FLOW_SAMPLER_ID, 	 	 "sampler ID",		_1byte,   _1byte, nop, nop, COMMON_BLOCK },
	{ NF9_FLOW_SAMPLER_ID, 	 	 "sampler ID",		_2bytes,  _2bytes, nop, nop, COMMON_BLOCK },
	{ FLOW_SAMPLER_MODE, 	 	 "sampler mode",	_1byte,   _1byte, nop, nop, COMMON_BLOCK },
	{ NF9_FLOW_SAMPLER_RANDOM_INTERVAL, "sampler rand interval",		_4bytes, _4bytes, nop, nop, COMMON_BLOCK },

	{ NF9_DST_TOS, 		 	 	 "dst tos",			_1byte,   _1byte, move8,  zero8, COMMON_BLOCK },

	{ NF9_IN_SRC_MAC, 			 "in src mac",		_6bytes,  _8bytes, move_mac, zero64, EX_MAC_1},
	{ NF9_OUT_DST_MAC, 	 		 "out dst mac",		_6bytes,  _8bytes, move_mac, zero64, EX_MAC_1},

	{ NF9_SRC_VLAN, 			 "src vlan",		_2bytes,  _2bytes, move16, zero16, EX_VLAN}, 
	{ NF9_DST_VLAN, 			 "dst vlan",		_2bytes,  _2bytes, move16, zero16, EX_VLAN},

	{ NF9_DIRECTION, 	 	 	 "direction",		_1byte,   _1byte,  move8, zero8, EX_MULIPLE },

	{ NF9_V6_NEXT_HOP,			 "V6 next hop IP",	_16bytes, _16bytes, move128, zero128, EX_NEXT_HOP_v6 },
	{ NF9_BPG_V6_NEXT_HOP,	 	 "V6 BGP next hop",	_16bytes, _16bytes, move128, zero128, EX_NEXT_HOP_BGP_v6 },

	// mpls
	{ NF9_MPLS_LABEL_1, 	 	 "mpls label 1",	_3bytes,  _4bytes, move_mpls, zero32, EX_MPLS},
	{ NF9_MPLS_LABEL_2, 	 	 "mpls label 2",	_3bytes,  _4bytes, move_mpls, zero32, EX_MPLS},
	{ NF9_MPLS_LABEL_3, 	 	 "mpls label 3",	_3bytes,  _4bytes, move_mpls, zero32, EX_MPLS},
	{ NF9_MPLS_LABEL_4, 	 	 "mpls label 4",	_3bytes,  _4bytes, move_mpls, zero32, EX_MPLS},
	{ NF9_MPLS_LABEL_5, 	 	 "mpls label 5",	_3bytes,  _4bytes, move_mpls, zero32, EX_MPLS},
	{ NF9_MPLS_LABEL_6, 	 	 "mpls label 6",	_3bytes,  _4bytes, move_mpls, zero32, EX_MPLS},
	{ NF9_MPLS_LABEL_7, 	 	 "mpls label 7",	_3bytes,  _4bytes, move_mpls, zero32, EX_MPLS},
	{ NF9_MPLS_LABEL_8, 	 	 "mpls label 8",	_3bytes,  _4bytes, move_mpls, zero32, EX_MPLS},
	{ NF9_MPLS_LABEL_9, 	 	 "mpls label 9",	_3bytes,  _4bytes, move_mpls, zero32, EX_MPLS},
	{ NF9_MPLS_LABEL_10, 	 	 "mpls label 10",	_3bytes,  _4bytes, move_mpls, zero32, EX_MPLS},

	{ NF9_IN_DST_MAC, 		 	 "in dst mac",		_6bytes,  _8bytes, move_mac, zero64, EX_MAC_2},
	{ NF9_OUT_SRC_MAC, 		 	 "out src mac",		_6bytes,  _8bytes, move_mac, zero64, EX_MAC_2},

	{ NF9_FORWARDING_STATUS, 	 "fwd status",		_1byte,   _1byte, move8, zero8, COMMON_BLOCK },
	{ NF9_BGP_ADJ_NEXT_AS, 	 	 "BGP next AS",		_4bytes,  _4bytes, move32, zero32, EX_BGPADJ },
	{ NF9_BGP_ADJ_PREV_AS, 	 	 "BGP prev AS",		_4bytes,  _4bytes, move32, zero32, EX_BGPADJ },

	// NSEL ASA extension
	// NSEL common
	{ NF_F_EVENT_TIME_MSEC,		"ASA event time",			_8bytes, _8bytes, PushTimeMsec, zero64, EX_NSEL_COMMON },
	{ NF_F_CONN_ID, 	 		"ASA conn ID",				_4bytes, _4bytes, move32, zero32, EX_NSEL_COMMON },
	{ NF_F_FW_EVENT_84, 	 	"ASA 8.4 event",			_1byte,  _1byte,  move8,  zero8,  EX_NSEL_COMMON },
	{ NF_F_FW_EVENT, 		 	"ASA event",				_1byte,  _1byte,  move8,  zero8,  EX_NSEL_COMMON },
	{ NF_F_FW_EXT_EVENT, 		"ASA ext event",			_2bytes, _2bytes, move16, zero16, EX_NSEL_COMMON },
	{ NF_F_ICMP_TYPE, 			"FNF ICMP type",			_1byte, _1byte,  move8,  zero8,  EX_NSEL_COMMON },
	{ NF_F_ICMP_CODE, 			"FNF ICMP code",			_1byte, _1byte,  move8,  zero8,  EX_NSEL_COMMON },
	{ NF_F_ICMP_TYPE_IPV6, 		"ASA ICMP type V6",			_1byte, _1byte,  move8,  zero8,  EX_NSEL_COMMON },
	{ NF_F_ICMP_CODE_IPV6, 		"ASA ICMP code V6",			_1byte, _1byte,  move8,  zero8,  EX_NSEL_COMMON },
	// XlATE extensions
	{ NF_F_XLATE_SRC_ADDR_IPV4, "ASA V4 xsrc addr",			_4bytes,  _4bytes,  move32,  zero32,  EX_NSEL_XLATE_IP_v4 },
	{ NF_F_XLATE_DST_ADDR_IPV4, "ASA V4 xdst addr",			_4bytes,  _4bytes,  move32,  zero32,  EX_NSEL_XLATE_IP_v4 },
	{ NF_F_XLATE_SRC_ADDR_IPV6, "ASA V6 xsrc addr",			_16bytes, _16bytes, move128, zero128, EX_NSEL_XLATE_IP_v6 },
	{ NF_F_XLATE_DST_ADDR_IPV6, "ASA V6 xdst addr",			_16bytes, _16bytes, move128, zero128, EX_NSEL_XLATE_IP_v6 },
	{ NF_F_XLATE_SRC_PORT, 		"ASA xsrc port",			_2bytes,  _2bytes,  move16,  zero16,  EX_NSEL_XLATE_PORTS },
	{ NF_F_XLATE_DST_PORT, 		"ASA xdst port",			_2bytes,  _2bytes,  move16,  zero16,  EX_NSEL_XLATE_PORTS },
	// ASA 8.4 mapping
	{ NF_F_XLATE_SRC_ADDR_84, 	"ASA V4 xsrc addr",			_4bytes,  _4bytes,  move32,  zero32,  EX_NSEL_XLATE_IP_v4 },
	{ NF_F_XLATE_DST_ADDR_84, 	"ASA V4 xdst addr",			_4bytes,  _4bytes,  move32,  zero32,  EX_NSEL_XLATE_IP_v4 },
	{ NF_F_XLATE_SRC_PORT_84, 	"ASA 8.4 xsrc port",		_2bytes,  _2bytes,  move16,  zero16,  EX_NSEL_XLATE_PORTS },
	{ NF_F_XLATE_DST_PORT_84, 	"ASA 8.4 xdst port",		_2bytes,  _2bytes,  move16,  zero16,  EX_NSEL_XLATE_PORTS },
	// ACL extension
	{ NF_F_INGRESS_ACL_ID, 		"ASA ingress ACL",			_12bytes,  _12bytes, move96, zero96, EX_NSEL_ACL },
	{ NF_F_EGRESS_ACL_ID, 		"ASA egress ACL",			_12bytes,  _12bytes, move96, zero96, EX_NSEL_ACL },
	// byte count
	{ NF_F_FLOW_BYTES, 			 "ASA bytes",				_4bytes,  _8bytes, move32_sampling, zero64, EX_NSEL_COMMON },
	{ NF_F_FLOW_BYTES, 			 "ASA bytes",				_8bytes,  _8bytes, move64_sampling, zero64, EX_NSEL_COMMON },
	{ NF_F_FWD_FLOW_DELTA_BYTES, "ASA fwd bytes",			_4bytes,  _8bytes, move32_sampling, zero64, EX_NSEL_COMMON },
	{ NF_F_FWD_FLOW_DELTA_BYTES, "ASA fwd bytes",			_8bytes,  _8bytes, move64_sampling, zero64, EX_NSEL_COMMON },
	{ NF_F_REV_FLOW_DELTA_BYTES,  "ASA rew bytes",			_4bytes,  _4bytes, move32_sampling, zero32, EX_OUT_BYTES_4 },
	{ NF_F_REV_FLOW_DELTA_BYTES,  "ASA rew bytes",			_8bytes,  _8bytes, move64_sampling, zero64, EX_OUT_BYTES_8 },
	// NSEL user names
	{ NF_F_USERNAME, 			 "ASA user name 20",		_20bytes,  _24bytes, move_user_20, zero32, EX_NSEL_USER },
	{ NF_F_USERNAME, 			 "ASA user name 65",		_65bytes,  _72bytes, move_user_65, zero32, EX_NSEL_USER_MAX },

	// NEL CISCO ASR 1000 series NAT logging
	// NEL COMMON extension
	{ NF_N_NAT_EVENT, 		 		"NAT event",			_1byte,  _1byte,  move8,  	zero8,  EX_NEL_COMMON },
	{ NF_N_EGRESS_VRFID, 	 		"NAT egress VRFID",		_4bytes, _4bytes, move32, 	zero32, EX_NEL_COMMON },
	{ NF_N_INGRESS_VRFID, 	 		"NAT ingress VRFID",	_4bytes, _4bytes, move32, 	zero32, EX_NEL_COMMON },

	// NAT Port block allocation
	{ NF_F_XLATE_PORT_BLOCK_START, 	"NAT port block start",	_2bytes, _2bytes, move16, 	zero16, EX_PORT_BLOCK_ALLOC },
	{ NF_F_XLATE_PORT_BLOCK_END, 	"NAT port block end",	_2bytes, _2bytes, move16, 	zero16, EX_PORT_BLOCK_ALLOC },
	{ NF_F_XLATE_PORT_BLOCK_STEP, 	"NAT port step size",	_2bytes, _2bytes, move16, 	zero16, EX_PORT_BLOCK_ALLOC },
	{ NF_F_XLATE_PORT_BLOCK_SIZE, 	"NAT port block size",	_2bytes, _2bytes, move16, 	zero16, EX_PORT_BLOCK_ALLOC },

	// nprobe latency extension
	{ NF9_NPROBE_CLIENT_NW_DELAY_USEC, 	 "NPROBE client lat usec",	_4bytes, _8bytes, move_ulatency, zero64, EX_LATENCY },
	{ NF9_NPROBE_SERVER_NW_DELAY_USEC, 	 "NPROBE server lat usec",	_4bytes, _8bytes, move_ulatency, zero64, EX_LATENCY },
	{ NF9_NPROBE_APPL_LATENCY_USEC, 	 "NPROBE appl lat usec",	_4bytes, _8bytes, move_ulatency, zero64, EX_LATENCY },
	{ NF9_NPROBE_CLIENT_NW_DELAY_SEC, 	 "NPROBE client lat sec",	_4bytes, _8bytes, move_slatency, nop, EX_LATENCY },
	{ NF9_NPROBE_SERVER_NW_DELAY_SEC, 	 "NPROBE server lat sec",	_4bytes, _8bytes, move_slatency, nop, EX_LATENCY },
	{ NF9_NPROBE_APPL_LATENCY_SEC, 	 	 "NPROBE appl lat sec",		_4bytes, _8bytes, move_slatency, nop, EX_LATENCY },

	{0, "NULL",	0, 0}
};

/* 
 * tmp cache while processing template records
 * array index = extension id, 
 * value = 1 -> extension exists, 0 -> extension does not exists
 */

static struct cache_s {
	struct element_param_s {
		uint16_t index;
		uint16_t found;
		uint16_t offset;
		uint16_t length;
	}			*lookup_info;		// 65535 element 16byte to map potentially
									// all possible elements
	uint32_t	max_v9_elements;
	uint32_t	*common_extensions;

} cache;


typedef struct output_templates_s {
	struct output_templates_s 	*next;
	uint32_t			flags;
	extension_map_t		*extension_map;		// extension map;
	time_t				time_sent;
	uint32_t			record_length;		// length of the data record resulting from this template
	uint32_t			flowset_length;		// length of the flowset record
	template_flowset_t *template_flowset;
} output_template_t;

#define MAX_LIFETIME 60

static output_template_t	*output_templates;
static uint64_t	boot_time;	// in msec
static uint16_t				template_id;
static uint32_t				Max_num_v9_tags;
static uint32_t				processed_records;

/* local function prototypes */
static void InsertSamplerOffset( FlowSource_t *fs, uint16_t id, uint16_t offset_sampler_id, uint16_t sampler_id_length, 
	uint16_t offset_sampler_mode, uint16_t offset_sampler_interval);

static void InsertStdSamplerOffset( FlowSource_t *fs, uint16_t id, uint16_t offset_std_sampler_interval, 
	uint16_t offset_std_sampler_algorithm);

static void InsertSampler( FlowSource_t *fs, exporter_v9_domain_t *exporter, int32_t id, uint16_t mode, uint32_t interval);

static inline void Process_v9_templates(exporter_v9_domain_t *exporter, void *template_flowset, FlowSource_t *fs);

static inline void Process_v9_option_templates(exporter_v9_domain_t *exporter, void *option_template_flowset, FlowSource_t *fs);

static inline void Process_v9_data(exporter_v9_domain_t *exporter, void *data_flowset, FlowSource_t *fs, input_translation_t *table );

static inline void Process_v9_option_data(exporter_v9_domain_t *exporter, void *data_flowset, FlowSource_t *fs);

static inline exporter_v9_domain_t *GetExporter(FlowSource_t *fs, uint32_t exporter_id);

static inline input_translation_t *GetTranslationTable(exporter_v9_domain_t *exporter, uint16_t id);

static input_translation_t *setup_translation_table (exporter_v9_domain_t *exporter, uint16_t id, uint16_t input_record_size);

static input_translation_t *add_translation_table(exporter_v9_domain_t *exporter, uint16_t id);

static output_template_t *GetOutputTemplate(uint32_t flags, extension_map_t *extension_map);

static void Append_Record(send_peer_t *peer, master_record_t *master_record);

static uint16_t	Get_val16(void *p);

static uint32_t	Get_val32(void *p);

static uint64_t	Get_val64(void *p);

/* local variables */


// for sending netflow v9
static netflow_v9_header_t	*v9_output_header;

/* functions */

#include "nffile_inline.c"

int Init_v9(void) {
int i;

	output_templates = NULL;

	cache.lookup_info	    = (struct element_param_s *)calloc(65536, sizeof(struct element_param_s));
	cache.common_extensions = (uint32_t *)malloc((Max_num_extensions+1)*sizeof(uint32_t));
	if ( !cache.common_extensions || !cache.lookup_info ) {
		syslog(LOG_ERR, "Process_v9: Panic! malloc(): %s line %d: %s", __FILE__, __LINE__, strerror (errno));
		return 0;
	}

	// init the helper element table
	for (i=1; v9_element_map[i].id != 0; i++ ) {
		uint32_t Type = v9_element_map[i].id;
		// multiple same type - save first index only
		// iterate through same Types afterwards
		if ( cache.lookup_info[Type].index == 0 ) 
			cache.lookup_info[Type].index  = i;
	}
	cache.max_v9_elements = i;

	syslog(LOG_DEBUG,"Init v9: Max number of v9 tags: %u", cache.max_v9_elements);


	return 1;
	
} // End of Init_v9

static inline exporter_v9_domain_t *GetExporter(FlowSource_t *fs, uint32_t exporter_id) {
#define IP_STRING_LEN   40
char ipstr[IP_STRING_LEN];
exporter_v9_domain_t **e = (exporter_v9_domain_t **)&(fs->exporter_data);

	while ( *e ) {
		if ( (*e)->info.id == exporter_id && (*e)->info.version == 9 && 
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
	*e = (exporter_v9_domain_t *)malloc(sizeof(exporter_v9_domain_t));
	if ( !(*e)) {
		syslog(LOG_ERR, "Process_v9: Panic! malloc() %s line %d: %s", __FILE__, __LINE__, strerror (errno));
		return NULL;
	}
	memset((void *)(*e), 0, sizeof(exporter_v9_domain_t));
	(*e)->info.header.type  = ExporterInfoRecordType;
	(*e)->info.header.size  = sizeof(exporter_info_record_t);
	(*e)->info.version 		= 9;
	(*e)->info.id 			= exporter_id;
	(*e)->info.ip			= fs->ip;
	(*e)->info.sa_family	= fs->sa_family;
	(*e)->info.sysid 		= 0;

	(*e)->first	 			= 1;
	(*e)->sequence_failure	= 0;

	(*e)->sampler 	 = NULL;
	(*e)->next	 	 = NULL;

	FlushInfoExporter(fs, &((*e)->info));

	dbg_printf("Process_v9: New exporter: SysID: %u, Domain: %u, IP: %s\n", 
		(*e)->info.sysid, exporter_id, ipstr);
	syslog(LOG_INFO, "Process_v9: New exporter: SysID: %u, Domain: %u, IP: %s\n", 
		(*e)->info.sysid, exporter_id, ipstr);


	return (*e);

} // End of GetExporter

static inline uint32_t MapElement(uint16_t Type, uint16_t Length, uint16_t Offset) {
int	index;

	index = cache.lookup_info[Type].index;
	if ( index )  {
		while ( index && v9_element_map[index].id == Type ) {
			if ( Length == v9_element_map[index].length ) {
				cache.lookup_info[Type].found  = 1;
				cache.lookup_info[Type].offset = Offset;
				cache.lookup_info[Type].length = Length;
				cache.lookup_info[Type].index  = index;
				dbg_printf("found extension %u for type: %u(%s), at index: %i, input length: %u output length: %u Extension: %u, Offset: %u\n", 
					v9_element_map[index].extension, v9_element_map[index].id, v9_element_map[index].name, index,
					v9_element_map[index].length, v9_element_map[index].out_length, v9_element_map[index].extension, Offset);
				return v9_element_map[index].extension;
			} 
			index++;
		}
	}
	dbg_printf("Skip unknown element type: %u, Length: %u\n", 
		Type, Length);

	return 0;

} // End of MapElement

static inline input_translation_t *GetTranslationTable(exporter_v9_domain_t *exporter, uint16_t id) {
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

	dbg_printf("[%u/%u] Get translation table %u: %s\n", 
		exporter->info.id, exporter->info.sysid, id, table == NULL ? "not found" : "found");

	exporter->current_table = table;
	return table;

} // End of GetTranslationTable

static input_translation_t *add_translation_table(exporter_v9_domain_t *exporter, uint16_t id) {
input_translation_t **table;

	table = &(exporter->input_translation_table);
	while ( *table ) {
		table = &((*table)->next);
	}

	// Allocate enough space for all potential v9 tags, which we support in v9_element_map
	// so template refreshing may change the table size without danger of overflowing 
	*table = calloc(1, sizeof(input_translation_t));
	if ( !(*table) ) {
			syslog(LOG_ERR, "Process_v9: Panic! calloc() %s line %d: %s", __FILE__, __LINE__, strerror (errno));
			return NULL;
	}
	(*table)->sequence = calloc(cache.max_v9_elements, sizeof(sequence_map_t));
	if ( !(*table)->sequence ) {
			syslog(LOG_ERR, "Process_v9: Panic! malloc() %s line %d: %s", __FILE__, __LINE__, strerror (errno));
			return NULL;
	}

	(*table)->id   = id;
	(*table)->next = NULL;

	dbg_printf("[%u] Get new translation table %u\n", exporter->info.id, id);

	return *table;

} // End of add_translation_table

static inline void PushSequence(input_translation_t *table, uint16_t Type, uint32_t *offset, void *stack) {
uint32_t i = table->number_of_sequences;
uint32_t index = cache.lookup_info[Type].index;

	if ( table->number_of_sequences >= cache.max_v9_elements ) {
		syslog(LOG_ERR, "Process_v9: Software bug! Sequence table full. at %s line %d", 
			__FILE__, __LINE__);
		dbg_printf("Software bug! Sequence table full. at %s line %d", 
			__FILE__, __LINE__);
		return;
	}

	if ( cache.lookup_info[Type].found ) {
			table->sequence[i].id = v9_element_map[index].sequence;
			table->sequence[i].input_offset  = cache.lookup_info[Type].offset;
			table->sequence[i].output_offset = *offset;
			table->sequence[i].stack = stack;
			dbg_printf("Fill ");
	} else {
			table->sequence[i].id = v9_element_map[index].zero_sequence;
			table->sequence[i].input_offset  = 0;
			table->sequence[i].output_offset = *offset;
			table->sequence[i].stack = NULL;
			dbg_printf("Zero ");
	}
	dbg_printf("Push: sequence: %u, Type: %u, length: %u, out length: %u, id: %u, in offset: %u, out offset: %u\n",
		i, Type, v9_element_map[index].length, v9_element_map[index].out_length, table->sequence[i].id, 
		table->sequence[i].input_offset, table->sequence[i].output_offset);
	table->number_of_sequences++;
	(*offset) += v9_element_map[index].out_length;

} // End of PushSequence


static input_translation_t *setup_translation_table (exporter_v9_domain_t *exporter, uint16_t id, uint16_t input_record_size) {
input_translation_t *table;
extension_map_t 	*extension_map;
uint32_t			i, ipv6, offset, next_extension;
size_t				size_required;

	ipv6 = 0;

	table = GetTranslationTable(exporter, id);
	if ( !table ) {
		syslog(LOG_INFO, "Process_v9: [%u] Add template %u", exporter->info.id, id);
		dbg_printf("[%u] Add template %u\n", exporter->info.id, id);
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
			syslog(LOG_ERR, "Process_v9: Panic! malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror (errno));
			return  NULL;
		}
		extension_map->type 	   = ExtensionMapType;
		// Set size to an empty table - will be updated later
		extension_map->size 	   = sizeof(extension_map_t);
		extension_map->map_id 	   = INIT_ID;
		// packed record size still unknown at this point - will be added later
		extension_map->extension_size = 0;

		table->extension_info.map 	 = extension_map;
		table->extension_map_changed = 1;
#ifdef DEVEL
		if ( !GetTranslationTable(exporter, id) ) {
			printf("*** ERROR failed to crosscheck translation table\n");
		} else {
			printf("table lookup ok!\n");
		}
#endif
 	} else {
		extension_map = table->extension_info.map;

		// reset size/extension size - it's refreshed automatically
		extension_map->size 	   	  = sizeof(extension_map_t);
		extension_map->extension_size = 0;

		dbg_printf("[%u] Refresh template %u\n", exporter->info.id, id);

		// very noisy for some exporters
		dbg_printf("[%u] Refresh template %u\n", exporter->info.id, id);
	}
	// clear current table
	memset((void *)table->sequence, 0, cache.max_v9_elements * sizeof(sequence_map_t));
	table->number_of_sequences = 0;

	table->updated  		= time(NULL);
	table->flags			= 0;
	table->flow_start		= 0;
	table->flow_end			= 0;
	table->EventTimeMsec	= 0;
	table->ICMP_offset		= 0;
	table->sampler_offset 	= 0;
	table->sampler_size		= 0;
	table->engine_offset 	= 0;
	table->received_offset 	= 0;
	table->router_ip_offset = 0;

	dbg_printf("[%u] Fill translation table %u\n", exporter->info.id, id);

	// fill table
	table->id 			= id;

	/* 
	 * common data block: The common record is expected in the output stream. If not available
	 * in the template, fill values with 0
	 */

	// All required extensions
	offset = BYTE_OFFSET_first;
	if ( cache.lookup_info[NF_F_FLOW_CREATE_TIME_MSEC].found ) {
		uint32_t _tmp = 0;
		PushSequence( table, NF_F_FLOW_CREATE_TIME_MSEC, &_tmp, &table->flow_start);
		dbg_printf("Push NF_F_FLOW_CREATE_TIME_MSEC\n");
	}
	if ( cache.lookup_info[NF_F_FLOW_END_TIME_MSEC].found ) {
		uint32_t _tmp = 0;
		PushSequence( table, NF_F_FLOW_END_TIME_MSEC, &_tmp, &table->flow_end);
		dbg_printf("Push NF_F_FLOW_END_TIME_MSEC\n");
	}

	PushSequence( table, NF9_FIRST_SWITCHED, &offset, NULL);
	offset = BYTE_OFFSET_first + 4;
	PushSequence( table, NF9_LAST_SWITCHED, &offset, NULL);
	offset = BYTE_OFFSET_first + 8;
	PushSequence( table, NF9_FORWARDING_STATUS, &offset, NULL);

	PushSequence( table, NF9_TCP_FLAGS, &offset, NULL);
	PushSequence( table, NF9_IN_PROTOCOL, &offset, NULL);
	PushSequence( table, NF9_SRC_TOS, &offset, NULL);

	PushSequence( table, NF9_L4_SRC_PORT, &offset, NULL);
	PushSequence( table, NF9_L4_DST_PORT, &offset, NULL);

	// skip exporter_sysid and reserved
	offset += 4;

	/* IP addresss record
	 * This record is expected in the output stream. If not available
	 * in the template, assume empty v4 address.
	 */
	if ( cache.lookup_info[NF9_IPV4_SRC_ADDR].found ) {
		// IPv4 addresses 
		PushSequence( table, NF9_IPV4_SRC_ADDR, &offset, NULL);
		PushSequence( table, NF9_IPV4_DST_ADDR, &offset, NULL);
	} else if ( cache.lookup_info[NF9_IPV6_SRC_ADDR].found ) {
		// IPv6 addresses 
		PushSequence( table, NF9_IPV6_SRC_ADDR, &offset, NULL);
		PushSequence( table, NF9_IPV6_DST_ADDR, &offset, NULL);
		// mark IPv6 
		SetFlag(table->flags, FLAG_IPV6_ADDR);
		ipv6 = 1;
	} else {
		// should not happen, assume empty IPv4 addresses
		PushSequence( table, NF9_IPV4_SRC_ADDR, &offset, NULL);
		PushSequence( table, NF9_IPV4_DST_ADDR, &offset, NULL);
	}

	/* packet counter
	 * This record is expected in the output stream. If not available
	 * in the template, assume empty 4 bytes value
	 */
	PushSequence( table, NF9_IN_PACKETS, &offset, &table->packets);
	// fix: always have 64bit counters due to possible sampling
	SetFlag(table->flags, FLAG_PKG_64);

	if ( cache.lookup_info[NF_F_FLOW_BYTES].found ) {
		// NSEL ASA bytes
		PushSequence( table, NF_F_FLOW_BYTES, &offset, &table->bytes);
	} else if ( cache.lookup_info[NF_F_FWD_FLOW_DELTA_BYTES].found ) {
		// NSEL ASA 8.4 bytes
		PushSequence( table, NF_F_FWD_FLOW_DELTA_BYTES, &offset, &table->bytes);
	} else {
		PushSequence( table, NF9_IN_BYTES, &offset, &table->bytes);
	}
	// fix: always have 64bit counters due to possible sampling
	SetFlag(table->flags, FLAG_BYTES_64);

#if defined NSEL || defined NEL
	if ( cache.lookup_info[NF_F_FW_EVENT].found || cache.lookup_info[NF_F_FW_EVENT_84].found || 
		 cache.lookup_info[NF_N_NAT_EVENT].found) {
		SetFlag(table->flags, FLAG_EVENT);
	}
#endif

	// Optional extensions
	next_extension = 0;
	for (i=4; i <= Max_num_extensions; i++ ) {
		uint32_t map_index = i;

		if ( cache.common_extensions[i] == 0 )
			continue;

		switch(i) {
			case EX_IO_SNMP_2:
				PushSequence( table, NF9_INPUT_SNMP, &offset, NULL);
				PushSequence( table, NF9_OUTPUT_SNMP, &offset, NULL);
				break;
			case EX_IO_SNMP_4:
				PushSequence( table, NF9_INPUT_SNMP, &offset, NULL);
				PushSequence( table, NF9_OUTPUT_SNMP, &offset, NULL);
				break;
			case EX_AS_2:
				PushSequence( table, NF9_SRC_AS, &offset, NULL);
				PushSequence( table, NF9_DST_AS, &offset, NULL);
				break;
			case EX_AS_4:
				PushSequence( table, NF9_SRC_AS, &offset, NULL);
				PushSequence( table, NF9_DST_AS, &offset, NULL);
				break;
			case EX_MULIPLE:
				PushSequence( table, NF9_DST_TOS, &offset, NULL);
				PushSequence( table, NF9_DIRECTION, &offset, NULL);
				if ( ipv6 ) {
					// IPv6
					PushSequence( table, NF9_IPV6_SRC_MASK, &offset, NULL);
					PushSequence( table, NF9_IPV6_DST_MASK, &offset, NULL);
				} else {
					// IPv4
					PushSequence( table, NF9_SRC_MASK, &offset, NULL);
					PushSequence( table, NF9_DST_MASK, &offset, NULL);
				}
				break;
			case EX_NEXT_HOP_v4:
				PushSequence( table, NF9_V4_NEXT_HOP, &offset, NULL);
				break;
			case EX_NEXT_HOP_v6:
				PushSequence( table, NF9_V6_NEXT_HOP, &offset, NULL);
				SetFlag(table->flags, FLAG_IPV6_NH);
				break;
			case EX_NEXT_HOP_BGP_v4:
				PushSequence( table, NF9_BGP_V4_NEXT_HOP, &offset, NULL);
				break;
			case EX_NEXT_HOP_BGP_v6:
				PushSequence( table, NF9_BPG_V6_NEXT_HOP, &offset, NULL);
				SetFlag(table->flags, FLAG_IPV6_NHB);
				break;
			case EX_VLAN:
				PushSequence( table, NF9_SRC_VLAN, &offset, NULL);
				PushSequence( table, NF9_DST_VLAN, &offset, NULL);
				break;
			case EX_OUT_PKG_4:
				PushSequence( table, NF9_OUT_PKTS, &offset, &table->out_packets);
				break;
			case EX_OUT_PKG_8:
				PushSequence( table, NF9_OUT_PKTS, &offset, &table->out_packets);
				break;
			case EX_OUT_BYTES_4:
				if ( cache.lookup_info[NF_F_REV_FLOW_DELTA_BYTES].found ) {
					PushSequence( table, NF_F_REV_FLOW_DELTA_BYTES, &offset, &table->out_bytes);
				} else {
					PushSequence( table, NF9_OUT_BYTES, &offset, &table->out_bytes);
				}
				break;
			case EX_OUT_BYTES_8:
				if ( cache.lookup_info[NF_F_REV_FLOW_DELTA_BYTES].found ) {
					PushSequence( table, NF_F_REV_FLOW_DELTA_BYTES, &offset, &table->out_bytes);
				} else {
					PushSequence( table, NF9_OUT_BYTES, &offset, &table->out_bytes);
				}
				break;
			case EX_AGGR_FLOWS_4:
				PushSequence( table, NF9_FLOWS_AGGR, &offset, NULL);
				break;
			case EX_AGGR_FLOWS_8:
				PushSequence( table, NF9_FLOWS_AGGR, &offset, NULL);
				break;
			case EX_MAC_1:
				PushSequence( table, NF9_IN_SRC_MAC, &offset, NULL);
				PushSequence( table, NF9_OUT_DST_MAC, &offset, NULL);
				break;
			case EX_MAC_2:
				PushSequence( table, NF9_IN_DST_MAC, &offset, NULL);
				PushSequence( table, NF9_OUT_SRC_MAC, &offset, NULL);
				break;
			case EX_MPLS:
				PushSequence( table, NF9_MPLS_LABEL_1, &offset, NULL);
				PushSequence( table, NF9_MPLS_LABEL_2, &offset, NULL);
				PushSequence( table, NF9_MPLS_LABEL_3, &offset, NULL);
				PushSequence( table, NF9_MPLS_LABEL_4, &offset, NULL);
				PushSequence( table, NF9_MPLS_LABEL_5, &offset, NULL);
				PushSequence( table, NF9_MPLS_LABEL_6, &offset, NULL);
				PushSequence( table, NF9_MPLS_LABEL_7, &offset, NULL);
				PushSequence( table, NF9_MPLS_LABEL_8, &offset, NULL);
				PushSequence( table, NF9_MPLS_LABEL_9, &offset, NULL);
				PushSequence( table, NF9_MPLS_LABEL_10, &offset, NULL);
				break;
			case EX_ROUTER_IP_v4:
			case EX_ROUTER_IP_v6:
				if ( exporter->info.sa_family == PF_INET6 ) {
					table->router_ip_offset = offset;
					dbg_printf("Router IPv6: Offset: %u, olen: %u\n", offset, 16 );
					// not an entry for the translateion table.
					// but reserve space in the output record for IPv6
					offset			 	   += 16;
					SetFlag(table->flags, FLAG_IPV6_EXP);
					map_index = EX_ROUTER_IP_v6;
				} else {
					table->router_ip_offset = offset;
					dbg_printf("Router IPv4: Offset: %u, olen: %u\n", offset, 4 );
					// not an entry for the translateion table.
					// but reserve space in the output record for IPv4
					offset				   += 4;
					ClearFlag(table->flags, FLAG_IPV6_EXP);
					map_index = EX_ROUTER_IP_v4;
				}
				break;
			case EX_ROUTER_ID:
				table->engine_offset = offset;
				dbg_printf("Engine offset: %u\n", offset);
				offset += 2;
				dbg_printf("Skip 2 unused bytes. Next offset: %u\n", offset);
				PushSequence( table, NF9_ENGINE_TYPE, &offset, NULL);
				PushSequence( table, NF9_ENGINE_ID, &offset, NULL);
				// unused fill element for 32bit alignment
				break;
			case EX_RECEIVED:
				table->received_offset = offset;
				dbg_printf("Received offset: %u\n", offset);
				offset				   += 8;
				break;
			case EX_LATENCY: {
				// it's bit of a hack, but .. sigh ..
				uint32_t i = table->number_of_sequences;

				// Insert a zero64 as subsequent sequences add values
				table->sequence[i].id = zero64;
				table->sequence[i].input_offset  = 0;
				table->sequence[i].output_offset = offset;
				table->sequence[i].stack = NULL;
				table->number_of_sequences++;
				dbg_printf("Zero latency at offset: %u\n", offset);

				PushSequence( table, NF9_NPROBE_CLIENT_NW_DELAY_SEC, &offset, NULL);
				offset -= 8;
				PushSequence( table, NF9_NPROBE_CLIENT_NW_DELAY_USEC, &offset, NULL);

				table->sequence[i].id = zero64;
				table->sequence[i].input_offset  = 0;
				table->sequence[i].output_offset = offset;
				table->sequence[i].stack = NULL;
				table->number_of_sequences++;
				dbg_printf("Zero latency at offset: %u\n", offset);

				PushSequence( table, NF9_NPROBE_SERVER_NW_DELAY_SEC, &offset, NULL);
				offset -= 8;
				PushSequence( table, NF9_NPROBE_SERVER_NW_DELAY_USEC, &offset, NULL);

				table->sequence[i].id = zero64;
				table->sequence[i].input_offset  = 0;
				table->sequence[i].output_offset = offset;
				table->sequence[i].stack = NULL;
				table->number_of_sequences++;
				dbg_printf("Zero latency at offset: %u\n", offset);

				PushSequence( table, NF9_NPROBE_APPL_LATENCY_SEC, &offset, NULL);
				offset -= 8;
				PushSequence( table, NF9_NPROBE_APPL_LATENCY_USEC, &offset, NULL);

				} break;
			case EX_BGPADJ:
				PushSequence( table, NF9_BGP_ADJ_NEXT_AS, &offset, NULL);
				PushSequence( table, NF9_BGP_ADJ_PREV_AS, &offset, NULL);
				break;
			case EX_NSEL_COMMON:
				PushSequence( table, NF_F_EVENT_TIME_MSEC, &offset, &table->EventTimeMsec);
				PushSequence( table, NF_F_CONN_ID, &offset, NULL);
				if ( ipv6 ) {
#ifdef WORDS_BIGENDIAN
					PushSequence( table, NF_F_ICMP_TYPE_IPV6, &offset, NULL);
					PushSequence( table, NF_F_ICMP_CODE_IPV6, &offset, NULL);
#else
					PushSequence( table, NF_F_ICMP_CODE_IPV6, &offset, NULL);
					PushSequence( table, NF_F_ICMP_TYPE_IPV6, &offset, NULL);
#endif
				} else {
#ifdef WORDS_BIGENDIAN
					PushSequence( table, NF_F_ICMP_TYPE, &offset, NULL);
					PushSequence( table, NF_F_ICMP_CODE, &offset, NULL);
#else
					PushSequence( table, NF_F_ICMP_CODE, &offset, NULL);
					PushSequence( table, NF_F_ICMP_TYPE, &offset, NULL);
#endif
				}
				cache.lookup_info[NF_F_FW_EVENT_84].found ?
					PushSequence( table, NF_F_FW_EVENT_84, &offset, NULL) :
					PushSequence( table, NF_F_FW_EVENT, &offset, NULL);
				offset += 1;
				PushSequence( table, NF_F_FW_EXT_EVENT, &offset, NULL);
				offset += 2;
				break;
			case EX_NSEL_XLATE_PORTS:
				if ( cache.lookup_info[NF_F_XLATE_SRC_ADDR_84].found ) {
					PushSequence( table, NF_F_XLATE_SRC_PORT_84, &offset, NULL);
					PushSequence( table, NF_F_XLATE_DST_PORT_84, &offset, NULL);
				} else {
					PushSequence( table, NF_F_XLATE_SRC_PORT, &offset, NULL);
					PushSequence( table, NF_F_XLATE_DST_PORT, &offset, NULL);
				}
				break;
			case EX_NSEL_XLATE_IP_v4:
				if ( cache.lookup_info[NF_F_XLATE_SRC_ADDR_84].found ) {
					PushSequence( table, NF_F_XLATE_SRC_ADDR_84, &offset, NULL);
					PushSequence( table, NF_F_XLATE_DST_ADDR_84, &offset, NULL);
				} else {
					PushSequence( table, NF_F_XLATE_SRC_ADDR_IPV4, &offset, NULL);
					PushSequence( table, NF_F_XLATE_DST_ADDR_IPV4, &offset, NULL);
				}
				break;
			case EX_NSEL_XLATE_IP_v6:
				PushSequence( table, NF_F_XLATE_SRC_ADDR_IPV6, &offset, NULL);
				PushSequence( table, NF_F_XLATE_DST_ADDR_IPV6, &offset, NULL);
				break;
			case EX_NSEL_ACL:
				PushSequence( table, NF_F_INGRESS_ACL_ID, &offset, NULL);
				PushSequence( table, NF_F_EGRESS_ACL_ID, &offset, NULL);
				break;
			case EX_NSEL_USER:
			case EX_NSEL_USER_MAX:
				PushSequence( table, NF_F_USERNAME, &offset, NULL);
				break;
			case EX_NEL_COMMON:
				PushSequence( table, NF_N_NAT_EVENT, &offset, NULL);
				offset += 3;
				PushSequence( table, NF_N_EGRESS_VRFID, &offset, NULL);
				PushSequence( table, NF_N_INGRESS_VRFID, &offset, NULL);
				break;
			case EX_PORT_BLOCK_ALLOC:
				PushSequence( table, NF_F_XLATE_PORT_BLOCK_START, &offset, NULL);
				PushSequence( table, NF_F_XLATE_PORT_BLOCK_END, &offset, NULL);
				PushSequence( table, NF_F_XLATE_PORT_BLOCK_STEP, &offset, NULL);
				PushSequence( table, NF_F_XLATE_PORT_BLOCK_SIZE, &offset, NULL);
				break;
			case EX_NEL_GLOBAL_IP_v4:
				// XXX no longer used
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

	/* ICMP hack for v9  */
	// for netflow historical reason, ICMP type/code goes into dst port field
	// remember offset, for decoding
	if ( cache.lookup_info[NF9_ICMP_TYPE].found && cache.lookup_info[NF9_ICMP_TYPE].length == 2 ) {
		table->ICMP_offset = cache.lookup_info[NF9_ICMP_TYPE].offset;
	} 

	/* Sampler ID */
	if ( cache.lookup_info[NF9_FLOW_SAMPLER_ID].found ) {
		if ( cache.lookup_info[NF9_FLOW_SAMPLER_ID].length == 1 ) {
			table->sampler_offset = cache.lookup_info[NF9_FLOW_SAMPLER_ID].offset;
			table->sampler_size = 1;
			dbg_printf("1 byte Sampling ID included at offset %u\n", table->sampler_offset);
		} else if ( cache.lookup_info[NF9_FLOW_SAMPLER_ID].length == 2 ) {
			table->sampler_offset = cache.lookup_info[NF9_FLOW_SAMPLER_ID].offset;
			table->sampler_size = 2;
			dbg_printf("2 byte Sampling ID included at offset %u\n", table->sampler_offset);
		}  else {
			syslog(LOG_ERR, "Process_v9: Unexpected SAMPLER ID field length: %d", 
				cache.lookup_info[NF9_FLOW_SAMPLER_ID].length);
			dbg_printf("Unexpected SAMPLER ID field length: %d", 
				cache.lookup_info[NF9_FLOW_SAMPLER_ID].length);

		}
	} else {
		dbg_printf("No Sampling ID found\n");
	}

#ifdef DEVEL
	if ( table->extension_map_changed ) {
		printf("Extension Map id=%u changed!\n", extension_map->map_id);
	} else {
		printf("[%u] template %u unchanged\n", exporter->info.id, id);
	}

	printf("Process_v9: Check extension map: id: %d, size: %u, extension_size: %u\n", 
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

static void InsertSamplerOffset( FlowSource_t *fs, uint16_t id, uint16_t offset_sampler_id, uint16_t sampler_id_length,
	uint16_t offset_sampler_mode, uint16_t offset_sampler_interval) {
option_offset_t	**t;

	t = &(fs->option_offset_table);
	while ( *t ) {
		if ( (*t)->id == id ) { // table already known to us - update data
			dbg_printf("Found existing sampling info in template %i\n", id);
			break;
		}
	
		t = &((*t)->next);
	}

	if ( *t == NULL ) {	// new table
		dbg_printf("Allocate new sampling info from template %i\n", id);
		*t = (option_offset_t *)calloc(1, sizeof(option_offset_t));
		if ( !*t ) {
			fprintf(stderr, "malloc() allocation error: %s\n", strerror(errno));
			return ;
		} 
		dbg_printf("Process_v9: New sampler: ID %i, mode: %i, interval: %i\n", 
			offset_sampler_id, offset_sampler_mode, offset_sampler_interval);
	}	// else existing table

	dbg_printf("Insert/Update sampling info from template %i\n", id);
	SetFlag((*t)->flags, HAS_SAMPLER_DATA);
	(*t)->id 				= id;
	(*t)->offset_id			= offset_sampler_id;
	(*t)->sampler_id_length = sampler_id_length;
	(*t)->offset_mode		= offset_sampler_mode;
	(*t)->offset_interval	= offset_sampler_interval;

} // End of InsertSamplerOffset

static void InsertStdSamplerOffset( FlowSource_t *fs, uint16_t id, uint16_t offset_std_sampler_interval, uint16_t offset_std_sampler_algorithm) {
option_offset_t	**t;

	t = &(fs->option_offset_table);
	while ( *t ) {
		if ( (*t)->id == id ) { // table already known to us - update data
			dbg_printf("Found existing std sampling info in template %i\n", id);
			break;
		}
	
		t = &((*t)->next);
	}

	if ( *t == NULL ) {	// new table
		dbg_printf("Allocate new std sampling info from template %i\n", id);
		*t = (option_offset_t *)calloc(1, sizeof(option_offset_t));
		if ( !*t ) {
			fprintf(stderr, "malloc() allocation error: %s\n", strerror(errno));
			return ;
		} 
		syslog(LOG_ERR, "Process_v9: New std sampler: interval: %i, algorithm: %i", 
			offset_std_sampler_interval, offset_std_sampler_algorithm);
	}	// else existing table

	dbg_printf("Insert/Update sampling info from template %i\n", id);
	SetFlag((*t)->flags, HAS_STD_SAMPLER_DATA);
	(*t)->id 				= id;
	(*t)->offset_id			= 0;
	(*t)->offset_mode		= 0;
	(*t)->offset_interval	= 0;
	(*t)->offset_std_sampler_interval	= offset_std_sampler_interval;
	(*t)->offset_std_sampler_algorithm	= offset_std_sampler_algorithm;
	
} // End of InsertStdSamplerOffset

static inline void Process_v9_templates(exporter_v9_domain_t *exporter, void *template_flowset, FlowSource_t *fs) {
void				*template;
input_translation_t *translation_table;
uint16_t	id, count, Offset;
uint32_t	size_left, size_required, num_extensions, num_v9tags;
int			i;

	size_left = GET_FLOWSET_LENGTH(template_flowset) - 4; // -4 for flowset header -> id and length
	template  = template_flowset + 4;					  // the template description begins at offset 4

	// process all templates in flowset, as long as any bytes are left
	size_required = 0;
	Offset 		  = 0;
	while (size_left) {
		void *p;
		template = template + size_required;

		// clear helper tables
		memset((void *)cache.common_extensions, 0,  (Max_num_extensions+1)*sizeof(uint32_t));
		memset((void *)cache.lookup_info, 0, 65536 * sizeof(struct element_param_s));
		for (i=1; v9_element_map[i].id != 0; i++ ) {
			uint32_t Type = v9_element_map[i].id;
			if ( v9_element_map[i].id == v9_element_map[i-1].id )
				continue;
			cache.lookup_info[Type].index  = i;
			// other elements cleard be memset
		}

		id 	  = GET_TEMPLATE_ID(template);
		count = GET_TEMPLATE_COUNT(template);
		size_required = 4 + 4 * count;	// id + count = 4 bytes, and 2 x 2 bytes for each entry

		dbg_printf("\n[%u] Template ID: %u\n", exporter->info.id, id);
		dbg_printf("template size: %u buffersize: %u\n", size_required, size_left);

		if ( size_left < size_required ) {
			syslog(LOG_ERR, "Process_v9: [%u] buffer size error: expected %u available %u", 
				exporter->info.id, size_required, size_left);
			size_left = 0;
			continue;
		}

		Offset = 0;
		num_extensions = 0;		// number of extensions
		num_v9tags = 0;			// number of optional v9 tags 

		p = template + 4;		// type/length pairs start at template offset 4
		for(i=0; i<count; i++ ) {
			uint16_t Type, Length;
			uint32_t ext_id;

			Type   = Get_val16(p); p = p + 2;
			Length = Get_val16(p); p = p + 2;
			num_v9tags++;

			// map v9 tag to extension id - if != 0 then when we support it.
			ext_id = MapElement(Type, Length, Offset);

			// do we store this extension? enabled != 0
			// more than 1 v9 tag may map to an extension - so count this extension once only
			if ( ext_id && extension_descriptor[ext_id].enabled ) {
				if ( cache.common_extensions[ext_id] == 0 ) {
					cache.common_extensions[ext_id] = 1;
					dbg_printf("Enable extension: %2i: %s\n", ext_id, extension_descriptor[ext_id].description);
					num_extensions++;
				}
			} 
			Offset += Length;
		}

		// as the router IP address extension is not part announced in a template, we need to deal with it here
		if ( extension_descriptor[EX_ROUTER_IP_v4].enabled ) {
			if ( cache.common_extensions[EX_ROUTER_IP_v4] == 0 ) {
				cache.common_extensions[EX_ROUTER_IP_v4] = 1;
				num_extensions++;
			}
			dbg_printf("Add sending router IP address (%s) => Extension: %u\n", 
				fs->sa_family == PF_INET6 ? "ipv6" : "ipv4", EX_ROUTER_IP_v4);
		}
	
		// as the router IP address extension is not part announced in a template, we need to deal with it here
		if ( extension_descriptor[EX_ROUTER_ID].enabled ) {
			if ( cache.common_extensions[EX_ROUTER_ID] == 0 ) {
				cache.common_extensions[EX_ROUTER_ID] = 1;
				num_extensions++;
			}
			dbg_printf("Force add router ID (engine type/ID), Extension: %u\n", EX_ROUTER_ID);
		}

		// as the received time is not announced in a template, we need to deal with it here
		if ( extension_descriptor[EX_RECEIVED].enabled ) {
			if ( cache.common_extensions[EX_RECEIVED] == 0 ) {
				cache.common_extensions[EX_RECEIVED] = 1;
				num_extensions++;
			}
			dbg_printf("Force add packet received time, Extension: %u\n", EX_RECEIVED);
		}
	
		dbg_printf("Parsed %u v9 tags, total %u extensions\n", num_v9tags, num_extensions);


#ifdef DEVEL
		{
			int i;
			for (i=0; i<=Max_num_extensions; i++ ) {
				if ( cache.common_extensions[i] ) {
					printf("Enabled extension: %2i: %s\n", i, extension_descriptor[i].description);
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
		size_left -= size_required;
		processed_records++;

		dbg_printf("\n");

	} // End of while size_left

} // End of Process_v9_templates

static inline void Process_v9_option_templates(exporter_v9_domain_t *exporter, void *option_template_flowset, FlowSource_t *fs) {
void		*option_template, *p;
uint32_t	size_left, nr_scopes, nr_options, i;
uint16_t	id, scope_length, option_length, offset, sampler_id_length;
uint16_t	offset_sampler_id, offset_sampler_mode, offset_sampler_interval, found_sampler;
uint16_t	offset_std_sampler_interval, offset_std_sampler_algorithm, found_std_sampling;

	i = 0;	// keep compiler happy
	size_left 		= GET_FLOWSET_LENGTH(option_template_flowset) - 4; // -4 for flowset header -> id and length
	option_template = option_template_flowset + 4;
	id 	  			= GET_OPTION_TEMPLATE_ID(option_template); 
	scope_length 	= GET_OPTION_TEMPLATE_OPTION_SCOPE_LENGTH(option_template);
	option_length 	= GET_OPTION_TEMPLATE_OPTION_LENGTH(option_template);

	if ( scope_length & 0x3 ) {
		syslog(LOG_ERR, "Process_v9: [%u] scope length error: length %u not multiple of 4", 
			exporter->info.id, scope_length);
		return;
	}

	if ( option_length & 0x3 ) {
		syslog(LOG_ERR, "Process_v9: [%u] option length error: length %u not multiple of 4", 
			exporter->info.id, option_length);
		return;
	}

	if ( (scope_length + option_length) > size_left ) {
		syslog(LOG_ERR, "Process_v9: [%u] option template length error: size left %u too small for %u scopes length and %u options length", 
			exporter->info.id, size_left, scope_length, option_length);
		return;
	}

	nr_scopes  = scope_length >> 2;
	nr_options = option_length >> 2;

	dbg_printf("\n[%u] Option Template ID: %u\n", exporter->info.id, id);
	dbg_printf("Scope length: %u Option length: %u\n", scope_length, option_length);

	sampler_id_length			 = 0;
	offset_sampler_id 			 = 0;
	offset_sampler_mode 		 = 0;
	offset_sampler_interval 	 = 0;
	offset_std_sampler_interval  = 0;
	offset_std_sampler_algorithm = 0;
	found_sampler				 = 0;
	found_std_sampling			 = 0;
	offset = 0;

	p = option_template + 6;	// start of length/type data
	for ( i=0; i<nr_scopes; i++ ) {
#ifdef DEVEL
		uint16_t type 	= Get_val16(p);
#endif
		p = p + 2;

		uint16_t length = Get_val16(p); p = p + 2;
		offset += length;
		dbg_printf("Scope field Type: %u, length %u\n", type, length);
	}

	for ( ; i<(nr_scopes+nr_options); i++ ) {
		uint16_t type 	= Get_val16(p); p = p + 2;
		uint16_t length = Get_val16(p); p = p + 2;
		uint32_t index  = cache.lookup_info[type].index;
		dbg_printf("Option field Type: %u, length %u\n", type, length);
		if ( !index ) {
			dbg_printf("Unsupported: Option field Type: %u, length %u\n", type, length);
			continue;
		}
		while ( index && v9_element_map[index].id == type ) {
			if ( length == v9_element_map[index].length ) {
				break;
			}
			index++;
		}

		if ( index && v9_element_map[index].length != length ) {
			syslog(LOG_ERR,"Process_v9: Option field Type: %u, length %u not supported\n", type, length);
			dbg_printf("Process_v9: Option field Type: %u, length %u not supported\n", type, length);
			continue;
		}
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
	}

	if ( found_sampler == 3 ) { // need all three tags
		dbg_printf("[%u] Sampling information found\n", exporter->info.id);
		InsertSamplerOffset(fs, id, offset_sampler_id, sampler_id_length, offset_sampler_mode, offset_sampler_interval);
	} else if ( found_std_sampling == 2 ) { // need all two tags
		dbg_printf("[%u] Std sampling information found\n", exporter->info.id);
		InsertStdSamplerOffset(fs, id, offset_std_sampler_interval, offset_std_sampler_algorithm);
	} else {
		dbg_printf("[%u] No Sampling information found\n", exporter->info.id);
	}
	dbg_printf("\n");
	processed_records++;

} // End of Process_v9_option_templates


static inline void Process_v9_data(exporter_v9_domain_t *exporter, void *data_flowset, FlowSource_t *fs, input_translation_t *table ){
uint64_t			start_time, end_time, sampling_rate;
uint32_t			size_left;
uint8_t				*in, *out;
int					i;
char				*string;

	size_left = GET_FLOWSET_LENGTH(data_flowset) - 4; // -4 for data flowset header -> id and length

	// map input buffer as a byte array
	in  	  = (uint8_t *)(data_flowset + 4);	// skip flowset header

	dbg_printf("[%u] Process data flowset size: %u\n", exporter->info.id, size_left);

	if ( table->sampler_offset ) 
		dbg_printf("table sampler offset: %u\n", table->sampler_offset);
	dbg_printf("[%u] Exporter is 0x%llu\n", exporter->info.id, (long long unsigned)exporter);
	dbg_printf("[%u] Exporter has sampler: %s\n", exporter->info.id, exporter->sampler ? "yes" : "no");

	// Check if sampling is announced
	if ( table->sampler_offset && exporter->sampler  ) {
		generic_sampler_t *sampler = exporter->sampler;
		uint32_t sampler_id;
		if ( table->sampler_size == 2 ) {
			sampler_id = Get_val16((void *)&in[table->sampler_offset]);
		} else {
			sampler_id = in[table->sampler_offset];
		}
		dbg_printf("Extract sampler: %u\n", sampler_id);
		// usually not that many samplers, so following a chain is not too expensive.
		while ( sampler && sampler->info.id != sampler_id ) 
			sampler = sampler->next;

		if ( sampler ) {
			sampling_rate = sampler->info.interval;
			dbg_printf("[%u] Sampling ID %u available\n", exporter->info.id, sampler_id);
			dbg_printf("[%u] Sampler_offset : %u\n", exporter->info.id, table->sampler_offset);
			dbg_printf("[%u] Sampler Data : %s\n", exporter->info.id, exporter->sampler == NULL ? "not available" : "available");
			dbg_printf("[%u] Sampling rate: %llu\n", exporter->info.id, (long long unsigned)sampling_rate);
		} else {
			sampling_rate = default_sampling;
			dbg_printf("[%u] Sampling ID %u not (yet) available\n", exporter->info.id, sampler_id);
		}

	} else {
		generic_sampler_t *sampler = exporter->sampler;
		while ( sampler && sampler->info.id != -1 ) 
			sampler = sampler->next;

		if ( sampler ) {
			sampling_rate = sampler->info.interval;
			dbg_printf("[%u] Std sampling available for this flow source: Rate: %llu\n", exporter->info.id, (long long unsigned)sampling_rate);
		} else {
			sampling_rate = default_sampling;
			dbg_printf("[%u] No Sampling record found\n", exporter->info.id);
		}
	}

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
				syslog(LOG_WARNING,"Process_v9: Corrupt data flowset? Pad bytes: %u", size_left);
				dbg_printf("Process_v9: Corrupt data flowset? Pad bytes: %u, table record_size: %u\n", 
					size_left, table->input_record_size);
			}
			size_left = 0;
			continue;
		}

		// check for enough space in output buffer
		if ( !CheckBufferSpace(fs->nffile, table->output_record_size) ) {
			// this should really never occur, because the buffer gets flushed ealier
			syslog(LOG_ERR,"Process_v9: output buffer size error. Abort v9 record processing");
			dbg_printf("Process_v9: output buffer size error. Abort v9 record processing");
			return;
		}
		processed_records++;

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

		table->packets 		  	    = 0;
		table->bytes 		  	    = 0;
		table->out_packets 	  	    = 0;
		table->out_bytes 	  	    = 0;

		dbg_printf("%u] Process data record: MapID: %u\n", exporter->info.id, table->extension_info.map->map_id);

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
				case move96: 
					{   *((uint32_t *)&out[output_offset]) = Get_val32((void *)&in[input_offset]);
						*((uint32_t *)&out[output_offset+4]) = Get_val32((void *)&in[input_offset+4]);
						*((uint32_t *)&out[output_offset+8]) = Get_val32((void *)&in[input_offset+8]);
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
				case move_mac:
					/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
					{ type_mask_t t;

						t.val.val64 = Get_val48((void *)&in[input_offset]);
						*((uint32_t *)&out[output_offset])   = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4]) = t.val.val32[1];
					}
					break;
				case move_mpls:
					*((uint32_t *)&out[output_offset]) = Get_val24((void *)&in[input_offset]);
					break;
				case move_ulatency:
					/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
					{ type_mask_t t;
						t.val.val32[0] = *((uint32_t *)&out[output_offset]);
						t.val.val32[1] = *((uint32_t *)&out[output_offset+4]);

						t.val.val64 += Get_val32((void *)&in[input_offset]);
						*((uint32_t *)&out[output_offset])   = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4]) = t.val.val32[1];
					} break;
				case move_slatency:
					/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
					{ type_mask_t t;
						t.val.val32[0] = *((uint32_t *)&out[output_offset]);
						t.val.val32[1] = *((uint32_t *)&out[output_offset+4]);

						// update sec to usec
						t.val.val64 += 1000000 * Get_val32((void *)&in[input_offset]);
						*((uint32_t *)&out[output_offset])   = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4]) = t.val.val32[1];
					} break;
				case move_user_20:
					memcpy((void *)&out[output_offset],(void *)&in[input_offset],20);
					out[output_offset+20] = 0;	// trailing 0 for string
					break;
				case move_user_65:
					memcpy((void *)&out[output_offset],(void *)&in[input_offset],65);
					out[output_offset+65] = 0;	// trailing 0 for string
					break;
				case TimeMsec:
					{ uint64_t DateMiliseconds = Get_val64((void *)&in[input_offset]);
					  *(uint64_t *)stack = DateMiliseconds;
					} break;
				case PushTimeMsec:
					{ type_mask_t t;
						t.val.val64 = Get_val64((void *)&in[input_offset]);
					  	*(uint64_t *)stack = t.val.val64;

						*((uint32_t *)&out[output_offset]) 	 = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4]) = t.val.val32[1];
					} break;

				// zero sequences for unavailable elements
				case zero8:
					out[output_offset] = 0;
					break;
				case zero16:
					*((uint16_t *)&out[output_offset]) = 0;
					break;
				case zero32:
					*((uint32_t *)&out[output_offset]) = 0;
					break;
				case zero64: {   
						*((uint32_t *)&out[output_offset])   = 0;
						*((uint32_t *)&out[output_offset+4]) = 0;
					} break;
				case zero96: 
					{   *((uint32_t *)&out[output_offset])   = 0;
						*((uint32_t *)&out[output_offset+4]) = 0;
						*((uint32_t *)&out[output_offset+8]) = 0;
					} break;
				case zero128: {   
						*((uint32_t *)&out[output_offset])   = 0;
						*((uint32_t *)&out[output_offset+4]) = 0;
						*((uint32_t *)&out[output_offset+8]) = 0;
						*((uint32_t *)&out[output_offset+12]) = 0;
					} break;
				default:
					syslog(LOG_ERR, "Process_v9: Software bug! Unknown Sequence: %u. at %s line %d", 
						table->sequence[i].id, __FILE__, __LINE__);
					dbg_printf("Software bug! Unknown Sequence: %u. at %s line %d", 
						table->sequence[i].id, __FILE__, __LINE__);
			}
		}


		// Ungly ICMP hack for v9, because some IOS version are lazzy
		// most of them send ICMP in dst port field some don't some have both
		if ( data_record->prot == IPPROTO_ICMP || data_record->prot == IPPROTO_ICMPV6 ) {
			if ( table->ICMP_offset ) {
				data_record->dstport = Get_val16((void *)&in[table->ICMP_offset]);
			}
			if ( data_record->dstport == 0 && data_record->srcport != 0 ) {
				// some IOSes are even lazzier and map ICMP code in src port - ughh
				data_record->dstport = data_record->srcport;
				data_record->srcport = 0;
			}
		}

		// Check for NSEL/NEL Event time
		if ( table->flow_start ) {
			data_record->first 		= table->flow_start / 1000;
			data_record->msec_first = table->flow_start % 1000;
			start_time 				= table->flow_start;
			// test for tags 152/153
			if ( table->flow_end ) {
				data_record->last 		= table->flow_end / 1000;
				data_record->msec_last  = table->flow_end % 1000;
				end_time   				= table->flow_end;
			} else {
				data_record->last 		= data_record->first;
				data_record->msec_last	= data_record->msec_first;
				end_time   				= table->flow_start;
			}
			dbg_printf("Found time flow start MSEC: %llu\n",  table->EventTimeMsec);
		} else if ( table->EventTimeMsec && data_record->first == 0 ) {
			data_record->first 		= table->EventTimeMsec / 1000;
			data_record->msec_first = table->EventTimeMsec % 1000;
			data_record->last 		= data_record->first;
			data_record->msec_last	= data_record->msec_first;
			start_time = table->EventTimeMsec;
			end_time   = table->EventTimeMsec;
			dbg_printf("Found Time Event MSEC: %llu\n",  table->EventTimeMsec);
		} else if ( data_record->first == 0 && data_record->last == 0 ) {
			// hmm - a record with no time at all ..
			data_record->first 		= 0;
			data_record->msec_last	= 0;
			start_time = 0;
			end_time   = 0;
		} else {
			uint32_t First = data_record->first;
			uint32_t Last  = data_record->last;

			if ( First > Last )
				/* First in msec, in case of msec overflow, between start and end */
				start_time = exporter->boot_time - 0x100000000LL + (uint64_t)First;
			else
				start_time = (uint64_t)First + exporter->boot_time;
	
			/* end time in msecs */
			end_time = (uint64_t)Last + exporter->boot_time;
	
			if ( (end_time - start_time) > 0xffc00000 && table->bytes < 2000 ) {
				dbg_printf("CISCO bugfix!\n");
				start_time += 0xffc00000;
			}
			data_record->first 		= start_time/1000;
			data_record->msec_first	= start_time - data_record->first*1000;
		
			data_record->last 		= end_time/1000;
			data_record->msec_last	= end_time - data_record->last*1000;
	
			if ( data_record->first == 0 && data_record->last == 0 )
				data_record->last = 0;
		}

		// update first_seen, last_seen
		if ( start_time < fs->first_seen )
			fs->first_seen = start_time;
		if ( end_time > fs->last_seen )
			fs->last_seen = end_time;

		// check if we need to record the router IP address
		if ( table->router_ip_offset ) {
			int output_offset = table->router_ip_offset;
			if ( exporter->info.sa_family == PF_INET6 ) {
				/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
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

		// Ugly hack. CISCO never really implemented #38/#39 tags in the records - so take it from the 
		// header, unless some data is filled in
		if ( table->engine_offset ) {
			if ( *((uint32_t *)&out[table->engine_offset]) == 0 ) {
				tpl_ext_25_t *tpl = (tpl_ext_25_t *)&out[table->engine_offset];
				tpl->engine_type = ( exporter->info.id >> 8 ) & 0xFF;
				tpl->engine_id	 = exporter->info.id & 0xFF;
			}
		}

		// check, if we need to store the packet received time
		if ( table->received_offset ) {
			type_mask_t t;
			t.val.val64 = (uint64_t)((uint64_t)fs->received.tv_sec * 1000LL) + (uint64_t)((uint64_t)fs->received.tv_usec / 1000LL);
				*((uint32_t *)&out[table->received_offset])   = t.val.val32[0];
				*((uint32_t *)&out[table->received_offset+4]) = t.val.val32[1];
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
			syslog(LOG_ERR,"Process v9: Output buffer overflow! Flush buffer and skip records.");
			syslog(LOG_ERR,"Buffer size: %u > %u", fs->nffile->block_header->size, BUFFSIZE);

			// reset buffer
			fs->nffile->block_header->size 		= 0;
			fs->nffile->block_header->NumRecords = 0;
			fs->nffile->buff_ptr = (void *)((pointer_addr_t)fs->nffile->block_header + sizeof(data_block_header_t) );
			return;
		}
	}

} // End of Process_v9_data

static inline void 	Process_v9_option_data(exporter_v9_domain_t *exporter, void *data_flowset, FlowSource_t *fs) {
option_offset_t *offset_table;
uint32_t	id;
uint8_t		*in;

	id 	= GET_FLOWSET_ID(data_flowset);

	offset_table = fs->option_offset_table;
	while ( offset_table && offset_table->id != id )
		offset_table = offset_table->next;

	if ( !offset_table ) {
		// should never happen - catch it anyway
		syslog(LOG_ERR, "Process_v9: Panic! - No Offset table found! : %s line %d", __FILE__, __LINE__);
		return;
	}

#ifdef DEVEL
	uint32_t size_left = GET_FLOWSET_LENGTH(data_flowset) - 4; // -4 for data flowset header -> id and length
	dbg_printf("[%u] Process option data flowset size: %u\n", exporter->info.id, size_left);
#endif

	// map input buffer as a byte array
	in	  = (uint8_t *)(data_flowset + 4);	// skip flowset header

	if ( TestFlag(offset_table->flags, HAS_SAMPLER_DATA) ) {
		int32_t  id;
		uint16_t mode;
		uint32_t interval;
		if (offset_table->sampler_id_length == 2) {
			id = Get_val16((void *)&in[offset_table->offset_id]);
		} else {
			id = in[offset_table->offset_id];
		}
		mode 	 = in[offset_table->offset_mode];
		interval = Get_val32((void *)&in[offset_table->offset_interval]); 
	
		dbg_printf("Extracted Sampler data:\n");
		dbg_printf("Sampler ID      : %u\n", id);
		dbg_printf("Sampler mode    : %u\n", mode);
		dbg_printf("Sampler interval: %u\n", interval);
	
		InsertSampler(fs, exporter, id, mode, interval);
	}

	if ( TestFlag(offset_table->flags, HAS_STD_SAMPLER_DATA) ) {
		int32_t  id 	  = -1;
		uint16_t mode 	  = in[offset_table->offset_std_sampler_algorithm];
		uint32_t interval = Get_val32((void *)&in[offset_table->offset_std_sampler_interval]);

		InsertSampler(fs, exporter, id, mode, interval);

		dbg_printf("Extracted Std Sampler data:\n");
		dbg_printf("Sampler ID       : %u\n", id);
		dbg_printf("Sampler algorithm: %u\n", mode);
		dbg_printf("Sampler interval : %u\n", interval);

		syslog(LOG_INFO, "Set std sampler: algorithm: %u, interval: %u\n", 
				mode, interval);
		dbg_printf("Set std sampler: algorithm: %u, interval: %u\n", 
				mode, interval);
	}
	processed_records++;

} // End of Process_v9_option_data

void Process_v9(void *in_buff, ssize_t in_buff_cnt, FlowSource_t *fs) {
exporter_v9_domain_t	*exporter;
void				*flowset_header;
option_template_flowset_t	*option_flowset;
netflow_v9_header_t	*v9_header;
int64_t 			distance;
uint32_t 			flowset_id, flowset_length, exporter_id;
ssize_t				size_left;
static int pkg_num = 0;

	pkg_num++;
	size_left = in_buff_cnt;
	if ( size_left < NETFLOW_V9_HEADER_LENGTH ) {
		syslog(LOG_ERR, "Process_v9: Too little data for v9 packet: '%lli'", (long long)size_left);
		return;
	}

	// map v9 data structure to input buffer
	v9_header 	= (netflow_v9_header_t *)in_buff;
	exporter_id = ntohl(v9_header->source_id);

	exporter	= GetExporter(fs, exporter_id);
	if ( !exporter ) {
		syslog(LOG_ERR,"Process_v9: Exporter NULL: Abort v9 record processing");
		return;
	}
	exporter->packets++;

	/* calculate boot time in msec */
  	v9_header->SysUptime 	= ntohl(v9_header->SysUptime);
  	v9_header->unix_secs	= ntohl(v9_header->unix_secs);
	exporter->boot_time  	= (uint64_t)1000 * (uint64_t)(v9_header->unix_secs) - (uint64_t)v9_header->SysUptime;
	
	flowset_header 			= (void *)v9_header + NETFLOW_V9_HEADER_LENGTH;

	size_left -= NETFLOW_V9_HEADER_LENGTH;

#ifdef DEVEL
	uint32_t expected_records 		= ntohs(v9_header->count);
	printf("\n[%u] Next packet: %i %u records, buffer: %li \n", exporter_id, pkg_num, expected_records, size_left);
#endif

	// sequence check
	if ( exporter->first ) {
		exporter->last_sequence = ntohl(v9_header->sequence);
		exporter->sequence 	  	= exporter->last_sequence;
		exporter->first			= 0;
	} else {
		exporter->last_sequence = exporter->sequence;
		exporter->sequence 	  = ntohl(v9_header->sequence);
		distance 	  = exporter->sequence - exporter->last_sequence;
		// handle overflow
		if (distance < 0) {
			distance = 0xffffffff + distance  +1;
		}
		if (distance != 1) {
			exporter->sequence_failure++;
			fs->nffile->stat_record->sequence_failure++;
			dbg_printf("[%u] Sequence error: last seq: %lli, seq %lli dist %lli\n", 
				exporter->info.id, (long long)exporter->last_sequence, (long long)exporter->sequence, (long long)distance);
			/*
			if ( report_seq ) 
				syslog(LOG_ERR,"Flow sequence mismatch. Missing: %lli packets", delta(last_count,distance));
			*/
		}
	}

	processed_records = 0;

	// iterate over all flowsets in export packet, while there are bytes left
	flowset_length = 0;
	while (size_left) {
		flowset_header = flowset_header + flowset_length;

		flowset_id 		= GET_FLOWSET_ID(flowset_header);
		flowset_length 	= GET_FLOWSET_LENGTH(flowset_header);
			
		dbg_printf("[%u] Next flowset: %u, length: %u buffersize: %li addr: %llu\n", 
			exporter->info.id, flowset_id, flowset_length, size_left, 
			(long long unsigned)(flowset_header - in_buff) );

		if ( flowset_length == 0 ) {
			/* 	this should never happen, as 4 is an empty flowset 
				and smaller is an illegal flowset anyway ...
				if it happends, we can't determine the next flowset, so skip the entire export packet
			 */
			syslog(LOG_ERR,"Process_v9: flowset zero length error.");
			dbg_printf("Process_v9: flowset zero length error.\n");
			return;
		}

		// possible padding
		if ( flowset_length <= 4 ) {
			size_left = 0;
			continue;
		}

		if ( flowset_length > size_left ) {
			dbg_printf("flowset length error. Expected bytes: %u > buffersize: %lli", 
				flowset_length, (long long)size_left);
			syslog(LOG_ERR,"Process_v9: flowset length error. Expected bytes: %u > buffersize: %lli", 
				flowset_length, (long long)size_left);
			size_left = 0;
			continue;
		}

#ifdef DEVEL
		if ( (ptrdiff_t)fs->nffile->buff_ptr & 0x3 ) {
			fprintf(stderr, "PANIC: alignment error!! \n");
			exit(255);
		}
#endif

		switch (flowset_id) {
			case NF9_TEMPLATE_FLOWSET_ID:
				Process_v9_templates(exporter, flowset_header, fs);
				break;
			case NF9_OPTIONS_FLOWSET_ID:
				option_flowset = (option_template_flowset_t *)flowset_header;
				syslog(LOG_DEBUG,"Process_v9: Found options flowset: template %u", ntohs(option_flowset->template_id));
				Process_v9_option_templates(exporter, flowset_header, fs);
				break;
			default: {
				input_translation_t *table;
				if ( flowset_id < NF9_MIN_RECORD_FLOWSET_ID ) {
					dbg_printf("Invalid flowset id: %u\n", flowset_id);
					syslog(LOG_ERR,"Process_v9: Invalid flowset id: %u", flowset_id);
				} else {

					dbg_printf("[%u] ID %u Data flowset\n", exporter->info.id, flowset_id);

					table = GetTranslationTable(exporter, flowset_id);
					if ( table ) {
						Process_v9_data(exporter, flowset_header, fs, table);
					} else if ( HasOptionTable(fs, flowset_id) ) {
						Process_v9_option_data(exporter, flowset_header, fs);
					} else {
						// maybe a flowset with option data
						dbg_printf("Process v9: [%u] No table for id %u -> Skip record\n", 
							exporter->info.id, flowset_id);
					}
				}
			}
		}

		// next flowset
		size_left -= flowset_length;

	} // End of while 

#ifdef DEVEL
	if ( processed_records != expected_records ) {
		syslog(LOG_ERR, "Process_v9: Processed records %u, expected %u", processed_records, expected_records);
		printf("Process_v9: Processed records %u, expected %u\n", processed_records, expected_records);
	}
#endif

	return;
	
} /* End of Process_v9 */

/*
 * functions for sending netflow v9 records
 */

void Init_v9_output(send_peer_t *peer) {
int i;

	v9_output_header = (netflow_v9_header_t *)peer->send_buffer;
	v9_output_header->version 		= htons(9);
	v9_output_header->SysUptime		= 0;
	v9_output_header->unix_secs		= 0;
	v9_output_header->count 		= 0;
	v9_output_header->source_id 	= htonl(1);
	template_id						= NF9_MIN_RECORD_FLOWSET_ID;
	peer->buff_ptr = (void *)((pointer_addr_t)v9_output_header + (pointer_addr_t)sizeof(netflow_v9_header_t));	

	// set the max number of v9 tags, we support.
	Max_num_v9_tags = 0;
	for (i=1; v9_element_map[i].id != 0; i++ ) {
		if ( v9_element_map[i].id != v9_element_map[i-1].id ) 
			Max_num_v9_tags++;
	}

} // End of Init_v9_output

static output_template_t *GetOutputTemplate(uint32_t flags, extension_map_t *extension_map) {
output_template_t **t;
template_record_t	*fields;
uint32_t	i, count, record_length;

	t = &output_templates;
	// search for the template, which corresponds to our flags and extension map
	while ( *t ) {
		if ( (*t)->flags == flags &&  (*t)->extension_map == extension_map ) 
			return *t;
		t = &((*t)->next);
	}

	// nothing found, otherwise we would not get here
	*t = (output_template_t *)malloc(sizeof(output_template_t));
	if ( !(*t)) {
		fprintf(stderr, "Panic! malloc() %s line %d: %s", __FILE__, __LINE__, strerror (errno));
		exit(255);
	}
	memset((void *)(*t), 0, sizeof(output_template_t));
	(*t)->next	 		 = NULL;
	(*t)->flags	 		 = flags;
	(*t)->extension_map  = extension_map;
	(*t)->time_sent		 = 0;
	(*t)->template_flowset = malloc(sizeof(template_flowset_t) + ((Max_num_v9_tags * 4))); // 4 for 2 x uint16_t: type/length

	count 			= 0;
	record_length 	= 0;
	fields = (*t)->template_flowset->fields;

	// Fill the template flowset in the order of the common_record_t 
	// followed be the available extensions
	fields->record[count].type	 = htons(NF9_FIRST_SWITCHED);
	fields->record[count].length = htons(4);
	record_length 				+= 4;
	count++;

	fields->record[count].type   = htons(NF9_LAST_SWITCHED);
	fields->record[count].length = htons(4);
	record_length 				+= 4;
	count++;

	fields->record[count].type   = htons(NF9_FORWARDING_STATUS);
	fields->record[count].length = htons(1);
	record_length 				+= 1;
	count++;

	fields->record[count].type   = htons(NF9_TCP_FLAGS);
	fields->record[count].length = htons(1);
	record_length 				+= 1;
	count++;

	fields->record[count].type   = htons(NF9_IN_PROTOCOL);
	fields->record[count].length = htons(1);
	record_length 				+= 1;
	count++;

	fields->record[count].type   = htons(NF9_SRC_TOS);
	fields->record[count].length = htons(1);
	record_length 				+= 1;
	count++;

	fields->record[count].type   = htons(NF9_L4_SRC_PORT);
	fields->record[count].length = htons(2);
	record_length 				+= 2;
	count++;

	fields->record[count].type   = htons(NF9_L4_DST_PORT);
	fields->record[count].length = htons(2);
	record_length 				+= 2;
	count++;

    fields->record[count].type   = htons(NF9_ICMP_TYPE);
    fields->record[count].length = htons(2);
    record_length               += 2;
    count++;

	// common record processed

	// fill in IP address tags
	if ( (flags & FLAG_IPV6_ADDR) != 0 ) { // IPv6 addresses
		fields->record[count].type   = htons(NF9_IPV6_SRC_ADDR);
		fields->record[count].length = htons(16);
		record_length 				+= 16;
		count++;
		fields->record[count].type   = htons(NF9_IPV6_DST_ADDR);
		fields->record[count].length = htons(16);
		record_length 				+= 16;
	} else { // IPv4 addresses
		fields->record[count].type   = htons(NF9_IPV4_SRC_ADDR);
		fields->record[count].length = htons(4);
		record_length 				+= 4;
		count++;
		fields->record[count].type   = htons(NF9_IPV4_DST_ADDR);
		fields->record[count].length = htons(4);
		record_length 				+= 4;
	}
	count++;

	// packet counter
	fields->record[count].type  = htons(NF9_IN_PACKETS);
	if ( (flags & FLAG_PKG_64) != 0 ) {  // 64bit packet counter
		fields->record[count].length = htons(8);
		record_length 				+= 8;
	} else {
		fields->record[count].length = htons(4);
		record_length 				+= 4;
	}
	count++;

	// bytes counter
	fields->record[count].type  = htons(NF9_IN_BYTES);
	if ( (flags & FLAG_BYTES_64) != 0 ) { // 64bit byte counter
		fields->record[count].length = htons(8);
		record_length 				+= 8;
	} else {
		fields->record[count].length = htons(4);
		record_length 				+= 4;
	}
	count++;
	// process extension map 
	i = 0;
	while ( extension_map->ex_id[i] ) {
		switch (extension_map->ex_id[i++]) {
			// 0 - 3 should never be in an extension table so - ignore it
			case 0:
			case 1:
			case 2:
			case 3:
				break;
			case EX_IO_SNMP_2:
				fields->record[count].type   = htons(NF9_INPUT_SNMP);
				fields->record[count].length = htons(2);
				record_length 				+= 2;
				count++;

				fields->record[count].type   = htons(NF9_OUTPUT_SNMP);
				fields->record[count].length = htons(2);
				record_length 				+= 2;
				count++;
				break;
			case EX_IO_SNMP_4:	// input/output SNMP 4 byte
				fields->record[count].type   = htons(NF9_INPUT_SNMP);
				fields->record[count].length = htons(4);
				record_length 				+= 4;
				count++;

				fields->record[count].type   = htons(NF9_OUTPUT_SNMP);
				fields->record[count].length = htons(4);
				record_length 				+= 4;
				count++;
				break;
			case EX_AS_2:	// srcas/dstas 2 byte
				fields->record[count].type   = htons(NF9_SRC_AS);
				fields->record[count].length = htons(2);
				record_length 				+= 2;
				count++;

				fields->record[count].type   = htons(NF9_DST_AS);
				fields->record[count].length = htons(2);
				record_length 				+= 2;
				count++;
				break;
			case EX_AS_4:	// srcas/dstas 4 byte
				fields->record[count].type   = htons(NF9_SRC_AS);
				fields->record[count].length = htons(4);
				record_length 				+= 4;
				count++;

				fields->record[count].type   = htons(NF9_DST_AS);
				fields->record[count].length = htons(4);
				record_length 				+= 4;
				count++;
				break;
			case EX_MULIPLE: {
				uint16_t src_mask, dst_mask;
				fields->record[count].type   = htons(NF9_DST_TOS);
				fields->record[count].length = htons(1);
				record_length 				+= 1;
				count++;

				fields->record[count].type   = htons(NF9_DIRECTION);
				fields->record[count].length = htons(1);
				record_length 				+= 1;
				count++;

				if ( (flags & FLAG_IPV6_ADDR) != 0 ) { // IPv6 addresses
					src_mask = NF9_IPV6_SRC_MASK;
					dst_mask = NF9_IPV6_DST_MASK;
				} else { // IPv4 addresses
					src_mask = NF9_SRC_MASK;
					dst_mask = NF9_DST_MASK;
				}

				fields->record[count].type   = htons(src_mask);
				fields->record[count].length = htons(1);
				record_length 				+= 1;
				count++;

				fields->record[count].type   = htons(dst_mask);
				fields->record[count].length = htons(1);
				record_length 				+= 1;
				count++;
				} break;
			case EX_NEXT_HOP_v4:
				fields->record[count].type   = htons(NF9_V4_NEXT_HOP);
				fields->record[count].length = htons(4);
				record_length 				+= 4;
				count++;
				break;
			case EX_NEXT_HOP_v6:
				fields->record[count].type   = htons(NF9_V6_NEXT_HOP);
				fields->record[count].length = htons(16);
				record_length 				+= 16;
				count++;
				break;
			case EX_NEXT_HOP_BGP_v4:
				fields->record[count].type   = htons(NF9_BGP_V4_NEXT_HOP);
				fields->record[count].length = htons(4);
				record_length 				+= 4;
				count++;
				break;
			case EX_NEXT_HOP_BGP_v6:
				fields->record[count].type   = htons(NF9_BPG_V6_NEXT_HOP);
				fields->record[count].length = htons(16);
				record_length 				+= 16;
				count++;
				break;
			case EX_VLAN:
				fields->record[count].type   = htons(NF9_SRC_VLAN);
				fields->record[count].length = htons(2);
				record_length 				+= 2;
				count++;

				fields->record[count].type   = htons(NF9_DST_VLAN);
				fields->record[count].length = htons(2);
				record_length 				+= 2;
				count++;
				break;
			case EX_OUT_PKG_4:
				fields->record[count].type   = htons(NF9_OUT_PKTS);
				fields->record[count].length = htons(4);
				record_length 				+= 4;
				count++;
				break;
			case EX_OUT_PKG_8:
				fields->record[count].type   = htons(NF9_OUT_PKTS);
				fields->record[count].length = htons(8);
				record_length 				+= 8;
				count++;
				break;
			case EX_OUT_BYTES_4:
				fields->record[count].type   = htons(NF9_OUT_BYTES);
				fields->record[count].length = htons(4);
				record_length 				+= 4;
				count++;
				break;
			case EX_OUT_BYTES_8:
				fields->record[count].type   = htons(NF9_OUT_BYTES);
				fields->record[count].length = htons(8);
				record_length 				+= 8;
				count++;
				break;
			case EX_AGGR_FLOWS_4:
				fields->record[count].type   = htons(NF9_FLOWS_AGGR);
				fields->record[count].length = htons(4);
				record_length 				+= 4;
				count++;
				break;
			case EX_AGGR_FLOWS_8:
				fields->record[count].type   = htons(NF9_FLOWS_AGGR);
				fields->record[count].length = htons(8);
				record_length 				+= 8;
				count++;
				break;
			case EX_MAC_1:
				fields->record[count].type   = htons(NF9_IN_SRC_MAC);
				fields->record[count].length = htons(6);
				record_length 				+= 6;
				count++;

				fields->record[count].type   = htons(NF9_OUT_DST_MAC);
				fields->record[count].length = htons(6);
				record_length 				+= 6;
				count++;
				break;
			case EX_MAC_2:
				fields->record[count].type   = htons(NF9_IN_DST_MAC);
				fields->record[count].length = htons(6);
				record_length 				+= 6;
				count++;

				fields->record[count].type   = htons(NF9_OUT_SRC_MAC);
				fields->record[count].length = htons(6);
				record_length 				+= 6;
				count++;
				break;
			case EX_MPLS:
				fields->record[count].type   = htons(NF9_MPLS_LABEL_1);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				fields->record[count].type   = htons(NF9_MPLS_LABEL_2);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				fields->record[count].type   = htons(NF9_MPLS_LABEL_3);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				fields->record[count].type   = htons(NF9_MPLS_LABEL_4);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				fields->record[count].type   = htons(NF9_MPLS_LABEL_5);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				fields->record[count].type   = htons(NF9_MPLS_LABEL_6);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				fields->record[count].type   = htons(NF9_MPLS_LABEL_7);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				fields->record[count].type   = htons(NF9_MPLS_LABEL_8);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				fields->record[count].type   = htons(NF9_MPLS_LABEL_9);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				fields->record[count].type   = htons(NF9_MPLS_LABEL_10);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				break;
			case EX_ROUTER_ID:
				fields->record[count].type   = htons(NF9_ENGINE_TYPE);
				fields->record[count].length = htons(1);
				record_length 				+= 1;
				count++;

				fields->record[count].type   = htons(NF9_ENGINE_ID);
				fields->record[count].length = htons(1);
				record_length 				+= 1;
				count++;
				break;
			case EX_BGPADJ:
				fields->record[count].type   = htons(NF9_BGP_ADJ_NEXT_AS);
				fields->record[count].length = htons(4);
				record_length 				+= 4;
				count++;

				fields->record[count].type   = htons(NF9_BGP_ADJ_PREV_AS);
				fields->record[count].length = htons(4);
				record_length 				+= 4;
				count++;
				break;

			// default: other extensions are not (yet) recognised
		}
	}

	(*t)->template_flowset->flowset_id   = htons(NF9_TEMPLATE_FLOWSET_ID);
	(*t)->flowset_length				 = 4 * (2+count); // + 2 for the header

	// add proper padding for 32bit boundary
	if ( ((*t)->flowset_length & 0x3 ) != 0 ) 
		(*t)->flowset_length += (4 - ((*t)->flowset_length & 0x3 ));
	(*t)->template_flowset->length  	 = htons((*t)->flowset_length);

	(*t)->record_length		= record_length;

	fields->template_id		= htons(template_id++);
	fields->count			= htons(count);

	return *t;

} // End of GetOutputTemplate

static void Append_Record(send_peer_t *peer, master_record_t *master_record) {
extension_map_t *extension_map = master_record->map_ref;
uint32_t	i, t1, t2;
uint16_t	icmp;

	t1 	= (uint32_t)(1000LL * (uint64_t)master_record->first + master_record->msec_first - boot_time);
	t2	= (uint32_t)(1000LL * (uint64_t)master_record->last  + master_record->msec_last - boot_time);
  	master_record->first	= htonl(t1);
  	master_record->last		= htonl(t2);

  	master_record->srcport	= htons(master_record->srcport);
  	master_record->dstport	= htons(master_record->dstport);

	// if it's an ICMP send it in the appropriate v9 tag
	if ( master_record->prot == IPPROTO_ICMP || master_record->prot == IPPROTO_ICMPV6  ) { // it's an ICMP
		icmp = master_record->dstport;
		master_record->dstport = 0;
	} else {
		icmp = 0;
	}
	// write the first 16 bytes of the master_record starting with first up to and including dst port
	memcpy(peer->buff_ptr, (void *)&master_record->first, 16);
	peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + 16);

	// write ICMP type/code
	memcpy(peer->buff_ptr, (void *)&icmp,2);
	peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + 2);

	// IP address info
	if ((master_record->flags & FLAG_IPV6_ADDR) != 0 ) { // IPv6
		master_record->v6.srcaddr[0] = htonll(master_record->v6.srcaddr[0]);
		master_record->v6.srcaddr[1] = htonll(master_record->v6.srcaddr[1]);
		master_record->v6.dstaddr[0] = htonll(master_record->v6.dstaddr[0]);
		master_record->v6.dstaddr[1] = htonll(master_record->v6.dstaddr[1]);
		// keep compiler happy
		// memcpy(peer->buff_ptr, master_record->v6.srcaddr, 4 * sizeof(uint64_t));
		memcpy(peer->buff_ptr, master_record->ip_union._ip_64.addr, 4 * sizeof(uint64_t));
		peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + 4 * sizeof(uint64_t));
	} else {
		Put_val32(htonl(master_record->v4.srcaddr), peer->buff_ptr);
		peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
		Put_val32(htonl(master_record->v4.dstaddr), peer->buff_ptr);
		peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
	}

	// packet counter
	if ((master_record->flags & FLAG_PKG_64) != 0 ) { // 64bit counters
		Put_val64(htonll(master_record->dPkts), peer->buff_ptr);
		peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint64_t));
	} else {
		Put_val32(htonl((uint32_t)master_record->dPkts), peer->buff_ptr);
		peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
	}

	// bytes counter
	if ((master_record->flags & FLAG_BYTES_64) != 0 ) { // 64bit counters
		Put_val64(htonll(master_record->dOctets),peer->buff_ptr);
		peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint64_t));
	} else {
		Put_val32(htonl((uint32_t)master_record->dOctets),peer->buff_ptr);
		peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
	}

	// send now optional extensions according the extension map
	i=0;
	while ( extension_map->ex_id[i] ) {
		switch (extension_map->ex_id[i++]) {
			// 0 - 3 should never be in an extension table so - ignore it
			case 0:
			case 1:
			case 2:
			case 3:
				break;
			case EX_IO_SNMP_2: {
				uint16_t in, out;

				in  = htons(master_record->input);
				Put_val16(in, peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint16_t));

				out = htons(master_record->output);
				Put_val16(out, peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint16_t));
				} break;
			case EX_IO_SNMP_4:
				Put_val32(htonl(master_record->input), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				Put_val32(htonl(master_record->output), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				break;
			case EX_AS_2: { // srcas/dstas 2 byte
				uint16_t src, dst;

				src = htons(master_record->srcas);
				Put_val16(src, peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint16_t));

				dst = htons(master_record->dstas);
				Put_val16(dst, peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint16_t));
				} break;
			case EX_AS_4:  // srcas/dstas 4 byte
				Put_val32(htonl(master_record->srcas), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				Put_val32(htonl(master_record->dstas), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				break;
			case EX_MULIPLE: {
				tpl_ext_8_t *tpl = (tpl_ext_8_t *)peer->buff_ptr;
				tpl->dst_tos  = master_record->dst_tos;
				tpl->dir 	  = master_record->dir;
				tpl->src_mask = master_record->src_mask;
				tpl->dst_mask = master_record->dst_mask;
				peer->buff_ptr = (void *)tpl->data;
				} break;
			case EX_NEXT_HOP_v4:
				Put_val32(htonl(master_record->ip_nexthop.v4), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				break;
			case EX_NEXT_HOP_v6: 
				Put_val64(htonll(master_record->ip_nexthop.v6[0]), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint64_t));
				Put_val64(htonll(master_record->ip_nexthop.v6[1]), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint64_t));
				break;
			case EX_NEXT_HOP_BGP_v4: 
				Put_val32(htonl(master_record->bgp_nexthop.v4), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				break;
			case EX_NEXT_HOP_BGP_v6: 
				Put_val64(htonll(master_record->bgp_nexthop.v6[0]), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint64_t));
				Put_val64(htonll(master_record->bgp_nexthop.v6[1]), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint64_t));
				break;
			case EX_VLAN: 
				Put_val16(htons(master_record->src_vlan), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint16_t));
				Put_val16(htons(master_record->dst_vlan), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint16_t));
				break;
			case EX_OUT_PKG_4: 
				Put_val32(htonl((uint32_t)master_record->out_pkts), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				break;
			case EX_OUT_PKG_8:
				Put_val64(htonll(master_record->out_pkts), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint64_t));
				break;
			case EX_OUT_BYTES_4:
				Put_val32(htonl((uint32_t)master_record->out_bytes), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				break;
			case EX_OUT_BYTES_8:
				Put_val64(htonll(master_record->out_bytes), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint64_t));
				break;
			case EX_AGGR_FLOWS_4:
				Put_val32(htonl(master_record->aggr_flows), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				break;
			case EX_AGGR_FLOWS_8:
				Put_val64(htonll(master_record->aggr_flows), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint64_t));
				break;
			case EX_MAC_1: {
				uint64_t	val64;
				val64 = htonll(master_record->in_src_mac);
				Put_val48(val64, peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + 6);	// 48 bits

				val64 = htonll(master_record->out_dst_mac);
				Put_val48(val64, peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + 6);	// 48 bits

				} break;
			case EX_MAC_2: {
				uint64_t	val64;
				val64 = htonll(master_record->in_dst_mac);
				Put_val48(val64, peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + 6);	// 48 bits

				val64 = htonll(master_record->out_src_mac);
				Put_val48(val64, peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + 6);	// 48 bits

				} break;
			case EX_MPLS: {
				uint32_t val32, i;
				for ( i=0; i<10; i++ ) {
					val32 = htonl(master_record->mpls_label[i]);
					Put_val24(val32, peer->buff_ptr);
					peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + 3);	// 24 bits
				}
				} break;
			case EX_ROUTER_ID: {
				uint8_t *u = (uint8_t *)peer->buff_ptr;
				*u++ = master_record->engine_type;
				*u++ = master_record->engine_id;
				peer->buff_ptr = (void *)u;
				} break;
			case EX_BGPADJ:
				Put_val32(htonl(master_record->bgpNextAdjacentAS), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				Put_val32(htonl(master_record->bgpPrevAdjacentAS), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				break;

			// default: ignore all other extension, as we do not understand them
		}
	}

} // End of Append_Record

int Add_v9_output_record(master_record_t *master_record, send_peer_t *peer) {
static data_flowset_t		*data_flowset;
static output_template_t	*template;
static uint32_t	last_flags = 0;
static extension_map_t *last_map = NULL;
static int	record_count, template_count, flowset_count, packet_count;
uint32_t	required_size;
void		*endwrite;
time_t		now = time(NULL);

#ifdef DEVEL
//	char		*string;
//	format_file_block_record(master_record, 1, &string, 0);
//	dbg_printf("%s\n", string);
#endif

	if ( !v9_output_header->unix_secs ) {	// first time a record is added
		// boot time is set one day back - assuming that the start time of every flow does not start ealier
		boot_time	   = (uint64_t)(master_record->first - 86400)*1000;
		v9_output_header->unix_secs = htonl(master_record->first - 86400);
		v9_output_header->sequence  = 0;
		peer->buff_ptr  = (void *)((pointer_addr_t)peer->send_buffer + NETFLOW_V9_HEADER_LENGTH);
		record_count   = 0;
		template_count = 0;
		flowset_count  = 0;
		packet_count   = 0;
		data_flowset   = NULL;

		// write common blocksize from frst up to including dstas for one write (memcpy)
//		common_block_size = (pointer_addr_t)&master_record->fill - (pointer_addr_t)&master_record->first;

	} else if ( flowset_count == 0 ) {	// after a buffer flush
		packet_count++;
		v9_output_header->sequence = htonl(packet_count);
	}

	if ( data_flowset ) {
		// output buffer contains already a data flowset
		if ( last_flags == master_record->flags && last_map == master_record->map_ref ) {
			// same id as last record
			// if ( now - template->time_sent > MAX_LIFETIME )
			if ( (record_count & 0xFFF) == 0 ) {	// every 4096 flow records
				uint16_t length = (pointer_addr_t)peer->buff_ptr - (pointer_addr_t)data_flowset;
				uint8_t	align   = length & 0x3;
				if ( align != 0 ) {
					length += ( 4 - align );
					data_flowset->length = htons(length);
					peer->buff_ptr += align;
				}
				// template refresh is needed
				// terminate the current data flowset
				data_flowset = NULL;
				if ( (pointer_addr_t)peer->buff_ptr + template->flowset_length > (pointer_addr_t)peer->endp ) {
					// not enough space for template flowset => flush buffer first
					record_count   = 0;
					flowset_count  = 0;
					template_count = 0;
					peer->flush = 1;
					return 1;	// return to flush buffer
				}
				memcpy(peer->buff_ptr, (void *)template->template_flowset, template->flowset_length);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + template->flowset_length);
				template->time_sent = now;
				flowset_count++;
				template_count++;

				// open a new data flow set at this point in the output buffer
				data_flowset = (data_flowset_t *)peer->buff_ptr;
				data_flowset->flowset_id = template->template_flowset->fields[0].template_id;
				peer->buff_ptr = (void *)data_flowset->data;
				flowset_count++;
			} // else Add record

		} else {
			// record with different template id
			// terminate the current data flowset
			uint16_t length = (pointer_addr_t)peer->buff_ptr - (pointer_addr_t)data_flowset;
			uint8_t	align   = length & 0x3;
			if ( align != 0 ) {
				length += ( 4 - align );
				data_flowset->length = htons(length);
				peer->buff_ptr += align;
			}
			data_flowset = NULL;

			last_flags 	= master_record->flags;
			last_map	= master_record->map_ref;
			template 	= GetOutputTemplate(last_flags, master_record->map_ref);
			if ( now - template->time_sent > MAX_LIFETIME ) {
				// refresh template is needed
				endwrite= (void *)((pointer_addr_t)peer->buff_ptr + template->flowset_length + sizeof(data_flowset_t));
				if ( endwrite > peer->endp ) {
					// not enough space for template flowset => flush buffer first
					record_count   = 0;
					flowset_count  = 0;
					template_count = 0;
					peer->flush = 1;
					return 1;	// return to flush the buffer
				}
				memcpy(peer->buff_ptr, (void *)template->template_flowset, template->flowset_length);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + template->flowset_length);
				template->time_sent = now;
				flowset_count++;
				template_count++;
			}
			// open a new data flow set at this point in the output buffer
			data_flowset = (data_flowset_t *)peer->buff_ptr;
			data_flowset->flowset_id = template->template_flowset->fields[0].template_id;
			peer->buff_ptr = (void *)data_flowset->data;
			flowset_count++;
		}
	} else {
		// output buffer does not contain a data flowset
		peer->buff_ptr = (void *)((pointer_addr_t)v9_output_header + (pointer_addr_t)sizeof(netflow_v9_header_t));	
		last_flags = master_record->flags;
		last_map	= master_record->map_ref;
		template = GetOutputTemplate(last_flags, master_record->map_ref);
		if ( now - template->time_sent > MAX_LIFETIME ) {
			// refresh template
			endwrite= (void *)((pointer_addr_t)peer->buff_ptr + template->flowset_length + sizeof(data_flowset_t));
			if ( endwrite > peer->endp ) {
				// this must never happen!
				fprintf(stderr, "Panic: Software error in %s line %d\n", __FILE__, __LINE__);
				fprintf(stderr, "buffer %p, buff_ptr %p template length %x, endbuff %p\n", 
					peer->send_buffer, peer->buff_ptr, template->flowset_length + (uint32_t)sizeof(data_flowset_t), peer->endp );
				exit(255);
			}
			memcpy(peer->buff_ptr, (void *)template->template_flowset, template->flowset_length);
			peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + template->flowset_length);
			template->time_sent = now;
			flowset_count++;
			template_count++;
		}
		// open a new data flow set at this point in the output buffer
		data_flowset = (data_flowset_t *)peer->buff_ptr;
		data_flowset->flowset_id = template->template_flowset->fields[0].template_id;
		peer->buff_ptr = (void *)data_flowset->data;
		flowset_count++;
	}
	// now add the record

	required_size = template->record_length;

	endwrite = (void *)((pointer_addr_t)peer->buff_ptr + required_size);
	if ( endwrite > peer->endp ) {
		uint16_t length = (pointer_addr_t)peer->buff_ptr - (pointer_addr_t)data_flowset;

		// flush the buffer
		data_flowset->length = htons(length);
		if ( length == 4 ) {	// empty flowset
			peer->buff_ptr = (void *)data_flowset;
		} 
		data_flowset = NULL;
		v9_output_header->count = htons(record_count+template_count);
		record_count   = 0;
		template_count = 0;
		flowset_count  = 0;
		peer->flush    = 1;
		return 1;	// return to flush buffer
	}

	// this was a long way up to here, now we can add the data
	Append_Record(peer, master_record);

	data_flowset->length = htons((pointer_addr_t)peer->buff_ptr - (pointer_addr_t)data_flowset);
	record_count++;
	v9_output_header->count = htons(record_count+template_count);

	return 0;

} // End of Add_v9_output_record


static void InsertSampler( FlowSource_t *fs, exporter_v9_domain_t *exporter, int32_t id, uint16_t mode, uint32_t interval) {
generic_sampler_t *sampler;

	dbg_printf("[%u] Insert Sampler: Exporter is 0x%llu\n", exporter->info.id, (long long unsigned)exporter);
	if ( !exporter->sampler ) {
		// no samplers so far 
		sampler = (generic_sampler_t *)malloc(sizeof(generic_sampler_t));
		if ( !sampler ) {
			syslog(LOG_ERR, "Process_v9: Panic! malloc(): %s line %d: %s", __FILE__, __LINE__, strerror (errno));
			return;
		}

		sampler->info.header.type = SamplerInfoRecordype;
		sampler->info.header.size = sizeof(sampler_info_record_t);
		sampler->info.exporter_sysid = exporter->info.sysid;
		sampler->info.id 	   = id;
		sampler->info.mode 	   = mode;
		sampler->info.interval = interval;
		sampler->next 		   = NULL;
		exporter->sampler = sampler;

		FlushInfoSampler(fs, &(sampler->info));
		syslog(LOG_INFO, "Add new sampler: ID: %i, mode: %u, interval: %u\n", 
			id, mode, interval);
		dbg_printf("Add new sampler: ID: %i, mode: %u, interval: %u\n", 
			id, mode, interval);

	} else {
		sampler = exporter->sampler;
		while ( sampler ) {
			// test for update of existing sampler
			if ( sampler->info.id == id ) {
				// found same sampler id - update record
				syslog(LOG_INFO, "Update existing sampler id: %i, mode: %u, interval: %u\n", 
					id, mode, interval);
				dbg_printf("Update existing sampler id: %i, mode: %u, interval: %u\n", 
					id, mode, interval);

				// we update only on changes
				if ( mode != sampler->info.mode || interval != sampler->info.interval ) {
					FlushInfoSampler(fs, &(sampler->info));
					sampler->info.mode 	   = mode;
					sampler->info.interval = interval;
				} else {
					dbg_printf("Sampler unchanged!\n");
				}

				break;
			}

			// test for end of chain
			if ( sampler->next == NULL ) {
				// end of sampler chain - insert new sampler
				sampler->next = (generic_sampler_t *)malloc(sizeof(generic_sampler_t));
				if ( !sampler->next ) {
					syslog(LOG_ERR, "Process_v9: Panic! malloc(): %s line %d: %s", __FILE__, __LINE__, strerror (errno));
					return;
				}
				sampler = sampler->next;

				sampler->info.header.type 	 = SamplerInfoRecordype;
				sampler->info.header.size 	 = sizeof(sampler_info_record_t);
				sampler->info.exporter_sysid = exporter->info.sysid;
				sampler->info.id 	   = id;
				sampler->info.mode 	   = mode;
				sampler->info.interval = interval;
				sampler->next 		   = NULL;

				FlushInfoSampler(fs, &(sampler->info));


				syslog(LOG_INFO, "Append new sampler: ID: %u, mode: %u, interval: %u\n", 
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

