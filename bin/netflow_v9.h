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
 *  $Id: netflow_v9.h 51 2010-01-29 09:01:54Z haag $
 *
 *  $LastChangedRevision: 51 $
 *	
 */

/* v9 structures */

/*   Packet Header Field Descriptions
 *
 *   Version
 *         Version of Flow Record format exported in this packet.  The
 *         value of this field is 9 for the current version.
 *
 *   Count
 *         The total number of records in the Export Packet, which is the
 *         sum of Options FlowSet records, Template FlowSet records, and
 *         Data FlowSet records.
 *
 *   sysUpTime
 *         Time in milliseconds since this device was first booted.
 *
 *   UNIX Secs
 *         Time in seconds since 0000 UTC 1970, at which the Export Packet
 *         leaves the Exporter.
 *
 *   Sequence Number
 *         Incremental sequence counter of all Export Packets sent from
 *         the current Observation Domain by the Exporter.  This value
 *         MUST be cumulative, and SHOULD be used by the Collector to
 *         identify whether any Export Packets have been missed.
 *
 *   Source ID
 *         A 32-bit value that identifies the Exporter Observation Domain.
 *         NetFlow Collectors SHOULD use the combination of the source IP
 *         address and the Source ID field to separate different export
 *         streams originating from the same Exporter.
 */

#ifndef _NETFLOW_V9_H
#define _NETFLOW_V9_H 1

typedef struct netflow_v9_header {
	uint16_t  version;
	uint16_t  count;
	uint32_t  SysUptime;
	uint32_t  unix_secs;
	uint32_t  sequence;
	uint32_t  source_id;
} netflow_v9_header_t;

#define NETFLOW_V9_HEADER_LENGTH sizeof(netflow_v9_header_t)

/* FlowSet ID
 *         FlowSet ID value of 0 is reserved for the Template FlowSet.
 *   Length
 *         Total length of this FlowSet.  Because an individual Template
 *         FlowSet MAY contain multiple Template Records, the Length value
 *         MUST be used to determine the position of the next FlowSet
 *         record, which could be any type of FlowSet.  Length is the sum
 *         of the lengths of the FlowSet ID, the Length itself, and all
 *         Template Records within this FlowSet.
 *
 *   Template ID
 *         Each of the newly generated Template Records is given a unique
 *         Template ID.  This uniqueness is local to the Observation
 *         Domain that generated the Template ID.  Template IDs 0-255 are
 *         reserved for Template FlowSets, Options FlowSets, and other
 *         reserved FlowSets yet to be created.  Template IDs of Data
 *         FlowSets are numbered from 256 to 65535.
 *
 *   Field Count
 *         Number of fields in this Template Record.   Because a Template
 *         FlowSet usually contains multiple Template Records, this field
 *         allows the Collector to determine the end of the current
 *         Template Record and the start of the next.
 *
 *   Field Type
 *         A numeric value that represents the type of the field.  Refer
 *         to the "Field Type Definitions" section.
 *
 *   Field Length
 *         The length of the corresponding Field Type, in bytes.  Refer to
 *         the "Field Type Definitions" section.
 */

typedef struct template_record_s {
	uint16_t  	template_id;
	uint16_t  	count;
	struct {
		uint16_t  type;
		uint16_t  length;
	} record[1];
} template_record_t;

typedef struct template_flowset_s {
	uint16_t  	flowset_id;
	uint16_t  	length;
	template_record_t	fields[1];
} template_flowset_t;

typedef struct data_flowset_s {
	uint16_t  	flowset_id;
	uint16_t  	length;
	uint8_t		data[4];
} data_flowset_t;

typedef struct option_template_flowset_s {
	uint16_t  	flowset_id;
	uint16_t  	length;
	uint16_t	template_id;
	uint16_t	option_scope_length;
	uint16_t	option_length;
	struct {
		uint16_t  type;
		uint16_t  length;
	} record[1];
} option_template_flowset_t;

typedef struct common_header_s {
	uint16_t  	flowset_id;
	uint16_t  	length;
} common_header_t;

#define _1byte    1
#define _2bytes   2
#define _3bytes   3
#define _4bytes   4
#define _6bytes   6
#define _8bytes   8
#define _12bytes  12
#define _16bytes  16
#define _20bytes  20
#define _24bytes  24
#define _65bytes  65
#define _72bytes  72

#define NF9_TEMPLATE_FLOWSET_ID     0
#define NF9_OPTIONS_FLOWSET_ID      1
#define NF9_MIN_RECORD_FLOWSET_ID   256

// Flowset record types
#define NF9_IN_BYTES            1
#define NF9_IN_PACKETS          2
#define NF9_FLOWS_AGGR			3
#define NF9_IN_PROTOCOL         4
#define NF9_SRC_TOS         	5
#define NF9_TCP_FLAGS           6
#define NF9_L4_SRC_PORT         7
#define NF9_IPV4_SRC_ADDR       8
#define NF9_SRC_MASK			9
#define NF9_INPUT_SNMP          10
#define NF9_L4_DST_PORT         11
#define NF9_IPV4_DST_ADDR       12
#define NF9_DST_MASK			13
#define NF9_OUTPUT_SNMP         14
#define NF9_V4_NEXT_HOP			15
#define NF9_SRC_AS          	16
#define NF9_DST_AS          	17
#define NF9_BGP_V4_NEXT_HOP		18

#define NF9_LAST_SWITCHED       21
#define NF9_FIRST_SWITCHED      22
#define NF9_OUT_BYTES       	23
#define NF9_OUT_PKTS    		24

#define NF9_IPV6_SRC_ADDR       27
#define NF9_IPV6_DST_ADDR       28
#define NF9_IPV6_SRC_MASK		29
#define NF9_IPV6_DST_MASK		30

#define NF9_IPV6_FLOW_LABEL		31
#define NF9_ICMP_TYPE			32

#define NF9_SAMPLING_INTERVAL	34
#define NF9_SAMPLING_ALGORITHM	35

#define NF9_ENGINE_TYPE			38
#define NF9_ENGINE_ID			39

#define NF9_FLOW_SAMPLER_ID 	48 
#define FLOW_SAMPLER_MODE 	49 
#define NF9_FLOW_SAMPLER_RANDOM_INTERVAL 50

// #define NF9_MIN_TTL			52
// #define NF9_MAX_TTL			53
// #define NF9_IPV4_IDENT		54

#define NF9_DST_TOS         	55
#define NF9_IN_SRC_MAC			56
#define NF9_OUT_DST_MAC			57
#define NF9_SRC_VLAN			58
#define NF9_DST_VLAN			59

#define NF9_DIRECTION	        61
#define NF9_V6_NEXT_HOP 		62 
#define NF9_BPG_V6_NEXT_HOP   	63 
// #define NF9_V6_OPTION_HEADERS 64

#define NF9_MPLS_LABEL_1		70
#define NF9_MPLS_LABEL_2		71
#define NF9_MPLS_LABEL_3		72
#define NF9_MPLS_LABEL_4		73
#define NF9_MPLS_LABEL_5		74
#define NF9_MPLS_LABEL_6		75
#define NF9_MPLS_LABEL_7		76
#define NF9_MPLS_LABEL_8		77
#define NF9_MPLS_LABEL_9		78
#define NF9_MPLS_LABEL_10		79
#define NF9_IN_DST_MAC			80
#define NF9_OUT_SRC_MAC			81


#define NF9_FORWARDING_STATUS	89

#define NF9_BGP_ADJ_NEXT_AS 	128
#define NF9_BGP_ADJ_PREV_AS 	129

// CISCO ASA NSEL extension - Network Security Event Logging
#define NF_F_FLOW_BYTES				   85
#define NF_F_CONN_ID                  148
#define NF_F_FLOW_CREATE_TIME_MSEC	  152
#define NF_F_FLOW_END_TIME_MSEC		  153
#define NF_F_ICMP_TYPE                176
#define NF_F_ICMP_CODE                177
#define NF_F_ICMP_TYPE_IPV6           178
#define NF_F_ICMP_CODE_IPV6           179
#define NF_F_FWD_FLOW_DELTA_BYTES	  231
#define NF_F_REV_FLOW_DELTA_BYTES	  232
#define NF_F_EVENT_TIME_MSEC          323
#define NF_F_INGRESS_ACL_ID         33000
#define NF_F_EGRESS_ACL_ID          33001
#define NF_F_FW_EXT_EVENT           33002
#define NF_F_USERNAME               40000

#define NF_F_XLATE_SRC_ADDR_IPV4	  225
#define NF_F_XLATE_DST_ADDR_IPV4	  226
#define NF_F_XLATE_SRC_PORT			  227
#define NF_F_XLATE_DST_PORT			  228
#define NF_F_XLATE_SRC_ADDR_IPV6	  281
#define NF_F_XLATE_DST_ADDR_IPV6	  282
#define NF_F_FW_EVENT				  233

// ASA 8.4 compat elements
#define NF_F_XLATE_SRC_ADDR_84		40001
#define NF_F_XLATE_DST_ADDR_84		40002
#define NF_F_XLATE_SRC_PORT_84      40003
#define NF_F_XLATE_DST_PORT_84      40004
#define NF_F_FW_EVENT_84            40005

// Cisco ASR 1000 series NEL extension - Nat Event Logging
#define NF_N_NAT_EVENT				230
#define NF_N_INGRESS_VRFID			234
#define NF_N_EGRESS_VRFID			235
#define NF_F_XLATE_PORT_BLOCK_START 361
#define NF_F_XLATE_PORT_BLOCK_END   362
#define NF_F_XLATE_PORT_BLOCK_STEP  363
#define NF_F_XLATE_PORT_BLOCK_SIZE  364

// nprobe latency extensions
#define NF9_NPROBE_CLIENT_NW_DELAY_SEC	57554
#define NF9_NPROBE_CLIENT_NW_DELAY_USEC	57555
#define NF9_NPROBE_SERVER_NW_DELAY_SEC	57556
#define NF9_NPROBE_SERVER_NW_DELAY_USEC 57557
#define NF9_NPROBE_APPL_LATENCY_SEC		57558
#define NF9_NPROBE_APPL_LATENCY_USEC	57559

/* prototypes */
int Init_v9(void);

void Process_v9(void *in_buff, ssize_t in_buff_cnt, FlowSource_t *fs);

void Init_v9_output(send_peer_t *peer);

int Add_v9_output_record(master_record_t *master_record, send_peer_t *peer);

#endif //_NETFLOW_V9_H 1
