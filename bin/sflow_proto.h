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
 *  $Id: sflow_proto.h 39 2009-11-25 08:11:15Z haag $
 *
 *  $LastChangedRevision: 39 $
 *	
 *
 */

/* 
 * sfcapd makes use of code originated from sflowtool by InMon Corp. 
 * Those parts of the code are distributed under the InMon Public License below.
 * All other/additional code is pubblished under BSD license.
 */


/*
 *  ----------------------------------------------------------------------- 
 *         Copyright (c) 2001-2002 InMon Corp.  All rights reserved.
 *  -----------------------------------------------------------------------
 * 
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer. 
 * 
 *  2. Redistributions in binary form must reproduce the above 
 *     copyright notice, this list of conditions and the following 
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 * 
 *  3. Redistributions of any form whatsoever must retain the following
 *     acknowledgment:
 *      "This product includes sFlow(TM), freely available from
 *       http://www.inmon.com/".
 *       
 *  4. All advertising materials mentioning features or use of this
 *     software must display the following acknowledgment:
 *      "This product includes sFlow(TM), freely available from
 *       http://www.inmon.com/".
 * 
 *  5. InMon Corp. may publish revised and/or new versions
 *     of the license from time to time. Each version will be given a
 *     distinguishing version number. Once covered code has been
 *     published under a particular version of the license, you may
 *     always continue to use it under the terms of that version. You
 *     may also choose to use such covered code under the terms of any
 *     subsequent version of the license published by InMon Corp.
 *     No one other than the InMon Corp. has the right to modify the terms
 *     applicable to covered code created under this License.
 *     
 *  6. The name "sFlow" must not be used to endorse or promote products 
 *     derived from this software without prior written permission
 *     from InMon Corp.  This does not apply to add-on libraries or tools
 *     that work in conjunction with sFlow.  In such a case the sFlow name
 *     may be used to indicate that the product supports sFlow.
 * 
 *  7. Products derived from this software may not be called "sFlow",
 *     nor may "sFlow" appear in their name, without prior written
 *     permission of InMon Corp.
 *
 *
 *  THIS SOFTWARE IS PROVIDED BY INMON CORP. ``AS IS'' AND
 *  ANY EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A 
 *  PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL 
 *  INMON CORP. OR ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
 *  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 *  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 *  OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  -------------------------------------------------------------------- 
 *
 *  This software consists of voluntary contributions made by many
 *  individuals on behalf of InMon Corp.
 *
 *  InMon Corp. can be contacted via Email at info@inmon.com.
 *  
 *  For more information on InMon Corp. and sFlow, 
 *  please see http://www.inmon.com/.
 *  
 *  InMon Public License Version 1.0 written May 31, 2001
 *
 */

/////////////////////////////////////////////////////////////////////////////////
/////////////////////// sFlow Sampling Packet Data Types ////////////////////////
/////////////////////////////////////////////////////////////////////////////////

#ifndef _SFLOW_PROTO_H
#define _SFLOW_PROTO_H 1

#if defined(__cplusplus)
extern "C" {
#endif

enum SFLAddress_type {
  SFLADDRESSTYPE_IP_V4 = 1,
  SFLADDRESSTYPE_IP_V6 = 2
};

typedef union _SFLAddress_value {
  struct in_addr ip_v4;
  struct in6_addr ip_v6;
} SFLAddress_value;

typedef struct _SFLAddress {
  uint32_t type;           /* enum SFLAddress_type */
  SFLAddress_value address;
} SFLAddress;

/* Packet header data */

#define SFL_DEFAULT_HEADER_SIZE 128
#define SFL_DEFAULT_COLLECTOR_PORT 6343
#define SFL_DEFAULT_SAMPLING_RATE 400

/* The header protocol describes the format of the sampled header */
enum SFLHeader_protocol {
  SFLHEADER_ETHERNET_ISO8023     = 1,
  SFLHEADER_ISO88024_TOKENBUS    = 2,
  SFLHEADER_ISO88025_TOKENRING   = 3,
  SFLHEADER_FDDI                 = 4,
  SFLHEADER_FRAME_RELAY          = 5,
  SFLHEADER_X25                  = 6,
  SFLHEADER_PPP                  = 7,
  SFLHEADER_SMDS                 = 8,
  SFLHEADER_AAL5                 = 9,
  SFLHEADER_AAL5_IP              = 10, /* e.g. Cisco AAL5 mux */
  SFLHEADER_IPv4                 = 11,
  SFLHEADER_IPv6                 = 12,
  SFLHEADER_MPLS                 = 13
};

/* raw sampled header */

typedef struct _SFLSampled_header {
  uint32_t header_protocol;            /* (enum SFLHeader_protocol) */
  uint32_t frame_length;               /* Original length of packet before sampling */
  uint32_t stripped;                   /* header/trailer bytes stripped by sender */
  uint32_t header_length;              /* length of sampled header bytes to follow */
  uint8_t *header_bytes;               /* Header bytes */
} SFLSampled_header;

/* decoded ethernet header */

typedef struct _SFLSampled_ethernet {
  uint32_t eth_len;       /* The length of the MAC packet excluding 
                             lower layer encapsulations */
  uint8_t src_mac[8];    /* 6 bytes + 2 pad */
  uint8_t dst_mac[8];
  uint32_t eth_type;
} SFLSampled_ethernet;

/* decoded IP version 4 header */

typedef struct _SFLSampled_ipv4 {
  uint32_t length;      /* The length of the IP packet
			    excluding lower layer encapsulations */
  uint32_t protocol;    /* IP Protocol type (for example, TCP = 6, UDP = 17) */
  struct in_addr src_ip; /* Source IP Address */
  struct in_addr dst_ip; /* Destination IP Address */
  uint32_t src_port;    /* TCP/UDP source port number or equivalent */
  uint32_t dst_port;    /* TCP/UDP destination port number or equivalent */
  uint32_t tcp_flags;   /* TCP flags */
  uint32_t tos;         /* IP type of service */
} SFLSampled_ipv4;

/* decoded IP version 6 data */

typedef struct _SFLSampled_ipv6 {
  uint32_t length;       /* The length of the IP packet
			     excluding lower layer encapsulations */
  uint32_t protocol;     /* IP Protocol type (for example, TCP = 6, UDP = 17) */
  struct in6_addr src_ip; /* Source IP Address */
  struct in6_addr dst_ip; /* Destination IP Address */
  uint32_t src_port;     /* TCP/UDP source port number or equivalent */
  uint32_t dst_port;     /* TCP/UDP destination port number or equivalent */
  uint32_t tcp_flags;    /* TCP flags */
  uint32_t priority;     /* IP priority */
} SFLSampled_ipv6;

/* Extended data types */

/* Extended switch data */

typedef struct _SFLExtended_switch {
  uint32_t src_vlan;       /* The 802.1Q VLAN id of incomming frame */
  uint32_t src_priority;   /* The 802.1p priority */
  uint32_t dst_vlan;       /* The 802.1Q VLAN id of outgoing frame */
  uint32_t dst_priority;   /* The 802.1p priority */
} SFLExtended_switch;

/* Extended router data */

typedef struct _SFLExtended_router {
  SFLAddress nexthop;               /* IP address of next hop router */
  uint32_t src_mask;               /* Source address prefix mask bits */
  uint32_t dst_mask;               /* Destination address prefix mask bits */
} SFLExtended_router;

/* Extended gateway data */
enum SFLExtended_as_path_segment_type {
  SFLEXTENDED_AS_SET = 1,      /* Unordered set of ASs */
  SFLEXTENDED_AS_SEQUENCE = 2  /* Ordered sequence of ASs */
};
  
typedef struct _SFLExtended_as_path_segment {
  uint32_t type;   /* enum SFLExtended_as_path_segment_type */
  uint32_t length; /* number of AS numbers in set/sequence */
  union {
    uint32_t *set;
    uint32_t *seq;
  } as;
} SFLExtended_as_path_segment;

typedef struct _SFLExtended_gateway {
  SFLAddress nexthop;                       /* Address of the border router that should
                                               be used for the destination network */
  uint32_t as;                             /* AS number for this gateway */
  uint32_t src_as;                         /* AS number of source (origin) */
  uint32_t src_peer_as;                    /* AS number of source peer */
  uint32_t dst_as_path_segments;           /* number of segments in path */
  SFLExtended_as_path_segment *dst_as_path; /* list of seqs or sets */
  uint32_t communities_length;             /* number of communities */
  uint32_t *communities;                   /* set of communities */
  uint32_t localpref;                      /* LocalPref associated with this route */
} SFLExtended_gateway;

typedef struct _SFLString {
  uint32_t len;
  char *str;
} SFLString;

/* Extended user data */

typedef struct _SFLExtended_user {
  uint32_t src_charset;  /* MIBEnum value of character set used to encode a string - See RFC 2978
			     Where possible UTF-8 encoding (MIBEnum=106) should be used. A value
			     of zero indicates an unknown encoding. */
  SFLString src_user;
  uint32_t dst_charset;
  SFLString dst_user;
} SFLExtended_user;

/* Extended URL data */

enum SFLExtended_url_direction {
  SFLEXTENDED_URL_SRC = 1, /* URL is associated with source address */
  SFLEXTENDED_URL_DST = 2  /* URL is associated with destination address */
};

typedef struct _SFLExtended_url {
  uint32_t direction;   /* enum SFLExtended_url_direction */
  SFLString url;         /* URL associated with the packet flow.
			    Must be URL encoded */
  SFLString host;        /* The host field from the HTTP header */
} SFLExtended_url;

/* Extended MPLS data */

typedef struct _SFLLabelStack {
  uint32_t depth;
  uint32_t *stack; /* first entry is top of stack - see RFC 3032 for encoding */
} SFLLabelStack;

typedef struct _SFLExtended_mpls {
  SFLAddress nextHop;        /* Address of the next hop */ 
  SFLLabelStack in_stack;
  SFLLabelStack out_stack;
} SFLExtended_mpls;

  /* Extended NAT data
     Packet header records report addresses as seen at the sFlowDataSource.
     The extended_nat structure reports on translated source and/or destination
     addesses for this packet. If an address was not translated it should 
     be equal to that reported for the header. */

typedef struct _SFLExtended_nat {
  SFLAddress src;    /* Source address */
  SFLAddress dst;    /* Destination address */
} SFLExtended_nat;

  /* additional Extended MPLS stucts */

typedef struct _SFLExtended_mpls_tunnel {
   SFLString tunnel_lsp_name;  /* Tunnel name */
   uint32_t tunnel_id;        /* Tunnel ID */
   uint32_t tunnel_cos;       /* Tunnel COS value */
} SFLExtended_mpls_tunnel;

typedef struct _SFLExtended_mpls_vc {
   SFLString vc_instance_name; /* VC instance name */
   uint32_t vll_vc_id;        /* VLL/VC instance ID */
   uint32_t vc_label_cos;     /* VC Label COS value */
} SFLExtended_mpls_vc;

/* Extended MPLS FEC
    - Definitions from MPLS-FTN-STD-MIB mplsFTNTable */

typedef struct _SFLExtended_mpls_FTN {
   SFLString mplsFTNDescr;
   uint32_t mplsFTNMask;
} SFLExtended_mpls_FTN;

/* Extended MPLS LVP FEC
    - Definition from MPLS-LDP-STD-MIB mplsFecTable
    Note: mplsFecAddrType, mplsFecAddr information available
          from packet header */

typedef struct _SFLExtended_mpls_LDP_FEC {
   uint32_t mplsFecAddrPrefixLength;
} SFLExtended_mpls_LDP_FEC;

/* Extended VLAN tunnel information 
   Record outer VLAN encapsulations that have 
   been stripped. extended_vlantunnel information 
   should only be reported if all the following conditions are satisfied: 
     1. The packet has nested vlan tags, AND 
     2. The reporting device is VLAN aware, AND 
     3. One or more VLAN tags have been stripped, either 
        because they represent proprietary encapsulations, or 
        because switch hardware automatically strips the outer VLAN 
        encapsulation. 
   Reporting extended_vlantunnel information is not a substitute for 
   reporting extended_switch information. extended_switch data must 
   always be reported to describe the ingress/egress VLAN information 
   for the packet. The extended_vlantunnel information only applies to 
   nested VLAN tags, and then only when one or more tags has been 
   stripped. */ 

typedef SFLLabelStack SFLVlanStack;
typedef struct _SFLExtended_vlan_tunnel { 
  SFLVlanStack stack;  /* List of stripped 802.1Q TPID/TCI layers. Each 
			  TPID,TCI pair is represented as a single 32 bit 
			  integer. Layers listed from outermost to 
			  innermost. */ 
} SFLExtended_vlan_tunnel;


  ////////////////// InMon Extension structs //////////////////////////

typedef struct _SFLProcess {
  uint32_t pid;
  SFLString command;
} SFLProcess;

#define SFL_MAX_PROCESSES 10
typedef struct _SFLExtended_process {
  uint32_t num_processes;
  SFLProcess processes[SFL_MAX_PROCESSES];
} SFLExtended_process;

  //////////////////////////////////////////////////////////////////////

enum SFLFlow_type_tag {
  /* enterprise = 0, format = ... */
  SFLFLOW_HEADER    = 1,      /* Packet headers are sampled */
  SFLFLOW_ETHERNET  = 2,      /* MAC layer information */
  SFLFLOW_IPV4      = 3,      /* IP version 4 data */
  SFLFLOW_IPV6      = 4,      /* IP version 6 data */
  SFLFLOW_EX_SWITCH    = 1001,      /* Extended switch information */
  SFLFLOW_EX_ROUTER    = 1002,      /* Extended router information */
  SFLFLOW_EX_GATEWAY   = 1003,      /* Extended gateway router information */
  SFLFLOW_EX_USER      = 1004,      /* Extended TACAS/RADIUS user information */
  SFLFLOW_EX_URL       = 1005,      /* Extended URL information */
  SFLFLOW_EX_MPLS      = 1006,      /* Extended MPLS information */
  SFLFLOW_EX_NAT       = 1007,      /* Extended NAT information */
  SFLFLOW_EX_MPLS_TUNNEL  = 1008,   /* additional MPLS information */
  SFLFLOW_EX_MPLS_VC      = 1009,
  SFLFLOW_EX_MPLS_FTN     = 1010,
  SFLFLOW_EX_MPLS_LDP_FEC = 1011,
  SFLFLOW_EX_VLAN_TUNNEL  = 1012,   /* VLAN stack */
  /* enterprise = 4300 (inmon)...*/
  SFLFLOW_EX_PROCESS   = (4300 << 12) + 3, /* =17612803 Extended Process information */
};

typedef union _SFLFlow_type {
  SFLSampled_header header;
  SFLSampled_ethernet ethernet;
  SFLSampled_ipv4 ipv4;
  SFLSampled_ipv6 ipv6;
  SFLExtended_switch sw;
  SFLExtended_router router;
  SFLExtended_gateway gateway;
  SFLExtended_user user;
  SFLExtended_url url;
  SFLExtended_mpls mpls;
  SFLExtended_nat nat;
  SFLExtended_mpls_tunnel mpls_tunnel;
  SFLExtended_mpls_vc mpls_vc;
  SFLExtended_mpls_FTN mpls_ftn;
  SFLExtended_mpls_LDP_FEC mpls_ldp_fec;
  SFLExtended_vlan_tunnel vlan_tunnel;
  // extensions
  SFLExtended_process process;
} SFLFlow_type;

typedef struct _SFLFlow_sample_element {
  struct _SFLFlow_sample_element *nxt;
  uint32_t tag;  /* SFLFlow_type_tag */
  uint32_t length;
  SFLFlow_type flowType;
} SFLFlow_sample_element;

enum SFL_sample_tag {
  SFLFLOW_SAMPLE = 1,              /* enterprise = 0 : format = 1 */
  SFLCOUNTERS_SAMPLE = 2,          /* enterprise = 0 : format = 2 */
  SFLFLOW_SAMPLE_EXPANDED = 3,     /* enterprise = 0 : format = 3 */
  SFLCOUNTERS_SAMPLE_EXPANDED = 4  /* enterprise = 0 : format = 4 */
};
  
/* Format of a single flow sample */

typedef struct _SFLFlow_sample {
  /* uint32_t tag;    */         /* SFL_sample_tag -- enterprise = 0 : format = 1 */
  /* uint32_t length; */
  uint32_t sequence_number;      /* Incremented with each flow sample
				     generated */
  uint32_t source_id;            /* fsSourceId */
  uint32_t sampling_rate;        /* fsPacketSamplingRate */
  uint32_t sample_pool;          /* Total number of packets that could have been
				     sampled (i.e. packets skipped by sampling
				     process + total number of samples) */
  uint32_t drops;                /* Number of times a packet was dropped due to
				     lack of resources */
  uint32_t input;                /* SNMP ifIndex of input interface.
				     0 if interface is not known. */
  uint32_t output;               /* SNMP ifIndex of output interface,
				     0 if interface is not known.
				     Set most significant bit to indicate
				     multiple destination interfaces
				     (i.e. in case of broadcast or multicast)
				     and set lower order bits to indicate
				     number of destination interfaces.
				     Examples:
				     0x00000002  indicates ifIndex = 2
				     0x00000000  ifIndex unknown.
				     0x80000007  indicates a packet sent
				     to 7 interfaces.
				     0x80000000  indicates a packet sent to
				     an unknown number of
				     interfaces greater than 1.*/
  uint32_t num_elements;
  SFLFlow_sample_element *elements;
} SFLFlow_sample;

  /* same thing, but the expanded version (for full 32-bit ifIndex numbers) */

typedef struct _SFLFlow_sample_expanded {
  /* uint32_t tag;    */         /* SFL_sample_tag -- enterprise = 0 : format = 1 */
  /* uint32_t length; */
  uint32_t sequence_number;      /* Incremented with each flow sample
				     generated */
  uint32_t ds_class;             /* EXPANDED */
  uint32_t ds_index;             /* EXPANDED */
  uint32_t sampling_rate;        /* fsPacketSamplingRate */
  uint32_t sample_pool;          /* Total number of packets that could have been
				     sampled (i.e. packets skipped by sampling
				     process + total number of samples) */
  uint32_t drops;                /* Number of times a packet was dropped due to
				     lack of resources */
  uint32_t inputFormat;          /* EXPANDED */
  uint32_t input;                /* SNMP ifIndex of input interface.
				     0 if interface is not known. */
  uint32_t outputFormat;         /* EXPANDED */
  uint32_t output;               /* SNMP ifIndex of output interface,
				     0 if interface is not known. */
  uint32_t num_elements;
  SFLFlow_sample_element *elements;
} SFLFlow_sample_expanded;

/* Counter types */

/* Generic interface counters - see RFC 1573, 2233 */

typedef struct _SFLIf_counters {
  uint32_t ifIndex;
  uint32_t ifType;
  uint64_t ifSpeed;
  uint32_t ifDirection;        /* Derived from MAU MIB (RFC 2668)
				   0 = unknown, 1 = full-duplex,
				   2 = half-duplex, 3 = in, 4 = out */
  uint32_t ifStatus;           /* bit field with the following bits assigned:
				   bit 0 = ifAdminStatus (0 = down, 1 = up)
				   bit 1 = ifOperStatus (0 = down, 1 = up) */
  uint64_t ifInOctets;
  uint32_t ifInUcastPkts;
  uint32_t ifInMulticastPkts;
  uint32_t ifInBroadcastPkts;
  uint32_t ifInDiscards;
  uint32_t ifInErrors;
  uint32_t ifInUnknownProtos;
  uint64_t ifOutOctets;
  uint32_t ifOutUcastPkts;
  uint32_t ifOutMulticastPkts;
  uint32_t ifOutBroadcastPkts;
  uint32_t ifOutDiscards;
  uint32_t ifOutErrors;
  uint32_t ifPromiscuousMode;
} SFLIf_counters;

/* Ethernet interface counters - see RFC 2358 */
typedef struct _SFLEthernet_counters {
  uint32_t dot3StatsAlignmentErrors;
  uint32_t dot3StatsFCSErrors;
  uint32_t dot3StatsSingleCollisionFrames;
  uint32_t dot3StatsMultipleCollisionFrames;
  uint32_t dot3StatsSQETestErrors;
  uint32_t dot3StatsDeferredTransmissions;
  uint32_t dot3StatsLateCollisions;
  uint32_t dot3StatsExcessiveCollisions;
  uint32_t dot3StatsInternalMacTransmitErrors;
  uint32_t dot3StatsCarrierSenseErrors;
  uint32_t dot3StatsFrameTooLongs;
  uint32_t dot3StatsInternalMacReceiveErrors;
  uint32_t dot3StatsSymbolErrors;
} SFLEthernet_counters;

/* Token ring counters - see RFC 1748 */

typedef struct _SFLTokenring_counters {
  uint32_t dot5StatsLineErrors;
  uint32_t dot5StatsBurstErrors;
  uint32_t dot5StatsACErrors;
  uint32_t dot5StatsAbortTransErrors;
  uint32_t dot5StatsInternalErrors;
  uint32_t dot5StatsLostFrameErrors;
  uint32_t dot5StatsReceiveCongestions;
  uint32_t dot5StatsFrameCopiedErrors;
  uint32_t dot5StatsTokenErrors;
  uint32_t dot5StatsSoftErrors;
  uint32_t dot5StatsHardErrors;
  uint32_t dot5StatsSignalLoss;
  uint32_t dot5StatsTransmitBeacons;
  uint32_t dot5StatsRecoverys;
  uint32_t dot5StatsLobeWires;
  uint32_t dot5StatsRemoves;
  uint32_t dot5StatsSingles;
  uint32_t dot5StatsFreqErrors;
} SFLTokenring_counters;

/* 100 BaseVG interface counters - see RFC 2020 */

typedef struct _SFLVg_counters {
  uint32_t dot12InHighPriorityFrames;
  uint64_t dot12InHighPriorityOctets;
  uint32_t dot12InNormPriorityFrames;
  uint64_t dot12InNormPriorityOctets;
  uint32_t dot12InIPMErrors;
  uint32_t dot12InOversizeFrameErrors;
  uint32_t dot12InDataErrors;
  uint32_t dot12InNullAddressedFrames;
  uint32_t dot12OutHighPriorityFrames;
  uint64_t dot12OutHighPriorityOctets;
  uint32_t dot12TransitionIntoTrainings;
  uint64_t dot12HCInHighPriorityOctets;
  uint64_t dot12HCInNormPriorityOctets;
  uint64_t dot12HCOutHighPriorityOctets;
} SFLVg_counters;

typedef struct _SFLVlan_counters {
  uint32_t vlan_id;
  uint64_t octets;
  uint32_t ucastPkts;
  uint32_t multicastPkts;
  uint32_t broadcastPkts;
  uint32_t discards;
} SFLVlan_counters;

/* Processor Information */
/* opaque = counter_data; enterprise = 0; format = 1001 */

typedef struct _SFLProcessor_counters {
   uint32_t five_sec_cpu;  /* 5 second average CPU utilization */
   uint32_t one_min_cpu;   /* 1 minute average CPU utilization */
   uint32_t five_min_cpu;  /* 5 minute average CPU utilization */
   uint64_t total_memory;  /* total memory (in bytes) */
   uint64_t free_memory;   /* free memory (in bytes) */
} SFLProcessor_counters;

/* Counters data */

enum SFLCounters_type_tag {
  /* enterprise = 0, format = ... */
  SFLCOUNTERS_GENERIC      = 1,
  SFLCOUNTERS_ETHERNET     = 2,
  SFLCOUNTERS_TOKENRING    = 3,
  SFLCOUNTERS_VG           = 4,
  SFLCOUNTERS_VLAN         = 5,
  SFLCOUNTERS_PROCESSOR    = 1001
};

typedef union _SFLCounters_type {
  SFLIf_counters generic;
  SFLEthernet_counters ethernet;
  SFLTokenring_counters tokenring;
  SFLVg_counters vg;
  SFLVlan_counters vlan;
  SFLProcessor_counters processor;
} SFLCounters_type;

typedef struct _SFLCounters_sample_element {
  struct _SFLCounters_sample_element *nxt; /* linked list */
  uint32_t tag; /* SFLCounters_type_tag */
  uint32_t length;
  SFLCounters_type counterBlock;
} SFLCounters_sample_element;

typedef struct _SFLCounters_sample {
  /* uint32_t tag;    */       /* SFL_sample_tag -- enterprise = 0 : format = 2 */
  /* uint32_t length; */
  uint32_t sequence_number;    /* Incremented with each counters sample
				   generated by this source_id */
  uint32_t source_id;          /* fsSourceId */
  uint32_t num_elements;
  SFLCounters_sample_element *elements;
} SFLCounters_sample;

/* same thing, but the expanded version, so ds_index can be a full 32 bits */
typedef struct _SFLCounters_sample_expanded {
  /* uint32_t tag;    */       /* SFL_sample_tag -- enterprise = 0 : format = 2 */
  /* uint32_t length; */
  uint32_t sequence_number;    /* Incremented with each counters sample
				   generated by this source_id */
  uint32_t ds_class;           /* EXPANDED */
  uint32_t ds_index;           /* EXPANDED */
  uint32_t num_elements;
  SFLCounters_sample_element *elements;
} SFLCounters_sample_expanded;

#define SFLADD_ELEMENT(_sm, _el) do { (_el)->nxt = (_sm)->elements; (_sm)->elements = (_el); } while(0)

/* Format of a sample datagram */

enum SFLDatagram_version {
  SFLDATAGRAM_VERSION2 = 2,
  SFLDATAGRAM_VERSION4 = 4,
  SFLDATAGRAM_VERSION5 = 5
};

typedef struct _SFLSample_datagram_hdr {
  uint32_t datagram_version;      /* (enum SFLDatagram_version) = VERSION5 = 5 */
  SFLAddress agent_address;        /* IP address of sampling agent */
  uint32_t sub_agent_id;          /* Used to distinguishing between datagram
                                      streams from separate agent sub entities
                                      within an device. */
  uint32_t sequence_number;       /* Incremented with each sample datagram
				      generated */
  uint32_t uptime;                /* Current time (in milliseconds since device
				      last booted). Should be set as close to
				      datagram transmission time as possible.*/
  uint32_t num_records;           /* Number of tag-len-val flow/counter records to follow */
} SFLSample_datagram_hdr;

#define SFL_MAX_DATAGRAM_SIZE 1500
#define SFL_MIN_DATAGRAM_SIZE 200
#define SFL_DEFAULT_DATAGRAM_SIZE 1400

#define SFL_DATA_PAD 400

#if defined(__cplusplus)
}  /* extern "C" */
#endif

#endif /* _SFLOW_PROTO_H */
