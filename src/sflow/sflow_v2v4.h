/* Copyright (c) 2002-2011 InMon Corp. Licensed under the terms of the InMon sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

#ifndef SFLOW_V2V4_H
#define SFLOW_V2V4_H 1

#include "config.h"

#include <sys/types.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <sflow.h>

#if defined(__cplusplus)
extern "C" {
#endif

enum INMAddress_type {
  INMADDRESSTYPE_IP_V4 = 1,
  INMADDRESSTYPE_IP_V6 = 2
};

typedef union _INMAddress_value {
  SFLIPv4 ip_v4;
  SFLIPv6 ip_v6;
} INMAddress_value;

typedef struct _INMAddress {
  uint32_t type;           /* enum INMAddress_type */
  INMAddress_value address;
} INMAddress;

/* Packet header data */

#define INM_MAX_HEADER_SIZE 256   /* The maximum sampled header size. */
#define INM_DEFAULT_HEADER_SIZE 128
#define INM_DEFAULT_COLLECTOR_PORT 6343
#define INM_DEFAULT_SAMPLING_RATE 400

/* The header protocol describes the format of the sampled header */
enum INMHeader_protocol {
  INMHEADER_ETHERNET_ISO8023     = 1,
  INMHEADER_ISO88024_TOKENBUS    = 2,
  INMHEADER_ISO88025_TOKENRING   = 3,
  INMHEADER_FDDI                 = 4,
  INMHEADER_FRAME_RELAY          = 5,
  INMHEADER_X25                  = 6,
  INMHEADER_PPP                  = 7,
  INMHEADER_SMDS                 = 8,
  INMHEADER_AAL5                 = 9,
  INMHEADER_AAL5_IP              = 10, /* e.g. Cisco AAL5 mux */
  INMHEADER_IPv4                 = 11,
  INMHEADER_IPv6                 = 12
};

typedef struct _INMSampled_header {
  uint32_t header_protocol;            /* (enum INMHeader_protocol) */
  uint32_t frame_length;               /* Original length of packet before sampling */
  uint32_t header_length;              /* length of sampled header bytes to follow */
  uint8_t header[INM_MAX_HEADER_SIZE]; /* Header bytes */
} INMSampled_header;

/* Packet IP version 4 data */

typedef struct _INMSampled_ipv4 {
  uint32_t length;      /* The length of the IP packet
			    excluding lower layer encapsulations */
  uint32_t protocol;    /* IP Protocol type (for example, TCP = 6, UDP = 17) */
  SFLIPv4 src_ip; /* Source IP Address */
  SFLIPv4 dst_ip; /* Destination IP Address */
  uint32_t src_port;    /* TCP/UDP source port number or equivalent */
  uint32_t dst_port;    /* TCP/UDP destination port number or equivalent */
  uint32_t tcp_flags;   /* TCP flags */
  uint32_t tos;         /* IP type of service */
} INMSampled_ipv4;

/* Packet IP version 6 data */

typedef struct _INMSampled_ipv6 {
  uint32_t length;       /* The length of the IP packet
			     excluding lower layer encapsulations */
  uint32_t protocol;     /* IP Protocol type (for example, TCP = 6, UDP = 17) */
  SFLIPv6 src_ip; /* Source IP Address */
  SFLIPv6 dst_ip; /* Destination IP Address */
  uint32_t src_port;     /* TCP/UDP source port number or equivalent */
  uint32_t dst_port;     /* TCP/UDP destination port number or equivalent */
  uint32_t tcp_flags;    /* TCP flags */
  uint32_t tos;          /* IP type of service */
} INMSampled_ipv6;


/* Packet data */

enum INMPacket_information_type {
  INMPACKETTYPE_HEADER  = 1,      /* Packet headers are sampled */
  INMPACKETTYPE_IPV4    = 2,      /* IP version 4 data */
  INMPACKETTYPE_IPV6    = 3       /* IP version 4 data */
};

typedef union _INMPacket_data_type {
  INMSampled_header header;
  INMSampled_ipv4 ipv4;
  INMSampled_ipv6 ipv6;
} INMPacket_data_type;

/* Extended data types */

/* Extended switch data */

typedef struct _INMExtended_switch {
  uint32_t src_vlan;       /* The 802.1Q VLAN id of incoming frame */
  uint32_t src_priority;   /* The 802.1p priority */
  uint32_t dst_vlan;       /* The 802.1Q VLAN id of outgoing frame */
  uint32_t dst_priority;   /* The 802.1p priority */
} INMExtended_switch;

/* Extended router data */

typedef struct _INMExtended_router {
  INMAddress nexthop;               /* IP address of next hop router */
  uint32_t src_mask;               /* Source address prefix mask bits */
  uint32_t dst_mask;               /* Destination address prefix mask bits */
} INMExtended_router;

/* Extended gateway data */

enum INMExtended_as_path_segment_type {
  INMEXTENDED_AS_SET = 1,      /* Unordered set of ASs */
  INMEXTENDED_AS_SEQUENCE = 2  /* Ordered sequence of ASs */
};
  
typedef struct _INMExtended_as_path_segment {
  uint32_t type;   /* enum INMExtended_as_path_segment_type */
  uint32_t length; /* number of AS numbers in set/sequence */
  union {
    uint32_t *set;
    uint32_t *seq;
  } as;
} INMExtended_as_path_segment;

/* note: the INMExtended_gateway structure has changed between v2 and v4.
   Here is the old version first... */

typedef struct _INMExtended_gateway_v2 {
  uint32_t as;                             /* AS number for this gateway */
  uint32_t src_as;                         /* AS number of source (origin) */
  uint32_t src_peer_as;                    /* AS number of source peer */
  uint32_t dst_as_path_length;             /* number of AS numbers in path */
  uint32_t *dst_as_path;
} INMExtended_gateway_v2;

/* now here is the new version... */

typedef struct _INMExtended_gateway_v4 {
  uint32_t as;                             /* AS number for this gateway */
  uint32_t src_as;                         /* AS number of source (origin) */
  uint32_t src_peer_as;                    /* AS number of source peer */
  uint32_t dst_as_path_segments;           /* number of segments in path */
  INMExtended_as_path_segment *dst_as_path; /* list of seqs or sets */
  uint32_t communities_length;             /* number of communities */
  uint32_t *communities;                   /* set of communities */
  uint32_t localpref;                      /* LocalPref associated with this route */
} INMExtended_gateway_v4;

/* Extended user data */
typedef struct _INMExtended_user {
  uint32_t src_user_len;
  char *src_user;
  uint32_t dst_user_len;
  char *dst_user;
} INMExtended_user;
enum INMExtended_url_direction {
  INMEXTENDED_URL_SRC = 1, /* URL is associated with source address */
  INMEXTENDED_URL_DST = 2  /* URL is associated with destination address */
};

typedef struct _INMExtended_url {
  uint32_t direction; /* enum INMExtended_url_direction */
  uint32_t url_len;
  char *url;
} INMExtended_url;

/* Extended data */

enum INMExtended_information_type {
  INMEXTENDED_SWITCH    = 1,      /* Extended switch information */
  INMEXTENDED_ROUTER    = 2,      /* Extended router information */
  INMEXTENDED_GATEWAY   = 3,      /* Extended gateway router information */
  INMEXTENDED_USER      = 4,      /* Extended TACAS/RADIUS user information */
  INMEXTENDED_URL       = 5       /* Extended URL information */
};

/* Format of a single sample */

typedef struct _INMFlow_sample {
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
  uint32_t packet_data_tag;       /* enum INMPacket_information_type */
  INMPacket_data_type packet_data; /* Information about sampled packet */

  /* in the sFlow packet spec the next field is the number of extended objects
     followed by the data for each one (tagged with the type).  Here we just
     provide space for each one, and flags to enable them.  The correct format
     is then put together by the serialization code */
  int gotSwitch;
  INMExtended_switch switchDevice;
  int gotRouter;
  INMExtended_router router;
  int gotGateway;
  union {
    INMExtended_gateway_v2 v2;  /* make the version explicit so that there is */
    INMExtended_gateway_v4 v4;  /* less danger of mistakes when upgrading code */
  } gateway;
  int gotUser;
  INMExtended_user user;
  int gotUrl;
  INMExtended_url url;
} INMFlow_sample;

/* Counter types */

/* Generic interface counters - see RFC 1573, 2233 */

typedef struct _INMIf_counters {
  uint32_t ifIndex;
  uint32_t ifType;
  uint64_t ifSpeed;
  uint32_t ifDirection;        /* Derived from MAU MIB (RFC 2239)
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
} INMIf_counters;

/* Ethernet interface counters - see RFC 2358 */
typedef struct _INMEthernet_specific_counters {
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
} INMEthernet_specific_counters;

typedef struct _INMEthernet_counters {
  INMIf_counters generic;
  INMEthernet_specific_counters ethernet;
} INMEthernet_counters;

/* FDDI interface counters - see RFC 1512 */
typedef struct _INMFddi_counters {
  INMIf_counters generic;
} INMFddi_counters;

/* Token ring counters - see RFC 1748 */

typedef struct _INMTokenring_specific_counters {
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
} INMTokenring_specific_counters;

typedef struct _INMTokenring_counters {
  INMIf_counters generic;
  INMTokenring_specific_counters tokenring;
} INMTokenring_counters;

/* 100 BaseVG interface counters - see RFC 2020 */

typedef struct _INMVg_specific_counters {
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
} INMVg_specific_counters;

typedef struct _INMVg_counters {
  INMIf_counters generic;
  INMVg_specific_counters vg;
} INMVg_counters;

/* WAN counters */

typedef struct _INMWan_counters {
  INMIf_counters generic;
} INMWan_counters;

typedef struct _INMVlan_counters {
  uint32_t vlan_id;
  uint64_t octets;
  uint32_t ucastPkts;
  uint32_t multicastPkts;
  uint32_t broadcastPkts;
  uint32_t discards;
} INMVlan_counters;

/* Counters data */

enum INMCounters_version {
  INMCOUNTERSVERSION_GENERIC      = 1,
  INMCOUNTERSVERSION_ETHERNET     = 2,
  INMCOUNTERSVERSION_TOKENRING    = 3,
  INMCOUNTERSVERSION_FDDI         = 4,
  INMCOUNTERSVERSION_VG           = 5,
  INMCOUNTERSVERSION_WAN          = 6,
  INMCOUNTERSVERSION_VLAN         = 7
};

typedef union _INMCounters_type {
  INMIf_counters generic;
  INMEthernet_counters ethernet;
  INMTokenring_counters tokenring;
  INMFddi_counters fddi;
  INMVg_counters vg;
  INMWan_counters wan;
  INMVlan_counters vlan;
} INMCounters_type;

typedef struct _INMCounters_sample_hdr {
  uint32_t sequence_number;    /* Incremented with each counters sample
				   generated by this source_id */
  uint32_t source_id;          /* fsSourceId */
  uint32_t sampling_interval;  /* fsCounterSamplingInterval */
} INMCounters_sample_hdr;

typedef struct _INMCounters_sample {
  INMCounters_sample_hdr hdr;
  uint32_t counters_type_tag;  /* Enum INMCounters_version */
  INMCounters_type counters;    /* Counter set for this interface type */
} INMCounters_sample;

/* when I turn on optimisation with the Microsoft compiler it seems to change
   the values of these enumerated types and break the program - not sure why */
enum INMSample_types {
   FLOWSAMPLE  = 1,
   COUNTERSSAMPLE = 2
};

typedef union _INMSample_type {
  INMFlow_sample flowsample;
  INMCounters_sample counterssample;
} INMSample_type;

/* Format of a sample datagram */

enum INMDatagram_version {
  INMDATAGRAM_VERSION2 = 2,
  INMDATAGRAM_VERSION4 = 4
};

typedef struct _INMSample_datagram_hdr {
  uint32_t datagram_version;      /* (enum INMDatagram_version) = VERSION4 */
  INMAddress agent_address;        /* IP address of sampling agent */
  uint32_t sequence_number;       /* Incremented with each sample datagram
				      generated */
  uint32_t uptime;                /* Current time (in milliseconds since device
				      last booted). Should be set as close to
				      datagram transmission time as possible.*/
  uint32_t num_samples;           /* Number of flow and counters samples to follow */
} INMSample_datagram_hdr;

#define INM_MAX_DATAGRAM_SIZE 1500
#define INM_MIN_DATAGRAM_SIZE 200
#define INM_DEFAULT_DATAGRAM_SIZE 1400

#define INM_DATA_PAD 400

#if defined(__cplusplus)
}  /* extern "C" */
#endif

#endif /* SFLOW_V2V4_H */
