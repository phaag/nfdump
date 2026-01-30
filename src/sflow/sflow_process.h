/*
 *  Copyright (c) 2023, Peter Haag
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

/* Copyright (c) 2002-2011 InMon Corp. Licensed under the terms of the InMon sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

#ifndef _SFLOW_PROCESS_H
#define _SFLOW_PROCESS_H 1

#include <sys/types.h>

#include "config.h"
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <netinet/in.h>
#include <setjmp.h>

#include "collector.h"
#include "nfdump.h"
#include "sflow.h"

// sflow definition

#define YES 1
#define NO 0

/* define my own IP header struct - to ease portability */
struct myiphdr {
    uint8_t version_and_headerLen;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

/* ip6 header if no option headers */
struct myip6hdr {
    uint8_t version_and_priority;
    uint8_t label1;
    uint8_t label2;
    uint8_t label3;
    uint16_t payloadLength;
    uint8_t nextHeader;
    uint8_t ttl;
    struct in6_addr saddr;
    struct in6_addr daddr;
};

/* same for tcp */
struct mytcphdr {
    uint16_t th_sport; /* source port */
    uint16_t th_dport; /* destination port */
    uint32_t th_seq;   /* sequence number */
    uint32_t th_ack;   /* acknowledgement number */
    uint8_t th_off_and_unused;
    uint8_t th_flags;
    uint16_t th_win; /* window */
    uint16_t th_sum; /* checksum */
    uint16_t th_urp; /* urgent pointer */
};

/* and UDP */
struct myudphdr {
    uint16_t uh_sport; /* source port */
    uint16_t uh_dport; /* destination port */
    uint16_t uh_ulen;  /* udp length */
    uint16_t uh_sum;   /* udp checksum */
};

/* and ICMP */
struct myicmphdr {
    uint8_t type; /* message type */
    uint8_t code; /* type sub-code */
                  /* ignore the rest */
};

/* and GRE (RFC 2890) */
struct mygreheader {        /* only relevant fields */
    uint8_t flags;          /* presence indicators for checksum, key, and sequence number */
    uint8_t version;        /* GRE version */
    uint16_t protocol_type; /* EtherType code for encapsulated protocol */
};

typedef struct _SFSample {
    /* exception handler context */
    jmp_buf env;

    /* the raw pdu */
    uint8_t *rawSample;
    uint32_t rawSampleLen;
    uint8_t *endp;
    time_t readTimestamp;

    /* decode cursor */
    uint32_t *datap;

    /* datagram fields */
    ip128_t sourceIP;  // EX_ROUTER_IP
    SFLAddress agent_addr;
    uint32_t agentSubId;
    uint32_t datagramVersion;
    uint32_t sysUpTime;
    uint32_t sequenceNo;

    /* per sample data */
    uint32_t sampleType;
    uint32_t elementType;
    uint32_t ds_class;
    uint32_t ds_index;

    /* generic interface counter sample */
    SFLIf_counters ifCounters;

    /* sample stream info */
    uint32_t sampledPacketSize;
    uint32_t samplesGenerated;
    uint32_t meanSkipCount;
    uint32_t samplePool;
    uint32_t dropEvents;

    /* the sampled header */
    uint32_t packet_data_tag;
    uint32_t headerProtocol;
    uint8_t *header;
    uint32_t headerLen;
    uint32_t stripped;
    uint32_t *headerDescriptionStart;

    /* header decode */
    int gotIPV4;
    int gotIPV4Struct;
    int offsetToIPV4;
    int gotIPV6;  // v6 flag
    int gotIPV6Struct;
    int offsetToIPV6;
    int offsetToPayload;
    SFLAddress ipsrc;          // Common (v6)
    SFLAddress ipdst;          // Common (v6)
                               // XXX
    struct in_addr dcd_srcIP;  // Common (v4)
    struct in_addr dcd_dstIP;  // Common (v4)
    uint32_t dcd_ipProtocol;   // Common
    uint32_t dcd_ipTos;        // EX_MULIPLE
    uint32_t dcd_ipTTL;
    uint32_t dcd_sport;     // Common
    uint32_t dcd_dport;     // Common
    uint32_t dcd_tcpFlags;  // Common
    uint32_t ip_fragmentOffset;
    uint32_t udp_pduLen;

    /* ports */
    uint32_t inputPortFormat;
    uint32_t outputPortFormat;
    uint32_t inputPort;   // EX_IO_SNMP_4
    uint32_t outputPort;  // EX_IO_SNMP_4

    /* ethernet */
    uint32_t eth_type;
    uint32_t eth_len;
    u_char eth_src[8];  // EX_MAC_1
    u_char eth_dst[8];  // EX_MAC_1

    /* vlan */
    uint32_t in_vlan;  // EX_VLAN
    uint32_t in_priority;
    uint32_t internalPriority;
    uint32_t out_vlan;  // EX_VLAN
    uint32_t out_priority;
    int vlanFilterReject;

    /* mpls */
    int mpls_num_labels;
    uint32_t mpls_label[10];

    /* extended data fields */
    uint32_t num_extended;
    uint32_t extended_data_tag;
#define SASAMPLE_EXTENDED_DATA_SWITCH 1
#define SASAMPLE_EXTENDED_DATA_ROUTER 4
#define SASAMPLE_EXTENDED_DATA_GATEWAY 8
#define SASAMPLE_EXTENDED_DATA_USER 16
#define SASAMPLE_EXTENDED_DATA_URL 32
#define SASAMPLE_EXTENDED_DATA_MPLS 64
#define SASAMPLE_EXTENDED_DATA_NAT 128
#define SASAMPLE_EXTENDED_DATA_MPLS_TUNNEL 256
#define SASAMPLE_EXTENDED_DATA_MPLS_VC 512
#define SASAMPLE_EXTENDED_DATA_MPLS_FTN 1024
#define SASAMPLE_EXTENDED_DATA_MPLS_LDP_FEC 2048
#define SASAMPLE_EXTENDED_DATA_VLAN_TUNNEL 4096
#define SASAMPLE_EXTENDED_DATA_NAT_PORT 8192

    /* IP forwarding info */
    SFLAddress nextHop;  // EX_NEXT_HOP_v4, EX_NEXT_HOP_v6
    uint32_t srcMask;    // EX_MULIPLE
    uint32_t dstMask;    // EX_MULIPLE

    /* BGP info */
    SFLAddress bgp_nextHop;  // EX_NEXT_HOP_BGP_v4, EX_NEXT_HOP_BGP_v6
    uint32_t my_as;
    uint32_t src_as;  // EX_AS_4
    uint32_t src_peer_as;
    uint32_t dst_as_path_len;
    uint32_t *dst_as_path;
    /* note: version 4 dst as path segments just get printed, not stored here, however
     * the dst_peer and dst_as are filled in, since those are used for netflow encoding
     */
    uint32_t dst_peer_as;
    uint32_t dst_as;  // EX_AS_4

    uint32_t communities_len;
    uint32_t *communities;
    uint32_t localpref;

    /* user id */
#define SA_MAX_EXTENDED_USER_LEN 200
    uint32_t src_user_charset;
    uint32_t src_user_len;
    char src_user[SA_MAX_EXTENDED_USER_LEN + 1];
    uint32_t dst_user_charset;
    uint32_t dst_user_len;
    char dst_user[SA_MAX_EXTENDED_USER_LEN + 1];

    /* url */
#define SA_MAX_EXTENDED_URL_LEN 200
#define SA_MAX_EXTENDED_HOST_LEN 200
    uint32_t url_direction;
    uint32_t url_len;
    char url[SA_MAX_EXTENDED_URL_LEN + 1];
    uint32_t host_len;
    char host[SA_MAX_EXTENDED_HOST_LEN + 1];

    /* mpls */
    SFLAddress mpls_nextHop;

    /* nat */
    SFLAddress nat_src;  // EXnatXlateIPv4ID
    SFLAddress nat_dst;
    uint32_t nat_src_port;
    uint32_t nat_dst_port;

    /* counter blocks */
    uint32_t statsSamplingInterval;
    uint32_t counterBlockVersion;

#define SFABORT(s, r) longjmp((s)->env, (r))
#define SF_ABORT_EOS 1
#define SF_ABORT_DECODE_ERROR 2
#define SF_ABORT_LENGTH_ERROR 3

    // tunnels
    int parse_tun;
    SFLAddress tun_ipsrc;
    SFLAddress tun_ipdst;
    uint32_t tun_proto;
} SFSample;

#define sampleDataOffset offsetof(SFSample, sampleType)

void readSFlowDatagram(SFSample *sample, FlowSource_t *fs, int verbose);

#endif  // _SFLOW_PROCESS_H
