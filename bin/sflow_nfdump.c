/*
 *  Copyright (c) 2017, Peter Haag
 *  Copyright (c) 2016, Peter Haag
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

#include "config.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <time.h>
#include <ctype.h>
#include <setjmp.h>

#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nffile.h"
#include "nfx.h"
#include "nf_common.h"
#include "util.h"
#include "bookkeeper.h"
#include "collector.h"

#include "sflow.h" /* sFlow v5 */
#include "sflow_v2v4.h" /* sFlow v2/4 */
#include "sflow_nfdump.h"


/*
#ifdef DARWIN
#include <architecture/byte_order.h>
#define bswap_16(x) NXSwapShort(x)
#define bswap_32(x) NXSwapInt(x)
#else
#include <byteswap.h>
#endif
*/

#ifndef DEVEL
#   define dbg_printf(...) /* printf(__VA_ARGS__) */
#else
#   define dbg_printf(...) printf(__VA_ARGS__)
#endif

#define MAX_SFLOW_EXTENSIONS 8

typedef struct exporter_sflow_s {
	// link chain
	struct exporter_sflow_s *next;

	// generic exporter information
	exporter_info_record_t info;

    uint64_t    packets;            // number of packets sent by this exporter
    uint64_t    flows;              // number of flow records sent by this exporter
    uint32_t    sequence_failure;   // number of sequence failues

    generic_sampler_t       *sampler;

	// extension map
	// extension maps are common for all exporters
	extension_info_t sflow_extension_info[MAX_SFLOW_EXTENSIONS];

} exporter_sflow_t;

extern extension_descriptor_t extension_descriptor[];
extern FlowSource_t *FlowSource;

/* module limited globals */

/*
 * As sflow has no templates, we need to have an extension map for each possible
 * combination of IPv4/IPv6 addresses in all ip fields
 *
 * index id:
 * 0 : EX_NEXT_HOP_v4, EX_NEXT_HOP_BGP_v4, EX_ROUTER_IP_v4
 * 1 : EX_NEXT_HOP_v6, EX_NEXT_HOP_BGP_v4, EX_ROUTER_IP_v4
 * 2 : EX_NEXT_HOP_v4, EX_NEXT_HOP_BGP_v6, EX_ROUTER_IP_v4
 * 3 : EX_NEXT_HOP_v6, EX_NEXT_HOP_BGP_v6, EX_ROUTER_IP_v4
 * 4 : EX_NEXT_HOP_v4, EX_NEXT_HOP_BGP_v4, EX_ROUTER_IP_v6
 * 5 : EX_NEXT_HOP_v6, EX_NEXT_HOP_BGP_v4, EX_ROUTER_IP_v6
 * 6 : EX_NEXT_HOP_v4, EX_NEXT_HOP_BGP_v6, EX_ROUTER_IP_v6
 * 7 : EX_NEXT_HOP_v6, EX_NEXT_HOP_BGP_v6, EX_ROUTER_IP_v6
 */
static uint16_t sflow_output_record_size[MAX_SFLOW_EXTENSIONS];

// All available extensions for sflow
static uint16_t sflow_extensions[] = { 
	EX_IO_SNMP_4, 
	EX_AS_4, 
	EX_MULIPLE, 
	EX_VLAN, 
	EX_MAC_1, 
	EX_RECEIVED,
	0 			// final token
};
static int Num_enabled_extensions;

static struct sflow_ip_extensions_s {
	int next_hop;
	int next_hop_bgp;
	int router_ip;
} sflow_ip_extensions[] = {
	{ EX_NEXT_HOP_v4, EX_NEXT_HOP_BGP_v4, EX_ROUTER_IP_v4 },
	{ EX_NEXT_HOP_v6, EX_NEXT_HOP_BGP_v4, EX_ROUTER_IP_v4 },
	{ EX_NEXT_HOP_v4, EX_NEXT_HOP_BGP_v6, EX_ROUTER_IP_v4 },
	{ EX_NEXT_HOP_v6, EX_NEXT_HOP_BGP_v6, EX_ROUTER_IP_v4 },
	{ EX_NEXT_HOP_v4, EX_NEXT_HOP_BGP_v4, EX_ROUTER_IP_v6 },
	{ EX_NEXT_HOP_v6, EX_NEXT_HOP_BGP_v4, EX_ROUTER_IP_v6 },
	{ EX_NEXT_HOP_v4, EX_NEXT_HOP_BGP_v6, EX_ROUTER_IP_v6 },
	{ EX_NEXT_HOP_v6, EX_NEXT_HOP_BGP_v6, EX_ROUTER_IP_v6 },
};

#define SFLOW_NEXT_HOP 	   1
#define SFLOW_NEXT_HOP_BGP 2
#define SFLOW_ROUTER_IP    4
static int IP_extension_mask = 0;

static inline exporter_sflow_t *GetExporter(FlowSource_t *fs, uint32_t agentSubId, uint32_t meanSkipCount);

/* 
 * unused
//
static uint32_t MyByteSwap32(uint32_t n) {
	return (((n & 0x000000FF)<<24) +
		((n & 0x0000FF00)<<8) +
		((n & 0x00FF0000)>>8) +
		((n & 0xFF000000)>>24));
}

static uint16_t MyByteSwap16(uint16_t n) {
	return ((n >> 8) | (n << 8));
}
*/

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
		uint16_t th_sport;		/* source port */
		uint16_t th_dport;		/* destination port */
		uint32_t th_seq;		/* sequence number */
		uint32_t th_ack;		/* acknowledgement number */
		uint8_t th_off_and_unused;
		uint8_t th_flags;
		uint16_t th_win;		/* window */
		uint16_t th_sum;		/* checksum */
		uint16_t th_urp;		/* urgent pointer */
};

/* and UDP */
struct myudphdr {
	uint16_t uh_sport;           /* source port */
	uint16_t uh_dport;           /* destination port */
	uint16_t uh_ulen;            /* udp length */
	uint16_t uh_sum;             /* udp checksum */
};

/* and ICMP */
struct myicmphdr {
	uint8_t type;		/* message type */
	uint8_t code;		/* type sub-code */
	/* ignore the rest */
};

typedef struct _SFForwardingTarget {
	struct _SFForwardingTarget *nxt;
	struct in_addr host;
	uint32_t port;
	struct sockaddr_in addr;
	int sock;
} SFForwardingTarget;

typedef enum { SFLFMT_FULL=0, SFLFMT_PCAP, SFLFMT_LINE } EnumSFLFormat;

typedef struct _SFSample {
	/* exception handler context */
	jmp_buf env;

	struct in_addr sourceIP;		// EX_ROUTER_IP_v4

	SFLAddress agent_addr;
	uint32_t agentSubId;

	/* the raw pdu */
	uint8_t *rawSample;
	uint32_t rawSampleLen;
	uint8_t *endp;
	time_t readTimestamp;

	/* decode cursor */
	uint32_t *datap;

	uint32_t datagramVersion;
	uint32_t sampleType;
	uint32_t elementType;
	uint32_t ds_class;
	uint32_t ds_index;

	/* generic interface counter sample */
	SFLIf_counters ifCounters;

	/* sample stream info */
	uint32_t sysUpTime;
	uint32_t sequenceNo;
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

	/* header decode */
	int gotIPV4;
	int gotIPV4Struct;
	int offsetToIPV4;
	int gotIPV6;				// v6 flag
	int gotIPV6Struct;
	int offsetToIPV6;
	int offsetToPayload;
	SFLAddress ipsrc;			// Common (v6)
	SFLAddress ipdst;			// Common (v6)
// XXX
	struct in_addr dcd_srcIP;	// Common (v4)
	struct in_addr dcd_dstIP;	// Common (v4)
	uint32_t dcd_ipProtocol;	// Common
	uint32_t dcd_ipTos;			// EX_MULIPLE
	uint32_t dcd_ipTTL;
	uint32_t dcd_sport;			// Common
	uint32_t dcd_dport;			// Common
	uint32_t dcd_tcpFlags;		// Common
	uint32_t ip_fragmentOffset;
	uint32_t udp_pduLen;

	/* ports */
	uint32_t inputPortFormat;
	uint32_t outputPortFormat;
	uint32_t inputPort;			// EX_IO_SNMP_4
	uint32_t outputPort;		// EX_IO_SNMP_4

	/* ethernet */
	uint32_t eth_type;
	uint32_t eth_len;
	u_char eth_src[8];			// EX_MAC_1
	u_char eth_dst[8];			// EX_MAC_1

	/* vlan */
	uint32_t in_vlan;			// EX_VLAN
	uint32_t in_priority;
	uint32_t internalPriority;
	uint32_t out_vlan;			// EX_VLAN
	uint32_t out_priority;
	int vlanFilterReject;

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
	SFLAddress nextHop;			// EX_NEXT_HOP_v4, EX_NEXT_HOP_v6
	uint32_t srcMask;			// EX_MULIPLE
	uint32_t dstMask;			// EX_MULIPLE

	/* BGP info */
	SFLAddress bgp_nextHop;		// EX_NEXT_HOP_BGP_v4, EX_NEXT_HOP_BGP_v6
	uint32_t my_as;
	uint32_t src_as;			// EX_AS_4
	uint32_t src_peer_as;
	uint32_t dst_as_path_len;
	uint32_t *dst_as_path;
	/* note: version 4 dst as path segments just get printed, not stored here, however
	 * the dst_peer and dst_as are filled in, since those are used for netflow encoding
	 */
	uint32_t dst_peer_as;
	uint32_t dst_as;			// EX_AS_4
	
	uint32_t communities_len;
	uint32_t *communities;
	uint32_t localpref;

	/* user id */
#define SA_MAX_EXTENDED_USER_LEN 200
	uint32_t src_user_charset;
	uint32_t src_user_len;
	char src_user[SA_MAX_EXTENDED_USER_LEN+1];
	uint32_t dst_user_charset;
	uint32_t dst_user_len;
	char dst_user[SA_MAX_EXTENDED_USER_LEN+1];

	/* url */
#define SA_MAX_EXTENDED_URL_LEN 200
#define SA_MAX_EXTENDED_HOST_LEN 200
	uint32_t url_direction;
	uint32_t url_len;
	char url[SA_MAX_EXTENDED_URL_LEN+1];
	uint32_t host_len;
	char host[SA_MAX_EXTENDED_HOST_LEN+1];

	/* mpls */
	SFLAddress mpls_nextHop;

	/* nat */
	SFLAddress nat_src;
	SFLAddress nat_dst;

	/* counter blocks */
	uint32_t statsSamplingInterval;
	uint32_t counterBlockVersion;

#define SFABORT(s, r) longjmp((s)->env, (r))
#define SF_ABORT_EOS 1
#define SF_ABORT_DECODE_ERROR 2
#define SF_ABORT_LENGTH_ERROR 3

} SFSample;

int Setup_Extension_Info(FlowSource_t *fs, exporter_sflow_t	*exporter, int num);

static int printHex(const u_char *a, int len, char *buf, int bufLen, int marker, int bytesPerOutputLine);

static char *IP_to_a(uint32_t ipaddr, char *buf, int buflen);

static inline uint32_t getData32(SFSample *sample);

static inline uint32_t getData32_nobswap(SFSample *sample);

static inline uint64_t getData64(SFSample *sample);

static void writeCountersLine(SFSample *sample);

static void receiveError(SFSample *sample, char *errm, int hexdump) __attribute__ ((noreturn));

static inline void skipBytes(SFSample *sample, uint32_t skip);

static inline uint32_t sf_log_next32(SFSample *sample, char *fieldName);

static inline uint64_t sf_log_next64(SFSample *sample, char *fieldName);

static inline void sf_log_nextMAC(SFSample *sample, char *fieldName);

static inline void sf_log_percentage(SFSample *sample, char *fieldName);

static inline uint32_t getString(SFSample *sample, char *buf, uint32_t bufLen);

static inline uint32_t getAddress(SFSample *sample, SFLAddress *address);

static inline void skipTLVRecord(SFSample *sample, uint32_t tag, uint32_t len, char *description);

static inline void readSFlowDatagram(SFSample *sample, FlowSource_t *fs);

static inline void readFlowSample(SFSample *sample, int expanded, FlowSource_t *fs);

static inline void readCountersSample(SFSample *sample, int expanded, FlowSource_t *fs);

static inline void readFlowSample_header(SFSample *sample);

static inline void readFlowSample_v2v4(SFSample *sample, FlowSource_t *fs);

static inline void readCountersSample_v2v4(SFSample *sample, FlowSource_t *fs);

static inline void StoreSflowRecord(SFSample *sample, FlowSource_t *fs);

#ifdef DEVEL
static char *URLEncode(char *in, char *out, int outlen);
#endif

static int printUUID(const uint8_t *a, char *buf, int bufLen);

extern int verbose;

#ifdef DEVEL
static inline char *printTag(uint32_t tag, char *buf, int bufLen);

static inline char *printTag(uint32_t tag, char *buf, int bufLen) {
    snprintf(buf, bufLen, "%u:%u", (tag >> 12), (tag & 0x00000FFF));
    return buf;
} // End of printTag

#endif


/*_________________---------------------------__________________
	_________________        printHex           __________________
	-----------------___________________________------------------
*/

static u_char bin2hex(int nib) { return (nib < 10) ? ('0' + nib) : ('A' - 10 + nib); }

static int printHex(const u_char *a, int len, char *buf, int bufLen, int marker, int bytesPerOutputLine) {
	int b = 0, i = 0;
	for(; i < len; i++) {
		u_char byte;
		if(b > (bufLen - 10)) break;
		if(marker > 0 && i == marker) {
			buf[b++] = '<';
			buf[b++] = '*';
			buf[b++] = '>';
			buf[b++] = '-';
		}
		byte = a[i];
		buf[b++] = bin2hex(byte >> 4);
		buf[b++] = bin2hex(byte & 0x0f);
		if(i > 0 && (i % bytesPerOutputLine) == 0) buf[b++] = '\n';
		else {
			// separate the bytes with a dash
			if (i < (len - 1)) buf[b++] = '-';
		}
	}
	buf[b] = '\0';
	return b;
}

/*_________________---------------------------__________________
	_________________      IP_to_a              __________________
	-----------------___________________________------------------
*/

static char *IP_to_a(uint32_t ipaddr, char *buf, int buflen) {
	u_char *ip = (u_char *)&ipaddr;
	snprintf(buf, buflen, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
	buf[buflen-1] = '\0';
	return buf;
}

static char *printAddress(SFLAddress *address, char *buf, int bufLen) {
  switch(address->type) {
  	case SFLADDRESSTYPE_IP_V4:
		IP_to_a(address->address.ip_v4.addr, buf, bufLen);
		break;
  	case SFLADDRESSTYPE_IP_V6: {
		u_char *b = address->address.ip_v6.addr;
		snprintf(buf, bufLen, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
			b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
	} break;
	default:
    	sprintf(buf, "-");
  	}
	return buf;
}

/*_________________---------------------------__________________
	_________________    writeFlowLine          __________________
	-----------------___________________________------------------
*/

static void writeFlowLine(SFSample *sample) {
char agentIP[51], srcIP[51], dstIP[51];
	// source
	printf("FLOW,%s,%d,%d,",
	 printAddress(&sample->agent_addr, agentIP, 50),
	 sample->inputPort,
	 sample->outputPort);
	// layer 2
	printf("%02x%02x%02x%02x%02x%02x,%02x%02x%02x%02x%02x%02x,0x%04x,%d,%d",
	 sample->eth_src[0],
	 sample->eth_src[1],
	 sample->eth_src[2],
	 sample->eth_src[3],
	 sample->eth_src[4],
	 sample->eth_src[5],
	 sample->eth_dst[0],
	 sample->eth_dst[1],
	 sample->eth_dst[2],
	 sample->eth_dst[3],
	 sample->eth_dst[4],
	 sample->eth_dst[5],
	 sample->eth_type,
	 sample->in_vlan,
	 sample->out_vlan);
	// layer 3/4
	printf(",IP: %s,%s,%d,0x%02x,%d,%d,%d,0x%02x",
	IP_to_a(sample->dcd_srcIP.s_addr, srcIP, 51),
	IP_to_a(sample->dcd_dstIP.s_addr, dstIP, 51),
	sample->dcd_ipProtocol,
	sample->dcd_ipTos,	
	sample->dcd_ipTTL,
	sample->dcd_sport,
	sample->dcd_dport,
	sample->dcd_tcpFlags);
	// bytes
	printf(",%d,%d,%d\n",
	 sample->sampledPacketSize,
	 sample->sampledPacketSize - sample->stripped - sample->offsetToIPV4,
	 sample->meanSkipCount);
}

/*_________________---------------------------__________________
	_________________    writeCountersLine      __________________
	-----------------___________________________------------------
*/

static void writeCountersLine(SFSample *sample)
{
	// source
	char agentIP[51];
	printf("CNTR,%s,", printAddress(&sample->agent_addr, agentIP, 50));
	printf("%u,%u,%llu,%u,%u,%llu,%u,%u,%u,%u,%u,%u,%llu,%u,%u,%u,%u,%u,%u\n",
	 sample->ifCounters.ifIndex,
	 sample->ifCounters.ifType,
	 (unsigned long long)sample->ifCounters.ifSpeed,
	 sample->ifCounters.ifDirection,
	 sample->ifCounters.ifStatus,
	 (unsigned long long)sample->ifCounters.ifInOctets,
	 sample->ifCounters.ifInUcastPkts,
	 sample->ifCounters.ifInMulticastPkts,
	 sample->ifCounters.ifInBroadcastPkts,
	 sample->ifCounters.ifInDiscards,
	 sample->ifCounters.ifInErrors,
	 sample->ifCounters.ifInUnknownProtos,
	 (unsigned long long)sample->ifCounters.ifOutOctets,
	 sample->ifCounters.ifOutUcastPkts,
	 sample->ifCounters.ifOutMulticastPkts,
	 sample->ifCounters.ifOutBroadcastPkts,
	 sample->ifCounters.ifOutDiscards,
	 sample->ifCounters.ifOutErrors,
	 sample->ifCounters.ifPromiscuousMode);
}

/*_________________---------------------------__________________
	_________________    receiveError           __________________
	-----------------___________________________------------------
*/

static void receiveError(SFSample *sample, char *errm, int hexdump) 
{
	char ipbuf[51];
	char scratch[6000];
	char *msg = "";
	char *hex = "";
	uint32_t markOffset = (u_char *)sample->datap - sample->rawSample;
	if(errm) msg = errm;
	if(hexdump) {
		printHex(sample->rawSample, sample->rawSampleLen, scratch, 6000, markOffset, 16);
		hex = scratch;
	}
	LogError("SFLOW: %s (source IP = %s) %s", msg, IP_to_a(sample->sourceIP.s_addr, ipbuf, 51), hex);

	SFABORT(sample, SF_ABORT_DECODE_ERROR);

}

/*_________________---------------------------__________________
	_________________    lengthCheck            __________________
	-----------------___________________________------------------
*/

static void lengthCheck(SFSample *sample, char *description, u_char *start, int len) {
	uint32_t actualLen = (u_char *)sample->datap - start;
	uint32_t adjustedLen = ((len + 3) >> 2) << 2;
	if(actualLen != adjustedLen) {
		dbg_printf("%s length error (expected %d, found %d)\n", description, len, actualLen);
		LogError("SFLOW: %s length error (expected %d, found %d)", description, len, actualLen);
		SFABORT(sample, SF_ABORT_LENGTH_ERROR);
  }

}

/*_________________---------------------------__________________
	_________________     decodeLinkLayer       __________________
	-----------------___________________________------------------
	store the offset to the start of the ipv4 header in the sequence_number field
	or -1 if not found. Decode the 802.1d if it's there.
*/

#define NFT_ETHHDR_SIZ 14
#define NFT_8022_SIZ 3
#define NFT_MAX_8023_LEN 1500

#define NFT_MIN_SIZ (NFT_ETHHDR_SIZ + sizeof(struct myiphdr))

static void decodeLinkLayer(SFSample *sample)
{
  uint8_t *start = sample->header;
  uint8_t *end = start + sample->headerLen;
  uint8_t *ptr = start;
  uint16_t type_len;

  /* assume not found */
  sample->gotIPV4 = NO;
  sample->gotIPV6 = NO;

  if((end - ptr) < NFT_ETHHDR_SIZ) return; /* not enough for an Ethernet header */

  dbg_printf("dstMAC %02x%02x%02x%02x%02x%02x\n", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
  memcpy(sample->eth_dst, ptr, 6);
  ptr += 6;
  dbg_printf("srcMAC %02x%02x%02x%02x%02x%02x\n", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
  memcpy(sample->eth_src, ptr, 6);
  ptr += 6;
  type_len = (ptr[0] << 8) + ptr[1];
  ptr += 2;

  if(type_len == 0x8100) {
    if((end - ptr) < 4) return; /* not enough for an 802.1Q header */
    /* VLAN  - next two bytes */
    uint32_t vlanData = (ptr[0] << 8) + ptr[1];
    uint32_t vlan = vlanData & 0x0fff;
#ifdef DEVEL
    uint32_t priority = vlanData >> 13;
#endif
    ptr += 2;
    /*  _____________________________________ */
    /* |   pri  | c |         vlan-id        | */
    /*  ------------------------------------- */
    /* [priority = 3bits] [Canonical Format Flag = 1bit] [vlan-id = 12 bits] */
    dbg_printf("decodedVLAN %u\n", vlan);
    dbg_printf("decodedPriority %u\n", priority);
    sample->in_vlan = vlan;
    /* now get the type_len again (next two bytes) */
    type_len = (ptr[0] << 8) + ptr[1];
    ptr += 2;
  }

  /* now we're just looking for IP */
  if((end - start) < sizeof(struct myiphdr)) return; /* not enough for an IPv4 header (or IPX, or SNAP) */

  /* peek for IPX */
  if(type_len == 0x0200 || type_len == 0x0201 || type_len == 0x0600) {
#define IPX_HDR_LEN 30
#define IPX_MAX_DATA 546
    int ipxChecksum = (ptr[0] == 0xff && ptr[1] == 0xff);
    int ipxLen = (ptr[2] << 8) + ptr[3];
    if(ipxChecksum &&
       ipxLen >= IPX_HDR_LEN &&
       ipxLen <= (IPX_HDR_LEN + IPX_MAX_DATA))
      /* we don't do anything with IPX here */
      return;
  }
  if(type_len <= NFT_MAX_8023_LEN) {
    /* assume 802.3+802.2 header */
    /* check for SNAP */
    if(ptr[0] == 0xAA &&
       ptr[1] == 0xAA &&
       ptr[2] == 0x03) {
      ptr += 3;
      if(ptr[0] != 0 ||
	 ptr[1] != 0 ||
	 ptr[2] != 0) {
	dbg_printf("VSNAP_OUI %02X-%02X-%02X\n", ptr[0], ptr[1], ptr[2]);
	return; /* no further decode for vendor-specific protocol */
      }
      ptr += 3;
      /* OUI == 00-00-00 means the next two bytes are the ethernet type (RFC 2895) */
      type_len = (ptr[0] << 8) + ptr[1];
      ptr += 2;
    }
    else {
      if (ptr[0] == 0x06 &&
	  ptr[1] == 0x06 &&
	  (ptr[2] & 0x01)) {
	/* IP over 8022 */
	ptr += 3;
	/* force the type_len to be IP so we can inline the IP decode below */
	type_len = 0x0800;
      }
      else return;
    }
  }

  /* assume type_len is an ethernet-type now */
  sample->eth_type = type_len;

  if(type_len == 0x0800) {
    /* IPV4 - check again that we have enough header bytes */
    if((end - ptr) < sizeof(struct myiphdr)) return;
    /* look at first byte of header.... */
    /*  ___________________________ */
    /* |   version   |    hdrlen   | */
    /*  --------------------------- */
    if((*ptr >> 4) != 4) return; /* not version 4 */
    if((*ptr & 15) < 5) return; /* not IP (hdr len must be 5 quads or more) */
    /* survived all the tests - store the offset to the start of the ip header */
    sample->gotIPV4 = YES;
    sample->offsetToIPV4 = (ptr - start);
  }

  if(type_len == 0x86DD) {
    /* IPV6 */
    /* look at first byte of header.... */
    if((*ptr >> 4) != 6) return; /* not version 6 */
    /* survived all the tests - store the offset to the start of the ip6 header */
    sample->gotIPV6 = YES;
    sample->offsetToIPV6 = (ptr - start);
  }
}

#define WIFI_MIN_HDR_SIZ 24

static void decode80211MAC(SFSample *sample)
{
  uint8_t *start = sample->header;
//  uint8_t *end = start + sample->headerLen;
  uint8_t *ptr = start;

  /* assume not found */
  sample->gotIPV4 = NO;
  sample->gotIPV6 = NO;

  if(sample->headerLen < WIFI_MIN_HDR_SIZ) return; /* not enough for an 80211 MAC header */

  uint32_t fc = (ptr[1] << 8) + ptr[0];  /* [b7..b0][b15..b8] */
  uint32_t control = (fc >> 2) & 3;
  uint32_t toDS = (fc >> 8) & 1;
  uint32_t fromDS = (fc >> 9) & 1;
/* not used
uint32_t protocolVersion = fc & 3;
uint32_t subType = (fc >> 4) & 15;
uint32_t moreFrag = (fc >> 10) & 1;
uint32_t retry = (fc >> 11) & 1;
uint32_t pwrMgt = (fc >> 12) & 1;
uint32_t moreData = (fc >> 13) & 1;
uint32_t encrypted = (fc >> 14) & 1;
uint32_t order = fc >> 15;
*/
  ptr += 2;

//  uint32_t duration_id = (ptr[1] << 8) + ptr[0]; /* not in network byte order either? */
  ptr += 2;

  switch(control) {
  case 0: /* mgmt */
  case 1: /* ctrl */
  case 3: /* rsvd */
  break;

  case 2: /* data */
    {

      uint8_t *macAddr1 = ptr;
      ptr += 6;
      uint8_t *macAddr2 = ptr;
      ptr += 6;
      uint8_t *macAddr3 = ptr;
      ptr += 6;
  // XXX not used    uint32_t sequence = (ptr[0] << 8) + ptr[1];
      ptr += 2;

      /* ToDS   FromDS   Addr1   Addr2  Addr3   Addr4
         0      0        DA      SA     BSSID   N/A (ad-hoc)
         0      1        DA      BSSID  SA      N/A
         1      0        BSSID   SA     DA      N/A
         1      1        RA      TA     DA      SA  (wireless bridge) */

      uint8_t *rxMAC = macAddr1;
      uint8_t *txMAC = macAddr2;
      uint8_t *srcMAC = NULL;
      uint8_t *dstMAC = NULL;

      if(toDS) {
	dstMAC = macAddr3;
	if(fromDS) {
	  srcMAC = ptr; /* macAddr4.  1,1 => (wireless bridge) */
	  ptr += 6;
	}
	else srcMAC = macAddr2;  /* 1,0 */
      }
      else {
	dstMAC = macAddr1;
	if(fromDS) srcMAC = macAddr3; /* 0,1 */
	else srcMAC = macAddr2; /* 0,0 */
      }

      if(srcMAC) {
	dbg_printf("srcMAC %02x%02x%02x%02x%02x%02x\n", srcMAC[0], srcMAC[1], srcMAC[2], srcMAC[3], srcMAC[4], srcMAC[5]);
	memcpy(sample->eth_src, srcMAC, 6);
      }
      if(dstMAC) {
	dbg_printf("dstMAC %02x%02x%02x%02x%02x%02x\n", dstMAC[0], dstMAC[1], dstMAC[2], dstMAC[3], dstMAC[4], dstMAC[5]);
	memcpy(sample->eth_dst, dstMAC, 6);
      }
      if(txMAC) dbg_printf("txMAC %02x%02x%02x%02x%02x%02x\n", txMAC[0], txMAC[1], txMAC[2], txMAC[3], txMAC[4], txMAC[5]);
      if(rxMAC) dbg_printf("rxMAC %02x%02x%02x%02x%02x%02x\n", rxMAC[0], rxMAC[1], rxMAC[2], rxMAC[3], rxMAC[4], rxMAC[5]);
    }
  }
}


/*_________________---------------------------__________________
	_________________     decodeIPLayer4        __________________
	-----------------___________________________------------------
*/

static void decodeIPLayer4(SFSample *sample, uint8_t *ptr) {
  uint8_t *end = sample->header + sample->headerLen;
  if(ptr > (end - 8)) {
    /* not enough header bytes left */
    return;
  }
  switch(sample->dcd_ipProtocol) {
  case 1: /* ICMP */
    {
      struct myicmphdr icmp;
      memcpy(&icmp, ptr, sizeof(icmp));
      dbg_printf("ICMPType %u\n", icmp.type);
      dbg_printf("ICMPCode %u\n", icmp.code);
      sample->dcd_sport = icmp.type;
      sample->dcd_dport = icmp.code;
      sample->offsetToPayload = ptr + sizeof(icmp) - sample->header;
    }
    break;
  case 6: /* TCP */
    {
      struct mytcphdr tcp;
      int headerBytes;
      memcpy(&tcp, ptr, sizeof(tcp));
      sample->dcd_sport = ntohs(tcp.th_sport);
      sample->dcd_dport = ntohs(tcp.th_dport);
      sample->dcd_tcpFlags = tcp.th_flags;
      dbg_printf("TCPSrcPort %u\n", sample->dcd_sport);
      dbg_printf("TCPDstPort %u\n",sample->dcd_dport);
      dbg_printf("TCPFlags %u\n", sample->dcd_tcpFlags);
      headerBytes = (tcp.th_off_and_unused >> 4) * 4;
      ptr += headerBytes;
      sample->offsetToPayload = ptr - sample->header;
    }
    break;
  case 17: /* UDP */
    {
      struct myudphdr udp;
      memcpy(&udp, ptr, sizeof(udp));
      sample->dcd_sport = ntohs(udp.uh_sport);
      sample->dcd_dport = ntohs(udp.uh_dport);
      sample->udp_pduLen = ntohs(udp.uh_ulen);
      dbg_printf("UDPSrcPort %u\n", sample->dcd_sport);
      dbg_printf("UDPDstPort %u\n", sample->dcd_dport);
      dbg_printf("UDPBytes %u\n", sample->udp_pduLen);
      sample->offsetToPayload = ptr + sizeof(udp) - sample->header;
    }
    break;
  default: /* some other protcol */
    sample->offsetToPayload = ptr - sample->header;
    break;
  }
}


/*_________________---------------------------__________________
	_________________     decodeIPV4            __________________
	-----------------___________________________------------------
*/

static void decodeIPV4(SFSample *sample)
{
	if(sample->gotIPV4) {
#ifdef DEVEL
		char buf[51];
#endif
		uint8_t *end = sample->header + sample->headerLen;
		uint8_t *start = sample->header + sample->offsetToIPV4;
		uint8_t *ptr = start;
		if((end - ptr) < sizeof(struct myiphdr)) return;

		/* Create a local copy of the IP header (cannot overlay structure in case it is not quad-aligned...some
			 platforms would core-dump if we tried that).  It's OK coz this probably performs just as well anyway. */
		struct myiphdr ip;
		memcpy(&ip, ptr, sizeof(ip));
		/* Value copy all ip elements into sample */
    	sample->ipsrc.type = SFLADDRESSTYPE_IP_V4;
    	sample->ipsrc.address.ip_v4.addr = ip.saddr;
    	sample->ipdst.type = SFLADDRESSTYPE_IP_V4;
    	sample->ipdst.address.ip_v4.addr = ip.daddr;
		sample->dcd_srcIP.s_addr = ip.saddr;
		sample->dcd_dstIP.s_addr = ip.daddr;
		sample->dcd_ipProtocol = ip.protocol;
		sample->dcd_ipTos = ip.tos;
		sample->dcd_ipTTL = ip.ttl;
		dbg_printf("ip.tot_len %d\n", ntohs(ip.tot_len));
		/* Log out the decoded IP fields */
		dbg_printf("srcIP %s\n", IP_to_a(sample->dcd_srcIP.s_addr, buf, 51));
		dbg_printf("dstIP %s\n", IP_to_a(sample->dcd_dstIP.s_addr, buf, 51));
		dbg_printf("IPProtocol %u\n", sample->dcd_ipProtocol);
		dbg_printf("IPTOS %u\n", sample->dcd_ipTos);
		dbg_printf("IPTTL %u\n", sample->dcd_ipTTL);
		/* check for fragments */
		sample->ip_fragmentOffset = ntohs(ip.frag_off) & 0x1FFF;
		if(sample->ip_fragmentOffset > 0) {
			dbg_printf("IPFragmentOffset %u\n", sample->ip_fragmentOffset);
		}
		else {
			dbg_printf("Unfragmented\n");
			/* advance the pointer to the next protocol layer */
			/* ip headerLen is expressed as a number of quads */
      		uint32_t headerBytes = (ip.version_and_headerLen & 0x0f) * 4;
      		if((end - ptr) < headerBytes) return;
      		ptr += headerBytes;
      		decodeIPLayer4(sample, ptr);
		}
	}
}

/*_________________---------------------------__________________
	_________________     decodeIPV6            __________________
	-----------------___________________________------------------
*/

static void decodeIPV6(SFSample *sample)
{
	uint16_t payloadLen;
	uint32_t label;
	uint32_t nextHeader;

	uint8_t *end = sample->header + sample->headerLen;
	uint8_t *start = sample->header + sample->offsetToIPV6;
	uint8_t *ptr = start;
	if((end - ptr) < sizeof(struct myip6hdr)) return;

	if(sample->gotIPV6) {
		u_char *ptr = sample->header + sample->offsetToIPV6;
		// check the version
		{
			int ipVersion = (*ptr >> 4);
			if(ipVersion != 6) {
				LogError("SFLOW: decodeIPV6() header decode error: unexpected IP version: %d\n", ipVersion);
				return;
			}
		}

		// get the tos (priority)
		sample->dcd_ipTos = *ptr++ & 15;
		dbg_printf("IPTOS %u\n", sample->dcd_ipTos);
		// 24-bit label
		label = *ptr++;
		label <<= 8;
		label += *ptr++;
		label <<= 8;
		label += *ptr++;
		dbg_printf("IP6_label 0x%x\n", label);
		// payload
		payloadLen = (ptr[0] << 8) + ptr[1];
		ptr += 2;
		// if payload is zero, that implies a jumbo payload
		if(payloadLen == 0) dbg_printf("IPV6_payloadLen <jumbo>\n");
		else dbg_printf("IPV6_payloadLen %u\n", payloadLen);

		// next header
		nextHeader = *ptr++;

		// TTL
		sample->dcd_ipTTL = *ptr++;
		dbg_printf("IPTTL %u\n", sample->dcd_ipTTL);

		{// src and dst address
#ifdef DEVEL
			char buf[101];
#endif
			sample->ipsrc.type = SFLADDRESSTYPE_IP_V6;
			memcpy(&sample->ipsrc.address, ptr, 16);
			ptr +=16;
			dbg_printf("srcIP6 %s\n", printAddress(&sample->ipsrc, buf, 100));
			sample->ipdst.type = SFLADDRESSTYPE_IP_V6;
			memcpy(&sample->ipdst.address, ptr, 16);
			ptr +=16;
			dbg_printf("dstIP6 %s\n", printAddress(&sample->ipdst, buf, 100));
		}

		// skip over some common header extensions...
		// http://searchnetworking.techtarget.com/originalContent/0,289142,sid7_gci870277,00.html
		while(nextHeader == 0 ||  // hop
		nextHeader == 43 || // routing
		nextHeader == 44 || // fragment
		// nextHeader == 50 || // encryption - don't bother coz we'll not be able to read any further
		nextHeader == 51 || // auth
		nextHeader == 60) { // destination options
			uint32_t optionLen, skip;
			dbg_printf("IP6HeaderExtension: %d\n", nextHeader);
			nextHeader = ptr[0];
			optionLen = 8 * (ptr[1] + 1);  // second byte gives option len in 8-byte chunks, not counting first 8
			skip = optionLen - 2;
			ptr += skip;
			if(ptr > end) return; // ran off the end of the header
		}
		
		// now that we have eliminated the extension headers, nextHeader should have what we want to
		// remember as the ip protocol...
		sample->dcd_ipProtocol = nextHeader;
		dbg_printf("IPProtocol %u\n", sample->dcd_ipProtocol);
		decodeIPLayer4(sample, ptr);
	}
}


#include "inline.c"
#include "nffile_inline.c"
#include "collector_inline.c"

/*_________________---------------------------__________________
	_________________   StoreSflowRecord     __________________
	-----------------___________________________------------------
*/

static inline void StoreSflowRecord(SFSample *sample, FlowSource_t *fs) {
common_record_t	*common_record;
stat_record_t *stat_record = fs->nffile->stat_record;
exporter_sflow_t 	*exporter;
extension_map_t		*extension_map;
struct timeval now;
void	 *next_data;
value32_t	*val;
uint32_t bytes, j, id, ipsize, ip_flags;
uint64_t _bytes, _packets, _t;	// tmp buffers

	dbg_printf("StoreSflowRecord\n");

	gettimeofday(&now, NULL);

	if( sample->ip_fragmentOffset > 0 ) {
		sample->dcd_sport = 0;
		sample->dcd_dport = 0;
	}

	bytes = sample->sampledPacketSize;
	
	ip_flags = 0;
	if ( sample->nextHop.type == SFLADDRESSTYPE_IP_V6 )
		SetFlag(ip_flags, SFLOW_NEXT_HOP);
		
	if ( sample->bgp_nextHop.type == SFLADDRESSTYPE_IP_V6 )
		SetFlag(ip_flags, SFLOW_NEXT_HOP_BGP);
		
	if ( fs->sa_family == AF_INET6 ) 
		SetFlag(ip_flags, SFLOW_ROUTER_IP);

	ip_flags &= IP_extension_mask;

	if ( ip_flags >= MAX_SFLOW_EXTENSIONS ) {
		LogError("SFLOW: Corrupt ip_flags: %u", ip_flags);
	}
	exporter = GetExporter(fs, sample->agentSubId, sample->meanSkipCount);
	if ( !exporter ) {
		LogError("SFLOW: Exporter NULL: Abort sflow record processing");
		return;
	}
	exporter->packets++;

	// get appropriate extension map
	extension_map = exporter->sflow_extension_info[ip_flags].map;
	if ( !extension_map ) {
		LogInfo("SFLOW: setup extension map: %u", ip_flags);
		if ( !Setup_Extension_Info(fs, exporter, ip_flags ) ) {
			LogError("SFLOW: Extension map: NULL: Abort sflow record processing");
			return;
		}
		extension_map = exporter->sflow_extension_info[ip_flags].map;
		LogInfo("SFLOW: setup extension map: %u done", ip_flags);
	}

	// output buffer size check
	// IPv6 needs 2 x 16 bytes, IPv4 2 x 4 bytes
	ipsize = sample->gotIPV6 ? 32 : 8;
	if ( !CheckBufferSpace(fs->nffile, sflow_output_record_size[ip_flags] + ipsize )) {
		// fishy! - should never happen. maybe disk full?
		LogError("SFLOW: output buffer size error. Abort sflow record processing");
		return;
	}

	dbg_printf("Fill Record\n");
	common_record = (common_record_t *)fs->nffile->buff_ptr;

	common_record->size			  = sflow_output_record_size[ip_flags] + ipsize;
	common_record->type			  = CommonRecordType;
	common_record->flags		  = 0;
	SetFlag(common_record->flags, FLAG_SAMPLED);

	common_record->exporter_sysid = exporter->info.sysid;
	common_record->ext_map		  = extension_map->map_id;

	common_record->first		  = now.tv_sec;
	common_record->last			  = common_record->first;
	common_record->msec_first	  = now.tv_usec / 1000;
	common_record->msec_last	  = common_record->msec_first;
	_t							  = 1000LL * now.tv_sec + common_record->msec_first;	// tmp buff for first_seen

	common_record->fwd_status	  = 0;
	common_record->reserved	  	  = 0;
	common_record->tcp_flags	  = sample->dcd_tcpFlags;
	common_record->prot			  = sample->dcd_ipProtocol;
	common_record->tos			  = sample->dcd_ipTos;
	common_record->srcport		  = (uint16_t)sample->dcd_sport;
	common_record->dstport		  = (uint16_t)sample->dcd_dport;

	if(sample->gotIPV6) {
		u_char 		*b;
		uint64_t	*u;
		ipv6_block_t	*ipv6 	= (ipv6_block_t *)common_record->data;
		SetFlag(common_record->flags, FLAG_IPV6_ADDR);

		b = sample->ipsrc.address.ip_v6.addr;
		u = (uint64_t *)b;
		ipv6->srcaddr[0] = ntohll(*u);
		u = (uint64_t *)&(b[8]);
		ipv6->srcaddr[1] = ntohll(*u);

		b = sample->ipdst.address.ip_v6.addr;
		u = (uint64_t *)b;
		ipv6->dstaddr[0] = ntohll(*u);
		u = (uint64_t *)&(b[8]);
		ipv6->dstaddr[1] = ntohll(*u);

		next_data = (void *)ipv6->data;
	} else {
		ipv4_block_t *ipv4 = (ipv4_block_t *)common_record->data;
		ipv4->srcaddr = ntohl(sample->dcd_srcIP.s_addr);
		ipv4->dstaddr = ntohl(sample->dcd_dstIP.s_addr);
	
		next_data = (void *)ipv4->data;
	}

	// 4 byte Packet value
	val = (value32_t *)next_data;
	val->val = sample->meanSkipCount;
	_packets = val->val;

	// 4 byte Bytes value
	val = (value32_t *)val->data;
	val->val = sample->meanSkipCount * bytes;
	_bytes = val->val;

	next_data = (void *)val->data;

	j = 0;
	while ( (id = extension_map->ex_id[j]) != 0 ) {
		switch (id) {
			case EX_IO_SNMP_4:	{	// 4 byte input/output interface index
				tpl_ext_5_t *tpl = (tpl_ext_5_t *)next_data;
				tpl->input  = sample->inputPort;
				tpl->output = sample->outputPort;
				next_data = (void *)tpl->data;
				} break;
			case EX_AS_4:	 {	// 4 byte src/dst AS number
				tpl_ext_7_t *tpl = (tpl_ext_7_t *)next_data;
				tpl->src_as	= sample->src_as;
				tpl->dst_as	= sample->dst_as;
				next_data = (void *)tpl->data;
				} break;
			case EX_VLAN: { // 2 byte valn label
				tpl_ext_13_t *tpl = (tpl_ext_13_t *)next_data;
				tpl->src_vlan = sample->in_vlan;
				tpl->dst_vlan = sample->out_vlan;
				next_data = (void *)tpl->data;
				} break;
			case EX_MULIPLE:	 {	// dst tos, direction, src/dst mask
				tpl_ext_8_t *tpl = (tpl_ext_8_t *)next_data;
				tpl->dst_tos	= sample->dcd_ipTos;
				tpl->dir		= 0;
				tpl->src_mask	= sample->srcMask;
				tpl->dst_mask	= sample->dstMask;
				next_data = (void *)tpl->data;
				} break;
			case EX_MAC_1: 	{ // MAC addreses
				tpl_ext_20_t *tpl = (tpl_ext_20_t *)next_data;
				tpl->in_src_mac  = Get_val48((void *)&sample->eth_src);
				tpl->out_dst_mac = Get_val48((void *)&sample->eth_dst);
				next_data = (void *)tpl->data;
			} break;
			case EX_NEXT_HOP_v4:	 {	// next hop IPv4 router address
				tpl_ext_9_t *tpl = (tpl_ext_9_t *)next_data;
				if ( sample->nextHop.type == SFLADDRESSTYPE_IP_V4 ) {
					tpl->nexthop = ntohl(sample->nextHop.address.ip_v4.addr);
				} else {
					tpl->nexthop = 0;
				}
				next_data = (void *)tpl->data;
			} break;
			case EX_NEXT_HOP_v6:	 {	// next hop IPv6 router address
				tpl_ext_10_t *tpl = (tpl_ext_10_t *)next_data;
				void *ptr = (void *)sample->nextHop.address.ip_v6.addr;
				if ( sample->nextHop.type == SFLADDRESSTYPE_IP_V6 ) {
					tpl->nexthop[0] = ntohll(((uint64_t *)ptr)[0]);
					tpl->nexthop[1] = ntohll(((uint64_t *)ptr)[1]);
				} else {
					tpl->nexthop[0] = 0;
					tpl->nexthop[1] = 0;
				}
				SetFlag(common_record->flags, FLAG_IPV6_NH);
				next_data = (void *)tpl->data;
			} break;
			case EX_NEXT_HOP_BGP_v4:	 {	// next hop bgp IPv4 router address
				tpl_ext_11_t *tpl = (tpl_ext_11_t *)next_data;
				if ( sample->bgp_nextHop.type == SFLADDRESSTYPE_IP_V4 ) {
					tpl->bgp_nexthop = ntohl(sample->bgp_nextHop.address.ip_v4.addr);
				} else {
					tpl->bgp_nexthop = 0;
				}
				next_data = (void *)tpl->data;
			} break;
			case EX_NEXT_HOP_BGP_v6:	 {	// next hop IPv4 router address
				tpl_ext_12_t *tpl = (tpl_ext_12_t *)next_data;
				void *ptr = (void *)sample->bgp_nextHop.address.ip_v6.addr;
				if ( sample->bgp_nextHop.type == SFLADDRESSTYPE_IP_V6 ) {
					tpl->bgp_nexthop[0] = ntohll(((uint64_t *)ptr)[0]);
					tpl->bgp_nexthop[1] = ntohll(((uint64_t *)ptr)[1]);
				} else {
					tpl->bgp_nexthop[0] = 0;
					tpl->bgp_nexthop[1] = 0;
				}
				SetFlag(common_record->flags, FLAG_IPV6_NHB);
				next_data = (void *)tpl->data;
			} break;
			case EX_ROUTER_IP_v4:
			case EX_ROUTER_IP_v6: 	// IPv4/IPv6 router address
			if(sample->agent_addr.type == SFLADDRESSTYPE_IP_V4) {
				tpl_ext_23_t *tpl = (tpl_ext_23_t *)next_data;
				tpl->router_ip = ntohl(sample->agent_addr.address.ip_v4.addr);
				next_data = (void *)tpl->data;
				ClearFlag(common_record->flags, FLAG_IPV6_EXP);
			} else {
				tpl_ext_24_t *tpl = (tpl_ext_24_t *)next_data;
				void *ptr = (void *)sample->agent_addr.address.ip_v6.addr;
				tpl->router_ip[0] = ntohll(((uint64_t *)ptr)[0]);
				tpl->router_ip[1] = ntohll(((uint64_t *)ptr)[1]);
				next_data = (void *)tpl->data;
				SetFlag(common_record->flags, FLAG_IPV6_EXP);
			}
			break;
			case EX_RECEIVED: {
				tpl_ext_27_t *tpl = (tpl_ext_27_t *)next_data;
				tpl->received  = (uint64_t)((uint64_t)fs->received.tv_sec * 1000LL) + (uint64_t)((uint64_t)fs->received.tv_usec / 1000LL);
				next_data = (void *)tpl->data;
			} break;
			default: 
				// this should never happen
				LogError("SFLOW: Unexpected extension %i for sflow record. Skip extension", id);
				dbg_printf("SFLOW: Unexpected extension %i for sflow record. Skip extension", id);
		}
		j++;
	}

	// update first_seen, last_seen
	if ( _t < fs->first_seen )	// the very first time stamp need to be set
		fs->first_seen = _t;
	fs->last_seen = _t;

	// Update stats
	switch (common_record->prot) {
		case 1:
			stat_record->numflows_icmp++;
			stat_record->numpackets_icmp += _packets;
			stat_record->numbytes_icmp   += _bytes;
			break;
		case 6:
			stat_record->numflows_tcp++;
			stat_record->numpackets_tcp += _packets;
			stat_record->numbytes_tcp   += _bytes;
			break;
		case 17:
			stat_record->numflows_udp++;
			stat_record->numpackets_udp += _packets;
			stat_record->numbytes_udp   += _bytes;
			break;
		default:
			stat_record->numflows_other++;
			stat_record->numpackets_other += _packets;
			stat_record->numbytes_other   += _bytes;
	}
	exporter->flows++;
	stat_record->numflows++;
	stat_record->numpackets	+= _packets;
	stat_record->numbytes	+= _bytes;

	if ( verbose ) {
		master_record_t master_record;
		char	*string;
		ExpandRecord_v2((common_record_t *)common_record, &exporter->sflow_extension_info[ip_flags], &(exporter->info), &master_record);
	 	format_file_block_record(&master_record, &string, 0);
		printf("%s\n", string);
	}

	// update file record size ( -> output buffer size )
	fs->nffile->block_header->NumRecords++;
	fs->nffile->block_header->size 		+= (sflow_output_record_size[ip_flags] + ipsize);
#ifdef DEVEL
	if ( (next_data - fs->nffile->buff_ptr) != (sflow_output_record_size[ip_flags] + ipsize) ) {
		printf("PANIC: Size error. Buffer diff: %llu, Size: %u\n", 
			(unsigned long long)(next_data - fs->nffile->buff_ptr), 
			(sflow_output_record_size[ip_flags] + ipsize));
		exit(255);
	}
#endif
	fs->nffile->buff_ptr 					= next_data;

}
			
void Init_sflow(void) {
int i, id;

	i=0;
	Num_enabled_extensions = 0;
	while ( (id = sflow_extensions[i]) != 0  ) {
		if ( extension_descriptor[id].enabled ) {
			dbg_printf("Enabled extension: %i\n", id);
			Num_enabled_extensions++;
		}
		i++;
	}

	IP_extension_mask = 0;
	i=0;
	while ( extension_descriptor[i].description != NULL  ) {
		switch (extension_descriptor[i].id) {
			case EX_NEXT_HOP_v4:
			// case EX_NEXT_HOP_v6: - not really needed
				if ( extension_descriptor[i].enabled ) {
					SetFlag(IP_extension_mask, SFLOW_NEXT_HOP);
					Num_enabled_extensions++;
				} break;
			case EX_NEXT_HOP_BGP_v4:
			// case EX_NEXT_HOP_BGP_v6: - not really needed
				if ( extension_descriptor[i].enabled ) {
					SetFlag(IP_extension_mask, SFLOW_NEXT_HOP_BGP);
					Num_enabled_extensions++;
				} break;
			case EX_ROUTER_IP_v4:
			// case EX_ROUTER_IP_v6: - not really needed
				if ( extension_descriptor[i].enabled ) {
					SetFlag(IP_extension_mask, SFLOW_ROUTER_IP);
					Num_enabled_extensions++;
				} break;
		}
		i++;
	}

	dbg_printf("Num enabled Extensions: %i\n", Num_enabled_extensions);

} // End of Init_sflow

int Setup_Extension_Info(FlowSource_t *fs, exporter_sflow_t	*exporter, int num) {
int i, id, extension_size, map_size, map_index;

	dbg_printf("Setup Extension ID 0x%x\n", num);
	LogInfo("SFLOW: setup extension map %u", num);

	// prepare sflow extension map <num>
	exporter->sflow_extension_info[num].map   = NULL;
	extension_size	 = 0;

	// calculate the full extension map size
	map_size 	= Num_enabled_extensions * sizeof(uint16_t) + sizeof(extension_map_t);

	// align 32 bits
	if ( ( map_size & 0x3 ) != 0 )
		map_size += 2;


	// Create a generic sflow extension map
	exporter->sflow_extension_info[num].map = (extension_map_t *)malloc((size_t)map_size);
	if ( !exporter->sflow_extension_info[num].map ) {
		LogError("SFLOW: malloc() allocation error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
		return 0;
	}

	// calclate the extension size
	i=0;
	map_index = 0;
	while ( (id = sflow_extensions[i]) != 0  ) {
		if ( extension_descriptor[id].enabled ) {
			extension_size += extension_descriptor[id].size;
			exporter->sflow_extension_info[num].map->ex_id[map_index++] = id;
		}
		i++;
	}

	if ( TestFlag(IP_extension_mask, SFLOW_NEXT_HOP)) {
		id = sflow_ip_extensions[num].next_hop;
		extension_size += extension_descriptor[id].size;
		exporter->sflow_extension_info[num].map->ex_id[map_index++] = id;
	}

	if ( TestFlag(IP_extension_mask, SFLOW_NEXT_HOP_BGP)) {
		id = sflow_ip_extensions[num].next_hop_bgp;
		extension_size += extension_descriptor[id].size;
		exporter->sflow_extension_info[num].map->ex_id[map_index++] = id;
	}

	if ( TestFlag(IP_extension_mask, SFLOW_ROUTER_IP)) {
		id = sflow_ip_extensions[num].router_ip;
		extension_size += extension_descriptor[id].size;
		exporter->sflow_extension_info[num].map->ex_id[map_index++] = id;
	}

	// terminating null record
	exporter->sflow_extension_info[num].map->ex_id[map_index] = 0;

	dbg_printf("Extension size: %i\n", extension_size);

	// caculate the basic record size: without IP addr space ( v4/v6 dependant )
	// byte/packet counters are 32bit -> 2 x uint32_t
	// extension_size contains the sum of all optional extensions
	sflow_output_record_size[num] = COMMON_RECORD_DATA_SIZE + 2*sizeof(uint32_t) + extension_size;	

	dbg_printf("Record size: %i\n", sflow_output_record_size[num]);

	exporter->sflow_extension_info[num].map->type 	   	  = ExtensionMapType;
	exporter->sflow_extension_info[num].map->size 	   	  = map_size;
	exporter->sflow_extension_info[num].map->map_id   	  = INIT_ID;		
	exporter->sflow_extension_info[num].map->extension_size = extension_size;		

	LogInfo("Extension size: %i", extension_size);
	LogInfo("Extension map size: %i", map_size);

	if ( !AddExtensionMap(fs, exporter->sflow_extension_info[num].map) ) {
		// bad - we must free this map and fail - otherwise data can not be read any more
		free(exporter->sflow_extension_info[num].map);
		exporter->sflow_extension_info[num].map = NULL;
		return 0;
	}
	dbg_printf("New Extension map ID %i\n", exporter->sflow_extension_info[num].map->map_id);
	LogInfo("New extension map id: %i", exporter->sflow_extension_info[num].map->map_id);

	return 1;

} // End of Setup_Extension_Info

static inline exporter_sflow_t *GetExporter(FlowSource_t *fs, uint32_t agentSubId, uint32_t meanSkipCount) {
exporter_sflow_t **e = (exporter_sflow_t **)&(fs->exporter_data);
generic_sampler_t *sampler;
#define IP_STRING_LEN   40
char ipstr[IP_STRING_LEN];
int i;

	// search the appropriate exporter engine
	while ( *e ) {
		if ( (*e)->info.id == agentSubId && (*e)->info.version == SFLOW_VERSION &&
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
	LogInfo("SFLOW: New exporter" );

	*e = (exporter_sflow_t *)malloc(sizeof(exporter_sflow_t));
	if ( !(*e)) {
		LogError("SFLOW: malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror (errno));
		return NULL;
	}
	memset((void *)(*e), 0, sizeof(exporter_sflow_t));
	(*e)->next	 			= NULL;
	(*e)->info.header.type  = ExporterInfoRecordType;
	(*e)->info.header.size  = sizeof(exporter_info_record_t);
	(*e)->info.version		= SFLOW_VERSION;
	(*e)->info.id 			= agentSubId;
	(*e)->info.ip			= fs->ip;
	(*e)->info.sa_family	= fs->sa_family;
	(*e)->sequence_failure	= 0;
	(*e)->packets			= 0;
	(*e)->flows				= 0;
	for (i=0; i<MAX_SFLOW_EXTENSIONS; i++ ) {
		(*e)->sflow_extension_info[i].map = NULL;
	}

	sampler = (generic_sampler_t *)malloc(sizeof(generic_sampler_t));
	if ( !sampler ) {
		LogError("SFLOW: malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror (errno));
		return NULL;
	}
	(*e)->sampler = sampler;

	sampler->info.header.type 	= SamplerInfoRecordype;
	sampler->info.header.size	= sizeof(sampler_info_record_t);
	sampler->info.id			= -1;
	sampler->info.mode			= 0;
	sampler->info.interval		= meanSkipCount;
	sampler->next				= NULL;

	FlushInfoExporter(fs, &((*e)->info));
	sampler->info.exporter_sysid		= (*e)->info.sysid;
	FlushInfoSampler(fs, &(sampler->info));

	dbg_printf("SFLOW: New exporter: SysID: %u, agentSubId: %u, MeanSkipCount: %u, IP: %s\n", 
		(*e)->info.sysid, agentSubId, meanSkipCount, ipstr);
	LogInfo("SFLOW: New exporter: SysID: %u, agentSubId: %u, MeanSkipCount: %u, IP: %s", 
		(*e)->info.sysid, agentSubId, meanSkipCount, ipstr);

	return (*e);

} // End of GetExporter

void Process_sflow(void *in_buff, ssize_t in_buff_cnt, FlowSource_t *fs) {

SFSample 	sample;
int 		exceptionVal;

	memset(&sample, 0, sizeof(sample));
	sample.rawSample = in_buff;
	sample.rawSampleLen = in_buff_cnt;
	sample.sourceIP.s_addr = fs->sa_family == PF_INET ? htonl(fs->ip.V4) : 0;;

	dbg_printf("startDatagram =================================\n");
	if((exceptionVal = setjmp(sample.env)) == 0)	{
		// TRY
		sample.datap = (uint32_t *)sample.rawSample;
		sample.endp = (u_char *)sample.rawSample + sample.rawSampleLen;
		readSFlowDatagram(&sample, fs );
	} else {
		// CATCH
		dbg_printf("SFLOW: caught exception: %d\n", exceptionVal);
		LogError("SFLOW: caught exception: %d", exceptionVal);
	}
	dbg_printf("endDatagram	 =================================\n");

} // End of Process_sflow


// include sflow functions
// based on sflowtool https://github.com/sflow/sflowtool
// commit 7322984  on Jul 21

/*_________________---------------------------__________________
  _________________   read data fns           __________________
  -----------------___________________________------------------
*/

static uint32_t getData32_nobswap(SFSample *sample) {
  uint32_t ans = *(sample->datap)++;
  /* make sure we didn't run off the end of the datagram.  Thanks to
     Sven Eschenberg for spotting a bug/overrun-vulnerabilty that was here before. */
  if((uint8_t *)sample->datap > sample->endp) {
    SFABORT(sample, SF_ABORT_EOS);
  }
  return ans;
}

static uint32_t getData32(SFSample *sample) {
  return ntohl(getData32_nobswap(sample));
}

static float getFloat(SFSample *sample) {
  float fl;
  uint32_t reg = getData32(sample);
  memcpy(&fl, &reg, 4);
  return fl;
}

static uint64_t getData64(SFSample *sample) {
  uint64_t tmpLo, tmpHi;
  tmpHi = getData32(sample);
  tmpLo = getData32(sample);
  return (tmpHi << 32) + tmpLo;
}

static double getDouble(SFSample *sample) {
  double dbl;
  uint64_t reg = getData64(sample);
  memcpy(&dbl, &reg, 8);
  return dbl;
}

static void inline skipBytes(SFSample *sample, uint32_t skip) {
  int quads = (skip + 3) / 4;
  sample->datap += quads;
  if(skip > sample->rawSampleLen || (uint8_t *)sample->datap > sample->endp) {
    SFABORT(sample, SF_ABORT_EOS);
  }
}

static uint32_t sf_log_next32(SFSample *sample, char *fieldName) {
  uint32_t val = getData32(sample);
  dbg_printf("%s %u\n", fieldName, val);
  return val;
}

static uint64_t sf_log_next64(SFSample *sample, char *fieldName) {
  uint64_t val64 = getData64(sample);
  dbg_printf("%s %llu\n", fieldName, (unsigned long long)val64);
  return val64;
}

void sf_log_percentage(SFSample *sample, char *fieldName)
{
  uint32_t hundredths = getData32(sample);
  if(hundredths == (uint32_t)-1) dbg_printf("%s unknown\n", fieldName);
  else {
#ifdef DEVEL
    float percent = (float)hundredths / (float)100.0;
    dbg_printf("%s %.2f\n", fieldName, percent);
#endif
  }
}

static float sf_log_nextFloat(SFSample *sample, char *fieldName) {
  float val = getFloat(sample);
  dbg_printf("%s %.3f\n", fieldName, val);
  return val;
}

static void sf_log_nextMAC(SFSample *sample, char *fieldName)
{
#ifdef DEVEL
  uint8_t *mac = (uint8_t *)sample->datap;
#endif
  skipBytes(sample, 6);
  dbg_printf("%s %02x%02x%02x%02x%02x%02x\n", fieldName, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static inline uint32_t getString(SFSample *sample, char *buf, uint32_t bufLen) {
  uint32_t len, read_len;
  len = getData32(sample);
  /* check the bytes are there first */
  uint32_t *dp = sample->datap;
  skipBytes(sample, len);
  /* truncate if too long */
  read_len = (len >= bufLen) ? (bufLen - 1) : len;
  memcpy(buf, dp, read_len);
  buf[read_len] = '\0';   /* null terminate */
  return len;
}

static uint32_t getAddress(SFSample *sample, SFLAddress *address) {
  address->type = getData32(sample);
  switch(address->type) {
  case SFLADDRESSTYPE_IP_V4:
    address->address.ip_v4.addr = getData32_nobswap(sample);
    break;
  case SFLADDRESSTYPE_IP_V6:
    {
      /* make sure the data is there before we memcpy */
      uint32_t *dp = sample->datap;
      skipBytes(sample, 16);
      memcpy(&address->address.ip_v6.addr, dp, 16);
    }
    break;
  default:
    /* undefined address type - bail out */
    LogError("SFLOW: getAddress() unknown address type = %d\n", address->type);
    SFABORT(sample, SF_ABORT_EOS);
  }
  return address->type;
}

static void skipTLVRecord(SFSample *sample, uint32_t tag, uint32_t len, char *description) {
#ifdef DEVEL
  char buf[51];
#endif
  dbg_printf("skipping unknown %s: %s len=%d\n", description, printTag(tag, buf, 50), len);
  skipBytes(sample, len);
}

/*_________________---------------------------__________________
  _________________    readExtendedSwitch     __________________
  -----------------___________________________------------------
*/

static void readExtendedSwitch(SFSample *sample)
{
  dbg_printf("extendedType SWITCH\n");
  sample->in_vlan = getData32(sample);
  sample->in_priority = getData32(sample);
  sample->out_vlan = getData32(sample);
  sample->out_priority = getData32(sample);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_SWITCH;

  dbg_printf("in_vlan %u\n", sample->in_vlan);
  dbg_printf("in_priority %u\n", sample->in_priority);
  dbg_printf("out_vlan %u\n", sample->out_vlan);
  dbg_printf("out_priority %u\n", sample->out_priority);
}

/*_________________---------------------------__________________
  _________________    readExtendedRouter     __________________
  -----------------___________________________------------------
*/

static void readExtendedRouter(SFSample *sample)
{
#ifdef DEVEL
  char buf[51];
#endif
  dbg_printf("extendedType ROUTER\n");
  getAddress(sample, &sample->nextHop);
  sample->srcMask = getData32(sample);
  sample->dstMask = getData32(sample);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_ROUTER;

  dbg_printf("nextHop %s\n", printAddress(&sample->nextHop, buf, 50));
  dbg_printf("srcSubnetMask %u\n", sample->srcMask);
  dbg_printf("dstSubnetMask %u\n", sample->dstMask);
}

/*_________________---------------------------__________________
  _________________  readExtendedGateway_v2   __________________
  -----------------___________________________------------------
*/

static void readExtendedGateway_v2(SFSample *sample)
{
  dbg_printf("extendedType GATEWAY\n");

  sample->my_as = getData32(sample);
  sample->src_as = getData32(sample);
  sample->src_peer_as = getData32(sample);

  /* clear dst_peer_as and dst_as to make sure we are not
     remembering values from a previous sample - (thanks Marc Lavine) */
  sample->dst_peer_as = 0;
  sample->dst_as = 0;

  sample->dst_as_path_len = getData32(sample);
  /* just point at the dst_as_path array */
  if(sample->dst_as_path_len > 0) {
    sample->dst_as_path = sample->datap;
    /* and skip over it in the input */
    skipBytes(sample, sample->dst_as_path_len * 4);
    /* fill in the dst and dst_peer fields too */
    sample->dst_peer_as = ntohl(sample->dst_as_path[0]);
    sample->dst_as = ntohl(sample->dst_as_path[sample->dst_as_path_len - 1]);
  }

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_GATEWAY;

  dbg_printf("my_as %u\n", sample->my_as);
  dbg_printf("src_as %u\n", sample->src_as);
  dbg_printf("src_peer_as %u\n", sample->src_peer_as);
  dbg_printf("dst_as %u\n", sample->dst_as);
  dbg_printf("dst_peer_as %u\n", sample->dst_peer_as);
  dbg_printf("dst_as_path_len %u\n", sample->dst_as_path_len);
  if(sample->dst_as_path_len > 0) {
    uint32_t i = 0;
    for(; i < sample->dst_as_path_len; i++) {
      if(i == 0) dbg_printf("dst_as_path ");
      else dbg_printf("-");
      dbg_printf("%u", ntohl(sample->dst_as_path[i]));
    }
    dbg_printf("\n");
  }
}

/*_________________---------------------------__________________
  _________________  readExtendedGateway      __________________
  -----------------___________________________------------------
*/

static void readExtendedGateway(SFSample *sample)
{
  uint32_t segments;
  uint32_t seg;
#ifdef DEVEL
  char buf[51];
#endif

  dbg_printf("extendedType GATEWAY\n");

  if(sample->datagramVersion >= 5) {
    getAddress(sample, &sample->bgp_nextHop);
    dbg_printf("bgp_nexthop %s\n", printAddress(&sample->bgp_nextHop, buf, 50));
  }

  sample->my_as = getData32(sample);
  sample->src_as = getData32(sample);
  sample->src_peer_as = getData32(sample);
  dbg_printf("my_as %u\n", sample->my_as);
  dbg_printf("src_as %u\n", sample->src_as);
  dbg_printf("src_peer_as %u\n", sample->src_peer_as);
  segments = getData32(sample);

  /* clear dst_peer_as and dst_as to make sure we are not
     remembering values from a previous sample - (thanks Marc Lavine) */
  sample->dst_peer_as = 0;
  sample->dst_as = 0;

  if(segments > 0) {
    dbg_printf("dst_as_path ");
    for(seg = 0; seg < segments; seg++) {
      uint32_t seg_type;
      uint32_t seg_len;
      uint32_t i;
      seg_type = getData32(sample);
      seg_len = getData32(sample);
      for(i = 0; i < seg_len; i++) {
	uint32_t asNumber;
	asNumber = getData32(sample);
	/* mark the first one as the dst_peer_as */
	if(i == 0 && seg == 0) sample->dst_peer_as = asNumber;
	else dbg_printf("-");
	/* make sure the AS sets are in parentheses */
	if(i == 0 && seg_type == SFLEXTENDED_AS_SET) dbg_printf("(");
	dbg_printf("%u", asNumber);
	/* mark the last one as the dst_as */
	if(seg == (segments - 1) && i == (seg_len - 1)) sample->dst_as = asNumber;
      }
      if(seg_type == SFLEXTENDED_AS_SET) dbg_printf(")");
    }
    dbg_printf("\n");
  }
  dbg_printf("dst_as %u\n", sample->dst_as);
  dbg_printf("dst_peer_as %u\n", sample->dst_peer_as);

  sample->communities_len = getData32(sample);
  /* just point at the communities array */
  if(sample->communities_len > 0) sample->communities = sample->datap;
  /* and skip over it in the input */
  skipBytes(sample, sample->communities_len * 4);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_GATEWAY;
  if(sample->communities_len > 0) {
    uint32_t j = 0;
    for(; j < sample->communities_len; j++) {
      if(j == 0) dbg_printf("BGP_communities ");
      else dbg_printf("-");
      dbg_printf("%u", ntohl(sample->communities[j]));
    }
    dbg_printf("\n");
  }

  sample->localpref = getData32(sample);
  dbg_printf("BGP_localpref %u\n", sample->localpref);

}

/*_________________---------------------------__________________
  _________________    readExtendedUser       __________________
  -----------------___________________________------------------
*/

static void readExtendedUser(SFSample *sample)
{
  dbg_printf("extendedType USER\n");

  if(sample->datagramVersion >= 5) {
    sample->src_user_charset = getData32(sample);
    dbg_printf("src_user_charset %d\n", sample->src_user_charset);
  }

  sample->src_user_len = getString(sample, sample->src_user, SA_MAX_EXTENDED_USER_LEN);

  if(sample->datagramVersion >= 5) {
    sample->dst_user_charset = getData32(sample);
    dbg_printf("dst_user_charset %d\n", sample->dst_user_charset);
  }

  sample->dst_user_len = getString(sample, sample->dst_user, SA_MAX_EXTENDED_USER_LEN);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_USER;

  dbg_printf("src_user %s\n", sample->src_user);
  dbg_printf("dst_user %s\n", sample->dst_user);
}

/*_________________---------------------------__________________
  _________________    readExtendedUrl        __________________
  -----------------___________________________------------------
*/

static void readExtendedUrl(SFSample *sample)
{
  dbg_printf("extendedType URL\n");

  sample->url_direction = getData32(sample);
  dbg_printf("url_direction %u\n", sample->url_direction);
  sample->url_len = getString(sample, sample->url, SA_MAX_EXTENDED_URL_LEN);
  dbg_printf("url %s\n", sample->url);
  if(sample->datagramVersion >= 5) {
    sample->host_len = getString(sample, sample->host, SA_MAX_EXTENDED_HOST_LEN);
    dbg_printf("host %s\n", sample->host);
  }
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_URL;
}


/*_________________---------------------------__________________
  _________________       mplsLabelStack      __________________
  -----------------___________________________------------------
*/

static void mplsLabelStack(SFSample *sample, char *fieldName)
{
  SFLLabelStack lstk;
  uint32_t lab;
  lstk.depth = getData32(sample);
  /* just point at the lablelstack array */
  if(lstk.depth > 0) lstk.stack = (uint32_t *)sample->datap;
  /* and skip over it in the input */
  skipBytes(sample, lstk.depth * 4);
 
  if(lstk.depth > 0) {
    uint32_t j = 0;
    for(; j < lstk.depth; j++) {
      if(j == 0) dbg_printf("%s ", fieldName);
      else dbg_printf("-");
      lab = ntohl(lstk.stack[j]);
      dbg_printf("%u.%u.%u.%u",
	     (lab >> 12),     /* label */
	     (lab >> 9) & 7,  /* experimental */
	     (lab >> 8) & 1,  /* bottom of stack */
	     (lab &  255));   /* TTL */
    }
    dbg_printf("\n");
  }
}

/*_________________---------------------------__________________
  _________________    readExtendedMpls       __________________
  -----------------___________________________------------------
*/

static void readExtendedMpls(SFSample *sample)
{
#ifdef DEVEL
  char buf[51];
#endif
  dbg_printf("extendedType MPLS\n");
  getAddress(sample, &sample->mpls_nextHop);
  dbg_printf("mpls_nexthop %s\n", printAddress(&sample->mpls_nextHop, buf, 50));

  mplsLabelStack(sample, "mpls_input_stack");
  mplsLabelStack(sample, "mpls_output_stack");
  
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS;
}

/*_________________---------------------------__________________
  _________________    readExtendedNat        __________________
  -----------------___________________________------------------
*/

static void readExtendedNat(SFSample *sample)
{
#ifdef DEVEL
  char buf[51];
#endif
  dbg_printf("extendedType NAT\n");
  getAddress(sample, &sample->nat_src);
  dbg_printf("nat_src %s\n", printAddress(&sample->nat_src, buf, 50));
  getAddress(sample, &sample->nat_dst);
  dbg_printf("nat_dst %s\n", printAddress(&sample->nat_dst, buf, 50));
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_NAT;
}

/*_________________---------------------------__________________
  _________________    readExtendedNatPort    __________________
  -----------------___________________________------------------
*/

static void readExtendedNatPort(SFSample *sample)
{
  dbg_printf("extendedType NAT PORT\n");
  sf_log_next32(sample, "nat_src_port");
  sf_log_next32(sample, "nat_dst_port");
}


/*_________________---------------------------__________________
  _________________    readExtendedMplsTunnel __________________
  -----------------___________________________------------------
*/

static void readExtendedMplsTunnel(SFSample *sample)
{
#define SA_MAX_TUNNELNAME_LEN 100
  char tunnel_name[SA_MAX_TUNNELNAME_LEN+1];
  uint32_t tunnel_id, tunnel_cos;
  
  if(getString(sample, tunnel_name, SA_MAX_TUNNELNAME_LEN) > 0)
    dbg_printf("mpls_tunnel_lsp_name %s\n", tunnel_name);
  tunnel_id = getData32(sample);
  dbg_printf("mpls_tunnel_id %u\n", tunnel_id);
  tunnel_cos = getData32(sample);
  dbg_printf("mpls_tunnel_cos %u\n", tunnel_cos);
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_TUNNEL;
}

/*_________________---------------------------__________________
  _________________    readExtendedMplsVC     __________________
  -----------------___________________________------------------
*/

static void readExtendedMplsVC(SFSample *sample)
{
#define SA_MAX_VCNAME_LEN 100
  char vc_name[SA_MAX_VCNAME_LEN+1];
  uint32_t vll_vc_id, vc_cos;
  if(getString(sample, vc_name, SA_MAX_VCNAME_LEN) > 0)
    dbg_printf("mpls_vc_name %s\n", vc_name);
  vll_vc_id = getData32(sample);
  dbg_printf("mpls_vll_vc_id %u\n", vll_vc_id);
  vc_cos = getData32(sample);
  dbg_printf("mpls_vc_cos %u\n", vc_cos);
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_VC;
}

/*_________________---------------------------__________________
  _________________    readExtendedMplsFTN    __________________
  -----------------___________________________------------------
*/

static void readExtendedMplsFTN(SFSample *sample)
{
#define SA_MAX_FTN_LEN 100
  char ftn_descr[SA_MAX_FTN_LEN+1];
  uint32_t ftn_mask;
  if(getString(sample, ftn_descr, SA_MAX_FTN_LEN) > 0)
    dbg_printf("mpls_ftn_descr %s\n", ftn_descr);
  ftn_mask = getData32(sample);
  dbg_printf("mpls_ftn_mask %u\n", ftn_mask);
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_FTN;
}

/*_________________---------------------------__________________
  _________________  readExtendedMplsLDP_FEC  __________________
  -----------------___________________________------------------
*/

static void readExtendedMplsLDP_FEC(SFSample *sample)
{
#ifdef DEVEL
  uint32_t fec_addr_prefix_len = getData32(sample);
  dbg_printf("mpls_fec_addr_prefix_len %u\n", fec_addr_prefix_len);
#endif
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_LDP_FEC;
}

/*_________________---------------------------__________________
  _________________  readExtendedVlanTunnel   __________________
  -----------------___________________________------------------
*/

static void readExtendedVlanTunnel(SFSample *sample)
{
  uint32_t lab;
  SFLLabelStack lstk;
  lstk.depth = getData32(sample);
  /* just point at the lablelstack array */
  if(lstk.depth > 0) lstk.stack = (uint32_t *)sample->datap;
  /* and skip over it in the input */
  skipBytes(sample, lstk.depth * 4);
 
  if(lstk.depth > 0) {
    uint32_t j = 0;
    for(; j < lstk.depth; j++) {
      if(j == 0) dbg_printf("vlan_tunnel ");
      else dbg_printf("-");
      lab = ntohl(lstk.stack[j]);
      dbg_printf("0x%04x.%u.%u.%u",
	     (lab >> 16),       /* TPI */
	     (lab >> 13) & 7,   /* priority */
	     (lab >> 12) & 1,   /* CFI */
	     (lab & 4095));     /* VLAN */
    }
    dbg_printf("\n");
  }
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_VLAN_TUNNEL;
}

/*_________________---------------------------__________________
  _________________  readExtendedWifiPayload  __________________
  -----------------___________________________------------------
*/

static void readExtendedWifiPayload(SFSample *sample)
{
  sf_log_next32(sample, "cipher_suite");
  readFlowSample_header(sample);
}

/*_________________---------------------------__________________
  _________________  readExtendedWifiRx       __________________
  -----------------___________________________------------------
*/

static void readExtendedWifiRx(SFSample *sample)
{
  uint32_t i;
  uint8_t *bssid;
  char ssid[SFL_MAX_SSID_LEN+1];
  if(getString(sample, ssid, SFL_MAX_SSID_LEN) > 0) {
    dbg_printf("rx_SSID %s\n", ssid);
  }

  bssid = (uint8_t *)sample->datap;
  dbg_printf("rx_BSSID ");
  for(i = 0; i < 6; i++) dbg_printf("%02x", bssid[i]);
  dbg_printf("\n");
  skipBytes(sample, 6);

  sf_log_next32(sample, "rx_version");
  sf_log_next32(sample, "rx_channel");
  sf_log_next64(sample, "rx_speed");
  sf_log_next32(sample, "rx_rsni");
  sf_log_next32(sample, "rx_rcpi");
  sf_log_next32(sample, "rx_packet_uS");
}

/*_________________---------------------------__________________
  _________________  readExtendedWifiTx       __________________
  -----------------___________________________------------------
*/

static void readExtendedWifiTx(SFSample *sample)
{
  uint32_t i;
  uint8_t *bssid;
  char ssid[SFL_MAX_SSID_LEN+1];
  if(getString(sample, ssid, SFL_MAX_SSID_LEN) > 0) {
    dbg_printf("tx_SSID %s\n", ssid);
  }

  bssid = (uint8_t *)sample->datap;
  dbg_printf("tx_BSSID ");
  for(i = 0; i < 6; i++) dbg_printf("%02x", bssid[i]);
  dbg_printf("\n");
  skipBytes(sample, 6);

  sf_log_next32(sample, "tx_version");
  sf_log_next32(sample, "tx_transmissions");
  sf_log_next32(sample, "tx_packet_uS");
  sf_log_next32(sample, "tx_retrans_uS");
  sf_log_next32(sample, "tx_channel");
  sf_log_next64(sample, "tx_speed");
  sf_log_next32(sample, "tx_power_mW");
}

/*_________________---------------------------__________________
  _________________  readExtendedAggregation  __________________
  -----------------___________________________------------------
*/

#if 0 /* commenting this out until its caller is uncommented too */
static void readExtendedAggregation(SFSample *sample)
{
  uint32_t i, num_pdus = getData32(sample);
  dbg_printf("aggregation_num_pdus %u\n", num_pdus);
  for(i = 0; i < num_pdus; i++) {
    dbg_printf("aggregation_pdu %u\n", i);
    readFlowSample(sample, NO); /* not sure if this the right one here */
  }
}
#endif

/*_________________---------------------------__________________
  _________________  readFlowSample_header    __________________
  -----------------___________________________------------------
*/

static void readFlowSample_header(SFSample *sample)
{
  dbg_printf("flowSampleType HEADER\n");
  sample->headerProtocol = getData32(sample);
  dbg_printf("headerProtocol %u\n", sample->headerProtocol);
  sample->sampledPacketSize = getData32(sample);
  dbg_printf("sampledPacketSize %u\n", sample->sampledPacketSize);
  if(sample->datagramVersion > 4) {
    /* stripped count introduced in sFlow version 5 */
    sample->stripped = getData32(sample);
    dbg_printf("strippedBytes %u\n", sample->stripped);
  }
  sample->headerLen = getData32(sample);
  dbg_printf("headerLen %u\n", sample->headerLen);
  
  sample->header = (uint8_t *)sample->datap; /* just point at the header */
  skipBytes(sample, sample->headerLen);
  {
    char scratch[2000];
    printHex(sample->header, sample->headerLen, scratch, 2000, 0, 2000);
    dbg_printf("headerBytes %s\n", scratch);
  }
  
  switch(sample->headerProtocol) {
    /* the header protocol tells us where to jump into the decode */
  case SFLHEADER_ETHERNET_ISO8023:
    decodeLinkLayer(sample);
    break;
  case SFLHEADER_IPv4: 
    sample->gotIPV4 = YES;
    sample->offsetToIPV4 = 0;
    break;
  case SFLHEADER_IPv6: 
    sample->gotIPV6 = YES;
    sample->offsetToIPV6 = 0;
    break;
  case SFLHEADER_IEEE80211MAC:
    decode80211MAC(sample);
    break;
  case SFLHEADER_ISO88024_TOKENBUS:
  case SFLHEADER_ISO88025_TOKENRING:
  case SFLHEADER_FDDI:
  case SFLHEADER_FRAME_RELAY:
  case SFLHEADER_X25:
  case SFLHEADER_PPP:
  case SFLHEADER_SMDS:
  case SFLHEADER_AAL5:
  case SFLHEADER_AAL5_IP:
  case SFLHEADER_MPLS:
  case SFLHEADER_POS:
  case SFLHEADER_IEEE80211_AMPDU:
  case SFLHEADER_IEEE80211_AMSDU_SUBFRAME:
    dbg_printf("NO_DECODE headerProtocol=%d\n", sample->headerProtocol);
    break;
  default:
    LogError("SFLOW: readFlowSample_header() undefined headerProtocol = %d\n", sample->headerProtocol);
    exit(-12);
  }
  
  if(sample->gotIPV4) {
    /* report the size of the original IPPdu (including the IP header) */
    dbg_printf("IPSize %d\n",  sample->sampledPacketSize - sample->stripped - sample->offsetToIPV4);
    decodeIPV4(sample);
  }
  else if(sample->gotIPV6) {
    /* report the size of the original IPPdu (including the IP header) */
    dbg_printf("IPSize %d\n",  sample->sampledPacketSize - sample->stripped - sample->offsetToIPV6);
    decodeIPV6(sample);
  }

}

/*_________________---------------------------__________________
  _________________  readFlowSample_ethernet  __________________
  -----------------___________________________------------------
*/

static void readFlowSample_ethernet(SFSample *sample, char *prefix)
{
  uint8_t *p;
  dbg_printf("flowSampleType %sETHERNET\n", prefix);
  sample->eth_len = getData32(sample);
  memcpy(sample->eth_src, sample->datap, 6);
  skipBytes(sample, 6);
  memcpy(sample->eth_dst, sample->datap, 6);
  skipBytes(sample, 6);
  sample->eth_type = getData32(sample);
  dbg_printf("%sethernet_type %u\n", prefix, sample->eth_type);
  dbg_printf("%sethernet_len %u\n", prefix, sample->eth_len);
  p = sample->eth_src;
  dbg_printf("%sethernet_src %02x%02x%02x%02x%02x%02x\n", prefix, p[0], p[1], p[2], p[3], p[4], p[5]);
  p = sample->eth_dst;
  dbg_printf("%sethernet_dst %02x%02x%02x%02x%02x%02x\n", prefix, p[0], p[1], p[2], p[3], p[4], p[5]);
}


/*_________________---------------------------__________________
  _________________    readFlowSample_IPv4    __________________
  -----------------___________________________------------------
*/

static void readFlowSample_IPv4(SFSample *sample, char *prefix)
{
  dbg_printf("flowSampleType %sIPV4\n", prefix);
  sample->headerLen = sizeof(SFLSampled_ipv4);
  sample->header = (uint8_t *)sample->datap; /* just point at the header */
  skipBytes(sample, sample->headerLen);
  {
#ifdef DEVEL
    char buf[51];
#endif
    SFLSampled_ipv4 nfKey;
    memcpy(&nfKey, sample->header, sizeof(nfKey));
    sample->sampledPacketSize = ntohl(nfKey.length);
    dbg_printf("%ssampledPacketSize %u\n", prefix, sample->sampledPacketSize); 
    dbg_printf("%sIPSize %u\n", prefix,  sample->sampledPacketSize);
    sample->ipsrc.type = SFLADDRESSTYPE_IP_V4;
    sample->ipsrc.address.ip_v4 = nfKey.src_ip;
    sample->ipdst.type = SFLADDRESSTYPE_IP_V4;
    sample->ipdst.address.ip_v4 = nfKey.dst_ip;
    sample->dcd_ipProtocol = ntohl(nfKey.protocol);
    sample->dcd_ipTos = ntohl(nfKey.tos);
    dbg_printf("%ssrcIP %s\n", prefix, printAddress(&sample->ipsrc, buf, 50));
    dbg_printf("%sdstIP %s\n", prefix, printAddress(&sample->ipdst, buf, 50));
    dbg_printf("%sIPProtocol %u\n", prefix, sample->dcd_ipProtocol);
    dbg_printf("%sIPTOS %u\n", prefix, sample->dcd_ipTos);
    sample->dcd_sport = ntohl(nfKey.src_port);
    sample->dcd_dport = ntohl(nfKey.dst_port);
    switch(sample->dcd_ipProtocol) {
    case 1: /* ICMP */
      dbg_printf("%sICMPType %u\n", prefix, sample->dcd_dport);
      /* not sure about the dest port being icmp type
	 - might be that src port is icmp type and dest
	 port is icmp code.  Still, have seen some
	 implementations where src port is 0 and dst
	 port is the type, so it may be safer to
	 assume that the destination port has the type */
      break;
    case 6: /* TCP */
      dbg_printf("%sTCPSrcPort %u\n", prefix, sample->dcd_sport);
      dbg_printf("%sTCPDstPort %u\n", prefix, sample->dcd_dport);
      sample->dcd_tcpFlags = ntohl(nfKey.tcp_flags);
      dbg_printf("%sTCPFlags %u\n", prefix, sample->dcd_tcpFlags);
      break;
    case 17: /* UDP */
      dbg_printf("%sUDPSrcPort %u\n", prefix, sample->dcd_sport);
      dbg_printf("%sUDPDstPort %u\n", prefix, sample->dcd_dport);
      break;
    default: /* some other protcol */
      break;
    }
  }
}

/*_________________---------------------------__________________
  _________________    readFlowSample_IPv6    __________________
  -----------------___________________________------------------
*/

static void readFlowSample_IPv6(SFSample *sample, char *prefix)
{
  dbg_printf("flowSampleType %sIPV6\n", prefix);
  sample->header = (uint8_t *)sample->datap; /* just point at the header */
  sample->headerLen = sizeof(SFLSampled_ipv6);
  skipBytes(sample, sample->headerLen);
  {
#ifdef DEVEL
    char buf[51];
#endif
    SFLSampled_ipv6 nfKey6;
    memcpy(&nfKey6, sample->header, sizeof(nfKey6));
    sample->sampledPacketSize = ntohl(nfKey6.length);
    dbg_printf("%ssampledPacketSize %u\n", prefix, sample->sampledPacketSize); 
    dbg_printf("%sIPSize %u\n", prefix, sample->sampledPacketSize); 
    sample->ipsrc.type = SFLADDRESSTYPE_IP_V6;
    memcpy(&sample->ipsrc.address.ip_v6, &nfKey6.src_ip, 16);
    sample->ipdst.type = SFLADDRESSTYPE_IP_V6;
    memcpy(&sample->ipdst.address.ip_v6, &nfKey6.dst_ip, 16);
    sample->dcd_ipProtocol = ntohl(nfKey6.protocol);
    dbg_printf("%ssrcIP6 %s\n", prefix, printAddress(&sample->ipsrc, buf, 50));
    dbg_printf("%sdstIP6 %s\n", prefix, printAddress(&sample->ipdst, buf, 50));
    dbg_printf("%sIPProtocol %u\n", prefix, sample->dcd_ipProtocol);
    dbg_printf("%spriority %u\n", prefix, ntohl(nfKey6.priority));
    sample->dcd_sport = ntohl(nfKey6.src_port);
    sample->dcd_dport = ntohl(nfKey6.dst_port);
    switch(sample->dcd_ipProtocol) {
    case 1: /* ICMP */
      dbg_printf("%sICMPType %u\n", prefix, sample->dcd_dport);
      /* not sure about the dest port being icmp type
	 - might be that src port is icmp type and dest
	 port is icmp code.  Still, have seen some
	 implementations where src port is 0 and dst
	 port is the type, so it may be safer to
	 assume that the destination port has the type */
      break;
    case 6: /* TCP */
      dbg_printf("%sTCPSrcPort %u\n", prefix, sample->dcd_sport);
      dbg_printf("%sTCPDstPort %u\n", prefix, sample->dcd_dport);
      sample->dcd_tcpFlags = ntohl(nfKey6.tcp_flags);
      dbg_printf("%sTCPFlags %u\n", prefix, sample->dcd_tcpFlags);
      break;
    case 17: /* UDP */
      dbg_printf("%sUDPSrcPort %u\n", prefix, sample->dcd_sport);
      dbg_printf("%sUDPDstPort %u\n", prefix, sample->dcd_dport);
      break;
    default: /* some other protcol */
      break;
    }
  }
}

/*_________________----------------------------__________________
  _________________  readFlowSample_memcache   __________________
  -----------------____________________________------------------
*/

static void readFlowSample_memcache(SFSample *sample)
{
  char key[SFL_MAX_MEMCACHE_KEY+1];
#define ENC_KEY_BYTES (SFL_MAX_MEMCACHE_KEY * 3) + 1
  dbg_printf("flowSampleType memcache\n");
  sf_log_next32(sample, "memcache_op_protocol");
  sf_log_next32(sample, "memcache_op_cmd");
  if(getString(sample, key, SFL_MAX_MEMCACHE_KEY) > 0) {
#ifdef DEVEL
  	char enc_key[ENC_KEY_BYTES];
    dbg_printf("memcache_op_key %s\n", URLEncode(key, enc_key, ENC_KEY_BYTES));
#endif
  }
  sf_log_next32(sample, "memcache_op_nkeys");
  sf_log_next32(sample, "memcache_op_value_bytes");
  sf_log_next32(sample, "memcache_op_duration_uS");
  sf_log_next32(sample, "memcache_op_status");
}

/*_________________----------------------------__________________
  _________________  readFlowSample_http       __________________
  -----------------____________________________------------------
*/

/* absorb compiler warning about strftime printing */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat"

static void readFlowSample_http(SFSample *sample, uint32_t tag)
{
  char uri[SFL_MAX_HTTP_URI+1];
  char host[SFL_MAX_HTTP_HOST+1];
  char referrer[SFL_MAX_HTTP_REFERRER+1];
  char useragent[SFL_MAX_HTTP_USERAGENT+1];
  char xff[SFL_MAX_HTTP_XFF+1];
  char authuser[SFL_MAX_HTTP_AUTHUSER+1];
  char mimetype[SFL_MAX_HTTP_MIMETYPE+1];
  uint32_t method;
  uint32_t protocol;
  uint32_t status;
  uint64_t req_bytes;
  uint64_t resp_bytes;

  dbg_printf("flowSampleType http\n");
  method = sf_log_next32(sample, "http_method");
  protocol = sf_log_next32(sample, "http_protocol");
  if(getString(sample, uri, SFL_MAX_HTTP_URI) > 0) {
    dbg_printf("http_uri %s\n", uri);
  }
  if(getString(sample, host, SFL_MAX_HTTP_HOST) > 0) {
    dbg_printf("http_host %s\n", host);
  }
  if(getString(sample, referrer, SFL_MAX_HTTP_REFERRER) > 0) {
    dbg_printf("http_referrer %s\n", referrer);
  }
  if(getString(sample, useragent, SFL_MAX_HTTP_USERAGENT) > 0) {
    dbg_printf("http_useragent %s\n", useragent);
  }
  if(tag == SFLFLOW_HTTP2) {
    if(getString(sample, xff, SFL_MAX_HTTP_XFF) > 0) {
      dbg_printf("http_xff %s\n", xff);
    }
  }
  if(getString(sample, authuser, SFL_MAX_HTTP_AUTHUSER) > 0) {
    dbg_printf("http_authuser %s\n", authuser);
  }
  if(getString(sample, mimetype, SFL_MAX_HTTP_MIMETYPE) > 0) {
    dbg_printf("http_mimetype %s\n", mimetype);
  }
  if(tag == SFLFLOW_HTTP2) {
    req_bytes = sf_log_next64(sample, "http_request_bytes");
  }
  resp_bytes = sf_log_next64(sample, "http_bytes");
  sf_log_next32(sample, "http_duration_uS");
  status = sf_log_next32(sample, "http_status");

// XXX
#ifdef DEVEL
  {
	static const char *SFHTTP_method_names[] = { "-", "OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT" };

    time_t now = time(NULL);
    char nowstr[200];
    strftime(nowstr, 200, "%d/%b/%Y:%H:%M:%S %z", localtime(&now)); /* there seems to be no simple portable equivalent to %z */
    /* should really be: snprintf(sfCLF.http_log, SFLFMT_CLF_MAX_LINE,...) but snprintf() is not always available */
    printf("- %s [%s] \"%s %s HTTP/%u.%u\" %u %llu \"%s\" \"%s\"",
	     authuser[0] ? authuser : "-",
	     nowstr,
	     SFHTTP_method_names[method],
	     uri[0] ? uri : "-",
	     protocol / 1000,
	     protocol % 1000,
	     status,
	     resp_bytes,
	     referrer[0] ? referrer : "-",
	     useragent[0] ? useragent : "-");
  }
#endif
}

#pragma GCC diagnostic pop

/*_________________----------------------------__________________
  _________________  readFlowSample_APP        __________________
  -----------------____________________________------------------
*/

static void readFlowSample_APP(SFSample *sample)
{
  char application[SFLAPP_MAX_APPLICATION_LEN];
  char operation[SFLAPP_MAX_OPERATION_LEN];
  char attributes[SFLAPP_MAX_ATTRIBUTES_LEN];
  char status[SFLAPP_MAX_STATUS_LEN];
  uint32_t status32;

  dbg_printf("flowSampleType applicationOperation\n");

  if(getString(sample, application, SFLAPP_MAX_APPLICATION_LEN) > 0) {
    dbg_printf("application %s\n", application);
  }
  if(getString(sample, operation, SFLAPP_MAX_OPERATION_LEN) > 0) {
    dbg_printf("operation %s\n", operation);
  }
  if(getString(sample, attributes, SFLAPP_MAX_ATTRIBUTES_LEN) > 0) {
    dbg_printf("attributes %s\n", attributes);
  }
  if(getString(sample, status, SFLAPP_MAX_STATUS_LEN) > 0) {
    dbg_printf("status_descr %s\n", status);
  }
  sf_log_next64(sample, "request_bytes");
  sf_log_next64(sample, "response_bytes");
  sf_log_next32(sample, "duration_uS");
  status32 = getData32(sample);
  if(status32 >= SFLAPP_NUM_STATUS_CODES)
    dbg_printf("status <out-of-range=%u>\n", status32);
  else
    dbg_printf("status %s\n", SFL_APP_STATUS_names[status32]);
}


/*_________________----------------------------__________________
  _________________  readFlowSample_APP_CTXT   __________________
  -----------------____________________________------------------
*/

static void readFlowSample_APP_CTXT(SFSample *sample)
{
  char application[SFLAPP_MAX_APPLICATION_LEN];
  char operation[SFLAPP_MAX_OPERATION_LEN];
  char attributes[SFLAPP_MAX_ATTRIBUTES_LEN];
  if(getString(sample, application, SFLAPP_MAX_APPLICATION_LEN) > 0) {
    dbg_printf("server_context_application %s\n", application);
  }
  if(getString(sample, operation, SFLAPP_MAX_OPERATION_LEN) > 0) {
    dbg_printf("server_context_operation %s\n", operation);
  }
  if(getString(sample, attributes, SFLAPP_MAX_ATTRIBUTES_LEN) > 0) {
    dbg_printf("server_context_attributes %s\n", attributes);
  }
}

/*_________________---------------------------------__________________
  _________________  readFlowSample_APP_ACTOR_INIT  __________________
  -----------------_________________________________------------------
*/

static void readFlowSample_APP_ACTOR_INIT(SFSample *sample)
{
  char actor[SFLAPP_MAX_ACTOR_LEN];
  if(getString(sample, actor, SFLAPP_MAX_ACTOR_LEN) > 0) {
    dbg_printf("actor_initiator %s\n", actor);
  }
}

/*_________________---------------------------------__________________
  _________________  readFlowSample_APP_ACTOR_TGT   __________________
  -----------------_________________________________------------------
*/

static void readFlowSample_APP_ACTOR_TGT(SFSample *sample)
{
  char actor[SFLAPP_MAX_ACTOR_LEN];
  if(getString(sample, actor, SFLAPP_MAX_ACTOR_LEN) > 0) {
    dbg_printf("actor_target %s\n", actor);
  }
}

/*_________________----------------------------__________________
  _________________   readExtendedSocket4      __________________
  -----------------____________________________------------------
*/

static void readExtendedSocket4(SFSample *sample)
{
#ifdef DEVEL
  char buf[51];
#endif
  dbg_printf("extendedType socket4\n");
  sf_log_next32(sample, "socket4_ip_protocol");
  sample->ipsrc.type = SFLADDRESSTYPE_IP_V4;
  sample->ipsrc.address.ip_v4.addr = getData32_nobswap(sample);
  sample->ipdst.type = SFLADDRESSTYPE_IP_V4;
  sample->ipdst.address.ip_v4.addr = getData32_nobswap(sample);
  dbg_printf("socket4_local_ip %s\n", printAddress(&sample->ipsrc, buf, 50));
  dbg_printf("socket4_remote_ip %s\n", printAddress(&sample->ipdst, buf, 50));
  sf_log_next32(sample, "socket4_local_port");
  sf_log_next32(sample, "socket4_remote_port");
  
}

/*_________________----------------------------__________________
  _________________ readExtendedProxySocket4   __________________
  -----------------____________________________------------------
*/

static void readExtendedProxySocket4(SFSample *sample)
{
#ifdef DEVEL
  char buf[51];
#endif
  SFLAddress ipsrc,ipdst;
  dbg_printf("extendedType proxy_socket4\n");
  sf_log_next32(sample, "proxy_socket4_ip_protocol");
  ipsrc.type = SFLADDRESSTYPE_IP_V4;
  ipsrc.address.ip_v4.addr = getData32_nobswap(sample);
  ipdst.type = SFLADDRESSTYPE_IP_V4;
  ipdst.address.ip_v4.addr = getData32_nobswap(sample);
  dbg_printf("proxy_socket4_local_ip %s\n", printAddress(&ipsrc, buf, 50));
  dbg_printf("proxy_socket4_remote_ip %s\n", printAddress(&ipdst, buf, 50));
  sf_log_next32(sample, "proxy_socket4_local_port");
  sf_log_next32(sample, "proxy_socket4_remote_port");
}

/*_________________----------------------------__________________
  _________________  readExtendedSocket6       __________________
  -----------------____________________________------------------
*/

static void readExtendedSocket6(SFSample *sample)
{
#ifdef DEVEL
  char buf[51];
#endif
  dbg_printf("extendedType socket6\n");
  sf_log_next32(sample, "socket6_ip_protocol");
  sample->ipsrc.type = SFLADDRESSTYPE_IP_V6;
  memcpy(&sample->ipsrc.address.ip_v6, sample->datap, 16);
  skipBytes(sample, 16);
  sample->ipdst.type = SFLADDRESSTYPE_IP_V6;
  memcpy(&sample->ipdst.address.ip_v6, sample->datap, 16);
  skipBytes(sample, 16);
  dbg_printf("socket6_local_ip %s\n", printAddress(&sample->ipsrc, buf, 50));
  dbg_printf("socket6_remote_ip %s\n", printAddress(&sample->ipdst, buf, 50));
  sf_log_next32(sample, "socket6_local_port");
  sf_log_next32(sample, "socket6_remote_port");

}

/*_________________----------------------------__________________
  _________________ readExtendedProxySocket6   __________________
  -----------------____________________________------------------
*/

static void readExtendedProxySocket6(SFSample *sample)
{
#ifdef DEVEL
  char buf[51];
#endif
  SFLAddress ipsrc, ipdst;
  dbg_printf("extendedType proxy_socket6\n");
  sf_log_next32(sample, "proxy_socket6_ip_protocol");
  ipsrc.type = SFLADDRESSTYPE_IP_V6;
  memcpy(&ipsrc.address.ip_v6, sample->datap, 16);
  skipBytes(sample, 16);
  ipdst.type = SFLADDRESSTYPE_IP_V6;
  memcpy(&ipdst.address.ip_v6, sample->datap, 16);
  skipBytes(sample, 16);
  dbg_printf("proxy_socket6_local_ip %s\n", printAddress(&ipsrc, buf, 50));
  dbg_printf("proxy_socket6_remote_ip %s\n", printAddress(&ipdst, buf, 50));
  sf_log_next32(sample, "proxy_socket6_local_port");
  sf_log_next32(sample, "proxy_socket6_remote_port");
}

/*_________________----------------------------__________________
  _________________    readExtendedDecap       __________________
  -----------------____________________________------------------
*/

static void readExtendedDecap(SFSample *sample, char *prefix)
{
#ifdef DEVEL
  uint32_t offset = getData32(sample);
  dbg_printf("extendedType %sdecap\n", prefix);
  dbg_printf("%sdecap_inner_header_offset %u\n", prefix, offset);
#endif
}

/*_________________----------------------------__________________
  _________________    readExtendedVNI         __________________
  -----------------____________________________------------------
*/

static void readExtendedVNI(SFSample *sample, char *prefix)
{
#ifdef DEVEL
  uint32_t vni = getData32(sample);
  dbg_printf("extendedType %sVNI\n", prefix);
  dbg_printf("%sVNI %u\n", prefix, vni);
#endif
}

/*_________________----------------------------__________________
  _________________    readExtendedTCPInfo     __________________
  -----------------____________________________------------------
*/

static void readExtendedTCPInfo(SFSample *sample)
{
  char *direction;
  EnumPktDirection dirn = getData32(sample);
  switch(dirn) {
  case PKTDIR_unknown: direction = "unknown"; break;
  case PKTDIR_received: direction = "received"; break;
  case PKTDIR_sent: direction = "sent"; break;
  default: direction = "<bad value>"; break;
  }
  dbg_printf( "tcpinfo_direction %s\n", direction);
  sf_log_next32(sample, "tcpinfo_send_mss");
  sf_log_next32(sample, "tcpinfo_receive_mss");
  sf_log_next32(sample, "tcpinfo_unacked_pkts");
  sf_log_next32(sample, "tcpinfo_lost_pkts");
  sf_log_next32(sample, "tcpinfo_retrans_pkts");
  sf_log_next32(sample, "tcpinfo_path_mtu");
  sf_log_next32(sample, "tcpinfo_rtt_uS");
  sf_log_next32(sample, "tcpinfo_rtt_uS_var");
  sf_log_next32(sample, "tcpinfo_send_congestion_win");
  sf_log_next32(sample, "tcpinfo_reordering");
  sf_log_next32(sample, "tcpinfo_rtt_uS_min");
}

/*_________________---------------------------__________________
  _________________    readFlowSample_v2v4    __________________
  -----------------___________________________------------------
*/

static void readFlowSample_v2v4(SFSample *sample, FlowSource_t *fs)
{
  dbg_printf("sampleType FLOWSAMPLE\n");

  sample->samplesGenerated = getData32(sample);
  dbg_printf("sampleSequenceNo %u\n", sample->samplesGenerated);
  {
    uint32_t samplerId = getData32(sample);
    sample->ds_class = samplerId >> 24;
    sample->ds_index = samplerId & 0x00ffffff;
    dbg_printf("sourceId %u:%u\n", sample->ds_class, sample->ds_index);
  }
  
  sample->meanSkipCount = getData32(sample);
  sample->samplePool = getData32(sample);
  sample->dropEvents = getData32(sample);
  sample->inputPort = getData32(sample);
  sample->outputPort = getData32(sample);
  dbg_printf("meanSkipCount %u\n", sample->meanSkipCount);
  dbg_printf("samplePool %u\n", sample->samplePool);
  dbg_printf("dropEvents %u\n", sample->dropEvents);
  dbg_printf("inputPort %u\n", sample->inputPort);
  if(sample->outputPort & 0x80000000) {
    uint32_t numOutputs = sample->outputPort & 0x7fffffff;
    if(numOutputs > 0) dbg_printf("outputPort multiple %d\n", numOutputs);
    else dbg_printf("outputPort multiple >1\n");
  }
  else dbg_printf("outputPort %u\n", sample->outputPort);
  
  sample->packet_data_tag = getData32(sample);
  
  switch(sample->packet_data_tag) {
    
  case INMPACKETTYPE_HEADER: readFlowSample_header(sample); break;
  case INMPACKETTYPE_IPV4:
    sample->gotIPV4Struct = YES;
    readFlowSample_IPv4(sample, "");
    break;
  case INMPACKETTYPE_IPV6:
    sample->gotIPV6Struct = YES;
    readFlowSample_IPv6(sample, "");
    break;
  default: receiveError(sample, "unexpected packet_data_tag", YES); break;
  }

  sample->extended_data_tag = 0;
  {
    uint32_t x;
    sample->num_extended = getData32(sample);
    for(x = 0; x < sample->num_extended; x++) {
      uint32_t extended_tag;
      extended_tag = getData32(sample);
      switch(extended_tag) {
      case INMEXTENDED_SWITCH: readExtendedSwitch(sample); break;
      case INMEXTENDED_ROUTER: readExtendedRouter(sample); break;
      case INMEXTENDED_GATEWAY:
	if(sample->datagramVersion == 2) readExtendedGateway_v2(sample);
	else readExtendedGateway(sample);
	break;
      case INMEXTENDED_USER: readExtendedUser(sample); break;
      case INMEXTENDED_URL: readExtendedUrl(sample); break;
      default: receiveError(sample, "unrecognized extended data tag", YES); break;
      }
    }
  }

	if(sample->gotIPV4 || sample->gotIPV6) 
		StoreSflowRecord(sample, fs);

	if ( verbose ) 
		writeFlowLine(sample);

}

/*_________________---------------------------__________________
  _________________    readFlowSample         __________________
  -----------------___________________________------------------
*/

static void readFlowSample(SFSample *sample, int expanded, FlowSource_t *fs)
{
  uint32_t num_elements, sampleLength;
  uint8_t *sampleStart;

  dbg_printf("sampleType FLOWSAMPLE\n");
  sampleLength = getData32(sample);
  sampleStart = (uint8_t *)sample->datap;
  sample->samplesGenerated = getData32(sample);
  dbg_printf("sampleSequenceNo %u\n", sample->samplesGenerated);
  if(expanded) {
    sample->ds_class = getData32(sample);
    sample->ds_index = getData32(sample);
  }
  else {
    uint32_t samplerId = getData32(sample);
    sample->ds_class = samplerId >> 24;
    sample->ds_index = samplerId & 0x00ffffff;
  }
  dbg_printf("sourceId %u:%u\n", sample->ds_class, sample->ds_index);

  sample->meanSkipCount = getData32(sample);
  sample->samplePool = getData32(sample);
  sample->dropEvents = getData32(sample);
  dbg_printf("meanSkipCount %u\n", sample->meanSkipCount);
  dbg_printf("samplePool %u\n", sample->samplePool);
  dbg_printf("dropEvents %u\n", sample->dropEvents);
  if(expanded) {
    sample->inputPortFormat = getData32(sample);
    sample->inputPort = getData32(sample);
    sample->outputPortFormat = getData32(sample);
    sample->outputPort = getData32(sample);
  }
  else {
    uint32_t inp, outp;
    inp = getData32(sample);
    outp = getData32(sample);
    sample->inputPortFormat = inp >> 30;
    sample->outputPortFormat = outp >> 30;
    sample->inputPort = inp & 0x3fffffff;
    sample->outputPort = outp & 0x3fffffff;
  }

  switch(sample->inputPortFormat) {
  case 3: dbg_printf("inputPort format==3 %u\n", sample->inputPort); break;
  case 2: dbg_printf("inputPort multiple %u\n", sample->inputPort); break;
  case 1: dbg_printf("inputPort dropCode %u\n", sample->inputPort); break;
  case 0: dbg_printf("inputPort %u\n", sample->inputPort); break;
  }

  switch(sample->outputPortFormat) {
  case 3: dbg_printf("outputPort format==3 %u\n", sample->outputPort); break;
  case 2: dbg_printf("outputPort multiple %u\n", sample->outputPort); break;
  case 1: dbg_printf("outputPort dropCode %u\n", sample->outputPort); break;
  case 0: dbg_printf("outputPort %u\n", sample->outputPort); break;
  }

  num_elements = getData32(sample);
  {
    uint32_t el;
    for(el = 0; el < num_elements; el++) {
      uint32_t tag, length;
      uint8_t *start;
#ifdef DEVEL
      char buf[51];
#endif
      tag = sample->elementType = getData32(sample);
      dbg_printf("flowBlock_tag %s\n", printTag(tag, buf, 50));
      length = getData32(sample);
      start = (uint8_t *)sample->datap;

      switch(tag) {
      case SFLFLOW_HEADER:     readFlowSample_header(sample); break;
      case SFLFLOW_ETHERNET:   readFlowSample_ethernet(sample, ""); break;
      case SFLFLOW_IPV4:       readFlowSample_IPv4(sample, ""); break;
      case SFLFLOW_IPV6:       readFlowSample_IPv6(sample, ""); break;
      case SFLFLOW_MEMCACHE:   readFlowSample_memcache(sample); break;
      case SFLFLOW_HTTP:       readFlowSample_http(sample, tag); break;
      case SFLFLOW_HTTP2:      readFlowSample_http(sample, tag); break;
      case SFLFLOW_APP:        readFlowSample_APP(sample); break;
      case SFLFLOW_APP_CTXT:   readFlowSample_APP_CTXT(sample); break;
      case SFLFLOW_APP_ACTOR_INIT: readFlowSample_APP_ACTOR_INIT(sample); break;
      case SFLFLOW_APP_ACTOR_TGT: readFlowSample_APP_ACTOR_TGT(sample); break;
      case SFLFLOW_EX_SWITCH:  readExtendedSwitch(sample); break;
      case SFLFLOW_EX_ROUTER:  readExtendedRouter(sample); break;
      case SFLFLOW_EX_GATEWAY: readExtendedGateway(sample); break;
      case SFLFLOW_EX_USER:    readExtendedUser(sample); break;
      case SFLFLOW_EX_URL:     readExtendedUrl(sample); break;
      case SFLFLOW_EX_MPLS:    readExtendedMpls(sample); break;
      case SFLFLOW_EX_NAT:     readExtendedNat(sample); break;
      case SFLFLOW_EX_NAT_PORT:     readExtendedNatPort(sample); break;
      case SFLFLOW_EX_MPLS_TUNNEL:  readExtendedMplsTunnel(sample); break;
      case SFLFLOW_EX_MPLS_VC:      readExtendedMplsVC(sample); break;
      case SFLFLOW_EX_MPLS_FTN:     readExtendedMplsFTN(sample); break;
      case SFLFLOW_EX_MPLS_LDP_FEC: readExtendedMplsLDP_FEC(sample); break;
      case SFLFLOW_EX_VLAN_TUNNEL:  readExtendedVlanTunnel(sample); break;
      case SFLFLOW_EX_80211_PAYLOAD: readExtendedWifiPayload(sample); break;
      case SFLFLOW_EX_80211_RX: readExtendedWifiRx(sample); break;
      case SFLFLOW_EX_80211_TX: readExtendedWifiTx(sample); break;
	/* case SFLFLOW_EX_AGGREGATION: readExtendedAggregation(sample); break; */
      case SFLFLOW_EX_SOCKET4: readExtendedSocket4(sample); break;
      case SFLFLOW_EX_SOCKET6: readExtendedSocket6(sample); break;
      case SFLFLOW_EX_PROXYSOCKET4: readExtendedProxySocket4(sample); break;
      case SFLFLOW_EX_PROXYSOCKET6: readExtendedProxySocket6(sample); break;
      case SFLFLOW_EX_L2_TUNNEL_OUT: readFlowSample_ethernet(sample, "tunnel_l2_out_"); break;
      case SFLFLOW_EX_L2_TUNNEL_IN: readFlowSample_ethernet(sample, "tunnel_l2_in_"); break;
      case SFLFLOW_EX_IPV4_TUNNEL_OUT: readFlowSample_IPv4(sample, "tunnel_ipv4_out_"); break;
      case SFLFLOW_EX_IPV4_TUNNEL_IN: readFlowSample_IPv4(sample, "tunnel_ipv4_in_"); break;
      case SFLFLOW_EX_IPV6_TUNNEL_OUT: readFlowSample_IPv6(sample, "tunnel_ipv6_out_"); break;
      case SFLFLOW_EX_IPV6_TUNNEL_IN: readFlowSample_IPv6(sample, "tunnel_ipv6_in_"); break;
      case SFLFLOW_EX_DECAP_OUT: readExtendedDecap(sample, "out_"); break;
      case SFLFLOW_EX_DECAP_IN: readExtendedDecap(sample, "in_"); break;
      case SFLFLOW_EX_VNI_OUT: readExtendedVNI(sample, "out_"); break;
      case SFLFLOW_EX_VNI_IN: readExtendedVNI(sample, "in_"); break;
      case SFLFLOW_EX_TCP_INFO: readExtendedTCPInfo(sample); break;
      default: skipTLVRecord(sample, tag, length, "flow_sample_element"); break;
      }
      lengthCheck(sample, "flow_sample_element", start, length);
    }
  }
  lengthCheck(sample, "flow_sample", sampleStart, sampleLength);

 	if ( sample->gotIPV4 || sample->gotIPV6 )
		StoreSflowRecord(sample, fs);

	/* or line-by-line output... */
	if ( verbose ) 
		writeFlowLine(sample);
 
}

/*_________________---------------------------__________________
  _________________  readCounters_generic     __________________
  -----------------___________________________------------------
*/

static void readCounters_generic(SFSample *sample)
{
  /* the first part of the generic counters block is really just more info about the interface. */
  sample->ifCounters.ifIndex = sf_log_next32(sample, "ifIndex");
  sample->ifCounters.ifType = sf_log_next32(sample, "networkType");
  sample->ifCounters.ifSpeed = sf_log_next64(sample, "ifSpeed");
  sample->ifCounters.ifDirection = sf_log_next32(sample, "ifDirection");
  sample->ifCounters.ifStatus = sf_log_next32(sample, "ifStatus");
  /* the generic counters always come first */
  sample->ifCounters.ifInOctets = sf_log_next64(sample, "ifInOctets");
  sample->ifCounters.ifInUcastPkts = sf_log_next32(sample, "ifInUcastPkts");
  sample->ifCounters.ifInMulticastPkts = sf_log_next32(sample, "ifInMulticastPkts");
  sample->ifCounters.ifInBroadcastPkts = sf_log_next32(sample, "ifInBroadcastPkts");
  sample->ifCounters.ifInDiscards = sf_log_next32(sample, "ifInDiscards");
  sample->ifCounters.ifInErrors = sf_log_next32(sample, "ifInErrors");
  sample->ifCounters.ifInUnknownProtos = sf_log_next32(sample, "ifInUnknownProtos");
  sample->ifCounters.ifOutOctets = sf_log_next64(sample, "ifOutOctets");
  sample->ifCounters.ifOutUcastPkts = sf_log_next32(sample, "ifOutUcastPkts");
  sample->ifCounters.ifOutMulticastPkts = sf_log_next32(sample, "ifOutMulticastPkts");
  sample->ifCounters.ifOutBroadcastPkts = sf_log_next32(sample, "ifOutBroadcastPkts");
  sample->ifCounters.ifOutDiscards = sf_log_next32(sample, "ifOutDiscards");
  sample->ifCounters.ifOutErrors = sf_log_next32(sample, "ifOutErrors");
  sample->ifCounters.ifPromiscuousMode = sf_log_next32(sample, "ifPromiscuousMode");
}
 
/*_________________---------------------------__________________
  _________________  readCounters_ethernet    __________________
  -----------------___________________________------------------
*/

static  void readCounters_ethernet(SFSample *sample)
{
  sf_log_next32(sample, "dot3StatsAlignmentErrors");
  sf_log_next32(sample, "dot3StatsFCSErrors");
  sf_log_next32(sample, "dot3StatsSingleCollisionFrames");
  sf_log_next32(sample, "dot3StatsMultipleCollisionFrames");
  sf_log_next32(sample, "dot3StatsSQETestErrors");
  sf_log_next32(sample, "dot3StatsDeferredTransmissions");
  sf_log_next32(sample, "dot3StatsLateCollisions");
  sf_log_next32(sample, "dot3StatsExcessiveCollisions");
  sf_log_next32(sample, "dot3StatsInternalMacTransmitErrors");
  sf_log_next32(sample, "dot3StatsCarrierSenseErrors");
  sf_log_next32(sample, "dot3StatsFrameTooLongs");
  sf_log_next32(sample, "dot3StatsInternalMacReceiveErrors");
  sf_log_next32(sample, "dot3StatsSymbolErrors");
}	  

 
/*_________________---------------------------__________________
  _________________  readCounters_tokenring   __________________
  -----------------___________________________------------------
*/

static void readCounters_tokenring(SFSample *sample)
{
  sf_log_next32(sample, "dot5StatsLineErrors");
  sf_log_next32(sample, "dot5StatsBurstErrors");
  sf_log_next32(sample, "dot5StatsACErrors");
  sf_log_next32(sample, "dot5StatsAbortTransErrors");
  sf_log_next32(sample, "dot5StatsInternalErrors");
  sf_log_next32(sample, "dot5StatsLostFrameErrors");
  sf_log_next32(sample, "dot5StatsReceiveCongestions");
  sf_log_next32(sample, "dot5StatsFrameCopiedErrors");
  sf_log_next32(sample, "dot5StatsTokenErrors");
  sf_log_next32(sample, "dot5StatsSoftErrors");
  sf_log_next32(sample, "dot5StatsHardErrors");
  sf_log_next32(sample, "dot5StatsSignalLoss");
  sf_log_next32(sample, "dot5StatsTransmitBeacons");
  sf_log_next32(sample, "dot5StatsRecoverys");
  sf_log_next32(sample, "dot5StatsLobeWires");
  sf_log_next32(sample, "dot5StatsRemoves");
  sf_log_next32(sample, "dot5StatsSingles");
  sf_log_next32(sample, "dot5StatsFreqErrors");
}

 
/*_________________---------------------------__________________
  _________________  readCounters_vg          __________________
  -----------------___________________________------------------
*/

static void readCounters_vg(SFSample *sample)
{
  sf_log_next32(sample, "dot12InHighPriorityFrames");
  sf_log_next64(sample, "dot12InHighPriorityOctets");
  sf_log_next32(sample, "dot12InNormPriorityFrames");
  sf_log_next64(sample, "dot12InNormPriorityOctets");
  sf_log_next32(sample, "dot12InIPMErrors");
  sf_log_next32(sample, "dot12InOversizeFrameErrors");
  sf_log_next32(sample, "dot12InDataErrors");
  sf_log_next32(sample, "dot12InNullAddressedFrames");
  sf_log_next32(sample, "dot12OutHighPriorityFrames");
  sf_log_next64(sample, "dot12OutHighPriorityOctets");
  sf_log_next32(sample, "dot12TransitionIntoTrainings");
  sf_log_next64(sample, "dot12HCInHighPriorityOctets");
  sf_log_next64(sample, "dot12HCInNormPriorityOctets");
  sf_log_next64(sample, "dot12HCOutHighPriorityOctets");
}


 
/*_________________---------------------------__________________
  _________________  readCounters_vlan        __________________
  -----------------___________________________------------------
*/

static void readCounters_vlan(SFSample *sample)
{
  sample->in_vlan = getData32(sample);
  dbg_printf("in_vlan %u\n", sample->in_vlan);
  sf_log_next64(sample, "octets");
  sf_log_next32(sample, "ucastPkts");
  sf_log_next32(sample, "multicastPkts");
  sf_log_next32(sample, "broadcastPkts");
  sf_log_next32(sample, "discards");
}
 
/*_________________---------------------------__________________
  _________________  readCounters_80211       __________________
  -----------------___________________________------------------
*/

static void readCounters_80211(SFSample *sample)
{
  sf_log_next32(sample, "dot11TransmittedFragmentCount");
  sf_log_next32(sample, "dot11MulticastTransmittedFrameCount");
  sf_log_next32(sample, "dot11FailedCount");
  sf_log_next32(sample, "dot11RetryCount");
  sf_log_next32(sample, "dot11MultipleRetryCount");
  sf_log_next32(sample, "dot11FrameDuplicateCount");
  sf_log_next32(sample, "dot11RTSSuccessCount");
  sf_log_next32(sample, "dot11RTSFailureCount");
  sf_log_next32(sample, "dot11ACKFailureCount");
  sf_log_next32(sample, "dot11ReceivedFragmentCount");
  sf_log_next32(sample, "dot11MulticastReceivedFrameCount");
  sf_log_next32(sample, "dot11FCSErrorCount");
  sf_log_next32(sample, "dot11TransmittedFrameCount");
  sf_log_next32(sample, "dot11WEPUndecryptableCount");
  sf_log_next32(sample, "dot11QoSDiscardedFragmentCount");
  sf_log_next32(sample, "dot11AssociatedStationCount");
  sf_log_next32(sample, "dot11QoSCFPollsReceivedCount");
  sf_log_next32(sample, "dot11QoSCFPollsUnusedCount");
  sf_log_next32(sample, "dot11QoSCFPollsUnusableCount");
  sf_log_next32(sample, "dot11QoSCFPollsLostCount");
}
 
/*_________________---------------------------__________________
  _________________  readCounters_processor   __________________
  -----------------___________________________------------------
*/

static void readCounters_processor(SFSample *sample)
{
  sf_log_percentage(sample, "5s_cpu");
  sf_log_percentage(sample, "1m_cpu");
  sf_log_percentage(sample, "5m_cpu");
  sf_log_next64(sample, "total_memory_bytes");
  sf_log_next64(sample, "free_memory_bytes");
}
 
/*_________________---------------------------__________________
  _________________  readCounters_radio       __________________
  -----------------___________________________------------------
*/

static void readCounters_radio(SFSample *sample)
{
  sf_log_next32(sample, "radio_elapsed_time");
  sf_log_next32(sample, "radio_on_channel_time");
  sf_log_next32(sample, "radio_on_channel_busy_time");
}

/*_________________---------------------------__________________
  _________________  readCounters_OFPort      __________________
  -----------------___________________________------------------
*/

static void readCounters_OFPort(SFSample *sample)
{
#ifdef DEVEL
  uint64_t dpid = getData64(sample);
  dbg_printf( "openflow_datapath_id %llx\n", dpid);
#endif
  sf_log_next32(sample, "openflow_port");
}

/*_________________---------------------------__________________
  _________________  readCounters_portName    __________________
  -----------------___________________________------------------
*/

static void readCounters_portName(SFSample *sample)
{
  char ifname[SFL_MAX_PORTNAME_LEN+1];
  if(getString(sample, ifname, SFL_MAX_PORTNAME_LEN) > 0) {
    dbg_printf("ifName %s\n", ifname);
  }
}

/*_________________---------------------------__________________
  _________________  readCounters_OVSDP       __________________
  -----------------___________________________------------------
*/

static void readCounters_OVSDP(SFSample *sample)
{
  sf_log_next32(sample, "OVS_dp_hits");
  sf_log_next32(sample, "OVS_dp_misses");
  sf_log_next32(sample, "OVS_dp_lost");
  sf_log_next32(sample, "OVS_dp_mask_hits");
  sf_log_next32(sample, "OVS_dp_flows");
  sf_log_next32(sample, "OVS_dp_masks");
}

/*_________________---------------------------__________________
  _________________  readCounters_host_hid    __________________
  -----------------___________________________------------------
*/

static void readCounters_host_hid(SFSample *sample)
{
  uint8_t *uuid;
  char hostname[SFL_MAX_HOSTNAME_LEN+1];
  char os_release[SFL_MAX_OSRELEASE_LEN+1];
  char uuidStr[100];
  if(getString(sample, hostname, SFL_MAX_HOSTNAME_LEN) > 0) {
    dbg_printf("hostname %s\n", hostname);
  }
  uuid = (uint8_t *)sample->datap;
  printUUID(uuid, uuidStr, 100);
  dbg_printf("UUID %s\n", uuidStr);
  skipBytes(sample, 16);
  sf_log_next32(sample, "machine_type");
  sf_log_next32(sample, "os_name");
  if(getString(sample, os_release, SFL_MAX_OSRELEASE_LEN) > 0) {
    dbg_printf("os_release %s\n", os_release);
  }
}
 
/*_________________---------------------------__________________
  _________________  readCounters_adaptors    __________________
  -----------------___________________________------------------
*/

static void readCounters_adaptors(SFSample *sample)
{
  uint8_t *mac;
  uint32_t i, j, ifindex, num_macs, num_adaptors = getData32(sample);
  for(i = 0; i < num_adaptors; i++) {
    ifindex = getData32(sample);
    dbg_printf("adaptor_%u_ifIndex %u\n", i, ifindex);
    num_macs = getData32(sample);
    dbg_printf("adaptor_%u_MACs %u\n", i, num_macs);
    for(j = 0; j < num_macs; j++) {
      mac = (uint8_t *)sample->datap;
      dbg_printf("adaptor_%u_MAC_%u %02x%02x%02x%02x%02x%02x\n",
	     i, j,
	     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
      skipBytes(sample, 8);
    }
  }
}
 
 
/*_________________----------------------------__________________
  _________________  readCounters_host_parent  __________________
  -----------------____________________________------------------
*/

static void readCounters_host_parent(SFSample *sample)
{
  sf_log_next32(sample, "parent_dsClass");
  sf_log_next32(sample, "parent_dsIndex");
}

/*_________________---------------------------__________________
  _________________  readCounters_host_cpu    __________________
  -----------------___________________________------------------
*/

static void readCounters_host_cpu(SFSample *sample, uint32_t length)
{
  sf_log_nextFloat(sample, "cpu_load_one");
  sf_log_nextFloat(sample, "cpu_load_five");
  sf_log_nextFloat(sample, "cpu_load_fifteen");
  sf_log_next32(sample, "cpu_proc_run");
  sf_log_next32(sample, "cpu_proc_total");
  sf_log_next32(sample, "cpu_num");
  sf_log_next32(sample, "cpu_speed");
  sf_log_next32(sample, "cpu_uptime");
  sf_log_next32(sample, "cpu_user");
  sf_log_next32(sample, "cpu_nice");
  sf_log_next32(sample, "cpu_system");
  sf_log_next32(sample, "cpu_idle");
  sf_log_next32(sample, "cpu_wio");
  sf_log_next32(sample, "cpuintr");
  sf_log_next32(sample, "cpu_sintr");
  sf_log_next32(sample, "cpuinterrupts");
  sf_log_next32(sample, "cpu_contexts");
  if(length > 68) {
    /* these three fields were added in December 2014 */
    sf_log_next32(sample, "cpu_steal");
    sf_log_next32(sample, "cpu_guest");
    sf_log_next32(sample, "cpu_guest_nice");
  }
}
 
/*_________________---------------------------__________________
  _________________  readCounters_host_mem    __________________
  -----------------___________________________------------------
*/

static void readCounters_host_mem(SFSample *sample)
{
  sf_log_next64(sample, "mem_total");
  sf_log_next64(sample, "mem_free");
  sf_log_next64(sample, "mem_shared");
  sf_log_next64(sample, "mem_buffers");
  sf_log_next64(sample, "mem_cached");
  sf_log_next64(sample, "swap_total");
  sf_log_next64(sample, "swap_free");
  sf_log_next32(sample, "page_in");
  sf_log_next32(sample, "page_out");
  sf_log_next32(sample, "swap_in");
  sf_log_next32(sample, "swap_out");
}

 
/*_________________---------------------------__________________
  _________________  readCounters_host_dsk    __________________
  -----------------___________________________------------------
*/

static void readCounters_host_dsk(SFSample *sample)
{
  sf_log_next64(sample, "disk_total");
  sf_log_next64(sample, "disk_free");
  sf_log_percentage(sample, "disk_partition_max_used");
  sf_log_next32(sample, "disk_reads");
  sf_log_next64(sample, "disk_bytes_read");
  sf_log_next32(sample, "disk_read_time");
  sf_log_next32(sample, "disk_writes");
  sf_log_next64(sample, "disk_bytes_written");
  sf_log_next32(sample, "disk_write_time");
}

/*_________________---------------------------__________________
  _________________  readCounters_host_nio    __________________
  -----------------___________________________------------------
*/

static void readCounters_host_nio(SFSample *sample)
{
  sf_log_next64(sample, "nio_bytes_in");
  sf_log_next32(sample, "nio_pkts_in");
  sf_log_next32(sample, "nio_errs_in");
  sf_log_next32(sample, "nio_drops_in");
  sf_log_next64(sample, "nio_bytes_out");
  sf_log_next32(sample, "nio_pkts_out");
  sf_log_next32(sample, "nio_errs_out");
  sf_log_next32(sample, "nio_drops_out");
}

/*_________________---------------------------__________________
  _________________  readCounters_host_ip     __________________
  -----------------___________________________------------------
*/

static void readCounters_host_ip(SFSample *sample)
{
  sf_log_next32(sample, "ipForwarding");
  sf_log_next32(sample, "ipDefaultTTL");
  sf_log_next32(sample, "ipInReceives");
  sf_log_next32(sample, "ipInHdrErrors");
  sf_log_next32(sample, "ipInAddrErrors");
  sf_log_next32(sample, "ipForwDatagrams");
  sf_log_next32(sample, "ipInUnknownProtos");
  sf_log_next32(sample, "ipInDiscards");
  sf_log_next32(sample, "ipInDelivers");
  sf_log_next32(sample, "ipOutRequests");
  sf_log_next32(sample, "ipOutDiscards");
  sf_log_next32(sample, "ipOutNoRoutes");
  sf_log_next32(sample, "ipReasmTimeout");
  sf_log_next32(sample, "ipReasmReqds");
  sf_log_next32(sample, "ipReasmOKs");
  sf_log_next32(sample, "ipReasmFails");
  sf_log_next32(sample, "ipFragOKs");
  sf_log_next32(sample, "ipFragFails");
  sf_log_next32(sample, "ipFragCreates");
}

/*_________________---------------------------__________________
  _________________  readCounters_host_icmp   __________________
  -----------------___________________________------------------
*/

static void readCounters_host_icmp(SFSample *sample)
{
  sf_log_next32(sample, "icmpInMsgs");
  sf_log_next32(sample, "icmpInErrors");
  sf_log_next32(sample, "icmpInDestUnreachs");
  sf_log_next32(sample, "icmpInTimeExcds");
  sf_log_next32(sample, "icmpInParamProbs");
  sf_log_next32(sample, "icmpInSrcQuenchs");
  sf_log_next32(sample, "icmpInRedirects");
  sf_log_next32(sample, "icmpInEchos");
  sf_log_next32(sample, "icmpInEchoReps");
  sf_log_next32(sample, "icmpInTimestamps");
  sf_log_next32(sample, "icmpInAddrMasks");
  sf_log_next32(sample, "icmpInAddrMaskReps");
  sf_log_next32(sample, "icmpOutMsgs");
  sf_log_next32(sample, "icmpOutErrors");
  sf_log_next32(sample, "icmpOutDestUnreachs");
  sf_log_next32(sample, "icmpOutTimeExcds");
  sf_log_next32(sample, "icmpOutParamProbs");
  sf_log_next32(sample, "icmpOutSrcQuenchs");
  sf_log_next32(sample, "icmpOutRedirects");
  sf_log_next32(sample, "icmpOutEchos");
  sf_log_next32(sample, "icmpOutEchoReps");
  sf_log_next32(sample, "icmpOutTimestamps");
  sf_log_next32(sample, "icmpOutTimestampReps");
  sf_log_next32(sample, "icmpOutAddrMasks");
  sf_log_next32(sample, "icmpOutAddrMaskReps");
}

/*_________________---------------------------__________________
  _________________  readCounters_host_tcp     __________________
  -----------------___________________________------------------
*/

static void readCounters_host_tcp(SFSample *sample)
{
  sf_log_next32(sample, "tcpRtoAlgorithm");
  sf_log_next32(sample, "tcpRtoMin");
  sf_log_next32(sample, "tcpRtoMax");
  sf_log_next32(sample, "tcpMaxConn");
  sf_log_next32(sample, "tcpActiveOpens");
  sf_log_next32(sample, "tcpPassiveOpens");
  sf_log_next32(sample, "tcpAttemptFails");
  sf_log_next32(sample, "tcpEstabResets");
  sf_log_next32(sample, "tcpCurrEstab");
  sf_log_next32(sample, "tcpInSegs");
  sf_log_next32(sample, "tcpOutSegs");
  sf_log_next32(sample, "tcpRetransSegs");
  sf_log_next32(sample, "tcpInErrs");
  sf_log_next32(sample, "tcpOutRsts");
  sf_log_next32(sample, "tcpInCsumErrors");
}

/*_________________---------------------------__________________
  _________________  readCounters_host_udp    __________________
  -----------------___________________________------------------
*/

static void readCounters_host_udp(SFSample *sample)
{
  sf_log_next32(sample, "udpInDatagrams");
  sf_log_next32(sample, "udpNoPorts");
  sf_log_next32(sample, "udpInErrors");
  sf_log_next32(sample, "udpOutDatagrams");
  sf_log_next32(sample, "udpRcvbufErrors");
  sf_log_next32(sample, "udpSndbufErrors");
  sf_log_next32(sample, "udpInCsumErrors");
}

/*_________________-----------------------------__________________
  _________________  readCounters_host_vnode    __________________
  -----------------_____________________________------------------
*/

static void readCounters_host_vnode(SFSample *sample)
{
  sf_log_next32(sample, "vnode_mhz");
  sf_log_next32(sample, "vnode_cpus");
  sf_log_next64(sample, "vnode_memory");
  sf_log_next64(sample, "vnode_memory_free");
  sf_log_next32(sample, "vnode_num_domains");
}

/*_________________----------------------------__________________
  _________________  readCounters_host_vcpu    __________________
  -----------------____________________________------------------
*/

static void readCounters_host_vcpu(SFSample *sample)
{
  sf_log_next32(sample, "vcpu_state");
  sf_log_next32(sample, "vcpu_cpu_mS");
  sf_log_next32(sample, "vcpu_cpuCount");
}

/*_________________----------------------------__________________
  _________________  readCounters_host_vmem    __________________
  -----------------____________________________------------------
*/

static void readCounters_host_vmem(SFSample *sample)
{
  sf_log_next64(sample, "vmem_memory");
  sf_log_next64(sample, "vmem_maxMemory");
}

/*_________________----------------------------__________________
  _________________  readCounters_host_vdsk    __________________
  -----------------____________________________------------------
*/

static void readCounters_host_vdsk(SFSample *sample)
{
  sf_log_next64(sample, "vdsk_capacity");
  sf_log_next64(sample, "vdsk_allocation");
  sf_log_next64(sample, "vdsk_available");
  sf_log_next32(sample, "vdsk_rd_req");
  sf_log_next64(sample, "vdsk_rd_bytes");
  sf_log_next32(sample, "vdsk_wr_req");
  sf_log_next64(sample, "vdsk_wr_bytes");
  sf_log_next32(sample, "vdsk_errs");
}

/*_________________----------------------------__________________
  _________________  readCounters_host_vnio    __________________
  -----------------____________________________------------------
*/

static void readCounters_host_vnio(SFSample *sample)
{
  sf_log_next64(sample, "vnio_bytes_in");
  sf_log_next32(sample, "vnio_pkts_in");
  sf_log_next32(sample, "vnio_errs_in");
  sf_log_next32(sample, "vnio_drops_in");
  sf_log_next64(sample, "vnio_bytes_out");
  sf_log_next32(sample, "vnio_pkts_out");
  sf_log_next32(sample, "vnio_errs_out");
  sf_log_next32(sample, "vnio_drops_out");
}

/*_________________------------------------------__________________
  _________________  readCounters_host_gpu_nvml  __________________
  -----------------______________________________------------------
*/

static void readCounters_host_gpu_nvml(SFSample *sample)
{
  sf_log_next32(sample, "nvml_device_count");
  sf_log_next32(sample, "nvml_processes");
  sf_log_next32(sample, "nvml_gpu_mS");
  sf_log_next32(sample, "nvml_mem_mS");
  sf_log_next64(sample, "nvml_mem_bytes_total");
  sf_log_next64(sample, "nvml_mem_bytes_free");
  sf_log_next32(sample, "nvml_ecc_errors");
  sf_log_next32(sample, "nvml_energy_mJ");
  sf_log_next32(sample, "nvml_temperature_C");
  sf_log_next32(sample, "nvml_fan_speed_pc");
}

/*_________________------------------------------__________________
  _________________  readCounters_bcm_tables     __________________
  -----------------______________________________------------------
*/

static void readCounters_bcm_tables(SFSample *sample)
{
  sf_log_next32(sample, "bcm_asic_host_entries");
  sf_log_next32(sample, "bcm_host_entries_max");
  sf_log_next32(sample, "bcm_ipv4_entries");
  sf_log_next32(sample, "bcm_ipv4_entries_max");
  sf_log_next32(sample, "bcm_ipv6_entries");
  sf_log_next32(sample, "bcm_ipv6_entries_max");
  sf_log_next32(sample, "bcm_ipv4_ipv6_entries");
  sf_log_next32(sample, "bcm_ipv4_ipv6_entries_max");
  sf_log_next32(sample, "bcm_long_ipv6_entries");
  sf_log_next32(sample, "bcm_long_ipv6_entries_max");
  sf_log_next32(sample, "bcm_total_routes");
  sf_log_next32(sample, "bcm_total_routes_max");
  sf_log_next32(sample, "bcm_ecmp_nexthops");
  sf_log_next32(sample, "bcm_ecmp_nexthops_max");
  sf_log_next32(sample, "bcm_mac_entries");
  sf_log_next32(sample, "bcm_mac_entries_max");
  sf_log_next32(sample, "bcm_ipv4_neighbors");
  sf_log_next32(sample, "bcm_ipv6_neighbors");
  sf_log_next32(sample, "bcm_ipv4_routes");
  sf_log_next32(sample, "bcm_ipv6_routes");
  sf_log_next32(sample, "bcm_acl_ingress_entries");
  sf_log_next32(sample, "bcm_acl_ingress_entries_max");
  sf_log_next32(sample, "bcm_acl_ingress_counters");
  sf_log_next32(sample, "bcm_acl_ingress_counters_max");
  sf_log_next32(sample, "bcm_acl_ingress_meters");
  sf_log_next32(sample, "bcm_acl_ingress_meters_max");
  sf_log_next32(sample, "bcm_acl_ingress_slices");
  sf_log_next32(sample, "bcm_acl_ingress_slices_max");
  sf_log_next32(sample, "bcm_acl_egress_entries");
  sf_log_next32(sample, "bcm_acl_egress_entries_max");
  sf_log_next32(sample, "bcm_acl_egress_counters");
  sf_log_next32(sample, "bcm_acl_egress_counters_max");
  sf_log_next32(sample, "bcm_acl_egress_meters");
  sf_log_next32(sample, "bcm_acl_egress_meters_max");
  sf_log_next32(sample, "bcm_acl_egress_slices");
  sf_log_next32(sample, "bcm_acl_egress_slices_max");
}

/*_________________----------------------------__________________
  _________________  readCounters_memcache     __________________
  -----------------____________________________------------------
 for structure 2200 (deprecated)
*/

static void readCounters_memcache(SFSample *sample)
{
  sf_log_next32(sample, "memcache_uptime");
  sf_log_next32(sample, "memcache_rusage_user");
  sf_log_next32(sample, "memcache_rusage_system");
  sf_log_next32(sample, "memcache_curr_connections");
  sf_log_next32(sample, "memcache_total_connections");
  sf_log_next32(sample, "memcache_connection_structures");
  sf_log_next32(sample, "memcache_cmd_get");
  sf_log_next32(sample, "memcache_cmd_set");
  sf_log_next32(sample, "memcache_cmd_flush");
  sf_log_next32(sample, "memcache_get_hits");
  sf_log_next32(sample, "memcache_get_misses");
  sf_log_next32(sample, "memcache_delete_misses");
  sf_log_next32(sample, "memcache_delete_hits");
  sf_log_next32(sample, "memcache_incr_misses");
  sf_log_next32(sample, "memcache_incr_hits");
  sf_log_next32(sample, "memcache_decr_misses");
  sf_log_next32(sample, "memcache_decr_hits");
  sf_log_next32(sample, "memcache_cas_misses");
  sf_log_next32(sample, "memcache_cas_hits");
  sf_log_next32(sample, "memcache_cas_badval");
  sf_log_next32(sample, "memcache_auth_cmds");
  sf_log_next32(sample, "memcache_auth_errors");
  sf_log_next64(sample, "memcache_bytes_read");
  sf_log_next64(sample, "memcache_bytes_written");
  sf_log_next32(sample, "memcache_limit_maxbytes");
  sf_log_next32(sample, "memcache_accepting_conns");
  sf_log_next32(sample, "memcache_listen_disabled_num");
  sf_log_next32(sample, "memcache_threads");
  sf_log_next32(sample, "memcache_conn_yields");
  sf_log_next64(sample, "memcache_bytes");
  sf_log_next32(sample, "memcache_curr_items");
  sf_log_next32(sample, "memcache_total_items");
  sf_log_next32(sample, "memcache_evictions");
}

/*_________________----------------------------__________________
  _________________  readCounters_memcache2    __________________
  -----------------____________________________------------------
  for structure 2204
*/

static void readCounters_memcache2(SFSample *sample)
{
  sf_log_next32(sample, "memcache_cmd_set");
  sf_log_next32(sample, "memcache_cmd_touch");
  sf_log_next32(sample, "memcache_cmd_flush");
  sf_log_next32(sample, "memcache_get_hits");
  sf_log_next32(sample, "memcache_get_misses");
  sf_log_next32(sample, "memcache_delete_hits");
  sf_log_next32(sample, "memcache_delete_misses");
  sf_log_next32(sample, "memcache_incr_hits");
  sf_log_next32(sample, "memcache_incr_misses");
  sf_log_next32(sample, "memcache_decr_hits");
  sf_log_next32(sample, "memcache_decr_misses");
  sf_log_next32(sample, "memcache_cas_hits");
  sf_log_next32(sample, "memcache_cas_misses");
  sf_log_next32(sample, "memcache_cas_badval");
  sf_log_next32(sample, "memcache_auth_cmds");
  sf_log_next32(sample, "memcache_auth_errors");
  sf_log_next32(sample, "memcache_threads");
  sf_log_next32(sample, "memcache_conn_yields");
  sf_log_next32(sample, "memcache_listen_disabled_num");
  sf_log_next32(sample, "memcache_curr_connections");
  sf_log_next32(sample, "memcache_rejected_connections");
  sf_log_next32(sample, "memcache_total_connections");
  sf_log_next32(sample, "memcache_connection_structures");
  sf_log_next32(sample, "memcache_evictions");
  sf_log_next32(sample, "memcache_reclaimed");
  sf_log_next32(sample, "memcache_curr_items");
  sf_log_next32(sample, "memcache_total_items");
  sf_log_next64(sample, "memcache_bytes_read");
  sf_log_next64(sample, "memcache_bytes_written");
  sf_log_next64(sample, "memcache_bytes");
  sf_log_next64(sample, "memcache_limit_maxbytes");
}

/*_________________----------------------------__________________
  _________________  readCounters_http         __________________
  -----------------____________________________------------------
*/

static void readCounters_http(SFSample *sample)
{
  sf_log_next32(sample, "http_method_option_count");
  sf_log_next32(sample, "http_method_get_count");
  sf_log_next32(sample, "http_method_head_count");
  sf_log_next32(sample, "http_method_post_count");
  sf_log_next32(sample, "http_method_put_count");
  sf_log_next32(sample, "http_method_delete_count");
  sf_log_next32(sample, "http_method_trace_count");
  sf_log_next32(sample, "http_methd_connect_count");
  sf_log_next32(sample, "http_method_other_count");
  sf_log_next32(sample, "http_status_1XX_count");
  sf_log_next32(sample, "http_status_2XX_count");
  sf_log_next32(sample, "http_status_3XX_count");
  sf_log_next32(sample, "http_status_4XX_count");
  sf_log_next32(sample, "http_status_5XX_count");
  sf_log_next32(sample, "http_status_other_count");
}

/*_________________----------------------------__________________
  _________________  readCounters_JVM          __________________
  -----------------____________________________------------------
*/

static void readCounters_JVM(SFSample *sample)
{
  char vm_name[SFLJVM_MAX_VMNAME_LEN];
  char vendor[SFLJVM_MAX_VENDOR_LEN];
  char version[SFLJVM_MAX_VERSION_LEN];
  if(getString(sample, vm_name, SFLJVM_MAX_VMNAME_LEN) > 0) {
    dbg_printf("jvm_name %s\n", vm_name);
  }
  if(getString(sample, vendor, SFLJVM_MAX_VENDOR_LEN) > 0) {
    dbg_printf("jvm_vendor %s\n", vendor);
  }
  if(getString(sample, version, SFLJVM_MAX_VERSION_LEN) > 0) {
    dbg_printf("jvm_version %s\n", version);
  }
}

/*_________________----------------------------__________________
  _________________  readCounters_JMX          __________________
  -----------------____________________________------------------
*/

static void readCounters_JMX(SFSample *sample, uint32_t length)
{
  sf_log_next64(sample, "heap_mem_initial");
  sf_log_next64(sample, "heap_mem_used");
  sf_log_next64(sample, "heap_mem_committed");
  sf_log_next64(sample, "heap_mem_max");
  sf_log_next64(sample, "non_heap_mem_initial");
  sf_log_next64(sample, "non_heap_mem_used");
  sf_log_next64(sample, "non_heap_mem_committed");
  sf_log_next64(sample, "non_heap_mem_max");
  sf_log_next32(sample, "gc_count");
  sf_log_next32(sample, "gc_mS");
  sf_log_next32(sample, "classes_loaded");
  sf_log_next32(sample, "classes_total");
  sf_log_next32(sample, "classes_unloaded");
  sf_log_next32(sample, "compilation_mS");
  sf_log_next32(sample, "threads_live");
  sf_log_next32(sample, "threads_daemon");
  sf_log_next32(sample, "threads_started");
  if(length > 100) {
    sf_log_next32(sample, "fds_open");
    sf_log_next32(sample, "fds_max");
  }
}

/*_________________----------------------------__________________
  _________________  readCounters_APP          __________________
  -----------------____________________________------------------
*/

static void readCounters_APP(SFSample *sample)
{
  char application[SFLAPP_MAX_APPLICATION_LEN];
  if(getString(sample, application, SFLAPP_MAX_APPLICATION_LEN) > 0) {
    dbg_printf("application %s\n", application);
  }
  sf_log_next32(sample, "status_OK");
  sf_log_next32(sample, "errors_OTHER");
  sf_log_next32(sample, "errors_TIMEOUT");
  sf_log_next32(sample, "errors_INTERNAL_ERROR");
  sf_log_next32(sample, "errors_BAD_REQUEST");
  sf_log_next32(sample, "errors_FORBIDDEN");
  sf_log_next32(sample, "errors_TOO_LARGE");
  sf_log_next32(sample, "errors_NOT_IMPLEMENTED");
  sf_log_next32(sample, "errors_NOT_FOUND");
  sf_log_next32(sample, "errors_UNAVAILABLE");
  sf_log_next32(sample, "errors_UNAUTHORIZED");
}

/*_________________----------------------------__________________
  _________________  readCounters_APP_RESOURCE __________________
  -----------------____________________________------------------
*/

static void readCounters_APP_RESOURCE(SFSample *sample)
{
  sf_log_next32(sample, "user_time");
  sf_log_next32(sample, "system_time");
  sf_log_next64(sample, "memory_used");
  sf_log_next64(sample, "memory_max");
  sf_log_next32(sample, "files_open");
  sf_log_next32(sample, "files_max");
  sf_log_next32(sample, "connections_open");
  sf_log_next32(sample, "connections_max");
}

/*_________________----------------------------__________________
  _________________  readCounters_APP_WORKERS  __________________
  -----------------____________________________------------------
*/

static void readCounters_APP_WORKERS(SFSample *sample)
{
  sf_log_next32(sample, "workers_active");
  sf_log_next32(sample, "workers_idle");
  sf_log_next32(sample, "workers_max");
  sf_log_next32(sample, "requests_delayed");
  sf_log_next32(sample, "requests_dropped");
}

/*_________________----------------------------__________________
  _________________       readCounters_VDI     __________________
  -----------------____________________________------------------
*/

static void readCounters_VDI(SFSample *sample)
{
  sf_log_next32(sample, "vdi_sessions_current");
  sf_log_next32(sample, "vdi_sessions_total");
  sf_log_next32(sample, "vdi_sessions_duration");
  sf_log_next32(sample, "vdi_rx_bytes");
  sf_log_next32(sample, "vdi_tx_bytes");
  sf_log_next32(sample, "vdi_rx_packets");
  sf_log_next32(sample, "vdi_tx_packets");
  sf_log_next32(sample, "vdi_rx_packets_lost");
  sf_log_next32(sample, "vdi_tx_packets_lost");
  sf_log_next32(sample, "vdi_rtt_min_ms");
  sf_log_next32(sample, "vdi_rtt_max_ms");
  sf_log_next32(sample, "vdi_rtt_avg_ms");
  sf_log_next32(sample, "vdi_audio_rx_bytes");
  sf_log_next32(sample, "vdi_audio_tx_bytes");
  sf_log_next32(sample, "vdi_audio_tx_limit");
  sf_log_next32(sample, "vdi_img_rx_bytes");
  sf_log_next32(sample, "vdi_img_tx_bytes");
  sf_log_next32(sample, "vdi_img_frames");
  sf_log_next32(sample, "vdi_img_qual_min");
  sf_log_next32(sample, "vdi_img_qual_max");
  sf_log_next32(sample, "vdi_img_qual_avg");
  sf_log_next32(sample, "vdi_usb_rx_bytes");
  sf_log_next32(sample, "vdi_usb_tx_bytes");
}

/*_________________------------------------------__________________
  _________________     readCounters_LACP        __________________
  -----------------______________________________------------------
*/

static void readCounters_LACP(SFSample *sample)
{
  SFLLACP_portState portState;
  sf_log_nextMAC(sample, "actorSystemID");
  sf_log_nextMAC(sample, "partnerSystemID");
  sf_log_next32(sample, "attachedAggID");
  portState.all = getData32_nobswap(sample);
  dbg_printf("actorAdminPortState %u\n", portState.v.actorAdmin);
  dbg_printf("actorOperPortState %u\n", portState.v.actorOper);
  dbg_printf("partnerAdminPortState %u\n", portState.v.partnerAdmin);
  dbg_printf("partnerOperPortState %u\n", portState.v.partnerOper);
  sf_log_next32(sample, "LACPDUsRx");
  sf_log_next32(sample, "markerPDUsRx");
  sf_log_next32(sample, "markerResponsePDUsRx");
  sf_log_next32(sample, "unknownRx");
  sf_log_next32(sample, "illegalRx");
  sf_log_next32(sample, "LACPDUsTx");
  sf_log_next32(sample, "markerPDUsTx");
  sf_log_next32(sample, "markerResponsePDUsTx");
}

/*_________________----------------------------__________________
  _________________  readCounters_SFP          __________________
  -----------------____________________________------------------
*/

static void readCounters_SFP(SFSample *sample)
{
  uint32_t num_lanes,ll;
  sf_log_next32(sample, "sfp_module_id");
  sf_log_next32(sample, "sfp_module_total_lanes");
  sf_log_next32(sample, "sfp_module_supply_voltage");
  sf_log_next32(sample, "sfp_module_temperature");
  num_lanes = getData32(sample);
  dbg_printf( "sfp_module_active_lanes %u\n", num_lanes);
  for(ll=0; ll < num_lanes; ll++) {
    dbg_printf( "sfp_lane_index.%u %u\n", ll, getData32(sample));
    dbg_printf( "sfp_lane_tx_bias_current_uA.%u %u\n", ll, getData32(sample));
    dbg_printf( "sfp_lane_tx_power_uW.%u %u\n", ll, getData32(sample));
    dbg_printf( "sfp_lane_tx_power_min_uW.%u %u\n", ll, getData32(sample));
    dbg_printf( "sfp_lane_tx_power_max_uW.%u %u\n", ll, getData32(sample));
    dbg_printf( "sfp_lane_tx_wavelength_nM.%u %u\n", ll, getData32(sample));
    dbg_printf( "sfp_lane_rx_power_uW.%u %u\n", ll, getData32(sample));
    dbg_printf( "sfp_lane_rx_power_min_uW.%u %u\n", ll, getData32(sample));
    dbg_printf( "sfp_lane_rx_power_max_uW.%u %u\n", ll, getData32(sample));
    dbg_printf( "sfp_lane_rx_wavelength_nM.%u %u\n", ll, getData32(sample));
  }
}

/*_________________---------------------------__________________
  _________________  readCountersSample_v2v4  __________________
  -----------------___________________________------------------
*/

static void readCountersSample_v2v4(SFSample *sample, FlowSource_t *fs)
{
  dbg_printf("sampleType COUNTERSSAMPLE\n");
  sample->samplesGenerated = getData32(sample);
  dbg_printf("sampleSequenceNo %u\n", sample->samplesGenerated);
  {
    uint32_t samplerId = getData32(sample);
    sample->ds_class = samplerId >> 24;
    sample->ds_index = samplerId & 0x00ffffff;
  }
  dbg_printf("sourceId %u:%u\n", sample->ds_class, sample->ds_index);


  sample->statsSamplingInterval = getData32(sample);
  dbg_printf("statsSamplingInterval %u\n", sample->statsSamplingInterval);
  /* now find out what sort of counter blocks we have here... */
  sample->counterBlockVersion = getData32(sample);
  dbg_printf("counterBlockVersion %u\n", sample->counterBlockVersion);
  
  /* first see if we should read the generic stats */
  switch(sample->counterBlockVersion) {
  case INMCOUNTERSVERSION_GENERIC:
  case INMCOUNTERSVERSION_ETHERNET:
  case INMCOUNTERSVERSION_TOKENRING:
  case INMCOUNTERSVERSION_FDDI:
  case INMCOUNTERSVERSION_VG:
  case INMCOUNTERSVERSION_WAN: readCounters_generic(sample); break;
  case INMCOUNTERSVERSION_VLAN: break;
  default: receiveError(sample, "unknown stats version", YES); break;
  }
  
  /* now see if there are any specific counter blocks to add */
  switch(sample->counterBlockVersion) {
  case INMCOUNTERSVERSION_GENERIC: /* nothing more */ break;
  case INMCOUNTERSVERSION_ETHERNET: readCounters_ethernet(sample); break;
  case INMCOUNTERSVERSION_TOKENRING:readCounters_tokenring(sample); break;
  case INMCOUNTERSVERSION_FDDI: break;
  case INMCOUNTERSVERSION_VG: readCounters_vg(sample); break;
  case INMCOUNTERSVERSION_WAN: break;
  case INMCOUNTERSVERSION_VLAN: readCounters_vlan(sample); break;
  default: receiveError(sample, "unknown INMCOUNTERSVERSION", YES); break;
  }
  /* line-by-line output... */
	if ( verbose )
		writeCountersLine(sample);
}

/*_________________---------------------------__________________
  _________________   readCountersSample      __________________
  -----------------___________________________------------------
*/

static void readCountersSample(SFSample *sample, int expanded, FlowSource_t *fs)
{
  uint32_t sampleLength;
  uint32_t num_elements;
  uint8_t *sampleStart;
  dbg_printf("sampleType COUNTERSSAMPLE\n");
  sampleLength = getData32(sample);
  sampleStart = (uint8_t *)sample->datap;
  sample->samplesGenerated = getData32(sample);
  
  dbg_printf("sampleSequenceNo %u\n", sample->samplesGenerated);
  if(expanded) {
    sample->ds_class = getData32(sample);
    sample->ds_index = getData32(sample);
  }
  else {
    uint32_t samplerId = getData32(sample);
    sample->ds_class = samplerId >> 24;
    sample->ds_index = samplerId & 0x00ffffff;
  }
  dbg_printf("sourceId %u:%u\n", sample->ds_class, sample->ds_index);
  
  num_elements = getData32(sample);
  {
    uint32_t el;
    for(el = 0; el < num_elements; el++) {
      uint32_t tag, length;
      uint8_t *start;
#ifdef DEVEL
      char buf[51];
#endif
      tag = sample->elementType = getData32(sample);
      dbg_printf("counterBlock_tag %s\n", printTag(tag, buf, 50));
      length = getData32(sample);
      start = (uint8_t *)sample->datap;
      
      switch(tag) {
      case SFLCOUNTERS_GENERIC: readCounters_generic(sample); break;
      case SFLCOUNTERS_ETHERNET: readCounters_ethernet(sample); break;
      case SFLCOUNTERS_TOKENRING:readCounters_tokenring(sample); break;
      case SFLCOUNTERS_VG: readCounters_vg(sample); break;
      case SFLCOUNTERS_VLAN: readCounters_vlan(sample); break;
      case SFLCOUNTERS_80211: readCounters_80211(sample); break;
      case SFLCOUNTERS_LACP: readCounters_LACP(sample); break;
      case SFLCOUNTERS_SFP: readCounters_SFP(sample); break;
      case SFLCOUNTERS_PROCESSOR: readCounters_processor(sample); break;
      case SFLCOUNTERS_RADIO: readCounters_radio(sample); break;
      case SFLCOUNTERS_OFPORT: readCounters_OFPort(sample); break;
      case SFLCOUNTERS_PORTNAME: readCounters_portName(sample); break;
      case SFLCOUNTERS_HOST_HID: readCounters_host_hid(sample); break;
      case SFLCOUNTERS_ADAPTORS: readCounters_adaptors(sample); break;
      case SFLCOUNTERS_HOST_PAR: readCounters_host_parent(sample); break;
      case SFLCOUNTERS_HOST_CPU: readCounters_host_cpu(sample, length); break;
      case SFLCOUNTERS_HOST_MEM: readCounters_host_mem(sample); break;
      case SFLCOUNTERS_HOST_DSK: readCounters_host_dsk(sample); break;
      case SFLCOUNTERS_HOST_NIO: readCounters_host_nio(sample); break;
      case SFLCOUNTERS_HOST_IP: readCounters_host_ip(sample); break;
      case SFLCOUNTERS_HOST_ICMP: readCounters_host_icmp(sample); break;
      case SFLCOUNTERS_HOST_TCP: readCounters_host_tcp(sample); break;
      case SFLCOUNTERS_HOST_UDP: readCounters_host_udp(sample); break;
      case SFLCOUNTERS_HOST_VRT_NODE: readCounters_host_vnode(sample); break;
      case SFLCOUNTERS_HOST_VRT_CPU: readCounters_host_vcpu(sample); break;
      case SFLCOUNTERS_HOST_VRT_MEM: readCounters_host_vmem(sample); break;
      case SFLCOUNTERS_HOST_VRT_DSK: readCounters_host_vdsk(sample); break;
      case SFLCOUNTERS_HOST_VRT_NIO: readCounters_host_vnio(sample); break;
      case SFLCOUNTERS_HOST_GPU_NVML: readCounters_host_gpu_nvml(sample); break;
      case SFLCOUNTERS_BCM_TABLES: readCounters_bcm_tables(sample); break;
      case SFLCOUNTERS_MEMCACHE: readCounters_memcache(sample); break;
      case SFLCOUNTERS_MEMCACHE2: readCounters_memcache2(sample); break;
      case SFLCOUNTERS_HTTP: readCounters_http(sample); break;
      case SFLCOUNTERS_JVM: readCounters_JVM(sample); break;
      case SFLCOUNTERS_JMX: readCounters_JMX(sample, length); break;
      case SFLCOUNTERS_APP: readCounters_APP(sample); break;
      case SFLCOUNTERS_APP_RESOURCE: readCounters_APP_RESOURCE(sample); break;
      case SFLCOUNTERS_APP_WORKERS: readCounters_APP_WORKERS(sample); break;
      case SFLCOUNTERS_VDI: readCounters_VDI(sample); break;
      case SFLCOUNTERS_OVSDP: readCounters_OVSDP(sample); break;
      default: skipTLVRecord(sample, tag, length, "counters_sample_element"); break;
      }
      lengthCheck(sample, "counters_sample_element", start, length);
    }
  }
  lengthCheck(sample, "counters_sample", sampleStart, sampleLength);
	/* line-by-line output... */
	if ( verbose )
		writeCountersLine(sample);
}

/*_________________---------------------------__________________
  _________________       readRTMetric        __________________
  -----------------___________________________------------------
*/

static void readRTMetric(SFSample *sample, FlowSource_t *fs)
{
#define SFL_MAX_RTMETRIC_KEY_LEN 64
#define SFL_MAX_RTMETRIC_VAL_LEN 255
  char dsName[SFL_MAX_RTMETRIC_KEY_LEN];
  uint32_t sampleLength;
  uint32_t num_elements;
  uint8_t *sampleStart;
  dbg_printf("sampleType RTMETRIC\n");
  sampleLength = getData32(sample);
  sampleStart = (uint8_t *)sample->datap;
  if(getString(sample, dsName, SFL_MAX_RTMETRIC_KEY_LEN) > 0) {
    dbg_printf( "rtmetric_datasource_name %s\n", dsName);
  }
  num_elements = getData32(sample);
  {
    uint32_t el;
    for(el = 0; el < num_elements; el++) {
      char mname[SFL_MAX_RTMETRIC_KEY_LEN];
      uint32_t mtype;
      char mvalstr[SFL_MAX_RTMETRIC_VAL_LEN];
      uint32_t mvali32;
      uint64_t mvali64;
      float mvalfloat;
      double mvaldouble;
      getString(sample, mname, SFL_MAX_RTMETRIC_KEY_LEN);
      mtype = getData32(sample);
      switch(mtype) {
      case 0:
	getString(sample, mvalstr, SFL_MAX_RTMETRIC_VAL_LEN);
	dbg_printf( "rtmetric %s = (string) \"%s\"\n", mname, mvalstr);
	break;
      case 1:
	mvali32 = getData32(sample);
	dbg_printf( "rtmetric %s = (counter32) %u\n", mname, mvali32);
	break;
      case 2:
	mvali64 = getData64(sample);
	dbg_printf( "rtmetric %s = (counter64) %llu\n", mname, mvali64);
	break;
      case 3:
	mvali32 = getData32(sample);
	dbg_printf( "rtmetric %s = (gauge32) %u\n", mname, mvali32);
	break;
      case 4:
	mvali64 = getData64(sample);
	dbg_printf( "rtmetric %s = (gauge64) %llu\n", mname, mvali64);
	break;
      case 5:
	mvalfloat = getFloat(sample);
	dbg_printf( "rtmetric %s = (gaugefloat) %.3f\n", mname, mvalfloat);
	break;
      case 6:
	mvaldouble = getDouble(sample);
	dbg_printf( "rtmetric %s = (gaugefloat) %.3f\n", mname, mvaldouble);
	break;
      default:
	dbg_printf( "rtmetric unknown_type %u\n", mtype);
	SFABORT(sample, SF_ABORT_DECODE_ERROR);
	break;
      }
    }
  }
  lengthCheck(sample, "rtmetric_sample", sampleStart, sampleLength);

  if ( verbose )
	writeCountersLine(sample);

}

/*_________________---------------------------__________________
  _________________       readRTFlow          __________________
  -----------------___________________________------------------
*/

static void readRTFlow(SFSample *sample, FlowSource_t *fs)
{
  char dsName[SFL_MAX_RTMETRIC_KEY_LEN];
  uint32_t sampleLength;
  uint32_t num_elements;
  uint8_t *sampleStart;
  dbg_printf("sampleType RTFLOW\n");
  sampleLength = getData32(sample);
  sampleStart = (uint8_t *)sample->datap;
  if(getString(sample, dsName, SFL_MAX_RTMETRIC_KEY_LEN) > 0) {
    dbg_printf( "rtflow_datasource_name %s\n", dsName);
  }
  sf_log_next32(sample, "rtflow_sampling_rate");
  sf_log_next32(sample, "rtflow_sample_pool");
  num_elements = getData32(sample);
  {
    uint32_t el;
    for(el = 0; el < num_elements; el++) {
      char fname[SFL_MAX_RTMETRIC_KEY_LEN];
      uint32_t ftype;
      char fvalstr[SFL_MAX_RTMETRIC_VAL_LEN];
      uint32_t fvali32;
      uint64_t fvali64;
      float fvalfloat;
      double fvaldouble;
      SFLAddress fvaladdr;
#ifdef DEVEL
      char fvaladdrstr[64];
#endif
      u_char fvalmac[6];
      char fvalmacstr[32];
      getString(sample, fname, SFL_MAX_RTMETRIC_KEY_LEN);
      ftype = getData32(sample);
      switch(ftype) {
      case 0:
	getString(sample, fvalstr, SFL_MAX_RTMETRIC_VAL_LEN);
	dbg_printf( "rtflow %s = (string) \"%s\"\n", fname, fvalstr);
	break;
      case 1:
	memcpy(fvalmac, sample->datap, 6);
	skipBytes(sample, 6);
	printHex(fvalmac, 6, fvalmacstr, 32, 0, 100);
	dbg_printf( "rtflow %s = (mac) %s\n", fname, fvalmacstr);
	break;
      case 2:
	fvaladdr.type = SFLADDRESSTYPE_IP_V4;
	fvaladdr.address.ip_v4.addr = getData32_nobswap(sample);
	dbg_printf( "rtflow %s = (ip) %s\n",
	       fname,
	       printAddress(&fvaladdr,fvaladdrstr, 63));
	break;
      case 3:
	fvaladdr.type = SFLADDRESSTYPE_IP_V6;
	memcpy(fvaladdr.address.ip_v6.addr, sample->datap, 16);
	skipBytes(sample, 16);
	dbg_printf( "rtflow %s = (ip6) %s\n",
	       fname,
	       printAddress(&fvaladdr,fvaladdrstr, 63));
	break;
      case 4:
	fvali32 = getData32(sample);
	dbg_printf( "rtflow %s = (int32) %u\n", fname, fvali32);
	break;
      case 5:
	fvali64 = getData64(sample);
	dbg_printf( "rtflow %s = (int64) %llu\n", fname, fvali64);
	break;
      case 6:
	fvalfloat = getFloat(sample);
	dbg_printf( "rtflow %s = (gaugefloat) %.3f\n", fname, fvalfloat);
	break;
      case 7:
	fvaldouble = getDouble(sample);
	dbg_printf( "rtflow %s = (gaugefloat) %.3f\n", fname, fvaldouble);
	break;
      default:
	dbg_printf( "rtflow unknown_type %u\n", ftype);
	SFABORT(sample, SF_ABORT_DECODE_ERROR);
	break;
      }
    }
  }
  lengthCheck(sample, "rtflow_sample", sampleStart, sampleLength);

  if ( verbose )
	writeCountersLine(sample);

}

/*_________________---------------------------__________________
  _________________      readSFlowDatagram    __________________
  -----------------___________________________------------------
*/

static void readSFlowDatagram(SFSample *sample, FlowSource_t *fs)
{
  uint32_t samplesInPacket;
#ifdef DEVEL
  char buf[51];
#endif  

  /* log some datagram info */
  dbg_printf("datagramSourceIP %s\n", IP_to_a(sample->sourceIP.s_addr, buf, 51));
  dbg_printf("datagramSize %u\n", sample->rawSampleLen);
  dbg_printf("unixSecondsUTC %llu\n", (unsigned long long)sample->readTimestamp);

  /* check the version */
  sample->datagramVersion = getData32(sample);
  dbg_printf("datagramVersion %d\n", sample->datagramVersion);
  if(sample->datagramVersion != 2 &&
     sample->datagramVersion != 4 &&
     sample->datagramVersion != 5) {
    receiveError(sample,  "unexpected datagram version number\n", YES);
  }
  
  /* get the agent address */
  getAddress(sample, &sample->agent_addr);

  /* version 5 has an agent sub-id as well */
  if(sample->datagramVersion >= 5) {
    sample->agentSubId = getData32(sample);
    dbg_printf("agentSubId %u\n", sample->agentSubId);
  }

  sample->sequenceNo = getData32(sample);  /* this is the packet sequence number */
  sample->sysUpTime = getData32(sample);
  samplesInPacket = getData32(sample);
  dbg_printf("agent %s\n", printAddress(&sample->agent_addr, buf, 50));
  dbg_printf("packetSequenceNo %u\n", sample->sequenceNo);
  dbg_printf("sysUpTime %u\n", sample->sysUpTime);
  dbg_printf("samplesInPacket %u\n", samplesInPacket);

  /* now iterate and pull out the flows and counters samples */
  {
    uint32_t samp = 0;
    for(; samp < samplesInPacket; samp++) {
      if((uint8_t *)sample->datap >= sample->endp) {
	LogError("SFLOW: readSFlowDatagram() unexpected end of datagram after sample %d of %d\n", samp, samplesInPacket);
	SFABORT(sample, SF_ABORT_EOS);
      }
      /* just read the tag, then call the approriate decode fn */
      sample->elementType = 0;
      sample->sampleType = getData32(sample);
      dbg_printf("startSample ----------------------\n");
      dbg_printf("sampleType_tag %s\n", printTag(sample->sampleType, buf, 50));
      if(sample->datagramVersion >= 5) {
	switch(sample->sampleType) {
	case SFLFLOW_SAMPLE: readFlowSample(sample, NO, fs); break;
	case SFLCOUNTERS_SAMPLE: readCountersSample(sample, NO, fs); break;
	case SFLFLOW_SAMPLE_EXPANDED: readFlowSample(sample, YES, fs); break;
	case SFLCOUNTERS_SAMPLE_EXPANDED: readCountersSample(sample, YES, fs); break;
	case SFLRTMETRIC: readRTMetric(sample, fs); break;
	case SFLRTFLOW: readRTFlow(sample, fs); break;
	default: skipTLVRecord(sample, sample->sampleType, getData32(sample), "sample"); break;
	}
      }
      else {
	switch(sample->sampleType) {
	case FLOWSAMPLE: readFlowSample_v2v4(sample, fs); break;
	case COUNTERSSAMPLE: readCountersSample_v2v4(sample, fs); break;
	default: receiveError(sample, "unexpected sample type", YES); break;
	}
      }
      dbg_printf("endSample   ----------------------\n");
    }
  }
}

/*_________________---------------------------__________________
  _________________      printUUID            __________________
  -----------------___________________________------------------
*/

  static int printUUID(const uint8_t *a, char *buf, int bufLen)
  {
    int i, b = 0;
    b += printHex(a, 4, buf, bufLen, 0, 100);
    buf[b++] = '-';
    b += printHex(a + 4, 2, buf + b, bufLen - b, 0, 100);
    buf[b++] = '-';
    b += printHex(a + 6, 2, buf + b, bufLen - b, 0, 100);
    buf[b++] = '-';
    b += printHex(a + 8, 2, buf + b, bufLen - b, 0, 100);
    buf[b++] = '-';
    b += printHex(a + 10, 6, buf + b, bufLen - b, 0, 100);

    /* should really be lowercase hex - fix that here */
    for(i = 0; i < b; i++) buf[i] = tolower(buf[i]);

    /* add NUL termination */
    buf[b] = '\0';

    return b;
  }

#ifdef DEVEL
static char *URLEncode(char *in, char *out, int outlen)
{
  register char c, *r = in, *w = out;
  int maxlen = (strlen(in) * 3) + 1;
  if(outlen < maxlen) return "URLEncode: not enough space";
  while ((c = *r++)) {
    if(isalnum(c)) *w++ = c;
    else if(isspace(c)) *w++ = '+';
    else {
      *w++ = '%';
      *w++ = bin2hex(c >> 4);
      *w++ = bin2hex(c & 0x0f);
    }
  }
  *w++ = '\0';
  return out;
}
#endif
