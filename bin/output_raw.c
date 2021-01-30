/*
 *  Copyright (c) 2019-2020, Peter Haag
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
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "util.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfxV3.h"
#include "nbar.h"
#include "output_util.h"
#include "output_raw.h"

#define STRINGSIZE 10240
#define IP_STRING_LEN (INET6_ADDRSTRLEN)

static char data_string[STRINGSIZE];

// record counter 
static uint32_t recordCount;

static void stringEXgenericFlow(char *s, size_t size, master_record_t *r) {
char datestr1[64], datestr2[64], datestr3[64];

	struct tm *ts;
	time_t when = r->msecFirst / 1000LL;
	if ( when == 0 ) {
		strncpy(datestr1, "<unknown>", 63);
	} else {
		ts = localtime(&when);
		strftime(datestr1, 63, "%Y-%m-%d %H:%M:%S", ts);
	}

	when = r->msecLast / 1000LL;
	if ( when == 0 ) {
		strncpy(datestr2, "<unknown>", 63);
	} else {
		ts = localtime(&when);
		strftime(datestr2, 63, "%Y-%m-%d %H:%M:%S", ts);
	}

	if ( r->msecReceived ) {
		when = r->msecReceived / 1000LL;
		ts = localtime(&when);
		strftime(datestr3, 63, "%Y-%m-%d %H:%M:%S", ts);
	} else {
		datestr3[0] = '0';
		datestr3[1] = '\0';
	}

	int len = snprintf(s, size-1, 
"  first        =     %13llu [%s.%03llu]\n"
"  last         =     %13llu [%s.%03llu]\n"
"  received at  =     %13llu [%s.%03llu]\n"
"  proto        =               %3u %s\n"
"  tcp flags    =              0x%.2x %s\n"
, (long long unsigned)r->msecFirst, datestr1, r->msecFirst % 1000LL
, (long long unsigned)r->msecLast, datestr2, r->msecLast % 1000LL
, (long long unsigned)r->msecReceived, datestr3, (long long unsigned)r->msecReceived % 1000L
, r->proto, ProtoString(r->proto, 0)
, r->proto == IPPROTO_TCP ? r->tcp_flags : 0, FlagsString(r->proto == IPPROTO_TCP ? r->tcp_flags :0));
	s += len;
	size -= len;

	if ( r->proto == IPPROTO_ICMP || r->proto == IPPROTO_ICMPV6 ) { // ICMP
		len = snprintf(s, size-1,
"  ICMP         =              %2u.%-2u type.code\n"
	, r->icmp_type, r->icmp_code);
	} else {
		len = snprintf(s, size-1,
"  src port     =             %5u\n"
"  dst port     =             %5u\n"
"  src tos      =               %3u\n"
	, r->srcPort, r->dstPort, r->tos);
	}
	s += len;
	size -= len;

	snprintf(s, size-1,
"  in packets   =        %10llu\n"
"  in bytes     =        %10llu\n"
	, (unsigned long long)r->inPackets, (unsigned long long)r->inBytes);

} // End of EXgenericFlowID


static void stringsEXipv4Flow(char *s, size_t size, master_record_t *r) {
char as[IP_STRING_LEN], ds[IP_STRING_LEN];

	uint32_t src = htonl(r->V4.srcaddr);
	uint32_t dst = htonl(r->V4.dstaddr);
	inet_ntop(AF_INET, &src, as, sizeof(as));
	inet_ntop(AF_INET, &dst, ds, sizeof(ds));

	snprintf(s, size-1,
"  src addr     =  %16s\n"
"  dst addr     =  %16s\n"
	, as,ds);

} // End of stringsEXipv4Flow

static void stringsEXipv6Flow(char *s, size_t size, master_record_t *r) {
char as[IP_STRING_LEN], ds[IP_STRING_LEN];
uint64_t src[2];
uint64_t dst[2];

	src[0] = htonll(r->V6.srcaddr[0]);
	src[1] = htonll(r->V6.srcaddr[1]);
	dst[0] = htonll(r->V6.dstaddr[0]);
	dst[1] = htonll(r->V6.dstaddr[1]);
	inet_ntop(AF_INET6, &src, as, sizeof(as));
	inet_ntop(AF_INET6, &dst, ds, sizeof(ds));

	snprintf(s, size-1,
"  src addr     =  %16s\n"
"  dst addr     =  %16s\n"
	, as,ds);

} // End of stringsEXipv6Flow

static void stringsEXflowMisc(char *s, size_t size, master_record_t *r) {
char snet[IP_STRING_LEN], dnet[IP_STRING_LEN];

	if ( TestFlag(r->mflags, V3_FLAG_IPV6_ADDR)) {
		// IPv6
		inet6_ntop_mask(r->V6.srcaddr, r->src_mask, snet, sizeof(snet));
 		inet6_ntop_mask(r->V6.dstaddr, r->dst_mask, dnet, sizeof(dnet));
	} else {
		// IPv4
 		inet_ntop_mask(r->V4.srcaddr, r->src_mask, snet, sizeof(snet));
 		inet_ntop_mask(r->V4.dstaddr, r->dst_mask, dnet, sizeof(dnet));
	}

	snprintf(s, size-1,
"  input        =             %5u\n"
"  output       =             %5u\n"
"  src mask     =             %5u %s/%u\n"
"  dst mask     =             %5u %s/%u\n"
"  fwd status   =               %3u\n"
"  dst tos      =               %3u\n"
"  direction    =               %3u\n"
"  biFlow Dir   =              0x%.2x %s\n"
"  end reason   =              0x%.2x %s\n"
	, r->input, r->output, 
	  r->src_mask, snet, r->src_mask, r->dst_mask, dnet, r->dst_mask, 
	  r->fwd_status, r->tos, r->dir, r->biFlowDir, biFlowString(r->biFlowDir),
	  r->flowEndReason, FlowEndString(r->flowEndReason));

} // End of stringsEXflowMisc

static void stringsEXcntFlow(char *s, size_t size, master_record_t *r) {

	snprintf(s, size-1,
"  out packets  =        %10llu\n"
"  out bytes    =        %10llu\n"
"  aggr flows   =        %10llu\n"
	, (long long unsigned)r->out_pkts, (long long unsigned)r->out_bytes,
	  (long long unsigned)r->aggr_flows);

} // End of stringEXcntFlow

static void stringsEXvLan(char *s, size_t size, master_record_t *r) {

	snprintf(s, size-1,
"  src vlan     =             %5u\n"
"  dst vlan     =             %5u\n"
, r->src_vlan, r->dst_vlan);

} // End of stringsEXvLan

static void stringsEXasRouting(char *s, size_t size, master_record_t *r) {

	snprintf(s, size-1,
"  src as       =             %5u\n"
"  dst as       =             %5u\n"
, r->srcas, r->dstas);

} // End of stringsEXasRouting

static void stringsEXbgpNextHopV4(char *s, size_t size, master_record_t *r) {
char ip[IP_STRING_LEN];

	ip[0] = 0;
	uint32_t i = htonl(r->bgp_nexthop.V4);
	inet_ntop(AF_INET, &i, ip, sizeof(ip));
	ip[IP_STRING_LEN-1] = 0;

	snprintf(s, size-1,
"  bgp next hop =  %16s\n"
, ip);

} // End of stringsEXbgpNextHopV4

static void stringsEXbgpNextHopV6(char *s, size_t size, master_record_t *r) {
char ip[IP_STRING_LEN];
uint64_t i[2];

	i[0] = htonll(r->bgp_nexthop.V6[0]);
	i[1] = htonll(r->bgp_nexthop.V6[1]);
	inet_ntop(AF_INET6, i, ip, sizeof(ip));
	ip[IP_STRING_LEN-1] = 0;

	snprintf(s, size-1,
"  bgp next hop =  %16s\n"
, ip);

} // End of stringsEXbgpNextHopV6

static void stringsEXipNextHopV4(char *s, size_t size, master_record_t *r) {
char ip[IP_STRING_LEN];

	ip[0] = 0;
	uint32_t i = htonl(r->ip_nexthop.V4);
	inet_ntop(AF_INET, &i, ip, sizeof(ip));
	ip[IP_STRING_LEN-1] = 0;

	snprintf(s, size-1,
"  ip next hop  =  %16s\n"
, ip);

} // End of stringsEXipNextHopV4

static void stringsEXipNextHopV6(char *s, size_t size, master_record_t *r) {
char ip[IP_STRING_LEN];
uint64_t i[2];

	i[0] = htonll(r->ip_nexthop.V6[0]);
	i[1] = htonll(r->ip_nexthop.V6[1]);
	inet_ntop(AF_INET6, i, ip, sizeof(ip));
	ip[IP_STRING_LEN-1] = 0;

	snprintf(s, size-1,
"  ip next hop  =  %16s\n"
, ip);

} // End of stringsEXipNextHopV6

static void stringsEXipReceivedV4(char *s, size_t size, master_record_t *r) {
char ip[IP_STRING_LEN];

	ip[0] = 0;
	uint32_t i = htonl(r->ip_router.V4);
	inet_ntop(AF_INET, &i, ip, sizeof(ip));
	ip[IP_STRING_LEN-1] = 0;

	snprintf(s, size-1,
"  ip exporter  =  %16s\n"
, ip);

} // End of stringsEXipReceivedV4

static void stringsEXipReceivedV6(char *s, size_t size, master_record_t *r) {
char ip[IP_STRING_LEN];
uint64_t i[2];

	i[0] = htonll(r->ip_router.V6[0]);
	i[1] = htonll(r->ip_router.V6[1]);
	inet_ntop(AF_INET6, i, ip, sizeof(ip));
	ip[IP_STRING_LEN-1] = 0;

	snprintf(s, size-1,
"  ip exporter  =  %16s\n"
, ip);

} // End of stringsEXipReceivedV6

static void stringsEXmplsLabel(char *s, size_t size, master_record_t *r) {

	for (int i=0; i<10; i++ ) {
		snprintf(s, size-1,
"  MPLS Lbl %2u  =      %8u-%1u-%1u\n", i+1
, r->mpls_label[i] >> 4 , (r->mpls_label[i] & 0xF ) >> 1, r->mpls_label[i] & 1 );
		size = strlen(data_string);
		s = data_string + size;
		size = STRINGSIZE - size;
	}

} // End of stringsEXipReceivedV6

static void stringsEXmacAddr(char *s, size_t size, master_record_t *r) {
uint8_t mac1[6], mac2[6], mac3[6], mac4[6];

	for ( int i=0; i<6; i++ ) {
		mac1[i] = (r->in_src_mac >> ( i*8 )) & 0xFF;
		mac2[i] = (r->out_dst_mac >> ( i*8 )) & 0xFF;
		mac3[i] = (r->in_dst_mac >> ( i*8 )) & 0xFF;
		mac4[i] = (r->out_src_mac >> ( i*8 )) & 0xFF;
	}

	snprintf(s, size-1,
"  in src mac   = %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n"
"  out dst mac  = %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n"
"  in dst mac   = %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n"
"  out src mac  = %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n"
, mac1[5], mac1[4], mac1[3], mac1[2], mac1[1], mac1[0]
, mac2[5], mac2[4], mac2[3], mac2[2], mac2[1], mac2[0]
, mac3[5], mac3[4], mac3[3], mac3[2], mac3[1], mac3[0]
, mac4[5], mac4[4], mac4[3], mac4[2], mac4[1], mac4[0]);

} // End of stringsEXmacAddr

static void stringsEXasAdjacent(char *s, size_t size, master_record_t *r) {

	snprintf(s, size-1,
"  bgp next as  =             %5u\n"
"  bgp prev as  =             %5u\n"
, r->bgpNextAdjacentAS, r->bgpPrevAdjacentAS);

} // End of stringsEXasAdjacent

static void stringsEXlatency(char *s, size_t size, master_record_t *r) {
double f1, f2, f3;

	f1 = (double)r->client_nw_delay_usec / 1000.0;
	f2 = (double)r->server_nw_delay_usec / 1000.0;
	f3 = (double)r->appl_latency_usec / 1000.0;

	snprintf(s, size-1,
"  cli latency  =         %9.3f ms\n"
"  srv latency  =         %9.3f ms\n"
"  app latency  =         %9.3f ms\n"
, f1, f2, f3);

} // End of stringsEXlatency

#ifdef NSEL
static void stringsEXnselCommon(char *s, size_t size, master_record_t *r) {
char datestr[64];

	time_t when = r->msecEvent / 1000LL;
	if ( when == 0 ) {
		strncpy(datestr, "<unknown>", 63);
	} else {
		struct tm *ts = localtime(&when);
		strftime(datestr, 63, "%Y-%m-%d %H:%M:%S", ts);
	}
	snprintf(s, size-1,
"  connect ID   =        %10u\n"
"  fw event     =             %5u: %s\n"
"  fw ext event =             %5u: %s\n"
"  Event time   =     %13llu [%s.%03llu]\n"
, r->connID, r->event, r->event_flag == FW_EVENT ? FwEventString(r->event) : EventString(r->event)
, r->fwXevent, EventXString(r->fwXevent)
, (long long unsigned)r->msecEvent, datestr
, (long long unsigned)(r->msecEvent % 1000L));

} // End of stringsEXnselCommon

static void stringsEXnselXlateIPv4(char *s, size_t size, master_record_t *r) {
char as[IP_STRING_LEN], ds[IP_STRING_LEN];

	uint32_t src = htonl(r->xlate_src_ip.V4);
	uint32_t dst = htonl(r->xlate_dst_ip.V4);
	inet_ntop(AF_INET, &src, as, sizeof(as));
	inet_ntop(AF_INET, &dst, ds, sizeof(ds));

	snprintf(s, size-1,
"  src xlt ip   =  %16s\n"
"  dst xlt ip   =  %16s\n"
	, as,ds);

} // End of stringsEXnselXlateIPv4

static void stringsEXnselXlateIPv6(char *s, size_t size, master_record_t *r) {
char as[IP_STRING_LEN], ds[IP_STRING_LEN];
uint64_t src[2];
uint64_t dst[2];

	src[0] = htonll(r->xlate_src_ip.V6[0]);
	src[1] = htonll(r->xlate_src_ip.V6[1]);
	dst[0] = htonll(r->xlate_dst_ip.V6[0]);
	dst[1] = htonll(r->xlate_dst_ip.V6[1]);
	inet_ntop(AF_INET6, &src, as, sizeof(as));
	inet_ntop(AF_INET6, &dst, ds, sizeof(ds));

	snprintf(s, size-1,
"  src xlt ip   =  %16s\n"
"  dst xlt ip   =  %16s\n"
	, as,ds);

} // End of stringsEXnselXlateIPv4

static void stringsEXnselXlatePort(char *s, size_t size, master_record_t *r) {
	snprintf(s, size-1,
"  src xlt port =             %5u\n"
"  dst xlt port =             %5u\n"
, r->xlate_src_port, r->xlate_dst_port );

} // End of stringsEXnselXlatePort

static void stringsEXnselAcl(char *s, size_t size, master_record_t *r) {
	snprintf(s, size-1,
"  Ingress ACL  =       0x%x/0x%x/0x%x\n"
"  Egress ACL   =       0x%x/0x%x/0x%x\n"
, r->ingressAcl[0], r->ingressAcl[1], r->ingressAcl[2], 
  r->egressAcl[0], r->egressAcl[1], r->egressAcl[2]);

} // End of stringsEXnselAcl

static void stringsEXnselUserID(char *s, size_t size, master_record_t *r) {
	snprintf(s, size-1,
"  username     =       %s\n"
, r->username);

} // End of stringsEXnselUserID

static void stringsEXnelCommon(char *s, size_t size, master_record_t *r) {
char datestr[64];

	time_t when = r->msecEvent / 1000LL;
	if ( when == 0 ) {
		strncpy(datestr, "<unknown>", 63);
	} else {
		struct tm *ts = localtime(&when);
		strftime(datestr, 63, "%Y-%m-%d %H:%M:%S", ts);
	}
	snprintf(s, size-1,
"  nat event    =             %5u: %s\n"
"  Event time   =     %13llu [%s.%03llu]\n"
"  ingress VRF  =        %10u\n"
"  egress VRF   =        %10u\n"
, r->event, r->event_flag == FW_EVENT ? FwEventString(r->event) : EventString(r->event)
, (long long unsigned)r->msecEvent, datestr , (long long unsigned)(r->msecEvent % 1000L)
, r->ingressVrf, r->egressVrf);

} // End of stringsEXnelCommon

static void stringsEXnelXlatePort(char *s, size_t size, master_record_t *r) {

	snprintf(s, size-1,
"  pblock start =             %5u\n"
"  pblock end   =             %5u\n"
"  pblock step  =             %5u\n"
"  pblock size  =             %5u\n"
, r->block_start, r->block_end, r->block_step, r->block_size );

} // End of stringsEXnelXlatePort

#endif
static void stringsEXnbarApp(char *s, size_t size, master_record_t *r) {
union {
        uint8_t     val8[4];
        uint32_t    val32;
}conv;

	char *name = GetNbarInfo(r->nbarAppID, 4);
	if ( name == NULL) {
		printf("No nbar app name\n");
		name = "<no info>";
	} else {
		printf("Found nbar app name\n");
	}

	conv.val8[0] = 0;
	conv.val8[1] = r->nbarAppID[1];
	conv.val8[2] = r->nbarAppID[2];
	conv.val8[3] = r->nbarAppID[3];

	snprintf(s, size-1,
"  app ID       =             %2u..%u: %s\n"
, r->nbarAppID[0], ntohl(conv.val32), name);

} // End of stringsEXnbarAppID

static void stringsEXpayload(char *s, size_t size, master_record_t *r) {

	snprintf(s, size-1,
"  payload      =             %s\n"
, r->payload);

} // End of stringsEXnelXlatePort


void raw_prolog(void) {
	recordCount = 0;
	memset(data_string, 0, STRINGSIZE);
} // End of pipe_prolog

void raw_epilog(void) {
	// empty
} // End of pipe_epilog

void flow_record_to_raw(void *record, char **s, int tag) {
char 		*_s;
ssize_t		slen, _slen;
master_record_t *r = (master_record_t *)record;
char elementString[MAXELEMENTS * 5];

	elementString[0] = '\0';
	for (int i=0; i<r->numElements; i++) {
		snprintf(elementString + strlen(elementString), sizeof(elementString) - strlen(elementString), "%u ", r->exElementList[i]);
	}

	char *type;
	char version[8];
	if ( TestFlag(r->flags, V3_FLAG_EVENT)) {
		type = "EVENT";
		version[0] = '\0';
	} else {
		if ( r->nfversion != 0 ) {
			snprintf(version, 8, " v%u", r->nfversion & 0x0F);
			if ( r->nfversion & 0x80 ) {
				type = "SFLOW";
			} else if ( r->nfversion & 0x40 ) {
				type = "PCAP";
			} else {
				type = "NETFLOW";
			}
		} else {
			// compat with previous versions
			type = "FLOW";
			version[0] = '\0';
		}
	}

	_s = data_string;
	slen = STRINGSIZE;
	snprintf(_s, slen-1, "\n"
"Flow Record: \n"
"  Flags        =              0x%.2x %s%s, %s\n"
"  Elements     =             %5u: %s\n"
"  size         =             %5u\n"
"  engine type  =             %5u\n"
"  engine ID    =             %5u\n"
"  export sysid =             %5u\n"
,	r->flags, type, version,
	TestFlag(r->flags, V3_FLAG_SAMPLED) ? "Sampled" : "Unsampled", 
	r->numElements, elementString, r->size, r->engine_type, r->engine_id, r->exporter_sysid);

	if ( r->label ) {
		_slen = strlen(data_string);
		_s = data_string + _slen;
	snprintf(_s, slen-1, 
"  Label        =  %16s\n"
, r->label);
	}

	int i = 0;
	while (r->exElementList[i]) {
		_slen = strlen(data_string);
		_s = data_string + _slen;
		slen = STRINGSIZE - _slen;
		switch (r->exElementList[i]) {
			case EXnull:
				fprintf(stderr, "Found unexpected NULL extension \n");
				break;
			case EXgenericFlowID: 
				stringEXgenericFlow(_s, slen, r);
				break;
			case EXipv4FlowID:
				stringsEXipv4Flow(_s, slen, r);
				break;
			case EXipv6FlowID:
				stringsEXipv6Flow(_s, slen, r);
				break;
			case EXflowMiscID:
				stringsEXflowMisc(_s, slen, r);
				break;
			case EXcntFlowID:
				stringsEXcntFlow(_s, slen, r);
				break;
			case EXvLanID:
				stringsEXvLan(_s, slen, r);
				break;
			case EXasRoutingID:
				stringsEXasRouting(_s, slen, r);
				break;
			case EXbgpNextHopV4ID:
				stringsEXbgpNextHopV4(_s, slen, r);
				break;
			case EXbgpNextHopV6ID:
				stringsEXbgpNextHopV6(_s, slen, r);
				break;
			case EXipNextHopV4ID:
				stringsEXipNextHopV4(_s, slen, r);
				break;
			case EXipNextHopV6ID:
				stringsEXipNextHopV6(_s, slen, r);
				break;
			case EXipReceivedV4ID:
				stringsEXipReceivedV4(_s, slen, r);
				break;
			case EXipReceivedV6ID:
				stringsEXipReceivedV6(_s, slen, r);
				break;
			case EXmplsLabelID:
				stringsEXmplsLabel(_s, slen, r);
				break;
			case EXmacAddrID:
				stringsEXmacAddr(_s, slen, r);
				break;
			case EXasAdjacentID:
				stringsEXasAdjacent(_s, slen, r);
				break;
			case EXlatencyID:
				stringsEXlatency(_s, slen, r);
				break;
#ifdef NSEL
			case EXnselCommonID:
				stringsEXnselCommon(_s, slen, r);
				break;
			case EXnselXlateIPv4ID:
				stringsEXnselXlateIPv4(_s, slen, r);
				break;
			case EXnselXlateIPv6ID:
				stringsEXnselXlateIPv6(_s, slen, r);
				break;
			case EXnselXlatePortID:
				stringsEXnselXlatePort(_s, slen, r);
				break;
			case EXnselAclID:
				stringsEXnselAcl(_s, slen, r);
				break;
			case EXnselUserID:
				stringsEXnselUserID(_s, slen, r);
				break;
			case EXnelCommonID:
				stringsEXnelCommon(_s, slen, r);
				break;
			case EXnelXlatePortID:
				stringsEXnelXlatePort(_s, slen, r);
				break;
#endif
			case EXnbarAppID:
				stringsEXnbarApp(_s, slen, r);
				break;
			case EXpayloadID:
				stringsEXpayload(_s, slen, r);
				break;
			default:
				dbg_printf("Extension %i not yet implemented\n", r->exElementList[i]);
		}
		i++;
	}

	data_string[STRINGSIZE-1] = 0;
	*s = data_string;

} // flow_record_to_raw


