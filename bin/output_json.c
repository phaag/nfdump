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

// for asprintf prototype
#define _GNU_SOURCE

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
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
#include "nfx.h"
#include "nfxV3.h"
#include "output_util.h"
#include "output_json.h"

#define STRINGSIZE 10240
#define IP_STRING_LEN (INET6_ADDRSTRLEN)

static char data_string[STRINGSIZE];

// record counter 
static uint32_t recordCount;

static void stringEXgenericFlow(char *s, size_t size, master_record_t *r) {
char datebuff1[64], datebuff2[64], dateBuff3[64];

	time_t when   = r->msecFirst/1000LL;
	struct tm *ts = localtime(&when);
	strftime(datebuff1, 63, "%Y-%m-%dT%H:%M:%S", ts);

	when = r->msecLast/1000LL;
	ts = localtime(&when);
	strftime(datebuff2, 63, "%Y-%m-%dT%H:%M:%S", ts);

	when = r->received / 1000LL;
	ts = localtime(&when);
	strftime(dateBuff3, 63, "%Y-%m-%dT%H:%M:%S", ts);

	snprintf(s, size-1, 
"	\"first\" : \"%s.%u\",\n"
"	\"last\" : \"%s.%u\",\n"
"	\"received\" : \"%s.%u\",\n"
"	\"in_packets\" : %llu,\n"
"	\"in_bytes\" : %llu,\n"
	, datebuff1, (unsigned)(r->msecFirst % 1000LL)
	, datebuff2, (unsigned)(r->msecLast % 1000LL)
	, dateBuff3, (unsigned)(r->received % 1000LL)
	, (unsigned long long)r->dPkts, (unsigned long long)r->dOctets);

	if ( r->proto == IPPROTO_ICMP || r->proto == IPPROTO_ICMPV6 ) { // ICMP
		snprintf(s, size-1,
"	\"proto\" : %u,\n"
"	\"icmp_type\" : %u,\n"
"	\"icmp_code\" : %u,\n"
"	\"src_tos\" : %u,\n", r->proto, r->icmp_type, r->icmp_code, r->tos);
	} else {
		snprintf(s, size-1,
"	\"proto\" : %u,\n"
"	\"tcp_flags\" : \"%s\",\n"
"	\"src_port\" : %u,\n"
"	\"dst_port\" : %u,\n"
"	\"src_tos\" : %u,\n", r->proto, FlagsString(r->tcp_flags), r->srcPort, r->dstPort, r->tos);
	}

} // End of stringEXgenericFlow

static void stringsEXipv4Flow(char *s, size_t size, master_record_t *r) {
char as[IP_STRING_LEN], ds[IP_STRING_LEN];

	uint32_t src = htonl(r->V4.srcaddr);
	uint32_t dst = htonl(r->V4.dstaddr);
	inet_ntop(AF_INET, &src, as, sizeof(as));
	inet_ntop(AF_INET, &dst, ds, sizeof(ds));

	snprintf(s, size-1,
"	\"src4_addr\" : \"%s\",\n"
"	\"dst4_addr\" : \"%s\",\n" , as,ds);

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
"	\"src6_addr\" : \"%s\",\n"
"	\"dst6_addr\" : \"%s\",\n", as,ds);

} // End of stringsEXipv6Flow

static void stringsEXflowMisc(char *s, size_t size, master_record_t *r) {
char snet[IP_STRING_LEN], dnet[IP_STRING_LEN];

	if ( TestFlag(r->flags,FLAG_IPV6_ADDR ) != 0 ) {
		// IPv6
		if ( r->src_mask || r->dst_mask) {
			uint64_t src[2];
			uint64_t dst[2];
			if ( r->src_mask >= 64 ) {
				src[0] = r->V6.srcaddr[0] & (0xffffffffffffffffLL << (r->src_mask - 64));
				src[1] = 0;
			} else {
				src[0] = r->V6.srcaddr[0];
				src[1] = r->V6.srcaddr[1] & (0xffffffffffffffffLL << r->src_mask);
			}
			src[0] = htonll(src[0]);
			src[1] = htonll(src[1]);
			inet_ntop(AF_INET6, &src, snet, sizeof(snet));

			if ( r->dst_mask >= 64 ) {
				dst[0] = r->V6.dstaddr[0] & (0xffffffffffffffffLL << (r->dst_mask - 64));
				dst[1] = 0;
			} else {
				dst[0] = r->V6.dstaddr[0];
				dst[1] = r->V6.dstaddr[1] & (0xffffffffffffffffLL << r->dst_mask);
			}
			dst[0] = htonll(dst[0]);
			dst[1] = htonll(dst[1]);
			inet_ntop(AF_INET6, &dst, dnet, sizeof(dnet));
	
		} else {
			snet[0] = '\0';
			dnet[0] = '\0';
		}

	} else {
		// IPv4
		if ( r->src_mask || r->dst_mask) {
			uint32_t src, dst;
			src = r->V4.srcaddr & (0xffffffffL << (32 - r->src_mask));
			src = htonl(src);
			inet_ntop(AF_INET, &src, snet, sizeof(snet));

			dst = r->V4.dstaddr & (0xffffffffL << (32 - r->dst_mask));
			dst = htonl(dst);
			inet_ntop(AF_INET, &dst, dnet, sizeof(dnet));
		} else {
			snet[0] = '\0';
			dnet[0] = '\0';
		}
	}

	snprintf(s, size-1,
"	\"input_snmp\" : %u,\n"
"	\"output_snmp\" : %u,\n"
"	\"src_mask\" : %u,\n"
"	\"dst_mask\" : %u,\n"
"	\"src_net\" : \"%s\",\n"
"	\"dst_net\" : \"%s\",\n"
"	\"fwd_status\" : %u,\n"
"	\"direction\" : %u,\n"
"	\"dst_tos\" : %u,\n"
	, r->input, r->output, r->src_mask, r->dst_mask, snet, dnet, r->fwd_status, r->dir, r->dst_tos);

} // End of stringsEXflowMisc

static void stringsEXcntFlow(char *s, size_t size, master_record_t *r) {

	snprintf(s, size-1,
"	\"out_packets\" : %llu,\n"
"	\"out_bytes\" : %llu,\n"
"	\"aggr_flows\" : %llu,\n"
	, (long long unsigned)r->out_pkts, (long long unsigned)r->out_bytes,
	  (long long unsigned)r->aggr_flows);

} // End of stringEXcntFlow

static void stringsEXvLan(char *s, size_t size, master_record_t *r) {

	snprintf(s, size-1,
"	\"src_vlan\" : %u,\n"
"	\"dst_vlan\" : %u,\n"
, r->src_vlan, r->dst_vlan);

} // End of stringsEXvLan

static void stringsEXasRouting(char *s, size_t size, master_record_t *r) {

	snprintf(s, size-1,
"	\"src_as\" : %u,\n"
"	\"dst_as\" : %u,\n"
, r->srcas, r->dstas);

} // End of stringsEXasRouting

static void stringsEXbgpNextHopV4(char *s, size_t size, master_record_t *r) {
char ip[IP_STRING_LEN];

	ip[0] = 0;
	uint32_t i = htonl(r->bgp_nexthop.V4);
	inet_ntop(AF_INET, &i, ip, sizeof(ip));
	ip[IP_STRING_LEN-1] = 0;

	snprintf(s, size-1,
"	\"bgp4_next_hop\" : \"%s\",\n", ip);

} // End of stringsEXbgpNextHopV4

static void stringsEXbgpNextHopV6(char *s, size_t size, master_record_t *r) {
char ip[IP_STRING_LEN];
uint64_t i[2];

	i[0] = htonll(r->bgp_nexthop.V6[0]);
	i[1] = htonll(r->bgp_nexthop.V6[1]);
	inet_ntop(AF_INET6, i, ip, sizeof(ip));
	ip[IP_STRING_LEN-1] = 0;

	snprintf(s, size-1,
"	\"bgp6_next_hop\" : \"%s\",\n", ip);

} // End of stringsEXbgpNextHopV6

static void stringsEXipNextHopV4(char *s, size_t size, master_record_t *r) {
char ip[IP_STRING_LEN];

	ip[0] = 0;
	uint32_t i = htonl(r->ip_nexthop.V4);
	inet_ntop(AF_INET, &i, ip, sizeof(ip));
	ip[IP_STRING_LEN-1] = 0;

	snprintf(s, size-1,
"	\"ip4_next_hop\" : \"%s\",\n", ip);

} // End of stringsEXipNextHopV4

static void stringsEXipNextHopV6(char *s, size_t size, master_record_t *r) {
char ip[IP_STRING_LEN];
uint64_t i[2];

	i[0] = htonll(r->ip_nexthop.V6[0]);
	i[1] = htonll(r->ip_nexthop.V6[1]);
	inet_ntop(AF_INET6, i, ip, sizeof(ip));
	ip[IP_STRING_LEN-1] = 0;

	snprintf(s, size-1,
"	\"ip6_next_hop\" : \"%s\",\n", ip);

} // End of stringsEXipNextHopV6

static void stringsEXipReceivedV4(char *s, size_t size, master_record_t *r) {
char ip[IP_STRING_LEN];

	ip[0] = 0;
	uint32_t i = htonl(r->ip_router.V4);
	inet_ntop(AF_INET, &i, ip, sizeof(ip));
	ip[IP_STRING_LEN-1] = 0;

	snprintf(s, size-1,
"	\"ip4_router\" : \"%s\",\n", ip);

} // End of stringsEXipReceivedV4

static void stringsEXipReceivedV6(char *s, size_t size, master_record_t *r) {
char ip[IP_STRING_LEN];
uint64_t i[2];

	i[0] = htonll(r->ip_router.V6[0]);
	i[1] = htonll(r->ip_router.V6[1]);
	inet_ntop(AF_INET6, i, ip, sizeof(ip));
	ip[IP_STRING_LEN-1] = 0;

	snprintf(s, size-1,
"	\"ip6_router\" : \"%s\",\n", ip);

} // End of stringsEXipReceivedV6

static void stringsEXmplsLabel(char *s, size_t size, master_record_t *r) {

	for (int i=0; i<10; i++ ) {
		snprintf(s, size-1,
"	\"mpls_%u\" : \"%u-%u-%u\",\n", i+1
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
"	\"in_src_mac\" : \"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\",\n"
"	\"out_dst_mac\" : \"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\",\n"
"	\"in_dst_mac\" : \"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\",\n"
"	\"out_src_mac\" : \"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\",\n"
, mac1[5], mac1[4], mac1[3], mac1[2], mac1[1], mac1[0]
, mac2[5], mac2[4], mac2[3], mac2[2], mac2[1], mac2[0]
, mac3[5], mac3[4], mac3[3], mac3[2], mac3[1], mac3[0]
, mac4[5], mac4[4], mac4[3], mac4[2], mac4[1], mac4[0]);

} // End of stringsEXmacAddr

static void stringsEXasAdjacent(char *s, size_t size, master_record_t *r) {

	snprintf(s, size-1,
"	\"next_as\" : %u,\n"
"	\"prev_as\" : %u,\n"
, r->bgpNextAdjacentAS, r->bgpPrevAdjacentAS);

} // End of stringsEXasAdjacent

static void stringsEXlatency(char *s, size_t size, master_record_t *r) {
double f1, f2, f3;

	f1 = (double)r->client_nw_delay_usec / 1000.0;
	f2 = (double)r->server_nw_delay_usec / 1000.0;
	f3 = (double)r->appl_latency_usec / 1000.0;

	snprintf(s, size-1,
"	\"cli_latency\" : %f,\n"
"	\"srv_latency\" : %f,\n"
"	\"app_latency\" : %f,\n"
, f1, f2, f3);

} // End of stringsEXlatency

#ifdef NSEL
static void stringsEXnselCommon(char *s, size_t size, master_record_t *r) {
char datestr[64];

	time_t when = r->event_time / 1000LL;
	if ( when == 0 ) {
		strncpy(datestr, "<unknown>", 63);
	} else {
		struct tm *ts = localtime(&when);
		strftime(datestr, 63, "%Y-%m-%dT%H:%M:%S", ts);
	}
	snprintf(s, size-1,
"	\"connect_id\" : \"%u\",\n"
"	\"event_id\" : \"%u\",\n"
"	\"event\" : \"%s\",\n"
"	\"xevent_id\" : \"%u\",\n"
"	\"t_event\" : \"%s.%llu\",\n"
, r->conn_id, r->event, r->event_flag == FW_EVENT ? FwEventString(r->event) : EventString(r->event)
, r->fw_xevent, datestr, r->event_time % 1000LL);

} // End of stringsEXnselCommon

static void stringsEXnselXlateIPv4(char *s, size_t size, master_record_t *r) {
char as[IP_STRING_LEN], ds[IP_STRING_LEN];

	uint32_t src = htonl(r->xlate_src_ip.V4);
	uint32_t dst = htonl(r->xlate_dst_ip.V4);
	inet_ntop(AF_INET, &src, as, sizeof(as));
	inet_ntop(AF_INET, &dst, ds, sizeof(ds));

	snprintf(s, size-1,
"	\"src4_xlt_ip\" : \"%s\",\n"
"	\"dst4_xlt_ip\" : \"%s\",\n"
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
"	\"src6_xlt_ip\" : \"%s\",\n"
"	\"dst6_xlt_ip\" : \"%s\",\n"
	, as,ds);

} // End of stringsEXnselXlateIPv4

static void stringsEXnselXlatePort(char *s, size_t size, master_record_t *r) {
	snprintf(s, size-1,
"	\"src_xlt_port\" : \"%u\",\n"
"	\"dst_xlt_port\" : \"%u\",\n"
, r->xlate_src_port, r->xlate_dst_port );

} // End of stringsEXnselXlatePort

static void stringsEXnselAcl(char *s, size_t size, master_record_t *r) {
	snprintf(s, size-1,
"	\"ingress_acl\" : \"0x%x/0x%x/0x%x\",\n"
"	\"egress_acl\" : \"0x%x/0x%x/0x%x\",\n"
, r->ingress_acl_id[0], r->ingress_acl_id[1], r->ingress_acl_id[2], 
  r->egress_acl_id[0], r->egress_acl_id[1], r->egress_acl_id[2]);

} // End of stringsEXnselAcl

static void stringsEXnselUserID(char *s, size_t size, master_record_t *r) {
	snprintf(s, size-1,
"	\"user_name\" : \"%s\",\n"
, r->username[0] ? r->username : "<empty>");

} // End of stringsEXnselUserID

static void stringsEXnelCommon(char *s, size_t size, master_record_t *r) {
char datestr[64];
char *event;

	switch (r->event) {
		case 0:
			event = "Reserved"; break;
		case 1:
			event = "NAT translation create"; break;
		case 2:
			event = "NAT translation delete"; break;
		case 3:
			event = "NAT Addresses exhausted"; break;
		case 4:
			event = "NAT44 session create"; break;
		case 5:
			event = "NAT44 session delete"; break;
		case 6:
			event = "NAT64 session create"; break;
		case 7:
			event = "NAT64 session delete"; break;
		case 8:
			event = "NAT44 BIB create"; break;
		case 9:
			event = "NAT44 BIB delete"; break;
		case 10:
			event = "NAT64 BIB create"; break;
		case 11:
			event = "NAT64 BIB delete"; break;
		case 12:
			event = "NAT ports exhausted"; break;
		case 13:
			event = "Quota Exceeded"; break;
		case 14:
			event = "Address binding create"; break;
		case 15:
			event = "Address binding delete"; break;
		case 16:
			event = "Port block allocation"; break;
		case 17:
			event = "Port block de-allocation"; break;
		case 18:
			event = "Threshold Reached"; break;
		default:
			event = ""; break;
	}

	time_t when = r->event_time / 1000LL;
	if ( when == 0 ) {
		strncpy(datestr, "<unknown>", 63);
	} else {
		struct tm *ts = localtime(&when);
		strftime(datestr, 63, "%Y-%m-%dT%H:%M:%S", ts);
	}
	snprintf(s, size-1,
"	\"nat_event_id\" : \"%u\",\n"
"	\"nat_event\" : \"%s\",\n"
"	\"ingress_vrf\" : \"%u\",\n"
"	\"egress_vrf\" : \"%u\",\n"
"	\"t_event\" : \"%s.%llu\",\n"
, r->event, event, r->ingress_vrfid, r->egress_vrfid
, datestr, r->event_time % 1000LL);

} // End of stringsEXnelCommon

static void stringsEXnelXlatePort(char *s, size_t size, master_record_t *r) {

	snprintf(s, size-1,
"	\"pblock_start\" : \"%u\",\n"
"	\"pblock_end\" : \"%u\",\n"
"	\"pblock_step\" : \"%u\",\n"
"	\"pblock_size\" : \"%u\",\n"
, r->block_start, r->block_end, r->block_step, r->block_size );

} // End of stringsEXnelXlatePort
#endif

void json_prolog(void) {
	recordCount = 0;
	memset(data_string, 0, STRINGSIZE);
	printf("[\n");
} // End of json_prolog

void json_epilog(void) {
	printf("]\n");
} // End of json_epilog

void flow_record_to_json(void *record, char ** s, int tag) {
master_record_t *r = (master_record_t *)record;

	if ( recordCount ) {
		strncpy(data_string, ",\n", STRINGSIZE-1);
	}
	recordCount++;

	ssize_t _slen = strlen(data_string);
	char *_s = data_string + _slen;	
	ssize_t slen = STRINGSIZE - _slen;
	snprintf(_s, slen-1, "{\n"
"	\"type\" : \"%s\",\n"
"	\"sampled\" : %u,\n"
"	\"export_sysid\" : %u,\n"
, TestFlag(r->flags, FLAG_EVENT) ? "EVENT" : "FLOW", 
	TestFlag(r->flags, FLAG_SAMPLED) ? 1 : 0, 
	r->exporter_sysid);

	int i = 0;
	while (r->exElementList[i]) {
		ssize_t _slen = strlen(data_string);
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
			default:
				dbg_printf("Extension %i not yet implemented\n", r->exElementList[i]);
		}
		i++;
	}

	// add label and close json object
	snprintf(_s, slen-1, 
"	\"label\" : \"%s\"\n"
"}", r->label ? r->label : "<none>");

	data_string[STRINGSIZE-1] = 0;
	*s = data_string;

} // End of flow_record_to_json
