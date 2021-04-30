/*
 *  Copyright (c) 2021, Peter Haag
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
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>

#include "util.h"
#include "nfdump.h"
#include "nfxV3.h"
#include "output_util.h"
#include "output_short.h"

#define IP_STRING_LEN (INET6_ADDRSTRLEN)

static void stringEXgenericFlow(FILE *stream, master_record_t *r) {
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

	fprintf(stream, 
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

	if ( r->proto == IPPROTO_ICMP || r->proto == IPPROTO_ICMPV6 ) { // ICMP
		fprintf(stream,
"  ICMP         =              %2u.%-2u type.code\n"
	, r->icmp_type, r->icmp_code);
	} else {
		fprintf(stream,
"  src port     =             %5u\n"
"  dst port     =             %5u\n"
"  src tos      =               %3u\n"
	, r->srcPort, r->dstPort, r->tos);
	}

	fprintf(stream,
"  in packets   =        %10llu\n"
"  in bytes     =        %10llu\n"
	, (unsigned long long)r->inPackets, (unsigned long long)r->inBytes);

} // End of EXgenericFlowID


static void stringsEXipv4Flow(FILE *stream, master_record_t *r) {
char as[IP_STRING_LEN], ds[IP_STRING_LEN];

	uint32_t src = htonl(r->V4.srcaddr);
	uint32_t dst = htonl(r->V4.dstaddr);
	inet_ntop(AF_INET, &src, as, sizeof(as));
	inet_ntop(AF_INET, &dst, ds, sizeof(ds));

	fprintf(stream,
"  src addr     =  %16s\n"
"  dst addr     =  %16s\n"
	, as, ds);

} // End of stringsEXipv4Flow

static void stringsEXipv6Flow(FILE *stream, master_record_t *r) {
char as[IP_STRING_LEN], ds[IP_STRING_LEN];
uint64_t src[2], dst[2];

	src[0] = htonll(r->V6.srcaddr[0]);
	src[1] = htonll(r->V6.srcaddr[1]);
	dst[0] = htonll(r->V6.dstaddr[0]);
	dst[1] = htonll(r->V6.dstaddr[1]);
	inet_ntop(AF_INET6, &src, as, sizeof(as));
	inet_ntop(AF_INET6, &dst, ds, sizeof(ds));

	fprintf(stream,
"  src addr     =  %16s\n"
"  dst addr     =  %16s\n"
	, as, ds);

} // End of stringsEXipv6Flow

static void stringsEXflowMisc(FILE *stream, master_record_t *r) {
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

	fprintf(stream,
"  input        =          %8u\n"
"  output       =          %8u\n"
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

static void stringsEXcntFlow(FILE *stream, master_record_t *r) {

	fprintf(stream,
"  out packets  =        %10llu\n"
"  out bytes    =        %10llu\n"
"  aggr flows   =        %10llu\n"
	, (long long unsigned)r->out_pkts, (long long unsigned)r->out_bytes,
	  (long long unsigned)r->aggr_flows);

} // End of stringEXcntFlow

static void stringsEXipReceivedV4(FILE *stream, master_record_t *r) {
char ip[IP_STRING_LEN];

	ip[0] = 0;
	uint32_t i = htonl(r->ip_router.V4);
	inet_ntop(AF_INET, &i, ip, sizeof(ip));
	ip[IP_STRING_LEN-1] = 0;

	fprintf(stream,
"  ip exporter  =  %16s\n"
, ip);

} // End of stringsEXipReceivedV4

static void stringsEXipReceivedV6(FILE *stream, master_record_t *r) {
char ip[IP_STRING_LEN];
uint64_t i[2];

	i[0] = htonll(r->ip_router.V6[0]);
	i[1] = htonll(r->ip_router.V6[1]);
	inet_ntop(AF_INET6, i, ip, sizeof(ip));
	ip[IP_STRING_LEN-1] = 0;

	fprintf(stream,
"  ip exporter  =  %16s\n"
, ip);

} // End of stringsEXipReceivedV6

void flow_record_short(FILE *stream, void *record, int tag) {
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

	fprintf(stream, "\n"
"Flow Record: \n"
"  Flags        =              0x%.2x %s%s%s, %s\n"
"  Elements     =             %5u: %s\n"
"  size         =             %5u\n"
"  engine type  =             %5u\n"
"  engine ID    =             %5u\n"
"  export sysid =             %5u\n"
,	r->flags, type, version,
	TestFlag(r->flags, V3_FLAG_ANON) ? " Anonymized" : "", 
	TestFlag(r->flags, V3_FLAG_SAMPLED) ? "Sampled" : "Unsampled", 
	r->numElements, elementString, r->size, r->engine_type, r->engine_id, r->exporter_sysid);

	if ( r->label ) {
	fprintf(stream, 
"  Label        =  %16s\n"
, r->label);
	}

	int i = 0;
	while (r->exElementList[i]) {
		switch (r->exElementList[i]) {
			case EXnull:
				fprintf(stderr, "Found unexpected NULL extension \n");
				break;
			case EXgenericFlowID: 
				stringEXgenericFlow(stream, r);
				break;
			case EXipv4FlowID:
				stringsEXipv4Flow(stream, r);
				break;
			case EXipv6FlowID:
				stringsEXipv6Flow(stream, r);
				break;
			case EXflowMiscID:
				stringsEXflowMisc(stream, r);
				break;
			case EXcntFlowID:
				stringsEXcntFlow(stream, r);
				break;
			case EXipReceivedV4ID:
				stringsEXipReceivedV4(stream, r);
				break;
			case EXipReceivedV6ID:
				stringsEXipReceivedV6(stream, r);
				break;
		}
		i++;
	}

} // flow_record_short


