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
#include "nfx.h"
#include "output_util.h"
#include "output_raw.h"

#define STRINGSIZE 10240
#define IP_STRING_LEN (INET6_ADDRSTRLEN)

static char data_string[STRINGSIZE];

// record counter 
static uint32_t recordCount;

void raw_prolog(void) {
	recordCount = 0;
	memset(data_string, 0, STRINGSIZE);
} // End of raw_prolog

void raw_epilog(void) {
	// empty
} // End of raw_epilog

void flow_record_to_raw(void *record, char ** s, int tag) {
char 		*_s, as[IP_STRING_LEN], ds[IP_STRING_LEN], datestr1[64], datestr2[64], datestr3[64];
char		s_snet[IP_STRING_LEN], s_dnet[IP_STRING_LEN];
int			i, id;
ssize_t		slen, _slen;
time_t		when;
struct tm 	*ts;
master_record_t *r = (master_record_t *)record;
extension_map_t	*extension_map = r->map_ref;

	as[0] = 0;
	ds[0] = 0;
	if ( TestFlag(r->flags,FLAG_IPV6_ADDR ) != 0 ) { // IPv6
		uint64_t snet[2];
		uint64_t dnet[2];

		snet[0] = htonll(r->V6.srcaddr[0]);
		snet[1] = htonll(r->V6.srcaddr[1]);
		dnet[0] = htonll(r->V6.dstaddr[0]);
		dnet[1] = htonll(r->V6.dstaddr[1]);
		inet_ntop(AF_INET6, snet, as, sizeof(as));
		inet_ntop(AF_INET6, dnet, ds, sizeof(ds));

		inet6_ntop_mask(r->V6.srcaddr, r->src_mask, s_snet, sizeof(s_snet));
		inet6_ntop_mask(r->V6.dstaddr, r->dst_mask, s_dnet, sizeof(s_dnet));

	} else {	// IPv4
		uint32_t snet, dnet;
		snet = htonl(r->V4.srcaddr);
		dnet = htonl(r->V4.dstaddr);
		inet_ntop(AF_INET, &snet, as, sizeof(as));
		inet_ntop(AF_INET, &dnet, ds, sizeof(ds));

		inet_ntop_mask(r->V4.srcaddr, r->src_mask, s_snet, sizeof(s_snet));
		inet_ntop_mask(r->V4.dstaddr, r->dst_mask, s_dnet, sizeof(s_dnet));

	}
	as[IP_STRING_LEN-1] = 0;
	ds[IP_STRING_LEN-1] = 0;

	when = r->msecFirst/1000LL;
	ts = localtime(&when);
	strftime(datestr1, 63, "%Y-%m-%d %H:%M:%S", ts);

	when = r->msecLast/1000LL;
	ts = localtime(&when);
	strftime(datestr2, 63, "%Y-%m-%d %H:%M:%S", ts);

	_s = data_string;
	slen = STRINGSIZE;
	snprintf(_s, slen-1, "\n"
"Flow Record: \n"
"  Flags        =              0x%.2x %s, %s\n"
"  label        =  %16s\n"
"  export sysid =             %5u\n"
"  size         =             %5u\n"
"  first        =     %13llu [%s.%03llu]\n"
"  last         =     %13llu [%s.%03llu]\n"
"  src addr     =  %16s\n"
"  dst addr     =  %16s\n"
, 
		r->flags, TestFlag(r->flags, FLAG_EVENT) ? "EVENT" : "FLOW", 
		TestFlag(r->flags, FLAG_SAMPLED) ? "Sampled" : "Unsampled", 
		r->label ? r->label : "<none>",
		r->exporter_sysid, r->size, r->msecFirst, datestr1, r->msecFirst % 1000LL,
		r->msecLast, datestr2, r->msecLast % 1000LL,
		as, ds );

	_slen = strlen(data_string);
	_s = data_string + _slen;
	slen = STRINGSIZE - _slen;

	if ( r->proto == IPPROTO_ICMP || r->proto == IPPROTO_ICMPV6 ) { // ICMP
		snprintf(_s, slen-1,
"  ICMP         =              %2u.%-2u type.code\n",
		r->icmp_type, r->icmp_code);
	} else {
		snprintf(_s, slen-1,
"  src port     =             %5u\n"
"  dst port     =             %5u\n",
		r->srcPort, r->dstPort);
	}

	_slen = strlen(data_string);
	_s = data_string + _slen;
	slen = STRINGSIZE - _slen;

	snprintf(_s, slen-1,
"  fwd status   =               %3u\n"
"  tcp flags    =              0x%.2x %s\n"
"  proto        =               %3u %s\n"
"  (src)tos     =               %3u\n"
"  (in)packets  =        %10llu\n"
"  (in)bytes    =        %10llu\n",
	r->fwd_status, r->tcp_flags, FlagsString(r->tcp_flags), r->proto, ProtoString(r->proto, 0), r->tos,
		(unsigned long long)r->dPkts, (unsigned long long)r->dOctets);

	_slen = strlen(data_string);
	_s = data_string + _slen;
	slen = STRINGSIZE - _slen;
	
	i = 0;
	while ( (id = extension_map->ex_id[i]) != 0 ) {
		if ( slen <= 20 ) {
			fprintf(stderr, "String too short! Missing record data!\n");
			data_string[STRINGSIZE-1] = 0;
			*s = data_string;
		}
		switch(id) {
			case EX_IO_SNMP_2:
			case EX_IO_SNMP_4:
				snprintf(_s, slen-1,
"  input        =             %5u\n"
"  output       =             %5u\n"
, r->input, r->output);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
				break;
			case EX_AS_2:
			case EX_AS_4:
				snprintf(_s, slen-1,
"  src as       =             %5u\n"
"  dst as       =             %5u\n"
, r->srcas, r->dstas);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
				break;
			case EX_BGPADJ:
				snprintf(_s, slen-1,
"  next as      =             %5u\n"
"  prev as      =             %5u\n"
, r->bgpNextAdjacentAS, r->bgpPrevAdjacentAS);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
				break;
			case EX_MULIPLE:
				snprintf(_s, slen-1,
"  src mask     =             %5u %s/%u\n"
"  dst mask     =             %5u %s/%u\n"
"  dst tos      =               %3u\n"
"  direction    =               %3u\n"
, r->src_mask, s_snet, r->src_mask, r->dst_mask, s_dnet, r->dst_mask, r->dst_tos, r->dir );
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
				break;
			case EX_NEXT_HOP_v4:
			case EX_NEXT_HOP_v6:
				if ( (r->flags & FLAG_IPV6_NH ) != 0 ) { // IPv6
					as[0] = 0;
					r->ip_nexthop.V6[0] = htonll(r->ip_nexthop.V6[0]);
					r->ip_nexthop.V6[1] = htonll(r->ip_nexthop.V6[1]);
					inet_ntop(AF_INET6, r->ip_nexthop.V6, as, sizeof(as));
					as[IP_STRING_LEN-1] = 0;
				} else {
					as[0] = 0;
					r->ip_nexthop.V4 = htonl(r->ip_nexthop.V4);
					inet_ntop(AF_INET, &r->ip_nexthop.V4, as, sizeof(as));
					as[IP_STRING_LEN-1] = 0;
				}

				snprintf(_s, slen-1,
"  ip next hop  =  %16s\n"
, as);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
			break;
			case EX_NEXT_HOP_BGP_v4:
			case EX_NEXT_HOP_BGP_v6:
				if ( (r->flags & FLAG_IPV6_NHB ) != 0 ) { // IPv6
					as[0] = 0;
					r->bgp_nexthop.V6[0] = htonll(r->bgp_nexthop.V6[0]);
					r->bgp_nexthop.V6[1] = htonll(r->bgp_nexthop.V6[1]);
					inet_ntop(AF_INET6, r->ip_nexthop.V6, as, sizeof(as));
					as[IP_STRING_LEN-1] = 0;
				} else {
					as[0] = 0;
					r->bgp_nexthop.V4 = htonl(r->bgp_nexthop.V4);
					inet_ntop(AF_INET, &r->bgp_nexthop.V4, as, sizeof(as));
					as[IP_STRING_LEN-1] = 0;
				}
				snprintf(_s, slen-1,
"  bgp next hop =  %16s\n"
, as);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
			break;
			case EX_VLAN:
				snprintf(_s, slen-1,
"  src vlan     =             %5u\n"
"  dst vlan     =             %5u\n"
, r->src_vlan, r->dst_vlan);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
			break;
			case EX_OUT_PKG_4:
			case EX_OUT_PKG_8:
				snprintf(_s, slen-1,
"  out packets  =        %10llu\n"
, (long long unsigned)r->out_pkts);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
			break;
			case EX_OUT_BYTES_4:
			case EX_OUT_BYTES_8:
				snprintf(_s, slen-1,
"  out bytes    =        %10llu\n"
, (long long unsigned)r->out_bytes);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
			break;
			case EX_AGGR_FLOWS_4:
			case EX_AGGR_FLOWS_8:
				snprintf(_s, slen-1,
"  aggr flows   =        %10llu\n"
, (long long unsigned)r->aggr_flows);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
			break;
			case EX_MAC_1: {
				int i;
				uint8_t mac1[6], mac2[6];

				for ( i=0; i<6; i++ ) {
					mac1[i] = (r->in_src_mac >> ( i*8 )) & 0xFF;
				}
				for ( i=0; i<6; i++ ) {
					mac2[i] = (r->out_dst_mac >> ( i*8 )) & 0xFF;
				}

				snprintf(_s, slen-1,
"  in src mac   = %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n"
"  out dst mac  = %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n"
, mac1[5], mac1[4], mac1[3], mac1[2], mac1[1], mac1[0], mac2[5], mac2[4], mac2[3], mac2[2], mac2[1], mac2[0] );
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
			} break;
			case EX_MAC_2: {
				int i;
				uint8_t mac1[6], mac2[6];

				for ( i=0; i<6; i++ ) {
					mac1[i] = (r->in_dst_mac >> ( i*8 )) & 0xFF;
				}
				for ( i=0; i<6; i++ ) {
					mac2[i] = (r->out_src_mac >> ( i*8 )) & 0xFF;
				}

				snprintf(_s, slen-1,
"  in dst mac   = %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n"
"  out src mac  = %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n"
, mac1[5], mac1[4], mac1[3], mac1[2], mac1[1], mac1[0], mac2[5], mac2[4], mac2[3], mac2[2], mac2[1], mac2[0] );
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
			} break;
			case EX_MPLS: {
				unsigned int i;
				for ( i=0; i<10; i++ ) {
					snprintf(_s, slen-1,
"  MPLS Lbl %2u  =      %8u-%1u-%1u\n", i+1
, r->mpls_label[i] >> 4 , (r->mpls_label[i] & 0xF ) >> 1, r->mpls_label[i] & 1 );
					_slen = strlen(data_string);
					_s = data_string + _slen;
					slen = STRINGSIZE - _slen;
				}
			} break;
			case EX_ROUTER_IP_v4:
				as[0] = 0;
				r->ip_router.V4 = htonl(r->ip_router.V4);
				inet_ntop(AF_INET, &r->ip_router.V4, as, sizeof(as));
				as[IP_STRING_LEN-1] = 0;

				snprintf(_s, slen-1,
"  ip router    =  %16s\n"
, as);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
	
			break;
			case EX_ROUTER_IP_v6:
				as[0] = 0;
				r->ip_router.V6[0] = htonll(r->ip_router.V6[0]);
				r->ip_router.V6[1] = htonll(r->ip_router.V6[1]);
				inet_ntop(AF_INET6, &r->ip_router.V6, as, sizeof(as));
				as[IP_STRING_LEN-1] = 0;

				snprintf(_s, slen-1,
"  ip router    =  %16s\n"
, as);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
			break;
			case EX_LATENCY: {
				double f1, f2, f3;
				f1 = (double)r->client_nw_delay_usec / 1000.0;
				f2 = (double)r->server_nw_delay_usec / 1000.0;
				f3 = (double)r->appl_latency_usec / 1000.0;

				snprintf(_s, slen-1,
"  cli latency  =         %9.3f ms\n"
"  srv latency  =         %9.3f ms\n"
"  app latency  =         %9.3f ms\n"
, f1, f2, f3);

				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;

			} break;
			case EX_ROUTER_ID:
				snprintf(_s, slen-1,
"  engine type  =             %5u\n"
"  engine ID    =             %5u\n"
, r->engine_type, r->engine_id);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
				break;
			case EX_RECEIVED:
				when = r->received / 1000LL;
				ts = localtime(&when);
				strftime(datestr3, 63, "%Y-%m-%d %H:%M:%S", ts);

				snprintf(_s, slen-1,
"  received at  =     %13llu [%s.%03llu]\n"
, (long long unsigned)r->received, datestr3, (long long unsigned)(r->received % 1000L));
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
				break;
#ifdef NSEL
			case EX_NSEL_COMMON: {
				when = r->event_time / 1000LL;
				ts = localtime(&when);
				strftime(datestr3, 63, "%Y-%m-%d %H:%M:%S", ts);
				snprintf(_s, slen-1,
"  connect ID   =        %10u\n"
"  fw event     =             %5u: %s\n"
"  fw ext event =             %5u: %s\n"
"  secgroup tag =             %5u\n"
"  Event time   =     %13llu [%s.%03llu]\n"
, r->conn_id, r->event, r->event_flag == FW_EVENT ? FwEventString(r->event) : EventString(r->event)
, r->fw_xevent, EventXString(r->fw_xevent), r->sec_group_tag
, (long long unsigned)r->event_time, datestr3, (long long unsigned)(r->event_time % 1000L));
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
				} break;
			case EX_NEL_COMMON: {
				snprintf(_s, slen-1,
"  nat event    =             %5u: %s\n"
"  ingress VRF  =        %10u\n"
"  egress VRF   =        %10u\n"
, r->event, r->event_flag == FW_EVENT ? FwEventString(r->event) : EventString(r->event)
, r->ingress_vrfid, r->egress_vrfid);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
				} break;
			case EX_NSEL_XLATE_PORTS: {
				snprintf(_s, slen-1,
"  src xlt port =             %5u\n"
"  dst xlt port =             %5u\n"
, r->xlate_src_port, r->xlate_dst_port );
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
				} break;
			case EX_PORT_BLOCK_ALLOC: {
				snprintf(_s, slen-1,
"  pblock start =             %5u\n"
"  pblock end   =             %5u\n"
"  pblock step  =             %5u\n"
"  pblock size  =             %5u\n"
, r->block_start, r->block_end, r->block_step, r->block_size );
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
				} break;
			case EX_NSEL_XLATE_IP_v4:
				as[0] = 0;
				ds[0] = 0;
				r->xlate_src_ip.V4 = htonl(r->xlate_src_ip.V4);
				r->xlate_dst_ip.V4 = htonl(r->xlate_dst_ip.V4);
				inet_ntop(AF_INET, &r->xlate_src_ip.V4, as, sizeof(as));
				inet_ntop(AF_INET, &r->xlate_dst_ip.V4, ds, sizeof(ds));
				as[IP_STRING_LEN-1] = 0;
				ds[IP_STRING_LEN-1] = 0;

				snprintf(_s, slen-1,
"  src xlt ip   =  %16s\n"
"  dst xlt ip   =  %16s\n"
, as, ds);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
			break;
			case EX_NSEL_XLATE_IP_v6:
				as[0] = 0;
				ds[0] = 0;
				r->xlate_src_ip.V6[0] = htonll(r->xlate_src_ip.V6[0]);
				r->xlate_src_ip.V6[1] = htonll(r->xlate_src_ip.V6[1]);
				r->xlate_dst_ip.V6[0] = htonll(r->xlate_dst_ip.V6[0]);
				r->xlate_dst_ip.V6[1] = htonll(r->xlate_dst_ip.V6[1]);
				inet_ntop(AF_INET6, &r->xlate_src_ip.V6, as, sizeof(as));
				inet_ntop(AF_INET6, &r->xlate_dst_ip.V6, ds, sizeof(ds));
				as[IP_STRING_LEN-1] = 0;
				ds[IP_STRING_LEN-1] = 0;

				snprintf(_s, slen-1,
"  src xlate ip =  %16s\n"
"  dst xlate ip =  %16s\n"
, as, ds);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
			break;
			case EX_NSEL_ACL:
				snprintf(_s, slen-1,
"  Ingress ACL  =       0x%x/0x%x/0x%x\n"
"  Egress ACL   =       0x%x/0x%x/0x%x\n"
, r->ingress_acl_id[0], r->ingress_acl_id[1], r->ingress_acl_id[2], 
  r->egress_acl_id[0], r->egress_acl_id[1], r->egress_acl_id[2]);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
				break;
			case EX_NSEL_USER:
			case EX_NSEL_USER_MAX:
				snprintf(_s, slen-1,
"  User name    = %s\n"
, r->username[0] ? r->username : "          <empty>");
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
				break;
#endif
			default:
				snprintf(_s, slen-1, "Type %u not implemented\n", id);

		}
		i++;
	}

	data_string[STRINGSIZE-1] = 0;
	*s = data_string;

} // End of flow_record_to_raw
