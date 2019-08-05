/*
 *  Copyright (c) 2017, Peter Haag
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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nffile.h"
#include "util.h"
#include "nf_common.h"
#include "output_json.h"

#define STRINGSIZE 10240
#define IP_STRING_LEN (INET6_ADDRSTRLEN)

#ifdef NSEL
static char *NSEL_event_string[6] = {
	"IGNORE", "CREATE", "DELETE", "DENIED", "ALERT", "UPDATE"
};

static char *NEL_event_string[3] = {
	"INVALID", "ADD", "DELETE"
};
#endif

static char data_string[STRINGSIZE];

static void String_Flags(master_record_t *r, char *string) {

	string[0] = r->tcp_flags & 128 ? 'C' : '.';	// Congestion window reduced -  CWR
	string[1] = r->tcp_flags &  64 ? 'E' : '.';	// ECN-Echo
	string[2] = r->tcp_flags &  32 ? 'U' : '.';	// Urgent
	string[3] = r->tcp_flags &  16 ? 'A' : '.';	// Ack
	string[4] = r->tcp_flags &   8 ? 'P' : '.';	// Push
	string[5] = r->tcp_flags &   4 ? 'R' : '.';	// Reset
	string[6] = r->tcp_flags &   2 ? 'S' : '.';	// Syn
	string[7] = r->tcp_flags &   1 ? 'F' : '.';	// Fin
	string[8] = '\0';

} // End of String_Flags

void flow_record_to_json(void *record, char ** s, int tag) {
char 		*_s, as[IP_STRING_LEN], ds[IP_STRING_LEN], *datestr1, *datestr2, datebuff[64], flags_str[16];
int			i, id;
ssize_t		slen, _slen;
time_t		when;
struct tm 	*ts;
master_record_t *r = (master_record_t *)record;
extension_map_t	*extension_map = r->map_ref;

	when = r->first;
	ts = localtime(&when);
	strftime(datebuff, 63, "%Y-%m-%dT%H:%M:%S", ts);
	asprintf(&datestr1, "%s.%u", datebuff, r->msec_first);

	when = r->last;
	ts = localtime(&when);
	strftime(datebuff, 63, "%Y-%m-%dT%H:%M:%S", ts);
	asprintf(&datestr2, "%s.%u", datebuff, r->msec_last);

	String_Flags(record, flags_str);

	_s = data_string;
	slen = STRINGSIZE;
	snprintf(_s, slen-1, "{\n"
"	\"type\" : \"%s\",\n"
"	\"sampled\" : %u,\n"
"	\"export_sysid\" : %u,\n"
"	\"t_first\" : \"%s\",\n"
"	\"t_last\" : \"%s\",\n"
"	\"proto\" : %u,\n"
, TestFlag(r->flags, FLAG_EVENT) ? "EVENT" : "FLOW", 
	TestFlag(r->flags, FLAG_SAMPLED) ? 1 : 0, 
	r->exporter_sysid, datestr1, datestr2, r->prot);

	free(datestr1);
	free(datestr2);
	_slen = strlen(data_string);
	_s = data_string + _slen;
	slen = STRINGSIZE - _slen;

	as[0] = 0;
	ds[0] = 0;
	if ( TestFlag(r->flags,FLAG_IPV6_ADDR ) != 0 ) { // IPv6
		uint64_t _src[2];
		uint64_t _dst[2];

		_src[0] = htonll(r->V6.srcaddr[0]);
		_src[1] = htonll(r->V6.srcaddr[1]);
		_dst[0] = htonll(r->V6.dstaddr[0]);
		_dst[1] = htonll(r->V6.dstaddr[1]);
		inet_ntop(AF_INET6, _src, as, sizeof(as));
		inet_ntop(AF_INET6, _dst, ds, sizeof(ds));
		as[IP_STRING_LEN-1] = 0;
		ds[IP_STRING_LEN-1] = 0;

		snprintf(_s, slen-1, 
"	\"src6_addr\" : \"%s\",\n"
"	\"dst6_addr\" : \"%s\",\n"
, as, ds );
	} else {	// IPv4
		uint32_t _src, _dst;
		_src = htonl(r->V4.srcaddr);
		_dst = htonl(r->V4.dstaddr);
		inet_ntop(AF_INET, &_src, as, sizeof(as));
		inet_ntop(AF_INET, &_dst, ds, sizeof(ds));
		as[IP_STRING_LEN-1] = 0;
		ds[IP_STRING_LEN-1] = 0;

		snprintf(_s, slen-1, 
"	\"src4_addr\" : \"%s\",\n"
"	\"dst4_addr\" : \"%s\",\n"
, as, ds );
	}
	_slen = strlen(data_string);
	_s = data_string + _slen;
	slen = STRINGSIZE - _slen;


	if ( r->prot == IPPROTO_ICMP || r->prot == IPPROTO_ICMPV6 ) { // ICMP
		snprintf(_s, slen-1,
"	\"icmp_type\" : %u,\n"
"	\"icmp_code\" : %u,\n"
, r->icmp_type, r->icmp_code);
	} else {
		snprintf(_s, slen-1,
"	\"src_port\" : %u,\n"
"	\"dst_port\" : %u,\n"
, r->srcport, r->dstport);
	}

	_slen = strlen(data_string);
	_s = data_string + _slen;
	slen = STRINGSIZE - _slen;

	snprintf(_s, slen-1,
"	\"fwd_status\" : %u,\n"
"	\"tcp_flags\" : \"%s\",\n"
"	\"src_tos\" : %u,\n"
"	\"in_packets\" : %llu,\n"
"	\"in_bytes\" : %llu,\n"
, r->fwd_status, flags_str, r->tos,
	(unsigned long long)r->dPkts, (unsigned long long)r->dOctets);

	_slen = strlen(data_string);
	_s = data_string + _slen;
	slen = STRINGSIZE - _slen;
	
	i = 0;
	while ( (id = extension_map->ex_id[i]) != 0 ) {
		if ( slen <= 20 ) {
		// XXX
			data_string[STRINGSIZE-1] = 0;
			*s = data_string;
		}
		switch(id) {
			case EX_IO_SNMP_2:
			case EX_IO_SNMP_4:
				snprintf(_s, slen-1,
"	\"input_snmp\" : %u,\n"
"	\"output_snmp\" : %u,\n"
, r->input, r->output);
				break;
			case EX_AS_2:
			case EX_AS_4:
				snprintf(_s, slen-1,
"	\"src_as\" : %u,\n"
"	\"dst_as\" : %u,\n"
, r->srcas, r->dstas);
				break;
			case EX_BGPADJ:
				snprintf(_s, slen-1,
"	\"next_as\" : %u,\n"
"	\"prev_as\" : %u,\n"
, r->bgpNextAdjacentAS, r->bgpPrevAdjacentAS);
				break;
			case EX_MULIPLE:
				snprintf(_s, slen-1,
"	\"src_mask\" : %u,\n"
"	\"dst_mask\" : %u,\n"
"	\"dst_tos\" : %u,\n"
"	\"direction\" : %u,\n"
, r->src_mask, r->dst_mask, r->dst_tos, r->dir );
				break;
			case EX_NEXT_HOP_v4: {
				uint32_t _ip;
				as[0] = 0;
				_ip = htonl(r->ip_nexthop.V4);
				inet_ntop(AF_INET, &_ip, as, sizeof(as));
				as[IP_STRING_LEN-1] = 0;

				snprintf(_s, slen-1,
"	\"ip4_next_hop\" : \"%s\",\n"
, as);
			} break;
			case EX_NEXT_HOP_v6: {
				uint64_t _ip[2];
				as[0] = 0;
				_ip[0] = htonll(r->ip_nexthop.V6[0]);
				_ip[1] = htonll(r->ip_nexthop.V6[1]);
				inet_ntop(AF_INET6, _ip, as, sizeof(as));
				as[IP_STRING_LEN-1] = 0;

				snprintf(_s, slen-1,
"	\"ip6_next_hop\" : \"%s\",\n"
, as);
			} break;
			case EX_NEXT_HOP_BGP_v4: {
				uint32_t _ip;
				as[0] = 0;
				_ip = htonl(r->bgp_nexthop.V4);
				inet_ntop(AF_INET, &_ip, as, sizeof(as));
				as[IP_STRING_LEN-1] = 0;

				snprintf(_s, slen-1,
"	\"bgp4_next_hop\" : \"%s\",\n"
, as);
			} break;
			case EX_NEXT_HOP_BGP_v6: {
				uint64_t _ip[2];
				as[0] = 0;
				_ip[0] = htonll(r->bgp_nexthop.V6[0]);
				_ip[1] = htonll(r->bgp_nexthop.V6[1]);
				inet_ntop(AF_INET6, _ip, as, sizeof(as));
				as[IP_STRING_LEN-1] = 0;

				snprintf(_s, slen-1,
"	\"bgp6_next_hop\" : \"%s\",\n"
, as);
			} break;
			case EX_VLAN:
				snprintf(_s, slen-1,
"	\"src_vlan\" : %u,\n"
"	\"dst_vlan\" : %u,\n"
, r->src_vlan, r->dst_vlan);
			break;
			case EX_OUT_PKG_4:
			case EX_OUT_PKG_8:
				snprintf(_s, slen-1,
"	\"out_packets\" : %llu,\n"
, (long long unsigned)r->out_pkts);
			break;
			case EX_OUT_BYTES_4:
			case EX_OUT_BYTES_8:
				snprintf(_s, slen-1,
"	\"out_bytes\" : %llu,\n"
, (long long unsigned)r->out_bytes);
			break;
			case EX_AGGR_FLOWS_4:
			case EX_AGGR_FLOWS_8:
				snprintf(_s, slen-1,
"	\"aggr_flows\" : %llu,\n"
, (long long unsigned)r->aggr_flows);
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
"	\"in_src_mac\" : \"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\",\n"
"	\"out_dst_mac\" : \"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\",\n"
, mac1[5], mac1[4], mac1[3], mac1[2], mac1[1], mac1[0],
  mac2[5], mac2[4], mac2[3], mac2[2], mac2[1], mac2[0] );
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
"	\"in_dst_mac\" : \"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\",\n"
"	\"out_src_mac\" : \"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\",\n"
, mac1[5], mac1[4], mac1[3], mac1[2], mac1[1], mac1[0], 
  mac2[5], mac2[4], mac2[3], mac2[2], mac2[1], mac2[0] );
			} break;
			case EX_MPLS: {
				unsigned int i;
				for ( i=0; i<10; i++ ) {
					snprintf(_s, slen-1,
"	\"mpls_%u\" : \"%u-%u-%u\",\n", i+1
, r->mpls_label[i] >> 4 , (r->mpls_label[i] & 0xF ) >> 1, r->mpls_label[i] & 1 );
					_slen = strlen(data_string);
					_s = data_string + _slen;
					slen = STRINGSIZE - _slen;
				}
			} break;
			case EX_ROUTER_IP_v4: {
				uint32_t _ip;
				as[0] = 0;
				_ip = htonl(r->ip_router.V4);
				inet_ntop(AF_INET, &_ip, as, sizeof(as));
				as[IP_STRING_LEN-1] = 0;
				snprintf(_s, slen-1,
"	\"ip4_router\" : \"%s\",\n"
, as);
			} break;
			case EX_ROUTER_IP_v6: {
				uint64_t _ip[2];
				as[0] = 0;
				_ip[0] = htonll(r->ip_router.V6[0]);
				_ip[1] = htonll(r->ip_router.V6[1]);
				inet_ntop(AF_INET6, _ip, as, sizeof(as));
				as[IP_STRING_LEN-1] = 0;
				snprintf(_s, slen-1,
"	\"ip6_router\" : \"%s\",\n"
, as);
			} break;
			case EX_LATENCY: {
				double f1, f2, f3;
				f1 = (double)r->client_nw_delay_usec / 1000.0;
				f2 = (double)r->server_nw_delay_usec / 1000.0;
				f3 = (double)r->appl_latency_usec / 1000.0;

				snprintf(_s, slen-1,
"	\"cli_latency\" : %f,\n"
"	\"srv_latency\" : %f,\n"
"	\"app_latency\" : %f,\n"
, f1, f2, f3);
			} break;
			case EX_ROUTER_ID:
				snprintf(_s, slen-1,
"	\"engine_type\" : %u,\n"
"	\"engine_id\" : %u,\n"
, r->engine_type, r->engine_id);
				break;
			case EX_RECEIVED: {
				char *datestr, datebuff[64];
				when = r->received / 1000LL;
				ts = localtime(&when);
				strftime(datebuff, 63, "%Y-%m-%dT%H:%M:%S", ts);
				asprintf(&datestr, "%s.%llu", datebuff, (long long unsigned)r->received % 1000L);

				snprintf(_s, slen-1,
"	\"t_received\" : \"%s\",\n"
, datestr);
				free(datestr);
				} break;
#ifdef NSEL
			case EX_NSEL_COMMON: {
				char *event = "UNKNOWN";
				char *datestr, datebuff[64];
				if ( r->event <= 5 ) {
					event = NSEL_event_string[r->event];
				} 
				when = r->event_time / 1000LL;
				ts = localtime(&when);
				strftime(datebuff, 63, "%Y-%m-%dT%H:%M:%S", ts);
				asprintf(&datestr, "%s.%llu", datebuff, r->event_time % 1000LL);
				snprintf(_s, slen-1,
"	\"connect_id\" : \"%u\",\n"
"	\"event_id\" : \"%u\",\n"
"	\"event\" : \"%s\",\n"
"	\"xevent_id\" : \"%u\",\n"
"	\"t_event\" : \"%s\",\n"
, r->conn_id, r->event, event, r->fw_xevent, datestr);
				free(datestr);
				} break;
			case EX_NEL_COMMON: {
				char *event = "UNKNOWN";
				if ( r->event <= 2 ) {
					event = NEL_event_string[r->event];
				}
				snprintf(_s, slen-1,
"	\"nat_event_id\" : \"%u\",\n"
"	\"nat_event\" : \"%s\",\n"
"	\"ingress_vrf\" : \"%u\",\n"
"	\"egress_vrf\" : \"%u\",\n"
, r->event, event, r->ingress_vrfid, r->egress_vrfid);
				} break;
			case EX_NSEL_XLATE_PORTS: {
				snprintf(_s, slen-1,
"	\"src_xlt_port\" : \"%u\",\n"
"	\"dst_xlt_port\" : \"%u\",\n"
, r->xlate_src_port, r->xlate_dst_port );
				} break;
			case EX_PORT_BLOCK_ALLOC: {
				snprintf(_s, slen-1,
"	\"pblock_start\" : \"%u\",\n"
"	\"pblock_end\" : \"%u\",\n"
"	\"pblock_step\" : \"%u\",\n"
"	\"pblock_size\" : \"%u\",\n"
, r->block_start, r->block_end, r->block_step, r->block_size );
				} break;
			case EX_NSEL_XLATE_IP_v4: {
				uint32_t _src, _dst;
				as[0] = 0;
				ds[0] = 0;
				_src = htonl(r->xlate_src_ip.V4);
				_dst = htonl(r->xlate_dst_ip.V4);
				inet_ntop(AF_INET, &_src, as, sizeof(as));
				inet_ntop(AF_INET, &_dst, ds, sizeof(ds));
				as[IP_STRING_LEN-1] = 0;
				ds[IP_STRING_LEN-1] = 0;

				snprintf(_s, slen-1,
"	\"src4_xlt_ip\" : \"%s\",\n"
"	\"dst4_xlt_ip\" : \"%s\",\n"
, as, ds);
			} break;
			case EX_NSEL_XLATE_IP_v6: {
				uint64_t _src[2], _dst[2];
				as[0] = 0;
				ds[0] = 0;
				_src[0] = htonll(r->xlate_src_ip.V6[0]);
				_src[1] = htonll(r->xlate_src_ip.V6[1]);
				_dst[0] = htonll(r->xlate_dst_ip.V6[0]);
				_dst[1] = htonll(r->xlate_dst_ip.V6[1]);
				inet_ntop(AF_INET6, _src, as, sizeof(as));
				inet_ntop(AF_INET6, _dst, ds, sizeof(ds));
				as[IP_STRING_LEN-1] = 0;
				ds[IP_STRING_LEN-1] = 0;

				snprintf(_s, slen-1,
"	\"src6_xlt_ip\" : \"%s\",\n"
"	\"dst6_xlt_ip\" : \"%s\",\n"
, as, ds);
			} break;
			case EX_NSEL_ACL:
				snprintf(_s, slen-1,
"	\"ingress_acl\" : \"0x%x/0x%x/0x%x\",\n"
"	\"egress_acl\" : \"0x%x/0x%x/0x%x\",\n"
, r->ingress_acl_id[0], r->ingress_acl_id[1], r->ingress_acl_id[2], 
  r->egress_acl_id[0], r->egress_acl_id[1], r->egress_acl_id[2]);
				break;
			case EX_NSEL_USER:
			case EX_NSEL_USER_MAX:
				snprintf(_s, slen-1,
"	\"user_name\" : \"%s\",\n"
, r->username[0] ? r->username : "<empty>");
				break;
#endif
		}
		_slen = strlen(data_string);
		_s = data_string + _slen;
		slen = STRINGSIZE - _slen;
		i++;
	}


	// add label and close json object
	snprintf(_s, slen-1, 
"	\"label\" : \"%s\"\n"
"}\n", r->label ? r->label : "<none>");

	data_string[STRINGSIZE-1] = 0;
	*s = data_string;


} // End of format_file_block_record
