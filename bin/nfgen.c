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
 *	 this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice, 
 *	 this list of conditions and the following disclaimer in the documentation 
 *	 and/or other materials provided with the distribution.
 *   * Neither the name of the author nor the names of its contributors may be 
 *	 used to endorse or promote products derived from this software without 
 *	 specific prior written permission.
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
 *  $Id: nfgen.c 39 2009-11-25 08:11:15Z haag $
 *
 *  $LastChangedRevision: 39 $
 *	
 */

#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nffile.h"
#include "nfx.h"
#include "nfnet.h"
#include "nf_common.h"
#include "util.h"
#include "bookkeeper.h"
#include "nfxstat.h"
#include "collector.h"
#include "exporter.h"
#include "netflow_v5_v7.h"

extern extension_descriptor_t extension_descriptor[];

static time_t	when;
uint32_t offset  = 10;
uint32_t msecs   = 10;

static extension_info_t extension_info;

#define NEED_PACKRECORD 1
#include "nffile_inline.c"
#undef NEED_PACKRECORD

void *GenRecord(int af, void *buff_ptr, char *src_ip, char *dst_ip, int src_port, int dst_port, 
	int proto, int tcp_flags, int tos, uint64_t packets, uint64_t bytes, int src_as, int dst_as);

static void SetIPaddress(master_record_t *record, int af,  char *src_ip, char *dst_ip);

static void SetNextIPaddress(master_record_t *record, int af,  char *next_ip);

static void SetRouterIPaddress(master_record_t *record, int af,  char *next_ip);

static void SetBGPNextIPaddress(master_record_t *record, int af,  char *next_ip);

static void UpdateRecord(master_record_t *record);

static void SetIPaddress(master_record_t *record, int af,  char *src_ip, char *dst_ip) {

	if ( af == PF_INET6 ) {
		SetFlag(record->flags, FLAG_IPV6_ADDR);
		inet_pton(PF_INET6, src_ip, &(record->v6.srcaddr[0]));
		inet_pton(PF_INET6, dst_ip, &(record->v6.dstaddr[0]));
		record->v6.srcaddr[0] = ntohll(record->v6.srcaddr[0]);
		record->v6.srcaddr[1] = ntohll(record->v6.srcaddr[1]);
		record->v6.dstaddr[0] = ntohll(record->v6.dstaddr[0]);
		record->v6.dstaddr[1] = ntohll(record->v6.dstaddr[1]);
	} else {
		ClearFlag(record->flags, FLAG_IPV6_ADDR);
		inet_pton(PF_INET, src_ip, &record->v4.srcaddr);
		inet_pton(PF_INET, dst_ip, &record->v4.dstaddr);
		record->v4.srcaddr = ntohl(record->v4.srcaddr);
		record->v4.dstaddr = ntohl(record->v4.dstaddr);
	}

} // End of SetIPaddress

static void SetNextIPaddress(master_record_t *record, int af,  char *next_ip) {

	if ( af == PF_INET6 ) {
		SetFlag(record->flags, FLAG_IPV6_NH);
		inet_pton(PF_INET6, next_ip, &(record->ip_nexthop.v6[0]));
		record->ip_nexthop.v6[0] = ntohll(record->ip_nexthop.v6[0]);
		record->ip_nexthop.v6[1] = ntohll(record->ip_nexthop.v6[1]);
	} else {
		ClearFlag(record->flags, FLAG_IPV6_NH);
		inet_pton(PF_INET, next_ip, &record->ip_nexthop.v4);
		record->ip_nexthop.v4 = ntohl(record->ip_nexthop.v4);
	}

} // End of SetNextIPaddress

static void SetRouterIPaddress(master_record_t *record, int af,  char *next_ip) {

	if ( af == PF_INET6 ) {
		SetFlag(record->flags, FLAG_IPV6_NH);
		inet_pton(PF_INET6, next_ip, &(record->ip_router.v6[0]));
		record->ip_router.v6[0] = ntohll(record->ip_router.v6[0]);
		record->ip_router.v6[1] = ntohll(record->ip_router.v6[1]);
	} else {
		ClearFlag(record->flags, FLAG_IPV6_NH);
		inet_pton(PF_INET, next_ip, &record->ip_router.v4);
		record->ip_router.v4 = ntohl(record->ip_router.v4);
	}

} // End of SetRouterIPaddress

static void SetBGPNextIPaddress(master_record_t *record, int af,  char *next_ip) {

	if ( af == PF_INET6 ) {
		SetFlag(record->flags, FLAG_IPV6_NHB);
		inet_pton(PF_INET6, next_ip, &(record->bgp_nexthop.v6[0]));
		record->bgp_nexthop.v6[0] = ntohll(record->bgp_nexthop.v6[0]);
		record->bgp_nexthop.v6[1] = ntohll(record->bgp_nexthop.v6[1]);
	} else {
		ClearFlag(record->flags, FLAG_IPV6_NHB);
		inet_pton(PF_INET, next_ip, &record->bgp_nexthop.v4);
		record->bgp_nexthop.v4 = ntohl(record->bgp_nexthop.v4);
	}

} // End of SetBGPNextIPaddress


static void UpdateRecord(master_record_t *record) {

	record->first		= when;
	record->last		 = when + offset;
	record->msec_first   = msecs;
	record->msec_last	= msecs + 10;

	when   += 10;
	offset += 10;

	msecs += 100;
	if ( msecs > 1000 )
		msecs = msecs - 1000;

	record->fwd_status++;

} // End of UpdateRecord

int main( int argc, char **argv ) {
int i, c;
master_record_t		record;
nffile_t			*nffile;

	when = ISO2UNIX(strdup("200407111030"));
	while ((c = getopt(argc, argv, "h")) != EOF) {
		switch(c) {
			case 'h':
				break;
			default:
				fprintf(stderr, "ERROR: Unsupported option: '%c'\n", c);
				exit(255);
		}
	}

	extension_info.map = (extension_map_t *)malloc(sizeof(extension_map_t) + 32 * sizeof(uint16_t));
	if ( !extension_info.map ) {
		fprintf(stderr, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
		exit(255);
	}
	extension_info.map->type = ExtensionMapType;
	extension_info.map->map_id = 0;
	i = 0;
	extension_info.map->ex_id[i++] = EX_IO_SNMP_2;
	extension_info.map->ex_id[i++] = EX_AS_2;
	extension_info.map->ex_id[i++] = EX_MULIPLE;
	extension_info.map->ex_id[i++] = EX_NEXT_HOP_v4;
	extension_info.map->ex_id[i++] = EX_NEXT_HOP_BGP_v4;
	extension_info.map->ex_id[i++] = EX_VLAN;
	extension_info.map->ex_id[i++] = EX_OUT_PKG_4;
	extension_info.map->ex_id[i++] = EX_OUT_BYTES_4;
	extension_info.map->ex_id[i++] = EX_AGGR_FLOWS_4;
 	extension_info.map->ex_id[i++] = EX_MAC_1;
 	extension_info.map->ex_id[i++] = EX_MAC_2;
 	extension_info.map->ex_id[i++] = EX_MPLS;
 	extension_info.map->ex_id[i++] = EX_ROUTER_IP_v4;
 	extension_info.map->ex_id[i++] = EX_ROUTER_ID;
 	extension_info.map->ex_id[i++] = EX_BGPADJ;
	extension_info.map->ex_id[i] = 0;
	extension_info.map->size = sizeof(extension_map_t) + i * sizeof(uint16_t);

	// align 32bits
	if (( extension_info.map->size & 0x3 ) != 0 ) {
		extension_info.map->size += 4 - ( extension_info.map->size & 0x3 );
	}

	extension_info.map->extension_size = 0;
	i=0;
	while (extension_info.map->ex_id[i]) {
		int id = extension_info.map->ex_id[i];
		extension_info.map->extension_size += extension_descriptor[id].size;
		i++;
	}
	memset((void *)&record, 0, sizeof(record));

	nffile = OpenNewFile("-", NULL, 0, 0, NULL);
	if ( !nffile ) {
		exit(255);
	}

	AppendToBuffer(nffile, (void *)extension_info.map, extension_info.map->size);
	
	record.map_ref = extension_info.map;
	record.type	= CommonRecordType;

	record.flags   		= 0;
	record.exporter_sysid = 1;
	record.tcp_flags   	= 1;
	record.tos 		   	= 2;
	record.fwd_status	= 0;
	record.srcport 	 	= 1024;
	record.dstport 	 	= 25;
	record.prot 	 	= IPPROTO_TCP;
	record.input 	 	= 12;
	record.output 	 	= 14;
	record.srcas 	 	= 775;
	record.dstas 	 	= 8404;
	SetIPaddress(&record,  PF_INET, "172.16.1.66", "192.168.170.100");
	SetNextIPaddress(&record,  PF_INET, "172.72.1.2");
	SetBGPNextIPaddress(&record,  PF_INET, "172.73.2.3");
	SetRouterIPaddress(&record,  PF_INET, "127.0.0.1");
	record.engine_type	= 5;
	record.engine_id	= 6;
	record.dPkts 	 	= 202;
	record.dOctets 	 	= 303;
	record.dst_tos		= 128;
	record.dir			= 1;
	record.src_mask		= 16;
	record.dst_mask		= 24;
	record.src_vlan		= 82;
	record.dst_vlan		= 93;
	record.out_pkts		= 212;
	record.out_bytes	= 3234;
	record.aggr_flows	= 3;
	record.in_src_mac	= 0x0234567890aaLL;
	record.out_dst_mac	= 0xffeeddccbbaaLL;
	record.out_src_mac	= 0xaa3456789002LL;
	record.in_dst_mac	= 0xaaeeddccbbffLL;
	record.mpls_label[0] = 1010 << 4;
	record.mpls_label[1] = 2020 << 4;
	record.mpls_label[2] = 3030 << 4;
	record.mpls_label[3] = 4040 << 4;
	record.mpls_label[4] = 5050 << 4;
	record.mpls_label[5] = 6060 << 4;
	record.mpls_label[6] = 7070 << 4;
	record.mpls_label[7] = 8080 << 4;
	record.mpls_label[8] = 9090 << 4;
	record.mpls_label[9] = (100100 << 4) + 1;
	record.client_nw_delay_usec = 2;
	record.server_nw_delay_usec = 22;
	record.appl_latency_usec = 222;
	record.bgpNextAdjacentAS = 45804;
	record.bgpPrevAdjacentAS = 32775;

	fprintf(stderr, "IPv4 32bit packets 32bit bytes\n");
	UpdateRecord(&record);
	PackRecord(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.2.66", "192.168.170.101");
	fprintf(stderr, "IPv4 32bit packets 32bit bytes\n");
	UpdateRecord(&record);
	PackRecord(&record, nffile);

	record.dPkts 	 	= 101;
	record.dOctets 	 	= 102;
	fprintf(stderr, "IPv4 32bit packets 32bit bytes\n");
	UpdateRecord(&record);
	PackRecord(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.3.66", "192.168.170.102");
	fprintf(stderr, "IPv4 32bit packets 32bit bytes\n");
	UpdateRecord(&record);
	PackRecord(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.4.66", "192.168.170.103");
	record.srcport 	 = 2024;
	record.prot 	 = IPPROTO_UDP;
	record.tcp_flags = 1;
	record.tos 		 = 1;
	record.dPkts 	 = 1001;
	record.dOctets 	 = 1002;
	fprintf(stderr, "IPv4 32bit packets 32bit bytes\n");
	UpdateRecord(&record);
	PackRecord(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.5.66", "192.168.170.104");
	record.srcport 	 	= 3024;
	record.prot 	 	= 51;
	record.tcp_flags 	= 2;
	record.tos 		 	= 2;
	record.dPkts 	 	= 10001;
	record.dOctets 	 	= 10002;
	fprintf(stderr, "IPv4 32bit packets 32bit bytes\n");
	UpdateRecord(&record);
	PackRecord(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.6.66", "192.168.170.105");
	record.srcport 	 	= 4024;
	record.prot 	 	= IPPROTO_TCP;
	record.tcp_flags 	= 4;
	record.tos 		 	= 3;
	record.dPkts 	 	= 100001;
	record.dOctets 	 	= 100002;
	fprintf(stderr, "IPv4 32bit packets 32bit bytes\n");
	UpdateRecord(&record);
	PackRecord(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.7.66", "192.168.170.106");
	record.srcport 	 	= 5024;
	record.tcp_flags 	= 8;
	record.tos 		 	= 4;
	record.dPkts 	 	= 1000001;
	record.dOctets 	 	= 1000002;
	fprintf(stderr, "IPv4 32bit packets 32bit bytes\n");
	UpdateRecord(&record);
	PackRecord(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.8.66", "192.168.170.107");
	record.tcp_flags 	= 1;
	record.tos 		 	= 4;
	record.dPkts 	 	= 10000001;
	record.dOctets 	 	= 1001;
	fprintf(stderr, "IPv4 32bit packets 32bit bytes\n");
	UpdateRecord(&record);
	PackRecord(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.9.66", "192.168.170.108");
	record.srcport 	 	= 6024;
	record.tcp_flags 	= 16;
	record.tos 		 	= 5;
	record.dPkts 	 	= 500;
	record.dOctets 	 	= 10000001;
	fprintf(stderr, "IPv4 32bit packets 32bit bytes\n");
	UpdateRecord(&record);
	PackRecord(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.10.66", "192.168.170.109");
	fprintf(stderr, "IPv4 32bit packets 32bit bytes\n");
	UpdateRecord(&record);
	PackRecord(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.11.66", "192.168.170.110");
	record.srcport 		= 7024;
	record.tcp_flags 	= 32;
	record.tos 		 	= 255;
	record.dPkts 	 	= 5000;
	record.dOctets 	 	= 100000001;
	fprintf(stderr, "IPv4 32bit packets 32bit bytes\n");
	UpdateRecord(&record);
	PackRecord(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.12.66", "192.168.170.111");
	record.srcport 	 	= 8024;
	record.tcp_flags 	= 63;
	record.tos 		 	= 0;
	record.dOctets 	 	= 1000000001;
	fprintf(stderr, "IPv4 32bit packets 32bit bytes\n");
	UpdateRecord(&record);
	PackRecord(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.13.66", "192.168.170.112");
	record.srcport 	 	= 0;
	record.dstport 	 	= 8;
	record.prot 	 	= 1;
	record.tcp_flags 	= 0;
	record.tos 		 	= 0;
	record.dPkts 	 	= 50002;
	record.dOctets 	 	= 50000;
	fprintf(stderr, "IPv4 32bit packets 32bit bytes\n");
	UpdateRecord(&record);
	PackRecord(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.160.160.166", "172.160.160.180");
	record.srcport 	 = 10024;
	record.dstport 	 = 25000;
	record.prot 	 = IPPROTO_TCP;
	record.dPkts 	 = 500001;
	record.dOctets 	 = 500000;
	fprintf(stderr, "IPv4 32bit packets 32bit bytes\n");
	UpdateRecord(&record);
	PackRecord(&record, nffile);

	SetIPaddress(&record,  PF_INET6, "fe80::2110:abcd:1234:0", "fe80::2110:abcd:1235:4321");
//	SetNextIPaddress(&record,  PF_INET6, "2003:234:aabb::211:24ff:fe80:d01e");
//	SetBGPNextIPaddress(&record,  PF_INET6, "2004:234:aabb::211:24ff:fe80:d01e");
	record.srcport 	 = 1024;
	record.dstport 	 = 25;
	record.tcp_flags = 27;
	record.dPkts 	 = 10;
	record.dOctets 	 = 15100;
	fprintf(stderr, "IPv6 32bit packets 32bit bytes\n");
	UpdateRecord(&record);
	PackRecord(&record, nffile);

	SetIPaddress(&record,  PF_INET6, "2001:234:aabb::211:24ff:fe80:d01e", "2001:620::8:203:baff:fe52:38e5");
	record.srcport 	 = 10240;
	record.dstport 	 = 52345;
	record.dPkts 	 = 10100;
	record.dOctets 	 = 15000000;
	fprintf(stderr, "IPv6 32bit packets 32bit bytes\n");
	UpdateRecord(&record);
	PackRecord(&record, nffile);

	record.dPkts 	 = 10100000;
	record.dOctets 	 = 0x100000000LL;
	fprintf(stderr, "IPv6 32bit packets 64bit bytes\n");
	UpdateRecord(&record);
	PackRecord(&record, nffile);

	record.dPkts 	 = 0x100000000LL;
	record.dOctets 	 = 15000000;
	fprintf(stderr, "IPv6 64bit packets 32bit bytes\n");
	UpdateRecord(&record);
	PackRecord(&record, nffile);

	record.dOctets 	 = 0x200000000LL;
	fprintf(stderr, "IPv6 64bit packets 64bit bytes\n");
	UpdateRecord(&record);
	PackRecord(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.14.18", "192.168.170.113");
//	SetNextIPaddress(&record,  PF_INET, "172.72.1.2");
//	SetBGPNextIPaddress(&record,  PF_INET, "172.73.2.3");
	record.srcport 	 = 10240;
	record.dstport 	 = 52345;
	record.dPkts 	 = 10100000;
	record.dOctets 	 = 0x100000000LL;
	fprintf(stderr, "IPv4 32bit packets 64bit bytes\n");
	UpdateRecord(&record);
	PackRecord(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.15.18", "192.168.170.114");
	record.dPkts 	 = 0x100000000LL;
	record.dOctets 	 = 15000000;
	fprintf(stderr, "IPv4 64bit packets 32bit bytes\n");
	UpdateRecord(&record);
	PackRecord(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.16.18", "192.168.170.115");
	record.dOctets 	 = 0x200000000LL;
	fprintf(stderr, "IPv4 64bit packets 64bit bytes\n");
	UpdateRecord(&record);
	PackRecord(&record, nffile);

	extension_info.map->ex_id[0] = EX_IO_SNMP_4;

	extension_info.map->extension_size = 0;
	i=0;
	while (extension_info.map->ex_id[i]) {
		int id = extension_info.map->ex_id[i];
		extension_info.map->extension_size += extension_descriptor[id].size;
		i++;
	}

	memcpy(nffile->buff_ptr, (void *)extension_info.map, extension_info.map->size);
	nffile->buff_ptr += extension_info.map->size;
	nffile->block_header->NumRecords++;
	nffile->block_header->size 		+= extension_info.map->size;

	UpdateRecord(&record);
	fprintf(stderr, "4 bytes interfaces, 2 bytes AS numbers %d %d\n", record.fwd_status, nffile->block_header->NumRecords);
	PackRecord(&record, nffile);

	extension_info.map->ex_id[0] = EX_IO_SNMP_2;
	extension_info.map->ex_id[1] = EX_AS_4;

	extension_info.map->extension_size = 0;
	i=0;
	while (extension_info.map->ex_id[i]) {
		int id = extension_info.map->ex_id[i];
		extension_info.map->extension_size += extension_descriptor[id].size;
		i++;
	}

	memcpy(nffile->buff_ptr, (void *)extension_info.map, extension_info.map->size);
	nffile->buff_ptr += extension_info.map->size;
	nffile->block_header->NumRecords++;
	nffile->block_header->size 		+= extension_info.map->size;

	UpdateRecord(&record);
	fprintf(stderr, "2 bytes interfaces, 4 bytes AS numbers %d %d\n", record.fwd_status, nffile->block_header->NumRecords);
	PackRecord(&record, nffile);

	extension_info.map->ex_id[0] = EX_IO_SNMP_4;

	extension_info.map->extension_size = 0;
	i=0;
	while (extension_info.map->ex_id[i]) {
		int id = extension_info.map->ex_id[i];
		extension_info.map->extension_size += extension_descriptor[id].size;
		i++;
	}

	memcpy(nffile->buff_ptr, (void *)extension_info.map, extension_info.map->size);
	nffile->buff_ptr += extension_info.map->size;
	nffile->block_header->NumRecords++;
	nffile->block_header->size 		+= extension_info.map->size;

	UpdateRecord(&record);
	fprintf(stderr, "4 bytes interfaces, 4 bytes AS numbers %d %d\n", record.fwd_status, nffile->block_header->NumRecords);
	PackRecord(&record, nffile);

	if ( nffile->block_header->NumRecords ) {
		if ( WriteBlock(nffile) <= 0 ) {
			fprintf(stderr, "Failed to write output buffer to disk: '%s'" , strerror(errno));
		} 
	}

	return 0;
}

