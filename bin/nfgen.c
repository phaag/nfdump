/*
 *  Copyright (c) 2009-2020, Peter Haag
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

#include "nfdump.h"
#include "nffile.h"
#include "nfxV3.h"
#include "nfnet.h"
#include "util.h"
#include "bookkeeper.h"
#include "collector.h"
#include "exporter.h"
#include "netflow_v5_v7.h"

static time_t	when;
time_t offset  = 10;
uint64_t msecs   = 10;

#define NEED_PACKRECORD 1
#include "nfx.h"
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
		inet_pton(PF_INET6, src_ip, &(record->V6.srcaddr[0]));
		inet_pton(PF_INET6, dst_ip, &(record->V6.dstaddr[0]));
		record->V6.srcaddr[0] = ntohll(record->V6.srcaddr[0]);
		record->V6.srcaddr[1] = ntohll(record->V6.srcaddr[1]);
		record->V6.dstaddr[0] = ntohll(record->V6.dstaddr[0]);
		record->V6.dstaddr[1] = ntohll(record->V6.dstaddr[1]);
	} else {
		ClearFlag(record->flags, FLAG_IPV6_ADDR);
		inet_pton(PF_INET, src_ip, &record->V4.srcaddr);
		inet_pton(PF_INET, dst_ip, &record->V4.dstaddr);
		record->V4.srcaddr = ntohl(record->V4.srcaddr);
		record->V4.dstaddr = ntohl(record->V4.dstaddr);
	}

} // End of SetIPaddress

static void SetNextIPaddress(master_record_t *record, int af,  char *next_ip) {

	if ( af == PF_INET6 ) {
		SetFlag(record->flags, FLAG_IPV6_NH);
		inet_pton(PF_INET6, next_ip, &(record->ip_nexthop.V6[0]));
		record->ip_nexthop.V6[0] = ntohll(record->ip_nexthop.V6[0]);
		record->ip_nexthop.V6[1] = ntohll(record->ip_nexthop.V6[1]);
	} else {
		ClearFlag(record->flags, FLAG_IPV6_NH);
		inet_pton(PF_INET, next_ip, &record->ip_nexthop.V4);
		record->ip_nexthop.V4 = ntohl(record->ip_nexthop.V4);
	}

} // End of SetNextIPaddress

static void SetRouterIPaddress(master_record_t *record, int af,  char *next_ip) {

	if ( af == PF_INET6 ) {
		SetFlag(record->flags, FLAG_IPV6_NH);
		inet_pton(PF_INET6, next_ip, &(record->ip_router.V6[0]));
		record->ip_router.V6[0] = ntohll(record->ip_router.V6[0]);
		record->ip_router.V6[1] = ntohll(record->ip_router.V6[1]);
	} else {
		ClearFlag(record->flags, FLAG_IPV6_NH);
		inet_pton(PF_INET, next_ip, &record->ip_router.V4);
		record->ip_router.V4 = ntohl(record->ip_router.V4);
	}

} // End of SetRouterIPaddress

static void SetBGPNextIPaddress(master_record_t *record, int af,  char *next_ip) {

	if ( af == PF_INET6 ) {
		SetFlag(record->flags, FLAG_IPV6_NHB);
		inet_pton(PF_INET6, next_ip, &(record->bgp_nexthop.V6[0]));
		record->bgp_nexthop.V6[0] = ntohll(record->bgp_nexthop.V6[0]);
		record->bgp_nexthop.V6[1] = ntohll(record->bgp_nexthop.V6[1]);
	} else {
		ClearFlag(record->flags, FLAG_IPV6_NHB);
		inet_pton(PF_INET, next_ip, &record->bgp_nexthop.V4);
		record->bgp_nexthop.V4 = ntohl(record->bgp_nexthop.V4);
	}

} // End of SetBGPNextIPaddress

static void UpdateRecord(master_record_t *record) {

	record->msecFirst	= 1000LL * when + msecs;
	record->msecLast	= 1000LL * when + offset + msecs + 10LL;
	record->received	= record->msecLast - 1000LL +1LL;

	record->srcPort		+= 10;
	record->dstPort		+= 11;

	record->dPkts		+= 1;
	record->dOctets		+= 1024;

	when   += 10LL;
	offset += 10LL;

	msecs += 100LL;
	if ( msecs > 1000 )
		msecs = msecs - 1000;

	record->engine_id++;
	record->engine_type = offset;

} // End of UpdateRecord

int main( int argc, char **argv ) {
int i, c;
master_record_t		record;
nffile_t			*nffile;

	when = ISO2UNIX(strdup("201907111030"));
	while ((c = getopt(argc, argv, "h")) != EOF) {
		switch(c) {
			case 'h':
				break;
			default:
				fprintf(stderr, "ERROR: Unsupported option: '%c'\n", c);
				exit(255);
		}
	}

	memset((void *)&record, 0, sizeof(record));

	nffile = OpenNewFile("testflows", NULL, NOT_COMPRESSED, 0);
	if ( !nffile ) {
		exit(255);
	}

	i = 0;

	// Start with empty record
	record.size = V3HeaderRecordSize;
	record.numElements = i;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	record.exElementList[i++] = EXgenericFlowID; record.size += EXgenericFlowSize;
	record.numElements = i;
	record.fwd_status  	= 1;
	record.tcp_flags	= 2;
	record.tos			= 3;
	record.dst_tos		= 4;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	record.exElementList[i++] = EXipv4FlowID; record.size += EXipv4FlowSize;
	SetIPaddress(&record,  PF_INET, "172.16.1.66", "192.168.170.100");
	record.numElements = i;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	record.exElementList[i-1] = EXipv6FlowID;
	record.size -= EXipv4FlowSize;
	record.size += EXipv6FlowSize;
	SetIPaddress(&record,  PF_INET6, "fe80::2110:abcd:1234:0", "fe80::2110:abcd:1235:4321");
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	record.exElementList[i-1] = EXipv4FlowID;
	record.size += EXipv4FlowSize;
	record.size -= EXipv6FlowSize;
	SetIPaddress(&record,  PF_INET, "172.16.2.66", "192.168.170.101");
	record.exElementList[i++] = EXflowMiscID; record.size += EXflowMiscSize;
	record.numElements = i;
	record.input 	 	= 32;
	record.output 	 	= 33;
	record.src_mask		= 16;
	record.dst_mask		= 24;
	record.tcp_flags   	= 1;
	record.proto 	 	= IPPROTO_TCP;
	record.dir			= 1;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	record.exElementList[i++] = EXcntFlowID; record.size += EXcntFlowSize;
	record.numElements = i;
	record.tcp_flags++;
	record.out_pkts		= 203;
	record.out_bytes	= 204;
	record.aggr_flows	= 7;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	record.exElementList[i++] = EXvLanID; record.size += EXvLanSize;
	record.numElements = i;
	record.tcp_flags++;
	record.src_vlan		= 45;
	record.dst_vlan		= 46;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	record.exElementList[i++] = EXasRoutingID; record.size += EXasRoutingSize;
	record.numElements = i;
	record.tcp_flags++;
	record.srcas 	 	= 775;
	record.dstas 	 	= 3303;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	record.exElementList[i++] = EXipNextHopV4ID; record.size += EXipNextHopV4Size;
	record.numElements = i;
	record.tcp_flags++;
	SetNextIPaddress(&record,  PF_INET, "172.72.1.2");
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	record.exElementList[i++] = EXbgpNextHopV4ID; record.size += EXbgpNextHopV4Size; // 7
	record.numElements = i;
	record.tcp_flags++;
	SetBGPNextIPaddress(&record,  PF_INET, "172.73.2.3");
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	record.exElementList[i++] = EXipReceivedV4ID; record.size += EXipReceivedV4Size; // 9
	record.numElements = i;
	record.tcp_flags++;
	SetRouterIPaddress(&record,  PF_INET, "127.0.0.1");
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	record.exElementList[i++] = EXmplsLabelID; record.size += EXmplsLabelSize;
	record.numElements = i;
	record.tcp_flags++;
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
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	record.exElementList[i++] = EXmacAddrID; record.size += EXmacAddrSize;
	record.numElements = i;
	record.tcp_flags++;
	record.in_src_mac	= 0x1234567890aaLL;
	record.out_dst_mac	= 0x2feeddccbbabLL;
	record.in_dst_mac	= 0x3aeeddccbbfcLL;
	record.out_src_mac	= 0x4a345678900dLL;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	record.exElementList[i++] = EXasAdjacentID; record.size += EXasAdjacentSize;
	record.numElements = i;
	record.tcp_flags++;
	record.bgpNextAdjacentAS = 7751;
	record.bgpPrevAdjacentAS = 33032;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	record.exElementList[i++] = EXlatencyID; record.size += EXlatencySize;
	record.numElements = i;
	record.tcp_flags++;
	record.client_nw_delay_usec = 2;
	record.server_nw_delay_usec = 22;
	record.appl_latency_usec = 222;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

/*
	record.exElementList[i] = 0;
	record.numElements = i;
					
	record.map_ref = 0;
	record.type	= CommonRecordType;

	record.flags   		= 0;
	record.exporter_sysid = 1;

	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.2.66", "192.168.170.101");
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	record.dPkts 	 	= 101;
	record.dOctets 	 	= 102;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.3.66", "192.168.170.102");
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.4.66", "192.168.170.103");
	record.srcPort 	 = 2024;
	record.proto 	 = IPPROTO_UDP;
	record.tcp_flags = 1;
	record.tos 		 = 1;
	record.dPkts 	 = 1001;
	record.dOctets 	 = 1002;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.5.66", "192.168.170.104");
	record.srcPort 	 	= 3024;
	record.proto 	 	= 51;
	record.tcp_flags 	= 2;
	record.tos 		 	= 2;
	record.dPkts 	 	= 10001;
	record.dOctets 	 	= 10002;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.6.66", "192.168.170.105");
	record.srcPort 	 	= 4024;
	record.proto 	 	= IPPROTO_TCP;
	record.tcp_flags 	= 4;
	record.tos 		 	= 3;
	record.dPkts 	 	= 100001;
	record.dOctets 	 	= 100002;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.7.66", "192.168.170.106");
	record.srcPort 	 	= 5024;
	record.tcp_flags 	= 8;
	record.tos 		 	= 4;
	record.dPkts 	 	= 1000001;
	record.dOctets 	 	= 1000002;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.8.66", "192.168.170.107");
	record.tcp_flags 	= 1;
	record.tos 		 	= 4;
	record.dPkts 	 	= 10000001;
	record.dOctets 	 	= 1001;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.9.66", "192.168.170.108");
	record.srcPort 	 	= 6024;
	record.tcp_flags 	= 16;
	record.tos 		 	= 5;
	record.dPkts 	 	= 500;
	record.dOctets 	 	= 10000001;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.10.66", "192.168.170.109");
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.11.66", "192.168.170.110");
	record.srcPort 		= 7024;
	record.tcp_flags 	= 32;
	record.tos 		 	= 255;
	record.dPkts 	 	= 5000;
	record.dOctets 	 	= 100000001;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.12.66", "192.168.170.111");
	record.srcPort 	 	= 8024;
	record.tcp_flags 	= 63;
	record.tos 		 	= 0;
	record.dOctets 	 	= 1000000001;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.13.66", "192.168.170.112");
	record.srcPort 	 	= 0;
	record.dstPort 	 	= 8;
	record.proto 	 	= 1;
	record.tcp_flags 	= 0;
	record.tos 		 	= 0;
	record.dPkts 	 	= 50002;
	record.dOctets 	 	= 50000;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.160.160.166", "172.160.160.180");
	record.srcPort 	 = 10024;
	record.dstPort 	 = 25000;
	record.proto 	 = IPPROTO_TCP;
	record.dPkts 	 = 500001;
	record.dOctets 	 = 500000;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	SetIPaddress(&record,  PF_INET6, "fe80::2110:abcd:1234:0", "fe80::2110:abcd:1235:4321");
	SetNextIPaddress(&record,  PF_INET6, "2003:234:aabb::211:24ff:fe80:d01e");
	SetBGPNextIPaddress(&record,  PF_INET6, "2004:234:aabb::211:24ff:fe80:d01e");
	record.srcPort 	 = 1024;
	record.dstPort 	 = 25;
	record.tcp_flags = 27;
	record.dPkts 	 = 10;
	record.dOctets 	 = 15100;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	SetIPaddress(&record,  PF_INET6, "2001:234:aabb::211:24ff:fe80:d01e", "2001:620::8:203:baff:fe52:38e5");
	record.srcPort 	 = 10240;
	record.dstPort 	 = 52345;
	record.dPkts 	 = 10100;
	record.dOctets 	 = 15000000;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	record.dPkts 	 = 10100000;
	record.dOctets 	 = 0x100000000LL;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	record.dPkts 	 = 0x100000000LL;
	record.dOctets 	 = 15000000;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	record.dOctets 	 = 0x200000000LL;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.14.18", "192.168.170.113");
	SetNextIPaddress(&record,  PF_INET, "172.72.1.2");
	SetBGPNextIPaddress(&record,  PF_INET, "172.73.2.3");
	record.srcPort 	 = 10240;
	record.dstPort 	 = 52345;
	record.dPkts 	 = 10100000;
	record.dOctets 	 = 0x100000000LL;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.15.18", "192.168.170.114");
	record.dPkts 	 = 0x100000000LL;
	record.dOctets 	 = 15000000;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);

	SetIPaddress(&record,  PF_INET, "172.16.16.18", "192.168.170.115");
	record.dOctets 	 = 0x200000000LL;
	UpdateRecord(&record);
	PackRecordV3(&record, nffile);
*/
	if ( nffile->block_header->NumRecords ) {
		if ( WriteBlock(nffile) <= 0 ) {
			fprintf(stderr, "Failed to write output buffer to disk: '%s'" , strerror(errno));
		} 
	}
	CloseUpdateFile(nffile);
	return 0;
}

