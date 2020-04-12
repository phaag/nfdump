/*
 *  Copyright (c) 2009-2020, Peter Haag
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

static inline int CheckBufferSpace(nffile_t *nffile, size_t required);

static inline void AppendToBuffer(nffile_t *nffile, void *record, size_t required);

static inline void CopyV6IP(uint32_t *dst, uint32_t *src);

static inline void ExpandRecord_v2(common_record_t *input_record, extension_info_t *extension_info, exporter_info_record_t *exporter_info, master_record_t *output_record );

#ifdef NEED_PACKRECORD
static void PackRecord(master_record_t *master_record, nffile_t *nffile);
#endif

static inline int CheckBufferSpace(nffile_t *nffile, size_t required) {

	dbg_printf("Buffer Size %u\n", nffile->block_header->size);
	// flush current buffer to disc
	if ( (nffile->block_header->size + required )  > WRITE_BUFFSIZE ) {

		// this should never happen, but catch it anyway
		if ( required > WRITE_BUFFSIZE ) {
			LogError("Required buffer size %zu too big for output buffer!" , required);
			return 0;
		}

		if ( WriteBlock(nffile) <= 0 ) {
			LogError("Failed to write output buffer to disk: '%s'" , strerror(errno));
			return 0;
		} 
	}

	return 1;
} // End of CheckBufferSpace

// Use 4 uint32_t copy cycles, as SPARC CPUs brak
static inline void CopyV6IP(uint32_t *dst, uint32_t *src) {
	dst[0] = src[0];
	dst[1] = src[1];
	dst[2] = src[2];
	dst[3] = src[3];
} // End of CopyV6IP

/*
 * Expand file record into master record for further processing
 * LP64 CPUs need special 32bit operations as it is not guarateed, that 64bit
 * values are aligned 
 */
static inline void ExpandRecord_v2(common_record_t *input_record, extension_info_t *extension_info, exporter_info_record_t *exporter_info, master_record_t *output_record ) {
extension_map_t *extension_map = extension_info->map;
uint32_t	i, *u;
void		*p = (void *)input_record;
// printf("Byte: %u\n", _b);

#ifdef NSEL
		// nasty bug work around - compat issues 1.6.10 - 1.6.12 onwards
		union {
			uint16_t port[2];
			uint32_t vrf;
		} compat_nel_bug;
		compat_nel_bug.vrf = 0;
		int compat_nel = 0;
#endif

	// set map ref
	output_record->map_ref = extension_map;

	output_record->size		 = input_record->size;
	output_record->flags	 = input_record->flags;
	output_record->proto	 = input_record->prot;
	output_record->tcp_flags = input_record->tcp_flags;
 	output_record->srcPort	 = input_record->srcPort;
 	output_record->dstPort	 = input_record->dstPort;
	output_record->fwd_status = input_record->fwd_status;
	output_record->tos		 = input_record->tos;
	output_record->msecFirst = input_record->first * 1000L + input_record->msec_first;
	output_record->msecLast  = input_record->last  * 1000L + input_record->msec_last;
	output_record->exporter_sysid = input_record->exporter_sysid;

	p = (void *)input_record->data;

	if ( exporter_info ) {
		uint32_t sysid = exporter_info->sysid;
		output_record->exporter_sysid = sysid;
		input_record->exporter_sysid  = sysid;
		output_record->exp_ref 		  = exporter_info;
	} else {
		output_record->exp_ref 		  = NULL;
	}
	output_record->label = NULL;

	// map icmp type/code in it's own vars
	output_record->icmp = output_record->dstPort;

	// Required extension 1 - IP addresses
	if ( (input_record->flags & FLAG_IPV6_ADDR) != 0 )	{ // IPv6
		// IPv6
		// keep compiler happy
		// memcpy((void *)output_record->V6.srcaddr, p, 4 * sizeof(uint64_t));	
		memcpy((void *)output_record->ip_union._ip_64.addr, p, 4 * sizeof(uint64_t));	
		p = (void *)((pointer_addr_t)p + 4 * sizeof(uint64_t));
	} else { 	
		// IPv4
		u = (uint32_t *)p;
		output_record->V6.srcaddr[0] = 0;
		output_record->V6.srcaddr[1] = 0;
		output_record->V4.srcaddr 	 = u[0];

		output_record->V6.dstaddr[0] = 0;
		output_record->V6.dstaddr[1] = 0;
		output_record->V4.dstaddr 	 = u[1];
		p = (void *)((pointer_addr_t)p + 2 * sizeof(uint32_t));
	}

	// Required extension 2 - packet counter
	if ( (input_record->flags & FLAG_PKG_64 ) != 0 ) { 
		// 64bit packet counter
		value64_t	l, *v = (value64_t *)p;
		l.val.val32[0] = v->val.val32[0];
		l.val.val32[1] = v->val.val32[1];
		output_record->dPkts = l.val.val64;
		p = (void *)((pointer_addr_t)p + sizeof(uint64_t));
	} else {	
		// 32bit packet counter
		output_record->dPkts = *((uint32_t *)p);
		p = (void *)((pointer_addr_t)p + sizeof(uint32_t));
	}

	// Required extension 3 - byte counter
	if ( (input_record->flags & FLAG_BYTES_64 ) != 0 ) { 
		// 64bit byte counter
		value64_t	l, *v = (value64_t *)p;
		l.val.val32[0] = v->val.val32[0];
		l.val.val32[1] = v->val.val32[1];
		output_record->dOctets = l.val.val64;
		p = (void *)((pointer_addr_t)p + sizeof(uint64_t));
	} else {	
		// 32bit bytes counter
		output_record->dOctets = *((uint32_t *)p);
		p = (void *)((pointer_addr_t)p + sizeof(uint32_t));
	}

	// preset one single flow
	output_record->aggr_flows = 1;

	// Process optional extensions
	i=0;
	while ( extension_map->ex_id[i] ) {
		switch (extension_map->ex_id[i++]) {
			// 0 - 3 should never be in an extension table so - ignore it
			case 0:
			case 1:
			case 2:
			case 3:
				break;
			case EX_IO_SNMP_2: {
				tpl_ext_4_t *tpl = (tpl_ext_4_t *)p;
				output_record->input  = tpl->input;
				output_record->output = tpl->output;
				p = (void *)tpl->data;
				} break;
			case EX_IO_SNMP_4: {
				tpl_ext_5_t *tpl = (tpl_ext_5_t *)p;
				output_record->input  = tpl->input;
				output_record->output = tpl->output;
				p = (void *)tpl->data;
				} break;
			case EX_AS_2: {
				tpl_ext_6_t *tpl = (tpl_ext_6_t *)p;
				output_record->srcas = tpl->src_as;
				output_record->dstas = tpl->dst_as;
				p = (void *)tpl->data;
				} break;
			case EX_AS_4: {
				tpl_ext_7_t *tpl = (tpl_ext_7_t *)p;
				output_record->srcas = tpl->src_as;
				output_record->dstas = tpl->dst_as;
				p = (void *)tpl->data;
				} break;
			case EX_MULIPLE: {
				tpl_ext_8_t *tpl = (tpl_ext_8_t *)p;
				// use a 32 bit int to copy all 4 fields
				output_record->any = tpl->any;
				p = (void *)tpl->data;
				} break;
			case EX_NEXT_HOP_v4: {
				tpl_ext_9_t *tpl = (tpl_ext_9_t *)p;
				output_record->ip_nexthop.V6[0] = 0;
				output_record->ip_nexthop.V6[1] = 0;
				output_record->ip_nexthop.V4	= tpl->nexthop;
				p = (void *)tpl->data;
				ClearFlag(output_record->flags, FLAG_IPV6_NH);
				} break;
			case EX_NEXT_HOP_v6: {
				tpl_ext_10_t *tpl = (tpl_ext_10_t *)p;
				CopyV6IP((uint32_t *)output_record->ip_nexthop.V6, (uint32_t *)tpl->nexthop);
				p = (void *)tpl->data;
				SetFlag(output_record->flags, FLAG_IPV6_NH);
				} break;
			case EX_NEXT_HOP_BGP_v4: {
				tpl_ext_11_t *tpl = (tpl_ext_11_t *)p;
				output_record->bgp_nexthop.V6[0] = 0;
				output_record->bgp_nexthop.V6[1] = 0;
				output_record->bgp_nexthop.V4	= tpl->bgp_nexthop;
				ClearFlag(output_record->flags, FLAG_IPV6_NHB);
				p = (void *)tpl->data;
				} break;
			case EX_NEXT_HOP_BGP_v6: {
				tpl_ext_12_t *tpl = (tpl_ext_12_t *)p;
				CopyV6IP((uint32_t *)output_record->bgp_nexthop.V6, (uint32_t *)tpl->bgp_nexthop);
				p = (void *)tpl->data;
				SetFlag(output_record->flags, FLAG_IPV6_NHB);
				} break;
			case EX_VLAN: {
				tpl_ext_13_t *tpl = (tpl_ext_13_t *)p;
				output_record->src_vlan = tpl->src_vlan;
				output_record->dst_vlan = tpl->dst_vlan;
				p = (void *)tpl->data;
				} break;
			case EX_OUT_PKG_4: {
				tpl_ext_14_t *tpl = (tpl_ext_14_t *)p;
				output_record->out_pkts = tpl->out_pkts;
				p = (void *)tpl->data;
				} break;
			case EX_OUT_PKG_8: {
				tpl_ext_15_t v, *tpl = (tpl_ext_15_t *)p;
				v.v[0] = tpl->v[0];
				v.v[1] = tpl->v[1];
				output_record->out_pkts = v.out_pkts;
				p = (void *)tpl->data;
				} break;
			case EX_OUT_BYTES_4: {
				tpl_ext_16_t *tpl = (tpl_ext_16_t *)p;
				output_record->out_bytes = tpl->out_bytes;
				p = (void *)tpl->data;
				} break;
			case EX_OUT_BYTES_8: {
				tpl_ext_17_t v,*tpl = (tpl_ext_17_t *)p;
				v.v[0] = tpl->v[0];
				v.v[1] = tpl->v[1];
				output_record->out_bytes = v.out_bytes;
				p = (void *)tpl->data;
				} break;
			case EX_AGGR_FLOWS_4: {
				tpl_ext_18_t *tpl = (tpl_ext_18_t *)p;
				output_record->aggr_flows = tpl->aggr_flows;
				p = (void *)tpl->data;
				} break;
			case EX_AGGR_FLOWS_8: {
				tpl_ext_19_t v, *tpl = (tpl_ext_19_t *)p;
				v.v[0] = tpl->v[0];
				v.v[1] = tpl->v[1];
				output_record->aggr_flows = v.aggr_flows;
				p = (void *)tpl->data;
				} break;
			case EX_MAC_1: {
				tpl_ext_20_t v, *tpl = (tpl_ext_20_t *)p;
				v.v1[0] = tpl->v1[0];
				v.v1[1] = tpl->v1[1];
				output_record->in_src_mac = v.in_src_mac;

				v.v2[0] = tpl->v2[0];
				v.v2[1] = tpl->v2[1];
				output_record->out_dst_mac = v.out_dst_mac;
				p = (void *)tpl->data;
				} break;
			case EX_MAC_2: {
				tpl_ext_21_t v, *tpl = (tpl_ext_21_t *)p;
				v.v1[0] = tpl->v1[0];
				v.v1[1] = tpl->v1[1];
				output_record->in_dst_mac = v.in_dst_mac;
				v.v2[0] = tpl->v2[0];
				v.v2[1] = tpl->v2[1];
				output_record->out_src_mac = v.out_src_mac;
				p = (void *)tpl->data;
				} break;
			case EX_MPLS: {
				tpl_ext_22_t *tpl = (tpl_ext_22_t *)p;
				int j;
				for (j=0; j<10; j++ ) {
					output_record->mpls_label[j] = tpl->mpls_label[j];
				}
				p = (void *)tpl->data;
			} break;
			case EX_ROUTER_IP_v4: {
				tpl_ext_23_t *tpl = (tpl_ext_23_t *)p;
				output_record->ip_router.V6[0] = 0;
				output_record->ip_router.V6[1] = 0;
				output_record->ip_router.V4	= tpl->router_ip;
				p = (void *)tpl->data;
				ClearFlag(output_record->flags, FLAG_IPV6_EXP);
				} break;
			case EX_ROUTER_IP_v6: {
				tpl_ext_24_t *tpl = (tpl_ext_24_t *)p;
				CopyV6IP((uint32_t *)output_record->ip_router.V6, (uint32_t *)tpl->router_ip);
				p = (void *)tpl->data;
				SetFlag(output_record->flags, FLAG_IPV6_EXP);
				} break;
			case EX_ROUTER_ID: {
				tpl_ext_25_t *tpl = (tpl_ext_25_t *)p;
				output_record->engine_type = tpl->engine_type;
				output_record->engine_id   = tpl->engine_id;
				p = (void *)tpl->data;
				} break;
			case EX_BGPADJ: {
				tpl_ext_26_t *tpl = (tpl_ext_26_t *)p;
				output_record->bgpNextAdjacentAS = tpl->bgpNextAdjacentAS;
				output_record->bgpPrevAdjacentAS = tpl->bgpPrevAdjacentAS;
				p = (void *)tpl->data;
			} break;
			case EX_LATENCY: {
				tpl_ext_latency_t *tpl = (tpl_ext_latency_t *)p;
				output_record->client_nw_delay_usec = tpl->client_nw_delay_usec;
				output_record->server_nw_delay_usec = tpl->server_nw_delay_usec;
				output_record->appl_latency_usec = tpl->appl_latency_usec;
				p = (void *)tpl->data;
			} break;
			case EX_RECEIVED: {
				tpl_ext_27_t *tpl = (tpl_ext_27_t *)p;
				value64_t v;
				v.val.val32[0] = tpl->v[0];
				v.val.val32[1] = tpl->v[1];
				output_record->received = v.val.val64;
				p = (void *)tpl->data;
			} break;
#ifdef NSEL
			case EX_NSEL_COMMON: {
				tpl_ext_37_t *tpl = (tpl_ext_37_t *)p;
				value64_t v;
				v.val.val32[0] = tpl->v[0];
				v.val.val32[1] = tpl->v[1];
				output_record->event_time = v.val.val64;
				output_record->conn_id 	  = tpl->conn_id;
				output_record->event   	  = tpl->fw_event;
				output_record->event_flag = FW_EVENT;
				output_record->fw_xevent  = tpl->fw_xevent;
				output_record->icmp = tpl->nsel_icmp;
				output_record->sec_group_tag = tpl->sec_group_tag;
				p = (void *)tpl->data;
			} break;
			case EX_NSEL_XLATE_PORTS: {
				tpl_ext_38_t *tpl = (tpl_ext_38_t *)p;
				output_record->xlate_src_port = tpl->xlate_src_port;
				output_record->xlate_dst_port = tpl->xlate_dst_port;
				p = (void *)tpl->data;
			} break;
			case EX_NSEL_XLATE_IP_v4: {
				tpl_ext_39_t *tpl = (tpl_ext_39_t *)p;
				output_record->xlate_src_ip.V6[0] = 0;
				output_record->xlate_src_ip.V6[1] = 0;
				output_record->xlate_src_ip.V4	= tpl->xlate_src_ip;
				output_record->xlate_dst_ip.V6[0] = 0;
				output_record->xlate_dst_ip.V6[1] = 0;
				output_record->xlate_dst_ip.V4	= tpl->xlate_dst_ip;
				p = (void *)tpl->data;
				output_record->xlate_flags = 0;
				} break;
			case EX_NSEL_XLATE_IP_v6: {
				tpl_ext_40_t *tpl = (tpl_ext_40_t *)p;
				output_record->xlate_src_ip.V6[0] = tpl->xlate_src_ip[0];
				output_record->xlate_src_ip.V6[1] = tpl->xlate_src_ip[1];
				output_record->xlate_dst_ip.V6[0] = tpl->xlate_dst_ip[0];
				output_record->xlate_dst_ip.V6[1] = tpl->xlate_dst_ip[1];
				p = (void *)tpl->data;
				output_record->xlate_flags = 1;
				} break;
			case EX_NSEL_ACL: {
				tpl_ext_41_t *tpl = (tpl_ext_41_t *)p;
				int j;
				for (j=0; j<3; j++) {
					output_record->ingress_acl_id[j] = tpl->ingress_acl_id[j];
					output_record->egress_acl_id[j] = tpl->egress_acl_id[j];
				}
				p = (void *)tpl->data;
			} break;
			case EX_NSEL_USER: {
				tpl_ext_42_t *tpl = (tpl_ext_42_t *)p;
				strncpy((void *)output_record->username, (void *)tpl->username, sizeof(output_record->username));
				output_record->username[sizeof(output_record->username)-1] = '\0';	// safety 0
				p = (void *)tpl->data;
			} break;
			case EX_NSEL_USER_MAX: {
				tpl_ext_43_t *tpl = (tpl_ext_43_t *)p;
				strncpy((void *)output_record->username, (void *)tpl->username, sizeof(output_record->username));
				output_record->username[sizeof(output_record->username)-1] = '\0';	// safety 0
				p = (void *)tpl->data;
			} break;
			case EX_NEL_COMMON: {
				tpl_ext_46_t *tpl = (tpl_ext_46_t *)p;
				output_record->event 	  = tpl->nat_event;
				output_record->event_flag = FW_EVENT;
				// XXX	- 3 bytes unused
				output_record->egress_vrfid  = tpl->egress_vrfid;
				output_record->ingress_vrfid = tpl->ingress_vrfid;
				p = (void *)tpl->data;

				// remember this value, if we read old 1.6.10 files
				compat_nel_bug.vrf = tpl->egress_vrfid;
				if ( compat_nel ) {
					output_record->xlate_src_port = compat_nel_bug.port[0];
					output_record->xlate_dst_port = compat_nel_bug.port[1];
					output_record->egress_vrfid   = 0;
				}
			} break;
			// compat record v1.6.10
			case EX_NEL_GLOBAL_IP_v4: {
				tpl_ext_47_t *tpl = (tpl_ext_47_t *)p;
				output_record->xlate_src_ip.V6[0] = 0;
				output_record->xlate_src_ip.V6[1] = 0;
				output_record->xlate_src_ip.V4	= tpl->nat_inside;
				output_record->xlate_dst_ip.V6[0] = 0;
				output_record->xlate_dst_ip.V6[1] = 0;
				output_record->xlate_dst_ip.V4	= tpl->nat_outside;
				p = (void *)tpl->data;

				output_record->xlate_src_port = compat_nel_bug.port[0];
				output_record->xlate_dst_port = compat_nel_bug.port[1];
				output_record->egress_vrfid   = 0;
				compat_nel = 1;
			} break;
			case EX_PORT_BLOCK_ALLOC: {
				tpl_ext_48_t *tpl = (tpl_ext_48_t *)p;
				output_record->block_start = tpl->block_start;
				output_record->block_end = tpl->block_end;
				output_record->block_step = tpl->block_step;
				output_record->block_size = tpl->block_size;
				if ( output_record->block_end == 0 && output_record->block_size != 0 ) 
					output_record->block_end = output_record->block_start + output_record->block_size - 1;
				p = (void *)tpl->data;
			} break;
			
#endif
		}
	}
	
} // End of ExpandRecord_v2

/*
static inline void ExpandRecord_v3(recordHeaderV3_t *v3Record, master_record_t *output_record ) {
void		*p   = (void *)v3Record;
void		*eor = p + v3Record->size;
elementHeader_t *elementHeader;
uint32_t	s = sizeof(recordHeaderV3_t);

	// set map ref
	output_record->map_ref = NULL;
	output_record->exp_ref = NULL;

	output_record->size = v3Record->size;
	output_record->flags = v3Record->flags;
	output_record->exporter_sysid = v3Record->exporterID;
	output_record->numElements = v3Record->numElements;
	output_record->engine_type = v3Record->engineType;
	output_record->engine_id = v3Record->engineID;

	if ( v3Record->size < s ) {
		LogError("Size error v3Record: '%u'", v3Record->size);
		exit(255);
	}
	dbg_printf("Record announces %u extensions with total size %u\n", v3Record->numElements, v3Record->size);
	// first record header
	elementHeader = (elementHeader_t *)(p + sizeof(recordHeaderV3_t));
	for (int i=0; i<v3Record->numElements; i++ ) {
		int skip = 0;
		dbg_printf("[%i] next extension: %u\n", i, elementHeader->type);
		switch (elementHeader->type) {
			case EXnull:
				fprintf(stderr, "ExpandRecord_v3() Found unexpected NULL extension\n");
				break;
			case EXmsecRelTimeFlowID: {
				EXmsecRelTimeFlow_t *msecRelTimeFlow = (EXmsecRelTimeFlow_t *)((void *)elementHeader + sizeof(elementHeader_t));
				UNUSED(msecRelTimeFlow);
				} break;
			case EXmsecTimeFlowID: {
				EXmsecTimeFlow_t *msecTimeFlow = (EXmsecTimeFlow_t *)((void *)elementHeader + sizeof(elementHeader_t));
				output_record->msecFirst = msecTimeFlow->msecFirst;
				output_record->msecLast  = msecTimeFlow->msecLast;
				} break;
			case EXmsecReceivedID: {
				EXmsecReceived_t *msecReceived = (EXmsecReceived_t *)((void *)elementHeader + sizeof(elementHeader_t));
				output_record->received = msecReceived->msecReceived;
				} break;
			case EXipv4FlowID: {
				EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)((void *)elementHeader + sizeof(elementHeader_t));
				output_record->V6.srcaddr[0] = 0;
				output_record->V6.srcaddr[1] = 0;
				output_record->V4.srcaddr 	 = ipv4Flow->srcAddr;

				output_record->V6.dstaddr[0] = 0;
				output_record->V6.dstaddr[1] = 0;
				output_record->V4.dstaddr 	 = ipv4Flow->dstAddr;
				} break;
			case EXipv6FlowID: {
				EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)((void *)elementHeader + sizeof(elementHeader_t));

				output_record->V6.srcaddr[0] = ipv6Flow->srcAddr[0];
				output_record->V6.srcaddr[1] = ipv6Flow->srcAddr[1];
				output_record->V6.dstaddr[0] = ipv6Flow->dstAddr[0];
				output_record->V6.dstaddr[1] = ipv6Flow->dstAddr[1];

				SetFlag(output_record->flags, FLAG_IPV6_ADDR);
				} break;
			case EXflowMiscID: {
				EXflowMisc_t *flowMisc = (EXflowMisc_t *)((void *)elementHeader + sizeof(elementHeader_t));
				output_record->srcPort	 = flowMisc->srcPort;
				output_record->dstPort	 = flowMisc->dstPort;
				output_record->tcp_flags = flowMisc->tcpFlags;
				output_record->proto	 = flowMisc->proto;
				output_record->dir		 = flowMisc->dir;
				} break;
			case EXflowAddID: {
				EXflowAdd_t *flowAdd = (EXflowAdd_t *)((void *)elementHeader + sizeof(elementHeader_t));
				output_record->fwd_status = flowAdd->fwdStatus;
				output_record->tos		= flowAdd->srcTos;
				output_record->dst_tos	= flowAdd->dstTos;
				output_record->src_mask	= flowAdd->srcMask;
				output_record->dst_mask	= flowAdd->dstMask;
				} break;
			case EXcntFlowID: {
				EXcntFlow_t *cntFlow = (EXcntFlow_t *)((void *)elementHeader + sizeof(elementHeader_t));
				output_record->dPkts	  = cntFlow->inPackets;
				output_record->dOctets	  = cntFlow->inBytes;
				output_record->out_pkts	  = cntFlow->outPackets;
				output_record->out_bytes  = cntFlow->outBytes;
				output_record->aggr_flows = cntFlow->flows;
				SetFlag(output_record->flags, FLAG_PKG_64);
				SetFlag(output_record->flags, FLAG_BYTES_64);
				} break;
			case EXsnmpInterfaceID: {
				EXsnmpInterface_t *snmpInterface = (EXsnmpInterface_t *)((void *)elementHeader + sizeof(elementHeader_t));
				output_record->input  = snmpInterface->input;
				output_record->output = snmpInterface->output;
				} break;
			case EXvLanID: {
				EXvLan_t *vLan = (EXvLan_t *)((void *)elementHeader + sizeof(elementHeader_t));
				output_record->src_vlan = vLan->srcVlan;
				output_record->dst_vlan = vLan->dstVlan;
				} break;
			case EXasRoutingID: {
				EXasRouting_t *asRouting = (EXasRouting_t *)((void *)elementHeader + sizeof(elementHeader_t));
				output_record->srcas = asRouting->srcAS;
				output_record->dstas = asRouting->dstAS;
				} break;
			case EXbgpNextHopV4ID: {
				EXbgpNextHopV4_t *bgpNextHopV4 = (EXbgpNextHopV4_t *)((void *)elementHeader + sizeof(elementHeader_t));
				output_record->bgp_nexthop.V6[0] = 0;
				output_record->bgp_nexthop.V6[1] = 0;
				output_record->bgp_nexthop.V4	= bgpNextHopV4->ip;
				ClearFlag(output_record->flags, FLAG_IPV6_NHB);
				} break;
			case EXbgpNextHopV6ID: {
				EXbgpNextHopV6_t *bgpNextHopV6 = (EXbgpNextHopV6_t *)((void *)elementHeader + sizeof(elementHeader_t));
				output_record->bgp_nexthop.V6[0] = bgpNextHopV6->ip[0];
				output_record->bgp_nexthop.V6[1] = bgpNextHopV6->ip[1];
				SetFlag(output_record->flags, FLAG_IPV6_NHB);
				} break;
			case EXipNextHopV4ID: {
				EXipNextHopV4_t *ipNextHopV4 = (EXipNextHopV4_t *)((void *)elementHeader + sizeof(elementHeader_t));
				output_record->ip_nexthop.V6[0] = 0;
				output_record->ip_nexthop.V6[1] = 0;
				output_record->ip_nexthop.V4 = ipNextHopV4->ip;
				ClearFlag(output_record->flags, FLAG_IPV6_NH);
				} break;
			case EXipNextHopV6ID: {
				EXipNextHopV6_t *ipNextHopV6 = (EXipNextHopV6_t *)((void *)elementHeader + sizeof(elementHeader_t));
				output_record->ip_nexthop.V6[0] = ipNextHopV6->ip[0];
				output_record->ip_nexthop.V6[1] = ipNextHopV6->ip[1];
				SetFlag(output_record->flags, FLAG_IPV6_NH);
				} break;
			case EXipReceivedV4ID: {
				EXipNextHopV4_t *ipNextHopV4 = (EXipNextHopV4_t *)((void *)elementHeader + sizeof(elementHeader_t));
				output_record->ip_router.V6[0] = 0;
				output_record->ip_router.V6[1] = 0;
				output_record->ip_router.V4 = ipNextHopV4->ip;
				ClearFlag(output_record->flags, FLAG_IPV6_EXP);
				} break;
			case EXipReceivedV6ID: {
				EXipReceivedV6_t *ipNextHopV6 = (EXipReceivedV6_t *)((void *)elementHeader + sizeof(elementHeader_t));
				output_record->ip_router.V6[0] = ipNextHopV6->ip[0];
				output_record->ip_router.V6[1] = ipNextHopV6->ip[1];
				SetFlag(output_record->flags, FLAG_IPV6_EXP);
				} break;
			case EXmplsLabelID: {
				EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)((void *)elementHeader + sizeof(elementHeader_t));
				for (int j=0; j<10; j++) {
					output_record->mpls_label[j] = mplsLabel->mplsLabel[j];
				}
				} break;
			case EXmacAddrID: {
				EXmacAddr_t *macAddr = (EXmacAddr_t *)((void *)elementHeader + sizeof(elementHeader_t));
				output_record->in_src_mac	= macAddr->inSrcMac;
				output_record->out_dst_mac	= macAddr->outDstMac;
				output_record->in_dst_mac	= macAddr->inDstMac;
				output_record->out_src_mac	= macAddr->outSrcMac;
				} break;
			case EXasAdjacentID: {
				EXasAdjacent_t *asAdjacent = (EXasAdjacent_t *)((void *)elementHeader + sizeof(elementHeader_t));
				output_record->bgpNextAdjacentAS = asAdjacent->nextAdjacentAS;
				output_record->bgpPrevAdjacentAS = asAdjacent->prevAdjacentAS;
			} break;
			case EXlatencyID: {
				EXlatency_t *latency = (EXlatency_t *)((void *)elementHeader + sizeof(elementHeader_t));
				output_record->client_nw_delay_usec = latency->usecClientNwDelay;
				output_record->server_nw_delay_usec = latency->usecServerNwDelay;
				output_record->appl_latency_usec = latency->usecApplLatency;
			} break;
			case EXnselCommonID: {
				EXnselCommon_t *nselCommon = (EXnselCommon_t *)((void *)elementHeader + sizeof(elementHeader_t));
				output_record->event_flag = FW_EVENT;
				output_record->conn_id 	  = nselCommon->connID;
				output_record->event   	  = nselCommon->fwEvent;
				output_record->fw_xevent  = nselCommon->fwXevent;
				output_record->event_time = nselCommon->msecEvent;
				SetFlag(output_record->flags, FLAG_EVENT);
			} break;
			case EXnselXlateIPv4ID: {
				EXnselXlateIPv4_t *nselXlateIPv4 = (EXnselXlateIPv4_t *)((void *)elementHeader + sizeof(elementHeader_t));
				output_record->xlate_src_ip.V6[0] = 0;
				output_record->xlate_src_ip.V6[1] = 0;
				output_record->xlate_src_ip.V4	= nselXlateIPv4->xlateSrcAddr;
				output_record->xlate_dst_ip.V6[0] = 0;
				output_record->xlate_dst_ip.V6[1] = 0;
				output_record->xlate_dst_ip.V4	= nselXlateIPv4->xlateDstAddr;
				output_record->xlate_flags = 0;
			} break;
			case EXnselXlateIPv6ID: {
				EXnselXlateIPv6_t *nselXlateIPv6 = (EXnselXlateIPv6_t *)((void *)elementHeader + sizeof(elementHeader_t));
				memcpy(output_record->xlate_src_ip.V6, &(nselXlateIPv6->xlateSrcAddr), 16);
				memcpy(output_record->xlate_dst_ip.V6, &(nselXlateIPv6->xlateDstAddr), 16);
				output_record->xlate_flags = 1;
			} break;
			case EXnselXlatePortID: {
				EXnselXlatePort_t *nselXlatePort = (EXnselXlatePort_t *)((void *)elementHeader + sizeof(elementHeader_t));
				output_record->xlate_src_port = nselXlatePort->xlateSrcPort;
				output_record->xlate_dst_port = nselXlatePort->xlateDstPort;
			} break;
			case EXnselAclID: {
				EXnselAcl_t *nselAcl = (EXnselAcl_t *)((void *)elementHeader + sizeof(elementHeader_t));
				memcpy(output_record->ingress_acl_id, nselAcl->ingressAcl, 12);
				memcpy(output_record->egress_acl_id, nselAcl->egressAcl, 12);
			} break;
			case EXnselUserID: {
				EXnselUser_t *nselUser = (EXnselUser_t *)((void *)elementHeader + sizeof(elementHeader_t));
				memcpy(output_record->username, nselUser->username, 66);
			} break;
			case EXnelCommonID: {
				EXnelCommon_t *nelCommon = (EXnelCommon_t *)((void *)elementHeader + sizeof(elementHeader_t));
				output_record->event_time = nelCommon->msecEvent;
				output_record->event 	  = nelCommon->natEvent;
				output_record->event_flag = FW_EVENT;
				output_record->egress_vrfid  = nelCommon->egressVrf;
				output_record->ingress_vrfid = nelCommon->ingressVrf;
			} break;
			case EXnelXlatePortID: {
				EXnelXlatePort_t *nelXlatePort = (EXnelXlatePort_t *)((void *)elementHeader + sizeof(elementHeader_t));
				output_record->block_start = nelXlatePort->blockStart;
				output_record->block_end   = nelXlatePort->blockEnd;
				output_record->block_step  = nelXlatePort->blockStep;
				output_record->block_size  = nelXlatePort->blockSize;
			} break;
			default:
				fprintf(stderr, "Unknown extension '%u'\n", elementHeader->type);
				skip = 1;
		}
		if (!skip) {
			output_record->exElementList[i] = elementHeader->type;
		} else {
			skip = 0;
		}

		s += elementHeader->length;
		elementHeader = (elementHeader_t *)((void *)elementHeader + elementHeader->length);

		if( (void *)elementHeader > eor ) {
			fprintf(stderr, "ptr error - elementHeader > eor\n");
			exit(255);
		}
	}
	// map icmp type/code in it's own vars
	output_record->icmp = output_record->dstPort;
	if ( s != v3Record->size ) {
		fprintf(stderr, "Record size info: '%u' not equal sum extensions: '%u'\n", v3Record->size, s);
		exit(255);
	}
} // End of ExpandRecord_v3
*/

#ifdef NEED_PACKRECORD
static void PackRecord(master_record_t *master_record, nffile_t *nffile) {
extension_map_t *extension_map = master_record->map_ref;
common_record_t *common_record;
uint32_t required =  COMMON_RECORD_DATA_SIZE + extension_map->extension_size;
size_t	 size;
void	 *p;
int		i;

	// check size of packets and bytes
	if ( master_record->dPkts >  0xffffffffLL ) {
		master_record->flags |= FLAG_PKG_64;
		required += 8;
	} else {
		master_record->flags &= ~FLAG_PKG_64;
		required += 4;
	}

	if ( master_record->dOctets >  0xffffffffLL ) {
		master_record->flags |= FLAG_BYTES_64;
		required += 8;
	} else {
		master_record->flags &= ~FLAG_BYTES_64;
		required += 4;
	}
	if ( (master_record->flags & FLAG_IPV6_ADDR) != 0 )	// IPv6
		required += 32;
	else
		required += 8;

	master_record->size = required;

	// flush current buffer to disc if not enough space
	if ( !CheckBufferSpace(nffile, required) ) {
		return;
	}

	// write common record
	// enough buffer space available at this point
	size = COMMON_RECORD_DATA_SIZE;
	common_record = (common_record_t *)nffile->buff_ptr;

	common_record->type = CommonRecordType;
	common_record->size = master_record->size;
	common_record->flags = master_record->flags;
	common_record->ext_map = master_record->ext_map;
	common_record->first = master_record->msecFirst / 1000;
	common_record->msec_first = master_record->msecFirst % 1000;
	common_record->last = master_record->msecLast / 1000;
	common_record->msec_last = master_record->msecLast % 1000;
	common_record->fwd_status = master_record->fwd_status;
	common_record->tcp_flags = master_record->tcp_flags;
	common_record->prot = master_record->proto;
	common_record->tos = master_record->tos;
	common_record->srcPort = master_record->srcPort;
	common_record->dstPort = master_record->dstPort;
	common_record->exporter_sysid = master_record->exporter_sysid;
	common_record->reserved = 0;
	p = (void *)((pointer_addr_t)common_record + size);

	// Required extension 1 - IP addresses
	if ( (master_record->flags & FLAG_IPV6_ADDR) != 0 )	{ // IPv6
		// IPv6
		// keep compiler happy
		// memcpy(p, (void *)master_record->V6.srcaddr, 4 * sizeof(uint64_t));	
		memcpy(p, (void *)master_record->ip_union._ip_64.addr, 4 * sizeof(uint64_t));	
		p = (void *)((pointer_addr_t)p + 4 * sizeof(uint64_t));
	} else { 	
		// IPv4
		uint32_t *u = (uint32_t *)p;
		u[0] = master_record->V4.srcaddr;
		u[1] = master_record->V4.dstaddr;
		p = (void *)((pointer_addr_t)p + 2 * sizeof(uint32_t));
	}

	// Required extension 2 - packet counter
	if ( (master_record->flags & FLAG_PKG_64 ) != 0 ) { 
		// 64bit packet counter
		value64_t	l, *v = (value64_t *)p;
		l.val.val64 = master_record->dPkts;
		v->val.val32[0] = l.val.val32[0];
		v->val.val32[1] = l.val.val32[1];
		p = (void *)((pointer_addr_t)p + sizeof(uint64_t));
	} else {	
		// 32bit packet counter
		*((uint32_t *)p) = master_record->dPkts;
		p = (void *)((pointer_addr_t)p + sizeof(uint32_t));
	}

	// Required extension 3 - byte counter
	if ( (master_record->flags & FLAG_BYTES_64 ) != 0 ) { 
		// 64bit byte counter
		value64_t	l, *v = (value64_t *)p;
		l.val.val64 = master_record->dOctets;
		v->val.val32[0] = l.val.val32[0];
		v->val.val32[1] = l.val.val32[1];
		p = (void *)((pointer_addr_t)p + sizeof(uint64_t));
	} else {	
		// 32bit bytes counter
		*((uint32_t *)p) = master_record->dOctets;
		p = (void *)((pointer_addr_t)p + sizeof(uint32_t));
	}

	// Process optional extensions
	i=0;
	while ( extension_map->ex_id[i] ) {
		switch (extension_map->ex_id[i++]) {
			// 0 - 3 should never be in an extension table so - ignore it
			case 0:
			case 1:
			case 2:
			case 3:
				break;
			case EX_IO_SNMP_2: { // input/output SNMP 2 byte
				tpl_ext_4_t *tpl = (tpl_ext_4_t *)p;
				tpl->input  = master_record->input;
				tpl->output = master_record->output;
				p = (void *)tpl->data;
				} break;
			case EX_IO_SNMP_4: { // input/output SNMP 4 byte
				tpl_ext_5_t *tpl = (tpl_ext_5_t *)p;
				tpl->input  = master_record->input;
				tpl->output = master_record->output;
				p = (void *)tpl->data;
				} break;
			case EX_AS_2: { // srcas/dstas 2 byte
				tpl_ext_6_t *tpl = (tpl_ext_6_t *)p;
				tpl->src_as = master_record->srcas;
				tpl->dst_as = master_record->dstas;
				p = (void *)tpl->data;
				} break;
			case EX_AS_4: { // srcas/dstas 4 byte
				tpl_ext_7_t *tpl = (tpl_ext_7_t *)p;
				tpl->src_as = master_record->srcas;
				tpl->dst_as = master_record->dstas;
				p = (void *)tpl->data;
				} break;
			case EX_MULIPLE: {
				tpl_ext_8_t *tpl = (tpl_ext_8_t *)p;
				// use a 32 bit int to copy all 4 fields
				tpl->any = master_record->any;
				p = (void *)tpl->data;
				} break;
			case EX_NEXT_HOP_v4: {
				tpl_ext_9_t *tpl = (tpl_ext_9_t *)p;
				tpl->nexthop = master_record->ip_nexthop.V4;
				p = (void *)tpl->data;
				} break;
			case EX_NEXT_HOP_v6: {
				tpl_ext_10_t *tpl = (tpl_ext_10_t *)p;
				tpl->nexthop[0] = master_record->ip_nexthop.V6[0];
				tpl->nexthop[1] = master_record->ip_nexthop.V6[1];
				p = (void *)tpl->data;
				} break;
			case EX_NEXT_HOP_BGP_v4: {
				tpl_ext_11_t *tpl = (tpl_ext_11_t *)p;
				tpl->bgp_nexthop = master_record->bgp_nexthop.V4;
				p = (void *)tpl->data;
				} break;
			case EX_NEXT_HOP_BGP_v6: {
				tpl_ext_12_t *tpl = (tpl_ext_12_t *)p;
				tpl->bgp_nexthop[0] = master_record->bgp_nexthop.V6[0];
				tpl->bgp_nexthop[1] = master_record->bgp_nexthop.V6[1];
				p = (void *)tpl->data;
				} break;
			case EX_VLAN: {
				tpl_ext_13_t *tpl = (tpl_ext_13_t *)p;
				tpl->src_vlan = master_record->src_vlan;
				tpl->dst_vlan = master_record->dst_vlan;
				p = (void *)tpl->data;
				} break;
			case EX_OUT_PKG_4: {
				tpl_ext_14_t *tpl = (tpl_ext_14_t *)p;
				tpl->out_pkts = master_record->out_pkts;
				p = (void *)tpl->data;
				} break;
			case EX_OUT_PKG_8: {
				tpl_ext_15_t v, *tpl = (tpl_ext_15_t *)p;
				v.out_pkts = master_record->out_pkts;
				tpl->v[0] = v.v[0];
				tpl->v[1] = v.v[1];
				p = (void *)tpl->data;
				} break;
			case EX_OUT_BYTES_4: {
				tpl_ext_16_t *tpl = (tpl_ext_16_t *)p;
				tpl->out_bytes = master_record->out_bytes;
				p = (void *)tpl->data;
				} break;
			case EX_OUT_BYTES_8: {
				tpl_ext_17_t v, *tpl = (tpl_ext_17_t *)p;
				v.out_bytes = master_record->out_bytes;
				tpl->v[0] = v.v[0];
				tpl->v[1] = v.v[1];
				p = (void *)tpl->data;
				} break;
			case EX_AGGR_FLOWS_4: {
				tpl_ext_18_t *tpl = (tpl_ext_18_t *)p;
				tpl->aggr_flows = master_record->aggr_flows;
				p = (void *)tpl->data;
				} break;
			case EX_AGGR_FLOWS_8: {
				tpl_ext_19_t v, *tpl = (tpl_ext_19_t *)p;
				v.aggr_flows = master_record->aggr_flows;
				tpl->v[0] = v.v[0];
				tpl->v[1] = v.v[1];
				p = (void *)tpl->data;
				} break;
			case EX_MAC_1: {
				tpl_ext_20_t v, *tpl = (tpl_ext_20_t *)p;
				v.in_src_mac = master_record->in_src_mac;
				tpl->v1[0] = v.v1[0];
				tpl->v1[1] = v.v1[1];
				v.out_dst_mac = master_record->out_dst_mac;
				tpl->v2[0] = v.v2[0];
				tpl->v2[1] = v.v2[1];
				p = (void *)tpl->data;
				} break;
			case EX_MAC_2: {
				tpl_ext_21_t v, *tpl = (tpl_ext_21_t *)p;
				v.in_dst_mac = master_record->in_dst_mac;
				tpl->v1[0] = v.v1[0];
				tpl->v1[1] = v.v1[1];
				v.out_src_mac = master_record->out_src_mac;
				tpl->v2[0] = v.v2[0];
				tpl->v2[1] = v.v2[1];
				p = (void *)tpl->data;
				} break;
			case EX_MPLS: {
				tpl_ext_22_t *tpl = (tpl_ext_22_t *)p;
				int j;
				for (j=0; j<10; j++ ) {
					tpl->mpls_label[j] = master_record->mpls_label[j];
				}
				p = (void *)tpl->data;
				} break;
			case EX_ROUTER_IP_v4: {
				tpl_ext_23_t *tpl = (tpl_ext_23_t *)p;
				tpl->router_ip = master_record->ip_router.V4;
				p = (void *)tpl->data;
				} break;
			case EX_ROUTER_IP_v6: {
				tpl_ext_24_t *tpl = (tpl_ext_24_t *)p;
				tpl->router_ip[0] = master_record->ip_router.V6[0];
				tpl->router_ip[1] = master_record->ip_router.V6[1];
				p = (void *)tpl->data;
				} break;
			case EX_ROUTER_ID: {
				tpl_ext_25_t *tpl = (tpl_ext_25_t *)p;
				tpl->engine_type = master_record->engine_type;
				tpl->engine_id   = master_record->engine_id;
				p = (void *)tpl->data;
				} break;
			case EX_BGPADJ: {
				tpl_ext_26_t *tpl = (tpl_ext_26_t *)p;
				tpl->bgpNextAdjacentAS = master_record->bgpNextAdjacentAS;
				tpl->bgpPrevAdjacentAS = master_record->bgpPrevAdjacentAS;
				p = (void *)tpl->data;
				} break;
			case EX_RECEIVED: {
				tpl_ext_27_t *tpl = (tpl_ext_27_t *)p;
				tpl->received = master_record->received;
				p = (void *)tpl->data;
				} break;
			case EX_LATENCY: {
				tpl_ext_latency_t *tpl = (tpl_ext_latency_t *)p;
				tpl->client_nw_delay_usec = master_record->client_nw_delay_usec;
				tpl->server_nw_delay_usec = master_record->server_nw_delay_usec;
				tpl->appl_latency_usec	  = master_record->appl_latency_usec;
				p = (void *)tpl->data;
			} break;
#ifdef NSEL
			case EX_NSEL_COMMON: {
				tpl_ext_37_t *tpl = (tpl_ext_37_t *)p;
				tpl->event_time = master_record->event_time;
				tpl->conn_id    = master_record->conn_id;
				tpl->fw_event   = master_record->event;
				tpl->nsel_icmp  = master_record->icmp;
				tpl->fill  = 0;
				tpl->sec_group_tag = master_record->sec_group_tag;
				tpl->fw_xevent = master_record->fw_xevent;
				p = (void *)tpl->data;
				} break;
			case EX_NSEL_XLATE_PORTS: {
				tpl_ext_38_t *tpl = (tpl_ext_38_t *)p;
				tpl->xlate_src_port	 = master_record->xlate_src_port;
				tpl->xlate_dst_port	 = master_record->xlate_dst_port;
				p = (void *)tpl->data;
				} break;
			case EX_NSEL_XLATE_IP_v4: {
				tpl_ext_39_t *tpl = (tpl_ext_39_t *)p;
				tpl->xlate_src_ip = master_record->xlate_src_ip.V4;
				tpl->xlate_dst_ip = master_record->xlate_dst_ip.V4;
				p = (void *)tpl->data;
				} break;
			case EX_NSEL_XLATE_IP_v6: {
				tpl_ext_40_t *tpl = (tpl_ext_40_t *)p;
				tpl->xlate_src_ip[0] = master_record->xlate_src_ip.V6[0];
				tpl->xlate_src_ip[1] = master_record->xlate_src_ip.V6[1];
				p = (void *)tpl->data;
				tpl->xlate_dst_ip[0] = master_record->xlate_dst_ip.V6[0];
				tpl->xlate_dst_ip[1] = master_record->xlate_dst_ip.V6[1];
				p = (void *)tpl->data;
				} break;
			case EX_NSEL_ACL: {
				tpl_ext_41_t *tpl = (tpl_ext_41_t *)p;
				int j;
				for (j=0; j<3; j++) {
					tpl->ingress_acl_id[j] = master_record->ingress_acl_id[j];
					tpl->egress_acl_id[j]  = master_record->egress_acl_id[j];
				}
				p = (void *)tpl->data;
			} break;
			case EX_NSEL_USER: {
				tpl_ext_42_t *tpl = (tpl_ext_42_t *)p;
				strncpy((void *)tpl->username, (void *)master_record->username, sizeof(tpl->username));
				tpl->username[sizeof(tpl->username)-1] = '\0';	// safety 0
				p = (void *)tpl->data;
			} break;
			case EX_NSEL_USER_MAX: {
				tpl_ext_43_t *tpl = (tpl_ext_43_t *)p;
				strncpy((void *)tpl->username, (void *)master_record->username, sizeof(tpl->username));
				tpl->username[sizeof(tpl->username)-1] = '\0';	// safety 0
				p = (void *)tpl->data;
			} break;
			case EX_NEL_COMMON: {
				tpl_ext_46_t *tpl = (tpl_ext_46_t *)p;
				tpl->nat_event  = master_record->event;
				tpl->fill  = 0;
				tpl->flags = 0;
				tpl->egress_vrfid  = master_record->egress_vrfid;
				tpl->ingress_vrfid = master_record->ingress_vrfid;
				p = (void *)tpl->data;
			} break;
			case EX_PORT_BLOCK_ALLOC: {
				tpl_ext_48_t *tpl = (tpl_ext_48_t *)p;
				tpl->block_start = master_record->block_start;
				tpl->block_end   = master_record->block_end;
				tpl->block_step  = master_record->block_step;
				tpl->block_size  = master_record->block_size;
				p = (void *)tpl->data;
			} break;
#endif
		}
	}

	nffile->block_header->size += required;
	nffile->block_header->NumRecords++;
#ifdef DEVEL
	if ( ((pointer_addr_t)p - (pointer_addr_t)nffile->buff_ptr) != required ) {
		fprintf(stderr, "Packrecord: size missmatch: required: %i, written: %li!\n", 
			required, (long)((ptrdiff_t)p - (ptrdiff_t)nffile->buff_ptr));
		exit(255);
	}
#endif
	nffile->buff_ptr = p;

} // End of PackRecord
#endif

static inline void AppendToBuffer(nffile_t *nffile, void *record, size_t required) {

	// flush current buffer to disc
	if ( !CheckBufferSpace(nffile, required)) {
		return;
	}

	// enough buffer space available at this point
	memcpy(nffile->buff_ptr, record, required);

	// update stat
	nffile->block_header->NumRecords++;
	nffile->block_header->size += required;

	// advance write pointer
	nffile->buff_ptr = (void *)((pointer_addr_t)nffile->buff_ptr + required);

} // End of AppendToBuffer
