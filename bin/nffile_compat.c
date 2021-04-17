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

static inline int ExpandRecord_v2(record_header_t *record_ptr, master_record_t *output_record);

static inline int ConvertRecordV2(common_record_t *input_record, record_header_t *record_ptr);

static inline int ConvertRecordV2(common_record_t *input_record, record_header_t *record_ptr) {
void		*p = input_record->data;

	// valid flow_record converted if needed
	uint32_t map_id = input_record->ext_map;
	if ( map_id >= MAX_EXTENSION_MAPS ) {
		LogError("Corrupt data file. Extension map id %u too big.\n", input_record->ext_map);
		return 0;
	}
	if ( extension_map_list->slot[map_id] == NULL ) {
		LogError("Corrupt data file. Missing extension map %u. Skip record.\n", input_record->ext_map);
		return 0;
	} 
	extension_info_t *extension_info = extension_map_list->slot[map_id];
	extension_map_t *extension_map = extension_info->map;

	AddV3Header(record_ptr, recordHeader);
	recordHeader->exporterID = input_record->exporter_sysid;

	// pack V3 record
	PushExtension(recordHeader, EXgenericFlow, genericFlow);
	genericFlow->msecFirst = input_record->first * 1000L + input_record->msec_first;
	genericFlow->msecLast  = input_record->last  * 1000L + input_record->msec_last;
	genericFlow->proto	   = input_record->prot;
	genericFlow->tcpFlags  = input_record->tcp_flags;
 	genericFlow->srcPort   = input_record->srcPort;
 	genericFlow->dstPort   = input_record->dstPort;
	genericFlow->fwdStatus = input_record->fwd_status;
	genericFlow->srcTos	   = input_record->tos;

	if ( TestFlag(input_record->flags, FLAG_IPV6_ADDR))	{ // IPv6
		// IPv6
		PushExtension(recordHeader, EXipv6Flow, ipv6Flow);
		memcpy(ipv6Flow->srcAddr, (void *)input_record->data, 4 * sizeof(uint64_t));	

		p = (void *)(p + 4 * sizeof(uint64_t));
	} else {
		// IPv4
		uint32_t *u = (uint32_t *)p;
		PushExtension(recordHeader, EXipv4Flow, ipv4Flow);

		ipv4Flow->srcAddr = u[0];
		ipv4Flow->dstAddr = u[1];

		p = (void *)(p + 2 * sizeof(uint32_t));
	}

	if ( TestFlag(input_record->flags, FLAG_PKG_64)) { 
		// 64bit packet counter
		genericFlow->inPackets = *((uint64_t *)p);
		p = (void *)(p + sizeof(uint64_t));
	} else {	
		// 32bit packet counter
		genericFlow->inPackets = *((uint32_t *)p);
		p = (void *)(p + sizeof(uint32_t));
	}

	if ( TestFlag(input_record->flags, FLAG_BYTES_64)) { 
		// 64bit byte counter
		genericFlow->inBytes = *((uint64_t *)p);
		p = (void *)(p + sizeof(uint64_t));
	} else {	
		// 32bit bytes counter
		genericFlow->inBytes = *((uint32_t *)p);
		p = (void *)(p + sizeof(uint32_t));
	}

	EXmacAddr_t *macAddr = NULL;	// combine old extensions 21/22
	EXflowMisc_t *_flowMisc = NULL;

	uint64_t outPackets	= 0;
	uint64_t outBytes 	= 0;
	uint64_t numFlows 	= 0;
	uint32_t input  = 0;
	uint32_t output = 0;

	int i=0;
	while ( extension_map->ex_id[i] ) {
	// dbg_printf("[%i] EX: %u\n", i, extension_map->ex_id[i]);
		switch (extension_map->ex_id[i++]) {
			// 0 - 3 should never be in an extension table so - ignore it
			case 0:
			case 1:
			case 2:
			case 3:
				break;
			case EX_IO_SNMP_2: {
				tpl_ext_4_t *tpl = (tpl_ext_4_t *)p;
				input  = tpl->input;
				output = tpl->output;
				p = (void *)tpl->data;
				} break;
			case EX_IO_SNMP_4: {
				tpl_ext_5_t *tpl = (tpl_ext_5_t *)p;
				input  = tpl->input;
				output = tpl->output;
				p = (void *)tpl->data;
				} break;
			case EX_AS_2: {
				tpl_ext_6_t *tpl = (tpl_ext_6_t *)p;
				PushExtension(recordHeader, EXasRouting, asRouting);
				asRouting->srcAS = tpl->src_as;
				asRouting->dstAS = tpl->dst_as;
				p = (void *)tpl->data;
				} break;
			case EX_AS_4: {
				tpl_ext_7_t *tpl = (tpl_ext_7_t *)p;
				PushExtension(recordHeader, EXasRouting, asRouting);
				asRouting->srcAS = tpl->src_as;
				asRouting->dstAS = tpl->dst_as;
				p = (void *)tpl->data;
				} break;
			case EX_MULIPLE: {
				tpl_ext_8_t *tpl = (tpl_ext_8_t *)p;
				PushExtension(recordHeader, EXflowMisc, flowMisc);
				flowMisc->srcMask	= tpl->src_mask;
				flowMisc->dstMask	= tpl->dst_mask;
				flowMisc->dstTos	= tpl->dst_tos;
				flowMisc->dir		= tpl->dir;
				flowMisc->biFlowDir	= input_record->biFlowDir;
				flowMisc->flowEndReason	= input_record->flowEndReason;
				_flowMisc = flowMisc;
				p = (void *)tpl->data;
				} break;
			case EX_VLAN: {
				tpl_ext_13_t *tpl = (tpl_ext_13_t *)p;
				PushExtension(recordHeader, EXvLan, vLan);
				vLan->srcVlan = tpl->src_vlan;
				vLan->dstVlan = tpl->dst_vlan;
				p = (void *)tpl->data;
				} break;
			case EX_RECEIVED: {
				tpl_ext_27_t *tpl = (tpl_ext_27_t *)p;
				value64_t v;
				v.val.val32[0] = tpl->v[0];
				v.val.val32[1] = tpl->v[1];
				genericFlow->msecReceived = v.val.val64;
				p = (void *)tpl->data;
			} break;
			case EX_NEXT_HOP_v4: {
				tpl_ext_9_t *tpl = (tpl_ext_9_t *)p;
				PushExtension(recordHeader, EXipNextHopV4, ipNextHopV4);
				ipNextHopV4->ip = tpl->nexthop;
				p = (void *)tpl->data;
				} break;
			case EX_NEXT_HOP_v6: {
				tpl_ext_10_t *tpl = (tpl_ext_10_t *)p;
				PushExtension(recordHeader, EXipNextHopV6, ipNextHopV6);
				ipNextHopV6->ip[0] = tpl->nexthop[0];
				ipNextHopV6->ip[1] = tpl->nexthop[1];
				p = (void *)tpl->data;
				} break;
			case EX_ROUTER_ID: {
				tpl_ext_25_t *tpl = (tpl_ext_25_t *)p;
				recordHeader->engineType = tpl->engine_type;
				recordHeader->engineID   = tpl->engine_id;
				p = (void *)tpl->data;
				} break;
			case EX_ROUTER_IP_v4: {
				tpl_ext_23_t *tpl = (tpl_ext_23_t *)p;
				PushExtension(recordHeader, EXipReceivedV4, ipReceivedV4);
				ipReceivedV4->ip = tpl->router_ip;
				p = (void *)tpl->data;
				} break;
			case EX_ROUTER_IP_v6: {
				tpl_ext_24_t *tpl = (tpl_ext_24_t *)p;
				PushExtension(recordHeader, EXipReceivedV6, ipReceivedV6);
				ipReceivedV6->ip[0] = tpl->router_ip[0];
				ipReceivedV6->ip[1] = tpl->router_ip[1];
				p = (void *)tpl->data;
				} break;
			case EX_NEXT_HOP_BGP_v4: {
				tpl_ext_11_t *tpl = (tpl_ext_11_t *)p;
				PushExtension(recordHeader, EXbgpNextHopV4, bgpNextHopV4);
				bgpNextHopV4->ip = tpl->bgp_nexthop;
				p = (void *)tpl->data;
				} break;
			case EX_NEXT_HOP_BGP_v6: {
				tpl_ext_12_t *tpl = (tpl_ext_12_t *)p;
				PushExtension(recordHeader, EXipReceivedV6, ipNextHopV6);
				ipNextHopV6->ip[0] = tpl->bgp_nexthop[0];
				ipNextHopV6->ip[1] = tpl->bgp_nexthop[1];
				p = (void *)tpl->data;
				} break;
			case EX_OUT_PKG_4: {
				tpl_ext_14_t *tpl = (tpl_ext_14_t *)p;
				outPackets = tpl->out_pkts;
				p = (void *)tpl->data;
				} break;
			case EX_OUT_PKG_8: {
				tpl_ext_15_t *tpl = (tpl_ext_15_t *)p;
				outPackets = tpl->out_pkts;
				p = (void *)tpl->data;
				} break;
			case EX_OUT_BYTES_4: {
				tpl_ext_16_t *tpl = (tpl_ext_16_t *)p;
				outBytes = tpl->out_bytes;
				p = (void *)tpl->data;
				} break;
			case EX_OUT_BYTES_8: {
				tpl_ext_17_t *tpl = (tpl_ext_17_t *)p;
				outBytes = tpl->out_bytes;
				p = (void *)tpl->data;
				} break;
			case EX_AGGR_FLOWS_4: {
				tpl_ext_18_t *tpl = (tpl_ext_18_t *)p;
				numFlows = tpl->aggr_flows;
				p = (void *)tpl->data;
				} break;
			case EX_AGGR_FLOWS_8: {
				tpl_ext_19_t *tpl = (tpl_ext_19_t *)p;
				numFlows = tpl->aggr_flows;
				p = (void *)tpl->data;
				} break;
			case EX_MAC_1: {
				tpl_ext_20_t *tpl = (tpl_ext_20_t *)p;
				if ( !macAddr ) { // XXX fix 
					PushExtension(recordHeader, EXmacAddr, m);
					macAddr = m;
					macAddr->inSrcMac	= tpl->in_src_mac;
					macAddr->outDstMac	= tpl->out_dst_mac;
					macAddr->inDstMac	= 0;
					macAddr->outSrcMac	= 0;
				} else {
					macAddr->inSrcMac	= tpl->in_src_mac;
					macAddr->outDstMac	= tpl->out_dst_mac;
				}
				p = (void *)tpl->data;
				} break;
			case EX_MAC_2: {
				tpl_ext_21_t *tpl = (tpl_ext_21_t *)p;
				if ( !macAddr ) {
					PushExtension(recordHeader, EXmacAddr, m);
					macAddr = m;
					macAddr->inSrcMac	= 0;
					macAddr->outDstMac	= 0;
					macAddr->inDstMac	= tpl->in_dst_mac;
					macAddr->outSrcMac	= tpl->out_src_mac;
				} else {
					macAddr->inDstMac	= tpl->in_dst_mac;
					macAddr->outSrcMac	= tpl->out_src_mac;
				}
				p = (void *)tpl->data;
				} break;
			case EX_MPLS: {
				tpl_ext_22_t *tpl = (tpl_ext_22_t *)p;
				PushExtension(recordHeader, EXmplsLabel, mplsLabel);
				for (int j=0; j<10; j++ ) {
					mplsLabel->mplsLabel[j] = tpl->mpls_label[j];
				}
				p = (void *)tpl->data;
			} break;
			case EX_BGPADJ: {
				PushExtension(recordHeader, EXasAdjacent, asAdjacent);
				tpl_ext_26_t *tpl = (tpl_ext_26_t *)p;
				asAdjacent->nextAdjacentAS = tpl->bgpNextAdjacentAS;
				asAdjacent->prevAdjacentAS = tpl->bgpPrevAdjacentAS;
				p = (void *)tpl->data;
			} break;
			case EX_LATENCY: {
				PushExtension(recordHeader, EXlatency, latency);
				tpl_ext_latency_t *tpl = (tpl_ext_latency_t *)p;
				latency->usecClientNwDelay = tpl->client_nw_delay_usec;
				latency->usecServerNwDelay = tpl->server_nw_delay_usec;
				latency->usecApplLatency = tpl->appl_latency_usec;
				p = (void *)tpl->data;
			} break;
#ifdef NSEL
			case EX_NSEL_COMMON: {
				tpl_ext_37_t *tpl = (tpl_ext_37_t *)p;
				PushExtension(recordHeader, EXnselCommon, nselCommon);
				recordHeader->flags = FW_EVENT;
				nselCommon->msecEvent = tpl->event_time;
				nselCommon->connID    = tpl->conn_id;
				nselCommon->fwXevent  = tpl->fw_xevent;
				nselCommon->fwEvent   = tpl->fw_event;
				genericFlow->dstPort  = tpl->nsel_icmp;
				p = (void *)tpl->data;
			} break;
			case EX_NSEL_XLATE_IP_v4: {
				tpl_ext_39_t *tpl = (tpl_ext_39_t *)p;
				PushExtension(recordHeader, EXnselXlateIPv4, nselXlateIPv4);
				nselXlateIPv4->xlateSrcAddr	= tpl->xlate_src_ip;
				nselXlateIPv4->xlateDstAddr	= tpl->xlate_dst_ip;
				p = (void *)tpl->data;
				} break;
			case EX_NSEL_XLATE_IP_v6: {
				tpl_ext_40_t *tpl = (tpl_ext_40_t *)p;
				PushExtension(recordHeader, EXnselXlateIPv6, nselXlateIPv6);
				memcpy(nselXlateIPv6->xlateSrcAddr, tpl->xlate_src_ip, 16);
				memcpy(nselXlateIPv6->xlateDstAddr, tpl->xlate_dst_ip, 16);
				p = (void *)tpl->data;
				} break;
			case EX_NSEL_XLATE_PORTS: {
				tpl_ext_38_t *tpl = (tpl_ext_38_t *)p;
				PushExtension(recordHeader, EXnselXlatePort, nselXlatePort);
				nselXlatePort->xlateSrcPort = tpl->xlate_src_port;
				nselXlatePort->xlateDstPort = tpl->xlate_dst_port;
				p = (void *)tpl->data;
			} break;
			case EX_NSEL_ACL: {
				tpl_ext_41_t *tpl = (tpl_ext_41_t *)p;
				PushExtension(recordHeader, EXnselAcl, nselAcl);
				memcpy(nselAcl->ingressAcl, tpl->ingress_acl_id, 12);
				memcpy(nselAcl->egressAcl, tpl->egress_acl_id, 12);
				p = (void *)tpl->data;
			} break;
			case EX_NSEL_USER_MAX: {
				tpl_ext_43_t *tpl = (tpl_ext_43_t *)p;
				PushExtension(recordHeader, EXnselUser, nselUser);
				strncpy((void *)nselUser->username, (void *)tpl->username, 65);
				nselUser->username[65] = '\0';
				p = (void *)tpl->data;
			} break;
			case EX_NSEL_USER: {
				tpl_ext_42_t *tpl = (tpl_ext_42_t *)p;
				PushExtension(recordHeader, EXnselUser, nselUser);
				strncpy((void *)nselUser->username, (void *)tpl->username, 24);
				nselUser->username[25] = '\0';
				p = (void *)tpl->data;
			} break;
			case EX_NEL_COMMON: {
				tpl_ext_46_t *tpl = (tpl_ext_46_t *)p;
				PushExtension(recordHeader, EXnelCommon, nelCommon);
				nelCommon->natEvent = tpl->nat_event;
				recordHeader->flags = FW_EVENT;
				nelCommon->egressVrf = tpl->egress_vrfid;
				nelCommon->ingressVrf = tpl->ingress_vrfid;
				p = (void *)tpl->data;
			} break;
			case EX_NEL_GLOBAL_IP_v4: {
				tpl_ext_47_t *tpl = (tpl_ext_47_t *)p;
				LogError("Old extension ID %u, no longer supported", EX_NEL_GLOBAL_IP_v4);
				p = (void *)tpl->data;
			} break;
			case EX_PORT_BLOCK_ALLOC: {
				tpl_ext_48_t *tpl = (tpl_ext_48_t *)p;
				PushExtension(recordHeader, EXnelXlatePort, nelXlatePort);
				nelXlatePort->blockStart = tpl->block_start;
				nelXlatePort->blockEnd   = tpl->block_end;
				nelXlatePort->blockStep  = tpl->block_step;
				nelXlatePort->blockSize  = tpl->block_size;
				if ( nelXlatePort->blockEnd == 0 && nelXlatePort->blockSize != 0 ) 
					nelXlatePort->blockEnd = nelXlatePort->blockStart + nelXlatePort->blockSize - 1;
				p = (void *)tpl->data;
			} break;
#endif
		}
	}

	if ( outPackets || outBytes || numFlows) {
		PushExtension(recordHeader, EXcntFlow, cntFlow);
		cntFlow->outPackets = outPackets;
		cntFlow->outBytes = outBytes;
		cntFlow->flows = numFlows;
	}

	if ( input || output ) {
		if ( _flowMisc ) {
			_flowMisc->input  = input;
			_flowMisc->output = output;
		} else {
			PushExtension(recordHeader, EXflowMisc, flowMisc);
			flowMisc->input  = input;
			flowMisc->output = output;
		}
	}

	dbg_printf("V3 record: elements: %u, size: %u\n", recordHeader->numElements, recordHeader->size);
	return 1;

} // End of ConvertRecordV3

static inline void InsertElelement(uint16_t *list, int index, int elememt) { 
	// insert element in order to list
	int j = 0;
	uint32_t val = elememt;
	while ( j < index ) {
		if ( val < list[j] ) {
			uint32_t _tmp = list[j];
			list[j] = val;
			val = _tmp;
		}
		j++;
	}
	list[j] = val;
}

// Use 4 uint32_t copy cycles, as SPARC CPUs brak
static inline void CopyV6IP(uint32_t *dst, uint32_t *src) {
	dst[0] = src[0];
	dst[1] = src[1];
	dst[2] = src[2];
	dst[3] = src[3];
} // End of CopyV6IP

static inline int ExpandRecord_v2(record_header_t *record_ptr, master_record_t *output_record) {
common_record_t *input_record = (common_record_t *)record_ptr;
uint32_t	*u;
uint32_t	index;
void		*p = (void *)input_record;

	// valid flow_record converted if needed
	uint32_t map_id = input_record->ext_map;
	if ( map_id >= MAX_EXTENSION_MAPS ) {
		LogError("Corrupt data file. Extension map id %u too big.\n", input_record->ext_map);
		return 0;
	}
	if ( extension_map_list->slot[map_id] == NULL ) {
		LogError("Corrupt data file. Missing extension map %u. Skip record.\n", input_record->ext_map);
		return 0;
	} 
	extension_info_t *extension_info = extension_map_list->slot[map_id];
	extension_map_t *extension_map = extension_info->map;

	exporter_t *exp_info = exporter_list[input_record->exporter_sysid];
	exporter_info_record_t *exporter_info = exp_info ? &(exp_info->info) : NULL;

	index = 0;

	// set map ref
	output_record->engine_type = 0;
	output_record->engine_id   = 0;

	output_record->size		 = 0;
	output_record->flags	 = input_record->flags >> 6;
	output_record->mflags	 = 0;
	output_record->proto	 = input_record->prot;
	output_record->tcp_flags = input_record->tcp_flags;
 	output_record->srcPort	 = input_record->srcPort;
 	output_record->dstPort	 = input_record->dstPort;
	output_record->fwd_status = input_record->fwd_status;
	output_record->tos		 = input_record->tos;
	output_record->biFlowDir = input_record->biFlowDir;
	output_record->flowEndReason = input_record->flowEndReason;
	output_record->msecFirst = input_record->first * 1000L + input_record->msec_first;
	output_record->msecLast  = input_record->last  * 1000L + input_record->msec_last;
	output_record->msecReceived = 0;
	output_record->exporter_sysid = input_record->exporter_sysid;

	InsertElelement(output_record->exElementList, index++, EXgenericFlowID);
	output_record->size += EXgenericFlowSize;
	output_record->numElements++;

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
	if ( TestFlag(input_record->flags, FLAG_IPV6_ADDR))	{ // IPv6
		// IPv6
		// keep compiler happy
		// memcpy((void *)output_record->V6.srcaddr, p, 4 * sizeof(uint64_t));	
		memcpy((void *)output_record->ip_union._ip_64.addr, p, 4 * sizeof(uint64_t));	
		p = (void *)((pointer_addr_t)p + 4 * sizeof(uint64_t));
		InsertElelement(output_record->exElementList, index++, EXipv6FlowID);
		output_record->size += EXipv6FlowSize;
		output_record->numElements++;
		SetFlag(output_record->mflags, V3_FLAG_IPV6_ADDR);
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
		InsertElelement(output_record->exElementList, index++, EXipv4FlowID);
		output_record->size += EXipv4FlowSize;
		output_record->numElements++;
	}

	// Required extension 2 - packet counter
	if ( TestFlag(input_record->flags, FLAG_PKG_64)) { 
		// 64bit packet counter
		value64_t	l, *v = (value64_t *)p;
		l.val.val32[0] = v->val.val32[0];
		l.val.val32[1] = v->val.val32[1];
		output_record->inPackets = l.val.val64;
		p = (void *)((pointer_addr_t)p + sizeof(uint64_t));
	} else {	
		// 32bit packet counter
		output_record->inPackets = *((uint32_t *)p);
		p = (void *)((pointer_addr_t)p + sizeof(uint32_t));
	}

	// Required extension 3 - byte counter
	if ( TestFlag(input_record->flags, FLAG_BYTES_64)) { 
		// 64bit byte counter
		value64_t	l, *v = (value64_t *)p;
		l.val.val32[0] = v->val.val32[0];
		l.val.val32[1] = v->val.val32[1];
		output_record->inBytes = l.val.val64;
		p = (void *)((pointer_addr_t)p + sizeof(uint64_t));
	} else {	
		// 32bit bytes counter
		output_record->inBytes = *((uint32_t *)p);
		p = (void *)((pointer_addr_t)p + sizeof(uint32_t));
	}

	// preset one single flow
	output_record->aggr_flows = 1;

	int hasMisc = 0;
	int hasCnt = 0;
	int hasMac = 0;
	// Process optional extensions
	int i=0;
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
				if ( !hasMisc ) {
					InsertElelement(output_record->exElementList, index++, EXflowMiscID);
					output_record->size += EXflowMiscSize;
					output_record->numElements++;
					hasMisc = 1;
				}
				} break;
			case EX_IO_SNMP_4: {
				tpl_ext_5_t *tpl = (tpl_ext_5_t *)p;
				output_record->input  = tpl->input;
				output_record->output = tpl->output;
				p = (void *)tpl->data;
				if ( !hasMisc ) {
					InsertElelement(output_record->exElementList, index++, EXflowMiscID);
					output_record->size += EXflowMiscSize;
					output_record->numElements++;
					hasMisc = 1;
				}
				} break;
			case EX_AS_2: {
				tpl_ext_6_t *tpl = (tpl_ext_6_t *)p;
				output_record->srcas = tpl->src_as;
				output_record->dstas = tpl->dst_as;
				p = (void *)tpl->data;
				InsertElelement(output_record->exElementList, index++, EXasRoutingID);
				output_record->size += EXasRoutingSize;
				output_record->numElements++;
				} break;
			case EX_AS_4: {
				tpl_ext_7_t *tpl = (tpl_ext_7_t *)p;
				output_record->srcas = tpl->src_as;
				output_record->dstas = tpl->dst_as;
				p = (void *)tpl->data;
				InsertElelement(output_record->exElementList, index++, EXasRoutingID);
				output_record->size += EXasRoutingSize;
				output_record->numElements++;
				} break;
			case EX_MULIPLE: {
				tpl_ext_8_t *tpl = (tpl_ext_8_t *)p;
				// use a 32 bit int to copy all 4 fields
				output_record->any = tpl->any;
				p = (void *)tpl->data;
				if ( !hasMisc ) {
					InsertElelement(output_record->exElementList, index++, EXflowMiscID);
					output_record->size += EXflowMiscSize;
					output_record->numElements++;
					hasMisc = 1;
				}
				} break;
			case EX_NEXT_HOP_v4: {
				tpl_ext_9_t *tpl = (tpl_ext_9_t *)p;
				output_record->ip_nexthop.V6[0] = 0;
				output_record->ip_nexthop.V6[1] = 0;
				output_record->ip_nexthop.V4	= tpl->nexthop;
				p = (void *)tpl->data;
				InsertElelement(output_record->exElementList, index++, EXipNextHopV4ID);
				output_record->size += EXipNextHopV4Size;
				output_record->numElements++;
				} break;
			case EX_NEXT_HOP_v6: {
				tpl_ext_10_t *tpl = (tpl_ext_10_t *)p;
				CopyV6IP((uint32_t *)output_record->ip_nexthop.V6, (uint32_t *)tpl->nexthop);
				p = (void *)tpl->data;
				SetFlag(output_record->mflags, V3_FLAG_IPV6_NH);
				InsertElelement(output_record->exElementList, index++, EXipNextHopV6ID);
				output_record->size += EXipNextHopV6Size;
				output_record->numElements++;
				} break;
			case EX_NEXT_HOP_BGP_v4: {
				tpl_ext_11_t *tpl = (tpl_ext_11_t *)p;
				output_record->bgp_nexthop.V6[0] = 0;
				output_record->bgp_nexthop.V6[1] = 0;
				output_record->bgp_nexthop.V4	= tpl->bgp_nexthop;
				p = (void *)tpl->data;
				InsertElelement(output_record->exElementList, index++, EXbgpNextHopV4ID);
				output_record->size += EXbgpNextHopV4Size;
				output_record->numElements++;
				} break;
			case EX_NEXT_HOP_BGP_v6: {
				tpl_ext_12_t *tpl = (tpl_ext_12_t *)p;
				CopyV6IP((uint32_t *)output_record->bgp_nexthop.V6, (uint32_t *)tpl->bgp_nexthop);
				p = (void *)tpl->data;
				SetFlag(output_record->mflags, V3_FLAG_IPV6_NHB);
				InsertElelement(output_record->exElementList, index++, EXbgpNextHopV6ID);
				output_record->size += EXbgpNextHopV6Size;
				output_record->numElements++;
				} break;
			case EX_VLAN: {
				tpl_ext_13_t *tpl = (tpl_ext_13_t *)p;
				output_record->src_vlan = tpl->src_vlan;
				output_record->dst_vlan = tpl->dst_vlan;
				p = (void *)tpl->data;
				InsertElelement(output_record->exElementList, index++, EXvLanID);
				output_record->size += EXvLanSize;
				output_record->numElements++;
				} break;
			case EX_OUT_PKG_4: {
				tpl_ext_14_t *tpl = (tpl_ext_14_t *)p;
				output_record->out_pkts = tpl->out_pkts;
				p = (void *)tpl->data;
				if ( !hasCnt ) {
					InsertElelement(output_record->exElementList, index++, EXcntFlowID);
					output_record->size += EXcntFlowSize;
					output_record->numElements++;
					hasCnt = 1;
				}
				} break;
			case EX_OUT_PKG_8: {
				tpl_ext_15_t v, *tpl = (tpl_ext_15_t *)p;
				v.v[0] = tpl->v[0];
				v.v[1] = tpl->v[1];
				output_record->out_pkts = v.out_pkts;
				p = (void *)tpl->data;
				if ( !hasCnt ) {
					InsertElelement(output_record->exElementList, index++, EXcntFlowID);
					output_record->size += EXcntFlowSize;
					output_record->numElements++;
					hasCnt = 1;
				}
				} break;
			case EX_OUT_BYTES_4: {
				tpl_ext_16_t *tpl = (tpl_ext_16_t *)p;
				output_record->out_bytes = tpl->out_bytes;
				p = (void *)tpl->data;
				if ( !hasCnt ) {
					InsertElelement(output_record->exElementList, index++, EXcntFlowID);
					output_record->size += EXcntFlowSize;
					output_record->numElements++;
					hasCnt = 1;
				}
				} break;
			case EX_OUT_BYTES_8: {
				tpl_ext_17_t v,*tpl = (tpl_ext_17_t *)p;
				v.v[0] = tpl->v[0];
				v.v[1] = tpl->v[1];
				output_record->out_bytes = v.out_bytes;
				p = (void *)tpl->data;
				if ( !hasCnt ) {
					InsertElelement(output_record->exElementList, index++, EXcntFlowID);
					output_record->size += EXcntFlowSize;
					output_record->numElements++;
					hasCnt = 1;
				}
				} break;
			case EX_AGGR_FLOWS_4: {
				tpl_ext_18_t *tpl = (tpl_ext_18_t *)p;
				output_record->aggr_flows = tpl->aggr_flows;
				p = (void *)tpl->data;
				if ( !hasCnt ) {
					InsertElelement(output_record->exElementList, index++, EXcntFlowID);
					output_record->size += EXcntFlowSize;
					output_record->numElements++;
					hasCnt = 1;
				}
				} break;
			case EX_AGGR_FLOWS_8: {
				tpl_ext_19_t v, *tpl = (tpl_ext_19_t *)p;
				v.v[0] = tpl->v[0];
				v.v[1] = tpl->v[1];
				output_record->aggr_flows = v.aggr_flows;
				p = (void *)tpl->data;
				if ( !hasCnt ) {
					InsertElelement(output_record->exElementList, index++, EXcntFlowID);
					output_record->size += EXcntFlowSize;
					output_record->numElements++;
					hasCnt = 1;
				}
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
				if ( !hasMac ) {
					InsertElelement(output_record->exElementList, index++, EXmacAddrID);
					output_record->size += EXmacAddrSize;
					output_record->numElements++;
					hasMac = 1;
				}
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
				if ( !hasMac ) {
					InsertElelement(output_record->exElementList, index++, EXmacAddrID);
					output_record->size += EXmacAddrSize;
					output_record->numElements++;
					hasMac = 1;
				}
				} break;
			case EX_MPLS: {
				tpl_ext_22_t *tpl = (tpl_ext_22_t *)p;
				int j;
				for (j=0; j<10; j++ ) {
					output_record->mpls_label[j] = tpl->mpls_label[j];
				}
				p = (void *)tpl->data;
				InsertElelement(output_record->exElementList, index++, EXmplsLabelID);
				output_record->size += EXmplsLabelSize;
				output_record->numElements++;
			} break;
			case EX_ROUTER_IP_v4: {
				tpl_ext_23_t *tpl = (tpl_ext_23_t *)p;
				output_record->ip_router.V6[0] = 0;
				output_record->ip_router.V6[1] = 0;
				output_record->ip_router.V4	= tpl->router_ip;
				p = (void *)tpl->data;
				InsertElelement(output_record->exElementList, index++, EXipReceivedV4ID);
				output_record->size += EXipReceivedV4Size;
				output_record->numElements++;
				} break;
			case EX_ROUTER_IP_v6: {
				tpl_ext_24_t *tpl = (tpl_ext_24_t *)p;
				CopyV6IP((uint32_t *)output_record->ip_router.V6, (uint32_t *)tpl->router_ip);
				p = (void *)tpl->data;
				SetFlag(output_record->mflags, V3_FLAG_IPV6_EXP);
				InsertElelement(output_record->exElementList, index++, EXipReceivedV6ID);
				output_record->size += EXipReceivedV6Size;
				output_record->numElements++;
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
				InsertElelement(output_record->exElementList, index++, EXasAdjacentID);
				output_record->size += EXasAdjacentSize;
				output_record->numElements++;
				p = (void *)tpl->data;
			} break;
			case EX_LATENCY: {
				tpl_ext_latency_t *tpl = (tpl_ext_latency_t *)p;
				output_record->client_nw_delay_usec = tpl->client_nw_delay_usec;
				output_record->server_nw_delay_usec = tpl->server_nw_delay_usec;
				output_record->appl_latency_usec = tpl->appl_latency_usec;
				p = (void *)tpl->data;
				InsertElelement(output_record->exElementList, index++, EXlatencyID);
				output_record->size += EXlatencySize;
				output_record->numElements++;
			} break;
			case EX_RECEIVED: {
				tpl_ext_27_t *tpl = (tpl_ext_27_t *)p;
				value64_t v;
				v.val.val32[0] = tpl->v[0];
				v.val.val32[1] = tpl->v[1];
				output_record->msecReceived = v.val.val64;
				p = (void *)tpl->data;
			} break;
#ifdef NSEL
			case EX_NSEL_COMMON: {
				tpl_ext_37_t *tpl = (tpl_ext_37_t *)p;
				value64_t v;
				v.val.val32[0] = tpl->v[0];
				v.val.val32[1] = tpl->v[1];
				output_record->msecEvent  = v.val.val64;
				output_record->connID 	  = tpl->conn_id;
				output_record->event   	  = tpl->fw_event;
				output_record->event_flag = FW_EVENT;
				output_record->fwXevent   = tpl->fw_xevent;
				output_record->icmp		  = tpl->nsel_icmp;
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
					output_record->ingressAcl[j] = tpl->ingress_acl_id[j];
					output_record->egressAcl[j] = tpl->egress_acl_id[j];
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
				output_record->egressVrf  = tpl->egress_vrfid;
				output_record->ingressVrf = tpl->ingress_vrfid;
				p = (void *)tpl->data;

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
	
	return 1;

} // End of ExpandRecord_v2
