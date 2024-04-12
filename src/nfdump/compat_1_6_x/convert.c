/*
 *  Copyright (c) 2024, Peter Haag
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

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nfdump_1_6_x.h"
#include "nffileV2.h"
#include "nfx.h"
#include "util.h"

extension_map_list_t *extension_map_list = NULL;

static inline int ConvertRecordV2(common_record_t *commonRecord, dataBlock_t *dataBlock);

static void InitCompat16(void) {
    if (extension_map_list) return;

    extension_map_list = InitExtensionMaps(NEEDS_EXTENSION_LIST);
}  // End of InitCompat16

static inline int ConvertRecordV2(common_record_t *commonRecord, dataBlock_t *dataBlock) {
    /*
     * v2 blocks are max 1MB. v3 blocks have 2MB.
     * each v2 block can be stored in a v3 block
     * check anyway
     */
    uint32_t required = 2 * commonRecord->size;
    assert(IsAvailable(dataBlock, required));

    record_header_t *v3record_ptr = GetCurrentCursor(dataBlock);
    void *p = commonRecord->data;

    // valid flow_record converted if needed
    uint32_t map_id = commonRecord->ext_map;
    if (map_id >= MAX_EXTENSION_MAPS) {
        LogError("Corrupt data file. Extension map id %u too big.\n", commonRecord->ext_map);
        return 0;
    }
    if (extension_map_list->slot[map_id] == NULL) {
        LogError("Corrupt data file. Missing extension map %u. Skip record.\n", commonRecord->ext_map);
        return 0;
    }
    if (commonRecord->size > 2048) {
        LogError("Corrupt data file. record size %u. Skip record.\n", commonRecord->size);
        return 0;
    }
    extension_info_t *extension_info = extension_map_list->slot[map_id];
    extension_map_t *extension_map = extension_info->map;

    AddV3Header(v3record_ptr, recordHeader);
    recordHeader->exporterID = commonRecord->exporter_sysid;

    // pack V3 record
    PushExtension(recordHeader, EXgenericFlow, genericFlow);
    genericFlow->msecFirst = commonRecord->first * 1000L + commonRecord->msec_first;
    genericFlow->msecLast = commonRecord->last * 1000L + commonRecord->msec_last;
    genericFlow->proto = commonRecord->prot;
    genericFlow->tcpFlags = commonRecord->tcp_flags;
    genericFlow->srcPort = commonRecord->srcPort;
    genericFlow->dstPort = commonRecord->dstPort;
    genericFlow->fwdStatus = commonRecord->fwd_status;
    genericFlow->srcTos = commonRecord->tos;

    if (TestFlag(commonRecord->flags, FLAG_IPV6_ADDR)) {  // IPv6
        // IPv6
        PushExtension(recordHeader, EXipv6Flow, ipv6Flow);
        memcpy(ipv6Flow->srcAddr, (void *)commonRecord->data, 4 * sizeof(uint64_t));

        p = (void *)(p + 4 * sizeof(uint64_t));
    } else {
        // IPv4
        uint32_t *u = (uint32_t *)p;
        PushExtension(recordHeader, EXipv4Flow, ipv4Flow);

        ipv4Flow->srcAddr = u[0];
        ipv4Flow->dstAddr = u[1];

        p = (void *)(p + 2 * sizeof(uint32_t));
    }

    if (TestFlag(commonRecord->flags, FLAG_PKG_64)) {
        // 64bit packet counter
        genericFlow->inPackets = *((uint64_t *)p);
        p = (void *)(p + sizeof(uint64_t));
    } else {
        // 32bit packet counter
        genericFlow->inPackets = *((uint32_t *)p);
        p = (void *)(p + sizeof(uint32_t));
    }

    if (TestFlag(commonRecord->flags, FLAG_BYTES_64)) {
        // 64bit byte counter
        genericFlow->inBytes = *((uint64_t *)p);
        p = (void *)(p + sizeof(uint64_t));
    } else {
        // 32bit bytes counter
        genericFlow->inBytes = *((uint32_t *)p);
        p = (void *)(p + sizeof(uint32_t));
    }

    EXmacAddr_t *macAddr = NULL;  // combine old extensions 21/22
    EXflowMisc_t *_flowMisc = NULL;

    uint64_t msecEvent = 0;
    uint64_t outPackets = 0;
    uint64_t outBytes = 0;
    uint64_t numFlows = 0;
    uint32_t input = 0;
    uint32_t output = 0;

    int i = 0;
    while (extension_map->ex_id[i]) {
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
                input = tpl->input;
                output = tpl->output;
                p = (void *)tpl->data;
            } break;
            case EX_IO_SNMP_4: {
                tpl_ext_5_t *tpl = (tpl_ext_5_t *)p;
                input = tpl->input;
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
                flowMisc->srcMask = tpl->src_mask;
                flowMisc->dstMask = tpl->dst_mask;
                flowMisc->dstTos = tpl->dst_tos;
                flowMisc->dir = tpl->dir;
                flowMisc->biFlowDir = commonRecord->biFlowDir;
                flowMisc->flowEndReason = commonRecord->flowEndReason;
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
                recordHeader->engineID = tpl->engine_id;
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
                PushExtension(recordHeader, EXbgpNextHopV6, bgpNextHopV6);
                bgpNextHopV6->ip[0] = tpl->bgp_nexthop[0];
                bgpNextHopV6->ip[1] = tpl->bgp_nexthop[1];
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
                if (!macAddr) {  // XXX fix
                    PushExtension(recordHeader, EXmacAddr, m);
                    macAddr = m;
                    macAddr->inSrcMac = tpl->in_src_mac;
                    macAddr->outDstMac = tpl->out_dst_mac;
                    macAddr->inDstMac = 0;
                    macAddr->outSrcMac = 0;
                } else {
                    macAddr->inSrcMac = tpl->in_src_mac;
                    macAddr->outDstMac = tpl->out_dst_mac;
                }
                p = (void *)tpl->data;
            } break;
            case EX_MAC_2: {
                tpl_ext_21_t *tpl = (tpl_ext_21_t *)p;
                if (!macAddr) {
                    PushExtension(recordHeader, EXmacAddr, m);
                    macAddr = m;
                    macAddr->inSrcMac = 0;
                    macAddr->outDstMac = 0;
                    macAddr->inDstMac = tpl->in_dst_mac;
                    macAddr->outSrcMac = tpl->out_src_mac;
                } else {
                    macAddr->inDstMac = tpl->in_dst_mac;
                    macAddr->outSrcMac = tpl->out_src_mac;
                }
                p = (void *)tpl->data;
            } break;
            case EX_MPLS: {
                tpl_ext_22_t *tpl = (tpl_ext_22_t *)p;
                PushExtension(recordHeader, EXmplsLabel, mplsLabel);
                for (int j = 0; j < 10; j++) {
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
            case EX_NSEL_COMMON: {
                tpl_ext_37_t *tpl = (tpl_ext_37_t *)p;
                PushExtension(recordHeader, EXnselCommon, nselCommon);
                nselCommon->msecEvent = tpl->event_time;
                msecEvent = tpl->event_time;
                nselCommon->connID = tpl->conn_id;
                nselCommon->fwXevent = tpl->fw_xevent;
                nselCommon->fwEvent = tpl->fw_event;
                genericFlow->dstPort = tpl->nsel_icmp;
                p = (void *)tpl->data;
            } break;
            case EX_NSEL_XLATE_IP_v4: {
                tpl_ext_39_t *tpl = (tpl_ext_39_t *)p;
                PushExtension(recordHeader, EXnselXlateIPv4, nselXlateIPv4);
                nselXlateIPv4->xlateSrcAddr = tpl->xlate_src_ip;
                nselXlateIPv4->xlateDstAddr = tpl->xlate_dst_ip;
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
                tpl->username[65] = '\0';  // truncate old username
                strncpy((void *)nselUser->username, (void *)tpl->username, 65);
                nselUser->username[65] = '\0';
                p = (void *)tpl->data;
            } break;
            case EX_NSEL_USER: {
                tpl_ext_42_t *tpl = (tpl_ext_42_t *)p;
                PushExtension(recordHeader, EXnselUser, nselUser);
                strncpy((void *)nselUser->username, (void *)tpl->username, 65);
                nselUser->username[65] = '\0';
                p = (void *)tpl->data;
            } break;
            case EX_NEL_COMMON: {
                tpl_ext_46_t *tpl = (tpl_ext_46_t *)p;
                PushExtension(recordHeader, EXnelCommon, nelCommon);
                nelCommon->natEvent = tpl->nat_event;
                PushExtension(recordHeader, EXvrf, vrf);
                vrf->egressVrf = tpl->egress_vrfid;
                vrf->ingressVrf = tpl->ingress_vrfid;
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
                nelXlatePort->blockEnd = tpl->block_end;
                nelXlatePort->blockStep = tpl->block_step;
                nelXlatePort->blockSize = tpl->block_size;
                if (nelXlatePort->blockEnd == 0 && nelXlatePort->blockSize != 0)
                    nelXlatePort->blockEnd = nelXlatePort->blockStart + nelXlatePort->blockSize - 1;
                p = (void *)tpl->data;
            } break;
        }
    }

    if (outPackets || outBytes || numFlows) {
        PushExtension(recordHeader, EXcntFlow, cntFlow);
        cntFlow->outPackets = outPackets;
        cntFlow->outBytes = outBytes;
        cntFlow->flows = numFlows;
    }

    if (input || output) {
        if (_flowMisc) {
            _flowMisc->input = input;
            _flowMisc->output = output;
        } else {
            PushExtension(recordHeader, EXflowMisc, flowMisc);
            flowMisc->input = input;
            flowMisc->output = output;
        }
    }

    if (genericFlow && genericFlow->msecFirst == 0 && msecEvent) {
        genericFlow->msecFirst = msecEvent;
    }

    dataBlock->NumRecords++;
    dataBlock->size += recordHeader->size;

    // dbg_printf("V3 record: elements: %u, size: %u\n", recordHeader->numElements, recordHeader->size);
    return 1;

}  // End of ConvertRecordV2

void ConvertBlockType2(dataBlock_t *v2DataBlock, dataBlock_t *v3DataBlock) {
    record_header_t *v2record_ptr = GetCursor(v2DataBlock);
    uint32_t sumSize = 0;
    uint32_t commonRecords = 0;
    for (int i = 0; i < v2DataBlock->NumRecords; i++) {
        if ((sumSize + v2record_ptr->size) > v2DataBlock->size || (v2record_ptr->size < sizeof(record_header_t))) {
            LogError("Corrupt data file. Inconsistent block size in %s line %d\n", __FILE__, __LINE__);
            sumSize = 0;
            break;
        }

        switch (v2record_ptr->type) {
            case CommonRecordType: {
                ConvertRecordV2((common_record_t *)v2record_ptr, v3DataBlock);
                commonRecords++;
            } break;
            case ExtensionMapType: {
                InitCompat16();
                extension_map_t *map = (extension_map_t *)v2record_ptr;
                if (Insert_Extension_Map(extension_map_list, map) < 0) {
                    LogError("Corrupt data file. Unable to decode at %s line %d\n", __FILE__, __LINE__);
                    exit(EXIT_FAILURE);
                }
            } break;
            // other records just copy
            case ExporterInfoRecordType:
            case ExporterStatRecordType:
            case SamplerLegacyRecordType: {
                void *ptr = GetCurrentCursor(v3DataBlock);
                memcpy(ptr, v2record_ptr, v2record_ptr->size);
                v3DataBlock->NumRecords++;
                v3DataBlock->size += v2record_ptr->size;
            } break;
            default: {
                printf("Convert v2 block: Unknown record type %i skipped\n", v2record_ptr->type);
            }
        }

        // Advance pointer by number of bytes for netflow record
        v2record_ptr = (record_header_t *)((void *)v2record_ptr + v2record_ptr->size);
    }

}  // End of ConvertBlockType2
