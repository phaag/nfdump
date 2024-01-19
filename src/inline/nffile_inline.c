/*
 *  Copyright (c) 2009-2023, Peter Haag
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

static inline size_t CheckBufferSpace(nffile_t *nffile, size_t required);

static inline void AppendToBuffer(nffile_t *nffile, void *record, size_t required);

static inline void MapRecordHandle(recordHandle_t *handle, recordHeaderV3_t *recordHeaderV3, uint32_t flowCount);

static inline void ClearMasterRecord(master_record_t *record);

static inline void ExpandRecord_v3(recordHeaderV3_t *v3Record, master_record_t *output_record);

#ifdef NEED_PACKRECORD
static void PackRecordV3(master_record_t *master_record, nffile_t *nffile);
#endif

static inline size_t CheckBufferSpace(nffile_t *nffile, size_t required) {
    // if actual output size is unknown, make sure at least
    // MAXRECORDSIZE is available
    if (required == 0) {
        required = MAXRECORDSIZE;
    }
    dbg_printf("Buffer Size %u, check for %zu\n", nffile->block_header->size, required);

    // flush current buffer to disc
    if ((nffile->block_header->size + required) > WRITE_BUFFSIZE) {
        if (required > WRITE_BUFFSIZE) {
            // this should never happen, but catch it anyway
            LogError("Required buffer size %zu too big for output buffer!", required);
            return 0;
        }

        if (WriteBlock(nffile) <= 0) {
            LogError("Failed to write output buffer to disk: '%s'", strerror(errno));
            return 0;
        }
    }

    dbg_printf("CheckBuffer returns %u\n", WRITE_BUFFSIZE - nffile->block_header->size);
    return WRITE_BUFFSIZE - nffile->block_header->size;

}  // End of CheckBufferSpace

static inline void MapRecordHandle(recordHandle_t *handle, recordHeaderV3_t *recordHeaderV3, uint32_t flowCount) {
    handle->recordHeaderV3 = recordHeaderV3;

    elementHeader_t *elementHeader = (elementHeader_t *)((void *)recordHeaderV3 + sizeof(recordHeaderV3_t));
    // map all extensions
    for (int i = 0; i < recordHeaderV3->numElements; i++) {
        if (elementHeader->type < MAXEXTENSIONS) {
            handle->extensionList[elementHeader->type] = (void *)elementHeader + sizeof(elementHeader_t);
            elementHeader = (elementHeader_t *)((void *)elementHeader + elementHeader->length);
            handle->elementsBits |= 1 << elementHeader->type;
        } else {
            LogError("Unknown extension '%u'", elementHeader->type);
        }
    }
    handle->extensionList[EXnull] = (void *)recordHeaderV3;
    handle->extensionList[EXlocal] = (void *)handle;
    handle->flowCount = flowCount;
    handle->numElements = recordHeaderV3->numElements;

    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)handle->extensionList[EXgenericFlowID];
    if (genericFlow->msecFirst == 0) {
        EXnselCommon_t *nselCommon = (EXnselCommon_t *)handle->extensionList[EXnselCommonID];
        if (nselCommon) {
            genericFlow->msecFirst = nselCommon->msecEvent;
        } else {
            EXnelCommon_t *nelCommon = (EXnelCommon_t *)handle->extensionList[EXnelCommonID];
            genericFlow->msecFirst = nelCommon->msecEvent;
        }
    }
}

static inline void ClearMasterRecord(master_record_t *record) {
    if (record->inPayload) free(record->inPayload);
    if (record->outPayload) free(record->outPayload);
    memset((void *)record, 0, sizeof(master_record_t));
}  // End of ClearMasterRecord

static inline void ExpandRecord_v3(recordHeaderV3_t *v3Record, master_record_t *output_record) {
    elementHeader_t *elementHeader;
    uint32_t size = sizeof(recordHeaderV3_t);

    void *p = (void *)v3Record;
    void *eor = p + v3Record->size;

    // set map ref
    output_record->exp_ref = NULL;

    output_record->size = v3Record->size;
    output_record->flags = v3Record->flags;
    output_record->mflags = 0;
    output_record->exporter_sysid = v3Record->exporterID;
    output_record->numElements = v3Record->numElements;
    output_record->engine_type = v3Record->engineType;
    output_record->engine_id = v3Record->engineID;
    output_record->nfversion = v3Record->nfversion;

    if (v3Record->size < size) {
        LogError("ExpandRecord_v3() Unexpected size: '%u'", v3Record->size);
        abort();
    }

    int compatVRF = 0;
    dbg_printf("Record announces %u extensions with total size %u\n", v3Record->numElements, v3Record->size);
    // first record header
    elementHeader = (elementHeader_t *)(p + sizeof(recordHeaderV3_t));
    for (int i = 0; i < v3Record->numElements; i++) {
        dbg_printf("[%i] next extension: %u: %s\n", i, elementHeader->type,
                   elementHeader->type < MAXEXTENSIONS ? extensionTable[elementHeader->type].name : "<unknown>");
        switch (elementHeader->type) {
            case EXnull:
                fprintf(stderr, "ExpandRecord_v3() Found unexpected NULL extension\n");
                break;
            case EXgenericFlowID: {
                EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)((void *)elementHeader + sizeof(elementHeader_t));
                output_record->msecFirst = genericFlow->msecFirst;
                output_record->msecLast = genericFlow->msecLast;
                output_record->msecReceived = genericFlow->msecReceived;
                output_record->inPackets = genericFlow->inPackets;
                output_record->inBytes = genericFlow->inBytes;
                output_record->srcPort = genericFlow->srcPort;
                output_record->dstPort = genericFlow->dstPort;
                output_record->proto = genericFlow->proto;
                output_record->tcp_flags = genericFlow->tcpFlags;
                output_record->fwd_status = genericFlow->fwdStatus;
                output_record->tos = genericFlow->srcTos;
            } break;
            case EXipv4FlowID: {
                EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)((void *)elementHeader + sizeof(elementHeader_t));
                output_record->V6.srcaddr[0] = 0;
                output_record->V6.srcaddr[1] = 0;
                output_record->V4.srcaddr = ipv4Flow->srcAddr;

                output_record->V6.dstaddr[0] = 0;
                output_record->V6.dstaddr[1] = 0;
                output_record->V4.dstaddr = ipv4Flow->dstAddr;
            } break;
            case EXipv6FlowID: {
                EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)((void *)elementHeader + sizeof(elementHeader_t));

                output_record->V6.srcaddr[0] = ipv6Flow->srcAddr[0];
                output_record->V6.srcaddr[1] = ipv6Flow->srcAddr[1];
                output_record->V6.dstaddr[0] = ipv6Flow->dstAddr[0];
                output_record->V6.dstaddr[1] = ipv6Flow->dstAddr[1];

                SetFlag(output_record->mflags, V3_FLAG_IPV6_ADDR);
            } break;
            case EXflowMiscID: {
                EXflowMisc_t *flowMisc = (EXflowMisc_t *)((void *)elementHeader + sizeof(elementHeader_t));
                output_record->dir = flowMisc->dir;
                output_record->dst_tos = flowMisc->dstTos;
                output_record->src_mask = flowMisc->srcMask;
                output_record->dst_mask = flowMisc->dstMask;
                output_record->input = flowMisc->input;
                output_record->output = flowMisc->output;
                output_record->biFlowDir = flowMisc->biFlowDir;
                output_record->flowEndReason = flowMisc->flowEndReason;
                output_record->fragmentFlags = flowMisc->fragmentFlags;
            } break;
            case EXcntFlowID: {
                EXcntFlow_t *cntFlow = (EXcntFlow_t *)((void *)elementHeader + sizeof(elementHeader_t));
                output_record->out_pkts = cntFlow->outPackets;
                output_record->out_bytes = cntFlow->outBytes;
                output_record->aggr_flows = cntFlow->flows;
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
                output_record->bgp_nexthop.V4 = bgpNextHopV4->ip;
            } break;
            case EXbgpNextHopV6ID: {
                EXbgpNextHopV6_t *bgpNextHopV6 = (EXbgpNextHopV6_t *)((void *)elementHeader + sizeof(elementHeader_t));
                output_record->bgp_nexthop.V6[0] = bgpNextHopV6->ip[0];
                output_record->bgp_nexthop.V6[1] = bgpNextHopV6->ip[1];
                SetFlag(output_record->mflags, V3_FLAG_IPV6_NHB);
            } break;
            case EXipNextHopV4ID: {
                EXipNextHopV4_t *ipNextHopV4 = (EXipNextHopV4_t *)((void *)elementHeader + sizeof(elementHeader_t));
                output_record->ip_nexthop.V6[0] = 0;
                output_record->ip_nexthop.V6[1] = 0;
                output_record->ip_nexthop.V4 = ipNextHopV4->ip;
            } break;
            case EXipNextHopV6ID: {
                EXipNextHopV6_t *ipNextHopV6 = (EXipNextHopV6_t *)((void *)elementHeader + sizeof(elementHeader_t));
                output_record->ip_nexthop.V6[0] = ipNextHopV6->ip[0];
                output_record->ip_nexthop.V6[1] = ipNextHopV6->ip[1];
                SetFlag(output_record->mflags, V3_FLAG_IPV6_NH);
            } break;
            case EXipReceivedV4ID: {
                EXipNextHopV4_t *ipNextHopV4 = (EXipNextHopV4_t *)((void *)elementHeader + sizeof(elementHeader_t));
                output_record->ip_router.V6[0] = 0;
                output_record->ip_router.V6[1] = 0;
                output_record->ip_router.V4 = ipNextHopV4->ip;
            } break;
            case EXipReceivedV6ID: {
                EXipReceivedV6_t *ipReceivedV6 = (EXipReceivedV6_t *)((void *)elementHeader + sizeof(elementHeader_t));
                output_record->ip_router.V6[0] = ipReceivedV6->ip[0];
                output_record->ip_router.V6[1] = ipReceivedV6->ip[1];
                SetFlag(output_record->mflags, V3_FLAG_IPV6_EXP);
            } break;
            case EXmplsLabelID: {
                EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)((void *)elementHeader + sizeof(elementHeader_t));
                for (int j = 0; j < 10; j++) {
                    output_record->mpls_label[j] = mplsLabel->mplsLabel[j];
                }
            } break;
            case EXmacAddrID: {
                EXmacAddr_t *macAddr = (EXmacAddr_t *)((void *)elementHeader + sizeof(elementHeader_t));
                output_record->in_src_mac = macAddr->inSrcMac;
                output_record->out_dst_mac = macAddr->outDstMac;
                output_record->in_dst_mac = macAddr->inDstMac;
                output_record->out_src_mac = macAddr->outSrcMac;
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
            case EXsamplerInfoID: {
                EXsamplerInfo_t *samplerInfo = (EXsamplerInfo_t *)((void *)elementHeader + sizeof(elementHeader_t));
                output_record->exporterSampler = samplerInfo->exporter_sysid;
                output_record->selectorID = samplerInfo->selectorID;
            } break;
            case EXobservationID: {
                EXobservation_t *observation = (EXobservation_t *)((void *)elementHeader + sizeof(elementHeader_t));
                output_record->observationDomainID = observation->domainID;
                output_record->observationPointID = observation->pointID;
            } break;
            case EXvrfID: {
                EXvrf_t *vrf = (EXvrf_t *)((void *)elementHeader + sizeof(elementHeader_t));
                output_record->egressVrf = vrf->egressVrf;
                output_record->ingressVrf = vrf->ingressVrf;
            } break;

#ifdef NSEL
            case EXnselCommonID: {
                EXnselCommon_t *nselCommon = (EXnselCommon_t *)((void *)elementHeader + sizeof(elementHeader_t));
                output_record->event_flag = FW_EVENT;
                output_record->connID = nselCommon->connID;
                output_record->event = nselCommon->fwEvent;
                output_record->fwXevent = nselCommon->fwXevent;
                output_record->msecEvent = nselCommon->msecEvent;
            } break;
            case EXnselXlateIPv4ID: {
                EXnselXlateIPv4_t *nselXlateIPv4 = (EXnselXlateIPv4_t *)((void *)elementHeader + sizeof(elementHeader_t));
                output_record->xlate_src_ip.V6[0] = 0;
                output_record->xlate_src_ip.V6[1] = 0;
                output_record->xlate_src_ip.V4 = nselXlateIPv4->xlateSrcAddr;
                output_record->xlate_dst_ip.V6[0] = 0;
                output_record->xlate_dst_ip.V6[1] = 0;
                output_record->xlate_dst_ip.V4 = nselXlateIPv4->xlateDstAddr;
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
                output_record->ingressAcl[0] = ntohl(nselAcl->ingressAcl[0]);
                output_record->ingressAcl[1] = ntohl(nselAcl->ingressAcl[1]);
                output_record->ingressAcl[2] = ntohl(nselAcl->ingressAcl[2]);
                output_record->egressAcl[0] = ntohl(nselAcl->egressAcl[0]);
                output_record->egressAcl[1] = ntohl(nselAcl->egressAcl[1]);
                output_record->egressAcl[2] = ntohl(nselAcl->egressAcl[2]);
            } break;
            case EXnselUserID: {
                EXnselUser_t *nselUser = (EXnselUser_t *)((void *)elementHeader + sizeof(elementHeader_t));
                memcpy(output_record->username, nselUser->username, 66);
            } break;
            case EXnelCommonID: {
                // check for compat record in older files
                if (elementHeader->length == EXnelCommonCompatSize) {
                    EXnelCommonCompat_t *nelCommon = (EXnelCommonCompat_t *)((void *)elementHeader + sizeof(elementHeader_t));
                    output_record->msecEvent = nelCommon->msecEvent;
                    output_record->event = nelCommon->natEvent;
                    output_record->event_flag = NAT_EVENT;
                    output_record->egressVrf = nelCommon->egressVrf;
                    output_record->ingressVrf = nelCommon->ingressVrf;
                    compatVRF = 1;
                } else {
                    EXnelCommon_t *nelCommon = (EXnelCommon_t *)((void *)elementHeader + sizeof(elementHeader_t));
                    output_record->msecEvent = nelCommon->msecEvent;
                    output_record->event = nelCommon->natEvent;
                    output_record->event_flag = NAT_EVENT;
                }
            } break;
            case EXnelXlatePortID: {
                EXnelXlatePort_t *nelXlatePort = (EXnelXlatePort_t *)((void *)elementHeader + sizeof(elementHeader_t));
                output_record->block_start = nelXlatePort->blockStart;
                output_record->block_end = nelXlatePort->blockEnd;
                output_record->block_step = nelXlatePort->blockStep;
                output_record->block_size = nelXlatePort->blockSize;
            } break;
#else
            case EXnelCommonID:
                // check for compat record in older files
                if (elementHeader->length == EXnelCommonCompatSize) {
                    EXnelCommonCompat_t *nelCommon = (EXnelCommonCompat_t *)((void *)elementHeader + sizeof(elementHeader_t));
                    output_record->egressVrf = nelCommon->egressVrf;
                    output_record->ingressVrf = nelCommon->ingressVrf;
                    // we use only vrf info - so pretend new EXvrfID
                    elementHeader->type = EXvrfID;
                } else {
                    LogError("Skip nsel extension: '%u' - nsel options not compiled", elementHeader->type);
                }
                break;
            case EXnselCommonID:
            case EXnselXlateIPv4ID:
            case EXnselXlateIPv6ID:
            case EXnselXlatePortID:
            case EXnselAclID:
            case EXnselUserID:
            case EXnelXlatePortID:
                LogError("Skip nsel extension: '%u' - nsel options not compiled", elementHeader->type);
                break;
#endif
            case EXnbarAppID: {
                EXnbarApp_t *EXnbarApp = (EXnbarApp_t *)((void *)elementHeader + sizeof(elementHeader_t));
                // the byte array is stored in full length
                // we support up to MAX_NBAR_LENGTH bytes - skip everything else
                if (elementHeader->length > (MAX_NBAR_LENGTH + sizeof(elementHeader_t))) {  // 15 + 4 header
                    LogError("nbar application ID length %u > %u bytes not supported", elementHeader->length - sizeof(elementHeader_t),
                             MAX_NBAR_LENGTH);
                } else {
                    memcpy(output_record->nbarAppID, EXnbarApp->id, elementHeader->length - sizeof(elementHeader_t));
                    output_record->nbarAppIDlen = elementHeader->length - sizeof(elementHeader_t);
                }
            } break;
            case EXlabelID: {
                char *label = (char *)((void *)elementHeader + sizeof(elementHeader_t));
                int labelLength = elementHeader->length - sizeof(elementHeader_t);
                if (labelLength <= 0) {
                    LogError("Invalid label data length");
                    output_record->label = NULL;
                } else {
                    output_record->label = malloc(labelLength);
                    memcpy(output_record->label, label, labelLength);
                    output_record->label[labelLength - 1] = '\0';
                }
            } break;
            case EXinPayloadID: {
                void *data = (void *)((void *)elementHeader + sizeof(elementHeader_t));
                int dataLength = elementHeader->length - sizeof(elementHeader_t);
                if (dataLength <= 0) {
                    LogError("Invalid payload data length");
                    output_record->inPayloadLength = 0;
                    output_record->inPayload = NULL;
                } else {
                    output_record->inPayloadLength = dataLength;
                    output_record->inPayload = malloc(dataLength);
                    memcpy(output_record->inPayload, data, dataLength);
                }
            } break;
            case EXoutPayloadID: {
                void *data = (void *)((void *)elementHeader + sizeof(elementHeader_t));
                int dataLength = elementHeader->length - sizeof(elementHeader_t);
                if (dataLength <= 0) {
                    LogError("Invalid payload data length");
                    output_record->outPayloadLength = 0;
                    output_record->outPayload = NULL;
                } else {
                    output_record->outPayloadLength = dataLength;
                    output_record->outPayload = malloc(dataLength);
                    memcpy(output_record->outPayload, data, dataLength);
                }
            } break;
            case EXtunIPv4ID: {
                EXtunIPv4_t *tunIPv4 = (EXtunIPv4_t *)((void *)elementHeader + sizeof(elementHeader_t));
                output_record->tun_src_ip.V6[0] = 0;
                output_record->tun_src_ip.V6[1] = 0;
                output_record->tun_dst_ip.V6[0] = 0;
                output_record->tun_dst_ip.V6[1] = 0;
                output_record->tun_src_ip.V4 = tunIPv4->tunSrcAddr;
                output_record->tun_dst_ip.V4 = tunIPv4->tunDstAddr;
                output_record->tun_ip_version = 4;
                output_record->tun_proto = tunIPv4->tunProto;
            } break;
            case EXtunIPv6ID: {
                EXtunIPv6_t *tunIPv6 = (EXtunIPv6_t *)((void *)elementHeader + sizeof(elementHeader_t));
                memcpy(output_record->tun_src_ip.V6, &(tunIPv6->tunSrcAddr), 16);
                memcpy(output_record->tun_dst_ip.V6, &(tunIPv6->tunDstAddr), 16);
                output_record->tun_ip_version = 6;
                output_record->tun_proto = tunIPv6->tunProto;
            } break;
            case EXpfinfoID: {
                EXpfinfo_t *pfinfo = (EXpfinfo_t *)((void *)elementHeader + sizeof(elementHeader_t));
                output_record->pfAction = pfinfo->action;
                output_record->pfReason = pfinfo->reason;
                output_record->pfDir = pfinfo->dir;
                output_record->pfRewritten = pfinfo->rewritten;
                output_record->pfRulenr = pfinfo->rulenr;
                size_t nameLen = sizeof(output_record->pfIfName);
                strncpy(output_record->pfIfName, pfinfo->ifname, nameLen);
                output_record->pfIfName[nameLen - 1] = '\0';
            } break;
            default:
                LogError("Unknown extension '%u'", elementHeader->type);
        }

        // unordered element list
        // insert element in order to list
        int j = 0;
        uint32_t val = elementHeader->type;
        while (j < i) {
            if (val < output_record->exElementList[j]) {
                uint32_t _tmp = output_record->exElementList[j];
                output_record->exElementList[j] = val;
                val = _tmp;
            }
            j++;
        }
        output_record->exElementList[j] = val;

        size += elementHeader->length;
        elementHeader = (elementHeader_t *)((void *)elementHeader + elementHeader->length);

        if ((void *)elementHeader > eor) {
            fprintf(stderr, "ptr error - elementHeader > eor\n");
            exit(255);
        }
    }
    // map icmp type/code in it's own vars
    if (size != v3Record->size) {
        LogError("Record size info: '%u' not equal sum extensions: '%u'", v3Record->size, size);
        exit(255);
    }

    // at least one flow
    if (output_record->aggr_flows == 0) output_record->aggr_flows = 1;

    // old EXnelCommon was split into separate vrf extension. So add EXvrf
    // to be removed 2023 - get rid of compat code
    if (compatVRF) {
        int j = 0;
        uint32_t val = EXvrfID;
        printf("insert EXvrf: %u\n", val);
        while (j < output_record->numElements) {
            if (val < output_record->exElementList[j]) {
                uint32_t _tmp = output_record->exElementList[j];
                output_record->exElementList[j] = val;
                val = _tmp;
            }
            j++;
        }
        output_record->exElementList[j] = val;
        output_record->numElements++;
    }

#ifdef NSEL
    if (output_record->msecFirst == 0) output_record->msecFirst = output_record->msecEvent;
    if (output_record->msecLast == 0) output_record->msecLast = output_record->msecEvent;
#endif

#ifdef DEVEL
    printf("Ordered extensions: %u\n", output_record->numElements);
    for (int i = 0; i <= output_record->numElements; i++) {
        int type = output_record->exElementList[i];
        printf("[%i] next extension: %u: %s\n", i, type, type < MAXEXTENSIONS ? extensionTable[type].name : "<unknown>");
    }
#endif

    if (output_record->numElements > MAXEXTENSIONS) {
        LogError("Number of elements %u exceeds max number defined %u", output_record->numElements, MAXEXTENSIONS);
        exit(255);
    }
}  // End of ExpandRecord_v3

static inline void AppendToBuffer(nffile_t *nffile, void *record, size_t required) {
    // flush current buffer to disc
    if (!CheckBufferSpace(nffile, required)) {
        return;
    }

    // enough buffer space available at this point
    memcpy(nffile->buff_ptr, record, required);

    // update stat
    nffile->block_header->NumRecords++;
    nffile->block_header->size += required;

    // advance write pointer
    nffile->buff_ptr = (void *)((pointer_addr_t)nffile->buff_ptr + required);

}  // End of AppendToBuffer
