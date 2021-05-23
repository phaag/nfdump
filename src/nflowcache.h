/*
 *  Copyright (c) 2009-2021, Peter Haag
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
 *   * Neither the name of the auhor nor the names of its contributors may be 
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

#ifndef _NFLOWCACHE_H
#define _NFLOWCACHE_H 1

#include "config.h"

#include <sys/types.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nffile.h"
#include "output_util.h"

#define NeedSwap(GuessDir, r) ( GuessDir && \
	((r)->proto == IPPROTO_TCP || (r)->proto == IPPROTO_UDP) && \
	 ((((r)->srcPort < 1024) && ((r)->dstPort >= 1024)) || \
	  (((r)->srcPort < 32768) && ((r)->dstPort >= 32768)) || \
	  (((r)->srcPort < 49152) && ((r)->dstPort >= 49152)) \
	 ) \
	)

#define SwapFlow(r) { \
uint64_t _tmp_ip[2]; \
uint64_t _tmp_l;	\
uint32_t _tmp;	\
	\
	_tmp_ip[0] = (r)->V6.srcaddr[0];	\
	_tmp_ip[1] = (r)->V6.srcaddr[1];	\
	(r)->V6.srcaddr[0] = (r)->V6.dstaddr[0];	\
	(r)->V6.srcaddr[1] = (r)->V6.dstaddr[1];	\
	(r)->V6.dstaddr[0] = _tmp_ip[0];	\
	(r)->V6.dstaddr[1] = _tmp_ip[1];	\
	\
	_tmp = (r)->srcPort;	\
	(r)->srcPort = (r)->dstPort;	\
	(r)->dstPort = _tmp;	\
	\
	_tmp = (r)->srcas;	\
	(r)->srcas = (r)->dstas;	\
	(r)->dstas = _tmp;	\
	\
	_tmp = (r)->input;	\
	(r)->input = (r)->output;	\
	(r)->output = _tmp;	\
	\
	_tmp_l = (r)->inPackets;	\
	(r)->inPackets = (r)->out_pkts;	\
	(r)->out_pkts = _tmp_l;	\
	\
	_tmp_l = (r)->inBytes;	\
	(r)->inBytes = (r)->out_bytes;	\
	(r)->out_bytes = _tmp_l;	\
}

#define SwapRawFlow(genericFlow, ipv4Flow, ipv6Flow, flowMisc, cntFlow, asRouting) { \
	if (ipv4Flow) {	\
		uint32_t _tmp = ipv4Flow->srcAddr; \
		ipv4Flow->srcAddr = ipv4Flow->dstAddr; \
		ipv4Flow->dstAddr = _tmp; \
	} else if (ipv6Flow) { \
		uint64_t _tmp_ip[2]; \
		_tmp_ip[0] = ipv6Flow->srcAddr[0];	\
		_tmp_ip[1] = ipv6Flow->srcAddr[1];	\
		ipv6Flow->srcAddr[0] = ipv6Flow->dstAddr[0];	\
		ipv6Flow->srcAddr[1] = ipv6Flow->dstAddr[1];	\
		ipv6Flow->dstAddr[0] = _tmp_ip[0];	\
		ipv6Flow->dstAddr[1] = _tmp_ip[1];	\
	} \
	if (genericFlow) { \
		uint16_t _tmp = genericFlow->srcPort;	\
		genericFlow->srcPort = genericFlow->dstPort;	\
		genericFlow->dstPort = _tmp;	\
	} \
	if (asRouting) {	\
		uint32_t _tmp = asRouting->srcAS;	\
		asRouting->srcAS = asRouting->dstAS;	\
		asRouting->dstAS = _tmp;	\
	}	\
	if (flowMisc) {	\
		uint32_t _tmp = flowMisc->input;	\
		flowMisc->input = flowMisc->output;	\
		flowMisc->output = _tmp;	\
		uint8_t mask = flowMisc->srcMask;	\
		flowMisc->srcMask = flowMisc->dstMask;	\
		flowMisc->dstMask = mask;	\
	}	\
	if (genericFlow && cntFlow) {	\
		uint64_t _tmp = genericFlow->inPackets;	\
		genericFlow->inPackets = cntFlow->outPackets;	\
		cntFlow->outPackets = _tmp;	\
		_tmp = genericFlow->inBytes;	\
		genericFlow->inBytes = cntFlow->outBytes;	\
		cntFlow->outBytes = _tmp;	\
	}	\
}

typedef struct SortElement {
    void        *record;
    uint64_t    count;
} SortElement_t;

int Init_FlowCache(void);

void Dispose_FlowTable(void);

int Parse_PrintOrder(char *order);

char *ParseAggregateMask(char *arg);

int SetBidirAggregation(void);

void Add_FlowStatOrder(uint32_t order, uint32_t direction);

int SetStat(char *str, int *element_stat, int *flow_stat);

void InsertFlow(void *raw_record, master_record_t *flow_record);

void AddFlowCache(void *raw_record, master_record_t *flow_record);

void PrintFlowTable(printer_t print_record, outputParams_t *outputParams, int GuessDir);

void PrintFlowStat(func_prolog_t record_header, printer_t print_record, outputParams_t *outputParams);

int ExportFlowTable(nffile_t *nffile, int aggregate, int bidir, int GuessDir);

#endif //_NFLOWCACHE_H
