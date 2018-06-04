/*
 *  Copyright (c) 2017, Peter Haag
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
 */


// to improve readability - separate some code blocks in functions and make them inline
// as it's called for every single flow
static inline void UpdateStat(stat_record_t	*stat_record, master_record_t *master_record);

static inline void UpdateStat(stat_record_t	*stat_record, master_record_t *master_record) {

	switch (master_record->prot) {
		case IPPROTO_ICMP:
		case IPPROTO_ICMPV6:
			stat_record->numflows_icmp   += master_record->aggr_flows ? master_record->aggr_flows : 1;
			stat_record->numpackets_icmp += master_record->dPkts;
			stat_record->numpackets_icmp += master_record->out_pkts;
			stat_record->numbytes_icmp   += master_record->dOctets;
			stat_record->numbytes_icmp   += master_record->out_bytes;
			break;
		case IPPROTO_TCP:
			stat_record->numflows_tcp   += master_record->aggr_flows ? master_record->aggr_flows : 1;
			stat_record->numpackets_tcp += master_record->dPkts;
			stat_record->numpackets_tcp += master_record->out_pkts;
			stat_record->numbytes_tcp   += master_record->dOctets;
			stat_record->numbytes_tcp   += master_record->out_bytes;
			break;
		case IPPROTO_UDP:
			stat_record->numflows_udp   += master_record->aggr_flows ? master_record->aggr_flows : 1;
			stat_record->numpackets_udp += master_record->dPkts;
			stat_record->numpackets_udp += master_record->out_pkts;
			stat_record->numbytes_udp   += master_record->dOctets;
			stat_record->numbytes_udp   += master_record->out_bytes;
			break;
		default:
			stat_record->numflows_other   += master_record->aggr_flows ? master_record->aggr_flows : 1;
			stat_record->numpackets_other += master_record->dPkts;
			stat_record->numpackets_other += master_record->out_pkts;
			stat_record->numbytes_other   += master_record->dOctets;
			stat_record->numbytes_other   += master_record->out_bytes;
	}
	stat_record->numflows   += master_record->aggr_flows ? master_record->aggr_flows : 1;
	stat_record->numpackets	+= master_record->dPkts;
	stat_record->numpackets	+= master_record->out_pkts;
	stat_record->numbytes 	+= master_record->dOctets;
	stat_record->numbytes 	+= master_record->out_bytes;

	if ( master_record->first < stat_record->first_seen ) {
		stat_record->first_seen = master_record->first;
		stat_record->msec_first = master_record->msec_first;
	}
	if ( master_record->first == stat_record->first_seen && 
	 	master_record->msec_first < stat_record->msec_first ) 
			stat_record->msec_first = master_record->msec_first;

	if ( master_record->last > stat_record->last_seen ) {
		stat_record->last_seen = master_record->last;
		stat_record->msec_last = master_record->msec_last;
	}
	if ( master_record->last == stat_record->last_seen && 
	 	master_record->msec_last > stat_record->msec_last ) 
			stat_record->msec_last = master_record->msec_last;

} // End of UpdateStat
