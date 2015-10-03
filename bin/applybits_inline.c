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
 *  $Author: haag $
 *
 *  $Id: applybits_inline.c 39 2009-11-25 08:11:15Z haag $
 *
 *  $LastChangedRevision: 39 $
 *  
 */

static inline void ApplyNetMaskBits(master_record_t *flow_record, int apply_netbits);

static inline void ApplyNetMaskBits(master_record_t *flow_record, int apply_netbits) {

		if ( (flow_record->flags & FLAG_IPV6_ADDR ) != 0 ) { // IPv6
			if ( apply_netbits & 1 ) {
				uint64_t mask;
				uint32_t mask_bits = flow_record->src_mask;
				if ( mask_bits > 64 ) {
                    mask = 0xffffffffffffffffLL << ( 128 - mask_bits );
					flow_record->v6.srcaddr[1] &= mask;
                } else {
                    mask = 0xffffffffffffffffLL << ( 64 - mask_bits );
					flow_record->v6.srcaddr[0] &= mask;
					flow_record->v6.srcaddr[1] = 0;
                }
			}
			if ( apply_netbits & 2 ) {
				uint64_t mask;
				uint32_t mask_bits = flow_record->dst_mask;

				if ( mask_bits > 64 ) {
                    mask = 0xffffffffffffffffLL << ( 128 - mask_bits );
					flow_record->v6.dstaddr[1] &= mask;
                } else {
                    mask = 0xffffffffffffffffLL << ( 64 - mask_bits );
					flow_record->v6.dstaddr[0] &= mask;
					flow_record->v6.dstaddr[1] = 0;
                }
			}
		} else { // IPv4
			if ( apply_netbits & 1 ) {
				uint32_t srcmask = 0xffffffff << ( 32 - flow_record->src_mask );
				flow_record->v4.srcaddr &= srcmask;
			}
			if ( apply_netbits & 2 ) {
				uint32_t dstmask = 0xffffffff << ( 32 - flow_record->dst_mask );
				flow_record->v4.dstaddr &= dstmask;
			}
		}

} // End of ApplyNetMaskBits

static inline void ApplyAggrMask(master_record_t *record, master_record_t *mask) {
uint64_t *r = (uint64_t *)record;
uint64_t *m = (uint64_t *)mask;
int i, max_offset;

	max_offset = offsetof(master_record_t, map_ref) >> 3;
	for (i=2; i<max_offset; i++) {
		r[i] &= m[i];
	}

} // End of ApplyAggrMask
