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
 *
 */

static inline void ApplyNetMaskBits(master_record_t *flow_record, int apply_netbits);

static inline void ApplyNetMaskBits(master_record_t *flow_record, int apply_netbits) {
    if ((flow_record->mflags & V3_FLAG_IPV6_ADDR) != 0) {  // IPv6
        if (apply_netbits & 1) {
            uint64_t mask;
            uint32_t mask_bits = flow_record->src_mask;
            if (mask_bits > 64) {
                mask = 0xffffffffffffffffLL << (128 - mask_bits);
                flow_record->V6.srcaddr[1] &= mask;
            } else {
                mask = 0xffffffffffffffffLL << (64 - mask_bits);
                flow_record->V6.srcaddr[0] &= mask;
                flow_record->V6.srcaddr[1] = 0;
            }
        }
        if (apply_netbits & 2) {
            uint64_t mask;
            uint32_t mask_bits = flow_record->dst_mask;

            if (mask_bits > 64) {
                mask = 0xffffffffffffffffLL << (128 - mask_bits);
                flow_record->V6.dstaddr[1] &= mask;
            } else {
                mask = 0xffffffffffffffffLL << (64 - mask_bits);
                flow_record->V6.dstaddr[0] &= mask;
                flow_record->V6.dstaddr[1] = 0;
            }
        }
    } else {  // IPv4
        if (apply_netbits & 1) {
            uint32_t srcmask = 0xffffffff << (32 - flow_record->src_mask);
            flow_record->V4.srcaddr &= srcmask;
        }
        if (apply_netbits & 2) {
            uint32_t dstmask = 0xffffffff << (32 - flow_record->dst_mask);
            flow_record->V4.dstaddr &= dstmask;
        }
    }

}  // End of ApplyNetMaskBits

static inline void SetNetMaskBits(EXipv4Flow_t *EXipv4Flow, EXipv6Flow_t *EXipv6Flow, EXflowMisc_t *EXflowMisc, int apply_netbits);

static inline void SetNetMaskBits(EXipv4Flow_t *EXipv4Flow, EXipv6Flow_t *EXipv6Flow, EXflowMisc_t *EXflowMisc, int apply_netbits) {
    if (EXipv6Flow) {  // IPv6
        if (apply_netbits & 1) {
            uint64_t mask;
            uint32_t mask_bits = EXflowMisc->srcMask;
            if (mask_bits > 64) {
                mask = 0xffffffffffffffffLL << (128 - mask_bits);
                EXipv6Flow->srcAddr[1] &= mask;
            } else {
                mask = 0xffffffffffffffffLL << (64 - mask_bits);
                EXipv6Flow->srcAddr[0] &= mask;
                EXipv6Flow->srcAddr[1] = 0;
            }
        }
        if (apply_netbits & 2) {
            uint64_t mask;
            uint32_t mask_bits = EXflowMisc->dstMask;

            if (mask_bits > 64) {
                mask = 0xffffffffffffffffLL << (128 - mask_bits);
                EXipv6Flow->dstAddr[1] &= mask;
            } else {
                mask = 0xffffffffffffffffLL << (64 - mask_bits);
                EXipv6Flow->dstAddr[0] &= mask;
                EXipv6Flow->dstAddr[1] = 0;
            }
        }
    } else if (EXipv4Flow) {  // IPv4
        if (apply_netbits & 1) {
            uint32_t srcmask = 0xffffffff << (32 - EXflowMisc->srcMask);
            EXipv4Flow->srcAddr &= srcmask;
        }
        if (apply_netbits & 2) {
            uint32_t dstmask = 0xffffffff << (32 - EXflowMisc->dstMask);
            EXipv4Flow->dstAddr &= dstmask;
        }
    }

}  // End of SetNetMaskBits

static inline void ApplyAggrMask(master_record_t *record, master_record_t *mask) {
    uint64_t *r = (uint64_t *)record;
    uint64_t *m = (uint64_t *)mask;

    for (int i = INDEX_BASE; i < Offset_MR_LAST; i++) {
        r[i] &= m[i];
    }

}  // End of ApplyAggrMask
