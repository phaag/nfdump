/*
 *  Copyright (c) 2023, Peter Haag
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

#ifndef _NFD_RAW_H
#define _NFD_RAW_H 1

#include <stdint.h>
#include <sys/types.h>

#include "collector.h"
#include "network/nfd_udp_crypto.h"

/*
 * NFD_LEGACY_UDP_VERSION (250) — bare, unwrapped wire format used by
 * nfdump/nfpcapd/nfreplay 1.7.x. Rejected by nfdump 1.8.x
 */
#define NFD_LEGACY_UDP_VERSION 250u

typedef struct transfer_record_header {
    uint16_t recordType;    // record-batch format identifier
    uint16_t length;        // Total length incl. this header. up to 65535 bytes
    uint32_t exportTime;    // UNIX epoch export Time of flow.
    uint32_t lastSequence;  // Incremental sequence counter modulo 2^32 of all pcapd Data Records
    uint32_t numRecord;     // number of pcapd records in this packet
} transfer_record_header_t;

/* prototypes */
int Init_pcapd(int verbose);

/*
 * Init_pcapd_udp_crypto — configure authentication/decryption for incoming
 * -H/nfreplay UDP packets.
 *
 * sessionKey       32-byte Argon2id-derived key (from DeriveUdpSessionKey).
 *                  Pass NULL to accept only crypto=NONE traffic (no -k given).
 *                  Non-NULL makes -k mean "authentication required":
 *                  Process_nfd() then rejects crypto=NONE packets outright,
 *                  rather than silently accepting them alongside
 *                  authenticated ones.
 * replayWindowBits Per-source anti-replay window width in packets.
 *                  Must be a power of 2 in [64, ANTI_REPLAY_WINDOW_MAX].
 *                  Pass 0 to use ANTI_REPLAY_WINDOW_DEFAULT (256).
 * rekeyIntervalSecs Epoch duration for key rotation.  Pass 0 to disable
 *                  rekeying (single session-key for daemon lifetime).
 *                  Must match the value given to the sender side.
 *
 * Must be called before the first encrypted packet arrives.
 */
void Init_pcapd_udp_crypto(const uint8_t *sessionKey, uint32_t replayWindowBits, uint32_t rekeyIntervalSecs);

void Process_nfd(void *in_buff, ssize_t in_buff_cnt, FlowSource_t *fs);

#endif  // _NFD_RAW_H
