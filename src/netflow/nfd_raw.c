/*
 *  Copyright (c) 2025-2026, Peter Haag
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

#include "nfd_raw.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "bookkeeper.h"
#include "collector.h"
#include "id.h"
#include "logging.h"
#include "metric.h"
#include "network/nfnet.h"
#include "nfdump.h"
#include "nffileV3/nffileV3.h"
#include "nfxV4.h"
#include "output_short.h"
#include "stat_record.h"
#include "util.h"

/* module limited globals */
static int printRecord;

// UDP session key — set once by Init_pcapd_udp_crypto().
static const uint8_t *g_udpSessionKey = NULL;

/*
 * Per-source anti-replay window width in bits.  Set once by
 * Init_pcapd_udp_crypto(); used by GetSourceAntiReplay() when allocating
 * a new anti_replay_t for a source.
 */
static uint32_t g_replayWindowBits = ANTI_REPLAY_WINDOW_DEFAULT;

// Decryption scratch buffer — written by Process_nfd when version == 251.
// Sized for the largest possible inner payload (65535 bytes).
static uint8_t g_decryptBuf[65536];

static inline exporter_entry_t *getExporter(FlowSource_t *fs, nfd_header_t *header);

/* functions */

int Init_pcapd(int verbose) {
    printRecord = verbose;
    return 1;
}  // End of Init_pcapd

void Init_pcapd_udp_crypto(const uint8_t *sessionKey, uint32_t replayWindowBits, uint32_t rekeyIntervalSecs) {
    g_udpSessionKey = sessionKey;

    // Validate and snap replay window to a power of 2 in [64, MAX].
    if (replayWindowBits == 0) replayWindowBits = ANTI_REPLAY_WINDOW_DEFAULT;
    if (replayWindowBits < 64 || replayWindowBits > ANTI_REPLAY_WINDOW_MAX || (replayWindowBits & (replayWindowBits - 1u)) != 0) {
        LogError("Init_pcapd_udp_crypto: replay window %u invalid (must be power of 2 in [64,%u]), using default %u", replayWindowBits,
                 ANTI_REPLAY_WINDOW_MAX, ANTI_REPLAY_WINDOW_DEFAULT);
        replayWindowBits = ANTI_REPLAY_WINDOW_DEFAULT;
    }
    g_replayWindowBits = replayWindowBits;

    // Configure epoch rekeying in the crypto module.
    SetUdpRekeyInterval(rekeyIntervalSecs);

    LogInfo("nfd_raw: UDP crypto configured — replay window=%u bits, rekey interval=%u s", g_replayWindowBits, rekeyIntervalSecs);
}  // End of Init_pcapd_udp_crypto

/*
 * GetSourceAntiReplay — return the per-source anti_replay_t for 'fs',
 * allocating and zero-initialising it on the first call for this source.
 * Returns NULL only on allocation failure (extremely unlikely).
 */
static anti_replay_t *GetSourceAntiReplay(FlowSource_t *fs) {
    if (fs->udpAntiReplay) return (anti_replay_t *)fs->udpAntiReplay;

    anti_replay_t *ar = calloc(1, sizeof(anti_replay_t));
    if (!ar) {
        LogError("GetSourceAntiReplay: calloc failed for source anti-replay state");
        return NULL;
    }
    ar->windowBits = g_replayWindowBits;
    // initialized == 0 after calloc — anti_replay_check bootstraps on first packet
    fs->udpAntiReplay = ar;
    return ar;
}  // End of GetSourceAntiReplay

static inline exporter_entry_t *getExporter(FlowSource_t *fs, nfd_header_t *header) {
    (void)header;
    const exporter_key_t key = {.version = VERSION_NFDUMP, .id = 0, .ip = fs->ipAddr};

    // fast cache
    if (fs->last_exp && EXPORTER_KEY_EQUAL(fs->last_key, key)) {
        return fs->last_exp;
    }

    exporter_table_t *tab = &fs->exporters;
    // Check load factor in case we need a new slot
    if ((tab->count * 4) >= (tab->capacity * 3)) {
        // expand exporter index
        expand_exporter_table(tab);
        tab = &fs->exporters;
    }

    // not identical of last exporter
    uint32_t hash = EXPORTERHASH(key);
    uint32_t mask = tab->capacity - 1;
    uint32_t i = hash & mask;

    for (uint32_t probes = 0; probes < tab->capacity; probes++) {
        exporter_entry_t *e = &tab->entries[i];
        // key does not exists - create new exporter
        if (!e->in_use) {
            // create new exporter
            void *info = calloc(1, sizeof(exporter_info_record_v4_t));
            if (info == NULL) {
                LogError("Process_nfd: calloc(): %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                return NULL;
            }

            // create new exporter
            *e = (exporter_entry_t){.key = key, .sequence = UINT32_MAX, .sysID = AssignExporterID(), .in_use = 1, .info = info};
            tab->count++;

            *(e->info) = (exporter_info_record_v4_t){
                .type = ExporterInfoRecordV4Type,
                .size = sizeof(exporter_info_record_v4_t),
                .version = key.version,
                .id = key.id,
                .sysID = e->sysID,
            };
            memcpy(e->info->ip, fs->ipAddr.bytes, 16);

            e->nfd = (exporter_nfd_t){0};

            char ipstr[INET6_ADDRSTRLEN];
            LogInfo("Process_nfd: SysID: %u, New exporter: IP: %s\n", e->sysID, ip128_2_str(&fs->ipAddr, ipstr));

            fs->last_key = key;
            fs->last_exp = e;
            return e;
        }
        if (EXPORTER_KEY_EQUAL(e->key, key)) {
            fs->last_key = key;
            fs->last_exp = e;
            return e;
        }

        dbg_assert(tab->count < tab->capacity);
        // next slot
        i = (i + 1) & mask;
    }

    LogError("Process_nfd: exporter table is full");
    return NULL;

}  // End of getExporter

void Process_nfd(void *in_buff, ssize_t in_buff_cnt, FlowSource_t *fs) {
    // Every -H/nfreplay packet arrives wrapped in the universal
    // nfd_wire_header_t envelope (wire version VERSION_NFD_WIRE) — see
    // nfd_udp_crypto.h. authenticated reflects this specific packet's own
    // crypto field (peeked below, before unwrapping) and gates two things:
    // the per-record verify-cost level further down, and whether anti-replay
    // applies at all — replay protection without authentication isn't
    // meaningful, so it's skipped entirely for crypto=NONE packets, same as
    // the old plain v250 path's properties.
    bool authenticated = false;

    if (in_buff_cnt < (ssize_t)NFD_WIRE_HDR_SIZE) {
        LogError("Process_nfd: packet too short for wire header (%zd bytes)", in_buff_cnt);
        fs->bad_packets++;
        return;
    }

    uint16_t wireVersion = 0;
    memcpy(&wireVersion, in_buff, sizeof(wireVersion));
    if (ntohs(wireVersion) != VERSION_NFD_WIRE) {
        LogError("Process_nfd: unsupported wire version %u — drop", ntohs(wireVersion));
        fs->bad_packets++;
        return;
    }

    // crypto is byte offset 2 of nfd_wire_header_t — peek directly rather
    // than parsing the full struct, mirroring the version peek above.
    uint8_t wireCrypto = ((const uint8_t *)in_buff)[2];
    authenticated = (wireCrypto == NFD_CRYPTO_XCHACHA20_POLY1305);

    if (g_udpSessionKey && !authenticated) {
        // -k means "authentication required" on the receive side: a
        // receiver that was configured to expect authenticated traffic
        // does not silently fall back to accepting plain packets.
        LogError("Process_nfd: -k configured but received unauthenticated (crypto=NONE) packet — drop");
        fs->bad_packets++;
        return;
    }
    if (!g_udpSessionKey && authenticated) {
        LogError("Process_nfd: received encrypted packet but no UDP session key configured — drop");
        fs->bad_packets++;
        return;
    }

    ssize_t innerLen = NfdWireDecode(g_decryptBuf, sizeof(g_decryptBuf), in_buff, (size_t)in_buff_cnt, g_udpSessionKey);
    if (innerLen < 0) {
        // NfdWireDecode already logged the reason (auth failure, bad/
        // unsupported algorithm, short packet, etc.)
        fs->bad_packets++;
        return;
    }
    if ((size_t)innerLen < sizeof(nfd_header_t)) {
        LogError("Process_nfd: decoded inner payload too short (%zd bytes)", innerLen);
        fs->bad_packets++;
        return;
    }

    if (authenticated) {
        /* Anti-replay check on the inner sequence number.
         * MAC verified above, so the sequence is trustworthy.
         * Window is keyed per FlowSource (per source IP). */
        anti_replay_t *ar = GetSourceAntiReplay(fs);
        if (!ar) {
            // allocation failure — treat as transient error
            fs->bad_packets++;
            return;
        }
        const nfd_header_t *innerHdr = (const nfd_header_t *)g_decryptBuf;
        uint32_t seq = ntohl(innerHdr->lastSequence);
        if (!anti_replay_check(ar, seq)) {
            LogError("Process_nfd: replay detected from source, seq=%u — drop", seq);
            fs->bad_packets++;
            return;
        }
    }

    // Continue processing the decoded inner nfd payload
    in_buff = g_decryptBuf;
    in_buff_cnt = innerLen;

    // map pcapd data structure to input buffer
    if ((size_t)in_buff_cnt < sizeof(nfd_header_t)) {
        LogError("Process_nfd: packet too short for nfd header (%zd bytes)", in_buff_cnt);
        fs->bad_packets++;
        return;
    }
    nfd_header_t *pcapd_header = (nfd_header_t *)in_buff;
    if (ntohs(pcapd_header->version) != VERSION_NFDUMP || ntohs(pcapd_header->length) != (uint16_t)in_buff_cnt) {
        LogError("Process_nfd: invalid inner header version or length");
        fs->bad_packets++;
        return;
    }
    exporter_entry_t *exporter = getExporter(fs, pcapd_header);
    if (!exporter) {
        LogError("Process_nfd: NULL Exporter: Skip pcapd record processing");
        return;
    }
    if (fs->isNffileBackend) exporter->packets++;

    // this many data to process
    ssize_t size_left = in_buff_cnt;

    // time received for this packet
    uint64_t msecReceived = ((uint64_t)fs->received.tv_sec * 1000LL) + (uint64_t)((uint64_t)fs->received.tv_usec / 1000LL);

    uint32_t count = ntohl(pcapd_header->numRecord);
    uint32_t numRecords = 0;
    dbg_printf("Process nfd packet: %" PRIu64 ", size: %zd, recordCnt: %u\n", exporter->packets, in_buff_cnt, count);

    if (count == 0) {
        LogError("Process_nfd: Empty packet.");
        return;
    }

    if ((sizeof(nfd_header_t) + sizeof(recordHeaderV4_t)) > size_left) {
        LogError("Process_nfd: Not enough data.");
        return;
    }

    // 1st record
    recordHeaderV4_t *recordHeaderV4 = in_buff + sizeof(nfd_header_t);
    size_left -= sizeof(nfd_header_t);
    while (size_left >= (ssize_t)sizeof(recordHeaderV4_t)) {
        // output buffer size check
        dbg_printf("Next record - type: %u, size: %u\n", recordHeaderV4->type, recordHeaderV4->size);
        if (recordHeaderV4->size > size_left) {
            LogError("Process_nfd: record size error. Size V4header: %u > size left: %zd", recordHeaderV4->size, size_left);
            LogError("Process_nfd: expected %u records, processd: %u", count, numRecords);
            return;
        }

        // Verify only after the declared record size is known to fit in this datagram.
        //
        // Check level depends on transport trust, not on record content:
        // crypto=XCHACHA (authenticated) already carries a verified AEAD tag
        // over the whole payload, so a structurally malformed record at this
        // point can only come from a bug in a trusted peer, not a forger —
        // BASIC (header/size/type only) is enough, skipping the
        // extension-table walk entirely. crypto=NONE has no transport-level
        // integrity guarantee at all (compressed or not — compression is
        // independent of authentication), so it keeps the full structural
        // check, including the pairwise extension-overlap validation.
        //
        // (A one-pass, rank-order high-water-mark replacement for that
        // pairwise check was tried here and reverted: an extension's
        // offset-table *slot* is assigned by rank [popcount of extID bits
        // below it, see GetExtension()/AddV4Extension() in nfxV4.h], but the
        // *byte offset* stored in that slot is assigned by the encoder in
        // whatever order it happens to call AddV4Extension() — pipeline/
        // template field order, not ascending extID. So a legitimate
        // record's extensions are routinely non-monotonic when walked in
        // rank order, and a high-water-mark check rejects them. At the
        // extension counts a real record actually carries [single digits to
        // ~15], neither a sort-then-scan nor any other correct alternative
        // meaningfully beats VerifyV4Record()'s existing O(n^2) pairwise
        // check, so this path just uses it directly.)
        int recordOK = VerifyV4Record(recordHeaderV4, (size_t)size_left, authenticated ? V4RECORD_CHECK_BASIC : V4RECORD_CHECK_EXTENSIONS);
        if (!recordOK) {
            LogError("Process_nfd: Corrupt nfd record: expected %u records, processd: %u", count, numRecords);
            return;
        }

        uint32_t outputSize = recordHeaderV4->size;
        if (!IsAvailable(fs->dataBlock, BLOCK_SIZE_V3, outputSize)) {
            // flush block - get an empty one
            PushBlockV3(fs->blockQueue, fs->dataBlock);
            fs->dataBlock = NULL;
            InitDataBlock(fs->dataBlock, BLOCK_SIZE_V3);
            if (!fs->dataBlock) {
                LogError("Process_nfd: out of memory allocating output block");
                return;
            }
        }

        // Plain copy, verbatim — including whatever EXipReceived extension
        // (or lack of one) the record already carries. Every decoder that
        // can originate a V4 record (netflow_v1/v5_v7/v9, ipfix) already
        // stamps EXipReceived with the address it received the flow from at
        // the point of original ingest, unless that extension was disabled
        // via -X; forwarding preserves that original provenance unchanged.
        // Previously, a record that reached here without EXipReceived (e.g.
        // that -X case) had one inserted here, stamped with fs->ipAddr —
        // the immediate relay's own address, not the original exporter's.
        // In a relay chain that's actively misleading (it looks like the
        // flow was received directly from the relay), so it's not
        // reconstructed here; a record without it is left without it.
        void *buffPtr = GetCursor(fs->dataBlock);
        memcpy(buffPtr, (void *)recordHeaderV4, recordHeaderV4->size);
        recordHeaderV4_t *copiedV4 = (recordHeaderV4_t *)buffPtr;

        /* Native UDP carries no exporter metadata. The receiver owns the
         * single exporter for this sender, so do not leave stale source-side
         * sysIDs in records that will be written with that one exporter. */
        copiedV4->exporterID = exporter->sysID;

        dbg_printf("Record: %u elements, size: %u\n\n", copiedV4->numExtensions, copiedV4->size);

        EXgenericFlow_t *genericFlow = GetExtension(copiedV4, EXgenericFlow);
        if (genericFlow) {
            genericFlow->msecReceived = msecReceived;
            if (fs->isNffileBackend) {
                UpdateRecordStat(&fs->stat_record, genericFlow, GetExtension(copiedV4, EXcntFlow));
                UpdateMetric(fs->Ident, MetricExpporterID(copiedV4), genericFlow);
            }
        }

        numRecords++;
        if (fs->isNffileBackend) exporter->flows++;

        if (printRecord) {
            flow_record_short(stdout, copiedV4);
        }

        // update size_left
        size_left -= recordHeaderV4->size;

        // update record block
        fs->dataBlock->rawSize += copiedV4->size;
        fs->dataBlock->numRecords++;

        // advance input buffer to next flow record
        recordHeaderV4 = (recordHeaderV4_t *)((void *)recordHeaderV4 + recordHeaderV4->size);
    }

    if (size_left) LogInfo("Process_nfd(): bytes left in buffer: %zu", size_left);

    if (numRecords != count) LogInfo("Process_nfd(): expected %u records, processd: %u", count, numRecords);

    return;

} /* End of Process_nfd */
