/*
 *  Copyright (c) 2026, Peter Haag
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

/*
 * Public-reader shim. File parsing, block decoding, and record mapping remain
 * in libnffile. Uncompressed, unencrypted blocks are read directly from the
 * mmap; other blocks are decoded once per block. The reader reuses its record
 * handle and copies only requested field values to the public ABI.
 */

#include <arpa/inet.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "id.h"
#include "logging.h"
#include "nfcommon.h"
#include "nfconvert.h"
#include "nfcrypto.h"
#include "nffileV3.h"
#include "util.h"

#define XXH_INLINE_ALL
#include "xxhash.h"

// nffile_inline.c intentionally provides static inline record helpers.
#include "nfdump.h"
#include "nffile_inline.c"

// --------------------------------------------------------------------
// Reader state
// --------------------------------------------------------------------

struct nfdump_reader_s {
    nffileV3_t *nffile;

    int usesQueue;      // 1: legacy V2 file transparently upgraded by mmapFileV3() - no real on-disk
                        // V3 directory exists, blocks come from ReadBlockV3()'s queue instead; see
                        // advanceToNextFlowBlock(). 0: real V3 file, walk blockDirectory directly.
    uint32_t dirIndex;  // next blockDirectory entry to consider (unused when usesQueue)
    uint32_t dirCount;

    flowBlockV3_t *block;  // current flow block, or NULL before the first / after the last
    int blockOwned;        // 1: heap block from DecodeBlockV3(), must FreeDataBlock(); 0: points into mmap

    recordHeader_t *cursor;  // next record within 'block'
    uint32_t recordsLeftInBlock;
    uint32_t blockConsumed;   // bytes consumed from the record area so far
    uint32_t blockAvailable;  // size of the record area (rawSize - header)

    recordHandle_t recHandle;  // reused for every record: no per-record allocation
    uint64_t ordinal;          // count of records this reader has yielded
    int haveCurrent;           // 1 once recHandle holds a valid mapped record

    char lastError[256];
};

static void setError(nfdump_reader_t *reader, const char *fmt, ...) {
    if (!reader) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(reader->lastError, sizeof(reader->lastError), fmt, ap);
    va_end(ap);
}  // End of setError

NFDUMP_API uint32_t nfdump_abi_version(void) { return NFDUMP_ABI_VERSION; }

NFDUMP_API const char *nfdump_reader_last_error(const nfdump_reader_t *reader) {
    if (!reader) return "invalid reader";
    return reader->lastError[0] ? reader->lastError : "";
}  // End of nfdump_reader_last_error

// --------------------------------------------------------------------
// open / close
// --------------------------------------------------------------------

// nfcrypto uses one process-global read context while opening a file.
static pthread_mutex_t g_cryptoOpenLock = PTHREAD_MUTEX_INITIALIZER;

NFDUMP_API nfdump_status_t nfdump_reader_open(const char *path, const nfdump_reader_options_t *options, nfdump_reader_t **out_reader) {
    if (!path || !out_reader) return NFDUMP_ERR_INVALID_ARG;
    *out_reader = NULL;

    if (options && (options->abi_version != NFDUMP_ABI_VERSION || options->struct_size < sizeof(*options))) {
        return NFDUMP_ERR_INVALID_ARG;
    }

    nfdump_reader_t *reader = calloc(1, sizeof(*reader));
    if (!reader) return NFDUMP_ERR_IO;

    crypto_ctx_t *ctx = NULL;
    if (options && options->passphrase && options->passphrase[0]) {
        ctx = NewCryptoCtx(options->passphrase);
        if (!ctx) {
            free(reader);
            return NFDUMP_ERR_CRYPTO;
        }
    }

    pthread_mutex_lock(&g_cryptoOpenLock);
    int wasInteractive = SetReadCryptoInteractive(0);
    RegisterReadCryptoCtx(ctx);
    nffileV3_t *nffile = mmapFileV3(path);
    RegisterReadCryptoCtx(NULL);
    SetReadCryptoInteractive(wasInteractive);
    pthread_mutex_unlock(&g_cryptoOpenLock);

    if (ctx) FreeCryptoCtx(ctx);

    if (!nffile) {
        free(reader);
        return NFDUMP_ERR_FORMAT;
    }

    // Converted V2 input delivers blocks through ReadBlockV3()'s queue.
    reader->nffile = nffile;
    reader->usesQueue = nffile->fileHeader && nffile->fileHeader->layoutVersion == LAYOUT_VERSION_2;
    reader->dirCount = nffile->blockDirectory ? nffile->blockDirectory->numEntries : 0;
    *out_reader = reader;
    return NFDUMP_OK;
}  // End of nfdump_reader_open

static void releaseCurrentBlock(nfdump_reader_t *reader) {
    if (reader->block && reader->blockOwned) {
        FreeDataBlock(reader->block);
    }
    reader->block = NULL;
    reader->blockOwned = 0;
    reader->cursor = NULL;
    reader->recordsLeftInBlock = 0;
}  // End of releaseCurrentBlock

NFDUMP_API void nfdump_reader_close(nfdump_reader_t *reader) {
    if (!reader) return;
    releaseCurrentBlock(reader);
    if (reader->nffile) CloseFileV3(reader->nffile);
    free(reader);
}  // End of nfdump_reader_close

NFDUMP_API nfdump_status_t nfdump_reader_file_info(const nfdump_reader_t *reader, nfdump_file_info_t *out) {
    if (!reader || !out) return NFDUMP_ERR_INVALID_ARG;
    if (out->struct_size < sizeof(nfdump_file_info_t)) return NFDUMP_ERR_INVALID_ARG;

    const stat_record_t *s = reader->nffile->stat_record;
    out->abi_version = NFDUMP_ABI_VERSION;
    out->struct_size = sizeof(*out);
    out->numFlows = s ? s->numflows : 0;
    out->numBytes = s ? s->numbytes : 0;
    out->numPackets = s ? s->numpackets : 0;
    out->msecFirstSeen = s ? s->msecFirstSeen : 0;
    out->msecLastSeen = s ? s->msecLastSeen : 0;
    out->ident = reader->nffile->ident;
    return NFDUMP_OK;
}  // End of nfdump_reader_file_info

// Returns a decoded block. *owned indicates whether it must be freed.
static dataBlockV3_t *decodeFlowBlock(nffileV3_t *nffile, const directoryEntryV3_t *entry, int *owned) {
    *owned = 0;

    if (entry->offset > nffile->mapSize || entry->size > nffile->mapSize - (size_t)entry->offset) return NULL;
    const dataBlockV3_t *raw = (const dataBlockV3_t *)(nffile->map + entry->offset);
    if (entry->size < sizeof(dataBlockV3_t)) return NULL;

    int uncompressed = raw->compression == NOT_COMPRESSED || raw->compression == UNDEF_COMPRESSED;
    if (uncompressed && raw->encryption == NOT_ENCRYPTED && raw->discSize == entry->size && raw->discSize == raw->rawSize) {
        // Verified, uncompressed data can remain in the mmap.
        if (raw->checksum != 0 && raw->discSize > (uint32_t)sizeof(dataBlockV3_t)) {
            const uint8_t *payload = (const uint8_t *)raw + sizeof(dataBlockV3_t);
            uint32_t payloadSize = raw->discSize - (uint32_t)sizeof(dataBlockV3_t);
            if (XXH3_64bits(payload, payloadSize) != raw->checksum) return NULL;
        }
        return (dataBlockV3_t *)raw;
    }

    dataBlockV3_t *decoded = DecodeBlockV3(nffile->map, nffile->mapSize, nffile->fileHeader->blockSize, entry, nffile->crypto);
    if (decoded) *owned = 1;
    return decoded;
}  // End of decodeFlowBlock

// Makes decoded the current flow block.
static void installCurrentBlock(nfdump_reader_t *reader, dataBlockV3_t *decoded, int owned) {
    reader->block = (flowBlockV3_t *)decoded;
    reader->blockOwned = owned;
    reader->cursor = ResetCursor(reader->block);
    reader->recordsLeftInBlock = reader->block->numRecords;
    reader->blockConsumed = 0;
    reader->blockAvailable = decoded->rawSize > sizeof(flowBlockV3_t) ? decoded->rawSize - (uint32_t)sizeof(flowBlockV3_t) : 0;
}  // End of installCurrentBlock

static int advanceToNextFlowBlock(nfdump_reader_t *reader) {
    nffileV3_t *nffile = reader->nffile;

    if (reader->usesQueue) {
        for (;;) {
            dataBlockV3_t *block = ReadBlockV3(nffile);
            if (!block) return 0;  // producer thread done - EOF
            if (block->type != BLOCK_TYPE_FLOW) {
                FreeDataBlock(block);
                continue;
            }
            installCurrentBlock(reader, block, 1);
            return 1;
        }
    }

    const blockDirectoryV3_t *dir = nffile->blockDirectory;
    while (reader->dirIndex < reader->dirCount) {
        const directoryEntryV3_t *entry = &dir->entries[reader->dirIndex++];
        if (entry->type != BLOCK_TYPE_FLOW) continue;

        int owned = 0;
        dataBlockV3_t *decoded = decodeFlowBlock(nffile, entry, &owned);
        if (!decoded) {
            setError(reader, "corrupt or unreadable flow block at directory entry %u", reader->dirIndex - 1);
            return -1;
        }

        installCurrentBlock(reader, decoded, owned);
        return 1;
    }
    return 0;  // no more flow blocks
}  // End of advanceToNextFlowBlock

/*
 * Map a record without MapV4RecordHandle()'s NSEL first-seen backfill,
 * which writes into the record. The zero-copy path is read-only; the
 * equivalent value is computed by getFirstSeenField() below.
 */
static int mapV4RecordHandleReadOnly(recordHandle_t *handle, recordHeaderV4_t *recordHeaderV4, uint64_t flowCount) {
    *handle = (recordHandle_t){.recordHeaderV4 = recordHeaderV4, .numElements = recordHeaderV4->numExtensions, .flowCount = flowCount};

    uint8_t *eor = (uint8_t *)recordHeaderV4 + recordHeaderV4->size;
    uint8_t *recordBase = (uint8_t *)recordHeaderV4;
    uint16_t *offset = (uint16_t *)(recordBase + sizeof(recordHeaderV4_t));
    uint64_t maxMask = (1LL << MAXEXTENSIONS) - 1;

    uint64_t bitMap = recordHeaderV4->extBitmap & maxMask;
    while (bitMap) {
        uint32_t extID = __builtin_ctzll(bitMap);
        bitMap &= bitMap - 1;

        uint8_t *extension = recordBase + *offset++;
        if (extension > eor) return 0;  // extension offset out of bounds - corrupt record

        handle->extensionList[extID] = extension;
    }

    handle->extensionList[EXheader] = (void *)recordHeaderV4;
    handle->extensionList[EXlocal] = (void *)handle;

    if (unlikely(handle->extensionList[EXipv6FlowID] && handle->extensionList[EXipv4FlowID])) {
        ResolveMultipleIPrecords(handle, flowCount);
    }

    return 1;
}  // End of mapV4RecordHandleReadOnly

NFDUMP_API nfdump_status_t nfdump_reader_next(nfdump_reader_t *reader, nfdump_record_view_t *record) {
    if (!reader || !record) return NFDUMP_ERR_INVALID_ARG;
    reader->haveCurrent = 0;

    for (;;) {
        while (reader->block == NULL || reader->recordsLeftInBlock == 0) {
            releaseCurrentBlock(reader);
            int rc = advanceToNextFlowBlock(reader);
            if (rc < 0) return NFDUMP_ERR_FORMAT;
            if (rc == 0) return NFDUMP_EOF;
        }

        recordHeader_t *rp = reader->cursor;
        if (rp->size < sizeof(recordHeader_t) || (reader->blockConsumed + rp->size) > reader->blockAvailable) {
            setError(reader, "corrupt flow block: invalid record size %u", rp->size);
            return NFDUMP_ERR_FORMAT;
        }
        reader->blockConsumed += rp->size;
        reader->recordsLeftInBlock--;
        reader->cursor = (recordHeader_t *)((uint8_t *)rp + rp->size);

        if (rp->type != V4Record) continue;

        reader->ordinal++;
        recordHeaderV4_t *v4 = (recordHeaderV4_t *)rp;
        if (!mapV4RecordHandleReadOnly(&reader->recHandle, v4, reader->ordinal)) {
            setError(reader, "corrupt record %" PRIu64 ": extension offset out of bounds", reader->ordinal);
            return NFDUMP_ERR_FORMAT;
        }
        reader->haveCurrent = 1;

        record->abi_version = NFDUMP_ABI_VERSION;
        record->struct_size = sizeof(*record);
        record->ordinal = reader->ordinal;
        record->data = (const uint8_t *)v4;
        record->size = v4->size;
        return NFDUMP_OK;
    }
}  // End of nfdump_reader_next

enum { FM_HEADER = -1, FM_COMPUTED = -2 };

typedef struct {
    int ext;  // internal EX...ID, or FM_HEADER / FM_COMPUTED
    size_t offset;
    uint16_t size;
    nfdump_field_type_t type;
    const char *name;
} fieldDef_t;

// Maps stable public fields to current internal extensions and offsets.
static const fieldDef_t fieldDefs[NFDUMP_FIELD_MAX] = {
    [NFDUMP_FIELD_FIRST_SEEN] = {EXgenericFlowID, offsetof(EXgenericFlow_t, msecFirst), 8, NFDUMP_T_U64, "firstSeen"},
    [NFDUMP_FIELD_LAST_SEEN] = {EXgenericFlowID, offsetof(EXgenericFlow_t, msecLast), 8, NFDUMP_T_U64, "lastSeen"},
    [NFDUMP_FIELD_RECEIVED] = {EXgenericFlowID, offsetof(EXgenericFlow_t, msecReceived), 8, NFDUMP_T_U64, "received"},

    [NFDUMP_FIELD_IP_VERSION] = {FM_COMPUTED, 0, 1, NFDUMP_T_U8, "ipVersion"},
    [NFDUMP_FIELD_SRC_ADDR] = {FM_COMPUTED, 0, 16, NFDUMP_T_IPV6, "srcAddr"},
    [NFDUMP_FIELD_DST_ADDR] = {FM_COMPUTED, 0, 16, NFDUMP_T_IPV6, "dstAddr"},

    [NFDUMP_FIELD_SRC_PORT] = {EXgenericFlowID, offsetof(EXgenericFlow_t, srcPort), 2, NFDUMP_T_U16, "srcPort"},
    [NFDUMP_FIELD_DST_PORT] = {EXgenericFlowID, offsetof(EXgenericFlow_t, dstPort), 2, NFDUMP_T_U16, "dstPort"},
    [NFDUMP_FIELD_ICMP_TYPE] = {EXgenericFlowID, offsetof(EXgenericFlow_t, icmpType), 1, NFDUMP_T_U8, "icmpType"},
    [NFDUMP_FIELD_ICMP_CODE] = {EXgenericFlowID, offsetof(EXgenericFlow_t, icmpCode), 1, NFDUMP_T_U8, "icmpCode"},
    [NFDUMP_FIELD_PROTO] = {EXgenericFlowID, offsetof(EXgenericFlow_t, proto), 1, NFDUMP_T_U8, "proto"},
    [NFDUMP_FIELD_TCP_FLAGS] = {EXgenericFlowID, offsetof(EXgenericFlow_t, tcpFlags), 1, NFDUMP_T_U8, "tcpFlags"},
    [NFDUMP_FIELD_SRC_TOS] = {EXgenericFlowID, offsetof(EXgenericFlow_t, srcTos), 1, NFDUMP_T_U8, "srcTos"},
    [NFDUMP_FIELD_FWD_STATUS] = {EXgenericFlowID, offsetof(EXgenericFlow_t, fwdStatus), 1, NFDUMP_T_U8, "fwdStatus"},

    [NFDUMP_FIELD_IN_PACKETS] = {EXgenericFlowID, offsetof(EXgenericFlow_t, inPackets), 8, NFDUMP_T_U64, "inPackets"},
    [NFDUMP_FIELD_IN_BYTES] = {EXgenericFlowID, offsetof(EXgenericFlow_t, inBytes), 8, NFDUMP_T_U64, "inBytes"},
    [NFDUMP_FIELD_OUT_PACKETS] = {EXcntFlowID, offsetof(EXcntFlow_t, outPackets), 8, NFDUMP_T_U64, "outPackets"},
    [NFDUMP_FIELD_OUT_BYTES] = {EXcntFlowID, offsetof(EXcntFlow_t, outBytes), 8, NFDUMP_T_U64, "outBytes"},
    [NFDUMP_FIELD_AGGR_FLOWS] = {EXcntFlowID, offsetof(EXcntFlow_t, flows), 8, NFDUMP_T_U64, "aggrFlows"},

    [NFDUMP_FIELD_INPUT_IF] = {EXinterfaceID, offsetof(EXinterface_t, input), 4, NFDUMP_T_U32, "inputIf"},
    [NFDUMP_FIELD_OUTPUT_IF] = {EXinterfaceID, offsetof(EXinterface_t, output), 4, NFDUMP_T_U32, "outputIf"},
    [NFDUMP_FIELD_SRC_AS] = {EXasInfoID, offsetof(EXasInfo_t, srcAS), 4, NFDUMP_T_U32, "srcAS"},
    [NFDUMP_FIELD_DST_AS] = {EXasInfoID, offsetof(EXasInfo_t, dstAS), 4, NFDUMP_T_U32, "dstAS"},
    [NFDUMP_FIELD_SRC_VLAN] = {EXvLanID, offsetof(EXvLan_t, srcVlan), 4, NFDUMP_T_U32, "srcVlan"},
    [NFDUMP_FIELD_DST_VLAN] = {EXvLanID, offsetof(EXvLan_t, dstVlan), 4, NFDUMP_T_U32, "dstVlan"},

    [NFDUMP_FIELD_SRC_MASK] = {EXflowMiscID, offsetof(EXflowMisc_t, srcMask), 1, NFDUMP_T_U8, "srcMask"},
    [NFDUMP_FIELD_DST_MASK] = {EXflowMiscID, offsetof(EXflowMisc_t, dstMask), 1, NFDUMP_T_U8, "dstMask"},
    [NFDUMP_FIELD_DIRECTION] = {EXflowMiscID, offsetof(EXflowMisc_t, direction), 1, NFDUMP_T_U8, "direction"},
    [NFDUMP_FIELD_DST_TOS] = {EXflowMiscID, offsetof(EXflowMisc_t, dstTos), 1, NFDUMP_T_U8, "dstTos"},
    [NFDUMP_FIELD_FLOW_END_REASON] = {EXflowMiscID, offsetof(EXflowMisc_t, flowEndReason), 1, NFDUMP_T_U8, "flowEndReason"},

    [NFDUMP_FIELD_EXPORTER_ID] = {FM_HEADER, offsetof(recordHeaderV4_t, exporterID), 4, NFDUMP_T_U32, "exporterID"},
    [NFDUMP_FIELD_ENGINE_TYPE] = {FM_HEADER, offsetof(recordHeaderV4_t, engineType), 1, NFDUMP_T_U8, "engineType"},
    [NFDUMP_FIELD_ENGINE_ID] = {FM_HEADER, offsetof(recordHeaderV4_t, engineID), 1, NFDUMP_T_U8, "engineID"},
    [NFDUMP_FIELD_NF_VERSION] = {FM_HEADER, offsetof(recordHeaderV4_t, nfVersion), 1, NFDUMP_T_U8, "nfVersion"},
};

NFDUMP_API size_t nfdump_field_count(void) { return NFDUMP_FIELD_MAX - 1; }

NFDUMP_API nfdump_status_t nfdump_field_describe(nfdump_field_id_t field, nfdump_field_info_t *out) {
    if (!out || field <= NFDUMP_FIELD_NONE || field >= NFDUMP_FIELD_MAX) return NFDUMP_ERR_INVALID_ARG;
    if (out->struct_size < sizeof(nfdump_field_info_t)) return NFDUMP_ERR_INVALID_ARG;

    const fieldDef_t *fd = &fieldDefs[field];
    out->abi_version = NFDUMP_ABI_VERSION;
    out->struct_size = sizeof(*out);
    out->name = fd->name;
    out->type = fd->type;
    out->size = fd->size;
    return NFDUMP_OK;
}  // End of nfdump_field_describe

// Returns normalized, network-order IPv6; IPv4 uses the mapped form.
static nfdump_status_t getAddrField(const recordHandle_t *h, int wantSrc, uint8_t out[16]) {
    const EXipv4Flow_t *v4 = (const EXipv4Flow_t *)h->extensionList[EXipv4FlowID];
    const EXipv6Flow_t *v6 = (const EXipv6Flow_t *)h->extensionList[EXipv6FlowID];

    if (v4) {
        memset(out, 0, 10);
        out[10] = 0xff;
        out[11] = 0xff;
        uint32_t be = htonl(wantSrc ? v4->srcAddr : v4->dstAddr);
        memcpy(out + 12, &be, 4);
        return NFDUMP_OK;
    }
    if (v6) {
        uint64_t hi = htonll(wantSrc ? v6->srcAddr[0] : v6->dstAddr[0]);
        uint64_t lo = htonll(wantSrc ? v6->srcAddr[1] : v6->dstAddr[1]);
        memcpy(out, &hi, 8);
        memcpy(out + 8, &lo, 8);
        return NFDUMP_OK;
    }
    return NFDUMP_ABSENT;
}  // End of getAddrField

// NSEL/ASA event records may have only msecEvent, not msecFirst.
static uint64_t getFirstSeenField(const recordHandle_t *h, nfdump_status_t *status) {
    const EXgenericFlow_t *gf = (const EXgenericFlow_t *)h->extensionList[EXgenericFlowID];
    if (!gf) {
        *status = NFDUMP_ABSENT;
        return 0;
    }
    *status = NFDUMP_OK;
    if (gf->msecFirst != 0) return gf->msecFirst;

    const EXnselCommon_t *nsel = (const EXnselCommon_t *)h->extensionList[EXnselCommonID];
    return nsel ? nsel->msecEvent : 0;
}  // End of getFirstSeenField

NFDUMP_API nfdump_status_t nfdump_record_get(nfdump_reader_t *reader, nfdump_field_id_t field, void *out, size_t out_size) {
    if (!reader || !out) return NFDUMP_ERR_INVALID_ARG;
    if (field <= NFDUMP_FIELD_NONE || field >= NFDUMP_FIELD_MAX) return NFDUMP_ERR_INVALID_ARG;
    if (!reader->haveCurrent) return NFDUMP_ERR_INVALID_ARG;  // no successful nfdump_reader_next() yet

    const fieldDef_t *fd = &fieldDefs[field];
    if (out_size < fd->size) return NFDUMP_ERR_INVALID_ARG;

    const recordHandle_t *h = &reader->recHandle;

    if (field == NFDUMP_FIELD_IP_VERSION) {
        uint8_t v = h->extensionList[EXipv4FlowID] ? 4 : (h->extensionList[EXipv6FlowID] ? 6 : 0);
        memcpy(out, &v, 1);
        return v ? NFDUMP_OK : NFDUMP_ABSENT;
    }
    if (field == NFDUMP_FIELD_SRC_ADDR || field == NFDUMP_FIELD_DST_ADDR) {
        return getAddrField(h, field == NFDUMP_FIELD_SRC_ADDR, (uint8_t *)out);
    }
    if (field == NFDUMP_FIELD_FIRST_SEEN) {
        nfdump_status_t status;
        uint64_t v = getFirstSeenField(h, &status);
        if (status == NFDUMP_OK) memcpy(out, &v, 8);
        return status;
    }

    const uint8_t *base;
    if (fd->ext == FM_HEADER) {
        base = (const uint8_t *)h->recordHeaderV4;
    } else {
        base = (const uint8_t *)h->extensionList[fd->ext];
        if (!base) return NFDUMP_ABSENT;
    }
    memcpy(out, base + fd->offset, fd->size);
    return NFDUMP_OK;
}  // End of nfdump_record_get
