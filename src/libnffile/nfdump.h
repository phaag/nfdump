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
 * nfdump.h — public, stable read-only ABI for nffile V3 files.
 *
 * Design goals and rationale, in short:
 *   - opaque handle (nfdump_reader_t), no internal struct ever crosses
 *     this boundary.
 *   - every extensible struct carries {abi_version, struct_size} so a
 *     future ABI version can append fields without breaking callers
 *     built against this header.
 *   - one error taxonomy (nfdump_status_t) used by every function.
 *   - pull iteration: nfdump_reader_next() returns a *borrowed* view,
 *     valid only until the next nfdump_reader_next()/nfdump_reader_close()
 *     call on the same reader. Copy out anything you need to keep.
 *   - field access goes through a hand-frozen, append-only public field
 *     enum (nfdump_field_id_t), never through nfdump's internal,
 *     insertion-order extension IDs — those are not a stable contract
 *     and are renumbered as nfdump's on-disk format evolves.
 *   - this header has no dependency beyond <stdint.h>/<stddef.h> so it
 *     can be parsed standalone by cffi/ctypesgen/bindgen without pulling
 *     in nfdump's internal headers or build tree.
 *
 * Byte order: all scalar fields (counters, ports, AS numbers, VLAN ids,
 * timestamps, flags, ...) are returned in host byte order — the same
 * convention nfdump uses internally. NFDUMP_FIELD_SRC_ADDR/DST_ADDR are
 * the one exception: they are returned as 16-byte buffers in network
 * byte order (IPv4 addresses are IPv4-mapped per RFC 4291, e.g.
 * ::ffff:a.b.c.d), ready to pass straight to inet_ntop(AF_INET6, ...).
 *
 * Thread-safety: a single nfdump_reader_t must not be used from more
 * than one thread concurrently. Independent readers (one per thread,
 * one per open file) are fully independent and safe to use concurrently.
 *
 * Status: first implementation. Field coverage in nfdump_field_id_t is
 * intentionally partial (the common 5-tuple/counters/metadata fields) —
 * append more at the end as needed, never renumber or reuse a value.
 */

#ifndef _NFDUMP_H
#define _NFDUMP_H 1

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#define NFDUMP_API __declspec(dllexport)
#elif defined(__GNUC__) || defined(__clang__)
#define NFDUMP_API __attribute__((visibility("default")))
#else
#define NFDUMP_API
#endif

// Compile-time ABI version. Bump on any breaking change; pair with a
// SONAME bump on the shared object once this ships as one.
#define NFDUMP_ABI_VERSION 1u

/*
 * Returns the ABI version this library was built with — the only one of
 * the three version signals (SONAME, this macro, this call) a ctypes/
 * dlopen caller that never saw this header at compile time can check.
 */
NFDUMP_API uint32_t nfdump_abi_version(void);

// --------------------------------------------------------------------
// Status / error taxonomy — used by every function below.
// --------------------------------------------------------------------

typedef enum {
    NFDUMP_OK = 0,
    NFDUMP_EOF = 1,               // nfdump_reader_next(): no more records
    NFDUMP_ABSENT = 2,            // nfdump_record_get(): field not on this record
    NFDUMP_ERR_IO = -1,           // open()/fstat()/mmap() failure
    NFDUMP_ERR_FORMAT = -2,       // corrupt / unrecognized file structure
    NFDUMP_ERR_UNSUPPORTED = -3,  // layout version newer than this library, or feature unavailable
    NFDUMP_ERR_CRYPTO = -4,       // bad passphrase, corrupt crypto header, or no crypto support built in
    NFDUMP_ERR_INVALID_ARG = -5,  // NULL/out-of-range argument, or out_size too small
} nfdump_status_t;

// --------------------------------------------------------------------
// Reader: open, iterate, close.
// --------------------------------------------------------------------

typedef struct nfdump_reader_s nfdump_reader_t;  // opaque

typedef struct {
    uint32_t abi_version;  // set to NFDUMP_ABI_VERSION
    uint32_t struct_size;  // set to sizeof(nfdump_reader_options_t)

    /*
     * NULL/"" for an unencrypted file. If the file is encrypted and this
     * is wrong or absent, nfdump_reader_open() fails with
     * NFDUMP_ERR_CRYPTO — it never prompts a terminal or blocks on
     * stdin, unlike some internal nfdump code paths.
     */
    const char *passphrase;
} nfdump_reader_options_t;

/*
 * Opens 'path' read-only, validates the V3 header/directory/footer (and,
 * for an encrypted file, derives and verifies the key), and positions
 * the reader at the first record. Does not spawn any threads and touches
 * no global nfdump configuration — every reader is fully self-contained.
 *
 * Fails closed: on any return other than NFDUMP_OK, *out_reader is left
 * NULL and there is nothing for the caller to close. Details of an open
 * failure (bad magic, wrong passphrase, truncated file, ...) go to
 * nfdump's normal logging, not to a reader — there is no reader yet.
 */
NFDUMP_API nfdump_status_t nfdump_reader_open(const char *path, const nfdump_reader_options_t *options, nfdump_reader_t **out_reader);

NFDUMP_API void nfdump_reader_close(nfdump_reader_t *reader);

/*
 * Human-readable detail for the most recent NFDUMP_ERR_* returned by
 * nfdump_reader_next()/nfdump_record_get() on this reader (open() failures
 * are not covered — see nfdump_reader_open()). Always returns a non-NULL,
 * NUL-terminated string, empty if nothing has failed yet.
 */
NFDUMP_API const char *nfdump_reader_last_error(const nfdump_reader_t *reader);

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;

    uint64_t ordinal;  // 1-based traversal sequence number within this file

    /*
     * Raw V4 record bytes, borrowed — valid only until the next
     * nfdump_reader_next()/nfdump_reader_close() call on this reader.
     * Opaque, internal wire format: it may change shape between nfdump
     * releases. Provided for pass-through/archival use (e.g. re-emit the
     * exact bytes elsewhere); do not parse it directly — use
     * nfdump_record_get() for individual fields instead.
     */
    const uint8_t *data;
    uint32_t size;
} nfdump_record_view_t;

/*
 * Advances to the next flow record and fills *record.
 * Returns NFDUMP_OK (record filled), NFDUMP_EOF (no more records —
 * *record is left unfilled), or an NFDUMP_ERR_* on a corrupt file.
 */
NFDUMP_API nfdump_status_t nfdump_reader_next(nfdump_reader_t *reader, nfdump_record_view_t *record);

// --------------------------------------------------------------------
// File-level metadata — cheap, available immediately after open().
// --------------------------------------------------------------------

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;

    uint64_t numFlows;
    uint64_t numBytes;
    uint64_t numPackets;
    uint64_t msecFirstSeen;
    uint64_t msecLastSeen;

    const char *ident;  // borrowed, valid until nfdump_reader_close(); may be NULL
} nfdump_file_info_t;

/*
 * Caller must set out->struct_size = sizeof(nfdump_file_info_t) before
 * calling (the {abi_version, struct_size} idiom from the top of this
 * file) — this and nfdump_field_describe() are the two functions here
 * that fill an existing caller struct rather than one they only just
 * declared, so there is no other point where size is implied.
 */
NFDUMP_API nfdump_status_t nfdump_reader_file_info(const nfdump_reader_t *reader, nfdump_file_info_t *out);

// --------------------------------------------------------------------
// Field access — decoupled from nfdump's internal extension numbering.
// --------------------------------------------------------------------

/*
 * Public, hand-frozen, append-only. Never renumber or reuse a value —
 * these numbers are the ABI. Internally each of these is mapped to
 * whatever nfdump's current on-disk extension layout happens to be; that
 * mapping is free to change between nfdump releases without affecting
 * these values.
 */
typedef enum {
    NFDUMP_FIELD_NONE = 0,

    NFDUMP_FIELD_FIRST_SEEN,  // U64  - flow start, milliseconds since epoch. For an NSEL/ASA
                              // event record with no separate start time, this is the event
                              // time (EXnselCommon.msecEvent) instead - matching nfdump's own
                              // CLI output for the same record.
    NFDUMP_FIELD_LAST_SEEN,   // U64  - flow end,          milliseconds since epoch
    NFDUMP_FIELD_RECEIVED,    // U64  - exporter received, milliseconds since epoch

    NFDUMP_FIELD_IP_VERSION,  // U8   - 4 or 6 (0 if neither extension present)
    NFDUMP_FIELD_SRC_ADDR,    // IPV6 - 16 bytes, network byte order, see header comment
    NFDUMP_FIELD_DST_ADDR,    // IPV6 - 16 bytes, network byte order, see header comment

    NFDUMP_FIELD_SRC_PORT,    // U16
    NFDUMP_FIELD_DST_PORT,    // U16  - aliases ICMP type/code on the wire, like nfdump's own output
    NFDUMP_FIELD_ICMP_TYPE,   // U8   - meaningful only when NFDUMP_FIELD_PROTO is ICMP/ICMPv6
    NFDUMP_FIELD_ICMP_CODE,   // U8
    NFDUMP_FIELD_PROTO,       // U8   - IP protocol number
    NFDUMP_FIELD_TCP_FLAGS,   // U8
    NFDUMP_FIELD_SRC_TOS,     // U8
    NFDUMP_FIELD_FWD_STATUS,  // U8

    NFDUMP_FIELD_IN_PACKETS,   // U64
    NFDUMP_FIELD_IN_BYTES,     // U64
    NFDUMP_FIELD_OUT_PACKETS,  // U64  - NFDUMP_ABSENT if the record has no reverse-direction extension
    NFDUMP_FIELD_OUT_BYTES,    // U64
    NFDUMP_FIELD_AGGR_FLOWS,   // U64  - number of flows aggregated into this record

    NFDUMP_FIELD_INPUT_IF,   // U32
    NFDUMP_FIELD_OUTPUT_IF,  // U32
    NFDUMP_FIELD_SRC_AS,     // U32
    NFDUMP_FIELD_DST_AS,     // U32
    NFDUMP_FIELD_SRC_VLAN,   // U32
    NFDUMP_FIELD_DST_VLAN,   // U32

    NFDUMP_FIELD_SRC_MASK,         // U8
    NFDUMP_FIELD_DST_MASK,         // U8
    NFDUMP_FIELD_DIRECTION,        // U8
    NFDUMP_FIELD_DST_TOS,          // U8
    NFDUMP_FIELD_FLOW_END_REASON,  // U8

    NFDUMP_FIELD_EXPORTER_ID,  // U32 - always present (record header, not an extension)
    NFDUMP_FIELD_ENGINE_TYPE,  // U8  - always present
    NFDUMP_FIELD_ENGINE_ID,    // U8  - always present
    NFDUMP_FIELD_NF_VERSION,   // U8  - always present: netflow v1/v5/v7/v9/ipfix/sflow/nfpcapd source marker

    NFDUMP_FIELD_MAX  // one past the last valid value; not a field itself
} nfdump_field_id_t;

typedef enum {
    NFDUMP_T_U8 = 1,
    NFDUMP_T_U16,
    NFDUMP_T_U32,
    NFDUMP_T_U64,
    NFDUMP_T_IPV6,  // 16 bytes, network byte order — see header comment
} nfdump_field_type_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;

    const char *name;  // stable, e.g. "srcAddr" - for generic/introspecting tooling
    nfdump_field_type_t type;
    uint16_t size;  // byte size nfdump_record_get() writes for this field
} nfdump_field_info_t;

/*
 * Number of valid field ids, i.e. NFDUMP_FIELD_MAX - 1. Lets a generic
 * caller (e.g. an Arkime plugin registering fields at startup) enumerate
 * every field with nfdump_field_describe(1..nfdump_field_count()).
 */
NFDUMP_API size_t nfdump_field_count(void);

// Caller must set out->struct_size = sizeof(nfdump_field_info_t) first —
// see the note on nfdump_reader_file_info() above.
NFDUMP_API nfdump_status_t nfdump_field_describe(nfdump_field_id_t field, nfdump_field_info_t *out);

/*
 * Copies the current record's value for 'field' into *out.
 * 'reader' must have a current record, i.e. the most recent
 * nfdump_reader_next() call on it returned NFDUMP_OK.
 *
 * Returns NFDUMP_OK (copied), NFDUMP_ABSENT (field's extension is not
 * present on this record — *out is untouched), or NFDUMP_ERR_INVALID_ARG
 * (bad field id, no current record, or out_size smaller than the field's
 * size per nfdump_field_describe()).
 */
NFDUMP_API nfdump_status_t nfdump_record_get(nfdump_reader_t *reader, nfdump_field_id_t field, void *out, size_t out_size);

#ifdef __cplusplus
}
#endif

#endif  //_NFDUMP_H
