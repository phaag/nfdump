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
 * Public, stable, read-only ABI for nffile flow files.
 *
 * Readers are opaque. Field IDs are append-only and independent of nfdump's
 * internal extension IDs. The header depends only on <stdint.h> and
 * <stddef.h>, so it is suitable for FFI generators.
 *
 * Scalar fields use host byte order. Source and destination addresses are
 * 16-byte, network-order IPv6 values; IPv4 is returned as ::ffff:a.b.c.d.
 *
 * A reader is not safe for concurrent use. Independent readers are safe to
 * use concurrently. The initial field set is intentionally limited to common
 * flow, counter, routing, and exporter metadata fields; later fields are
 * appended without renumbering existing IDs.
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

// Bump this and the shared-library ABI version for a breaking change.
#define NFDUMP_ABI_VERSION 1u

// Returns the ABI version of the loaded library.
NFDUMP_API uint32_t nfdump_abi_version(void);

typedef enum {
    NFDUMP_OK = 0,
    NFDUMP_EOF = 1,               // nfdump_reader_next(): no more records
    NFDUMP_ABSENT = 2,            // nfdump_record_get(): field not on this record
    NFDUMP_ERR_IO = -1,           // allocation or other resource failure
    NFDUMP_ERR_FORMAT = -2,       // file cannot be opened, validated, or decoded
    NFDUMP_ERR_UNSUPPORTED = -3,  // unsupported layout or feature
    NFDUMP_ERR_CRYPTO = -4,       // crypto context cannot be prepared
    NFDUMP_ERR_INVALID_ARG = -5,  // invalid argument or too-small output buffer
} nfdump_status_t;

typedef struct nfdump_reader_s nfdump_reader_t;  // opaque

typedef struct {
    uint32_t abi_version;  // NFDUMP_ABI_VERSION
    uint32_t struct_size;  // sizeof(nfdump_reader_options_t)

    // NULL or "" for an unencrypted file. The reader never prompts.
    const char *passphrase;
} nfdump_reader_options_t;

/*
 * Opens path read-only. options may be NULL. Otherwise abi_version must be
 * NFDUMP_ABI_VERSION and struct_size must be at least sizeof(*options).
 * The passphrase is used for encrypted files and is never read from stdin.
 *
 * On failure, *out_reader is NULL. Open diagnostics are reported through
 * nfdump's normal logging because no reader exists yet.
 */
NFDUMP_API nfdump_status_t nfdump_reader_open(const char *path, const nfdump_reader_options_t *options, nfdump_reader_t **out_reader);

NFDUMP_API void nfdump_reader_close(nfdump_reader_t *reader);

// Returns a non-NULL diagnostic for the latest iteration or field-access
// error, or an empty string. It does not cover open failures.
NFDUMP_API const char *nfdump_reader_last_error(const nfdump_reader_t *reader);

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;

    uint64_t ordinal;  // 1-based traversal sequence number within this file

    // Borrowed raw V4 bytes, valid until the next reader_next() or close().
    // This is opaque internal data; use nfdump_record_get() to read fields.
    const uint8_t *data;
    uint32_t size;
} nfdump_record_view_t;

// Advances to the next flow record. On EOF, *record is unchanged.
NFDUMP_API nfdump_status_t nfdump_reader_next(nfdump_reader_t *reader, nfdump_record_view_t *record);

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

// Caller sets out->struct_size to sizeof(*out). The library fills all fields,
// including abi_version. ident is borrowed until nfdump_reader_close().
NFDUMP_API nfdump_status_t nfdump_reader_file_info(const nfdump_reader_t *reader, nfdump_file_info_t *out);

// Public, append-only field IDs. Never renumber or reuse values.
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

// Number of valid field IDs. Describe IDs 1 through this value.
NFDUMP_API size_t nfdump_field_count(void);

// Caller sets out->struct_size to sizeof(*out). The library fills all fields.
NFDUMP_API nfdump_status_t nfdump_field_describe(nfdump_field_id_t field, nfdump_field_info_t *out);

/*
 * Copies a field from the current record. Call only after reader_next()
 * returned NFDUMP_OK. NFDUMP_ABSENT leaves *out unchanged. out_size must be
 * at least the size returned by nfdump_field_describe().
 */
NFDUMP_API nfdump_status_t nfdump_record_get(nfdump_reader_t *reader, nfdump_field_id_t field, void *out, size_t out_size);

#ifdef __cplusplus
}
#endif

#endif  //_NFDUMP_H
