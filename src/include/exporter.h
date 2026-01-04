/*
 *  Copyright (c) 2012-2024, Peter Haag
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

#ifndef _EXPORTER_H
#define _EXPORTER_H 1

#include <stdint.h>
#include <sys/types.h>

#include "config.h"
#include "ip128.h"
#include "nffile.h"

/*
 * sampler record for deprecated tags #34, #34, #48 records and mapped records
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  - |	     0     |      1       |      2       |      3       |      4       |      5       |      6       |      7       |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |       record type == 9      |             size            |                             id                            |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |                          interval                         |          algorithm          |       exporter_sysid        |
 * +----+--------------+--------------+--------------+-----------------------------+--------------+--------------+--------------+
 */
typedef struct samplerV0_record_s {
    // record header
    uint16_t type;
    uint16_t size;

    // sampler data
    int32_t id;               // #48 id assigned by the exporting device
    uint32_t interval;        // #34 sampling interval
    uint16_t algorithm;       // #35 sampling algorithm
    uint16_t exporter_sysid;  // internal reference to exporter
} samplerV0_record_t;

/*
 * sampler record for new records tags #302, #304, #305, #306
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  - |	     0     |      1       |      2       |      3       |      4       |      5       |      6       |      7       |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |       record type == 15     |             size            |       exporter_sysid        |          algorithm          |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |                                                           id                                                          |
 * +----+--------------+--------------+--------------+-----------------------------+--------------+--------------+--------------+
 * |  2 |                      packet interval                      |                       packet space                        |
 * +----+--------------+--------------+--------------+-----------------------------+--------------+--------------+--------------+
 *
 * old sampler data is mapped into new sampler record:
 * #302 = #48
 * #304 = #35
 * #305 = #34 - 1
 * #306 = 1
 */

typedef struct sampler_record_s {
    // record header
    uint16_t type;
    uint16_t size;

    // sampler data
    uint16_t exporter_sysid;  // internal reference to exporter
    uint16_t algorithm;       // #304 sampling algorithm
    int64_t id;               // #302 assigned by the exporter or negativ for static -s nn
#define SAMPLER_OVERWRITE -3
#define SAMPLER_DEFAULT -2
#define SAMPLER_GENERIC -1
    uint32_t packetInterval;  // #305 packet interval
    uint32_t spaceInterval;   // #306 packet space
} sampler_record_t;

// linked sampler v0 or v1 list
typedef struct sampler_s {
    struct sampler_s *next;
    sampler_record_t record;  // sampler record nffile
} sampler_t;

/*
 *
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  - |	     0     |      1       |      2       |      3       |      4       |      5       |      6       |      7       |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |       record type == 7      |             size            |                          version                          |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |                                                                                                                       |
 * +----+--------------+--------------+--------------+----------  ip   ------------+--------------+--------------+--------------+
 * |  2 |                                                                                                                       |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  3 |          sa_family          |            sysid            |                             id                            |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */

typedef struct exporter_info_record_s {
    record_header_t header;

    // exporter version
    uint32_t version;
#define SFLOW_VERSION 9999

    // IP address
    uint8_t ip[16];
    uint16_t fill;

    // internal assigned ID
    uint16_t sysid;

    // exporter ID/Domain ID/Observation Domain ID assigned by the device
    uint32_t id;

} exporter_info_record_t;

/*
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  - |	     0     |      1       |      2       |      3       |      4       |      5       |      6       |      7       |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |       record type == 8      |             size            |                         stat_count                        |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |                           sysid[0]                        |                      sequence_failure[0]                  |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  2 |                                                        packets[0]                                                     |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  3 |                                                         flows[0]                                                      |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * ... more stat records [x], one for each exporter
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */
typedef struct exporter_stats_record_s {
    record_header_t header;

    uint32_t stat_count;  // number of stat records

    struct exporter_stat_s {
        uint32_t sysid;             // identifies the exporter
        uint32_t sequence_failure;  // number of sequence failures
        uint64_t packets;           // number of packets sent by this exporter
        uint64_t flows;             // number of flow records sent by this exporter
    } stat[1];

} exporter_stats_record_t;

// key into exporter hash
typedef struct exporter_key_s {
    ip128_t ip;        // IP address of exporter
    uint32_t version;  // NetFlow/IPFIX version
    uint32_t id;       // v1:0, v5/v7: engine_tag, v9: sourceID, ipfix: observationID
} exporter_key_t;

#define EXPORTERHASH(KEY)                                    \
    ({                                                       \
        const exporter_key_t *_k = &(KEY);                   \
        const uint32_t *_w = (const uint32_t *)_k->ip.bytes; \
        uint32_t _h = _w[0] ^ _w[1] ^ _w[2] ^ _w[3];         \
        _h ^= (_k->version * 0x9e3779b1u);                   \
        _h ^= _k->id;                                        \
        _h ^= _h >> 16;                                      \
        _h *= 0x7feb352du;                                   \
        _h ^= _h >> 15;                                      \
        _h *= 0x846ca68bu;                                   \
        _h ^= _h >> 16;                                      \
        _h;                                                  \
    })

#define EXPORTER_KEY_EQUAL(A, B)                                                                            \
    ({                                                                                                      \
        const exporter_key_t *_a = &(A);                                                                    \
        const exporter_key_t *_b = &(B);                                                                    \
        const uint64_t *_ipa = (const uint64_t *)_a->ip.bytes;                                              \
        const uint64_t *_ipb = (const uint64_t *)_b->ip.bytes;                                              \
        (_a->version == _b->version) && (_a->id == _b->id) && (_ipa[0] == _ipb[0]) && (_ipa[1] == _ipb[1]); \
    })

// netflow specific exporter data
// netflow v1
typedef struct exporter_v1_s {
    uint32_t outRecordSize;  // fixed size of v3 record
} exporter_v1_t;

// netflow v5
typedef struct exporter_v5_s {
    uint32_t last_count;     // sequence distance
    uint32_t outRecordSize;  // fixed size of v3 record
} exporter_v5_t;

// netflow v9
typedef struct templateList_s templateList_t;
typedef struct exporter_v9_s {
    // exporter parameters
    uint64_t boot_time;

    // statistics
    uint64_t TemplateRecords;  // stat counter
    uint64_t DataRecords;      // stat counter

    // SysUptime if sent with #160
    uint64_t SysUpTime;  // in msec

    // in order to prevent search through all lists keep
    // the last template we processed as a cache
    templateList_t *currentTemplate;

    // list of all templates of this exporter
    templateList_t *template;

} exporter_v9_t;

// ipfix
typedef struct exporter_ipfix_s {
    // exporter parameters
    uint32_t ExportTime;

    // Current sequence number
    uint32_t PacketSequence;

    // statistics
    uint64_t TemplateRecords;  // stat counter
    uint64_t DataRecords;      // stat counter

    // SysUptime if sent with #160
    uint64_t SysUpTime;  // in msec

    // in order to prevent search through all lists keep
    // the last template we processed as a cache
    templateList_t *currentTemplate;

    // list of all templates of this exporter
    templateList_t *template;

} exporter_ipfix_t;

typedef struct exporter_nfd_s {
    uint32_t empty;  // no extra data
} exporter_nfd_t;

typedef struct exporter_sflow_s {
    sampler_t *sampler;  // sampler info
} exporter_sflow_t;

// exporter struct
typedef struct exporter_entry_s {
    exporter_key_t key;           // key to identify this exporter
    exporter_info_record_t info;  // common exporter struct to flush to backend
    uint64_t packets;             // number of packets sent by this exporter
    uint64_t flows;               // number of flow records sent by this exporter
    uint32_t sequence_failure;    // number of sequence failures
    uint32_t sequence;            // sequence counter
    // sampling information:

    sampler_t *sampler;  // sampler info
    // each flow source may have several sampler applied:
    // SAMPLER_OVERWRITE - supplied on cmd line -s -interval
    // SAMPLER_DEFAULT   - supplied on cmd line -s interval
    // SAMPLER_GENERIC   - sampling information tags #34 #35 or v5 header
    // samplerID         - sampling information tags #48, #49, #50 - mapped to
    // samplerID         - sampling information tags #302, #304, #305, #306

    int in_use;  // flag
    union {
        exporter_v1_t v1;        // netflow v1 specific data
        exporter_v5_t v5;        // netflow v1 specific data
        exporter_v9_t v9;        // netflow v9 specific data
        exporter_ipfix_t ipfix;  // ipfix specific data
        exporter_nfd_t nfd;      // nfd specific data
        exporter_sflow_t sflow;  // sflow specific data
    } version;                   // all exporter structs to all netflow/sflow versions
} exporter_entry_t;

// exporter table
typedef struct exporter_table_s {
    exporter_entry_t *entries;  // array of exporters
    // initial number of exporters
#define NUMEXPORTERS 16
    uint32_t capacity;  // always power of two, e.g. 128
    uint32_t count;     // max in use
} exporter_table_t;

int InitExporterList(void);

int AddExporterInfo(exporter_info_record_t *exporter_record);

int AddSamplerRecord(sampler_record_t *sampler_record);

sampler_record_t *ConvertLegacyRecord(samplerV0_record_t *legacy_record);

int AddExporterStat(exporter_stats_record_t *stat_record);

dataBlock_t *ExportExporterList(nffile_t *nffile, dataBlock_t *dataBlock);

exporter_entry_t *GetExporterInfo(uint32_t sysID);

void PrintExporters(void);

#endif  //_EXPORTER_H
