/*
 *  Copyright (c) 2012-2023, Peter Haag
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
    int64_t id;               // #302 id assigned by the exporting device or
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
    ip_addr_t ip;
    uint16_t sa_family;

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

typedef struct exporter_s {
    // linked chain
    struct exporter_s *next;

    // exporter information
    exporter_info_record_t info;  // exporter record nffile

    uint64_t packets;           // number of packets sent by this exporter
    uint64_t flows;             // number of flow records sent by this exporter
    uint32_t sequence_failure;  // number of sequence failures
                                // uint32_t padding_errors;    // number of sequence failures

    sampler_t *sampler;  // list of samplers associated with this exporter

} exporter_t;

int InitExporterList(void);

int AddExporterInfo(exporter_info_record_t *exporter_record);

int AddSamplerInfo(sampler_record_t *sampler_record);

int AddExporterStat(exporter_stats_record_t *stat_record);

void ExportExporterList(nffile_t *nffile);

exporter_t *GetExporterInfo(int exporterID);

void PrintExporters(void);

#endif  //_EXPORTER_H
