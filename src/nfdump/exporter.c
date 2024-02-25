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

#include "exporter.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "nfdump.h"
#include "nfxV3.h"
#include "util.h"

/* global */
exporter_t **exporter_list = NULL;

/* local variables */
#define MAX_EXPORTERS 65536

static const struct versionString_s {
    uint16_t version;
    char *string;
} versionString[] = {{5, "netflow v5"}, {9, "netflow v9"}, {10, "ipfix v10"}, {9999, "sflow"}, {0, NULL}};

/* local prototypes */
static exporter_t *exporter_root;

static char *getVersionString(uint16_t nfversion);

#include "nffile_inline.c"

static char *getVersionString(uint16_t nfversion) {
    for (int i = 0; versionString[i].string != NULL; i++) {
        if (nfversion == versionString[i].version) return versionString[i].string;
    }
    return "Unknown version";

}  // End of getVersionString

/* functions */
int InitExporterList(void) {
    exporter_list = (exporter_t **)calloc(MAX_EXPORTERS, sizeof(exporter_t *));
    if (!exporter_list) {
        LogError("calloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
        return 0;
    }
    exporter_root = NULL;
    return 1;

}  // End of InitExporterList

int AddExporterInfo(exporter_info_record_t *exporter_record) {
    if (exporter_record->header.size != sizeof(exporter_info_record_t)) {
        LogError("Corrupt exporter record in %s line %d\n", __FILE__, __LINE__);
        return 0;
    }

    // sanity check
    uint32_t id = exporter_record->sysid;
    if (id >= MAX_EXPORTERS) {
        LogError("Corrupt exporter record in %s line %d\n", __FILE__, __LINE__);
        return 0;
    }
    if (exporter_list[id] != NULL) {
        // slot already taken - check if exporters are identical
        exporter_record->sysid = exporter_list[id]->info.sysid;
        if (memcmp((void *)exporter_record, (void *)&(exporter_list[id]->info), sizeof(exporter_info_record_t)) == 0) {
            dbg_printf("Found identical exporter record at SysID: %i, Slot: %u\n", exporter_record->sysid, id);
            // we are done
            return 2;
        } else {
            // exporters not identical - move current slot
            int i;
            // search first empty slot at the top of the list
            for (i = id + 1; i < MAX_EXPORTERS && exporter_list[i] != NULL; i++) {
                ;
            }
            if (i >= MAX_EXPORTERS) {
                // all slots taken
                LogError("Too many exporters (>256)\n");
                return 0;
            }
            dbg_printf("Move existing exporter from slot %u, to %i\n", id, i);
            // else - move slot
            exporter_list[i] = exporter_list[id];
            exporter_list[id] = NULL;
            exporter_record->sysid = i;
        }
    }

    // slot[id] is now available
    exporter_list[id] = (exporter_t *)calloc(1, sizeof(exporter_t));
    if (!exporter_list[id]) {
        LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    // SPARC gcc fails here, if we use directly a pointer to the struct.
    // SPARC barfs and core dumps otherwise
    // memcpy((void *)&(exporter_list[id]->info), (void *)exporter_record, sizeof(exporter_info_record_t));
    char *p1 = (char *)&(exporter_list[id]->info);
    char *p2 = (char *)exporter_record;
    for (int i = 0; i < sizeof(exporter_info_record_t); i++) *p1++ = *p2++;

    dbg_printf("Insert exporter record in Slot: %i, Sysid: %u\n", id, exporter_record->sysid);

#ifdef DEVEL
    {
#define IP_STRING_LEN 40
        char ipstr[IP_STRING_LEN];
        if (exporter_record->sa_family == AF_INET) {
            uint32_t _ip = htonl(exporter_record->ip.V4);
            inet_ntop(AF_INET, &_ip, ipstr, sizeof(ipstr));
            printf("SysID: %u, IP: %16s, version: %u, ID: %2u, Slot: %u\n", exporter_record->sysid, ipstr, exporter_record->version,
                   exporter_record->id, id);
        } else if (exporter_record->sa_family == AF_INET6) {
            uint64_t _ip[2];
            _ip[0] = htonll(exporter_record->ip.V6[0]);
            _ip[1] = htonll(exporter_record->ip.V6[1]);
            inet_ntop(AF_INET6, &_ip, ipstr, sizeof(ipstr));
            printf("SysID: %u, IP: %40s, version: %u, ID: %2u, Slot: %u\n", exporter_record->sysid, ipstr, exporter_record->version,
                   exporter_record->id, id);
        } else {
            strncpy(ipstr, "<unknown>", IP_STRING_LEN);
            printf("**** Exporter IP version unknown ****\n");
        }
    }
    printf("\n");
#endif

    if (!exporter_root) {
        exporter_root = exporter_list[id];
    }

    return 1;
}  // End of AddExporterInfo

int AddSamplerLegacyRecord(samplerV0_record_t *sampler_record) {
    if (sampler_record->size != sizeof(samplerV0_record_t)) {
        LogError("Corrupt sampler record in %s line %d\n", __FILE__, __LINE__);
        return 0;
    }

    sampler_record_t convert_record = {0};
    sampler_record_t *record = &convert_record;
    if (sampler_record->size == sizeof(samplerV0_record_t)) {
        samplerV0_record_t *samplerV0_record = (samplerV0_record_t *)sampler_record;

        convert_record.type = SamplerRecordType;
        convert_record.size = sizeof(sampler_record_t);
        convert_record.exporter_sysid = samplerV0_record->exporter_sysid;
        convert_record.id = samplerV0_record->id;
        convert_record.algorithm = samplerV0_record->algorithm;
        convert_record.packetInterval = 1;
        convert_record.spaceInterval = samplerV0_record->interval - 1;
        record = &convert_record;
    }
    return AddSamplerRecord(record);

}  // End of AddSamplerLegacyRecord

int AddSamplerRecord(sampler_record_t *sampler_record) {
    uint32_t id = sampler_record->exporter_sysid;
    if (id >= MAX_EXPORTERS) {
        LogError("Corrupt sampler record in %s line %d\n", __FILE__, __LINE__);
        return 0;
    }

    if (!exporter_list[id]) {
        LogError("Exporter SysID: %u not found! - Skip sampler record", id);
        return 0;
    }

    sampler_t **sampler = &exporter_list[id]->sampler;
    while (*sampler) {
        if (memcmp((void *)&(*sampler)->record, (void *)sampler_record, sizeof(sampler_record_t)) == 0) {
            // Found identical sampler already registered
            dbg_printf("Identical sampler already registered: %u, algorithm: %u, packet interval: %u, packet space: %u\n", record->exporter_sysid,
                       sampler_record->algorithm, sampler_record->packetInterval, sampler_record->spaceInterval);
            return 2;
        }
        sampler = &((*sampler)->next);
    }

    *sampler = (sampler_t *)malloc(sizeof(sampler_t));
    if (!*sampler) {
        LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
        return 0;
    }
    (*sampler)->next = NULL;
    sampler_record->exporter_sysid = exporter_list[id]->info.sysid;

    memcpy((void *)&(*sampler)->record, (void *)sampler_record, sizeof(sampler_record_t));
    dbg_printf("Insert sampler record for exporter at slot %i:\n", id);

#ifdef DEVEL
    {
        if (sampler_record->id < 0) {
            printf("Exporter SysID: %u,	Generic Sampler: algorithm: %u, packet interval: %u, packet space: %u\n", record->exporter_sysid,
                   record->algorithm, record->packetInterval, record->spaceInterval);
        } else {
            printf("Exporter SysID: %u,	Sampler: algorithm: %u, packet interval: %u, packet space: %u\n", record->exporter_sysid, record->algorithm,
                   record->packetInterval, record->spaceInterval);
        }
    }
#endif

    return 1;
}  // End of AddSamplerRecord

int AddExporterStat(exporter_stats_record_t *stat_record) {
    if (stat_record->header.size < sizeof(exporter_stats_record_t)) {
        LogError("Corrupt exporter record in %s line %d\n", __FILE__, __LINE__);
        return 0;
    }

    size_t required = sizeof(exporter_stats_record_t) + (stat_record->stat_count - 1) * sizeof(struct exporter_stat_s);
    if ((stat_record->stat_count == 0) || (stat_record->header.size != required)) {
        LogError("Corrupt exporter record in %s line %d\n", __FILE__, __LINE__);
        return 0;
    }

    // 64bit counters can be potentially unaligned
    int use_copy;
    exporter_stats_record_t *rec;
    if (((ptrdiff_t)stat_record & 0x7) != 0) {
        rec = (exporter_stats_record_t *)malloc(stat_record->header.size);
        if (!rec) {
            LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
            exit(255);
        }
        memcpy(rec, stat_record, stat_record->header.size);
        use_copy = 1;
    } else {
        rec = stat_record;
        use_copy = 0;
    }

    for (int i = 0; i < rec->stat_count; i++) {
        uint32_t id = rec->stat[i].sysid;
        if (id >= MAX_EXPORTERS) {
            LogError("Corrupt exporter record in %s line %d\n", __FILE__, __LINE__);
            return 0;
        }
        if (!exporter_list[id]) {
            LogError("Exporter SysID: %u not found! - Skip stat record record.\n");
            continue;
        }
        exporter_list[id]->sequence_failure += rec->stat[i].sequence_failure;
        exporter_list[id]->packets += rec->stat[i].packets;
        exporter_list[id]->flows += rec->stat[i].flows;
        dbg_printf("Update exporter stat for SysID: %i: Sequence failures: %u, packets: %llu, flows: %llu\n", id, exporter_list[id]->sequence_failure,
                   exporter_list[id]->packets, exporter_list[id]->flows);
    }

    if (use_copy) free(rec);

    return 1;

}  // End of AddExporterStat

exporter_t *GetExporterInfo(int exporterID) {
    if (exporterID >= MAX_EXPORTERS) {
        LogError("Corrupt exporter record in %s line %d\n", __FILE__, __LINE__);
        return NULL;
    }

    return exporter_list[exporterID];

}  // End of GetExporter

void ExportExporterList(nffile_t *nffile) {
    // sysid 0 unused -> no exporter available
    int i = 1;
    while (i < MAX_EXPORTERS && exporter_list[i] != NULL) {
        exporter_info_record_t *exporter;
        sampler_t *sampler;

        exporter = &exporter_list[i]->info;
        AppendToBuffer(nffile, (void *)exporter, exporter->header.size);

        sampler = exporter_list[i]->sampler;
        while (sampler) {
            AppendToBuffer(nffile, (void *)&(sampler->record), sampler->record.size);
            sampler = sampler->next;
        }

        i++;
    }

}  // End of ExportExporterList

void PrintExporters(void) {
    printf("Exporters:\n");

    nffile_t *nffile = GetNextFile(NULL);
    if (!nffile) {
        return;
    }

    int done = 0;
    int found = 0;
    while (!done) {
        // get next data block from file
        int ret = ReadBlock(nffile);
        switch (ret) {
            case NF_CORRUPT:
            case NF_ERROR:
                if (ret == NF_CORRUPT)
                    LogError("Corrupt data file");
                else
                    LogError("Read error: %s", strerror(errno));
                done = 1;
                continue;
                break;
                // fall through - get next file in chain
            case NF_EOF:
                done = 1;
                continue;
                break;

                // default:
                // successfully read block
        }

        if (nffile->block_header->type != DATA_BLOCK_TYPE_2 && nffile->block_header->type != DATA_BLOCK_TYPE_3) {
            printf("Skip unknown block type: %u\n", nffile->block_header->type);
            continue;
        }

        record_header_t *record = (record_header_t *)nffile->buff_ptr;
        for (int i = 0; i < nffile->block_header->NumRecords; i++) {
            switch (record->type) {
                case LegacyRecordType1:
                case LegacyRecordType2:
                    LogError("Legacy record type: %i no longer supported\n", record->type);
                    break;
                case ExporterInfoRecordType:
                    found = 1;
                    if (!AddExporterInfo((exporter_info_record_t *)record)) {
                        LogError("Failed to add exporter record\n");
                    }
                    break;
                case ExporterStatRecordType:
                    AddExporterStat((exporter_stats_record_t *)record);
                    break;
                case SamplerRecordType:
                    if (!AddSamplerRecord((sampler_record_t *)record)) {
                        LogError("Failed to add sampler record\n");
                    }
                case SamplerLegacyRecordType:
                    if (!AddSamplerLegacyRecord((samplerV0_record_t *)record)) {
                        LogError("Failed to add legacy sampler record\n");
                    }
                    break;
            }
            // Advance pointer by number of bytes for netflow record
            record = (record_header_t *)((void *)record + record->size);
        }
    }

    CloseFile(nffile);
    DisposeFile(nffile);
    if (!found) {
        printf("No Exporter records found\n");
    }

    printf("\n");
    int i = 1;
    while (i < MAX_EXPORTERS) {
        if (exporter_list[i] == NULL) {
            i++;
            continue;
        }
#define IP_STRING_LEN 40
        char ipstr[IP_STRING_LEN];

        exporter_info_record_t *exporter;

        exporter = &exporter_list[i]->info;
        if (exporter->sa_family == AF_INET) {
            uint32_t _ip = htonl(exporter->ip.V4);
            inet_ntop(AF_INET, &_ip, ipstr, sizeof(ipstr));
            if (exporter_list[i]->flows)
                printf("SysID: %u, IP: %16s, version: %s, ID: %2u, Sequence failures: %u, packets: %llu, flows: %llu\n", exporter->sysid, ipstr,
                       getVersionString(exporter->version), exporter->id, exporter_list[i]->sequence_failure,
                       (long long unsigned)exporter_list[i]->packets, (long long unsigned)exporter_list[i]->flows);
            else
                printf("SysID: %u, IP: %16s, version: %s, ID: %2u - no flows sent\n", exporter->sysid, ipstr, getVersionString(exporter->version),
                       exporter->id);

        } else if (exporter->sa_family == AF_INET6) {
            uint64_t _ip[2] = {htonll(exporter->ip.V6[0]), htonll(exporter->ip.V6[1])};
            inet_ntop(AF_INET6, &_ip, ipstr, sizeof(ipstr));
            if (exporter_list[i]->flows)
                printf("SysID: %u, IP: %40s, version: %s, ID: %2u, Sequence failures: %u, packets: %llu, flows: %llu\n ", exporter->sysid, ipstr,
                       getVersionString(exporter->version), exporter->id, exporter_list[i]->sequence_failure,
                       (long long unsigned)exporter_list[i]->packets, (long long unsigned)exporter_list[i]->flows);
            else
                printf("SysID: %u, IP: %40s, version: %s, ID: %2u\n ", exporter->sysid, ipstr, getVersionString(exporter->version), exporter->id);
        } else {
            strncpy(ipstr, "<unknown>", IP_STRING_LEN);
            printf("**** Exporter IP version unknown ****\n");
        }

        sampler_t *sampler = exporter_list[i]->sampler;
        while (sampler) {
            switch (sampler->record.id) {
                case SAMPLER_OVERWRITE:
                    printf("    Sampler: Static overwrite Sampler: algorithm: %u, packet interval: %u, packet space: %u\n", sampler->record.algorithm,
                           sampler->record.packetInterval, sampler->record.spaceInterval);
                    break;
                case SAMPLER_DEFAULT:
                    printf("    Sampler: Static default Sampler: algorithm: %u, packet interval: %u, packet space: %u\n", sampler->record.algorithm,
                           sampler->record.packetInterval, sampler->record.spaceInterval);
                    break;
                case SAMPLER_GENERIC:
                    printf("    Sampler: Generic Sampler: algorithm: %u, packet interval: %u, packet space: %u\n", sampler->record.algorithm,
                           sampler->record.packetInterval, sampler->record.spaceInterval);
                    break;
                default:
                    printf("    Sampler: Assigned Sampler: id: %lld, algorithm: %u, packet interval: %u, packet space: %u\n",
                           (long long)sampler->record.id, sampler->record.algorithm, sampler->record.packetInterval, sampler->record.spaceInterval);
            }
            sampler = sampler->next;
        }

        i++;
    }

}  // End of PrintExporters
