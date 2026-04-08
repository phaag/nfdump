/*
 *  Copyright (c) 2012-2026, Peter Haag
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

#include "id.h"
#include "logging.h"
#include "nfdump.h"
#include "nffileV3/nffileV3.h"
#include "nfxV3.h"
#include "nfxV4.h"
#include "util.h"

// exporter local variables
#define MAX_EXPORTERS 65536

// exporter index
static exporter_table_t exporter_table = {0};

// linear exporter ID array - temporary struct which will
// get removed in v1.8
static struct exporter_array_s {
#define EXPORTER_BLOCK_SIZE 8
    uint32_t count;
    uint32_t capacity;
    exporter_entry_t **entries;
} exporter_array = {0};

static const struct versionString_s {
    uint16_t version;
    char *string;
} versionString[] = {{1, "netflow v1"}, {5, "netflow v5"}, {9, "netflow v9"}, {10, "ipfix v10"}, {9999, "sflow"}, {0, NULL}};

/* local prototypes */
static char *getVersionString(uint16_t nfversion);

static void expand_exporter_table(exporter_table_t *tab);

static void update_exporter_array(void);

#include "nffile_inline.c"

static char *getVersionString(uint16_t nfversion) {
    for (int i = 0; versionString[i].string != NULL; i++) {
        if (nfversion == versionString[i].version) return versionString[i].string;
    }
    return "Unknown version";

}  // End of getVersionString

/* functions */
int InitExporterList(void) {
    // init exporter table with a default
    exporter_table.capacity = NUMEXPORTERS;
    exporter_table.entries = calloc(exporter_table.capacity, sizeof(exporter_entry_t));
    if (exporter_table.entries == NULL) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }
    exporter_table.count = 0;

    return 1;

}  // End of InitExporterList

int AddExporterInfo(exporter_info_record_v4_t *exporter_record) {
    if (exporter_record->size < sizeof(exporter_info_record_v4_t)) {
        LogError("Corrupt exporter record in %s line %d", __FILE__, __LINE__);
        return 0;
    }

    ip128_t ipAddr;
    memcpy(ipAddr.bytes, exporter_record->ip, sizeof(ip128_t));

    // check for exhausted hash
    if ((exporter_table.count * 4) >= (exporter_table.capacity * 3)) {
        // expand exporter index
        expand_exporter_table(&exporter_table);
        update_exporter_array();
    }

    const exporter_key_t key = {.version = exporter_record->version, .id = exporter_record->id, .ip = ipAddr};

    uint32_t hash = EXPORTERHASH(key);
    uint32_t mask = exporter_table.capacity - 1;
    uint32_t i = hash & mask;

    for (;;) {
        // check for key
        exporter_entry_t *e = &exporter_table.entries[i];
        // key does not exists - insert new exporter
        if (!e->in_use) {
            // insert new exporter
            e->key = key;
            e->packets = 0;
            e->flows = 0;
            e->sequence_failure = 0;
            e->sequence = UINT32_MAX;
            e->in_use = 1;
            exporter_table.count++;

            e->info = malloc(exporter_record->size);
            if (!e->info) {
                LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                return 0;
            }
            memcpy(e->info, exporter_record, exporter_record->size);
#ifdef DEVEL
            {
                char ipstr[INET6_ADDRSTRLEN];
                static const uint8_t prefix[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};
                if (memcmp(ipAddr.bytes, prefix, 12) == 0) {
                    // IPv4
                    uint32_t ipv4;
                    memcpy(&ipv4, ipAddr.bytes + 12, 4);
                    inet_ntop(AF_INET, &ipv4, ipstr, sizeof(ipstr));
                    printf("SysID: %u, IP: %16s, version: %u, ID: %2u\n", exporter_record->sysID, ipstr, exporter_record->version,
                           exporter_record->id);
                } else {
                    inet_ntop(AF_INET6, ipAddr.bytes, ipstr, sizeof(ipstr));
                    printf("SysID: %u, IP: %40s, version: %u, ID: %2u\n", exporter_record->sysID, ipstr, exporter_record->version,
                           exporter_record->id);
                }
            }
#endif
            uint32_t sysID = exporter_record->sysID;
            if (sysID >= exporter_array.capacity) {
                uint32_t capacity;
                for (capacity = exporter_array.capacity; sysID >= capacity; capacity += EXPORTER_BLOCK_SIZE) {
                }
                dbg_printf("Expand exporter_array for sysID: %u, capacity: %u, new capacity: %u\n", sysID, exporter_array.capacity, capacity);
                exporter_entry_t **entries = realloc(exporter_array.entries, capacity * sizeof(exporter_entry_t *));
                if (entries == NULL) {
                    LogError("realloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                    return 0;
                }
                for (unsigned i = exporter_array.capacity; i < capacity; i++) entries[i] = NULL;
                if (exporter_array.count == 0) memset(entries, 0, capacity * sizeof(exporter_entry_t *));
                exporter_array.entries = entries;
                exporter_array.capacity = capacity;
            }
            exporter_array.entries[sysID] = e;
            exporter_array.count++;

            return 1;
        }
        // slot already occupied - same exporter
        if (EXPORTER_KEY_EQUAL(e->key, key)) {
            // same exporter - skip
            dbg_printf("Insert same exporter with sysID %u skipped\n", exporter_record->sysID);
            return 1;
        }

        dbg_assert(exporter_table.count < exporter_table.capacity);
        i = (i + 1) & mask;
    }

    // unreached
    return 1;

}  // End of AddExporterInfo

exporter_entry_t *GetExporterInfo(uint32_t sysID) {
    if (sysID >= exporter_array.capacity) {
        LogError("exporter ID %u out of range in %s line %d", sysID, __FILE__, __LINE__);
        return NULL;
    }

    return exporter_array.entries[sysID];

}  // End of GetExporter

void ExportExporterList(nffileV3_t *nffile) {
    if (exporter_table.count == 0) return;

    dbg_printf("Flush all exporters\n");
    expBlockV3_t *expBlock = NULL;
    InitDataBlock(expBlock, BLOCK_SIZE_V3);

    // push exporter info to exporter block
    uint32_t available = BLOCK_SIZE_V3 - expBlock->rawSize;
    uint8_t *p = ResetCursor(expBlock);
    for (unsigned i = 0; i < exporter_table.capacity; i++) {
        // linear check for sysID exporter
        exporter_entry_t *e = &exporter_table.entries[i];
        if (!e->in_use) continue;
        exporter_info_record_v4_t *exporter_info = e->info;

        if (available < exporter_info->size) {
            queue_push(nffile->processQueue, expBlock);
            expBlock = NULL;
            InitDataBlock(expBlock, BLOCK_SIZE_V3);
            p = GetCursor(expBlock);
            available = BLOCK_SIZE_V3 - expBlock->rawSize;
        }
        dbg_printf("Dump exporter: %u\n", exporter_info->sysID);
        memcpy(p, (void *)exporter_info, exporter_info->size);
        expBlock->rawSize += exporter_info->size;
        expBlock->numExporter++;
        available -= exporter_info->size;
    }

}  // End of ExportExporterList

void PrintExporters(const char *fileName) {
    if (!InitExporterList()) {
        exit(EXIT_FAILURE);
    }

    printf("Exporters:\n");

    nffileV3_t *nffile = mmapFileV3(fileName);
    if (!nffile) {
        return;
    }

    uint32_t nextOffset = 0;
    const expBlockV3_t *dataBlock = getNextExporter(nffile, &nextOffset);
    while (dataBlock) {
        exporter_info_record_v4_t *record = ResetCursor(dataBlock);
        for (int i = 0; i < (int)dataBlock->numExporter; i++) {
            if (!AddExporterInfo(record)) {
                LogError("Failed to add exporter record\n");
            }
            record++;
        }
        dataBlock = getNextExporter(nffile, &nextOffset);
    }
    CloseFileV3(nffile);

    if (exporter_table.count == 0) {
        printf("No Exporter records found\n");
    }

    for (unsigned i = 0; i < exporter_array.capacity; i++) {
        // linear check for sysID exporter
        exporter_entry_t *e = exporter_array.entries[i];
        if (e == NULL || !e->in_use) continue;

        char ipstr[INET6_ADDRSTRLEN];

        exporter_info_record_v4_t *exporter = e->info;
        static const uint8_t prefix[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};
        if (memcmp(exporter->ip, prefix, 12) == 0) {
            // ipv4
            uint32_t ipv4;
            memcpy(&ipv4, e->key.ip.bytes + 12, 4);
            inet_ntop(AF_INET, &ipv4, ipstr, sizeof(ipstr));
            if (exporter->flows)
                printf("SysID: %u, IP: %16s, version: %s, ID: %2u, Sequence failures: %u, packets: %" PRIu64 ", flows: %" PRIu64 "\n",
                       exporter->sysID, ipstr, getVersionString(exporter->version), exporter->sysID, exporter->sequence_failure, exporter->packets,
                       exporter->flows);
            else
                printf("SysID: %u, IP: %16s, version: %s, ID: %2u - no flows sent\n", exporter->sysID, ipstr, getVersionString(exporter->version),
                       exporter->id);

        } else {
            inet_ntop(AF_INET6, e->key.ip.bytes, ipstr, sizeof(ipstr));
            if (e->flows)
                printf("SysID: %u, IP: %40s, version: %s, ID: %2u, Sequence failures: %u, packets: %" PRIu64 ", flows: %" PRIu64 "\n",
                       exporter->sysID, ipstr, getVersionString(exporter->version), exporter->sysID, exporter->sequence_failure, exporter->packets,
                       exporter->flows);
            else
                printf("SysID: %u, IP: %40s, version: %s, ID: %2u - no flows sent\n", exporter->sysID, ipstr, getVersionString(exporter->version),
                       exporter->id);
        }

        if (exporter->sampler_count > 0) {
            sampler_record_v4_t *sampler = exporter->samplers;
            for (int i = 0; i < exporter->sampler_count; i++) {
                switch (sampler->selectorID) {
                    case SAMPLER_OVERWRITE:
                        printf("    Sampler: static overwrite sampler: algorithm: %u, packet interval: %u, packet space: %u\n", sampler->algorithm,
                               sampler->packetInterval, sampler->spaceInterval);
                        break;
                    case SAMPLER_DEFAULT:
                        printf("    Sampler: static default sampler: algorithm: %u, packet interval: %u, packet space: %u\n", sampler->algorithm,
                               sampler->packetInterval, sampler->spaceInterval);
                        break;
                    case SAMPLER_GENERIC:
                        printf("    Sampler: generic sampler: algorithm: %u, packet interval: %u, packet space: %u\n", sampler->algorithm,
                               sampler->packetInterval, sampler->spaceInterval);
                        break;
                    default:
                        printf("    Sampler: assigned Sampler: id: %lld, algorithm: %u, packet interval: %u, packet space: %u\n",
                               (long long)sampler->selectorID, sampler->algorithm, sampler->packetInterval, sampler->spaceInterval);
                }
                sampler++;
            }
        } else {
            printf("    No Sampler information\n");
        }
    }

}  // End of PrintExporters

static void update_exporter_array(void) {
    for (unsigned i = 0; i < exporter_table.capacity; i++) {
        // linear check for sysID exporter
        exporter_entry_t *e = &exporter_table.entries[i];
        if (!e->in_use) continue;

        uint32_t sysID = e->info->sysID;
        exporter_array.entries[sysID] = e;
    }
}  // End of update_exporter_array

static void expand_exporter_table(exporter_table_t *tab) {
    uint32_t old_cap = tab->capacity;
    exporter_entry_t *old_entries = tab->entries;

    uint32_t new_cap = old_cap * 2;
    exporter_entry_t *new_entries = calloc(new_cap, sizeof(exporter_entry_t));
    if (!new_entries) {
        LogError("expand_exporter_table: calloc failed");
        return;
    }

    tab->entries = new_entries;
    tab->capacity = new_cap;
    tab->count = 0;

    for (uint32_t i = 0; i < old_cap; i++) {
        exporter_entry_t *e = &old_entries[i];
        if (!e->in_use) continue;

        uint32_t h = EXPORTERHASH(e->key);
        uint32_t mask = new_cap - 1;
        uint32_t j = h & mask;

        while (new_entries[j].in_use) j = (j + 1) & mask;

        new_entries[j] = *e;
        tab->count++;
    }

    free(old_entries);
}  // End of expand_exporter_table
