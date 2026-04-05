/*
 *  Copyright (c) 2009-2026, Peter Haag
 *  Copyright (c) 2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
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

#include "collector.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "bookkeeper.h"
#include "conf/nfconf.h"
#include "flist.h"
#include "flowsource.h"
#include "id.h"
#include "ip128.h"
#include "launch.h"
#include "logging.h"
#include "nfdump.h"
#include "nffileV3/nffileV3.h"
#include "nfxV4.h"
#include "util.h"

typedef struct finaliseArgs_s {
    nffileV3_t *nffile;
    uint32_t badPacket;
} finaliseArgs_t;

/* local variables */

static uint32_t exporter_sysid = 0;

/* local prototypes */

static int parse_cidr(const char *cidr, ip128_t *ip, ip128_t *mask);

static uint32_t ParseIPlist(const char *ipListStr, struct ipList_s *ipList);

uint32_t AssignExporterID(void);

// configures the default flow source.
// option -w <dataDir>
// returns 1 on success or 0 on error or dataDir == NULL
int ConfigureDefaultFlowSource(collector_ctx_t *ctx, const char *ident, const char *dataDir, unsigned subDir) {
    if (dataDir == NULL) return 0;

    // check for source model conflicts
    if (ctx->dynamicSource || ctx->index.count) {
        LogError("Options -w, -n and -M are mutually exclusive. Use only one flow source model.");
        return 0;
    }

    ctx->any_source = newFlowSource(ident, dataDir, subDir);
    if (ctx->any_source == NULL) {
        LogError("Failed to add default flow source");
        return 0;
    }

    LogInfo("Add flow source: ident: %s, IP: <any IP>, flowdir: %s", ident, dataDir);
    return 1;

}  // End of ConfigureDefaultFlowSource

// configure fixed IP sources
// one or multiple -n options
// returns 1 on success or 0 on error or number of sources == 0
int ConfigureFixedFlowSource(collector_ctx_t *ctx, stringlist_t *sourceList, unsigned subDir) {
    if (sourceList->num_strings == 0) return 0;

    if (ctx->any_source || ctx->dynamicSource) {
        LogError("Options -w, -n and -M are mutually exclusive. Use only one flow source model.");
        return 0;
    }

    for (int i = 0; i < (int)sourceList->num_strings; i++) {
        // separate ident, IP address and directory path
        char *ident = sourceList->list[i];
        char *ipList = NULL;
        // separate IP address from ident
        if ((ipList = strchr(ident, ',')) == NULL) {
            LogError("Argument error for netflow source definition. Expect -n ident,IP,path. Found: %s", ident);
            return 0;
        }

        char *s = ipList;
        char *dataDir = NULL;
        // separate path from IP
        if ((dataDir = strchr(s + 1, ',')) == NULL) {
            LogError("Argument error for netflow source definition. Expect -n ident,IP,path. Found: %s", ident);
            return 0;
        }
        *ipList++ = '\0';
        *dataDir++ = '\0';

        uint32_t ipNum = ParseIPlist(ipList, NULL);
        if (ipNum == 0) {
            LogError("Argument error for netflow source definition. Failed to parse IP string: %s", ipList);
            return 0;
        }

        source_array_t *source_array = calloc(1, sizeof(source_array_t) + ipNum * sizeof(struct ipList_s));
        if (!source_array) {
            LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return 0;
        }

        if (ParseIPlist(ipList, source_array->ipList) != ipNum) {
            free(source_array);
            return 0;
        }

        FlowSource_t *fs = newFlowSource(ident, dataDir, subDir);
        if (fs == NULL) {
            LogError("Failed to add default flow source");
            free(source_array);
            return 0;
        }

        source_array->fs = fs;
        source_array->ipNum = ipNum;

        // link at start of linked list
        source_array->next = ctx->source_array;
        ctx->source_array = source_array;

        LogInfo("Add flow source: ident: %s, IP: %s, flowdir: %s", ident, ipList, dataDir);
    }

    return 1;
}  // End of ConfigureFixedFlowSource

// configures the dynamic flow source model
// option -M <dynFlowDir>
// returns 1 on success or 0 on error or dynFlowDir == NULL
int ConfigureDynFlowSource(collector_ctx_t *ctx, const char *dynFlowDir, unsigned subDir) {
    if (dynFlowDir == NULL) return 0;
    if (ctx->any_source || ctx->index.count > 0) {
        LogError("Options -w, -n and -M are mutually exclusive. Use only one flow source model.");
        return 0;
    }

    ctx->dynamicSource = newFlowSource("none", dynFlowDir, subDir);
    if (ctx->dynamicSource == NULL) {
        LogError("Failed to add default flow source");
        return 0;
    }

    LogInfo("Add dynamic source in flowdir: %s", dynFlowDir);
    return 1;
}  // End of ConfigureDynFlowSource

// Returns 1 on success, 0 on error
static int parse_cidr(const char *cidr, ip128_t *ip, ip128_t *mask) {
    if (!cidr || !ip || !mask) return 0;

    char buf[256];
    strncpy(buf, cidr, sizeof(buf));
    buf[sizeof(buf) - 1] = '\0';

    // Split "address/prefix"
    char *slash = strchr(buf, '/');
    if (!slash) return 0;

    *slash = '\0';
    char *addr_str = buf;
    char *prefix_str = slash + 1;

    // Parse prefix length
    char *endptr = NULL;
    long prefix = strtol(prefix_str, &endptr, 10);
    if (endptr == prefix_str || prefix < 0 || prefix > 128) return 0;

    // Convert address to ip128_t
    *ip = ip128_2_bin(addr_str);

    if (is_ipv4_mapped(ip)) {
        if (prefix == 0 || prefix > 32) return 0;
        // IPv4-mapped: ::ffff:a.b.c.d
        uint32_t maskv4 = 0xFFFFFFFF << (32 - prefix);
        uint8_t prefix[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};
        memcpy(mask->bytes, prefix, 12);
        maskv4 = ntohl(maskv4);
        memcpy(mask->bytes + 12, &maskv4, sizeof(uint32_t));

    } else {
        memset(mask, 0, sizeof(ip128_t));
        uint8_t *m = mask->bytes;

        int full_bytes = prefix / 8;
        int remaining_bits = prefix % 8;

        for (int i = 0; i < full_bytes; i++) m[i] = 0xFF;

        if (remaining_bits) {
            uint8_t b = (uint8_t)(0xFF << (8 - remaining_bits));
            m[full_bytes] = b;
        }
    }

    return 1;
}  // // End of parse_cidr

// parse ipList string
// format:
// ipAddr             single IPv4 or IPv6 address
// ipAddr;ipAddr..    semicolon separated list of IPv4 or IPv6 address
// [ipAddr ipAddr ..] list of ipAddr in []
static uint32_t ParseIPlist(const char *ipListStr, struct ipList_s *ipList) {
    char *s = strdup(ipListStr);
    if (!s) {
        LogError("strdup() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    uint32_t count = 0;
    if (ipList == NULL) {
        // pass 1: count just the number of IPs

        char *saveptr;
        char *tok = strtok_r(s, ";", &saveptr);
        while (tok) {
            count++;
            tok = strtok_r(NULL, ";", &saveptr);
        }
        free(s);

        return count;
    }

    // pass 2 - parse the IP addresses and store them in ipList
    char *saveptr;
    for (char *tok = strtok_r(s, ";", &saveptr); tok != NULL; tok = strtok_r(NULL, ";", &saveptr)) {
        // CIDR?
        char *slash = strchr(tok, '/');
        ip128_t mask = {0};
        if (slash) {
            ip128_t ip;
            if (!parse_cidr(tok, &ip, &mask)) {
                LogError("Invalid CIDR in -n: %s", tok);
                return 0;
            }
            ip128_and(&ipList[count].net, &ip, &mask);
#ifdef DEVEL
            {
                char ipStr[INET6_ADDRSTRLEN];
                char maskStr[INET6_ADDRSTRLEN];
                ip128_2_str(&ip, ipStr);
                ip128_2_str(&mask, maskStr);
                printf("New CIDR block from: %s - net: %s, mask: %s\n", tok, ipStr, maskStr);
            }
#endif
        } else {
            // Single IP
            ip128_t ip = ip128_2_bin(tok);
            if (is_zero128(&ip)) {
                LogError("Invalid IP in -n: %s", tok);
                return 0;
            }
            ipList[count].net = ip;
#ifdef DEVEL
            {
                char ipStr[INET6_ADDRSTRLEN];
                char maskStr[INET6_ADDRSTRLEN];
                ip128_2_str(&ip, ipStr);
                ip128_2_str(&mask, maskStr);
                printf("New IP from: %s - IP: %s, mask: %s\n", tok, ipStr, maskStr);
            }
#endif
        }
        ipList[count].mask = mask;
        count++;
    }

    return count;

}  // End of ParseIPlist

/* local functions */
uint32_t AssignExporterID(void) {
    if (exporter_sysid >= 0xFFFF) {
        LogError("Too many exporters (id > 65535). Flow records collected but without reference to exporter");
        return 0;
    }

    return ++exporter_sysid;

}  // End of AssignExporterID

// XXX needs fixing - broken
int AddFlowSourceConfig(collector_ctx_t *ctx) {
    char *ident, *ipStr, *dataDir;
    stringlist_t sourceList = {0};
    do {
        int ret = ConfGetExporter(&ident, &ipStr, &dataDir);
        if (ret > 0) {
            // XXX missing subDir ID - fix
            if (ident && dataDir && ipStr == NULL) ConfigureDefaultFlowSource(ctx, ident, dataDir, 2);
            if (ident && ipStr && dataDir) {
                // XXX add to sourceList
            }
            // XXX missing subDir ID - fix
            if (ident == NULL && ipStr == NULL && dataDir) ConfigureDynFlowSource(ctx, dataDir, 2);
            free(ident);
            free(ipStr);
            free(dataDir);
        } else {
            break;
        }
    } while (1);

    if (sourceList.num_strings) {
        // XXX missing subDir ID - fix
        ConfigureFixedFlowSource(ctx, &sourceList, 2);
    }

    return 1;
}  // end of AddFlowSourceConfig

int PeriodicCycle(const collector_ctx_t *ctx, time_t t_start, int done) {
    // flush current datablock and signal to backend
    for (FlowSource_t *fs = NextFlowSource(ctx); fs != NULL; fs = NextFlowSource(NULL)) {
        dbg_printf("Periodic cycle for ident: %s\n", fs->Ident);

        // Flush Exporter to file
        FlushExporter(fs);

        // log stats
        LogInfo("Ident: '%s' Flows: %" PRIu64 ", Packets: %" PRIu64 ", Bytes: %" PRIu64 ", Sequence Errors: %" PRIu64 ", Bad Packets: %u, Blocks: %u",
                fs->Ident, fs->stat_record.numflows, fs->stat_record.numpackets, fs->stat_record.numbytes, fs->stat_record.sequence_failure,
                fs->bad_packets, ReportBlocks());

        // reset stats
        fs->bad_packets = 0;

        // Flush current dataBlock
        fs->dataBlock = PushBlockV3(fs->blockQueue, fs->dataBlock);
        if (fs->dataBlock == QUEUE_CLOSED) {
            fs->dataBlock = NULL;
            return 0;
        }

        // Signaling rote for backend
        msgBlockV3_t *msgBlock = (msgBlockV3_t *)NewDataBlock(BLOCK_SIZE_V3);
        InitMsgBlock(msgBlock);
        uint8_t *p = GetCursor(msgBlock);
        cycle_message_t cycle_message = {.type = MESSAGE_CYCLE, .length = sizeof(cycle_message_t), .when = t_start, .done = done};
        memcpy(&cycle_message.stat_record, (void *)&fs->stat_record, sizeof(stat_record_t));
        memcpy(p, &cycle_message, sizeof(cycle_message_t));

        msgBlock->rawSize += sizeof(cycle_message_t);
        msgBlock->numMessages = 1;
        dbg_printf("Signaling backend\n");
        if (queue_push(fs->blockQueue, msgBlock) == QUEUE_CLOSED) {
            FreeDataBlock(msgBlock);
            return 0;
        }

        dbg_printf("%s() - length blockQueue: %zu\n", __func__, queue_length(fs->blockQueue));

        // new handle - flush exporter and sampler records to new file
        // or close queue if done
        if (done) {
            queue_close(fs->blockQueue);
        } else {
            // clear previous stat
            memset((void *)&fs->stat_record, 0, sizeof(stat_record_t));
        }
    }

    return 1;
}  // End of PeriodicCycle

void FlushExporter(FlowSource_t *fs) {
    dbg_printf("Flush all exporters\n");
    expBlockV3_t *expBlock = (expBlockV3_t *)NewDataBlock(BLOCK_SIZE_V3);
    InitExpBlock(expBlock);

    // push exporter info to exporter block
    uint32_t available = BLOCK_SIZE_V3 - expBlock->rawSize;
    uint8_t *p = GetCursor(expBlock);
    for (exporter_entry_t *entry = NextExporter(fs); entry != NULL; entry = NextExporter(NULL)) {
        exporter_info_record_v4_t *info_record = entry->info;
        info_record->flows = entry->flows;
        info_record->packets = entry->packets;
        info_record->sequence_failure = entry->sequence_failure;
        if (available < info_record->size) {
            queue_push(fs->blockQueue, expBlock);
            expBlock = (expBlockV3_t *)NewDataBlock(BLOCK_SIZE_V3);
            InitExpBlock(expBlock);
            p = GetCursor(expBlock);
            available = BLOCK_SIZE_V3 - expBlock->rawSize;
        }
        memcpy(p, (void *)info_record, info_record->size);
        expBlock->rawSize += info_record->size;
        expBlock->numExporter++;
        available -= info_record->size;

#ifdef DEVEL
        printf("Stat: SysID: %u, version: %u, ID: %2u, Packets: %" PRIu64 ", Flows: %" PRIu64 ", Sequence Failures: %u\n", info_record->sysID,
               info_record->version, info_record->id, info_record->packets, info_record->flows, info_record->sequence_failure);
        sampler_record_v4_t *sampler = info_record->samplers;
        for (int i = 0; i < info_record->sampler_count; i++) {
            printf("[%d] Sampler - ID: %lld, packetInterval: %u, spaceInterval: %u, algorithm: %u\n", i, sampler->selectorID, sampler->packetInterval,
                   sampler->spaceInterval, sampler->algorithm);
        }

#endif
    }
    queue_push(fs->blockQueue, expBlock);

}  // End of FlushExporter

int ScanExtension(char *extensionList) {
    static char *s = NULL;
    static char *list = NULL;

    // first call - initialise string
    if (extensionList) {
        list = strdup(extensionList);
        s = list;
    }

    // no list - error
    if (list == NULL) return -1;

    // last entry
    if (s == NULL || *s == '\0') {
        free(list);
        list = s = NULL;
        return 0;
    }

    // scan next extension number

    // skip white space
    while (*s && isspace(*s)) s++;

    // next separator
    char *q = strchr(s, ',');
    if (q) *q++ = '\0';
    int num = atoi(s);

    // wrong range of extension
    if (num == 0 || num >= MAXEXTENSIONS) {
        free(list);
        s = list = NULL;
        return -1;
    }

    s = q;
    return num;

}  // End of ScanExtension

void CleanupCollector(collector_ctx_t *ctx) {
    dbg_printf("Cleanup Collector\n");
    for (FlowSource_t *fs = NextFlowSource(ctx); fs != NULL; fs = NextFlowSource(NULL)) {
        queue_free(fs->blockQueue);
        FreeDataBlock(fs->dataBlock);
        fs->dataBlock = NULL;
    }
}  // End of CleanupCollector