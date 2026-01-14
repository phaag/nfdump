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
#include "ip128.h"
#include "launch.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfxV3.h"
#include "util.h"

typedef struct finaliseArgs_s {
    nffile_t *nffile;
    uint32_t badPacket;
} finaliseArgs_t;

/* local variables */

static uint32_t exporter_sysid = 0;

/* local prototypes */

static int parse_cidr(const char *cidr, ip128_t *ip, ip128_t *mask);

static uint32_t ParseIPlist(const char *ipListStr, struct ipList_s *ipList);

static uint32_t AssignExporterID(void);

#include "nffile_inline.c"

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

        char *tok = strtok(s, ";");
        while (tok) {
            count++;
            tok = strtok(NULL, ";");
        }
        free(s);

        return count;
    }

    // pass 2 - parse the IP addresses and store them in ipList
    for (char *tok = strtok(s, ";"); tok != NULL; tok = strtok(NULL, ";")) {
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
static uint32_t AssignExporterID(void) {
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

int RotateCycle(const collector_ctx_t *ctx, post_args_t *post_args, time_t t_start, int done) {
    // enter mutex
    pthread_mutex_lock(&post_args->mutex);
    // make sure the previous cycle completed
    while (post_args->cycle_pending) {
        LogError("Waiting for postprocessor to complete previous cycle");
        pthread_cond_wait(&post_args->cond, &post_args->mutex);
    }

    // set cycle arguments
    post_args->cycle_pending = 1;
    post_args->done = done;
    post_args->when = t_start;

    int err = 0;
    for (FlowSource_t *fs = NextFlowSource(ctx); fs != NULL; fs = NextFlowSource(NULL)) {
        // Flush Exporter Stat to file
        FlushExporterStats(fs);

        // log stats
        LogInfo("Ident: '%s' Flows: %" PRIu64 ", Packets: %" PRIu64 ", Bytes: %" PRIu64 ", Sequence Errors: %" PRIu64 ", Bad Packets: %u, Blocks: %u",
                fs->Ident, fs->nffile->stat_record->numflows, fs->nffile->stat_record->numpackets, fs->nffile->stat_record->numbytes,
                fs->nffile->stat_record->sequence_failure, fs->bad_packets, ReportBlocks());

        // reset stats
        fs->bad_packets = 0;

        // Flush dataBlock, ready for new file
        fs->dataBlock = WriteBlock(fs->nffile, fs->dataBlock);

        // swap nffile for post processor
        nffile_t *swap_nffile = fs->swap_nffile;
        fs->swap_nffile = fs->nffile;
        fs->nffile = swap_nffile;
    }

    dbg_printf("Signaling post_processor\n");
    pthread_cond_signal(&post_args->cond);
    pthread_mutex_unlock(&post_args->mutex);

    for (FlowSource_t *fs = NextFlowSource(ctx); fs != NULL; fs = NextFlowSource(NULL)) {
        if (done) {
            // we are done - delete prepared new tmp file
            DeleteFile(fs->nffile);
            fs->nffile = NULL;
        } else {
            if (fs->nffile) {
                // new handle - flush exporter and sampler records to new file
                FlushStdRecords(fs);
            } else {
                // expected a new file handle - cannot continue
                err++;
            }
        }
    }

    return err;
}  // End of RotateCycle

static int RunCycle(time_t t_start, const char *time_extension, const collector_ctx_t *ctx, int *pfd, int done) {
    // periodic file rotation
    struct tm *now = localtime(&t_start);
    char fmt[32];
    strftime(fmt, sizeof(fmt), time_extension, now);

    dbg_printf("Enter RunCycle\n");

    int err = 0;
    for (FlowSource_t *fs = NextFlowSource(ctx); fs != NULL; fs = NextFlowSource(NULL)) {
        nffile_t *nffile = fs->swap_nffile;
        if (nffile == NULL) continue;

        char nfcapd_filename[MAXPATHLEN];
        nfcapd_filename[0] = '\0';

        int pos = SetupPath(now, fs->datadir, fs->subdir, nfcapd_filename);
        char *p = nfcapd_filename + (ptrdiff_t)pos;
        snprintf(p, MAXPATHLEN - pos - 1, "nfcapd.%s", fmt);
        nfcapd_filename[MAXPATHLEN - 1] = '\0';
        dbg_printf("SetupPath(): %s for: %s\n", nfcapd_filename, nffile->fileName);

        // update stat record
        // if no flows were collected, fs->msecLast is still 0
        // set msecFirst and msecLast and to start of this time slot
        if (nffile->stat_record->msecLastSeen == 0) {
            nffile->stat_record->msecFirstSeen = 1000LL * (uint64_t)t_start;
            nffile->stat_record->msecLastSeen = nffile->stat_record->msecFirstSeen;
        }

        // need tmp filename for renaming - Closing the file, discards the filename
        char tmpFilename[MAXPATHLEN];
        strncpy(tmpFilename, nffile->fileName, MAXPATHLEN - 1);
        tmpFilename[MAXPATHLEN - 1] = '\0';

        // Close file
        FinaliseFile(nffile);
        CloseFile(nffile);

        // if rename fails, we are in big trouble, as we need to get rid of the old .current
        // file otherwise, we will loose flows and can not continue collecting new flows
        if (RenameAppend(tmpFilename, nfcapd_filename) < 0) {
            LogError("Ident: %s, Can't rename dump file: %s", fs->Ident, strerror(errno));

            // we do not update the books here, as the file failed to rename properly
            // otherwise the books may be wrong
        } else {
            struct stat fstat;

            // Update books
            stat(nfcapd_filename, &fstat);
            UpdateBooks(fs->bookkeeper, t_start, (uint64_t)(512U * fstat.st_blocks));
        }

        if (*pfd) {
            if (SendLauncherMessage(*pfd, t_start, nfcapd_filename, fmt, fs->datadir, fs->Ident) < 0) {
                LogError("Disable launcher due to errors");
                close(*pfd);
                *pfd = 0;
            }
        }

        if (done) {
            // dispose handle
            DisposeFile(nffile);
            fs->swap_nffile = NULL;
        } else {
            // open new - next file
            int retry = 0;
            do {
                nffile = OpenNewFile(SetUniqueTmpName(fs->tmpFileName), nffile, CREATOR_NFCAPD, INHERIT, INHERIT);
                if (nffile) break;

                nffile = fs->swap_nffile;
                retry++;
                usleep(1000);
            } while (retry < 2);

            if (nffile) {
                fs->swap_nffile = nffile;
                SetIdent(fs->swap_nffile, fs->Ident);
            } else {
                LogError("Ident: %s, Can't re-open empty flow file");
                fs->swap_nffile = NULL;
                // unrecoverable error
                err++;
            }
        }

    }  // end of while (fs)

    return err;

}  // End of RunCycle

int FlushInfoExporter(FlowSource_t *fs, exporter_info_record_t *exporter) {
    exporter->sysid = AssignExporterID();
    fs->dataBlock = AppendToBuffer(fs->nffile, fs->dataBlock, (void *)exporter, exporter->header.size);

#ifdef DEVEL
    {
        char ipstr[INET6_ADDRSTRLEN];
        printf("Flush Exporter: ");
        static const uint8_t prefix[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};
        uint8_t *ip = (uint8_t *)&exporter->ip;
        if (memcmp(ip, prefix, 12) == 0) {
            inet_ntop(AF_INET, (void *)(exporter->ip + 12), ipstr, sizeof(ipstr));
            printf("SysID: %u, IP: %16s, version: %u, ID: %2u\n", exporter->sysid, ipstr, exporter->version, exporter->id);
        } else {
            inet_ntop(AF_INET6, (void *)exporter->ip, ipstr, sizeof(ipstr));
            printf("SysID: %u, IP: %40s, version: %u, ID: %2u\n", exporter->sysid, ipstr, exporter->version, exporter->id);
        }
    }
#endif

    return 1;

}  // End of FlushInfoExporter

void FlushStdRecords(FlowSource_t *fs) {
    for (exporter_entry_t *entry = NextExporter(fs); entry != NULL; entry = NextExporter(NULL)) {
        fs->dataBlock = AppendToBuffer(fs->nffile, fs->dataBlock, (void *)&(entry->info), entry->info.header.size);
        sampler_t *sampler = entry->sampler;
        while (sampler) {
            fs->dataBlock = AppendToBuffer(fs->nffile, fs->dataBlock, (void *)&(sampler->record), sampler->record.size);
            sampler = sampler->next;
        }
    }

}  // End of FlushStdRecords

void FlushExporterStats(FlowSource_t *fs) {
    uint32_t numExporters = fs->exporters.count;

    // idle collector ..
    if (numExporters == 0) return;

    uint32_t size = sizeof(exporter_stats_record_t) + ((numExporters - 1) * sizeof(struct exporter_stat_s));
    exporter_stats_record_t *exporter_stats = (exporter_stats_record_t *)malloc(size);
    if (!exporter_stats) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return;
    }
    exporter_stats->header.type = ExporterStatRecordType;
    exporter_stats->header.size = size;
    exporter_stats->stat_count = numExporters;

#ifdef DEVEL
    printf("Flush Exporter Stats: %u exporters, size: %u\n", numExporters, size);
#endif

    unsigned i = 0;
    for (exporter_entry_t *entry = NextExporter(fs); entry != NULL; entry = NextExporter(NULL)) {
        exporter_stats->stat[i].sysid = entry->info.sysid;
        exporter_stats->stat[i].sequence_failure = entry->sequence_failure;
        exporter_stats->stat[i].packets = entry->packets;
        exporter_stats->stat[i].flows = entry->flows;
#ifdef DEVEL
        printf("Stat: SysID: %u, version: %u, ID: %2u, Packets: %" PRIu64 ", Flows: %" PRIu64 ", Sequence Failures: %u\n", entry->info.sysid,
               entry->info.version, entry->info.id, entry->packets, entry->flows, entry->sequence_failure);

#endif
        // reset counters
        entry->sequence_failure = 0;
        entry->packets = 0;
        entry->flows = 0;

        i++;
    }

    fs->dataBlock = AppendToBuffer(fs->nffile, fs->dataBlock, (void *)exporter_stats, size);
    free(exporter_stats);

    if (i != numExporters) {
        LogError("ERROR: exporter stats: Expected %u records, but found %u in %s line %d: %s", numExporters, i, __FILE__, __LINE__, strerror(errno));
    }

}  // End of FlushExporterStats

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

static void *post_processor_thread(void *args) {
    // dispatch const arguments
    post_args_t *post_args = (post_args_t *)args;
    const char *time_extension = post_args->time_extension;
    const collector_ctx_t *ctx = post_args->ctx;
    int pfd = post_args->pfd;

    dbg_printf("Startup post processor thread\n");

    while (1) {
        pthread_mutex_lock(&(post_args->mutex));

        // Wait until there is a cycle to process, or shutdown is requested.
        while (!post_args->cycle_pending && !post_args->done) {
            pthread_cond_wait(&post_args->cond, &post_args->mutex);
        }

        // dispatch var arguments per cycle
        int cycle_pending = post_args->cycle_pending;
        int done = post_args->done;
        time_t when = post_args->when;
        pthread_mutex_unlock(&post_args->mutex);

        int err = 0;
#if 0
        dbg_printf("Wakeup post processor - done: %d\n", done);
        struct timespec t_start, t_end;
        clock_gettime(CLOCK_MONOTONIC, &t_start);

        // Perform the rotation cycle
        if (cycle_pending) err = RunCycle(when, time_extension, ctx, &pfd, done);

        clock_gettime(CLOCK_MONOTONIC, &t_end);
        // Compute elapsed time in milliseconds
        long sec = t_end.tv_sec - t_start.tv_sec;
        long nsec = t_end.tv_nsec - t_start.tv_nsec;
        double elapsed_ms = (double)sec * 1000.0 + (double)nsec / 1e6;

        printf("Post processor cycle completed in %.3f ms\n", elapsed_ms);
#else
        // Perform the rotation cycle
        if (cycle_pending) err = RunCycle(when, time_extension, ctx, &pfd, done);
#endif

        // cycle done
        pthread_mutex_lock(&(post_args->mutex));
        post_args->cycle_pending = 0;
        pthread_cond_signal(&post_args->cond);
        pthread_mutex_unlock(&post_args->mutex);

        if (done || err) break;
    }

    dbg_printf("Exit post processor thread\n");
    pthread_exit(NULL);
}  // End of post_processor_thread

int Lauch_postprocessor(post_args_t *post_args) {
    if (pthread_mutex_init(&post_args->mutex, NULL) != 0) {
        LogError("pthread_mutex_init() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }
    if (pthread_cond_init(&post_args->cond, NULL) != 0) {
        LogError("pthread_cond_init() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    int err = pthread_create(&post_args->tid, NULL, post_processor_thread, (void *)post_args);
    if (err) {
        LogError("pthread_create() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    return 1;
}  // End of Lauch_postprocessor

void CleanupCollector(collector_ctx_t *ctx, post_args_t *post_args) {
    // wait for last cycle completed of post processor
    pthread_mutex_lock(&post_args->mutex);
    // make sure the previous cycle completed
    while (post_args->cycle_pending) {
        LogError("Waiting for postprocessor to complete previous cycle");
        pthread_cond_wait(&post_args->cond, &post_args->mutex);
    }
    pthread_mutex_unlock(&post_args->mutex);

    // sync postprocessor thread is gone
    pthread_join(post_args->tid, NULL);
    free(post_args);

    dbg_printf("Cleanup Collector\n");
    for (FlowSource_t *fs = NextFlowSource(ctx); fs != NULL; fs = NextFlowSource(NULL)) {
        DisposeFile(fs->nffile);
        DisposeFile(fs->swap_nffile);
        fs->nffile = NULL;
        fs->swap_nffile = NULL;
        FreeDataBlock(fs->dataBlock);
        fs->dataBlock = NULL;
    }
}  // End of CleanupCollector