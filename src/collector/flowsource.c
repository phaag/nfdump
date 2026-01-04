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

#include "flowsource.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "config.h"
#include "ip128.h"
#include "util.h"

static void freeFlowSource(FlowSource_t *fs);

static int inline GetClientIP(const struct sockaddr_storage *ss, ip128_t *ip, uint32_t *family);

static int initFileInfo(FlowSource_t *fs, const char *ident, const char *dataDir, unsigned subDir);

static void expand_source_index(source_index_t *idx);

static inline FlowSource_t *index_lookup(const source_index_t *idx, const ip128_t *ip);

int init_collector_ctx(collector_ctx_t *ctx) {
    memset((void *)ctx, 0, sizeof(collector_ctx_t));

    ctx->index.capacity = NUMSOURCES;
    ctx->index.entries = calloc(ctx->index.capacity, sizeof(source_index_entry_t));
    ctx->numFlowSources = 0;
    ctx->source_array = NULL;
    if (!ctx->index.entries) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }
    ctx->index.count = 0;

    return 1;
}  // End of init_collector_ctx

// initialise a new FlowSource
FlowSource_t *newFlowSource(const char *ident, const char *dataDir, unsigned subDir) {
    FlowSource_t *fs = calloc(1, sizeof(FlowSource_t));
    if (!fs) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    // init exporter table with a default
    fs->exporters.capacity = NUMEXPORTERS;
    fs->exporters.entries = calloc(fs->exporters.capacity, sizeof(exporter_entry_t));
    if (fs->exporters.entries == NULL) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    // init backend info
    if (initFileInfo(fs, ident, dataDir, subDir) == 0) {
        freeFlowSource(fs);
        return NULL;
    }

    fs->exporters.count = 0;
    fs->last_exp = NULL;

    return fs;

}  // End of newFlowSource

void insertFlowSource(collector_ctx_t *ctx, const ip128_t *ip, FlowSource_t *fs) {
    source_index_t *idx = &ctx->index;
    // expand index if load factor > 0.75
    if ((idx->count * 4) >= (idx->capacity * 3)) {
        expand_source_index(idx);
    }

    uint32_t h = IP128HASH(ip);
    uint32_t mask = ctx->index.capacity - 1;
    uint32_t i = h & mask;

    for (;;) {
        source_index_entry_t *e = &idx->entries[i];
        if (!e->in_use) {
            e->ip = *ip;
            e->fs = fs;
            e->in_use = 1;
            idx->count++;
            return;
        }
        i = (i + 1) & mask;
    }

}  // End of insertFlowSource

static FlowSource_t *AddDynamicSource(collector_ctx_t *ctx, const ip128_t *ip) {
    // create new flow directory for dynamic source
    char *ipStr = ip128_2_str(ip);

    char path[MAXPATHLEN];
    snprintf(path, MAXPATHLEN - 1, "%s/%s", ctx->dynamicSource->datadir, ipStr);
    path[MAXPATHLEN - 1] = '\0';

    int err = mkdir(path, 0755);
    if (err != 0 && errno != EEXIST) {
        LogError("mkdir() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    // replace '.' and ':' in ident - old NfSen requirement
    char *ident = strdup(ipStr);
    char *c = ident;
    while (*c != '\0') {
        if (*c == '.' || *c == ':') *c = '-';
        c++;
    }

    source_array_t *source_array = calloc(1, sizeof(source_array_t) + 1 * sizeof(struct ipList_s));
    if (!source_array) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }
    source_array->ipList->net = *ip;

    // allocate new flowsource for this IP
    FlowSource_t *fs = newFlowSource(ident, path, ctx->dynamicSource->subdir);
    if (fs == NULL) return NULL;

    source_array->fs = fs;
    source_array->ipNum = 1;

    // link at start of linked list
    source_array->next = ctx->source_array;
    ctx->source_array = source_array;

    fs->ipAddr = *ip;

    LogInfo("Dynamic source added: IP: %s, ident: %s in directory: %s", ipStr, ident, path);

    return fs;

}  // End of AddDynamicSource

FlowSource_t *GetFlowSource(collector_ctx_t *ctx, const struct sockaddr_storage *nf_sender) {
    ip128_t ipAddr;
    uint32_t family;
    if (GetClientIP(nf_sender, &ipAddr, &family) == 0) return NULL;

    // fast path - try cache
    if (ctx->lru_fs && ip128_equal(&ctx->lru_fs->ipAddr, &ipAddr)) {
        dbg_printf("LRU lookup success\n");
        return ctx->lru_fs;
    }

    // search in index
    FlowSource_t *fs = index_lookup(&ctx->index, &ipAddr);
    if (fs) {
        ctx->lru_fs = fs;
        fs->ipAddr = ipAddr;
        fs->sa_family = family;
        dbg_printf("Index lookup success\n");
        return fs;
    }

    // not in index - check for any IP allowed
    if (ctx->any_source) {
        // insert this IP into the index
        insertFlowSource(ctx, &ipAddr, ctx->any_source);
        ctx->any_source->ipAddr = ipAddr;
        ctx->any_source->sa_family = family;
        ctx->lru_fs = ctx->any_source;
        dbg_printf("Any source - add to index\n");
        return ctx->any_source;
    }

    // still unknown - check for IP list
    static const ip128_t zero128 = {.bytes = {0}};
    for (source_array_t *sa = ctx->source_array; sa != NULL; sa = sa->next) {
        for (int i = 0; i < sa->ipNum; i++) {
            if (ip128_equal(&sa->ipList[i].mask, &zero128)) {
                if (ip128_equal(&sa->ipList[i].net, &ipAddr)) {
                    FlowSource_t *fs = sa->fs;
                    insertFlowSource(ctx, &ipAddr, fs);
                    fs->ipAddr = ipAddr;
                    fs->sa_family = family;
                    ctx->lru_fs = fs;
                    dbg_printf("Fixed IP address - add to index\n");
                    return fs;
                }
            } else {
                if (ip_in_subnet(&ipAddr, &sa->ipList[i].net, &sa->ipList[i].mask)) {
                    FlowSource_t *fs = sa->fs;
                    insertFlowSource(ctx, &ipAddr, fs);
                    fs->ipAddr = ipAddr;
                    fs->sa_family = family;
                    ctx->lru_fs = fs;
                    dbg_printf("Fixed CIDR block - add IP to index\n");
                    return fs;
                }
            }
        }
    }

    // nothing found
    return NULL;
}  // End of GetFlowSource

FlowSource_t *NewDynFlowSource(collector_ctx_t *ctx, const struct sockaddr_storage *nf_sender) {
    ip128_t ipAddr;
    uint32_t family;
    if (GetClientIP(nf_sender, &ipAddr, &family) == 0) return NULL;

    // add new flowsource
    if (ctx->dynamicSource) {
        FlowSource_t *fs = AddDynamicSource(ctx, &ipAddr);
        if (fs == NULL) return NULL;

        insertFlowSource(ctx, &ipAddr, fs);
        fs->ipAddr = ipAddr;
        fs->sa_family = family;
        ctx->lru_fs = fs;

        dbg_printf("Dynamic source added\n");
        return fs;
    }

    return NULL;
}  // End of GetDynFlowSource

FlowSource_t *NextFlowSource(const collector_ctx_t *ctx) {
    // Static iteration state
    static source_array_t *source_array = NULL;

    // First call: ctx != NULL
    if (ctx) {
        source_array = ctx->source_array;

        // If any_source exists, return it first
        if (ctx->any_source) {
            return ctx->any_source;
        }

        // Otherwise fall through to daisy-chained sources
    }

    // no more sources
    if (source_array == NULL) return NULL;

    FlowSource_t *fs = source_array->fs;
    source_array = source_array->next;

    return fs;
}  // End of NextFlowSource

exporter_entry_t *NextExporter(FlowSource_t *fs) {
    // Static iteration state
    static exporter_table_t *tab = NULL;
    static uint32_t idx = 0;

    // First call: fs != NULL
    if (fs) {
        tab = &fs->exporters;
        idx = 0;
    }

    // No table to iterate
    if (!tab || tab->capacity == 0) return NULL;

    // Iterate through hash table
    while (idx < tab->capacity) {
        exporter_entry_t *e = &tab->entries[idx++];
        if (e->in_use) return e;
    }

    // Done
    tab = NULL;
    return NULL;

}  // End of NextExporter

void expand_exporter_table(exporter_table_t *tab) {
    uint32_t old_cap = tab->capacity;
    exporter_entry_t *old_entries = tab->entries;

    uint32_t new_cap = old_cap * 2;
    dbg_printf("Expand eporter table old: %u -> new: %u\n", old_cap, new_cap);
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

static void freeFlowSource(FlowSource_t *fs) {
    if (fs->exporters.entries) free(fs->exporters.entries);
    free(fs);
}  // End of freeFlowSource

static int inline GetClientIP(const struct sockaddr_storage *ss, ip128_t *ip, uint32_t *family) {
    union {
        const struct sockaddr_storage *ss;
        const struct sockaddr_in *sa_in;
        const struct sockaddr_in6 *sa_in6;
    } u;
    u.ss = ss;

    *family = ss->ss_family;
    switch (ss->ss_family) {
        case PF_INET: {
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN
            if (ss->ss_len != sizeof(struct sockaddr_in)) {
                // malformed struct
                LogError("Malformed IPv4 socket struct in '%s', line '%d'", __FILE__, __LINE__);
                return NULL;
            }
#endif
            memset(ip->bytes, 0, 10);
            ip->bytes[10] = 0xff;
            ip->bytes[11] = 0xff;
            memcpy(ip->bytes + 12, &u.sa_in->sin_addr.s_addr, 4);
        } break;
        case PF_INET6: {
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN
            if (ss->ss_len != sizeof(struct sockaddr_in6)) {
                // malformed struct
                LogError("Malformed IPv6 socket struct in '%s', line '%d'", __FILE__, __LINE__);
                return ip;
            }
#endif
            memcpy(ip->bytes, u.sa_in6->sin6_addr.s6_addr, 16);
            static const uint8_t prefix[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};

            if (memcmp(u.sa_in6->sin6_addr.s6_addr, prefix, 12) == 0) {
                // if listen on dual stack, check, if client was IPv4 client
                dbg_printf("IPv4 mapped IP address\n");
                *family = PF_INET;
            } else {
                *family = PF_INET6;
            }

        } break;
        default:
            // keep compiler happy
            *family = 0;
            memset(ip->bytes, 0, 16);

            LogError("Unknown sa family: %d in '%s', line '%d'", ss->ss_family, __FILE__, __LINE__);
            return 0;
    }

    return 1;
}  // End of GetClientIP

static int initFileInfo(FlowSource_t *fs, const char *ident, const char *dataDir, unsigned subDir) {
    // Check identifier
    if (CheckIdent(ident) == 0) {
        LogError("Invalid source identifier: %s", ident);
        return 0;
    }

    // data directory
    if (!CheckPath(dataDir, S_IFDIR)) {
        return 0;
    }
    char *path = realpath(dataDir, NULL);
    if (!path) {
        LogError("realpath() error %s: %s", dataDir, strerror(errno));
        return 0;
    }

    // current generic collector file
    char tmpFile[MAXPATHLEN];
    if (snprintf(tmpFile, MAXPATHLEN - 1, "%s/%s.XXXXXX", path, NF_TMPFILE) >= (MAXPATHLEN - 1)) {
        LogError("Path too long: %s", dataDir);
        return 0;
    }

    strncpy(fs->Ident, ident, IDENTLEN - 1);
    fs->Ident[IDENTLEN - 1] = '\0';

    fs->datadir = path;
    fs->subdir = subDir;
    fs->tmpFileName = strdup(tmpFile);
    if (fs->tmpFileName == NULL) {
        LogError("strdup() error: %s", strerror(errno));
        return 0;
    }

    return 1;

}  // End of newFileInfo

static void expand_source_index(source_index_t *idx) {
    uint32_t old_cap = idx->capacity;
    source_index_entry_t *old_entries = idx->entries;

    uint32_t new_cap = old_cap * 2;
    source_index_entry_t *new_entries = calloc(new_cap, sizeof(source_index_entry_t));
    if (!new_entries) {
        LogError("expand_source_index: calloc failed");
        return;  // in worst case, table stays full, lookups slow but correct
    }

    idx->entries = new_entries;
    idx->capacity = new_cap;
    idx->count = 0;

    uint32_t mask = new_cap - 1;
    for (uint32_t i = 0; i < old_cap; i++) {
        source_index_entry_t *e = &old_entries[i];
        if (!e->in_use) continue;

        uint32_t h = IP128HASH(&e->ip);
        uint32_t j = h & mask;

        while (new_entries[j].in_use) j = (j + 1) & mask;

        new_entries[j] = *e;
        idx->count++;
    }

    free(old_entries);
}  // End of expand_source_index

static inline FlowSource_t *index_lookup(const source_index_t *idx, const ip128_t *ip) {
    if (idx->count == 0) return NULL;

    uint32_t h = IP128HASH(ip);
    uint32_t mask = idx->capacity - 1;
    uint32_t i = h & mask;

    for (uint32_t probes = 0; probes < idx->capacity; probes++, i = (i + 1) & mask) {
        const source_index_entry_t *e = &idx->entries[i];
        if (!e->in_use) return NULL;
        if (ip128_equal(&e->ip, ip)) return e->fs;
    }

    return NULL;
}  // End of index_lookup

char *GetClientIPstring(struct sockaddr_storage *ss) {
    static char as[128];
    as[0] = '\0';

    union {
        struct sockaddr_storage *ss;
        struct sockaddr_in *sa_in;
        struct sockaddr_in6 *sa_in6;
    } u;
    u.ss = ss;

    int family = ss->ss_family;
    void *ptr = NULL;
    switch (ss->ss_family) {
        case PF_INET: {
            ptr = &u.sa_in->sin_addr;
        } break;
        case PF_INET6: {
            ptr = &u.sa_in6->sin6_addr;
            static const uint8_t prefix[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};
            if (memcmp(u.sa_in6->sin6_addr.s6_addr, prefix, 12) == 0) {
                family = PF_INET;
                ptr = &(u.sa_in6->sin6_addr.s6_addr[12]);
            }
        } break;
        default:
            snprintf(as, sizeof(as) - 1, "Unknown sa family: %d", ss->ss_family);
            return as;
    }

    inet_ntop(family, ptr, as, sizeof(as));
    return as;

}  // End of GetClientIPstring