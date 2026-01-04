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

#ifndef _FLOWSOURCE_H
#define _FLOWSOURCE_H 1

#include <netinet/in.h>
#include <stdint.h>

#include "bookkeeper.h"
#include "exporter.h"
#include "nffileV2.h"

// FlowSource struct:
// contains information about the backend
// contains the hash of exporters for this flow source
typedef struct FlowSource_s {
    char Ident[IDENTLEN];      // source identifier
    bookkeeper_t *bookkeeper;  // legacy nfsen bookkeeper - may get removed in future
    char *datadir;             // base dir to store flow files
    char *tmpFileName;         // name of tmp collection file
    unsigned subdir;           // index of sub dir layout - see nffile.h
    nffile_t *nffile;          // nffile handle
    dataBlock_t *dataBlock;    // current datablock to write records

    ip128_t ipAddr;        // IPv4/IPv6 address of this flow source
    int sa_family;         // AF_INET of AF_INET6 cacheonly flag
    uint32_t bad_packets;  // bad packets from this IP

    exporter_table_t exporters;  // exporter hash array for this IP
    exporter_key_t last_key;     // last used exporter key - cache
    exporter_entry_t *last_exp;  // last used exporter entry - cache
    struct timeval received;     // time last packet received
} FlowSource_t;

// index entry per flow source
// Points to the FlowSource for this entry
// provides IP filter information:
// - if mask != {0}
//   allows IP addresses which match ip[1]/mask
// if mask == {0}
//   allows IP addresses stored in array ip[] of ipNum IPs
typedef struct source_index_entry_s {
    ip128_t ip;
    FlowSource_t *fs;
    uint32_t in_use;
} source_index_entry_t;

typedef struct source_index_s {
    source_index_entry_t *entries;
    // start with this number of sources
#define NUMSOURCES 8
    uint32_t capacity;  // power of 2 sources
    uint32_t count;
} source_index_t;

typedef struct source_array_s {
    struct source_array_s *next;  // daisy chain
    FlowSource_t *fs;             // allocated FlowSource

    uint32_t ipNum;  // number of entries in ipList
    struct ipList_s {
        ip128_t net;   // exact ip is mask = {0}, else network address
        ip128_t mask;  // mask = {0} for single IP, else network mask
    } ipList[];
} source_array_t;

typedef struct collector_ctx_s {
    FlowSource_t *lru_fs;          // last recently used flow source - cache
    FlowSource_t *any_source;      // option  -w - fast path if one source accepts any IP
    FlowSource_t *dynamicSource;   // option  -M - flow sources are allocated dynamically for each IP
    source_index_t index;          // options -n - list of flow sources with attached IPs
    uint32_t numFlowSources;       // number of entries in source_array
    source_array_t *source_array;  // linear array of all flow sources with IP filter
} collector_ctx_t;

// prototypes
int init_collector_ctx(collector_ctx_t *ctx);

FlowSource_t *newFlowSource(const char *ident, const char *dataDir, unsigned subDir);

void insertFlowSource(collector_ctx_t *ctx, const ip128_t *ip, FlowSource_t *fs);

FlowSource_t *GetFlowSource(collector_ctx_t *ctx, const struct sockaddr_storage *nf_sender);

FlowSource_t *NewDynFlowSource(collector_ctx_t *ctx, const struct sockaddr_storage *nf_sender);

FlowSource_t *NextFlowSource(const collector_ctx_t *ctx);

exporter_entry_t *NextExporter(FlowSource_t *fs);

void expand_exporter_table(exporter_table_t *tab);

char *GetClientIPstring(struct sockaddr_storage *ss);

#endif
