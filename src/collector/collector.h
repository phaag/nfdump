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

#ifndef _COLLECTOR_H
#define _COLLECTOR_H 1

#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "bookkeeper.h"
#include "config.h"
#include "exporter.h"
#include "flist.h"
#include "flowsource.h"
#include "ip128.h"
#include "nffile.h"
#include "util.h"

#define ANYIP NULL

#define FNAME_SIZE 256

/* Default time window in seconds to rotate files */
#define TIME_WINDOW 300

// time nfcapd will wait for launcher to terminate
#define LAUNCHER_TIMEOUT 60

// common minimum netflow header for all versions
typedef struct common_flow_header {
    uint16_t version;
    uint16_t count;
} common_flow_header_t;

typedef struct cycle_message_s {
    time_t when;  // timestamp of cycle
    int done;     // done flag
    // stat_record of flowsource follows
} cycle_message_t;

#define UpdateFirstLast(fs, First, Last)                                                     \
    if ((First) < (fs)->stat_record.msecFirstSeen || (fs)->stat_record.msecFirstSeen == 0) { \
        (fs)->stat_record.msecFirstSeen = (First);                                           \
    }                                                                                        \
    if ((Last) > (fs)->stat_record.msecLastSeen) {                                           \
        (fs)->stat_record.msecLastSeen = (Last);                                             \
    }

int ConfigureDefaultFlowSource(collector_ctx_t *ctx, const char *ident, const char *dataDir, unsigned subDir);

int ConfigureDynFlowSource(collector_ctx_t *ctx, const char *dynFlowDir, unsigned subDir);

int ConfigureFixedFlowSource(collector_ctx_t *ctx, stringlist_t *sourceList, unsigned subDir);

int AddFlowSourceConfig(collector_ctx_t *ctx);

int PeriodicCycle(const collector_ctx_t *ctx, time_t t_start, int done);

uint32_t AssignExporterID(void);

void FlushExporter(FlowSource_t *fs);

void FlushStdRecords(FlowSource_t *fs);

void FlushExporterStats(FlowSource_t *fs);

int FlushInfoExporter(FlowSource_t *fs, exporter_info_record_v4_t *exporter);

int ScanExtension(char *extensionList);

void CleanupCollector(collector_ctx_t *ctx);

#endif  //_COLLECTOR_H
