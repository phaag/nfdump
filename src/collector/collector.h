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

/* overdue time:
 * if nfcapd does not get any data, wake up the receive system call
 * at least after OVERDUE_TIME seconds after the time window
 */
#define OVERDUE_TIME 10

// time nfcapd will wait for launcher to terminate
#define LAUNCHER_TIMEOUT 60

// common minimum netflow header for all versions
typedef struct common_flow_header {
    uint16_t version;
    uint16_t count;
} common_flow_header_t;

// argument vector for post processor thread
typedef struct post_args_s {
    pthread_mutex_t mutex;  // synchronisation
    pthread_cond_t cond;    // synchronisation
    // const args
    char *time_extension;  // parameter passing
    collector_ctx_t *ctx;  // pasarmeter passing
    pthread_t tid;         // tid of post processor thread
    int pfd;               // launcher fd if used by post-processor
    // cycle args
    int cycle_pending;  // 0 = idle, 1 = work pending/in progress
    int done;           // shutdown flag
    time_t when;        // t_start for current cycle
} post_args_t;

#define UpdateFirstLast(nffile, First, Last)              \
    if ((First) < (nffile)->stat_record->msecFirstSeen) { \
        (nffile)->stat_record->msecFirstSeen = (First);   \
    }                                                     \
    if ((Last) > (nffile)->stat_record->msecLastSeen) {   \
        (nffile)->stat_record->msecLastSeen = (Last);     \
    }

int ConfigureDefaultFlowSource(collector_ctx_t *ctx, const char *ident, const char *dataDir, unsigned subDir);

int ConfigureDynFlowSource(collector_ctx_t *ctx, const char *dynFlowDir, unsigned subDir);

int ConfigureFixedFlowSource(collector_ctx_t *ctx, stringlist_t *sourceList, unsigned subDir);

int AddFlowSourceConfig(collector_ctx_t *ctx);

FlowSource_t *AddDynamicSource(collector_ctx_t *ctx, const char *ipStr);

int RotateCycle(const collector_ctx_t *ctx, post_args_t *post_args, time_t t_start, int done);

void FlushStdRecords(FlowSource_t *fs);

void FlushExporterStats(FlowSource_t *fs);

int FlushInfoExporter(FlowSource_t *fs, exporter_info_record_t *exporter);

int ScanExtension(char *extensionList);

int Lauch_postprocessor(post_args_t *post_args);

void CleanupCollector(collector_ctx_t *ctx, post_args_t *post_args);

#endif  //_COLLECTOR_H
