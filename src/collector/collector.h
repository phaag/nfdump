/*
 *  Copyright (c) 2009-2024, Peter Haag
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
#include "nffile.h"

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

#define SYSLOG_FACILITY "daemon"

/* common minimum netflow header for all versions */
typedef struct common_flow_header {
    uint16_t version;
    uint16_t count;
} common_flow_header_t;

typedef struct FlowSource_s {
    // link
    struct FlowSource_s *next;

    // exporter identifiers
    char Ident[IDENTLEN];
    ip_addr_t ip;
    uint32_t sa_family;
    in_port_t port;

    int any_source;
    bookkeeper_t *bookkeeper;

    // all about data storage
    char *datadir;           // where to store data for this source
    char *current;           // current file name - typically nfcad.current.pid
    int subdir;              // sub dir structur
    nffile_t *nffile;        // the writing file handle
    dataBlock_t *dataBlock;  // writing buffer

    // statistical data per source
    uint32_t bad_packets;
    uint64_t msecFirst;  // in msec
    uint64_t msecLast;   // in msec

    // Any exporter specific data
    exporter_t *exporter_data;
    uint32_t exporter_count;
    struct timeval received;

} FlowSource_t;

/* input buffer size, to read data from the network */
#define NETWORK_INPUT_BUFF_SIZE 65535  // Maximum UDP message size

#define UpdateFirstLast(fs, First, Last) \
    if ((First) < (fs)->msecFirst) {     \
        (fs)->msecFirst = (First);       \
    }                                    \
    if ((Last) > (fs)->msecLast) {       \
        (fs)->msecLast = (Last);         \
    }

// prototypes
int AddFlowSource(FlowSource_t **FlowSource, char *ident, char *ip, char *flowpath);

int AddFlowSourceConfig(FlowSource_t **FlowSource);

int AddFlowSourceString(FlowSource_t **FlowSource, char *argument);

int SetDynamicSourcesDir(FlowSource_t **FlowSource, char *dir);

FlowSource_t *AddDynamicSource(FlowSource_t **FlowSource, struct sockaddr_storage *ss);

int RotateFlowFiles(time_t t_start, char *time_extension, FlowSource_t *fs, int done);

int TriggerLauncher(time_t t_start, char *time_extension, int pfd, FlowSource_t *fs);

void FlushStdRecords(FlowSource_t *fs);

void FlushExporterStats(FlowSource_t *fs);

int FlushInfoExporter(FlowSource_t *fs, exporter_info_record_t *exporter);

int ScanExtension(char *extensionList);

char *GetExporterIP(FlowSource_t *fs);

#endif  //_COLLECTOR_H
