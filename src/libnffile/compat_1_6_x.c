/*
 *  Copyright (c) 2024-2026, Peter Haag
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

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "nfdump_1_6_x.h"
#include "nffile.h"
#include "nffileV2.h"
#include "util.h"

static void UpdateStat(stat_record_t *s, stat_recordV1_t *sv1) {
    s->numflows = sv1->numflows;
    s->numbytes = sv1->numbytes;
    s->numpackets = sv1->numpackets;
    s->numflows_tcp = sv1->numflows_tcp;
    s->numflows_udp = sv1->numflows_udp;
    s->numflows_icmp = sv1->numflows_icmp;
    s->numflows_other = sv1->numflows_other;
    s->numbytes_tcp = sv1->numbytes_tcp;
    s->numbytes_udp = sv1->numbytes_udp;
    s->numbytes_icmp = sv1->numbytes_icmp;
    s->numbytes_other = sv1->numbytes_other;
    s->numpackets_tcp = sv1->numpackets_tcp;
    s->numpackets_udp = sv1->numpackets_udp;
    s->numpackets_icmp = sv1->numpackets_icmp;
    s->numpackets_other = sv1->numpackets_other;
    s->msecFirstSeen = 1000LL * (uint64_t)sv1->first_seen + (uint64_t)sv1->msec_first;
    s->msecLastSeen = 1000LL * (uint64_t)sv1->last_seen + (uint64_t)sv1->msec_last;
    s->sequence_failure = sv1->sequence_failure;
}  // End of UpdateStat

int Convert_v1fileHeader(nffile_t *nffile, const char *filename, struct stat *stat_buf) {
    dbg_printf("Found layout type 1 => convert\n");
    // transparent read old v1 layout
    // convert old layout
    fileHeaderV1_t fileHeaderV1;

    // re-read file header - assume layout V1
    if (lseek(nffile->fd, 0, SEEK_SET) < 0) {
        LogError("lseek() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        DisposeFile(nffile);
        return 0;
    }

    int ret = read(nffile->fd, (void *)&fileHeaderV1, sizeof(fileHeaderV1_t));
    if (ret < 1) {
        LogError("read() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        DisposeFile(nffile);
        return 0;
    }

    if (ret != sizeof(fileHeaderV1_t)) {
        LogError("Short read from file: %s", filename);
        DisposeFile(nffile);
        return 0;
    }

    if (fileHeaderV1.version != LAYOUT_VERSION_1) {
        LogError("Open file %s: bad version: %u", filename, fileHeaderV1.version);
        DisposeFile(nffile);
        return 0;
    }

    // initialize V2 header
    memset((void *)nffile->file_header, 0, sizeof(fileHeaderV2_t));
    nffile->file_header->magic = MAGIC;
    nffile->file_header->version = LAYOUT_VERSION_2;
    nffile->file_header->nfdversion = NFDVERSION;
#ifdef __APPLE__
#define st_mtim st_mtimespec
#endif
    nffile->file_header->created = stat_buf->st_mtim.tv_sec;
    nffile->file_header->compression = FILEV1_COMPRESSION(&fileHeaderV1);
    nffile->compression_level = 0;
    nffile->file_header->encryption = NOT_ENCRYPTED;
    nffile->file_header->NumBlocks = fileHeaderV1.NumBlocks;
    if (strlen(fileHeaderV1.ident) > 0) nffile->ident = strdup(fileHeaderV1.ident);

    // read v1 stat record
    stat_recordV1_t stat_recordV1;
    ret = read(nffile->fd, (void *)&stat_recordV1, sizeof(stat_recordV1_t));
    if (ret < 0) {
        LogError("read() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        DisposeFile(nffile);
        return 0;
    }
    UpdateStat(nffile->stat_record, &stat_recordV1);

    return 1;

}  // End of Convert_v1fileHeader