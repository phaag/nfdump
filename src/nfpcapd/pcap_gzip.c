/*
 *  Copyright (c) 2025, Peter Haag
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

#include "pcap_gzip.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "packet_pcap.h"
#include "util.h"
#include "zlib.h"

int OpenZIPfile(readerParam_t *readerParam, struct pcap_file_header *fileHeader, const char *fileName) {
    gzFile gz = gzopen(fileName, "rb");
    if (!gz) {
        LogError("Reading pcapd file: not a compressed file");
        return 0;
    }
    if (gzread(gz, fileHeader, sizeof(struct pcap_file_header)) != sizeof(struct pcap_file_header)) {
        LogError("Reading compressed pcapd file: failed to read header");
        gzclose(gz);
        return 0;
    }

    if (fileHeader->magic != 0xd4c3b2a1 && fileHeader->magic != 0xa1b2c3d4) {
        LogError("Reading compressed pcapd file: MAGIC missmatch - not a pcap file");
        gzclose(gz);
        return 0;
    }

    if (fileHeader->magic == 0xd4c3b2a1) readerParam->swapped = 1;

    readerParam->gz = 1;
    readerParam->gzfp = gz;
    readerParam->snaplen = fileHeader->snaplen;
    readerParam->linkType = fileHeader->linktype;
    // use fix batch size, as we need payload memory as well
    readerParam->batch_size = 64;

    if (readerParam->snaplen == 0) {
        LogError("Missing snaplen in pcap file header");
        gzclose(gz);
        return 0;
    }
    return 1;

}  // End of OpenGZIPfile

int reader_gz_run(readerParam_t *readerParam) {
    gzFile gz = readerParam->gzfp;
    size_t batch_size = readerParam->batch_size;
    int swapped = readerParam->swapped;

    // make sure we have a snaplen, as we need extra memory for the payload
    if (readerParam->snaplen == 0) {
        LogError("snaplen 0 in pcap file");
        return -1;
    }

    // header already processed
    PktBatch_t *batch = batch_alloc(batch_size, readerParam->snaplen);
    if (!batch) return -1;

    struct pcaprec_hdr rh;
    while (gzread(gz, &rh, sizeof(rh)) == sizeof(rh)) {
        /* reference into mmap region */
        PacketRef pr;
        if (swapped) {
            pr.hdr.ts.tv_sec = swap32(rh.ts_sec);
            pr.hdr.ts.tv_usec = swap32(rh.ts_usec);
            pr.hdr.caplen = swap32(rh.incl_len);
            pr.hdr.len = swap32(rh.orig_len);
        } else {
            pr.hdr.ts.tv_sec = rh.ts_sec;
            pr.hdr.ts.tv_usec = rh.ts_usec;
            pr.hdr.caplen = rh.incl_len;
            pr.hdr.len = rh.orig_len;
        }

        int incl = pr.hdr.caplen;

        // get new payload handle
        void *buf = payload_handle(batch, batch->count);

        // should never trigger - test it anyway to prevent memory corruption
        dbg_assert(incl <= batch->payload_size);
        if (incl > batch->payload_size) {
            incl = batch->payload_size;
        }
        int got = gzread(gz, buf, incl);
        if (got != (int)incl) {
            LogError("Failed to gzread payload of size: %u", incl);
            break;
        }

        pr.data = buf;
        // apply filter if present
        if (readerParam->have_filter) {
            if (!pcap_offline_filter(&readerParam->prog, &pr.hdr, pr.data)) {
                // packet doesn't match; skip
                continue;
            }
        }

        batch->pkts[batch->count++] = pr;

        if (batch->count == batch->capacity) {
            if (queue_push(readerParam->batchQueue, batch) == QUEUE_CLOSED) {
                batch_free(batch);
                return -1;
            }

            batch = batch_alloc(batch_size, readerParam->snaplen);
            if (!batch) {
                return -1;
            }
        }
    }

    if (batch->count > 0) {
        if (queue_push(readerParam->batchQueue, batch) == QUEUE_CLOSED) {
            batch_free(batch);
            return -1;
        }
        batch = NULL;
    } else {
        batch_free(batch);
    }

    return 0;
}  // End of reader_gz_run
