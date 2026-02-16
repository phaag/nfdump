/*
 *  Copyright (c) 2023-2026, Peter Haag
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

#include "packet_pcap.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

/*
 * Batch helper functions for pcap file processing
 */

PktBatch_t *batch_alloc(size_t cap, uint32_t snaplen) {
    PktBatch_t *batch = calloc(1, sizeof(PktBatch_t) + cap * sizeof(PacketRef));
    if (!batch) {
        LogError("batch_alloc() error in %s line %d", __FILE__, __LINE__);
        return NULL;
    }
    batch->capacity = cap;
    batch->count = 0;
    batch->payload_size = 0;
    batch->payload_slab = NULL;

    // no payload memory required for mmap file
    if (snaplen == 0) return batch;

    // Add payload memory
    // round snaplen up to 16-byte boundary
    size_t payload_size = (snaplen + 15u) & ~15u;
    size_t total = payload_size * cap;

    void *mem = NULL;
    if (posix_memalign(&mem, 16, total) != 0) {
        LogError("posix_memalign() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        free(batch);
        return NULL;
    }
    batch->payload_size = payload_size;
    batch->payload_slab = mem;

    return batch;
}  // End of batch_alloc

void batch_clear(PktBatch_t *batch) {
    // reset counter
    batch->count = 0;
}  // End of batch_clear

void batch_free(PktBatch_t *batch) {
    if (!batch) return;

    if (batch->payload_slab) free(batch->payload_slab);

    free(batch);
}  // End of batch_free
