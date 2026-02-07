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

#ifndef _FILTERED_REPEATER_H
#define _FILTERED_REPEATER_H 1

#include "repeater.h"
#include "nfxV3.h"

// Forward declaration
struct FlowSource_s;

// Context for filtered repeater state
typedef struct filtered_repeater_ctx_s {
    repeater_t *repeater;       // Array of repeaters
    int num_repeaters;          // Number of configured repeaters
    int num_filtered;           // Number of repeaters with filters
    int rfd;                    // Pipe file descriptor for privsep communication
} filtered_repeater_ctx_t;

// Initialize filtered repeaters (compile filters, allocate buffers)
// Returns 0 on success, -1 on error
int InitFilteredRepeaters(repeater_t *repeater, int rfd);

// Cleanup filtered repeater resources
void CleanupFilteredRepeaters(repeater_t *repeater);

// Check if any repeater has a filter configured
int HasFilteredRepeaters(repeater_t *repeater);

// Process a decoded flow record through filtered repeaters
// Called for each flow record after it's been decoded
// recordHeaderV3: pointer to the decoded V3 record
// Returns number of repeaters the record was sent to
int ProcessFilteredRecord(repeater_t *repeater, int rfd, recordHeaderV3_t *recordHeaderV3);

// Flush all filtered repeater buffers (call at end of packet or periodically)
void FlushFilteredRepeaters(repeater_t *repeater, int rfd);

#endif  // _FILTERED_REPEATER_H
