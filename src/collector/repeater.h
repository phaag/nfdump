/*
 *  Copyright (c) 2023, Peter Haag
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

#ifndef _REPEATER_H
#define _REPEATER_H 1

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef FIX_INCLUDE
#include <sys/types.h>
#endif
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>

#define MAX_REPEATERS 8

typedef struct repeater_s {
    char *hostname;
    char *port;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    int sockfd;
    // Filtered repeater fields
    char *filter;           // Filter expression string (NULL = no filtering, forward all)
    void *filterEngine;     // Compiled filter engine (NULL = no filtering)
    int netflow_version;    // Output NetFlow version: 5 or 9 (default 5 for now)
    void *send_buffer;      // Buffer for encoding filtered flows
    void *buff_ptr;         // Current position in send buffer
    int flush;              // Flag indicating buffer should be flushed
    int index;              // Index of this repeater in the array
} repeater_t;

typedef struct repeater_message_s {
    int packet_size;
    socklen_t storage_size;
    struct sockaddr_storage addr;
} repeater_message_t;

// Message for filtered repeater, sends to a specific repeater by index
typedef struct filtered_repeater_message_s {
    int packet_size;        // Size of the encoded NetFlow packet
    int repeater_index;     // Index of the target repeater
} filtered_repeater_message_t;

// Buffer size for encoding filtered flows
#define FILTERED_SEND_BUFFER_SIZE 65536

int StartupRepeater(repeater_t *repeater, unsigned bufflen, unsigned srcSpoofing, char *userid, char *groupid);

// Check if any repeater has a filter configured
int HasFilteredRepeaters(repeater_t *repeater);

// Initialize filtered repeater resources (buffers, etc.)
int InitFilteredRepeater(repeater_t *rep);

// Cleanup filtered repeater resources
void CleanupFilteredRepeater(repeater_t *rep);

#endif