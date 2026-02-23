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

#ifndef _REPEATER_H
#define _REPEATER_H 1

#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "queue.h"

#define MAX_REPEATERS 8
#define REPEATER_QUEUE_CAPACITY 8

typedef struct repeater_host_s {
    char *hostname;
    char *port;
} repeater_host_t;

typedef struct repeater_s {
    char *hostname;
    char *port;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    int sockfd;   // UDP socket if spoofed == 0
    int use_raw;  // 0 = normal UDP, 1 = spoof via raw
} repeater_t;

typedef struct repeater_ctx_s {
    _Atomic int done;                    // done flag
    queue_t *bufferQueue;                // queue of empty buffers to reuse
    queue_t *packetQueue;                // queue of packets to repeat
    pthread_t tid;                       // tid of repeater thread
    int rawSocket;                       // if we do src spoofing, use this raw socket
    repeater_t repeater[MAX_REPEATERS];  // array of MAX_REPEATERS
} repeater_ctx_t;

repeater_ctx_t *RepeaterInit(repeater_host_t *repeater_host, uint32_t queue_len, int srcSpoofing);

pthread_t RepeaterStart(repeater_ctx_t *repeater_ctx);

void RepeaterShutdown(repeater_ctx_t *rctx);

#endif