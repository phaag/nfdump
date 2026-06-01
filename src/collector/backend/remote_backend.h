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

/*
 * remote backend — forwards collected flows to a remote nfcapd instance via UDP.
 *
 * Sends nfd v250 (plain) or v251 (XChaCha20-Poly1305 encrypted) packets to the
 * configured destination.  A single FlowSource is supported; -M and -n are
 * incompatible with this backend.
 *
 * The backend is selected when nfcapd is invoked with -H host[/port].
 */

#ifndef _REMOTE_BACKEND_H
#define _REMOTE_BACKEND_H 1

#include <pthread.h>
#include <stdint.h>

#include "flowsource.h"
#include "network/repeater.h"
#include "queue.h"

typedef struct udpsend_backend_ctx_s {
    repeater_t sendHost;          /* UDP target: addr, addrlen, sockfd  */
    const uint8_t *udpSessionKey; /* NULL = plain v250, else v251 AEAD  */
    uint32_t sequence;            /* incrementing packet sequence number */
    queue_t *blockQueue;          /* queue from the collector frontend   */
    pthread_t self;               /* thread ID                           */
} udpsend_backend_ctx_t;

/*
 * Init_udpsend_backend — initialise the UDP send backend for a FlowSource.
 *
 * sendHost      A pre-populated repeater_t with sockfd already opened via
 *               Unicast_send_socket().
 * udpSessionKey 32-byte derived key for v251 AEAD encryption; NULL for plain v250.
 *
 * Sets fs->backend_ctx and fs->blockQueue.
 * Returns 0 on success, 1 on error.
 */
int Init_udpsend_backend(FlowSource_t *fs, const repeater_t *sendHost, const uint8_t *udpSessionKey);

/* Launch_udpsend_backend — start the backend thread.  Returns 1 on success. */
int Launch_udpsend_backend(FlowSource_t *fs);

/* Close_udpsend_backend — close queue, join thread, free context. */
void Close_udpsend_backend(FlowSource_t *fs);

#endif /* _REMOTE_BACKEND_H */
