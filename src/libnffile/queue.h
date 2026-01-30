/*
 *  Copyright (c) 2022-2026, Peter Haag
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

#ifndef _QUEUE_H
#define _QUEUE_H 1

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>

#define QUEUE_FULL ((void *)-1)
#define QUEUE_EMPTY ((void *)-2)
#define QUEUE_TIMEOUT ((void *)-3)
#define QUEUE_CLOSED ((void *)-4)

typedef struct element_s {
    void *data;
} element_t;

typedef struct queueStat_s {
    size_t maxUsed;
    size_t length;
} queueStat_t;

typedef struct queue_s {
    pthread_mutex_t mutex;

    pthread_cond_t cond_not_empty;  // consumers wait here
    pthread_cond_t cond_not_full;   // producers wait here

    uint32_t closed;  // flag - is queue closed

    size_t length;  // length of queue
    size_t mask;    // mask of queue
    uint32_t next_free;
    uint32_t next_avail;

    uint32_t producers;  // number of active producers
    uint32_t c_wait;     // consumers waiting
    uint32_t p_wait;     // producers waiting
    uint32_t aborted;    // terminate all action

    size_t num_elements;

    queueStat_t stat;
    void *element[];  // flexible array
} queue_t;

queue_t *queue_init(size_t length);

void queue_producers(queue_t *queue, unsigned producers);

void queue_free(queue_t *queue);

void *queue_push(queue_t *queue, void *data);

void *queue_try_push(queue_t *q, void *data);

void *queue_pop(queue_t *queue);

void *queue_try_pop(queue_t *q);

void queue_close(queue_t *queue);

void queue_sync(queue_t *queue);

void queue_abort(queue_t *q);

size_t queue_clear(queue_t *q, void (*free_fn)(void *));

queueStat_t queue_stat(queue_t *queue);

size_t queue_length(queue_t *queue);

#endif  // _QUEUE_H
