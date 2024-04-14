/*
 *  Copyright (c) 2022, Peter Haag
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

#define QUEUE_FULL (void *)-1
#define QUEUE_EMPTY (void *)-2
#define QUEUE_CLOSED (void *)-3

typedef struct element_s {
    void *data;
} element_t;

typedef struct queueStat_s {
    size_t maxUsed;
    size_t length;
} queueStat_t;

typedef struct queue_s {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    uint32_t closed;

    size_t length;
    size_t mask;
    unsigned next_free;
    unsigned next_avail;
    int producers;
    _Atomic unsigned c_wait;
    _Atomic unsigned p_wait;
    size_t num_elements;

    queueStat_t stat;
    void *element[1];
} queue_t;

queue_t *queue_init(size_t length);

void queue_producers(queue_t *queue, unsigned producers);

void queue_free(queue_t *queue);

void *queue_push(queue_t *queue, void *data);

void *queue_pop(queue_t *queue);

void queue_open(queue_t *queue);

void queue_close(queue_t *queue);

void queue_sync(queue_t *queue);

queueStat_t queue_stat(queue_t *queue);

size_t queue_length(queue_t *queue);

uint32_t queue_done(queue_t *queue);

#endif  // _QUEUE_H
