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

#include "queue.h"

#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "util.h"

queue_t *queue_init(size_t length) {
    queue_t *queue;

    if (!(length && ((length & (length - 1)) == 0))) {
        LogError("Queue length %zu not a power of 2", length);
        return NULL;
    }

    queue = calloc(1, sizeof(queue_t) + length * sizeof(element_t));
    if (!queue) {
        LogError("malloc() allocation error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }
    if (pthread_mutex_init(&queue->mutex, NULL) != 0) {
        LogError("pthread_mutex_init() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }
    if (pthread_cond_init(&queue->cond, NULL) != 0) {
        LogError("pthread_cond_init() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    queue->producers = 1;
    queue->length = length;
    queue->mask = length - 1;
    atomic_init(&queue->c_wait, 0);
    atomic_init(&queue->p_wait, 0);

    return queue;

}  // End of Queue_init

void queue_producers(queue_t *queue, unsigned producers) {
    //
    queue->producers = producers;
}  // End of queue_producers

void queue_free(queue_t *queue) {
    queue_sync(queue);
    free(queue);

}  // End of Queue_free

void queue_open(queue_t *queue) {
    pthread_mutex_lock(&(queue->mutex));
    queue->closed = 0;
    pthread_mutex_unlock(&(queue->mutex));

}  // End of queue_open

void queue_close(queue_t *queue) {
    pthread_mutex_lock(&(queue->mutex));
    queue->producers--;
    if (queue->producers <= 0) queue->closed = 1;
    if (queue->c_wait) {
        pthread_cond_broadcast(&(queue->cond));
    }
    pthread_mutex_unlock(&(queue->mutex));

}  // End of queue_close

size_t queue_length(queue_t *queue) {
    pthread_mutex_lock(&(queue->mutex));
    size_t length = queue->num_elements;
    pthread_mutex_unlock(&(queue->mutex));

    return length;

}  // End of queue_length

queueStat_t queue_stat(queue_t *queue) {
    pthread_mutex_lock(&(queue->mutex));
    queueStat_t stat = queue->stat;
    stat.length = queue->num_elements;
    queue->stat.maxUsed = 0;
    pthread_mutex_unlock(&(queue->mutex));
    return stat;
}  // End of queue_stat

// block until queue is empty
void queue_sync(queue_t *queue) {
    pthread_mutex_lock(&(queue->mutex));
    while (1) {
        if (queue->num_elements == 0) {
            // queue is empty
            if (queue->c_wait) {
                // signal waiting threads. If queue is closed, they quit too
                pthread_cond_broadcast(&(queue->cond));
            }
            pthread_mutex_unlock(&(queue->mutex));
            return;
        } else {
            queue->p_wait++;
            pthread_cond_wait(&(queue->cond), &(queue->mutex));
            queue->p_wait--;
        }
    }

    /*NOTREACHED*/

}  // End of queue_wait

void *queue_push(queue_t *queue, void *data) {
    pthread_mutex_lock(&(queue->mutex));
    while (1) {
        if (queue->closed) {
            pthread_mutex_unlock(&(queue->mutex));
            return QUEUE_CLOSED;
        }
        if (queue->num_elements < queue->length) {
            // push element into queue
            unsigned index = queue->next_free;
            queue->element[index] = data;
            queue->num_elements++;
            queue->next_free = (queue->next_free + 1) & queue->mask;

            if (queue->stat.maxUsed < queue->num_elements) queue->stat.maxUsed = queue->num_elements;

            // if consumers are waiting, signal new data
            if (atomic_load(&queue->c_wait)) {
                pthread_cond_signal(&(queue->cond));
            }
            pthread_mutex_unlock(&(queue->mutex));
            return NULL;
        } else {
            // queue is full - wait until a slot becomes available
            queue->p_wait++;
            pthread_cond_wait(&(queue->cond), &(queue->mutex));
            queue->p_wait--;
        }
    }

    /*NOTREACHED*/

}  // End of queue_push

void *queue_pop(queue_t *queue) {
    pthread_mutex_lock(&(queue->mutex));
    while (1) {
        if (queue->closed && queue->num_elements == 0) {
            pthread_mutex_unlock(&(queue->mutex));
            return QUEUE_CLOSED;
        }

        if (queue->num_elements > 0) {
            // get next element to be processed
            unsigned index = queue->next_avail;
            void *data = queue->element[index];
            queue->num_elements--;
            queue->next_avail = (queue->next_avail + 1) & queue->mask;

            // if a producer is waiting, signal the new free slot
            if (queue->p_wait) {
                pthread_cond_broadcast(&(queue->cond));
            }
            // if the queue was closed, signal all waiting consumers
            if (queue->closed && queue->c_wait) {
                pthread_cond_broadcast(&(queue->cond));
            }
            pthread_mutex_unlock(&(queue->mutex));
            return data;
        } else {
            // queue is empty - wait for next available element
            atomic_fetch_add(&queue->c_wait, 1);
            pthread_cond_wait(&(queue->cond), &(queue->mutex));
            atomic_fetch_sub(&queue->c_wait, 1);
        }
    }

    /*NOTREACHED*/

}  // End of queue_pop

/*
static void *producer(void *arg) {
    queue_t *queue = (queue_t *)arg;

    printf("producer started\n");
    for (long i = 1; i < 1024; i++) {
        queue_push(queue, (void *)i);
        printf("pushed data: %li\n", i);
        uint32_t randValue = arc4random();
        usleep(randValue);
    }
    printf("close Q\n");
    queue_close(queue);

    return NULL;
}

static void *consumer(void *arg) {
    printf("consumer started\n");
    queue_t *queue = (queue_t *)arg;
    while (1) {
        void *data = queue_pop(queue);
        if (data == QUEUE_CLOSED) {
            printf("Q closed\n");
            break;
        }
        printf("got data: %li\n", (long)data);
        uint32_t randValue = arc4random() & 0x1FFF;
        usleep(randValue);
    }
    return NULL;
}

int main(int argc, char **argv) {
    queue_t *queue = queue_init(128);
    pthread_t t1, t2;

    // pthread_create(&t1, NULL, producer, (void *)queue);
    pthread_create(&t1, NULL, consumer, (void *)queue);
    pthread_create(&t2, NULL, consumer, (void *)queue);

    for (long i = 1; i < 256; i++) {
        queue_push(queue, (void *)i);
        printf("pushed data: %li\n", i);
        uint32_t randValue = arc4random() & 0xFFF;
        usleep(randValue);
    }
    printf("wait Q\n");
    queue_sync(queue);
    printf("close Q\n");
    queue_close(queue);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    printf("Done\n");
    return 0;
}
*/
