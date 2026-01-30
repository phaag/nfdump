/*
 *  Copyright (c) 2025-2026, Peter Haag
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
    if (!(length && ((length & (length - 1)) == 0))) {
        LogError("Queue length %zu not a power of 2", length);
        return NULL;
    }

    queue_t *q = calloc(1, sizeof(queue_t) + length * sizeof(void *));
    if (!q) {
        LogError("calloc() allocation error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond_not_empty, NULL);
    pthread_cond_init(&q->cond_not_full, NULL);

    q->length = length;
    q->mask = length - 1;
    q->producers = 1;

    return q;
}  // End of Queue_init

void queue_producers(queue_t *queue, unsigned producers) {
    //
    queue->producers = producers;
}  // End of queue_producers

void queue_free(queue_t *q) {
    if (!q) return;

    // Free any remaining elements (safe even after abort)
    queue_clear(q, free);

    // Destroy synchronization primitives
    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->cond_not_empty);
    pthread_cond_destroy(&q->cond_not_full);

    // Free queue memory
    free(q);
}  // End of queue_free

void queue_close(queue_t *q) {
    pthread_mutex_lock(&q->mutex);

    q->producers--;
    if (q->producers == 0) {
        q->closed = 1;
        pthread_cond_broadcast(&q->cond_not_empty);
        pthread_cond_broadcast(&q->cond_not_full);
    }

    pthread_mutex_unlock(&q->mutex);
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
void queue_sync(queue_t *q) {
    pthread_mutex_lock(&q->mutex);

    while (q->num_elements > 0) pthread_cond_wait(&q->cond_not_full, &q->mutex);

    pthread_mutex_unlock(&q->mutex);

    // UNREACHED

}  // End of queue_wait

void *queue_push(queue_t *q, void *data) {
    pthread_mutex_lock(&q->mutex);

    if (q->aborted) {
        pthread_mutex_unlock(&q->mutex);
        return QUEUE_CLOSED;
    }

    while (1) {
        if (q->closed) {
            pthread_mutex_unlock(&q->mutex);
            return QUEUE_CLOSED;
        }

        if (q->num_elements < q->length) {
            unsigned idx = q->next_free;
            q->element[idx] = data;
            q->next_free = (idx + 1) & q->mask;
            q->num_elements++;

            // if consumers are waiting, signal new data
            if (q->c_wait > 0) pthread_cond_signal(&q->cond_not_empty);

            pthread_mutex_unlock(&q->mutex);
            return NULL;
        }

        // queue full
        q->p_wait++;
        pthread_cond_wait(&q->cond_not_full, &q->mutex);
        q->p_wait--;
    }

    // NOTREACHED

}  // End of queue_push

void *queue_try_push(queue_t *q, void *data) {
    pthread_mutex_lock(&q->mutex);

    if (q->aborted) {
        pthread_mutex_unlock(&q->mutex);
        return QUEUE_CLOSED;
    }

    if (q->closed) {
        pthread_mutex_unlock(&q->mutex);
        return QUEUE_CLOSED;
    }

    if (q->num_elements == q->length) {
        pthread_mutex_unlock(&q->mutex);
        return QUEUE_FULL;
    }

    unsigned idx = q->next_free;
    q->element[idx] = data;
    q->next_free = (idx + 1) & q->mask;
    q->num_elements++;

    if (q->c_wait > 0) pthread_cond_signal(&q->cond_not_empty);

    pthread_mutex_unlock(&q->mutex);
    return NULL;
}  // End of queue_try_push

void *queue_pop(queue_t *q) {
    pthread_mutex_lock(&q->mutex);

    if (q->aborted) {
        pthread_mutex_unlock(&q->mutex);
        return QUEUE_CLOSED;
    }

    while (1) {
        if (q->num_elements > 0) {
            unsigned idx = q->next_avail;
            void *data = q->element[idx];
            q->next_avail = (idx + 1) & q->mask;
            q->num_elements--;

            pthread_cond_signal(&q->cond_not_full);

            pthread_mutex_unlock(&q->mutex);
            return data;
        }

        if (q->closed) {
            pthread_mutex_unlock(&q->mutex);
            return QUEUE_CLOSED;
        }

        // queue empty
        q->c_wait++;
        pthread_cond_wait(&q->cond_not_empty, &q->mutex);
        q->c_wait--;
    }

    // NOTREACHED

}  // End of queue_pop

void *queue_try_pop(queue_t *q) {
    pthread_mutex_lock(&q->mutex);

    if (q->aborted) {
        pthread_mutex_unlock(&q->mutex);
        return QUEUE_CLOSED;
    }

    if (q->num_elements == 0) {
        if (q->closed) {
            pthread_mutex_unlock(&q->mutex);
            return QUEUE_CLOSED;
        }
        pthread_mutex_unlock(&q->mutex);
        return QUEUE_EMPTY;
    }

    unsigned idx = q->next_avail;
    void *data = q->element[idx];
    q->next_avail = (idx + 1) & q->mask;
    q->num_elements--;

    pthread_cond_signal(&q->cond_not_full);

    pthread_mutex_unlock(&q->mutex);
    return data;
}  // End of queue_try_pop

void *queue_pop_timed(queue_t *q, const struct timespec *abstime) {
    pthread_mutex_lock(&q->mutex);

    while (1) {
        if (q->num_elements > 0) {
            unsigned idx = q->next_avail;
            void *data = q->element[idx];
            q->next_avail = (idx + 1) & q->mask;
            q->num_elements--;

            if (q->p_wait > 0) pthread_cond_signal(&q->cond_not_full);

            pthread_mutex_unlock(&q->mutex);
            return data;
        }

        if (q->closed) {
            pthread_mutex_unlock(&q->mutex);
            return QUEUE_CLOSED;
        }

        q->c_wait++;
        int rc = pthread_cond_timedwait(&q->cond_not_empty, &q->mutex, abstime);
        q->c_wait--;

        if (rc == ETIMEDOUT) {
            pthread_mutex_unlock(&q->mutex);
            return QUEUE_TIMEOUT;
        }
    }
}  // End of queue_pop_timed

void queue_abort(queue_t *q) {
    pthread_mutex_lock(&q->mutex);

    q->aborted = 1;
    q->closed = 1;     // ensure all threads exit
    q->producers = 0;  // no more producers

    // wake everyone to leave queue
    pthread_cond_broadcast(&q->cond_not_empty);
    pthread_cond_broadcast(&q->cond_not_full);

    pthread_mutex_unlock(&q->mutex);
}  // End of queue_abort

// Clears the queue and returns the number of cleared elements.
// The caller receives each element via the callback.
size_t queue_clear(queue_t *q, void (*free_fn)(void *)) {
    pthread_mutex_lock(&q->mutex);

    size_t count = q->num_elements;

    for (size_t i = 0; i < count; i++) {
        unsigned idx = (q->next_avail + i) & q->mask;
        void *elem = q->element[idx];
        if (elem && free_fn) free_fn(elem);
    }

    // Reset queue state
    q->next_avail = 0;
    q->next_free = 0;
    q->num_elements = 0;

    pthread_mutex_unlock(&q->mutex);
    return count;
}  // End of queue_clear

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
