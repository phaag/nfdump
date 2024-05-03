/*
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

#include "blocksort.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

void blocksort(SortElement_t *data, int len);

#define swap(a, b)              \
    {                           \
        SortElement_t _h = (a); \
        (a) = (b);              \
        (b) = _h;               \
    }

#define min(a, b) ((a) < (b) ? (a) : (b))

#define sort3fast(a, b, c)               \
    if ((b).count < (a).count) {         \
        if ((c).count < (a).count) {     \
            if ((c).count < (b).count) { \
                swap(a, c);              \
            } else {                     \
                SortElement_t h = (a);   \
                (a) = (b);               \
                (b) = (c);               \
                (c) = h;                 \
            }                            \
        } else {                         \
            swap((a), (b));              \
        }                                \
    } else {                             \
        if ((c).count < (b).count) {     \
            if ((c).count < (a).count) { \
                SortElement_t h = (c);   \
                (c) = (b);               \
                (b) = (a);               \
                (a) = h;                 \
            } else {                     \
                swap((b), (c));          \
            }                            \
        }                                \
    }

static int max_threads;
static int n_threads;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

// static void init(SortElement_t *data, int len);

static void qusort(SortElement_t *left, SortElement_t *right);

static void insert_sort(SortElement_t *left, SortElement_t *right);

static void partition(SortElement_t *left0, SortElement_t *right0, SortElement_t **l1, SortElement_t **r1, SortElement_t **l2, SortElement_t **r2);

static void *sort_thr(void *arg);

void insert_sort(SortElement_t *left, SortElement_t *right) {
    // put minimum to left position, so we can save
    // one inner loop comparison for insert sort
    for (SortElement_t *pi = left + 1; pi <= right; pi++) {
        if (pi->count < left->count) {
            swap(*pi, *left);
        }
    }
    for (SortElement_t *pi = left + 2; pi <= right; pi++) {
        SortElement_t h = *pi;
        SortElement_t *pj = pi - 1;
        while (h.count < pj->count) {
            *(pj + 1) = *pj;
            pj -= 1;
        }
        *(pj + 1) = h;
    }
}

static void partition(SortElement_t *left0, SortElement_t *right0, SortElement_t **l1, SortElement_t **r1, SortElement_t **l2, SortElement_t **r2) {
    SortElement_t *left = left0 + 1;
    SortElement_t *right = right0;

    SortElement_t *mid = left0 + (right0 - left0) / 2;
    SortElement_t piv = *mid;
    *mid = *left;
    sort3fast(*left0, piv, *right0);
    *left = piv;

    while (1) {
        do left += 1;
        while (left->count < piv.count);
        do right -= 1;
        while (right->count > piv.count);
        if (left >= right) break;
        swap(*left, *right);
    }
    *(left0 + 1) = *right;
    *right = piv;

    if (right < mid) {
        *l1 = left0;
        *r1 = right - 1;
        *l2 = right + 1;
        *r2 = right0;
    } else {
        *l1 = right + 1;
        *r1 = right0;
        *l2 = left0;
        *r2 = right - 1;
    }
}

static void *sort_thr(void *arg) {
    SortElement_t **par = (SortElement_t **)arg;
    qusort(par[0], par[1]);
    free(arg);
    pthread_mutex_lock(&mutex);
    n_threads--;
    if (n_threads <= 0) {
        pthread_cond_signal(&cond);
    }
    pthread_mutex_unlock(&mutex);
    return NULL;
}

static void qusort_single(SortElement_t *left, SortElement_t *right) {
    SortElement_t *l, *r;
    while (right - left >= 50) {
        partition(left, right, &l, &r, &left, &right);
        qusort(l, r);
    }
    insert_sort(left, right);
}

static void qusort(SortElement_t *left, SortElement_t *right) {
    while (right - left >= 50) {
        SortElement_t *l, *r;
        partition(left, right, &l, &r, &left, &right);

        if (right - left > 100000 && n_threads < max_threads) {
            // start a new thread - max_threads is a soft limit
            pthread_t thread;
            SortElement_t **param = (SortElement_t **)malloc(2 * sizeof(SortElement_t *));
            if (!param) abort();
            param[0] = left;
            param[1] = right;
            pthread_mutex_lock(&mutex);
            n_threads++;
            pthread_mutex_unlock(&mutex);
            pthread_create(&thread, NULL, sort_thr, param);
            left = l;
            right = r;
        } else {
            qusort(l, r);
        }
    }
    insert_sort(left, right);
}

void blocksort(SortElement_t *data, int len) {
    // shortcut for few entries
    if (len < 50) {
        SortElement_t *left = data;
        SortElement_t *right = data + len - 1;
        qusort_single(left, right);
        return;
    }

    int n_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (n_cpus > 0)
        max_threads = n_cpus * 2;
    else
        max_threads = 8;

    pthread_t thread;
    SortElement_t **param = (SortElement_t **)malloc(2 * sizeof(SortElement_t *));
    if (!param) abort();
    param[0] = data;
    param[1] = data + len - 1;
    pthread_create(&thread, NULL, sort_thr, param);

    pthread_mutex_lock(&mutex);
    n_threads++;
    while (n_threads > 0) pthread_cond_wait(&cond, &mutex);
    pthread_mutex_unlock(&mutex);

}  // End of blocksort