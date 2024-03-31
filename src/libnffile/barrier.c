/*
 *  Copyright (c) 2024, Peter Haag
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

#include "barrier.h"

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <unistd.h>

#include "barrier.h"
#include "nfdump.h"
#include "util.h"

// get decent number of workers depending
// on the number of cores online
uint32_t GetNumWorkers(uint32_t requested) {
    long CoresOnline = sysconf(_SC_NPROCESSORS_ONLN);

    if (CoresOnline < 0) {
        LogError("sysconf(_SC_NPROCESSORS_ONLN) error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        CoresOnline = 1;
    }

    uint32_t numWorkers = DEFAULTWORKERS;
    if (requested && requested < CoresOnline) {
        numWorkers = requested;
    } else {
        numWorkers = CoresOnline;
    }

    // limit to MAXWORKERS
    if (numWorkers > MAXWORKERS) numWorkers = DEFAULTWORKERS;

    LogInfo("CoresOnline: %lld, Requested: %u, Set workers to: %u", CoresOnline, requested, numWorkers);

    return numWorkers;

}  // End of GetNumWorkers

// initialize barrier for numWorkers + 1 controller
pthread_control_barrier_t *pthread_control_barrier_init(uint32_t numWorkers) {
    pthread_control_barrier_t *barrier = calloc(1, sizeof(pthread_control_barrier_t));
    if (!barrier) return NULL;

    if (numWorkers == 0) {
        errno = EINVAL;
        return NULL;
    }

    if (pthread_mutex_init(&barrier->workerMutex, 0) < 0) {
        return NULL;
    }

    if (pthread_cond_init(&barrier->workerCond, 0) < 0 || pthread_cond_init(&barrier->controllerCond, 0) < 0) {
        pthread_mutex_destroy(&barrier->workerMutex);
        return NULL;
    }

    barrier->numWorkers = numWorkers;
    barrier->workersWaiting = 0;

    return barrier;

}  // End of pthread_barrier_init

// destroy mutex/cond variables
void pthread_control_barrier_destroy(pthread_control_barrier_t *barrier) {
    pthread_cond_destroy(&barrier->workerCond);
    pthread_cond_destroy(&barrier->controllerCond);
    pthread_mutex_destroy(&barrier->workerMutex);
}  // End of pthread_control_barrier_destroy

// enter the barrier and block execution.
// If all workers are waiting, signal the controller
void pthread_control_barrier_wait(pthread_control_barrier_t *barrier) {
    pthread_mutex_lock(&barrier->workerMutex);
    barrier->workersWaiting++;
    dbg_printf("Worker wait: %d\n", barrier->workersWaiting);
    if (barrier->workersWaiting >= barrier->numWorkers) {
        pthread_cond_broadcast(&barrier->controllerCond);
    }
    pthread_cond_wait(&barrier->workerCond, &(barrier->workerMutex));
    dbg_printf("Worker dbg_awake\n");
    pthread_mutex_unlock(&barrier->workerMutex);

}  // End of pthread_control_barrier_wait

// wait for all workers to reach the barrier.
// if all workers wait, controller continues
void pthread_controller_wait(pthread_control_barrier_t *barrier) {
    dbg_printf("Controller wait\n");
    pthread_mutex_lock(&barrier->workerMutex);
    while (barrier->workersWaiting < barrier->numWorkers)
        // wait for all workers
        pthread_cond_wait(&barrier->controllerCond, &(barrier->workerMutex));

    pthread_mutex_unlock(&barrier->workerMutex);
    dbg_printf("Controller wait done.\n");

}  // End of pthread_controller_wait

// release barrier and let all workers continue
void pthread_control_barrier_release(pthread_control_barrier_t *barrier) {
    dbg_printf("Controller release\n");
    pthread_mutex_lock(&barrier->workerMutex);
    barrier->workersWaiting = 0;
    pthread_cond_broadcast(&barrier->workerCond);
    pthread_mutex_unlock(&barrier->workerMutex);
    dbg_printf("Controller release done\n");

}  // End of pthread_control_barrier_release