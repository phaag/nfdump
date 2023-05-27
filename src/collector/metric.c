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

#include "metric.h"

#include <errno.h>
#include <math.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "nffile.h"
#include "nfxV3.h"
#include "util.h"

static char *socket_path = NULL;
static _Atomic unsigned tstart = 0;

// list of chained metric records
static metric_chain_t *metric_list = NULL;

// cache last metric record
static metric_record_t *metricCache = NULL;
static uint32_t numMetrics = 0;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t tid = 0;

static int OpenSocket(void) {
    struct sockaddr_un addr;

    dbg_printf("Connect to UNIX socket\n");
    int fd;
    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        LogError("socket() failed on %s: %s", socket_path, strerror(errno));
        return 0;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        LogError("connect() failed on %s: %s", socket_path, strerror(errno));
        return 0;
    }
    return fd;
}

static inline metric_record_t *GetMetric(char *ident, uint32_t exporterID) {
    metric_chain_t *metric_chain = metric_list;
    while (metric_chain && strncmp(metric_chain->record->ident, ident, 128)) metric_chain = metric_chain->next;

    if (metric_chain) {
        dbg_printf("Found metric: %x\n", exporterID);
        return metric_chain->record;
    }

    dbg_printf("New metric: %s, %x\n", ident, exporterID);
    metric_chain = malloc(sizeof(metric_chain_t));
    metric_record_t *metric_record = calloc(1, sizeof(metric_record_t));
    if (!metric_chain || !metric_record) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }
    numMetrics++;
    strncpy(metric_record->ident, ident, 127);
    metric_record->exporterID = exporterID;
    metric_chain->record = metric_record;
    metric_chain->next = metric_list;
    metric_list = metric_chain;
    return metric_record;

}  // End of GetMetric

int OpenMetric(char *path, int interval) {
    socket_path = path;
    int fd = OpenSocket();
    if (fd == 0) {
        LogError("metric socket unreachable");
    } else {
        close(fd);
    }

    int err = pthread_create(&tid, NULL, MetricThread, NULL);
    if (err) {
        LogError("pthread_create() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }
    LogInfo("Metric initialized");

    return 1;

}  // End of OpenMetric

int CloseMetric(void) {
    dbg_printf("Close metric\n");

    // if no MetricThread is running
    if (atomic_load(&tstart) == 0) return 0;

    // signal MetricThread too terminate
    atomic_init(&tstart, 0);
    int status = pthread_kill(tid, SIGINT);
    if (status < 0) LogError("pthread_kill() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));

    status = pthread_join(tid, NULL);
    if (status < 0) LogError("pthread_join() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));

    pthread_mutex_lock(&mutex);
    metric_chain_t *metric_chain = metric_list;
    while (metric_chain) {
        free(metric_chain->record);
        metric_chain_t *elem = metric_chain;
        metric_chain = metric_chain->next;
        free(elem);
    }
    metric_list = NULL;
    pthread_mutex_unlock(&mutex);

    return 0;

}  // End of CloseMetric

void UpdateMetric(char *ident, uint32_t exporterID, EXgenericFlow_t *genericFlow) {
    dbg_printf("Update metric: exporter ID: %x\n", exporterID);

    // if no MetricThread is running
    if (atomic_load(&tstart) == 0) return;

    dbg_printf("Update metric\n");
    pthread_mutex_lock(&mutex);
    metric_record_t *metric_record = metricCache;
    if (metric_record == NULL || strncmp(metric_record->ident, ident, 128) != 0) {
        dbg_printf("Get metric\n");
        metric_record = GetMetric(ident, exporterID);
        if (!metric_record) {
            pthread_mutex_unlock(&mutex);
            return;
        }
        metricCache = metric_record;
    }
#ifdef DEVEL
    else {
        printf("Cached metric\n");
    }
#endif
    // fill metric
    switch (genericFlow->proto) {
        case IPPROTO_ICMPV6:
        case IPPROTO_ICMP:
            metric_record->numflows_icmp++;
            metric_record->numpackets_icmp += genericFlow->inPackets;
            metric_record->numbytes_icmp += genericFlow->inBytes;
            break;
        case IPPROTO_TCP:
            metric_record->numflows_tcp++;
            metric_record->numpackets_tcp += genericFlow->inPackets;
            metric_record->numbytes_tcp += genericFlow->inBytes;
            break;
        case IPPROTO_UDP:
            metric_record->numflows_udp++;
            metric_record->numpackets_udp += genericFlow->inPackets;
            metric_record->numbytes_udp += genericFlow->inBytes;
            break;
        default:
            metric_record->numflows_other++;
            metric_record->numpackets_other += genericFlow->inPackets;
            metric_record->numbytes_other += genericFlow->inBytes;
    }
    pthread_mutex_unlock(&mutex);

}  // End of UpdateMetric

__attribute__((noreturn)) void *MetricThread(void *arg) {
    dbg_printf("Started MetricThread\n");
    void *message = malloc(sizeof(message_header_t) + sizeof(metric_record_t));
    if (!message) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        pthread_exit(NULL);
    }
    time_t interval = 60;
    message_header_t *message_header = (message_header_t *)message;
    message_header->prefix = '@';
    message_header->version = 1;
    message_header->size = sizeof(metric_record_t);
    message_header->numMetrics = 1;
    message_header->timeStamp = 0;
    message_header->interval = interval;
    message_header->uptime = 0;

    // set start time of collector
    atomic_init(&tstart, (uint64_t)time(NULL) * 1000LL);

    // number of allocated metric records in message
    uint32_t cnt = 1;

    struct timespec sleepTime;
    struct timeval te;
    gettimeofday(&te, NULL);
    sleepTime.tv_sec = interval - (te.tv_sec % interval) - 1;
    sleepTime.tv_nsec = 1000000000LL - 1000LL * te.tv_usec;

    while (1) {
        nanosleep(&sleepTime, NULL);
        gettimeofday(&te, NULL);

        // check for end condition
        uint64_t _tstart = atomic_load(&tstart);
        if (_tstart == 0) break;

        if (numMetrics == 0) {
            dbg_printf("No metric available\n");
            sleepTime.tv_sec = interval - (te.tv_sec % interval) - 1;
            sleepTime.tv_nsec = 1000000000LL - 1000LL * te.tv_usec;
            continue;
        }

        dbg_printf("Process %u metrics\n", numMetrics);
        pthread_mutex_lock(&mutex);
        if (numMetrics > cnt) {
            dbg_printf("Expand message: %u -> %u\n", cnt, numMetrics);
            void *_message = realloc(message, numMetrics * sizeof(metric_record_t) + sizeof(message_header_t));
            if (!_message) {
                pthread_mutex_unlock(&mutex);
                LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                pthread_exit(NULL);
            }
            message = _message;
            message_header = (message_header_t *)message;
            cnt = numMetrics;
            message_header->size = cnt * sizeof(metric_record_t);
            message_header->numMetrics = cnt;
        }

        // update uptime
        message_header->uptime = te.tv_sec - _tstart;
        // update timestamp rounded correctly to the interval slot
        message_header->timeStamp = 1000L * (te.tv_sec - (te.tv_sec % interval));

        metric_chain_t *metric_chain = metric_list;
        int fd = OpenSocket();
        if (fd) {
            size_t offset = sizeof(message_header_t);
            while (metric_chain) {
                metric_record_t *metric_record = metric_chain->record;

                dbg_printf("Copy metric\n");
                // compose message
                memcpy(message + offset, (void *)metric_record, sizeof(metric_record_t));
                uint64_t exporterID = metric_record->exporterID;
                char ident[128];
                strncpy(ident, metric_record->ident, 128);
                memset((void *)metric_record, 0, sizeof(metric_record_t));
                metric_record->exporterID = exporterID;
                strncpy(metric_record->ident, ident, 128);

                offset += sizeof(metric_record_t);

                metric_chain = metric_chain->next;
                LogVerbose("Message sent for '%s', exporter: %d\n", metric_record->ident, exporterID);
            }
            ssize_t ret = write(fd, message, offset);
            if (ret < 0) {
                LogError("write() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            }
            close(fd);
        } else {
            LogError("metric socket unreachable");
        }
        pthread_mutex_unlock(&mutex);

        gettimeofday(&te, NULL);
        sleepTime.tv_sec = interval - (te.tv_sec % interval) - 1;
        sleepTime.tv_nsec = 1000000000LL - 1000LL * te.tv_usec;
    }
    free(message);
    pthread_exit(NULL);

}  // End of SendMetric
