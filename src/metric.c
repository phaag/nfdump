/*
 *  Copyright (c) 2021, Peter Haag
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
#include <netinet/in.h>
#include <pthread.h>
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

static char *socket_path = "/tmp/nfsen.sock";
static int fd = 0;
static _Atomic unsigned tstart = ATOMIC_VAR_INIT(0);

// list of chained metric records
static metric_chain_t *metric_list = NULL;

// cache last metric record
static metric_record_t *metricCache = NULL;
static uint64_t exporterIDcache = 0;
static uint32_t numMetrics = 0;
static char identCache[128];

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t tid = 0;

static int OpenSocket(void) {
    struct sockaddr_un addr;

    dbg_printf("Connect to UNIX socket\n");
    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        LogError("socket() failed on %s: %s", socket_path, strerror(errno));
        return 0;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        LogError("connect() failed on %s: %s", socket_path, strerror(errno));
        fd = 0;
        return 0;
    }
    return 1;
}

static inline metric_record_t *GetMetric(uint32_t exporterID) {
    metric_record_t *metric_record = NULL;
    metric_chain_t *metric_chain = metric_list;
    while (metric_chain && metric_chain->record->exporterID != exporterID) metric_chain = metric_chain->next;

    if (metric_chain) {
        dbg_printf("Found metric: %x\n", exporterID);
        return metric_chain->record;
    }

    dbg_printf("New metric: %x\n", exporterID);
    metric_chain = malloc(sizeof(metric_chain_t));
    metric_record = calloc(1, sizeof(metric_record_t));
    if (!metric_chain || !metric_record) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }
    numMetrics++;

    metric_record->exporterID = exporterID;
    metric_chain->record = metric_record;
    metric_chain->next = metric_list;
    metric_list = metric_chain;
    return metric_record;

}  // End of GetMetric

static inline void CalculateRates(metric_record_t *metric_record, time_t interval) {
    metric_record->numflows_tcp /= interval;
    metric_record->numflows_udp /= interval;
    metric_record->numflows_icmp /= interval;
    metric_record->numflows_other /= interval;
    metric_record->numbytes_tcp /= interval;
    metric_record->numbytes_udp /= interval;
    metric_record->numbytes_icmp /= interval;
    metric_record->numbytes_other /= interval;
    metric_record->numpackets_tcp /= interval;
    metric_record->numpackets_udp /= interval;
    metric_record->numpackets_icmp /= interval;
    metric_record->numpackets_other /= interval;
}  // End of CalculateRates

int OpenMetric(char *path, char *ident, int interval) {
    socket_path = path;
    if (!OpenSocket()) {
        return 0;
    }
    close(fd);
    fd = 0;

    // save ident
    strncpy(identCache, ident, 128);
    identCache[127] = '\0';

    // set start time of collector
    atomic_init(&tstart, (uint64_t)time(NULL) * 1000LL);
    int err = pthread_create(&tid, NULL, MetricThread, NULL);
    if (err) {
        LogError("pthread_create() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }
    dbg_printf("Metric initialised\n");

    return 1;

}  // End of OpenMetric

int CloseMetric() {
    dbg_printf("Close metric\n");

    // signal MetricThread too terminate
    atomic_init(&tstart, 0);

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

    if (tid) {
        int err = pthread_join(tid, NULL);
        if (err) {
            LogError("pthread_join() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        }
    }

    return 0;

}  // End of CloseMetric

void UpdateMetric(uint32_t exporterID, EXgenericFlow_t *genericFlow) {
    dbg_printf("Update metric: exporter ID: %x\n", exporterID);

    // if no MetricThread is running
    if (atomic_load(&tstart) == 0) return;

    dbg_printf("Update metric\n");
    pthread_mutex_lock(&mutex);
    metric_record_t *metric_record = metricCache;
    if (exporterIDcache != exporterID || metricCache == NULL) {
        dbg_printf("Get metric\n");
        metric_record = GetMetric(exporterID);
        if (!metric_record) {
            pthread_mutex_unlock(&mutex);
            return;
        }
        metricCache = metric_record;
        exporterIDcache = exporterID;
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
    strncpy(message_header->ident, identCache, 128);
    identCache[127] = '\0';

    // number of allocated metric records in message
    uint32_t cnt = 1;

    time_t sleepTime = interval - (time(NULL) % interval);
    while (1) {
        sleep(sleepTime);
        struct timeval te;
        gettimeofday(&te, NULL);
        uint64_t now = te.tv_sec * 1000LL + te.tv_usec / 1000;

        // check for end condition
        uint64_t _tstart = atomic_load(&tstart);
        if (_tstart == 0) break;

        if (numMetrics == 0) {
            dbg_printf("No metric available\n");
            sleepTime = interval - (time(NULL) % interval);
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
        message_header->uptime = now - _tstart;
        message_header->timeStamp = now;

        metric_chain_t *metric_chain = metric_list;
        if (OpenSocket()) {
            size_t offset = sizeof(message_header_t);
            while (metric_chain) {
                metric_record_t *metric_record = metric_chain->record;
                CalculateRates(metric_record, interval);

                dbg_printf("Copy metric\n");
                // compose message
                memcpy(message + offset, (void *)metric_record, sizeof(metric_record_t));
                uint64_t exporterID = metric_record->exporterID;
                memset((void *)metric_record, 0, sizeof(metric_record_t));
                metric_record->exporterID = exporterID;

                offset += sizeof(metric_record_t);

                metric_chain = metric_chain->next;
            }
            int ret = write(fd, message, offset);
            if (ret < 0) {
                LogError("write() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            }
            close(fd);
            fd = 0;
            dbg_printf("Message sent\n");
        }
        pthread_mutex_unlock(&mutex);
        sleepTime = interval - (te.tv_sec % interval);
    }
    free(message);
    pthread_exit(NULL);

}  // End of SendMetric
