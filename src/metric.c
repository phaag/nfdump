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


#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include "queue.h"
#include "nfxV3.h"
#include "nffile.h"
#include "util.h"
#include "metric.h"

static char *socket_path = "/tmp/nfsen.sock";
static int fd = 0;
static uint64_t uptime = 0;
static metric_record_t *metric_record = NULL;
static pthread_mutex_t mutex;

static int OpenSocket(void) {
struct sockaddr_un addr;

	if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		LogError("socket() failed on %s: %s", socket_path, strerror(errno));
		return 0;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);

	if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		LogError("connect() failed on %s: %s", socket_path, strerror(errno));
		fd = 0;
		return 0;
	}
	return 1;
}

int OpenMetric(char *path) {

	socket_path = path;
	if ( !OpenSocket() ) {
		return 0;
	}
	close(fd);
	fd = 0;

	metric_record = calloc(1, sizeof(metric_record_t));
	if ( !metric_record ) {
		LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
		return 0;
	}

	if (pthread_mutex_init(&mutex, NULL) != 0) {
        LogError("pthread_mutex_init() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

	pthread_t tid;
	int err = pthread_create(&tid, NULL, MetricThread, NULL);
	if ( err ) {
		LogError("pthread_create() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
		return 0;
	}

	return 1;

} // End of OpenMetric

int CloseMetric() {

	pthread_mutex_lock(&mutex);
	if ( metric_record == NULL ) {
		pthread_mutex_unlock(&mutex);
		return 0;
	}
	metric_record_t *r = metric_record;
	metric_record = NULL;
	pthread_mutex_unlock(&mutex);

	free(r);

	return 0;

} // End of CloseMetric

void UpdateMetric(nffile_t *nffile, EXgenericFlow_t *genericFlow) {

	pthread_mutex_lock(&mutex);
	if ( metric_record == NULL) {
		pthread_mutex_unlock(&mutex);
		return;
	}

	// fill metric
	switch (genericFlow->proto) {
		case IPPROTO_ICMPV6:
		case IPPROTO_ICMP:
			metric_record->numflows_icmp++;
			metric_record->numpackets_icmp += genericFlow->inPackets;
			metric_record->numbytes_icmp   += genericFlow->inBytes;
			break;
		case IPPROTO_TCP:
			metric_record->numflows_tcp++;
			metric_record->numpackets_tcp += genericFlow->inPackets;
			metric_record->numbytes_tcp   += genericFlow->inBytes;
			break;
		case IPPROTO_UDP:
			metric_record->numflows_udp++;
			metric_record->numpackets_udp += genericFlow->inPackets;
			metric_record->numbytes_udp   += genericFlow->inBytes;
			break;
		default:
			metric_record->numflows_other++;
			metric_record->numpackets_other += genericFlow->inPackets;
			metric_record->numbytes_other   += genericFlow->inBytes;
	}
	pthread_mutex_unlock(&mutex);
	
} // End of UpdateMetric

__attribute__((noreturn)) void* MetricThread(void *arg) {

	metric_record_t *record = calloc(1, sizeof(metric_record_t));
	void *message = malloc(sizeof(metric_record_t)+4);
	if ( !record ||!message ) {
		LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
		close(fd);
		fd = 0;
		pthread_exit(NULL);
	}
	message_header_t *message_header = (message_header_t *)message;
	message_header->prefix  = '@';
	message_header->version = 1;
	message_header->size    = sizeof(metric_record_t);

	uptime = (uint64_t)time(NULL) * 1000LL;

	while (1) {
		sleep(10);
		pthread_mutex_lock(&mutex);
		if ( metric_record == NULL ) {
			pthread_mutex_unlock(&mutex);
			break;
		}
		metric_record_t *r = metric_record;
		metric_record = record;
		pthread_mutex_unlock(&mutex);
		record = r;

		struct timeval te; 
		gettimeofday(&te, NULL);
		uint64_t milliseconds = te.tv_sec*1000LL + te.tv_usec/1000;
		record->uptime = milliseconds - uptime;

		// set ident - static for now
		strncpy(record->ident, "live", 5);

		// compose message
		memcpy(message + sizeof(message_header_t), (void *)record, sizeof(metric_record_t));
		if ( OpenSocket() ) {
			int ret = write(fd, message, sizeof(message_header_t) + sizeof(metric_record_t));
			if ( ret < 0 ) {
				LogError("write() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
			}
			close(fd);
			fd = 0;
		}
		memset((void *)record, 0, sizeof(metric_record_t));
	}

	free(record);
	free(message);
	pthread_exit(NULL);

} // End of SendMetric

