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

#ifndef _PACKETPCAP_H
#define _PACKETPCAP_H 1

#include <pcap.h>
#include <pthread.h>

#include "queue.h"
#include "flowtree.h"

#define PROMISC		1

#ifndef PCAP_NETMASK_UNKNOWN
#define PCAP_NETMASK_UNKNOWN 0xffffffff
#endif

struct pcap_timeval {
	int32_t tv_sec;   /* seconds */
	int32_t tv_usec;  /* microseconds */
};

struct pcap_sf_pkthdr {
	struct pcap_timeval ts; /* time stamp */
	uint32_t	caplen;		/* length of portion present */
	uint32_t	len;		/* length this packet (off wire) */
};

typedef struct packetBuffer_s {
	time_t	timeStamp;
	size_t	bufferSize;
	void	*buffer;
} packetBuffer_t;

typedef struct proc_stat_s {
    uint32_t    packets;
    uint32_t    skipped;
    uint32_t    unknown;
    uint32_t    short_snap;
} proc_stat_t;

#ifdef USE_TPACKETV3
#include <linux/if_packet.h>

struct ring {
	struct iovec *rd;
	uint8_t *map;
	struct tpacket_req3 req;
};
#endif

typedef struct packetParam_s {
	pthread_t tid;
	pthread_t parent;
	queue_t	  *bufferQueue;
	queue_t	  *flushQueue;
#ifdef USE_BPFSOCKET
	void	  *bpfBuffer;
	size_t	  bpfBufferSize;
	int		  bpf;
#endif
#ifdef USE_TPACKETV3
	int		  fd;
	struct ring ring;
#endif

	NodeList_t *NodeList;
	pcap_t 	  *pcap_dev;
	int 	  t_win;
	int 	  *done;

    uint32_t snaplen;
    uint32_t linkoffset;
    uint32_t linktype;

    uint32_t live;
	uint32_t fat;
	uint32_t extendedFlow;
	uint32_t addPayload;
    proc_stat_t proc_stat;
} packetParam_t;

int setup_pcap_live(packetParam_t *param, char *device, char *filter, int snaplen, int buffsize, int to_ms);

void __attribute__((noreturn)) *pcap_packet_thread(void *args);

#ifdef USE_BPFSOCKET
int setup_bpf_live(packetParam_t *param, char *device, char *filter, int snaplen, int buffsize, int to_ms);

void __attribute__((noreturn)) *bpf_packet_thread(void *args);
#endif 

#ifdef USE_TPACKETV3
int setup_linux_live(packetParam_t *param, char *device, char *filter, int snaplen, int buffsize, int to_ms);

void __attribute__((noreturn)) *linux_packet_thread(void *args);
#endif

#endif
