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

#ifndef _PACKETPCAP_H
#define _PACKETPCAP_H 1

#include <pcap.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>

#include "config.h"

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

#include "flowhash.h"
#include "queue.h"

#define PROMISC 1

#ifndef PCAP_NETMASK_UNKNOWN
#define PCAP_NETMASK_UNKNOWN 0xffffffff
#endif

struct pcap_timeval {
    int32_t tv_sec;  /* seconds */
    int32_t tv_usec; /* microseconds */
};

struct pcap_sf_pkthdr {
    struct pcap_timeval ts; /* time stamp */
    uint32_t caplen;        /* length of portion present */
    uint32_t len;           /* length this packet (off wire) */
};

typedef struct proc_stat_s {
    uint64_t packets;
    uint64_t bytes;
    uint32_t unknown;
    uint32_t decoding_errors;
    uint32_t short_snap;
    uint32_t duplicates;
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
    queue_t *bufferQueue;
    queue_t *flushQueue;
    queue_t *batchQueue;
#ifdef USE_BPFSOCKET
    void *bpfBuffer;
    size_t bpfBufferSize;
    int bpf;
#endif
#ifdef USE_TPACKETV3
    int fd;
    struct ring ring;
#endif

    NodeList_t *NodeList;
    pcap_t *pcap_dev;
    time_t t_win;
    _Atomic uint32_t *done;
    unsigned doDedup;

    uint32_t snaplen;
    uint32_t linktype;

    uint32_t live;
    uint32_t fat;
    uint32_t extendedFlow;
    uint32_t addPayload;
    uint64_t totalPackets;
    uint64_t totalBytes;
    proc_stat_t proc_stat;
} packetParam_t;

// fast pcap reader thread
typedef struct readerParam_s {
    pthread_t reader_thread;
    queue_t *batchQueue;
    _Atomic uint32_t *done;
    size_t batch_size;
    int snaplen;
    int linkType;

    int swapped;

    int use_mmap;
    // memory mapped pcapd
    void *mmap_base;
    size_t mmap_size;
    int fd;

    // compressed pcapd file
#ifdef HAVE_ZLIB
    int gz;
    gzFile gzfp;
#endif
    /* compiled BPF program (optional) */
    struct bpf_program prog;
    int have_filter;
} readerParam_t;

typedef struct pcaprec_hdr {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcaprec_hdr_t;

/* batch structures */
#define DEFAULT_BATCH_SIZE 256

typedef struct PacketRef {
    struct pcap_pkthdr hdr;  // packet header
    const uint8_t *data;     // pointer to packet bytes
} PacketRef;

typedef struct PktBatch_s {
    size_t count;
    size_t capacity;
    size_t payload_size;
    void *payload_slab;
    PacketRef pkts[];  // batch array
} PktBatch_t;

// read swapped numbers
static inline uint32_t swap32(uint32_t v) { return ((v & 0xff) << 24) | ((v & 0xff00) << 8) | ((v & 0xff0000) >> 8) | ((v & 0xff000000) >> 24); }

PktBatch_t *batch_alloc(size_t cap, uint32_t snaplen);

void batch_clear(PktBatch_t *batch);

void batch_free(PktBatch_t *batch);

void *payload_handle(PktBatch_t *batch, size_t idx);

int setup_pcap_live(packetParam_t *param, char *device, char *filter, unsigned snaplen, size_t buffsize, int to_ms);

void __attribute__((noreturn)) * pcap_packet_thread(void *args);

/* Fast file reader integration (mmap/gzip + batching) */
int pcap_file_reader_start(packetParam_t *packetParam, readerParam_t *readerParam, const char *path, const char *filter);

void pcap_file_reader_stop(readerParam_t *readerParam);
void __attribute__((noreturn)) * pcap_file_packet_thread(void *args);

#ifdef USE_BPFSOCKET
int setup_bpf_live(packetParam_t *param, char *device, char *filter, unsigned snaplen, size_t buffsize, int to_ms);

void __attribute__((noreturn)) * bpf_packet_thread(void *args);
#endif

#ifdef USE_TPACKETV3
int setup_linux_live(packetParam_t *param, char *device, char *filter, unsigned snaplen, size_t buffsize, int to_ms);

void __attribute__((noreturn)) * linux_packet_thread(void *args);
#endif

#endif
