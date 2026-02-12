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

/*
 * Fast offline pcap reader with mmap (or gzip) support.
 * reads packets directly from file and packs them in batches.
 * Batching and * a simple SPSC queue between reader thread and packet thread.
 * reader_thread_fn() thread reads and pushes batches in queue, ready for
 * packet thread.
 *
 * API (minimal):
 *  int pcap_file_reader_start(const char *path, size_t batch_size);
 *  PktBatch_t *pcap_file_reader_pop(void); // blocking, returns NULL on EOF/error
 *  void pcap_file_reader_free_batch(PktBatch_t *b);
 *  void pcap_file_reader_stop(void);
 *
 * Notes:
 *  - For gzipped files the reader copies packet payloads into malloc'd buffers
 *    (PacketRef.owned != NULL) which the consumer must free via
 *    pcap_file_reader_free_batch(). For mmap'ed files the data pointers
 *    point into the mmap region (owned == NULL) and must not be freed.
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "config.h"

#ifdef HAVE_ZLIB
#include <zlib.h>

#include "pcap_gzip.h"
#endif

#include "flowhash.h"
#include "nffile.h"
#include "packet_pcap.h"
#include "pcapdump.h"
#include "pcaproc.h"
#include "queue.h"
#include "util.h"

static proc_stat_t proc_stat = {0};

/* Compile BPF filter into readerParam->prog using a dead pcap handle. */
static int compile_pcap_filter(readerParam_t *readerParam, packetParam_t *packetParam, const char *filter) {
    pcap_t *dead = pcap_open_dead((int)packetParam->linktype, (int)packetParam->snaplen);
    if (!dead) {
        LogError("pcap_open_dead() failed in %s:%u", __FILE__, __LINE__);
        return -1;
    }

    if (pcap_compile(dead, &readerParam->prog, filter, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        pcap_close(dead);
        return -1;
    }
    pcap_close(dead);

    LogInfo("Set packet filter: '%s'", filter);

    readerParam->have_filter = 1;
    return 0;
}  // End of compile_pcap_filter

static int reader_mmap_run(readerParam_t *readerParam) {
    dbg_printf("(%s) enter\n", __func__);
    size_t batch_size = readerParam->batch_size;
    size_t remaining = readerParam->mmap_size;
    if (remaining < sizeof(struct pcap_file_header)) return -1;

    // skip header - already processed
    remaining -= sizeof(struct pcap_file_header);
    uint8_t *p = readerParam->mmap_base + sizeof(struct pcap_file_header);

    int swapped = readerParam->swapped;

    PktBatch_t *batch = batch_alloc(batch_size, 0);
    if (!batch) return -1;

    uint32_t cnt = 0;
    int done = atomic_load_explicit(readerParam->done, memory_order_relaxed);
    while (remaining >= sizeof(struct pcaprec_hdr) && !done) {
        struct pcaprec_hdr rh;
        memcpy(&rh, p, sizeof(rh));
        p += sizeof(rh);
        remaining -= sizeof(rh);

        cnt++;
        /* reference into mmap region */
        PacketRef pr;
        if (swapped) {
            pr.hdr.ts.tv_sec = swap32(rh.ts_sec);
            pr.hdr.ts.tv_usec = swap32(rh.ts_usec);
            pr.hdr.caplen = swap32(rh.incl_len);
            pr.hdr.len = swap32(rh.orig_len);
        } else {
            pr.hdr.ts.tv_sec = rh.ts_sec;
            pr.hdr.ts.tv_usec = rh.ts_usec;
            pr.hdr.caplen = rh.incl_len;
            pr.hdr.len = rh.orig_len;
        }
        int incl = pr.hdr.caplen;

        if (incl > remaining) break;  // truncated - incomplete packet

        pr.data = p;

        /* apply filter if present */
        if (readerParam->have_filter) {
            if (!pcap_offline_filter(&readerParam->prog, &pr.hdr, pr.data)) {
                /* packet doesn't match; skip */
                p += incl;
                remaining -= incl;
                continue;
            }
        }

        batch->pkts[batch->count++] = pr;

        p += incl;
        remaining -= incl;

        if (batch->count == batch->capacity) {
            dbg_printf("(%s) reader - Push full batch\n", __func__);
            if (queue_push(readerParam->batchQueue, batch) == QUEUE_CLOSED) {
                dbg_printf("(%s) batchQueue closed\n", __func__);
                batch_free(batch);
                return -1;
            }

            batch = batch_alloc(batch_size, 0);
            if (!batch) {
                return -1;
            }
        }
        // check for user interrupt - SIGINTR SIGTERM
        done = atomic_load_explicit(readerParam->done, memory_order_relaxed);
    }
    dbg_printf("(%s) exit packet loop. Processed %u packets. Done state: %u\n", __func__, cnt, done);

    (void)cnt;

    if (!done && batch->count > 0) {
        dbg_printf("(%s) Push last batch with %zu slots\n", __func__, batch->count);
        if (queue_push(readerParam->batchQueue, batch) == QUEUE_CLOSED) {
            batch_free(batch);
            return -1;
        }
        batch = NULL;
    } else {
        batch_free(batch);
    }

    dbg_printf("(%s) exit\n", __func__);

    return 0;
}  // End of reader_mmap_run

static void *reader_thread(void *arg) {
    readerParam_t *readerParam = (readerParam_t *)arg;

    dbg_printf("Enter thread %s\n", __func__);

    int rc = 0;
    if (readerParam->use_mmap) {
        rc = reader_mmap_run(readerParam);
#ifdef HAVE_ZLIB
    } else if (readerParam->gz) {
        rc = reader_gz_run(readerParam);
#endif
    } else {
        rc = -1;
    }

    /* signal EOF by closing queue */
    queue_close(readerParam->batchQueue);
    (void)rc; /* rc currently unused here; kept for future logging */

    dbg_printf("Exit thread %s\n", __func__);

    pthread_exit(NULL);
}  // End of reader_thread

// public pcap reader API
int pcap_file_reader_start(packetParam_t *packetParam, readerParam_t *readerParam, const char *path, const char *filter) {
    if (readerParam->batch_size == 0) readerParam->batch_size = DEFAULT_BATCH_SIZE;

    /* initialize queue with capacity 64 (must be power of two) */
    readerParam->batchQueue = queue_init(8);
    if (!readerParam->batchQueue) return -1;

    // path already cleared by argument checking
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        LogError("open() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        queue_free(readerParam->batchQueue);
        return -1;
    }

    // default - attempt plain pcap file
    struct stat st;
    if (fstat(fd, &st) < 0) {
        LogError("fstat() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        close(fd);
        queue_free(readerParam->batchQueue);
        return -1;
    }

    if (S_ISREG(st.st_mode) == 0 || st.st_size < sizeof(struct pcap_file_header)) {
        LogError("File: %s not a regular file or too small", path);
        close(fd);
        queue_free(readerParam->batchQueue);
        return -1;
    }

    struct pcap_file_header fileHeader = {0};
    int swapped = 0;

    // mmap file
    void *base = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (base == MAP_FAILED) {
        LogError("mmap() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        close(fd);
        queue_free(readerParam->batchQueue);
        return -1;
    }

    /* quick magic check */
    uint32_t magic = *(uint32_t *)base;
    if (magic == 0xa1b2c3d4 || magic == 0xd4c3b2a1) {
        memcpy(&fileHeader, base, sizeof(struct pcap_file_header));

        readerParam->use_mmap = 1;
        readerParam->mmap_base = base;
        readerParam->mmap_size = st.st_size;
        readerParam->fd = fd;
        readerParam->snaplen = fileHeader.snaplen;
        readerParam->linkType = fileHeader.linktype;

    } else {
        // MAGIC mismatch - try gzopen()
        munmap(base, st.st_size);
        close(fd);

#ifdef HAVE_ZLIB
        if (OpenZIPfile(readerParam, &fileHeader, path) == 0) {
            queue_free(readerParam->batchQueue);
            return -1;
        }

#else
        LogError("Reading pcapd file: MAGIC missmatch - not a pcap file");
        queue_free(readerParam->batchQueue);
        return -1;
#endif
    }

    packetParam->linktype = fileHeader.linktype;
    packetParam->snaplen = fileHeader.snaplen;
    packetParam->batchQueue = readerParam->batchQueue;
    packetParam->live = 0;

    readerParam->swapped = swapped;

    /* compile BPF filter if provided */
    readerParam->have_filter = 0;
    if (filter && filter[0] != '\0') {
        if (compile_pcap_filter(readerParam, packetParam, filter) != 0) {
            LogError("pcap filter compile failed for '%s'", filter);
            if (readerParam->use_mmap) {
                munmap(readerParam->mmap_base, readerParam->mmap_size);
                close(readerParam->fd);
            }
#ifdef HAVE_ZLIB
            if (readerParam->gz) gzclose(readerParam->gzfp);
#endif
            if (readerParam->batchQueue) {
                queue_free(readerParam->batchQueue);
                readerParam->batchQueue = NULL;
            }
            return -1;
        }
    }

    if (pthread_create(&readerParam->reader_thread, NULL, reader_thread, (void *)readerParam) != 0) {
        if (readerParam->use_mmap) {
            munmap(readerParam->mmap_base, readerParam->mmap_size);
            close(readerParam->fd);
        }
#ifdef HAVE_ZLIB
        if (readerParam->gz) {
            gzclose(readerParam->gzfp);
        }
#endif
        if (readerParam->batchQueue) {
            queue_free(readerParam->batchQueue);
        }
        return -1;
    }
    return 0;
}  // End of pcap_file_reader_start

void pcap_file_reader_stop(readerParam_t *readerParam) {
    /* wait for reader thread to exit (queue_close will be called by reader) */
    pthread_join(readerParam->reader_thread, NULL);
    if (readerParam->use_mmap) {
        munmap(readerParam->mmap_base, readerParam->mmap_size);
        close(readerParam->fd);
        readerParam->use_mmap = 0;
    }
#ifdef HAVE_ZLIB
    if (readerParam->gz) {
        gzclose(readerParam->gzfp);
        readerParam->gz = 0;
    }
#endif
    if (readerParam->have_filter) {
        pcap_freecode(&readerParam->prog);
        readerParam->have_filter = 0;
    }
    if (readerParam->batchQueue) {
        queue_free(readerParam->batchQueue);
        readerParam->batchQueue = NULL;
    }
}  // End of pcap_file_reader_stop

static void ReportStat(packetParam_t *param) {
    LogInfo("Processed: %u, skipped: %u, short caplen: %u, unknown: %u", param->proc_stat.packets - proc_stat.packets,
            param->proc_stat.skipped - proc_stat.skipped, param->proc_stat.short_snap - proc_stat.short_snap,
            param->proc_stat.unknown - proc_stat.unknown);

    proc_stat = param->proc_stat;

    param->totalPackets += param->proc_stat.packets;
    param->totalBytes += param->proc_stat.bytes;
}  // End of ReportStat

static inline void PcapDump(packetBuffer_t *packetBuffer, struct pcap_pkthdr *hdr, const u_char *sp) {
    if (packetBuffer == NULL) return;

    // caller checks for enough space in buffer
    struct pcap_sf_pkthdr sf_hdr;
    sf_hdr.ts.tv_sec = hdr->ts.tv_sec;
    sf_hdr.ts.tv_usec = hdr->ts.tv_usec;
    sf_hdr.caplen = hdr->caplen;
    sf_hdr.len = hdr->len;

    void *p = packetBuffer->buffer + packetBuffer->bufferSize;
    memcpy(p, (void *)&sf_hdr, sizeof(sf_hdr));
    p += sizeof(struct pcap_sf_pkthdr);

    memcpy(p, (void *)sp, hdr->caplen);
    packetBuffer->bufferSize += (sizeof(struct pcap_sf_pkthdr) + hdr->caplen);

}  // End of PcapDump

void __attribute__((noreturn)) * pcap_file_packet_thread(void *args) {
    packetParam_t *packetParam = (packetParam_t *)args;

    dbg_printf("Enter thread %s\n", __func__);

    Init_NodeAllocator();
    time_t t_win = packetParam->t_win;
    time_t now = 0;
    time_t t_start = 0;

    int DoPacketDump = packetParam->bufferQueue != NULL;

    packetBuffer_t *packetBuffer = NULL;
    if (DoPacketDump) {
        packetBuffer = queue_pop(packetParam->bufferQueue);
        if (packetBuffer == QUEUE_CLOSED) {
            LogError("Disable packet dump due to closed packetBuffer");
            DoPacketDump = 0;
        }
    }

    int done = 0;
    while (!done) {
        struct pcap_pkthdr *hdr;
        const u_char *data;

        PktBatch_t *batch = queue_pop(packetParam->batchQueue);
        if (batch == QUEUE_CLOSED) {
            batch = NULL;
            done = 1;
            continue;
        }
        dbg_printf("Packet - process next batch with %zu entries\n", batch->count);

        for (int i = 0; i < batch->count; i++) {
            hdr = &batch->pkts[i].hdr;
            data = batch->pkts[i].data;

            if (now == 0) {
                now = hdr->ts.tv_sec;
                t_start = now - (now % t_win);
            }

            time_t t_packet = hdr->ts.tv_sec;
            if ((t_packet - t_start) >= t_win) {
                if (DoPacketDump) {
                    // Rote dump file - close old - open new
                    dbg_printf("packet_thread() flush file - buffer: %zu\n", packetBuffer->bufferSize);
                    packetBuffer->timeStamp = t_start;
                    queue_push(packetParam->flushQueue, packetBuffer);
                    packetBuffer = queue_pop(packetParam->bufferQueue);
                    if (packetBuffer == QUEUE_CLOSED) {
                        LogError("Failed to get packetBuffer in file %s:%u", __FILE__, __LINE__);
                        DoPacketDump = 0;
                    }
                }
                // Rotate flow file
                ReportStat(packetParam);
                Push_SyncNode(packetParam->NodeList, t_start);
                t_start = t_packet - (t_packet % t_win);
                CacheCheck(packetParam->NodeList, t_start);
            }

            int ok = ProcessPacket(packetParam, hdr, data);

            size_t size = sizeof(struct pcap_sf_pkthdr) + hdr->caplen;
            if (DoPacketDump && ok) {
                if ((packetBuffer->bufferSize + size) > BUFFSIZE) {
                    packetBuffer->timeStamp = 0;
                    dbg_printf("packet_thread() flush buffer - size %zu\n", packetBuffer->bufferSize);
                    queue_push(packetParam->flushQueue, packetBuffer);
                    packetBuffer = queue_pop(packetParam->bufferQueue);
                    if (packetBuffer == QUEUE_CLOSED) {
                        LogError("Failed to get packetBuffer in file %s:%u", __FILE__, __LINE__);
                        DoPacketDump = 0;
                        packetBuffer = NULL;
                    }
                }
                PcapDump(packetBuffer, hdr, data);
            }
        }
        batch_free(batch);
        CacheCheck(packetParam->NodeList, t_start);
        if (atomic_load_explicit(packetParam->done, memory_order_relaxed)) {
            // user requested interrup - SIGTERM, SIGINT
            queue_close(packetParam->batchQueue);
            dbg_printf("packet thread %s - get signal done\n", __func__);
            done = 1;
        }
    }

    dbg_printf("Done capture loop - signal close\n");
    if (DoPacketDump && packetBuffer != QUEUE_CLOSED) {
        packetBuffer->timeStamp = t_start;
        queue_push(packetParam->flushQueue, packetBuffer);
        queue_close(packetParam->flushQueue);
    }

    ReportStat(packetParam);
    packetParam->t_win = t_start;

    dbg_printf("Exit thread %s\n", __func__);

    // Tell parent we are gone
    pthread_kill(packetParam->parent, SIGUSR1);
    pthread_exit(NULL);
    /* NOTREACHED */
}
