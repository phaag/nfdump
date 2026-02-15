/*
 *  Copyright (c) 2023-2025, Peter Haag
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *	 this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice,
 *	 this list of conditions and the following disclaimer in the documentation
 *	 and/or other materials provided with the distribution.
 *   * Neither the name of the author nor the names of its contributors may be
 *	 used to endorse or promote products derived from this software without
 *	 specific prior written permission.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "packet_pcap.h"
#include "pcapdump.h"
#include "pcaproc.h"
#include "queue.h"
#include "util.h"

static void CloseSocket(packetParam_t *param);

static int setup_pcap_filter(packetParam_t *param, char *filter);

static void ReportStat(packetParam_t *param);

static inline void PcapDump(packetBuffer_t *packetBuffer, struct bpf_hdr *hdr, const u_char *sp);

static struct bpf_stat last_stat = {0};
static proc_stat_t proc_stat = {0};

/*
 * Functions
 */

static int open_bpf(void) {
    int fd = -1;

    // Open bpf device
    for (int i = 0; i < 255; i++) {
        char dev[32];
        (void)snprintf(dev, sizeof(dev), "/dev/bpf%u", i);

        fd = open(dev, O_RDWR);
        if (fd > -1) return fd;

        switch (errno) {
            case EBUSY:
                break;
            default:
                return -1;
        }
    }

    errno = ENOENT;
    return -1;
}  // End of open_bpf

static void CloseSocket(packetParam_t *param) {
    // close bpf device
    close(param->bpf);
}  // End of CloseSocket

// live device
int setup_bpf_live(packetParam_t *param, char *device, char *filter, unsigned snaplen, size_t buffsize, int to_ms) {
    param->pcap_dev = NULL;
    param->bpf = 0;
    int bpf = open_bpf();
    if (bpf < 0) {
        LogError("open_bpf() failed: %s", strerror(errno));
        return -1;
    }

    unsigned int buf_len = param->bpfBufferSize;
    if (ioctl(bpf, BIOCSBLEN, &buf_len) == -1) {
        LogError("ioctl(BIOCSBLEN) failed: %s", strerror(errno));
        close(bpf);
        return -1;
    }
    dbg_printf("BIOCSBLEN requested: %zu, returned: %u\n", param->bpfBufferSize, buf_len);
    if (buf_len && (buf_len < param->bpfBufferSize)) {
        LogError("ioctl(BIOCSBLEN) buffer set to max: %u", buf_len);
        param->bpfBufferSize = buf_len;
    }

    param->bpfBuffer = malloc(param->bpfBufferSize);
    if (!param->bpfBuffer) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        close(bpf);
        return -1;
    }

    struct ifreq if_req;
    strncpy(if_req.ifr_name, device, IFNAMSIZ - 1);
    if (ioctl(bpf, BIOCSETIF, &if_req) > 0) {
        LogError("ioctl(BIOCSETIF) failed: %s", strerror(errno));
        close(bpf);
        return -1;
    }

    unsigned int mode = 0;
    if (ioctl(bpf, BIOCIMMEDIATE, &mode) == -1) {
        LogError("ioctl(BIOCIMMEDIATE) failed: %s", strerror(errno));
        close(bpf);
        return -1;
    }

    if (ioctl(bpf, BIOCPROMISC, NULL) == -1) {
        LogError("ioctl(BIOCPROMISC) failed: %s", strerror(errno));
        close(bpf);
        return -1;
    }

    uint32_t dlt = 0;
    if (ioctl(bpf, BIOCGDLT, &dlt) < 0) {
        LogError("ioctl(BIOCGDLT) failed: %s", strerror(errno));
        close(bpf);
        return -1;
    }

    switch (dlt) {
        case DLT_RAW:
            param->linktype = DLT_RAW;
            break;
        case DLT_EN10MB:
            param->linktype = DLT_EN10MB;
            break;
        default:
            LogError("Unsupported datalink type: %u", dlt);
            errno = EINVAL;
            close(bpf);
            return -1;
    }

    param->bpf = bpf;

    // pcap handle for dumper
    param->snaplen = snaplen;
    param->linktype = dlt;

    if (filter && !setup_pcap_filter(param, filter)) {
        return -1;
    }

    return 0;

}  // End of setup_bpf_live

static int setup_pcap_filter(packetParam_t *param, char *filter) {
    pcap_t *dead = pcap_open_dead((int)param->linktype, (int)param->snaplen);
    if (!dead) {
        LogError("pcap_open_dead() failed in %s:%u", __FILE__, __LINE__);
        return 0;
    }

    struct bpf_program filter_code = {0};
    if (pcap_compile(dead, &filter_code, filter, 1, PCAP_NETMASK_UNKNOWN)) {
        LogError("pcap_compile() failed: %s", pcap_geterr(param->pcap_dev));
        return 0;
    }

    if (ioctl(param->bpf, BIOCSETF, (caddr_t)&filter_code) < 0) {
        LogError("ioctl(BIOCSETF) failed: %s", strerror(errno));
        return 0;
    }

    LogInfo("Set packet filter: '%s'", filter);
    pcap_close(dead);

    return 1;

}  // End of setup_pcap_filter

static void ReportStat(packetParam_t *param) {
    struct bpf_stat pstat;

    memset((void *)&pstat, 0, sizeof(struct bpf_stat));
    if (ioctl(param->bpf, BIOCGSTATS, &pstat) < 0) {
        LogError("ioctl(BIOCGSTATS) failed: %s", strerror(errno));
    }

    LogInfo("Packets kernel received: %u, dropped by OS/Buffer: %u, processed: %u, decode errors: %u, short caplen: %u, unknown: %u",
            pstat.bs_recv - last_stat.bs_recv, pstat.bs_drop - last_stat.bs_drop, param->proc_stat.packets - proc_stat.packets,
            param->proc_stat.decoding_errors - proc_stat.decoding_errors, param->proc_stat.short_snap - proc_stat.short_snap,
            param->proc_stat.unknown - proc_stat.unknown);

    last_stat = pstat;
    proc_stat = param->proc_stat;

}  // End of ReportStat

static inline void PcapDump(packetBuffer_t *packetBuffer, struct bpf_hdr *hdr, const u_char *sp) {
    // caller checks for enough space in buffer
    struct pcap_sf_pkthdr sf_hdr;
    sf_hdr.ts.tv_sec = hdr->bh_tstamp.tv_sec;
    sf_hdr.ts.tv_usec = hdr->bh_tstamp.tv_usec;
    sf_hdr.caplen = hdr->bh_caplen;
    sf_hdr.len = hdr->bh_datalen;

    void *p = packetBuffer->buffer + packetBuffer->bufferSize;
    memcpy(p, (void *)&sf_hdr, sizeof(sf_hdr));
    p += sizeof(struct pcap_sf_pkthdr);

    memcpy(p, (void *)sp, hdr->bh_caplen);
    packetBuffer->bufferSize += (sizeof(struct pcap_sf_pkthdr) + hdr->bh_caplen);
    dbg_printf("Buffer size: %zu\n", packetBuffer->bufferSize);

}  // End of PcapDump

void __attribute__((noreturn)) * bpf_packet_thread(void *args) {
    packetParam_t *packetParam = (packetParam_t *)args;

    Init_NodeAllocator();

    time_t t_win = packetParam->t_win;
    time_t now = time(NULL);
    time_t t_start = now - (now % t_win);

    int done = atomic_load_explicit(packetParam->done, memory_order_relaxed);
    int DoPacketDump = packetParam->bufferQueue != NULL;

    packetBuffer_t *packetBuffer = NULL;
    if (DoPacketDump) {
        packetBuffer = queue_pop(packetParam->bufferQueue);
        if (packetBuffer == QUEUE_CLOSED) done = 1;
    }

    fd_set mask;
    int width = packetParam->bpf + 1;

    while (!done) {
        struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};
        FD_ZERO(&mask);
        FD_SET(packetParam->bpf, &mask);

        dbg_printf("select() wait\n");
        int ready = select(width, &mask, NULL, NULL, &timeout);

        time_t t_packet = 0;
        if (ready == -1) {
            if (errno != EINTR) LogError("select() on bpf socket failed: %s", strerror(errno));
            break;
        } else if (ready == 0) {
            dbg_printf("select() bpf - timeout\n");
            struct timeval tv;
            gettimeofday(&tv, NULL);
            t_packet = tv.tv_sec;
            if ((t_packet - t_start) >= t_win) { /* rotate file */
                if (DoPacketDump) {
                    // Rotate dump file - close old - open new
                    packetBuffer->timeStamp = t_start;
                    queue_push(packetParam->flushQueue, packetBuffer);
                    packetBuffer = queue_pop(packetParam->bufferQueue);
                    if (packetBuffer == QUEUE_CLOSED) {
                        done = 1;
                        continue;
                    }
                }
                // Rotate flow file
                ReportStat(packetParam);
                Push_SyncNode(packetParam->NodeList, t_start);
                t_start = t_packet - (t_packet % t_win);
            }
            CacheCheck(packetParam->NodeList, t_start);
            done = done || atomic_load_explicit(packetParam->done, memory_order_relaxed);
            continue;
        }

        if (done) break;

        ssize_t len = read(packetParam->bpf, packetParam->bpfBuffer, packetParam->bpfBufferSize);
        if (len <= 0) {     // error or eof
            if (len < 0) {  // error other than interrupted system call
                LogError("read() bpf socket failed: %s", strerror(errno));
                pthread_kill(packetParam->parent, SIGUSR1);
            }
            done = 1;
            dbg_printf("read() bpf buffer: %s\n", strerror(errno));
            break;
        }

        dbg_printf("read() bpf buffer, len: %zd\n", len);
        void *p = packetParam->bpfBuffer;
        while (p < (packetParam->bpfBuffer + len)) {
            struct bpf_hdr *hdr = (struct bpf_hdr *)p;
            dbg_printf("loop - next packet\n");
            t_packet = hdr->bh_tstamp.tv_sec;

            if ((t_packet - t_start) >= t_win) {
                // Rote dump file - close old - open new
                if (DoPacketDump) {
                    dbg_printf("packet_thread() flush file - buffer: %zu\n", packetBuffer->bufferSize);
                    // Rotate dump file - close old - open new
                    packetBuffer->timeStamp = t_start;
                    queue_push(packetParam->flushQueue, packetBuffer);
                    packetBuffer = queue_pop(packetParam->bufferQueue);
                    if (packetBuffer == QUEUE_CLOSED) {
                        done = 1;
                        continue;
                    }
                }
                // Rotate flow file
                ReportStat(packetParam);
                Push_SyncNode(packetParam->NodeList, t_start);
                t_start = t_packet - (t_packet % t_win);
            }

            size_t size = sizeof(struct pcap_sf_pkthdr) + hdr->bh_caplen;
            u_char *data = (u_char *)(p + hdr->bh_hdrlen);
            struct pcap_pkthdr phdr = {//
                                       .ts.tv_sec = hdr->bh_tstamp.tv_sec,
                                       .ts.tv_usec = hdr->bh_tstamp.tv_usec,
                                       .caplen = hdr->bh_caplen,
                                       .len = hdr->bh_datalen};
            int ok = ProcessPacket(packetParam, &phdr, data);

            if (DoPacketDump && ok) {
                if ((packetBuffer->bufferSize + size) > BUFFSIZE) {
                    packetBuffer->timeStamp = 0;
                    dbg_printf("packet_thread() flush buffer - size %zu\n", packetBuffer->bufferSize);
                    queue_push(packetParam->flushQueue, packetBuffer);
                    packetBuffer = queue_pop(packetParam->bufferQueue);
                    if (packetBuffer == QUEUE_CLOSED) {
                        done = 1;
                        continue;
                    }
                }
                PcapDump(packetBuffer, hdr, data);
            }

            p += BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
        }
        done = done || atomic_load_explicit(packetParam->done, memory_order_relaxed);
    }

    // flush buffer
    dbg_printf("Done capture loop - signal close\n");
    if (DoPacketDump && packetBuffer != QUEUE_CLOSED) {
        packetBuffer->timeStamp = t_start;
        queue_push(packetParam->flushQueue, packetBuffer);
        queue_close(packetParam->flushQueue);
    }

    ReportStat(packetParam);
    CloseSocket(packetParam);
    packetParam->t_win = t_start;

    // Tell parent we are gone
    pthread_kill(packetParam->parent, SIGUSR1);
    pthread_exit(NULL);
    /* NOTREACHED */

} /* End of packet_thread */
