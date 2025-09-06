/*
 *  Copyright (c) 2023, Peter Haag
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

#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "packet_pcap.h"
#include "pcaproc.h"
#include "queue.h"
#include "util.h"

struct block_desc {
    uint32_t version;
    uint32_t offset_to_priv;
    struct tpacket_hdr_v1 h1;
};

static void CloseSocket(packetParam_t *param);

static int setup_pcap_filter(packetParam_t *param, char *filter);

static void ReportStat(packetParam_t *param);

static inline void PcapDump(packetBuffer_t *packetBuffer, struct tpacket3_hdr *ppd);

static struct tpacket_stats_v3 last_stat = {0};
static proc_stat_t proc_stat = {0};

/*
 * Functions
 */

static void CloseSocket(packetParam_t *param) {
    struct ring *ring = &(param->ring);
    if (ring->map) munmap(ring->map, ring->req.tp_block_size * ring->req.tp_block_nr);
    if (ring->rd) free(ring->rd);
    if (param->fd) close(param->fd);
    ring->map = NULL;
    ring->rd = NULL;
    param->fd = 0;
}

// Initialize the socket rx ring buffer
static int InitRing(packetParam_t *param, char *device) {
    unsigned int blocksiz = 1 << 22, framesiz = 1 << 11;
    unsigned int blocknum = 64;

    struct ring *ring = &(param->ring);
    memset(&ring->req, 0, sizeof(ring->req));
    ring->req.tp_block_size = blocksiz;
    ring->req.tp_frame_size = framesiz;
    ring->req.tp_block_nr = blocknum;
    ring->req.tp_frame_nr = (blocksiz * blocknum) / framesiz;
    ring->req.tp_retire_blk_tov = 60;
    ring->req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

    int err = setsockopt(param->fd, SOL_PACKET, PACKET_RX_RING, &ring->req, sizeof(ring->req));
    if (err < 0) {
        LogError("setsockopt(PACKET_RX_RING) failed: %s", strerror(errno));
        return -1;
    }

    ring->map = mmap(NULL, ring->req.tp_block_size * ring->req.tp_block_nr, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, param->fd, 0);
    if (ring->map == MAP_FAILED) {
        LogError("mmap() failed: %s", strerror(errno));
        return -1;
    }

    ring->rd = malloc(ring->req.tp_block_nr * sizeof(*ring->rd));
    if (!ring->rd) {
        LogError("malloc() failed: %s", strerror(errno));
        return -1;
    }

    for (int i = 0; i < ring->req.tp_block_nr; ++i) {
        ring->rd[i].iov_base = ring->map + (i * ring->req.tp_block_size);
        ring->rd[i].iov_len = ring->req.tp_block_size;
    }

    struct sockaddr_ll ll;
    memset(&ll, 0, sizeof(ll));
    ll.sll_family = PF_PACKET;
    ll.sll_protocol = htons(ETH_P_ALL);
    ll.sll_ifindex = if_nametoindex(device);
    ll.sll_hatype = 0;
    ll.sll_pkttype = 0;
    ll.sll_halen = 0;

    err = bind(param->fd, (struct sockaddr *)&ll, sizeof(ll));
    if (err < 0) {
        LogError("bind() failed: %s", strerror(errno));
        CloseSocket(param);
        return -1;
    }

    return 0;

}  // End of InitRing

int setup_linux_live(packetParam_t *param, char *device, char *filter, int snaplen, int buffsize, int to_ms) {
    param->pcap_dev = NULL;
    param->fd = 0;

    // open packet socket
    int fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        LogError("socket() failed: %s", strerror(errno));
        return -1;
    }

    int v = TPACKET_V3;
    int err = setsockopt(fd, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
    if (err < 0) {
        LogError("setsockopt(TPACKET_V3) failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    param->fd = fd;
    if (InitRing(param, device) < 0) {
        CloseSocket(param);
        return -1;
    }

    // determine the correct linktype for this device
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name) - 1);

    int linktype = DLT_RAW;  // safe default
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
        switch (ifr.ifr_hwaddr.sa_family) {
            case ARPHRD_ETHER:
                linktype = DLT_EN10MB;  // Ethernet
                break;
            case ARPHRD_NONE:    // tun/tap
            case ARPHRD_TUNNEL:  // or TUNNEL
            case ARPHRD_TUNNEL6:
                linktype = DLT_RAW;  // raw IP packets
                break;
            default:
                LogError("Unknown arptype %d for %s, using DLT_RAW as linktype", ifr.ifr_hwaddr.sa_family, device);
                linktype = DLT_RAW;
                break;
        }
    } else {
        LogError("octl(SIOCGIFHWADDR) failed: %s", strerror(errno));
    }

    param->linktype = linktype;

    // pcap handle for dumper (pcap_open_dead just sets the linktype and snaplen)
    pcap_t *p = pcap_open_dead(param->linktype, snaplen > 0 ? snaplen : (1 << 16));
    if (!p) {
        LogError("pcap_open_dead() failed");
        CloseSocket(param);
        return -1;
    }
    param->pcap_dev = p;

    if (filter && !setup_pcap_filter(param, filter)) {
        pcap_close(param->pcap_dev);
        CloseSocket(param);
        return -1;
    }

    return 0;

}  // End of setup_pcap_live

static int setup_pcap_filter(packetParam_t *param, char *filter) {
    struct bpf_program filter_code;

    if (pcap_compile(param->pcap_dev, &filter_code, filter, 1, PCAP_NETMASK_UNKNOWN)) {
        LogError("pcap_compile() failed: %s", pcap_geterr(param->pcap_dev));
        return 0;
    }

    struct sock_fprog fcode;
    fcode.len = filter_code.bf_len;
    fcode.filter = (struct sock_filter *)filter_code.bf_insns;

    if (setsockopt(param->fd, SOL_SOCKET, SO_ATTACH_FILTER, &fcode, sizeof(fcode)) < 0) {
        LogError("setsockopt(SO_ATTACH_FILTER) failed: %s", strerror(errno));
        return 0;
    }

    return 1;

}  // End of setup_pcap_filter

static void ReportStat(packetParam_t *param) {
    struct tpacket_stats_v3 pstat;

    memset((void *)&pstat, 0, sizeof(struct tpacket_stats_v3));
    unsigned int len = sizeof(pstat);
    int err = getsockopt(param->fd, SOL_PACKET, PACKET_STATISTICS, &pstat, &len);
    if (err < 0) {
        LogError("getsockopt(PACKET_STATISTICS) failed: %s", strerror(errno));
    } else {
        LogInfo("Stat: received: %u, dropped by OS/Buffer: %u, freeze_q_cnt: %u", pstat.tp_packets - last_stat.tp_packets,
                pstat.tp_drops - last_stat.tp_drops, pstat.tp_freeze_q_cnt - last_stat.tp_freeze_q_cnt);
        last_stat = pstat;
    }

    LogInfo("Processed: %u, skipped: %u, short caplen: %u, unknown: %u", param->proc_stat.packets - proc_stat.packets,
            param->proc_stat.skipped - proc_stat.skipped, param->proc_stat.short_snap - proc_stat.short_snap,
            param->proc_stat.unknown - proc_stat.unknown);

    proc_stat = param->proc_stat;

}  // End of ReportStat

static inline void PcapDump(packetBuffer_t *packetBuffer, struct tpacket3_hdr *ppd) {
    // caller checks for enough space in buffer
    struct pcap_sf_pkthdr sf_hdr;
    sf_hdr.ts.tv_sec = ppd->tp_sec;
    sf_hdr.ts.tv_usec = ppd->tp_nsec / 1000;
    sf_hdr.caplen = ppd->tp_snaplen;
    sf_hdr.len = ppd->tp_len;

    void *p = packetBuffer->buffer + packetBuffer->bufferSize;
    memcpy(p, (void *)&sf_hdr, sizeof(sf_hdr));
    p += sizeof(struct pcap_sf_pkthdr);

    void *sp = (void *)ppd + ppd->tp_mac;
    memcpy(p, (void *)sp, ppd->tp_snaplen);
    packetBuffer->bufferSize += (sizeof(struct pcap_sf_pkthdr) + ppd->tp_snaplen);
    dbg_printf("Buffer size: %zu\n", packetBuffer->bufferSize);

}  // End of PcapDump

void __attribute__((noreturn)) * linux_packet_thread(void *args) {
    packetParam_t *packetParam = (packetParam_t *)args;

    time_t t_win = packetParam->t_win;
    time_t now = time(NULL);
    time_t t_start = now - (now % t_win);

    int done = *(packetParam->done);
    int DoPacketDump = packetParam->bufferQueue != NULL;

    packetBuffer_t *packetBuffer = NULL;
    if (DoPacketDump) packetBuffer = queue_pop(packetParam->bufferQueue);

    struct pollfd pfd;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = packetParam->fd;
    pfd.events = POLLIN | POLLERR;
    pfd.revents = 0;

    unsigned int block_num = 0;
    while (!done) {
        struct block_desc *pbd;
        pbd = (struct block_desc *)packetParam->ring.rd[block_num].iov_base;

        int ready;
        time_t t_packet = 0;
        if ((pbd->h1.block_status & TP_STATUS_USER) == 0) {
            ready = poll(&pfd, 1, 1000);
            if (ready == -1) {
                if (errno != EINTR) LogError("poll() on socket failed: %s", strerror(errno));
                done = 1;
            } else if (ready == 0) {
                dbg_printf("poll() - timeout\n");
                struct timeval tv;
                gettimeofday(&tv, NULL);
                t_packet = tv.tv_sec;
                if ((t_packet - t_start) >= t_win) { /* rotate file */
                    if (DoPacketDump) {
                        // Rote dump file - close old - open new
                        packetBuffer->timeStamp = t_start;
                        queue_push(packetParam->flushQueue, packetBuffer);
                        packetBuffer = queue_pop(packetParam->bufferQueue);
                    }
                    // Rotate flow file
                    ReportStat(packetParam);
                    Push_SyncNode(packetParam->NodeList, t_start);
                    t_start = t_packet - (t_packet % t_win);
                }
                CacheCheck(packetParam->NodeList, t_start);
                continue;
            }
        }

        if (done) break;

        int num_pkts = pbd->h1.num_pkts;
        dbg_printf("next block. packets: %u\n", num_pkts);
        struct tpacket3_hdr *ppd;
        ppd = (struct tpacket3_hdr *)((uint8_t *)pbd + pbd->h1.offset_to_first_pkt);
        for (int i = 0; i < num_pkts; ++i) {
            dbg_printf("loop - next packet\n");
            t_packet = ppd->tp_sec;

            if ((t_packet - t_start) >= t_win) {
                // Rote dump file - close old - open new
                if (DoPacketDump) {
                    dbg_printf("packet_thread() flush file - buffer: %zu\n", packetBuffer->bufferSize);
                    packetBuffer->timeStamp = t_start;
                    queue_push(packetParam->flushQueue, packetBuffer);
                    packetBuffer = queue_pop(packetParam->bufferQueue);
                }
                // Rotate flow file
                ReportStat(packetParam);
                Push_SyncNode(packetParam->NodeList, t_start);
                t_start = t_packet - (t_packet % t_win);
            }

            struct pcap_pkthdr phdr = {//
                                       .ts.tv_sec = ppd->tp_sec,
                                       .ts.tv_usec = ppd->tp_nsec / 1000,
                                       .caplen = ppd->tp_snaplen,
                                       .len = ppd->tp_len};
            void *data = (void *)ppd + ppd->tp_mac;
            int ok = ProcessPacket(packetParam, &phdr, data);

            size_t size = sizeof(struct pcap_sf_pkthdr) + ppd->tp_len;
            if (DoPacketDump && ok) {
                if ((packetBuffer->bufferSize + size) > BUFFSIZE) {
                    packetBuffer->timeStamp = 0;
                    dbg_printf("packet_thread() flush buffer - size %zu\n", packetBuffer->bufferSize);
                    queue_push(packetParam->flushQueue, packetBuffer);
                    packetBuffer = queue_pop(packetParam->bufferQueue);
                }
                PcapDump(packetBuffer, ppd);
            }

            ppd = (struct tpacket3_hdr *)((uint8_t *)ppd + ppd->tp_next_offset);
        }
        done = done || *(packetParam->done);

        pbd->h1.block_status = TP_STATUS_KERNEL;
        block_num = (block_num + 1) % 64;
    }

    // flush buffer
    dbg_printf("Done capture loop - signal close\n");
    if (DoPacketDump) {
        packetBuffer->timeStamp = t_start;
        queue_push(packetParam->flushQueue, packetBuffer);
        queue_close(packetParam->flushQueue);
    }

    ReportStat(packetParam);
    CloseSocket(packetParam);

    // Tell parent we are gone
    pthread_kill(packetParam->parent, SIGUSR1);
    pthread_exit("End packet_thread()");
    /* NOTREACHED */

} /* End of packet_thread */
