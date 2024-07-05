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

#include "packet_pcap.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "pcaproc.h"
#include "queue.h"
#include "util.h"

static void CloseSocket(packetParam_t *param);

static int setup_pcap_filter(packetParam_t *param, char *filter);

static void ReportStat(packetParam_t *param);

static inline void PcapDump(packetBuffer_t *packetBuffer, struct pcap_pkthdr *hdr, const u_char *sp);

static struct pcap_stat last_stat = {0};
static proc_stat_t proc_stat = {0};

/*
 * Functions
 */

static void CloseSocket(packetParam_t *param) { pcap_close(param->pcap_dev); }  // End of CloseSocket

// live device
int setup_pcap_live(packetParam_t *param, char *device, char *filter, int snaplen, int buffsize, int to_ms) {
    pcap_t *p;
    char errbuf[PCAP_ERRBUF_SIZE];

    errbuf[0] = '\0';

    /*
     *  If device is NULL, that means the user did not specify one and is
     *  leaving it up libpcap to find one.
     */
    if (device == NULL) {
        pcap_if_t *alldevsp = NULL;
        if (pcap_findalldevs(&alldevsp, errbuf) == -1) {
            LogError("pcap_findalldevs() error: %s in %s line %d", errbuf, __FILE__, __LINE__);
            return -1;
        }
        if (alldevsp == NULL) {
            LogError("Couldn't find default device");
            return -1;
        }
        device = alldevsp[0].name;
        LogError("Listen on %s", device);
    }

    /*
     *  Open the packet capturing device with the following values:
     *
     *  SNAPLEN: User defined or 1600 bytes
     *  PROMISC: on
     *  The interface needs to be in promiscuous mode to capture all
     *		network traffic on the localnet.
     *  TO_MS: 100ms
     *		this value specifies how long to wait, if a packet arrives
     *		until the application may request it. longer time have the advantage
     * 		in processing multiple packets - less interrupts but more packet loss
     */
    p = pcap_create(device, errbuf);
    if (!p) {
        LogError("pcap_create() failed on %s: %s", device, errbuf);
        return -1;
    }

    if (pcap_set_snaplen(p, snaplen)) {
        LogError("pcap_set_snaplen() failed: %s", pcap_geterr(p));
        pcap_close(p);
        return -1;
    }

    if (pcap_set_promisc(p, PROMISC)) {
        LogError("pcap_set_promisc() failed: %s", pcap_geterr(p));
        pcap_close(p);
        return -1;
    }

    if (pcap_set_timeout(p, to_ms)) {
        LogError("pcap_set_timeout() failed: %s", pcap_geterr(p));
        pcap_close(p);
        return -1;
    }

    if (pcap_set_buffer_size(p, buffsize) < 0) {
        LogError("pcap_set_buffer_size() failed: %s", pcap_geterr(p));
        pcap_close(p);
        return -1;
    }

    if (pcap_activate(p)) {
        LogError("pcap_activate() failed: %s", pcap_geterr(p));
        pcap_close(p);
        return -1;
    }

    param->linktype = pcap_datalink(p);
    switch (param->linktype) {
        case DLT_RAW:
        case DLT_PPP:
        case DLT_PPP_SERIAL:
        case DLT_NULL:
        case DLT_LOOP:
        case DLT_EN10MB:
#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL 113
#endif
        case DLT_LINUX_SLL:
        case DLT_IEEE802_11:
        case DLT_NFLOG:
        case DLT_PFLOG:
            break;
        default:
            LogError("Unsupported data link type %i", param->linktype);
            pcap_close(p);
            return -1;
    }

    param->pcap_dev = p;

    if (filter && !setup_pcap_filter(param, filter)) {
        pcap_close(param->pcap_dev);
        return -1;
    }

    return 0;

} /* setup_pcap_live */

static int setup_pcap_filter(packetParam_t *param, char *filter) {
    struct bpf_program filter_code;

    if (pcap_compile(param->pcap_dev, &filter_code, filter, 1, PCAP_NETMASK_UNKNOWN)) {
        LogError("pcap_compile() failed: %s", pcap_geterr(param->pcap_dev));
        return 0;
    }

    if (pcap_setfilter(param->pcap_dev, &filter_code)) {
        LogError("pcap_setfilter() failed: %s", pcap_geterr(param->pcap_dev));
        return 0;
    }

    return 1;

}  // End of setup_pcap_filter

static void ReportStat(packetParam_t *param) {
    struct pcap_stat pstat;

    if (param->live) {
        memset((void *)&pstat, 0, sizeof(struct pcap_stat));
        if (pcap_stats(param->pcap_dev, &pstat) < 0) {
            LogError("pcap_stats() failed: %s", pcap_geterr(param->pcap_dev));
        } else {
            LogInfo("Stat: received: %d, dropped by OS/Buffer: %d, dropped by interface/driver: %d", pstat.ps_recv - last_stat.ps_recv,
                    pstat.ps_drop - last_stat.ps_drop, pstat.ps_ifdrop - last_stat.ps_ifdrop);
            last_stat = pstat;
        }
    }

    LogInfo("Processed: %u, skipped: %u, short caplen: %u, unknown: %u", param->proc_stat.packets - proc_stat.packets,
            param->proc_stat.skipped - proc_stat.skipped, param->proc_stat.short_snap - proc_stat.short_snap,
            param->proc_stat.unknown - proc_stat.unknown);

    proc_stat = param->proc_stat;

}  // End of ReportStat

static inline void PcapDump(packetBuffer_t *packetBuffer, struct pcap_pkthdr *hdr, const u_char *sp) {
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

void __attribute__((noreturn)) * pcap_packet_thread(void *args) {
    packetParam_t *packetParam = (packetParam_t *)args;

    time_t t_win = packetParam->t_win;
    time_t now = 0;
    if (packetParam->live) {
        // start time is now for live capture
        now = time(NULL);
    } else {
        struct pcap_pkthdr *hdr;
        const u_char *data;
        // start time is time of 1st packet for file reading
        long pos = ftell(pcap_file(packetParam->pcap_dev));
        if (pcap_next_ex(packetParam->pcap_dev, &hdr, &data) == 1) {
            now = hdr->ts.tv_sec;
        }
        // reset file to 1st packet
        fseek(pcap_file(packetParam->pcap_dev), pos, SEEK_SET);
    }
    time_t t_start = now - (now % t_win);

    int done = *(packetParam->done);
    int DoPacketDump = packetParam->bufferQueue != NULL;

    packetBuffer_t *packetBuffer = NULL;
    if (DoPacketDump) packetBuffer = queue_pop(packetParam->bufferQueue);

    while (!done) {
        struct pcap_pkthdr *hdr;
        const u_char *data;

        int ret = pcap_next_ex(packetParam->pcap_dev, &hdr, &data);
        time_t t_packet = 0;
        switch (ret) {
            case 1: {
                // packet read ok
                dbg_printf("pcap_next_ex() next packet\n");
                t_packet = hdr->ts.tv_sec;
                if ((t_packet - t_start) >= t_win) {
                    if (DoPacketDump) {
                        // Rote dump file - close old - open new
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

                int ok = ProcessPacket(packetParam, hdr, data);
                size_t size = sizeof(struct pcap_sf_pkthdr) + hdr->caplen;
                if (DoPacketDump && ok) {
                    if ((packetBuffer->bufferSize + size) > BUFFSIZE) {
                        packetBuffer->timeStamp = 0;
                        dbg_printf("packet_thread() flush buffer - size %zu\n", packetBuffer->bufferSize);
                        queue_push(packetParam->flushQueue, packetBuffer);
                        packetBuffer = queue_pop(packetParam->bufferQueue);
                    }
                    PcapDump(packetBuffer, hdr, data);
                }
            } break;
            case 0: {
                // live capture idle cycle
                dbg_printf("pcap_next_ex() read live - timeout\n");
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
                    ReportStat(packetParam);
                    Push_SyncNode(packetParam->NodeList, t_start);
                    t_start = t_packet - (t_packet % t_win);
                }
                CacheCheck(packetParam->NodeList, t_start);
            } break;
            case -1:
                // signal error reading the packet
                dbg_printf("pcap_next_ex() read live - error\n");
                LogError("pcap_next_ex() read error: '%s'", pcap_geterr(packetParam->pcap_dev));
                done = 1;
                break;
            case -2:  // End of packet file
                // signal parent, job is done
                dbg_printf("pcap_next_ex() read live - eof\n");
                done = 1;
                break;
            default:
                pcap_breakloop(packetParam->pcap_dev);
                LogError("Unexpected pcap_next_ex() return value: %i", ret);
                done = 1;
        }
        done = done || *(packetParam->done);
    }

    dbg_printf("Done capture loop - signal close\n");
    if (DoPacketDump) {
        packetBuffer->timeStamp = t_start;
        queue_push(packetParam->flushQueue, packetBuffer);
        queue_close(packetParam->flushQueue);
    }

    CloseSocket(packetParam);
    ReportStat(packetParam);
    packetParam->t_win = t_start;

    // Tell parent we are gone
    pthread_kill(packetParam->parent, SIGUSR1);
    pthread_exit("leave pcap_loop()");
    /* NOTREACHED */

} /* End of packet_thread */
