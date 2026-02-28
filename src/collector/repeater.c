/*
 *  Copyright (c) 2023-2026, Peter Haag
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

#include "repeater.h"

#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "daemon.h"
#include "logging.h"
#include "nfnet.h"
#include "queue.h"
#include "util.h"

#define IP_HDR_LEN 5
#define UDP_HDR_SIZE 8
#define MAXTTL 255

static unsigned ip_header_checksum(struct ip *header);

static uint16_t udp_sum_calc(uint16_t len_udp, uint32_t src_addr, uint16_t src_port, uint32_t dest_addr, uint16_t dest_port, const void *buff);

static ssize_t raw_send_to(int sock, void *msg, size_t msglen, struct sockaddr_in *src_addr, struct sockaddr_in *dst_addr, int ttl, int flags);

// calculate IP hdr checksum for IP spoofing raw socket
static unsigned ip_header_checksum(struct ip *header) {
    unsigned long csum = 0;
    unsigned size = header->ip_hl;
    uint16_t *h = (uint16_t *)header;

    for (unsigned k = 0; k < size; ++k) {
        csum += *h++, csum += *h++;
    }
    while (csum > 0xffff) {
        csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum & 0xffff;
}

// calculate UDP checksum for IP spoofing raw socket
static uint16_t udp_sum_calc(uint16_t len_udp, uint32_t src_addr, uint16_t src_port, uint32_t dest_addr, uint16_t dest_port, const void *buff) {
    uint16_t prot_udp = IPPROTO_UDP;
    uint16_t chksum_init = 0;
    uint16_t udp_len_total = 0;
    uint32_t sum = 0;
    uint16_t pad = 0;

    /* if we have an odd number of bytes in the data payload, then set the pad to 1
     * for special processing
     */
    if (len_udp % 2 != 0) {
        pad = 1;
    }
    /* do the source and destination addresses, first, we have to split them
     * into 2 shorts instead of the 32 long as sent.  Sorry, that's just how they
     * calculate
     */
    uint16_t low = src_addr;
    uint16_t high = (src_addr >> 16);
    sum += ((uint32_t)high + (uint32_t)low);

    /* now do the same with the destination address */
    low = dest_addr;
    high = (dest_addr >> 16);
    sum += ((uint32_t)high + (uint32_t)low);

    /* the protocol and the number and the length of the UDP packet */
    udp_len_total = len_udp + 8; /* length sent is length of data, need to add 8 */
    sum += ((uint32_t)prot_udp + (uint32_t)udp_len_total);

    /* next comes the source and destination ports */
    sum += ((uint32_t)src_port + (uint32_t)dest_port);

    /* Now add the UDP length and checksum=0 bits
     * The Length will always be 8 bytes plus the length of the udp data sent
     * and the checksum will always be zero
     */
    sum += ((uint32_t)udp_len_total + (uint32_t)chksum_init);

    /* Add all 16 bit words to the sum, if pad is set (ie, odd data length) this will just read up
     * to the last full 16 bit word.
     * */
    for (int i = 0; i < (len_udp - pad); i += 2) {
        high = ntohs(*(uint16_t *)buff);
        buff += 2;
        sum += (uint32_t)high;
    }

    /* ok, if pad is true, then the pointer is now  right before the last single byte in
     * the payload.  We only need to add till the end of the string (1-byte) , not the next 2 bytes
     * as above.
     */
    if (pad) {
        sum += ntohs(*(unsigned char *)buff);
    }

    /* keep only the last 16 bits of the 32 bit calculated sum and add the carry overs */
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    /* one's compliment the sum */
    sum = ~sum;

    /* finally, return the 16bit network formatted checksum */
    return ((uint16_t)htons(sum));
};

static ssize_t raw_send_to(int sock, void *msg, size_t msglen, struct sockaddr_in *src_addr, struct sockaddr_in *dst_addr, int ttl, int flags) {
    struct udphdr udp;
    udp.uh_sport = src_addr->sin_port;
    udp.uh_dport = dst_addr->sin_port;
    udp.uh_ulen = htons(msglen + sizeof(struct udphdr));
    udp.uh_sum = udp_sum_calc(msglen, ntohl(src_addr->sin_addr.s_addr), ntohs(src_addr->sin_port), ntohl(dst_addr->sin_addr.s_addr),
                              ntohs(dst_addr->sin_port), msg);

    struct ip iphdr = {0};
    iphdr.ip_hl = IP_HDR_LEN;
    iphdr.ip_v = 4;
    iphdr.ip_tos = 0;
    uint16_t iplen = 4 * IP_HDR_LEN + UDP_HDR_SIZE + msglen;
    iphdr.ip_len = htons(iplen);
    iphdr.ip_off = 0;
    iphdr.ip_id = 0;
    iphdr.ip_ttl = ttl;
    iphdr.ip_p = IPPROTO_UDP;
    iphdr.ip_src.s_addr = src_addr->sin_addr.s_addr;
    iphdr.ip_dst.s_addr = dst_addr->sin_addr.s_addr;
    iphdr.ip_sum = 0;
    iphdr.ip_sum = ip_header_checksum(&iphdr);

#ifdef __APPLE__
    /*
     * For some reason, the IP header's length field needs to be in host byte order
     * in OS X - set checksum to 0.
     */
    iphdr.ip_len = iplen;
    iphdr.ip_sum = 0;
#endif

    struct iovec iov[3];
    iov[0].iov_base = (void *)&iphdr;
    iov[0].iov_len = sizeof(struct ip);
    iov[1].iov_base = (void *)&udp;
    iov[1].iov_len = sizeof(struct udphdr);
    iov[2].iov_base = msg;
    iov[2].iov_len = msglen;

    struct msghdr mh = {0};
    mh.msg_name = (void *)dst_addr;
    mh.msg_namelen = sizeof(struct sockaddr_in);
    mh.msg_iov = iov;
    mh.msg_iovlen = 3;

    return sendmsg(sock, &mh, 0);
}  // End of raw_send_to

static void *repeater_thread_main(void *arg) {
    repeater_ctx_t *repeater_ctx = (repeater_ctx_t *)arg;

    dbg_printf("Startup %s()\n", __func__);
    while (!atomic_load(&repeater_ctx->done)) {
        PacketCtx_t *packetCtx = queue_pop(repeater_ctx->packetQueue);
        if (packetCtx == QUEUE_CLOSED) {
            // packetCtx cannot get NULL, but handle it anyway
            atomic_store(&repeater_ctx->done, 1);
            break;
        }

        for (int i = 0; i < MAX_REPEATERS && repeater_ctx->repeater[i].hostname; i++) {
            repeater_t *repeater = &repeater_ctx->repeater[i];

            ssize_t len = 0;
            if (repeater->use_raw) {
                struct sockaddr_in *src_addr = (struct sockaddr_in *)&packetCtx->sender;
                struct sockaddr_in *dst_addr = (struct sockaddr_in *)&repeater->addr;

                dbg_printf("%s() Send next raw packet of len %zu\n", __func__, packetCtx->bufferLen);
                if (src_addr->sin_family == AF_INET) {
                    len = raw_send_to(repeater_ctx->rawSocket, packetCtx->buffer, packetCtx->bufferLen, src_addr, dst_addr, MAXTTL, 0);
                } else {
                    dbg_printf("%s() Unknown AF family: %u\n", __func__, src_addr->sin_family);
                }
            } else {
                dbg_printf("%s() Send next packet of len %zu\n", __func__, packetCtx->bufferLen);
                len = sendto(repeater->sockfd, packetCtx->buffer, packetCtx->bufferLen, 0, (struct sockaddr *)&repeater->addr, repeater->addrlen);
            }
            if (len < 0) {
                LogError("sendto() repeater %s: %s", repeater->hostname, strerror(errno));
            }
            dbg_printf("%s() Send packet size: %zu\n", __func__, len);
        }

        // return packet context to collector
        queue_push(repeater_ctx->bufferQueue, (void *)packetCtx);
    }

    dbg_printf("Exit %s()\n", __func__);
    return NULL;
}  // End of repeater_thread_main

pthread_t RepeaterStart(repeater_ctx_t *repeater_ctx) {
    dbg_printf("%s()\n", __func__);
    pthread_t tid;
    int err = pthread_create(&tid, NULL, repeater_thread_main, (void *)repeater_ctx);
    if (err) {
        LogError("pthread_create(repeater) failed: %s", strerror(err));
        return 0;
    }
    repeater_ctx->tid = tid;

    return tid;
}  // End of RepeaterStart

void RepeaterShutdown(repeater_ctx_t *repeater_ctx) {
    if (repeater_ctx == NULL) return;

    dbg_printf("%s()\n", __func__);

    atomic_store(&repeater_ctx->done, 1);
    queue_close(repeater_ctx->bufferQueue);
    queue_close(repeater_ctx->packetQueue);
    if (repeater_ctx->tid) {
        pthread_join(repeater_ctx->tid, NULL);
    }

    if (repeater_ctx->rawSocket > 0) close(repeater_ctx->rawSocket);
    for (int i = 0; i < MAX_REPEATERS; i++) {
        if (repeater_ctx->repeater[i].sockfd) close(repeater_ctx->repeater[i].sockfd);
        if (repeater_ctx->repeater[i].hostname) free(repeater_ctx->repeater[i].hostname);
    }

    // clear and free all packet context buffers and free queues
    queue_clear(repeater_ctx->bufferQueue, free);
    queue_free(repeater_ctx->bufferQueue);
    queue_free(repeater_ctx->packetQueue);
    free(repeater_ctx);

}  // End of RepeaterShutdown

repeater_ctx_t *RepeaterInit(repeater_host_t *repeater_host, uint32_t queue_len, int srcSpoofing) {
    repeater_ctx_t *repeater_ctx = calloc(1, sizeof(repeater_ctx_t));
    if (!repeater_ctx) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    atomic_store(&repeater_ctx->done, 0);

    repeater_ctx->bufferQueue = queue_init(queue_len);
    repeater_ctx->packetQueue = queue_init(queue_len);
    if (!repeater_ctx->bufferQueue || !repeater_ctx->packetQueue) {
        RepeaterShutdown(repeater_ctx);
        return NULL;
    }

    int err = 0;
    // init REPEATER_QUEUE_CAPACITY - 1, as the collector by default allocates a packet context
    for (int i = 0; err == 0 && i < (queue_len - 1); i++) {
        PacketCtx_t *pkt_ctx = init_packet_ctx(NETWORK_INPUT_BUFF_SIZE);
        if (!pkt_ctx) err = 1;
        if (queue_push(repeater_ctx->bufferQueue, (void *)pkt_ctx) != NULL) {
            // catch queue error
            err = 1;
        }
    }

    if (err) {
        RepeaterShutdown(repeater_ctx);
        return NULL;
    }

    // XXX make bufflen configurable
    uint32_t bufflen = 0;
    if (srcSpoofing) {
        // src spoofing - use 1 raw socket
        repeater_ctx->rawSocket = Raw_send_socket(bufflen);
        if (repeater_ctx->rawSocket == 0) err = 1;
    } else {
        repeater_ctx->rawSocket = 0;
    }

    for (int i = 0; err == 0 && i < MAX_REPEATERS && repeater_host[i].hostname; i++) {
        if (srcSpoofing) {
            struct sockaddr_in *dst = (struct sockaddr_in *)&repeater_ctx->repeater[i].addr;
            if (LookupHost(repeater_host[i].hostname, repeater_host[i].port, dst) != 0) {
                LogError("Can not resolve %s to a valid IPv4 address", repeater_host[i].hostname);
                err = 1;
            }

            repeater_ctx->repeater[i].addrlen = sizeof(struct sockaddr_in);
            repeater_ctx->repeater[i].use_raw = 1;
            repeater_ctx->repeater[i].sockfd = -1;
        } else {
            // each sender gets its socket
            repeater_ctx->rawSocket = -1;
            int sockfd = Unicast_send_socket(repeater_host[i].hostname, repeater_host[i].port, AF_UNSPEC, bufflen, &repeater_ctx->repeater[i].addr,
                                             &repeater_ctx->repeater[i].addrlen);
            if (sockfd <= 0) {
                LogError("Failed to open UDP socket for repeater %s:%s", repeater_host[i].hostname, repeater_host[i].port);
                err = 1;
            } else {
                repeater_ctx->repeater[i].sockfd = sockfd;
                repeater_ctx->repeater[i].use_raw = 0;
            }
        }

        // hostname has been strdup() in main. Take ownership
        repeater_ctx->repeater[i].hostname = repeater_host[i].hostname;
        LogVerbose("Repeat packet to host: %s port: %s", repeater_host[i].hostname, repeater_host[i].port);
    }

    if (err) {
        RepeaterShutdown(repeater_ctx);
        repeater_ctx = NULL;
    }

    return repeater_ctx;

}  // End of RepeaterInit