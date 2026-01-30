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

#include <arpa/inet.h>
#include <errno.h>
#include <stddef.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "daemon.h"
#include "nfnet.h"
#include "privsep.h"
#include "util.h"

#define IP_HDR_LEN 5
#define UDP_HDR_SIZE 8
#define MAXTLL 255

static int done = 1;
static int child_exit = 0;
static pthread_t reader_tid;

static unsigned ip_header_checksum(struct ip *header);

static uint16_t udp_sum_calc(uint16_t len_udp, uint32_t src_addr, uint16_t src_port, uint32_t dest_addr, uint16_t dest_port, const void *buff);

int raw_send_to(int sock, void *msg, size_t msglen, struct sockaddr_in *src_addr, struct sockaddr_in *dst_addr, int ttl, int flags);

static void SignalHandler(int signal) {
    switch (signal) {
        case SIGTERM:
            done = 1;
            break;
        case SIGCHLD:
            child_exit++;
            break;
    }

} /* End of IntHandler */

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

int raw_send_to(int sock, void *msg, size_t msglen, struct sockaddr_in *src_addr, struct sockaddr_in *dst_addr, int ttl, int flags) {
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

    int ret = sendmsg(sock, &mh, 0);
    if (ret == -1) {
        LogError("sendmsg() error: %s", strerror(errno));
    } else {
        dbg_printf("sendmsg() ok\n");
    }

    return ret;
}

static void RepeaterMessageFunc(message_t *message, void *extraArg) {
    repeater_t *repeater = (repeater_t *)extraArg;
    void *p = (void *)message;
    p += sizeof(message_t);

    dbg_printf("repeater received message: %u %u\n", message->type, message->length);

    if (message->type == PRIVMSG_REPEAT && message->length > (sizeof(message_t) + sizeof(repeater_message_t))) {
        // Original raw packet repeating to all repeaters
        dbg_printf("repeater process message: type: %d, length: %d\n", message->type, message->length);

        repeater_message_t *repeater_message = (repeater_message_t *)p;
        p += sizeof(repeater_message_t);

        void *in_buff = p;
        size_t cnt = repeater_message->packet_size;
        if (message->length < (sizeof(message_t) + sizeof(repeater_message_t) + cnt)) {
            LogError("Repeater message size check error: %u", message->length);
            return;
        }
        int i = 0;
        while (repeater[i].hostname && (i < MAX_REPEATERS)) {
            // Skip repeaters with filters, they get filtered packets via PRIVMSG_FILTERED_REPEAT
            if (repeater[i].filter != NULL) {
                i++;
                continue;
            }
            if (repeater[i].addrlen == 0) {
                // packet spoofing
                struct sockaddr_in *src_addr = (struct sockaddr_in *)&repeater_message->addr;
                struct sockaddr_in *dst_addr = (struct sockaddr_in *)&repeater[i].addr;
                if (src_addr->sin_family == PF_INET) {
                    // Only IPv4 spoofing supported
                    raw_send_to(repeater[i].sockfd, in_buff, cnt, src_addr, dst_addr, MAXTTL, 0);
                }
            } else {
                // normal packet repeating
                ssize_t len = sendto(repeater[i].sockfd, in_buff, cnt, 0, (struct sockaddr *)&(repeater[i].addr), repeater[i].addrlen);
                if (len < 0) {
                    LogError("sendto(): %d: %s %s", i, repeater[i].hostname, strerror(errno));
                } else {
                    dbg_printf("Repeated: %zd\n", len);
                }
            }
            i++;
        }
    } else if (message->type == PRIVMSG_FILTERED_REPEAT && message->length > (sizeof(message_t) + sizeof(filtered_repeater_message_t))) {
        // Filtered packet repeating to a specific repeater
        dbg_printf("repeater process filtered message: type: %d, length: %d\n", message->type, message->length);

        filtered_repeater_message_t *frm = (filtered_repeater_message_t *)p;
        p += sizeof(filtered_repeater_message_t);

        void *in_buff = p;
        size_t cnt = frm->packet_size;
        int idx = frm->repeater_index;

        if (message->length < (sizeof(message_t) + sizeof(filtered_repeater_message_t) + cnt)) {
            LogError("Filtered repeater message size check error: %u", message->length);
            return;
        }

        if (idx < 0 || idx >= MAX_REPEATERS || !repeater[idx].hostname) {
            LogError("Invalid repeater index in filtered message: %d", idx);
            return;
        }

        // Send to the specific repeater
        if (repeater[idx].addrlen == 0) {
            LogError("Packet spoofing not supported for filtered repeaters :(");
        } else {
            ssize_t len = sendto(repeater[idx].sockfd, in_buff, cnt, 0,
                                 (struct sockaddr *)&(repeater[idx].addr), repeater[idx].addrlen);
            if (len < 0) {
                LogError("sendto() filtered: %d: %s %s", idx, repeater[idx].hostname, strerror(errno));
            } else {
                dbg_printf("Filtered repeated to %s: %zd bytes\n", repeater[idx].hostname, len);
            }
        }
    }
}

int StartupRepeater(repeater_t *repeater, unsigned bufflen, unsigned srcSpoofing, char *userid, char *groupid) {
    LogInfo("StartupRepeater: userid: %s, groupid: %s", userid ? userid : "default", groupid ? groupid : "default");

    if (srcSpoofing == 0) {
        SetPriv(userid, groupid);
        int i = 0;
        while (repeater[i].hostname && (i < MAX_REPEATERS)) {
            repeater[i].sockfd =
                Unicast_send_socket(repeater[i].hostname, repeater[i].port, AF_UNSPEC, bufflen, &repeater[i].addr, &repeater[i].addrlen);
            if (repeater[i].sockfd <= 0) return 0;
            LogVerbose("Replay flows to host: %s port: %s", repeater[i].hostname, repeater[i].port);
            i++;
        }
    } else {
        int rawSocket = Raw_send_socket(bufflen);
        if (rawSocket == 0) {
            LogVerbose("Failed to open raw socket");
            return 255;
        }
        SetPriv(userid, groupid);
        LogInfo("Note: packet spoofing only works for IPv4 addresses");
        int i = 0;
        while (repeater[i].hostname && (i < MAX_REPEATERS)) {
            if (LookupHost(repeater[i].hostname, repeater[i].port, (struct sockaddr_in *)&(repeater[i].addr)) == 0) {
                // set addrlen to 0 to flag raw socket
                repeater[i].sockfd = rawSocket;
                repeater[i].addrlen = 0;
                LogVerbose("Replay flows to host: %s port: %s, spoofing sender address", repeater[i].hostname, repeater[i].port);
            } else {
                LogError("Can not resolve %s to a valid IPv4 address", repeater[i].hostname);
            }
            i++;
        }
    }

    /* Signal handling */
    struct sigaction act;
    memset((void *)&act, 0, sizeof(struct sigaction));
    act.sa_handler = SignalHandler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGCHLD, &act, NULL);

    thread_arg_t thread_arg = {0};
    thread_arg.messageFunc = RepeaterMessageFunc;
    thread_arg.extraArg = repeater;
    pthread_t tid;
    int err = pthread_create(&reader_tid, NULL, pipeReader, (void *)&thread_arg);
    if (err) {
        LogError("pthread_create() error in %s line %d: %s", __FILE__, __LINE__, strerror(err));
        return 255;
    }
    tid = reader_tid;

    err = pthread_join(tid, NULL);
    if (err) {
        LogError("pthread_join() error in %s line %d: %s", __FILE__, __LINE__, strerror(err));
    }

    LogVerbose("End StartupRepeater()");
    return 0;

}  // End of StartupRepeater