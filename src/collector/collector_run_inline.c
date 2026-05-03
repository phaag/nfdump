/*
 *  Copyright (c) 2009-2026, Peter Haag
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
 * collector_run_inline.c — shared hot-path helpers for all collectors.
 *
 * This file is meant to be #include'd directly into each collector's .c file
 * (nfcapd.c, sfcapd.c), NOT compiled as a separate translation unit.
 * This preserves single-TU semantics so the compiler can inline these
 * functions into run_network() / run_file_mode() without LTO.
 *
 * Requirements for the including translation unit:
 *   - static int done;            (module shutdown flag)
 *   - #include "nfnet.h"          (PacketCtx_t, init_packet_ctx)
 *   - #include "logging.h"        (LogError)
 *   - standard POSIX headers      (poll.h, time.h, errno.h, sys/time.h)
 */

/* Signal handler — identical in nfcapd and sfcapd */
static void IntHandler(int signal) {
    switch (signal) {
        case SIGHUP:
        case SIGINT:
        case SIGTERM:
            done = 1;
            break;
        default:
            break;
    }
}  // End of IntHandler

/*
 * Read next UDP datagram into pkt_ctx.
 * Extracts the kernel SO_TIMESTAMP into *tv when available; falls back to
 * gettimeofday() for valid packets and time(NULL) for zero/error returns.
 * Returns the byte count from recvmsg() (may be 0 or negative).
 */
static inline ssize_t get_next_packet(int sockfd, PacketCtx_t *pkt_ctx, struct timeval *tv) {
    // Reset lengths that might have been modified by previous recvmsg calls
    pkt_ctx->msg.msg_namelen = sizeof(pkt_ctx->sender);
    pkt_ctx->msg.msg_controllen = sizeof(pkt_ctx->control);

    ssize_t cnt = recvmsg(sockfd, &pkt_ctx->msg, 0);

    if (cnt > 0) {
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&pkt_ctx->msg);
        if (cmsg && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMP) {
            memcpy(tv, CMSG_DATA(cmsg), sizeof(*tv));
        } else {
            gettimeofday(tv, NULL);  // fallback only for valid packets
        }
    } else {
        // cnt <= 0 → no valid packet
        tv->tv_sec = time(NULL);
        tv->tv_usec = 0;
    }

    return cnt;
}  // End of get_next_packet

/*
 * Wait for a packet or for the rotation deadline to arrive.
 *
 * Returns:
 *   > 0  packet ready
 *   = 0  timeout (time to rotate)
 *   -2   interrupted by signal while done == 1 (initiate shutdown)
 *   -1   fatal poll() error (already logged)
 */
static inline int poll_for_packet(int fd, time_t next_rotate, time_t now) {
    int timeout_ms = (int)(next_rotate - now) * 1000;
    if (timeout_ms < 0) timeout_ms = 0;

    struct pollfd pfd = {.fd = fd, .events = POLLIN};

    for (;;) {
        int ret = poll(&pfd, 1, timeout_ms);
        if (ret >= 0) {
            // 0 = timeout, >0 = ready
            return ret;
        }
        if (errno == EINTR) {
            if (done) {
                // interrupted by signal and we're shutting down
                return -2;
            }
            // retry poll with same timeout (best-effort)
            continue;
        }

        // real error
        LogError("poll() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return -1;
    }
}  // End of poll_for_packet

/*
 * Receive one complete packet from the socket.
 * Retries automatically on EINTR unless done == 1.
 *
 * Returns:
 *   >= 0  byte count (0 is a valid zero-length UDP datagram)
 *   -2    EINTR + done (initiate shutdown)
 *   -1    recvmsg() error (already logged)
 */
static inline ssize_t recv_packet(int sockfd, PacketCtx_t *pkt_ctx, struct timeval *tv) {
    for (;;) {
        ssize_t cnt = get_next_packet(sockfd, pkt_ctx, tv);
        if (cnt >= 0) {
            pkt_ctx->bufferLen = cnt;
            return cnt;
        }
        if (errno == EINTR) {
            if (done) {
                // signal + shutdown
                return -2;
            }
            continue;
        }
        LogError("recvmsg() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return -1;
    }
}  // End of recv_packet
