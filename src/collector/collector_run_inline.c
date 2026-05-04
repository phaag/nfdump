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
 *   - standard POSIX headers      (sys/select.h, time.h, errno.h, sys/time.h)
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
 * pselect() is a true syscall on every platform (Linux, macOS, all BSDs).
 * It atomically unblocks the nominated signals for the duration of the wait,
 * so delivery of SIGTERM/SIGINT/SIGHUP is guaranteed to return EINTR.
 *
 * Caller contract:
 *   - SIGTERM/SIGINT/SIGHUP must already be blocked in the calling thread
 *     before entering the collection loop (see run_network()).
 *   - origmask is the signal mask to restore atomically inside pselect().
 *   - The caller restores the original mask after the loop exits.
 *
 * socks[0..nsocks-1] are the receive file descriptors to watch (1 or 2).
 *
 * Returns:
 *   >= 0  index into socks[] of the socket with a pending datagram
 *   -3    timeout (time to rotate)
 *   -2    interrupted by signal while done == 1 (initiate shutdown)
 *   -1    fatal pselect() error (already logged)
 */
static inline int poll_for_packet(const int *socks, int nsocks, time_t next_rotate, const sigset_t *origmask) {
    // compute nfds = max(socks[i]) + 1
    int nfds = 0;
    for (int i = 0; i < nsocks; i++)
        if (socks[i] > nfds) nfds = socks[i];
    nfds++;

    for (;;) {
        // check done while signals are blocked — no race with the handler
        if (done) return -2;

        // recalculate remaining time on every iteration (handles EINTR drift)
        time_t remaining = next_rotate - time(NULL);
        if (remaining < 0) remaining = 0;
        struct timespec ts = {.tv_sec = remaining, .tv_nsec = 0};

        fd_set rfd;
        FD_ZERO(&rfd);
        for (int i = 0; i < nsocks; i++) FD_SET(socks[i], &rfd);

        // pselect() atomically swaps in origmask (unblocking the signals)
        // for the duration of the call, then restores the blocked mask on return
        int ret = pselect(nfds, &rfd, NULL, NULL, &ts, origmask);
        if (ret > 0) {
            for (int i = 0; i < nsocks; i++)
                if (FD_ISSET(socks[i], &rfd)) return i;
            continue;  // pselect returned ready but no fd matched — shouldn't happen
        }
        if (ret == 0) return -3;
        if (errno == EINTR) {
            // signal arrived — loop back to check done
            continue;
        }

        // real error
        LogError("pselect() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
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
