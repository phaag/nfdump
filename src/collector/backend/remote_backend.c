/*
 *  Copyright (c) 2026, Peter Haag
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
 * UDP send backend for nfcapd.
 *
 * Receives full flow data blocks via blockQueue from the collector frontend
 * and forwards them as nfd v250 (or v251 encrypted) UDP packets to a remote
 * nfcapd instance.  Each UDP packet is capped at UDP_SEND_THRESHOLD bytes of
 * inner payload to avoid IP fragmentation.
 *
 * Block handling:
 *   BLOCK_TYPE_FLOW  — iterate recordHeaderV4_t records; pack into UDP packets.
 *   BLOCK_TYPE_MSG   — flush pending records; read done flag from cycle_message.
 *   all others       — discarded (BLOCK_TYPE_EXP, BLOCK_TYPE_ARRAY, …).
 */

#include "backend/remote_backend.h"

#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "collector.h"
#include "flowsource.h"
#include "logging.h"
#include "network/nfd_udp_crypto.h"
#include "nfd_raw.h"
#include "nffileV3/nffileV3.h"
#include "nfxV4.h"
#include "queue.h"
#include "util.h"

/*
 * Maximum inner-payload bytes before flushing to a UDP packet.
 * Chosen so that even after encryption overhead (NFD_ENC_HDR_SIZE + 16-byte
 * Poly1305 tag = 52 bytes) the wire packet stays below a 1500-byte Ethernet
 * MTU.  Matches the threshold used in nfpcapd/flowsend.c.
 */
#define UDP_SEND_THRESHOLD 1200u

static noreturn void *udpsend_backend_thread(void *arg);

/*
 * SendUDPPacket — serialise the buffered nfd_header payload and transmit it.
 *
 * Plain path  (udpSessionKey == NULL): send sendBuffer as a v250 packet.
 * Crypto path (udpSessionKey != NULL): encrypt into encBuffer and send as v251.
 *
 * The header fields are fixed up in network byte order before sending and
 * reset to empty (length = sizeof header, numRecord = 0) on return.
 *
 * Returns 0 on success, -1 on error (packet is reset in both cases).
 */
static int SendUDPPacket(udpsend_backend_ctx_t *ctx, nfd_header_t *hdr, void *sendBuffer, void *encBuffer) {
    if (hdr->numRecord == 0) return 0;

    uint32_t length = hdr->length;

    hdr->length = htons((uint16_t)hdr->length);
    hdr->lastSequence = htonl(ctx->sequence++);
    hdr->numRecord = htonl(hdr->numRecord);

    const void *sendPtr;
    ssize_t sendLen;

    if (ctx->udpSessionKey) {
        sendLen = UdpEncrypt(encBuffer, NFD_ENC_HDR_SIZE + 65535 + NFD_AEAD_TAG_SIZE, sendBuffer, length, ctx->udpSessionKey);
        if (sendLen < 0) {
            LogError("SendUDPPacket: UdpEncrypt failed — packet not sent");
            hdr->length = sizeof(nfd_header_t);
            hdr->numRecord = 0;
            return -1;
        }
        sendPtr = encBuffer;
    } else {
        sendLen = (ssize_t)length;
        sendPtr = sendBuffer;
    }

    ssize_t ret = sendto(ctx->sendHost.sockfd, sendPtr, (size_t)sendLen, 0, (struct sockaddr *)&ctx->sendHost.addr, ctx->sendHost.addrlen);
    if (ret < 0) {
        LogError("SendUDPPacket: sendto() failed: %s", strerror(errno));
    }

    hdr->length = sizeof(nfd_header_t);
    hdr->numRecord = 0;
    return (ret < 0) ? -1 : 0;

}  // End of SendUDPPacket

/*
 * PackFlowBlock — iterate V4 records inside a flowBlockV3_t and pack them
 * into the UDP send buffer, flushing whenever the threshold is crossed.
 *
 * The records are already in recordHeaderV4_t wire format; they are copied
 * verbatim into the nfd_header payload, so no re-serialisation is needed.
 */
static void PackFlowBlock(udpsend_backend_ctx_t *ctx, flowBlockV3_t *flowBlock, nfd_header_t *hdr, void *sendBuffer, void *encBuffer) {
    uint8_t *ptr = (uint8_t *)flowBlock + sizeof(flowBlockV3_t);
    uint32_t remaining = flowBlock->rawSize - (uint32_t)sizeof(flowBlockV3_t);

    while (remaining >= sizeof(recordHeaderV4_t)) {
        recordHeaderV4_t *rec = (recordHeaderV4_t *)ptr;
        uint32_t recSize = rec->size;

        if (recSize < sizeof(recordHeaderV4_t) || recSize > remaining) {
            LogError("PackFlowBlock: invalid record size %u (remaining %u) — stopping block iteration", recSize, remaining);
            break;
        }

        /* flush before the inner payload would overflow 65535 or the threshold */
        if ((uint32_t)hdr->length + recSize > 65535u || (uint32_t)hdr->length > UDP_SEND_THRESHOLD) {
            SendUDPPacket(ctx, hdr, sendBuffer, encBuffer);
        }

        memcpy((uint8_t *)sendBuffer + hdr->length, rec, recSize);
        hdr->length += recSize;
        hdr->numRecord++;

        ptr += recSize;
        remaining -= recSize;
    }

}  // End of PackFlowBlock

/*
 * Init_udpsend_backend — initialise the UDP send backend for a FlowSource.
 *
 * sendHost      pre-connected repeater_t (sockfd already open).
 * udpSessionKey 32-byte XChaCha20-Poly1305 key; NULL for plain v250.
 *
 * Sets fs->backend_ctx and fs->blockQueue.
 * Returns 0 on success, 1 on error.
 */
int Init_udpsend_backend(FlowSource_t *fs, const repeater_t *sendHost, const uint8_t *udpSessionKey) {
    udpsend_backend_ctx_t *ctx = calloc(1, sizeof(udpsend_backend_ctx_t));
    if (!ctx) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 1;
    }

    ctx->sendHost = *sendHost;
    ctx->udpSessionKey = udpSessionKey;
    ctx->sequence = 0;

    ctx->blockQueue = queue_init(64);
    if (!ctx->blockQueue) {
        LogError("Init_udpsend_backend: queue_init failed");
        free(ctx);
        return 1;
    }

    fs->backend_ctx = (void *)ctx;
    fs->blockQueue = ctx->blockQueue;
    return 0;

}  // End of Init_udpsend_backend

/*
 * Close_udpsend_backend — flush, join the backend thread and free resources.
 */
void Close_udpsend_backend(FlowSource_t *fs) {
    if (!fs || !fs->backend_ctx) return;

    udpsend_backend_ctx_t *ctx = (udpsend_backend_ctx_t *)fs->backend_ctx;

    if (fs->blockQueue) queue_close(fs->blockQueue);

    dbg_printf("Join udpsend backend thread\n");
    if (fs->tid) pthread_join(fs->tid, NULL);
    fs->tid = 0;

    queue_free(ctx->blockQueue);
    free(ctx);
    fs->backend_ctx = NULL;

}  // End of Close_udpsend_backend

/*
 * Launch_udpsend_backend — start the backend thread for this FlowSource.
 * Returns 1 on success, 0 on error.
 */
int Launch_udpsend_backend(FlowSource_t *fs) {
    fs->tid = 0;
    int err = pthread_create(&fs->tid, NULL, udpsend_backend_thread, fs->backend_ctx);
    if (err) {
        LogError("pthread_create() failed: %s", strerror(err));
        return 0;
    }
    return 1;

}  // End of Launch_udpsend_backend

/*
 * udpsend_backend_thread — backend thread body.
 *
 * Pops data blocks from blockQueue and forwards flow records as UDP packets.
 * Exits when a cycle message with done==1 is received or the queue is closed.
 */
static noreturn void *udpsend_backend_thread(void *arg) {
    udpsend_backend_ctx_t *ctx = (udpsend_backend_ctx_t *)arg;

    dbg_printf("%s() thread startup\n", __func__);

    void *sendBuffer = malloc(65535);
    void *encBuffer = malloc(NFD_ENC_HDR_SIZE + 65535 + NFD_AEAD_TAG_SIZE);
    if (!sendBuffer || !encBuffer) {
        LogError("udpsend_backend_thread: malloc failed");
        free(sendBuffer);
        free(encBuffer);
        queue_close(ctx->blockQueue);
        pthread_exit(NULL);
    }

    nfd_header_t *hdr = (nfd_header_t *)sendBuffer;
    memset(hdr, 0, sizeof(nfd_header_t));
    hdr->version = htons(VERSION_NFDUMP);
    hdr->length = sizeof(nfd_header_t);

    uint32_t cnt = 0;
    int done = 0;
    while (!done) {
        dataBlockV3_t *block = (dataBlockV3_t *)queue_pop(ctx->blockQueue);
        if (block == QUEUE_CLOSED) {
            dbg_printf("%s() queue closed — exit loop\n", __func__);
            break;
        }

        dbg_printf("%s() received block type %u\n", __func__, block->type);
        switch (block->type) {
            case BLOCK_TYPE_FLOW:
                PackFlowBlock(ctx, (flowBlockV3_t *)block, hdr, sendBuffer, encBuffer);
                cnt++;
                break;

            case BLOCK_TYPE_MSG: {
                /* flush any pending records before processing the cycle */
                if (hdr->numRecord > 0) SendUDPPacket(ctx, hdr, sendBuffer, encBuffer);

                /* read done flag — no file rotation needed for send backend */
                cycle_message_t *msg = (cycle_message_t *)ResetCursor((msgBlockV3_t *)block);
                if (msg->type == MESSAGE_CYCLE) done = msg->done;
                dbg_printf("%s() cycle message: done=%d\n", __func__, done);
                break;
            }

            default:
                /* BLOCK_TYPE_EXP, BLOCK_TYPE_ARRAY, etc. are not forwarded */
                dbg_printf("%s() discarding block type %u\n", __func__, block->type);
                break;
        }

        FreeDataBlock(block);
    }

    /* final flush of any partially-filled packet */
    if (hdr->numRecord > 0) SendUDPPacket(ctx, hdr, sendBuffer, encBuffer);

    close(ctx->sendHost.sockfd);
    ctx->sendHost.sockfd = -1;

    free(sendBuffer);
    free(encBuffer);

    dbg_printf("%s() exit — forwarded %u flow blocks\n", __func__, cnt);
    (void)cnt;

    pthread_exit(NULL);

}  // End of udpsend_backend_thread
