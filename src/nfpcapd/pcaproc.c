/*
 *  Copyright (c) 2014-2026, Peter Haag
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

#include "pcaproc.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>

#include "config.h"
#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif
#ifdef HAVE_NET_ETHERTYPES_H
#include <net/ethertypes.h>
#endif

#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "bookkeeper.h"
#include "collector.h"
#include "flowhash.h"
#include "ip128.h"
#include "ip_frag.h"
#include "nfdump.h"
#include "nffile.h"
#include "nflog.h"
#include "nfxV3.h"
#include "pflog.h"
#include "util.h"

typedef struct cursor_s {
    uint8_t *ptr;
    uint8_t *end;
} cursor_t;

static time_t lastRun = 0;  // remember last run to idle cache

static inline void SetServer_latency(struct FlowNode *node);

static inline void SetClient_latency(struct FlowNode *node, const struct timeval *t_packet);

static inline void SetApplication_latency(struct FlowNode *node, const struct timeval *t_packet);

static inline void ProcessTCPFlow(packetParam_t *packetParam, const hotNode_t *hotNode, const coldNode_t *coldNode, void *payload,
                                  size_t payloadSize);

static inline void ProcessUDPFlow(packetParam_t *packetParam, const hotNode_t *hotNode, const coldNode_t *coldNode, void *payload,
                                  size_t payloadSize);

static inline void ProcessICMPFlow(packetParam_t *packetParam, const hotNode_t *hotNode, const coldNode_t *coldNode, void *payload,
                                   size_t payloadSize);

static inline void ProcessOtherFlow(packetParam_t *packetParam, const hotNode_t *hotNode, const coldNode_t *coldNode, void *payload,
                                    size_t payloadSize);

#include "decode_ctx.h"

static inline __attribute__((always_inline)) ptrdiff_t cursor_size(cursor_t *c) {
    //
    return (ptrdiff_t)(c->end - c->ptr);

}  // End of cursor_size

static inline __attribute__((always_inline)) int cursor_advance(cursor_t *c, size_t len) {
    if (c->ptr + len > c->end) return 0;
    c->ptr += len;
    return 1;
}  // End of cursor_advance

static inline __attribute__((always_inline)) int cursor_read(cursor_t *c, void *dst, size_t len) {
    if (c->ptr + len > c->end) return 0;
    memcpy(dst, c->ptr, len);
    c->ptr += len;

    return 1;
}  // End of cursor_read

static inline __attribute__((always_inline)) int cursor_get(cursor_t *c, void *dst, size_t len) {
    if (c->ptr + len > c->end) return 0;
    memcpy(dst, c->ptr, len);

    return 1;
}  // End of cursor_get

/* Include decoder modules - compiled into single unit for optimization */
#include "decode_ip.c"
#include "decode_link.c"
#include "decode_proto.c"
#include "decode_transport.c"

pcapfile_t *OpenNewPcapFile(pcap_t *p, char *filename, pcapfile_t *pcapfile) {
    if (!pcapfile) {
        // Create struct
        pcapfile = calloc(1, sizeof(pcapfile_t));
        if (!pcapfile) {
            LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return NULL;
        }
        pthread_mutex_init(&pcapfile->m_pbuff, NULL);
        pthread_cond_init(&pcapfile->c_pbuff, NULL);

        pcapfile->data_buffer = malloc(BUFFSIZE);
        if (!pcapfile->data_buffer) {
            free(pcapfile);
            LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return NULL;
        }
        pcapfile->alternate_buffer = malloc(BUFFSIZE);
        if (!pcapfile->data_buffer) {
            free(pcapfile->data_buffer);
            free(pcapfile);
            LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return NULL;
        }
        pcapfile->data_ptr = pcapfile->data_buffer;
        pcapfile->data_size = 0;
        pcapfile->alternate_size = 0;
        pcapfile->p = p;
    }

    if (filename) {
        FILE *pFile = fopen(filename, "wb");
        if (!pFile) {
            LogError("fopen() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return NULL;
        }
        pcapfile->pd = pcap_dump_fopen(p, pFile);
        if (!pcapfile->pd) {
            LogError("Fatal: pcap_dump_open() failed for file '%s': %s", filename, pcap_geterr(p));
            return NULL;
        } else {
            fflush(pFile);
            pcapfile->pfd = fileno((FILE *)pFile);
            return pcapfile;
        }
    } else
        return pcapfile;

}  // End of OpenNewPcapFile

int ClosePcapFile(pcapfile_t *pcapfile) {
    int err = 0;

    pcap_dump_close(pcapfile->pd);
    pcapfile->pfd = -1;

    return err;

}  // End of ClosePcapFile

void RotateFile(pcapfile_t *pcapfile, time_t t_CloseRename, int live) {
    struct pcap_stat p_stat;
    void *_b;

    dbg_printf("RotateFile() time: %s\n", UNIX2ISO(t_CloseRename));
    // make sure, alternate buffer is already flushed
    pthread_mutex_lock(&pcapfile->m_pbuff);
    while (pcapfile->alternate_size) {
        pthread_cond_wait(&pcapfile->c_pbuff, &pcapfile->m_pbuff);
    }

    // swap buffers
    _b = pcapfile->data_buffer;
    pcapfile->data_buffer = pcapfile->alternate_buffer;
    pcapfile->data_ptr = pcapfile->data_buffer;
    pcapfile->alternate_buffer = _b;
    pcapfile->alternate_size = pcapfile->data_size;
    pcapfile->t_CloseRename = t_CloseRename;

    // release mutex and signal thread
    pthread_mutex_unlock(&pcapfile->m_pbuff);
    pthread_cond_signal(&pcapfile->c_pbuff);

    pcapfile->data_size = 0;

    if (live) {
        // not a capture file
        if (pcap_stats(pcapfile->p, &p_stat) < 0) {
            LogError("pcap_stats() failed: %s", pcap_geterr(pcapfile->p));
        } else {
            LogInfo("Packets received: %u, dropped: %u, dropped by interface: %u ", p_stat.ps_recv, p_stat.ps_drop, p_stat.ps_ifdrop);
        }
    }

}  // End of RotateFile

// Server latency = t(SYN ACK Server) - t(SYN CLient)
static inline void SetServer_latency(struct FlowNode *node) {
    struct FlowNode *Client_node = node->coldNode.rev_node;
    if (!Client_node) return;

    uint64_t latency = ((uint64_t)node->hotNode.t_first.tv_sec * (uint64_t)1000000 + (uint64_t)node->hotNode.t_first.tv_usec) -
                       ((uint64_t)Client_node->hotNode.t_first.tv_sec * (uint64_t)1000000 + (uint64_t)Client_node->hotNode.t_first.tv_usec);

    node->coldNode.latency.server = latency;
    Client_node->coldNode.latency.server = latency;
    // set flag, to calc app latency with nex packet from server
    node->coldNode.latency.flag = 2;
    // set flag, to calc client latency with nex packet from client
    Client_node->coldNode.latency.flag = 1;
    dbg_printf("Server latency: %llu\n", (long long unsigned)latency);

}  // End of SetServerClient_latency

// Client latency = t(ACK CLient) - t(SYN ACK Server)
static inline void SetClient_latency(struct FlowNode *node, const struct timeval *t_packet) {
    struct FlowNode *serverNode = node->coldNode.rev_node;
    if (!serverNode) return;

    uint64_t latency = ((uint64_t)t_packet->tv_sec * (uint64_t)1000000 + (uint64_t)t_packet->tv_usec) -
                       ((uint64_t)serverNode->hotNode.t_last.tv_sec * (uint64_t)1000000 + (uint64_t)serverNode->hotNode.t_last.tv_usec);

    node->coldNode.latency.client = latency;
    serverNode->coldNode.latency.client = latency;
    // reset flag
    node->coldNode.latency.flag = 0;
    dbg_printf("Client latency: %llu\n", (long long unsigned)latency);

}  // End of SetClient_latency

// Application latency = t(ACK Server) - t(ACK CLient)
static inline void SetApplication_latency(struct FlowNode *node, const struct timeval *t_packet) {
    struct FlowNode *clientNode = node->coldNode.rev_node;
    if (!clientNode) return;

    uint64_t latency = ((uint64_t)t_packet->tv_sec * (uint64_t)1000000 + (uint64_t)t_packet->tv_usec) -
                       ((uint64_t)clientNode->hotNode.t_last.tv_sec * (uint64_t)1000000 + (uint64_t)clientNode->hotNode.t_last.tv_usec);

    node->coldNode.latency.application = latency;
    clientNode->coldNode.latency.application = latency;
    // reset flag
    node->coldNode.latency.flag = 0;
    // set flag, to calc application latency with nex packet from server
    clientNode->coldNode.latency.flag = 0;
    dbg_printf("Application latency: %llu\n", (long long unsigned)latency);

}  // End of SetApplication_latency

static inline void AddPayload(struct FlowNode *Node, void *payload, size_t payloadSize) {
    Node->coldNode.payload = malloc(payloadSize);
    if (!Node->coldNode.payload) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
    } else {
        memcpy(Node->coldNode.payload, payload, payloadSize);
        Node->coldNode.payloadSize = payloadSize;
    }
}  // End of AddPayload

static inline void ProcessTCPFlow(packetParam_t *packetParam, const hotNode_t *hotNode, const coldNode_t *coldNode, void *payload,
                                  size_t payloadSize) {
    struct FlowNode lookup = {0};
    lookup.hotNode.flowKey = hotNode->flowKey;

    struct FlowNode *Node = Lookup_Node(&lookup);

    if (Node == NULL) {
        // New flow
        dbg_printf("New TCP flow: Packets: %u, Bytes: %u\n", hotNode->packets, hotNode->bytes);
        struct FlowNode *NewNode = New_Node();

        NewNode->hotNode = *hotNode;
        NewNode->coldNode = *coldNode;

        if (payloadSize && packetParam->addPayload) {
            dbg_printf("New TCP flow: Set payload of size: %zu\n", payloadSize);
            AddPayload(NewNode, payload, payloadSize);
        }

        if (hotNode->flush) {
            Push_Node(packetParam->NodeList, NewNode);
            return;
        }

        struct FlowNode *existing = Insert_Node(NewNode);
        if (existing != NULL) {
            // extremely rare race: treat as existing flow
            Node = existing;
            Free_Node(NewNode);
            goto update_existing;
        }

#ifdef DEVEL
        if ((NewNode->hotNode.flags & 0x3F) == 0x2) {
            printf("SYN Node\n");
        }
        if ((NewNode->hotNode.flags & 0x37) == 0x12) {
            printf("SYN ACK Node\n");
        }
#endif
        if (packetParam->extendedFlow && Link_RevNode(NewNode)) {
            // if we could link this new node, it is the server answer
            // -> calculate server latency
            SetServer_latency(NewNode);
        }

        return;
    }
update_existing:

    assert(Node->memflag == NODE_IN_USE);

    // update existing flow
    Node->hotNode.flags |= hotNode->flags;
    Node->hotNode.packets++;
    Node->hotNode.bytes += hotNode->bytes;
    Node->hotNode.t_last = hotNode->t_last;
    dbg_printf("Existing TCP flow: Packets: %u, Bytes: %u\n", Node->hotNode.packets, Node->hotNode.bytes);

    // --- process extendedFlow is ---
    if (packetParam->extendedFlow) {
        if (Node->coldNode.latency.flag == 1) {
            SetClient_latency(Node, &hotNode->t_first);
        } else if (Node->coldNode.latency.flag == 2) {
            dbg_printf("Set App lat slot: %u -> %u diff: %u\n", Node->coldNode.latency.tsVal, coldNode->latency.tsVal,
                       coldNode->latency.tsVal - Node->coldNode.latency.tsVal);
            SetApplication_latency(Node, &hotNode->t_first);
        }

        if (coldNode->minTTL < Node->coldNode.minTTL) Node->coldNode.minTTL = coldNode->minTTL;
        if (coldNode->maxTTL > Node->coldNode.maxTTL) Node->coldNode.maxTTL = coldNode->maxTTL;
    }

    // payload stays cold unless explicitly requested
    if (packetParam->addPayload && Node->coldNode.payloadSize == 0 && payloadSize > 0) {
        dbg_printf("Existing TCP flow: Set payload of size: %zu\n", payloadSize);
        AddPayload(Node, payload, payloadSize);
    }

    if (hotNode->flush) {
        dbg_printf("TCP flush node\n");
        Remove_Node(Node);
        Push_Node(packetParam->NodeList, Node);
    } else {
        TimeWheel_Reschedule(Node, hotNode->t_last.tv_sec);
    }

}  // End of ProcessTCPFlow

static inline void ProcessUDPFlow(packetParam_t *packetParam, const hotNode_t *hotNode, const coldNode_t *coldNode, void *payload,
                                  size_t payloadSize) {
    // DNS: flush immediately, payload optional
    if (hotNode->flowKey.src_port == 53 || hotNode->flowKey.dst_port == 53) {
        struct FlowNode *NewNode = New_Node();

        NewNode->hotNode = *hotNode;
        NewNode->coldNode = *coldNode;

        if (packetParam->addPayload && payloadSize) {
            dbg_printf("UDP DNS flow: payload size: %zu\n", payloadSize);
            AddPayload(NewNode, payload, payloadSize);
        }
        dbg_printf("Flush UDP DNS packet\n");
        Push_Node(packetParam->NodeList, NewNode);
        return;
    }

    struct FlowNode lookup = {0};
    lookup.hotNode.flowKey = hotNode->flowKey;

    struct FlowNode *Node = Lookup_Node(&lookup);
    if (Node == NULL) {
        // new flow
        dbg_printf("New UDP flow: Packets: %u, Bytes: %u\n", hotNode->packets, hotNode->bytes);
        struct FlowNode *NewNode = New_Node();

        NewNode->hotNode = *hotNode;
        NewNode->coldNode = *coldNode;

        struct FlowNode *existing = Insert_Node(NewNode);
        if (existing != NULL) {
            Free_Node(NewNode);
            Node = existing;
            goto update_existing;
        }

        if (packetParam->addPayload && payloadSize) {
            dbg_printf("New UDP flow: Set payload of size: %zu\n", payloadSize);
            AddPayload(NewNode, payload, payloadSize);
        }
        return;
    }
update_existing:

    assert(Node->memflag == NODE_IN_USE);

    /* hot updates */
    Node->hotNode.packets++;
    Node->hotNode.bytes += hotNode->bytes;
    Node->hotNode.t_last = hotNode->t_last;

    // --- process extendedFlow is ---
    if (packetParam->extendedFlow) {
        if (coldNode->minTTL < Node->coldNode.minTTL) Node->coldNode.minTTL = coldNode->minTTL;
        if (coldNode->maxTTL > Node->coldNode.maxTTL) Node->coldNode.maxTTL = coldNode->maxTTL;
    }
    dbg_printf("Existing UDP flow: Packets: %u, Bytes: %u\n", Node->hotNode.packets, Node->hotNode.bytes);

    if (packetParam->addPayload && Node->coldNode.payloadSize == 0 && payloadSize > 0) {
        dbg_printf("Existing UDP flow: Set payload of size: %zu\n", payloadSize);
        AddPayload(Node, payload, payloadSize);
    }

    TimeWheel_Reschedule(Node, hotNode->t_last.tv_sec);

}  // End of ProcessUDPFlow

static inline void ProcessICMPFlow(packetParam_t *packetParam, const hotNode_t *hotNode, const coldNode_t *coldNode, void *payload,
                                   size_t payloadSize) {
    // Flush ICMP directly
    dbg_printf("Flush ICMP flow: Packets: %u, Bytes: %u\n", hotNode->packets, hotNode->bytes);

    struct FlowNode *NewNode = New_Node();
    NewNode->hotNode = *hotNode;
    NewNode->coldNode = *coldNode;

    if (payloadSize && packetParam->addPayload) {
        dbg_printf("ICMP flow: payload size: %zu\n", payloadSize);
        AddPayload(NewNode, payload, payloadSize);
    }
    Push_Node(packetParam->NodeList, NewNode);

}  // End of ProcessICMPFlow

static inline void ProcessOtherFlow(packetParam_t *packetParam, const hotNode_t *hotNode, const coldNode_t *coldNode, void *payload,
                                    size_t payloadSize) {
    struct FlowNode lookup = {0};
    lookup.hotNode.flowKey = hotNode->flowKey;

    struct FlowNode *Node = Lookup_Node(&lookup);
    if (Node == NULL) {
        // new flow
        dbg_printf("New flow IP proto: %u. Packets: %u, Bytes: %u\n", hotNode->flowKey.proto, hotNode->packets, hotNode->bytes);

        struct FlowNode *NewNode = New_Node();
        NewNode->hotNode = *hotNode;
        NewNode->coldNode = *coldNode;
        if (packetParam->addPayload && payloadSize) {
            dbg_printf("flow: payload size: %zu\n", payloadSize);
            AddPayload(NewNode, payload, payloadSize);
        }

        struct FlowNode *existing = Insert_Node(NewNode);
        if (existing != NULL) {
            Node = existing;
            Free_Node(NewNode);
            goto update_existing;
        }

        return;
    }
update_existing:

    assert(Node->memflag == NODE_IN_USE);

    // update existing flow
    Node->hotNode.packets++;
    Node->hotNode.bytes += hotNode->bytes;
    Node->hotNode.t_last = hotNode->t_last;

    // --- process extendedFlow is ---
    if (packetParam->extendedFlow) {
        if (coldNode->minTTL < Node->coldNode.minTTL) Node->coldNode.minTTL = coldNode->minTTL;
        if (coldNode->maxTTL > Node->coldNode.maxTTL) Node->coldNode.maxTTL = coldNode->maxTTL;
    }
    dbg_printf("Existing flow IP proto: %u Packets: %u, Bytes: %u\n", hotNode->flowKey.proto, Node->hotNode.packets, Node->hotNode.bytes);

    if (packetParam->addPayload && Node->coldNode.payloadSize == 0 && payloadSize > 0) {
        dbg_printf("Existing flow: Set payload of size: %zu\n", payloadSize);
        AddPayload(Node, payload, payloadSize);
    }

    TimeWheel_Reschedule(Node, hotNode->t_last.tv_sec);

}  // End of ProcessOtherFlow

// Initialize decode context for a new packet
static inline void decode_ctx_init(decode_ctx_t *ctx, packetParam_t *packetParam, const struct pcap_pkthdr *hdr, const u_char *data,
                                   hotNode_t *hotNode, coldNode_t *coldNode, unsigned pkg_cnt) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->state = DECODE_LINK_LAYER;
    ctx->cur.ptr = (uint8_t *)data;
    ctx->cur.end = (uint8_t *)(data + hdr->caplen);
    ctx->linktype = packetParam->linktype;
    ctx->hdr = hdr;
    ctx->pkg_cnt = pkg_cnt;
    ctx->hotNode = hotNode;
    ctx->coldNode = coldNode;
    ctx->packetParam = packetParam;
}  // End of decode_ctx_init

// Cleanup decode context (free defragmented buffer)
static inline void decode_ctx_cleanup(decode_ctx_t *ctx) {
    if (ctx->defragmented) {
        free(ctx->defragmented);
        ctx->defragmented = NULL;
    }

}  // End of decode_ctx_cleanup

int ProcessPacket(packetParam_t *packetParam, const struct pcap_pkthdr *hdr, const u_char *data) {
    __builtin_prefetch(data + 64, 0, 1);
    hotNode_t hotNode = {0};
    coldNode_t coldNode = {0};

    packetParam->proc_stat.packets++;
    packetParam->proc_stat.bytes += hdr->len;
    dbg_printf("\nNext Packet: %llu, cap len:%u, len: %u\n", packetParam->proc_stat.packets, hdr->caplen, hdr->len);

    // Initialize decode context
    decode_ctx_t ctx;
    decode_ctx_init(&ctx, packetParam, hdr, data, &hotNode, &coldNode, packetParam->proc_stat.packets);

    // State machine loop
    // Max iterations handles deep encapsulation (VLAN stacking, MPLS, GRE, etc.)
    // protecting against infinite loops
    int iterations = 0;
    const int MAX_ITERATIONS = 32;
    int done = 0;
    while (!done) {
        if (++iterations > MAX_ITERATIONS) {
            LogError("Decode loop exceeded max iterations in state %d", ctx.state);
            packetParam->proc_stat.decoding_errors++;
            break;
        }
        switch (ctx.state) {
            case DECODE_LINK_LAYER:
                ctx.state = decode_link_layer(&ctx);
                break;
            case DECODE_ETHERTYPE:
                ctx.state = decode_ethertype(&ctx);
                break;
            case DECODE_IP_LAYER:
                ctx.state = decode_ip_layer(&ctx);
                break;
            case DECODE_TRANSPORT:
                /* Finalize cold node before transport processing */
                hotNode.flowKey.proto = ctx.IPproto;
                coldNode.vlanID = ctx.vlanID;
                coldNode.srcMac = ctx.srcMac;
                coldNode.dstMac = ctx.dstMac;
                coldNode.pflog = ctx.pflog;

                for (uint32_t i = 0; i < ctx.numMPLS; i++) {
                    coldNode.mpls[i] = ctx.mplsLabel[i];
                }
                ctx.state = decode_transport(&ctx);
                break;
            case DECODE_DONE:
                done = 1;
                break;
            case DECODE_SKIP:
                packetParam->proc_stat.short_snap++;
                done = 1;
                break;
            case DECODE_ERROR:
                packetParam->proc_stat.decoding_errors++;
                done = 1;
                break;
            case DECODE_UNKNOWN:
                packetParam->proc_stat.unknown++;
                done = 1;
                break;
            default:
                LogError("ProcessPacket: unexpected state: %d", ctx.state);
                done = 1;
                break;
        }
    }

    /* Cleanup */
    decode_ctx_cleanup(&ctx);

    /* Periodic cache maintenance */
    if ((hdr->ts.tv_sec - lastRun) > 1) {
        CacheCheck(packetParam->NodeList, hdr->ts.tv_sec);
        lastRun = hdr->ts.tv_sec;
    }

    return 1;
}  // End of ProcessPacket
