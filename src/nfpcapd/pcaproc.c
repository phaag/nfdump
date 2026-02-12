/*
 *  Copyright (c) 2014-2025, Peter Haag
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

// Standardized Link-Type Wire Values - defined them locally as
// they may differ
#define LT_NULL 0
#define LT_LOOP 108
#define LT_RAW 101
#define LT_BSD_LOOP 12  // Often used by OpenBSD
#define LT_OPENBSD_RAW 14
#define LT_IEEE802_11_RADIO 127

typedef struct cursor_s {
    uint8_t *ptr;
    uint8_t *end;
} cursor_t;

typedef struct gre_flags_s {
    int C : 1;
    int R : 1;
    int K : 1;
    int S : 1;
    int s : 1;
    int Recur : 3;
    int A : 1;
    int flag : 4;
    int version : 3;
} gre_flags_t;

typedef struct gre_hdr_s {
    uint16_t flags;
    uint16_t type;
} gre_hdr_t;

typedef struct vlan_hdr_s {
    uint16_t vlan_id;
    uint16_t type;
} vlan_hdr_t;

// remember the last SlotSize packets with len and hash
// for duplicate check
#define SlotSize 8
static struct {
    uint32_t len;
    uint64_t hash;
} lastPacketStat[SlotSize] = {0};
static uint32_t packetSlot = 0;

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

#include "metrohash.c"

static inline ptrdiff_t cursor_size(cursor_t *c) {
    //
    return (ptrdiff_t)c->end - (ptrdiff_t)c->ptr;
}  // End of cursor_size

static inline int cursor_advance(cursor_t *c, size_t len) {
    if (c->ptr + len > c->end) return 0;
    c->ptr += len;
    return 1;
}  // End of cursor_advance

static inline int cursor_read(cursor_t *c, void *dst, size_t len) {
    if (c->ptr + len > c->end) return 0;
    memcpy(dst, c->ptr, len);
    c->ptr += len;

    return 1;
}  // End of cursor_read

static inline int cursor_get(cursor_t *c, void *dst, size_t len) {
    if (c->ptr + len > c->end) return 0;
    memcpy(dst, c->ptr, len);

    return 1;
}  // End of cursor_get

static int is_duplicate(const uint8_t *data_ptr, const uint32_t len) {
    uint64_t hash = metrohash64_1(data_ptr, len, 0);

    for (int i = 0; i < SlotSize; i++) {
        if (lastPacketStat[i].len == len && lastPacketStat[i].hash == hash) return 1;
    }

    // not found - add to next slot round robin
    lastPacketStat[packetSlot].len = len;
    lastPacketStat[packetSlot].hash = hash;
    packetSlot = (packetSlot + 1) & (SlotSize - 1);
    return 0;
}  // End of is_duplicate

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

int ProcessPacket(packetParam_t *packetParam, const struct pcap_pkthdr *hdr, const u_char *data) {
    hotNode_t hotNode = {0};
    coldNode_t coldNode = {0};
    char s1[64];
    char s2[64];
    static unsigned pkg_cnt = 0;

    pkg_cnt++;
    packetParam->proc_stat.packets++;
    dbg_printf("\nNext Packet: %u, cap len:%u, len: %u\n", pkg_cnt, hdr->caplen, hdr->len);

    // snaplen is minimum 54 bytes
    cursor_t cur = {(uint8_t *)data, (uint8_t *)(data + hdr->caplen)};

    void *defragmented = NULL;
    void *payload = NULL;
    ssize_t payloadSize = 0;
    uint32_t vlanID = 0;
    uint64_t srcMac = 0;
    uint64_t dstMac = 0;
    uint32_t numMPLS = 0;
#define MPLSMAX 10
    uint32_t mplsLabel[MPLSMAX];
    pflog_hdr_t pflog = {0};

    // link layer processing
    uint16_t protocol = 0;
    uint32_t linktype = packetParam->linktype;
    int redoLink = 0;
REDO_LINK:
    switch (linktype) {
        case LT_NULL: {
            // DLT_NULL uses HOST byte order of the capturing system.
            // Heuristic: If the high 16 bits are non-zero, it's likely swapped.
            uint32_t header;
            if (!cursor_read(&cur, &header, 4)) {
                LogInfo("Packet: %u: LT_NULL: not enough data", pkg_cnt);
                packetParam->proc_stat.skipped++;
                goto END_FUNC;
            }

            // Corrected Precedence and Manual Swap
            if ((header & 0xFFFF0000) != 0) {
                header = ((header >> 24) & 0xff) | ((header << 8) & 0xff0000) | ((header >> 8) & 0xff00) | ((header << 24) & 0xff000000);
            }

            if (header == 2) {
                protocol = 0x0800;  // IPv4 EtherType
                dbg_printf("Linktype: LT_NULL - IPv4\n");
            } else if (header == 24 || header == 28 || header == 30) {
                protocol = 0x86DD;  // IPv6 EtherType
                dbg_printf("Linktype: LT_NULL - IPv6\n");
            }

        } break;
        case LT_LOOP:
        case LT_BSD_LOOP: {
            // Lookahead check for mislabeled RAW data
            if (linktype == LT_BSD_LOOP && cur.ptr < cur.end) {
                uint8_t first_byte = cur.ptr[0];
                if (first_byte == 0x45 || (first_byte & 0xf0) == 0x60) {
                    protocol = (first_byte == 0x45) ? 0x0800 : 0x86DD;
                    dbg_printf("Linktype: LT_BSD_LOOP (RAW fallback) - %s\n", protocol == 0x0800 ? "IPv4" : "IPv6");
                    break;  // Payload starts here, no 4-byte header to skip
                }
            }

            uint32_t header;
            if (!cursor_read(&cur, &header, 4)) {
                LogInfo("Packet: %u: LT_NULL: not enough data", pkg_cnt);
                packetParam->proc_stat.skipped++;
                goto END_FUNC;
            }
            header = ntohl(header);  // DLT_LOOP is always Big Endian

            // Map PF_ values to EtherTypes
            if (header == 2) {
                protocol = 0x0800;
            } else if (header == 24 || header == 28 || header == 30) {
                protocol = 0x86DD;
            }
            dbg_printf("Linktype: %u - Protocol: 0x%04X\n", linktype, protocol);
        } break;
        case LT_RAW:
        case LT_OPENBSD_RAW: {
            // Raw IP - no link layer header, starts directly with IP
            if (cursor_size(&cur) < 1) {
                LogInfo("Packet: %u: LT_RAW: not enough data", pkg_cnt);
                packetParam->proc_stat.skipped++;
                goto END_FUNC;
            }
            uint8_t version = (cur.ptr[0] >> 4);
            if (version == 4) {
                protocol = 0x0800;  // IPv4
            } else if (version == 6) {
                protocol = 0x86DD;  // IPv6
            } else {
                LogInfo("Packet: %u: LT_RAW: unsupported IP version: %u", pkg_cnt, version);
                packetParam->proc_stat.skipped++;
                goto END_FUNC;
            }
            dbg_printf("Linktype: LT_RAW - %s\n", protocol == 0x0800 ? "IPv4" : "IPv6");
        } break;
        case DLT_EN10MB:
            if (cursor_size(&cur) < 14) {
                LogInfo("Packet: %u: DLT_EN10MB: not enough data", pkg_cnt);
                packetParam->proc_stat.skipped++;
                goto END_FUNC;
            }
            cursor_read(&cur, &dstMac, 6);
            cursor_read(&cur, &srcMac, 6);
            cursor_read(&cur, &protocol, 2);
            protocol = ntohs(protocol);
            int IEEE802 = protocol <= 1500;
            if (IEEE802) {
                packetParam->proc_stat.skipped++;
                return 1;
            }
            dbg_printf("Linktype: DLT_EN10MB\n");
            break;
        case DLT_PPP:
            protocol = 0x800;
            if (!cursor_advance(&cur, 2)) {
                LogInfo("Packet: %u: DLT_PPP: not enough data", pkg_cnt);
                packetParam->proc_stat.skipped++;
                goto END_FUNC;
            }
            dbg_printf("Linktype: DLT_PPP\n");
            break;
        case DLT_PPP_SERIAL:
            protocol = 0x800;
            if (!cursor_advance(&cur, 2)) {
                LogInfo("Packet: %u: DLT_PPP_SERIAL: not enough data", pkg_cnt);
                packetParam->proc_stat.skipped++;
                goto END_FUNC;
            }
            dbg_printf("Linktype: DLT_PPP_SERIAL\n");
            break;
        case DLT_LINUX_SLL:
            if (!cursor_advance(&cur, 14) || !cursor_read(&cur, &protocol, 2)) {
                LogInfo("Packet: %u: DLT_LINUX_SLL: not enough data", pkg_cnt);
                packetParam->proc_stat.skipped++;
                goto END_FUNC;
            }
            protocol = ntohs(protocol);
            dbg_printf("Linktype: DLT_LINUX_SSL\n");
            break;
        case DLT_IEEE802_11:
            protocol = 0x800;
            if (!cursor_advance(&cur, 22)) {
                LogInfo("Packet: %u: DLT_IEEE802_11: not enough data", pkg_cnt);
                packetParam->proc_stat.skipped++;
                goto END_FUNC;
            }
            dbg_printf("Linktype: DLT_IEEE802_11\n");
            break;
        case DLT_NFLOG: {
            nflog_hdr_t nflog_hdr;
            if (!cursor_read(&cur, &nflog_hdr, sizeof(nflog_hdr_t))) {
                LogInfo("Packet: %u: DLT_NFLOG: not enough data", pkg_cnt);
                return 1;
            }

            if (nflog_hdr.nflog_version != 0) {
                LogInfo("Packet: %u: unsupported NFLOG version: %d", pkg_cnt, nflog_hdr.nflog_version);
                return 1;
            }

            // Set protocol based on family immediately
            if (nflog_hdr.nflog_family == 2) {
                protocol = 0x0800;  // IPv4
                dbg_printf("Linktype DLT_NFLOG: IPv4, rid: %u\n", ntohs(nflog_hdr.nflog_rid));
            } else if (nflog_hdr.nflog_family == 10) {
                protocol = 0x86DD;  // IPv6
                dbg_printf("Linktype DLT_NFLOG: IPv6, rid: %u\n", ntohs(nflog_hdr.nflog_rid));
            } else {
                dbg_printf("Linktype DLT_NFLOG: unknown, rid: %u\n", ntohs(nflog_hdr.nflog_rid));
            }

            // TLVs following
            nflog_tlv_t tlv;
            while (cursor_read(&cur, &tlv, sizeof(nflog_tlv_t))) {
                dbg_printf("NFLOG: tlv type: %u, length: %u\n", tlv.tlv_type, tlv.tlv_length);

                // Validation: TLV length must at least include itself
                if (tlv.tlv_length < sizeof(nflog_tlv_t)) {
                    LogInfo("Packet: %u: NFLOG: Malformed TLV length", pkg_cnt);
                    return 1;
                }

                if (tlv.tlv_type == NFULA_PAYLOAD) {
                    // Payload found! Cursor is now positioned at start of IP header
                    // because cursor_read moved us past the TLV header.
                    dbg_printf("Linktype DLT_NFLOG: %s, payload found\n", protocol == 0x0800 ? "IPv4" : "IPv6");
                    break;
                }

                // skip the current TLV including optional padding
                size_t aligned_size = (tlv.tlv_length + 3) & ~3;
                // 2. Subtract the 4 bytes we already read via cursor_read
                size_t remaining_to_skip = aligned_size - sizeof(nflog_tlv_t);

                if (!cursor_advance(&cur, remaining_to_skip)) {
                    LogInfo("Packet: %u: NFLOG: tlv skip error", pkg_cnt);
                    return 1;
                }
            }

        } break;
        case DLT_PFLOG: {
            if (!cursor_read(&cur, &pflog, sizeof(pflog_hdr_t))) {
                LogInfo("Packet: %u: PFLOG: not enough data", pkg_cnt);
                return 1;
            }
            // pflog.af is in host byte order
            if (pflog.af == 2)
                protocol = 0x0800;
            else
                protocol = 0x86DD;

            dbg_printf("Linktype: DLT_PFLOG - %s\n", protocol == 0x0800 ? "IPv4" : "IPv6");

        } break;
        case LT_IEEE802_11_RADIO: {
            uint16_t it_len;

            // The Radiotap header length is at offset 2 (2nd and 3rd bytes)
            // Header structure: version (1), pad (1), length (2)
            if (cur.ptr + 4 > cur.end) {
                LogInfo("Packet: %u: Radiotap: header too short", pkg_cnt);
                return 1;
            }

            // Radiotap length is always Little Endian
            // Use pointer arithmetic to get the 16-bit length at offset 2
            it_len = cur.ptr[2] | (cur.ptr[3] << 8);

            dbg_printf("Linktype: IEEE802_11_RADIO (Radiotap len: %u)\n", it_len);

            if (!cursor_advance(&cur, it_len)) {
                LogInfo("Packet: %u: Radiotap: skip error", pkg_cnt);
                return 1;
            }

            // Now at the start of the 802.11 MAC header.
            // Note: 802.11 requires complex parsing to find the payload.
            // For a simple 'assumed' IP payload over WiFi:
            protocol = 0x0800;

            cursor_advance(&cur, 32);  // Skip common MAC (24) + LLC/SNAP (8)
        } break;
        default:
            LogInfo("Packet: %u: unsupported link type: 0x%x, packet: %u", pkg_cnt, linktype);
            return 1;
    }

REDO_LINK_PROTO:

    dbg_printf("Next protocol: 0x%x\n", protocol);
    int IEEE802 = protocol <= 1500;
    if (IEEE802) {
        packetParam->proc_stat.skipped++;
        return 1;
    }
    switch (protocol) {
        case ETHERTYPE_IP:    // IPv4
        case ETHERTYPE_IPV6:  // IPv6
            break;
        case ETHERTYPE_VLAN: {  // VLAN
            do {
                vlan_hdr_t vlan_hdr;
                if (!cursor_read(&cur, &vlan_hdr, sizeof(vlan_hdr_t))) {
                    LogError("Length error decoding vlan");
                    return 1;
                }
                dbg_printf("VLAN ID: %u, type: 0x%x\n", ntohs(vlan_hdr.vlan_id), ntohs(vlan_hdr.type));
                protocol = ntohs(vlan_hdr.type);
                vlanID = ntohs(vlan_hdr.vlan_id) & 0xFFF;
            } while (protocol == 0x8100 || protocol == 0x88A8);

            // redo protocol evaluation
            goto REDO_LINK_PROTO;
        } break;
        case ETHERTYPE_MPLS: {  // MPLS
            // unwrap MPLS label stack

            numMPLS = 0;
            uint32_t label;
            do {
                if (!cursor_read(&cur, &label, sizeof(uint32_t))) {
                    LogError("Length error decoding mpls stack");
                    return 1;
                }
                if (numMPLS < MPLSMAX) {
                    mplsLabel[numMPLS++] = label;
                    dbg_printf("MPLS label %u: %x\n", numMPLS, ntohl(label) >> 8);
                }
            } while ((ntohl(label) & 0x100) == 0);  // check for bottom of stack

            uint8_t nxHdr = cur.ptr[0];
            if ((nxHdr >> 4) == 4)
                protocol = ETHERTYPE_IP;  // IPv4
            else if ((nxHdr >> 4) == 6)
                protocol = ETHERTYPE_IPV6;  // IPv6
            else {
                LogInfo("Unsupported next protocol in mpls: 0x%x\n", nxHdr >> 4);
                packetParam->proc_stat.skipped++;
                goto END_FUNC;
            }
            // redo protocol evaluation
            goto REDO_LINK_PROTO;
        } break;
        case ETHERTYPE_TRANSETHER: {  // GRE ethernet bridge
            dbg_printf("  GRE tap tunnel\n");
            uint16_t nextProtocol = 0;
            if (!cursor_read(&cur, &dstMac, 6) || !cursor_read(&cur, &srcMac, 6) || !cursor_read(&cur, &nextProtocol, sizeof(uint16_t))) {
                LogError("Length error decoding GRE tap tunnel");
                goto END_FUNC;
            }

            protocol = ntohs(nextProtocol);
            goto REDO_LINK_PROTO;
        } break;
        case ETHERTYPE_PPPOE: {
            uint8_t VersionType = 0;
            uint8_t Code = 0;
            uint16_t pppProto = 0;

            if (!cursor_read(&cur, &VersionType, 1) || !cursor_read(&cur, &Code, 1)) {
                LogError("Length error decoding ethertype PPPoE");
                goto END_FUNC;
            }
            cursor_advance(&cur, 4);
            if (!cursor_read(&cur, &pppProto, sizeof(uint16_t))) {
                LogError("Length error decoding ethertype PPPoE");
                goto END_FUNC;
            }

            pppProto = ntohs(pppProto);

            // uint16_t SessionID	= ntohs(*((uint16_t *)(dataptr21)));
            if (VersionType != 0x11) {
                LogError("Unsupported ppp Version/Type: 0x%x", VersionType);
                packetParam->proc_stat.skipped++;
                goto END_FUNC;
            }
            if (Code != 0) {
                // skip packets other than session data
                packetParam->proc_stat.skipped++;
                goto END_FUNC;
            }
            if (pppProto != 0x0021 /* v4 */ && pppProto != 0x0057 /* v6 */) {
                LogError("Unsupported ppp proto: 0x%x", pppProto);
                packetParam->proc_stat.skipped++;
                goto END_FUNC;
            }
            protocol = (pppProto == 0x0021) ? ETHERTYPE_IP : ETHERTYPE_IPV6;
            goto REDO_LINK_PROTO;

        } break;
        case ETHERTYPE_PPPOEDISC: {
            // skip PPPoE discovery messages
            packetParam->proc_stat.skipped++;
            goto END_FUNC;
        } break;
        case ETHERTYPE_ARP:          // skip ARP
        case ETHERTYPE_LOOPBACK:     // skip Loopback
        case ETHERTYPE_LLDP:         // skip LLDP
        case ETHERTYPE_FLOWCONTROL:  // skip flow control
            goto END_FUNC;
            break;
        default:
            // int	IEEE802 = protocol <= 1500;
            LogError("Unsupported link protocol: 0x%x, packet: %u", protocol, pkg_cnt);
            packetParam->proc_stat.skipped++;
            goto END_FUNC;
    }

    dbg_printf("Link layer processed: %td bytes, remaining: %td\n", (ptrdiff_t)(cur.ptr - (uint8_t *)data), cur.end - cur.ptr);

    // link layer, vpn and mpls header removed

    uint16_t IPproto = 0;

// IP layer processing
REDO_IPPROTO:
    // IP decoding
    if (defragmented) {
        // Nested IP-in-IP where outer was fragmented.
        // Free outer reassembly buffer before processing inner IP.
        // This loses the outer packet's exact byte count but allows
        // processing the inner (which is what we want for flow tracking).
        free(defragmented);
        defragmented = NULL;
        dbg_printf("Freed outer defragmented buffer for nested IP processing\n");
    }

    uint8_t ipVersion;
    if (!cursor_get(&cur, &ipVersion, sizeof(uint8_t))) {
        LogError("Length error decoding IP version");
        goto END_FUNC;
    }
    ipVersion = ipVersion >> 4;

    ptrdiff_t ipPayloadLength = 0;
    uint8_t *ipPayloadEnd = NULL;
    if (ipVersion == 6) {
        void *ip = cur.ptr;
        struct ip6_hdr ip6;
        if (!cursor_read(&cur, &ip6, sizeof(struct ip6_hdr))) {
            packetParam->proc_stat.short_snap++;
            LogVerbose("Length error decoding IPv6 header");
            goto END_FUNC;
        }

        // IPv6 duplicate check
        // duplicate check starts from the IP header over the rest of the packet
        // vlan, mpls and layer 1 headers are ignored
        if (unlikely(packetParam->doDedup && redoLink == 0)) {
            // check for de-dup
            uint32_t hopLimit = ip6.ip6_ctlun.ip6_un1.ip6_un1_hlim;
            ip6.ip6_ctlun.ip6_un1.ip6_un1_hlim = 0;
            uint16_t len = ntohs(ip6.ip6_ctlun.ip6_un1.ip6_un1_plen);
            if (is_duplicate((const uint8_t *)ip, len + 40)) {
                packetParam->proc_stat.duplicates++;
                return 0;
            }
            ip6.ip6_ctlun.ip6_un1.ip6_un1_hlim = hopLimit;
            // prevent recursive dedub checks with IP in IP packets
            redoLink++;
        }

        uint16_t remaining_plen = ntohs(ip6.ip6_plen);

        // ipv6 Extension headers
        IPproto = ip6.ip6_nxt;
        while (IPproto == IPPROTO_HOPOPTS || IPproto == IPPROTO_ROUTING || IPproto == IPPROTO_DSTOPTS || IPproto == IPPROTO_AH) {
            struct {
                uint8_t nxt;
                uint8_t len;
            } ext;
            if (!cursor_read(&cur, &ext, 2)) goto END_FUNC;
            size_t skip = (ext.len + 1) << 3;  // Length in 8-byte units
            if (skip > remaining_plen) goto END_FUNC;
            remaining_plen -= skip;
            if (!cursor_advance(&cur, skip - 2)) goto END_FUNC;
            IPproto = ext.nxt;
        }

        uint8_t fragment_flag = 0;
        if (unlikely(IPproto == IPPROTO_FRAGMENT)) {
            struct ip6_frag *ip6_frag = (struct ip6_frag *)cur.ptr;
            struct ip6_frag ip6_frag_hdr;
            if (!cursor_get(&cur, &ip6_frag_hdr, sizeof(struct ip6_frag))) goto END_FUNC;

            IPproto = ip6_frag_hdr.ip6f_nxt;
            uint32_t reassembledLength = 0;
            void *payload = ProcessIP6Fragment(ip, ip6_frag, cur.end, &reassembledLength);
            if (payload == NULL) {
                // not yet complete
                dbg_printf("IPv6 de-fragmentation not yet completed\n");
                goto END_FUNC;
            }
            defragmented = payload;
            ipPayloadLength = reassembledLength;
            cur.ptr = payload;
            cur.end = cur.ptr + ipPayloadLength;
            fragment_flag = flagMF;
        } else {
            ipPayloadLength = remaining_plen;
        }

        ipPayloadEnd = cur.ptr + ipPayloadLength;

        // Sanity check: ipPayloadEnd must not exceed captured data
        if (ipPayloadLength < 0 || ipPayloadEnd > cur.end) {
            LogVerbose("IPv6 payload length exceeds captured data");
            packetParam->proc_stat.short_snap++;
            goto END_FUNC;
        }

        dbg_printf("Packet IPv6, SRC %s, DST %s, padding %zu\n", inet_ntop(AF_INET6, &ip6.ip6_src, s1, sizeof(s1)),
                   inet_ntop(AF_INET6, &ip6.ip6_dst, s2, sizeof(s2)), (ptrdiff_t)(cur.end - ipPayloadEnd));

        hotNode.flowKey.version = AF_INET6;
        hotNode.t_first.tv_sec = hdr->ts.tv_sec;
        hotNode.t_last.tv_sec = hdr->ts.tv_sec;
        hotNode.t_first.tv_usec = hdr->ts.tv_usec;
        hotNode.t_last.tv_usec = hdr->ts.tv_usec;
        // Use ipPayloadLength which is correct after defragmentation
        hotNode.bytes = ipPayloadLength + sizeof(struct ip6_hdr);
        hotNode.packets = 1;

        uint8_t ttl = ip6.ip6_ctlun.ip6_un1.ip6_un1_hlim;
        coldNode.minTTL = ttl;
        coldNode.maxTTL = ttl;
        coldNode.fragmentFlags = fragment_flag;

        memcpy(hotNode.flowKey.src_addr.bytes, ip6.ip6_src.s6_addr, 16);
        memcpy(hotNode.flowKey.dst_addr.bytes, ip6.ip6_dst.s6_addr, 16);

    } else if (ipVersion == 4) {
        void *ip = cur.ptr;
        struct ip ip4;
        if (!cursor_get(&cur, &ip4, sizeof(struct ip))) {
            packetParam->proc_stat.short_snap++;
            LogVerbose("Length error decoding IPv4 header");
            goto END_FUNC;
        }

        int size_ip4 = (ip4.ip_hl << 2);
        if (size_ip4 < (int)sizeof(struct ip)) {
            // Malformed: Header length cannot be less than 20
            LogVerbose("Length error decoding IPv4 header - malformed length");
            goto END_FUNC;
        }

        if (!cursor_advance(&cur, size_ip4)) {
            packetParam->proc_stat.short_snap++;
            LogVerbose("Length error decoding IPv4 header");
            goto END_FUNC;
        }
        ipPayloadLength = ntohs(ip4.ip_len) - size_ip4;
        ipPayloadEnd = cur.ptr + ipPayloadLength;

        // IPv4 duplicate check
        // duplicate check starts from the IP header over the rest of the packet
        // vlan, mpls and layer 1 headers are ignored
        uint8_t fragment_flag = 0;
        if (unlikely(packetParam->doDedup && redoLink == 0)) {
            struct ip *iph = (struct ip *)ip;
            uint8_t old_ttl = iph->ip_ttl;
            uint16_t old_sum = iph->ip_sum;
            // check for de-dup
            iph->ip_ttl = 0;
            iph->ip_sum = 0;
            if (is_duplicate((const uint8_t *)ip, ntohs(iph->ip_len))) {
                packetParam->proc_stat.duplicates++;
                return 0;
            }
            iph->ip_ttl = old_ttl;  // RESTORE
            iph->ip_sum = old_sum;  // RESTORE
            // prevent recursive dedub checks with IP in IP packets
            redoLink++;
        }

        IPproto = ip4.ip_p;
        dbg_printf("Packet IPv4 SRC %s, DST %s, padding %zu\n", inet_ntop(AF_INET, &ip4.ip_src, s1, sizeof(s1)),
                   inet_ntop(AF_INET, &ip4.ip_dst, s2, sizeof(s2)), (ptrdiff_t)(cur.end - ipPayloadEnd));

        // IPv4 defragmentation
        uint16_t ip_off = ntohs(ip4.ip_off);
        uint32_t frag_offset = (ip_off & IP_OFFMASK) << 3U;
        if ((ip_off & IP_MF) || frag_offset) {
            // fragmented packet
            uint32_t reassembledLength = 0;
            void *payload = ProcessIP4Fragment(ip, cur.end, &reassembledLength);
            if (payload == NULL) {
                // not yet complete
                dbg_printf("IPv4 de-fragmentation not yet completed\n");
                goto END_FUNC;
            }

            // packet defragmented - set payload to defragmented data
            defragmented = payload;
            ipPayloadLength = reassembledLength;
            cur.ptr = payload;
            cur.end = cur.ptr + ipPayloadLength;
            fragment_flag = flagMF;
        } else {
            ipPayloadLength = ntohs(ip4.ip_len) - size_ip4;
        }
        ipPayloadEnd = cur.ptr + ipPayloadLength;

        // Sanity check: ipPayloadEnd must not exceed captured data
        if (ipPayloadLength < 0 || ipPayloadEnd > cur.end) {
            LogVerbose("IPv4 payload length exceeds captured data");
            packetParam->proc_stat.short_snap++;
            goto END_FUNC;
        }

        hotNode.flowKey.version = AF_INET;
        hotNode.t_first.tv_sec = hdr->ts.tv_sec;
        hotNode.t_last.tv_sec = hdr->ts.tv_sec;
        hotNode.t_first.tv_usec = hdr->ts.tv_usec;
        hotNode.t_last.tv_usec = hdr->ts.tv_usec;
        hotNode.packets = 1;
        // Use ipPayloadLength + header size, correct after defragmentation
        hotNode.bytes = ipPayloadLength + size_ip4;

        static const uint8_t prefix[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};
        memcpy(hotNode.flowKey.src_addr.bytes, prefix, 12);
        memcpy(hotNode.flowKey.dst_addr.bytes, prefix, 12);
        memcpy(hotNode.flowKey.src_addr.bytes + 12, &ip4.ip_src.s_addr, 4);
        memcpy(hotNode.flowKey.dst_addr.bytes + 12, &ip4.ip_dst.s_addr, 4);

        coldNode.minTTL = ip4.ip_ttl;
        coldNode.maxTTL = ip4.ip_ttl;
        coldNode.fragmentFlags = fragment_flag;
        if (ip_off & IP_DF) coldNode.fragmentFlags |= flagDF;

    } else {
        dbg_printf("ProcessPacket() Unsupported protocol version: %i\n", ipVersion);
        packetParam->proc_stat.unknown++;
        goto END_FUNC;
    }

    // fill ipv4/ipv6 node with extracted data
    hotNode.flowKey.proto = IPproto;
    coldNode.vlanID = vlanID;
    coldNode.srcMac = srcMac;
    coldNode.dstMac = dstMac;
    if (pflog.length) {
        coldNode.pflog = malloc(sizeof(pflog));
        memcpy(coldNode.pflog, &pflog, sizeof(pflog));
    }

    // bytes = number of bytes on wire - data link data
    dbg_printf("Payload: %td bytes, Full packet: %u bytes\n", cur.end - cur.ptr, hotNode.bytes);

    if (numMPLS) {
        for (int i = 0; i < (int)numMPLS; i++) {
            coldNode.mpls[i] = mplsLabel[i];
        }
    }

    if (ipPayloadEnd < cur.ptr || ipPayloadEnd > cur.end) {
        LogError("ProcessPacket() payload data length error line: %u", __LINE__);
        goto END_FUNC;
    }

    // transport protocol processing
    switch (IPproto) {
        case IPPROTO_UDP: {
            struct udphdr udp;
            if (!cursor_read(&cur, &udp, sizeof(struct udphdr))) {
                packetParam->proc_stat.short_snap++;
                LogVerbose("Length error decoding UDP header");
                goto END_FUNC;
            }

            uint16_t UDPlen = ntohs(udp.uh_ulen);
            if (UDPlen < 8) {
                LogError("UDP payload length error: %u bytes < 8", UDPlen);
                break;
            }

            dbg_printf("  UDP: size: %u, SRC: %i, DST: %i\n", UDPlen, ntohs(udp.uh_sport), ntohs(udp.uh_dport));

            hotNode.flags = 0;
            hotNode.flowKey.src_port = ntohs(udp.uh_sport);
            hotNode.flowKey.dst_port = ntohs(udp.uh_dport);

            payloadSize = (ptrdiff_t)(ipPayloadEnd - cur.ptr);
            if (payloadSize > 0) payload = (void *)cur.ptr;
            ProcessUDPFlow(packetParam, &hotNode, &coldNode, payload, (size_t)payloadSize);

        } break;
        case IPPROTO_TCP: {
            struct tcphdr tcp;
            if (!cursor_get(&cur, &tcp, sizeof(struct tcphdr))) {
                packetParam->proc_stat.short_snap++;
                LogVerbose("Length error decoding tcp header");
                goto END_FUNC;
            }

            // strip tcp headers
            uint32_t size_tcp = tcp.th_off << 2;
            if (size_tcp < sizeof(struct tcphdr)) {
                LogVerbose("Length error decoding tcp header - malformed header length");
                goto END_FUNC;
            }

            if (!cursor_advance(&cur, size_tcp)) {
                packetParam->proc_stat.short_snap++;
                LogVerbose("Length error decoding tcp header");
                goto END_FUNC;
            }

            payloadSize = (ptrdiff_t)(ipPayloadEnd - cur.ptr);
            if (payloadSize > 0) payload = (void *)cur.ptr;

#ifdef DEVEL
            printf("  Size TCP header: %u, size TCP payload: %zu ", size_tcp, payloadSize);
            printf("  src port %i, dst port %i, flags %i : \n", ntohs(tcp.th_sport), ntohs(tcp.th_dport), tcp.th_flags);
            if (tcp.th_flags & TH_SYN) printf("SYN ");
            if (tcp.th_flags & TH_ACK) printf("ACK ");
            if (tcp.th_flags & TH_URG) printf("URG ");
            if (tcp.th_flags & TH_PUSH) printf("PUSH ");
            if (tcp.th_flags & TH_FIN) printf("FIN ");
            if (tcp.th_flags & TH_RST) printf("RST ");
            printf("\n");
#endif
            hotNode.flags = tcp.th_flags;
            hotNode.flowKey.src_port = ntohs(tcp.th_sport);
            hotNode.flowKey.dst_port = ntohs(tcp.th_dport);
            hotNode.flush = ((tcp.th_flags & (TH_FIN | TH_RST)) != 0);
            ProcessTCPFlow(packetParam, &hotNode, &coldNode, payload, payloadSize);

        } break;
        case IPPROTO_ICMP: {
            // Only read the 8-byte ICMP header, not full struct icmp (which is 28 bytes on BSD)
            uint8_t icmp_hdr[8];
            if (!cursor_read(&cur, &icmp_hdr, 8)) {
                packetParam->proc_stat.short_snap++;
                LogVerbose("Length error decoding icmp header");
                goto END_FUNC;
            }
            uint8_t icmp_type = icmp_hdr[0];
            uint8_t icmp_code = icmp_hdr[1];

            payloadSize = (ptrdiff_t)(ipPayloadEnd - cur.ptr);
            if (payloadSize > 0) payload = (void *)cur.ptr;

            hotNode.flowKey.dst_port = (icmp_type << 8) + icmp_code;
            dbg_printf("  IPv%d ICMP: type: %u, code: %u\n", ipVersion, icmp_type, icmp_code);
            ProcessICMPFlow(packetParam, &hotNode, &coldNode, payload, payloadSize);
        } break;
        case IPPROTO_ICMPV6: {
            struct icmp6_hdr icmp6;
            if (!cursor_read(&cur, &icmp6, sizeof(struct icmp6_hdr))) {
                packetParam->proc_stat.short_snap++;
                LogVerbose("Length error decoding icmp6 header");
                goto END_FUNC;
            }

            payloadSize = (ptrdiff_t)(ipPayloadEnd - cur.ptr);
            if (payloadSize > 0) payload = (void *)cur.ptr;

            hotNode.flowKey.dst_port = (icmp6.icmp6_type << 8) + icmp6.icmp6_code;
            dbg_printf("  IPv%d ICMP: type: %u, code: %u\n", ipVersion, icmp6.icmp6_type, icmp6.icmp6_code);
            ProcessICMPFlow(packetParam, &hotNode, &coldNode, payload, payloadSize);
        } break;
        case IPPROTO_IPV6: {
            uint32_t size_inner_ip = sizeof(struct ip6_hdr);

            if ((cur.ptr + size_inner_ip) > cur.end) {
                dbg_printf("  IPIPv6 tunnel Short packet: %u, Check line: %u\n", hdr->caplen, __LINE__);
                packetParam->proc_stat.short_snap++;
                goto END_FUNC;
            }

            // move IP to tun IP
            coldNode.tun_src_addr = hotNode.flowKey.src_addr;
            coldNode.tun_dst_addr = hotNode.flowKey.dst_addr;
            coldNode.tun_proto = IPPROTO_IPV6;
            coldNode.tun_ip_version = hotNode.flowKey.version;

            dbg_printf("  IPIPv6 tunnel - inner IPv6:\n");

            // redo proto evaluation
            goto REDO_IPPROTO;
        } break;
        case IPPROTO_IPIP: {
            struct ip *inner_ip = (struct ip *)cur.ptr;
            uint32_t size_inner_ip = (inner_ip->ip_hl << 2);

            if ((cur.ptr + size_inner_ip) > cur.end) {
                dbg_printf("  IPIP tunnel Short packet: %u, Check line: %u\n", hdr->caplen, __LINE__);
                packetParam->proc_stat.short_snap++;
                goto END_FUNC;
            }

            // move IP to tun IP
            coldNode.tun_src_addr = hotNode.flowKey.src_addr;
            coldNode.tun_dst_addr = hotNode.flowKey.dst_addr;
            coldNode.tun_proto = IPPROTO_IPIP;
            coldNode.tun_ip_version = hotNode.flowKey.version;

            dbg_printf("  IPIP tunnel - inner IP:\n");

            // redo proto evaluation
            goto REDO_IPPROTO;

        } break;
        case IPPROTO_GRE:
        case 0x6558: {
            gre_hdr_t gre;
            if (!cursor_read(&cur, &gre, sizeof(gre_hdr_t))) {
                packetParam->proc_stat.short_snap++;
                LogVerbose("Length error decoding GRE header");
                goto END_FUNC;
            }

            uint16_t gre_flags = ntohs(gre.flags);
            uint16_t gre_proto = ntohs(gre.type);

            // 1. Handle GRE Optional Fields (Checksum, Key, Sequence)
            // Order matters: Checksum (4) -> Key (4) -> Sequence (4)
            if (gre_flags & 0x8000) cursor_advance(&cur, 4);  // Checksum + Reserved
            if (gre_flags & 0x2000) cursor_advance(&cur, 4);  // Key
            if (gre_flags & 0x1000) cursor_advance(&cur, 4);  // Sequence Number

            dbg_printf("  GRE proto encapsulation: type: 0x%x\n", gre_proto);

            // 2. Handle Routing/Version (PPTP/VPN)
            uint8_t version = gre_flags & 0x0007;
            if (version == 1) {
                // PPTP / Enhanced GRE
                cursor_advance(&cur, 2);
                uint16_t callID;
                cursor_read(&cur, &callID, sizeof(uint16_t));
                hotNode.flowKey.dst_port = ntohs(callID);
                if (gre_proto != 0x880b) {
                    LogError("Unexpected protocol in LLTP GRE header: 0x%x", gre_proto);
                    packetParam->proc_stat.short_snap++;
                    goto END_FUNC;
                }

                // pptp - vpn
                // 2 bytes key paload length, 2 byte call ID
                if (gre_flags & 0x0080) cursor_advance(&cur, 4);  // Ack Number

                payloadSize = (ptrdiff_t)(ipPayloadEnd - cur.ptr);
                if (payloadSize > 0) payload = (void *)cur.ptr;

                ProcessOtherFlow(packetParam, &hotNode, &coldNode, payload, payloadSize);
                goto END_FUNC;
            }

            // 3. Handle ERSPAN (Encapsulated Remote SPAN)
            if (gre_proto == PROTO_ERSPAN) {  // ERSPAN Type II
                cursor_advance(&cur, 8);      // Skip 8-byte ERSPAN Header
                linktype = DLT_EN10MB;
                goto REDO_LINK;                // Start over as Ethernet
            } else if (gre_proto == 0x22EB) {  // ERSPAN Type III
                cursor_advance(&cur, 20);      // Skip 20-byte ERSPAN Header
                linktype = DLT_EN10MB;
                goto REDO_LINK;
            }

            // 4. Handle Transparent Ethernet Bridge (GRE Tap)
            if (gre_proto == 0x6558) {
                linktype = DLT_EN10MB;
                goto REDO_LINK;
            }

            // 5. Standard GRE Tunnel (Raw IP)
            if (gre_proto == ETHERTYPE_IP || gre_proto == ETHERTYPE_IPV6) {
                protocol = gre_proto;

                // Store Tunnel Metadata (Important for Flow Tracking)
                coldNode.tun_src_addr = hotNode.flowKey.src_addr;
                coldNode.tun_dst_addr = hotNode.flowKey.dst_addr;
                coldNode.tun_proto = IPPROTO_GRE;
                coldNode.tun_ip_version = hotNode.flowKey.version;

                goto REDO_LINK_PROTO;  // Process internal IP packet
            }

            dbg_printf("Unsupported GRE protocol: 0x%x\n", gre_proto);
            goto END_FUNC;

        } break;
        default:
            // not handled transport protocol
            // raw flow
            payloadSize = (ptrdiff_t)(ipPayloadEnd - cur.ptr);
            if (payloadSize > 0) payload = (void *)cur.ptr;

            dbg_printf("  raw proto: %u, payload size: %zu\n", IPproto, payloadSize);

            ProcessOtherFlow(packetParam, &hotNode, &coldNode, payload, payloadSize);
            break;
    }

END_FUNC:
    if (defragmented) {
        free(defragmented);
        defragmented = NULL;
        dbg_printf("Defragmented buffer freed for proto %u\n", IPproto);
    }

    if (coldNode.pflog) free(coldNode.pflog);

    if ((hdr->ts.tv_sec - lastRun) > 1) {
        CacheCheck(packetParam->NodeList, hdr->ts.tv_sec);
        lastRun = hdr->ts.tv_sec;
    }

    return 1;
}  // End of ProcessPacket
