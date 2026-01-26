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
#include "flowtree.h"
#include "ip128.h"
#include "ip_frag.h"
#include "nfdump.h"
#include "nffile.h"
#include "nflog.h"
#include "nfxV3.h"
#include "pflog.h"
#include "util.h"

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

static inline void SetClient_latency(struct FlowNode *node, struct timeval *t_packet);

static inline void SetApplication_latency(struct FlowNode *node, struct timeval *t_packet);

static inline void ProcessTCPFlow(packetParam_t *packetParam, struct FlowNode *NewNode, void *payload, size_t payloadSize);

static inline void ProcessUDPFlow(packetParam_t *packetParam, struct FlowNode *NewNode, void *payload, size_t payloadSize);

static inline void ProcessICMPFlow(packetParam_t *packetParam, struct FlowNode *NewNode, void *payload, size_t payloadSize);

static inline void ProcessOtherFlow(packetParam_t *packetParam, struct FlowNode *NewNode, void *payload, size_t payloadSize);

#include "metrohash.c"

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
    struct FlowNode *Client_node = node->rev_node;
    if (!Client_node) return;

    uint64_t latency = ((uint64_t)node->t_first.tv_sec * (uint64_t)1000000 + (uint64_t)node->t_first.tv_usec) -
                       ((uint64_t)Client_node->t_first.tv_sec * (uint64_t)1000000 + (uint64_t)Client_node->t_first.tv_usec);

    node->latency.server = latency;
    Client_node->latency.server = latency;
    // set flag, to calc app latency with nex packet from server
    node->latency.flag = 2;
    // set flag, to calc client latency with nex packet from client
    Client_node->latency.flag = 1;
    dbg_printf("Server latency: %llu\n", (long long unsigned)latency);

}  // End of SetServerClient_latency

// Client latency = t(ACK CLient) - t(SYN ACK Server)
static inline void SetClient_latency(struct FlowNode *node, struct timeval *t_packet) {
    struct FlowNode *serverNode = node->rev_node;
    if (!serverNode) return;

    uint64_t latency = ((uint64_t)t_packet->tv_sec * (uint64_t)1000000 + (uint64_t)t_packet->tv_usec) -
                       ((uint64_t)serverNode->t_last.tv_sec * (uint64_t)1000000 + (uint64_t)serverNode->t_last.tv_usec);

    node->latency.client = latency;
    serverNode->latency.client = latency;
    // reset flag
    node->latency.flag = 0;
    dbg_printf("Client latency: %llu\n", (long long unsigned)latency);

}  // End of SetClient_latency

// Application latency = t(ACK Server) - t(ACK CLient)
void SetApplication_latency(struct FlowNode *node, struct timeval *t_packet) {
    struct FlowNode *clientNode = node->rev_node;
    if (!clientNode) return;

    uint64_t latency = ((uint64_t)t_packet->tv_sec * (uint64_t)1000000 + (uint64_t)t_packet->tv_usec) -
                       ((uint64_t)clientNode->t_last.tv_sec * (uint64_t)1000000 + (uint64_t)clientNode->t_last.tv_usec);

    node->latency.application = latency;
    clientNode->latency.application = latency;
    // reset flag
    node->latency.flag = 0;
    // set flag, to calc application latency with nex packet from server
    clientNode->latency.flag = 0;
    dbg_printf("Application latency: %llu\n", (long long unsigned)latency);

}  // End of SetApplication_latency

static inline void AddPayload(struct FlowNode *Node, void *payload, size_t payloadSize) {
    Node->payload = malloc(payloadSize);
    if (!Node->payload) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
    } else {
        memcpy(Node->payload, payload, payloadSize);
        Node->payloadSize = payloadSize;
    }
}

static inline void ProcessTCPFlow(packetParam_t *packetParam, struct FlowNode *NewNode, void *payload, size_t payloadSize) {
    // make sure node is in use - maybe removed later
    assert(NewNode->memflag == NODE_IN_USE);

    struct FlowNode *Node = Insert_Node(NewNode);

    if (Node == NULL) {
        // New flow
        dbg_printf("New TCP flow: Packets: %u, Bytes: %u\n", NewNode->packets, NewNode->bytes);

        if (payloadSize && packetParam->addPayload) {
            dbg_printf("New TCP flow: Set payload of size: %zu\n", payloadSize);
            AddPayload(NewNode, payload, payloadSize);
        }

        if (NewNode->signal == SIGNAL_FIN) {
            Remove_Node(NewNode);
            Push_Node(packetParam->NodeList, NewNode);
            return;
        }

#ifdef DEVEL
        if ((NewNode->flags & 0x3F) == 0x2) {
            printf("SYN Node\n");
        }
        if ((NewNode->flags & 0x37) == 0x12) {
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

    assert(Node->memflag == NODE_IN_USE);

    // --- process latency, if extendedFlow is enabled ---
    if (packetParam->extendedFlow) {
        if (Node->latency.flag == 1) {
            SetClient_latency(Node, &NewNode->t_first);
        } else if (Node->latency.flag == 2) {
            dbg_printf("Set App lat slot: %u -> %u diff: %u\n", Node->latency.tsVal, NewNode->latency.tsVal,
                       NewNode->latency.tsVal - Node->latency.tsVal);
            SetApplication_latency(Node, &NewNode->t_first);
        }
    }

    // update existing flow
    Node->flags |= NewNode->flags;
    Node->packets++;
    Node->bytes += NewNode->bytes;
    Node->t_last = NewNode->t_last;

    if (NewNode->minTTL < Node->minTTL) Node->minTTL = NewNode->minTTL;
    if (NewNode->maxTTL > Node->maxTTL) Node->maxTTL = NewNode->maxTTL;

    // DEVEL RTT - disabled for now
#if 0
    if (NewNode->signal != SIGNAL_FIN && Node->latency.ack && ((NewNode->latency.ack - Node->latency.ack) > 0)) {
        uint32_t rtt = NewNode->latency.tsVal - Node->latency.tsVal;
        printf("Node old RTT: %u ", Node->latency.rtt);
        if (rtt) Node->latency.rtt = Node->latency.rtt ? (Node->latency.rtt + rtt) >> 1 : rtt;
        dbg_printf("Node rtt: %u, new RTT: %u\n", rtt, Node->latency.rtt);
    }
    Node->latency.tsVal = NewNode->latency.tsVal;
    Node->latency.ack = NewNode->latency.ack;
    dbg_printf("Existing TCP flow: Packets: %u, Bytes: %u\n", Node->packets, Node->bytes);
#endif

    // payload stays cold unless explicitly requested
    if (packetParam->addPayload && Node->payloadSize == 0 && payloadSize > 0) {
        dbg_printf("Existing TCP flow: Set payload of size: %zu\n", payloadSize);
        AddPayload(Node, payload, payloadSize);
    }

    if (NewNode->signal == SIGNAL_FIN) {
        // Set node signal
        Node->signal = SIGNAL_FIN;
        // flush node for further processing
        Remove_Node(Node);
        Push_Node(packetParam->NodeList, Node);
    }

    Free_Node(NewNode);
}  // End of ProcessTCPFlow

static inline void ProcessUDPFlow(packetParam_t *packetParam, struct FlowNode *NewNode, void *payload, size_t payloadSize) {
    assert(NewNode->memflag == NODE_IN_USE);

    /* DNS: flush immediately, payload optional */
    if (NewNode->flowKey.src_port == 53 || NewNode->flowKey.dst_port == 53) {
        if (packetParam->addPayload && payloadSize) {
            dbg_printf("UDP DNS flow: payload size: %zu\n", payloadSize);
            AddPayload(NewNode, payload, payloadSize);
        }
        Push_Node(packetParam->NodeList, NewNode);
        return;
    }

    struct FlowNode *Node = Insert_Node(NewNode);
    if (Node == NULL) {
        // new flow
        dbg_printf("New UDP flow: Packets: %u, Bytes: %u\n", NewNode->packets, NewNode->bytes);
        if (packetParam->addPayload && payloadSize) {
            dbg_printf("New UDP flow: Set payload of size: %zu\n", payloadSize);
            AddPayload(NewNode, payload, payloadSize);
        }
        return;
    }

    assert(Node->memflag == NODE_IN_USE);

    /* hot updates */
    Node->packets++;
    Node->bytes += NewNode->bytes;
    Node->t_last = NewNode->t_last;

    if (NewNode->minTTL < Node->minTTL) Node->minTTL = NewNode->minTTL;
    if (NewNode->maxTTL > Node->maxTTL) Node->maxTTL = NewNode->maxTTL;

    dbg_printf("Existing UDP flow: Packets: %u, Bytes: %u\n", Node->packets, Node->bytes);

    if (packetParam->addPayload && Node->payloadSize == 0 && payloadSize > 0) {
        dbg_printf("Existing UDP flow: Set payload of size: %zu\n", payloadSize);
        AddPayload(Node, payload, payloadSize);
    }

    Free_Node(NewNode);
}

static inline void ProcessICMPFlow(packetParam_t *packetParam, struct FlowNode *NewNode, void *payload, size_t payloadSize) {
    // Flush ICMP directly
    dbg_printf("Flush ICMP flow: Packets: %u, Bytes: %u\n", NewNode->packets, NewNode->bytes);
    if (payloadSize && packetParam->addPayload) {
        dbg_printf("ICMP flow: payload size: %zu\n", payloadSize);
        AddPayload(NewNode, payload, payloadSize);
    }
    Push_Node(packetParam->NodeList, NewNode);

}  // End of ProcessICMPFlow

static inline void ProcessOtherFlow(packetParam_t *packetParam, struct FlowNode *NewNode, void *payload, size_t payloadSize) {
    assert(NewNode->memflag == NODE_IN_USE);

    struct FlowNode *Node = Insert_Node(NewNode);
    if (Node == NULL) {
        // new flow
        dbg_printf("New flow IP proto: %u. Packets: %u, Bytes: %u\n", NewNode->flowKey.proto, NewNode->packets, NewNode->bytes);
        if (packetParam->addPayload && payloadSize) {
            dbg_printf("flow: payload size: %zu\n", payloadSize);
            AddPayload(NewNode, payload, payloadSize);
        }
        return;
    }

    assert(Node->memflag == NODE_IN_USE);

    // update existing flow
    Node->packets++;
    Node->bytes += NewNode->bytes;
    Node->t_last = NewNode->t_last;

    if (NewNode->minTTL < Node->minTTL) Node->minTTL = NewNode->minTTL;
    if (NewNode->maxTTL > Node->maxTTL) Node->maxTTL = NewNode->maxTTL;

    dbg_printf("Existing flow IP proto: %u Packets: %u, Bytes: %u\n", NewNode->flowKey.proto, Node->packets, Node->bytes);

    if (packetParam->addPayload && Node->payloadSize == 0 && payloadSize > 0) {
        dbg_printf("Existing flow: Set payload of size: %zu\n", payloadSize);
        AddPayload(Node, payload, payloadSize);
    }

    Free_Node(NewNode);
}  // End of ProcessOtherFlow

int ProcessPacket(packetParam_t *packetParam, const struct pcap_pkthdr *hdr, const u_char *data) {
    struct FlowNode *Node = NULL;
    uint16_t version, IPproto;
    char s1[64];
    char s2[64];
    static unsigned pkg_cnt = 0;

    pkg_cnt++;
    packetParam->proc_stat.packets++;
    dbg_printf("\nNext Packet: %u, cap len:%u, len: %u\n", pkg_cnt, hdr->caplen, hdr->len);

    // snaplen is minimum 54 bytes
    uint8_t *dataptr = (uint8_t *)data;
    uint8_t *eodata = (uint8_t *)data + hdr->caplen;
    void *defragmented = NULL;
    void *payload = NULL;
    ssize_t payloadSize = 0;
    uint32_t vlanID = 0;
    uint64_t srcMac = 0;
    uint64_t dstMac = 0;
    uint32_t numMPLS = 0;
    uint32_t *mplsLabel = NULL;
    pflog_hdr_t *pflog = NULL;

    // link layer processing
    uint16_t protocol = 0;
    uint32_t linktype = packetParam->linktype;
    int redoLink = 0;
REDO_LINK:
    switch (linktype) {
        case DLT_EN10MB:
            memcpy(&dstMac, dataptr, 6);
            memcpy(&srcMac, dataptr + 6, 6);
            protocol = dataptr[12] << 0x08 | dataptr[13];
            int IEEE802 = protocol <= 1500;
            if (IEEE802) {
                packetParam->proc_stat.skipped++;
                return 1;
            }
            // unwrap link layer
            dataptr += 14;
            dbg_printf("Linktype: DLT_EN10MB\n");
            break;
        case DLT_RAW:
            protocol = 0x800;
            dbg_printf("Linktype: DLT_RAW\n");
            break;
        case DLT_PPP:
            protocol = 0x800;
            // unwrap link layer
            dataptr += 2;
            dbg_printf("Linktype: DLT_PPP\n");
            break;
        case DLT_PPP_SERIAL:
            protocol = 0x800;
            // unwrap link layer
            dataptr += 4;
            dbg_printf("Linktype: DLT_PPP_SERIAL\n");
            break;
        case DLT_LOOP:
        case DLT_NULL: {
            uint32_t header;
            if (linktype == DLT_LOOP) {
                header = ntohl(*((uint32_t *)dataptr));
                // unwrap link layer
                dataptr += 14;
                dbg_printf("Linktype: DLT_LOOP\n");
            } else {
                header = *((uint32_t *)dataptr);
                // unwrap link layer
                dataptr += 4;
                dbg_printf("Linktype: DLT_NULL\n");
            }
            switch (header) {
                case 2:
                    protocol = 0x800;
                    break;
                case 24:
                case 28:
                case 30:
                    protocol = 0x86DD;
                    break;
                default:
                    LogInfo("Packet: %u: unsupported DLT_NULL protocol: 0x%x, packet: %u", pkg_cnt, header);
                    return 1;
            }
        } break;
        case DLT_LINUX_SLL:
            protocol = dataptr[14] << 8 | dataptr[15];
            // unwrap link layer
            dataptr += 16;
            dbg_printf("Linktype: DLT_LINUX_SSL\n");
            break;
        case DLT_IEEE802_11:
            protocol = 0x800;
            // unwrap link layer
            dataptr += 22;
            dbg_printf("Linktype: DLT_IEEE802_11\n");
            break;
        case DLT_NFLOG: {
            nflog_hdr_t *nflog_hdr = (nflog_hdr_t *)dataptr;
            if (hdr->caplen < sizeof(nflog_hdr_t)) {
                LogInfo("Packet: %u: NFLOG: not enough data", pkg_cnt);
                return 1;
            }

            if (nflog_hdr->nflog_version != 0) {
                LogInfo("Packet: %u: unsupported NFLOG version: %d", pkg_cnt, nflog_hdr->nflog_version);
                return 1;
            }
            dbg_printf("Linktype: DLT_NFLOG\n");
            dbg_printf("NFLOG: %s, rid: %u\n", nflog_hdr->nflog_family == 2 ? "IPv4" : "IPv6", ntohs(nflog_hdr->nflog_rid));
            // TLVs following
            dataptr += sizeof(nflog_hdr_t);
            while (dataptr < eodata) {
                nflog_tlv_t *tlv = (nflog_tlv_t *)(dataptr);
                dbg_printf("NFLOG: tlv type: %u, length: %u\n", tlv->tlv_type, tlv->tlv_length);

                size_t size = tlv->tlv_length;
                if (size % 4 != 0) size += 4 - size % 4;
                if (size < sizeof(nflog_tlv_t)) {
                    LogInfo("Packet: %u: NFLOG: tlv size error: %u", pkg_cnt, size);
                    return 1;
                }

                if (tlv->tlv_type == NFULA_PAYLOAD) {
                    dataptr += sizeof(nflog_tlv_t);
                    protocol = 0x800;
                    break;
                }

                dataptr += size;
            }
        } break;
        case DLT_PFLOG: {
            pflog_hdr_t *pfloghdr = (pflog_hdr_t *)dataptr;
            if (hdr->caplen < PFLOG_HDRLEN) {
                LogInfo("Packet: %u: PFLOG: not enough data", pkg_cnt);
                return 1;
            }
            pflog = malloc(sizeof(pflog_hdr_t));
            memcpy(pflog, pfloghdr, sizeof(pflog_hdr_t));

            protocol = 0x800;
            dataptr += PFLOG_HDRLEN;
            dbg_printf("Linktype: DLT_PFLOG\n");
        } break;
        default:
            LogInfo("Packet: %u: unsupported link type: 0x%x, packet: %u", pkg_cnt, linktype);
            return 1;
    }

REDO_LINK_PROTO:
    if (dataptr >= eodata) {
        packetParam->proc_stat.short_snap++;
        dbg_printf("Short packet: %u, Check line: %u", hdr->caplen, __LINE__);
        return 1;
    }
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
                vlan_hdr_t *vlan_hdr = (vlan_hdr_t *)dataptr;
                dbg_printf("VLAN ID: %u, type: 0x%x\n", ntohs(vlan_hdr->vlan_id), ntohs(vlan_hdr->type));
                protocol = ntohs(vlan_hdr->type);
                vlanID = ntohs(vlan_hdr->vlan_id) & 0xFFF;
                dataptr += 4;
            } while ((dataptr < eodata) && protocol == 0x8100);

            // redo protocol evaluation
            goto REDO_LINK_PROTO;
        } break;
        case ETHERTYPE_MPLS: {  // MPLS
            // unwind MPLS label stack
            uint32_t *mpls;
            mplsLabel = (uint32_t *)dataptr;  // 1st label
            do {
                mpls = (uint32_t *)dataptr;
                dbg_printf("MPLS label: %x\n", ntohl(*mpls) >> 8);
                dataptr += 4;
                numMPLS++;
            } while ((dataptr < eodata) && ((ntohl(*mpls) & 0x100) == 0));  // check for Bottom of stack

            uint8_t *nxHdr = (uint8_t *)dataptr;
            if ((*nxHdr >> 4) == 4)
                protocol = ETHERTYPE_IP;  // IPv4
            else if ((*nxHdr >> 4) == 6)
                protocol = ETHERTYPE_IPV6;  // IPv6
            else {
                dbg_printf("Unsupported protocol in mpls: 0x%x\n", *nxHdr >> 4);
                packetParam->proc_stat.skipped++;
                goto END_FUNC;
            }
            // redo protocol evaluation
            goto REDO_LINK_PROTO;
        } break;
        case ETHERTYPE_TRANSETHER: {  // GRE ethernet bridge
            dbg_printf("  GRE tap tunnel\n");
            if ((dataptr + 14) > eodata) {
                dbg_printf("Short packet: %u, Check line: %u", hdr->caplen, __LINE__);
                packetParam->proc_stat.short_snap++;
                goto END_FUNC;
            }
            memcpy(&dstMac, dataptr, 6);
            memcpy(&srcMac, dataptr + 6, 6);
            dataptr += 12;
            uint16_t *nextProtocol = (uint16_t *)dataptr;
            dataptr += 2;
            protocol = ntohs(*nextProtocol);
            goto REDO_LINK_PROTO;
        } break;
        case ETHERTYPE_PPPOE: {
            uint8_t VersionType = *((uint8_t *)dataptr);
            uint8_t Code = *((uint8_t *)(dataptr + 1));
            uint16_t pppProto = ntohs(*((uint16_t *)(dataptr + 6)));
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
            dataptr += 8;
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

    dbg_printf("Link layer processed: %td bytes, remaining: %td\n", (ptrdiff_t)(dataptr - (uint8_t *)data), eodata - dataptr);

    // link layer, vpn and mpls header removed
    if (dataptr >= eodata) {
        packetParam->proc_stat.short_snap++;
        dbg_printf("Short packet: %u, Check line: %u", hdr->caplen, __LINE__);
        goto END_FUNC;
    }

// IP layer processing
REDO_IPPROTO:
    // IP decoding
    if (defragmented) {
        // data is sitting on a defragmented IPv4 packet memory region
        // REDO loop could result in a memory leak, if again IP is fragmented
        // XXX memory leak to be fixed
        LogError("Fragmentation memory leak triggered! - skip packet");
        goto END_FUNC;
    }

    struct ip *ip = (struct ip *)dataptr;  // offset points to end of link layer
    version = ip->ip_v;                    // ip version

    ptrdiff_t ipPayloadLength = 0;
    uint8_t *ipPayloadEnd = NULL;
    if (version == 6) {
        struct ip6_hdr *ip6 = (struct ip6_hdr *)dataptr;
        size_t size_ip = sizeof(struct ip6_hdr);

        dataptr += size_ip;
        if (dataptr >= eodata) {
            dbg_printf("Short packet: %u, Check line: %u", hdr->caplen, __LINE__);
            packetParam->proc_stat.short_snap++;
            goto END_FUNC;
        }

        // IPv6 duplicate check
        // duplicate check starts from the IP header over the rest of the packet
        // vlan, mpls and layer 1 headers are ignored
        if (unlikely(packetParam->doDedup && redoLink == 0)) {
            // check for de-dup
            uint32_t hopLimit = ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim;
            ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim = 0;
            uint16_t len = ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen);
            if (is_duplicate((const uint8_t *)ip, len + 40)) {
                packetParam->proc_stat.duplicates++;
                return 0;
            }
            ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim = hopLimit;
            // prevent recursive dedub checks with IP in IP packets
            redoLink++;
        }

        // ipv6 Extension headers not processed
        IPproto = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        struct ip6_frag *ip6_frag = NULL;
        uint8_t fragment_flag = 0;
        if (unlikely(IPproto == IPPROTO_FRAGMENT)) {
            ip6_frag = (struct ip6_frag *)dataptr;
            IPproto = ip6_frag->ip6f_nxt;
            void *payload = ProcessIP6Fragment(ip6, ip6_frag, eodata);
            if (payload == NULL) {
                // not yet complete
                dbg_printf("IPv6 de-fragmentation not yet completed\n");
                goto END_FUNC;
            }
            defragmented = payload;
            dataptr = payload;
            ipPayloadLength = ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen) - sizeof(struct ip6_frag);
            eodata = dataptr + ipPayloadLength;
            fragment_flag = flagMF;
        } else {
            ipPayloadLength = ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen);
            dbg_printf("Packet IPv6, SRC %s, DST %s, padding %zu\n", inet_ntop(AF_INET6, &ip6->ip6_src, s1, sizeof(s1)),
                       inet_ntop(AF_INET6, &ip6->ip6_dst, s2, sizeof(s2)), (ptrdiff_t)(eodata - ipPayloadEnd));
        }
        ipPayloadEnd = dataptr + ipPayloadLength;

        if (!Node) Node = New_Node();
        Node->flowKey.version = AF_INET6;
        Node->t_first.tv_sec = hdr->ts.tv_sec;
        Node->t_last.tv_sec = hdr->ts.tv_sec;
        Node->t_first.tv_usec = hdr->ts.tv_usec;
        Node->t_last.tv_usec = hdr->ts.tv_usec;
        Node->bytes = ntohs(ip6->ip6_plen) + size_ip;
        uint8_t ttl = ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim;
        Node->minTTL = ttl;
        Node->maxTTL = ttl;
        Node->fragmentFlags = fragment_flag;

        memcpy(Node->flowKey.src_addr.bytes, ip6->ip6_src.s6_addr, 16);
        memcpy(Node->flowKey.dst_addr.bytes, ip6->ip6_dst.s6_addr, 16);

    } else if (version == 4) {
        int size_ip = (ip->ip_hl << 2);

        dataptr += size_ip;
        if (dataptr > eodata) {
            dbg_printf("Short packet: %u, Check line: %u", hdr->caplen, __LINE__);
            packetParam->proc_stat.short_snap++;
            goto END_FUNC;
        }

        ipPayloadLength = ntohs(ip->ip_len) - size_ip;
        ipPayloadEnd = dataptr + ipPayloadLength;

        // IPv4 duplicate check
        // duplicate check starts from the IP header over the rest of the packet
        // vlan, mpls and layer 1 headers are ignored
        uint8_t fragment_flag = 0;
        if (unlikely(packetParam->doDedup && redoLink == 0)) {
            // check for de-dup
            uint32_t ttl = ip->ip_ttl;
            uint32_t sum = ip->ip_sum;
            ip->ip_ttl = 0;
            ip->ip_sum = 0;
            if (is_duplicate((const uint8_t *)ip, ntohs(ip->ip_len))) {
                packetParam->proc_stat.duplicates++;
                return 0;
            }
            ip->ip_ttl = ttl;
            ip->ip_sum = sum;
            // prevent recursive dedub checks with IP in IP packets
            redoLink++;
        }

        IPproto = ip->ip_p;
        dbg_printf("Packet IPv4 SRC %s, DST %s, padding %zu\n", inet_ntop(AF_INET, &ip->ip_src, s1, sizeof(s1)),
                   inet_ntop(AF_INET, &ip->ip_dst, s2, sizeof(s2)), (ptrdiff_t)(eodata - ipPayloadEnd));

        // IPv4 defragmentation
        uint16_t ip_off = ntohs(ip->ip_off);
        uint32_t frag_offset = (ip_off & IP_OFFMASK) << 3U;
        if ((ip_off & IP_MF) || frag_offset) {
            // fragmented packet
            void *payload = ProcessIP4Fragment(ip, eodata);
            if (payload == NULL) {
                // not yet complete
                dbg_printf("IPv4 de-fragmentation not yet completed\n");
                goto END_FUNC;
            }

            // packet defragmented - set payload to defragmented data
            defragmented = payload;
            dataptr = payload;
            ipPayloadLength = ntohs(ip->ip_len) - size_ip;
            eodata = dataptr + ipPayloadLength;
            fragment_flag = flagMF;
        } else {
            ipPayloadLength = ntohs(ip->ip_len) - size_ip;
        }
        ipPayloadEnd = dataptr + ipPayloadLength;

        if (!Node) Node = New_Node();
        Node->flowKey.version = AF_INET;
        Node->t_first.tv_sec = hdr->ts.tv_sec;
        Node->t_last.tv_sec = hdr->ts.tv_sec;
        Node->t_first.tv_usec = hdr->ts.tv_usec;
        Node->t_last.tv_usec = hdr->ts.tv_usec;
        Node->bytes = ntohs(ip->ip_len);

        static const uint8_t prefix[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};
        memcpy(Node->flowKey.src_addr.bytes, prefix, 12);
        memcpy(Node->flowKey.dst_addr.bytes, prefix, 12);
        memcpy(Node->flowKey.src_addr.bytes + 12, &ip->ip_src.s_addr, 4);
        memcpy(Node->flowKey.dst_addr.bytes + 12, &ip->ip_dst.s_addr, 4);

        Node->minTTL = ip->ip_ttl;
        Node->maxTTL = ip->ip_ttl;
        Node->fragmentFlags = fragment_flag;
        if (ip_off & IP_DF) Node->fragmentFlags |= flagDF;

    } else {
        dbg_printf("ProcessPacket() Unsupported protocol version: %i\n", version);
        packetParam->proc_stat.unknown++;
        goto END_FUNC;
    }

    // fill ipv4/ipv6 node with extracted data
    Node->vlanID = vlanID;
    Node->srcMac = srcMac;
    Node->dstMac = dstMac;
    Node->packets = 1;
    Node->flowKey.proto = IPproto;
    Node->nodeType = FLOW_NODE;
    Node->pflog = pflog;

    // bytes = number of bytes on wire - data link data
    dbg_printf("Payload: %td bytes, Full packet: %u bytes\n", eodata - dataptr, Node->bytes);

    if (numMPLS) {
        if (numMPLS > 10) numMPLS = 10;
        for (unsigned i = 0; i < numMPLS; i++) {
            Node->mpls[i] = *mplsLabel;
            mplsLabel++;
        }
    }

    if (ipPayloadEnd < dataptr || ipPayloadEnd > eodata) {
        LogError("ProcessPacket() payload data length error line: %u", __LINE__);
        Free_Node(Node);
        goto END_FUNC;
    }

    // transport protocol processing
    switch (IPproto) {
        case IPPROTO_UDP: {
            struct udphdr *udp = (struct udphdr *)dataptr;
            dataptr += sizeof(struct udphdr);

            if (dataptr > eodata) {
                dbg_printf("  UDP Short packet: %u, Check line: %u", hdr->caplen, __LINE__);
                packetParam->proc_stat.short_snap++;
                Free_Node(Node);
                goto END_FUNC;
            }

            uint16_t UDPlen = ntohs(udp->uh_ulen);
            if (UDPlen < 8) {
                LogError("UDP payload length error: %u bytes < 8, SRC %s, DST %s", UDPlen, inet_ntop(AF_INET, &ip->ip_src, s1, sizeof(s1)),
                         inet_ntop(AF_INET, &ip->ip_dst, s2, sizeof(s2)));
                Free_Node(Node);
                break;
            }

            dbg_printf("  UDP: size: %u, SRC: %i, DST: %i\n", UDPlen, ntohs(udp->uh_sport), ntohs(udp->uh_dport));

            Node->flags = 0;
            Node->flowKey.src_port = ntohs(udp->uh_sport);
            Node->flowKey.dst_port = ntohs(udp->uh_dport);

            dbg_assert(dataptr <= eodata);
            payloadSize = (ptrdiff_t)(ipPayloadEnd - dataptr);
            if (payloadSize > 0) {
                payload = (void *)dataptr;
                ProcessUDPFlow(packetParam, Node, payload, (size_t)payloadSize);
            }

        } break;
        case IPPROTO_TCP: {
            struct tcphdr *tcp = (struct tcphdr *)dataptr;
            uint32_t size_tcp = tcp->th_off << 2;
            dataptr += size_tcp;
            if (dataptr > eodata) {
                dbg_printf("  TCP Short packet: %u, Check line: %u\n", hdr->caplen, __LINE__);
                packetParam->proc_stat.short_snap++;
                Free_Node(Node);
                goto END_FUNC;
            }

            dbg_assert(dataptr <= eodata);
            payloadSize = (ptrdiff_t)(ipPayloadEnd - dataptr);
            if (payloadSize > 0) payload = (void *)dataptr;

#ifdef DEVEL
            printf("  Size TCP header: %u, size TCP payload: %zu ", size_tcp, payloadSize);
            printf("  src port %i, dst port %i, flags %i : \n", ntohs(tcp->th_sport), ntohs(tcp->th_dport), tcp->th_flags);
            if (tcp->th_flags & TH_SYN) printf("SYN ");
            if (tcp->th_flags & TH_ACK) printf("ACK ");
            if (tcp->th_flags & TH_URG) printf("URG ");
            if (tcp->th_flags & TH_PUSH) printf("PUSH ");
            if (tcp->th_flags & TH_FIN) printf("FIN ");
            if (tcp->th_flags & TH_RST) printf("RST ");
            printf("\n");
#endif
            Node->signal = tcp->th_flags & TH_FIN || tcp->th_flags & TH_RST;

            // RTT DEVEL - disabled for now

#if 0
            if (tcp->th_off > 5) {
                uint32_t optLen = (tcp->th_off - 5) << 2;
                uint8_t *optData = dataptr - (ptrdiff_t)optLen;
                dbg_printf("TCP HLen: %u, tcp option len: %u\n", tcp->th_off, optLen);
                while (optData < dataptr) {
                    uint8_t opt = *optData++;
                    uint8_t optLen = 0;
                    switch (opt) {
                        case 0:  // End of options
                        case 1:  // NOP
                            continue;
                            break;
                        case 8:  // TS
                            optLen = *optData++;
                            if (optLen != 10) {
                                // skip unknown TS len
                                LogError("TCP option TS len error: %u", optLen);
                            } else {
                                uint32_t tsVal = ntohl(*(uint32_t *)optData);
                                Node->latency.tsVal = tsVal;
                                optData += 4;
                                uint32_t tsEcr = ntohl(*(uint32_t *)optData);
                                optData += 4;
                                dbg_printf("TS tcp option: %u, optLen: %u, tsVal: %u, tsEcr: %u\n", opt, optLen, tsVal, tsEcr);
                                Node->latency.ack = ntohl(tcp->th_ack);
                                continue;
                            }
                            break;
                        default:
                            optLen = *optData++;
                            optData += (optLen - 2);
                            dbg_printf("Next tcp option: %u, optLen: %u, size left: %lu\n", opt, optLen, (dataptr - optData));
                    }
                }
            } else {
                dbg_printf("OptLen: %u, no tcp option decoded\n", tcp->th_off);
            }
#endif
            Node->flags = tcp->th_flags;
            Node->flowKey.src_port = ntohs(tcp->th_sport);
            Node->flowKey.dst_port = ntohs(tcp->th_dport);
            ProcessTCPFlow(packetParam, Node, payload, payloadSize);

        } break;
        case IPPROTO_ICMP: {
            struct icmp *icmp = (struct icmp *)dataptr;
            dataptr += 8;

            if (dataptr > eodata) {
                dbg_printf("  ICMP Short packet: %u, Check line: %u\n", hdr->caplen, __LINE__);
                packetParam->proc_stat.short_snap++;
                Free_Node(Node);
                goto END_FUNC;
            }

            dbg_assert(dataptr <= eodata);
            payloadSize = (ptrdiff_t)(ipPayloadEnd - dataptr);
            if (payloadSize > 0) payload = (void *)dataptr;

            Node->flowKey.dst_port = (icmp->icmp_type << 8) + icmp->icmp_code;
            dbg_printf("  IPv%d ICMP proto: %u, type: %u, code: %u\n", version, ip->ip_p, icmp->icmp_type, icmp->icmp_code);
            ProcessICMPFlow(packetParam, Node, payload, payloadSize);
        } break;
        case IPPROTO_ICMPV6: {
            struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)dataptr;
            dataptr += sizeof(struct icmp6_hdr);

            if (dataptr > eodata) {
                dbg_printf("  ICMPv6 Short packet: %u, Check line: %u\n", hdr->caplen, __LINE__);
                packetParam->proc_stat.short_snap++;
                Free_Node(Node);
                goto END_FUNC;
            }

            dbg_assert(dataptr <= eodata);
            payloadSize = (ptrdiff_t)(ipPayloadEnd - dataptr);
            if (payloadSize > 0) payload = (void *)dataptr;

            Node->flowKey.dst_port = (icmp6->icmp6_type << 8) + icmp6->icmp6_code;
            dbg_printf("  IPv%d ICMP proto: %u, type: %u, code: %u\n", version, ip->ip_p, icmp6->icmp6_type, icmp6->icmp6_code);
            ProcessICMPFlow(packetParam, Node, payload, payloadSize);
        } break;
        case IPPROTO_IPV6: {
            uint32_t size_inner_ip = sizeof(struct ip6_hdr);

            if ((dataptr + size_inner_ip) > eodata) {
                dbg_printf("  IPIPv6 tunnel Short packet: %u, Check line: %u\n", hdr->caplen, __LINE__);
                packetParam->proc_stat.short_snap++;
                Free_Node(Node);
                goto END_FUNC;
            }

            // move IP to tun IP
            Node->tun_src_addr = Node->flowKey.src_addr;
            Node->tun_dst_addr = Node->flowKey.dst_addr;
            Node->tun_proto = IPPROTO_IPV6;
            Node->tun_ip_version = Node->flowKey.version;

            dbg_printf("  IPIPv6 tunnel - inner IPv6:\n");

            // redo proto evaluation
            goto REDO_IPPROTO;
        } break;
        case IPPROTO_IPIP: {
            struct ip *inner_ip = (struct ip *)dataptr;
            uint32_t size_inner_ip = (inner_ip->ip_hl << 2);

            if ((dataptr + size_inner_ip) > eodata) {
                dbg_printf("  IPIP tunnel Short packet: %u, Check line: %u\n", hdr->caplen, __LINE__);
                packetParam->proc_stat.short_snap++;
                Free_Node(Node);
                goto END_FUNC;
            }

            // move IP to tun IP
            Node->tun_src_addr = Node->flowKey.src_addr;
            Node->tun_dst_addr = Node->flowKey.dst_addr;
            Node->tun_proto = IPPROTO_IPIP;
            Node->tun_ip_version = Node->flowKey.version;

            dbg_printf("  IPIP tunnel - inner IP:\n");

            // redo proto evaluation
            goto REDO_IPPROTO;

        } break;
        case IPPROTO_GRE:
        case 0x6558: {
            gre_hdr_t *gre_hdr = (gre_hdr_t *)dataptr;
            protocol = ntohs(gre_hdr->type);
            uint16_t gre_flags = ntohs(gre_hdr->flags);
            dbg_printf("  GRE proto encapsulation: type: 0x%x\n", protocol);

            if (protocol == PROTO_ERSPAN) {
                // unwrap gre hdr
                dataptr += sizeof(gre_hdr_t);
                if (gre_flags & 0x1000) {  // Sequence supplied
#ifdef DEVEL
                    uint32_t *sequence = NULL;
                    sequence = (uint32_t *)(dataptr);
                    printf("GRE sequence: %u\n", ntohl(*sequence));
#endif
                    // unwrap sequence
                    dataptr += 4;
                    // unwrap erspan hdr
                    dataptr += 8;
                }
                // inner ethernet packet
                linktype = DLT_EN10MB;
                goto REDO_LINK;
            }

            int optionSize = 0;
            uint16_t version = gre_flags & 0x7;
            if (version == 0) {
                // XXX checksum, routing options not evaluated gre tunnel
                dataptr += sizeof(gre_hdr_t);
            } else if (version == 1) {
                uint16_t proto = ntohs(gre_hdr->type);
                uint16_t callID = ntohs(*((uint16_t *)(dataptr + 6)));
                Node->flowKey.dst_port = callID;
                if (proto != 0x880b) {
                    LogError("Unexpected protocol in LLTP GRE header: 0x%x", proto);
                    packetParam->proc_stat.short_snap++;
                    Free_Node(Node);
                    goto END_FUNC;
                }
                // pptp - vpn
                dataptr += sizeof(gre_hdr_t);
                // 2 bytes key paload length, 2 byte call ID
                optionSize += 4;
                if (gre_flags & 0x1000)  // Sequence supplied
                    optionSize += 4;
                if (gre_flags & 0x80)  // Ack number present ?
                    optionSize += 4;
                dataptr += optionSize;

                payloadSize = (ptrdiff_t)(ipPayloadEnd - dataptr);
                if (payloadSize > 0) payload = (void *)dataptr;

                ProcessOtherFlow(packetParam, Node, payload, payloadSize);
                goto END_FUNC;
            } else {
                dbg_printf("  GRE version error: %u\n", version);
                packetParam->proc_stat.short_snap++;
                Free_Node(Node);
                goto END_FUNC;
            }

            if (dataptr > eodata) {
                dbg_printf("  GRE tunnel Short packet: %u\n", hdr->caplen);
                packetParam->proc_stat.short_snap++;
                Free_Node(Node);
                goto END_FUNC;
            }
            // move IP to tun IP
            Node->tun_src_addr = Node->flowKey.src_addr;
            Node->tun_dst_addr = Node->flowKey.dst_addr;
            Node->tun_proto = IPPROTO_GRE;
            Node->tun_ip_version = Node->flowKey.version;
            // redo IP proto evaluation
            goto REDO_LINK_PROTO;

        } break;
        default:
            // not handled transport protocol
            // raw flow
            dbg_assert(dataptr <= eodata);
            payloadSize = (ptrdiff_t)(ipPayloadEnd - dataptr);
            if (payloadSize > 0) payload = (void *)dataptr;

            dbg_printf("  raw proto: %u, payload size: %zu\n", IPproto, payloadSize);

            ProcessOtherFlow(packetParam, Node, payload, payloadSize);
            break;
    }

END_FUNC:
    if (defragmented) {
        free(defragmented);
        defragmented = NULL;
        dbg_printf("Defragmented buffer freed for proto %u\n", IPproto);
    }

    if ((hdr->ts.tv_sec - lastRun) > 1) {
        CacheCheck(packetParam->NodeList, hdr->ts.tv_sec);
        lastRun = hdr->ts.tv_sec;
    }

    return 1;
}  // End of ProcessPacket
