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

#ifndef _FLOWHASH_H
#define _FLOWHASH_H 1

#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

#include "config.h"
#include "ip128.h"
#include "nfdump.h"
#include "nfxV3.h"

typedef struct flowHashStat_s {
    size_t activeNodes;
    size_t flowNodes;
    size_t fragNodes;
} flowHashStat_t;

// information updated or tested for every packet - hot path
typedef struct hotNode_s {
    struct flowKey_s {
        ip128_t src_addr;
        ip128_t dst_addr;
        uint16_t src_port;
        uint16_t dst_port;
        uint8_t proto;
        uint8_t version;
        uint16_t _ALIGN;  // keep alignment
    } flowKey;
    uint64_t hash;

    struct timeval t_first;  // first seen
    struct timeval t_last;   // last seen

    uint32_t packets;  // summed up number of packets
    uint32_t bytes;    // summed up number of bytes
    uint8_t flags;     // TCP flags etc.

    uint8_t flush;  // FIN/RST packet - flush node

} hotNode_t;

// information updated or tested once only - cold path
typedef struct coldNode_s {
    uint32_t vlanID;
    uint32_t mpls[10];

    ip128_t tun_src_addr;
    ip128_t tun_dst_addr;
    uint8_t tun_proto;
    uint8_t tun_ip_version;

    uint8_t fragmentFlags;
    uint8_t align;  // keep padding explicit

    // pf record information from OpenBSD pflog interface
    uint32_t ruleNr;
    uint8_t action;
    uint8_t reason;
    uint16_t _pad_pf;  // pad to 4 bytes

    void *pflog;
    void *payload;
    uint32_t payloadSize;

    uint8_t minTTL;   // IP min TTL
    uint8_t maxTTL;   // IP max TTL
    uint16_t _align;  // not used - alignment

    uint64_t srcMac;
    uint64_t dstMac;

    struct FlowNode *rev_node;  // reverse flow, if requested

    struct latency_s {
        uint64_t client;
        uint64_t server;
        uint64_t application;
        uint32_t flag;
        uint32_t ack;
        uint32_t tsVal;
        uint32_t rtt;
    } latency;
} coldNode_t;

struct FlowNode {
    struct FlowNode *next;  // Linked list in FreeList
    struct FlowSlab *slab;  // slab pointer
    // expire wheel
    struct FlowNode *wheel_next;
    struct FlowNode **wheel_prev_next;
    uint32_t wheel_slot;

    time_t timestamp;     // timestamp sync node
    hotNode_t hotNode;    // not node and cache relevant
    coldNode_t coldNode;  // flow additional information

#define FLOW_NODE 1
#define FRAG_NODE 2
#define SIGNAL_NODE_SYNC 3
#define SIGNAL_NODE_DONE 4
    uint8_t nodeType;

#define NODE_FREE 0xA5
#define NODE_IN_USE 0x5A
    uint8_t memflag;  // housekeeping
    uint8_t inTree;   // unused - alignment
};

// node cache struct
struct FlowSlab {
    struct FlowSlab *next;                   // chain
    struct FlowNode *local_free;             // free list of packet thread
    _Atomic(struct FlowNode *) remote_free;  // free list of flow thread
    _Atomic(bool) removing;                  // slab gets removed
    _Atomic uint32_t in_use;                 // number of nodes in use
    uint32_t capacity;                       // max number of nodes
    time_t removed_at;                       // timestamp when moved to quarantine
    struct FlowNode nodes[];                 // base pointer
};

typedef struct NodeList_s {
    struct FlowNode *list;
    struct FlowNode *last;
    pthread_mutex_t m_list;
    pthread_cond_t c_list;
    size_t length;
} NodeList_t;

int Init_FlowHash(uint32_t cacheSize, uint32_t expireActive, uint32_t expireInactive);

void Init_NodeAllocator(void);

void Dispose_NodeAllocator(void);

void Dispose_FlowTree(void);

uint32_t Hash_Flush(NodeList_t *NodeList, time_t when);

struct FlowNode *Lookup_Node(struct FlowNode *node);

struct FlowNode *New_Node(void);

void printFlowKey(struct FlowNode *node);

void printHash(void);

void Free_Node(struct FlowNode *node);

void CacheCheck(NodeList_t *NodeList, time_t when);

struct FlowNode *Insert_Node(struct FlowNode *node);

void Remove_Node(struct FlowNode *node);

int Link_RevNode(struct FlowNode *node);

// Node list functions
NodeList_t *NewNodeList(void);

void DisposeNodeList(NodeList_t *NodeList);

void Push_Node(NodeList_t *NodeList, struct FlowNode *node);

struct FlowNode *Pop_Node(NodeList_t *NodeList);

size_t Pop_Batch(NodeList_t *NodeList, struct FlowNode **out, size_t max);

void Push_SyncNode(NodeList_t *NodeList, time_t timestamp);

void TimeWheel_Reschedule(struct FlowNode *node, time_t now);

#endif  // _FLOWHASH_H
