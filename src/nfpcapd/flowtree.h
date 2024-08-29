/*
 *  Copyright (c) 2011-2022, Peter Haag
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

#ifndef _FLOWTREE_H
#define _FLOWTREE_H 1

#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

#include "config.h"
#include "nfdump.h"
#include "nfxV3.h"
#include "rbtree.h"

#define v4 ip_addr._v4
#define v6 ip_addr._v6

typedef struct flowTreeStat_s {
    size_t activeNodes;
    size_t flowNodes;
    size_t fragNodes;
} flowTreeStat_t;

struct FlowNode {
    // tree
    RB_ENTRY(FlowNode) entry;

    // linked list
    struct FlowNode *left;
    struct FlowNode *right;

    // flow key
    struct flowKey_s {
        // IP addr
        ip_addr_t src_addr;
        ip_addr_t dst_addr;

        uint16_t src_port;
        uint16_t dst_port;
        uint8_t proto;
        uint8_t version;
        uint16_t _ALIGN;  // empty but aligned
    } flowKey;
    // End of flow key

#define NODE_FREE 0xA5
#define NODE_IN_USE 0x5A
    uint8_t memflag;  // internal housekeeping flag
#define FLOW_NODE 1
#define SIGNAL_NODE 2
#define FRAG_NODE 3
    uint8_t nodeType;
    uint8_t flags;
#define SIGNAL_FIN 1
#define SIGNAL_SYNC 254
#define SIGNAL_DONE 255
    uint8_t signal;  //    1: fin received - end of flow
                     //  254: empty node - used to rotate file
                     //  255: empty node - used to terminate flow thread

    // vlan label
    uint32_t vlanID;

    // tunnel data
    ip_addr_t tun_src_addr;
    ip_addr_t tun_dst_addr;
    uint8_t tun_proto;
    uint8_t tun_ip_version;

    // pf data
    uint8_t action;
    uint8_t reason;
    uint32_t ruleNr;

    // flow stat data
    union {
        struct timeval t_first;  // used for file rotation
        time_t timestamp;        // used for flow dumping
    };
    struct timeval t_last;

    uint32_t packets;  // summed up number of packets
    uint32_t bytes;    // summed up number of bytes

    void *pflog;
    void *payload;         // payload
    uint32_t payloadSize;  // Size of payload
    uint8_t ttl;
    uint8_t fragmentFlags;
    uint16_t align;
    uint32_t mpls[10];
    uint64_t srcMac;
    uint64_t dstMac;

    struct FlowNode *rev_node;
    struct latency_s {
        uint64_t client;
        uint64_t server;
        uint64_t application;
        uint32_t flag;
    } latency;
};

typedef struct NodeList_s {
    struct FlowNode *list;
    struct FlowNode *last;
    pthread_mutex_t m_list;
    pthread_cond_t c_list;
    uint32_t length;
    uint32_t waiting;
    uint64_t waits;
} NodeList_t;

/* flow tree type */
typedef RB_HEAD(FlowTree, FlowNode) FlowTree_t;

// Insert the RB prototypes here
RB_PROTOTYPE(FlowTree, FlowNode, entry, FlowNodeCMP);

int Init_FlowTree(uint32_t CacheSize, int32_t expireActive, int32_t expireInactive);

void Dispose_FlowTree(void);

uint32_t Flush_FlowTree(NodeList_t *NodeList, time_t when);

uint32_t Expire_FlowTree(NodeList_t *NodeList, time_t when);

struct FlowNode *Lookup_Node(struct FlowNode *node);

struct FlowNode *New_Node(void);

void Free_Node(struct FlowNode *node);

void CacheCheck(NodeList_t *NodeList, time_t when);

int AddNodeData(struct FlowNode *node, uint32_t seq, void *payload, uint32_t size);

struct FlowNode *Insert_Node(struct FlowNode *node);

void Remove_Node(struct FlowNode *node);

int Link_RevNode(struct FlowNode *node);

// Node list functions
NodeList_t *NewNodeList(void);

void DisposeNodeList(NodeList_t *NodeList);

void Push_Node(NodeList_t *NodeList, struct FlowNode *node);

struct FlowNode *Pop_Node(NodeList_t *NodeList);

void Push_SyncNode(NodeList_t *NodeList, time_t timestamp);

void DumpList(NodeList_t *NodeList);

#endif  // _FLOWTREE_H
