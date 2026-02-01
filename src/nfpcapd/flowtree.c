/*
 *  Copyright (c) 2011-2025, Peter Haag
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

#include "flowtree.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "nfdump.h"
#include "nffile.h"
#include "util.h"

static int Extend_NodeCache(void);

static int FlowNodeCMP(struct FlowNode *e1, struct FlowNode *e2);

static void DumpTreeStat(NodeList_t *NodeList);

static size_t NodeList_length(NodeList_t *NodeList);

// Insert the IP RB tree code here
RB_GENERATE(FlowTree, FlowNode, entry, FlowNodeCMP);

// Flow Cache to store all nodes
#define EXPIREINTERVALL 10
#define DefaultCacheSize 8192
#define ExtentSize 4096
#define MaxSize (1024 * 1024 * 512)
static time_t lastExpire = 0;
static uint32_t expireActiveTimeout = 300;
static uint32_t expireInactiveTimeout = 60;

static _Atomic uint32_t Allocated = 0;

static struct FlowSlab *SlabList = NULL;
static struct FlowSlab *PreferredSlab = NULL;
static uint32_t FlowCacheSize = 0;
static pthread_t PacketThreadID;
static uint32_t LastExpireCount = 0;
static time_t LastShrinkTime = 0;

/*
 * node cache
 * The node cache builds up on a list of slabs. Each slab has ExtentSize nodes.
 * The minimum node cahce size is DefaultCacheSize nodes.
 * New slabs may be allocated, if more node are required (busy network, or packet peak)
 * Empty slab are freed, if they are no longer needed.
 * The current implementation works under the current design:
 * 1 packet thread, 1 flow thread
 * All slab maintainance such as Extend_NodeCache Shrink_NodeCache, drain remote_frees and
 * New_Node are touched exclusively by the packet thread and the flow thread exclusively
 * calls Free_node() and atomically add the freed node to remote_free. If this changes
 * the design needs to be adapted accordingly.
 */

// Flow tree
static FlowTree_t *FlowTree = NULL;
static flowTreeStat_t flowTreeStat = {0};
static struct FlowSlab *QuarantineList = NULL;

static inline void drain_remote_frees(struct FlowSlab *slab) {
    struct FlowNode *list = atomic_exchange_explicit(&slab->remote_free, NULL, memory_order_acquire);

    while (list) {
        struct FlowNode *n = list;
        list = n->next;

        n->next = slab->local_free;
        slab->local_free = n;
    }
}  // End of drain_remote_frees

void Init_NodeAllocator(void) {
    // self
    PacketThreadID = pthread_self();
}  // End of Init_NodeAllocator

/* flow tree functions */
int Init_FlowTree(uint32_t CacheSize, uint32_t expireActive, uint32_t expireInactive) {
    if (expireActive) {
        expireActiveTimeout = expireActive;
        LogInfo("Set active flow expire timeout to %us", expireActiveTimeout);
    }

    if (expireInactive) {
        expireInactiveTimeout = expireInactive;
        LogInfo("Set inactive flow expire timeout to %us", expireInactiveTimeout);
    }

    FlowTree = malloc(sizeof(FlowTree_t));
    if (!FlowTree) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }
    RB_INIT(FlowTree);

    if (CacheSize == 0) CacheSize = DefaultCacheSize;

    while (FlowCacheSize < CacheSize)
        if (!Extend_NodeCache()) return 0;

    Allocated = 0;
    PreferredSlab = SlabList;

    LogInfo("Init flow cache size: %u nodes", FlowCacheSize);
    return 1;
}  // End of Init_FlowTree

void Dispose_NodeAllocator(void) {
    struct FlowSlab *s = SlabList;
    while (s) {
        struct FlowSlab *next = s->next;

        uint32_t in_use = atomic_load_explicit(&s->in_use, memory_order_relaxed);
        if (in_use != 0) {
            LogError("Dispose_NodeAllocator(): slab still has %u allocated nodes", in_use);
        }
        free(s);

        s = next;
    }

    SlabList = NULL;
    /* free any slabs that were moved to quarantine */
    struct FlowSlab *qs = QuarantineList;
    while (qs) {
        struct FlowSlab *next = qs->next;

        uint32_t in_use = atomic_load_explicit(&qs->in_use, memory_order_relaxed);
        if (in_use != 0) {
            LogError("Dispose_NodeAllocator(): quarantined slab still has %u allocated nodes", in_use);
        }

        /* drain any pending remote frees (best effort) */
        drain_remote_frees(qs);
        free(qs);

        qs = next;
    }
    QuarantineList = NULL;
    FlowCacheSize = 0;

}  // End of Dispose_NodeAllocator

void Dispose_FlowTree(void) {
    struct FlowNode *node, *nxt;

    // Dump all incomplete flows to the file
    nxt = NULL;
    for (node = RB_MIN(FlowTree, FlowTree); node != NULL; node = nxt) {
        nxt = RB_NEXT(FlowTree, FlowTree, node);
        Remove_Node(node);
    }

    Dispose_NodeAllocator();

}  // End of Dispose_FlowTree

struct FlowNode *New_Node(void) {
    struct FlowSlab *s;

    // used by packet thread only
    // First try preferred slab
    s = PreferredSlab;
    if (s) {
        if (!s->local_free) drain_remote_frees(s);
        if (s->local_free) {
            struct FlowNode *n = s->local_free;
            s->local_free = n->next;

            atomic_fetch_add_explicit(&s->in_use, 1, memory_order_relaxed);
            atomic_fetch_add_explicit(&Allocated, 1, memory_order_relaxed);

            n->next = NULL;
            n->memflag = NODE_IN_USE;
            n->nodeType = FLOW_NODE;
            return n;
        }
    }

    // Fallback: scan all slabs
    for (s = SlabList; s; s = s->next) {
        if (!s->local_free) drain_remote_frees(s);
        if (s->local_free) {
            PreferredSlab = s;
            struct FlowNode *n = s->local_free;
            s->local_free = n->next;

            atomic_fetch_add_explicit(&s->in_use, 1, memory_order_relaxed);
            atomic_fetch_add_explicit(&Allocated, 1, memory_order_relaxed);

            n->next = NULL;
            n->memflag = NODE_IN_USE;
            n->nodeType = FLOW_NODE;
            return n;
        }
    }

    if (FlowCacheSize >= MaxSize) return NULL;
    if (!Extend_NodeCache()) return NULL;

    PreferredSlab = SlabList;  // newest slab

    return New_Node();
}  // End of New_Node

// return node into free list
void Free_Node(struct FlowNode *node) {
    dbg_printf("Enter %s\n", __func__);

    if (node->memflag != NODE_IN_USE) {
        LogError("Free_Node() Fatal: Tried to free a node not in use");
        abort();
    }

    // cleanup node
    if (node->coldNode.payload) free(node->coldNode.payload);
    if (node->coldNode.pflog) free(node->coldNode.pflog);
    memset((void *)&node->hotNode, 0, sizeof(hotNode_t));
    memset((void *)&node->coldNode, 0, sizeof(coldNode_t));

    struct FlowSlab *s = node->slab;

    node->memflag = NODE_FREE;
    if (pthread_equal(PacketThreadID, pthread_self())) {
        // local free - packet thread
        node->next = s->local_free;
        s->local_free = node;
    } else {
        // remote free - flow_thread
        // If the slab is being removed, do not attempt to add to remote_free.
        // if removing is set we just decrement counters
        // and drop the node (slab will be reclaimed by packet thread).
        if (atomic_load_explicit(&s->removing, memory_order_acquire) == 0) {
            // best-effort push into remote_free using simple CAS loop
            struct FlowNode *old;
            do {
                old = atomic_load_explicit(&s->remote_free, memory_order_acquire);
                node->next = old;
            } while (!atomic_compare_exchange_weak_explicit(&s->remote_free, &old, node, memory_order_release, memory_order_relaxed));
        }
    }

    atomic_fetch_sub_explicit(&Allocated, 1, memory_order_relaxed);
    atomic_fetch_sub_explicit(&s->in_use, 1, memory_order_relaxed);
}  // End of Free_Node

static int Extend_NodeCache(void) {
    struct FlowSlab *slab = calloc(1, sizeof(struct FlowSlab) + ExtentSize * sizeof(struct FlowNode));
    if (!slab) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    slab->capacity = ExtentSize;
    atomic_init(&slab->in_use, 0);
    atomic_init(&slab->remote_free, NULL);
    atomic_init(&slab->removing, false);
    slab->removed_at = 0;

    for (uint32_t i = 0; i < ExtentSize; i++) {
        slab->nodes[i].slab = slab;
        slab->nodes[i].memflag = NODE_FREE;
        slab->nodes[i].next = slab->local_free;
        slab->local_free = &slab->nodes[i];
    }

    slab->next = SlabList;
    SlabList = slab;
    FlowCacheSize += ExtentSize;

    LogVerbose("Extended cache slab: %u -> %u", FlowCacheSize - ExtentSize, FlowCacheSize);
    return 1;
}  // End of Extend_NodeCache

// packet thread only
static void Shrink_NodeCache(time_t now) {
    if ((now - LastShrinkTime) < 10) return;

    uint32_t allocated = atomic_load_explicit(&Allocated, memory_order_relaxed);
    uint32_t slack = FlowCacheSize - allocated;

    // Only shrink if we have at least one full slab of slack
    // and never shrink below the default cache size
    if (slack < ExtentSize || FlowCacheSize <= DefaultCacheSize) return;

    // Never shrink below the default cache size
    uint32_t min_size = DefaultCacheSize;

    struct FlowSlab **pp = &SlabList;
    uint32_t oldCacheSize = FlowCacheSize;
    uint32_t quarantinedSlabs = 0;
    while (*pp && FlowCacheSize > min_size) {
        struct FlowSlab *s = *pp;

        drain_remote_frees(s);

        if (atomic_load_explicit(&s->in_use, memory_order_relaxed) == 0) {
            /* Move slab to quarantine: mark removing and unlink from SlabList.
             * Actual free is deferred and handled below after a grace period
             * to ensure no flow thread still touches slab memory. */
            atomic_store_explicit(&s->removing, true, memory_order_release);

            *pp = s->next;
            FlowCacheSize -= s->capacity;

            s->next = NULL;  // detach
            s->removed_at = now;
            /* prepend to quarantine list */
            s->next = QuarantineList;
            QuarantineList = s;
            quarantinedSlabs++;
            continue;
        }

        pp = &s->next;
    }

    // Sweep quarantine list: free slabs that have been quarantined since last 10s run
    uint32_t freedSlabs = 0;
    struct FlowSlab **qpp = &QuarantineList;
    while (*qpp) {
        struct FlowSlab *qs = *qpp;
        /* If the slab was moved to quarantine in this run (removed_at == now)
         * skip it; otherwise it's safe to attempt to free it now. */
        if (qs->removed_at == now) {
            qpp = &qs->next;
            continue;
        }

        // ensure no in-use nodes and no remote frees
        drain_remote_frees(qs);
        if (atomic_load_explicit(&qs->in_use, memory_order_relaxed) == 0 && atomic_load_explicit(&qs->remote_free, memory_order_relaxed) == NULL) {
            *qpp = qs->next;
            free(qs);
            freedSlabs++;
            continue;
        }

        qpp = &qs->next;
    }

    LastShrinkTime = now;

    LogVerbose("Adjust cache slab: %u -> %u. Slabs quarantined: %u, freed: %u", oldCacheSize, FlowCacheSize, quarantinedSlabs, freedSlabs);
}  // End of Shrink_NodeCache

void CacheCheck(NodeList_t *NodeList, time_t when) {
    dbg_printf("Cache check: ");
    if (lastExpire == 0) {
        lastExpire = when;
        dbg_printf("Init\n");
        return;
    }

    if ((when - lastExpire) > EXPIREINTERVALL) {
        uint32_t expired = Expire_FlowTree(NodeList, when);
        dbg_printf("  Expire cache: %u nodes\n", expired);
        LastExpireCount = expired;
        lastExpire = when;
    }

    Shrink_NodeCache(when);
}  // End of CacheCheck

void printFlowKey(struct FlowNode *node) {
    char srcAddr[INET6_ADDRSTRLEN];
    char dstAddr[INET6_ADDRSTRLEN];
    ip128_2_str(&node->hotNode.flowKey.src_addr, srcAddr);
    ip128_2_str(&node->hotNode.flowKey.dst_addr, dstAddr);
    printf("IP: %u, proto: %u, src: %s %u, dst: %s %u, align: %u\n", node->hotNode.flowKey.version, node->hotNode.flowKey.proto, srcAddr,
           node->hotNode.flowKey.src_port, dstAddr, node->hotNode.flowKey.dst_port, node->hotNode.flowKey._ALIGN);
}

void printTree(void) {
    struct FlowNode *node = NULL;
    struct FlowNode *nxt = NULL;
    printf("FlowTree %zu nodes:\n", flowTreeStat.activeNodes);
    for (node = RB_MIN(FlowTree, FlowTree); node != NULL; node = nxt) {
        printFlowKey(node);
        nxt = RB_NEXT(FlowTree, FlowTree, node);
    }
}

static int FlowNodeCMP(struct FlowNode *e1, struct FlowNode *e2) {
    int i = memcmp((void *)&e1->hotNode.flowKey, (void *)&e2->hotNode.flowKey, sizeof(e1->hotNode.flowKey));
    return i;
}  // End of FlowNodeCMP

struct FlowNode *Lookup_Node(struct FlowNode *node) { return RB_FIND(FlowTree, FlowTree, node); }  // End of Lookup_FlowTree

struct FlowNode *Insert_Node(struct FlowNode *node) {
    struct FlowNode *n;

    dbg_assert(node->next == NULL);

    // return RB_INSERT(FlowTree, FlowTree, node);
    n = RB_INSERT(FlowTree, FlowTree, node);
    if (n) {  // existing node
        return n;
    } else {
        flowTreeStat.activeNodes++;
        if (node->nodeType == FLOW_NODE)
            flowTreeStat.flowNodes++;
        else if (node->nodeType == FRAG_NODE)
            flowTreeStat.fragNodes++;
        node->inTree = 1;
        return NULL;
    }
}  // End of Insert_Node

void Remove_Node(struct FlowNode *node) {
    struct FlowNode *rev_node;

    assert(node->inTree == 1);

    dbg_assert(node->memflag == NODE_IN_USE);

    rev_node = node->coldNode.rev_node;
    if (rev_node) {
        // unlink rev node on both nodes
        dbg_assert(rev_node->coldNode.rev_node == node);
        rev_node->coldNode.rev_node = NULL;
        node->coldNode.rev_node = NULL;
    }

    RB_REMOVE(FlowTree, FlowTree, node);

    flowTreeStat.activeNodes--;
    if (node->nodeType == FLOW_NODE)
        flowTreeStat.flowNodes--;
    else if (node->nodeType == FRAG_NODE)
        flowTreeStat.fragNodes--;

    node->inTree = 0;

}  // End of Remove_Node

int Link_RevNode(struct FlowNode *node) {
    struct FlowNode lookup_node, *rev_node;

    dbg_printf("Link node: ");
    dbg_assert(node->coldNode.rev_node == NULL);
    lookup_node.hotNode.flowKey._ALIGN = 0;
    lookup_node.hotNode.flowKey.proto = node->hotNode.flowKey.proto;
    lookup_node.hotNode.flowKey.version = node->hotNode.flowKey.version;
    // reverse lookup key to find reverse node
    lookup_node.hotNode.flowKey.src_addr = node->hotNode.flowKey.dst_addr;
    lookup_node.hotNode.flowKey.dst_addr = node->hotNode.flowKey.src_addr;
    lookup_node.hotNode.flowKey.src_port = node->hotNode.flowKey.dst_port;
    lookup_node.hotNode.flowKey.dst_port = node->hotNode.flowKey.src_port;
    rev_node = Lookup_Node(&lookup_node);
    if (rev_node) {
        dbg_printf("Found revnode ");
        // rev node must not be linked already - otherwise there is an inconsistency
        if (node->coldNode.rev_node == NULL) {
            // link both nodes
            node->coldNode.rev_node = rev_node;
            rev_node->coldNode.rev_node = node;
            dbg_printf(" - linked\n");
        } else {
            dbg_printf("Rev-node != NULL skip linking - inconsistency\n");
            LogError("Rev-node != NULL skip linking - inconsistency\n");
        }
        return 1;
    } else {
        dbg_printf("no revnode node\n");
        return 0;
    }

    /* not reached */

}  // End of Link_RevNode

uint32_t Flush_FlowTree(NodeList_t *NodeList, time_t when) {
    struct FlowNode *node, *nxt;

    // Dump all incomplete flows to the file
    nxt = NULL;
    for (node = RB_MIN(FlowTree, FlowTree); node != NULL; node = nxt) {
        nxt = RB_NEXT(FlowTree, FlowTree, node);
        Remove_Node(node);
        if (node->nodeType == FRAG_NODE) {
            Free_Node(node);
        } else {
            Push_Node(NodeList, node);
        }
    }

    node = New_Node();
    node->timestamp = when;
    node->nodeType = SIGNAL_NODE_DONE;
    dbg_printf("Push signal_node_done\n");
    Push_Node(NodeList, node);

    return 0;

}  // End of Flush_FlowTree

uint32_t Expire_FlowTree(NodeList_t *NodeList, time_t when) {
    struct FlowNode *node, *nxt;

    if (flowTreeStat.activeNodes == 0) return 0;

    uint32_t flowCnt = 0;
    uint32_t fragCnt = 0;
    // Dump all incomplete flows to the file
    nxt = NULL;
    for (node = RB_MIN(FlowTree, FlowTree); node != NULL; node = nxt) {
        nxt = RB_NEXT(FlowTree, FlowTree, node);
        if ((node->nodeType == FLOW_NODE) &&
            // inactive timeout
            ((when - node->hotNode.t_last.tv_sec) > expireInactiveTimeout ||
             // active timeout
             (when - node->hotNode.t_first.tv_sec) > expireActiveTimeout || when == 0)) {
            Remove_Node(node);
            Push_Node(NodeList, node);
            flowCnt++;
        } else if ((node->nodeType == FRAG_NODE) && ((when - node->hotNode.t_last.tv_sec) > 15 || when == 0)) {
            Remove_Node(node);
            Free_Node(node);
            fragCnt++;
        }
    }

    if (flowCnt || fragCnt) {
        LogVerbose("Expired flow nodes: %u, frag nodes: %u. Active flow nodes: %d, frag nodes: %u", flowCnt, fragCnt, flowTreeStat.flowNodes,
                   flowTreeStat.fragNodes);
        LogVerbose("Node cache size: %u, allocated %u, cache size: %zd, queue size: %zu", FlowCacheSize, Allocated, flowTreeStat.activeNodes,
                   NodeList_length(NodeList));
    }

    return flowCnt + fragCnt;
}  // End of Expire_FlowTree

/* Node list functions */
NodeList_t *NewNodeList(void) {
    NodeList_t *NodeList;

    NodeList = (NodeList_t *)malloc(sizeof(NodeList_t));
    if (!NodeList) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }
    NodeList->list = NULL;
    NodeList->last = NULL;
    NodeList->length = 0;
    pthread_mutex_init(&NodeList->m_list, NULL);
    pthread_cond_init(&NodeList->c_list, NULL);

    return NodeList;

}  // End of NewNodeList

void DisposeNodeList(NodeList_t *NodeList) {
    if (!NodeList) return;

    if (NodeList->length) {
        LogError("Try to free non empty NodeList");
        return;
    }
    free(NodeList);

}  // End of DisposeNodeList

static void DumpTreeStat(NodeList_t *NodeList) {
    LogVerbose("Node cache size: %u, in use %u, cache size: %zu, queue size: %zu", FlowCacheSize, Allocated, flowTreeStat.activeNodes,
               NodeList_length(NodeList));
}  // End of DumpTreeStat

void Push_Node(NodeList_t *NodeList, struct FlowNode *node) {
    pthread_mutex_lock(&NodeList->m_list);

    dbg_assert(node->nodeType != 0);
    if (NodeList->length == 0) {
        NodeList->list = node;
    } else {
        NodeList->last->next = node;
    }
    node->next = NULL;
    NodeList->last = node;
    NodeList->length++;

    pthread_cond_signal(&NodeList->c_list);
    pthread_mutex_unlock(&NodeList->m_list);

}  // End of Push_Node

struct FlowNode *Pop_Node(NodeList_t *NodeList) {
    struct FlowNode *node;

    pthread_mutex_lock(&NodeList->m_list);
    while (NodeList->length == 0) {
        pthread_cond_wait(&NodeList->c_list, &NodeList->m_list);
    }

    node = NodeList->list;
    NodeList->list = node->next;
    node->next = NULL;

    if (NodeList->list == NULL) NodeList->last = NULL;

    NodeList->length--;
    pthread_mutex_unlock(&NodeList->m_list);

    return node;
}  // End of Pop_Node

static size_t NodeList_length(NodeList_t *NodeList) {
    size_t length = 0;
    pthread_mutex_lock(&NodeList->m_list);
    length = NodeList->length;
    pthread_mutex_unlock(&NodeList->m_list);
    return length;
}  // End of NodeList_length

size_t Pop_Batch(NodeList_t *NodeList, struct FlowNode **out, size_t max) {
    size_t n = 0;

    pthread_mutex_lock(&NodeList->m_list);
    while (NodeList->length == 0) {
        pthread_cond_wait(&NodeList->c_list, &NodeList->m_list);
    }

    while (n < max && NodeList->length > 0) {
        struct FlowNode *node = NodeList->list;
        NodeList->list = node->next;
        if (NodeList->list == NULL) NodeList->last = NULL;

        NodeList->length--;
        node->next = NULL;
        out[n++] = node;
    }
    pthread_mutex_unlock(&NodeList->m_list);

    return n;
}  // End of Pop_Batch

void Push_SyncNode(NodeList_t *NodeList, time_t timestamp) {
    struct FlowNode *Node = New_Node();
    Node->timestamp = timestamp;
    Node->nodeType = SIGNAL_NODE_SYNC;
    dbg_printf("Push sync node\n");
    Push_Node(NodeList, Node);
    DumpTreeStat(NodeList);

}  // End of Push_SyncNode
