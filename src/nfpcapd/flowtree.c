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

static int ExtendCache(void);

static int FlowNodeCMP(struct FlowNode *e1, struct FlowNode *e2);

static void DumpTreeStat(NodeList_t *NodeList);

// Insert the IP RB tree code here
RB_GENERATE(FlowTree, FlowNode, entry, FlowNodeCMP);

// Flow Cache to store all nodes
#define EXPIREINTERVALL 10
#define DefaultCacheSize (512 * 1024)
#define ExtentSize 4096
#define MaxSize (1024 * 1024 * 512)
static uint32_t FlowCacheSize = 0;
static time_t lastExpire = 0;
static uint32_t expireActiveTimeout = 300;
static uint32_t expireInactiveTimeout = 60;
static struct FlowNode *FlowElementCache = NULL;

// free list
static struct FlowNode *FlowNode_FreeList = NULL;
static pthread_mutex_t m_FreeList = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t c_FreeList = PTHREAD_COND_INITIALIZER;
static uint32_t EmptyFreeList = 0;
static uint32_t EmptyFreeListEvents = 0;
static uint32_t Allocated = 0;

// Flow tree
static FlowTree_t *FlowTree = NULL;
static int NumFlows = 0;
static flowTreeStat_t flowTreeStat = {0};

/* Free list handling functions */
// Get next free node from free list
struct FlowNode *New_Node(void) {
    struct FlowNode *node;

    pthread_mutex_lock(&m_FreeList);
    while (FlowNode_FreeList == NULL) {
        EmptyFreeList = 1;
        EmptyFreeListEvents++;
        if (FlowCacheSize < MaxSize) {
            dbg_printf("Auto expand flow cache\n");
            if (!ExtendCache()) abort();
        } else {
            LogError("Max cache size reached");
            pthread_cond_wait(&c_FreeList, &m_FreeList);
        }
    }

    node = FlowNode_FreeList;
    if (node->memflag != NODE_FREE) {
        LogError("New_Node() unexpected error in %s line %d: %s", __FILE__, __LINE__, "Tried to allocate a non free Node");
        abort();
    }

    FlowNode_FreeList = node->next;
    Allocated++;
    pthread_mutex_unlock(&m_FreeList);

    node->next = NULL;
    node->memflag = NODE_IN_USE;

    return node;

}  // End of New_Node

// return node into free list
void Free_Node(struct FlowNode *node) {
    if (node->memflag == NODE_FREE) {
        LogError("Free_Node() Fatal: Tried to free an already freed Node");
        abort();
    }

    if (node->memflag != NODE_IN_USE) {
        LogError("Free_Node() Fatal: Tried to free a Node not in use");
        abort();
    }

    if (node->coldNode.payload) free(node->coldNode.payload);
    if (node->coldNode.pflog) free(node->coldNode.pflog);

    dbg_assert(node->next == NULL);
    memset((void *)node, 0, sizeof(struct FlowNode));

    pthread_mutex_lock(&m_FreeList);
    node->next = FlowNode_FreeList;
    node->memflag = NODE_FREE;
    FlowNode_FreeList = node;
    Allocated--;
    if (EmptyFreeList) {
        EmptyFreeList = 0;
        pthread_cond_signal(&c_FreeList);
    }
    pthread_mutex_unlock(&m_FreeList);

}  // End of Free_Node

static int ExtendCache(void) {
    struct FlowNode *extent = calloc(ExtentSize, sizeof(struct FlowNode));
    if (!extent) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    struct FlowNode *current = FlowNode_FreeList;
    FlowNode_FreeList = extent;
    FlowNode_FreeList->next = &extent[1];
    FlowNode_FreeList->memflag = NODE_FREE;
    int i;
    for (i = 1; i < (ExtentSize - 1); i++) {
        extent[i].memflag = NODE_FREE;
        extent[i].next = &extent[i + 1];
    }
    extent[i].next = current;
    extent[i].memflag = NODE_FREE;

    dbg_printf("Extended cache: %u -> %u\n", FlowCacheSize, FlowCacheSize + ExtentSize);
    FlowCacheSize += ExtentSize;

    return 1;

}  // End of ExtendCache

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
        if (!ExtendCache()) return 0;

    EmptyFreeList = 0;
    Allocated = 0;
    NumFlows = 0;

    return 1;
}  // End of Init_FlowTree

void Dispose_FlowTree(void) {
    struct FlowNode *node, *nxt;

    // Dump all incomplete flows to the file
    nxt = NULL;
    for (node = RB_MIN(FlowTree, FlowTree); node != NULL; node = nxt) {
        nxt = RB_NEXT(FlowTree, FlowTree, node);
        Remove_Node(node);
    }
    free(FlowElementCache);
    FlowElementCache = NULL;
    FlowNode_FreeList = NULL;
    EmptyFreeList = 0;

}  // End of Dispose_FlowTree

/* safety check - this must never become 0 - otherwise the cache is too small */
void CacheCheck(NodeList_t *NodeList, time_t when) {
    dbg_printf("Cache check: ");
    if (lastExpire == 0) {
        lastExpire = when;
        dbg_printf("Init\n");
        return;
    }
    if ((when - lastExpire) > EXPIREINTERVALL) {
        uint32_t num __attribute__((unused)) = Expire_FlowTree(NodeList, when);
        dbg_printf("  Expire cache: %u\n", num);
        lastExpire = when;
    }

}  // End of CacheCheck

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
        if (node->hotNode.nodeType == FLOW_NODE)
            flowTreeStat.flowNodes++;
        else if (node->hotNode.nodeType == FRAG_NODE)
            flowTreeStat.fragNodes++;
        NumFlows++;
        return NULL;
    }
}  // End of Insert_Node

void Remove_Node(struct FlowNode *node) {
    struct FlowNode *rev_node;

#ifdef DEVEL
    assert(node->memflag == NODE_IN_USE);
    if (NumFlows == 0) {
        LogError("Remove_Node() Fatal Tried to remove a Node from empty tree");
        return;
    }
#endif

    rev_node = node->coldNode.rev_node;
    if (rev_node) {
        // unlink rev node on both nodes
        dbg_assert(rev_node->coldNode.rev_node == node);
        rev_node->coldNode.rev_node = NULL;
        node->coldNode.rev_node = NULL;
    }
    RB_REMOVE(FlowTree, FlowTree, node);
    NumFlows--;

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
        if (node->hotNode.nodeType == FRAG_NODE) {
            Free_Node(node);
        } else {
            Push_Node(NodeList, node);
        }
    }

    node = New_Node();
    node->timestamp = when;
    node->hotNode.nodeType = SIGNAL_NODE;
    node->hotNode.signal = SIGNAL_DONE;
    Push_Node(NodeList, node);

    return 0;

}  // End of Flush_FlowTree

uint32_t Expire_FlowTree(NodeList_t *NodeList, time_t when) {
    struct FlowNode *node, *nxt;

    if (NumFlows == 0) return 0;

    uint32_t flowCnt = 0;
    uint32_t fragCnt = 0;
    // Dump all incomplete flows to the file
    nxt = NULL;
    for (node = RB_MIN(FlowTree, FlowTree); node != NULL; node = nxt) {
        nxt = RB_NEXT(FlowTree, FlowTree, node);
        if ((node->hotNode.nodeType == FLOW_NODE) &&
            // inactive timeout
            ((when - node->hotNode.t_last.tv_sec) > expireInactiveTimeout ||
             // active timeout
             (when - node->hotNode.t_first.tv_sec) > expireActiveTimeout || when == 0)) {
            Remove_Node(node);
            Push_Node(NodeList, node);
            flowTreeStat.activeNodes--;
            flowTreeStat.flowNodes--;
            flowCnt++;
        } else if ((node->hotNode.nodeType == FRAG_NODE) && ((when - node->hotNode.t_last.tv_sec) > 15 || when == 0)) {
            Remove_Node(node);
            Free_Node(node);
            flowTreeStat.activeNodes--;
            flowTreeStat.fragNodes--;
        }
    }

    if (flowCnt || fragCnt)
        LogVerbose("Expired flow nodes: %u, expired frag nodes: %u, active tree nodes: %u, allocated nodes %u", flowCnt, fragCnt,
                   flowTreeStat.activeNodes, Allocated);

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
    LogInfo("Nodes: in use: %u, Flows: %u, Frag: %u, Nodes list length: %u, Waiting for freelist: %u", Allocated, flowTreeStat.activeNodes,
            flowTreeStat.fragNodes, NodeList->length, EmptyFreeListEvents);
    EmptyFreeListEvents = 0;
}  // End of DumpTreeStat

void Push_Node(NodeList_t *NodeList, struct FlowNode *node) {
    pthread_mutex_lock(&NodeList->m_list);

    if (NodeList->length == 0) {
        NodeList->list = node;
        node->next = NULL;
    } else {
        NodeList->last->next = node;
        node->next = NULL;
    }
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
}  // Ed of Pop_Node

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
    Node->hotNode.nodeType = SIGNAL_NODE;
    Node->hotNode.signal = SIGNAL_SYNC;
    Push_Node(NodeList, Node);
    DumpTreeStat(NodeList);

}  // End of Push_SyncNode
