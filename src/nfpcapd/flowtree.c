/*
 *  Copyright (c) 2011-2021, Peter Haag
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <assert.h>

#include "util.h"
#include "nfdump.h"
#include "nffile.h"
#include "flowtree.h"

static int ExtendCache(void);

static int FlowNodeCMP(struct FlowNode *e1, struct FlowNode *e2);

// Insert the IP RB tree code here
RB_GENERATE(FlowTree, FlowNode, entry, FlowNodeCMP);

// Flow Cache to store all nodes
#define EXPIREINTERVALL 10
#define DefaultCacheSize (512 * 1024)
#define ExtentSize  4096
#define MaxSize  (1024 * 1024 * 512)
static uint32_t FlowCacheSize = 0;
static time_t   lastExpire = 0;
static uint32_t expireActiveTimeout = 300;
static uint32_t expireInactiveTimeout = 60;
static struct FlowNode *FlowElementCache;

// free list 
static struct FlowNode *FlowNode_FreeList;
static pthread_mutex_t m_FreeList = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  c_FreeList = PTHREAD_COND_INITIALIZER;
static uint32_t	EmptyFreeList;
static uint32_t	EmptyFreeListEvents = 0;
static uint32_t	Allocated;

// Flow tree
static FlowTree_t *FlowTree;
static int NumFlows = 0;

// Simple unprotected list
typedef struct FlowNode_list_s {
	struct FlowNode *list;
	struct FlowNode *tail;
	uint32_t	size;
} Linked_list_t;

/* Free list handling functions */
// Get next free node from free list
struct FlowNode *New_Node(void) {
struct FlowNode *node;

	pthread_mutex_lock(&m_FreeList);
    while ( FlowNode_FreeList == NULL ) {
		EmptyFreeList = 1;
		EmptyFreeListEvents++;
		if ( FlowCacheSize < MaxSize) {
			dbg_printf("Auto expand flow cache\n");
			if (!ExtendCache())
				abort();
		} else {
			LogError("Max cache size reached");
        	pthread_cond_wait(&c_FreeList, &m_FreeList);
		}
	}

	node = FlowNode_FreeList;
	if ( node->memflag != NODE_FREE ) {
		LogError("New_Node() unexpected error in %s line %d: %s\n", 
			__FILE__, __LINE__, "Tried to allocate a non free Node");
		abort();
	}

	FlowNode_FreeList = node->right;
	Allocated++;
	pthread_mutex_unlock(&m_FreeList);

	node->left 	  = NULL;
	node->right	  = NULL;
	node->memflag = NODE_IN_USE;

	return node;

} // End of New_Node

// return node into free list
void Free_Node(struct FlowNode *node) {

	if ( node->memflag == NODE_FREE ) {
		LogError("Free_Node() Fatal: Tried to free an already freed Node");
		abort();
	}

	if ( node->memflag != NODE_IN_USE ) {
		LogError("Free_Node() Fatal: Tried to free a Node not in use");
		abort();
	}

	if ( node->payload ) 
		free(node->payload);

	dbg_assert(node->left == NULL);
	dbg_assert(node->right == NULL);

	memset((void *)node, 0, sizeof(struct FlowNode));

	pthread_mutex_lock(&m_FreeList);
	node->right = FlowNode_FreeList;
	node->left  = NULL;
	node->memflag = NODE_FREE;
	FlowNode_FreeList = node;
	Allocated--;
	if ( EmptyFreeList ) {
		EmptyFreeList = 0;
		pthread_cond_signal(&c_FreeList);
	}
	pthread_mutex_unlock(&m_FreeList);

} // End of Free_Node

static int ExtendCache(void) {

	struct FlowNode *extent = calloc(ExtentSize, sizeof(struct FlowNode));
	if ( !extent ) {
		LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
		return 0;
	}

	struct FlowNode *current   = FlowNode_FreeList;
	FlowNode_FreeList 		   = extent;
	FlowNode_FreeList->left    = NULL;
	FlowNode_FreeList->right   = &extent[1];
	FlowNode_FreeList->memflag = NODE_FREE;
	int i;
	for (i=1; i < (ExtentSize-1); i++ ) {
		extent[i].memflag = NODE_FREE;
		extent[i].left  = &extent[i-1];
		extent[i].right = &extent[i+1];
	}
	extent[i].left	  = &extent[i-1];
	extent[i].right   = current;
	extent[i].memflag = NODE_FREE;

	dbg_printf("Extended cache: %u -> %u\n", FlowCacheSize, FlowCacheSize + ExtentSize);
	FlowCacheSize += ExtentSize;

	return 1;

} // End of ExtendCache

/* flow tree functions */
int Init_FlowTree(uint32_t CacheSize, int32_t expireActive, int32_t expireInactive) {

	if ( expireActive ) {
		if ( expireActive < 0 || expireActive > 3600 ) {
			LogError("Active flow timeout %d out of range", expireActive);
			return 0;
		}
		expireActiveTimeout = expireActive;
		LogInfo("Set active flow expire timout to %us", expireActiveTimeout);
	}

	if ( expireInactive ) {
		if ( expireInactive < 0 || expireInactive > 3600 ) {
			LogError("Inactive flow timeout %d out of range", expireInactive);
			return 0;
		}
		expireInactiveTimeout = expireInactive;
		LogInfo("Set inactive flow expire timout to %us", expireInactiveTimeout);
	}

	FlowTree = malloc(sizeof(FlowTree_t));
	if ( !FlowTree ) {
		LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
		return 0;
	}
	RB_INIT(FlowTree);

	if ( CacheSize == 0 )
		CacheSize = DefaultCacheSize;

	while (FlowCacheSize < CacheSize)
		if (!ExtendCache())
			return 0;

	EmptyFreeList = 0;
	Allocated 	  = 0;
	NumFlows 	  = 0;

	return 1;
} // End of Init_FlowTree

void Dispose_FlowTree(void) {
struct FlowNode *node, *nxt;

	// Dump all incomplete flows to the file
	nxt = NULL;
	for (node = RB_MIN(FlowTree, FlowTree); node != NULL; node = nxt) {
		nxt = RB_NEXT(FlowTree, FlowTree, node);
		Remove_Node(node);
	}
	free(FlowElementCache);
	FlowElementCache 	 = NULL;
	FlowNode_FreeList 	 = NULL;
	EmptyFreeList = 0;

} // End of Dispose_FlowTree

/* safety check - this must never become 0 - otherwise the cache is too small */
void CacheCheck(NodeList_t *NodeList, time_t when) {

	dbg_printf("Cache check: ");
	if ( lastExpire == 0 ) {
		lastExpire = when;
		dbg_printf("Init\n");
		return;
	}
	if ( (when - lastExpire) > EXPIREINTERVALL ) {
		uint32_t num __attribute__((unused)) = Expire_FlowTree(NodeList, when);
		dbg_printf("  Expire cache: %u\n", num);
		lastExpire = when;
	}

} // End of CacheCheck


static int FlowNodeCMP(struct FlowNode *e1, struct FlowNode *e2) {
uint64_t *a = e1->src_addr.v6;
uint64_t *b = e2->src_addr.v6;
int i;

#define CMPLEN (offsetof(struct FlowNode, _ENDKEY_) - offsetof(struct FlowNode, src_addr))

	i = memcmp((void *)a, (void *)b, CMPLEN );
	return i; 
 
} // End of FlowNodeCMP

struct FlowNode *Lookup_Node(struct FlowNode *node) {
	return RB_FIND(FlowTree, FlowTree, node);
} // End of Lookup_FlowTree

struct FlowNode *Insert_Node(struct FlowNode *node) {
struct FlowNode *n;

	dbg_assert(node->left == NULL);
	dbg_assert(node->right == NULL);

	// return RB_INSERT(FlowTree, FlowTree, node);
	n = RB_INSERT(FlowTree, FlowTree, node);
	if ( n ) { // existing node
		return n;
	} else {
		NumFlows++;
		return NULL;
	}
} // End of Insert_Node

void Remove_Node(struct FlowNode *node) {
struct FlowNode *rev_node;

#ifdef DEVEL
	assert(node->memflag == NODE_IN_USE);
	if ( NumFlows == 0 ) {
		LogError("Remove_Node() Fatal Tried to remove a Node from empty tree");
		return;
	}
#endif

	rev_node = node->rev_node;
	if ( rev_node ) {
		// unlink rev node on both nodes
		dbg_assert(rev_node->rev_node == node);
		rev_node->rev_node = NULL;
		node->rev_node	   = NULL;
	}
	RB_REMOVE(FlowTree, FlowTree, node);
	NumFlows--;

} // End of Remove_Node

int Link_RevNode(struct FlowNode *node) {
struct FlowNode lookup_node, *rev_node;

    dbg_printf("Link node: ");
    dbg_assert(node->rev_node == NULL);
    lookup_node.src_addr = node->dst_addr;
    lookup_node.dst_addr = node->src_addr;
    lookup_node.src_port = node->dst_port;
    lookup_node.dst_port = node->src_port;
    lookup_node.version  = node->version;
    lookup_node.proto    = node->proto;
    rev_node = Lookup_Node(&lookup_node);
    if ( rev_node ) { 
        dbg_printf("Found revnode ");
		// rev node must not be linked already - otherwise there is an inconsistency
		dbg_assert(node->rev_node == NULL);
        if (node->rev_node == NULL ) {
			// link both nodes
            node->rev_node = rev_node;
            rev_node->rev_node = node;
            dbg_printf(" - linked\n");
        } else {
            dbg_printf("Rev-node != NULL skip linking - inconsitency\n");
            LogError("Rev-node != NULL skip linking - inconsitency\n");
        }
		return 1;
    } else {
        dbg_printf("no revnode node\n");
		return 0;
    }

	/* not reached */

} // End of Link_RevNode

uint32_t Flush_FlowTree(NodeList_t *NodeList, time_t when) {
struct FlowNode *node, *nxt;
uint32_t n = NumFlows;

	// Dump all incomplete flows to the file
	nxt = NULL;
	for (node = RB_MIN(FlowTree, FlowTree); node != NULL; node = nxt) {
		nxt = RB_NEXT(FlowTree, FlowTree, node);
		Remove_Node(node);
		if ( node->nodeType == FRAG_NODE ) {
			Free_Node(node);
		} else {
			Push_Node(NodeList, node);
		}
	}

	if ( NumFlows != 0 )
		LogInfo("Flush_FlowTree() flushed flows: %u\n", NumFlows);

	node = New_Node();
	node->timestamp = when;
	node->nodeType  = SIGNAL_NODE;
	node->fin		= SIGNAL_DONE;
	Push_Node(NodeList, node);

	return n;

} // End of Flush_FlowTree

uint32_t Expire_FlowTree(NodeList_t *NodeList, time_t when) {
struct FlowNode *node, *nxt;

	if ( NumFlows == 0 )
		return 0;

	uint32_t expireCnt = 0;
	uint32_t fragCnt   = 0;
	// Dump all incomplete flows to the file
	nxt = NULL;
	for (node = RB_MIN(FlowTree, FlowTree); node != NULL; node = nxt) {
		nxt = RB_NEXT(FlowTree, FlowTree, node);
		if ( when == 0 || 
			 // inactive timeout
			 (when - node->t_last.tv_sec) > expireInactiveTimeout || 
			 // active timeout
			 (when - node->t_first.tv_sec) > expireActiveTimeout  ||
			 // fragment assembly timeout
			 (node->nodeType == FRAG_NODE && (when - node->t_last.tv_sec) > 15)) {
			Remove_Node(node);
			if ( node->nodeType == FRAG_NODE ) {
				fragCnt++;
				Free_Node(node);
			} else {
				Push_Node(NodeList, node);
			}
			expireCnt++;
		}
	}
	if ( expireCnt ) 
		LogVerbose("Expired Nodes: %u, frag nodes: %u, in use: %u, total flows: %u", 
			expireCnt, fragCnt, Allocated, NumFlows);
	
	return NumFlows;
} // End of Expire_FlowTree


/* Node list functions */
NodeList_t *NewNodeList(void) {
NodeList_t *NodeList;

	NodeList = (NodeList_t *)malloc(sizeof(NodeList_t));
	if ( !NodeList ) {
		LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
		return NULL;
	}
	NodeList->list 		= NULL;
	NodeList->last 		= NULL;
	NodeList->length	= 0;
	NodeList->waiting	= 0;
	NodeList->waits		= 0;
	pthread_mutex_init(&NodeList->m_list, NULL);
	pthread_cond_init(&NodeList->c_list, NULL);

	return NodeList;

} // End of NewNodeList

void DisposeNodeList(NodeList_t *NodeList) {

	if ( !NodeList )
		return;

	if ( NodeList->length ) {
		LogError("Try to free non empty NodeList");
		return;
	}
 	free(NodeList);

} // End of DisposeNodeList

void DumpNodeStat(NodeList_t *NodeList) {
	LogInfo("Nodes in use: %u, Flows: %u, Nodes list length: %u, Waiting for freelist: %u", 
		Allocated, NumFlows, NodeList->length, EmptyFreeListEvents);
	EmptyFreeListEvents = 0;
} // End of DumpNodeStat


void Push_Node(NodeList_t *NodeList, struct FlowNode *node) {

	pthread_mutex_lock(&NodeList->m_list);
	if ( NodeList->length == 0 ) {
		// empty list
		NodeList->list = node;
		node->left = NULL;
		node->right = NULL;
	} else {
		NodeList->last->right = node;
		node->left = NodeList->last;
		node->right = NULL;
	}
	NodeList->last = node;
	NodeList->length++;

//	dbg_printf("pushed node 0x%llx proto: %u, length: %u first: %llx, last: %llx\n", 
//		(unsigned long long)node, node->proto, NodeList->length, 
//		(unsigned long long)NodeList->list, (unsigned long long)NodeList->last);

	int waiting = NodeList->waiting;
 	pthread_mutex_unlock(&NodeList->m_list);
	if ( waiting ) {
		pthread_cond_signal(&NodeList->c_list);
	}

} // End of Push_Node

struct FlowNode *Pop_Node(NodeList_t *NodeList) {
struct FlowNode *node;

	pthread_mutex_lock(&NodeList->m_list);
    while ( NodeList->length == 0) {
		NodeList->waiting = 1;
        pthread_cond_wait(&NodeList->c_list, &NodeList->m_list);
		// wake up
		NodeList->waiting = 0;
	}

	node = NodeList->list;
	NodeList->list = node->right;
	if ( NodeList->list ) 
		NodeList->list->left = NULL;
	else 
		NodeList->last = NULL;

	node->left = NULL;
	node->right = NULL;

	NodeList->length--;
 	pthread_mutex_unlock(&NodeList->m_list);

//	dbg_printf("popped node 0x%llx proto: %u, length: %u first: %llx, last: %llx\n", 
//		(unsigned long long)node, node->proto, NodeList->length, 
//		(unsigned long long)NodeList->list, (unsigned long long)NodeList->last);

	return node;
} // End of Pop_Node

void Push_SyncNode(NodeList_t *NodeList, time_t timestamp) {

	struct FlowNode	*Node = New_Node();
	Node->timestamp = timestamp;
	Node->nodeType  = SIGNAL_NODE;
	Node->fin		= SIGNAL_SYNC;
	Push_Node(NodeList, Node);

} // End of Push_SyncNode

