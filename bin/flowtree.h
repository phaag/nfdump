/*
 *  Copyright (c) 2014, Peter Haag
 *  Copyright (c) 2011, Peter Haag
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
 *  $Author$
 *
 *  $Id$
 *
 *  $LastChangedRevision$
 *  
 */

#include "rbtree.h"

#define v4 ip_union._v4
#define v6 ip_union._v6

struct FlowNode {
	// tree
	RB_ENTRY(FlowNode) entry;

	// linked list
	struct FlowNode *left;
	struct FlowNode *right;

	struct FlowNode *biflow;

	// flow key
	// IP addr
	ip_addr_t	src_addr;
	ip_addr_t	dst_addr;
	
	uint16_t	src_port;
	uint16_t	dst_port;
	uint8_t		proto;
	uint8_t		version;
	uint16_t	_ENDKEY_;
	// End of flow key

	ip_addr_t	tun_src_addr;
	ip_addr_t	tun_dst_addr;
	uint8_t		tun_proto;

#define NODE_FREE	0xA5
#define NODE_IN_USE	0x5A
	uint16_t	memflag;	// internal houskeeping flag
	uint8_t		flags;
#define FIN_NODE 1
#define SIGNAL_NODE 255
	uint8_t		fin;		// double use:  1: fin received - flow can be exported, if complete
							//            255: empty node - used to wake up flow thread priodically on quite lines
	
	// flow stat data
	struct timeval	t_first;
	struct timeval	t_last;

	uint32_t	packets;	// summed up number of packets
	uint32_t	bytes;		// summed up number of bytes

	// flow payload
#define DATABLOCKSIZE 256
	uint32_t	DataSize;	// max size of data buffer
	void		*data;		// start of data buffer
//	uint32_t	eodata;		// offset last byte in buffer
	
};

typedef struct NodeList_s {
	struct FlowNode *list;
	struct FlowNode *last;
	pthread_mutex_t m_list;
	pthread_cond_t  c_list;
	uint32_t length;
} NodeList_t;


/* flow tree type */
typedef RB_HEAD(FlowTree, FlowNode) FlowTree_t;

// Insert the RB prototypes here
RB_PROTOTYPE(FlowTree, FlowNode, entry, FlowNodeCMP);

int Init_FlowTree(uint32_t CacheSize);

void Dispose_FlowTree(void);

uint32_t Flush_FlowTree(FlowSource_t *fs);

struct FlowNode *Lookup_Node(struct FlowNode *node);

struct FlowNode *New_Node(void);

void Free_Node(struct FlowNode *node);

uint32_t CacheCheck(void);

int AddNodeData(struct FlowNode *node, uint32_t seq, void *payload, uint32_t size);

struct FlowNode *Insert_Node(struct FlowNode *node);

void Remove_Node(struct FlowNode *node);

// Node list functions 
NodeList_t *NewNodeList(void);

void DisposeNodeList(NodeList_t *NodeList);

void Push_Node(NodeList_t *NodeList, struct FlowNode *node);

struct FlowNode *Pop_Node(NodeList_t *NodeList, int *done);

void DumpList(NodeList_t *NodeList);

// Liked lists
void AppendUDPNode(struct FlowNode *node);

void TouchUDPNode(struct FlowNode *node);

void UDPexpire(FlowSource_t *fs, time_t t_expire);

// Stat functions
void DumpNodeStat(void);


