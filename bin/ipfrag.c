/*
 *  Copyright (c) 2014, Peter Haag
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
 *  $Author: phaag $
 *
 *  $Id: ipfrag.c 40874 2014-03-06 09:58:20Z phaag $
 *
 *  $LastChangedRevision: 40874 $
 *  
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <stdint.h>

#include "util.h"
#include "rbtree.h"
#include "ipfrag.h"

#ifndef DEVEL
#   define dbg_printf(...) /* printf(__VA_ARGS__) */
#else
#   define dbg_printf(...) printf(__VA_ARGS__)
#endif

#define KEYLEN (offsetof(IPFragNode_t,data_size) - offsetof(IPFragNode_t, src_addr))
static int IPFragNodeCMP(struct IPFragNode *e1, struct IPFragNode *e2);

static struct IPFragNode *New_node(void);

static void Free_node(struct IPFragNode *node, int free_data);

static void Remove_node(struct IPFragNode *node);

// Insert the IP RB tree code here
RB_GENERATE(IPFragTree, IPFragNode, entry, IPFragNodeCMP);

static IPFragTree_t *IPFragTree;

static int IPFragNodeCMP(struct IPFragNode *e1, struct IPFragNode *e2) {
uint32_t    *a = &e1->src_addr;
uint32_t    *b = &e2->src_addr;
int i;
   
	// 2 x sizeof(uint32_t) (8) + frag_offset == 12
	i = memcmp((void *)a, (void *)b, KEYLEN );
	return i; 
 
} // End of IPFragNodeCMP

static struct IPFragNode *New_node(void) {
struct IPFragNode *node;

	node = malloc(sizeof(struct IPFragNode));
	if ( !node ) {
		LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
		return NULL;
	}
	memset((void *)node, 0, sizeof(struct IPFragNode));

	node->data = malloc(IP_MAXPACKET);
	if ( !node->data ) {
		LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
		free(node);
		return NULL;
	}
	memset(node->data, 0, IP_MAXPACKET);

	node->eod = node->data;
	node->data_size = 0;

	node->holes = malloc(sizeof(hole_t));
	if ( !node->holes ) {
		LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
		free(node);
		return NULL;
	}
	node->holes->next  = NULL;
	node->holes->first = 0;
	node->holes->last = IP_MAXPACKET;

	return node;

} // End of New_node

static void Free_node(struct IPFragNode *node, int free_data) {
hole_t *hole, *h;

	hole = node->holes;
	while (hole) {
		h = hole->next;
		free(hole);
		hole = h;
	}
	if ( free_data) 
		free(node->data);
	free(node);

} // End of Free_node

static void Remove_node(struct IPFragNode *node) {
struct IPFragNode *n;

	n = RB_REMOVE(IPFragTree, IPFragTree, node);
	if ( n ) {
		Free_node(n, 0);
	} // else - node not in tree

} // End of Remove_node

int IPFragTree_init(void) {
	IPFragTree = malloc(sizeof(IPFragTree_t));
	if ( !IPFragTree ) {
		LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
		return 0;
	}
	RB_INIT(IPFragTree);
	dbg_printf("IPFrag key len: %lu\n", KEYLEN);
	return 1;
} // End of IPFragTree_init

void IPFragTree_free(void) {
struct IPFragNode *node, *nxt;

    // Dump all incomplete flows to the file
    for (node = RB_MIN(IPFragTree, IPFragTree); node != NULL; node = nxt) {
        nxt = RB_NEXT(IPFragTree, IPFragTree, node);
        RB_REMOVE(IPFragTree, IPFragTree, node);
		Free_node(node, 1);
    }

	free(IPFragTree);
	IPFragTree = NULL;
} // End of IPFragTree_free

void *IPFrag_tree_Update(uint32_t src, uint32_t dst, uint32_t ident, uint32_t *length, uint32_t ip_off, void *data) {
struct IPFragNode FindNode, *n;
hole_t *hole, *h, *hole_parent;
uint16_t more_fragments, first, last, max;
int found_hole;

	FindNode.src_addr = src;
	FindNode.dst_addr = dst;
	FindNode.ident 	  = ident;
	n = RB_FIND(IPFragTree, IPFragTree, &FindNode);
	if ( !n ) {
		n = New_node();
		n->src_addr = src;
		n->dst_addr = dst;
		n->ident 	= ident;
		if ( RB_INSERT(IPFragTree, IPFragTree, n) ) {
			// must never happen
			LogError("Node insert returned existing node - Software error in %s line %d", __FILE__, __LINE__);
		}
	}
	hole = n->holes;
	hole_parent = NULL;

	first = (ip_off & IP_OFFMASK) << 3;
	more_fragments = (ip_off & IP_MF) != 0 ? 1 : 0;
	last = first + *length - 1;
	
	if ( last > IP_MAXPACKET ) {
		LogError("Fragment assembly error: last > IP_MAXPACKET");
		LogError("Fraget assembly: first: %u, last: %u, MF: %u\n", first, last, more_fragments);
		return NULL;
	}

	// last fragment - sets max offset
	found_hole = 0;
	max = more_fragments == 0 ? last : 0;
	dbg_printf("Fraget assembly: first: %u, last: %u, MF: %u\n", first, last, more_fragments);
	while (hole) {
		uint16_t hole_last;
		if ( max ) {
			dbg_printf("max in last fragment: %u\n", max);
			// last fragment offset/length
			if ( hole->last == IP_MAXPACKET ) {
				// last fragment has max size
				if ( max > hole->first ) {
					dbg_printf("set max of last fragment: %u\n", max);
					hole->last = max;
				} else {
					LogError("last fragment offset error - teardrop attack??");
				}
			} else {
				// last fragment must always be max offset
				if ( max < hole->last ) {
					LogError("last fragment offset error - teardrop attack??");
				}
			}
		}
		dbg_printf("Check Hole: first: %u, last: %u\n", hole->first, hole->last);

		if ( first > hole->last ) {
			hole_parent = hole;
			hole = hole->next;
			dbg_printf("Fragment right outside hole\n");
			continue;
		}
		if ( last < hole->first ) {
			hole_parent = hole;
			hole = hole->next;
			dbg_printf("Fragment left outside hole\n");
			continue;
		}

		// fragment fits into hole
		found_hole = 1;
		if ( last > n->data_size ) 
			n->data_size = last;

		hole_last = hole->last;
		if ( first == hole->first ) {
			dbg_printf("Fragment matches first\n");
			// fragment fits at beginning of hole
			if ( last == hole->last ) { 
				dbg_printf("Fragment matches last\n");
				// fragment fits completly into hole - delete hole
				if ( hole_parent ) {
					hole_parent->next = hole->next;
				} else {
					n->holes = NULL;
				}
				free(hole);
				hole = NULL;
			} else { 
				// fragment smaller than hole
				dbg_printf("Fragment smaller than hole\n");
				hole->first = last+1;
			}
		} else {
			// fragment start within hole
			dbg_printf("Fragment inside hole\n");
			hole->last = first - 1;
			if ( last < hole_last ) {
				// fragment ends within hole - add another hole
				h = malloc(sizeof(hole_t));
				if ( !h ) {
					LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
					return NULL;
				}
				h->first = last + 1;
				h->last  = hole_last;
				h->next  = n->holes;
				n->holes = h;
			}
		}
		memcpy(n->data + first, data, *length);

		break;
	}
	
	if ( !found_hole )
		LogError("No space - Fragment overlap: first: %u, last: %u\n", first, last);
	
	if ( n->holes == NULL ) {
		void *data = n->data;
		n->data_size++;
		*length = n->data_size;
		Remove_node(n);
		dbg_printf("Datagramm complete - size: %u\n", n->data_size);
		return data;
	} else {
		return NULL;
	}

} // End of IPFrag_tree_Update
