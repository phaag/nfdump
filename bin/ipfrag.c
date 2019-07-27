/*
 *  Copyright (c) 2014-2019, Peter Haag
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
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdint.h>

#include "util.h"
#include "rbtree.h"
#include "ipfrag.h"

#define KEYLEN (offsetof(IPFragNode_t,data_size) - offsetof(IPFragNode_t, src_addr))
static int IPFragNodeCMP(struct IPFragNode *e1, struct IPFragNode *e2);

static struct IPFragNode *New_frag_node(void);

static void Free_node(struct IPFragNode *node, int free_data);

static void Remove_node(struct IPFragNode *node, int free_data);

// Insert the IP RB tree code here
RB_GENERATE(IPFragTree, IPFragNode, entry, IPFragNodeCMP);

static IPFragTree_t *IPFragTree;
static uint32_t NumFragments;
static time_t lastExpire = 0;

static int IPFragNodeCMP(struct IPFragNode *e1, struct IPFragNode *e2) {
uint32_t    *a = &e1->src_addr;
uint32_t    *b = &e2->src_addr;
int i;
   
	// 2 x sizeof(uint32_t) (8) + frag_offset == 12
	i = memcmp((void *)a, (void *)b, KEYLEN );
	return i; 
 
} // End of IPFragNodeCMP

static struct IPFragNode *New_frag_node(void) {
struct IPFragNode *node;

	node = calloc(1, sizeof(struct IPFragNode));
	if ( !node ) {
		LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
		return NULL;
	}

	node->data = calloc(1, IP_MAXPACKET);
	if ( !node->data ) {
		LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
		free(node);
		return NULL;
	}

	node->eod = node->data;
	node->data_size = 0;

	node->holes = calloc(1, sizeof(hole_t));
	if ( !node->holes ) {
		LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
		free(node->data);
		free(node);
		return NULL;
	}
	node->holes->next  = NULL;
	node->holes->first = 0;
	node->holes->last = IP_MAXPACKET;
	NumFragments++;

	return node;

} // End of New_frag_node

static void Free_node(struct IPFragNode *node, int free_data) {
hole_t *hole, *h;

	hole = node->holes;
	while (hole) {
		h = hole->next;
		free(hole);
		hole = h;
	}
	if (free_data) 
		free(node->data);
	free(node);
	NumFragments--;

} // End of Free_node

static void Remove_node(struct IPFragNode *node, int free_data) {
struct IPFragNode *n;

	n = RB_REMOVE(IPFragTree, IPFragTree, node);
	if ( n ) {
		Free_node(n, free_data);
	} // else - node not in tree

} // End of Remove_node

int IPFragTree_init(void) {
	IPFragTree = calloc(1, sizeof(IPFragTree_t));
	if ( !IPFragTree ) {
		LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
		return 0;
	}
	RB_INIT(IPFragTree);
	NumFragments = 0;
	dbg_printf("IPFrag key len: %lu\n", KEYLEN);
	return 1;
} // End of IPFragTree_init

void IPFragTree_free(void) {
struct IPFragNode *node, *nxt;

	nxt = NULL;
    for (node = RB_MIN(IPFragTree, IPFragTree); node != NULL; node = nxt) {
        nxt = RB_NEXT(IPFragTree, IPFragTree, node);
        RB_REMOVE(IPFragTree, IPFragTree, node);
		Free_node(node, 1);
    }

	free(IPFragTree);
	IPFragTree = NULL;
	NumFragments = 0;

} // End of IPFragTree_free

static void IPFragTree_expire(time_t when) {
struct IPFragNode *node, *nxt;

	uint32_t expireCnt = 0;
	nxt = NULL;
    for (node = RB_MIN(IPFragTree, IPFragTree); node != NULL; node = nxt) {
        nxt = RB_NEXT(IPFragTree, IPFragTree, node);
		if ( (when - node->last) > 15 ) {
        	RB_REMOVE(IPFragTree, IPFragTree, node);
			Free_node(node, 1);
			expireCnt++;
		}
    }
	dbg_printf("Expired %u incomplete IP fragments, total fragments: %u\n", expireCnt, NumFragments);
	if ( expireCnt )
		LogInfo("Expired %u incomplete IP fragments, total fragments: %u", expireCnt, NumFragments);

} // End of IPFragTree_expire

void *IPFrag_tree_Update(time_t when, uint32_t src, uint32_t dst, uint32_t ident, uint32_t *length, uint32_t ip_off, void *data) {
struct IPFragNode FindNode, *n;
hole_t *hole, *h, *hole_parent;
uint16_t more_fragments, first, last, max;
int found_hole;
char src_s[16], dst_s[16];

	if ( (when - lastExpire ) > 10 ) {
		IPFragTree_expire(when);
		lastExpire = when;
	}

#ifdef DEVEL
	inet_ntop(AF_INET, &src, src_s, 16);
	inet_ntop(AF_INET, &dst, dst_s, 16);
	printf("Update %s - %s\n", src_s, dst_s);
#endif

	FindNode.src_addr = src;
	FindNode.dst_addr = dst;
	FindNode.ident 	  = ident;
	FindNode.last 	  = 0;

	n = RB_FIND(IPFragTree, IPFragTree, &FindNode);
	if ( !n ) {
		n = New_frag_node();
		n->src_addr = src;
		n->dst_addr = dst;
		n->ident 	= ident;
		n->last 	= when;
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
		LogError("Fragment assembly: first: %u, last: %u, MF: %u\n", first, last, more_fragments);
		return NULL;
	}

	// last fragment - sets max offset
	found_hole = 0;
	max = more_fragments == 0 ? last : 0;
	dbg_printf("Fragment assembly: first: %u, last: %u, MF: %u, ID: %x\n", first, last, more_fragments, ident);
	while (hole) {
		uint16_t hole_last;
		if ( max ) {
			dbg_printf("max in last fragment: %u\n", max);
			// last fragment offset/length
			if ( hole->last == IP_MAXPACKET ) {
				// last fragment has max size
				if ( max >= hole->first ) {
					dbg_printf("set max of last fragment: %u\n", max);
					hole->last = max;
				} else {
					inet_ntop(AF_INET, &src, src_s, 16);
					inet_ntop(AF_INET, &dst, dst_s, 16);
					LogError("last fragment offset error - teardrop attack?? SRC: %s, DST: %s",
							src_s, dst_s);
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

		// check for overlapping - cut off overlap
		if ( last > hole->last ) {
			dbg_printf("Truncate right overlapping fragment: %u -> %u\n", last, hole->last);
			last = hole->last;
		}

		if ( first < hole->first ) {
			dbg_printf("Truncate left overlapping fragment: %u -> %u\n", first, hole->first);
			first = hole->first;
		}

		if ( first > last ) {
			LogInfo("fragment error first %u >= last %u", first, last);
			return NULL;
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
					n->holes = hole->next;
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

#ifdef DEVEL	
	if ( !found_hole ) {
	hole_t *h = n->holes;
		dbg_printf("No space in fragment list for: first: %u, last: %u\n", first, last);
		while ( h ) {
			dbg_printf("first: %u,last: %u\n", h->first, h->last);
			h = h->next;
		}
	}
#endif
	
	if ( n->holes == NULL ) {
		void *data = n->data;
		n->data_size++;
		*length = n->data_size;
		Remove_node(n, 0);
		dbg_printf("Defragmentation complete - size: %u\n", n->data_size);
		return data;
	} else {
		return NULL;
	}

} // End of IPFrag_tree_Update

uint32_t IPFragEntries() {
	return NumFragments;
} // End of IPFragEntries
