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
 *  $Id: ipfrag.h 40691 2014-03-03 11:24:22Z phaag $
 *
 *  $LastChangedRevision: 40691 $
 *  
 */

typedef struct hole_s {
	struct hole_s *next;
	uint32_t	first;
	uint32_t	last;
} hole_t;

struct IPFragNode {
	// tree
	RB_ENTRY(IPFragNode) entry;

	// flow key
	// IP addr
	uint32_t	src_addr;
	uint32_t	dst_addr;
	uint32_t	ident;
	// End of flow key

	uint32_t	data_size;
	// packet data
	void		*data;
	void		*eod;
	hole_t *holes;
};

typedef struct IPFragNode IPFragNode_t;

/* flow tree type */
typedef RB_HEAD(IPFragTree, IPFragNode) IPFragTree_t;

// Insert the RB prototypes here
RB_PROTOTYPE(IPFragTree, IPFragNode, entry, IPFragNodeCMP);

int IPFragTree_init(void);

void IPFragTree_free(void);

void *IPFrag_tree_Update(uint32_t src, uint32_t dst, uint32_t ident, uint32_t *length, uint32_t ip_off, void *data);

