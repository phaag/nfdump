/*
 *  Copyright (c) 2020, Peter Haag
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

#ifndef _FILTER_H
#define _FILTER_H 1

#include "config.h"

#include <sys/types.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "rbtree.h"

#define NSEL_EVENT_IGNORE 0LL
#define NSEL_EVENT_CREATE 1LL
#define NSEL_EVENT_DELETE 2LL
#define NSEL_EVENT_DENIED 3LL
#define NSEL_EVENT_ALERT  4LL
#define NSEL_EVENT_UPDATE 5LL

#define NEL_EVENT_INVALID 0LL
#define NEL_EVENT_ADD	  1LL
#define NEL_EVENT_DELETE  2LL

/* 
 * Definitions
 */
enum { CMP_EQ = 0, CMP_GT, CMP_LT, CMP_IDENT, CMP_FLAGS, CMP_IPLIST, CMP_ULLIST };

/*
 * filter functions:
 * For some filter functions, netflow records need to be processed first in order to filter them
 * This involves all data not directly available in the netflow record, such as packets per second etc. 
 * Filter speed is a bit slower due to extra netflow processsing
 * The sequence of the enum values must correspond with the entries in the flow_procs array
 */

enum { 	FUNC_NONE = 0,	/* no function - just plain filtering - just to be complete here */
		FUNC_PPS,		/* function code for pps ( packet per second ) filter function */
		FUNC_BPS,		/* function code for bps ( bits per second ) filter function */
		FUNC_BPP,		/* function code for bpp ( bytes per packet ) filter function */
		FUNC_DURATION,	/* function code for duration ( in miliseconds ) filter function */
		FUNC_MPLS_EOS,	/* function code for matching End of MPLS Stack label */
		FUNC_MPLS_ANY,	/* function code for matching any MPLS label */ 
		FUNC_PBLOCK		/* function code for matching ports against pblock start */
};

typedef struct FilterParam {
	uint16_t	comp;
	uint16_t	direction;
	uint32_t	data;
	uint32_t	inout;
	uint32_t	acl;
	uint32_t	self;
} FilterParam_t;

/* Definition of the IP list node */
struct IPListNode {
	RB_ENTRY(IPListNode) entry;
	uint64_t	ip[2];
	uint64_t	mask[2];
};

/* Definition of the port/AS list node */
struct ULongListNode {
	RB_ENTRY(ULongListNode) entry;
	uint64_t	value;
};

/* IP tree type */
typedef RB_HEAD(IPtree, IPListNode) IPlist_t;

/* Port/AS tree type */
typedef RB_HEAD(ULongtree, ULongListNode) ULongtree_t;

// Insert the RB prototypes here
RB_PROTOTYPE(IPtree, IPListNode, entry, IPNodeCMP);

RB_PROTOTYPE(ULongtree, ULongListNode, entry, ULNodeCMP);

/* parser/scanner prototypes */
int yyparse(void);

int yylex(void);

void lex_cleanup(void);

void lex_init(char *buf);

int ScreenIdentString(char *string);

/* 
 * Returns next free slot in blocklist
 */
uint32_t NewBlock(uint32_t offset, uint64_t mask, uint64_t value, uint16_t comp, uint32_t function, void *data);

/* 
 * Connects the to blocks b1 and b2 ( AND ) and returns index of superblock
 */
uint32_t Connect_AND(uint32_t b1, uint32_t b2);

/* 
 * Connects the to blocks b1 and b2 ( OR ) and returns index of superblock
 */
uint32_t Connect_OR(uint32_t b1, uint32_t b2);

/* 
 * Inverts OnTrue and OnFalse
 */
uint32_t Invert(uint32_t a );

/* 
 * Add label to filter index
 */
void AddLabel(uint32_t index, char *label);

/* 
 * Add Ident to Identlist
 */
uint32_t AddIdent(char *Ident);

#endif //_FILTER_H
