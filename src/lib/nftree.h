/*
 *  Copyright (c) 2009-2020, Peter Haag
 *  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
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

#ifndef _NFTREE_H
#define _NFTREE_H 1

#include "config.h"

#include <sys/types.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

/*
 * type definitions for nf tree
 */

typedef void (*flow_proc_t)(uint64_t *, uint64_t *);

typedef struct FilterBlock {
	/* Filter specific data */
	uint32_t	offset;
	uint64_t	mask;
	uint64_t	value;

	/* Internal block info for tree setup */
	uint32_t	superblock;			/* Index of superblock */
	uint32_t	*blocklist;			/* index array of blocks, belonging to
								   	   this superblock */
	uint32_t	numblocks;			/* number of blocks in blocklist */
	uint32_t	OnTrue, OnFalse;	/* Jump Index for tree */
	int16_t		invert;				/* Invert result of test */
	uint16_t	comp;				/* comperator */
	flow_proc_t	function;			/* function for flow processing */
	char		*fname;				/* ascii function name */
	char		*label;				/* label, if any */
	void		*data;				/* any additional data for this block */
} FilterBlock_t;

typedef struct FilterEngine_data_s {
	FilterBlock_t	*filter;
	uint32_t		StartNode;
	uint16_t 		Extended;
	uint8_t 		geoFilter;
	uint8_t 		ja3Filter;
	char			**IdentList;
	uint64_t		*nfrecord;
	char			*label;
	char			*ident;
	int (*FilterEngine)(struct FilterEngine_data_s *);
} FilterEngine_t;

/* 
 * Filter Engine Functions
 */
void InitTree(void);

FilterEngine_t *CompileFilter(char *FilterSyntax);

int RunFilter(FilterEngine_t *engine);

int RunExtendedFilter(FilterEngine_t *engine);

void ClearFilter(void);

void DumpEngine(FilterEngine_t *engine);

int nblocks(void);

int RunDebugFilter(uint32_t	*block);

#endif //_NFTREE_H
