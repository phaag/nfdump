/*
 *  Copyright (c) 2009-2021, Peter Haag
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>


#include "rbtree.h"
#include "filter.h"
#include "nfdump.h"
#include "nffile.h"
#include "ipconv.h"
#include "nftree.h"

/*
 * netflow filter engine
 *
 */

#define MAXBLOCKS 1024

static FilterBlock_t *FilterTree;
static uint32_t memblocks;

static uint32_t NumBlocks = 1;	/* index 0 reserved */

#define IdentNumBlockSize 32
static uint16_t MaxIdents;
static uint16_t NumIdents;
static char		**IdentList;

static void UpdateList(uint32_t a, uint32_t b);

/* flow processing functions */
static inline void pps_function(uint64_t *record_data, uint64_t *comp_values);
static inline void bps_function(uint64_t *record_data, uint64_t *comp_values);
static inline void bpp_function(uint64_t *record_data, uint64_t *comp_values);
static inline void duration_function(uint64_t *record_data, uint64_t *comp_values);
static inline void mpls_eos_function(uint64_t *record_data, uint64_t *comp_values);
static inline void mpls_any_function(uint64_t *record_data, uint64_t *comp_values);
static inline void pblock_function(uint64_t *record_data, uint64_t *comp_values);

/* 
 * flow processing function table:
 * order of entries must correspond with filter functions enum in nftree.h 
 */
static struct flow_procs_map_s {
	char		*name;
	flow_proc_t function;
} flow_procs_map[] = {
	{"none",		NULL},
	{"pps",			pps_function},
	{"bps",			bps_function},
	{"bpp",			bpp_function},
	{"duration",	duration_function},
	{"mpls eos",	mpls_eos_function},
	{"mpls any",	mpls_any_function},
 	{"pblock", 		pblock_function},
	{NULL,			NULL}
};

uint64_t *IPstack = NULL;
uint32_t StartNode;
uint16_t Extended;
uint8_t geoFilter = 0;
uint8_t ja3Filter = 0;

// 128bit compare for IPv6 
static int IPNodeCMP(struct IPListNode *e1, struct IPListNode *e2) {
uint64_t	ip_e1[2], ip_e2[2];
	
	ip_e1[0] = e1->ip[0] & e2->mask[0];
	ip_e1[1] = e1->ip[1] & e2->mask[1];

	ip_e2[0] = e2->ip[0] & e1->mask[0];
	ip_e2[1] = e2->ip[1] & e1->mask[1];

	if ( ip_e1[0] == ip_e2[0] ) {
		if ( ip_e1[1] == ip_e2[1] )
			return 0;
		else
			return (ip_e1[1] < ip_e2[1] ? -1 : 1);
	} else {
		return (ip_e1[0] < ip_e2[0] ? -1 : 1);
	}

} // End of IPNodeCMP

// 64bit uint64 compare
static int ULNodeCMP(struct ULongListNode *e1, struct ULongListNode *e2) {
	if ( e1->value == e2->value ) 
		return 0;
	else 
		return (e1->value < e2->value ? -1 : 1);

} // End of ULNodeCMP

// Insert the IP RB tree code here
RB_GENERATE(IPtree, IPListNode, entry, IPNodeCMP);

// Insert the Ulong RB tree code here
RB_GENERATE(ULongtree, ULongListNode, entry, ULNodeCMP);

void InitTree(void) {
	memblocks = 1;
	FilterTree = (FilterBlock_t *)malloc(MAXBLOCKS * sizeof(FilterBlock_t));
	if ( !FilterTree ) {
		fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(255);
	}
	ClearFilter();
} // End of InitTree


/*
 * Clear Filter
 */
void ClearFilter(void) {

	NumBlocks = 1;
	Extended  = 0;
	MaxIdents = 0;
	NumIdents = 0;
	IdentList = NULL;
	memset((void *)FilterTree, 0, MAXBLOCKS * sizeof(FilterBlock_t));

} /* End of ClearFilter */

FilterEngine_t *CompileFilter(char *FilterSyntax) {
FilterEngine_t	*engine;
int	ret;

	if ( !FilterSyntax ) 
		return NULL;

	IPstack = (uint64_t *)malloc(16 * MAXHOSTS);
	if ( !IPstack ) {
		fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(255);
	}

	InitTree();
	lex_init(FilterSyntax);
	ret = yyparse();
	if ( ret != 0 ) {
		return NULL;
	}
	lex_cleanup();
	free(IPstack);

	engine = malloc(sizeof(FilterEngine_t));
	if ( !engine ) {
		fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(255);
	}
	engine->nfrecord  = NULL;
	engine->label	  = NULL;
	engine->ident	  = NULL;
	engine->StartNode = StartNode;
	engine->Extended  = Extended;
	engine->geoFilter = geoFilter;
	engine->ja3Filter = ja3Filter;
	engine->IdentList = IdentList;
	engine->filter 	  = FilterTree;
	if ( Extended ) 
		engine->FilterEngine = RunExtendedFilter;
	else
		engine->FilterEngine = RunFilter;

	return (FilterEngine_t *)engine;

} // End of GetTree

/*
 * For testing purpose only
 */
int nblocks(void) {
	return NumBlocks - 1;
} /* End of nblocks */

/* 
 * Returns next free slot in blocklist
 */
uint32_t NewBlock(uint32_t offset, uint64_t mask, uint64_t value, uint16_t comp, uint32_t  function, void *data) {
uint32_t n = NumBlocks;

	if ( n >= ( memblocks * MAXBLOCKS ) ) {
		memblocks++;
		FilterTree = realloc(FilterTree, memblocks * MAXBLOCKS * sizeof(FilterBlock_t));
		if ( !FilterTree ) {
			fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			exit(255);
		}
	}

	FilterTree[n].offset	= offset;
	FilterTree[n].mask		= mask;
	FilterTree[n].value		= value;
	FilterTree[n].invert	= 0;
	FilterTree[n].OnTrue	= 0;
	FilterTree[n].OnFalse	= 0;
	FilterTree[n].comp 		= comp;
	FilterTree[n].function 	= flow_procs_map[function].function;
	FilterTree[n].fname 	= flow_procs_map[function].name;
	FilterTree[n].label 	= NULL;
	FilterTree[n].data 		= data;
	if ( comp > 0 || function > 0 )
		Extended = 1;

	FilterTree[n].numblocks = 1;
	FilterTree[n].blocklist = (uint32_t *)malloc(sizeof(uint32_t));
	FilterTree[n].superblock = n;
	FilterTree[n].blocklist[0] = n;
	NumBlocks++;
	return n;

} /* End of NewBlock */

/* 
 * Connects the two blocks b1 and b2 ( AND ) and returns index of superblock
 */
uint32_t Connect_AND(uint32_t b1, uint32_t b2) {

	uint32_t	a, b, i, j;

	// do not optimise blocks if block 'any' is appended
	if ((FilterTree[b2].data == (void *)-1) || (FilterTree[b1].numblocks <= FilterTree[b2].numblocks)) {
		a = b1;
		b = b2;
	} else {
		a = b2;
		b = b1;
	}
	/* a points to block with less children and becomes the superblock 
	 * connect b to a
	 */
	for ( i=0; i < FilterTree[a].numblocks; i++ ) {
		j = FilterTree[a].blocklist[i];
		if ( FilterTree[j].invert ) {
			if ( FilterTree[j].OnFalse == 0 ) {
				FilterTree[j].OnFalse = b;
			}
		} else {
			if ( FilterTree[j].OnTrue == 0 ) {
				FilterTree[j].OnTrue = b;
			}
		}
	}
	UpdateList(a,b);
	return a;

} /* End of Connect_AND */

/* 
 * Connects the two blocks b1 and b2 ( OR ) and returns index of superblock
 */
uint32_t Connect_OR(uint32_t b1, uint32_t b2) {

	uint32_t	a, b, i, j;

	// do not optimise block 'any' if appended as lastelement
	// for all prepending blocks to be evaluated. 
	if ((FilterTree[b2].data == (void *)-1) || (FilterTree[b1].numblocks <= FilterTree[b2].numblocks)) {
		a = b1;
		b = b2;
	} else {
		a = b2;
		b = b1;
	}
	/* a points to block with less children and becomes the superblock 
	 * connect b to a
	 */
	for ( i=0; i < FilterTree[a].numblocks; i++ ) {
		j = FilterTree[a].blocklist[i];
		if ( FilterTree[j].invert ) {
			if ( FilterTree[j].OnTrue == 0 ) {
				FilterTree[j].OnTrue = b;
			}
		} else {
			if ( FilterTree[j].OnFalse == 0 ) {
				FilterTree[j].OnFalse = b;
			}
		}
	}
	UpdateList(a,b);
	return a;

} /* End of Connect_OR */

/* 
 * Inverts OnTrue and OnFalse
 */
uint32_t Invert(uint32_t a) {
	uint32_t	i, j;

	for ( i=0; i< FilterTree[a].numblocks; i++ ) {
		j = FilterTree[a].blocklist[i];
		FilterTree[j].invert = FilterTree[j].invert ? 0 : 1 ;
	}
	return a;

} /* End of Invert */

/*
 * Update supernode infos:
 * node 'b' was connected to 'a'. update node 'a' supernode data
 */
static void UpdateList(uint32_t a, uint32_t b) {
	size_t s;
	uint32_t	i,j;

	/* numblocks contains the number of blocks in the superblock */
	s = FilterTree[a].numblocks + FilterTree[b].numblocks;
	FilterTree[a].blocklist = (uint32_t *)realloc(FilterTree[a].blocklist, s * sizeof(uint32_t));
	if ( !FilterTree[a].blocklist ) {
		fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(250);
	}

	/* connect list of node 'b' after list of node 'a' */
	j = FilterTree[a].numblocks;
	for ( i=0; i< FilterTree[b].numblocks; i++ ) {
		FilterTree[a].blocklist[j+i] = FilterTree[b].blocklist[i];
	}
	FilterTree[a].numblocks = s;

	/* set superblock info of all children to new superblock */
	for ( i=0; i< FilterTree[a].numblocks; i++ ) {
		j = FilterTree[a].blocklist[i];
		FilterTree[j].superblock = a;
	}

	/* cleanup old node 'b' */
	FilterTree[b].numblocks = 0;
	if ( FilterTree[b].blocklist ) 
		free(FilterTree[b].blocklist);

} /* End of UpdateList */

/*
 * Dump Filterlist 
 */
void DumpEngine(FilterEngine_t *engine) {
uint32_t i, j;

	for (i=1; i<NumBlocks; i++ ) {
		if ( engine->filter[i].invert )
			printf("Index: %u, Offset: %u, Mask: %.16llx, Value: %.16llx, Superblock: %u, Numblocks: %u, !OnTrue: %u, !OnFalse: %u Comp: %u Function: %s, Label: %s\n",
				i, engine->filter[i].offset, (unsigned long long)engine->filter[i].mask, 
				(unsigned long long)engine->filter[i].value, engine->filter[i].superblock, 
				engine->filter[i].numblocks, engine->filter[i].OnTrue, engine->filter[i].OnFalse, 
				engine->filter[i].comp, engine->filter[i].fname, engine->filter[i].label ? engine->filter[i].label : "<none>");
		else 
			printf("Index: %u, Offset: %u, Mask: %.16llx, Value: %.16llx, Superblock: %u, Numblocks: %u, OnTrue: %u, OnFalse: %u Comp: %u Function: %s, Label: %s\n",
				i, engine->filter[i].offset, (unsigned long long)engine->filter[i].mask, 
				(unsigned long long)engine->filter[i].value, engine->filter[i].superblock, 
				engine->filter[i].numblocks, engine->filter[i].OnTrue, engine->filter[i].OnFalse, 
				engine->filter[i].comp, engine->filter[i].fname, engine->filter[i].label ? engine->filter[i].label : "<none>");
		if ( engine->filter[i].OnTrue > (memblocks * MAXBLOCKS) || engine->filter[i].OnFalse > (memblocks * MAXBLOCKS) ) {
			fprintf(stderr, "Tree pointer out of range for index %u. *** ABORT ***\n", i);
			exit(255);
		}
		if ( engine->filter[i].data ) {
			if ( engine->filter[i].comp == CMP_IPLIST ) {
				struct IPListNode *node;
				RB_FOREACH(node, IPtree, engine->filter[i].data) {
					printf("value: %.16llx %.16llx mask: %.16llx %.16llx\n", 
						(unsigned long long)node->ip[0], (unsigned long long)node->ip[1], 
						(unsigned long long)node->mask[0], (unsigned long long)node->mask[1]);
				} 
			} else if ( engine->filter[i].comp == CMP_ULLIST ) {
				struct ULongListNode *node;
				RB_FOREACH(node, ULongtree, engine->filter[i].data) {
					printf("%.16llx \n", (unsigned long long)node->value);
				}
			} else 
				printf("Error comp: %i\n", engine->filter[i].comp);
		}
		printf("\tBlocks: ");
		for ( j=0; j<engine->filter[i].numblocks; j++ ) 
			printf("%i ", engine->filter[i].blocklist[j]);
		printf("\n");
	}
	printf("NumBlocks: %i\n", NumBlocks - 1);
	for ( i=0; i<NumIdents; i++ ) {
		printf("Ident %i: %s\n", i, IdentList[i]);
	}
} /* End of DumpList */

/* fast filter engine */
int RunFilter(FilterEngine_t *engine) {
uint32_t	index, offset;
int	evaluate, invert;

	engine->label = NULL;
	index = engine->StartNode;
	evaluate = 0;
	invert = 0;
	while ( index ) {
		offset   = engine->filter[index].offset;
		invert   = engine->filter[index].invert;
		evaluate = ( engine->nfrecord[offset] & engine->filter[index].mask ) == engine->filter[index].value;
		index    = evaluate ?  engine->filter[index].OnTrue : engine->filter[index].OnFalse;
	}
	return invert ? !evaluate : evaluate;

} /* End of RunFilter */

/* extended filter engine */
int RunExtendedFilter(FilterEngine_t *engine) {
uint32_t	index, offset; 
uint64_t	comp_value[2];
int	evaluate, invert;

	engine->label = NULL;
	index = engine->StartNode;
	evaluate = 0;
	invert = 0;
	while ( index ) {
		offset   = engine->filter[index].offset;
		invert   = engine->filter[index].invert;

		comp_value[0] = engine->nfrecord[offset] & engine->filter[index].mask;
		comp_value[1] = engine->filter[index].value;

		if (engine->filter[index].function != NULL)
			engine->filter[index].function(engine->nfrecord, comp_value);

		switch (engine->filter[index].comp) {
			case CMP_EQ:
				evaluate = comp_value[0] == comp_value[1];
				break;
			case CMP_GT:
				evaluate = comp_value[0] > comp_value[1];
				break;
			case CMP_LT:
				evaluate = comp_value[0] < comp_value[1];
				break;
			case CMP_GE:
				evaluate = comp_value[0] >= comp_value[1];
 				break;
 			case CMP_LE:
				evaluate = comp_value[0] <= comp_value[1];
 				break;
			case CMP_IDENT:
				evaluate = engine->ident ? strncmp(engine->ident, engine->IdentList[comp_value[1]], IDENTLEN) == 0 : 0;
				break;
			case CMP_FLAGS:
				if ( invert )
					evaluate = comp_value[0] > 0;
				else
					evaluate = comp_value[0] == comp_value[1];
				break;
			case CMP_IPLIST: {
				struct IPListNode find;
				find.ip[0] = engine->nfrecord[offset];
				find.ip[1] = engine->nfrecord[offset+1];
				find.mask[0] = 0xffffffffffffffffLL;
				find.mask[1] = 0xffffffffffffffffLL;
				evaluate = RB_FIND(IPtree, engine->filter[index].data, &find) != NULL; }
				break;
			case CMP_ULLIST: {
				struct ULongListNode find;
				find.value = comp_value[0];
				evaluate = RB_FIND(ULongtree, engine->filter[index].data, &find ) != NULL; }
				break;
			case CMP_PAYLOAD: {
				master_record_t *r = (master_record_t *)engine->nfrecord;
				char *string = (char *)engine->filter[index].data;

				if ( r->inPayload != NULL && string != NULL) {
					evaluate = strstr(r->inPayload, string) != NULL ? 1 : 0;
				} else {
					evaluate = 0;
				}
			} break;
		}

		/*
		 * Label evaluation:
		 * A flow gets labeled, if one filter expression has a label assigned and
		 * that filter expression is in the 'true' path of the tree, resulting
		 * to a final match. If subsequent expressions in the same path evaluate
		 * to false, the label is cleared again.
		 * In case of multiple labels in a true patch, the last seen label wins.
		 */
		if ( evaluate ) {
			// if filter expression has a label assigned, copy that
			if ( engine->filter[index].label ) {
				engine->label = engine->filter[index].label;
			}
			index = engine->filter[index].OnTrue;
		} else {
			// filter expression does not match - clear previous label if abailable
			if ( engine->label )
				engine->label = NULL;
			index = engine->filter[index].OnFalse;
		}
		// index = evaluate ? engine->filter[index].OnTrue : engine->filter[index].OnFalse;
	}
	return invert ? !evaluate : evaluate;

} /* End of RunExtendedFilter */

void AddLabel(uint32_t index, char *label) {
	char *l = strdup(label);

	// each block not further connected and returns true, gets the label 
	for ( int i=0; i< FilterTree[index].numblocks; i++ ) {
		int j = FilterTree[index].blocklist[i];
		if ( FilterTree[j].OnTrue == 0 ) {
			FilterTree[j].label = l;
		}
	}
	Extended = 1;

} // End of AddLabel

uint32_t AddIdent(char *Ident) {
uint32_t	num;

	if ( MaxIdents == 0 ) {
		// allocate first array block
		MaxIdents = IdentNumBlockSize;
		IdentList = (char **)malloc( MaxIdents * sizeof(char *));
		if ( !IdentList ) {
			fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			exit(254);
		}
		memset((void *)IdentList, 0, MaxIdents * sizeof(char *));
		NumIdents = 0;
	} else if ( NumIdents == MaxIdents ) {
		// extend array block
		MaxIdents += IdentNumBlockSize;
		IdentList = realloc((void *)IdentList, MaxIdents * sizeof(char *));
		if ( !IdentList ) {
			fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			exit(254);
		}
	}

	num = NumIdents++;
	IdentList[num] = strdup(Ident);
	if ( !IdentList[num] ) {
		fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(254);
	}

	return num;

} // End of AddIdent

/* record processing functions */

static inline void duration_function(uint64_t *record_data, uint64_t *comp_values) {
master_record_t *record = (master_record_t *)record_data;

	/* duration in msec */
	comp_values[0] = record->msecLast - record->msecFirst;
} // End of duration_function

static inline void pps_function(uint64_t *record_data, uint64_t *comp_values) {
master_record_t *record = (master_record_t *)record_data;
uint64_t		duration;

	/* duration in msec */
	duration = record->msecLast - record->msecFirst;
	if ( duration == 0 )
		comp_values[0] = 0;
	else 
		comp_values[0] = ( 1000LL * record->inPackets ) / duration;

} // End of pps_function

static inline void bps_function(uint64_t *record_data, uint64_t *comp_values) {
master_record_t *record = (master_record_t *)record_data;
uint64_t		duration;

	/* duration in msec */
	duration = record->msecLast - record->msecFirst;
	if ( duration == 0 )
		comp_values[0] = 0;
	else 
		comp_values[0] = ( 8000LL * record->inBytes ) / duration;	/* 8 bits per Octet - x 1000 for msec */

} // End of bps_function

static inline void bpp_function(uint64_t *record_data, uint64_t *comp_values) {
master_record_t *record = (master_record_t *)record_data;

	comp_values[0] = record->inPackets ? record->inBytes / record->inPackets : 0;

} // End of bpp_function

static inline void mpls_eos_function(uint64_t *record_data, uint64_t *comp_values) {
master_record_t *record = (master_record_t *)record_data;
int i;

	// search for end of MPLS stack label
	for (i=0; i<10; i++ ) {
		if ( record->mpls_label[i] & 1 ) {
			// End of stack found -> mask exp and eos bits
			comp_values[0] = record->mpls_label[i] & 0x00FFFFF0;
			return;
		}
	}

	// trick filter to fail with an invalid mpls label value
	comp_values[0] = 0xFF000000;

} // End of mpls_eos_function

static inline void mpls_any_function(uint64_t *record_data, uint64_t *comp_values) {
master_record_t *record = (master_record_t *)record_data;
int i;

	// search for end of MPLS stack label
	for (i=0; i<10; i++ ) {
		if ( (record->mpls_label[i] & 1) == 1 ) {
			// End of stack found -> mask exp and eos bits
			comp_values[0] = record->mpls_label[i] & 0x00FFFFF0;
			return;
		}
	}

	// trick filter to fail with an invalid mpls label value
	comp_values[0] = 0xFF000000;

} // End of mpls_eos_function

static inline void pblock_function(uint64_t *record_data, uint64_t *comp_values) {
#ifdef NSEL
master_record_t *record = (master_record_t *)record_data;
	comp_values[0] = comp_values[0] >> comp_values[1];
	if ( (comp_values[0] >= record->block_start) && (comp_values[0] <= record->block_end) ) {
		comp_values[1] = comp_values[0];
	} else {
		// force "not equal"
		comp_values[1] = comp_values[0] + 1;
	}
#else
	comp_values[1] = 0;
#endif

} // End of pblock_function
