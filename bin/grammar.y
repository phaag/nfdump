/*
 *  This file is part of the nfdump project.
 *
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
 *   * Neither the name of SWITCH nor the names of its contributors may be 
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
 *  $Author: peter $
 *
 *  $Id: grammar.y 100 2008-08-15 11:36:21Z peter $
 *
 *  $LastChangedRevision: 100 $
 *	
 *
 *
 */

%{

#include "config.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nf_common.h"
#include "rbtree.h"
#include "nfdump.h"
#include "nffile.h"
#include "nftree.h"
#include "ipconv.h"
#include "util.h"

/*
 * function prototypes
 */
static void  yyerror(char *msg);

static uint32_t ChainHosts(uint64_t *offsets, uint64_t *hostlist, int num_records, int type);

static uint64_t VerifyMac(char *s);

enum { DIR_UNSPEC = 1, 
	   SOURCE, DESTINATION, SOURCE_AND_DESTINATION, SOURCE_OR_DESTINATION, 
	   DIR_IN, DIR_OUT, 
	   IN_SRC, IN_DST, OUT_SRC, OUT_DST, 
	   ADJ_PREV, ADJ_NEXT };

enum { IS_START = 0, IS_END };

/* var defs */
extern int 			lineno;
extern char 		*yytext;
extern uint64_t		*IPstack;
extern uint32_t	StartNode;
extern uint16_t	Extended;
extern int (*FilterEngine)(uint32_t *);
extern char	*FilterFilename;

static uint32_t num_ip;

char yyerror_buff[256];

#define MPLSMAX 0x00ffffff
%}

%union {
	uint64_t		value;
	char			*s;
	FilterParam_t	param;
	void			*list;
}

%token ANY IP IF MAC MPLS TOS DIR FLAGS PROTO MASK HOSTNAME NET PORT FWDSTAT IN OUT SRC DST EQ LT GT PREV NEXT
%token NUMBER STRING IDENT PORTNUM ICMP_TYPE ICMP_CODE ENGINE_TYPE ENGINE_ID AS PACKETS BYTES FLOWS 
%token PPS BPS BPP DURATION NOT 
%token IPV4 IPV6 BGPNEXTHOP ROUTER VLAN
%token CLIENT SERVER APP LATENCY SYSID
%token ASA REASON DENIED XEVENT XIP XNET XPORT INGRESS EGRESS ACL ACE XACE
%token NAT ADD EVENT VRF NPORT NIP
%token PBLOCK START END STEP SIZE
%type <value>	expr NUMBER PORTNUM ICMP_TYPE ICMP_CODE
%type <s> STRING REASON 
%type <param> dqual term comp acl inout
%type <list> iplist ullist

%left	'+' OR
%left	'*' AND
%left	NEGATE

%%
prog: 		/* empty */
	| expr 	{   
		StartNode = $1; 
	}
	;

term:	ANY { /* this is an unconditionally true expression, as a filter applies in any case */
		$$.self = NewBlock(OffsetProto, 0, 0, CMP_EQ, FUNC_NONE, NULL ); 
	}

	| IDENT STRING {	
		if ( !ScreenIdentString($2) ) {
			yyerror("Illegal ident string");
			YYABORT;
		}

		uint32_t	index = AddIdent($2);
		$$.self = NewBlock(0, 0, index, CMP_IDENT, FUNC_NONE, NULL ); 
	}

	| IPV4 { 
		$$.self = NewBlock(OffsetRecordFlags, (1LL << ShiftRecordFlags)  & MaskRecordFlags, 
					(0LL << ShiftRecordFlags)  & MaskRecordFlags, CMP_EQ, FUNC_NONE, NULL); 
	}

	| IPV6 { 
		$$.self = NewBlock(OffsetRecordFlags, (1LL << ShiftRecordFlags)  & MaskRecordFlags, 
					(1LL << ShiftRecordFlags)  & MaskRecordFlags, CMP_EQ, FUNC_NONE, NULL); 
	}

	| PROTO NUMBER { 
		int64_t	proto;
		proto = $2;

		if ( proto > 255 ) {
			yyerror("Protocol number > 255");
			YYABORT;
		}
		if ( proto < 0 ) {
			yyerror("Unknown protocol");
			YYABORT;
		}
		$$.self = NewBlock(OffsetProto, MaskProto, (proto << ShiftProto)  & MaskProto, CMP_EQ, FUNC_NONE, NULL); 

	}

	| PROTO STRING { 
		int64_t	proto;
		proto = Proto_num($2);

		if ( proto > 255 ) {
			yyerror("Protocol number > 255");
			YYABORT;
		}
		if ( proto < 0 ) {
			yyerror("Unknown protocol");
			YYABORT;
		}
		$$.self = NewBlock(OffsetProto, MaskProto, (proto << ShiftProto)  & MaskProto, CMP_EQ, FUNC_NONE, NULL); 
	}

	| dqual PACKETS comp NUMBER { 

		switch ( $1.direction ) {
			case DIR_UNSPEC:
			case DIR_IN: 
				$$.self = NewBlock(OffsetPackets, MaskPackets, $4, $3.comp, FUNC_NONE, NULL); 
				break;
			case DIR_OUT: 
				$$.self = NewBlock(OffsetOutPackets, MaskPackets, $4, $3.comp, FUNC_NONE, NULL); 
				break;
			default:
				/* should never happen */
				yyerror("This token is not expected here!");
				YYABORT;
		} // End of switch

	}

	| dqual BYTES comp NUMBER {	

		switch ( $1.direction ) {
			case DIR_UNSPEC:
			case DIR_IN: 
				$$.self = NewBlock(OffsetBytes, MaskBytes, $4, $3.comp, FUNC_NONE, NULL); 
				break;
			case DIR_OUT: 
				$$.self = NewBlock(OffsetOutBytes, MaskBytes, $4, $3.comp, FUNC_NONE, NULL); 
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		} // End of switch

	}

	| FLOWS comp NUMBER {	
			$$.self = NewBlock(OffsetAggrFlows, MaskFlows, $3, $2.comp, FUNC_NONE, NULL); 
	}

	| PPS comp NUMBER {	
		$$.self = NewBlock(0, AnyMask, $3, $2.comp, FUNC_PPS, NULL); 
	}

	| BPS comp NUMBER {	
		$$.self = NewBlock(0, AnyMask, $3, $2.comp, FUNC_BPS, NULL); 
	}

	| BPP comp NUMBER {	
		$$.self = NewBlock(0, AnyMask, $3, $2.comp, FUNC_BPP, NULL); 
	}

	| DURATION comp NUMBER {	
		$$.self = NewBlock(0, AnyMask, $3, $2.comp, FUNC_DURATION, NULL); 
	}

	| dqual TOS comp NUMBER {	
		if ( $4 > 255 ) {
			yyerror("TOS must be 0..255");
			YYABORT;
		}

		switch ( $1.direction ) {
			case DIR_UNSPEC:
			case SOURCE:
				$$.self = NewBlock(OffsetTos, MaskTos, ($4 << ShiftTos) & MaskTos, $3.comp, FUNC_NONE, NULL); 
				break;
			case DESTINATION:
				$$.self = NewBlock(OffsetDstTos, MaskDstTos, ($4 << ShiftDstTos) & MaskDstTos, $3.comp, FUNC_NONE, NULL); 
				break;
			case SOURCE_OR_DESTINATION: 
				$$.self = Connect_OR(
					NewBlock(OffsetTos, MaskTos, ($4 << ShiftTos) & MaskTos, $3.comp, FUNC_NONE, NULL),
					NewBlock(OffsetDstTos, MaskDstTos, ($4 << ShiftDstTos) & MaskDstTos, $3.comp, FUNC_NONE, NULL)
				);
				break;
			case SOURCE_AND_DESTINATION:
				$$.self = Connect_AND(
					NewBlock(OffsetTos, MaskTos, ($4 << ShiftTos) & MaskTos, $3.comp, FUNC_NONE, NULL),
					NewBlock(OffsetDstTos, MaskDstTos, ($4 << ShiftDstTos) & MaskDstTos, $3.comp, FUNC_NONE, NULL)
				);
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
			}
	}

	| FLAGS comp NUMBER	{	
		if ( $3 > 63 ) {
			yyerror("Flags must be 0..63");
			YYABORT;
		}
		$$.self = NewBlock(OffsetFlags, MaskFlags, ($3 << ShiftFlags) & MaskFlags, $2.comp, FUNC_NONE, NULL); 
	}

	| FLAGS STRING	{	
		uint64_t fl = 0;
		int cnt     = 0;
		size_t		len = strlen($2);

		if ( len > 7 ) {
			yyerror("Too many flags");
			YYABORT;
		}

		if ( strchr($2, 'F') ) { fl |=  1; cnt++; }
		if ( strchr($2, 'S') ) { fl |=  2; cnt++; }
		if ( strchr($2, 'R') ) { fl |=  4; cnt++; }
		if ( strchr($2, 'P') ) { fl |=  8; cnt++; }
		if ( strchr($2, 'A') ) { fl |=  16; cnt++; }
		if ( strchr($2, 'U') ) { fl |=  32; cnt++; }
		if ( strchr($2, 'X') ) { fl =  63; cnt++; }

		if ( cnt != len ) {
			yyerror("Too many flags");
			YYABORT;
		}

		$$.self = NewBlock(OffsetFlags, (fl << ShiftFlags) & MaskFlags, 
					(fl << ShiftFlags) & MaskFlags, CMP_FLAGS, FUNC_NONE, NULL); 
	}

	| dqual IP STRING { 	
		int af, bytes, ret;

		ret = parse_ip(&af, $3, IPstack, &bytes, ALLOW_LOOKUP, &num_ip);

		if ( ret == 0 ) {
			yyerror("Error parsing IP address.");
			YYABORT;
		}

		// ret == -1 will never happen here, as ALLOW_LOOKUP is set
		if ( ret == -2 ) {
			// could not resolv host => 'not any'
			$$.self = Invert(NewBlock(OffsetProto, 0, 0, CMP_EQ, FUNC_NONE, NULL )); 
		} else {
			uint64_t offsets[4] = {OffsetSrcIPv6a, OffsetSrcIPv6b, OffsetDstIPv6a, OffsetDstIPv6b };
			if ( af && (( af == PF_INET && bytes != 4 ) || ( af == PF_INET6 && bytes != 16 ))) {
				yyerror("incomplete IP address");
				YYABORT;
			}

			switch ( $1.direction ) {
				case SOURCE:
				case DESTINATION:
					$$.self = ChainHosts(offsets, IPstack, num_ip, $1.direction);
					break;
				case DIR_UNSPEC:
				case SOURCE_OR_DESTINATION: {
					uint32_t src = ChainHosts(offsets, IPstack, num_ip, SOURCE);
					uint32_t dst = ChainHosts(offsets, IPstack, num_ip, DESTINATION);
					$$.self = Connect_OR(src, dst);
					} break;
				case SOURCE_AND_DESTINATION: {
					uint32_t src = ChainHosts(offsets, IPstack, num_ip, SOURCE);
					uint32_t dst = ChainHosts(offsets, IPstack, num_ip, DESTINATION);
					$$.self = Connect_AND(src, dst);
					} break;
				default:
					yyerror("This token is not expected here!");
					YYABORT;
	
			} // End of switch

		}
	}

	| dqual IP IN '[' iplist ']' { 	

		switch ( $1.direction ) {
			case SOURCE:
				$$.self = NewBlock(OffsetSrcIPv6a, MaskIPv6, 0 , CMP_IPLIST, FUNC_NONE, (void *)$5 );
				break;
			case DESTINATION:
				$$.self = NewBlock(OffsetDstIPv6a, MaskIPv6, 0 , CMP_IPLIST, FUNC_NONE, (void *)$5 );
				break;
			case DIR_UNSPEC:
			case SOURCE_OR_DESTINATION:
				$$.self = Connect_OR(
					NewBlock(OffsetSrcIPv6a, MaskIPv6, 0 , CMP_IPLIST, FUNC_NONE, (void *)$5 ),
					NewBlock(OffsetDstIPv6a, MaskIPv6, 0 , CMP_IPLIST, FUNC_NONE, (void *)$5 )
				);
				break;
			case SOURCE_AND_DESTINATION:
				$$.self = Connect_AND(
					NewBlock(OffsetSrcIPv6a, MaskIPv6, 0 , CMP_IPLIST, FUNC_NONE, (void *)$5 ),
					NewBlock(OffsetDstIPv6a, MaskIPv6, 0 , CMP_IPLIST, FUNC_NONE, (void *)$5 )
				);
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		}
	}

	| NEXT IP STRING { 	
		int af, bytes, ret;

		ret = parse_ip(&af, $3, IPstack, &bytes, STRICT_IP, &num_ip);

		if ( ret == 0 ) {
			yyerror("Error parsing IP address.");
			YYABORT;
		}

		if ( ret == -1 ) {
			yyerror("IP address required - hostname not allowed here.");
			YYABORT;
		}
		// ret == -2 will never happen here, as STRICT_IP is set

		if ( af && (( af == PF_INET && bytes != 4 ) || ( af == PF_INET6 && bytes != 16 ))) {
			yyerror("incomplete IP address");
			YYABORT;
		}

		$$.self = Connect_AND(
			NewBlock(OffsetNexthopv6b, MaskIPv6, IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
			NewBlock(OffsetNexthopv6a, MaskIPv6, IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
		);
	}

	| NEXT IP IN '[' iplist ']' { 	

		$$.self = NewBlock(OffsetNexthopv6a, MaskIPv6, 0 , CMP_IPLIST, FUNC_NONE, (void *)$5 );

	}

	| BGPNEXTHOP IP STRING { 	
		int af, bytes, ret;

		ret = parse_ip(&af, $3, IPstack, &bytes, STRICT_IP, &num_ip);

		if ( ret == 0 ) {
			yyerror("Error parsing IP address.");
			YYABORT;
		}

		if ( ret == -1 ) {
			yyerror("IP address required - hostname not allowed here.");
			YYABORT;
		}
		// ret == -2 will never happen here, as STRICT_IP is set

		if ( af && (( af == PF_INET && bytes != 4 ) || ( af == PF_INET6 && bytes != 16 ))) {
			yyerror("incomplete IP address");
			YYABORT;
		}

		$$.self = Connect_AND(
			NewBlock(OffsetBGPNexthopv6b, MaskIPv6, IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
			NewBlock(OffsetBGPNexthopv6a, MaskIPv6, IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
		);
	}

	| ROUTER IP STRING { 	
		int af, bytes, ret;

		ret = parse_ip(&af, $3, IPstack, &bytes, STRICT_IP, &num_ip);

		if ( ret == 0 ) {
			yyerror("Error parsing IP address.");
			YYABORT;
		}

		if ( ret == -1 ) {
			yyerror("IP address required - hostname not allowed here.");
			YYABORT;
		}
		// ret == -2 will never happen here, as STRICT_IP is set

		if ( af && (( af == PF_INET && bytes != 4 ) || ( af == PF_INET6 && bytes != 16 ))) {
			yyerror("incomplete IP address");
			YYABORT;
		}

		$$.self = Connect_AND(
			NewBlock(OffsetRouterv6b, MaskIPv6, IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
			NewBlock(OffsetRouterv6a, MaskIPv6, IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
		);
	}

	| CLIENT LATENCY comp NUMBER { 	
		$$.self = NewBlock(OffsetClientLatency, MaskLatency, $4, $3.comp, FUNC_NONE, NULL); 
	}

	| SERVER LATENCY comp NUMBER { 	
		$$.self = NewBlock(OffsetServerLatency, MaskLatency, $4, $3.comp, FUNC_NONE, NULL); 
	}

	| APP LATENCY comp NUMBER { 	
		$$.self = NewBlock(OffsetAppLatency, MaskLatency, $4, $3.comp, FUNC_NONE, NULL); 
	}

	| SYSID NUMBER { 	
		if ( $2 > 255 ) {
			yyerror("Router SysID expected between be 1..255");
			YYABORT;
		}
		$$.self = NewBlock(OffsetExporterSysID, MaskExporterSysID, ($2 << ShiftExporterSysID) & MaskExporterSysID, CMP_EQ, FUNC_NONE, NULL); 
	}

	| dqual PORT comp NUMBER {	
		if ( $4 > 65535 ) {
			yyerror("Port outside of range 0..65535");
			YYABORT;
		}

		switch ( $1.direction ) {
			case SOURCE:
				$$.self = NewBlock(OffsetPort, MaskSrcPort, ($4 << ShiftSrcPort) & MaskSrcPort, $3.comp, FUNC_NONE, NULL );
				break;
			case DESTINATION:
				$$.self = NewBlock(OffsetPort, MaskDstPort, ($4 << ShiftDstPort) & MaskDstPort, $3.comp, FUNC_NONE, NULL );
				break;
			case DIR_UNSPEC:
			case SOURCE_OR_DESTINATION:
				$$.self = Connect_OR(
					NewBlock(OffsetPort, MaskSrcPort, ($4 << ShiftSrcPort) & MaskSrcPort, $3.comp, FUNC_NONE, NULL ),
					NewBlock(OffsetPort, MaskDstPort, ($4 << ShiftDstPort) & MaskDstPort, $3.comp, FUNC_NONE, NULL )
				);
				break;
			case SOURCE_AND_DESTINATION:
				$$.self = Connect_AND(
					NewBlock(OffsetPort, MaskSrcPort, ($4 << ShiftSrcPort) & MaskSrcPort, $3.comp, FUNC_NONE, NULL ),
					NewBlock(OffsetPort, MaskDstPort, ($4 << ShiftDstPort) & MaskDstPort, $3.comp, FUNC_NONE, NULL )
				);
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		} // End switch

	}

	| dqual PORT IN PBLOCK {	
#ifdef NSEL
		switch ( $1.direction ) {
			case SOURCE:
					$$.self = NewBlock(OffsetPort, MaskSrcPort, ShiftSrcPort, CMP_EQ, FUNC_PBLOCK, NULL );
				break;
			case DESTINATION:
					$$.self = NewBlock(OffsetPort, MaskDstPort, ShiftDstPort, CMP_EQ, FUNC_PBLOCK, NULL );
				break;
			case DIR_UNSPEC:
			case SOURCE_OR_DESTINATION:
				$$.self = Connect_OR(
					NewBlock(OffsetPort, MaskSrcPort, ShiftSrcPort, CMP_EQ, FUNC_PBLOCK, NULL ),
					NewBlock(OffsetPort, MaskDstPort, ShiftDstPort, CMP_EQ, FUNC_PBLOCK, NULL )
				);
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		} // End switch

#else
		yyerror("NAT filters not available");
		YYABORT;
#endif
	}

	| dqual PORT IN '[' ullist ']' { 	
		struct ULongListNode *node;
		ULongtree_t *root = NULL;

		if ( $1.direction == DIR_UNSPEC || $1.direction == SOURCE_OR_DESTINATION || $1.direction == SOURCE_AND_DESTINATION ) {
			// src and/or dst port
			// we need a second rbtree due to different shifts for src and dst ports
			root = malloc(sizeof(ULongtree_t));

			struct ULongListNode *n;
			if ( root == NULL) {
				yyerror("malloc() error");
				YYABORT;
			}
			RB_INIT(root);

			RB_FOREACH(node, ULongtree, (ULongtree_t *)$5) {
				if ( node->value > 65535 ) {
					yyerror("Port outside of range 0..65535");
					YYABORT;
				}
				if ((n = malloc(sizeof(struct ULongListNode))) == NULL) {
					yyerror("malloc() error");
					YYABORT;
				}
				n->value 	= (node->value << ShiftDstPort) & MaskDstPort;
				node->value = (node->value << ShiftSrcPort) & MaskSrcPort;
				RB_INSERT(ULongtree, root, n);
			}
		}

		switch ( $1.direction ) {
			case SOURCE:
				RB_FOREACH(node, ULongtree, (ULongtree_t *)$5) {
					node->value = (node->value << ShiftSrcPort) & MaskSrcPort;
				}
				$$.self = NewBlock(OffsetPort, MaskSrcPort, 0, CMP_ULLIST, FUNC_NONE, (void *)$5 );
				break;
			case DESTINATION:
				RB_FOREACH(node, ULongtree, (ULongtree_t *)$5) {
					node->value = (node->value << ShiftDstPort) & MaskDstPort;
				}
				$$.self = NewBlock(OffsetPort, MaskDstPort, 0, CMP_ULLIST, FUNC_NONE, (void *)$5 );
				break;
			case DIR_UNSPEC:
			case SOURCE_OR_DESTINATION:
				$$.self = Connect_OR(
					NewBlock(OffsetPort, MaskSrcPort, 0, CMP_ULLIST, FUNC_NONE, (void *)$5 ),
					NewBlock(OffsetPort, MaskDstPort, 0, CMP_ULLIST, FUNC_NONE, (void *)root )
				);
				break;
			case SOURCE_AND_DESTINATION:
				$$.self = Connect_AND(
					NewBlock(OffsetPort, MaskSrcPort, 0, CMP_ULLIST, FUNC_NONE, (void *)$5 ),
					NewBlock(OffsetPort, MaskDstPort, 0, CMP_ULLIST, FUNC_NONE, (void *)root )
				);
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		} // End of switch

	}

	| ICMP_TYPE NUMBER {
		if ( $2 > 255 ) {
			yyerror("ICMP tpye of range 0..15");
			YYABORT;
		}
		$$.self = Connect_AND(
			// imply proto ICMP with a proto ICMP block
			Connect_OR (
				NewBlock(OffsetProto, MaskProto, ((uint64_t)IPPROTO_ICMP << ShiftProto)  & MaskProto, CMP_EQ, FUNC_NONE, NULL), 
				NewBlock(OffsetProto, MaskProto, ((uint64_t)IPPROTO_ICMPV6 << ShiftProto)  & MaskProto, CMP_EQ, FUNC_NONE, NULL)
			),
			NewBlock(OffsetPort, MaskICMPtype, ($2 << ShiftICMPtype) & MaskICMPtype, CMP_EQ, FUNC_NONE, NULL )
		);

	}

	| ICMP_CODE NUMBER {
		if ( $2 > 255 ) {
			yyerror("ICMP code of range 0..15");
			YYABORT;
		}
		$$.self = Connect_AND(
			// imply proto ICMP with a proto ICMP block
			Connect_OR (
				NewBlock(OffsetProto, MaskProto, ((uint64_t)IPPROTO_ICMP << ShiftProto)  & MaskProto, CMP_EQ, FUNC_NONE, NULL), 
				NewBlock(OffsetProto, MaskProto, ((uint64_t)IPPROTO_ICMPV6 << ShiftProto)  & MaskProto, CMP_EQ, FUNC_NONE, NULL)
			),
			NewBlock(OffsetPort, MaskICMPcode, ($2 << ShiftICMPcode) & MaskICMPcode, CMP_EQ, FUNC_NONE, NULL )
		);

	}

	| ENGINE_TYPE comp NUMBER {
		if ( $3 > 255 ) {
			yyerror("Engine type of range 0..255");
			YYABORT;
		}
		$$.self = NewBlock(OffsetRouterID, MaskEngineType, ($3 << ShiftEngineType) & MaskEngineType, $2.comp, FUNC_NONE, NULL);

	}

	| ENGINE_ID comp NUMBER {
		if ( $3 > 255 ) {
			yyerror("Engine ID of range 0..255");
			YYABORT;
		}
		$$.self = NewBlock(OffsetRouterID, MaskEngineID, ($3 << ShiftEngineID) & MaskEngineID, $2.comp, FUNC_NONE, NULL);

	}
 
	| ASA EVENT REASON {
#ifdef NSEL
		if ( strncasecmp($3,"ignore", 6) == 0) {
			$$.self = NewBlock(OffsetConnID, MaskFWevent, ( NSEL_EVENT_IGNORE << ShiftFWevent) & MaskFWevent, CMP_EQ, FUNC_NONE, NULL );
		} else if( strncasecmp($3,"create", 6) == 0) {
			$$.self = NewBlock(OffsetConnID, MaskFWevent, ( NSEL_EVENT_CREATE << ShiftFWevent) & MaskFWevent, CMP_EQ, FUNC_NONE, NULL );
		} else if( strncasecmp($3,"term", 4) == 0 || strncasecmp($3,"delete", 6) == 0) {
			$$.self = NewBlock(OffsetConnID, MaskFWevent, ( NSEL_EVENT_DELETE << ShiftFWevent) & MaskFWevent, CMP_EQ, FUNC_NONE, NULL );
		} else if  (strncasecmp($3,"deny", 4) == 0) {
			$$.self = NewBlock(OffsetConnID, MaskFWevent, ( NSEL_EVENT_DENIED << ShiftFWevent) & MaskFWevent, CMP_EQ, FUNC_NONE, NULL );
		} else if  (strncasecmp($3,"alert", 5) == 0) {
			$$.self = NewBlock(OffsetConnID, MaskFWevent, ( NSEL_EVENT_ALERT << ShiftFWevent) & MaskFWevent, CMP_EQ, FUNC_NONE, NULL );
		} else if  (strncasecmp($3,"update", 6) == 0) {
			$$.self = NewBlock(OffsetConnID, MaskFWevent, ( NSEL_EVENT_UPDATE << ShiftFWevent) & MaskFWevent, CMP_EQ, FUNC_NONE, NULL );
		} else {
			yyerror("Unknown asa event");
			YYABORT;
		}
#else
		yyerror("NSEL/ASA filters not available");
		YYABORT;
#endif
	}

	| ASA EVENT comp NUMBER {
#ifdef NSEL
		if ( $4 > 255 ) {
			yyerror("Invalid xevent ID");
			YYABORT;
		}
		$$.self = NewBlock(OffsetConnID, MaskFWevent, ( $4 << ShiftFWevent) & MaskFWevent, $3.comp, FUNC_NONE, NULL );
#else
		yyerror("NSEL/ASA filters not available");
		YYABORT;
#endif
	}

	| ASA EVENT DENIED inout {
#ifdef NSEL
		uint64_t xevent = 0;
		if ( $4.inout == INGRESS ) {
			xevent = 1001;
		} else if ( $4.inout == EGRESS ) {
			xevent = 1002;
		} else {
				yyerror("Invalid inout token");
				YYABORT;
		}
		$$.self = Connect_AND(
			NewBlock(OffsetConnID, MaskFWevent, ( NSEL_EVENT_DENIED << ShiftFWevent) & MaskFWevent, CMP_EQ, FUNC_NONE, NULL ),
			NewBlock(OffsetConnID, MaskFWXevent, ( xevent << ShiftFWXevent) & MaskFWXevent, CMP_EQ, FUNC_NONE, NULL )
		);
#else
		yyerror("NSEL/ASA filters not available");
		YYABORT;
#endif
	}
	| ASA EVENT DENIED STRING {
#ifdef NSEL
		uint64_t xevent = 0;
		if( strncasecmp($4,"interface", 9) == 0) {
			xevent = 1003;
		} else if( strncasecmp($4,"nosyn", 5) == 0) {
			xevent = 1004;
		} else {
			xevent = (uint64_t)strtol($4, (char **)NULL, 10);
			if ( (xevent == 0 && errno == EINVAL) || xevent > 65535 ) {
				yyerror("Invalid xevent ID");
				YYABORT;
			}
		}
		$$.self = Connect_AND(
			NewBlock(OffsetConnID, MaskFWevent, ( NSEL_EVENT_DENIED << ShiftFWevent) & MaskFWevent, CMP_EQ, FUNC_NONE, NULL ),
			NewBlock(OffsetConnID, MaskFWXevent, ( xevent << ShiftFWXevent) & MaskFWXevent, CMP_EQ, FUNC_NONE, NULL )
		);
#else
		yyerror("NSEL/ASA filters not available");
		YYABORT;
#endif
	}

	| ASA XEVENT comp NUMBER {
#ifdef NSEL
		if ( $4 > 65535 ) {
			yyerror("Invalid xevent ID");
			YYABORT;
		}
		$$.self = NewBlock(OffsetConnID, MaskFWXevent, ( $4 << ShiftFWXevent) & MaskFWXevent, $3.comp, FUNC_NONE, NULL );
#else
		yyerror("NSEL/ASA filters not available");
		YYABORT;
#endif
	}

	| dqual XIP STRING { 	
#ifdef NSEL
		int af, bytes, ret;

		ret = parse_ip(&af, $3, IPstack, &bytes, ALLOW_LOOKUP, &num_ip);

		if ( ret == 0 ) {
			yyerror("Error parsing IP address.");
			YYABORT;
		}

		// ret == -1 will never happen here, as ALLOW_LOOKUP is set
		if ( ret == -2 ) {
			// could not resolv host => 'not any'
			$$.self = Invert(NewBlock(OffsetProto, 0, 0, CMP_EQ, FUNC_NONE, NULL )); 
		} else {
			uint64_t offsets[4] = {OffsetXLATESRCv6a, OffsetXLATESRCv6b, OffsetXLATEDSTv6a, OffsetXLATEDSTv6b };
			if ( af && (( af == PF_INET && bytes != 4 ) || ( af == PF_INET6 && bytes != 16 ))) {
				yyerror("incomplete IP address");
				YYABORT;
			}

			switch ( $1.direction ) {
				case SOURCE:
				case DESTINATION:
					$$.self = ChainHosts(offsets, IPstack, num_ip, $1.direction);
					break;
				case DIR_UNSPEC:
				case SOURCE_OR_DESTINATION: {
					uint32_t src = ChainHosts(offsets, IPstack, num_ip, SOURCE);
					uint32_t dst = ChainHosts(offsets, IPstack, num_ip, DESTINATION);
					$$.self = Connect_OR(src, dst);
					} break;
				case SOURCE_AND_DESTINATION: {
					uint32_t src = ChainHosts(offsets, IPstack, num_ip, SOURCE);
					uint32_t dst = ChainHosts(offsets, IPstack, num_ip, DESTINATION);
					$$.self = Connect_AND(src, dst);
					} break;
				default:
					yyerror("This token is not expected here!");
					YYABORT;
	
			} // End of switch

		}
#else
		yyerror("NSEL/ASA filters not available");
		YYABORT;
#endif
	}

	| dqual XNET STRING '/' NUMBER { 
#ifdef NSEL
		int af, bytes, ret;
		uint64_t	mask[2];

		ret = parse_ip(&af, $3, IPstack, &bytes, STRICT_IP, &num_ip);
		if ( ret == 0 ) {
			yyerror("Invalid IP address");
			YYABORT;
		}
		if ( ret == -1 ) {
			yyerror("IP address required - hostname not allowed here.");
			YYABORT;
		}
		// ret == -2 will never happen here, as STRICT_IP is set


		if ( $5 > (bytes*8) ) {
			yyerror("Too many netbits for this IP addresss");
			YYABORT;
		}

		if ( af == PF_INET ) {
			mask[0] = 0xffffffffffffffffLL;
			mask[1] = 0xffffffffffffffffLL << ( 32 - $5 );
		} else {	// PF_INET6
			if ( $5 > 64 ) {
				mask[0] = 0xffffffffffffffffLL;
				mask[1] = 0xffffffffffffffffLL << ( 128 - $5 );
			} else {
				mask[0] = 0xffffffffffffffffLL << ( 64 - $5 );
				mask[1] = 0;
			}
		}
		// IP aadresses are stored in network representation 
		mask[0]	 = mask[0];
		mask[1]	 = mask[1];

		IPstack[0] &= mask[0];
		IPstack[1] &= mask[1];

		switch ( $1.direction ) {
			case SOURCE:
				$$.self = Connect_AND(
					NewBlock(OffsetXLATESRCv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
					NewBlock(OffsetXLATESRCv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
				);
				break;
			case DESTINATION:
				$$.self = Connect_AND(
					NewBlock(OffsetXLATEDSTv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
					NewBlock(OffsetXLATEDSTv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
				);
				break;
			case DIR_UNSPEC:
			case SOURCE_OR_DESTINATION:
				$$.self = Connect_OR(
					Connect_AND(
						NewBlock(OffsetXLATESRCv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetXLATESRCv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
					),
					Connect_AND(
						NewBlock(OffsetXLATEDSTv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetXLATEDSTv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
					)
				);
				break;
			case SOURCE_AND_DESTINATION:
				$$.self = Connect_AND(
					Connect_AND(
						NewBlock(OffsetXLATESRCv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetXLATESRCv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
					),
					Connect_AND(
						NewBlock(OffsetXLATEDSTv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetXLATEDSTv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
					)
				);
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		} // End of switch

#else
		yyerror("NSEL/ASA filters not available");
		YYABORT;
#endif
	}

	| dqual XPORT comp NUMBER {	
#ifdef NSEL
		if ( $4 > 65535 ) {
			yyerror("Port outside of range 0..65535");
			YYABORT;
		}

		switch ( $1.direction ) {
			case SOURCE:
				$$.self = NewBlock(OffsetXLATEPort, MaskXLATESRCPORT, ($4 << ShiftXLATESRCPORT) & MaskXLATESRCPORT, $3.comp, FUNC_NONE, NULL );
				break;
			case DESTINATION:
				$$.self = NewBlock(OffsetXLATEPort, MaskXLATEDSTPORT, ($4 << ShiftXLATEDSTPORT) & MaskXLATEDSTPORT, $3.comp, FUNC_NONE, NULL );
				break;
			case DIR_UNSPEC:
			case SOURCE_OR_DESTINATION:
				$$.self = Connect_OR(
					NewBlock(OffsetXLATEPort, MaskXLATESRCPORT, ($4 << ShiftXLATESRCPORT) & MaskXLATESRCPORT, $3.comp, FUNC_NONE, NULL ),
					NewBlock(OffsetXLATEPort, MaskXLATEDSTPORT, ($4 << ShiftXLATEDSTPORT) & MaskXLATEDSTPORT, $3.comp, FUNC_NONE, NULL )
				);
				break;
			case SOURCE_AND_DESTINATION:
				$$.self = Connect_AND(
					NewBlock(OffsetXLATEPort, MaskXLATESRCPORT, ($4 << ShiftXLATESRCPORT) & MaskXLATESRCPORT, $3.comp, FUNC_NONE, NULL ),
					NewBlock(OffsetXLATEPort, MaskXLATEDSTPORT, ($4 << ShiftXLATEDSTPORT) & MaskXLATEDSTPORT, $3.comp, FUNC_NONE, NULL )
				);
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		} // End switch
#else
		yyerror("NSEL/ASA filters not available");
		YYABORT;
#endif

	}

	| inout acl comp NUMBER {
#ifdef NSEL
		uint64_t offset, mask, shift;
		if ( $1.inout == INGRESS ) {
			switch ($2.acl) {
				case ACL:
					offset = OffsetIngressAclId;
					mask   = MaskIngressAclId;	
					shift  = ShiftIngressAclId;
					break;
				case ACE:
					offset = OffsetIngressAceId;
					mask   = MaskIngressAceId;	
					shift  = ShiftIngressAceId;
					break;
				case XACE:
					offset = OffsetIngressGrpId;
					mask   = MaskIngressGrpId;	
					shift  = ShiftIngressGrpId;
					break;
				default:
					yyerror("Invalid ACL specifier");
					YYABORT;
			}
		} else if ( $1.inout == EGRESS && $$.acl == ACL ) {
			offset = OffsetEgressAclId;
			mask   = MaskEgressAclId;	
			shift  = ShiftEgressAclId;
		} else {
			yyerror("ingress/egress syntax error");
			YYABORT;
		}
		$$.self = NewBlock(offset, mask, ($4 << shift) & mask , $3.comp, FUNC_NONE, NULL );

#else
		yyerror("NSEL/ASA filters not available");
		YYABORT;
#endif
	}

	| NAT EVENT REASON {
#ifdef NSEL
		if ( strncasecmp($3,"invalid", 7) == 0) {
			$$.self = NewBlock(OffsetNATevent, MasNATevent, ( NEL_EVENT_INVALID << ShiftNATevent) & MasNATevent, CMP_EQ, FUNC_NONE, NULL );
		} else if( strncasecmp($3,"add", 3) == 0 || strncasecmp($3,"create", 6) == 0) {
			$$.self = NewBlock(OffsetNATevent, MasNATevent, ( NEL_EVENT_ADD << ShiftNATevent) & MasNATevent, CMP_EQ, FUNC_NONE, NULL );
		} else if( strncasecmp($3,"delete", 6) == 0) {
			$$.self = NewBlock(OffsetNATevent, MasNATevent, ( NEL_EVENT_DELETE << ShiftNATevent) & MasNATevent, CMP_EQ, FUNC_NONE, NULL );
		} else {
			yyerror("Unknown nat event");
			YYABORT;
		}
#else
		yyerror("NAT filters not available");
		YYABORT;
#endif
	}

	| NAT EVENT comp NUMBER {
#ifdef NSEL
		if ( $4 > 255 ) {
			yyerror("Invalid event ID");
			YYABORT;
		}
		$$.self = NewBlock(OffsetNATevent, MasNATevent, ( $4 << ShiftNATevent) & MasNATevent, $3.comp, FUNC_NONE, NULL );
#else
		yyerror("NAT filters not available");
		YYABORT;
#endif
	}

	| INGRESS VRF comp NUMBER {
#ifdef NSEL
		if ( $4 > 0xFFFFFFFFLL ) {
			yyerror("Invalid ingress vrf ID");
			YYABORT;
		}
		$$.self = NewBlock(OffsetIVRFID, MaskIVRFID, ( $4 << ShiftIVRFID) & MaskIVRFID, $3.comp, FUNC_NONE, NULL );
#else
		yyerror("NAT filters not available");
		YYABORT;
#endif
	}

	| EGRESS VRF comp NUMBER {
#ifdef NSEL
		if ( $4 > 0xFFFFFFFFLL ) {
			yyerror("Invalid egress vrf ID");
			YYABORT;
		}
		$$.self = NewBlock(OffsetEVRFID, MaskEVRFID, ( $4 << ShiftEVRFID) & MaskEVRFID, $3.comp, FUNC_NONE, NULL );
#else
		yyerror("NAT filters not available");
		YYABORT;
#endif
	}

	| PBLOCK START comp NUMBER {
#ifdef NSEL
		if ( $4 > 65536 ) {
			yyerror("Invalid port");
			YYABORT;
		}
		$$.self = NewBlock(OffsetPortBlock, MaskPortBlockStart, ( $4 << ShiftPortBlockStart) & MaskPortBlockStart, $3.comp, FUNC_NONE, NULL );
#else
		yyerror("NAT filters not available");
		YYABORT;
#endif
	}

	| PBLOCK END comp NUMBER {
#ifdef NSEL
		if ( $4 > 65536 ) {
			yyerror("Invalid port");
			YYABORT;
		}
		$$.self = NewBlock(OffsetPortBlock, MaskPortBlockEnd, ( $4 << ShiftPortBlockEnd) & MaskPortBlockEnd, $3.comp, FUNC_NONE, NULL );
#else
		yyerror("NAT filters not available");
		YYABORT;
#endif
	}

	| PBLOCK STEP comp NUMBER {
#ifdef NSEL
		if ( $4 > 65536 ) {
			yyerror("Invalid port");
			YYABORT;
		}
		$$.self = NewBlock(OffsetPortBlock, MaskPortBlockStep, ( $4 << ShiftPortBlockStep) & MaskPortBlockStep, $3.comp, FUNC_NONE, NULL );
#else
		yyerror("NAT filters not available");
		YYABORT;
#endif
	}

	| PBLOCK SIZE comp NUMBER {
#ifdef NSEL
		if ( $4 > 65536 ) {
			yyerror("Invalid port");
			YYABORT;
		}
		$$.self = NewBlock(OffsetPortBlock, MaskPortBlockSize, ( $4 << ShiftPortBlockSize) & MaskPortBlockSize, $3.comp, FUNC_NONE, NULL );
#else
		yyerror("NAT filters not available");
		YYABORT;
#endif
	}

	| dqual NPORT comp NUMBER {	
#ifdef NSEL
		if ( $4 > 65535 ) {
			yyerror("Port outside of range 0..65535");
			YYABORT;
		}

		switch ( $1.direction ) {
			case SOURCE:
				$$.self = NewBlock(OffsetXLATEPort, MaskXLATESRCPORT, ($4 << ShiftXLATESRCPORT) & MaskXLATESRCPORT, $3.comp, FUNC_NONE, NULL );
				break;
			case DESTINATION:
				$$.self = NewBlock(OffsetXLATEPort, MaskXLATEDSTPORT, ($4 << ShiftXLATEDSTPORT) & MaskXLATEDSTPORT, $3.comp, FUNC_NONE, NULL );
				break;
			case DIR_UNSPEC:
			case SOURCE_OR_DESTINATION:
				$$.self = Connect_OR(
					NewBlock(OffsetXLATEPort, MaskXLATESRCPORT, ($4 << ShiftXLATESRCPORT) & MaskXLATESRCPORT, $3.comp, FUNC_NONE, NULL ),
					NewBlock(OffsetXLATEPort, MaskXLATEDSTPORT, ($4 << ShiftXLATEDSTPORT) & MaskXLATEDSTPORT, $3.comp, FUNC_NONE, NULL )
				);
				break;
			case SOURCE_AND_DESTINATION:
				$$.self = Connect_AND(
					NewBlock(OffsetXLATEPort, MaskXLATESRCPORT, ($4 << ShiftXLATESRCPORT) & MaskXLATESRCPORT, $3.comp, FUNC_NONE, NULL ),
					NewBlock(OffsetXLATEPort, MaskXLATEDSTPORT, ($4 << ShiftXLATEDSTPORT) & MaskXLATEDSTPORT, $3.comp, FUNC_NONE, NULL )
				);
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		} // End switch
#else
		yyerror("NEL/NAT filters not available");
		YYABORT;
#endif

	}

	| dqual NIP STRING { 	
#ifdef NSEL
		int af, bytes, ret;

		ret = parse_ip(&af, $3, IPstack, &bytes, ALLOW_LOOKUP, &num_ip);

		if ( ret == 0 ) {
			yyerror("Error parsing IP address.");
			YYABORT;
		}

		// ret == -1 will never happen here, as ALLOW_LOOKUP is set
		if ( ret == -2 ) {
			// could not resolv host => 'not any'
			$$.self = Invert(NewBlock(OffsetProto, 0, 0, CMP_EQ, FUNC_NONE, NULL )); 
		} else {
			uint64_t offsets[4] = {OffsetXLATESRCv6a, OffsetXLATESRCv6b, OffsetXLATEDSTv6a, OffsetXLATEDSTv6b };
			if ( af && (( af == PF_INET && bytes != 4 ) || ( af == PF_INET6 && bytes != 16 ))) {
				yyerror("incomplete IP address");
				YYABORT;
			}

			switch ( $1.direction ) {
				case SOURCE:
				case DESTINATION:
					$$.self = ChainHosts(offsets, IPstack, num_ip, $1.direction);
					break;
				case DIR_UNSPEC:
				case SOURCE_OR_DESTINATION: {
					uint32_t src = ChainHosts(offsets, IPstack, num_ip, SOURCE);
					uint32_t dst = ChainHosts(offsets, IPstack, num_ip, DESTINATION);
					$$.self = Connect_OR(src, dst);
					} break;
				case SOURCE_AND_DESTINATION: {
					uint32_t src = ChainHosts(offsets, IPstack, num_ip, SOURCE);
					uint32_t dst = ChainHosts(offsets, IPstack, num_ip, DESTINATION);
					$$.self = Connect_AND(src, dst);
					} break;
				default:
					yyerror("This token is not expected here!");
					YYABORT;
	
			} // End of switch

		}
#else
		yyerror("NSEL/ASA filters not available");
		YYABORT;
#endif
	}

	| dqual AS comp NUMBER {	
		if ( $4 > 0xfFFFFFFF ) {
			yyerror("AS number of range");
			YYABORT;
		}

		switch ( $1.direction ) {
			case SOURCE:
				$$.self = NewBlock(OffsetAS, MaskSrcAS, ($4 << ShiftSrcAS) & MaskSrcAS, $3.comp, FUNC_NONE, NULL );
				break;
			case DESTINATION:
				$$.self = NewBlock(OffsetAS, MaskDstAS, ($4 << ShiftDstAS) & MaskDstAS, $3.comp, FUNC_NONE, NULL);
				break;
			case DIR_UNSPEC:
			case SOURCE_OR_DESTINATION:
				$$.self = Connect_OR(
					NewBlock(OffsetAS, MaskSrcAS, ($4 << ShiftSrcAS) & MaskSrcAS, $3.comp, FUNC_NONE, NULL ),
					NewBlock(OffsetAS, MaskDstAS, ($4 << ShiftDstAS) & MaskDstAS, $3.comp, FUNC_NONE, NULL)
				);
				break;
			case SOURCE_AND_DESTINATION:
				$$.self = Connect_AND(
					NewBlock(OffsetAS, MaskSrcAS, ($4 << ShiftSrcAS) & MaskSrcAS, $3.comp, FUNC_NONE, NULL ),
					NewBlock(OffsetAS, MaskDstAS, ($4 << ShiftDstAS) & MaskDstAS, $3.comp, FUNC_NONE, NULL)
				);
				break;
			case ADJ_PREV:
				$$.self = NewBlock(OffsetBGPadj, MaskBGPadjPrev, ($4 << ShiftBGPadjPrev) & MaskBGPadjPrev, $3.comp, FUNC_NONE, NULL );
				break;
			case ADJ_NEXT:
				$$.self = NewBlock(OffsetBGPadj, MaskBGPadjNext, ($4 << ShiftBGPadjNext) & MaskBGPadjNext, $3.comp, FUNC_NONE, NULL );
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		} // End of switch

	}

	| dqual AS IN '[' ullist ']' { 	
		struct ULongListNode *node;
		ULongtree_t *root = NULL;

		if ( $1.direction == DIR_UNSPEC || $1.direction == SOURCE_OR_DESTINATION || $1.direction == SOURCE_AND_DESTINATION ) {
			// src and/or dst AS
			// we need a second rbtree due to different shifts for src and dst AS
			root = malloc(sizeof(ULongtree_t));

			struct ULongListNode *n;
			if ( root == NULL) {
				yyerror("malloc() error");
				YYABORT;
			}
			RB_INIT(root);

			RB_FOREACH(node, ULongtree, (ULongtree_t *)$5) {
				if ( node->value > 0xFFFFFFFFLL ) {
					yyerror("AS number of range");
					YYABORT;
				}
				if ((n = malloc(sizeof(struct ULongListNode))) == NULL) {
					yyerror("malloc() error");
					YYABORT;
				}
				n->value 	= (node->value << ShiftDstAS) & MaskDstAS;
				node->value = (node->value << ShiftSrcAS) & MaskSrcAS;
				RB_INSERT(ULongtree, root, n);
			}
		}

		switch ( $1.direction ) {
			case SOURCE:
				RB_FOREACH(node, ULongtree, (ULongtree_t *)$5) {
					node->value = (node->value << ShiftSrcAS) & MaskSrcAS;
				}
				$$.self = NewBlock(OffsetAS, MaskSrcAS, 0, CMP_ULLIST, FUNC_NONE, (void *)$5 );
				break;
			case DESTINATION:
				RB_FOREACH(node, ULongtree, (ULongtree_t *)$5) {
					node->value = (node->value << ShiftDstAS) & MaskDstAS;
				}
				$$.self = NewBlock(OffsetAS, MaskDstAS, 0, CMP_ULLIST, FUNC_NONE, (void *)$5 );
				break;
			case DIR_UNSPEC:
			case SOURCE_OR_DESTINATION:
				$$.self = Connect_OR(
					NewBlock(OffsetAS, MaskSrcAS, 0, CMP_ULLIST, FUNC_NONE, (void *)$5 ),
					NewBlock(OffsetAS, MaskDstAS, 0, CMP_ULLIST, FUNC_NONE, (void *)root )
				);
				break;
			case SOURCE_AND_DESTINATION:
				$$.self = Connect_AND(
					NewBlock(OffsetAS, MaskSrcAS, 0, CMP_ULLIST, FUNC_NONE, (void *)$5 ),
					NewBlock(OffsetAS, MaskDstAS, 0, CMP_ULLIST, FUNC_NONE, (void *)root )
				);
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		}

	}

	| dqual MASK NUMBER {	
		if ( $3 > 255 ) {
			yyerror("Mask outside of range 0..255");
			YYABORT;
		}

		switch ( $1.direction ) {
			case SOURCE:
				$$.self = NewBlock(OffsetMask, MaskSrcMask, ($3 << ShiftSrcMask) & MaskSrcMask, CMP_EQ, FUNC_NONE, NULL );
				break;
			case DESTINATION:
				$$.self = NewBlock(OffsetMask, MaskDstMask, ($3 << ShiftDstMask) & MaskDstMask, CMP_EQ, FUNC_NONE, NULL );
				break;
			case DIR_UNSPEC:
			case SOURCE_OR_DESTINATION:
				$$.self = Connect_OR(
					NewBlock(OffsetMask, MaskSrcMask, ($3 << ShiftSrcMask) & MaskSrcMask, CMP_EQ, FUNC_NONE, NULL ),
					NewBlock(OffsetMask, MaskDstMask, ($3 << ShiftDstMask) & MaskDstMask, CMP_EQ, FUNC_NONE, NULL )
				);
				break;
			case SOURCE_AND_DESTINATION:
				$$.self = Connect_AND(
					NewBlock(OffsetMask, MaskSrcMask, ($3 << ShiftSrcMask) & MaskSrcMask, CMP_EQ, FUNC_NONE, NULL ),
					NewBlock(OffsetMask, MaskDstMask, ($3 << ShiftDstMask) & MaskDstMask, CMP_EQ, FUNC_NONE, NULL )
				);
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		} // End switch

	}

	| dqual NET STRING STRING { 
		int af, bytes, ret;
		uint64_t	mask[2];
		ret = parse_ip(&af, $3, IPstack, &bytes, STRICT_IP, &num_ip);

		if ( ret == 0 ) {
			yyerror("Invalid IP address");
			YYABORT;
		}
		
		if ( ret == -1 ) {
			yyerror("IP address required - hostname not allowed here.");
			YYABORT;
		}
		// ret == -2 will never happen here, as STRICT_IP is set

		if ( af != PF_INET ) {
			yyerror("IP netmask syntax valid only for IPv4");
			YYABORT;
		}
		if ( bytes != 4 ) {
			yyerror("Need complete IP address");
			YYABORT;
		}

		ret = parse_ip(&af, $4, mask, &bytes, STRICT_IP, &num_ip);
		if ( ret == 0 ) {
			yyerror("Invalid IP address");
			YYABORT;
		}
		if ( ret == -1 ) {
			yyerror("IP address required - hostname not allowed here.");
			YYABORT;
		}
		// ret == -2 will never happen here, as STRICT_IP is set

		if ( af != PF_INET || bytes != 4 ) {
			yyerror("Invalid netmask for IPv4 address");
			YYABORT;
		}

		IPstack[0] &= mask[0];
		IPstack[1] &= mask[1];

		switch ( $1.direction ) {
			case SOURCE:
				$$.self = Connect_AND(
					NewBlock(OffsetSrcIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
					NewBlock(OffsetSrcIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
				);
				break;
			case DESTINATION:
				$$.self = Connect_AND(
					NewBlock(OffsetDstIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
					NewBlock(OffsetDstIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
				);
				break;
			case DIR_UNSPEC:
			case SOURCE_OR_DESTINATION:
				$$.self = Connect_OR(
					Connect_AND(
						NewBlock(OffsetSrcIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetSrcIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
					),
					Connect_AND(
						NewBlock(OffsetDstIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetDstIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
					)
				);		
				break;
			case SOURCE_AND_DESTINATION:
				$$.self = Connect_AND(
					Connect_AND(
						NewBlock(OffsetSrcIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetSrcIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
					),
					Connect_AND(
						NewBlock(OffsetDstIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetDstIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
					)
				);
				break;
			default:
				/* should never happen */
				yyerror("This token is not expected here!");
				YYABORT;
		} // End of switch

	}

	| dqual NET STRING '/' NUMBER { 
		int af, bytes, ret;
		uint64_t	mask[2];

		ret = parse_ip(&af, $3, IPstack, &bytes, STRICT_IP, &num_ip);
		if ( ret == 0 ) {
			yyerror("Invalid IP address");
			YYABORT;
		}
		if ( ret == -1 ) {
			yyerror("IP address required - hostname not allowed here.");
			YYABORT;
		}
		// ret == -2 will never happen here, as STRICT_IP is set


		if ( $5 > (bytes*8) ) {
			yyerror("Too many netbits for this IP addresss");
			YYABORT;
		}

		if ( af == PF_INET ) {
			mask[0] = 0xffffffffffffffffLL;
			mask[1] = 0xffffffffffffffffLL << ( 32 - $5 );
		} else {	// PF_INET6
			if ( $5 > 64 ) {
				mask[0] = 0xffffffffffffffffLL;
				mask[1] = 0xffffffffffffffffLL << ( 128 - $5 );
			} else {
				mask[0] = 0xffffffffffffffffLL << ( 64 - $5 );
				mask[1] = 0;
			}
		}
		// IP aadresses are stored in network representation 
		mask[0]	 = mask[0];
		mask[1]	 = mask[1];

		IPstack[0] &= mask[0];
		IPstack[1] &= mask[1];

		switch ( $1.direction ) {
			case SOURCE:
				$$.self = Connect_AND(
					NewBlock(OffsetSrcIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
					NewBlock(OffsetSrcIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
				);
				break;
			case DESTINATION:
				$$.self = Connect_AND(
					NewBlock(OffsetDstIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
					NewBlock(OffsetDstIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
				);
				break;
			case DIR_UNSPEC:
			case SOURCE_OR_DESTINATION:
				$$.self = Connect_OR(
					Connect_AND(
						NewBlock(OffsetSrcIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetSrcIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
					),
					Connect_AND(
						NewBlock(OffsetDstIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetDstIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
					)
				);
				break;
			case SOURCE_AND_DESTINATION:
				$$.self = Connect_AND(
					Connect_AND(
						NewBlock(OffsetSrcIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetSrcIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
					),
					Connect_AND(
						NewBlock(OffsetDstIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetDstIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
					)
				);
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		} // End of switch

	}

	| dqual IF NUMBER {
		if ( $3 > 0xffffffffLL ) {
			yyerror("Input interface number must 0..2^32");
			YYABORT;
		}

		switch ( $1.direction ) {
			case DIR_UNSPEC:
				$$.self = Connect_OR(
					NewBlock(OffsetInOut, MaskInput, ($3 << ShiftInput) & MaskInput, CMP_EQ, FUNC_NONE, NULL),
					NewBlock(OffsetInOut, MaskOutput, ($3 << ShiftOutput) & MaskOutput, CMP_EQ, FUNC_NONE, NULL)
				);
				break;
			case DIR_IN: 
				$$.self = NewBlock(OffsetInOut, MaskInput, ($3 << ShiftInput) & MaskInput, CMP_EQ, FUNC_NONE, NULL); 
				break;
			case DIR_OUT: 
				$$.self = NewBlock(OffsetInOut, MaskOutput, ($3 << ShiftOutput) & MaskOutput, CMP_EQ, FUNC_NONE, NULL); 
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		} // End of switch

	}
	
	| dqual VLAN NUMBER {	
		if ( $3 > 65535 ) {
			yyerror("VLAN number of range 0..65535");
			YYABORT;
		}

		switch ( $1.direction ) {
			case SOURCE:
				$$.self = NewBlock(OffsetVlan, MaskSrcVlan, ($3 << ShiftSrcVlan) & MaskSrcVlan, CMP_EQ, FUNC_NONE, NULL );
				break;
			case DESTINATION:
				$$.self = NewBlock(OffsetVlan, MaskDstVlan, ($3 << ShiftDstVlan) & MaskDstVlan, CMP_EQ, FUNC_NONE, NULL);
				break;
			case DIR_UNSPEC:
			case SOURCE_OR_DESTINATION:
				$$.self = Connect_OR(
					NewBlock(OffsetVlan, MaskSrcVlan, ($3 << ShiftSrcVlan) & MaskSrcVlan, CMP_EQ, FUNC_NONE, NULL ),
					NewBlock(OffsetVlan, MaskDstVlan, ($3 << ShiftDstVlan) & MaskDstVlan, CMP_EQ, FUNC_NONE, NULL)
				);
				break;
			case SOURCE_AND_DESTINATION:
				$$.self = Connect_AND(
					NewBlock(OffsetVlan, MaskSrcVlan, ($3 << ShiftSrcVlan) & MaskSrcVlan, CMP_EQ, FUNC_NONE, NULL ),
					NewBlock(OffsetVlan, MaskDstVlan, ($3 << ShiftDstVlan) & MaskDstVlan, CMP_EQ, FUNC_NONE, NULL)
				);
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		} // End of switch

	}

	| dqual MAC STRING {
		uint64_t	mac = VerifyMac($3);
		if ( mac == 0 ) {
			yyerror("Invalid MAC address format");
			YYABORT;
		}
		switch ( $1.direction ) {
			case DIR_UNSPEC: {
					uint32_t in, out;
					in  = Connect_OR(
						NewBlock(OffsetInSrcMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetInDstMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL )
					);
					out  = Connect_OR(
						NewBlock(OffsetOutSrcMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetOutDstMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL )
					);
					$$.self = Connect_OR(in, out);
					} break;
			case DIR_IN:
					$$.self = Connect_OR(
						NewBlock(OffsetInSrcMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetInDstMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL )
					);
					break;
			case DIR_OUT:
					$$.self = Connect_OR(
						NewBlock(OffsetOutSrcMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetOutDstMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL )
					);
					break;
			case SOURCE:
					$$.self = Connect_OR(
						NewBlock(OffsetInSrcMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetOutSrcMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL )
					);
					break;
			case DESTINATION:
					$$.self = Connect_OR(
						NewBlock(OffsetInDstMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL ),
						NewBlock(OffsetOutDstMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL )
					);
					break;
			case IN_SRC: 
					$$.self = NewBlock(OffsetInSrcMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL );
					break;
			case IN_DST: 
					$$.self = NewBlock(OffsetInDstMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL );
					break;
			case OUT_SRC: 
					$$.self = NewBlock(OffsetOutSrcMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL );
					break;
			case OUT_DST:
					$$.self = NewBlock(OffsetOutDstMAC, MaskMac, mac, CMP_EQ, FUNC_NONE, NULL );
					break;
				break;
			default:
				yyerror("This token is not expected here!");
				YYABORT;
		} // End of switch
	}

	| MPLS STRING comp NUMBER {	
		if ( $4 > MPLSMAX ) {
			yyerror("MPLS value out of range");
			YYABORT;
		}

		// search for label1 - label10
		if ( strncasecmp($2, "label", 5) == 0 ) {
			uint64_t mask;
			uint32_t offset, shift;
			char *s = &$2[5];
			if ( s == '\0' ) {
				yyerror("Missing label number");
				YYABORT;
			}
			int i = (int)strtol(s, (char **)NULL, 10);

			switch (i) {
				case 1:
					offset	= OffsetMPLS12;
					mask	= MaskMPLSlabelOdd;
					shift	= ShiftMPLSlabelOdd;
					break;
				case 2:
					offset	= OffsetMPLS12;
					mask	= MaskMPLSlabelEven;
					shift	= ShiftMPLSlabelEven;
					break;
				case 3:
					offset	= OffsetMPLS34;
					mask	= MaskMPLSlabelOdd;
					shift	= ShiftMPLSlabelOdd;
					break;
				case 4:
					offset	= OffsetMPLS34;
					mask	= MaskMPLSlabelEven;
					shift	= ShiftMPLSlabelEven;
					break;
				case 5:
					offset	= OffsetMPLS56;
					mask	= MaskMPLSlabelOdd;
					shift	= ShiftMPLSlabelOdd;
					break;
				case 6:
					offset	= OffsetMPLS56;
					mask	= MaskMPLSlabelEven;
					shift	= ShiftMPLSlabelEven;
					break;
				case 7:
					offset	= OffsetMPLS78;
					mask	= MaskMPLSlabelOdd;
					shift	= ShiftMPLSlabelOdd;
					break;
				case 8:
					offset	= OffsetMPLS78;
					mask	= MaskMPLSlabelEven;
					shift	= ShiftMPLSlabelEven;
					break;
				case 9:
					offset	= OffsetMPLS910;
					mask	= MaskMPLSlabelOdd;
					shift	= ShiftMPLSlabelOdd;
					break;
				case 10:
					offset	= OffsetMPLS910;
					mask	= MaskMPLSlabelEven;
					shift	= ShiftMPLSlabelEven;
					break;
				default: 
					yyerror("MPLS label out of range 1..10");
					YYABORT;
			}
			$$.self = NewBlock(offset, mask, ($4 << shift) & mask, $3.comp, FUNC_NONE, NULL );

		} else if ( strcasecmp($2, "eos") == 0 ) {
			// match End of Stack label 
			$$.self = NewBlock(0, AnyMask, $4 << 4, $3.comp, FUNC_MPLS_EOS, NULL );

		} else if ( strncasecmp($2, "exp", 3) == 0 ) {
			uint64_t mask;
			uint32_t offset, shift;
			char *s = &$2[3];
			if ( s == '\0' ) {
				yyerror("Missing label number");
				YYABORT;
			}
			int i = (int)strtol(s, (char **)NULL, 10);

			if ( $4 > 7 ) {
				yyerror("MPLS exp value out of range");
				YYABORT;
			}

			switch (i) {
				case 1:
					offset	= OffsetMPLS12;
					mask	= MaskMPLSexpOdd;
					shift	= ShiftMPLSexpOdd;
					break;
				case 2:
					offset	= OffsetMPLS12;
					mask	= MaskMPLSexpEven;
					shift	= ShiftMPLSexpEven;
					break;
				case 3:
					offset	= OffsetMPLS34;
					mask	= MaskMPLSexpOdd;
					shift	= ShiftMPLSexpOdd;
					break;
				case 4:
					offset	= OffsetMPLS34;
					mask	= MaskMPLSexpEven;
					shift	= ShiftMPLSexpEven;
					break;
				case 5:
					offset	= OffsetMPLS56;
					mask	= MaskMPLSexpOdd;
					shift	= ShiftMPLSexpOdd;
					break;
				case 6:
					offset	= OffsetMPLS56;
					mask	= MaskMPLSexpEven;
					shift	= ShiftMPLSexpEven;
					break;
				case 7:
					offset	= OffsetMPLS78;
					mask	= MaskMPLSexpOdd;
					shift	= ShiftMPLSexpOdd;
					break;
				case 8:
					offset	= OffsetMPLS78;
					mask	= MaskMPLSexpEven;
					shift	= ShiftMPLSexpEven;
					break;
				case 9:
					offset	= OffsetMPLS910;
					mask	= MaskMPLSexpOdd;
					shift	= ShiftMPLSexpOdd;
					break;
				case 10:
					offset	= OffsetMPLS910;
					mask	= MaskMPLSexpEven;
					shift	= ShiftMPLSexpEven;
					break;
				default: 
					yyerror("MPLS label out of range 1..10");
					YYABORT;
			}
			$$.self = NewBlock(offset, mask, $4 << shift, $3.comp, FUNC_NONE, NULL );

		} else {
			yyerror("Unknown MPLS option");
			YYABORT;
		}
	}
	| MPLS ANY NUMBER {	
		uint32_t *opt = malloc(sizeof(uint32_t));
		if ( $3 > MPLSMAX ) {
			yyerror("MPLS value out of range");
			YYABORT;
		}
		if ( opt == NULL) {
			yyerror("malloc() error");
			YYABORT;
		}
		*opt = $3 << 4;
		$$.self = NewBlock(0, AnyMask, $3 << 4, CMP_EQ, FUNC_MPLS_ANY, opt );

	}
	| FWDSTAT NUMBER {
		if ( $2 > 255 ) {
			yyerror("Forwarding status of range 0..255");
			YYABORT;
		}
		$$.self = NewBlock(OffsetStatus, MaskStatus, ($2 << ShiftStatus) & MaskStatus, CMP_EQ, FUNC_NONE, NULL);
	}

	| FWDSTAT STRING {
		uint64_t id = Get_fwd_status_id($2);
		if (id == 256 ) {
			yyerror("Unknown forwarding status");
			YYABORT;
		}

		$$.self = NewBlock(OffsetStatus, MaskStatus, (id << ShiftStatus) & MaskStatus, CMP_EQ, FUNC_NONE, NULL);

	}

	| DIR NUMBER {
		if ( $2 > 2 ) {
			yyerror("Flow direction status of range 0, 1");
			YYABORT;
		}
		$$.self = NewBlock(OffsetDir, MaskDir, ($2 << ShiftDir) & MaskDir, CMP_EQ, FUNC_NONE, NULL);

	}

	| DIR inout {
		uint64_t dir = 0xFF;
		if ( $2.inout == INGRESS )
			dir = 0;
		else if ( $2.inout == EGRESS )
			dir = 1;
		else {
			yyerror("Flow direction status of range ingress, egress");
			YYABORT;
		}

		$$.self = NewBlock(OffsetDir, MaskDir, (dir << ShiftDir) & MaskDir, CMP_EQ, FUNC_NONE, NULL);

	}

/* iplist definition */
iplist:	STRING	{ 
		int i, af, bytes, ret;
		struct IPListNode *node;

		IPlist_t *root = malloc(sizeof(IPlist_t));

		if ( root == NULL) {
			yyerror("malloc() error");
			YYABORT;
		}
		RB_INIT(root);

		ret = parse_ip(&af, $1, IPstack, &bytes, ALLOW_LOOKUP, &num_ip);

		if ( ret == 0 ) {
			yyerror("Invalid IP address");
			YYABORT;
		}
		// ret == -1 will never happen here, as ALLOW_LOOKUP is set
		
		if ( ret != -2 ) {
			if ( af && (( af == PF_INET && bytes != 4 ) || ( af == PF_INET6 && bytes != 16 ))) {
				yyerror("incomplete IP address");
				YYABORT;
			}

			for ( i=0; i<num_ip; i++ ) {
				if ((node = malloc(sizeof(struct IPListNode))) == NULL) {
					yyerror("malloc() error");
					YYABORT;
				}
				node->ip[0] = IPstack[2*i];
				node->ip[1] = IPstack[2*i+1];
				node->mask[0] = 0xffffffffffffffffLL;
				node->mask[1] = 0xffffffffffffffffLL;
				RB_INSERT(IPtree, root, node);
			}

		}
		$$ = (void *)root;

	}

iplist:	STRING '/' NUMBER	{ 
		int af, bytes, ret;
		struct IPListNode *node;

		IPlist_t *root = malloc(sizeof(IPlist_t));

		if ( root == NULL) {
			yyerror("malloc() error");
			YYABORT;
		}
		RB_INIT(root);

		ret = parse_ip(&af, $1, IPstack, &bytes, STRICT_IP, &num_ip);

		if ( ret == 0 ) {
			yyerror("Invalid IP address");
			YYABORT;
		}
		// ret == -1 will never happen here, as ALLOW_LOOKUP is set
		
		if ( ret != -2 ) {
			if ( af && (( af == PF_INET && bytes != 4 ) || ( af == PF_INET6 && bytes != 16 ))) {
				yyerror("incomplete IP address");
				YYABORT;
			}

			if ((node = malloc(sizeof(struct IPListNode))) == NULL) {
				yyerror("malloc() error");
				YYABORT;
			}

			if ( af == PF_INET ) {
				node->mask[0] = 0xffffffffffffffffLL;
				node->mask[1] = 0xffffffffffffffffLL << ( 32 - $3 );
			} else {	// PF_INET6
				if ( $3 > 64 ) {
					node->mask[0] = 0xffffffffffffffffLL;
					node->mask[1] = 0xffffffffffffffffLL << ( 128 - $3 );
				} else {
					node->mask[0] = 0xffffffffffffffffLL << ( 64 - $3 );
					node->mask[1] = 0;
				}
			}

			node->ip[0] = IPstack[0] & node->mask[0];
			node->ip[1] = IPstack[1] & node->mask[1];

			RB_INSERT(IPtree, root, node);

		}
		$$ = (void *)root;

	}

	| iplist STRING { 
		int i, af, bytes, ret;
		struct IPListNode *node;

		ret = parse_ip(&af, $2, IPstack, &bytes, ALLOW_LOOKUP, &num_ip);

		if ( ret == 0 ) {
			yyerror("Invalid IP address");
			YYABORT;
		}
		if ( af && (( af == PF_INET && bytes != 4 ) || ( af == PF_INET6 && bytes != 16 ))) {
			yyerror("incomplete IP address");
			YYABORT;
		}

		// ret == - 2 means lookup failure
		if ( ret != -2 ) {
			for ( i=0; i<num_ip; i++ ) {
				if ((node = malloc(sizeof(struct IPListNode))) == NULL) {
					yyerror("malloc() error");
					YYABORT;
				}
				node->ip[0] = IPstack[2*i];
				node->ip[1] = IPstack[2*i+1];
				node->mask[0] = 0xffffffffffffffffLL;
				node->mask[1] = 0xffffffffffffffffLL;
	
				RB_INSERT(IPtree, (IPlist_t *)$$, node);
			}
		}
	}
	| iplist ',' STRING { 
		int i, af, bytes, ret;
		struct IPListNode *node;

		ret = parse_ip(&af, $3, IPstack, &bytes, ALLOW_LOOKUP, &num_ip);

		if ( ret == 0 ) {
			yyerror("Invalid IP address");
			YYABORT;
		}
		if ( af && (( af == PF_INET && bytes != 4 ) || ( af == PF_INET6 && bytes != 16 ))) {
			yyerror("incomplete IP address");
			YYABORT;
		}

		// ret == - 2 means lookup failure
		if ( ret != -2 ) {
			for ( i=0; i<num_ip; i++ ) {
				if ((node = malloc(sizeof(struct IPListNode))) == NULL) {
					yyerror("malloc() error");
					YYABORT;
				}
				node->ip[0] = IPstack[2*i];
				node->ip[1] = IPstack[2*i+1];
				node->mask[0] = 0xffffffffffffffffLL;
				node->mask[1] = 0xffffffffffffffffLL;
	
				RB_INSERT(IPtree, (IPlist_t *)$$, node);
			}
		}
	}

	| iplist STRING '/' NUMBER  { 
		int af, bytes, ret;
		struct IPListNode *node;

		ret = parse_ip(&af, $2, IPstack, &bytes, STRICT_IP, &num_ip);

		if ( ret == 0 ) {
			yyerror("Invalid IP address");
			YYABORT;
		}
		if ( af && (( af == PF_INET && bytes != 4 ) || ( af == PF_INET6 && bytes != 16 ))) {
			yyerror("incomplete IP address");
			YYABORT;
		}

		// ret == - 2 means lookup failure
		if ( ret != -2 ) {
			if ((node = malloc(sizeof(struct IPListNode))) == NULL) {
				yyerror("malloc() error");
				YYABORT;
			}
			if ( af == PF_INET ) {
				node->mask[0] = 0xffffffffffffffffLL;
				node->mask[1] = 0xffffffffffffffffLL << ( 32 - $4 );
			} else {	// PF_INET6
				if ( $4 > 64 ) {
					node->mask[0] = 0xffffffffffffffffLL;
					node->mask[1] = 0xffffffffffffffffLL << ( 128 - $4 );
				} else {
					node->mask[0] = 0xffffffffffffffffLL << ( 64 - $4 );
					node->mask[1] = 0;
				}
			}

			node->ip[0] = IPstack[0] & node->mask[0];
			node->ip[1] = IPstack[1] & node->mask[1];

			RB_INSERT(IPtree, (IPlist_t *)$$, node);
		}
	}

	;

/* ULlist definition */
ullist:	NUMBER	{ 
		struct ULongListNode *node;

		ULongtree_t *root = malloc(sizeof(ULongtree_t));

		if ( root == NULL) {
			yyerror("malloc() error");
			YYABORT;
		}
		RB_INIT(root);

		if ((node = malloc(sizeof(struct ULongListNode))) == NULL) {
			yyerror("malloc() error");
			YYABORT;
		}
		node->value = $1;

		RB_INSERT(ULongtree, root, node);
		$$ = (void *)root;
	}

	| ullist NUMBER { 
		struct ULongListNode *node;

		if ((node = malloc(sizeof(struct ULongListNode))) == NULL) {
			yyerror("malloc() error");
			YYABORT;
		}
		node->value = $2;
		RB_INSERT(ULongtree, (ULongtree_t *)$$, node);
	}

	| ullist ',' NUMBER { 
		struct ULongListNode *node;

		if ((node = malloc(sizeof(struct ULongListNode))) == NULL) {
			yyerror("malloc() error");
			YYABORT;
		}
		node->value = $3;
		RB_INSERT(ULongtree, (ULongtree_t *)$$, node);
	}

	;

/* comparator qualifiers */
comp:				{ $$.comp = CMP_EQ; }
	| EQ			{ $$.comp = CMP_EQ; }
	| LT			{ $$.comp = CMP_LT; }
	| GT			{ $$.comp = CMP_GT; }
	;

/* 'direction' qualifiers */
dqual:	  			{ $$.direction = DIR_UNSPEC;  			 }
	| SRC			{ $$.direction = SOURCE;				 }
	| DST			{ $$.direction = DESTINATION;			 }
	| SRC OR DST 	{ $$.direction = SOURCE_OR_DESTINATION;  }
	| DST OR SRC	{ $$.direction = SOURCE_OR_DESTINATION;  }
	| SRC AND DST	{ $$.direction = SOURCE_AND_DESTINATION; }
	| DST AND SRC	{ $$.direction = SOURCE_AND_DESTINATION; }
	| IN			{ $$.direction = DIR_IN;				 }
	| OUT			{ $$.direction = DIR_OUT;				 }
	| IN SRC		{ $$.direction = IN_SRC;				 }
	| IN DST		{ $$.direction = IN_DST;				 }
	| OUT SRC		{ $$.direction = OUT_SRC;				 }
	| OUT DST		{ $$.direction = OUT_DST;				 }
	| PREV			{ $$.direction = ADJ_PREV;				 }
	| NEXT			{ $$.direction = ADJ_NEXT;				 }
	;

inout: INGRESS		{ $$.inout	= INGRESS;	}
	|  EGRESS		{ $$.inout	= EGRESS;   }
	;

acl:	ACL			{ $$.acl = ACL; 	}
	|	ACE			{ $$.acl = ACE;		}
	|	XACE		{ $$.acl = XACE;	}
	;

expr:	term		{ $$ = $1.self;        }
	| expr OR  expr	{ $$ = Connect_OR($1, $3);  }
	| expr AND expr	{ $$ = Connect_AND($1, $3); }
	| NOT expr	%prec NEGATE	{ $$ = Invert($2);			}
	| '(' expr ')'	{ $$ = $2; }
	;

%%

static void  yyerror(char *msg) {

	if ( FilterFilename )
		snprintf(yyerror_buff, 255 ,"File '%s' line %d: %s at '%s'", FilterFilename, lineno, msg, yytext);
	else 
		snprintf(yyerror_buff, 255, "Line %d: %s at '%s'", lineno, msg, yytext);

	yyerror_buff[255] = '\0';
	fprintf(stderr, "%s\n", yyerror_buff);

} /* End of yyerror */

static uint32_t ChainHosts(uint64_t *offsets, uint64_t *hostlist, int num_records, int type) {
uint32_t offset_a, offset_b, i, j, block;
	if ( type == SOURCE ) {
		offset_a = offsets[0];
		offset_b = offsets[1];
	} else {
		offset_a = offsets[2];
		offset_b = offsets[3];
	}

	i = 0;
	block = Connect_AND(
				NewBlock(offset_b, MaskIPv6, hostlist[i+1] , CMP_EQ, FUNC_NONE, NULL ),
				NewBlock(offset_a, MaskIPv6, hostlist[i] , CMP_EQ, FUNC_NONE, NULL )
			);
	i += 2;
	for ( j=1; j<num_records; j++ ) {
		uint32_t b = Connect_AND(
				NewBlock(offset_b, MaskIPv6, hostlist[i+1] , CMP_EQ, FUNC_NONE, NULL ),
				NewBlock(offset_a, MaskIPv6, hostlist[i] , CMP_EQ, FUNC_NONE, NULL )
			);
		block = Connect_OR(block, b);
		i += 2;
	}

	return block;

} // End of ChainHosts

uint64_t VerifyMac(char *s) {
uint64_t mac;
size_t slen = strlen(s);
long l;
char *p, *q, *r;
int i;

	if ( slen > 17 )
		return 0; 

	for (i=0; i<slen; i++ ) {
		if ( !isxdigit(s[i]) && s[i] != ':' ) 
			return 0;
	}

	p = strdup(s);
	if ( !p ) {
		yyerror("malloc() error");
		return 0;
	}

	mac = 0;
	i = 0;	// number of MAC octets must be 6
	r = p;
	q = strchr(r, ':');
	while ( r && i < 6 ) {
		if ( q ) 
			*q = '\0';
		l = strtol(r, NULL, 16);
		if ( (i == 0 && errno == EINVAL) ) {
			free(p);
			return 0;
		}
		if ( l > 255 ) {
			free(p);
			return 0;
		}

		mac = ( mac << 8 ) | (l & 0xFF );
		i++;

		if ( q ) {
			r = ++q;
			q = strchr(r, ':');
		} else 
			r = NULL;
	}

	if ( i != 6 )
		return 0;

	return mac;

} // End of VerifyMac
