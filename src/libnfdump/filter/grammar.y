/*
 *  Copyright (c) 2024, Peter Haag
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

%{

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "filter.h"
#include "userio.h"
#include "nfxV3.h"
#include "ipconv.h"
#include "sgregex.h"
#include "ja3/ja3.h"
#include "ja4/ja4.h"
#include "nfdump.h"
#include "util.h"

#define AnyMask 0xffffffffffffffffLL

const data_t NULLPtr = {NULL};

/*
 * function prototypes
 */
static void yyerror(char *msg);

/* var defs */
extern int 			lineno;
extern char 		*yytext;
extern uint32_t	StartNode;
extern char *FilterFilename;

static ipStack_t ipStack[MAXHOSTS];

static uint32_t ChainHosts(ipStack_t *ipStack, int numIP, int direction);

static int AddIdent(char *ident);

static int AddEngineNum(char *type, uint16_t comp, uint64_t num);

static int AddExporterNum(char *type, uint16_t comp, uint64_t num);

static int AddProto(direction_t direction, char *protoStr, uint64_t protoNum);

static int AddPortNumber(direction_t direction, uint16_t comp, uint64_t port);

static int AddICMP(char *type, uint16_t comp, uint64_t number);

static int AddAsNumber(direction_t direction, uint16_t comp, uint64_t as);

static int AddFlagsNumber(direction_t direction, uint16_t comp, uint64_t flags);

static int AddFlagsString(direction_t direction, char *flags);

static int AddTosNumber(direction_t direction, uint16_t comp, uint64_t tos);

static int AddIPttl(prefix_t prefix, uint16_t comp, uint64_t ttl);

static int AddIPttlEqual(char *arg);

static int AddPackets(direction_t direction, uint16_t comp, uint64_t packets);

static int AddBytes(direction_t direction, uint16_t comp, uint64_t bytes);

static int AddFwdStatNum(uint16_t comp, uint64_t num);

static int AddFwdStatString(char *string);

static int AddIP(direction_t direction, char *IPstr);

static int AddIPlist(direction_t direction, void *IPstr);

static int AddNet(direction_t direction, char *IPstr, char *maskStr);

static int AddNetPrefix(direction_t direction, char *IPstr, uint64_t mask);

static int AddInterfaceNumber(direction_t direction, uint64_t num);

static int AddVlanNumber(direction_t direction, uint64_t num);

static int AddMaskNumber(direction_t direction, uint64_t num);

static int AddFlowDir(direction_t direction, int64_t dirNum);

static int AddMPLS(char *type, uint16_t comp, uint64_t value);

static int AddMAC(direction_t direction, char *macString);

static int AddEthertype(uint64_t etherType);

static int AddLatency(direction_t direction, uint16_t comp, uint64_t number);

static int AddASAString(char *event, char *asaStr);

static int AddASA(char *event, uint16_t comp, uint64_t number);

static int AddASApblock(direction_t direction, char *arg);

static int AddNATString(char *event, char *asaStr);

static int AddNAT(char *event, uint16_t comp, uint64_t number);

static int AddNatPortBlocks(char *type, char *subtype, uint16_t comp, uint64_t number);

static int AddACL(direction_t direction, uint16_t comp, uint64_t number);

static int AddPayload(char *type, char *arg, char *opt);

static int AddGeo(direction_t direction, char *geo);

static int AddObservation(char *type, char *subType, uint16_t comp, uint64_t number);

static int AddVRF(direction_t direction, uint16_t comp, uint64_t number);

static int AddTimeSting(char *firstLast, uint16_t comp, char *timeString);

static int AddPFString(char *type, char *arg);

static int AddPFNumber(char *type, uint16_t comp, uint64_t number);

static void *NewIplist(char *IPstr, int prefix);

static void *NewU64list(uint64_t num);

static int InsertIPlist(void *IPlist, char *IPstr, int64_t prefix);

static int InsertU64list(void *U64list, uint64_t num);

static int AddPortList(direction_t direction, void *U64List);

static int AddASList(direction_t direction, void *U64List);

%}

%union {
	uint64_t			value;
	char					*s;
	FilterParam_t	param;
	void					*list;
}

%token EQ LT GT LE GE
%token ANY NOT IDENT COUNT
%token IP IPV4 IPV6 IPTTL NET
%token SRC DST IN OUT MIN MAX PREV NEXT BGP ROUTER INGRESS EGRESS
%token CLIENT SERVER
%token NAT XLATE TUN
%token ENGINE ENGINETYPE ENGINEID EXPORTER
%token DURATION PPS BPS BPP FLAGS
%token PROTO PORT AS IF VLAN MPLS MAC ICMP ICMPTYPE ICMPCODE
%token PACKETS BYTES FLOWS ETHERTYPE
%token MASK FLOWDIR TOS FWDSTAT LATENCY ASA ACL PAYLOAD VRF
%token OBSERVATION PF
%token SEEN
%token <s> STRING
%token <s> GEOSTRING
%token <value> NUMBER
%type <value> expr
%type <param> dqual minmax term comp
%type <list> iplist u64list

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
		data_t data = {.dataVal=1};
		$$.self = NewElement(EXheader, 0, 0, 0, CMP_EQ, FUNC_NONE, data);
	}

	| IPV4 { 
		$$.self = NewElement(EXipv4FlowID, OFFsrc4Addr, 0, 0, CMP_EQ, FUNC_NONE, NULLPtr); 
	}

	| IPV6 { 
		$$.self = NewElement(EXipv6FlowID, OFFsrc6Addr, 0, 0, CMP_EQ, FUNC_NONE, NULLPtr); 
	}

	| IDENT STRING {
	  $$.self  = AddIdent($2); if ( $$.self < 0 ) YYABORT;
	}

	| COUNT comp NUMBER {
		$$.self = NewElement(EXlocal, OFFflowCount, SIZEflowCount, $3, $2.comp, FUNC_NONE, NULLPtr); 
	}

	| ENGINETYPE comp NUMBER {
	  $$.self  = AddEngineNum("type", $2.comp, $3); if ( $$.self < 0 ) YYABORT;
  }

	| ENGINEID comp NUMBER {
	  $$.self  = AddEngineNum("id", $2.comp, $3); if ( $$.self < 0 ) YYABORT;
	}

	| ENGINE STRING comp NUMBER {
		$$.self  = AddEngineNum($2, $3.comp, $4); if ( $$.self < 0 ) YYABORT;
	}

  | EXPORTER STRING comp NUMBER {
 	  $$.self  = AddExporterNum($2, $3.comp, $4); if ( $$.self < 0 ) YYABORT;
	}

  | dqual PROTO NUMBER { 
    $$.self = AddProto($1.direction, NULL, $3); if ( $$.self < 0 ) YYABORT; 
  }

  | dqual PROTO STRING {
    $$.self = AddProto($1.direction, $3, 0); if ( $$.self < 0 ) YYABORT;
  }

  | dqual PROTO ICMP {
    $$.self = AddProto($1.direction, "icmp", 0); if ( $$.self < 0 ) YYABORT;
	}

	| dqual PORT comp NUMBER {
		$$.self = AddPortNumber($1.direction, $3.comp, $4); if ( $$.self < 0 ) YYABORT; 
	}

	| ICMPTYPE comp NUMBER {
		$$.self = AddICMP("type", $2.comp, $3); if ( $$.self < 0 ) YYABORT; 
	}

	| ICMPCODE comp NUMBER {
		$$.self = AddICMP("code", $2.comp, $3); if ( $$.self < 0 ) YYABORT; 
	}

	| ICMP STRING comp NUMBER {
		$$.self  = AddICMP($2, $3.comp, $4); if ( $$.self < 0 ) YYABORT;
	}

	| dqual FLAGS comp NUMBER {
		$$.self = AddFlagsNumber($1.direction, $3.comp, $4); if ( $$.self < 0 ) YYABORT;
	}

	| dqual FLAGS STRING {
		$$.self = AddFlagsString($1.direction, $3); if ( $$.self < 0 ) YYABORT;
	}

	| dqual TOS comp NUMBER {
	  $$.self = AddTosNumber($1.direction, $3.comp, $4); if ( $$.self < 0 ) YYABORT;
	}

	| minmax IPTTL comp NUMBER {
	  $$.self = AddIPttl($1.prefix, $3.comp, $4); if ( $$.self < 0 ) YYABORT;
	}

	| minmax IPTTL STRING {
	  $$.self = AddIPttlEqual($3); if ( $$.self < 0 ) YYABORT;
	}

	| FWDSTAT comp NUMBER {
	  $$.self = AddFwdStatNum($2.comp, $3); if ( $$.self < 0 ) YYABORT;
	}

	| FWDSTAT STRING {
	  $$.self = AddFwdStatString($2); if ( $$.self < 0 ) YYABORT;
  }

	| DURATION comp NUMBER {
		$$.self = NewElement(EXgenericFlowID, 0, SIZEmsecLast, $3, $2.comp, FUNC_DURATION, NULLPtr); 
	}

	| PPS comp NUMBER {
		$$.self = NewElement(EXgenericFlowID, 0, SIZEmsecLast, $3, $2.comp, FUNC_PPS, NULLPtr);
	}

	| BPS comp NUMBER {
		$$.self = NewElement(EXgenericFlowID, 0, SIZEmsecLast, $3, $2.comp, FUNC_BPS, NULLPtr);
	}

	| BPP comp NUMBER {
		$$.self = NewElement(EXgenericFlowID, 0, SIZEmsecLast, $3, $2.comp, FUNC_BPP, NULLPtr); 
	}

	| dqual PACKETS comp NUMBER {
		$$.self = AddPackets($1.direction, $3.comp, $4); if ( $$.self < 0 ) YYABORT;
	}

	| FLOWS comp NUMBER {
		$$.self = NewElement(EXcntFlowID, OFFflows, SIZEflows, $3, $2.comp, FUNC_NONE, NULLPtr); 
	}

	| dqual BYTES comp NUMBER {
		$$.self = AddBytes($1.direction, $3.comp, $4); if ( $$.self < 0 ) YYABORT;
	}

	| dqual IP STRING { 	
		$$.self = AddIP($1.direction, $3); if ( $$.self < 0 ) YYABORT;
	}

	| dqual NET STRING STRING {
		$$.self = AddNet($1.direction, $3, $4); if ( $$.self < 0 ) YYABORT;
	} 

	| dqual NET STRING '/' NUMBER {
		$$.self = AddNetPrefix($1.direction, $3, $5); if ( $$.self < 0 ) YYABORT;
	} 

	| dqual IF NUMBER {
		$$.self = AddInterfaceNumber($1.direction, $3); if ( $$.self < 0 ) YYABORT;
	}

	| dqual VLAN NUMBER {
		$$.self = AddVlanNumber($1.direction, $3); if ( $$.self < 0 ) YYABORT;
	}

	| dqual AS comp NUMBER {
		$$.self = AddAsNumber($1.direction, $3.comp, $4); if ( $$.self < 0 ) YYABORT; 
	}

	| dqual MASK NUMBER {
		$$.self = AddMaskNumber($1.direction, $3); if ( $$.self < 0 ) YYABORT;
	}

	| ETHERTYPE NUMBER {
		$$.self = AddEthertype($2); if ( $$.self < 0 ) YYABORT;
	}

	| FLOWDIR NUMBER {
		$$.self = AddFlowDir(DIR_UNSPEC, $2); if ( $$.self < 0 ) YYABORT;
	}

	| FLOWDIR dqual {
		$$.self = AddFlowDir($2.direction, -1); if ( $$.self < 0 ) YYABORT;
  }

	| MPLS STRING comp NUMBER {	
		$$.self = AddMPLS($2, $3.comp, $4); if ( $$.self < 0 ) YYABORT; 
	}

	| MPLS ANY comp NUMBER {	
		$$.self = AddMPLS("any", $3.comp, $4); if ( $$.self < 0 ) YYABORT; 
	}

	| dqual MAC STRING {	
		$$.self = AddMAC($1.direction, $3); if ( $$.self < 0 ) YYABORT; 
	}

	| dqual LATENCY comp NUMBER {
		$$.self = AddLatency($1.direction, $3.comp, $4); if ( $$.self < 0 ) YYABORT; 
	}

	| ASA STRING STRING {
		$$.self = AddASAString($2, $3); if ( $$.self < 0 ) YYABORT;
	}

	| ASA STRING dqual {
		switch ($3.direction) {
			case DIR_INGRESS:
				$$.self = AddASAString($2, "ingress");
				break;
			case DIR_EGRESS:
				$$.self = AddASAString($2, "egress");
				break;
			default:
				$$.self = -1;
				    yyerror("Unknown direction specifier");
		}
		if ( $$.self < 0 ) YYABORT;
	}

	| ASA STRING comp NUMBER{
		$$.self = AddASA($2, $3.comp, $4); if ( $$.self < 0 ) YYABORT; 
	}

	| dqual PORT IN NAT STRING {
		$$.self = AddASApblock($1.direction, $5); if ( $$.self < 0 ) YYABORT; 
	}

	| dqual ACL comp NUMBER {
		$$.self = AddACL($1.direction, $3.comp, $4); if ( $$.self < 0 ) YYABORT; 
	}

	| NAT STRING STRING {
		$$.self = AddNATString($2, $3); if ( $$.self < 0 ) YYABORT;
	}

	| NAT STRING STRING comp NUMBER {
		$$.self = AddNatPortBlocks($2, $3, $4.comp, $5); if ( $$.self < 0 ) YYABORT;
	}

	| NAT STRING comp NUMBER {
		$$.self = AddNAT($2, $3.comp, $4); if ( $$.self < 0 ) YYABORT; 
	}

	| PAYLOAD STRING STRING {
		$$.self = AddPayload($2, $3, NULL); if ( $$.self < 0 ) YYABORT;
	}

	| PAYLOAD STRING STRING STRING {
		$$.self = AddPayload($2, $3, $4); if ( $$.self < 0 ) YYABORT;
	}

	| dqual GEOSTRING {
		$$.self = AddGeo($1.direction, $2); if ( $$.self < 0 ) YYABORT;
	}

	| OBSERVATION STRING STRING comp NUMBER {
		$$.self = AddObservation($2, $3, $4.comp, $5); if ( $$.self < 0 ) YYABORT;
	}

	| dqual VRF comp NUMBER {
		$$.self = AddVRF($1.direction, $3.comp, $4); if ( $$.self < 0 ) YYABORT;
	}

	| STRING SEEN comp STRING {
		$$.self = AddTimeSting($1, $3.comp, $4);
	}

  | STRING SEEN comp NUMBER {
		char s[32] = {0};
		int i = $4;
		snprintf(s, 31, "%d", i );
		$$.self = AddTimeSting($1, $3.comp, s);
	}

	| PF STRING STRING {
		$$.self = AddPFString($2, $3); if ( $$.self < 0 ) YYABORT;
	}

	| PF STRING comp NUMBER {
		$$.self = AddPFNumber($2, $3.comp, $4); if ( $$.self < 0 ) YYABORT;
	}

	| PF STRING dqual {
		switch ($3.direction) {
			case DIR_IN:
				$$.self = AddPFString($2, "in");
				break;
			case DIR_OUT:
				$$.self = AddPFString($2, "out");
				break;
			case DIR_UNSPEC_NAT:
				$$.self = AddPFString($2, "nat");
				break;
			default:
				$$.self = -1;
				    yyerror("Unknown direction specifier");
		}
		if ( $$.self < 0 ) YYABORT;
	}

	| dqual IP IN '[' iplist ']' { 	
		$$.self = AddIPlist($1.direction, $5); if ( $$.self < 0 ) YYABORT;
	}

	| dqual PORT IN '[' u64list ']' {
		$$.self = AddPortList($1.direction, $5); if ( $$.self < 0 ) YYABORT;
	}

	| dqual AS IN '[' u64list ']' {
		$$.self = AddASList($1.direction, $5); if ( $$.self < 0 ) YYABORT;
	}
	;

/* iplist definition */
iplist:	STRING	{ 
		$$ = NewIplist($1, -1); if ( $$ == NULL ) YYABORT;
	}

	| STRING '/' NUMBER	{ 
		$$ = NewIplist($1, $3); if ( $$ == NULL ) YYABORT;
	}

	| iplist STRING { 
		if (InsertIPlist($1, $2, -1) == 0 ) YYABORT;
	}

	| iplist ',' STRING { 
		if (InsertIPlist($1, $3, -1) == 0 ) YYABORT;
	}

	| iplist STRING '/' NUMBER	{ 
		if (InsertIPlist($1, $2, $4) == 0 ) YYABORT;
	}

	| iplist ',' STRING '/' NUMBER	{ 
		if (InsertIPlist($1, $3, $5) == 0 ) YYABORT;
	}
	;

u64list: NUMBER { 
		$$ = NewU64list($1); if ( $$ == NULL ) YYABORT;
	}

	| u64list NUMBER { 
		if (InsertU64list($1, $2) == 0 ) YYABORT;
	}

	| u64list ',' NUMBER { 
		if (InsertU64list($1, $3) == 0 ) YYABORT;
	}
	;

/* comparator qualifiers */
comp:				{ $$.comp = CMP_EQ; }
	| EQ			{ $$.comp = CMP_EQ; }
	| LT			{ $$.comp = CMP_LT; }
	| GT			{ $$.comp = CMP_GT; }
	| LE			{ $$.comp = CMP_LE; }
	| GE			{ $$.comp = CMP_GE; }
	;

/* direction qualifiers for direction related elements or specifier for elements */
dqual:	     { $$.direction = DIR_UNSPEC;     }
	| SRC		   { $$.direction = DIR_SRC;        }
	| DST		   { $$.direction = DIR_DST;        }
	| SRC NAT	 { $$.direction = DIR_SRC_NAT;	  }
	| DST NAT  { $$.direction = DIR_DST_NAT;	  }
	| SRC TUN	 { $$.direction = DIR_SRC_TUN;    }
	| DST TUN  { $$.direction = DIR_DST_TUN;    }
	| NAT  		 { $$.direction = DIR_UNSPEC_NAT; }
	| TUN  		 { $$.direction = DIR_UNSPEC_TUN; }
	| IN		   { $$.direction = DIR_IN;         }
	| OUT		   { $$.direction = DIR_OUT;        }
	| IN SRC	 { $$.direction = DIR_IN_SRC;     }
	| IN DST	 { $$.direction = DIR_IN_DST;     }
	| OUT SRC	 { $$.direction = DIR_OUT_SRC;	  }
	| OUT DST	 { $$.direction = DIR_OUT_DST;    }
	| INGRESS	 { $$.direction = DIR_INGRESS;    }
	| EGRESS	 { $$.direction = DIR_EGRESS;     }
	| CLIENT	 { $$.direction = DIR_CLIENT;     }
	| SERVER	 { $$.direction = DIR_SERVER;     }
	| PREV		 { $$.direction = DIR_PREV;       }
	| NEXT		 { $$.direction = DIR_NEXT;       }
	| BGP NEXT { $$.direction = BGP_NEXT;	      }
	| ROUTER	 { $$.direction = SRC_ROUTER;     }
	| EXPORTER { $$.direction = SRC_ROUTER;     }
	;

minmax:      { $$.prefix = PRE_UNKNOWN; }
	| MIN		   { $$.prefix = PRE_MIN;     }
	| MAX		   { $$.prefix = PRE_MAX;     }
	;

expr:	term { $$ = $1.self; }
	| expr OR  expr	{ $$ = Connect_OR($1, $3);   }
	| expr AND expr	{ $$ = Connect_AND($1, $3);  }
	| NOT expr	%prec NEGATE	{ $$ = Invert($2); }
	| '(' expr ')'	{ $$ = $2; }
	;

%%

#define EBUFFSIZE 512
static char ebuf[EBUFFSIZE];

static void yyerror(char *msg) {
	if ( FilterFilename ) {
		printf("File '%s' line %d: %s at '%s'\n", FilterFilename, lineno, msg, yytext);
	} else {
		printf("Line %d: %s at '%s'\n", lineno, msg, yytext);
	}
} /* End of     */

#define yyprintf(...) do { \
    snprintf(ebuf, EBUFFSIZE, __VA_ARGS__); \
    yyerror(ebuf); \
} while (0)

static uint32_t NewIPElement(ipStack_t *ipStack, int direction, int comp, data_t *data) {

	int block = -1;

	if ( ipStack->af == PF_INET ) {
		// handle IPv4 addr element
		switch ( direction ) {
			case DIR_SRC:
				block = NewElement(EXipv4FlowID, OFFsrc4Addr, SIZEsrc4Addr, ipStack->ipaddr[1], comp, FUNC_NONE, data[0]); 
				break;
			case DIR_DST:
				block = NewElement(EXipv4FlowID, OFFdst4Addr, SIZEdst4Addr, ipStack->ipaddr[1], comp, FUNC_NONE, data[0]); 
				break;
			case DIR_SRC_NAT:
				block = NewElement(EXnatXlateIPv4ID, OFFxlateSrc4Addr, SIZExlateSrc4Addr, ipStack->ipaddr[1], comp, FUNC_NONE, data[0]); 
				break;
			case DIR_DST_NAT:
				block = NewElement(EXnatXlateIPv4ID, OFFxlateDst4Addr, SIZExlateDst4Addr, ipStack->ipaddr[1], comp, FUNC_NONE, data[0]); 
				break;
			case DIR_SRC_TUN:
				block = NewElement(EXtunIPv4ID, OFFtunSrc4Addr, SIZEtunSrc4Addr, ipStack->ipaddr[1], comp, FUNC_NONE, data[0]); 
				break;
			case DIR_DST_TUN:
				block = NewElement(EXtunIPv4ID, OFFtunDst4Addr, SIZEtunDst4Addr, ipStack->ipaddr[1], comp, FUNC_NONE, data[0]); 
				break;
			case DIR_NEXT:
				block = NewElement(EXipNextHopV4ID, OFFNextHopV4IP, SIZENextHopV4IP, ipStack->ipaddr[1], comp, FUNC_NONE, data[0]); 
				break;
			case BGP_NEXT:
				block = NewElement(EXbgpNextHopV4ID, OFFbgp4NextIP, SIZEbgp4NextIP, ipStack->ipaddr[1], comp, FUNC_NONE, data[0]); 
				break;
			case SRC_ROUTER:
				block = NewElement(EXipReceivedV4ID, OFFReceived4IP, SIZEReceived4IP, ipStack->ipaddr[1], comp, FUNC_NONE, data[0]); 
				break;
		} // End of switch

	} else {
		// handle IPv6 addr element
		int v6_1, v6_2 = 0;
		switch ( direction ) {
			case DIR_SRC:
				v6_1 = NewElement(EXipv6FlowID, OFFsrc6Addr, sizeof(uint64_t), ipStack->ipaddr[0], comp, FUNC_NONE, data[0]);
				v6_2 = NewElement(EXipv6FlowID, OFFsrc6Addr + sizeof(uint64_t), sizeof(uint64_t), ipStack->ipaddr[1], comp, FUNC_NONE, data[1]);
				break;
			case DIR_DST:
				v6_1 = NewElement(EXipv6FlowID, OFFdst6Addr, sizeof(uint64_t), ipStack->ipaddr[0], comp, FUNC_NONE, data[0]);
				v6_2 = NewElement(EXipv6FlowID, OFFdst6Addr + sizeof(uint64_t), sizeof(uint64_t), ipStack->ipaddr[1], comp, FUNC_NONE, data[1]);
				break;
			case DIR_SRC_NAT:
				v6_1 = NewElement(EXnatXlateIPv6ID, OFFxlateSrc6Addr, sizeof(uint64_t), ipStack->ipaddr[0], comp, FUNC_NONE, data[0]);
				v6_2 = NewElement(EXnatXlateIPv6ID, OFFxlateSrc6Addr + sizeof(uint64_t), sizeof(uint64_t), ipStack->ipaddr[1], comp, FUNC_NONE, data[1]);
				break;
			case DIR_DST_NAT:
				v6_1 = NewElement(EXnatXlateIPv6ID, OFFxlateDst6Addr, sizeof(uint64_t), ipStack->ipaddr[0], comp, FUNC_NONE, data[0]);
				v6_2 = NewElement(EXnatXlateIPv6ID, OFFxlateDst6Addr + sizeof(uint64_t), sizeof(uint64_t), ipStack->ipaddr[1], comp, FUNC_NONE, data[1]);
				break;
			case DIR_SRC_TUN:
				v6_1 = NewElement(EXtunIPv6ID, OFFtunSrc6Addr, sizeof(uint64_t), ipStack->ipaddr[0], comp, FUNC_NONE, data[0]);
				v6_2 = NewElement(EXtunIPv6ID, OFFtunSrc6Addr + sizeof(uint64_t), sizeof(uint64_t), ipStack->ipaddr[1], comp, FUNC_NONE, data[1]);
				break;
			case DIR_DST_TUN:
				v6_1 = NewElement(EXtunIPv6ID, OFFtunDst6Addr, sizeof(uint64_t), ipStack->ipaddr[0], comp, FUNC_NONE, data[0]);
				v6_2 = NewElement(EXtunIPv6ID, OFFtunDst6Addr + sizeof(uint64_t), sizeof(uint64_t), ipStack->ipaddr[1], comp, FUNC_NONE, data[1]);
				break;
			case DIR_NEXT:
				v6_1 = NewElement(EXipNextHopV6ID, OFFNextHopV6IP, sizeof(uint64_t), ipStack->ipaddr[0], comp, FUNC_NONE, data[0]);
				v6_2 = NewElement(EXipNextHopV6ID, OFFNextHopV6IP + sizeof(uint64_t), sizeof(uint64_t), ipStack->ipaddr[1], comp, FUNC_NONE, data[1]);
				break;
			case BGP_NEXT:
				v6_1 = NewElement(EXbgpNextHopV6ID, OFFbgp6NextIP, sizeof(uint64_t), ipStack->ipaddr[0], comp, FUNC_NONE, data[0]);
				v6_2 = NewElement(EXbgpNextHopV6ID, OFFbgp6NextIP + sizeof(uint64_t), sizeof(uint64_t), ipStack->ipaddr[1], comp, FUNC_NONE, data[1]);
				break;
			case SRC_ROUTER:
				v6_1 = NewElement(EXipReceivedV6ID, OFFReceived6IP, sizeof(uint64_t), ipStack->ipaddr[0], comp, FUNC_NONE, data[0]);
				v6_2 = NewElement(EXipReceivedV6ID, OFFReceived6IP + sizeof(uint64_t), sizeof(uint64_t), ipStack->ipaddr[1], comp, FUNC_NONE, data[1]);
				break;
		} // End of switch

		// IPv6
		if ( v6_1 && v6_2 )
			block = Connect_AND(v6_1, v6_2);

	}

	return block;
} // NewIPElement

static uint32_t ChainHosts(ipStack_t *ipStack, int numIP, int direction) {

	data_t data[2] = { NULLPtr, NULLPtr };

	uint32_t final = 0;
	int i = 0;
	do {
		// chain multiple IPs
		int block = NewIPElement(&ipStack[i], direction, CMP_EQ, data);
		final = final == 0 ? block : Connect_OR(final, block);

	} while (++i < numIP);
	
	return final;
} // End of ChainHosts

static int AddIdent(char *ident) {
	char *c;

	// ident[a-zA-Z0-9_\-]+ { 
	size_t len = strlen(ident);
	if ( len == 0 || len > 255 ) {
		yyprintf("Invalid ident string: %s", ident);
		return -1;
	}
	
	c = &ident[0];
	while ( *c ) {
		if ( *c != '_' && *c != '-' && !isalnum(*c) ) {
			yyprintf("Invalid char in ident string: %s: %c", ident, *c);
			return 0;
		}
		c++;
	}
	
	data_t data = {.dataPtr = strdup(ident)};
	return NewElement(EXheader, 0, 0, 0, CMP_IDENT, FUNC_NONE, data); 

} // End of AddIdent

static int AddProto(direction_t direction, char *protoStr, uint64_t protoNum) {

	if ( protoNum > 255 ) {
		yyprintf("Protocol %" PRIu64 " out of range", protoNum);
		return -1;
	}

	if ( protoStr != NULL ) {
		protoNum = ProtoNum(protoStr);
  	if ( protoNum == -1 ) {
	  	yyprintf("Unknown protocol: %s", protoStr);
			Protoinfo(protoStr);
			return -1;
  	}
	}

	if ( direction == DIR_UNSPEC ) {
		return NewElement(EXgenericFlowID, OFFproto, SIZEproto, protoNum, CMP_EQ, FUNC_NONE, NULLPtr); 
	} else if ( direction == DIR_UNSPEC_TUN ) {
		return Connect_OR(
			NewElement(EXtunIPv4ID, OFFtunProtoV4, SIZEtunProtoV4, protoNum, CMP_EQ, FUNC_NONE, NULLPtr),
			NewElement(EXtunIPv6ID, OFFtunProtoV6, SIZEtunProtoV6, protoNum, CMP_EQ, FUNC_NONE, NULLPtr)
		);
	} else {
	  	yyprintf("Unknown protocol specifier");
			return -1;
	}
} // End of AddProtoString

static int AddEngineNum(char *type, uint16_t comp, uint64_t num) {
	if ( num > 255 ) {
		yyprintf("Engine argument %" PRIu64 " of range 0..255", num);
		return -1;
  }

	int ret = -1;
	if ( strcasecmp(type, "type") == 0 ) {
		ret = NewElement(EXheader, OFFengineType, SIZEengineType, num, comp, FUNC_NONE, NULLPtr);
	} else if ( strcasecmp(type, "id") == 0 ) {
		ret = NewElement(EXheader, OFFengineID, SIZEengineID, num, comp, FUNC_NONE, NULLPtr);
	}

	return ret;
} // End of AddEngineNum

static int AddExporterNum(char *type, uint16_t comp, uint64_t num) {
	if ( num > 65535 ) {
	  yyprintf("Exporter argument %" PRIu64 " of range 0..65535", num);
		return -1;
	}

	int ret = -1;
  if ((strcasecmp(type, "id") == 0 ) || (strcasecmp(type, "sysid") == 0)) {
		ret = NewElement(EXheader, OFFexporterID, SIZEexporterID, num, comp, FUNC_NONE, NULLPtr);
	} else {
	  yyprintf("Unknown exporter argument: %s", type);
	}

	return ret;
} // End of AddExporterNum

static int AddPortNumber(direction_t direction, uint16_t comp, uint64_t port) {
	if ( port > 65535 ) {
		  yyprintf("Port number: %" PRIu64 " out of range", port);
			return -1;
	}

	int ret = -1;
  switch ( direction ) {
	  case DIR_SRC:
		  ret = NewElement(EXgenericFlowID, OFFsrcPort, SIZEsrcPort, port, comp, FUNC_NONE, NULLPtr);
		  break;
	  case DIR_DST:
		  ret = NewElement(EXgenericFlowID, OFFdstPort, SIZEdstPort, port, comp, FUNC_NONE, NULLPtr);
		  break;
	  case DIR_SRC_NAT:
		  ret = NewElement(EXnatXlatePortID, OFFxlateSrcPort, SIZExlateSrcPort, port, comp, FUNC_NONE, NULLPtr);
		  break;
	  case DIR_DST_NAT:
		  ret = NewElement(EXnatXlatePortID, OFFxlateDstPort, SIZExlateDstPort, port, comp, FUNC_NONE, NULLPtr);
		  break;
	  case DIR_UNSPEC:
		  ret = Connect_OR(
			  NewElement(EXgenericFlowID, OFFsrcPort, SIZEsrcPort, port, comp, FUNC_NONE, NULLPtr),
			  NewElement(EXgenericFlowID, OFFdstPort, SIZEdstPort, port, comp, FUNC_NONE, NULLPtr)
		  );
		  break;
	  case DIR_UNSPEC_NAT:
		  ret = Connect_OR(
		  	NewElement(EXnatXlatePortID, OFFxlateSrcPort, SIZExlateSrcPort, port, comp, FUNC_NONE, NULLPtr),
		  	NewElement(EXnatXlatePortID, OFFxlateDstPort, SIZExlateDstPort, port, comp, FUNC_NONE, NULLPtr)
		  );
		  break;
	  default:
		  yyprintf("Unknown direction");
  } // End switch

	return ret;
} // End of AddPortNumber

static int AddICMP(char *type, uint16_t comp, uint64_t number) {
	if ( number > 255 ) {
		  yyprintf("ICMP argument %" PRIu64 " of range 0..255", number);
			return -1;
  }

	int ret = -1;
	// imply ICMP-TYPE with a proto ICMP block
	int protoICMP = Connect_OR (
			  NewElement(EXgenericFlowID, OFFproto, SIZEproto, IPPROTO_ICMP, CMP_EQ, FUNC_NONE, NULLPtr), 
			  NewElement(EXgenericFlowID, OFFproto, SIZEproto, IPPROTO_ICMPV6, CMP_EQ, FUNC_NONE, NULLPtr)
		  );
	if ( strcasecmp(type, "type") == 0 ) {
		ret = Connect_AND(
			protoICMP,
		  NewElement(EXgenericFlowID, OFFicmpType, SIZEicmpType, number, comp, FUNC_NONE, NULLPtr)
	  );
	} else if ( strcasecmp(type, "code") == 0 ) {
		ret = Connect_AND(
			protoICMP,
			NewElement(EXgenericFlowID, OFFicmpCode, SIZEicmpCode, number, comp, FUNC_NONE, NULLPtr)
	  );
	} 

	return ret;
} // End of AddICMP

static int AddFlagsNumber(direction_t direction, uint16_t comp, uint64_t flags) {
	if ( flags > 255 ) {
		  yyprintf("flags number %" PRIu64 " > 255", flags);
			return -1;
	}

	// direction ignored

	return Connect_AND(
	  // imply flags with proto TCP
	  NewElement(EXgenericFlowID, OFFproto, SIZEproto, IPPROTO_TCP, CMP_EQ, FUNC_NONE, NULLPtr), 
	  NewElement(EXgenericFlowID, OFFtcpFlags, SIZEtcpFlags, flags, comp, FUNC_NONE, NULLPtr)
  );
} // End of AddFlagsNumber

static int AddFlagsString(direction_t direction, char *flags) {
	size_t len = strlen(flags);
  if ( len > 10 ) {
	  yyprintf("Flags string error");
		return -1;
  }

	int strict = 0;
	if ( flags[0] == '=') {
	  strict = 1;
	  len--;
  }

  int cnt     = 0;
  uint64_t fl = 0;
  if ( strchr(flags, 'F') ) { fl |=  1; cnt++; }
  if ( strchr(flags, 'S') ) { fl |=  2; cnt++; }
  if ( strchr(flags, 'R') ) { fl |=  4; cnt++; }
  if ( strchr(flags, 'P') ) { fl |=  8; cnt++; }
  if ( strchr(flags, 'A') ) { fl |=  16; cnt++; }
  if ( strchr(flags, 'U') ) { fl |=  32; cnt++; }
  if ( strchr(flags, 'E') ) { fl |=  64; cnt++; }
  if ( strchr(flags, 'C') ) { fl |= 128; cnt++; }
  if ( strchr(flags, 'X') ) { fl =  63; cnt++; }

  if ( cnt != len ) {
	  yyprintf("Unknown flags");
		return -1;
  }

  if (strict) {
		return AddFlagsNumber(direction, CMP_EQ, fl);
  } else {
		return AddFlagsNumber(direction, CMP_FLAGS, fl);
  }

	// unreached
} // End of AddFlagsString

static int AddTosNumber(direction_t direction, uint16_t comp, uint64_t tos) {
	if ( tos > 255 ) {
		yyprintf("Tos number %" PRIu64 " out of range", tos);
		return -1;
  }

	int ret = -1;
  switch (direction) {
	  case DIR_UNSPEC:
	  case DIR_SRC: 
		  ret = NewElement(EXgenericFlowID, OFFsrcTos, SIZEsrcTos, tos, comp, FUNC_NONE, NULLPtr);
		  break;
	  case DIR_DST: 
		  ret = NewElement(EXflowMiscID, OFFdstTos, SIZEdstTos, tos, comp, FUNC_NONE, NULLPtr);
		  break;
	  default:
		  yyprintf("syntax error");
  } // End of switch

	return ret;
} // End of AddTosNumber

static int AddIPttl(prefix_t prefix, uint16_t comp, uint64_t ttl) {
	if ( ttl > 255 ) {
		yyprintf("TTL number out of range");
		return -1;
  }

	int ret = 0;
	switch (prefix) {
		case PRE_UNKNOWN:
			ret = Connect_OR(
				NewElement(EXipInfoID, OFFminTTL, SIZEminTTL, ttl, comp, FUNC_NONE, NULLPtr),
				NewElement(EXipInfoID, OFFmaxTTL, SIZEmaxTTL, ttl, comp, FUNC_NONE, NULLPtr));
			break;
		case PRE_MIN:
			ret = NewElement(EXipInfoID, OFFminTTL, SIZEminTTL, ttl, comp, FUNC_NONE, NULLPtr);
			break;
		case PRE_MAX:
			ret = NewElement(EXipInfoID, OFFmaxTTL, SIZEmaxTTL, ttl, comp, FUNC_NONE, NULLPtr);
			break;
	}
	return ret;

} // End of AddIPttl

static int AddIPttlEqual(char *arg) {
	if (strcasecmp(arg, "equal") != 0 ) {
		yyprintf("Unexpected argument: %s", arg);
		return -1;
	}
	
	return NewElement(EXipInfoID, OFFminTTL, SIZEminTTL, 1, CMP_EQ, FUNC_TTL_EQUAL, NULLPtr);
} // End of AddIPttlEqual

static int AddPackets(direction_t direction, uint16_t comp, uint64_t packets) {

	int ret = -1;
	switch ( direction ) {
		case DIR_UNSPEC:
	  case DIR_IN: 
		  ret = NewElement(EXgenericFlowID, OFFinPackets, SIZEinPackets, packets, comp, FUNC_NONE, NULLPtr); 
		  break;
	  case DIR_OUT: 
		  ret = NewElement(EXgenericFlowID, OFFoutPackets, SIZEoutPackets, packets, comp, FUNC_NONE, NULLPtr); 
		break;
	  default:
		  yyprintf("Invalid direction for packets");
	} // End of switch
	return ret;
} // End of AddPackets

static int AddBytes(direction_t direction, uint16_t comp, uint64_t bytes) {
	int ret = -1;
	switch ( direction ) {
	  case DIR_UNSPEC:
	  case DIR_IN: 
		  ret = NewElement(EXgenericFlowID, OFFinBytes, SIZEinBytes, bytes, comp, FUNC_NONE, NULLPtr); 
		  break;
	  case DIR_OUT: 
		  ret = NewElement(EXgenericFlowID, OFFoutBytes, SIZEoutBytes, bytes, comp, FUNC_NONE, NULLPtr); 
		  break;
	  default:
		  yyprintf("Invalid direction for bytes");
	 } // End of switch
	 return ret;
} // End of AddBytes

static int AddFwdStatNum(uint16_t comp, uint64_t num) {
	if ( num > 255 ) {
	  yyprintf("Forwarding status: %" PRIu64 " our of range", num);
		return -1;
	}

	return NewElement(EXgenericFlowID, OFFfwdStatus, SIZEfwdStatus, num, comp, FUNC_NONE, NULLPtr);
} // End of AddFwdStatNum

static int AddFwdStatString(char *string) {
	int	fwdStatus = fwdStatusNum(string);
	if ( fwdStatus < 0 ) {
	  fwdStatusInfo();
	  yyprintf("Unkown forwarding status: %s", string);
		return -1;
	}

	return NewElement(EXgenericFlowID, OFFfwdStatus, SIZEfwdStatus, fwdStatus, CMP_EQ, FUNC_NONE, NULLPtr);
} // End of AddFwdStatString

static int AddMPLS(char *type, uint16_t comp, uint64_t value) {
	if ( strncasecmp(type, "label", 5) == 0 ) {
		char *s = type + 5;
		if ( *s == '\0' ) {
			yyprintf("Missing mpls stack number for label");
			return -1;
		}
		int lnum = (int)strtol(s, (char **)NULL, 10);
		data_t labelIndex = { .dataVal = lnum};
		return NewElement(EXmplsLabelID, 0, 0, value, comp, FUNC_MPLS_LABEL, labelIndex);
	} else if ( strcasecmp(type, "any") == 0 ) {
		data_t labelValue = { .dataVal = value};
		return NewElement(EXmplsLabelID, 0, 0, value, comp, FUNC_MPLS_ANY, labelValue);
	} else if ( strcasecmp(type, "eos") == 0 ) {
		// match End of Stack label 
		return NewElement(EXmplsLabelID, 0, 0, value, comp, FUNC_MPLS_EOS, NULLPtr);
	} else if ( strncasecmp(type, "exp", 3) == 0 ) {
		char *s = type + 3;
		if ( *s == '\0' ) {
			yyprintf("Missing mpls stack number for exp value");
			return -1;
		}
		int lnum = (int)strtol(s, (char **)NULL, 10);
		data_t data = {.dataVal = lnum};
		return NewElement(EXmplsLabelID, 0, 0, value, comp, FUNC_MPLS_EXP, data);
	} else {
			yyprintf("Unknown mpls argument: %s", type);
			return -1;
	}

	// unreached
	return -1;
} // End of AddMPLS

static int AddEthertype(uint64_t etherType) {
	return NewElement(EXlayer2ID, OFFetherType, SIZEetherType, etherType, CMP_EQ, FUNC_NONE, NULLPtr);
} // End of AddMAC

static int AddMAC(direction_t direction, char *macString) {

	uint64_t macVal = Str2Mac(macString);
	if ( macVal == 0 ) return -1;

	switch (direction) {
		case DIR_IN_SRC:
			return NewElement(EXmacAddrID, OFFinSrcMac, SIZEinSrcMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr);
			break;
		case DIR_IN_DST:
			return NewElement(EXmacAddrID, OFFinDstMac, SIZEinDstMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr);
			break;
		case DIR_OUT_SRC:
			return NewElement(EXmacAddrID, OFFoutSrcMac, SIZEoutSrcMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr);
			break;
		case DIR_OUT_DST:
			return NewElement(EXmacAddrID, OFFoutDstMac, SIZEoutDstMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr);
			break;
		case DIR_SRC:
			return Connect_OR (
				NewElement(EXmacAddrID, OFFinSrcMac, SIZEinSrcMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr),
				NewElement(EXmacAddrID, OFFoutSrcMac, SIZEoutSrcMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr)
			);
			break;
		case DIR_DST:
			return Connect_OR (
				NewElement(EXmacAddrID, OFFinDstMac, SIZEinDstMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr),
				NewElement(EXmacAddrID, OFFoutDstMac, SIZEoutDstMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr)
			);
			break;
		case DIR_IN:
			return Connect_OR (
				NewElement(EXmacAddrID, OFFinSrcMac, SIZEinSrcMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr),
				NewElement(EXmacAddrID, OFFinDstMac, SIZEinDstMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr)
			);
			break;
		case DIR_OUT:
			return Connect_OR (
				NewElement(EXmacAddrID, OFFoutSrcMac, SIZEoutSrcMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr),
				NewElement(EXmacAddrID, OFFoutDstMac, SIZEoutDstMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr)
			);
			break;
		case DIR_UNSPEC: {
				int in = Connect_OR (
					NewElement(EXmacAddrID, OFFinSrcMac, SIZEinSrcMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr),
					NewElement(EXmacAddrID, OFFinDstMac, SIZEinDstMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr)
				);
				int out = Connect_OR (
					NewElement(EXmacAddrID, OFFoutSrcMac, SIZEoutSrcMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr),
					NewElement(EXmacAddrID, OFFoutDstMac, SIZEoutDstMac, macVal, CMP_EQ, FUNC_NONE, NULLPtr)
				);
				return Connect_OR(in, out);
			} break;
		default:
			yyprintf("Unknown mac argument");
			return -1;
	}

	// unreached
	return -1;
} // End of AddMAC

static int AddLatency(direction_t direction, uint16_t comp, uint64_t number) {

	int ret = -1;
  switch (direction) {
		case DIR_CLIENT:
			ret =  NewElement(EXlatencyID, OFFusecClientNwDelay, SIZEusecClientNwDelay, number, comp, FUNC_NONE, NULLPtr);
		  break;
		case DIR_SERVER:
			ret =  NewElement(EXlatencyID, OFFusecServerNwDelay, SIZEusecServerNwDelay, number, comp, FUNC_NONE, NULLPtr);
		  break;
		// case XXX	ret =  NewElement(EXlatencyID, OFFusecApplLatency, SIZEusecApplLatency, number, comp, FUNC_NONE, NULLPtr);
		default:
			yyprintf("Unknown latency argument");
  }

	return ret;
} // End of AddLatency

static int AddASAString(char *event, char *asaStr) {

	if (strcasecmp(event, "event") == 0) {
		int eventNum = fwEventID(asaStr);
		if ( eventNum < 0 ) {
			yyprintf("Invalid ASA event type: %s", asaStr);
			return -1;
		}
		return NewElement(EXnselCommonID, OFFfwEvent, SIZEfwEvent, eventNum, CMP_EQ, FUNC_NONE, NULLPtr);
	} else if (strcasecmp(event, "denied") == 0) {
		int eventNum = fwXEventID(asaStr);
		if ( eventNum < 0 ) {
			yyprintf("Invalid ASA Xevent type: %s", asaStr);
			return -1;
		}
		return NewElement(EXnselCommonID, OFFfwXevent, SIZEfwXevent, eventNum, CMP_EQ, FUNC_NONE, NULLPtr);
	} else if (strcasecmp(event, "user") == 0) {
		if ( strlen(asaStr) > 65 ) {
			yyprintf("Length of ASA user name > 65 chars");
			return -1;
		}
		data_t data = {.dataPtr = strdup(asaStr)};
		return NewElement(EXnselUserID, OFFusername, 0, 0, CMP_STRING, FUNC_NONE, data);
	}

	yyprintf("Invalid ASA type: %s", event);
	return -1;

} // End of AddASAString

static int AddASA(char *event, uint16_t comp, uint64_t number) {

	if ( strcasecmp(event, "event") == 0 ) {
		if ( number > 5 ) {
			yyprintf("Invalid event number %" PRIu64 ". Expected 0..5", number);
			return -1;
		}
		return NewElement(EXnselCommonID, OFFfwEvent, SIZEfwEvent, number, comp, FUNC_NONE, NULLPtr);
	} else if ( strcasecmp(event, "xevent") == 0 ) {
		return NewElement(EXnselCommonID, OFFfwXevent, SIZEfwXevent, number, comp, FUNC_NONE, NULLPtr);
	}

	yyprintf("Invalid ASA type: %s", event);
	return -1;

} // End of AddASA

static int AddACL(direction_t direction, uint16_t comp, uint64_t number) {

	uint32_t offset = 0;
	switch (direction) {
		case DIR_INGRESS:
			offset = OFFingressAcl;
			break;
		case DIR_EGRESS:
			offset = OFFegressAcl;
			break;
		default:
			yyprintf("Invalid ACL direction");
			return -1;
	}
	
	uint32_t acl[3];
	acl[0] = NewElement(EXnselAclID, offset, sizeof(uint32_t), number, comp, FUNC_NONE, NULLPtr);
	acl[1] = NewElement(EXnselAclID, offset + sizeof(uint32_t), sizeof(uint32_t), number, comp, FUNC_NONE, NULLPtr);
	acl[2] = NewElement(EXnselAclID, offset + 2*sizeof(uint32_t), sizeof(uint32_t), number, comp, FUNC_NONE, NULLPtr);
	return Connect_OR (
		Connect_OR(acl[0], acl[1]), acl[2]
	);
	return -1;

} // End of AddASA

static int AddASApblock(direction_t direction, char *arg) {

	if (strcasecmp(arg, "pblock") != 0) {
			yyprintf("Invalid port block: %s", arg);
			return -1;
	}

	int ret = -1;
	switch (direction) {
		case DIR_SRC:
		  ret = NewElement(EXgenericFlowID, OFFsrcPort, SIZEsrcPort, 1, CMP_EQ, FUNC_PBLOCK, NULLPtr);
		  break;
	  case DIR_DST:
		  ret = NewElement(EXgenericFlowID, OFFdstPort, SIZEdstPort, 1, CMP_EQ, FUNC_PBLOCK, NULLPtr);
		  break;
	  case DIR_UNSPEC:
		  ret = Connect_OR(
			  NewElement(EXgenericFlowID, OFFsrcPort, SIZEsrcPort, 1, CMP_EQ, FUNC_PBLOCK, NULLPtr),
			  NewElement(EXgenericFlowID, OFFdstPort, SIZEdstPort, 1, CMP_EQ, FUNC_PBLOCK, NULLPtr)
		  );
		  break;
		default:
			yyprintf("Invalid port direction");
	}

	return ret;
} // End of AddASApblock

static int AddNATString(char *event, char *natStr) {

	if (strcasecmp(event, "event") == 0) {
		int eventNum = natEventNum(natStr);
		if ( eventNum < 0 ) {
			yyprintf("Invalid NAT event type: %s", natStr);
			natEventInfo();
			return -1;
		}
		return NewElement(EXnatCommonID, OFFnatEvent, SIZEnatEvent, eventNum, CMP_EQ, FUNC_NONE, NULLPtr);
	} 

	yyprintf("Invalid NAT type: %s", event);

	return -1;

} // End of AddNATString

static int AddNAT(char *event, uint16_t comp, uint64_t number) {

	if (strcasecmp(event, "event") == 0) {
		if ( number > MAX_NAT_EVENTS ) {
			yyprintf("NAT event: %" PRIu64 " out of range", number);
			return -1;
		}
		return NewElement(EXnatCommonID, OFFnatEvent, SIZEnatEvent, number, comp, FUNC_NONE, NULLPtr);
	} 

	return -1;
} // End of AddNAT

static int AddNatPortBlocks(char *type, char *subtype, uint16_t comp, uint64_t number) {

	uint32_t offset = 0;
	if (strcasecmp(type, "pblock") == 0) {
		if (strcasecmp(subtype, "start") == 0) {
			offset = OFFnelblockStart;
		} else if (strcasecmp(subtype, "end") == 0) {
			offset = OFFnelblockEnd;
		} else if (strcasecmp(subtype, "step") == 0) {
			offset = OFFnelblockStep;
		} else if (strcasecmp(subtype, "size") == 0) {
			offset = OFFnelblockSize;
		} else {
			yyprintf("Unknown port block argument: %s", subtype);
			return -1;
		}
	} else {
			yyprintf("Unknown NAT argument: %s", type);
			return -1;
	}

	return NewElement(EXnatPortBlockID, offset, SIZEnelblockStart, number, comp, FUNC_NONE, NULLPtr);
	return -1;
} // End of AddNatPortBlocks

static int AddPayloadSSL(char *type, char *arg, char *opt) {
	if (strcasecmp(arg, "defined") == 0) {
		return NewElement(SSLindex, 0, 0, 0, CMP_EQ, FUNC_NONE, NULLPtr);
	} else if (strcasecmp(arg, "version") == 0) {
		if ( opt == NULL ){
			yyprintf("String %s is not a valid SSL/TLS version", arg);
			return -1;
		}
		unsigned int major, minor;
		if (sscanf(opt, "%1u.%1u", &major, &minor) != 2 || major > 3 || minor > 3 ) {
			yyprintf("String %s is not a valid SSL/TLS version", opt);
			return -1;
		}
		// if old SSL 2.0 or 3.0
		if (major > 1 && minor > 0){
			yyprintf("String %s is not a valid SSL/TLS version", opt);
			return -1;
		}
		uint16_t version = 0;
		if ( strcasecmp(type, "tls") == 0 ) {
			if (major > 1){
				yyprintf("String %s is not a valid TLS version", opt);
				return -1;
			}
			// TLS
			version = (0x03 << 8) | (minor + 1);
		} else {
			if (minor > 0){
				yyprintf("String %s is not a valid SSL version", opt);
				return -1;
			}
			// SSL
			version = major << 8;
		}
		return NewElement(SSLindex, OFFsslVersion, SIZEsslVersion, version, CMP_EQ, FUNC_NONE, NULLPtr);
	} else if (strcasecmp(arg, "sni") == 0) {
		if ( opt == NULL || strlen(opt) > 64 ) {
			yyprintf("Invalid string %s for SSL/TLS sni name", opt != NULL ? opt : "");
			return -1;
		}
		data_t data = {.dataPtr=strdup(opt)};
		return NewElement(SSLindex, OFFsslSNI, SIZEsslSNI, 0, CMP_SUBSTRING, FUNC_NONE, data);
	}
	yyprintf("String %s is not a valid SSL/TLS filter", arg);
	return -1;
} // End of AddPayloadSSL

static int AddPayloadJA3(char *type, char *arg, char *opt) {
	if (strcasecmp(arg, "defined") == 0) {
		return NewElement(JA3index, OFFja3String, SIZEja3String, 0, CMP_EQ, FUNC_NONE, NULLPtr);
	} else if (IsMD5(arg) == 0) {
		yyprintf("String %s is not a valid ja3 string", arg);
		return -1;
	}
	data_t data = {.dataPtr=strdup(arg)};
	return NewElement(JA3index, OFFja3String, SIZEja3String, 0, CMP_STRING, FUNC_NONE, data);
} // End of AddPayloadJA3

static int AddPayloadJA4(char *type, char *arg, char *opt) {
	if (strcasecmp(arg, "defined") == 0) {
		return NewElement(JA4index, OFFja4String, SIZEja3String, 0, CMP_EQ, FUNC_NONE, NULLPtr);
	} else if ( ja4Check(arg) == 0 ){
		yyprintf("String %s is not a valid ja4 string", arg);
		return -1;
	}
	data_t data = {.dataPtr=strdup(arg)};
	return NewElement(JA4index, OFFja4String, SIZEja4String, 0, CMP_STRING, FUNC_NONE, data);
} // End of AddPayloadJA4

static int AddPayload(char *type, char *arg, char *opt) {

	if (strcasecmp(type, "content") == 0) {
		data_t data = {.dataPtr = arg};
		return NewElement(EXinPayloadID, 0, 0, 0, CMP_PAYLOAD, FUNC_NONE, data);
	} else if (strcasecmp(type, "regex") == 0) {
		int err[2];
		char *regexArg = opt ? opt : "";
		srx_Context *program = srx_CreateExt(arg, strlen(arg), regexArg, err, NULL, NULL);
		if ( !program ) {
			yyprintf("failed to compile regex: %s", arg);
			return -1;
		}
		data_t data = {.dataPtr = program};
		return NewElement(EXinPayloadID, 0, 0, 0, CMP_REGEX, FUNC_NONE, data);
	} else if (strcasecmp(type, "ssl") == 0 || strcasecmp(type, "tls") == 0) {
		return AddPayloadSSL(type, arg, opt);
	} else if (strcasecmp(type, "ja3") == 0) {
		return AddPayloadJA3(type, arg, opt);
	} else if (strcasecmp(type, "ja4") == 0) {
		return AddPayloadJA4(type, arg, opt);
	} else if (strcasecmp(type, "ja4s") == 0) {
#ifdef BUILDJA4
		if ( ja4sCheck(arg) == 0 ){
			yyprintf("String %s is not a valid ja4s string", arg);
			return -1;
		}
		data_t data = {.dataPtr=strdup(arg)};
		return NewElement(JA4index, OFFja4String, SIZEja4sString, 0, CMP_STRING, FUNC_NONE, data);
#else
		yyprintf("ja4s code not enabled");
		return -1;
#endif
	} else {
		yyprintf("Unknown 'payload' argument: %s", type);
		return -1;
	}

	return -1;
} // End of AddPayload

static int AddGeo(direction_t direction, char *geo) {

	// geo => "geo CC" -> remove CC
	// lex rule guarantees 6 bytes - just test again
	geo += 4;
	if ( strlen(geo) != 2 ) {
			yyprintf("Geo country code legnth error");
			return -1;
	}

	data_t data = {.dataVal = direction};
	int ret = -1;
	uint64_t geoVal = toupper(geo[0]) + (toupper(geo[1]) << 8);
	switch (direction) {
		case DIR_SRC:
			ret = NewElement(EXlocal, OFFgeoSrcIP, SizeGEOloc, geoVal, CMP_GEO, FUNC_NONE, data);
			break;
		case DIR_DST:
			ret = NewElement(EXlocal, OFFgeoDstIP, SizeGEOloc, geoVal, CMP_GEO, FUNC_NONE, data);
			break;
		case DIR_SRC_NAT:
			ret = NewElement(EXlocal, OFFgeoSrcNatIP, SizeGEOloc, geoVal, CMP_GEO, FUNC_NONE, data);
			break;
		case DIR_DST_NAT:
			ret = NewElement(EXlocal, OFFgeoDstNatIP, SizeGEOloc, geoVal, CMP_GEO, FUNC_NONE, data);
			break;
		case DIR_SRC_TUN:
			ret = NewElement(EXlocal, OFFgeoSrcTunIP, SizeGEOloc, geoVal, CMP_GEO, FUNC_NONE, data);
			break;
		case DIR_DST_TUN:
			ret = NewElement(EXlocal, OFFgeoDstTunIP, SizeGEOloc, geoVal, CMP_GEO, FUNC_NONE, data);
			break;
		case DIR_UNSPEC: {
			data_t srcData = {.dataVal = DIR_SRC};
			data_t dstData = {.dataVal = DIR_DST};
			ret = Connect_OR(
				NewElement(EXlocal, OFFgeoSrcIP, SizeGEOloc, geoVal, CMP_GEO, FUNC_NONE, srcData),
				NewElement(EXlocal, OFFgeoDstIP, SizeGEOloc, geoVal, CMP_GEO, FUNC_NONE, dstData)
			);
			} break;
		case DIR_UNSPEC_NAT: {
			data_t srcData = {.dataVal = DIR_SRC_NAT};
			data_t dstData = {.dataVal = DIR_DST_NAT};
			ret = Connect_OR(
				NewElement(EXlocal, OFFgeoSrcNatIP, SizeGEOloc, geoVal, CMP_GEO, FUNC_NONE, srcData),
				NewElement(EXlocal, OFFgeoDstNatIP, SizeGEOloc, geoVal, CMP_GEO, FUNC_NONE, dstData)
			);
			} break;
		case DIR_UNSPEC_TUN: {
			data_t srcData = {.dataVal = DIR_SRC_TUN};
			data_t dstData = {.dataVal = DIR_DST_TUN};
			ret = Connect_OR(
				NewElement(EXlocal, OFFgeoSrcTunIP, SizeGEOloc, geoVal, CMP_GEO, FUNC_NONE, srcData),
				NewElement(EXlocal, OFFgeoDstTunIP, SizeGEOloc, geoVal, CMP_GEO, FUNC_NONE, dstData)
			);
			} break;
		default:
			yyprintf("Unknown Geo specifier");
	}

	return ret;
} // End of AddGeo

static int AddObservation(char *type, char *subType, uint16_t comp, uint64_t number) {

	if (strcasecmp(subType, "id") != 0) {
			yyprintf("Unknown observation specifier: %s", subType);
			return -1;
	}
	int ret = -1;
	if (strcasecmp(type, "domain") == 0) {
		ret =  NewElement(EXobservationID, OFFdomainID, SIZEdomainID, number, comp, FUNC_NONE, NULLPtr);
	} else if (strcasecmp(type, "point") == 0) {
		ret =  NewElement(EXobservationID, OFFpointID, SIZEpointID, number, comp, FUNC_NONE, NULLPtr);
	} else {
		yyprintf("Unknown observation specifier: %s", type);
	}

	return ret;
} // End of AddObservation

static int AddVRF(direction_t direction, uint16_t comp, uint64_t number) {

	int ret = -1;
	switch(direction) {
		case DIR_INGRESS:
			ret =  NewElement(EXvrfID, OFFingressVrf, SIZEingressVrf, number, comp, FUNC_NONE, NULLPtr);
			break;
		case DIR_EGRESS:
			ret =  NewElement(EXvrfID, OFFegressVrf, SIZEegressVrf, number, comp, FUNC_NONE, NULLPtr);
			break;
		default:
			yyprintf("Unknown vrf specifier");
	}

	return ret;
} // End of AddVRF

static int AddTimeSting(char *firstLast, uint16_t comp, char *timeString) {

	int ret = -1;
	uint64_t number = ParseTime8601(timeString);
	if ( number == 0 ) {
		yyprintf("Invalid ISO8601 time string: %s", timeString);
		return ret;
	}

	if ( strcasecmp(firstLast, "first") == 0 ) { // first seen
		ret =  NewElement(EXgenericFlowID, OFFmsecFirst, SIZEmsecFirst, number, comp, FUNC_NONE, NULLPtr);
	} if ( strcasecmp(firstLast, "last") == 0 ) { // last seen
		ret =  NewElement(EXgenericFlowID, OFFmsecLast, SIZEmsecLast, number, comp, FUNC_NONE, NULLPtr);
	}	else { 
		yyprintf("Unexpected token: %s", timeString);
	}

	return ret;
} // End of AddTimeSting

static int AddPFString(char *type, char *arg) {

	int ret = -1;
	if (strcasecmp(type, "action") == 0) {
		int pfAction = pfActionNr(arg);
		if ( pfAction < 0 ) {
				yyprintf("Invalid pf action: %s", arg);
				printf("Possible pf action values: ");
				pfListActions();
			} else {
				ret = NewElement(EXpfinfoID, OFFpfAction, SIZEpfAction, pfAction, CMP_EQ, FUNC_NONE, NULLPtr);
			}
	} else if (strcasecmp(type, "reason") == 0) {
		int pfReason = pfReasonNr(arg);
			if ( pfReason < 0 ) {
				yyprintf("Invalid pf reason: %s", arg);
				printf("Possible pf reason values: ");
				pfListReasons();
			} else {
				ret = NewElement(EXpfinfoID, OFFpfReason, SIZEpfReason, pfReason, CMP_EQ, FUNC_NONE, NULLPtr);
			}
	} else if (strcasecmp(type, "dir") == 0) {
		int pfDir = strcasecmp(arg, "in") == 0 ? 1: 0;
		ret = NewElement(EXpfinfoID, OFFpfDir, SIZEpfDir, pfDir, CMP_EQ, FUNC_NONE, NULLPtr);
	} else if (strcasecmp(type, "interface") == 0) {
		data_t data = {.dataPtr=strdup(arg)};
		ret = NewElement(EXpfinfoID, OFFpfIfName, SIZEpfIfName, 0, CMP_STRING, FUNC_NONE, data);
	} else {
		yyprintf("Invalid pf argument: %s", type);
	}
	return ret;
} // End of AddPFString

static int AddPFNumber(char *type, uint16_t comp, uint64_t number) {

	int ret = -1;
	if (strcasecmp(type, "rule") == 0) {
		ret = NewElement(EXpfinfoID, OFFpfRuleNr, SIZEpfRuleNr, number, comp, FUNC_NONE, NULLPtr);
	} else {
		yyprintf("Invalid pf argument: %s", type);
	}

	return ret;
} // End of AddPFNumber

static int AddIP(direction_t direction, char *IPstr) {

	int ret = -1;

	// if it's a tor node check
	if (strcasecmp(IPstr, "tor") == 0 ) {
		switch ( direction ) {
		case DIR_SRC:
			ret = Connect_OR(
				NewElement(EXipv4FlowID, OFFsrc4Addr, SIZEsrc4Addr, 1, CMP_EQ, FUNC_TOR_LOOKUP, NULLPtr), 
				NewElement(EXipv6FlowID, OFFsrc6Addr, SIZEsrc6Addr, 1, CMP_EQ, FUNC_TOR_LOOKUP, NULLPtr)
			);
			break;
		case DIR_DST:
			ret = Connect_OR(
				NewElement(EXipv4FlowID, OFFdst4Addr, SIZEdst4Addr, 1, CMP_EQ, FUNC_TOR_LOOKUP, NULLPtr), 
				NewElement(EXipv6FlowID, OFFdst6Addr, SIZEdst6Addr, 1, CMP_EQ, FUNC_TOR_LOOKUP, NULLPtr)
			);
			break;
		case DIR_UNSPEC: {
			int src = Connect_OR(
				NewElement(EXipv4FlowID, OFFsrc4Addr, SIZEsrc4Addr, 1, CMP_EQ, FUNC_TOR_LOOKUP, NULLPtr), 
				NewElement(EXipv6FlowID, OFFsrc6Addr, SIZEsrc6Addr, 1, CMP_EQ, FUNC_TOR_LOOKUP, NULLPtr)
			);
			int dst = Connect_OR(
				NewElement(EXipv4FlowID, OFFdst4Addr, SIZEdst4Addr, 1, CMP_EQ, FUNC_TOR_LOOKUP, NULLPtr), 
				NewElement(EXipv6FlowID, OFFdst6Addr, SIZEdst6Addr, 1, CMP_EQ, FUNC_TOR_LOOKUP, NULLPtr)
			);
			ret = Connect_OR(src,dst); 
			} break;
		default:
			yyprintf("Invalid direction for tor lookup");
		}
		return ret;
	} 

	// else normal IP compare
	int lookupMode = STRICT_IP;
	switch ( direction ) {
			case DIR_SRC:
			case DIR_DST:
			case DIR_UNSPEC:
				lookupMode = ALLOW_LOOKUP;
				break;
			default:
				lookupMode = STRICT_IP;
	} // End of switch

	int numIP = parseIP(IPstr, ipStack, lookupMode);
	if ( numIP <= 0)  {
		yyprintf("Can not parse/lookup %s to an IP address", IPstr);
		return -1;
	}

	switch ( direction ) {
		case DIR_SRC:
		case DIR_DST:
		case DIR_SRC_NAT:
		case DIR_DST_NAT:
		case DIR_SRC_TUN:
		case DIR_DST_TUN:
		case DIR_NEXT:
		case BGP_NEXT:
		case SRC_ROUTER:
			ret = ChainHosts(ipStack, numIP, direction);
			break;
		case DIR_UNSPEC: {
			uint32_t src = ChainHosts(ipStack, numIP, DIR_SRC);
			uint32_t dst = ChainHosts(ipStack, numIP, DIR_DST);
			ret = Connect_OR(src, dst);
			} break;
		case DIR_UNSPEC_NAT: {
			uint32_t src = ChainHosts(ipStack, numIP, DIR_SRC_NAT);
			uint32_t dst = ChainHosts(ipStack, numIP, DIR_DST_NAT);
			ret = Connect_OR(src, dst);
			} break;
		case DIR_UNSPEC_TUN: {
			uint32_t src = ChainHosts(ipStack, numIP, DIR_SRC_TUN);
			uint32_t dst = ChainHosts(ipStack, numIP, DIR_DST_TUN);
			ret = Connect_OR(src, dst);
			} break;
		default:
			yyprintf("Unknown direction for IP address");
	} // End of switch

	return ret;
} // End of AddIP

static int AddNet(direction_t direction, char *IPstr, char *maskStr) {
	
	int numIP = parseIP(IPstr, ipStack, STRICT_IP);
	if (numIP <= 0)  {
		yyprintf("Can not parse/lookup %s to an IP address", IPstr);
		return -1;
	}

	ipStack_t	mask;
	numIP = parseIP(maskStr, &mask, STRICT_IP);
	if (numIP <= 0)  {
		yyprintf("Can not parse %s as IP mask", maskStr);
		return -1;
	}

	if (ipStack[0].af != PF_INET || mask.af != PF_INET) {
		yyprintf("Net address %s and netmask: %s must be IPv4", IPstr, maskStr);
		return -1;
	}

	data_t data = {.dataVal = mask.ipaddr[1]};

	int ret = -1;
	switch ( direction ) {
		case DIR_SRC:
		case DIR_DST:
		case DIR_SRC_NAT:
		case DIR_DST_NAT:
		case DIR_SRC_TUN:
		case DIR_DST_TUN:
		case DIR_NEXT:
		case BGP_NEXT:
		case SRC_ROUTER:
			ret = NewIPElement(&ipStack[0], direction, CMP_NET, &data);
			break;
		case DIR_UNSPEC: {
			uint32_t src = NewIPElement(&ipStack[0], DIR_SRC, CMP_NET, &data);
			uint32_t dst = NewIPElement(&ipStack[0], DIR_DST, CMP_NET, &data);
			ret = Connect_OR(src, dst);
			} break;
		case DIR_UNSPEC_NAT: {
			uint32_t src = NewIPElement(&ipStack[0], DIR_SRC_NAT, CMP_NET, &data);
			uint32_t dst = NewIPElement(&ipStack[0], DIR_DST_NAT, CMP_NET, &data);
			ret = Connect_OR(src, dst);
			} break;
		case DIR_UNSPEC_TUN: {
			uint32_t src = NewIPElement(&ipStack[0], DIR_SRC_TUN, CMP_NET, &data);
			uint32_t dst = NewIPElement(&ipStack[0], DIR_DST_TUN, CMP_NET, &data);
			ret = Connect_OR(src, dst);
			} break;
		default:
			yyprintf("Unknown direction for IP address");
	} // End of switch

	return ret;
} // End of AddNet

static int AddNetPrefix(direction_t direction, char *IPstr, uint64_t prefix) {
	int numIP = parseIP(IPstr, ipStack, STRICT_IP);
	if (numIP <= 0)  {
		yyprintf("Can not parse/lookup %s to an IP address", IPstr);
		return -1;
	}

	data_t data[2];
	if (ipStack[0].af == PF_INET) {
		// IPv4 
		if (prefix >32 ) {
			yyprintf("Prefix %" PRIu64 " out of range for IPv4 address", prefix);
			return -1;
		}
		data[0].dataVal = 0xffffffffffffffffLL << (32 - prefix);
	} else {
		// IPv6
		if (prefix >128 ) {
			yyprintf("Prefix %" PRIu64 " out of range for IPv6 address", prefix);
			return -1;
		}
		if ( prefix > 64 ) {
			data[0].dataVal = 0xffffffffffffffffLL;
			data[1].dataVal = 0xffffffffffffffffLL << (128 - prefix);
		} else {
			data[0].dataVal = 0xffffffffffffffffLL << (64 - prefix);
			data[1].dataVal = 0;
		}
	}

	int ret = -1;
	switch (direction) {
		case DIR_SRC:
		case DIR_DST:
		case DIR_SRC_NAT:
		case DIR_DST_NAT:
		case DIR_SRC_TUN:
		case DIR_DST_TUN:
		case DIR_NEXT:
		case BGP_NEXT:
		case SRC_ROUTER:
			ret = NewIPElement(&ipStack[0], direction, CMP_NET, data);
			break;
		case DIR_UNSPEC: {
			uint32_t src = NewIPElement(&ipStack[0], DIR_SRC, CMP_NET, data);
			uint32_t dst = NewIPElement(&ipStack[0], DIR_DST, CMP_NET, data);
			ret = Connect_OR(src, dst);
			} break;
		case DIR_UNSPEC_NAT: {
			uint32_t src = NewIPElement(&ipStack[0], DIR_SRC_NAT, CMP_NET, data);
			uint32_t dst = NewIPElement(&ipStack[0], DIR_DST_NAT, CMP_NET, data);
			ret = Connect_OR(src, dst);
			} break;
		case DIR_UNSPEC_TUN: {
			uint32_t src = NewIPElement(&ipStack[0], DIR_SRC_TUN, CMP_NET, data);
			uint32_t dst = NewIPElement(&ipStack[0], DIR_DST_TUN, CMP_NET, data);
			ret = Connect_OR(src, dst);
			} break;
		default:
			yyprintf("Unknown direction for IP address");
	} // End of switch

	return ret;
} // End of AddNetPrefix

static int AddIPlist(direction_t direction, void *IPlist) {
	int ret = -1;
	data_t IPlistData = {IPlist};
	switch ( direction ) {
		case DIR_SRC:
			ret = Connect_OR(
				NewElement(EXipv4FlowID, OFFsrc4Addr, SIZEsrc4Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData), 
				NewElement(EXipv6FlowID, OFFsrc6Addr, SIZEsrc6Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData)
			);
			break;
		case DIR_DST:
			ret = Connect_OR(
				NewElement(EXipv4FlowID, OFFdst4Addr, SIZEdst4Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData), 
				NewElement(EXipv6FlowID, OFFdst6Addr, SIZEdst6Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData)
			);
			break;
		case DIR_SRC_NAT:
			ret = Connect_OR(
				NewElement(EXnatXlateIPv4ID, OFFxlateSrc4Addr, SIZExlateSrc4Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData), 
				NewElement(EXnatXlateIPv6ID, OFFxlateSrc6Addr, SIZExlateSrc6Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData)
			);
			break;
		case DIR_DST_NAT:
			ret = Connect_OR(
				NewElement(EXnatXlateIPv4ID, OFFxlateDst4Addr, SIZExlateDst4Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData), 
				NewElement(EXnatXlateIPv6ID, OFFxlateDst6Addr, SIZExlateDst6Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData)
			);
			break;
		case DIR_SRC_TUN:
			ret = Connect_OR(
				NewElement(EXtunIPv4ID, OFFtunSrc4Addr, SIZEtunSrc4Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData), 
				NewElement(EXtunIPv6ID, OFFtunSrc6Addr, SIZEtunSrc6Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData)
			);
			break;
		case DIR_DST_TUN:
			ret = Connect_OR(
				NewElement(EXtunIPv4ID, OFFtunDst4Addr, SIZEtunDst4Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData), 
				NewElement(EXtunIPv6ID, OFFtunDst6Addr, SIZEtunDst6Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData)
			);
			break;
		case DIR_NEXT:
			ret = Connect_OR(
				NewElement(EXipNextHopV4ID, OFFNextHopV4IP, SIZENextHopV4IP, 0, CMP_IPLIST, FUNC_NONE, IPlistData), 
				NewElement(EXipNextHopV6ID, OFFNextHopV6IP, SIZENextHopV6IP, 0, CMP_IPLIST, FUNC_NONE, IPlistData)
			);
			break;
		case DIR_UNSPEC: {
			int v4 = Connect_OR(
				NewElement(EXipv4FlowID, OFFsrc4Addr, SIZEsrc4Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData), 
				NewElement(EXipv4FlowID, OFFdst4Addr, SIZEdst4Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData) 
			);
			int v6 = Connect_OR(
				NewElement(EXipv6FlowID, OFFsrc6Addr, SIZEsrc6Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData),
				NewElement(EXipv6FlowID, OFFdst6Addr, SIZEdst6Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData)
			);
			ret = Connect_OR(v4, v6);
		} break;
		case DIR_UNSPEC_NAT: {
			int v4 = Connect_OR(
				NewElement(EXnatXlateIPv4ID, OFFxlateSrc4Addr, SIZExlateSrc4Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData), 
				NewElement(EXnatXlateIPv4ID, OFFxlateDst4Addr, SIZExlateDst4Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData) 
			);
			int v6 = Connect_OR(
				NewElement(EXnatXlateIPv6ID, OFFxlateSrc6Addr, SIZExlateSrc6Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData),
				NewElement(EXnatXlateIPv6ID, OFFxlateDst6Addr, SIZExlateDst6Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData)
			);
			ret = Connect_OR(v4, v6);
		} break;
		case DIR_UNSPEC_TUN: {
			int v4 = Connect_OR(
				NewElement(EXtunIPv4ID, OFFtunSrc4Addr, SIZEtunSrc4Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData), 
				NewElement(EXtunIPv4ID, OFFtunDst4Addr, SIZEtunDst4Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData)
			);
			int v6 = Connect_OR(
				NewElement(EXtunIPv6ID, OFFtunSrc6Addr, SIZEtunSrc6Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData),
				NewElement(EXtunIPv6ID, OFFtunDst6Addr, SIZEtunDst6Addr, 0, CMP_IPLIST, FUNC_NONE, IPlistData)
			);
			ret = Connect_OR(v4, v6);
		} break;
		default:
			yyprintf("Unknown direction for IP list");
	}

	return ret;
} // AddIPlist

static struct IPListNode *mkNode(ipStack_t ipStack, int64_t prefix) {

	struct IPListNode *node = malloc(sizeof(struct IPListNode));
	if (node == NULL) {
		yyprintf("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
		return NULL;
	}

	node->ip[0] = ipStack.ipaddr[0];
	node->ip[1] = ipStack.ipaddr[1];
	node->mask[0] = 0xffffffffffffffffLL;
	node->mask[1] = 0xffffffffffffffffLL;

	if ( prefix > 0 ) {
		if (ipStack.af == PF_INET) {
		// IPv4 
			if (prefix >32 ) {
				yyprintf("Prefix %" PRIu64 " out of range for IPv4 address", prefix);
				return NULL;
			}
			node->mask[0] = 0;
			node->mask[1] = 0xffffffffffffffffLL << (32 - prefix);
		} else {
			// IPv6
			if (prefix >128 ) {
				yyprintf("Prefix %" PRIu64 " out of range for IPv6 address", prefix);
				return NULL;
			}
			if ( prefix > 64 ) {
				node->mask[0] = 0xffffffffffffffffLL;
				node->mask[1] = 0xffffffffffffffffLL << (128 - prefix);
			} else {
				node->mask[0] = 0xffffffffffffffffLL << (64 - prefix);
				node->mask[1] = 0;
			}
		}
	}
	return node;
}

static void *NewIplist(char *IPstr, int prefix) {
	IPlist_t *root = malloc(sizeof(IPlist_t));
	if (root == NULL) {
		yyprintf("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
		return NULL;
	}
	RB_INIT(root);

	int numIP = parseIP(IPstr, ipStack, ALLOW_LOOKUP);
	if ( numIP <= 0 ) {
		yyprintf("Can not parse/resolve %s to an IP address", IPstr);
		free(root);
		return NULL;
	}
		
	for (int i=0; i<numIP; i++ ) {
	  struct IPListNode *node = mkNode(ipStack[i], prefix);
		if ( node ) {
			RB_INSERT(IPtree, root, node);
		} else {
			free(root);
			return NULL;
		}
	}

	return root;
} // End of NewIPlist

static int InsertIPlist(void *IPlist, char *IPstr, int64_t prefix) {
	int numIP = parseIP(IPstr, ipStack, ALLOW_LOOKUP);
	if ( numIP <= 0 ) {
		// ret == - 2 means lookup failure
		yyprintf("Can not parse/resolve %s to an IP address", IPstr);
		return 0;
	}

	for (int i=0; i<numIP; i++ ) {
		struct IPListNode *node = mkNode(ipStack[i], prefix);
		if ( node ) {
			RB_INSERT(IPtree, (IPlist_t *)IPlist, node);
		} else {
			return 0;
		}
	}
	return 1;
} // End of InsertIPlist

static void *NewU64list(uint64_t num) {
	U64List_t *root = malloc(sizeof(U64List_t));
	if (root == NULL) {
		yyprintf("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
		return NULL;
	}
	RB_INIT(root);

  struct U64ListNode *node;
	if ((node = malloc(sizeof(struct U64ListNode))) == NULL) {
		yyprintf("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
		free(root);
		return NULL;
	}
	node->value = num;
	RB_INSERT(U64tree, root, node);

	return root;
} // End of NewU64list

static int InsertU64list(void *U64list, uint64_t num) {
	
	struct U64ListNode *node;
	if ((node = malloc(sizeof(struct U64ListNode))) == NULL) {
		yyprintf("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
		return 0;
	}
	node->value = num;
	RB_INSERT(U64tree, U64list, node);

	return 1;
} // End of InsertU64list

static int AddPortList(direction_t direction, void *U64List) {

	// check, that each element is a valid port number
	struct U64ListNode *node;
	RB_FOREACH(node, U64tree, (U64List_t *)U64List) {
		if ( node->value > 65535 ) {
			yyprintf("Port: %" PRIu64 " outside of range 0..65535", node->value);
			return -1;
		}
	}

	data_t U64ListPtr = {U64List};
	int ret = -1;
  switch ( direction ) {
	  case DIR_SRC:
		  ret = NewElement(EXgenericFlowID, OFFsrcPort, SIZEsrcPort, 0, CMP_U64LIST, FUNC_NONE, U64ListPtr);
		  break;
	  case DIR_DST:
		  ret = NewElement(EXgenericFlowID, OFFdstPort, SIZEdstPort, 0, CMP_U64LIST, FUNC_NONE, U64ListPtr);
		  break;
	  case DIR_UNSPEC:
		  ret = Connect_OR(
			  NewElement(EXgenericFlowID, OFFsrcPort, SIZEsrcPort, 0, CMP_U64LIST, FUNC_NONE, U64ListPtr),
				NewElement(EXgenericFlowID, OFFdstPort, SIZEdstPort, 0, CMP_U64LIST, FUNC_NONE, U64ListPtr)
		  );
		  break;
		case DIR_SRC_NAT:
		  ret = NewElement(EXnatXlatePortID, OFFxlateSrcPort, SIZExlateSrcPort, 0, CMP_U64LIST, FUNC_NONE, U64ListPtr);
		  break;
	  case DIR_DST_NAT:
		  ret = NewElement(EXnatXlatePortID, OFFxlateDstPort, SIZExlateDstPort, 0, CMP_U64LIST, FUNC_NONE, U64ListPtr);
		  break;
	  case DIR_UNSPEC_NAT:
		  ret = Connect_OR(
		  	NewElement(EXnatXlatePortID, OFFxlateSrcPort, SIZExlateSrcPort, 0, CMP_U64LIST, FUNC_NONE, U64ListPtr),
		  	NewElement(EXnatXlatePortID, OFFxlateDstPort, SIZExlateDstPort, 0, CMP_U64LIST, FUNC_NONE, U64ListPtr )
		  );
		  break;
	  default:
		  yyprintf("Unknown direction");
  } // End switch

	return ret;
} // AddPortList

static int AddASList(direction_t direction, void *U64List) {

	// check, that each element is a valid AS number
	struct U64ListNode *node;
	RB_FOREACH(node, U64tree, (U64List_t *)U64List) {
		if ( node->value > 0xFFFFFFFFLL ) {
			yyprintf("AS: %" PRIu64 " outside of range 32bit", node->value);
			return -1;
		}
	}

	data_t U64ListPtr = {U64List};
	int ret = -1;
  switch ( direction ) {
	  case DIR_SRC:
		  ret = NewElement(EXasRoutingID, OFFsrcAS, SIZEsrcAS, 0, CMP_U64LIST, FUNC_NONE, U64ListPtr);
		  break;
	  case DIR_DST:
		  ret = NewElement(EXasRoutingID, OFFdstAS, SIZEdstAS, 0, CMP_U64LIST, FUNC_NONE, U64ListPtr);
		  break;
	  case DIR_UNSPEC:
		  ret = Connect_OR(
			  NewElement(EXasRoutingID, OFFsrcAS, SIZEsrcAS, 0, CMP_U64LIST, FUNC_NONE, U64ListPtr),
			  NewElement(EXasRoutingID, OFFdstAS, SIZEdstAS, 0, CMP_U64LIST, FUNC_NONE, U64ListPtr)
		  );
		  break;
		case DIR_NEXT:
		  ret = NewElement(EXasAdjacentID, OFFnextAdjacentAS, SIZEnextAdjacentAS, 0, CMP_U64LIST, FUNC_NONE, U64ListPtr);
			break;
		case DIR_PREV:
		  ret = NewElement(EXasAdjacentID, OFFprevAdjacentAS, SIZEprevAdjacentAS, 0, CMP_U64LIST, FUNC_NONE, U64ListPtr);
		  break;
	  default:
			yyprintf("Unknown direction");
  } // End of switch

	return ret;
} // AddASList

static int AddInterfaceNumber(direction_t direction, uint64_t num) {
	if ( num > 0xffffffffLL ) {
		yyprintf("Interface number out of range 0..2^32");
		return -1;
	}

	int ret = -1;
	switch ( direction ) {
		case DIR_UNSPEC:
			ret = Connect_OR(
				NewElement(EXflowMiscID, OFFinput, SIZEinput, num, CMP_EQ, FUNC_NONE, NULLPtr),
				NewElement(EXflowMiscID, OFFoutput, SIZEoutput, num, CMP_EQ, FUNC_NONE, NULLPtr)
			);
			break;
		case DIR_IN: 
			ret = NewElement(EXflowMiscID, OFFinput, SIZEinput, num, CMP_EQ, FUNC_NONE, NULLPtr);
			break;
		case DIR_OUT: 
			ret = NewElement(EXflowMiscID, OFFoutput, SIZEoutput, num, CMP_EQ, FUNC_NONE, NULLPtr);
			break;
		default:
			yyprintf("Unknown interface direction");
	} // End of switch

	return ret;
} // End of AddInterfaceNumber

static int AddVlanNumber(direction_t direction, uint64_t num) {
	if ( num > 0xffffffffLL ) {
		yyprintf("Vlan number out of range 32bit");
		return -1;
	}

	int ret = -1;
	switch ( direction ) {
		case DIR_UNSPEC: {
			int src = Connect_OR(
			  NewElement(EXvLanID, OFFsrcVlan, SIZEsrcVlan, num, CMP_EQ, FUNC_NONE, NULLPtr),
			  NewElement(EXlayer2ID, OFFvlanID, SIZEvlanID, num, CMP_EQ, FUNC_NONE, NULLPtr)
			);
			int dst = Connect_OR(
			  NewElement(EXvLanID, OFFdstVlan, SIZEdstVlan, num, CMP_EQ, FUNC_NONE, NULLPtr),
			  NewElement(EXlayer2ID, OFFpostVlanID, SIZEpostVlanID, num, CMP_EQ, FUNC_NONE, NULLPtr)
			);
			ret = Connect_OR(src,dst);
			} break;
		case DIR_SRC: 
			ret = Connect_OR(
			  NewElement(EXvLanID, OFFsrcVlan, SIZEsrcVlan, num, CMP_EQ, FUNC_NONE, NULLPtr),
			  NewElement(EXlayer2ID, OFFvlanID, SIZEvlanID, num, CMP_EQ, FUNC_NONE, NULLPtr)
			);
			break;
		case DIR_DST: 
			ret = Connect_OR(
			  NewElement(EXvLanID, OFFdstVlan, SIZEdstVlan, num, CMP_EQ, FUNC_NONE, NULLPtr),
			  NewElement(EXlayer2ID, OFFpostVlanID, SIZEpostVlanID, num, CMP_EQ, FUNC_NONE, NULLPtr)
			);
			break;
		default:
			yyprintf("Unknown vlan direction");
	} // End of switch

	return ret;
} // End of AddVlanNumber

static int AddAsNumber(direction_t direction, uint16_t comp, uint64_t as) {
	if (as > UINT32_MAX ) {
		yyprintf("AS number of range");
		return -1;
  }

	int ret = -1;
  switch ( direction ) {
	  case DIR_SRC:
		  ret = NewElement(EXasRoutingID, OFFsrcAS, SIZEsrcAS, as, comp, FUNC_MMAS_LOOKUP, (data_t){.dataVal = OFFsrcAS});
		  break;
	  case DIR_DST:
		  ret = NewElement(EXasRoutingID, OFFdstAS, SIZEdstAS, as, comp, FUNC_MMAS_LOOKUP , (data_t){.dataVal = OFFdstAS});
		  break;
	  case DIR_UNSPEC:
		  ret = Connect_OR(
			  NewElement(EXasRoutingID, OFFsrcAS, SIZEsrcAS, as, comp, FUNC_MMAS_LOOKUP, (data_t){.dataVal = OFFsrcAS}),
			  NewElement(EXasRoutingID, OFFdstAS, SIZEdstAS, as, comp, FUNC_MMAS_LOOKUP ,(data_t){.dataVal = OFFdstAS} )
		  );
			break;
		case DIR_NEXT:
		  ret = NewElement(EXasAdjacentID, OFFnextAdjacentAS, SIZEnextAdjacentAS, as, comp, FUNC_MMAS_LOOKUP, NULLPtr);
			break;
		case DIR_PREV:
		  ret = NewElement(EXasAdjacentID, OFFprevAdjacentAS, SIZEprevAdjacentAS, as, comp, FUNC_MMAS_LOOKUP, NULLPtr);
		  break;
	  default:
			yyprintf("Unknown direction");
  } // End of switch

	return ret;
} // End of AddAsNumber

static int AddMaskNumber(direction_t direction, uint64_t num) {
	if ( num > 255 ) {
		yyprintf("Mask %" PRIu64 " out of range 0..255", num);
		return -1;
	}

	int ret = -1;
	switch ( direction ) {
		case DIR_UNSPEC:
			ret = Connect_OR(
				NewElement(EXflowMiscID, OFFsrcMask, SIZEsrcMask, num, CMP_EQ, FUNC_NONE, NULLPtr),
				NewElement(EXflowMiscID, OFFdstMask, SIZEdstMask, num, CMP_EQ, FUNC_NONE, NULLPtr)
			);
			break;
		case DIR_SRC: 
			ret = NewElement(EXflowMiscID, OFFsrcMask, SIZEsrcMask, num, CMP_EQ, FUNC_NONE, NULLPtr);
			break;
		case DIR_DST: 
			ret = NewElement(EXflowMiscID, OFFdstMask, SIZEdstMask, num, CMP_EQ, FUNC_NONE, NULLPtr);
			break;
		default:
			yyprintf("Invalid direction for mask");
	} // End of switch

	return ret;
} // End of AddMaskNumber

static int AddFlowDir(direction_t direction, int64_t dirNum) {

	int ret = -1;
	switch (direction) {
		case DIR_INGRESS:
	  	ret = NewElement(EXflowMiscID, OFFdir, SIZEdir, 0, CMP_EQ, FUNC_NONE, NULLPtr);
			break;
		case DIR_EGRESS:
	  	ret = NewElement(EXflowMiscID, OFFdir, SIZEdir, 1, CMP_EQ, FUNC_NONE, NULLPtr);
			break;
		case DIR_UNSPEC:
			if (dirNum != 0 && dirNum != 1) {
	 			yyprintf("Unknown flowdir: %" PRIi64, dirNum);
			} else {
	  		ret = NewElement(EXflowMiscID, OFFdir, SIZEdir, dirNum, CMP_EQ, FUNC_NONE, NULLPtr);
			}
			break;
		default:
	 			yyprintf("Unknown flowdir");
	}

	return ret;
} // End of AddFlowDirString
