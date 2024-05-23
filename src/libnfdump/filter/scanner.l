/*
 *  Copyright (c) 2023, Peter Haag
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
 */

%x incl

%{

#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>

#include "filter.h"
#include "grammar.h"

int lineno = 1;


#ifdef FLEX_SCANNER
#define YY_NO_UNPUT
static YY_BUFFER_STATE in_buffer;
#else
static char *in_buffer;

#undef getc
#define getc(fp)  (*in_buffer == 0 ? EOF : *in_buffer++)
#endif

#define MAX_INCLUDE_DEPTH 10
YY_BUFFER_STATE include_stack[MAX_INCLUDE_DEPTH];

struct buffer_info {
	char *name;
	int	 lineno;
} include_stack_info[MAX_INCLUDE_DEPTH];

int include_stack_ptr = 0;

char	*FilterFilename = NULL;;

static char *stripQuotes(char *word);

static void __attribute__((noreturn)) yy_fatal_error (yyconst char msg[]);

// static void __attribute__((unused))yyunput (int c, char * yy_bp);

%}

N				[0-9]+
H				(0X|0x)[0-9A-Fa-f]+

%%
@include		 BEGIN(incl);

[0-9]+			{ 
					yylval.value = (uint64_t) strtoull(yytext,NULL,10);
					return NUMBER;
				}

(0X|0x)[0-9A-Fa-f]+ {
					yylval.value = (uint64_t) strtoull(yytext,NULL,16);
					return NUMBER;
				}

[0-9]+[kmgtKGMT]{0,1}	{ 
					size_t len = strlen(yytext);
					switch (yytext[len-1]) {
						case 'k':
						case 'K':
							yylval.value = 1000LL * (uint64_t) strtoull(yytext,NULL,10);
							break;
						case 'm':
						case 'M':
							yylval.value = 1000LL * 1000LL * (uint64_t) strtoull(yytext,NULL,10);
							break;
						case 'g':
						case 'G':
							yylval.value = 1000LL * 1000LL * 1000LL * (uint64_t) strtoull(yytext,NULL,10);
							break;
						case 't':
						case 'T':
							yylval.value = 1000LL * 1000LL * 1000LL * 1000LL * (uint64_t) strtoull(yytext,NULL,10);
							break;
						default:
							yylval.value = (uint64_t) strtoull(yytext,NULL,10);
					}
					return NUMBER;
				}

any				{ return ANY;  }
ipv4			{ return IPV4; }
ipv6			{ return IPV6; }
ident			{ return IDENT; }
count			{ return COUNT; }
cnt			  { return COUNT; }
ip|host		{ return IP;   }
net				{ return NET;  }

src				{ return SRC;    }
dst				{ return DST;    }
in				{ return IN;     }
out				{ return OUT;    }
next			{ return NEXT;   }
prev			{ return PREV;   }
bgp				{ return BGP;    }
bgpnext		{ return BGPNEXT; }
router		{ return ROUTER; }
nat		    { return NAT;    }
xlate		  { return NAT;    }
tun		    { return TUN;    }
ingress		{ return INGRESS;}
egress		{ return EGRESS; }

and       { return AND; }
or        { return OR;  }
not|"!"		{ return NOT; }
"="|"=="	{ return EQ;  }
">"			  { return GT;  }
"<"			  { return LT;  }
">="			{ return GE;  }
"<="			{ return LE;  }
"eq"			{ return EQ;  }
"gt"		  { return GT;  }
"lt"		  { return LT;  }
"ge"			{ return GE;  }
"le"			{ return LE;  }

"engine"      { return ENGINE;     }
"engine-type" { return ENGINETYPE; }
"engine-id"   { return ENGINEID;   }
"exporter"    { return EXPORTER;   }

"packets"  { return PACKETS;  }
"bytes"    { return BYTES;    }
"flows"    { return FLOWS;    }
"duration" { return DURATION; }
"pps"      { return PPS;      }
"bps"      { return BPS;      }
"bpp"      { return BPP;      } 

"proto"     { return PROTO;    }
"port"      { return PORT;     }
"as"        { return AS;       }
"vlan"      { return VLAN;     }
"mpls"      { return MPLS;     }
"etherType" { return ETHERTYPE;}
"mac"       { return MAC;      }
"flags"     { return FLAGS;    }
"icmp"      { return ICMP;     }
"icmp-type" { return ICMPTYPE; }
"icmp-code" { return ICMPCODE; }

"if"        { return IF;      }
"mask"      { return MASK;    }
"flowdir"   { return FLOWDIR; }
"latency"		{ return LATENCY; }
"asa"       { return ASA;     }
"acl"       { return ACL;     }
"payload"   { return PAYLOAD; }
"geo"       { return GEO;			}
"vrf"       { return VRF;			}
"pf" 				{ return PF;			}

"observation" { return OBSERVATION; }

"tos"     { return TOS;     }
"fwdstat" { return FWDSTAT; }

#.*				{ ; }
[ \t]			{ ; }

[a-zA-Z0-9_:\.\-=]+ {
                    yylval.s = stripQuotes(yytext);
                    return STRING;
                }
[']([ -~]{-}['])*['] {
                    yylval.s = stripQuotes(yytext);
                    return STRING;
                }
["]([ -~]{-}["])*["] {
                    yylval.s = stripQuotes(yytext);
                    return STRING;
                }

\n			{ lineno++; }
.				{ return yytext[0]; }
			
	 
 <incl>[ \t]*	  /* eat the whitespace */
 <incl>[^ \t\n]+ { /* got the include file name */
					if ( include_stack_ptr >= MAX_INCLUDE_DEPTH ) {
						fprintf( stderr, "Includes nested too deeply" );
					 	exit(255);
					}
	 
				 	include_stack[include_stack_ptr] = YY_CURRENT_BUFFER;
					include_stack_info[include_stack_ptr].name = FilterFilename;
					include_stack_info[include_stack_ptr].lineno = lineno;
					include_stack_ptr++;

					lineno = 1;
				 	yyin = fopen( yytext, "r" );
	 
				 	if ( ! yyin ) {
					 	fprintf(stderr, "Failed to open include file '%s': %s\n", yytext, strerror(errno));
						exit(255);
					}

	 				FilterFilename = strdup(yytext);
				 	yy_switch_to_buffer( yy_create_buffer( yyin, YY_BUF_SIZE ) );
	 
				 	BEGIN(INITIAL);
				}

<<EOF>>			{
					if ( include_stack_ptr == 0 ) {
						yyterminate();
					} else {
						if ( include_stack_info[include_stack_ptr].name ) 
							free(include_stack_info[include_stack_ptr].name);
						include_stack_ptr--;
						yy_delete_buffer( YY_CURRENT_BUFFER );
						yy_switch_to_buffer( include_stack[include_stack_ptr] );
						lineno = include_stack_info[include_stack_ptr].lineno;
						FilterFilename = include_stack_info[include_stack_ptr].name;
					}
				}

%%

void lex_init(char *buf) {
#ifdef FLEX_SCANNER
		in_buffer = yy_scan_string(buf);
#else
		in_buffer = buf;
#endif
		lineno = 1;
}

/*
 * Do any cleanup necessary after parsing.
 */
void lex_cleanup(void) {
#ifdef FLEX_SCANNER
		if (in_buffer != NULL)
				yy_delete_buffer(in_buffer);
		in_buffer = NULL;
#endif
}

int yywrap(void) {
	return 1;
}

static char *stripQuotes(char *string) {
    char *w = strdup(string);

    // strip ", ' and /' from begin/end of string
    if ( w[0] == 0x27 || w[0] == 0x22 || w[0] == 0x2f ) w++;
  size_t last = strlen(w) -1;

    if ( w[last] == 0x27 || w[last] == 0x22 || w[last] == 0x2f ) w[last] = '\0';

    return w;
} // End of stripQuotes