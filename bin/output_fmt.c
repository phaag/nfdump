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

#include "config.h"

#include <stdio.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "util.h"
#include "nffile.h"
#include "output_util.h"
#include "output_fmt.h"

typedef void (*string_function_t)(master_record_t *, char *);

static struct token_list_s {
	string_function_t	string_function;	// function generation output string
	char				*string_buffer;		// buffer for output string
} *token_list;

static int	max_token_index	= 0;
static int	token_index		= 0;

#define BLOCK_SIZE	32

static char **format_list;		// ordered list of all individual strings formating the output line
static int	max_format_index	= 0;
static int	format_index		= 0;

static int		do_tag 		 = 0;
static int 		long_v6 	 = 0;
static int		scale	 	 = 1;
static double	duration;

#define STRINGSIZE 10240
#define IP_STRING_LEN (INET6_ADDRSTRLEN)

static char header_string[STRINGSIZE];
static char data_string[STRINGSIZE];

// tag 
static char tag_string[2];

/* prototypes */
static inline void ICMP_Port_decode(master_record_t *r, char *string);

static void InitFormatParser(void);

static void AddToken(int index);

static void AddString(char *string);

static void String_FlowFlags(master_record_t *r, char *string);

static void String_FirstSeen(master_record_t *r, char *string);

static void String_LastSeen(master_record_t *r, char *string);

static void String_Received(master_record_t *r, char *string);

static void String_FirstSeenRaw(master_record_t *r, char *string);

static void String_LastSeenRaw(master_record_t *r, char *string);

static void String_ReceivedRaw(master_record_t *r, char *string);

static void String_Duration(master_record_t *r, char *string);

static void String_Protocol(master_record_t *r, char *string);

static void String_SrcAddr(master_record_t *r, char *string);

static void String_DstAddr(master_record_t *r, char *string);

static void String_SrcAddrPort(master_record_t *r, char *string);

static void String_DstAddrPort(master_record_t *r, char *string);

static void String_SrcNet(master_record_t *r, char *string);

static void String_DstNet(master_record_t *r, char *string);

static void String_NextHop(master_record_t *r, char *string);

static void String_BGPNextHop(master_record_t *r, char *string);

static void String_RouterIP(master_record_t *r, char *string);

static void String_SrcPort(master_record_t *r, char *string);

static void String_DstPort(master_record_t *r, char *string);

static void String_ICMP_code(master_record_t *r, char *string);

static void String_ICMP_type(master_record_t *r, char *string);
 
static void String_SrcAS(master_record_t *r, char *string);

static void String_DstAS(master_record_t *r, char *string);

static void String_NextAS(master_record_t *r, char *string);

static void String_PrevAS(master_record_t *r, char *string);

static void String_Input(master_record_t *r, char *string);

static void String_Output(master_record_t *r, char *string);

static void String_InPackets(master_record_t *r, char *string);

static void String_OutPackets(master_record_t *r, char *string);

static void String_InBytes(master_record_t *r, char *string);

static void String_OutBytes(master_record_t *r, char *string);

static void String_Flows(master_record_t *r, char *string);

static void String_Tos(master_record_t *r, char *string);

static void String_Dir(master_record_t *r, char *string);

static void String_SrcTos(master_record_t *r, char *string);

static void String_DstTos(master_record_t *r, char *string);

static void String_SrcMask(master_record_t *r, char *string);

static void String_DstMask(master_record_t *r, char *string);

static void String_SrcVlan(master_record_t *r, char *string);

static void String_DstVlan(master_record_t *r, char *string);

static void String_FwdStatus(master_record_t *r, char *string);

static void String_Flags(master_record_t *r, char *string);

static void String_InSrcMac(master_record_t *r, char *string);

static void String_OutDstMac(master_record_t *r, char *string);

static void String_InDstMac(master_record_t *r, char *string);

static void String_OutSrcMac(master_record_t *r, char *string);

static void String_MPLS_1(master_record_t *r, char *string);

static void String_MPLS_2(master_record_t *r, char *string);

static void String_MPLS_3(master_record_t *r, char *string);

static void String_MPLS_4(master_record_t *r, char *string);

static void String_MPLS_5(master_record_t *r, char *string);

static void String_MPLS_6(master_record_t *r, char *string);

static void String_MPLS_7(master_record_t *r, char *string);

static void String_MPLS_8(master_record_t *r, char *string);

static void String_MPLS_9(master_record_t *r, char *string);

static void String_MPLS_10(master_record_t *r, char *string);

static void String_MPLSs(master_record_t *r, char *string);

static void String_Engine(master_record_t *r, char *string);

static void String_Label(master_record_t *r, char *string);

static void String_ClientLatency(master_record_t *r, char *string);

static void String_ServerLatency(master_record_t *r, char *string);

static void String_AppLatency(master_record_t *r, char *string);

static void String_bps(master_record_t *r, char *string);

static void String_pps(master_record_t *r, char *string);

static void String_bpp(master_record_t *r, char *string);

static void String_ExpSysID(master_record_t *r, char *string);

#ifdef NSEL
static void String_EventTime(master_record_t *r, char *string);

static void String_nfc(master_record_t *r, char *string);

static void String_evt(master_record_t *r, char *string);

static void String_xevt(master_record_t *r, char *string);

static void String_msec(master_record_t *r, char *string);

static void String_iacl(master_record_t *r, char *string);

static void String_eacl(master_record_t *r, char *string);

static void String_xlateSrcAddr(master_record_t *r, char *string);

static void String_xlateDstAddr(master_record_t *r, char *string);

static void String_xlateSrcPort(master_record_t *r, char *string);

static void String_xlateDstPort(master_record_t *r, char *string);

static void String_xlateSrcAddrPort(master_record_t *r, char *string);

static void String_xlateDstAddrPort(master_record_t *r, char *string);

static void String_userName(master_record_t *r, char *string);

static void String_ivrf(master_record_t *r, char *string);

static void String_evrf(master_record_t *r, char *string);

static void String_PortBlockStart(master_record_t *r, char *string);

static void String_PortBlockEnd(master_record_t *r, char *string);

static void String_PortBlockStep(master_record_t *r, char *string);

static void String_PortBlockSize(master_record_t *r, char *string);

#endif

static struct format_token_list_s {
	char				*token;				// token
	int					is_address;			// is an IP address
	char				*header;			// header line description
	string_function_t	string_function;	// function generation output string
} format_token_list[] = {
	{ "%ff", 0, "Flow Flags", 				String_FlowFlags }, 	// flow flags in hex
	{ "%tfs", 0, "Date first seen        ", String_FirstSeen },		// Start Time - first seen
	{ "%ts",  0, "Date first seen        ", String_FirstSeen },		// Start Time - first seen
	{ "%tsr",  0, "Date first seen (raw)    ", String_FirstSeenRaw },		// Start Time - first seen, seconds
	{ "%te",  0, "Date last seen         ", String_LastSeen },		// End Time	- last seen
	{ "%ter",  0, "Date last seen (raw)     ", String_LastSeenRaw },		// End Time - first seen, seconds
	{ "%tr",  0, "Date flow received     ", String_Received },		// Received Time
	{ "%trr",  0, "Date flow received (raw)  ", String_ReceivedRaw },		// Received Time, seconds
	{ "%td",  0, " Duration", 				String_Duration },		// Duration
	{ "%exp", 0, "Exp ID", 				 	String_ExpSysID },		// Exporter SysID
	{ "%pr",  0, "Proto", 					String_Protocol },		// Protocol
	{ "%sa",  1, "     Src IP Addr", 		String_SrcAddr },		// Source Address
	{ "%da",  1, "     Dst IP Addr", 		String_DstAddr },		// Destination Address
	{ "%sn",  1, "        Src Network",		String_SrcNet },		// Source Address applied source netmask
	{ "%dn",  1, "        Dst Network",		String_DstNet },		// Destination Address applied source netmask
	{ "%nh",  1, "     Next-hop IP", 		String_NextHop },		// Next-hop IP Address
	{ "%nhb", 1, " BGP next-hop IP", 		String_BGPNextHop },	// BGP Next-hop IP Address
	{ "%ra",  1, "       Router IP", 		String_RouterIP },		// Router IP Address
	{ "%sap", 1, "     Src IP Addr:Port ",	String_SrcAddrPort },	// Source Address:Port
	{ "%dap", 1, "     Dst IP Addr:Port ",  String_DstAddrPort },	// Destination Address:Port
	{ "%sp",  0, "Src Pt", 				 	String_SrcPort },		// Source Port
	{ "%dp",  0, "Dst Pt", 				 	String_DstPort },		// Destination Port
	{ "%it",  0, "ICMP-T", 					String_ICMP_type },		// ICMP type
	{ "%ic",  0, "ICMP-C", 					String_ICMP_code },		// ICMP code
	{ "%sas", 0, "Src AS",				 	String_SrcAS },			// Source AS
	{ "%das", 0, "Dst AS",				 	String_DstAS },			// Destination AS
	{ "%nas", 0, "Next AS",				 	String_NextAS },		// Next AS
	{ "%pas", 0, "Prev AS",				 	String_PrevAS },		// Previous AS
	{ "%in",  0, " Input", 				 	String_Input },			// Input Interface num
	{ "%out", 0, "Output", 				 	String_Output },		// Output Interface num
	{ "%pkt", 0, " Packets", 			 	String_InPackets },		// Packets - default input - compat
	{ "%ipkt", 0, "  In Pkt", 			 	String_InPackets },		// In Packets
	{ "%opkt", 0, " Out Pkt", 			 	String_OutPackets },	// Out Packets
	{ "%byt", 0, "   Bytes", 			 	String_InBytes },		// Bytes - default input - compat
	{ "%ibyt", 0, " In Byte", 			 	String_InBytes },		// In Bytes
	{ "%obyt", 0, "Out Byte", 			 	String_OutBytes },		// In Bytes
	{ "%fl",  0, "Flows", 				 	String_Flows },			// Flows
	{ "%flg", 0,  "   Flags", 			 	String_Flags },			// TCP Flags
	{ "%tos", 0, "Tos", 				 	String_Tos },			// Tos - compat
	{ "%stos", 0, "STos", 				 	String_SrcTos },		// Tos - Src tos
	{ "%dtos", 0, "DTos", 				 	String_DstTos },		// Tos - Dst tos
	{ "%dir", 0, "Dir", 				 	String_Dir },			// Direction: ingress, egress
	{ "%smk", 0, "SMask", 				 	String_SrcMask },		// Src mask
	{ "%dmk", 0, "DMask", 				 	String_DstMask },		// Dst mask
	{ "%fwd", 0, "Fwd", 				 	String_FwdStatus },		// Forwarding Status
	{ "%svln", 0, "SVlan", 				 	String_SrcVlan },		// Src Vlan
	{ "%dvln", 0, "DVlan", 				 	String_DstVlan },		// Dst Vlan
	{ "%ismc", 0, "  In src MAC Addr", 	 	String_InSrcMac },		// Input Src Mac Addr
	{ "%odmc", 0, " Out dst MAC Addr", 	 	String_OutDstMac },		// Output Dst Mac Addr
	{ "%idmc", 0, "  In dst MAC Addr", 	 	String_InDstMac },		// Input Dst Mac Addr
	{ "%osmc", 0, " Out src MAC Addr", 	 	String_OutSrcMac },		// Output Src Mac Addr
	{ "%mpls1", 0, " MPLS lbl 1 ", 			String_MPLS_1 },		// MPLS Label 1
	{ "%mpls2", 0, " MPLS lbl 2 ", 			String_MPLS_2 },		// MPLS Label 2
	{ "%mpls3", 0, " MPLS lbl 3 ", 			String_MPLS_3 },		// MPLS Label 3
	{ "%mpls4", 0, " MPLS lbl 4 ", 			String_MPLS_4 },		// MPLS Label 4
	{ "%mpls5", 0, " MPLS lbl 5 ", 			String_MPLS_5 },		// MPLS Label 5
	{ "%mpls6", 0, " MPLS lbl 6 ", 			String_MPLS_6 },		// MPLS Label 6
	{ "%mpls7", 0, " MPLS lbl 7 ", 			String_MPLS_7 },		// MPLS Label 7
	{ "%mpls8", 0, " MPLS lbl 8 ", 			String_MPLS_8 },		// MPLS Label 8
	{ "%mpls9", 0, " MPLS lbl 9 ", 			String_MPLS_9 },		// MPLS Label 9
	{ "%mpls10", 0, " MPLS lbl 10",			String_MPLS_10 },		// MPLS Label 10
	{ "%mpls", 0, "                                               MPLS labels 1-10                                                                   ", 			String_MPLSs },			// All MPLS labels
	//
	{ "%bps", 0, "     bps", 	 		 	String_bps },			// bps - bits per second
	{ "%pps", 0, "     pps", 			 	String_pps },			// pps - packets per second
	{ "%bpp", 0, "   Bpp", 				 	String_bpp },			// bpp - Bytes per package
	{ "%eng", 0, " engine", 			 	String_Engine },		// Engine Type/ID
	{ "%lbl", 0, "           label", 		String_Label },			// Flow Label

#ifdef NSEL
// NSEL specifics
	{ "%nfc",   0, "   Conn-ID", 			String_nfc },				// NSEL connection ID
	{ "%tevt", 	0, "Event time             ",String_EventTime },		// NSEL Flow start time
	{ "%evt",   0, " Event", 				String_evt },				// NSEL event
	{ "%xevt",  0, " XEvent", 				String_xevt },				// NSEL xevent
	{ "%msec",  0, "   Event Time", 		String_msec},				// NSEL event time in msec
	{ "%iacl",  0, "Ingress ACL                     ", String_iacl}, 	// NSEL ingress ACL
	{ "%eacl",  0, "Egress ACL                      ", String_eacl}, 	// NSEL egress ACL
	{ "%xsa",   0, "   X-late Src IP", 		String_xlateSrcAddr},		// NSEL XLATE src IP
	{ "%xda",   0, "   X-late Dst IP", 		String_xlateDstAddr},		// NSEL XLATE dst IP
	{ "%xsp",   0, "XsPort", 				String_xlateSrcPort},		// NSEL XLATE src port
	{ "%xdp",   0, "XdPort", 				String_xlateDstPort},		// NSEL SLATE dst port
	{ "%xsap", 1, "   X-Src IP Addr:Port ",	String_xlateSrcAddrPort },	// Xlate Source Address:Port
	{ "%xdap", 1, "   X-Dst IP Addr:Port ", String_xlateDstAddrPort },	// Xlate Destination Address:Port
	{ "%uname", 0, "UserName", 				String_userName},			// NSEL user name

// NEL
// for v.1.6.10 compatibility, keep NEL specific addr/port format tokens 
	{ "%nevt",   0, " Event", 				  String_evt },				// NAT event
	{ "%vrf",    0, "  I-VRF-ID", 			  String_ivrf },			// NAT ivrf ID - compatible
	{ "%ivrf",   0, "  I-VRF-ID", 			  String_ivrf },			// NAT ivrf ID
	{ "%evrf",   0, "  E-VRF-ID", 			  String_evrf },			// NAT ivrf ID
	{ "%nsa",    0, "   X-late Src IP", 	  String_xlateSrcAddr},		// NAT XLATE src IP
	{ "%nda",    0, "   X-late Dst IP", 	  String_xlateDstAddr},		// NAT XLATE dst IP
	{ "%nsp",    0, "XsPort", 				  String_xlateSrcPort},		// NAT XLATE src port
	{ "%ndp",    0, "XdPort", 				  String_xlateDstPort},		// NAT SLATE dst port
	{ "%nsap",   1, "   X-Src IP Addr:Port ", String_xlateSrcAddrPort },// NAT Xlate Source Address:Port
	{ "%ndap",   1, "   X-Dst IP Addr:Port ", String_xlateDstAddrPort },// NAT Xlate Destination Address:Port

	// Port block allocation
	{ "%pbstart", 0, "Pb-Start", 			  String_PortBlockStart},	// Port block start
	{ "%pbend",   0, "Pb-End", 				  String_PortBlockEnd},		// Port block end
	{ "%pbstep",  0, "Pb-Step", 			  String_PortBlockStep},	// Port block step
	{ "%pbsize",  0, "Pb-Size", 			  String_PortBlockSize},	// Port block size
#endif

	// latency extension for nfpcapd and nprobe
	{ "%cl", 0, "C Latency", 	 		 	String_ClientLatency },	// client latency
	{ "%sl", 0, "S latency", 	 		 	String_ServerLatency },	// server latency
	{ "%al", 0, "A latency", 			 	String_AppLatency },	// app latency
	
	{ NULL, 0, NULL, NULL }
};

/* each of the tokens above must not generate output strings larger than this */
#define MAX_STRING_LENGTH	256


#include "applybits_inline.c"

/* functions */


void Setv6Mode(int mode) {
	long_v6 += mode;
} 

int Getv6Mode(void) {
	return long_v6;
} 

void format_special(void *record, char ** s, int tag) {
master_record_t *r 		  = (master_record_t *)record;
int	i, index;

	do_tag		  = tag;
	tag_string[0] = do_tag ? TAG_CHAR : '\0';
	tag_string[1] = '\0';

	duration = r->last - r->first;
	duration += ((double)r->msec_last - (double)r->msec_first) / 1000.0;
	for ( i=0; i<token_index; i++ ) {
		token_list[i].string_function(r, token_list[i].string_buffer);
	}

	// concat all strings together for the output line
	i = 0;
	for ( index=0; index<format_index; index++ ) {
		int j = 0;
		while ( format_list[index][j] && i < STRINGSIZE ) 
			data_string[i++] = format_list[index][j++];
	}
	if ( i < STRINGSIZE ) 
		data_string[i] = '\0';

	data_string[STRINGSIZE-1] = '\0';
	*s = data_string;

} // End of format_special 

void text_prolog(void) {
	printf("%s\n", header_string);
} // End of text_prolog

void text_epilog(void) {
	// empty
} // End of text_epilog

static void InitFormatParser(void) {

	max_format_index = max_token_index = BLOCK_SIZE;
	format_list = (char **)malloc(max_format_index * sizeof(char *));
	token_list  = (struct token_list_s *)malloc(max_token_index * sizeof(struct token_list_s));
	if ( !format_list || !token_list ) {
		fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(255);
	}

} // End of InitFormatParser

static void AddToken(int index) {

	if ( token_index >= max_token_index ) { // no slot available - expand table
		max_token_index += BLOCK_SIZE;
		token_list = (struct token_list_s *)realloc(token_list, max_token_index * sizeof(struct token_list_s));
		if ( !token_list ) {
			fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			exit(255);
		}
	}
	token_list[token_index].string_function	 = format_token_list[index].string_function;
	token_list[token_index].string_buffer = malloc(MAX_STRING_LENGTH);
	if ( !token_list[token_index].string_buffer ) {
		fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(255);
	}

	AddString(token_list[token_index].string_buffer);
	token_index++;

} // End of AddToken

/* Add either a static string or the memory for a variable string from a token to the list */
static void AddString(char *string) {

	if ( !string ) {
		fprintf(stderr, "Panic! NULL string in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(255);
	}

	if ( format_index >= max_format_index ) { // no slot available - expand table
		max_format_index += BLOCK_SIZE;
		format_list = (char **)realloc(format_list, max_format_index * sizeof(char *));
		if ( !format_list ) {
			fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			exit(255);
		}
	}
	format_list[format_index++] = string;

} // End of AddString

static char* RecursiveReplace(char *format, printmap_t *printmap) {
int i = 0;

	while ( printmap[i].printmode ) {
		char *s, *r;
		// check for printmode string
		s = strstr(format, printmap[i].printmode);
		if ( s && printmap[i].Format && s != format ) {
			int len = strlen(printmap[i].printmode);
			if ( !isalpha((int)s[len]) ) {
				s--;
				if ( s[0] == '%' ) {
					int newlen = strlen(format) + strlen(printmap[i].Format);
					r = malloc(newlen);
					if ( !r ) {
						LogError("malloc() allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
						exit(255);
					}
					s[0] = '\0';
					snprintf(r, newlen, "%s%s%s", format, printmap[i].Format, &(s[len+1]) );
					r[newlen-1] = '\0';
					free(format);
					format = r;
				}
			}
		}
		i++;
	}

	return format;

} // End of RecursiveReplace

int ParseOutputFormat(char *format, int plain_numbers, printmap_t *printmap) {
char *c, *s, *h;
int	i, remaining;

	scale = plain_numbers == 0;

	InitFormatParser();
	
	s = strdup(format);
	if ( !s ) {
		fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(255);
	}
	s = RecursiveReplace(s, printmap);
	c = s;

	h = header_string;
	*h = '\0';
	while ( *c ) {
		if ( *c == '%' ) {	// it's a token from format_token_list
			i = 0;
			remaining = strlen(c);
			while ( format_token_list[i].token ) {	// sweep through the list
				int len = strlen(format_token_list[i].token);

				// a token is separated by either a space, another token, or end of string
				if ( remaining >= len &&  !isalpha((int)c[len]) ) {
					// separator found a expected position
					char p = c[len]; 	// save separator;
					c[len] = '\0';
					if ( strncmp(format_token_list[i].token, c, len) == 0 ) {	// token found
						AddToken(i);
						if ( long_v6 && format_token_list[i].is_address )
							snprintf(h, STRINGSIZE-1-strlen(h), "%23s%s", "", format_token_list[i].header);
						else
							snprintf(h, STRINGSIZE-1-strlen(h), "%s", format_token_list[i].header);
						h += strlen(h);
						c[len] = p;
						c += len;
						break;
					} else {
						c[len] = p;
					}
				}
				i++;
			}
			if ( format_token_list[i].token == NULL ) {
				fprintf(stderr, "Output format parse error at: %s\n", c);
				free(s);
				return 0;
			}
		} else {			// it's a static string
			/* a static string goes up to next '%' or end of string */
			char *p = strchr(c, '%');
			char format[16];
			if ( p ) {
				// p points to next '%' token
				*p = '\0';
				AddString(strdup(c));
				snprintf(format, 15, "%%%zus", strlen(c));
				format[15] = '\0';
				snprintf(h, STRINGSIZE-1-strlen(h), format, "");
				h += strlen(h);
				*p = '%';
				c = p;
			} else {
				// static string up to end of format string
				AddString(strdup(c));
				snprintf(format, 15, "%%%zus", strlen(c));
				format[15] = '\0';
				snprintf(h, STRINGSIZE-1-strlen(h), format, "");
				h += strlen(h);
				*c = '\0';
			}
		}
	}

	free(s);
	return 1;

} // End of ParseOutputFormat

static inline void ICMP_Port_decode(master_record_t *r, char *string) {

	if ( r->prot == IPPROTO_ICMP || r->prot == IPPROTO_ICMPV6 ) { // ICMP
		snprintf(string, MAX_STRING_LENGTH-1, "%u.%u",  r->icmp_type, r->icmp_code);
	} else { 	// dst port
		snprintf(string, MAX_STRING_LENGTH-1, "%u",  r->dstport);
	}
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of ICMP_Port_decode

/* functions, which create the individual strings for the output line */
static void String_FlowFlags(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1, "0x%.2x", r->flags);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_FlowFlags
 
static void String_FirstSeen(master_record_t *r, char *string) {
time_t 	tt;
struct tm * ts;
char 	*s;

	tt = r->first;
	ts = localtime(&tt);
	strftime(string, MAX_STRING_LENGTH-1, "%Y-%m-%d %H:%M:%S", ts);
	s = string + strlen(string);
	snprintf(s, MAX_STRING_LENGTH-strlen(string)-1,".%03u", r->msec_first);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_FirstSeen

static void String_LastSeen(master_record_t *r, char *string) {
time_t 	tt;
struct tm * ts;
char 	*s;

	tt = r->last;
	ts = localtime(&tt);
	strftime(string, MAX_STRING_LENGTH-1, "%Y-%m-%d %H:%M:%S", ts);
	s = string + strlen(string);
	snprintf(s, MAX_STRING_LENGTH-strlen(string)-1,".%03u", r->msec_last);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_LastSeen

static void String_Received(master_record_t *r, char *string) {
time_t 	tt;
struct tm * ts;
char 	*s;

	tt = r->received / 1000LL;
	ts = localtime(&tt);
	strftime(string, MAX_STRING_LENGTH-1, "%Y-%m-%d %H:%M:%S", ts);
	s = string + strlen(string);
	snprintf(s, MAX_STRING_LENGTH-strlen(string)-1,".%03llu", r->received % 1000LL);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_Received

static void String_ReceivedRaw(master_record_t *r, char *string) {

	 /* snprintf does write \0, and the max is INCL the terminating \0 */
	 snprintf(string, MAX_STRING_LENGTH, "%.3f", r->received/1000.0);

} // End of String_ReceivedRaw

static void String_FirstSeenRaw(master_record_t *r, char *string) {

	 /* snprintf does write \0, and the max is INCL the terminating \0 */
	 snprintf(string, MAX_STRING_LENGTH, "%u.%03u", r->first, r->msec_first);

} // End of String_FirstSeenRaw

static void String_LastSeenRaw(master_record_t *r, char *string) {

	 /* snprintf does write \0, and the max is INCL the terminating \0 */
	 snprintf(string, MAX_STRING_LENGTH, "%u.%03u", r->last, r->msec_last);

} // End of String_LastSeenRaw


#ifdef NSEL
static void String_EventTime(master_record_t *r, char *string) {
time_t 	tt;
struct tm * ts;
char 	*s;

	tt = r->event_time / 1000LL;
	ts = localtime(&tt);
	strftime(string, MAX_STRING_LENGTH-1, "%Y-%m-%d %H:%M:%S", ts);
	s = string + strlen(string);
	snprintf(s, MAX_STRING_LENGTH-strlen(string)-1,".%03llu", r->event_time % 1000LL);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_EventTime
#endif

static void String_Duration(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%9.3f", duration);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_Duration

static void String_Protocol(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%-5s", ProtoString(r->prot));
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_Protocol

static void String_SrcAddr(master_record_t *r, char *string) {
char tmp_str[IP_STRING_LEN];

	tmp_str[0] = 0;
	if ( (r->flags & FLAG_IPV6_ADDR ) != 0 ) { // IPv6
		uint64_t	ip[2];

		ip[0] = htonll(r->V6.srcaddr[0]);
		ip[1] = htonll(r->V6.srcaddr[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			CondenseV6(tmp_str);
		}
	} else {	// IPv4
		uint32_t	ip;
		ip = htonl(r->V4.srcaddr);
		inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
	}
	tmp_str[IP_STRING_LEN-1] = 0;
	if ( long_v6 ) 
		snprintf(string, MAX_STRING_LENGTH-1, "%s%39s", tag_string, tmp_str);
	else
		snprintf(string, MAX_STRING_LENGTH-1, "%s%16s", tag_string, tmp_str);

	string[MAX_STRING_LENGTH-1] = 0;


} // End of String_SrcAddr

static void String_SrcAddrPort(master_record_t *r, char *string) {
char 	tmp_str[IP_STRING_LEN], portchar;

	tmp_str[0] = 0;
	if ( (r->flags & FLAG_IPV6_ADDR ) != 0 ) { // IPv6
		uint64_t	ip[2];

		ip[0] = htonll(r->V6.srcaddr[0]);
		ip[1] = htonll(r->V6.srcaddr[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			CondenseV6(tmp_str);
		}
		portchar = '.';
	} else {	// IPv4
		uint32_t	ip;
		ip = htonl(r->V4.srcaddr);
		inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
		portchar = ':';
	}
	tmp_str[IP_STRING_LEN-1] = 0;

	if ( long_v6 ) 
		snprintf(string, MAX_STRING_LENGTH-1, "%s%39s%c%-5i", tag_string, tmp_str, portchar, r->srcport);
	else
		snprintf(string, MAX_STRING_LENGTH-1, "%s%16s%c%-5i", tag_string, tmp_str, portchar, r->srcport);

	string[MAX_STRING_LENGTH-1] = 0;

} // End of String_SrcAddrPort

static void String_DstAddr(master_record_t *r, char *string) {
char tmp_str[IP_STRING_LEN];

	tmp_str[0] = 0;
	if ( (r->flags & FLAG_IPV6_ADDR ) != 0 ) { // IPv6
		uint64_t	ip[2];

		ip[0] = htonll(r->V6.dstaddr[0]);
		ip[1] = htonll(r->V6.dstaddr[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			CondenseV6(tmp_str);
		}
	} else {	// IPv4
		uint32_t	ip;
		ip = htonl(r->V4.dstaddr);
		inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
	}
	tmp_str[IP_STRING_LEN-1] = 0;
	if ( long_v6 ) 
		snprintf(string, MAX_STRING_LENGTH-1, "%s%39s", tag_string, tmp_str);
	else
		snprintf(string, MAX_STRING_LENGTH-1, "%s%16s", tag_string, tmp_str);

	string[MAX_STRING_LENGTH-1] = 0;


} // End of String_DstAddr


static void String_NextHop(master_record_t *r, char *string) {
char tmp_str[IP_STRING_LEN];

	tmp_str[0] = 0;
	if ( (r->flags & FLAG_IPV6_NH ) != 0 ) { // IPv6
		uint64_t	ip[2];

		ip[0] = htonll(r->ip_nexthop.V6[0]);
		ip[1] = htonll(r->ip_nexthop.V6[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			CondenseV6(tmp_str);
		}
	} else {	// IPv4
		uint32_t	ip;
		ip = htonl(r->ip_nexthop.V4);
		inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
	}
	tmp_str[IP_STRING_LEN-1] = 0;
	if ( long_v6 ) 
		snprintf(string, MAX_STRING_LENGTH-1, "%s%39s", tag_string, tmp_str);
	else
		snprintf(string, MAX_STRING_LENGTH-1, "%s%16s", tag_string, tmp_str);

	string[MAX_STRING_LENGTH-1] = 0;


} // End of String_NextHop

static void String_BGPNextHop(master_record_t *r, char *string) {
char tmp_str[IP_STRING_LEN];

	tmp_str[0] = 0;
	if ( (r->flags & FLAG_IPV6_NHB ) != 0 ) { // IPv6
		uint64_t	ip[2];

		ip[0] = htonll(r->bgp_nexthop.V6[0]);
		ip[1] = htonll(r->bgp_nexthop.V6[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			CondenseV6(tmp_str);
		}
	} else {	// IPv4
		uint32_t	ip;
		ip = htonl(r->bgp_nexthop.V4);
		inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
	}
	tmp_str[IP_STRING_LEN-1] = 0;
	if ( long_v6 ) 
		snprintf(string, MAX_STRING_LENGTH-1, "%s%39s", tag_string, tmp_str);
	else
		snprintf(string, MAX_STRING_LENGTH-1, "%s%16s", tag_string, tmp_str);

	string[MAX_STRING_LENGTH-1] = 0;


} // End of String_NextHop

static void String_RouterIP(master_record_t *r, char *string) {
char tmp_str[IP_STRING_LEN];

	tmp_str[0] = 0;
	if ( (r->flags & FLAG_IPV6_EXP ) != 0 ) { // IPv6
		uint64_t	ip[2];

		ip[0] = htonll(r->ip_router.V6[0]);
		ip[1] = htonll(r->ip_router.V6[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			CondenseV6(tmp_str);
		}
	} else {	// IPv4
		uint32_t	ip;
		ip = htonl(r->ip_router.V4);
		inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
	}
	tmp_str[IP_STRING_LEN-1] = 0;
	if ( long_v6 ) 
		snprintf(string, MAX_STRING_LENGTH-1, "%s%39s", tag_string, tmp_str);
	else
		snprintf(string, MAX_STRING_LENGTH-1, "%s%16s", tag_string, tmp_str);

	string[MAX_STRING_LENGTH-1] = 0;


} // End of String_RouterIP


static void String_DstAddrPort(master_record_t *r, char *string) {
char 	tmp_str[IP_STRING_LEN], portchar;
char 	icmp_port[MAX_STRING_LENGTH];

	tmp_str[0] = 0;
	if ( (r->flags & FLAG_IPV6_ADDR ) != 0 ) { // IPv6
		uint64_t	ip[2];

		ip[0] = htonll(r->V6.dstaddr[0]);
		ip[1] = htonll(r->V6.dstaddr[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			CondenseV6(tmp_str);
		}
		portchar = '.';
	} else {	// IPv4
		uint32_t	ip;
		ip = htonl(r->V4.dstaddr);
		inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
		portchar = ':';
	}
	tmp_str[IP_STRING_LEN-1] = 0;
	ICMP_Port_decode(r, icmp_port);

	if ( long_v6 ) 
		snprintf(string, MAX_STRING_LENGTH-1, "%s%39s%c%-5s", tag_string, tmp_str, portchar, icmp_port);
	else
		snprintf(string, MAX_STRING_LENGTH-1, "%s%16s%c%-5s", tag_string, tmp_str, portchar, icmp_port);

	string[MAX_STRING_LENGTH-1] = 0;

} // End of String_DstAddrPort

static void String_SrcNet(master_record_t *r, char *string) {
char tmp_str[IP_STRING_LEN];

	ApplyNetMaskBits(r, 1);

	tmp_str[0] = 0;
	if ( (r->flags & FLAG_IPV6_ADDR ) != 0 ) { // IPv6
		uint64_t	ip[2];

		ip[0] = htonll(r->V6.srcaddr[0]);
		ip[1] = htonll(r->V6.srcaddr[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			CondenseV6(tmp_str);
		}
	} else {	// IPv4
		uint32_t	ip;
		ip = htonl(r->V4.srcaddr);
		inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
	}
	tmp_str[IP_STRING_LEN-1] = 0;
	if ( long_v6 ) 
		snprintf(string, MAX_STRING_LENGTH-1, "%s%39s/%-2u", tag_string, tmp_str, r->src_mask );
	else
		snprintf(string, MAX_STRING_LENGTH-1, "%s%16s/%-2u", tag_string, tmp_str, r->src_mask );

	string[MAX_STRING_LENGTH-1] = 0;


} // End of String_SrcNet

static void String_DstNet(master_record_t *r, char *string) {
char tmp_str[IP_STRING_LEN];

	ApplyNetMaskBits(r, 2);

	tmp_str[0] = 0;
	if ( (r->flags & FLAG_IPV6_ADDR ) != 0 ) { // IPv6
		uint64_t	ip[2];

		ip[0] = htonll(r->V6.dstaddr[0]);
		ip[1] = htonll(r->V6.dstaddr[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			CondenseV6(tmp_str);
		}
	} else {	// IPv4
		uint32_t	ip;
		ip = htonl(r->V4.dstaddr);
		inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
	}
	tmp_str[IP_STRING_LEN-1] = 0;
	if ( long_v6 ) 
		snprintf(string, MAX_STRING_LENGTH-1, "%s%39s/%-2u", tag_string, tmp_str, r->dst_mask );
	else
		snprintf(string, MAX_STRING_LENGTH-1, "%s%16s/%-2u", tag_string, tmp_str, r->dst_mask );

	string[MAX_STRING_LENGTH-1] = 0;


} // End of String_DstNet

static void String_SrcPort(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%6u", r->srcport);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_SrcPort

static void String_DstPort(master_record_t *r, char *string) {
char tmp[MAX_STRING_LENGTH];

	ICMP_Port_decode(r, tmp);
	snprintf(string, MAX_STRING_LENGTH-1 ,"%6s", tmp);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_DstPort

static void String_ICMP_type(master_record_t *r, char *string) {
	uint8_t type;

	type =  ( r->prot == IPPROTO_ICMP || r->prot == IPPROTO_ICMPV6 ) ? r->icmp_type : 0;
	snprintf(string, MAX_STRING_LENGTH-1, "%6u", type);
	string[MAX_STRING_LENGTH-1] = 0;

} // End of String_ICMP_type

static void String_ICMP_code(master_record_t *r, char *string) {
	uint8_t code;

	code =  ( r->prot == IPPROTO_ICMP || r->prot == IPPROTO_ICMPV6 ) ? r->icmp_code : 0;
	snprintf(string, MAX_STRING_LENGTH-1, "%6u", code);
	string[MAX_STRING_LENGTH-1] = 0;

} // End of String_ICMP_code

static void String_SrcAS(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%6u", r->srcas);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_SrcAS

static void String_DstAS(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%6u", r->dstas);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_DstAS

static void String_NextAS(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ," %6u", r->bgpNextAdjacentAS);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_NextAS

static void String_PrevAS(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ," %6u", r->bgpPrevAdjacentAS);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_PrevAS

static void String_Input(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%6u", r->input);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_Input

static void String_Output(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%6u", r->output);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_Output

static void String_InPackets(master_record_t *r, char *string) {
char s[NUMBER_STRING_SIZE];

	format_number(r->dPkts, s, scale, FIXED_WIDTH);
	snprintf(string, MAX_STRING_LENGTH-1 ,"%8s", s);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_InPackets

static void String_OutPackets(master_record_t *r, char *string) {
char s[NUMBER_STRING_SIZE];

	format_number(r->out_pkts, s, scale, FIXED_WIDTH);
	snprintf(string, MAX_STRING_LENGTH-1 ,"%8s", s);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_OutPackets

static void String_InBytes(master_record_t *r, char *string) {
char s[NUMBER_STRING_SIZE];

	format_number(r->dOctets, s, scale, FIXED_WIDTH);
	snprintf(string, MAX_STRING_LENGTH-1 ,"%8s", s);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_InBytes

static void String_OutBytes(master_record_t *r, char *string) {
char s[NUMBER_STRING_SIZE];

	format_number(r->out_bytes, s, scale, FIXED_WIDTH);
	snprintf(string, MAX_STRING_LENGTH-1 ,"%8s", s);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_OutBytes

static void String_Flows(master_record_t *r, char *string) {

	// snprintf(string, MAX_STRING_LENGTH-1 ,"%5llu", r->aggr_flows ? (unsigned long long)r->aggr_flows : 1 );
	snprintf(string, MAX_STRING_LENGTH-1 ,"%5llu", (unsigned long long)r->aggr_flows );
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_Flows

static void String_Tos(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%3u", r->tos);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_Tos

static void String_SrcTos(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%4u", r->tos);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_SrcTos

static void String_DstTos(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%4u", r->dst_tos);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_DstTos

static void String_SrcMask(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%5u", r->src_mask);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_SrcMask

static void String_DstMask(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%5u", r->dst_mask);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_DstMask

static void String_SrcVlan(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%5u", r->src_vlan);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_SrcVlan

static void String_DstVlan(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%5u", r->dst_vlan);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_DstVlan

static void String_Dir(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%3c", r->dir ? 'E' : 'I' );
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_Dir

static void String_FwdStatus(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%3u", r->fwd_status);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_FwdStatus

static void String_Flags(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%8s", FlagsString(r->tcp_flags));
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_Flags

static void String_InSrcMac(master_record_t *r, char *string) {
int i;
uint8_t mac[6];

	for ( i=0; i<6; i++ ) {
		mac[i] = (r->in_src_mac >> ( i*8 )) & 0xFF;
	}
	snprintf(string, MAX_STRING_LENGTH-1 ,"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_InSrcMac

static void String_OutDstMac(master_record_t *r, char *string) {
int i;
uint8_t mac[6];

	for ( i=0; i<6; i++ ) {
		mac[i] = (r->out_dst_mac >> ( i*8 )) & 0xFF;
	}
	snprintf(string, MAX_STRING_LENGTH-1 ,"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_OutDstMac

static void String_InDstMac(master_record_t *r, char *string) {
int i;
uint8_t mac[6];

	for ( i=0; i<6; i++ ) {
		mac[i] = (r->in_dst_mac >> ( i*8 )) & 0xFF;
	}
	snprintf(string, MAX_STRING_LENGTH-1 ,"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_InDstMac

static void String_OutSrcMac(master_record_t *r, char *string) {
int i;
uint8_t mac[6];

	for ( i=0; i<6; i++ ) {
		mac[i] = (r->out_src_mac >> ( i*8 )) & 0xFF;
	}
	snprintf(string, MAX_STRING_LENGTH-1 ,"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_OutSrcMac

static void String_MPLS_1(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%8u-%1u-%1u", 
		r->mpls_label[0] >> 4 , (r->mpls_label[0] & 0xF ) >> 1, r->mpls_label[0] & 1);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_MPLS

static void String_MPLS_2(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%8u-%1u-%1u", 
		r->mpls_label[1] >> 4 , (r->mpls_label[1] & 0xF ) >> 1, r->mpls_label[1] & 1);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_MPLS

static void String_MPLS_3(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%8u-%1u-%1u", 
		r->mpls_label[2] >> 4 , (r->mpls_label[2] & 0xF ) >> 1, r->mpls_label[2] & 1);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_MPLS

static void String_MPLS_4(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%8u-%1u-%1u", 
		r->mpls_label[3] >> 4 , (r->mpls_label[3] & 0xF ) >> 1, r->mpls_label[3] & 1);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_MPLS

static void String_MPLS_5(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%8u-%1u-%1u", 
		r->mpls_label[4] >> 4 , (r->mpls_label[4] & 0xF ) >> 1, r->mpls_label[4] & 1);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_MPLS

static void String_MPLS_6(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%8u-%1u-%1u", 
		r->mpls_label[5] >> 4 , (r->mpls_label[5] & 0xF ) >> 1, r->mpls_label[5] & 1);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_MPLS

static void String_MPLS_7(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%8u-%1u-%1u", 
		r->mpls_label[6] >> 4 , (r->mpls_label[6] & 0xF ) >> 1, r->mpls_label[6] & 1);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_MPLS

static void String_MPLS_8(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%8u-%1u-%1u", 
		r->mpls_label[7] >> 4 , (r->mpls_label[7] & 0xF ) >> 1, r->mpls_label[7] & 1);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_MPLS

static void String_MPLS_9(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%8u-%1u-%1u", 
		r->mpls_label[8] >> 4 , (r->mpls_label[8] & 0xF ) >> 1, r->mpls_label[8] & 1);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_MPLS

static void String_MPLS_10(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%8u-%1u-%1u", 
		r->mpls_label[9] >> 4 , (r->mpls_label[9] & 0xF ) >> 1, r->mpls_label[9] & 1);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_MPLS

static void String_MPLSs(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%8u-%1u-%1u %8u-%1u-%1u %8u-%1u-%1u %8u-%1u-%1u %8u-%1u-%1u %8u-%1u-%1u %8u-%1u-%1u %8u-%1u-%1u %8u-%1u-%1u %8u-%1u-%1u ", 
		r->mpls_label[0] >> 4 , (r->mpls_label[0] & 0xF ) >> 1, r->mpls_label[0] & 1,
		r->mpls_label[1] >> 4 , (r->mpls_label[1] & 0xF ) >> 1, r->mpls_label[1] & 1,
		r->mpls_label[2] >> 4 , (r->mpls_label[2] & 0xF ) >> 1, r->mpls_label[2] & 1,
		r->mpls_label[3] >> 4 , (r->mpls_label[3] & 0xF ) >> 1, r->mpls_label[3] & 1,
		r->mpls_label[4] >> 4 , (r->mpls_label[4] & 0xF ) >> 1, r->mpls_label[4] & 1,
		r->mpls_label[5] >> 4 , (r->mpls_label[5] & 0xF ) >> 1, r->mpls_label[5] & 1,
		r->mpls_label[6] >> 4 , (r->mpls_label[6] & 0xF ) >> 1, r->mpls_label[6] & 1,
		r->mpls_label[7] >> 4 , (r->mpls_label[7] & 0xF ) >> 1, r->mpls_label[7] & 1,
		r->mpls_label[8] >> 4 , (r->mpls_label[8] & 0xF ) >> 1, r->mpls_label[8] & 1,
		r->mpls_label[9] >> 4 , (r->mpls_label[9] & 0xF ) >> 1, r->mpls_label[9] & 1
	);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_MPLSs

static void String_Engine(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%3u/%-3u", r->engine_type, r->engine_id);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_Engine

static void String_Label(master_record_t *r, char *string) {

	if ( r->label ) 
		snprintf(string, MAX_STRING_LENGTH-1 ,"%16s", r->label);
	else
		snprintf(string, MAX_STRING_LENGTH-1 ,"<none>");

	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_Label

static void String_ClientLatency(master_record_t *r, char *string) {
double latency;

	latency = (double)r->client_nw_delay_usec / 1000.0;
	snprintf(string, MAX_STRING_LENGTH-1 ,"%9.3f", latency);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_ClientLatency

static void String_ServerLatency(master_record_t *r, char *string) {
double latency;

	latency = (double)r->server_nw_delay_usec / 1000.0;
	snprintf(string, MAX_STRING_LENGTH-1 ,"%9.3f", latency);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_ServerLatency

static void String_AppLatency(master_record_t *r, char *string) {
double latency;

	latency = (double)r->appl_latency_usec / 1000.0;
	snprintf(string, MAX_STRING_LENGTH-1 ,"%9.3f", latency);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_AppLatency

static void String_bps(master_record_t *r, char *string) {
uint64_t	bps;
char s[NUMBER_STRING_SIZE];

	if ( duration ) {
		bps = (( r->dOctets << 3 ) / duration);	// bits per second. ( >> 3 ) -> * 8 to convert octets into bits
	} else {
		bps = 0;
	}
	format_number(bps, s, scale, FIXED_WIDTH);
	snprintf(string, MAX_STRING_LENGTH-1 ,"%8s", s);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_bps

static void String_pps(master_record_t *r, char *string) {
uint64_t	pps;
char s[NUMBER_STRING_SIZE];

	if ( duration ) {
		pps = r->dPkts / duration;				// packets per second
	} else {
		pps = 0;
	}
	format_number(pps, s, scale, FIXED_WIDTH);
	snprintf(string, MAX_STRING_LENGTH-1 ,"%8s", s);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_Duration

static void String_bpp(master_record_t *r, char *string) {
uint32_t 	Bpp; 

	string[MAX_STRING_LENGTH-1] = '\0';

	if ( r->dPkts ) 
		Bpp = r->dOctets / r->dPkts;			// Bytes per Packet
	else 
		Bpp = 0;
	snprintf(string, MAX_STRING_LENGTH-1 ,"%6u", Bpp);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_bpp

static void String_ExpSysID(master_record_t *r, char *string) {

	string[MAX_STRING_LENGTH-1] = '\0';

	snprintf(string, MAX_STRING_LENGTH-1 ,"%6u", r->exporter_sysid);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_ExpSysID

#ifdef NSEL
static void String_nfc(master_record_t *r, char *string) {

 	snprintf(string, MAX_STRING_LENGTH-1, "%10u", r->conn_id);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_nfc

static void String_evt(master_record_t *r, char *string) {

	if (r->fw_xevent) {
		snprintf(string, MAX_STRING_LENGTH-1 ,"%7s", FwEventString(r->event));
	} else {
		snprintf(string, MAX_STRING_LENGTH-1 ,"%7s", EventString(r->event));
	}

} // End of String_evt


static void String_xevt(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%7s", EventXString(r->fw_xevent));

} // End of String_xevt

static void String_msec(master_record_t *r, char *string) {
	unsigned long long etime;

	etime = 1000LL * (unsigned long long)r->first + (unsigned long long)r->msec_first;
	snprintf(string, MAX_STRING_LENGTH-1,"%13llu",  etime);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_msec 

static void String_iacl(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1, "0x%-8x 0x%-8x 0x%-8x",
		r->ingress_acl_id[0], r->ingress_acl_id[1], r->ingress_acl_id[2]);
	string[MAX_STRING_LENGTH-1] = 0;

} // End of String_iacl

static void String_eacl(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1, "%10u %10u %10u",
		r->egress_acl_id[0], r->egress_acl_id[1], r->egress_acl_id[2]);

	string[MAX_STRING_LENGTH-1] = 0;

} // End of String_eacl

static void String_xlateSrcAddr(master_record_t *r, char *string) {
char tmp_str[IP_STRING_LEN];

	tmp_str[0] = 0;
	if ( (r->xlate_flags & 1 ) != 0 ) { // IPv6
		uint64_t	ip[2];

		ip[0] = htonll(r->xlate_src_ip.V6[0]);
		ip[1] = htonll(r->xlate_src_ip.V6[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			CondenseV6(tmp_str);
		}
	} else {	// IPv4
		uint32_t	ip;
		ip = htonl(r->xlate_src_ip.V4);
		inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
	}
	tmp_str[IP_STRING_LEN-1] = 0;
	if ( long_v6 ) 
		snprintf(string, MAX_STRING_LENGTH-1, "%s%39s", tag_string, tmp_str);
	else
		snprintf(string, MAX_STRING_LENGTH-1, "%s%16s", tag_string, tmp_str);

	string[MAX_STRING_LENGTH-1] = 0;

} // End of String_xlateSrcAddr

static void String_xlateDstAddr(master_record_t *r, char *string) {
char tmp_str[IP_STRING_LEN];

	tmp_str[0] = 0;
	if ( (r->xlate_flags & 1 ) != 0 ) { // IPv6
		uint64_t	ip[2];

		ip[0] = htonll(r->xlate_dst_ip.V6[0]);
		ip[1] = htonll(r->xlate_dst_ip.V6[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			CondenseV6(tmp_str);
		}
	} else {	// IPv4
		uint32_t	ip;
		ip = htonl(r->xlate_dst_ip.V4);
		inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
	}
	tmp_str[IP_STRING_LEN-1] = 0;
	if ( long_v6 ) 
		snprintf(string, MAX_STRING_LENGTH-1, "%s%39s", tag_string, tmp_str);
	else
		snprintf(string, MAX_STRING_LENGTH-1, "%s%16s", tag_string, tmp_str);

	string[MAX_STRING_LENGTH-1] = 0;

} // End of String_xlateDstAddr

static void String_xlateSrcPort(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%6u", r->xlate_src_port);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_xlateSrcPort

static void String_xlateDstPort(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%6u", r->xlate_dst_port);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_xlateDstPort

static void String_xlateSrcAddrPort(master_record_t *r, char *string) {
char 	tmp_str[IP_STRING_LEN], portchar;

	tmp_str[0] = 0;
	if ( (r->xlate_flags & 1 ) != 0 ) { // IPv6
		uint64_t	ip[2];

		ip[0] = htonll(r->xlate_src_ip.V6[0]);
		ip[1] = htonll(r->xlate_src_ip.V6[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			CondenseV6(tmp_str);
		}

		portchar = '.';
	} else {	// IPv4
		uint32_t	ip;
		ip = htonl(r->xlate_src_ip.V4);
		inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));

		portchar = ':';
	}
	tmp_str[IP_STRING_LEN-1] = 0;

	if ( long_v6 ) 
		snprintf(string, MAX_STRING_LENGTH-1, "%s%39s%c%-5i", tag_string, tmp_str, portchar, r->xlate_src_port);
	else
		snprintf(string, MAX_STRING_LENGTH-1, "%s%16s%c%-5i", tag_string, tmp_str, portchar, r->xlate_src_port);

	string[MAX_STRING_LENGTH-1] = 0;

} // End of String_xlateSrcAddrPort

static void String_xlateDstAddrPort(master_record_t *r, char *string) {
char 	tmp_str[IP_STRING_LEN], portchar;

	tmp_str[0] = 0;
	if ( (r->xlate_flags & 1 ) != 0 ) { // IPv6
		uint64_t	ip[2];

		ip[0] = htonll(r->xlate_dst_ip.V6[0]);
		ip[1] = htonll(r->xlate_dst_ip.V6[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			CondenseV6(tmp_str);
		}

		portchar = '.';
	} else {	// IPv4
		uint32_t	ip;
		ip = htonl(r->xlate_dst_ip.V4);
		inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));

		portchar = ':';
	}
	tmp_str[IP_STRING_LEN-1] = 0;

	if ( long_v6 ) 
		snprintf(string, MAX_STRING_LENGTH-1, "%s%39s%c%-5i", tag_string, tmp_str, portchar, r->xlate_dst_port);
	else
		snprintf(string, MAX_STRING_LENGTH-1, "%s%16s%c%-5i", tag_string, tmp_str, portchar, r->xlate_dst_port);

	string[MAX_STRING_LENGTH-1] = 0;


} // End of String_xlateDstAddrPort

static void String_userName(master_record_t *r, char *string) {

	if ( r->username[0] == '\0' ) 
		snprintf(string, MAX_STRING_LENGTH-1 ,"%s", "<empty>");
	else
		snprintf(string, MAX_STRING_LENGTH-1 ,"%s", r->username);

	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_userName

static void String_ivrf(master_record_t *r, char *string) {

 	snprintf(string, MAX_STRING_LENGTH-1, "%10u", r->ingress_vrfid);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_ivrf

static void String_evrf(master_record_t *r, char *string) {

 	snprintf(string, MAX_STRING_LENGTH-1, "%10u", r->egress_vrfid);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_evrf

static void String_PortBlockStart(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%7u", r->block_start);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_PortBlockStart

static void String_PortBlockEnd(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%7u", r->block_end);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_PortBlockEnd

static void String_PortBlockStep(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%7u", r->block_step);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_PortBlockStep

static void String_PortBlockSize(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%7u", r->block_size);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_PortBlockSize


#endif
