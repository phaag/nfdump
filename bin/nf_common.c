/*
 *  Copyright (c) 2014, Peter Haag
 *  Copyright (c) 2009, Peter Haag
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
 *  $Author: haag $
 *
 *  $Id: nf_common.c 69 2010-09-09 07:17:43Z haag $
 *
 *  $LastChangedRevision: 69 $
 *	
 */

#include "config.h"

#include <stdio.h>
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

#include "nffile.h"
#include "nf_common.h"
#include "util.h"

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

static void String_FirstSeen(master_record_t *r, char *string);

static void String_LastSeen(master_record_t *r, char *string);

static void String_Received(master_record_t *r, char *string);

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
	{ "%tfs", 0, "Date first seen        ", String_FirstSeen },		// Start Time - first seen
	{ "%ts",  0, "Date first seen        ", String_FirstSeen },		// Start Time - first seen
	{ "%te",  0, "Date last seen         ", String_LastSeen },		// End Time	- last seen
	{ "%tr",  0, "Date flow received     ", String_Received },		// Received Time
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
	{ "%flg", 0,  " Flags", 			 	String_Flags },			// TCP Flags
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

	// nprobe latency
	{ "%cl", 0, "C Latency", 	 		 	String_ClientLatency },	// client latency
	{ "%sl", 0, "S latency", 	 		 	String_ServerLatency },	// server latency
	{ "%al", 0, "A latency", 			 	String_AppLatency },	// app latency
	
	{ NULL, 0, NULL, NULL }
};

/* each of the tokens above must not generate output strings larger than this */
#define MAX_STRING_LENGTH	256

#define NumProtos	138
#define MAX_PROTO_STR 8
char protolist[NumProtos][MAX_PROTO_STR] = {
	"    0",	// 0   	masked out - no protocol info - set to '0'
	"ICMP ",	// 1   	Internet Control Message
	"IGMP ",	// 2	Internet Group Management
	"GGP  ",	// 3	Gateway-to-Gateway
	"IPIP ",	// 4	IP in IP (encapsulation)
	"ST   ",	// 5	Stream
	"TCP  ",	// 6	Transmission Control
	"CBT  ",	// 7	CBT
	"EGP  ",	// 8	Exterior Gateway Protocol
	"IGP  ",	// 9	any private interior gateway (used by Cisco for their IGRP)
	"BBN  ",	// 10	BBN RCC Monitoring
	"NVPII",	// 11	Network Voice Protocol
	"PUP  ",	// 12	PUP
	"ARGUS",	// 13	ARGUS
	"ENCOM",	// 14	EMCON
	"XNET ",	// 15	Cross Net Debugger
	"CHAOS",	// 16	Chaos
	"UDP  ",	// 17	User Datagram 
	"MUX  ",	// 18	Multiplexing
	"DCN  ",	// 19	DCN Measurement Subsystems
	"HMP  ",	// 20	Host Monitoring
	"PRM  ",	// 21	Packet Radio Measurement
	"XNS  ",	// 22	XEROX NS IDP 
	"Trnk1",	// 23	Trunk-1
	"Trnk2",	// 24	Trunk-2
	"Leaf1",	// 25	Leaf-1
	"Leaf2",	// 26	Leaf-2
	"RDP  ",	// 27	Reliable Data Protocol
	"IRTP ",	// 28	Internet Reliable Transaction
	"ISO-4",	// 29	ISO Transport Protocol Class 4
	"NETBK",	// 30	Bulk Data Transfer Protocol
	"MFESP",	// 31	MFE Network Services Protocol
	"MEINP",	// 32	MERIT Internodal Protocol
	"DCCP ",	// 33	Datagram Congestion Control Protocol
	"3PC  ",	// 34	Third Party Connect Protocol
	"IDPR ",	// 35	Inter-Domain Policy Routing Protocol 
	"XTP  ",	// 36	XTP
	"DDP  ",	// 37	Datagram Delivery Protocol
	"IDPR ",	// 38	IDPR Control Message Transport Proto
	"TP++ ",	// 39	TP++ Transport Protocol
	"IL   ",	// 40	IL Transport Protocol
	"IPv6 ",	// 41	IPv6
	"SDRP ",	// 42	Source Demand Routing Protocol
	"Rte6 ",	// 43	Routing Header for IPv6
	"Frag6",	// 44	Fragment Header for IPv6
	"IDRP ",	// 45	Inter-Domain Routing Protocol
	"RSVP ",	// 46	Reservation Protocol 
	"GRE  ",	// 47	General Routing Encapsulation
	"MHRP ",	// 48	Mobile Host Routing Protocol
	"BNA  ",	// 49	BNA
	"ESP  ",    // 50	Encap Security Payload 
	"AH   ",    // 51	Authentication Header
	"INLSP",    // 52	Integrated Net Layer Security  TUBA 
	"SWIPE",    // 53	IP with Encryption 
	"NARP ",    // 54	NBMA Address Resolution Protocol
	"MOBIL",    // 55	IP Mobility
	"TLSP ",    // 56	Transport Layer Security Protocol
	"SKIP ",    // 57	SKIP
	"ICMP6",	// 58	ICMP for IPv6
	"NOHE6",    // 59	No Next Header for IPv6
	"OPTS6",    // 60	Destination Options for IPv6
	"HOST ",    // 61	any host internal protocol
	"CFTP ",    // 62	CFTP
	"NET  ",    // 63	any local network
	"SATNT",    // 64	SATNET and Backroom EXPAK
	"KLAN ",    // 65	Kryptolan
	"RVD  ",    // 66	MIT Remote Virtual Disk Protocol
	"IPPC ",    // 67	Internet Pluribus Packet Core
	"FS   ",    // 68	any distributed file system
	"SATM ",    // 69	SATNET Monitoring 
	"VISA ",    // 70	VISA Protocol
	"IPCV ",    // 71	Internet Packet Core Utility
	"CPNX ",    // 72	Computer Protocol Network Executive
	"CPHB ",    // 73	Computer Protocol Heart Beat
	"WSN  ",    // 74	Wang Span Network
	"PVP  ",    // 75	Packet Video Protocol 
	"BSATM",    // 76	Backroom SATNET Monitoring
	"SUNND",    // 77	SUN ND PROTOCOL-Temporary
	"WBMON",    // 78	WIDEBAND Monitoring
	"WBEXP",    // 79	WIDEBAND EXPAK
	"ISOIP",    // 80	ISO Internet Protocol
	"VMTP ",    // 81	VMTP
	"SVMTP",    // 82	SECURE-VMTP
	"VINES",    // 83	VINES
	"TTP  ",    // 84	TTP
	"NSIGP",    // 85	NSFNET-IGP
	"DGP  ",    // 86	Dissimilar Gateway Protocol
	"TCP  ",    // 87	TCF
	"EIGRP",    // 88	EIGRP
	"OSPF ",    // 89	OSPFIGP
	"S-RPC",    // 90	Sprite RPC Protocol
	"LARP ",    // 91	Locus Address Resolution Protocol
	"MTP  ",    // 92	Multicast Transport Protocol
	"AX.25",    // 93	AX.25 Frames
	"IPIP ",	// 94	IP-within-IP Encapsulation Protocol
	"MICP ",    // 95	Mobile Internetworking Control Protocol
	"SCCSP",    // 96	Semaphore Communications Sec. Protocol
	"ETHIP",    // 97	Ethernet-within-IP Encapsulation
	"ENCAP",    // 98	Encapsulation Header
	"99   ",    // 99	any private encryption scheme
	"GMTP ",    // 100	GMTP
	"IFMP ",    // 101	Ipsilon Flow Management Protocol
	"PNNI ",    // 102	PNNI over IP 
	"PIM  ",	// 103	Protocol Independent Multicast
	"ARIS ",    // 104	ARIS
	"SCPS ",    // 105	SCPS
	"QNX  ",    // 106	QNX
	"A/N  ",    // 107	Active Networks
	"IPcmp",    // 108	IP Payload Compression Protocol
	"SNP  ",    // 109	Sitara Networks Protocol
	"CpqPP",    // 110	Compaq Peer Protocol
	"IPXIP",    // 111	IPX in IP
	"VRRP ",    // 112	Virtual Router Redundancy Protocol
	"PGM  ",    // 113	PGM Reliable Transport Protocol
	"0hop ",    // 114	any 0-hop protocol
	"L2TP ",    // 115	Layer Two Tunneling Protocol
	"DDX  ",    // 116	D-II Data Exchange (DDX)
	"IATP ",    // 117	Interactive Agent Transfer Protocol
	"STP  ",    // 118	Schedule Transfer Protocol
	"SRP  ",    // 119	SpectraLink Radio Protocol
	"UTI  ",    // 120	UTI
	"SMP  ",    // 121	Simple Message Protocol
	"SM   ",    // 122	SM
	"PTP  ",    // 123	Performance Transparency Protocol
	"ISIS4",    // 124	ISIS over IPv4
	"FIRE ",    // 125	FIRE
	"CRTP ",    // 126	Combat Radio Transport Protocol
	"CRUDP",    // 127	Combat Radio User Datagram
	"128  ",    // 128	SSCOPMCE
	"IPLT ",    // 129	IPLP
	"SPS  ",    // 130	Secure Packet Shield 
	"PIPE ",    // 131	Private IP Encapsulation within IP
	"SCTP ",    // 132	Stream Control Transmission Protocol
	"FC   ",    // 133	Fibre Channel
	"134  ",    // 134	RSVP-E2E-IGNORE
	"MHEAD",    // 135	Mobility Header
	"UDP-L",    // 136	UDPLite
	"MPLS "    // 137	MPLS-in-IP 
};

static struct fwd_status_def_s {
	uint32_t	id;
	char		*name;
} fwd_status_def_list[] = {
	{ 0,	"Ukwn"}, 	// Unknown
	{ 1,	"Forw"}, 	// Normal forwarding
	{ 2,	"Frag"}, 	// Fragmented
	{ 16,	"Drop"}, 	// Drop
	{ 17,	"DaclD"},	// Drop ACL deny
	{ 18,	"Daclp"},	// Drop ACL drop
	{ 19,	"Noroute"},	// Unroutable
	{ 20,	"Dadj"}, 	// Drop Adjacency
	{ 21,	"Dfrag"}, 	// Drop Fragmentation & DF set
	{ 22,	"Dbadh"}, 	// Drop Bad header checksum
	{ 23,	"Dbadtlen"}, // Drop Bad total Length
	{ 24,	"Dbadhlen"}, // Drop Bad Header Length
	{ 25,	"DbadTTL"}, // Drop bad TTL
	{ 26,	"Dpolicy"}, // Drop Policer
	{ 27,	"Dwred"}, 	// Drop WRED
	{ 28,	"Drpf"}, 	// Drop RPF
	{ 29,	"Dforus"}, 	// Drop For us
	{ 30,	"DbadOf"}, 	// Drop Bad output interface
	{ 31,	"Dhw"}, 	// Drop Hardware
	{ 128,	"Term"}, 	// Terminate
	{ 129,	"Tadj"}, 	// Terminate Punt Adjacency
	{ 130,	"TincAdj"}, // Terminate Incomplete Adjacency
	{ 131,	"Tforus"}, 	// Terminate For us
	{ 0,	NULL}		// Last entry
};

char *NSEL_event_string[6] = {
	"IGNORE", "CREATE", "DELETE", "DENIED", "ALERT", "UPDATE"
};

char *NEL_event_string[3] = {
	"INVALID", "ADD", "DELETE"
};

static char **fwd_status = NULL;

#include "applybits_inline.c"

/* functions */

int InitSymbols(void) {
int i;

	// already initialised?
	if ( fwd_status )
		return 1;

	// fill fwd status cache table
	fwd_status = ( char **)calloc(256, sizeof(char *));
	if ( !fwd_status ) {
		fprintf(stderr, "Process_v9: Panic! malloc(): %s line %d: %s", __FILE__, __LINE__, strerror (errno));
		return 0;
	}
	i=0;
	while ( fwd_status_def_list[i].name ) {
		uint32_t j = fwd_status_def_list[i].id;
		fwd_status[j] = fwd_status_def_list[i].name;
		i++;
	}
	return 1;

} // End of InitSymbols

void Setv6Mode(int mode) {
	long_v6 += mode;
} 

int Getv6Mode(void) {
	return long_v6;
} 

void Proto_string(uint8_t protonum, char *protostr) {

	if ( protonum >= NumProtos || !scale ) {
		snprintf(protostr,16,"%-5i", protonum );
	} else {
		strncpy(protostr, protolist[protonum], 16);
	}

} // End of Proto_string

int Proto_num(char *protostr) {
int i, len;

	if ( (len = strlen(protostr)) >= 6 )
		return -1;

	for ( i=0; i<NumProtos; i++ ) {
		if ( strncasecmp(protostr,protolist[i], len) == 0 && 
			( protolist[i][len] == 0 || protolist[i][len] == ' ') )
			return i;
	}

	return -1;

} // End of Proto_num

uint32_t Get_fwd_status_id(char *status) {
int i;

	i = 0;
	while ( i < 256 ) {
		if ( fwd_status[i] && strcasecmp(fwd_status[i], status) == 0 ) 
			return i;
		i++;
	}
	return 256;

} // End of Get_fwd_status_id

char *Get_fwd_status_name(uint32_t id) {

	return id < 256 ? fwd_status[id] : NULL;

} // End of Get_fwd_status_name

void format_file_block_header(void *header, char ** s, int tag) {
data_block_header_t *h = (data_block_header_t *)header;
	
	snprintf(data_string,STRINGSIZE-1 ,""
"File Block Header: \n"
"  NumBlocks     =  %10u\n"
"  Size          =  %10u\n"
"  id         	 =  %10u\n",
		h->NumRecords,
		h->size,
		h->id);
	*s = data_string;

} // End of format_file_block_header

void format_file_block_record(void *record, char ** s, int tag) {
char 		*_s, as[IP_STRING_LEN], ds[IP_STRING_LEN], datestr1[64], datestr2[64], datestr3[64], flags_str[16];
char		s_snet[IP_STRING_LEN], s_dnet[IP_STRING_LEN], s_proto[32];
int			i, id;
ssize_t		slen, _slen;
time_t		when;
struct tm 	*ts;
master_record_t *r = (master_record_t *)record;
extension_map_t	*extension_map = r->map_ref;

	as[0] = 0;
	ds[0] = 0;
	if ( TestFlag(r->flags,FLAG_IPV6_ADDR ) != 0 ) { // IPv6
		uint64_t snet[2];
		uint64_t dnet[2];

		// remember IPs for network 
		snet[0] = r->v6.srcaddr[0];
		snet[1] = r->v6.srcaddr[1];
		dnet[0] = r->v6.dstaddr[0];
		dnet[1] = r->v6.dstaddr[1];
		r->v6.srcaddr[0] = htonll(r->v6.srcaddr[0]);
		r->v6.srcaddr[1] = htonll(r->v6.srcaddr[1]);
		r->v6.dstaddr[0] = htonll(r->v6.dstaddr[0]);
		r->v6.dstaddr[1] = htonll(r->v6.dstaddr[1]);
		inet_ntop(AF_INET6, r->v6.srcaddr, as, sizeof(as));
		inet_ntop(AF_INET6, r->v6.dstaddr, ds, sizeof(ds));
		if ( ! long_v6 ) {
			condense_v6(as);
			condense_v6(ds);
		}
		if ( r->src_mask || r->dst_mask) {
			if ( r->src_mask > 64 )
				snet[1] &= 0xffffffffffffffffLL << ( 128 - r->src_mask );
			else {
				snet[1] &= 0xffffffffffffffffLL << ( 64 - r->src_mask );
				snet[1] = 0;
			}
			snet[0] = htonll(snet[0]);
			snet[1] = htonll(snet[1]);
			inet_ntop(AF_INET6, &snet, s_snet, sizeof(s_snet));

			if ( r->dst_mask > 64 )
				dnet[1] &= 0xffffffffffffffffLL << ( 128 - r->dst_mask );
			else {
				dnet[1] &= 0xffffffffffffffffLL << ( 64 - r->dst_mask );
				dnet[1] = 0;
			}
			dnet[0] = htonll(dnet[0]);
			dnet[1] = htonll(dnet[1]);
			inet_ntop(AF_INET6, &dnet, s_dnet, sizeof(s_dnet));
			if ( ! long_v6 ) {
				condense_v6(s_snet);
				condense_v6(s_dnet);
			}

		} else {
			s_snet[0] = '\0';
			s_dnet[0] = '\0';
		}

	} else {	// IPv4
		uint32_t snet, dnet;
		snet = r->v4.srcaddr;
		dnet = r->v4.dstaddr;
		r->v4.srcaddr = htonl(r->v4.srcaddr);
		r->v4.dstaddr = htonl(r->v4.dstaddr);
		inet_ntop(AF_INET, &r->v4.srcaddr, as, sizeof(as));
		inet_ntop(AF_INET, &r->v4.dstaddr, ds, sizeof(ds));
		if ( r->src_mask || r->dst_mask) {
			snet &= 0xffffffffL << ( 32 - r->src_mask );
			snet = htonl(snet);
			inet_ntop(AF_INET, &snet, s_snet, sizeof(s_snet));

			dnet &= 0xffffffffL << ( 32 - r->dst_mask );
			dnet = htonl(dnet);
			inet_ntop(AF_INET, &dnet, s_dnet, sizeof(s_dnet));
		} else {
			s_snet[0] = '\0';
			s_dnet[0] = '\0';
		}
	}
	as[IP_STRING_LEN-1] = 0;
	ds[IP_STRING_LEN-1] = 0;

	when = r->first;
	ts = localtime(&when);
	strftime(datestr1, 63, "%Y-%m-%d %H:%M:%S", ts);

	when = r->last;
	ts = localtime(&when);
	strftime(datestr2, 63, "%Y-%m-%d %H:%M:%S", ts);

	String_Flags(record, flags_str);

	_s = data_string;
	slen = STRINGSIZE;
	snprintf(_s, slen-1, "\n"
"Flow Record: \n"
"  Flags        =              0x%.2x %s, %s\n"
"  export sysid =             %5u\n"
"  size         =             %5u\n"
"  first        =        %10u [%s]\n"
"  last         =        %10u [%s]\n"
"  msec_first   =             %5u\n"
"  msec_last    =             %5u\n"
"  src addr     =  %16s\n"
"  dst addr     =  %16s\n"
, 
		r->flags, TestFlag(r->flags, FLAG_EVENT) ? "EVENT" : "FLOW", 
		TestFlag(r->flags, FLAG_SAMPLED) ? "Sampled" : "Unsampled", r->exporter_sysid, r->size, r->first, 
		datestr1, r->last, datestr2, r->msec_first, r->msec_last, 
		as, ds );

	_slen = strlen(data_string);
	_s = data_string + _slen;
	slen = STRINGSIZE - _slen;

	if ( r->prot == IPPROTO_ICMP || r->prot == IPPROTO_ICMPV6 ) { // ICMP
		snprintf(_s, slen-1,
"  ICMP         =              %2u.%-2u type.code\n",
		r->icmp_type, r->icmp_code);
	} else {
		snprintf(_s, slen-1,
"  src port     =             %5u\n"
"  dst port     =             %5u\n",
		r->srcport, r->dstport);
	}

	_slen = strlen(data_string);
	_s = data_string + _slen;
	slen = STRINGSIZE - _slen;

	Proto_string(r->prot, s_proto);

	snprintf(_s, slen-1,
"  fwd status   =               %3u\n"
"  tcp flags    =              0x%.2x %s\n"
"  proto        =               %3u %s\n"
"  (src)tos     =               %3u\n"
"  (in)packets  =        %10llu\n"
"  (in)bytes    =        %10llu\n",
	r->fwd_status, r->tcp_flags, flags_str, r->prot, s_proto, r->tos,
		(unsigned long long)r->dPkts, (unsigned long long)r->dOctets);

	_slen = strlen(data_string);
	_s = data_string + _slen;
	slen = STRINGSIZE - _slen;
	
	i = 0;
	while ( (id = extension_map->ex_id[i]) != 0 ) {
		if ( slen <= 20 ) {
			fprintf(stderr, "String too short! Missing record data!\n");
			data_string[STRINGSIZE-1] = 0;
			*s = data_string;
		}
		switch(id) {
			case EX_IO_SNMP_2:
			case EX_IO_SNMP_4:
				snprintf(_s, slen-1,
"  input        =             %5u\n"
"  output       =             %5u\n"
, r->input, r->output);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
				break;
			case EX_AS_2:
			case EX_AS_4:
				snprintf(_s, slen-1,
"  src as       =             %5u\n"
"  dst as       =             %5u\n"
, r->srcas, r->dstas);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
				break;
			case EX_BGPADJ:
				snprintf(_s, slen-1,
"  next as      =             %5u\n"
"  prev as      =             %5u\n"
, r->bgpNextAdjacentAS, r->bgpPrevAdjacentAS);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
				break;
			case EX_MULIPLE:
				snprintf(_s, slen-1,
"  src mask     =             %5u %s/%u\n"
"  dst mask     =             %5u %s/%u\n"
"  dst tos      =               %3u\n"
"  direction    =               %3u\n"
, r->src_mask, s_snet, r->src_mask, r->dst_mask, s_dnet, r->dst_mask, r->dst_tos, r->dir );
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
				break;
			case EX_NEXT_HOP_v4:
				as[0] = 0;
				r->ip_nexthop.v4 = htonl(r->ip_nexthop.v4);
				inet_ntop(AF_INET, &r->ip_nexthop.v4, as, sizeof(as));
				as[IP_STRING_LEN-1] = 0;

				snprintf(_s, slen-1,
"  ip next hop  =  %16s\n"
, as);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
	
			break;
			case EX_NEXT_HOP_v6:
				as[0] = 0;
				r->ip_nexthop.v6[0] = htonll(r->ip_nexthop.v6[0]);
				r->ip_nexthop.v6[1] = htonll(r->ip_nexthop.v6[1]);
				inet_ntop(AF_INET6, r->ip_nexthop.v6, as, sizeof(as));
				if ( ! long_v6 ) {
					condense_v6(as);
					condense_v6(ds);
				}
				as[IP_STRING_LEN-1] = 0;

				snprintf(_s, slen-1,
"  ip next hop  =  %16s\n"
, as);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
			break;
			case EX_NEXT_HOP_BGP_v4:
				as[0] = 0;
				r->bgp_nexthop.v4 = htonl(r->bgp_nexthop.v4);
				inet_ntop(AF_INET, &r->bgp_nexthop.v4, as, sizeof(as));
				as[IP_STRING_LEN-1] = 0;

				snprintf(_s, slen-1,
"  bgp next hop =  %16s\n"
, as);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
	
			break;
			case EX_NEXT_HOP_BGP_v6:
				as[0] = 0;
				r->bgp_nexthop.v6[0] = htonll(r->bgp_nexthop.v6[0]);
				r->bgp_nexthop.v6[1] = htonll(r->bgp_nexthop.v6[1]);
				inet_ntop(AF_INET6, r->ip_nexthop.v6, as, sizeof(as));
				if ( ! long_v6 ) {
					condense_v6(as);
					condense_v6(ds);
				}
				as[IP_STRING_LEN-1] = 0;

				snprintf(_s, slen-1,
"  bgp next hop =  %16s\n"
, as);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
			break;
			case EX_VLAN:
				snprintf(_s, slen-1,
"  src vlan     =             %5u\n"
"  dst vlan     =             %5u\n"
, r->src_vlan, r->dst_vlan);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
			break;
			case EX_OUT_PKG_4:
			case EX_OUT_PKG_8:
				snprintf(_s, slen-1,
"  out packets  =        %10llu\n"
, (long long unsigned)r->out_pkts);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
			break;
			case EX_OUT_BYTES_4:
			case EX_OUT_BYTES_8:
				snprintf(_s, slen-1,
"  out bytes    =        %10llu\n"
, (long long unsigned)r->out_bytes);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
			break;
			case EX_AGGR_FLOWS_4:
			case EX_AGGR_FLOWS_8:
				snprintf(_s, slen-1,
"  aggr flows   =        %10llu\n"
, (long long unsigned)r->aggr_flows);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
			break;
			case EX_MAC_1: {
				int i;
				uint8_t mac1[6], mac2[6];

				for ( i=0; i<6; i++ ) {
					mac1[i] = (r->in_src_mac >> ( i*8 )) & 0xFF;
				}
				for ( i=0; i<6; i++ ) {
					mac2[i] = (r->out_dst_mac >> ( i*8 )) & 0xFF;
				}

				snprintf(_s, slen-1,
"  in src mac   = %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n"
"  out dst mac  = %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n"
, mac1[5], mac1[4], mac1[3], mac1[2], mac1[1], mac1[0], mac2[5], mac2[4], mac2[3], mac2[2], mac2[1], mac2[0] );
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
			} break;
			case EX_MAC_2: {
				int i;
				uint8_t mac1[6], mac2[6];

				for ( i=0; i<6; i++ ) {
					mac1[i] = (r->in_dst_mac >> ( i*8 )) & 0xFF;
				}
				for ( i=0; i<6; i++ ) {
					mac2[i] = (r->out_src_mac >> ( i*8 )) & 0xFF;
				}

				snprintf(_s, slen-1,
"  in dst mac   = %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n"
"  out src mac  = %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n"
, mac1[5], mac1[4], mac1[3], mac1[2], mac1[1], mac1[0], mac2[5], mac2[4], mac2[3], mac2[2], mac2[1], mac2[0] );
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
			} break;
			case EX_MPLS: {
				unsigned int i;
				for ( i=0; i<10; i++ ) {
					snprintf(_s, slen-1,
"  MPLS Lbl %2u  =      %8u-%1u-%1u\n", i+1
, r->mpls_label[i] >> 4 , (r->mpls_label[i] & 0xF ) >> 1, r->mpls_label[i] & 1 );
					_slen = strlen(data_string);
					_s = data_string + _slen;
					slen = STRINGSIZE - _slen;
				}
			} break;
			case EX_ROUTER_IP_v4:
				as[0] = 0;
				r->ip_router.v4 = htonl(r->ip_router.v4);
				inet_ntop(AF_INET, &r->ip_router.v4, as, sizeof(as));
				as[IP_STRING_LEN-1] = 0;

				snprintf(_s, slen-1,
"  ip router    =  %16s\n"
, as);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
	
			break;
			case EX_ROUTER_IP_v6:
				as[0] = 0;
				r->ip_router.v6[0] = htonll(r->ip_router.v6[0]);
				r->ip_router.v6[1] = htonll(r->ip_router.v6[1]);
				inet_ntop(AF_INET6, &r->ip_router.v6, as, sizeof(as));
				if ( ! long_v6 ) {
					condense_v6(as);
				}
				as[IP_STRING_LEN-1] = 0;

				snprintf(_s, slen-1,
"  ip router    =  %16s\n"
, as);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
			break;
			case EX_LATENCY: {
				double f1, f2, f3;
				f1 = (double)r->client_nw_delay_usec / 1000.0;
				f2 = (double)r->server_nw_delay_usec / 1000.0;
				f3 = (double)r->appl_latency_usec / 1000.0;

				snprintf(_s, slen-1,
"  cli latency  =         %9.3f ms\n"
"  srv latency  =         %9.3f ms\n"
"  app latency  =         %9.3f ms\n"
, f1, f2, f3);

				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;

			} break;
			case EX_ROUTER_ID:
				snprintf(_s, slen-1,
"  engine type  =             %5u\n"
"  engine ID    =             %5u\n"
, r->engine_type, r->engine_id);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
				break;
			case EX_RECEIVED:
				when = r->received / 1000LL;
				ts = localtime(&when);
				strftime(datestr3, 63, "%Y-%m-%d %H:%M:%S", ts);

				snprintf(_s, slen-1,
"  received at  =     %13llu [%s.%03llu]\n"
, (long long unsigned)r->received, datestr3, (long long unsigned)(r->received % 1000L));
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
				break;
#ifdef NSEL
			case EX_NSEL_COMMON: {
				char *event = "UNKNOWN";
				if ( r->event <= 5 ) {
					event = NSEL_event_string[r->event];
				} 
				when = r->event_time / 1000LL;
				ts = localtime(&when);
				strftime(datestr3, 63, "%Y-%m-%d %H:%M:%S", ts);
				snprintf(_s, slen-1,
"  connect ID   =        %10u\n"
"  fw event     =             %5u: %s\n"
"  fw ext event =             %5u\n"
"  Event time   =     %13llu [%s.%03llu]\n"
, r->conn_id, r->event, event, r->fw_xevent
, (long long unsigned)r->event_time, datestr3, (long long unsigned)(r->event_time % 1000L));
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
				} break;
			case EX_NEL_COMMON: {
				char *event = "UNKNOWN";
				if ( r->event <= 2 ) {
					event = NEL_event_string[r->event];
				}
				snprintf(_s, slen-1,
"  nat event    =             %5u: %s\n"
"  ingress VRF  =        %10u\n"
"  egress VRF   =        %10u\n"
, r->event, event, r->ingress_vrfid, r->egress_vrfid);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
				} break;
			case EX_NSEL_XLATE_PORTS: {
				snprintf(_s, slen-1,
"  src xlt port =             %5u\n"
"  dst xlt port =             %5u\n"
, r->xlate_src_port, r->xlate_dst_port );
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
				} break;
			case EX_PORT_BLOCK_ALLOC: {
				snprintf(_s, slen-1,
"  pblock start =             %5u\n"
"  pblock end   =             %5u\n"
"  pblock step  =             %5u\n"
"  pblock size  =             %5u\n"
, r->block_start, r->block_end, r->block_step, r->block_size );
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
				} break;
			case EX_NSEL_XLATE_IP_v4:
				as[0] = 0;
				ds[0] = 0;
				r->xlate_src_ip.v4 = htonl(r->xlate_src_ip.v4);
				r->xlate_dst_ip.v4 = htonl(r->xlate_dst_ip.v4);
				inet_ntop(AF_INET, &r->xlate_src_ip.v4, as, sizeof(as));
				inet_ntop(AF_INET, &r->xlate_dst_ip.v4, ds, sizeof(ds));
				as[IP_STRING_LEN-1] = 0;
				ds[IP_STRING_LEN-1] = 0;

				snprintf(_s, slen-1,
"  src xlt ip   =  %16s\n"
"  dst xlt ip   =  %16s\n"
, as, ds);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
			break;
			case EX_NSEL_XLATE_IP_v6:
				as[0] = 0;
				ds[0] = 0;
				r->xlate_src_ip.v6[0] = htonll(r->xlate_src_ip.v6[0]);
				r->xlate_src_ip.v6[1] = htonll(r->xlate_src_ip.v6[1]);
				r->xlate_dst_ip.v6[0] = htonll(r->xlate_dst_ip.v6[0]);
				r->xlate_dst_ip.v6[1] = htonll(r->xlate_dst_ip.v6[1]);
				inet_ntop(AF_INET6, &r->xlate_src_ip.v6, as, sizeof(as));
				inet_ntop(AF_INET6, &r->xlate_dst_ip.v6, ds, sizeof(ds));
				if ( ! long_v6 ) {
					condense_v6(as);
					condense_v6(ds);
				}
				as[IP_STRING_LEN-1] = 0;
				ds[IP_STRING_LEN-1] = 0;

				snprintf(_s, slen-1,
"  src xlate ip =  %16s\n"
"  dst xlate ip =  %16s\n"
, as, ds);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
			break;
			case EX_NSEL_ACL:
				snprintf(_s, slen-1,
"  Ingress ACL  =       0x%x/0x%x/0x%x\n"
"  Egress ACL   =       0x%x/0x%x/0x%x\n"
, r->ingress_acl_id[0], r->ingress_acl_id[1], r->ingress_acl_id[2], 
  r->egress_acl_id[0], r->egress_acl_id[1], r->egress_acl_id[2]);
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
				break;
			case EX_NSEL_USER:
			case EX_NSEL_USER_MAX:
				snprintf(_s, slen-1,
"  User name    = %s\n"
, r->username[0] ? r->username : "          <empty>");
				_slen = strlen(data_string);
				_s = data_string + _slen;
				slen = STRINGSIZE - _slen;
				break;
#endif
			default:
				snprintf(_s, slen-1, "Type %u not implemented\n", id);

		}
		i++;
	}

	data_string[STRINGSIZE-1] = 0;
	*s = data_string;


} // End of format_file_block_record

void flow_record_to_pipe(void *record, char ** s, int tag) {
uint32_t	sa[4], da[4];
int			af;
master_record_t *r = (master_record_t *)record;

	if ( (r->flags & FLAG_IPV6_ADDR ) != 0 ) { // IPv6
		af = PF_INET6;
	} else {	// IPv4
		af = PF_INET;
	}

	// Make sure Endian does not screw us up
    sa[0] = ( r->v6.srcaddr[0] >> 32 ) & 0xffffffffLL;
    sa[1] = r->v6.srcaddr[0] & 0xffffffffLL;
    sa[2] = ( r->v6.srcaddr[1] >> 32 ) & 0xffffffffLL;
    sa[3] = r->v6.srcaddr[1] & 0xffffffffLL;

    da[0] = ( r->v6.dstaddr[0] >> 32 ) & 0xffffffffLL;
    da[1] = r->v6.dstaddr[0] & 0xffffffffLL;
    da[2] = ( r->v6.dstaddr[1] >> 32 ) & 0xffffffffLL;
    da[3] = r->v6.dstaddr[1] & 0xffffffffLL;

	snprintf(data_string, STRINGSIZE-1 ,"%i|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%llu|%llu",
		af, r->first, r->msec_first ,r->last, r->msec_last, r->prot, 
		sa[0], sa[1], sa[2], sa[3], r->srcport, da[0], da[1], da[2], da[3], r->dstport, 
		r->srcas, r->dstas, r->input, r->output,
		r->tcp_flags, r->tos, (unsigned long long)r->dPkts, (unsigned long long)r->dOctets);

	data_string[STRINGSIZE-1] = 0;

	*s = data_string;

} // End of flow_record_pipe

void flow_record_to_csv(void *record, char ** s, int tag) {
char 		*_s, as[IP_STRING_LEN], ds[IP_STRING_LEN]; 
char		proto_str[MAX_PROTO_STR], datestr1[64], datestr2[64], datestr3[64], flags_str[16];
char		s_snet[IP_STRING_LEN], s_dnet[IP_STRING_LEN];
ssize_t		slen, _slen;
time_t		when;
struct tm 	*ts;
master_record_t *r = (master_record_t *)record;

	as[0] = 0;
	ds[0] = 0;
	if ( (r->flags & FLAG_IPV6_ADDR ) != 0 ) { // IPv6
		uint64_t snet[2];
		uint64_t dnet[2];

		// remember IPs for network 
		snet[0] = r->v6.srcaddr[0];
		snet[1] = r->v6.srcaddr[1];
		dnet[0] = r->v6.dstaddr[0];
		dnet[1] = r->v6.dstaddr[1];
		r->v6.srcaddr[0] = htonll(r->v6.srcaddr[0]);
		r->v6.srcaddr[1] = htonll(r->v6.srcaddr[1]);
		r->v6.dstaddr[0] = htonll(r->v6.dstaddr[0]);
		r->v6.dstaddr[1] = htonll(r->v6.dstaddr[1]);
		inet_ntop(AF_INET6, r->v6.srcaddr, as, sizeof(as));
		inet_ntop(AF_INET6, r->v6.dstaddr, ds, sizeof(ds));

		if ( r->src_mask || r->dst_mask) {
			if ( r->src_mask > 64 )
				snet[1] &= 0xffffffffffffffffLL << ( 128 - r->src_mask );
			else {
				snet[1] &= 0xffffffffffffffffLL << ( 64 - r->src_mask );
				snet[1] = 0;
			}
			snet[0] = htonll(snet[0]);
			snet[1] = htonll(snet[1]);
			inet_ntop(AF_INET6, &snet, s_snet, sizeof(s_snet));

			if ( r->dst_mask > 64 )
				dnet[1] &= 0xffffffffffffffffLL << ( 128 - r->dst_mask );
			else {
				dnet[1] &= 0xffffffffffffffffLL << ( 64 - r->dst_mask );
				dnet[1] = 0;
			}
			dnet[0] = htonll(dnet[0]);
			dnet[1] = htonll(dnet[1]);
			inet_ntop(AF_INET6, &dnet, s_dnet, sizeof(s_dnet));

		} else {
			s_snet[0] = '\0';
			s_dnet[0] = '\0';
		}

	} else {	// IPv4
		uint32_t snet, dnet;
		snet = r->v4.srcaddr;
		dnet = r->v4.dstaddr;
		r->v4.srcaddr = htonl(r->v4.srcaddr);
		r->v4.dstaddr = htonl(r->v4.dstaddr);
		inet_ntop(AF_INET, &r->v4.srcaddr, as, sizeof(as));
		inet_ntop(AF_INET, &r->v4.dstaddr, ds, sizeof(ds));
		if ( r->src_mask || r->dst_mask) {
			snet &= 0xffffffffL << ( 32 - r->src_mask );
			snet = htonl(snet);
			inet_ntop(AF_INET, &snet, s_snet, sizeof(s_snet));

			dnet &= 0xffffffffL << ( 32 - r->dst_mask );
			dnet = htonl(dnet);
			inet_ntop(AF_INET, &dnet, s_dnet, sizeof(s_dnet));
		} else {
			s_snet[0] = '\0';
			s_dnet[0] = '\0';
		}
	}
	as[IP_STRING_LEN-1] = 0;
	ds[IP_STRING_LEN-1] = 0;

	when = r->first;
	ts = localtime(&when);
	strftime(datestr1, 63, "%Y-%m-%d %H:%M:%S", ts);

	when = r->last;
	ts = localtime(&when);
	strftime(datestr2, 63, "%Y-%m-%d %H:%M:%S", ts);

	duration = r->last - r->first;
	duration += ((double)r->msec_last - (double)r->msec_first) / 1000.0;

	String_Flags(record, flags_str);

	if ( r->prot >= NumProtos ) {
		snprintf(proto_str,MAX_PROTO_STR-1,"%u", r->prot );
		proto_str[MAX_PROTO_STR-1] = '\0';
	} else {
		int i = 0;;
		strncpy(proto_str, protolist[r->prot], MAX_PROTO_STR);
		// remove white spaces for csv
		while ( proto_str[i] ) {
			if ( proto_str[i] == ' ' )
				proto_str[i] = '\0';
			i++;
		}
	}

	_s = data_string;
	slen = STRINGSIZE;
	snprintf(_s, slen-1, "%s,%s,%.3f,%s,%s,%u,%u,%s,%s,%u,%u,%llu,%llu,%llu,%llu",
		datestr1, datestr2, duration, as,ds,r->srcport, r->dstport, proto_str, flags_str, 
		r->fwd_status, r->tos, (unsigned long long)r->dPkts, (unsigned long long)r->dOctets,
		(long long unsigned)r->out_pkts, (long long unsigned)r->out_bytes
	);

	_slen = strlen(data_string);
	_s += _slen;
	slen -= _slen;
	
	// EX_IO_SNMP_2:
	// EX_IO_SNMP_4:
	snprintf(_s, slen-1, ",%u,%u" , r->input, r->output);
		_slen = strlen(data_string);
		_s = data_string + _slen;
		slen = STRINGSIZE - _slen;

	// EX_AS_2:
	// EX_AS_4:
	snprintf(_s, slen-1, ",%u,%u", r->srcas, r->dstas);
		_slen = strlen(data_string);
		_s = data_string + _slen;
		slen = STRINGSIZE - _slen;

	// EX_MULIPLE:
	snprintf(_s, slen-1, ",%u,%u,%u,%u" , r->src_mask, r->dst_mask, r->dst_tos, r->dir );
		_slen = strlen(data_string);
		_s = data_string + _slen;
		slen = STRINGSIZE - _slen;

	if ( (r->flags & FLAG_IPV6_NH ) != 0 ) { // IPv6
		// EX_NEXT_HOP_v6:
		as[0] = 0;
		r->ip_nexthop.v6[0] = htonll(r->ip_nexthop.v6[0]);
		r->ip_nexthop.v6[1] = htonll(r->ip_nexthop.v6[1]);
		inet_ntop(AF_INET6, r->ip_nexthop.v6, as, sizeof(as));
		as[IP_STRING_LEN-1] = 0;
	
		snprintf(_s, slen-1, ",%s", as);
		_slen = strlen(data_string);
		_s = data_string + _slen;
		slen = STRINGSIZE - _slen;

	} else {
		// EX_NEXT_HOP_v4:
		as[0] = 0;
		r->ip_nexthop.v4 = htonl(r->ip_nexthop.v4);
		inet_ntop(AF_INET, &r->ip_nexthop.v4, as, sizeof(as));
		as[IP_STRING_LEN-1] = 0;

		snprintf(_s, slen-1, ",%s", as);
		_slen = strlen(data_string);
		_s = data_string + _slen;
		slen = STRINGSIZE - _slen;
	}
	
	if ( (r->flags & FLAG_IPV6_NH ) != 0 ) { // IPv6
		// EX_NEXT_HOP_BGP_v6:
		as[0] = 0;
		r->bgp_nexthop.v6[0] = htonll(r->bgp_nexthop.v6[0]);
		r->bgp_nexthop.v6[1] = htonll(r->bgp_nexthop.v6[1]);
		inet_ntop(AF_INET6, r->ip_nexthop.v6, as, sizeof(as));
		as[IP_STRING_LEN-1] = 0;
	
		snprintf(_s, slen-1, ",%s", as);
		_slen = strlen(data_string);
		_s = data_string + _slen;
		slen = STRINGSIZE - _slen;

	} else {
		// 	EX_NEXT_HOP_BGP_v4:
		as[0] = 0;
		r->bgp_nexthop.v4 = htonl(r->bgp_nexthop.v4);
		inet_ntop(AF_INET, &r->bgp_nexthop.v4, as, sizeof(as));
		as[IP_STRING_LEN-1] = 0;

		snprintf(_s, slen-1, ",%s", as);
		_slen = strlen(data_string);
		_s = data_string + _slen;
		slen = STRINGSIZE - _slen;

	}

	// EX_VLAN:
	snprintf(_s, slen-1, ",%u,%u", r->src_vlan, r->dst_vlan);
	_slen = strlen(data_string);
	_s = data_string + _slen;
	slen = STRINGSIZE - _slen;


	/* already in default output:
	EX_OUT_PKG_4:
	EX_OUT_PKG_8:
	EX_OUT_BYTES_4:
	EX_OUT_BYTES_8:
	*/

	// case EX_MAC_1: 
	{
		int i;
		uint8_t mac1[6], mac2[6];

		for ( i=0; i<6; i++ ) {
			mac1[i] = (r->in_src_mac >> ( i*8 )) & 0xFF;
		}
		for ( i=0; i<6; i++ ) {
			mac2[i] = (r->out_dst_mac >> ( i*8 )) & 0xFF;
		}

		snprintf(_s, slen-1, ",%.2x:%.2x:%.2x:%.2x:%.2x:%.2x,%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
			mac1[5], mac1[4], mac1[3], mac1[2], mac1[1], mac1[0], 
			mac2[5], mac2[4], mac2[3], mac2[2], mac2[1], mac2[0] );
		_slen = strlen(data_string);
		_s = data_string + _slen;
		slen = STRINGSIZE - _slen;
	} 

	// EX_MAC_2: 
	{
		int i;
		uint8_t mac1[6], mac2[6];

		for ( i=0; i<6; i++ ) {
			mac1[i] = (r->in_dst_mac >> ( i*8 )) & 0xFF;
		}
		for ( i=0; i<6; i++ ) {
			mac2[i] = (r->out_src_mac >> ( i*8 )) & 0xFF;
		}

		snprintf(_s, slen-1, ",%.2x:%.2x:%.2x:%.2x:%.2x:%.2x,%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
			mac1[5], mac1[4], mac1[3], mac1[2], mac1[1], mac1[0], 
			mac2[5], mac2[4], mac2[3], mac2[2], mac2[1], mac2[0] );
		_slen = strlen(data_string);
		_s = data_string + _slen;
		slen = STRINGSIZE - _slen;
	}

	// EX_MPLS: 
	{
		unsigned int i;
		for ( i=0; i<10; i++ ) {
			snprintf(_s, slen-1, ",%u-%1u-%1u", 
				r->mpls_label[i] >> 4 , (r->mpls_label[i] & 0xF ) >> 1, r->mpls_label[i] & 1 );
			_slen = strlen(data_string);
			_s = data_string + _slen;
			slen = STRINGSIZE - _slen;
		}
	} 

	{
		double f1, f2, f3;
		f1 = (double)r->client_nw_delay_usec / 1000.0;
		f2 = (double)r->server_nw_delay_usec / 1000.0;
		f3 = (double)r->appl_latency_usec / 1000.0;

				snprintf(_s, slen-1,
",%9.3f,%9.3f,%9.3f", f1, f2, f3);

		_slen = strlen(data_string);
		_s = data_string + _slen;
		slen = STRINGSIZE - _slen;
	} 


	// EX_ROUTER_IP_v4:
	if ( (r->flags & FLAG_IPV6_EXP ) != 0 ) { // IPv6
		// EX_NEXT_HOP_v6:
		as[0] = 0;
		r->ip_router.v6[0] = htonll(r->ip_router.v6[0]);
		r->ip_router.v6[1] = htonll(r->ip_router.v6[1]);
		inet_ntop(AF_INET6, r->ip_router.v6, as, sizeof(as));
		as[IP_STRING_LEN-1] = 0;
	
		snprintf(_s, slen-1, ",%s", as);
		_slen = strlen(data_string);
		_s = data_string + _slen;
		slen = STRINGSIZE - _slen;

	} else {
		// EX_NEXT_HOP_v4:
		as[0] = 0;
		r->ip_router.v4 = htonl(r->ip_router.v4);
		inet_ntop(AF_INET, &r->ip_router.v4, as, sizeof(as));
		as[IP_STRING_LEN-1] = 0;

		snprintf(_s, slen-1, ",%s", as);
		_slen = strlen(data_string);
		_s = data_string + _slen;
		slen = STRINGSIZE - _slen;
	}

	// EX_ROUTER_ID
	snprintf(_s, slen-1, ",%u/%u", r->engine_type, r->engine_id);
		_slen = strlen(data_string);
		_s = data_string + _slen;
		slen = STRINGSIZE - _slen;

	// Exporter SysID
	snprintf(_s, slen-1, ",%u", r->exporter_sysid);
		_slen = strlen(data_string);
		_s = data_string + _slen;
		slen = STRINGSIZE - _slen;

	// Date flow received
	when = r->received / 1000LL;
 	ts = localtime(&when);
 	strftime(datestr3, 63, ",%Y-%m-%d %H:%M:%S", ts);
 
 	snprintf(_s, slen-1, "%s.%03llu", datestr3, (long long unsigned)r->received % 1000LL);
 	        _slen = strlen(data_string);
 	        _s = data_string + _slen;
 	        slen = STRINGSIZE - _slen;

	// snprintf(_s, slen-1, "\n");
	data_string[STRINGSIZE-1] = 0;
	*s = data_string;


} // End of flow_record_to_csv

void flow_record_to_null(void *record, char ** s, int tag) {
	// empty - do not list any flows
} // End of flow_record_to_null

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

char *get_record_header(void) {
	return header_string;
} // End of get_record_header

void set_record_header(void) {

	snprintf(header_string, STRINGSIZE-1, "ts,te,td,sa,da,sp,dp,pr,flg,fwd,stos,ipkt,ibyt,opkt,obyt,in,out,sas,das,smk,dmk,dtos,dir,nh,nhb,svln,dvln,ismc,odmc,idmc,osmc,mpls1,mpls2,mpls3,mpls4,mpls5,mpls6,mpls7,mpls8,mpls9,mpls10,cl,sl,al,ra,eng,exid,tr");
	header_string[STRINGSIZE-1] = '\0';

} // End of format_csv_header

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

void condense_v6(char *s) {
size_t len = strlen(s);
char	*p, *q;

	if ( len <= 16 )
		return;

	// orig:      2001:620:1000:cafe:20e:35ff:fec0:fed5 len = 37
	// condensed: 2001:62..e0:fed5
	p = s + 7;
	*p++ = '.';
	*p++ = '.';
	q = s + len - 7;
	while ( *q ) { 
		*p++ = *q++; 
	}
	*p = 0;

} // End of condense_v6

static inline void ICMP_Port_decode(master_record_t *r, char *string) {

	if ( r->prot == IPPROTO_ICMP || r->prot == IPPROTO_ICMPV6 ) { // ICMP
		snprintf(string, MAX_STRING_LENGTH-1, "%u.%u",  r->icmp_type, r->icmp_code);
	} else { 	// dst port
		snprintf(string, MAX_STRING_LENGTH-1, "%u",  r->dstport);
	}
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of ICMP_Port_decode

/* functions, which create the individual strings for the output line */
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
char s[16];

	Proto_string(r->prot, s);
	snprintf(string, MAX_STRING_LENGTH-1 ,"%s", s);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_Protocol

static void String_SrcAddr(master_record_t *r, char *string) {
char tmp_str[IP_STRING_LEN];

	tmp_str[0] = 0;
	if ( (r->flags & FLAG_IPV6_ADDR ) != 0 ) { // IPv6
		uint64_t	ip[2];

		ip[0] = htonll(r->v6.srcaddr[0]);
		ip[1] = htonll(r->v6.srcaddr[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			condense_v6(tmp_str);
		}
	} else {	// IPv4
		uint32_t	ip;
		ip = htonl(r->v4.srcaddr);
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

		ip[0] = htonll(r->v6.srcaddr[0]);
		ip[1] = htonll(r->v6.srcaddr[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			condense_v6(tmp_str);
		}
		portchar = '.';
	} else {	// IPv4
		uint32_t	ip;
		ip = htonl(r->v4.srcaddr);
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

		ip[0] = htonll(r->v6.dstaddr[0]);
		ip[1] = htonll(r->v6.dstaddr[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			condense_v6(tmp_str);
		}
	} else {	// IPv4
		uint32_t	ip;
		ip = htonl(r->v4.dstaddr);
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

		ip[0] = htonll(r->ip_nexthop.v6[0]);
		ip[1] = htonll(r->ip_nexthop.v6[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			condense_v6(tmp_str);
		}
	} else {	// IPv4
		uint32_t	ip;
		ip = htonl(r->ip_nexthop.v4);
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
	if ( (r->flags & FLAG_IPV6_NH ) != 0 ) { // IPv6
		uint64_t	ip[2];

		ip[0] = htonll(r->bgp_nexthop.v6[0]);
		ip[1] = htonll(r->bgp_nexthop.v6[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			condense_v6(tmp_str);
		}
	} else {	// IPv4
		uint32_t	ip;
		ip = htonl(r->bgp_nexthop.v4);
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

		ip[0] = htonll(r->ip_router.v6[0]);
		ip[1] = htonll(r->ip_router.v6[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			condense_v6(tmp_str);
		}
	} else {	// IPv4
		uint32_t	ip;
		ip = htonl(r->ip_router.v4);
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

		ip[0] = htonll(r->v6.dstaddr[0]);
		ip[1] = htonll(r->v6.dstaddr[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			condense_v6(tmp_str);
		}
		portchar = '.';
	} else {	// IPv4
		uint32_t	ip;
		ip = htonl(r->v4.dstaddr);
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

		ip[0] = htonll(r->v6.srcaddr[0]);
		ip[1] = htonll(r->v6.srcaddr[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			condense_v6(tmp_str);
		}
	} else {	// IPv4
		uint32_t	ip;
		ip = htonl(r->v4.srcaddr);
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

		ip[0] = htonll(r->v6.dstaddr[0]);
		ip[1] = htonll(r->v6.dstaddr[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			condense_v6(tmp_str);
		}
	} else {	// IPv4
		uint32_t	ip;
		ip = htonl(r->v4.dstaddr);
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

	// if record contains unusuall flags, print the flags in hex as 0x.. number
	if ( r->tcp_flags > 63 ) {
		snprintf(string, 7, "  0x%2x\n", r->tcp_flags );
	} else {
		string[0] = r->tcp_flags & 32 ? 'U' : '.';
		string[1] = r->tcp_flags & 16 ? 'A' : '.';
		string[2] = r->tcp_flags &  8 ? 'P' : '.';
		string[3] = r->tcp_flags &  4 ? 'R' : '.';
		string[4] = r->tcp_flags &  2 ? 'S' : '.';
		string[5] = r->tcp_flags &  1 ? 'F' : '.';
	}
	string[6] = '\0';

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

	if ( r->event_flag == FW_EVENT ) {
		switch(r->event) {
			case 0:
					snprintf(string, MAX_STRING_LENGTH-1 ,"%3s", "IGNORE");
				break;
			case 1:
				snprintf(string, MAX_STRING_LENGTH-1 ,"%6s", "CREATE");
				break;
			case 2:
				snprintf(string, MAX_STRING_LENGTH-1 ,"%6s", "DELETE");
				break;
			case 3:
				snprintf(string, MAX_STRING_LENGTH-1 ,"%6s", "DENIED");
				break;
			case 4:
				snprintf(string, MAX_STRING_LENGTH-1 ,"%6s", "ALERT");
				break;
			case 5:
				snprintf(string, MAX_STRING_LENGTH-1 ,"%6s", "UPDATE");
				break;
			default:
				snprintf(string, MAX_STRING_LENGTH-1 ,"%6s", "UNKNOW");
		}			
	} else {
		switch(r->event) {
			case 0:
					snprintf(string, MAX_STRING_LENGTH-1 ,"%3s", "INVALID");
				break;
			case 1:
				snprintf(string, MAX_STRING_LENGTH-1 ,"%6s", "ADD");
				break;
			case 2:
				snprintf(string, MAX_STRING_LENGTH-1 ,"%6s", "DELETE");
				break;
			default:
				snprintf(string, MAX_STRING_LENGTH-1 ,"%6s", "UNKNOW");
		}			
	}
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_evt


static void String_xevt(master_record_t *r, char *string) {

	switch( r->fw_xevent) {
		case 0:
			snprintf(string, MAX_STRING_LENGTH-1 ,"%7s", "Ignore");
			break;
		case 1001:
			snprintf(string,MAX_STRING_LENGTH-1,"%7s","I-ACL");
			break;
		case 1002:
			snprintf(string,MAX_STRING_LENGTH-1,"%7s","E-ACL");
			break;
		case 1003:
			snprintf(string,MAX_STRING_LENGTH-1,"%7s","Adap");
			break;
		case 1004:
			snprintf(string,MAX_STRING_LENGTH-1,"%7s","No Syn");
			break;
		default:
			snprintf(string,MAX_STRING_LENGTH-1,"%7u",r->fw_xevent);
	}
	string[MAX_STRING_LENGTH-1] = '\0';

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

		ip[0] = htonll(r->xlate_src_ip.v6[0]);
		ip[1] = htonll(r->xlate_src_ip.v6[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			condense_v6(tmp_str);
		}
	} else {	// IPv4
		uint32_t	ip;
		ip = htonl(r->xlate_src_ip.v4);
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

		ip[0] = htonll(r->xlate_dst_ip.v6[0]);
		ip[1] = htonll(r->xlate_dst_ip.v6[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			condense_v6(tmp_str);
		}
	} else {	// IPv4
		uint32_t	ip;
		ip = htonl(r->xlate_dst_ip.v4);
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

		ip[0] = htonll(r->xlate_src_ip.v6[0]);
		ip[1] = htonll(r->xlate_src_ip.v6[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			condense_v6(tmp_str);
		}

		portchar = '.';
	} else {	// IPv4
		uint32_t	ip;
		ip = htonl(r->xlate_src_ip.v4);
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

		ip[0] = htonll(r->xlate_dst_ip.v6[0]);
		ip[1] = htonll(r->xlate_dst_ip.v6[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			condense_v6(tmp_str);
		}

		portchar = '.';
	} else {	// IPv4
		uint32_t	ip;
		ip = htonl(r->xlate_dst_ip.v4);
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
