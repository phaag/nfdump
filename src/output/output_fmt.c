/*
 *  Copyright (c) 2009-2023, Peter Haag
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

#include "output_fmt.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include "content_dns.h"
#include "ifvrf.h"
#include "ja3.h"
#include "maxmind.h"
#include "nbar.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfxV3.h"
#include "output_util.h"
#include "util.h"

typedef void (*string_function_t)(FILE *, master_record_t *);

static struct token_list_s {
    string_function_t string_function;  // function printing result to stream
    char *string_buffer;                // buffer for static output string
} *token_list = NULL;

static int max_token_index = 0;
static int token_index = 0;

#define BLOCK_SIZE 32

static char **format_list = NULL;  // ordered list of all individual strings formatting the output line
static int max_format_index = 0;

static int do_tag = 0;
static int long_v6 = 0;
static int printPlain = 0;
static double duration = 0;

#define IP_STRING_LEN (INET6_ADDRSTRLEN)

#define STRINGSIZE 10240
static char header_string[STRINGSIZE] = {'\0'};

// tag
static char tag_string[2] = {'\0'};

/* prototypes */
static char *ICMP_Port_decode(master_record_t *r);

static void InitFormatParser(void);

static void AddToken(int index, char *s);

static void String_Version(FILE *stream, master_record_t *r);

static void String_FlowCount(FILE *stream, master_record_t *r);

static void String_FirstSeen(FILE *stream, master_record_t *r);

static void String_LastSeen(FILE *stream, master_record_t *r);

static void String_Received(FILE *stream, master_record_t *r);

static void String_FirstSeenRaw(FILE *stream, master_record_t *r);

static void String_LastSeenRaw(FILE *stream, master_record_t *r);

static void String_ReceivedRaw(FILE *stream, master_record_t *r);

static void String_Duration(FILE *stream, master_record_t *r);

static void String_Duration_Seconds(FILE *stream, master_record_t *r);

static void String_Protocol(FILE *stream, master_record_t *r);

static void String_SrcAddr(FILE *stream, master_record_t *r);

static void String_DstAddr(FILE *stream, master_record_t *r);

static void String_SrcGeoAddr(FILE *stream, master_record_t *r);

static void String_DstGeoAddr(FILE *stream, master_record_t *r);

static void String_SrcAddrPort(FILE *stream, master_record_t *r);

static void String_DstAddrPort(FILE *stream, master_record_t *r);

static void String_SrcAddrGeoPort(FILE *stream, master_record_t *r);

static void String_DstAddrGeoPort(FILE *stream, master_record_t *r);

static void String_SrcNet(FILE *stream, master_record_t *r);

static void String_DstNet(FILE *stream, master_record_t *r);

static void String_NextHop(FILE *stream, master_record_t *r);

static void String_BGPNextHop(FILE *stream, master_record_t *r);

static void String_RouterIP(FILE *stream, master_record_t *r);

static void String_SrcPort(FILE *stream, master_record_t *r);

static void String_DstPort(FILE *stream, master_record_t *r);

static void String_ICMP_code(FILE *stream, master_record_t *r);

static void String_ICMP_type(FILE *stream, master_record_t *r);

static void String_SrcAS(FILE *stream, master_record_t *r);

static void String_DstAS(FILE *stream, master_record_t *r);

static void String_NextAS(FILE *stream, master_record_t *r);

static void String_PrevAS(FILE *stream, master_record_t *r);

static void String_Input(FILE *stream, master_record_t *r);

static void String_InputName(FILE *stream, master_record_t *r);

static void String_Output(FILE *stream, master_record_t *r);

static void String_OutputName(FILE *stream, master_record_t *r);

static void String_InPackets(FILE *stream, master_record_t *r);

static void String_OutPackets(FILE *stream, master_record_t *r);

static void String_InBytes(FILE *stream, master_record_t *r);

static void String_OutBytes(FILE *stream, master_record_t *r);

static void String_Flows(FILE *stream, master_record_t *r);

static void String_Tos(FILE *stream, master_record_t *r);

static void String_Dir(FILE *stream, master_record_t *r);

static void String_SrcTos(FILE *stream, master_record_t *r);

static void String_DstTos(FILE *stream, master_record_t *r);

static void String_SrcMask(FILE *stream, master_record_t *r);

static void String_DstMask(FILE *stream, master_record_t *r);

static void String_SrcVlan(FILE *stream, master_record_t *r);

static void String_DstVlan(FILE *stream, master_record_t *r);

static void String_FwdStatus(FILE *stream, master_record_t *r);

static void String_BiFlowDir(FILE *stream, master_record_t *r);

static void String_FlowEndReason(FILE *stream, master_record_t *r);

static void String_Flags(FILE *stream, master_record_t *r);

static void String_InSrcMac(FILE *stream, master_record_t *r);

static void String_OutDstMac(FILE *stream, master_record_t *r);

static void String_InDstMac(FILE *stream, master_record_t *r);

static void String_OutSrcMac(FILE *stream, master_record_t *r);

static void String_MPLS_1(FILE *stream, master_record_t *r);

static void String_MPLS_2(FILE *stream, master_record_t *r);

static void String_MPLS_3(FILE *stream, master_record_t *r);

static void String_MPLS_4(FILE *stream, master_record_t *r);

static void String_MPLS_5(FILE *stream, master_record_t *r);

static void String_MPLS_6(FILE *stream, master_record_t *r);

static void String_MPLS_7(FILE *stream, master_record_t *r);

static void String_MPLS_8(FILE *stream, master_record_t *r);

static void String_MPLS_9(FILE *stream, master_record_t *r);

static void String_MPLS_10(FILE *stream, master_record_t *r);

static void String_MPLSs(FILE *stream, master_record_t *r);

static void String_Engine(FILE *stream, master_record_t *r);

static void String_Label(FILE *stream, master_record_t *r);

static void String_ClientLatency(FILE *stream, master_record_t *r);

static void String_ServerLatency(FILE *stream, master_record_t *r);

static void String_AppLatency(FILE *stream, master_record_t *r);

static void String_bps(FILE *stream, master_record_t *r);

static void String_pps(FILE *stream, master_record_t *r);

static void String_bpp(FILE *stream, master_record_t *r);

static void String_ExpSysID(FILE *stream, master_record_t *r);

static void String_SrcCountry(FILE *stream, master_record_t *r);

static void String_DstCountry(FILE *stream, master_record_t *r);

static void String_SrcLocation(FILE *stream, master_record_t *r);

static void String_DstLocation(FILE *stream, master_record_t *r);

static void String_inPayload(FILE *stream, master_record_t *r);

static void String_outPayload(FILE *stream, master_record_t *r);

static void String_nbarID(FILE *stream, master_record_t *r);

static void String_nbarName(FILE *stream, master_record_t *r);

static void String_ja3(FILE *stream, master_record_t *r);

static void String_sniName(FILE *stream, master_record_t *r);

static void String_observationDomainID(FILE *stream, master_record_t *r);

static void String_observationPointID(FILE *stream, master_record_t *r);

static void String_ivrf(FILE *stream, master_record_t *r);

static void String_ivrfName(FILE *stream, master_record_t *r);

static void String_evrf(FILE *stream, master_record_t *r);

static void String_evrfName(FILE *stream, master_record_t *r);

static void String_NewLine(FILE *stream, master_record_t *r);

static void String_pfIfName(FILE *stream, master_record_t *r);

static void String_pfAction(FILE *stream, master_record_t *r);

static void String_pfReason(FILE *stream, master_record_t *r);

static void String_pfdir(FILE *stream, master_record_t *r);

static void String_pfrule(FILE *stream, master_record_t *r);

#ifdef NSEL
static void String_EventTime(FILE *stream, master_record_t *r);

static void String_nfc(FILE *stream, master_record_t *r);

static void String_evt(FILE *stream, master_record_t *r);

static void String_xevt(FILE *stream, master_record_t *r);

static void String_sgt(FILE *stream, master_record_t *r);

static void String_msecEvent(FILE *stream, master_record_t *r);

static void String_iacl(FILE *stream, master_record_t *r);

static void String_eacl(FILE *stream, master_record_t *r);

static void String_xlateSrcAddr(FILE *stream, master_record_t *r);

static void String_xlateDstAddr(FILE *stream, master_record_t *r);

static void String_xlateSrcPort(FILE *stream, master_record_t *r);

static void String_xlateDstPort(FILE *stream, master_record_t *r);

static void String_xlateSrcAddrPort(FILE *stream, master_record_t *r);

static void String_xlateDstAddrPort(FILE *stream, master_record_t *r);

static void String_userName(FILE *stream, master_record_t *r);

static void String_PortBlockStart(FILE *stream, master_record_t *r);

static void String_PortBlockEnd(FILE *stream, master_record_t *r);

static void String_PortBlockStep(FILE *stream, master_record_t *r);

static void String_PortBlockSize(FILE *stream, master_record_t *r);

#endif

static struct format_token_list_s {
    char *token;                                                                             // token
    int is_address;                                                                          // is an IP address
    char *header;                                                                            // header line description
    string_function_t string_function;                                                       // function generation output string
} format_token_list[] = {{"%nfv", 0, "Ver", String_Version},                                 // netflow version
                         {"%cnt", 0, "Count", String_FlowCount},                             // flow count
                         {"%tfs", 0, "Date first seen        ", String_FirstSeen},           // Start Time - first seen
                         {"%ts", 0, "Date first seen        ", String_FirstSeen},            // Start Time - first seen
                         {"%tsr", 0, "Date first seen (raw)    ", String_FirstSeenRaw},      // Start Time - first seen, seconds
                         {"%te", 0, "Date last seen         ", String_LastSeen},             // End Time	- last seen
                         {"%ter", 0, "Date last seen (raw)     ", String_LastSeenRaw},       // End Time - first seen, seconds
                         {"%tr", 0, "Date flow received     ", String_Received},             // Received Time
                         {"%trr", 0, "Date flow received (raw)  ", String_ReceivedRaw},      // Received Time, seconds
                         {"%td", 0, "    Duration    ", String_Duration},                    // Duration
                         {"%tds", 0, "    Duration    ", String_Duration_Seconds},           // Duration always in seconds
                         {"%exp", 0, "Exp ID", String_ExpSysID},                             // Exporter SysID
                         {"%pr", 0, "Proto", String_Protocol},                               // Protocol
                         {"%sa", 1, "     Src IP Addr", String_SrcAddr},                     // Source Address
                         {"%da", 1, "     Dst IP Addr", String_DstAddr},                     // Destination Address
                         {"%gsa", 1, "     Src IP Addr(..)", String_SrcGeoAddr},             // Source Address
                         {"%gda", 1, "     Dst IP Addr(..)", String_DstGeoAddr},             // Destination Address
                         {"%sn", 1, "        Src Network", String_SrcNet},                   // Source Address applied source netmask
                         {"%dn", 1, "        Dst Network", String_DstNet},                   // Destination Address applied source netmask
                         {"%nh", 1, "     Next-hop IP", String_NextHop},                     // Next-hop IP Address
                         {"%nhb", 1, " BGP next-hop IP", String_BGPNextHop},                 // BGP Next-hop IP Address
                         {"%ra", 1, "       Router IP", String_RouterIP},                    // Router IP Address
                         {"%sap", 1, "     Src IP Addr:Port ", String_SrcAddrPort},          // Source Address:Port
                         {"%dap", 1, "     Dst IP Addr:Port ", String_DstAddrPort},          // Destination Address:Port
                         {"%gsap", 1, "     Src IP Addr(..):Port ", String_SrcAddrGeoPort},  // Source Address(geo):Port
                         {"%gdap", 1, "     Dst IP Addr(..):Port ", String_DstAddrGeoPort},  // Destination Address(geo):Port
                         {"%sp", 0, "Src Pt", String_SrcPort},                               // Source Port
                         {"%dp", 0, "Dst Pt", String_DstPort},                               // Destination Port
                         {"%it", 0, "ICMP-T", String_ICMP_type},                             // ICMP type
                         {"%ic", 0, "ICMP-C", String_ICMP_code},                             // ICMP code
                         {"%sas", 0, "Src AS", String_SrcAS},                                // Source AS
                         {"%das", 0, "Dst AS", String_DstAS},                                // Destination AS
                         {"%nas", 0, "Next AS", String_NextAS},                              // Next AS
                         {"%pas", 0, "Prev AS", String_PrevAS},                              // Previous AS
                         {"%in", 0, " Input", String_Input},                                 // Input Interface num
                         {"%inam", 0, " Input interface name", String_InputName},            // Input Interface name
                         {"%out", 0, "Output", String_Output},                               // Output Interface num
                         {"%onam", 0, "Output interface name", String_OutputName},           // Output Interface name
                         {"%pkt", 0, " Packets", String_InPackets},                          // Packets - default input - compat
                         {"%ipkt", 0, "  In Pkt", String_InPackets},                         // In Packets
                         {"%opkt", 0, " Out Pkt", String_OutPackets},                        // Out Packets
                         {"%byt", 0, "   Bytes", String_InBytes},                            // Bytes - default input - compat
                         {"%ibyt", 0, " In Byte", String_InBytes},                           // In Bytes
                         {"%obyt", 0, "Out Byte", String_OutBytes},                          // In Bytes
                         {"%fl", 0, "Flows", String_Flows},                                  // Flows
                         {"%flg", 0, "   Flags", String_Flags},                              // TCP Flags
                         {"%tos", 0, "Tos", String_Tos},                                     // Tos - compat
                         {"%stos", 0, "STos", String_SrcTos},                                // Tos - Src tos
                         {"%dtos", 0, "DTos", String_DstTos},                                // Tos - Dst tos
                         {"%dir", 0, "Dir", String_Dir},                                     // Direction: ingress, egress
                         {"%smk", 0, "SMask", String_SrcMask},                               // Src mask
                         {"%dmk", 0, "DMask", String_DstMask},                               // Dst mask
                         {"%fwd", 0, "Fwd", String_FwdStatus},                               // Forwarding Status
                         {"%bfd", 0, "Bfd", String_BiFlowDir},                               // BiFlow Direction
                         {"%end", 0, "End", String_FlowEndReason},                           // Flow End Reason
                         {"%svln", 0, "SVlan", String_SrcVlan},                              // Src Vlan
                         {"%dvln", 0, "DVlan", String_DstVlan},                              // Dst Vlan
                         {"%ismc", 0, "  In src MAC Addr", String_InSrcMac},                 // Input Src Mac Addr
                         {"%odmc", 0, " Out dst MAC Addr", String_OutDstMac},                // Output Dst Mac Addr
                         {"%idmc", 0, "  In dst MAC Addr", String_InDstMac},                 // Input Dst Mac Addr
                         {"%osmc", 0, " Out src MAC Addr", String_OutSrcMac},                // Output Src Mac Addr
                         {"%mpls1", 0, " MPLS lbl 1 ", String_MPLS_1},                       // MPLS Label 1
                         {"%mpls2", 0, " MPLS lbl 2 ", String_MPLS_2},                       // MPLS Label 2
                         {"%mpls3", 0, " MPLS lbl 3 ", String_MPLS_3},                       // MPLS Label 3
                         {"%mpls4", 0, " MPLS lbl 4 ", String_MPLS_4},                       // MPLS Label 4
                         {"%mpls5", 0, " MPLS lbl 5 ", String_MPLS_5},                       // MPLS Label 5
                         {"%mpls6", 0, " MPLS lbl 6 ", String_MPLS_6},                       // MPLS Label 6
                         {"%mpls7", 0, " MPLS lbl 7 ", String_MPLS_7},                       // MPLS Label 7
                         {"%mpls8", 0, " MPLS lbl 8 ", String_MPLS_8},                       // MPLS Label 8
                         {"%mpls9", 0, " MPLS lbl 9 ", String_MPLS_9},                       // MPLS Label 9
                         {"%mpls10", 0, " MPLS lbl 10", String_MPLS_10},                     // MPLS Label 10
                         {"%mpls", 0,
                          "                                               MPLS labels 1-10                                                  "
                          "                 ",
                          String_MPLSs},  // All MPLS labels
                         //
                         {"%bps", 0, "     bps", String_bps},                          // bps - bits per second
                         {"%pps", 0, "     pps", String_pps},                          // pps - packets per second
                         {"%bpp", 0, "   Bpp", String_bpp},                            // bpp - Bytes per package
                         {"%eng", 0, " engine", String_Engine},                        // Engine Type/ID
                         {"%lbl", 0, "           label", String_Label},                // Flow Label
                         {"%sc", 0, "SC", String_SrcCountry},                          // src IP 2 letter country code
                         {"%dc", 0, "DC", String_DstCountry},                          // dst IP 2 letter country code
                         {"%sloc", 0, "Src IP location info", String_SrcLocation},     // src IP geo location info
                         {"%dloc", 0, "Dst IP location info", String_DstLocation},     // dst IP geo location info
                         {"%n", 0, "", String_NewLine},                                // \n
                         {"%ipl", 0, "", String_inPayload},                            // in payload
                         {"%opl", 0, "", String_outPayload},                           // out payload
                         {"%nbid", 0, "nbar ID", String_nbarID},                       // nbar ID
                         {"%ja3", 0, "                             ja3", String_ja3},  // ja3
                         {"%sni", 0, "sni name", String_sniName},                      // TLS sni Name
                         {"%nbnam", 0, "nbar name", String_nbarName},                  // nbar Name
                         {"%odid", 0, "obsDomainID", String_observationDomainID},      // observation domainID
                         {"%opid", 0, "  obsPointID", String_observationPointID},      // observation pointID
                         {"%vrf", 0, "  I-VRF-ID", String_ivrf},                       // ingress vrf ID - compatible
                         {"%ivrf", 0, "  I-VRF-ID", String_ivrf},                      // ingress vrf ID
                         {"%ivrfnam", 0, "  I-VRF-Name", String_ivrfName},             // ingress vrf name
                         {"%evrf", 0, "  E-VRF-ID", String_evrf},                      // egress vrf ID
                         {"%evrfnam", 0, "  E-VRF-Name", String_evrfName},             // egress vrf name

                         {"%pfifn", 0, "interface", String_pfIfName},  // pflog ifname
                         {"%pfact", 0, "action", String_pfAction},     // pflog action
                         {"%pfrea", 0, "reason", String_pfReason},     // pflog reason
                         {"%pfdir", 0, "dir", String_pfdir},           // pflog direction
                         {"%pfrule", 0, "rule", String_pfrule},        // pflog rule

#ifdef NSEL
                         // NSEL specifics
                         {"%nfc", 0, "   Conn-ID", String_nfc},                            // NSEL connection ID
                         {"%tevt", 0, "Event time             ", String_EventTime},        // NSEL Flow start time
                         {"%evt", 0, " Event", String_evt},                                // NSEL event
                         {"%xevt", 0, " XEvent", String_xevt},                             // NSEL xevent
                         {"%sgt", 0, "  SGT  ", String_sgt},                               // NSEL xevent
                         {"%msec", 0, "   Event Time", String_msecEvent},                  // NSEL event time in msec
                         {"%iacl", 0, "Ingress ACL                     ", String_iacl},    // NSEL ingress ACL
                         {"%eacl", 0, "Egress ACL                      ", String_eacl},    // NSEL egress ACL
                         {"%xsa", 0, "   X-late Src IP", String_xlateSrcAddr},             // NSEL XLATE src IP
                         {"%xda", 0, "   X-late Dst IP", String_xlateDstAddr},             // NSEL XLATE dst IP
                         {"%xsp", 0, "XsPort", String_xlateSrcPort},                       // NSEL XLATE src port
                         {"%xdp", 0, "XdPort", String_xlateDstPort},                       // NSEL SLATE dst port
                         {"%xsap", 1, "   X-Src IP Addr:Port ", String_xlateSrcAddrPort},  // Xlate Source Address:Port
                         {"%xdap", 1, "   X-Dst IP Addr:Port ", String_xlateDstAddrPort},  // Xlate Destination Address:Port
                         {"%uname", 0, "UserName", String_userName},                       // NSEL user name

                         // NEL
                         // for v.1.6.10 compatibility, keep NEL specific addr/port format tokens
                         {"%nevt", 0, " Event", String_evt},                               // NAT event
                         {"%nsa", 0, "   X-late Src IP", String_xlateSrcAddr},             // NAT XLATE src IP
                         {"%nda", 0, "   X-late Dst IP", String_xlateDstAddr},             // NAT XLATE dst IP
                         {"%nsp", 0, "XsPort", String_xlateSrcPort},                       // NAT XLATE src port
                         {"%ndp", 0, "XdPort", String_xlateDstPort},                       // NAT SLATE dst port
                         {"%nsap", 1, "   X-Src IP Addr:Port ", String_xlateSrcAddrPort},  // NAT Xlate Source Address:Port
                         {"%ndap", 1, "   X-Dst IP Addr:Port ", String_xlateDstAddrPort},  // NAT Xlate Destination Address:Port

                         // Port block allocation
                         {"%pbstart", 0, "Pb-Start", String_PortBlockStart},  // Port block start
                         {"%pbend", 0, "Pb-End", String_PortBlockEnd},        // Port block end
                         {"%pbstep", 0, "Pb-Step", String_PortBlockStep},     // Port block step
                         {"%pbsize", 0, "Pb-Size", String_PortBlockSize},     // Port block size
#endif

                         // latency extension for nfpcapd and nprobe
                         {"%cl", 0, "C Latency", String_ClientLatency},  // client latency
                         {"%sl", 0, "S latency", String_ServerLatency},  // server latency
                         {"%al", 0, "A latency", String_AppLatency},     // app latency

                         {NULL, 0, NULL, NULL}};

/* each of the tokens above must not generate output strings larger than this */
#define MAX_STRING_LENGTH 256

#include "applybits_inline.c"

/* functions */

void Setv6Mode(int mode) { long_v6 += mode; }

int Getv6Mode(void) { return long_v6; }

void fmt_record(FILE *stream, void *record, int tag) {
    master_record_t *r = (master_record_t *)record;

    // if this flow is a tunnel, add a flow line with the tunnel IPs
    if (r->tun_ip_version) {
        master_record_t _r = {0};
        _r.proto = r->tun_proto;
        _r.V6.srcaddr[0] = r->tun_src_ip.V6[0];
        _r.V6.srcaddr[1] = r->tun_src_ip.V6[1];
        _r.V6.dstaddr[0] = r->tun_dst_ip.V6[0];
        _r.V6.dstaddr[1] = r->tun_dst_ip.V6[1];
        _r.msecFirst = r->msecFirst;
        _r.msecLast = r->msecLast;
        if (r->tun_ip_version == 6) _r.mflags = V3_FLAG_IPV6_ADDR;
        fmt_record(stream, (void *)&_r, tag);
    }

    do_tag = tag;
    tag_string[0] = do_tag ? TAG_CHAR : '\0';
    tag_string[1] = '\0';

    duration = (r->msecLast - r->msecFirst) / 1000.0;
    for (int i = 0; i < token_index; i++) {
        if (token_list[i].string_function) {
            token_list[i].string_function(stream, r);
        }
        if (token_list[i].string_buffer) {
            fprintf(stream, "%s", token_list[i].string_buffer);
        }
    }
    fprintf(stream, "\n");

}  // End of fmt_record

void fmt_prolog(void) {
    // header
    printf("%s\n", header_string);
}  // End of fmt_prolog

void fmt_epilog(void) {
    // empty
}  // End of fmt_epilog

static void InitFormatParser(void) {
    max_format_index = max_token_index = BLOCK_SIZE;
    format_list = (char **)calloc(1, max_format_index * sizeof(char *));
    token_list = (struct token_list_s *)calloc(1, max_token_index * sizeof(struct token_list_s));
    if (!format_list || !token_list) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        exit(255);
    }

}  // End of InitFormatParser

static void AddToken(int index, char *s) {
    if (token_index >= max_token_index) {  // no slot available - expand table
        max_token_index += BLOCK_SIZE;
        token_list = (struct token_list_s *)realloc(token_list, max_token_index * sizeof(struct token_list_s));
        if (!token_list) {
            LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            exit(255);
        }
    }

    if (s == NULL) {
        token_list[token_index].string_function = format_token_list[index].string_function;
        token_list[token_index].string_buffer = s;
    } else {
        token_list[token_index].string_function = NULL;
        token_list[token_index].string_buffer = s;
    }
    token_index++;

}  // End of AddToken

/*
 * expand predefined print format into given format, such as -o fmt "%line %ipl"
 */
static char *RecursiveReplace(char *format, printmap_t *printmap) {
    int i = 0;

    while (printmap[i].printmode) {
        char *s, *r;
        // check for printmode string
        s = strstr(format, printmap[i].printmode);
        if (s && printmap[i].Format && s != format) {
            int len = strlen(printmap[i].printmode);
            if (!isalpha((int)s[len])) {
                s--;
                if (s[0] == '%') {
                    int newlen = strlen(format) + strlen(printmap[i].Format);
                    r = malloc(newlen);
                    if (!r) {
                        LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
                        exit(255);
                    }
                    s[0] = '\0';
                    snprintf(r, newlen, "%s%s%s", format, printmap[i].Format, &(s[len + 1]));
                    r[newlen - 1] = '\0';
                    free(format);
                    format = r;
                }
            }
        }
        i++;
    }

    return format;

}  // End of RecursiveReplace

int ParseOutputFormat(char *format, int plain_numbers, printmap_t *printmap) {
    char *c, *s, *h;
    int i, remaining;

    printPlain = plain_numbers;

    InitFormatParser();

    s = strdup(format);
    if (!s) {
        LogError("malloc() allocation error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }
    s = RecursiveReplace(s, printmap);
    c = s;

    h = header_string;
    *h = '\0';
    while (*c) {
        if (*c == '%') {  // it's a token from format_token_list
            i = 0;
            remaining = strlen(c);
            while (format_token_list[i].token) {  // sweep through the list
                int len = strlen(format_token_list[i].token);

                // a token is separated by either a space, another token, or end of string
                if (remaining >= len && !isalpha((int)c[len])) {
                    // separator found a expected position
                    char p = c[len];  // save separator;
                    c[len] = '\0';
                    if (strncmp(format_token_list[i].token, c, len) == 0) {  // token found
                        AddToken(i, NULL);
                        if (long_v6 && format_token_list[i].is_address)
                            snprintf(h, STRINGSIZE - 1 - strlen(header_string), "%23s%s", "", format_token_list[i].header);
                        else
                            snprintf(h, STRINGSIZE - 1 - strlen(header_string), "%s", format_token_list[i].header);
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
            if (format_token_list[i].token == NULL) {
                LogError("Output format parse error at: %s", c);
                free(s);
                return 0;
            }
        } else {  // it's a static string
            /* a static string goes up to next '%' or end of string */
            char *p = strchr(c, '%');
            char printFormat[32];
            if (p) {
                // p points to next '%' token
                *p = '\0';
                AddToken(0, strdup(c));
                snprintf(printFormat, 31, "%%%zus", strlen(c));
                printFormat[31] = '\0';
                snprintf(h, STRINGSIZE - 1 - strlen(header_string), printFormat, "");
                h += strlen(h);
                *p = '%';
                c = p;
            } else {
                // static string up to end of format string
                AddToken(0, strdup(c));
                snprintf(printFormat, 31, "%%%zus", strlen(c));
                printFormat[31] = '\0';
                snprintf(h, STRINGSIZE - 1 - strlen(header_string), printFormat, "");
                h += strlen(h);
                *c = '\0';
            }
        }
    }

    free(s);
    return 1;

}  // End of ParseOutputFormat

static char *ICMP_Port_decode(master_record_t *r) {
#define ICMPSTRLEN 16
    static char icmp_string[ICMPSTRLEN];

    if (r->proto == IPPROTO_ICMP || r->proto == IPPROTO_ICMPV6) {  // ICMP
        snprintf(icmp_string, ICMPSTRLEN - 1, "%u.%u", r->icmpType, r->icmpCode);
    } else {  // dst port
        snprintf(icmp_string, ICMPSTRLEN - 1, "%u", r->dstPort);
    }
    icmp_string[ICMPSTRLEN - 1] = '\0';

    return icmp_string;

}  // End of ICMP_Port_decode

/* functions, which create the individual strings for the output line */
static void String_Version(FILE *stream, master_record_t *r) {
    char *type;
    if (TestFlag(r->flags, V3_FLAG_EVENT)) {
        type = "EVT";
        fprintf(stream, "%s%u", type, r->nfversion);
    } else {
        if (r->nfversion != 0) {
            if (r->nfversion & 0x80) {
                type = "Sv";
            } else if (r->nfversion & 0x40) {
                type = "Pv";
            } else {
                type = "Nv";
            }
            fprintf(stream, "%s%u", type, r->nfversion & 0x0F);
        } else {
            // compat with previous versions
            type = "FLO";
            fprintf(stream, "%s", type);
        }
    }

}  // End of String_Version

static void String_FlowCount(FILE *stream, master_record_t *r) { fprintf(stream, "%5u", r->flowCount); }  // End of String_FlowCount

static void String_FirstSeen(FILE *stream, master_record_t *r) {
    time_t tt;
    struct tm *ts;
    char s[128];

    tt = r->msecFirst / 1000LL;
    ts = localtime(&tt);
    strftime(s, 128, "%Y-%m-%d %H:%M:%S", ts);
    s[127] = '\0';
    fprintf(stream, "%s.%03u", s, (unsigned)(r->msecFirst % 1000LL));

}  // End of String_FirstSeen

static void String_LastSeen(FILE *stream, master_record_t *r) {
    time_t tt;
    struct tm *ts;
    char s[128];

    tt = r->msecLast / 1000LL;
    ts = localtime(&tt);
    strftime(s, 128, "%Y-%m-%d %H:%M:%S", ts);
    s[127] = '\0';
    fprintf(stream, "%s.%03u", s, (unsigned)(r->msecLast % 1000LL));

}  // End of String_LastSeen

static void String_Received(FILE *stream, master_record_t *r) {
    time_t tt;
    struct tm *ts;
    char s[128];

    tt = r->msecReceived / 1000LL;
    ts = localtime(&tt);
    strftime(s, 128, "%Y-%m-%d %H:%M:%S", ts);
    s[127] = '\0';
    fprintf(stream, "%s.%03llu", s, r->msecReceived % 1000LL);

}  // End of String_Received

static void String_ReceivedRaw(FILE *stream, master_record_t *r) {
    /* snprintf does write \0, and the max is INCL the terminating \0 */
    fprintf(stream, "%.3f", r->msecReceived / 1000.0);

}  // End of String_ReceivedRaw

static void String_FirstSeenRaw(FILE *stream, master_record_t *r) {
    /* snprintf does write \0, and the max is INCL the terminating \0 */
    fprintf(stream, "%llu.%03llu", r->msecFirst / 1000LL, r->msecFirst % 1000LL);

}  // End of String_FirstSeenRaw

static void String_LastSeenRaw(FILE *stream, master_record_t *r) {
    /* snprintf does write \0, and the max is INCL the terminating \0 */
    fprintf(stream, "%llu.%03llu", r->msecLast / 1000LL, r->msecLast % 1000LL);

}  // End of String_LastSeenRaw

static void String_inPayload(FILE *stream, master_record_t *r) {
    int max = r->inPayloadLength > 256 ? 256 : r->inPayloadLength;
    if (r->srcPort == 53 || r->dstPort == 53) {
        content_decode_dns(stream, r->proto, (uint8_t *)r->inPayload, r->inPayloadLength);
    }
    int ascii = 1;
    for (int i = 0; i < max; i++) {
        if ((r->inPayload[i] < ' ' || r->inPayload[i] > '~') && r->inPayload[i] != '\n' && r->inPayload[i] != '\r' && r->inPayload[i] != 0x09) {
            ascii = 0;
            break;
        }
    }
    if (ascii) {
        fprintf(stream, "%.*s\n", max, r->inPayload);
    } else {
        DumpHex(stream, r->inPayload, max);
    }

}  // End of String_inPayload

static void String_outPayload(FILE *stream, master_record_t *r) {
    int max = r->inPayloadLength > 256 ? 256 : r->inPayloadLength;
    if (r->srcPort == 53 || r->dstPort == 53) {
        content_decode_dns(stream, r->proto, (uint8_t *)r->outPayload, r->outPayloadLength);
    }
    int ascii = 1;
    for (int i = 0; i < max; i++) {
        if ((r->outPayload[i] < ' ' || r->outPayload[i] > '~') && r->outPayload[i] != '\n' && r->outPayload[i] != '\r' && r->outPayload[i] != 0x09) {
            ascii = 0;
            break;
        }
    }
    if (ascii) {
        fprintf(stream, "%.*s\n", max, r->outPayload);
    } else {
        DumpHex(stream, r->outPayload, max);
    }

}  // End of String_outPayload

static void String_nbarID(FILE *stream, master_record_t *r) {
    union {
        uint8_t val8[4];
        uint32_t val32;
    } pen;

    if (r->nbarAppID[0] == 20) {  // PEN - private enterprise number
        pen.val8[0] = r->nbarAppID[4];
        pen.val8[1] = r->nbarAppID[3];
        pen.val8[2] = r->nbarAppID[2];
        pen.val8[3] = r->nbarAppID[1];

        int selector = 0;
        int length = r->nbarAppIDlen;
        int index = 5;
        while (index < length) {
            selector = (selector << 8) | r->nbarAppID[index];
            index++;
        }
        fprintf(stream, "%2u..%u..%u", r->nbarAppID[0], pen.val32, selector);
    } else {
        int selector = 0;
        int length = r->nbarAppIDlen;
        int index = 1;
        while (index < length) {
            selector = (selector << 8) | r->nbarAppID[index];
            index++;
        }
        fprintf(stream, "%2u..%u", r->nbarAppID[0], selector);
    }

}  // End of String_nbarID

static void String_nbarName(FILE *stream, master_record_t *r) {
    char *name = GetNbarInfo(r->nbarAppID, r->nbarAppIDlen);
    if (name == NULL) {
        name = "<no info>";
    }
    fprintf(stream, "%s", name);

}  // End of String_nbarName

static void String_ja3(FILE *stream, master_record_t *r) {
    uint8_t zero[16] = {0};
    if (memcmp(r->ja3, zero, 16) == 0) {
        if (r->inPayloadLength == 0) {
            fprintf(stream, "%32s", "");
            return;
        } else {
            ja3_t *ja3 = ja3Process((uint8_t *)r->inPayload, r->inPayloadLength);
            if (ja3) {
                memcpy((void *)r->ja3, ja3->md5Hash, 16);
                ja3Free(ja3);
            } else {
                fprintf(stream, "%32s", "ja3 error");
                return;
            }
        }
    }

    char out[33];
    int i, j;
    for (i = 0, j = 0; i < 16; i++, j += 2) {
        uint8_t ln = r->ja3[i] & 0xF;
        uint8_t hn = (r->ja3[i] >> 4) & 0xF;
        out[j + 1] = ln <= 9 ? ln + '0' : ln + 'a' - 10;
        out[j] = hn <= 9 ? hn + '0' : hn + 'a' - 10;
    }
    out[32] = '\0';
    fprintf(stream, "%32s", out);

}  // End of String_ja3

static void String_sniName(FILE *stream, master_record_t *r) {
    if (r->inPayloadLength == 0) {
        fprintf(stream, "%6s", "");
        return;
    } else {
        ja3_t *ja3 = ja3Process((uint8_t *)r->inPayload, r->inPayloadLength);
        if (ja3) {
            fprintf(stream, "%6s", ja3->sniName);
            ja3Free(ja3);
        } else {
            fprintf(stream, "%6s", "");
        }
    }
}  // End of String_sniName

static void String_observationDomainID(FILE *stream, master_record_t *r) {
    fprintf(stream, "0x%09x", r->observationDomainID);
}  // End of String_observationDomainID

static void String_observationPointID(FILE *stream, master_record_t *r) {
    fprintf(stream, "0x%010llx", (long long unsigned)r->observationPointID);
}  // End of String_observationPointID

static void String_NewLine(FILE *stream, master_record_t *r) { fprintf(stream, "\n"); }  // End of String_NewLine

#ifdef NSEL
static void String_EventTime(FILE *stream, master_record_t *r) {
    time_t tt;
    struct tm *ts;
    char s[128];

    tt = r->msecEvent / 1000LL;
    ts = localtime(&tt);
    strftime(s, 128, "%Y-%m-%d %H:%M:%S", ts);
    s[127] = '\0';
    fprintf(stream, "%s.%03llu", s, r->msecEvent % 1000LL);

}  // End of String_EventTime
#endif

static void String_Duration(FILE *stream, master_record_t *r) {
    if (printPlain) {
        fprintf(stream, "%16.3f", duration);
    } else {
        char *s = DurationString(duration);
        fprintf(stream, "%s", s);
    }
}  // End of String_Duration

static void String_Duration_Seconds(FILE *stream, master_record_t *r) { fprintf(stream, "%16.3f", duration); }  // End of String_Duration_Seconds

static void String_Protocol(FILE *stream, master_record_t *r) {
    fprintf(stream, "%-5s", ProtoString(r->proto, printPlain));
}  // End of String_Protocol

static void String_SrcAddr(FILE *stream, master_record_t *r) {
    char tmp_str[IP_STRING_LEN];

    tmp_str[0] = 0;
    if ((r->mflags & V3_FLAG_IPV6_ADDR) != 0) {  // IPv6
        uint64_t ip[2];

        ip[0] = htonll(r->V6.srcaddr[0]);
        ip[1] = htonll(r->V6.srcaddr[1]);
        inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
        if (!long_v6) {
            CondenseV6(tmp_str);
        }
    } else {  // IPv4
        uint32_t ip;
        ip = htonl(r->V4.srcaddr);
        inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
    }
    tmp_str[IP_STRING_LEN - 1] = 0;
    if (long_v6)
        fprintf(stream, "%s%39s", tag_string, tmp_str);
    else
        fprintf(stream, "%s%16s", tag_string, tmp_str);

}  // End of String_SrcAddr

static void String_SrcGeoAddr(FILE *stream, master_record_t *r) {
    char tmp_str[IP_STRING_LEN];

    tmp_str[0] = 0;
    if ((r->mflags & V3_FLAG_IPV6_ADDR) != 0) {  // IPv6
        uint64_t ip[2];

        ip[0] = htonll(r->V6.srcaddr[0]);
        ip[1] = htonll(r->V6.srcaddr[1]);
        inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
        if (!long_v6) {
            CondenseV6(tmp_str);
        }
    } else {  // IPv4
        uint32_t ip;
        ip = htonl(r->V4.srcaddr);
        inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
    }
    tmp_str[IP_STRING_LEN - 1] = 0;
    if (TestFlag(r->mflags, V3_FLAG_ENRICHED) == 0) LookupCountry(r->V6.srcaddr, r->src_geo);

    if (long_v6)
        fprintf(stream, "%s%39s(%s)", tag_string, tmp_str, r->src_geo);
    else
        fprintf(stream, "%s%16s(%s)", tag_string, tmp_str, r->src_geo);

}  // End of String_SrcGeoAddr

static void String_SrcAddrPort(FILE *stream, master_record_t *r) {
    char tmp_str[IP_STRING_LEN], portchar;

    tmp_str[0] = 0;
    if (TestFlag(r->mflags, V3_FLAG_IPV6_ADDR)) {  // IPv6
        uint64_t ip[2];

        ip[0] = htonll(r->V6.srcaddr[0]);
        ip[1] = htonll(r->V6.srcaddr[1]);
        inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
        if (!long_v6) {
            CondenseV6(tmp_str);
        }
        portchar = '.';
    } else {  // IPv4
        uint32_t ip;
        ip = htonl(r->V4.srcaddr);
        inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
        portchar = ':';
    }
    tmp_str[IP_STRING_LEN - 1] = 0;

    if (long_v6)
        fprintf(stream, "%s%39s%c%-5i", tag_string, tmp_str, portchar, r->srcPort);
    else
        fprintf(stream, "%s%16s%c%-5i", tag_string, tmp_str, portchar, r->srcPort);

}  // End of String_SrcAddrPort

static void String_SrcAddrGeoPort(FILE *stream, master_record_t *r) {
    char tmp_str[IP_STRING_LEN], portchar;

    tmp_str[0] = 0;
    if (TestFlag(r->mflags, V3_FLAG_IPV6_ADDR)) {  // IPv6
        uint64_t ip[2];

        ip[0] = htonll(r->V6.srcaddr[0]);
        ip[1] = htonll(r->V6.srcaddr[1]);
        inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
        if (!long_v6) {
            CondenseV6(tmp_str);
        }
        portchar = '.';
    } else {  // IPv4
        uint32_t ip;
        ip = htonl(r->V4.srcaddr);
        inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
        portchar = ':';
    }
    tmp_str[IP_STRING_LEN - 1] = 0;
    if (TestFlag(r->mflags, V3_FLAG_ENRICHED) == 0) LookupCountry(r->V6.srcaddr, r->src_geo);

    if (long_v6)
        fprintf(stream, "%s%39s(%s)%c%-5i", tag_string, tmp_str, r->src_geo, portchar, r->srcPort);
    else
        fprintf(stream, "%s%16s(%s)%c%-5i", tag_string, tmp_str, r->src_geo, portchar, r->srcPort);

}  // End of String_SrcAddrGeoPort

static void String_DstAddr(FILE *stream, master_record_t *r) {
    char tmp_str[IP_STRING_LEN];

    tmp_str[0] = 0;
    if (TestFlag(r->mflags, V3_FLAG_IPV6_ADDR)) {  // IPv6
        uint64_t ip[2];

        ip[0] = htonll(r->V6.dstaddr[0]);
        ip[1] = htonll(r->V6.dstaddr[1]);
        inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
        if (!long_v6) {
            CondenseV6(tmp_str);
        }
    } else {  // IPv4
        uint32_t ip;
        ip = htonl(r->V4.dstaddr);
        inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
    }
    tmp_str[IP_STRING_LEN - 1] = 0;
    if (long_v6)
        fprintf(stream, "%s%39s", tag_string, tmp_str);
    else
        fprintf(stream, "%s%16s", tag_string, tmp_str);

}  // End of String_DstAddr

static void String_DstGeoAddr(FILE *stream, master_record_t *r) {
    char tmp_str[IP_STRING_LEN];

    tmp_str[0] = 0;
    if (TestFlag(r->mflags, V3_FLAG_IPV6_ADDR)) {  // IPv6
        uint64_t ip[2];

        ip[0] = htonll(r->V6.dstaddr[0]);
        ip[1] = htonll(r->V6.dstaddr[1]);
        inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
        if (!long_v6) {
            CondenseV6(tmp_str);
        }
    } else {  // IPv4
        uint32_t ip;
        ip = htonl(r->V4.dstaddr);
        inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
    }
    tmp_str[IP_STRING_LEN - 1] = 0;
    if (TestFlag(r->mflags, V3_FLAG_ENRICHED) == 0) LookupCountry(r->V6.dstaddr, r->dst_geo);

    if (long_v6)
        fprintf(stream, "%s%39s(%s)", tag_string, tmp_str, r->dst_geo);
    else
        fprintf(stream, "%s%16s(%s)", tag_string, tmp_str, r->dst_geo);

}  // End of String_DstGeoAddr

static void String_NextHop(FILE *stream, master_record_t *r) {
    char tmp_str[IP_STRING_LEN];

    tmp_str[0] = 0;
    if (TestFlag(r->mflags, V3_FLAG_IPV6_NH)) {  // IPv6
        uint64_t ip[2];

        ip[0] = htonll(r->ip_nexthop.V6[0]);
        ip[1] = htonll(r->ip_nexthop.V6[1]);
        inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
        if (!long_v6) {
            CondenseV6(tmp_str);
        }
    } else {  // IPv4
        uint32_t ip;
        ip = htonl(r->ip_nexthop.V4);
        inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
    }
    tmp_str[IP_STRING_LEN - 1] = 0;
    if (long_v6)
        fprintf(stream, "%s%39s", tag_string, tmp_str);
    else
        fprintf(stream, "%s%16s", tag_string, tmp_str);

}  // End of String_NextHop

static void String_BGPNextHop(FILE *stream, master_record_t *r) {
    char tmp_str[IP_STRING_LEN];

    tmp_str[0] = 0;
    if (TestFlag(r->mflags, V3_FLAG_IPV6_NHB)) {  // IPv6
        uint64_t ip[2];

        ip[0] = htonll(r->bgp_nexthop.V6[0]);
        ip[1] = htonll(r->bgp_nexthop.V6[1]);
        inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
        if (!long_v6) {
            CondenseV6(tmp_str);
        }
    } else {  // IPv4
        uint32_t ip;
        ip = htonl(r->bgp_nexthop.V4);
        inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
    }
    tmp_str[IP_STRING_LEN - 1] = 0;
    if (long_v6)
        fprintf(stream, "%s%39s", tag_string, tmp_str);
    else
        fprintf(stream, "%s%16s", tag_string, tmp_str);

}  // End of String_NextHop

static void String_RouterIP(FILE *stream, master_record_t *r) {
    char tmp_str[IP_STRING_LEN];

    tmp_str[0] = 0;
    if (TestFlag(r->mflags, V3_FLAG_IPV6_EXP)) {  // IPv6
        uint64_t ip[2];

        ip[0] = htonll(r->ip_router.V6[0]);
        ip[1] = htonll(r->ip_router.V6[1]);
        inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
        if (!long_v6) {
            CondenseV6(tmp_str);
        }
    } else {  // IPv4
        uint32_t ip;
        ip = htonl(r->ip_router.V4);
        inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
    }
    tmp_str[IP_STRING_LEN - 1] = 0;
    if (long_v6)
        fprintf(stream, "%s%39s", tag_string, tmp_str);
    else
        fprintf(stream, "%s%16s", tag_string, tmp_str);

}  // End of String_RouterIP

static void String_DstAddrPort(FILE *stream, master_record_t *r) {
    char tmp_str[IP_STRING_LEN], portchar;

    tmp_str[0] = 0;
    if (TestFlag(r->mflags, V3_FLAG_IPV6_ADDR)) {  // IPv6
        uint64_t ip[2];

        ip[0] = htonll(r->V6.dstaddr[0]);
        ip[1] = htonll(r->V6.dstaddr[1]);
        inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
        if (!long_v6) {
            CondenseV6(tmp_str);
        }
        portchar = '.';
    } else {  // IPv4
        uint32_t ip;
        ip = htonl(r->V4.dstaddr);
        inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
        portchar = ':';
    }
    tmp_str[IP_STRING_LEN - 1] = 0;

    if (long_v6)
        fprintf(stream, "%s%39s%c%-5s", tag_string, tmp_str, portchar, ICMP_Port_decode(r));
    else
        fprintf(stream, "%s%16s%c%-5s", tag_string, tmp_str, portchar, ICMP_Port_decode(r));

}  // End of String_DstAddrPort

static void String_DstAddrGeoPort(FILE *stream, master_record_t *r) {
    char tmp_str[IP_STRING_LEN], portchar;

    tmp_str[0] = 0;
    if (TestFlag(r->mflags, V3_FLAG_IPV6_ADDR)) {  // IPv6
        uint64_t ip[2];

        ip[0] = htonll(r->V6.dstaddr[0]);
        ip[1] = htonll(r->V6.dstaddr[1]);
        inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
        if (!long_v6) {
            CondenseV6(tmp_str);
        }
        portchar = '.';
    } else {  // IPv4
        uint32_t ip;
        ip = htonl(r->V4.dstaddr);
        inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
        portchar = ':';
    }
    tmp_str[IP_STRING_LEN - 1] = 0;
    if (TestFlag(r->mflags, V3_FLAG_ENRICHED) == 0) LookupCountry(r->V6.dstaddr, r->dst_geo);

    if (long_v6)
        fprintf(stream, "%s%39s(%s)%c%-5s", tag_string, tmp_str, r->dst_geo, portchar, ICMP_Port_decode(r));
    else
        fprintf(stream, "%s%16s(%s)%c%-5s", tag_string, tmp_str, r->dst_geo, portchar, ICMP_Port_decode(r));

}  // End of String_DstAddrGeoPort

static void String_SrcNet(FILE *stream, master_record_t *r) {
    char tmp_str[IP_STRING_LEN];

    ApplyNetMaskBits(r, 1);

    tmp_str[0] = 0;
    if (TestFlag(r->mflags, V3_FLAG_IPV6_ADDR)) {  // IPv6
        uint64_t ip[2];

        ip[0] = htonll(r->V6.srcaddr[0]);
        ip[1] = htonll(r->V6.srcaddr[1]);
        inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
        if (!long_v6) {
            CondenseV6(tmp_str);
        }
    } else {  // IPv4
        uint32_t ip;
        ip = htonl(r->V4.srcaddr);
        inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
    }
    tmp_str[IP_STRING_LEN - 1] = 0;
    if (long_v6)
        fprintf(stream, "%s%39s/%-2u", tag_string, tmp_str, r->src_mask);
    else
        fprintf(stream, "%s%16s/%-2u", tag_string, tmp_str, r->src_mask);

}  // End of String_SrcNet

static void String_DstNet(FILE *stream, master_record_t *r) {
    char tmp_str[IP_STRING_LEN];

    ApplyNetMaskBits(r, 2);

    tmp_str[0] = 0;
    if (TestFlag(r->mflags, V3_FLAG_IPV6_ADDR)) {  // IPv6
        uint64_t ip[2];

        ip[0] = htonll(r->V6.dstaddr[0]);
        ip[1] = htonll(r->V6.dstaddr[1]);
        inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
        if (!long_v6) {
            CondenseV6(tmp_str);
        }
    } else {  // IPv4
        uint32_t ip;
        ip = htonl(r->V4.dstaddr);
        inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
    }
    tmp_str[IP_STRING_LEN - 1] = 0;
    if (long_v6)
        fprintf(stream, "%s%39s/%-2u", tag_string, tmp_str, r->dst_mask);
    else
        fprintf(stream, "%s%16s/%-2u", tag_string, tmp_str, r->dst_mask);

}  // End of String_DstNet

static void String_SrcPort(FILE *stream, master_record_t *r) { fprintf(stream, "%6u", r->srcPort); }  // End of String_SrcPort

static void String_DstPort(FILE *stream, master_record_t *r) { fprintf(stream, "%6s", ICMP_Port_decode(r)); }  // End of String_DstPort

static void String_ICMP_type(FILE *stream, master_record_t *r) {
    // Force printing type regardless of protocol
    fprintf(stream, "%6u", r->icmpType);
}  // End of String_ICMP_type

static void String_ICMP_code(FILE *stream, master_record_t *r) {
    // Force printing code regardless of protocol
    fprintf(stream, "%6u", r->icmpCode);
}  // End of String_ICMP_code

static void String_SrcAS(FILE *stream, master_record_t *r) {
    if (r->srcas == 0) r->srcas = LookupAS(r->V6.srcaddr);

    fprintf(stream, "%6u", r->srcas);
}  // End of String_SrcAS

static void String_DstAS(FILE *stream, master_record_t *r) {
    if (r->dstas == 0) r->dstas = LookupAS(r->V6.dstaddr);

    fprintf(stream, "%6u", r->dstas);
}  // End of String_DstAS

static void String_NextAS(FILE *stream, master_record_t *r) { fprintf(stream, " %6u", r->bgpNextAdjacentAS); }  // End of String_NextAS

static void String_PrevAS(FILE *stream, master_record_t *r) { fprintf(stream, " %6u", r->bgpPrevAdjacentAS); }  // End of String_PrevAS

static void String_Input(FILE *stream, master_record_t *r) { fprintf(stream, "%6u", r->input); }  // End of String_Input

static void String_InputName(FILE *stream, master_record_t *r) {
    char ifName[128];
    fprintf(stream, "%s", GetIfName(r->input, ifName, sizeof(ifName)));
}  // End of String_InputName

static void String_Output(FILE *stream, master_record_t *r) { fprintf(stream, "%6u", r->output); }  // End of String_Output

static void String_OutputName(FILE *stream, master_record_t *r) {
    char ifName[128];
    fprintf(stream, "%s", GetIfName(r->output, ifName, sizeof(ifName)));
}  // End of String_OutputName

static void String_InPackets(FILE *stream, master_record_t *r) {
    char s[NUMBER_STRING_SIZE];

    format_number(r->inPackets, s, printPlain, FIXED_WIDTH);
    fprintf(stream, "%8s", s);

}  // End of String_InPackets

static void String_OutPackets(FILE *stream, master_record_t *r) {
    char s[NUMBER_STRING_SIZE];

    format_number(r->out_pkts, s, printPlain, FIXED_WIDTH);
    fprintf(stream, "%8s", s);

}  // End of String_OutPackets

static void String_InBytes(FILE *stream, master_record_t *r) {
    char s[NUMBER_STRING_SIZE];

    format_number(r->inBytes, s, printPlain, FIXED_WIDTH);
    fprintf(stream, "%8s", s);

}  // End of String_InBytes

static void String_OutBytes(FILE *stream, master_record_t *r) {
    char s[NUMBER_STRING_SIZE];

    format_number(r->out_bytes, s, printPlain, FIXED_WIDTH);
    fprintf(stream, "%8s", s);

}  // End of String_OutBytes

static void String_Flows(FILE *stream, master_record_t *r) {
    // fprintf(stream ,"%5llu", r->aggr_flows ? (unsigned long long)r->aggr_flows : 1 );
    fprintf(stream, "%5llu", (unsigned long long)r->aggr_flows);

}  // End of String_Flows

static void String_Tos(FILE *stream, master_record_t *r) { fprintf(stream, "%3u", r->tos); }  // End of String_Tos

static void String_SrcTos(FILE *stream, master_record_t *r) { fprintf(stream, "%4u", r->tos); }  // End of String_SrcTos

static void String_DstTos(FILE *stream, master_record_t *r) { fprintf(stream, "%4u", r->dst_tos); }  // End of String_DstTos

static void String_SrcMask(FILE *stream, master_record_t *r) { fprintf(stream, "%5u", r->src_mask); }  // End of String_SrcMask

static void String_DstMask(FILE *stream, master_record_t *r) { fprintf(stream, "%5u", r->dst_mask); }  // End of String_DstMask

static void String_SrcVlan(FILE *stream, master_record_t *r) { fprintf(stream, "%5u", r->src_vlan); }  // End of String_SrcVlan

static void String_DstVlan(FILE *stream, master_record_t *r) { fprintf(stream, "%5u", r->dst_vlan); }  // End of String_DstVlan

static void String_Dir(FILE *stream, master_record_t *r) { fprintf(stream, "%3c", r->dir ? 'E' : 'I'); }  // End of String_Dir

static void String_FwdStatus(FILE *stream, master_record_t *r) { fprintf(stream, "%3u", r->fwd_status); }  // End of String_FwdStatus

static void String_BiFlowDir(FILE *stream, master_record_t *r) { fprintf(stream, "%3u", r->biFlowDir); }  // End of String_BiFlowDir

static void String_FlowEndReason(FILE *stream, master_record_t *r) { fprintf(stream, "%3u", r->flowEndReason); }  // End of String_FlowEndReason

static void String_Flags(FILE *stream, master_record_t *r) {
    fprintf(stream, "%8s", FlagsString(r->proto == IPPROTO_TCP ? r->tcp_flags : 0));

}  // End of String_Flags

static void String_InSrcMac(FILE *stream, master_record_t *r) {
    int i;
    uint8_t mac[6];

    for (i = 0; i < 6; i++) {
        mac[i] = (r->in_src_mac >> (i * 8)) & 0xFF;
    }
    fprintf(stream, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);

}  // End of String_InSrcMac

static void String_OutDstMac(FILE *stream, master_record_t *r) {
    int i;
    uint8_t mac[6];

    for (i = 0; i < 6; i++) {
        mac[i] = (r->out_dst_mac >> (i * 8)) & 0xFF;
    }
    fprintf(stream, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);

}  // End of String_OutDstMac

static void String_InDstMac(FILE *stream, master_record_t *r) {
    int i;
    uint8_t mac[6];

    for (i = 0; i < 6; i++) {
        mac[i] = (r->in_dst_mac >> (i * 8)) & 0xFF;
    }
    fprintf(stream, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);

}  // End of String_InDstMac

static void String_OutSrcMac(FILE *stream, master_record_t *r) {
    int i;
    uint8_t mac[6];

    for (i = 0; i < 6; i++) {
        mac[i] = (r->out_src_mac >> (i * 8)) & 0xFF;
    }
    fprintf(stream, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);

}  // End of String_OutSrcMac

static void String_MPLS_1(FILE *stream, master_record_t *r) {
    fprintf(stream, "%8u-%1u-%1u", r->mpls_label[0] >> 4, (r->mpls_label[0] & 0xF) >> 1, r->mpls_label[0] & 1);

}  // End of String_MPLS

static void String_MPLS_2(FILE *stream, master_record_t *r) {
    fprintf(stream, "%8u-%1u-%1u", r->mpls_label[1] >> 4, (r->mpls_label[1] & 0xF) >> 1, r->mpls_label[1] & 1);

}  // End of String_MPLS

static void String_MPLS_3(FILE *stream, master_record_t *r) {
    fprintf(stream, "%8u-%1u-%1u", r->mpls_label[2] >> 4, (r->mpls_label[2] & 0xF) >> 1, r->mpls_label[2] & 1);

}  // End of String_MPLS

static void String_MPLS_4(FILE *stream, master_record_t *r) {
    fprintf(stream, "%8u-%1u-%1u", r->mpls_label[3] >> 4, (r->mpls_label[3] & 0xF) >> 1, r->mpls_label[3] & 1);

}  // End of String_MPLS

static void String_MPLS_5(FILE *stream, master_record_t *r) {
    fprintf(stream, "%8u-%1u-%1u", r->mpls_label[4] >> 4, (r->mpls_label[4] & 0xF) >> 1, r->mpls_label[4] & 1);

}  // End of String_MPLS

static void String_MPLS_6(FILE *stream, master_record_t *r) {
    fprintf(stream, "%8u-%1u-%1u", r->mpls_label[5] >> 4, (r->mpls_label[5] & 0xF) >> 1, r->mpls_label[5] & 1);

}  // End of String_MPLS

static void String_MPLS_7(FILE *stream, master_record_t *r) {
    fprintf(stream, "%8u-%1u-%1u", r->mpls_label[6] >> 4, (r->mpls_label[6] & 0xF) >> 1, r->mpls_label[6] & 1);

}  // End of String_MPLS

static void String_MPLS_8(FILE *stream, master_record_t *r) {
    fprintf(stream, "%8u-%1u-%1u", r->mpls_label[7] >> 4, (r->mpls_label[7] & 0xF) >> 1, r->mpls_label[7] & 1);

}  // End of String_MPLS

static void String_MPLS_9(FILE *stream, master_record_t *r) {
    fprintf(stream, "%8u-%1u-%1u", r->mpls_label[8] >> 4, (r->mpls_label[8] & 0xF) >> 1, r->mpls_label[8] & 1);

}  // End of String_MPLS

static void String_MPLS_10(FILE *stream, master_record_t *r) {
    fprintf(stream, "%8u-%1u-%1u", r->mpls_label[9] >> 4, (r->mpls_label[9] & 0xF) >> 1, r->mpls_label[9] & 1);

}  // End of String_MPLS

static void String_MPLSs(FILE *stream, master_record_t *r) {
    fprintf(stream,
            "%8u-%1u-%1u %8u-%1u-%1u %8u-%1u-%1u %8u-%1u-%1u %8u-%1u-%1u %8u-%1u-%1u %8u-%1u-%1u %8u-%1u-%1u "
            "%8u-%1u-%1u %8u-%1u-%1u ",
            r->mpls_label[0] >> 4, (r->mpls_label[0] & 0xF) >> 1, r->mpls_label[0] & 1, r->mpls_label[1] >> 4, (r->mpls_label[1] & 0xF) >> 1,
            r->mpls_label[1] & 1, r->mpls_label[2] >> 4, (r->mpls_label[2] & 0xF) >> 1, r->mpls_label[2] & 1, r->mpls_label[3] >> 4,
            (r->mpls_label[3] & 0xF) >> 1, r->mpls_label[3] & 1, r->mpls_label[4] >> 4, (r->mpls_label[4] & 0xF) >> 1, r->mpls_label[4] & 1,
            r->mpls_label[5] >> 4, (r->mpls_label[5] & 0xF) >> 1, r->mpls_label[5] & 1, r->mpls_label[6] >> 4, (r->mpls_label[6] & 0xF) >> 1,
            r->mpls_label[6] & 1, r->mpls_label[7] >> 4, (r->mpls_label[7] & 0xF) >> 1, r->mpls_label[7] & 1, r->mpls_label[8] >> 4,
            (r->mpls_label[8] & 0xF) >> 1, r->mpls_label[8] & 1, r->mpls_label[9] >> 4, (r->mpls_label[9] & 0xF) >> 1, r->mpls_label[9] & 1);

}  // End of String_MPLSs

static void String_Engine(FILE *stream, master_record_t *r) { fprintf(stream, "%3u/%-3u", r->engine_type, r->engine_id); }  // End of String_Engine

static void String_Label(FILE *stream, master_record_t *r) {
    if (r->label)
        fprintf(stream, "%16s", r->label);
    else
        fprintf(stream, "%16s", "<none>");

}  // End of String_Label

static void String_ClientLatency(FILE *stream, master_record_t *r) {
    double latency;

    latency = (double)r->client_nw_delay_usec / 1000.0;
    fprintf(stream, "%9.3f", latency);

}  // End of String_ClientLatency

static void String_ServerLatency(FILE *stream, master_record_t *r) {
    double latency;

    latency = (double)r->server_nw_delay_usec / 1000.0;
    fprintf(stream, "%9.3f", latency);

}  // End of String_ServerLatency

static void String_AppLatency(FILE *stream, master_record_t *r) {
    double latency;

    latency = (double)r->appl_latency_usec / 1000.0;
    fprintf(stream, "%9.3f", latency);

}  // End of String_AppLatency

static void String_bps(FILE *stream, master_record_t *r) {
    uint64_t bps;
    char s[NUMBER_STRING_SIZE];

    if (duration) {
        bps = ((r->inBytes << 3) / duration);  // bits per second. ( >> 3 ) -> * 8 to convert octets into bits
    } else {
        bps = 0;
    }
    format_number(bps, s, printPlain, FIXED_WIDTH);
    fprintf(stream, "%8s", s);

}  // End of String_bps

static void String_pps(FILE *stream, master_record_t *r) {
    uint64_t pps;
    char s[NUMBER_STRING_SIZE];

    if (duration) {
        pps = r->inPackets / duration;  // packets per second
    } else {
        pps = 0;
    }
    format_number(pps, s, printPlain, FIXED_WIDTH);
    fprintf(stream, "%8s", s);

}  // End of String_Duration

static void String_bpp(FILE *stream, master_record_t *r) {
    uint32_t Bpp;

    if (r->inPackets)
        Bpp = r->inBytes / r->inPackets;  // Bytes per Packet
    else
        Bpp = 0;
    fprintf(stream, "%6u", Bpp);

}  // End of String_bpp

static void String_ExpSysID(FILE *stream, master_record_t *r) { fprintf(stream, "%6u", r->exporter_sysid); }  // End of String_ExpSysID

static void String_SrcCountry(FILE *stream, master_record_t *r) {
    if (TestFlag(r->mflags, V3_FLAG_ENRICHED) == 0) LookupCountry(r->V6.srcaddr, r->src_geo);
    fprintf(stream, "%2s", r->src_geo);

}  // End of String_SrcCountry

static void String_DstCountry(FILE *stream, master_record_t *r) {
    if (TestFlag(r->mflags, V3_FLAG_ENRICHED) == 0) LookupCountry(r->V6.dstaddr, r->dst_geo);
    fprintf(stream, "%2s", r->dst_geo);

}  // End of String_DstCountry

static void String_SrcLocation(FILE *stream, master_record_t *r) {
    char location[128];

    LookupLocation(r->V6.srcaddr, location, 128);
    fprintf(stream, "%s", location);

}  // End of String_SrcLocation

static void String_DstLocation(FILE *stream, master_record_t *r) {
    char location[128];

    LookupLocation(r->V6.dstaddr, location, 128);
    fprintf(stream, "%s", location);

}  // End of String_DstLocation

static void String_ivrf(FILE *stream, master_record_t *r) { fprintf(stream, "%10u", r->ingressVrf); }  // End of String_ivrf

static void String_evrf(FILE *stream, master_record_t *r) { fprintf(stream, "%10u", r->egressVrf); }  // End of String_evrf

static void String_ivrfName(FILE *stream, master_record_t *r) {
    char vrfName[128];
    fprintf(stream, "%s", GetVrfName(r->ingressVrf, vrfName, sizeof(vrfName)));
}  // End of String_ivrfName

static void String_evrfName(FILE *stream, master_record_t *r) {
    char vrfName[128];
    fprintf(stream, "%s", GetVrfName(r->egressVrf, vrfName, sizeof(vrfName)));
}  // End of String_evrfName

static void String_pfIfName(FILE *stream, master_record_t *r) {
    //
    fprintf(stream, "%9s", r->pfIfName);
}  // End of String_pfIfName

static void String_pfAction(FILE *stream, master_record_t *r) {
    //
    fprintf(stream, "%6s", pfAction(r->pfAction));
}  // End of String_pfAction

static void String_pfReason(FILE *stream, master_record_t *r) {
    //
    fprintf(stream, "%6s", pfReason(r->pfReason));
}  // End of String_pfReason

static void String_pfdir(FILE *stream, master_record_t *r) {
    //
    fprintf(stream, "%3s", r->pfDir ? "in" : "out");
}  // End of String_pfdir

static void String_pfrule(FILE *stream, master_record_t *r) {
    //
    fprintf(stream, "%4u", r->pfRulenr);
}  // End of String_pfrule

#ifdef NSEL
static void String_nfc(FILE *stream, master_record_t *r) { fprintf(stream, "%10u", r->connID); }  // End of String_nfc

static void String_evt(FILE *stream, master_record_t *r) {
    if (r->fwXevent) {
        fprintf(stream, "%7s", FwEventString(r->event));
    } else {
        fprintf(stream, "%7s", EventString(r->event));
    }

}  // End of String_evt

static void String_xevt(FILE *stream, master_record_t *r) { fprintf(stream, "%7s", EventXString(r->fwXevent)); }  // End of String_xevt

static void String_sgt(FILE *stream, master_record_t *r) { fprintf(stream, "%5u", r->sec_group_tag); }  // End of String_sgt

static void String_msecEvent(FILE *stream, master_record_t *r) {
    fprintf(stream, "%13llu", (long long unsigned)r->msecEvent);

}  // End of String_msecEvent

static void String_iacl(FILE *stream, master_record_t *r) {
    fprintf(stream, "0x%-8x 0x%-8x 0x%-8x", r->ingressAcl[0], r->ingressAcl[1], r->ingressAcl[2]);

}  // End of String_iacl

static void String_eacl(FILE *stream, master_record_t *r) {
    fprintf(stream, "%10u %10u %10u", r->egressAcl[0], r->egressAcl[1], r->egressAcl[2]);

}  // End of String_eacl

static void String_xlateSrcAddr(FILE *stream, master_record_t *r) {
    char tmp_str[IP_STRING_LEN];

    tmp_str[0] = 0;
    if ((r->xlate_flags & 1) != 0) {  // IPv6
        uint64_t ip[2];

        ip[0] = htonll(r->xlate_src_ip.V6[0]);
        ip[1] = htonll(r->xlate_src_ip.V6[1]);
        inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
        if (!long_v6) {
            CondenseV6(tmp_str);
        }
    } else {  // IPv4
        uint32_t ip;
        ip = htonl(r->xlate_src_ip.V4);
        inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
    }
    tmp_str[IP_STRING_LEN - 1] = 0;
    if (long_v6)
        fprintf(stream, "%s%39s", tag_string, tmp_str);
    else
        fprintf(stream, "%s%16s", tag_string, tmp_str);

}  // End of String_xlateSrcAddr

static void String_xlateDstAddr(FILE *stream, master_record_t *r) {
    char tmp_str[IP_STRING_LEN];

    tmp_str[0] = 0;
    if ((r->xlate_flags & 1) != 0) {  // IPv6
        uint64_t ip[2];

        ip[0] = htonll(r->xlate_dst_ip.V6[0]);
        ip[1] = htonll(r->xlate_dst_ip.V6[1]);
        inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
        if (!long_v6) {
            CondenseV6(tmp_str);
        }
    } else {  // IPv4
        uint32_t ip;
        ip = htonl(r->xlate_dst_ip.V4);
        inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
    }
    tmp_str[IP_STRING_LEN - 1] = 0;
    if (long_v6)
        fprintf(stream, "%s%39s", tag_string, tmp_str);
    else
        fprintf(stream, "%s%16s", tag_string, tmp_str);

}  // End of String_xlateDstAddr

static void String_xlateSrcPort(FILE *stream, master_record_t *r) { fprintf(stream, "%6u", r->xlate_src_port); }  // End of String_xlateSrcPort

static void String_xlateDstPort(FILE *stream, master_record_t *r) { fprintf(stream, "%6u", r->xlate_dst_port); }  // End of String_xlateDstPort

static void String_xlateSrcAddrPort(FILE *stream, master_record_t *r) {
    char tmp_str[IP_STRING_LEN], portchar;

    tmp_str[0] = 0;
    if ((r->xlate_flags & 1) != 0) {  // IPv6
        uint64_t ip[2];

        ip[0] = htonll(r->xlate_src_ip.V6[0]);
        ip[1] = htonll(r->xlate_src_ip.V6[1]);
        inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
        if (!long_v6) {
            CondenseV6(tmp_str);
        }

        portchar = '.';
    } else {  // IPv4
        uint32_t ip;
        ip = htonl(r->xlate_src_ip.V4);
        inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));

        portchar = ':';
    }
    tmp_str[IP_STRING_LEN - 1] = 0;

    if (long_v6)
        fprintf(stream, "%s%39s%c%-5i", tag_string, tmp_str, portchar, r->xlate_src_port);
    else
        fprintf(stream, "%s%16s%c%-5i", tag_string, tmp_str, portchar, r->xlate_src_port);

}  // End of String_xlateSrcAddrPort

static void String_xlateDstAddrPort(FILE *stream, master_record_t *r) {
    char tmp_str[IP_STRING_LEN], portchar;

    tmp_str[0] = 0;
    if ((r->xlate_flags & 1) != 0) {  // IPv6
        uint64_t ip[2];

        ip[0] = htonll(r->xlate_dst_ip.V6[0]);
        ip[1] = htonll(r->xlate_dst_ip.V6[1]);
        inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
        if (!long_v6) {
            CondenseV6(tmp_str);
        }

        portchar = '.';
    } else {  // IPv4
        uint32_t ip;
        ip = htonl(r->xlate_dst_ip.V4);
        inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));

        portchar = ':';
    }
    tmp_str[IP_STRING_LEN - 1] = 0;

    if (long_v6)
        fprintf(stream, "%s%39s%c%-5i", tag_string, tmp_str, portchar, r->xlate_dst_port);
    else
        fprintf(stream, "%s%16s%c%-5i", tag_string, tmp_str, portchar, r->xlate_dst_port);

}  // End of String_xlateDstAddrPort

static void String_userName(FILE *stream, master_record_t *r) {
    if (r->username[0] == '\0')
        fprintf(stream, "%s", "<empty>");
    else
        fprintf(stream, "%s", r->username);

}  // End of String_userName

static void String_PortBlockStart(FILE *stream, master_record_t *r) { fprintf(stream, "%7u", r->block_start); }  // End of String_PortBlockStart

static void String_PortBlockEnd(FILE *stream, master_record_t *r) { fprintf(stream, "%7u", r->block_end); }  // End of String_PortBlockEnd

static void String_PortBlockStep(FILE *stream, master_record_t *r) { fprintf(stream, "%7u", r->block_step); }  // End of String_PortBlockStep

static void String_PortBlockSize(FILE *stream, master_record_t *r) { fprintf(stream, "%7u", r->block_size); }  // End of String_PortBlockSize

#endif
