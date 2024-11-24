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

#include "output_csv.h"

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include "dns/dns.h"
#include "ifvrf.h"
#include "ja3/ja3.h"
#include "ja4/ja4.h"
#include "maxmind/maxmind.h"
#include "nbar.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfxV3.h"
#include "output.h"
#include "output_util.h"
#include "tor/tor.h"
#include "userio.h"
#include "util.h"

typedef char *(*string_function_t)(char *, recordHandle_t *);

#include "itoa.c"

#define AddString(s)               \
    do {                           \
        size_t len = strlen(s);    \
        memcpy(streamPtr, s, len); \
        streamPtr += len;          \
    } while (0)

#define AddChar(c) *streamPtr++ = (c);

#define AddU64(u64)                                       \
    do {                                                  \
        streamPtr = itoa_u64((uint64_t)(u64), streamPtr); \
    } while (0)

#define AddU32(u32)                                       \
    do {                                                  \
        streamPtr = itoa_u32((uint32_t)(u32), streamPtr); \
    } while (0)

#define STREAMBUFFSIZE 4096
#define STREAMLEN(ptr)                                \
    ((ptrdiff_t)STREAMBUFFSIZE - (ptr - streamBuff)); \
    assert((ptr - streamBuff) < STREAMBUFFSIZE)
static char *streamBuff = NULL;

static struct token_list_s {
    string_function_t string_function;  // function printing result to stream
} *token_list = NULL;

static int max_token_index = 0;
static int token_index = 0;

#define BLOCK_SIZE 32

static int max_format_index = 0;

static double duration = 0;

#define IP_STRING_LEN (INET6_ADDRSTRLEN)

#define STRINGSIZE 10240
static char header_string[STRINGSIZE] = {'\0'};

/* prototypes */
static char *ICMP_Port_decode(EXgenericFlow_t *genericFlow);

static inline uint32_t ApplyV4NetMaskBits(uint32_t ip, uint32_t maskBits);

static inline uint64_t *ApplyV6NetMaskBits(uint64_t *ip, uint32_t maskBits);

static void InitFormatParser(void);

static void AddToken(int index);

static char *String_Version(char *streamPtr, recordHandle_t *recordHandle);

static char *String_FlowCount(char *streamPtr, recordHandle_t *recordHandle);

static char *String_FirstSeen(char *streamPtr, recordHandle_t *recordHandle);

static char *String_LastSeen(char *streamPtr, recordHandle_t *recordHandle);

static char *String_Received(char *streamPtr, recordHandle_t *recordHandle);

static char *String_FirstSeenRaw(char *streamPtr, recordHandle_t *recordHandle);

static char *String_LastSeenRaw(char *streamPtr, recordHandle_t *recordHandle);

static char *String_ReceivedRaw(char *streamPtr, recordHandle_t *recordHandle);

static char *String_FirstSeenGMT(char *streamPtr, recordHandle_t *recordHandle);

static char *String_LastSeenGMT(char *streamPtr, recordHandle_t *recordHandle);

static char *String_ReceivedGMT(char *streamPtr, recordHandle_t *recordHandle);

static char *String_Duration(char *streamPtr, recordHandle_t *recordHandle);

static char *String_Duration_Seconds(char *streamPtr, recordHandle_t *recordHandle);

static char *String_Protocol(char *streamPtr, recordHandle_t *recordHandle);

static char *String_SrcAddr(char *streamPtr, recordHandle_t *recordHandle);

static char *String_DstAddr(char *streamPtr, recordHandle_t *recordHandle);

static char *String_SrcNet(char *streamPtr, recordHandle_t *recordHandle);

static char *String_DstNet(char *streamPtr, recordHandle_t *recordHandle);

static char *String_NextHop(char *streamPtr, recordHandle_t *recordHandle);

static char *String_BGPNextHop(char *streamPtr, recordHandle_t *recordHandle);

static char *String_RouterIP(char *streamPtr, recordHandle_t *recordHandle);

static char *String_SrcPort(char *streamPtr, recordHandle_t *recordHandle);

static char *String_DstPort(char *streamPtr, recordHandle_t *recordHandle);

static char *String_ICMP_code(char *streamPtr, recordHandle_t *recordHandle);

static char *String_ICMP_type(char *streamPtr, recordHandle_t *recordHandle);

static char *String_SrcAS(char *streamPtr, recordHandle_t *recordHandle);

static char *String_DstAS(char *streamPtr, recordHandle_t *recordHandle);

static char *String_NextAS(char *streamPtr, recordHandle_t *recordHandle);

static char *String_PrevAS(char *streamPtr, recordHandle_t *recordHandle);

static char *String_Input(char *streamPtr, recordHandle_t *recordHandle);

static char *String_InputName(char *streamPtr, recordHandle_t *recordHandle);

static char *String_Output(char *streamPtr, recordHandle_t *recordHandle);

static char *String_OutputName(char *streamPtr, recordHandle_t *recordHandle);

static char *String_InPackets(char *streamPtr, recordHandle_t *recordHandle);

static char *String_OutPackets(char *streamPtr, recordHandle_t *recordHandle);

static char *String_InBytes(char *streamPtr, recordHandle_t *recordHandle);

static char *String_OutBytes(char *streamPtr, recordHandle_t *recordHandle);

static char *String_Flows(char *streamPtr, recordHandle_t *recordHandle);

static char *String_Tos(char *streamPtr, recordHandle_t *recordHandle);

static char *String_Dir(char *streamPtr, recordHandle_t *recordHandle);

static char *String_SrcTos(char *streamPtr, recordHandle_t *recordHandle);

static char *String_DstTos(char *streamPtr, recordHandle_t *recordHandle);

static char *String_SrcMask(char *streamPtr, recordHandle_t *recordHandle);

static char *String_DstMask(char *streamPtr, recordHandle_t *recordHandle);

static char *String_SrcVlan(char *streamPtr, recordHandle_t *recordHandle);

static char *String_DstVlan(char *streamPtr, recordHandle_t *recordHandle);

static char *String_FwdStatus(char *streamPtr, recordHandle_t *recordHandle);

static char *String_BiFlowDir(char *streamPtr, recordHandle_t *recordHandle);

static char *String_FlowEndReason(char *streamPtr, recordHandle_t *recordHandle);

static char *String_ipTTL(char *streamPtr, recordHandle_t *recordHandle);

static char *String_ipminTTL(char *streamPtr, recordHandle_t *recordHandle);

static char *String_ipmaxTTL(char *streamPtr, recordHandle_t *recordHandle);

static char *String_ipFrag(char *streamPtr, recordHandle_t *recordHandle);

static char *String_Flags(char *streamPtr, recordHandle_t *recordHandle);

static char *String_InSrcMac(char *streamPtr, recordHandle_t *recordHandle);

static char *String_OutDstMac(char *streamPtr, recordHandle_t *recordHandle);

static char *String_InDstMac(char *streamPtr, recordHandle_t *recordHandle);

static char *String_OutSrcMac(char *streamPtr, recordHandle_t *recordHandle);

static char *String_MPLS_1(char *streamPtr, recordHandle_t *recordHandle);

static char *String_MPLS_2(char *streamPtr, recordHandle_t *recordHandle);

static char *String_MPLS_3(char *streamPtr, recordHandle_t *recordHandle);

static char *String_MPLS_4(char *streamPtr, recordHandle_t *recordHandle);

static char *String_MPLS_5(char *streamPtr, recordHandle_t *recordHandle);

static char *String_MPLS_6(char *streamPtr, recordHandle_t *recordHandle);

static char *String_MPLS_7(char *streamPtr, recordHandle_t *recordHandle);

static char *String_MPLS_8(char *streamPtr, recordHandle_t *recordHandle);

static char *String_MPLS_9(char *streamPtr, recordHandle_t *recordHandle);

static char *String_MPLS_10(char *streamPtr, recordHandle_t *recordHandle);

static char *String_MPLSs(char *streamPtr, recordHandle_t *recordHandle);

static char *String_Engine(char *streamPtr, recordHandle_t *recordHandle);

static char *String_Label(char *streamPtr, recordHandle_t *recordHandle);

static char *String_ClientLatency(char *streamPtr, recordHandle_t *recordHandle);

static char *String_ServerLatency(char *streamPtr, recordHandle_t *recordHandle);

static char *String_AppLatency(char *streamPtr, recordHandle_t *recordHandle);

static char *String_bps(char *streamPtr, recordHandle_t *recordHandle);

static char *String_pps(char *streamPtr, recordHandle_t *recordHandle);

static char *String_bpp(char *streamPtr, recordHandle_t *recordHandle);

static char *String_ExpSysID(char *streamPtr, recordHandle_t *recordHandle);

static char *String_SrcCountry(char *streamPtr, recordHandle_t *recordHandle);

static char *String_DstCountry(char *streamPtr, recordHandle_t *recordHandle);

static char *String_SrcLocation(char *streamPtr, recordHandle_t *recordHandle);

static char *String_DstLocation(char *streamPtr, recordHandle_t *recordHandle);

static char *String_SrcASorganisation(char *streamPtr, recordHandle_t *recordHandle);

static char *String_DstASorganisation(char *streamPtr, recordHandle_t *recordHandle);

static char *String_SrcTor(char *streamPtr, recordHandle_t *recordHandle);

static char *String_DstTor(char *streamPtr, recordHandle_t *recordHandle);

static char *String_nbarID(char *streamPtr, recordHandle_t *recordHandle);

static char *String_nbarName(char *streamPtr, recordHandle_t *recordHandle);

static char *String_ja3(char *streamPtr, recordHandle_t *recordHandle);

static char *String_ja4(char *streamPtr, recordHandle_t *recordHandle);

static char *String_sniName(char *streamPtr, recordHandle_t *recordHandle);

static char *String_tlsVersion(char *streamPtr, recordHandle_t *recordHandle);

static char *String_observationDomainID(char *streamPtr, recordHandle_t *recordHandle);

static char *String_observationPointID(char *streamPtr, recordHandle_t *recordHandle);

static char *String_ivrf(char *streamPtr, recordHandle_t *recordHandle);

static char *String_ivrfName(char *streamPtr, recordHandle_t *recordHandle);

static char *String_evrf(char *streamPtr, recordHandle_t *recordHandle);

static char *String_evrfName(char *streamPtr, recordHandle_t *recordHandle);

static char *String_pfIfName(char *streamPtr, recordHandle_t *recordHandle);

static char *String_pfAction(char *streamPtr, recordHandle_t *recordHandle);

static char *String_pfReason(char *streamPtr, recordHandle_t *recordHandle);

static char *String_pfdir(char *streamPtr, recordHandle_t *recordHandle);

static char *String_pfrule(char *streamPtr, recordHandle_t *recordHandle);

static char *String_EventTime(char *streamPtr, recordHandle_t *recordHandle);

static char *String_nfc(char *streamPtr, recordHandle_t *recordHandle);

static char *String_evt(char *streamPtr, recordHandle_t *recordHandle);

static char *String_xevt(char *streamPtr, recordHandle_t *recordHandle);

static char *String_msecEvent(char *streamPtr, recordHandle_t *recordHandle);

static char *String_iacl(char *streamPtr, recordHandle_t *recordHandle);

static char *String_eacl(char *streamPtr, recordHandle_t *recordHandle);

static char *String_xlateSrcAddr(char *streamPtr, recordHandle_t *recordHandle);

static char *String_xlateDstAddr(char *streamPtr, recordHandle_t *recordHandle);

static char *String_xlateSrcPort(char *streamPtr, recordHandle_t *recordHandle);

static char *String_xlateDstPort(char *streamPtr, recordHandle_t *recordHandle);

static char *String_userName(char *streamPtr, recordHandle_t *recordHandle);

static char *String_PortBlockStart(char *streamPtr, recordHandle_t *recordHandle);

static char *String_PortBlockEnd(char *streamPtr, recordHandle_t *recordHandle);

static char *String_PortBlockStep(char *streamPtr, recordHandle_t *recordHandle);

static char *String_PortBlockSize(char *streamPtr, recordHandle_t *recordHandle);

static char *String_flowId(char *streamPtr, recordHandle_t *recordHandle);

static char *String_inServiceID(char *streamPtr, recordHandle_t *recordHandle);

static char *String_outServiceID(char *streamPtr, recordHandle_t *recordHandle);

static char *String_natString(char *streamPtr, recordHandle_t *recordHandle);

static struct format_entry_s {
    char *token;                        // token
    int is_address;                     // is an IP address
    char *csvHeader;                    // csv header line description
    string_function_t string_function;  // function generation output string
} formatTable[] = {
    // csv format table
    {"%nfv", 0, "version", String_Version},      // netflow version
    {"%cnt", 0, "count", String_FlowCount},      // flow count
    {"%eng", 0, "engine", String_Engine},        // Engine Type/ID
    {"%exp", 0, "exporterID", String_ExpSysID},  // Exporter SysID

    // EXgenericFlowID
    {"%tfs", 0, "firstSeen", String_FirstSeen},        // Start Time - first seen
    {"%ts", 0, "firstSeen", String_FirstSeen},         // Start Time - first seen
    {"%tsr", 0, "firstSeen", String_FirstSeenRaw},     // Start Time - first seen, seconds
    {"%tsg", 0, "firstSeen", String_FirstSeenGMT},     // Start Time GMT - first seen, seconds
    {"%te", 0, "lastSeen", String_LastSeen},           // End Time	- last seen
    {"%ter", 0, "lastSeen", String_LastSeenRaw},       // End Time - first seen, seconds
    {"%teg", 0, "lastSeen", String_LastSeenGMT},       // End Time GMT - first seen, seconds
    {"%tr", 0, "received", String_Received},           // Received Time
    {"%trr", 0, "received", String_ReceivedRaw},       // Received Time, seconds
    {"%trg", 0, "received", String_ReceivedGMT},       // Received Time GMT, seconds
    {"%td", 0, "duration", String_Duration},           // Duration
    {"%tds", 0, "duration", String_Duration_Seconds},  // Duration always in seconds
    {"%pkt", 0, "packets", String_InPackets},          // Packets - default input - compat
    {"%ipkt", 0, "inPackets", String_InPackets},       // In Packets
    {"%byt", 0, "bytes", String_InBytes},              // Bytes - default input - compat
    {"%ibyt", 0, "inBytes", String_InBytes},           // In Bytes
    {"%sp", 0, "srcPort", String_SrcPort},             // Source Port
    {"%dp", 0, "dstPort", String_DstPort},             // Destination Port
    {"%it", 0, "icmpTYpe", String_ICMP_type},          // ICMP type
    {"%ic", 0, "icmpCode", String_ICMP_code},          // ICMP code
    {"%pr", 0, "proto", String_Protocol},              // Protocol
    {"%flg", 0, "flags", String_Flags},                // TCP Flags
    {"%fwd", 0, "fwdStatus", String_FwdStatus},        // Forwarding Status
    {"%tos", 0, "tos", String_Tos},                    // Tos - compat
    {"%stos", 0, "srcTos", String_SrcTos},             // Tos - Src tos
    {"%bps", 0, "bps", String_bps},                    // bps - bits per second
    {"%pps", 0, "pps", String_pps},                    // pps - packets per second
    {"%bpp", 0, "bpp", String_bpp},                    // bpp - Bytes per package

    // EXipv4FlowID EXipv6FlowID
    {"%sa", 1, "srcAddr", String_SrcAddr},  // Source Address
    {"%da", 1, "dstAddr", String_DstAddr},  // Destination Address

    // EXflowMiscID
    {"%in", 0, "input", String_Input},               // Input Interface num
    {"%out", 0, "output", String_Output},            // Output Interface num
    {"%smk", 0, "srcMask", String_SrcMask},          // Src mask
    {"%dmk", 0, "dstMask", String_DstMask},          // Dst mask
    {"%dir", 0, "direction", String_Dir},            // Direction: ingress, egress
    {"%dtos", 0, "dstTos", String_DstTos},           // Tos - Dst tos
    {"%bfd", 0, "biDirection", String_BiFlowDir},    // BiFlow Direction
    {"%end", 0, "endReason", String_FlowEndReason},  // Flow End Reason

    //
    {"%sn", 1, "srcNet", String_SrcNet},           // Source Address applied source netmask
    {"%dn", 1, "dstNet", String_DstNet},           // Destination Address applied source netmask
    {"%inam", 0, "inIfName", String_InputName},    // Input Interface name
    {"%onam", 0, "outIfName", String_OutputName},  // Output Interface name

    // EXcntFlowID
    {"%opkt", 0, "outPackets", String_OutPackets},  // Out Packets
    {"%obyt", 0, "outBytes", String_OutBytes},      // In Bytes
    {"%fl", 0, "flows", String_Flows},              // Flows

    // EXvLanID
    {"%svln", 0, "srcVlan", String_SrcVlan},  // Src Vlan
    {"%dvln", 0, "dstVlan", String_DstVlan},  // Dst Vlan

    // EXasRoutingID
    {"%sas", 0, "srcAS", String_SrcAS},  // Source AS
    {"%das", 0, "dstAS", String_DstAS},  // Destination AS

    // EXbgpNextHopV4ID EXbgpNextHopV6ID
    {"%nhb", 1, "bgpNextIP", String_BGPNextHop},  // BGP Next-hop IP Address

    // EXipNextHopV4ID
    {"%nh", 1, "nextIP", String_NextHop},  // Next-hop IP Address

    // EXipReceivedV4ID EXipReceivedV6ID
    {"%ra", 1, "routerIP", String_RouterIP},  // Router IP Address

    // EXmplsLabelID
    {"%mpls1", 0, "mplsLabel1", String_MPLS_1},     // MPLS Label 1
    {"%mpls2", 0, "mplsLabel2", String_MPLS_2},     // MPLS Label 2
    {"%mpls3", 0, "mplsLabel3", String_MPLS_3},     // MPLS Label 3
    {"%mpls4", 0, "mplsLabel4", String_MPLS_4},     // MPLS Label 4
    {"%mpls5", 0, "mplsLabel5", String_MPLS_5},     // MPLS Label 5
    {"%mpls6", 0, "mplsLabel6", String_MPLS_6},     // MPLS Label 6
    {"%mpls7", 0, "mplsLabel7", String_MPLS_7},     // MPLS Label 7
    {"%mpls8", 0, "mplsLabel8", String_MPLS_8},     // MPLS Label 8
    {"%mpls9", 0, "mplsLabel9", String_MPLS_9},     // MPLS Label 9
    {"%mpls10", 0, "mplsLabel10", String_MPLS_10},  // MPLS Label 10
    {"%mpls", 0, "mplsLabel1-10", String_MPLSs},    // All MPLS labels

    // EXmacAddrID
    {"%ismc", 0, "inSrcMac", String_InSrcMac},    // Input Src Mac Addr
    {"%odmc", 0, "outDstMac", String_OutDstMac},  // Output Dst Mac Addr
    {"%idmc", 0, "inDstMac", String_InDstMac},    // Input Dst Mac Addr
    {"%osmc", 0, "outSrcMac", String_OutSrcMac},  // Output Src Mac Addr

    // EXasAdjacentID
    {"%nas", 0, "nextAS", String_NextAS},  // Next AS
    {"%pas", 0, "prevAS", String_PrevAS},  // Previous AS

    // EXlatencyID - latency extension for nfpcapd and nprobe
    {"%cl", 0, "clientLatency", String_ClientLatency},  // client latency
    {"%sl", 0, "serverLatency", String_ServerLatency},  // server latency
    {"%al", 0, "appLatency", String_AppLatency},        // app latency

    // EXsamplerInfoID

    // EXnselCommonID & EXnatCommonID
    {"%tevt", 0, "eventTime", String_EventTime},  // NSEL Flow start time
    {"%msec", 0, "eventTime", String_msecEvent},  // NSEL event time in msec
    {"%evt", 0, "event", String_evt},             // NSEL event

    // EXnselCommonID
    {"%nfc", 0, "connectionID", String_nfc},  // NSEL connection ID
    {"%xevt", 0, "xEvent", String_xevt},      // NSEL xevent

    // EXnatXlateIPv4ID EXnatXlateIPv6ID
    // ASA Firewall
    {"%xsa", 0, "srcXIP", String_xlateSrcAddr},  // NSEL XLATE src IP
    {"%xda", 0, "dstXIP", String_xlateDstAddr},  // NSEL XLATE dst IP
    // NAT devices
    {"%nsa", 0, "srcXIP", String_xlateSrcAddr},  // NAT XLATE src IP
    {"%nda", 0, "dstXIP", String_xlateDstAddr},  // NAT XLATE dst IP

    // EXnatXlatePortID
    // ASA Firewall
    {"%xsp", 0, "srcXPort", String_xlateSrcPort},  // NSEL XLATE src port
    {"%xdp", 0, "dstXPort", String_xlateDstPort},  // NSEL SLATE dst port
    // NAT devices
    {"%nsp", 0, "srcXPort", String_xlateSrcPort},  // NAT XLATE src port
    {"%ndp", 0, "dstXPort", String_xlateDstPort},  // NAT SLATE dst port

    // EXnselAclID
    {"%iacl", 0, "ingressACL", String_iacl},  // NSEL ingress ACL
    {"%eacl", 0, "egressACL", String_eacl},   // NSEL egress ACL

    // EXnselUserID
    {"%uname", 0, "nselUser", String_userName},  // NSEL user name

    // EXnatPortBlockID - Port block allocation
    {"%pbstart", 0, "pbStart", String_PortBlockStart},  // Port block start
    {"%pbend", 0, "pbEnd", String_PortBlockEnd},        // Port block end
    {"%pbstep", 0, "pbStep", String_PortBlockStep},     // Port block step
    {"%pbsize", 0, "pbSize", String_PortBlockSize},     // Port block size

    // EXnbarAppID
    {"%nbid", 0, "nbarID", String_nbarID},       // nbar ID
    {"%nbnam", 0, "nbarName", String_nbarName},  // nbar Name

    // EXobservationID
    {"%odid", 0, "obsDomainID", String_observationDomainID},  // observation domainID
    {"%opid", 0, "obsPointID", String_observationPointID},    // observation pointID

    // EXinmonMetaID

    // EXvrfID
    {"%vrf", 0, "ingressVrfID", String_ivrf},            // ingress vrf ID - compatible
    {"%ivrf", 0, "ingressVrfID", String_ivrf},           // ingress vrf ID
    {"%ivrfnam", 0, "ingressVrfName", String_ivrfName},  // ingress vrf name
    {"%evrf", 0, "egressVrfID", String_evrf},            // egress vrf ID
    {"%evrfnam", 0, "egressVrfName", String_evrfName},   // egress vrf name

    // EXpfinfoID
    {"%pfifn", 0, "pfInterface", String_pfIfName},  // pflog ifname
    {"%pfact", 0, "pfAction", String_pfAction},     // pflog action
    {"%pfrea", 0, "pfReason", String_pfReason},     // pflog reason
    {"%pfdir", 0, "pfDirection", String_pfdir},     // pflog direction
    {"%pfrule", 0, "pfRule", String_pfrule},        // pflog rule

    // EXflowIdID
    {"%flid", 0, "flowID", String_flowId},  // flowID

    // EXnokiaNatID
    {"%isid", 0, "inSrvID", String_inServiceID},    // in Service ID
    {"%osid", 0, "outSrvID", String_outServiceID},  // out service ID

    // EXnokiaNatStringID
    {"%nats", 0, "natString", String_natString},  // nat String

    // EXlocal
    {"%ja3", 0, "ja3", String_ja3},                    // ja3 hashes
    {"%ja4", 0, "ja4", String_ja4},                    // ja4 hashes
    {"%sni", 0, "sniName", String_sniName},            // TLS sni Name
    {"%tls", 0, "tlsVersion", String_tlsVersion},      // TLS version
    {"%sc", 0, "srcGeo", String_SrcCountry},           // src IP 2 letter country code
    {"%dc", 0, "dstGeo", String_DstCountry},           // dst IP 2 letter country code
    {"%sloc", 0, "srcLocation", String_SrcLocation},   // src IP geo location info
    {"%dloc", 0, "dstLocation", String_DstLocation},   // dst IP geo location info
    {"%sasn", 0, "srcOrg", String_SrcASorganisation},  // src IP AS organistaion string
    {"%dasn", 0, "dstOrg", String_DstASorganisation},  // dst IP AS organisation string
    {"%stor", 0, "srcTor", String_SrcTor},             // src IP 2 letter tor node info
    {"%dtor", 0, "dstTor", String_DstTor},             // dst IP 2 letter tor node info
    {"%lbl", 0, "label", String_Label},                // Flow Label

    // EXipInfo
    {"%ttl", 0, "TTL", String_ipTTL},           // Flow ip ttl
    {"%minttl", 0, "minTTL", String_ipminTTL},  // Flow ip min ttl
    {"%maxttl", 0, "maxTTL", String_ipmaxTTL},  // Flow ip max ttl
    {"%frag", 0, "Frag", String_ipFrag},        // IP fragment flags

    {NULL, 0, NULL, NULL}};

/* each of the tokens above must not generate output strings larger than this */
#define MAX_STRING_LENGTH 256

/* functions */

static void ListOutputFormats(void) {
    printf("Available csv format elements:");
    for (int i = 0; formatTable[i].token != NULL; i++) {
        if ((i & 0xf) == 0) printf("\n");
        printf("%s ", formatTable[i].token);
    }
    printf("- See also nfdump(1)\n");

}  // End of ListOutputFormats

void csv_record(FILE *stream, recordHandle_t *recordHandle, int tag) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    EXtunIPv4_t *tunIPv4 = (EXtunIPv4_t *)recordHandle->extensionList[EXtunIPv4ID];
    EXtunIPv6_t *tunIPv6 = (EXtunIPv6_t *)recordHandle->extensionList[EXtunIPv6ID];

    // if this flow is a tunnel, add a flow line with the tunnel IPs
    if (genericFlow && (tunIPv4 || tunIPv6)) {
        size_t len = V3HeaderRecordSize + EXgenericFlowSize + EXipv6FlowSize;
        void *p = malloc(len);
        if (!p) {
            LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            exit(EXIT_FAILURE);
        }
        AddV3Header(p, v3TunHeader);
        PushExtension(v3TunHeader, EXgenericFlow, tunGenericFlow);
        memcpy((void *)tunGenericFlow, (void *)genericFlow, sizeof(EXgenericFlow_t));
        recordHandle_t tunRecordHandle = {
            .recordHeaderV3 = v3TunHeader, .extensionList[EXgenericFlowID] = tunGenericFlow, .flowCount = recordHandle->flowCount};
        if (tunIPv4) {
            tunGenericFlow->proto = tunIPv4->tunProto;
            PushExtension(v3TunHeader, EXipv4Flow, tunIPv4Flow);
            tunIPv4Flow->srcAddr = tunIPv4->tunSrcAddr;
            tunIPv4Flow->dstAddr = tunIPv4->tunDstAddr;
            tunRecordHandle.extensionList[EXipv4FlowID] = tunIPv4Flow;
        } else {
            tunGenericFlow->proto = tunIPv6->tunProto;
            PushExtension(v3TunHeader, EXipv6Flow, tunIPv6Flow);
            tunIPv6Flow->srcAddr[0] = tunIPv6->tunSrcAddr[0];
            tunIPv6Flow->srcAddr[1] = tunIPv6->tunSrcAddr[1];
            tunIPv6Flow->dstAddr[0] = tunIPv6->tunDstAddr[0];
            tunIPv6Flow->dstAddr[1] = tunIPv6->tunDstAddr[1];
            tunRecordHandle.extensionList[EXipv6FlowID] = tunIPv6Flow;
        }
        csv_record(stream, &tunRecordHandle, tag);
        free(p);
    }

    streamBuff[0] = '\0';
    char *streamPtr = streamBuff;
    duration = 0;
    if (genericFlow && genericFlow->msecFirst && genericFlow->msecLast) {
        if (genericFlow->msecLast >= genericFlow->msecFirst) {
            duration = (genericFlow->msecLast - genericFlow->msecFirst) / 1000.0;
        } else {
            LogError("Record: %u Time error - last < first", recordHandle->flowCount);
            duration = 0;
        }
    }

    for (int i = 0; i < token_index; i++) {
        if (i > 0) {
            AddChar(',');
        }
        if (token_list[i].string_function) {
            streamPtr = token_list[i].string_function(streamPtr, recordHandle);
        }
        if (unlikely((streamBuff + STREAMBUFFSIZE - streamPtr) < 512)) {
            LogError("csv_record() error in %s line %d: %s", __FILE__, __LINE__, "buffer error");
            exit(EXIT_FAILURE);
        }
    }
    AddChar('\n');
    AddChar('\0');
    fputs(streamBuff, stream);

}  // End of csv_record

void csv_prolog(outputParams_t *outputParam) {
    streamBuff = malloc(STREAMBUFFSIZE);
    if (!streamBuff) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        exit(EXIT_FAILURE);
    }
    streamBuff[0] = '\0';

    // header
    printf("%s\n", header_string);
}  // End of csv_prolog

void csv_epilog(outputParams_t *outputParam) {
    free(streamBuff);
    streamBuff = NULL;
}  // End of csv_epilog

static void InitFormatParser(void) {
    max_format_index = max_token_index = BLOCK_SIZE;
    token_list = (struct token_list_s *)calloc(1, max_token_index * sizeof(struct token_list_s));
    if (!token_list) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        exit(255);
    }

}  // End of InitFormatParser

static inline uint32_t ApplyV4NetMaskBits(uint32_t ip, uint32_t maskBits) {
    uint32_t srcMask = 0xffffffff << (32 - maskBits);
    return (ip &= srcMask);
}  // End of ApplyV4NetMaskBits

static inline uint64_t *ApplyV6NetMaskBits(uint64_t *ip, uint32_t maskBits) {
    static uint64_t net[2];
    uint64_t mask;
    if (maskBits > 64) {
        mask = 0xffffffffffffffffLL << (128 - maskBits);
        net[0] = ip[0];
        net[1] = ip[1] & mask;
    } else {
        mask = 0xffffffffffffffffLL << (64 - maskBits);
        net[0] = ip[0] & mask;
        net[1] = 0;
    }
    return net;

}  // End of ApplyV6NetMaskBits

static void AddToken(int index) {
    if (token_index >= max_token_index) {  // no slot available - expand table
        max_token_index += BLOCK_SIZE;
        token_list = (struct token_list_s *)realloc(token_list, max_token_index * sizeof(struct token_list_s));
        if (!token_list) {
            LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            exit(255);
        }
    }

    token_list[token_index].string_function = formatTable[index].string_function;
    token_index++;

}  // End of AddToken

int ParseCSVOutputFormat(char *format) {
    char *s = strdup(format);
    if (!s) {
        LogError("malloc() allocation error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    InitFormatParser();

    char *c = s;
    char *h = header_string;
    *h = '\0';
    while (*c && *c == ' ') c++;
    if (*c == '\0') {
        LogError("Empty csv token string");
        return 0;
    }
    while (*c) {
        if (*c == '%') {  // it's a token from formatTable
            int i = 0;
            int remaining = strlen(c);
            while (formatTable[i].token) {  // sweep through the list
                int len = strlen(formatTable[i].token);

                // a token is separated by either a space, another token, or end of string
                if (remaining >= len && !isalnum((int)c[len])) {
                    // separator found a expected position
                    char p = c[len];  // save separator;
                    c[len] = '\0';
                    if (strncmp(formatTable[i].token, c, len) == 0) {  // token found
                        AddToken(i);
                        size_t hlen = snprintf(h, STRINGSIZE - 1 - strlen(header_string), "%s,", formatTable[i].csvHeader);
                        h += hlen;
                        c[len] = p;
                        c += len;
                        break;
                    } else {
                        c[len] = p;
                    }
                }
                i++;
            }
            if (formatTable[i].token == NULL) {
                LogError("Output format parse error at: %s", c);
                free(s);
                ListOutputFormats();
                return 0;
            }
        } else {  // it's a static string
            while (*c && *c == ' ') c++;
            if (*c == '\0') continue;
            if (*c != ',') {
                LogError("Expected ',' separator, but found %c", *c);
                return 0;
            }
            c++;
            while (*c && *c == ' ') c++;
            if (*c == '\0' || *c != '%') {
                LogError("Expected '%%' token, but found %s", *c == '\0' ? "<end of string>" : c);
                return 0;
            }
        }
    }
    if (h > header_string) *--h = '\0';
    free(s);
    return 1;

}  // End of ParseOutputFormat

static char *ICMP_Port_decode(EXgenericFlow_t *genericFlow) {
#define ICMPSTRLEN 16
    static char icmpString[ICMPSTRLEN];
    icmpString[0] = '\0';

    if (genericFlow == NULL) return "0";

    if (genericFlow->proto == IPPROTO_ICMP || genericFlow->proto == IPPROTO_ICMPV6) {  // ICMP
        snprintf(icmpString, ICMPSTRLEN - 1, "%u.%u", genericFlow->icmpType, genericFlow->icmpCode);
    } else {  // dst port
        snprintf(icmpString, ICMPSTRLEN - 1, "%u", genericFlow->dstPort);
    }
    icmpString[ICMPSTRLEN - 1] = '\0';

    return icmpString;

}  // End of ICMP_Port_decode

/* functions, which create the individual strings for the output line */
static char *String_Version(char *streamPtr, recordHandle_t *recordHandle) {
    recordHeaderV3_t *recordHeaderV3 = recordHandle->recordHeaderV3;

    char *type = "unknown";
    uint8_t nfversion = recordHeaderV3->nfversion;
    if (TestFlag(recordHeaderV3->flags, V3_FLAG_EVENT)) {
        type = "event";
        AddString(type);
        AddU32(nfversion);
    } else {
        if (nfversion != 0) {
            if (nfversion & 0x80) {
                type = "sflowV";
            } else if (nfversion & 0x40) {
                type = "pcapdV";
            } else {
                type = "netflowV";
            }
            AddString(type);
            AddU32(nfversion & 0x0F);
        } else {
            // compat with previous versions
            type = "flow";
            AddString(type);
        }
    }

    return streamPtr;
}  // End of String_Version

static char *String_FlowCount(char *streamPtr, recordHandle_t *recordHandle) {
    AddU32(recordHandle->flowCount);

    return streamPtr;
}  // End of String_FlowCount

static char *String_FirstSeen(char *streamPtr, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];

    uint64_t msecFirst = genericFlow ? genericFlow->msecFirst : 0;

    if (msecFirst) {
        time_t tt = msecFirst / 1000LL;
        struct tm ts;
        localtime_r(&tt, &ts);
        char s[128];
        strftime(s, 128, "%Y-%m-%d %H:%M:%S", &ts);
        s[127] = '\0';
        ptrdiff_t lenStream = STREAMLEN(streamPtr);
        size_t len = snprintf(streamPtr, lenStream, "%s.%03u", s, (unsigned)(msecFirst % 1000LL));
        streamPtr += len;
    } else {
        AddString("0000-00-00 00:00:00.000");
    }

    return streamPtr;
}  // End of String_FirstSeen

static char *String_LastSeen(char *streamPtr, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];

    uint64_t msecLast = genericFlow ? genericFlow->msecLast : 0;

    if (msecLast) {
        time_t tt = msecLast / 1000LL;
        struct tm ts;
        localtime_r(&tt, &ts);
        char s[128];
        strftime(s, 128, "%Y-%m-%d %H:%M:%S", &ts);
        s[127] = '\0';
        ptrdiff_t lenStream = STREAMLEN(streamPtr);
        size_t len = snprintf(streamPtr, lenStream, "%s.%03u", s, (unsigned)(msecLast % 1000LL));
        streamPtr += len;
    } else {
        AddString("0000-00-00 00:00:00.000");
    }

    return streamPtr;
}  // End of String_LastSeen

static char *String_Received(char *streamPtr, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];

    uint64_t msecReceived = genericFlow ? genericFlow->msecReceived : 0;

    if (msecReceived) {
        time_t tt = msecReceived / 1000LL;
        struct tm ts;
        localtime_r(&tt, &ts);
        char s[128];
        strftime(s, 128, "%Y-%m-%d %H:%M:%S", &ts);
        s[127] = '\0';
        ptrdiff_t lenStream = STREAMLEN(streamPtr);
        size_t len = snprintf(streamPtr, lenStream, "%s.%03llu", s, msecReceived % 1000LL);
        streamPtr += len;
    } else {
        AddString("0000-00-00 00:00:00.000");
    }

    return streamPtr;
}  // End of String_Received

static char *String_ReceivedRaw(char *streamPtr, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];

    uint64_t msecReceived = genericFlow ? genericFlow->msecReceived : 0;
    ptrdiff_t lenStream = STREAMLEN(streamPtr);
    size_t len = snprintf(streamPtr, lenStream, "%llu.%03llu", msecReceived / 1000LL, msecReceived % 1000LL);
    streamPtr += len;

    return streamPtr;
}  // End of String_ReceivedRaw

static char *String_FirstSeenRaw(char *streamPtr, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];

    uint64_t msecFirst = genericFlow ? genericFlow->msecFirst : 0;
    ptrdiff_t lenStream = STREAMLEN(streamPtr);
    size_t len = snprintf(streamPtr, lenStream, "%llu.%03llu", msecFirst / 1000LL, msecFirst % 1000LL);
    streamPtr += len;

    return streamPtr;
}  // End of String_FirstSeenRaw

static char *String_LastSeenRaw(char *streamPtr, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];

    uint64_t msecLast = genericFlow ? genericFlow->msecLast : 0;
    ptrdiff_t lenStream = STREAMLEN(streamPtr);
    size_t len = snprintf(streamPtr, lenStream, "%llu.%03llu", msecLast / 1000LL, msecLast % 1000LL);
    streamPtr += len;

    return streamPtr;
}  // End of String_LastSeenRaw

static char *String_FirstSeenGMT(char *streamPtr, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];

    uint64_t msecFirst = genericFlow ? genericFlow->msecFirst : 0;

    if (msecFirst) {
        time_t tt = msecFirst / 1000LL;
        struct tm ts;
        gmtime_r(&tt, &ts);
        char s[128];
        strftime(s, 128, "%Y-%m-%d %H:%M:%S", &ts);
        s[127] = '\0';
        ptrdiff_t lenStream = STREAMLEN(streamPtr);
        size_t len = snprintf(streamPtr, lenStream, "%s.%03u", s, (unsigned)(msecFirst % 1000LL));
        streamPtr += len;
    } else {
        AddString("0000-00-00 00:00:00.000");
    }

    return streamPtr;
}  // End of String_FirstSeenGMT

static char *String_LastSeenGMT(char *streamPtr, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];

    uint64_t msecLast = genericFlow ? genericFlow->msecLast : 0;

    if (msecLast) {
        time_t tt = msecLast / 1000LL;
        struct tm ts;
        gmtime_r(&tt, &ts);
        char s[128];
        strftime(s, 128, "%Y-%m-%d %H:%M:%S", &ts);
        s[127] = '\0';
        ptrdiff_t lenStream = STREAMLEN(streamPtr);
        size_t len = snprintf(streamPtr, lenStream, "%s.%03u", s, (unsigned)(msecLast % 1000LL));
        streamPtr += len;
    } else {
        AddString("0000-00-00 00:00:00.000");
    }

    return streamPtr;
}  // End of String_LastSeenGMT

static char *String_ReceivedGMT(char *streamPtr, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];

    uint64_t msecReceived = genericFlow ? genericFlow->msecReceived : 0;

    if (msecReceived) {
        time_t tt = msecReceived / 1000LL;
        struct tm ts;
        gmtime_r(&tt, &ts);
        char s[128];
        strftime(s, 128, "%Y-%m-%d %H:%M:%S", &ts);
        s[127] = '\0';
        ptrdiff_t lenStream = STREAMLEN(streamPtr);
        size_t len = snprintf(streamPtr, lenStream, "%s.%03llu", s, msecReceived % 1000LL);
        streamPtr += len;
    } else {
        AddString("0000-00-00 00:00:00.000");
    }

    return streamPtr;
}  // End of String_ReceivedGMT

static char *String_nbarID(char *streamPtr, recordHandle_t *recordHandle) {
    uint8_t *nbar = (uint8_t *)recordHandle->extensionList[EXnbarAppID];

    union {
        uint8_t val8[4];
        uint32_t val32;
    } pen;

    if (nbar == NULL) {
        AddString("0..0..0");
        return streamPtr;
    }

    uint32_t nbarAppIDlen = ExtensionLength(nbar);
    if (nbar[0] == 20) {  // PEN - private enterprise number
        pen.val8[0] = nbar[4];
        pen.val8[1] = nbar[3];
        pen.val8[2] = nbar[2];
        pen.val8[3] = nbar[1];

        int selector = 0;
        int index = 5;
        while (index < nbarAppIDlen) {
            selector = (selector << 8) | nbar[index];
            index++;
        }
        AddU32(nbar[0]);
        AddString("..");
        AddU32(pen.val32);
        AddString("..");
        AddU32(selector);
    } else {
        int selector = 0;
        int index = 1;
        while (index < nbarAppIDlen) {
            selector = (selector << 8) | nbar[index];
            index++;
        }
        AddU32(nbar[0]);
        AddString("..");
        AddU32(selector);
    }

    return streamPtr;
}  // End of String_nbarID

static char *String_nbarName(char *streamPtr, recordHandle_t *recordHandle) {
    uint8_t *nbar = (uint8_t *)recordHandle->extensionList[EXnbarAppID];

    if (nbar == NULL) {
        AddString("no-nbar");
        return streamPtr;
    }

    uint32_t nbarAppIDlen = ExtensionLength(nbar);
    char *name = GetNbarInfo(nbar, nbarAppIDlen);
    if (name == NULL) {
        AddString("no-info");
    } else {
        AddString(name);
    }

    return streamPtr;
}  // End of String_nbarName

static char *String_ja3(char *streamPtr, recordHandle_t *recordHandle) {
    const uint8_t *payload = (uint8_t *)(recordHandle->extensionList[EXinPayloadID]);
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)(recordHandle->extensionList[EXgenericFlowID]);
    if (payload == NULL || genericFlow->proto != IPPROTO_TCP) {
        AddString("no-ja3");
        return streamPtr;
    }

    char *ja3 = recordHandle->extensionList[JA3index];
    ssl_t *ssl = recordHandle->extensionList[SSLindex];
    if (ja3 == NULL) {
        if (ssl == NULL) {
            uint32_t payloadLength = ExtensionLength(payload);
            ssl = sslProcess(payload, payloadLength);
            recordHandle->extensionList[SSLindex] = ssl;
        }
        ja3 = ja3Process(ssl, NULL);
        recordHandle->extensionList[JA3index] = ja3;
        if (ssl == NULL || ja3 == NULL) {
            AddString("no-ja3");
            return streamPtr;
        }
    }

    if (ssl->type == CLIENTssl)
        AddString(ja3);
    else
        AddString(ja3);

    return streamPtr;
}  // End of String_ja3

static char *String_ja4(char *streamPtr, recordHandle_t *recordHandle) {
    const uint8_t *payload = (const uint8_t *)recordHandle->extensionList[EXinPayloadID];
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    if (payload == NULL || genericFlow->proto != IPPROTO_TCP) {
        AddString("no-ja4");
        return streamPtr;
    }

    ja4_t *ja4 = recordHandle->extensionList[JA4index];
    ssl_t *ssl = recordHandle->extensionList[SSLindex];
    if (ja4 == NULL) {
        if (ssl == NULL) {
            uint32_t payloadLength = ExtensionLength(payload);
            ssl = sslProcess(payload, payloadLength);
            recordHandle->extensionList[SSLindex] = ssl;
        }
        ja4 = ja4Process(ssl, genericFlow->proto);
        recordHandle->extensionList[JA4index] = ja4;
        if (ssl == NULL || ja4 == NULL) {
            AddString("no-ja4");
            return streamPtr;
        }
    }

    // ja4 is defined
    if (ja4->type == TYPE_JA4) {
        AddString(ja4->string);
    } else {
        AddString(ja4->string);
    }

    return streamPtr;
}  // End of String_ja4

static char *String_tlsVersion(char *streamPtr, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    const uint8_t *payload = (const uint8_t *)recordHandle->extensionList[EXinPayloadID];

    if (payload == NULL || genericFlow->proto != IPPROTO_TCP) {
        AddChar('0');
        return streamPtr;
    }

    ssl_t *ssl = recordHandle->extensionList[SSLindex];
    if (ssl == NULL) {
        uint32_t payloadLength = ExtensionLength(payload);
        ssl = sslProcess(payload, payloadLength);
        recordHandle->extensionList[SSLindex] = ssl;
        if (ssl == NULL) {
            AddChar('0');
            return streamPtr;
        }
    }

    /*
    0x0304 = TLS 1.3 = “13”
    0x0303 = TLS 1.2 = “12”
    0x0302 = TLS 1.1 = “11”
    0x0301 = TLS 1.0 = “10”
    0x0300 = SSL 3.0 = “s3”
    0x0200 = SSL 2.0 = “s2”
    0x0100 = SSL 1.0 = “s1”
    */

    // ssl is defined
    switch (ssl->tlsCharVersion[0]) {
        case 0:
            AddChar('0');
            break;
        case 's':
            AddString("SSL-");
            AddChar(ssl->tlsCharVersion[1]);
            break;
        case '1':
            AddString("TLS-1.");
            AddChar(ssl->tlsCharVersion[1]);
            break;
        default: {
            ptrdiff_t lenStream = STREAMLEN(streamPtr);
            size_t len = snprintf(streamPtr, lenStream, "0x%4x", ssl->tlsVersion);
            streamPtr += len;
        } break;
    }

    return streamPtr;
}  // End of String_tlsVersion

static char *String_sniName(char *streamPtr, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    const uint8_t *payload = (const uint8_t *)recordHandle->extensionList[EXinPayloadID];

    if (payload == NULL || genericFlow->proto != IPPROTO_TCP) {
        AddChar('0');
        return streamPtr;
    }

    ssl_t *ssl = recordHandle->extensionList[SSLindex];
    if (ssl == NULL) {
        uint32_t payloadLength = ExtensionLength(payload);
        ssl = sslProcess(payload, payloadLength);
        recordHandle->extensionList[SSLindex] = ssl;
        if (ssl == NULL) {
            AddChar('0');
            return streamPtr;
        }
    }

    // ssl is defined
    if (ssl != NULL) AddString(ssl->sniName);

    return streamPtr;
}  // End of String_sniName

static char *String_observationDomainID(char *streamPtr, recordHandle_t *recordHandle) {
    EXobservation_t *observation = (EXobservation_t *)recordHandle->extensionList[EXobservationID];
    if (observation) {
        ptrdiff_t lenStream = STREAMLEN(streamPtr);
        size_t len = snprintf(streamPtr, lenStream, "0x%0x", observation->domainID);
        streamPtr += len;
    } else {
        AddString("0x00");
    }

    return streamPtr;
}  // End of String_observationDomainID

static char *String_observationPointID(char *streamPtr, recordHandle_t *recordHandle) {
    EXobservation_t *observation = (EXobservation_t *)recordHandle->extensionList[EXobservationID];
    if (observation) {
        ptrdiff_t lenStream = STREAMLEN(streamPtr);
        size_t len = snprintf(streamPtr, lenStream, "0x%0llx", (long long unsigned)observation->pointID);
        streamPtr += len;
    } else {
        AddString("0x00");
    }

    return streamPtr;
}  // End of String_observationPointID

static char *String_EventTime(char *streamPtr, recordHandle_t *recordHandle) {
    EXnselCommon_t *nselCommon = (EXnselCommon_t *)recordHandle->extensionList[EXnselCommonID];
    EXnatCommon_t *natCommon = (EXnatCommon_t *)recordHandle->extensionList[EXnatCommonID];

    uint64_t msecEvent = 0;
    if (nselCommon)
        msecEvent = nselCommon->msecEvent;
    else if (natCommon)
        msecEvent = natCommon->msecEvent;

    if (msecEvent) {
        time_t tt = msecEvent / 1000LL;
        struct tm *ts = localtime(&tt);
        char s[128];
        strftime(s, 128, "%Y-%m-%d %H:%M:%S", ts);
        s[127] = '\0';
        ptrdiff_t lenStream = STREAMLEN(streamPtr);
        size_t len = snprintf(streamPtr, lenStream, "%s.%03llu", s, msecEvent % 1000LL);
        streamPtr += len;
    } else {
        AddString("0000-00-00 00:00:00.000");
    }

    return streamPtr;
}  // End of String_EventTime

static char *String_Duration(char *streamPtr, recordHandle_t *recordHandle) {
    ptrdiff_t lenStream = STREAMLEN(streamPtr);
    size_t len = snprintf(streamPtr, lenStream, "%.3f", duration);
    streamPtr += len;

    return streamPtr;
}  // End of String_Duration

static char *String_Duration_Seconds(char *streamPtr, recordHandle_t *recordHandle) {
    ptrdiff_t lenStream = STREAMLEN(streamPtr);
    size_t len = snprintf(streamPtr, lenStream, "%.3f", duration);
    streamPtr += len;

    return streamPtr;
}  // End of String_Duration_Seconds

static char *String_Protocol(char *streamPtr, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    uint8_t proto = genericFlow ? genericFlow->proto : 0;
    AddU32(proto);

    return streamPtr;
}  // End of String_Protocol

static char *String_SrcAddr(char *streamPtr, recordHandle_t *recordHandle) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    char tmp_str[IP_STRING_LEN];
    tmp_str[0] = 0;
    if (ipv4Flow) {
        uint32_t ip = htonl(ipv4Flow->srcAddr);
        inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
    } else if (ipv6Flow) {
        uint64_t ip[2];
        ip[0] = htonll(ipv6Flow->srcAddr[0]);
        ip[1] = htonll(ipv6Flow->srcAddr[1]);
        inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
    } else {
        strcpy(tmp_str, "0.0.0.0");
    }
    tmp_str[IP_STRING_LEN - 1] = 0;

    AddString(tmp_str);

    return streamPtr;
}  // End of String_SrcAddr

static char *String_DstAddr(char *streamPtr, recordHandle_t *recordHandle) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    char tmp_str[IP_STRING_LEN];
    tmp_str[0] = 0;
    if (ipv4Flow) {
        uint32_t ip = htonl(ipv4Flow->dstAddr);
        inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
    } else if (ipv6Flow) {
        uint64_t ip[2];
        ip[0] = htonll(ipv6Flow->dstAddr[0]);
        ip[1] = htonll(ipv6Flow->dstAddr[1]);
        inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
    } else {
        strcpy(tmp_str, "0.0.0.0");
    }
    tmp_str[IP_STRING_LEN - 1] = 0;

    AddString(tmp_str);

    return streamPtr;
}  // End of String_DstAddr

static char *String_SrcNet(char *streamPtr, recordHandle_t *recordHandle) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)recordHandle->extensionList[EXflowMiscID];
    uint16_t srcMask = flowMisc ? flowMisc->srcMask : 0;

    char tmp_str[IP_STRING_LEN];
    tmp_str[0] = 0;
    if (ipv4Flow) {
        uint32_t ip = ApplyV4NetMaskBits(ipv4Flow->srcAddr, srcMask);
        ip = htonl(ip);
        inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
    } else if (ipv6Flow) {
        uint64_t *ip = ApplyV6NetMaskBits(ipv6Flow->srcAddr, srcMask);
        ip[0] = htonll(ip[0]);
        ip[1] = htonll(ip[1]);
        inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
    } else {
        strcpy(tmp_str, "0.0.0.0");
    }
    tmp_str[IP_STRING_LEN - 1] = 0;

    AddString(tmp_str);
    AddChar('/');
    AddU32(srcMask);

    return streamPtr;
}  // End of String_SrcNet

static char *String_DstNet(char *streamPtr, recordHandle_t *recordHandle) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)recordHandle->extensionList[EXflowMiscID];
    uint16_t dstMask = flowMisc ? flowMisc->dstMask : 0;

    char tmp_str[IP_STRING_LEN];
    tmp_str[0] = 0;
    if (ipv4Flow) {
        uint32_t ip = ApplyV4NetMaskBits(ipv4Flow->dstAddr, dstMask);
        ip = htonl(ip);
        inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
    } else if (ipv6Flow) {
        uint64_t *ip = ApplyV6NetMaskBits(ipv6Flow->dstAddr, dstMask);
        ip[0] = htonll(ip[0]);
        ip[1] = htonll(ip[1]);
        inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
    } else {
        strcpy(tmp_str, "0.0.0.0");
    }
    tmp_str[IP_STRING_LEN - 1] = 0;

    AddString(tmp_str);
    AddChar('/');
    AddU32(dstMask);

    return streamPtr;
}  // End of String_DstNet

static char *String_SrcPort(char *streamPtr, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    uint16_t port = genericFlow ? genericFlow->srcPort : 0;
    AddU32(port);

    return streamPtr;
}  // End of String_SrcPort

static char *String_DstPort(char *streamPtr, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    AddString(ICMP_Port_decode(genericFlow));

    return streamPtr;
}  // End of String_DstPort

static char *String_ICMP_type(char *streamPtr, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    uint16_t type = genericFlow ? genericFlow->icmpType : 0;
    // Force printing type regardless of protocol
    AddU32(type);

    return streamPtr;
}  // End of String_ICMP_type

static char *String_ICMP_code(char *streamPtr, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    uint16_t code = genericFlow ? genericFlow->icmpCode : 0;
    // Force printing code regardless of protocol
    AddU32(code);

    return streamPtr;
}  // End of String_ICMP_code

static char *String_SrcAS(char *streamPtr, recordHandle_t *recordHandle) {
    EXasRouting_t *asRouting = (EXasRouting_t *)recordHandle->extensionList[EXasRoutingID];
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    uint32_t srcAS = asRouting ? asRouting->srcAS : 0;
    if (ipv4Flow && srcAS == 0) {
        srcAS = LookupV4AS(ipv4Flow->srcAddr);
    }
    if (ipv6Flow && srcAS == 0) {
        srcAS = LookupV6AS(ipv6Flow->srcAddr);
    }

    AddU32(srcAS);

    return streamPtr;
}  // End of String_SrcAS

static char *String_DstAS(char *streamPtr, recordHandle_t *recordHandle) {
    EXasRouting_t *asRouting = (EXasRouting_t *)recordHandle->extensionList[EXasRoutingID];
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    uint32_t dstAS = asRouting ? asRouting->dstAS : 0;
    if (ipv4Flow && dstAS == 0) {
        dstAS = LookupV4AS(ipv4Flow->dstAddr);
    }
    if (ipv6Flow && dstAS == 0) {
        dstAS = LookupV6AS(ipv6Flow->dstAddr);
    }

    AddU32(dstAS);

    return streamPtr;
}  // End of String_DstAS

static char *String_NextAS(char *streamPtr, recordHandle_t *recordHandle) {
    EXasAdjacent_t *asAdjacent = (EXasAdjacent_t *)recordHandle->extensionList[EXasAdjacentID];
    uint32_t nextAS = asAdjacent ? asAdjacent->nextAdjacentAS : 0;
    AddU32(nextAS);

    return streamPtr;
}  // End of String_NextAS

static char *String_PrevAS(char *streamPtr, recordHandle_t *recordHandle) {
    EXasAdjacent_t *asAdjacent = (EXasAdjacent_t *)recordHandle->extensionList[EXasAdjacentID];
    uint32_t prevAS = asAdjacent ? asAdjacent->prevAdjacentAS : 0;
    AddU32(prevAS);

    return streamPtr;
}  // End of String_PrevAS

static char *String_Input(char *streamPtr, recordHandle_t *recordHandle) {
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)recordHandle->extensionList[EXflowMiscID];
    uint32_t input = flowMisc ? flowMisc->input : 0;
    AddU32(input);

    return streamPtr;
}  // End of String_Input

static char *String_InputName(char *streamPtr, recordHandle_t *recordHandle) {
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)recordHandle->extensionList[EXflowMiscID];
    uint32_t input = flowMisc ? flowMisc->input : 0;
    char ifName[128];
    AddString(GetIfName(input, ifName, sizeof(ifName)));

    return streamPtr;
}  // End of String_InputName

static char *String_Output(char *streamPtr, recordHandle_t *recordHandle) {
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)recordHandle->extensionList[EXflowMiscID];
    uint32_t output = flowMisc ? flowMisc->output : 0;
    AddU32(output);

    return streamPtr;
}  // End of String_Output

static char *String_OutputName(char *streamPtr, recordHandle_t *recordHandle) {
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)recordHandle->extensionList[EXflowMiscID];
    uint32_t output = flowMisc ? flowMisc->output : 0;
    char ifName[128];
    AddString(GetIfName(output, ifName, sizeof(ifName)));

    return streamPtr;
}  // End of String_OutputName

static char *String_InPackets(char *streamPtr, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    uint64_t packets = genericFlow ? genericFlow->inPackets : 0;

    AddU64(packets);

    return streamPtr;
}  // End of String_InPackets

static char *String_OutPackets(char *streamPtr, recordHandle_t *recordHandle) {
    EXcntFlow_t *cntFlow = (EXcntFlow_t *)recordHandle->extensionList[EXcntFlowID];
    uint64_t packets = cntFlow ? cntFlow->outPackets : 0;

    AddU64(packets);

    return streamPtr;
}  // End of String_OutPackets

static char *String_InBytes(char *streamPtr, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    uint64_t bytes = genericFlow ? genericFlow->inBytes : 0;

    AddU64(bytes);

    return streamPtr;
}  // End of String_InBytes

static char *String_OutBytes(char *streamPtr, recordHandle_t *recordHandle) {
    EXcntFlow_t *cntFlow = (EXcntFlow_t *)recordHandle->extensionList[EXcntFlowID];
    uint64_t bytes = cntFlow ? cntFlow->outBytes : 0;

    AddU64(bytes);

    return streamPtr;
}  // End of String_OutBytes

static char *String_Flows(char *streamPtr, recordHandle_t *recordHandle) {
    EXcntFlow_t *cntFlow = (EXcntFlow_t *)recordHandle->extensionList[EXcntFlowID];
    uint64_t flows = cntFlow ? cntFlow->flows : 1;

    AddU64(flows);

    return streamPtr;
}  // End of String_Flows

static char *String_NextHop(char *streamPtr, recordHandle_t *recordHandle) {
    EXipNextHopV4_t *ipNextHopV4 = (EXipNextHopV4_t *)recordHandle->extensionList[EXipNextHopV4ID];
    EXipNextHopV6_t *ipNextHopV6 = (EXipNextHopV6_t *)recordHandle->extensionList[EXipNextHopV6ID];

    char tmp_str[IP_STRING_LEN];
    tmp_str[0] = 0;
    if (ipNextHopV4) {
        uint32_t ip = htonl(ipNextHopV4->ip);
        inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
    } else if (ipNextHopV6) {
        uint64_t ip[2];

        ip[0] = htonll(ipNextHopV6->ip[0]);
        ip[1] = htonll(ipNextHopV6->ip[1]);
        inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
    } else {
        strcpy(tmp_str, "0.0.0.0");
    }
    tmp_str[IP_STRING_LEN - 1] = 0;

    AddString(tmp_str);

    return streamPtr;
}  // End of String_NextHop

static char *String_BGPNextHop(char *streamPtr, recordHandle_t *recordHandle) {
    EXbgpNextHopV4_t *bgpNextHopV4 = (EXbgpNextHopV4_t *)recordHandle->extensionList[EXbgpNextHopV4ID];
    EXbgpNextHopV6_t *bgpNextHopV6 = (EXbgpNextHopV6_t *)recordHandle->extensionList[EXbgpNextHopV6ID];

    char tmp_str[IP_STRING_LEN];
    tmp_str[0] = 0;
    if (bgpNextHopV4) {
        uint32_t ip = htonl(bgpNextHopV4->ip);
        inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
    } else if (bgpNextHopV6) {
        uint64_t ip[2];

        ip[0] = htonll(bgpNextHopV6->ip[0]);
        ip[1] = htonll(bgpNextHopV6->ip[1]);
        inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
    } else {
        strcpy(tmp_str, "0.0.0.0");
    }
    tmp_str[IP_STRING_LEN - 1] = 0;

    AddString(tmp_str);

    return streamPtr;
}  // End of String_BGPNextHop

static char *String_RouterIP(char *streamPtr, recordHandle_t *recordHandle) {
    EXipReceivedV4_t *ipReceivedV4 = (EXipReceivedV4_t *)recordHandle->extensionList[EXipReceivedV4ID];
    EXipReceivedV6_t *ipReceivedV6 = (EXipReceivedV6_t *)recordHandle->extensionList[EXipReceivedV6ID];

    char tmp_str[IP_STRING_LEN];
    tmp_str[0] = 0;
    if (ipReceivedV4) {
        uint32_t ip = htonl(ipReceivedV4->ip);
        inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
    } else if (ipReceivedV6) {
        uint64_t ip[2];

        ip[0] = htonll(ipReceivedV6->ip[0]);
        ip[1] = htonll(ipReceivedV6->ip[1]);
        inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
    } else {
        strcpy(tmp_str, "0.0.0.0");
    }
    tmp_str[IP_STRING_LEN - 1] = 0;

    AddString(tmp_str);

    return streamPtr;
}  // End of String_RouterIP

static char *String_Tos(char *streamPtr, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    uint32_t srcTos = genericFlow ? genericFlow->srcTos : 0;

    AddU32(srcTos);

    return streamPtr;
}  // End of String_Tos

static char *String_SrcTos(char *streamPtr, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    uint32_t srcTos = genericFlow ? genericFlow->srcTos : 0;

    AddU32(srcTos);

    return streamPtr;
}  // End of String_SrcTos

static char *String_DstTos(char *streamPtr, recordHandle_t *recordHandle) {
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)recordHandle->extensionList[EXflowMiscID];
    uint32_t dstTos = flowMisc ? flowMisc->dstTos : 0;

    AddU32(dstTos);

    return streamPtr;
}  // End of String_DstTos

static char *String_SrcMask(char *streamPtr, recordHandle_t *recordHandle) {
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)recordHandle->extensionList[EXflowMiscID];
    uint32_t srcMask = flowMisc ? flowMisc->srcMask : 0;

    AddU32(srcMask);

    return streamPtr;
}  // End of String_SrcMask

static char *String_DstMask(char *streamPtr, recordHandle_t *recordHandle) {
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)recordHandle->extensionList[EXflowMiscID];
    uint32_t dstMask = flowMisc ? flowMisc->dstMask : 0;

    AddU32(dstMask);

    return streamPtr;
}  // End of String_DstMask

static char *String_SrcVlan(char *streamPtr, recordHandle_t *recordHandle) {
    EXvLan_t *vLan = (EXvLan_t *)recordHandle->extensionList[EXvLanID];
    uint32_t srcVlan = vLan ? vLan->srcVlan : 0;

    AddU32(srcVlan);

    return streamPtr;
}  // End of String_SrcVlan

static char *String_DstVlan(char *streamPtr, recordHandle_t *recordHandle) {
    EXvLan_t *vLan = (EXvLan_t *)recordHandle->extensionList[EXvLanID];
    uint32_t dstVlan = vLan ? vLan->dstVlan : 0;

    AddU32(dstVlan);

    return streamPtr;
}  // End of String_DstVlan

static char *String_Dir(char *streamPtr, recordHandle_t *recordHandle) {
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)recordHandle->extensionList[EXflowMiscID];
    uint32_t dir = flowMisc ? flowMisc->dir : 0;

    AddChar(dir ? 'E' : 'I');

    return streamPtr;
}  // End of String_Dir

static char *String_FwdStatus(char *streamPtr, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    uint32_t fwdStatus = genericFlow ? genericFlow->fwdStatus : 0;

    AddU32(fwdStatus);

    return streamPtr;
}  // End of String_FwdStatus

static char *String_BiFlowDir(char *streamPtr, recordHandle_t *recordHandle) {
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)recordHandle->extensionList[EXflowMiscID];
    uint32_t biFlowDir = flowMisc ? flowMisc->biFlowDir : 0;

    AddU32(biFlowDir);

    return streamPtr;
}  // End of String_BiFlowDir

static char *String_FlowEndReason(char *streamPtr, recordHandle_t *recordHandle) {
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)recordHandle->extensionList[EXflowMiscID];
    uint32_t flowEndReason = flowMisc ? flowMisc->flowEndReason : 0;

    AddU32(flowEndReason);

    return streamPtr;
}  // End of String_FlowEndReason

static char *String_ipTTL(char *streamPtr, recordHandle_t *recordHandle) {
    EXipInfo_t *ipInfo = (EXipInfo_t *)recordHandle->extensionList[EXipInfoID];
    uint8_t ttl = ipInfo ? ipInfo->ttl : 0;

    AddU32(ttl);

    return streamPtr;
}  // End of String_ipTTL

static char *String_ipminTTL(char *streamPtr, recordHandle_t *recordHandle) {
    EXipInfo_t *ipInfo = (EXipInfo_t *)recordHandle->extensionList[EXipInfoID];
    uint8_t ttl = ipInfo ? ipInfo->minTTL : 0;

    AddU32(ttl);

    return streamPtr;
}  // End of String_ipminTTL

static char *String_ipmaxTTL(char *streamPtr, recordHandle_t *recordHandle) {
    EXipInfo_t *ipInfo = (EXipInfo_t *)recordHandle->extensionList[EXipInfoID];
    uint8_t ttl = ipInfo ? ipInfo->maxTTL : 0;

    AddU32(ttl);

    return streamPtr;
}  // End of String_ipminTTL

static char *String_ipFrag(char *streamPtr, recordHandle_t *recordHandle) {
    EXipInfo_t *ipInfo = (EXipInfo_t *)recordHandle->extensionList[EXipInfoID];
    EXipInfo_t localIpInfo = {0};
    if (ipInfo == NULL) ipInfo = &localIpInfo;

    char *DF = ipInfo->fragmentFlags & flagDF ? "DF" : "--";
    char *MF = ipInfo->fragmentFlags & flagMF ? "MF" : "--";
    AddString(DF);
    AddString(MF);

    return streamPtr;
}  // End of String_ipFrag

static char *String_Flags(char *streamPtr, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    uint32_t flags = genericFlow && genericFlow->proto == IPPROTO_TCP ? genericFlow->tcpFlags : 0;

    AddString(FlagsString(flags));

    return streamPtr;
}  // End of String_Flags

static char *printMacAddr(char *streamPtr, uint64_t macAddr) {
    uint8_t mac[6];
    for (int i = 0; i < 6; i++) {
        mac[i] = (macAddr >> (i * 8)) & 0xFF;
    }
    ptrdiff_t lenStream = STREAMLEN(streamPtr);
    size_t len = snprintf(streamPtr, lenStream, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);
    streamPtr += len;

    return streamPtr;
}  // End of printMacAddr

static char *String_InSrcMac(char *streamPtr, recordHandle_t *recordHandle) {
    EXmacAddr_t *macAddr = (EXmacAddr_t *)recordHandle->extensionList[EXmacAddrID];
    uint64_t mac = macAddr ? macAddr->inSrcMac : 0;

    return printMacAddr(streamPtr, mac);
}  // End of String_InSrcMac

static char *String_OutDstMac(char *streamPtr, recordHandle_t *recordHandle) {
    EXmacAddr_t *macAddr = (EXmacAddr_t *)recordHandle->extensionList[EXmacAddrID];
    uint64_t mac = macAddr ? macAddr->outDstMac : 0;

    return printMacAddr(streamPtr, mac);
}  // End of String_OutDstMac

static char *String_InDstMac(char *streamPtr, recordHandle_t *recordHandle) {
    EXmacAddr_t *macAddr = (EXmacAddr_t *)recordHandle->extensionList[EXmacAddrID];
    uint64_t mac = macAddr ? macAddr->inDstMac : 0;

    return printMacAddr(streamPtr, mac);
}  // End of String_InDstMac

static char *String_OutSrcMac(char *streamPtr, recordHandle_t *recordHandle) {
    EXmacAddr_t *macAddr = (EXmacAddr_t *)recordHandle->extensionList[EXmacAddrID];
    uint64_t mac = macAddr ? macAddr->outSrcMac : 0;

    return printMacAddr(streamPtr, mac);
}  // End of String_OutSrcMac

static inline char *printLabel(char *streamPtr, uint32_t label) {
    ptrdiff_t lenStream = STREAMLEN(streamPtr);
    size_t len = snprintf(streamPtr, lenStream, "%8u-%1u-%1u", label >> 4, (label & 0xF) >> 1, label & 1);
    streamPtr += len;

    return streamPtr;
}  // End of printLabel

static char *String_MPLS_1(char *streamPtr, recordHandle_t *recordHandle) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)recordHandle->extensionList[EXmplsLabelID];
    uint32_t label = mplsLabel ? mplsLabel->mplsLabel[0] : 0;

    return printLabel(streamPtr, label);
}  // End of String_MPLS

static char *String_MPLS_2(char *streamPtr, recordHandle_t *recordHandle) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)recordHandle->extensionList[EXmplsLabelID];
    uint32_t label = mplsLabel ? mplsLabel->mplsLabel[1] : 0;

    return printLabel(streamPtr, label);
}  // End of String_MPLS

static char *String_MPLS_3(char *streamPtr, recordHandle_t *recordHandle) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)recordHandle->extensionList[EXmplsLabelID];
    uint32_t label = mplsLabel ? mplsLabel->mplsLabel[2] : 0;

    return printLabel(streamPtr, label);
}  // End of String_MPLS

static char *String_MPLS_4(char *streamPtr, recordHandle_t *recordHandle) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)recordHandle->extensionList[EXmplsLabelID];
    uint32_t label = mplsLabel ? mplsLabel->mplsLabel[3] : 0;

    return printLabel(streamPtr, label);
}  // End of String_MPLS

static char *String_MPLS_5(char *streamPtr, recordHandle_t *recordHandle) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)recordHandle->extensionList[EXmplsLabelID];
    uint32_t label = mplsLabel ? mplsLabel->mplsLabel[4] : 0;

    return printLabel(streamPtr, label);
}  // End of String_MPLS

static char *String_MPLS_6(char *streamPtr, recordHandle_t *recordHandle) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)recordHandle->extensionList[EXmplsLabelID];
    uint32_t label = mplsLabel ? mplsLabel->mplsLabel[5] : 0;

    return printLabel(streamPtr, label);
}  // End of String_MPLS

static char *String_MPLS_7(char *streamPtr, recordHandle_t *recordHandle) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)recordHandle->extensionList[EXmplsLabelID];
    uint32_t label = mplsLabel ? mplsLabel->mplsLabel[6] : 0;

    return printLabel(streamPtr, label);
}  // End of String_MPLS

static char *String_MPLS_8(char *streamPtr, recordHandle_t *recordHandle) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)recordHandle->extensionList[EXmplsLabelID];
    uint32_t label = mplsLabel ? mplsLabel->mplsLabel[7] : 0;

    return printLabel(streamPtr, label);
}  // End of String_MPLS

static char *String_MPLS_9(char *streamPtr, recordHandle_t *recordHandle) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)recordHandle->extensionList[EXmplsLabelID];
    uint32_t label = mplsLabel ? mplsLabel->mplsLabel[8] : 0;

    return printLabel(streamPtr, label);
}  // End of String_MPLS

static char *String_MPLS_10(char *streamPtr, recordHandle_t *recordHandle) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)recordHandle->extensionList[EXmplsLabelID];
    uint32_t label = mplsLabel ? mplsLabel->mplsLabel[9] : 0;

    return printLabel(streamPtr, label);
}  // End of String_MPLS

static char *String_MPLSs(char *streamPtr, recordHandle_t *recordHandle) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)recordHandle->extensionList[EXmplsLabelID];
    uint32_t label[10] = {0};
    if (mplsLabel) memcpy((void *)label, (void *)mplsLabel->mplsLabel, sizeof(label));

    ptrdiff_t lenStream = STREAMLEN(streamPtr);
    size_t len = snprintf(streamPtr, lenStream,
                          "%8u-%1u-%1u %8u-%1u-%1u %8u-%1u-%1u %8u-%1u-%1u %8u-%1u-%1u %8u-%1u-%1u %8u-%1u-%1u %8u-%1u-%1u "
                          "%8u-%1u-%1u %8u-%1u-%1u ",
                          label[0] >> 4, (label[0] & 0xF) >> 1, label[0] & 1, label[1] >> 4, (label[1] & 0xF) >> 1, label[1] & 1, label[2] >> 4,
                          (label[2] & 0xF) >> 1, label[2] & 1, label[3] >> 4, (label[3] & 0xF) >> 1, label[3] & 1, label[4] >> 4,
                          (label[4] & 0xF) >> 1, label[4] & 1, label[5] >> 4, (label[5] & 0xF) >> 1, label[5] & 1, label[6] >> 4,
                          (label[6] & 0xF) >> 1, label[6] & 1, label[7] >> 4, (label[7] & 0xF) >> 1, label[7] & 1, label[8] >> 4,
                          (label[8] & 0xF) >> 1, label[8] & 1, label[9] >> 4, (label[9] & 0xF) >> 1, label[9] & 1);
    streamPtr += len;

    return streamPtr;
}  // End of String_MPLSs

static char *String_Engine(char *streamPtr, recordHandle_t *recordHandle) {
    AddU32(recordHandle->recordHeaderV3->engineType);
    AddChar('/');
    AddU32(recordHandle->recordHeaderV3->engineID);

    return streamPtr;
}  // End of String_Engine

static char *String_Label(char *streamPtr, recordHandle_t *recordHandle) {
    AddString("<none>");

    return streamPtr;
}  // End of String_Label

static char *String_ClientLatency(char *streamPtr, recordHandle_t *recordHandle) {
    EXlatency_t *latency = (EXlatency_t *)recordHandle->extensionList[EXlatencyID];
    double msecLatency = latency ? (double)latency->usecClientNwDelay / 1000.0 : 0.0;

    ptrdiff_t lenStream = STREAMLEN(streamPtr);
    size_t len = snprintf(streamPtr, lenStream, "%.3f", msecLatency);
    streamPtr += len;

    return streamPtr;
}  // End of String_ClientLatency

static char *String_ServerLatency(char *streamPtr, recordHandle_t *recordHandle) {
    EXlatency_t *latency = (EXlatency_t *)recordHandle->extensionList[EXlatencyID];
    double msecLatency = latency ? (double)latency->usecServerNwDelay / 1000.0 : 0.0;

    ptrdiff_t lenStream = STREAMLEN(streamPtr);
    size_t len = snprintf(streamPtr, lenStream, "%.3f", msecLatency);
    streamPtr += len;

    return streamPtr;
}  // End of String_ServerLatency

static char *String_AppLatency(char *streamPtr, recordHandle_t *recordHandle) {
    EXlatency_t *latency = (EXlatency_t *)recordHandle->extensionList[EXlatencyID];
    double msecLatency = latency ? (double)latency->usecApplLatency / 1000.0 : 0.0;

    ptrdiff_t lenStream = STREAMLEN(streamPtr);
    size_t len = snprintf(streamPtr, lenStream, "%.3f", msecLatency);
    streamPtr += len;

    return streamPtr;
}  // End of String_AppLatency

static char *String_bps(char *streamPtr, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    uint64_t inBytes = genericFlow ? genericFlow->inBytes : 0;

    uint64_t bps = 0;
    if (duration) {
        bps = ((inBytes << 3) / duration);  // bits per second. ( >> 3 ) -> * 8 to convert octets into bits
    }

    AddU64(bps);

    return streamPtr;
}  // End of String_bps

static char *String_pps(char *streamPtr, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    uint64_t inPackets = genericFlow ? genericFlow->inPackets : 0;

    uint64_t pps = 0;
    if (duration) {
        pps = inPackets / duration;  // packets per second
    }

    AddU64(pps);

    return streamPtr;
}  // End of String_Duration

static char *String_bpp(char *streamPtr, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    uint64_t inPackets = genericFlow ? genericFlow->inPackets : 0;
    uint64_t inBytes = genericFlow ? genericFlow->inBytes : 0;

    uint32_t Bpp = 0;
    if (inPackets) Bpp = inBytes / inPackets;  // Bytes per Packet

    AddU32(Bpp);

    return streamPtr;
}  // End of String_bpp

static char *String_ExpSysID(char *streamPtr, recordHandle_t *recordHandle) {
    AddU32(recordHandle->recordHeaderV3->exporterID);

    return streamPtr;
}  // End of String_ExpSysID

static char *String_SrcCountry(char *streamPtr, recordHandle_t *recordHandle) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    if (ipv4Flow) {
        if (recordHandle->geo[0] == '\0') LookupV4Country(ipv4Flow->srcAddr, recordHandle->geo);
    } else if (ipv6Flow) {
        if (recordHandle->geo[0] == '\0') LookupV6Country(ipv6Flow->srcAddr, recordHandle->geo);
    }

    if (recordHandle->geo[0]) {
        AddChar(recordHandle->geo[0]);
        AddChar(recordHandle->geo[1]);
    } else {
        AddChar('.');
        AddChar('.');
    }

    return streamPtr;
}  // End of String_SrcCountry

static char *String_DstCountry(char *streamPtr, recordHandle_t *recordHandle) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    if (ipv4Flow) {
        if (recordHandle->geo[2] == '\0') LookupV4Country(ipv4Flow->dstAddr, &recordHandle->geo[2]);
    } else if (ipv6Flow) {
        if (recordHandle->geo[2] == '\0') LookupV6Country(ipv6Flow->dstAddr, &recordHandle->geo[2]);
    }

    if (recordHandle->geo[2]) {
        AddChar(recordHandle->geo[2]);
        AddChar(recordHandle->geo[3]);
    } else {
        AddChar('.');
        AddChar('.');
    }

    return streamPtr;
}  // End of String_DstCountry

static char *String_SrcLocation(char *streamPtr, recordHandle_t *recordHandle) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    char location[128];
    location[0] = '\0';
    if (ipv4Flow) {
        LookupV4Location(ipv4Flow->srcAddr, location, sizeof(location));
    } else if (ipv6Flow) {
        LookupV6Location(ipv6Flow->srcAddr, location, sizeof(location));
    }

    if (location[0])
        AddString(location);
    else
        AddString("no location info");

    return streamPtr;
}  // End of String_SrcLocation

static char *String_DstLocation(char *streamPtr, recordHandle_t *recordHandle) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    char location[128];
    location[0] = '\0';
    if (ipv4Flow) {
        LookupV4Location(ipv4Flow->dstAddr, location, sizeof(location));
    } else if (ipv6Flow) {
        LookupV6Location(ipv6Flow->dstAddr, location, sizeof(location));
    }

    if (location[0])
        AddString(location);
    else
        AddString("no location info");

    return streamPtr;
}  // End of String_DstLocation

static char *String_SrcASorganisation(char *streamPtr, recordHandle_t *recordHandle) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    if (ipv4Flow) {
        AddString(LookupV4ASorg(ipv4Flow->srcAddr));
    } else if (ipv6Flow) {
        AddString(LookupV6ASorg(ipv6Flow->srcAddr));
    } else {
        AddString("none");
    }

    return streamPtr;
}  // End of String_SrcASorganisation

static char *String_DstASorganisation(char *streamPtr, recordHandle_t *recordHandle) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    if (ipv4Flow) {
        AddString(LookupV4ASorg(ipv4Flow->dstAddr));
    } else if (ipv6Flow) {
        AddString(LookupV6ASorg(ipv6Flow->dstAddr));
    } else {
        AddString("none");
    }

    return streamPtr;
}  // End of String_DstASorganisation

static char *String_SrcTor(char *streamPtr, recordHandle_t *recordHandle) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    char torInfo[4];
    if (ipv4Flow) {
        LookupV4Tor(ipv4Flow->srcAddr, genericFlow->msecFirst, genericFlow->msecLast, torInfo);
    } else {
        LookupV6Tor(ipv6Flow->srcAddr, genericFlow->msecFirst, genericFlow->msecLast, torInfo);
    }
    AddString(torInfo);

    return streamPtr;
}  // End of String_SrcTor

static char *String_DstTor(char *streamPtr, recordHandle_t *recordHandle) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];

    char torInfo[4];
    if (ipv4Flow) {
        LookupV4Tor(ipv4Flow->dstAddr, genericFlow->msecFirst, genericFlow->msecLast, torInfo);
    } else {
        LookupV6Tor(ipv6Flow->dstAddr, genericFlow->msecFirst, genericFlow->msecLast, torInfo);
    }
    AddString(torInfo);

    return streamPtr;
}  // End of String_DstTor

static char *String_ivrf(char *streamPtr, recordHandle_t *recordHandle) {
    EXvrf_t *vrf = (EXvrf_t *)recordHandle->extensionList[EXvrfID];
    uint32_t ingress = vrf ? vrf->ingressVrf : 0;

    AddU32(ingress);

    return streamPtr;
}  // End of String_ivrf

static char *String_evrf(char *streamPtr, recordHandle_t *recordHandle) {
    EXvrf_t *vrf = (EXvrf_t *)recordHandle->extensionList[EXvrfID];
    uint32_t egress = vrf ? vrf->egressVrf : 0;

    AddU32(egress);

    return streamPtr;
}  // End of String_evrf

static char *String_ivrfName(char *streamPtr, recordHandle_t *recordHandle) {
    EXvrf_t *vrf = (EXvrf_t *)recordHandle->extensionList[EXvrfID];
    uint32_t ingress = vrf ? vrf->ingressVrf : 0;

    char vrfName[128];
    AddString(GetVrfName(ingress, vrfName, sizeof(vrfName)));

    return streamPtr;
}  // End of String_ivrfName

static char *String_evrfName(char *streamPtr, recordHandle_t *recordHandle) {
    EXvrf_t *vrf = (EXvrf_t *)recordHandle->extensionList[EXvrfID];
    uint32_t egress = vrf ? vrf->egressVrf : 0;

    char vrfName[128];
    AddString(GetVrfName(egress, vrfName, sizeof(vrfName)));

    return streamPtr;
}  // End of String_evrfName

static char *String_pfIfName(char *streamPtr, recordHandle_t *recordHandle) {
    EXpfinfo_t *pfinfo = (EXpfinfo_t *)recordHandle->extensionList[EXpfinfoID];

    AddString(pfinfo ? pfinfo->ifname : "<no-pf>");

    return streamPtr;
}  // End of String_pfIfName

static char *String_pfAction(char *streamPtr, recordHandle_t *recordHandle) {
    EXpfinfo_t *pfinfo = (EXpfinfo_t *)recordHandle->extensionList[EXpfinfoID];

    if (pfinfo) {
        AddString(pfAction(pfinfo->action));
    } else {
        AddString("no-pf");
    }

    return streamPtr;
}  // End of String_pfAction

static char *String_pfReason(char *streamPtr, recordHandle_t *recordHandle) {
    EXpfinfo_t *pfinfo = (EXpfinfo_t *)recordHandle->extensionList[EXpfinfoID];

    if (pfinfo) {
        AddString(pfReason(pfinfo->reason));
    } else {
        AddString("no-pf");
    }

    return streamPtr;
}  // End of String_pfReason

static char *String_pfdir(char *streamPtr, recordHandle_t *recordHandle) {
    EXpfinfo_t *pfinfo = (EXpfinfo_t *)recordHandle->extensionList[EXpfinfoID];

    if (pfinfo) {
        AddString(pfinfo->dir ? "in" : "out");
    } else {
        AddString("no pfinfo");
    }

    return streamPtr;
}  // End of String_pfdir

static char *String_pfrule(char *streamPtr, recordHandle_t *recordHandle) {
    EXpfinfo_t *pfinfo = (EXpfinfo_t *)recordHandle->extensionList[EXpfinfoID];
    uint32_t rulenr = pfinfo ? pfinfo->rulenr : 0;

    AddU32(rulenr);

    return streamPtr;
}  // End of String_pfrule

static char *String_nfc(char *streamPtr, recordHandle_t *recordHandle) {
    EXnselCommon_t *nselCommon = (EXnselCommon_t *)recordHandle->extensionList[EXnselCommonID];
    uint32_t connID = nselCommon ? nselCommon->connID : 0;

    AddU32(connID);

    return streamPtr;
}  // End of String_nfc

static char *String_evt(char *streamPtr, recordHandle_t *recordHandle) {
    EXnselCommon_t *nselCommon = (EXnselCommon_t *)recordHandle->extensionList[EXnselCommonID];
    EXnatCommon_t *natCommon = (EXnatCommon_t *)recordHandle->extensionList[EXnatCommonID];

    uint32_t evtNum = 0;
    if (nselCommon) {
        evtNum = nselCommon->fwEvent;
    } else if (natCommon) {
        evtNum = natCommon->natEvent;
    }
    AddU32(evtNum);

    return streamPtr;
}  // End of String_evt

static char *String_xevt(char *streamPtr, recordHandle_t *recordHandle) {
    EXnselCommon_t *nselCommon = (EXnselCommon_t *)recordHandle->extensionList[EXnselCommonID];

    if (nselCommon) {
        AddString(fwXEventString(nselCommon->fwXevent));
    } else {
        AddString("no-evt");
    }

    return streamPtr;
}  // End of String_xevt

static char *String_msecEvent(char *streamPtr, recordHandle_t *recordHandle) {
    EXnselCommon_t *nselCommon = (EXnselCommon_t *)recordHandle->extensionList[EXnselCommonID];
    EXnatCommon_t *natCommon = (EXnatCommon_t *)recordHandle->extensionList[EXnatCommonID];
    uint64_t msecEvent = nselCommon ? nselCommon->msecEvent : (natCommon ? natCommon->msecEvent : 0);

    AddU64(msecEvent);

    return streamPtr;
}  // End of String_msecEvent

static char *String_iacl(char *streamPtr, recordHandle_t *recordHandle) {
    EXnselAcl_t *nselAcl = (EXnselAcl_t *)recordHandle->extensionList[EXnselAclID];

    ptrdiff_t lenStream = STREAMLEN(streamPtr);
    size_t len = 0;
    if (nselAcl)
        len = snprintf(streamPtr, lenStream, "0x%-8x 0x%-8x 0x%-8x", nselAcl->ingressAcl[0], nselAcl->ingressAcl[1], nselAcl->ingressAcl[2]);
    else
        len = snprintf(streamPtr, lenStream, "0x%-8x 0x%-8x 0x%-8x", 0, 0, 0);
    streamPtr += len;

    return streamPtr;
}  // End of String_iacl

static char *String_eacl(char *streamPtr, recordHandle_t *recordHandle) {
    EXnselAcl_t *nselAcl = (EXnselAcl_t *)recordHandle->extensionList[EXnselAclID];

    ptrdiff_t lenStream = STREAMLEN(streamPtr);
    size_t len = 0;
    if (nselAcl)
        len = snprintf(streamPtr, lenStream, "%u %u %u", nselAcl->egressAcl[0], nselAcl->egressAcl[1], nselAcl->egressAcl[2]);
    else
        len = snprintf(streamPtr, lenStream, "%u %u %u", 0, 0, 0);
    streamPtr += len;

    return streamPtr;
}  // End of String_eacl

static char *String_xlateSrcAddr(char *streamPtr, recordHandle_t *recordHandle) {
    EXnatXlateIPv4_t *natXlateIPv4 = (EXnatXlateIPv4_t *)recordHandle->extensionList[EXnatXlateIPv4ID];
    EXnatXlateIPv6_t *natXlateIPv6 = (EXnatXlateIPv6_t *)recordHandle->extensionList[EXnatXlateIPv6ID];

    char tmp_str[IP_STRING_LEN];
    tmp_str[0] = 0;
    if (natXlateIPv4) {
        uint32_t ip = htonl(natXlateIPv4->xlateSrcAddr);
        inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
    } else if (natXlateIPv6) {
        uint64_t ip[2];

        ip[0] = htonll(natXlateIPv6->xlateSrcAddr[0]);
        ip[1] = htonll(natXlateIPv6->xlateSrcAddr[1]);
        inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
    } else {
        strcpy(tmp_str, "0.0.0.0");
    }
    tmp_str[IP_STRING_LEN - 1] = 0;

    AddString(tmp_str);

    return streamPtr;
}  // End of String_xlateSrcAddr

static char *String_xlateDstAddr(char *streamPtr, recordHandle_t *recordHandle) {
    EXnatXlateIPv4_t *natXlateIPv4 = (EXnatXlateIPv4_t *)recordHandle->extensionList[EXnatXlateIPv4ID];
    EXnatXlateIPv6_t *natXlateIPv6 = (EXnatXlateIPv6_t *)recordHandle->extensionList[EXnatXlateIPv6ID];

    char tmp_str[IP_STRING_LEN];
    tmp_str[0] = 0;
    if (natXlateIPv4) {
        uint32_t ip = htonl(natXlateIPv4->xlateDstAddr);
        inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
    } else if (natXlateIPv6) {
        uint64_t ip[2];

        ip[0] = htonll(natXlateIPv6->xlateDstAddr[0]);
        ip[1] = htonll(natXlateIPv6->xlateDstAddr[1]);
        inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
    } else {
        strcpy(tmp_str, "0.0.0.0");
    }
    tmp_str[IP_STRING_LEN - 1] = 0;

    AddString(tmp_str);

    return streamPtr;
}  // End of String_xlateDstAddr

static char *String_xlateSrcPort(char *streamPtr, recordHandle_t *recordHandle) {
    EXnatXlatePort_t *natXlatePort = (EXnatXlatePort_t *)recordHandle->extensionList[EXnatXlatePortID];
    uint16_t port = natXlatePort ? natXlatePort->xlateSrcPort : 0;
    AddU32(port);

    return streamPtr;
}  // End of String_xlateSrcPort

static char *String_xlateDstPort(char *streamPtr, recordHandle_t *recordHandle) {
    EXnatXlatePort_t *natXlatePort = (EXnatXlatePort_t *)recordHandle->extensionList[EXnatXlatePortID];
    uint16_t port = natXlatePort ? natXlatePort->xlateDstPort : 0;
    AddU32(port);

    return streamPtr;
}  // End of String_xlateDstPort

static char *String_userName(char *streamPtr, recordHandle_t *recordHandle) {
    EXnselUser_t *nselUser = (EXnselUser_t *)recordHandle->extensionList[EXnselUserID];

    AddString(nselUser ? nselUser->username : "<empty>");

    return streamPtr;
}  // End of String_userName

static char *String_PortBlockStart(char *streamPtr, recordHandle_t *recordHandle) {
    EXnatPortBlock_t *natPortBlock = (EXnatPortBlock_t *)recordHandle->extensionList[EXnatPortBlockID];

    AddU32(natPortBlock ? natPortBlock->blockStart : 0);

    return streamPtr;
}  // End of String_PortBlockStart

static char *String_PortBlockEnd(char *streamPtr, recordHandle_t *recordHandle) {
    EXnatPortBlock_t *natPortBlock = (EXnatPortBlock_t *)recordHandle->extensionList[EXnatPortBlockID];
    AddU32(natPortBlock ? natPortBlock->blockEnd : 0);

    return streamPtr;
}  // End of String_PortBlockEnd

static char *String_PortBlockStep(char *streamPtr, recordHandle_t *recordHandle) {
    EXnatPortBlock_t *natPortBlock = (EXnatPortBlock_t *)recordHandle->extensionList[EXnatPortBlockID];
    AddU32(natPortBlock ? natPortBlock->blockStep : 0);

    return streamPtr;
}  // End of String_PortBlockStep

static char *String_PortBlockSize(char *streamPtr, recordHandle_t *recordHandle) {
    EXnatPortBlock_t *natPortBlock = (EXnatPortBlock_t *)recordHandle->extensionList[EXnatPortBlockID];
    AddU32(natPortBlock ? natPortBlock->blockSize : 0);

    return streamPtr;
}  // End of String_PortBlockSize

static char *String_flowId(char *streamPtr, recordHandle_t *recordHandle) {
    EXflowId_t *flowId = (EXflowId_t *)recordHandle->extensionList[EXflowIdID];
    ptrdiff_t lenStream = STREAMLEN(streamPtr);
    size_t len = snprintf(streamPtr, lenStream, "0x%" PRIu64, flowId ? flowId->flowId : 0);
    streamPtr += len;

    return streamPtr;
}  // End of String_flowId

static char *String_inServiceID(char *streamPtr, recordHandle_t *recordHandle) {
    EXnokiaNat_t *nokiaNat = (EXnokiaNat_t *)recordHandle->extensionList[EXnokiaNatID];

    AddU32(nokiaNat ? nokiaNat->inServiceID : 0);

    return streamPtr;
}  // End of String_inServiceID

static char *String_outServiceID(char *streamPtr, recordHandle_t *recordHandle) {
    EXnokiaNat_t *nokiaNat = (EXnokiaNat_t *)recordHandle->extensionList[EXnokiaNatID];

    AddU32(nokiaNat ? nokiaNat->outServiceID : 0);

    return streamPtr;
}  // End of String_outServiceID

static char *String_natString(char *streamPtr, recordHandle_t *recordHandle) {
    char *natString = (char *)recordHandle->extensionList[EXnokiaNatStringID];

    AddString(natString ? natString : "<unknown>");

    return streamPtr;
}  // End of String_natString
