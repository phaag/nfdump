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

typedef void (*string_function_t)(FILE *, recordHandle_t *);

static struct token_list_s {
    string_function_t string_function;  // function printing result to stream
    char *string_buffer;                // buffer for static output string
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

static void AddToken(int index, char *s);

static void String_Version(FILE *stream, recordHandle_t *recordHandle);

static void String_FlowCount(FILE *stream, recordHandle_t *recordHandle);

static void String_FirstSeen(FILE *stream, recordHandle_t *recordHandle);

static void String_LastSeen(FILE *stream, recordHandle_t *recordHandle);

static void String_Received(FILE *stream, recordHandle_t *recordHandle);

static void String_FirstSeenRaw(FILE *stream, recordHandle_t *recordHandle);

static void String_LastSeenRaw(FILE *stream, recordHandle_t *recordHandle);

static void String_ReceivedRaw(FILE *stream, recordHandle_t *recordHandle);

static void String_Duration(FILE *stream, recordHandle_t *recordHandle);

static void String_Duration_Seconds(FILE *stream, recordHandle_t *recordHandle);

static void String_Protocol(FILE *stream, recordHandle_t *recordHandle);

static void String_SrcAddr(FILE *stream, recordHandle_t *recordHandle);

static void String_DstAddr(FILE *stream, recordHandle_t *recordHandle);

static void String_SrcNet(FILE *stream, recordHandle_t *recordHandle);

static void String_DstNet(FILE *stream, recordHandle_t *recordHandle);

static void String_NextHop(FILE *stream, recordHandle_t *recordHandle);

static void String_BGPNextHop(FILE *stream, recordHandle_t *recordHandle);

static void String_RouterIP(FILE *stream, recordHandle_t *recordHandle);

static void String_SrcPort(FILE *stream, recordHandle_t *recordHandle);

static void String_DstPort(FILE *stream, recordHandle_t *recordHandle);

static void String_ICMP_code(FILE *stream, recordHandle_t *recordHandle);

static void String_ICMP_type(FILE *stream, recordHandle_t *recordHandle);

static void String_SrcAS(FILE *stream, recordHandle_t *recordHandle);

static void String_DstAS(FILE *stream, recordHandle_t *recordHandle);

static void String_NextAS(FILE *stream, recordHandle_t *recordHandle);

static void String_PrevAS(FILE *stream, recordHandle_t *recordHandle);

static void String_Input(FILE *stream, recordHandle_t *recordHandle);

static void String_InputName(FILE *stream, recordHandle_t *recordHandle);

static void String_Output(FILE *stream, recordHandle_t *recordHandle);

static void String_OutputName(FILE *stream, recordHandle_t *recordHandle);

static void String_InPackets(FILE *stream, recordHandle_t *recordHandle);

static void String_OutPackets(FILE *stream, recordHandle_t *recordHandle);

static void String_InBytes(FILE *stream, recordHandle_t *recordHandle);

static void String_OutBytes(FILE *stream, recordHandle_t *recordHandle);

static void String_Flows(FILE *stream, recordHandle_t *recordHandle);

static void String_Tos(FILE *stream, recordHandle_t *recordHandle);

static void String_Dir(FILE *stream, recordHandle_t *recordHandle);

static void String_SrcTos(FILE *stream, recordHandle_t *recordHandle);

static void String_DstTos(FILE *stream, recordHandle_t *recordHandle);

static void String_SrcMask(FILE *stream, recordHandle_t *recordHandle);

static void String_DstMask(FILE *stream, recordHandle_t *recordHandle);

static void String_SrcVlan(FILE *stream, recordHandle_t *recordHandle);

static void String_DstVlan(FILE *stream, recordHandle_t *recordHandle);

static void String_FwdStatus(FILE *stream, recordHandle_t *recordHandle);

static void String_BiFlowDir(FILE *stream, recordHandle_t *recordHandle);

static void String_FlowEndReason(FILE *stream, recordHandle_t *recordHandle);

static void String_Flags(FILE *stream, recordHandle_t *recordHandle);

static void String_InSrcMac(FILE *stream, recordHandle_t *recordHandle);

static void String_OutDstMac(FILE *stream, recordHandle_t *recordHandle);

static void String_InDstMac(FILE *stream, recordHandle_t *recordHandle);

static void String_OutSrcMac(FILE *stream, recordHandle_t *recordHandle);

static void String_MPLS_1(FILE *stream, recordHandle_t *recordHandle);

static void String_MPLS_2(FILE *stream, recordHandle_t *recordHandle);

static void String_MPLS_3(FILE *stream, recordHandle_t *recordHandle);

static void String_MPLS_4(FILE *stream, recordHandle_t *recordHandle);

static void String_MPLS_5(FILE *stream, recordHandle_t *recordHandle);

static void String_MPLS_6(FILE *stream, recordHandle_t *recordHandle);

static void String_MPLS_7(FILE *stream, recordHandle_t *recordHandle);

static void String_MPLS_8(FILE *stream, recordHandle_t *recordHandle);

static void String_MPLS_9(FILE *stream, recordHandle_t *recordHandle);

static void String_MPLS_10(FILE *stream, recordHandle_t *recordHandle);

static void String_MPLSs(FILE *stream, recordHandle_t *recordHandle);

static void String_Engine(FILE *stream, recordHandle_t *recordHandle);

static void String_Label(FILE *stream, recordHandle_t *recordHandle);

static void String_ClientLatency(FILE *stream, recordHandle_t *recordHandle);

static void String_ServerLatency(FILE *stream, recordHandle_t *recordHandle);

static void String_AppLatency(FILE *stream, recordHandle_t *recordHandle);

static void String_bps(FILE *stream, recordHandle_t *recordHandle);

static void String_pps(FILE *stream, recordHandle_t *recordHandle);

static void String_bpp(FILE *stream, recordHandle_t *recordHandle);

static void String_ExpSysID(FILE *stream, recordHandle_t *recordHandle);

static void String_SrcCountry(FILE *stream, recordHandle_t *recordHandle);

static void String_DstCountry(FILE *stream, recordHandle_t *recordHandle);

static void String_SrcLocation(FILE *stream, recordHandle_t *recordHandle);

static void String_DstLocation(FILE *stream, recordHandle_t *recordHandle);

static void String_SrcASorganisation(FILE *stream, recordHandle_t *recordHandle);

static void String_DstASorganisation(FILE *stream, recordHandle_t *recordHandle);

static void String_SrcTor(FILE *stream, recordHandle_t *recordHandle);

static void String_DstTor(FILE *stream, recordHandle_t *recordHandle);

static void String_nbarID(FILE *stream, recordHandle_t *recordHandle);

static void String_nbarName(FILE *stream, recordHandle_t *recordHandle);

static void String_ja3(FILE *stream, recordHandle_t *recordHandle);

static void String_ja4(FILE *stream, recordHandle_t *recordHandle);

static void String_sniName(FILE *stream, recordHandle_t *recordHandle);

static void String_tlsVersion(FILE *stream, recordHandle_t *recordHandle);

static void String_observationDomainID(FILE *stream, recordHandle_t *recordHandle);

static void String_observationPointID(FILE *stream, recordHandle_t *recordHandle);

static void String_ivrf(FILE *stream, recordHandle_t *recordHandle);

static void String_ivrfName(FILE *stream, recordHandle_t *recordHandle);

static void String_evrf(FILE *stream, recordHandle_t *recordHandle);

static void String_evrfName(FILE *stream, recordHandle_t *recordHandle);

static void String_pfIfName(FILE *stream, recordHandle_t *recordHandle);

static void String_pfAction(FILE *stream, recordHandle_t *recordHandle);

static void String_pfReason(FILE *stream, recordHandle_t *recordHandle);

static void String_pfdir(FILE *stream, recordHandle_t *recordHandle);

static void String_pfrule(FILE *stream, recordHandle_t *recordHandle);

static void String_EventTime(FILE *stream, recordHandle_t *recordHandle);

static void String_nfc(FILE *stream, recordHandle_t *recordHandle);

static void String_evt(FILE *stream, recordHandle_t *recordHandle);

static void String_xevt(FILE *stream, recordHandle_t *recordHandle);

static void String_msecEvent(FILE *stream, recordHandle_t *recordHandle);

static void String_iacl(FILE *stream, recordHandle_t *recordHandle);

static void String_eacl(FILE *stream, recordHandle_t *recordHandle);

static void String_xlateSrcAddr(FILE *stream, recordHandle_t *recordHandle);

static void String_xlateDstAddr(FILE *stream, recordHandle_t *recordHandle);

static void String_xlateSrcPort(FILE *stream, recordHandle_t *recordHandle);

static void String_xlateDstPort(FILE *stream, recordHandle_t *recordHandle);

static void String_userName(FILE *stream, recordHandle_t *recordHandle);

static void String_PortBlockStart(FILE *stream, recordHandle_t *recordHandle);

static void String_PortBlockEnd(FILE *stream, recordHandle_t *recordHandle);

static void String_PortBlockStep(FILE *stream, recordHandle_t *recordHandle);

static void String_PortBlockSize(FILE *stream, recordHandle_t *recordHandle);

static void String_flowId(FILE *stream, recordHandle_t *recordHandle);

static void String_inServiceID(FILE *stream, recordHandle_t *recordHandle);

static void String_outServiceID(FILE *stream, recordHandle_t *recordHandle);

static void String_natString(FILE *stream, recordHandle_t *recordHandle);

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
    {"%te", 0, "lastSeen", String_LastSeen},           // End Time	- last seen
    {"%ter", 0, "lastSeen", String_LastSeenRaw},       // End Time - first seen, seconds
    {"%trr", 0, "received", String_ReceivedRaw},       // Received Time, seconds
    {"%tr", 0, "received", String_Received},           // Received Time
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
        if (token_list[i].string_function) {
            token_list[i].string_function(stream, recordHandle);
        }
        if (token_list[i].string_buffer) {
            fprintf(stream, "%s", token_list[i].string_buffer);
        }
    }
    fprintf(stream, "\n");

}  // End of csv_record

void csv_prolog(void) {
    // header
    printf("%s\n", header_string);
}  // End of csv_prolog

void csv_epilog(void) {
    // empty
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
        token_list[token_index].string_function = formatTable[index].string_function;
        token_list[token_index].string_buffer = s;
    } else {
        token_list[token_index].string_function = NULL;
        token_list[token_index].string_buffer = s;
    }
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
                        AddToken(i, NULL);
                        snprintf(h, STRINGSIZE - 1 - strlen(header_string), "%s", formatTable[i].csvHeader);
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
            if (formatTable[i].token == NULL) {
                LogError("Output format parse error at: %s", c);
                free(s);
                ListOutputFormats();
                return 0;
            }
        } else {  // it's a static string
            /* a static string goes up to next '%' or end of string */
            char *p = strchr(c, '%');
            if (p) {
                // p points to next '%' token
                *p = '\0';
                AddToken(0, strdup(c));
                snprintf(h, STRINGSIZE - 1 - strlen(header_string), "%s", c);
                h += strlen(h);
                *p = '%';
                c = p;
            } else {
                // static string up to end of format string
                AddToken(0, strdup(c));
                snprintf(h, STRINGSIZE - 1 - strlen(header_string), "%s", c);
                h += strlen(h);
                *c = '\0';
            }
        }
    }

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
static void String_Version(FILE *stream, recordHandle_t *recordHandle) {
    recordHeaderV3_t *recordHeaderV3 = recordHandle->recordHeaderV3;

    char *type = "unknown";
    uint8_t nfversion = recordHeaderV3->nfversion;
    if (TestFlag(recordHeaderV3->flags, V3_FLAG_EVENT)) {
        type = "event";
        fprintf(stream, "%s%u", type, nfversion);
    } else {
        if (nfversion != 0) {
            if (nfversion & 0x80) {
                type = "sflowV";
            } else if (nfversion & 0x40) {
                type = "pcapdV";
            } else {
                type = "netflowV";
            }
            fprintf(stream, "%s%u", type, nfversion & 0x0F);
        } else {
            // compat with previous versions
            type = "flow";
            fprintf(stream, "%s", type);
        }
    }

}  // End of String_Version

static void String_FlowCount(FILE *stream, recordHandle_t *recordHandle) {
    fprintf(stream, "%u", recordHandle->flowCount);
}  // End of String_FlowCount

static void String_FirstSeen(FILE *stream, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];

    uint64_t msecFirst = genericFlow ? genericFlow->msecFirst : 0;

    if (msecFirst) {
        time_t tt = msecFirst / 1000LL;
        struct tm *ts = localtime(&tt);
        char s[128];
        strftime(s, 128, "%Y-%m-%d %H:%M:%S", ts);
        s[127] = '\0';
        fprintf(stream, "%s.%03u", s, (unsigned)(msecFirst % 1000LL));
    } else {
        fprintf(stream, "%s", "0000-00-00 00:00:00.000");
    }

}  // End of String_FirstSeen

static void String_LastSeen(FILE *stream, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];

    uint64_t msecLast = genericFlow ? genericFlow->msecLast : 0;

    if (msecLast) {
        time_t tt = msecLast / 1000LL;
        struct tm *ts = localtime(&tt);
        char s[128];
        strftime(s, 128, "%Y-%m-%d %H:%M:%S", ts);
        s[127] = '\0';
        fprintf(stream, "%s.%03u", s, (unsigned)(msecLast % 1000LL));
    } else {
        fprintf(stream, "%s", "0000-00-00 00:00:00.000");
    }

}  // End of String_LastSeen

static void String_Received(FILE *stream, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];

    uint64_t msecReceived = genericFlow ? genericFlow->msecReceived : 0;

    if (msecReceived) {
        time_t tt = msecReceived / 1000LL;
        struct tm *ts = localtime(&tt);
        char s[128];
        strftime(s, 128, "%Y-%m-%d %H:%M:%S", ts);
        s[127] = '\0';
        fprintf(stream, "%s.%03llu", s, msecReceived % 1000LL);
    } else {
        fprintf(stream, "%s", "0000-00-00 00:00:00.000");
    }

}  // End of String_Received

static void String_ReceivedRaw(FILE *stream, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];

    uint64_t msecReceived = genericFlow ? genericFlow->msecReceived : 0;
    fprintf(stream, "%llu.%03llu", msecReceived / 1000LL, msecReceived % 1000LL);

}  // End of String_ReceivedRaw

static void String_FirstSeenRaw(FILE *stream, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];

    uint64_t msecFirst = genericFlow ? genericFlow->msecFirst : 0;
    fprintf(stream, "%llu.%03llu", msecFirst / 1000LL, msecFirst % 1000LL);

}  // End of String_FirstSeenRaw

static void String_LastSeenRaw(FILE *stream, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];

    uint64_t msecLast = genericFlow ? genericFlow->msecLast : 0;
    fprintf(stream, "%llu.%03llu", msecLast / 1000LL, msecLast % 1000LL);

}  // End of String_LastSeenRaw

static void String_nbarID(FILE *stream, recordHandle_t *recordHandle) {
    uint8_t *nbar = (uint8_t *)recordHandle->extensionList[EXnbarAppID];

    union {
        uint8_t val8[4];
        uint32_t val32;
    } pen;

    if (nbar == NULL) {
        fprintf(stream, "0..0..0");
        return;
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
        fprintf(stream, "%u..%u..%u", nbar[0], pen.val32, selector);
    } else {
        int selector = 0;
        int index = 1;
        while (index < nbarAppIDlen) {
            selector = (selector << 8) | nbar[index];
            index++;
        }
        fprintf(stream, "%u..%u", nbar[0], selector);
    }

}  // End of String_nbarID

static void String_nbarName(FILE *stream, recordHandle_t *recordHandle) {
    uint8_t *nbar = (uint8_t *)recordHandle->extensionList[EXnbarAppID];

    if (nbar == NULL) {
        fprintf(stream, "no-nbar");
        return;
    }

    uint32_t nbarAppIDlen = ExtensionLength(nbar);
    char *name = GetNbarInfo(nbar, nbarAppIDlen);
    if (name == NULL) {
        name = "no-info";
    }
    fprintf(stream, "%s", name);

}  // End of String_nbarName

static void String_ja3(FILE *stream, recordHandle_t *recordHandle) {
    const uint8_t *payload = (uint8_t *)(recordHandle->extensionList[EXinPayloadID]);
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)(recordHandle->extensionList[EXgenericFlowID]);
    if (payload == NULL || genericFlow->proto != IPPROTO_TCP) {
        fprintf(stream, "%s", "no-ja3");
        return;
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
            fprintf(stream, "%s", "no-ja3");
            return;
        }
    }

    if (ssl->type == CLIENTssl)
        fprintf(stream, "%s", ja3);
    else
        fprintf(stream, "%s", ja3);

}  // End of String_ja3

static void String_ja4(FILE *stream, recordHandle_t *recordHandle) {
    const uint8_t *payload = (const uint8_t *)recordHandle->extensionList[EXinPayloadID];
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    if (payload == NULL || genericFlow->proto != IPPROTO_TCP) {
        fprintf(stream, "%s", "no-ja4");
        return;
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
            fprintf(stream, "%s", "no-ja4");
            return;
        }
    }

    // ja4 is defined
    if (ja4->type == TYPE_JA4) {
        fprintf(stream, "%s", ja4->string);
    } else {
        fprintf(stream, "%s", ja4->string);
    }

}  // End of String_ja4

static void String_tlsVersion(FILE *stream, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    const uint8_t *payload = (const uint8_t *)recordHandle->extensionList[EXinPayloadID];

    if (payload == NULL || genericFlow->proto != IPPROTO_TCP) {
        fprintf(stream, "0");
        return;
    }

    ssl_t *ssl = recordHandle->extensionList[SSLindex];
    if (ssl == NULL) {
        uint32_t payloadLength = ExtensionLength(payload);
        ssl = sslProcess(payload, payloadLength);
        recordHandle->extensionList[SSLindex] = ssl;
        if (ssl == NULL) {
            fprintf(stream, "0");
            return;
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
            fprintf(stream, "0");
            break;
        case 's':
            fprintf(stream, "SSL-%c", ssl->tlsCharVersion[1]);
            break;
        case '1':
            fprintf(stream, "TLS-1.%c", ssl->tlsCharVersion[1]);
            break;
        default:
            fprintf(stream, "0x%4x", ssl->tlsVersion);
            break;
    }

}  // End of String_tlsVersion

static void String_sniName(FILE *stream, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    const uint8_t *payload = (const uint8_t *)recordHandle->extensionList[EXinPayloadID];

    if (payload == NULL || genericFlow->proto != IPPROTO_TCP) {
        fprintf(stream, "0");
        return;
    }

    ssl_t *ssl = recordHandle->extensionList[SSLindex];
    if (ssl == NULL) {
        uint32_t payloadLength = ExtensionLength(payload);
        ssl = sslProcess(payload, payloadLength);
        recordHandle->extensionList[SSLindex] = ssl;
        if (ssl == NULL) {
            fprintf(stream, "0");
            return;
        }
    }

    // ssl is defined
    fprintf(stream, "%s", ssl != NULL ? ssl->sniName : "");

}  // End of String_sniName

static void String_observationDomainID(FILE *stream, recordHandle_t *recordHandle) {
    EXobservation_t *observation = (EXobservation_t *)recordHandle->extensionList[EXobservationID];
    if (observation)
        fprintf(stream, "0x%0x", observation->domainID);
    else
        fprintf(stream, "0x00");
}  // End of String_observationDomainID

static void String_observationPointID(FILE *stream, recordHandle_t *recordHandle) {
    EXobservation_t *observation = (EXobservation_t *)recordHandle->extensionList[EXobservationID];
    if (observation)
        fprintf(stream, "0x%0llx", (long long unsigned)observation->pointID);
    else
        fprintf(stream, "0x00");
}  // End of String_observationPointID

static void String_EventTime(FILE *stream, recordHandle_t *recordHandle) {
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
        fprintf(stream, "%s.%03llu", s, msecEvent % 1000LL);
    } else {
        fprintf(stream, "%s", "0000-00-00 00:00:00.000");
    }

}  // End of String_EventTime

static void String_Duration(FILE *stream, recordHandle_t *recordHandle) {
    //
    fprintf(stream, "%.3f", duration);
}  // End of String_Duration

static void String_Duration_Seconds(FILE *stream, recordHandle_t *recordHandle) {
    fprintf(stream, "%.3f", duration);
}  // End of String_Duration_Seconds

static void String_Protocol(FILE *stream, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    uint8_t proto = genericFlow ? genericFlow->proto : 0;
    fprintf(stream, "%d", proto);
}  // End of String_Protocol

static void String_SrcAddr(FILE *stream, recordHandle_t *recordHandle) {
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

    fprintf(stream, "%s", tmp_str);

}  // End of String_SrcAddr

static void String_DstAddr(FILE *stream, recordHandle_t *recordHandle) {
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

    fprintf(stream, "%s", tmp_str);

}  // End of String_DstAddr

static void String_SrcNet(FILE *stream, recordHandle_t *recordHandle) {
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

    fprintf(stream, "%s/%u", tmp_str, srcMask);

}  // End of String_SrcNet

static void String_DstNet(FILE *stream, recordHandle_t *recordHandle) {
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

    fprintf(stream, "%s/%u", tmp_str, dstMask);

}  // End of String_DstNet

static void String_SrcPort(FILE *stream, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    uint16_t port = genericFlow ? genericFlow->srcPort : 0;
    fprintf(stream, "%u", port);
}  // End of String_SrcPort

static void String_DstPort(FILE *stream, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    fprintf(stream, "%s", ICMP_Port_decode(genericFlow));
}  // End of String_DstPort

static void String_ICMP_type(FILE *stream, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    uint16_t type = genericFlow ? genericFlow->icmpType : 0;
    // Force printing type regardless of protocol
    fprintf(stream, "%u", type);
}  // End of String_ICMP_type

static void String_ICMP_code(FILE *stream, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    uint16_t code = genericFlow ? genericFlow->icmpCode : 0;
    // Force printing code regardless of protocol
    fprintf(stream, "%u", code);
}  // End of String_ICMP_code

static void String_SrcAS(FILE *stream, recordHandle_t *recordHandle) {
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

    fprintf(stream, "%u", srcAS);
}  // End of String_SrcAS

static void String_DstAS(FILE *stream, recordHandle_t *recordHandle) {
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

    fprintf(stream, "%u", dstAS);

}  // End of String_DstAS

static void String_NextAS(FILE *stream, recordHandle_t *recordHandle) {
    EXasAdjacent_t *asAdjacent = (EXasAdjacent_t *)recordHandle->extensionList[EXasAdjacentID];
    uint32_t nextAS = asAdjacent ? asAdjacent->nextAdjacentAS : 0;
    fprintf(stream, " %u", nextAS);
}  // End of String_NextAS

static void String_PrevAS(FILE *stream, recordHandle_t *recordHandle) {
    EXasAdjacent_t *asAdjacent = (EXasAdjacent_t *)recordHandle->extensionList[EXasAdjacentID];
    uint32_t prevAS = asAdjacent ? asAdjacent->prevAdjacentAS : 0;
    fprintf(stream, " %u", prevAS);
}  // End of String_PrevAS

static void String_Input(FILE *stream, recordHandle_t *recordHandle) {
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)recordHandle->extensionList[EXflowMiscID];
    uint32_t input = flowMisc ? flowMisc->input : 0;
    fprintf(stream, "%u", input);
}  // End of String_Input

static void String_InputName(FILE *stream, recordHandle_t *recordHandle) {
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)recordHandle->extensionList[EXflowMiscID];
    uint32_t input = flowMisc ? flowMisc->input : 0;
    char ifName[128];
    fprintf(stream, "%s", GetIfName(input, ifName, sizeof(ifName)));
}  // End of String_InputName

static void String_Output(FILE *stream, recordHandle_t *recordHandle) {
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)recordHandle->extensionList[EXflowMiscID];
    uint32_t output = flowMisc ? flowMisc->output : 0;
    fprintf(stream, "%u", output);
}  // End of String_Output

static void String_OutputName(FILE *stream, recordHandle_t *recordHandle) {
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)recordHandle->extensionList[EXflowMiscID];
    uint32_t output = flowMisc ? flowMisc->output : 0;
    char ifName[128];
    fprintf(stream, "%s", GetIfName(output, ifName, sizeof(ifName)));
}  // End of String_OutputName

static void String_InPackets(FILE *stream, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    uint64_t packets = genericFlow ? genericFlow->inPackets : 0;

    fprintf(stream, "%" PRIu64, packets);

}  // End of String_InPackets

static void String_OutPackets(FILE *stream, recordHandle_t *recordHandle) {
    EXcntFlow_t *cntFlow = (EXcntFlow_t *)recordHandle->extensionList[EXcntFlowID];
    uint64_t packets = cntFlow ? cntFlow->outPackets : 0;

    fprintf(stream, "%" PRIu64, packets);

}  // End of String_OutPackets

static void String_InBytes(FILE *stream, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    uint64_t bytes = genericFlow ? genericFlow->inBytes : 0;

    fprintf(stream, "%" PRIu64, bytes);

}  // End of String_InBytes

static void String_OutBytes(FILE *stream, recordHandle_t *recordHandle) {
    EXcntFlow_t *cntFlow = (EXcntFlow_t *)recordHandle->extensionList[EXcntFlowID];
    uint64_t bytes = cntFlow ? cntFlow->outBytes : 0;

    fprintf(stream, "%" PRIu64, bytes);

}  // End of String_OutBytes

static void String_Flows(FILE *stream, recordHandle_t *recordHandle) {
    EXcntFlow_t *cntFlow = (EXcntFlow_t *)recordHandle->extensionList[EXcntFlowID];
    uint64_t flows = cntFlow ? cntFlow->flows : 1;

    fprintf(stream, "%" PRIu64, flows);

}  // End of String_Flows

static void String_NextHop(FILE *stream, recordHandle_t *recordHandle) {
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

    fprintf(stream, "%s", tmp_str);

}  // End of String_NextHop

static void String_BGPNextHop(FILE *stream, recordHandle_t *recordHandle) {
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

    fprintf(stream, "%s", tmp_str);

}  // End of String_BGPNextHop

static void String_RouterIP(FILE *stream, recordHandle_t *recordHandle) {
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

    fprintf(stream, "%s", tmp_str);

}  // End of String_RouterIP

static void String_Tos(FILE *stream, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    uint32_t srcTos = genericFlow ? genericFlow->srcTos : 0;

    fprintf(stream, "%u", srcTos);
}  // End of String_Tos

static void String_SrcTos(FILE *stream, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    uint32_t srcTos = genericFlow ? genericFlow->srcTos : 0;

    fprintf(stream, "%u", srcTos);
}  // End of String_SrcTos

static void String_DstTos(FILE *stream, recordHandle_t *recordHandle) {
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)recordHandle->extensionList[EXflowMiscID];
    uint32_t dstTos = flowMisc ? flowMisc->dstTos : 0;

    fprintf(stream, "%u", dstTos);
}  // End of String_DstTos

static void String_SrcMask(FILE *stream, recordHandle_t *recordHandle) {
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)recordHandle->extensionList[EXflowMiscID];
    uint32_t srcMask = flowMisc ? flowMisc->srcMask : 0;

    fprintf(stream, "%u", srcMask);
}  // End of String_SrcMask

static void String_DstMask(FILE *stream, recordHandle_t *recordHandle) {
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)recordHandle->extensionList[EXflowMiscID];
    uint32_t dstMask = flowMisc ? flowMisc->dstMask : 0;

    fprintf(stream, "%u", dstMask);
}  // End of String_DstMask

static void String_SrcVlan(FILE *stream, recordHandle_t *recordHandle) {
    EXvLan_t *vLan = (EXvLan_t *)recordHandle->extensionList[EXvLanID];
    uint32_t srcVlan = vLan ? vLan->srcVlan : 0;

    fprintf(stream, "%u", srcVlan);
}  // End of String_SrcVlan

static void String_DstVlan(FILE *stream, recordHandle_t *recordHandle) {
    EXvLan_t *vLan = (EXvLan_t *)recordHandle->extensionList[EXvLanID];
    uint32_t dstVlan = vLan ? vLan->dstVlan : 0;

    fprintf(stream, "%u", dstVlan);
}  // End of String_DstVlan

static void String_Dir(FILE *stream, recordHandle_t *recordHandle) {
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)recordHandle->extensionList[EXflowMiscID];
    uint32_t dir = flowMisc ? flowMisc->dir : 0;

    fprintf(stream, "%c", dir ? 'E' : 'I');
}  // End of String_Dir

static void String_FwdStatus(FILE *stream, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    uint32_t fwdStatus = genericFlow ? genericFlow->fwdStatus : 0;

    fprintf(stream, "%u", fwdStatus);
}  // End of String_FwdStatus

static void String_BiFlowDir(FILE *stream, recordHandle_t *recordHandle) {
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)recordHandle->extensionList[EXflowMiscID];
    uint32_t biFlowDir = flowMisc ? flowMisc->biFlowDir : 0;

    fprintf(stream, "%u", biFlowDir);
}  // End of String_BiFlowDir

static void String_FlowEndReason(FILE *stream, recordHandle_t *recordHandle) {
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)recordHandle->extensionList[EXflowMiscID];
    uint32_t flowEndReason = flowMisc ? flowMisc->flowEndReason : 0;

    fprintf(stream, "%u", flowEndReason);
}  // End of String_FlowEndReason

static void String_Flags(FILE *stream, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    uint32_t flags = genericFlow && genericFlow->proto == IPPROTO_TCP ? genericFlow->tcpFlags : 0;

    fprintf(stream, "%s", FlagsString(flags));

}  // End of String_Flags

static void printMacAddr(FILE *stream, uint64_t macAddr) {
    uint8_t mac[6];
    for (int i = 0; i < 6; i++) {
        mac[i] = (macAddr >> (i * 8)) & 0xFF;
    }
    fprintf(stream, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);

}  // End of printMacAddr

static void String_InSrcMac(FILE *stream, recordHandle_t *recordHandle) {
    EXmacAddr_t *macAddr = (EXmacAddr_t *)recordHandle->extensionList[EXmacAddrID];
    uint64_t mac = macAddr ? macAddr->inSrcMac : 0;

    printMacAddr(stream, mac);
}  // End of String_InSrcMac

static void String_OutDstMac(FILE *stream, recordHandle_t *recordHandle) {
    EXmacAddr_t *macAddr = (EXmacAddr_t *)recordHandle->extensionList[EXmacAddrID];
    uint64_t mac = macAddr ? macAddr->outDstMac : 0;

    printMacAddr(stream, mac);
}  // End of String_OutDstMac

static void String_InDstMac(FILE *stream, recordHandle_t *recordHandle) {
    EXmacAddr_t *macAddr = (EXmacAddr_t *)recordHandle->extensionList[EXmacAddrID];
    uint64_t mac = macAddr ? macAddr->inDstMac : 0;

    printMacAddr(stream, mac);
}  // End of String_InDstMac

static void String_OutSrcMac(FILE *stream, recordHandle_t *recordHandle) {
    EXmacAddr_t *macAddr = (EXmacAddr_t *)recordHandle->extensionList[EXmacAddrID];
    uint64_t mac = macAddr ? macAddr->outSrcMac : 0;

    printMacAddr(stream, mac);
}  // End of String_OutSrcMac

static void String_MPLS_1(FILE *stream, recordHandle_t *recordHandle) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)recordHandle->extensionList[EXmplsLabelID];
    uint32_t label = mplsLabel ? mplsLabel->mplsLabel[0] : 0;

    fprintf(stream, "%8u-%1u-%1u", label >> 4, (label & 0xF) >> 1, label & 1);

}  // End of String_MPLS

static void String_MPLS_2(FILE *stream, recordHandle_t *recordHandle) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)recordHandle->extensionList[EXmplsLabelID];
    uint32_t label = mplsLabel ? mplsLabel->mplsLabel[1] : 0;

    fprintf(stream, "%8u-%1u-%1u", label >> 4, (label & 0xF) >> 1, label & 1);

}  // End of String_MPLS

static void String_MPLS_3(FILE *stream, recordHandle_t *recordHandle) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)recordHandle->extensionList[EXmplsLabelID];
    uint32_t label = mplsLabel ? mplsLabel->mplsLabel[2] : 0;

    fprintf(stream, "%8u-%1u-%1u", label >> 4, (label & 0xF) >> 1, label & 1);

}  // End of String_MPLS

static void String_MPLS_4(FILE *stream, recordHandle_t *recordHandle) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)recordHandle->extensionList[EXmplsLabelID];
    uint32_t label = mplsLabel ? mplsLabel->mplsLabel[3] : 0;

    fprintf(stream, "%8u-%1u-%1u", label >> 4, (label & 0xF) >> 1, label & 1);

}  // End of String_MPLS

static void String_MPLS_5(FILE *stream, recordHandle_t *recordHandle) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)recordHandle->extensionList[EXmplsLabelID];
    uint32_t label = mplsLabel ? mplsLabel->mplsLabel[4] : 0;

    fprintf(stream, "%8u-%1u-%1u", label >> 4, (label & 0xF) >> 1, label & 1);

}  // End of String_MPLS

static void String_MPLS_6(FILE *stream, recordHandle_t *recordHandle) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)recordHandle->extensionList[EXmplsLabelID];
    uint32_t label = mplsLabel ? mplsLabel->mplsLabel[5] : 0;

    fprintf(stream, "%8u-%1u-%1u", label >> 4, (label & 0xF) >> 1, label & 1);

}  // End of String_MPLS

static void String_MPLS_7(FILE *stream, recordHandle_t *recordHandle) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)recordHandle->extensionList[EXmplsLabelID];
    uint32_t label = mplsLabel ? mplsLabel->mplsLabel[6] : 0;

    fprintf(stream, "%8u-%1u-%1u", label >> 4, (label & 0xF) >> 1, label & 1);

}  // End of String_MPLS

static void String_MPLS_8(FILE *stream, recordHandle_t *recordHandle) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)recordHandle->extensionList[EXmplsLabelID];
    uint32_t label = mplsLabel ? mplsLabel->mplsLabel[7] : 0;

    fprintf(stream, "%8u-%1u-%1u", label >> 4, (label & 0xF) >> 1, label & 1);

}  // End of String_MPLS

static void String_MPLS_9(FILE *stream, recordHandle_t *recordHandle) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)recordHandle->extensionList[EXmplsLabelID];
    uint32_t label = mplsLabel ? mplsLabel->mplsLabel[8] : 0;

    fprintf(stream, "%8u-%1u-%1u", label >> 4, (label & 0xF) >> 1, label & 1);

}  // End of String_MPLS

static void String_MPLS_10(FILE *stream, recordHandle_t *recordHandle) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)recordHandle->extensionList[EXmplsLabelID];
    uint32_t label = mplsLabel ? mplsLabel->mplsLabel[9] : 0;

    fprintf(stream, "%8u-%1u-%1u", label >> 4, (label & 0xF) >> 1, label & 1);

}  // End of String_MPLS

static void String_MPLSs(FILE *stream, recordHandle_t *recordHandle) {
    EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)recordHandle->extensionList[EXmplsLabelID];
    uint32_t label[10] = {0};
    if (mplsLabel) memcpy((void *)label, (void *)mplsLabel->mplsLabel, sizeof(label));

    fprintf(stream,
            "%8u-%1u-%1u %8u-%1u-%1u %8u-%1u-%1u %8u-%1u-%1u %8u-%1u-%1u %8u-%1u-%1u %8u-%1u-%1u %8u-%1u-%1u "
            "%8u-%1u-%1u %8u-%1u-%1u ",
            label[0] >> 4, (label[0] & 0xF) >> 1, label[0] & 1, label[1] >> 4, (label[1] & 0xF) >> 1, label[1] & 1, label[2] >> 4,
            (label[2] & 0xF) >> 1, label[2] & 1, label[3] >> 4, (label[3] & 0xF) >> 1, label[3] & 1, label[4] >> 4, (label[4] & 0xF) >> 1,
            label[4] & 1, label[5] >> 4, (label[5] & 0xF) >> 1, label[5] & 1, label[6] >> 4, (label[6] & 0xF) >> 1, label[6] & 1, label[7] >> 4,
            (label[7] & 0xF) >> 1, label[7] & 1, label[8] >> 4, (label[8] & 0xF) >> 1, label[8] & 1, label[9] >> 4, (label[9] & 0xF) >> 1,
            label[9] & 1);

}  // End of String_MPLSs

static void String_Engine(FILE *stream, recordHandle_t *recordHandle) {
    fprintf(stream, "%u/%u", recordHandle->recordHeaderV3->engineType, recordHandle->recordHeaderV3->engineID);
}  // End of String_Engine

static void String_Label(FILE *stream, recordHandle_t *recordHandle) { fprintf(stream, "%16s", "<none>"); }  // End of String_Label

static void String_ClientLatency(FILE *stream, recordHandle_t *recordHandle) {
    EXlatency_t *latency = (EXlatency_t *)recordHandle->extensionList[EXlatencyID];
    double msecLatency = latency ? (double)latency->usecClientNwDelay / 1000.0 : 0.0;

    fprintf(stream, "%.3f", msecLatency);

}  // End of String_ClientLatency

static void String_ServerLatency(FILE *stream, recordHandle_t *recordHandle) {
    EXlatency_t *latency = (EXlatency_t *)recordHandle->extensionList[EXlatencyID];
    double msecLatency = latency ? (double)latency->usecServerNwDelay / 1000.0 : 0.0;

    fprintf(stream, "%.3f", msecLatency);

}  // End of String_ServerLatency

static void String_AppLatency(FILE *stream, recordHandle_t *recordHandle) {
    EXlatency_t *latency = (EXlatency_t *)recordHandle->extensionList[EXlatencyID];
    double msecLatency = latency ? (double)latency->usecApplLatency / 1000.0 : 0.0;

    fprintf(stream, "%.3f", msecLatency);

}  // End of String_AppLatency

static void String_bps(FILE *stream, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    uint64_t inBytes = genericFlow ? genericFlow->inBytes : 0;

    uint64_t bps = 0;
    if (duration) {
        bps = ((inBytes << 3) / duration);  // bits per second. ( >> 3 ) -> * 8 to convert octets into bits
    }

    fprintf(stream, "%" PRIu64, bps);

}  // End of String_bps

static void String_pps(FILE *stream, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    uint64_t inPackets = genericFlow ? genericFlow->inPackets : 0;

    uint64_t pps = 0;
    if (duration) {
        pps = inPackets / duration;  // packets per second
    }

    fprintf(stream, "%" PRIu64, pps);

}  // End of String_Duration

static void String_bpp(FILE *stream, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    uint64_t inPackets = genericFlow ? genericFlow->inPackets : 0;
    uint64_t inBytes = genericFlow ? genericFlow->inBytes : 0;

    uint32_t Bpp = 0;
    if (inPackets) Bpp = inBytes / inPackets;  // Bytes per Packet

    fprintf(stream, "%u", Bpp);

}  // End of String_bpp

static void String_ExpSysID(FILE *stream, recordHandle_t *recordHandle) {
    fprintf(stream, "%u", recordHandle->recordHeaderV3->exporterID);
}  // End of String_ExpSysID

static void String_SrcCountry(FILE *stream, recordHandle_t *recordHandle) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    if (ipv4Flow) {
        if (recordHandle->geo[0] == '\0') LookupV4Country(ipv4Flow->srcAddr, recordHandle->geo);
    } else if (ipv6Flow) {
        if (recordHandle->geo[0] == '\0') LookupV6Country(ipv6Flow->srcAddr, recordHandle->geo);
    }

    if (recordHandle->geo[0])
        fprintf(stream, "%c%c", recordHandle->geo[0], recordHandle->geo[1]);
    else
        fprintf(stream, "..");

}  // End of String_SrcCountry

static void String_DstCountry(FILE *stream, recordHandle_t *recordHandle) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    if (ipv4Flow) {
        if (recordHandle->geo[2] == '\0') LookupV4Country(ipv4Flow->dstAddr, &recordHandle->geo[2]);
    } else if (ipv6Flow) {
        if (recordHandle->geo[2] == '\0') LookupV6Country(ipv6Flow->dstAddr, &recordHandle->geo[2]);
    }

    if (recordHandle->geo[2])
        fprintf(stream, "%c%c", recordHandle->geo[2], recordHandle->geo[3]);
    else
        fprintf(stream, "..");

}  // End of String_DstCountry

static void String_SrcLocation(FILE *stream, recordHandle_t *recordHandle) {
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
        fprintf(stream, "%s", location);
    else
        fprintf(stream, "no location info");

}  // End of String_SrcLocation

static void String_DstLocation(FILE *stream, recordHandle_t *recordHandle) {
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
        fprintf(stream, "%s", location);
    else
        fprintf(stream, "no location info");

}  // End of String_DstLocation

static void String_SrcASorganisation(FILE *stream, recordHandle_t *recordHandle) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    if (ipv4Flow) {
        fprintf(stream, "%s", LookupV4ASorg(ipv4Flow->srcAddr));
    } else if (ipv6Flow) {
        fprintf(stream, "%s", LookupV6ASorg(ipv6Flow->srcAddr));
    } else {
        fprintf(stream, "%s", "none");
    }

}  // End of String_SrcASorganisation

static void String_DstASorganisation(FILE *stream, recordHandle_t *recordHandle) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    if (ipv4Flow) {
        fprintf(stream, "%s", LookupV4ASorg(ipv4Flow->dstAddr));
    } else if (ipv6Flow) {
        fprintf(stream, "%s", LookupV6ASorg(ipv6Flow->dstAddr));
    } else {
        fprintf(stream, "%s", "none");
    }

}  // End of String_DstASorganisation

static void String_SrcTor(FILE *stream, recordHandle_t *recordHandle) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    char torInfo[4];
    if (ipv4Flow) {
        LookupV4Tor(ipv4Flow->srcAddr, genericFlow->msecFirst, genericFlow->msecLast, torInfo);
    } else {
        LookupV6Tor(ipv6Flow->srcAddr, genericFlow->msecFirst, genericFlow->msecLast, torInfo);
    }
    fprintf(stream, "%s", torInfo);

}  // End of String_SrcTor

static void String_DstTor(FILE *stream, recordHandle_t *recordHandle) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];

    char torInfo[4];
    if (ipv4Flow) {
        LookupV4Tor(ipv4Flow->dstAddr, genericFlow->msecFirst, genericFlow->msecLast, torInfo);
    } else {
        LookupV6Tor(ipv6Flow->dstAddr, genericFlow->msecFirst, genericFlow->msecLast, torInfo);
    }
    fprintf(stream, "%s", torInfo);

}  // End of String_DstTor

static void String_ivrf(FILE *stream, recordHandle_t *recordHandle) {
    EXvrf_t *vrf = (EXvrf_t *)recordHandle->extensionList[EXvrfID];
    uint32_t ingress = vrf ? vrf->ingressVrf : 0;

    fprintf(stream, "%u", ingress);
}  // End of String_ivrf

static void String_evrf(FILE *stream, recordHandle_t *recordHandle) {
    EXvrf_t *vrf = (EXvrf_t *)recordHandle->extensionList[EXvrfID];
    uint32_t egress = vrf ? vrf->egressVrf : 0;

    fprintf(stream, "%u", egress);
}  // End of String_evrf

static void String_ivrfName(FILE *stream, recordHandle_t *recordHandle) {
    EXvrf_t *vrf = (EXvrf_t *)recordHandle->extensionList[EXvrfID];
    uint32_t ingress = vrf ? vrf->ingressVrf : 0;

    char vrfName[128];
    fprintf(stream, "%s", GetVrfName(ingress, vrfName, sizeof(vrfName)));
}  // End of String_ivrfName

static void String_evrfName(FILE *stream, recordHandle_t *recordHandle) {
    EXvrf_t *vrf = (EXvrf_t *)recordHandle->extensionList[EXvrfID];
    uint32_t egress = vrf ? vrf->egressVrf : 0;

    char vrfName[128];
    fprintf(stream, "%s", GetVrfName(egress, vrfName, sizeof(vrfName)));
}  // End of String_evrfName

static void String_pfIfName(FILE *stream, recordHandle_t *recordHandle) {
    EXpfinfo_t *pfinfo = (EXpfinfo_t *)recordHandle->extensionList[EXpfinfoID];

    fprintf(stream, "%s", pfinfo ? pfinfo->ifname : "<no-pf>");
}  // End of String_pfIfName

static void String_pfAction(FILE *stream, recordHandle_t *recordHandle) {
    EXpfinfo_t *pfinfo = (EXpfinfo_t *)recordHandle->extensionList[EXpfinfoID];

    if (pfinfo) {
        fprintf(stream, "%s", pfAction(pfinfo->action));
    } else {
        fprintf(stream, "no-pf");
    }
}  // End of String_pfAction

static void String_pfReason(FILE *stream, recordHandle_t *recordHandle) {
    EXpfinfo_t *pfinfo = (EXpfinfo_t *)recordHandle->extensionList[EXpfinfoID];

    if (pfinfo) {
        fprintf(stream, "%s", pfReason(pfinfo->reason));
    } else {
        fprintf(stream, "no-pf");
    }
}  // End of String_pfReason

static void String_pfdir(FILE *stream, recordHandle_t *recordHandle) {
    EXpfinfo_t *pfinfo = (EXpfinfo_t *)recordHandle->extensionList[EXpfinfoID];

    if (pfinfo) {
        fprintf(stream, "%s", pfinfo->dir ? "in" : "out");
    } else {
        fprintf(stream, "no pfinfo");
    }
}  // End of String_pfdir

static void String_pfrule(FILE *stream, recordHandle_t *recordHandle) {
    EXpfinfo_t *pfinfo = (EXpfinfo_t *)recordHandle->extensionList[EXpfinfoID];
    uint32_t rulenr = pfinfo ? pfinfo->rulenr : 0;

    fprintf(stream, "%u", rulenr);
}  // End of String_pfrule

static void String_nfc(FILE *stream, recordHandle_t *recordHandle) {
    EXnselCommon_t *nselCommon = (EXnselCommon_t *)recordHandle->extensionList[EXnselCommonID];
    uint32_t connID = nselCommon ? nselCommon->connID : 0;

    fprintf(stream, "%u", connID);
}  // End of String_nfc

static void String_evt(FILE *stream, recordHandle_t *recordHandle) {
    EXnselCommon_t *nselCommon = (EXnselCommon_t *)recordHandle->extensionList[EXnselCommonID];
    EXnatCommon_t *natCommon = (EXnatCommon_t *)recordHandle->extensionList[EXnatCommonID];

    uint32_t evtNum = 0;
    if (nselCommon) {
        evtNum = nselCommon->fwEvent;
    } else if (natCommon) {
        evtNum = natCommon->natEvent;
    }
    fprintf(stream, "%u", evtNum);

}  // End of String_evt

static void String_xevt(FILE *stream, recordHandle_t *recordHandle) {
    EXnselCommon_t *nselCommon = (EXnselCommon_t *)recordHandle->extensionList[EXnselCommonID];

    if (nselCommon) {
        fprintf(stream, "%s", fwXEventString(nselCommon->fwXevent));
    } else {
        fprintf(stream, "%s", "no-evt");
    }

}  // End of String_xevt

static void String_msecEvent(FILE *stream, recordHandle_t *recordHandle) {
    EXnselCommon_t *nselCommon = (EXnselCommon_t *)recordHandle->extensionList[EXnselCommonID];
    EXnatCommon_t *natCommon = (EXnatCommon_t *)recordHandle->extensionList[EXnatCommonID];
    uint64_t msecEvent = nselCommon ? nselCommon->msecEvent : (natCommon ? natCommon->msecEvent : 0);

    fprintf(stream, "%llu", (long long unsigned)msecEvent);

}  // End of String_msecEvent

static void String_iacl(FILE *stream, recordHandle_t *recordHandle) {
    EXnselAcl_t *nselAcl = (EXnselAcl_t *)recordHandle->extensionList[EXnselAclID];

    if (nselAcl)
        fprintf(stream, "0x%-8x 0x%-8x 0x%-8x", nselAcl->ingressAcl[0], nselAcl->ingressAcl[1], nselAcl->ingressAcl[2]);
    else
        fprintf(stream, "0x%-8x 0x%-8x 0x%-8x", 0, 0, 0);

}  // End of String_iacl

static void String_eacl(FILE *stream, recordHandle_t *recordHandle) {
    EXnselAcl_t *nselAcl = (EXnselAcl_t *)recordHandle->extensionList[EXnselAclID];

    if (nselAcl)
        fprintf(stream, "%u %u %u", nselAcl->egressAcl[0], nselAcl->egressAcl[1], nselAcl->egressAcl[2]);
    else
        fprintf(stream, "%u %u %u", 0, 0, 0);

}  // End of String_eacl

static void String_xlateSrcAddr(FILE *stream, recordHandle_t *recordHandle) {
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

    fprintf(stream, "%s", tmp_str);

}  // End of String_xlateSrcAddr

static void String_xlateDstAddr(FILE *stream, recordHandle_t *recordHandle) {
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

    fprintf(stream, "%s", tmp_str);

}  // End of String_xlateDstAddr

static void String_xlateSrcPort(FILE *stream, recordHandle_t *recordHandle) {
    EXnatXlatePort_t *natXlatePort = (EXnatXlatePort_t *)recordHandle->extensionList[EXnatXlatePortID];
    uint16_t port = natXlatePort ? natXlatePort->xlateSrcPort : 0;
    fprintf(stream, "%u", port);
}  // End of String_xlateSrcPort

static void String_xlateDstPort(FILE *stream, recordHandle_t *recordHandle) {
    EXnatXlatePort_t *natXlatePort = (EXnatXlatePort_t *)recordHandle->extensionList[EXnatXlatePortID];
    uint16_t port = natXlatePort ? natXlatePort->xlateDstPort : 0;
    fprintf(stream, "%u", port);

}  // End of String_xlateDstPort

static void String_userName(FILE *stream, recordHandle_t *recordHandle) {
    EXnselUser_t *nselUser = (EXnselUser_t *)recordHandle->extensionList[EXnselUserID];

    fprintf(stream, "%s", nselUser ? nselUser->username : "<empty>");

}  // End of String_userName

static void String_PortBlockStart(FILE *stream, recordHandle_t *recordHandle) {
    EXnatPortBlock_t *natPortBlock = (EXnatPortBlock_t *)recordHandle->extensionList[EXnatPortBlockID];

    fprintf(stream, "%u", natPortBlock ? natPortBlock->blockStart : 0);
}  // End of String_PortBlockStart

static void String_PortBlockEnd(FILE *stream, recordHandle_t *recordHandle) {
    EXnatPortBlock_t *natPortBlock = (EXnatPortBlock_t *)recordHandle->extensionList[EXnatPortBlockID];
    fprintf(stream, "%u", natPortBlock ? natPortBlock->blockEnd : 0);
}  // End of String_PortBlockEnd

static void String_PortBlockStep(FILE *stream, recordHandle_t *recordHandle) {
    EXnatPortBlock_t *natPortBlock = (EXnatPortBlock_t *)recordHandle->extensionList[EXnatPortBlockID];
    fprintf(stream, "%u", natPortBlock ? natPortBlock->blockStep : 0);
}  // End of String_PortBlockStep

static void String_PortBlockSize(FILE *stream, recordHandle_t *recordHandle) {
    EXnatPortBlock_t *natPortBlock = (EXnatPortBlock_t *)recordHandle->extensionList[EXnatPortBlockID];
    fprintf(stream, "%u", natPortBlock ? natPortBlock->blockSize : 0);
}  // End of String_PortBlockSize

static void String_flowId(FILE *stream, recordHandle_t *recordHandle) {
    EXflowId_t *flowId = (EXflowId_t *)recordHandle->extensionList[EXflowIdID];
    fprintf(stream, "0x%" PRIu64, flowId ? flowId->flowId : 0);
}  // End of String_flowId

static void String_inServiceID(FILE *stream, recordHandle_t *recordHandle) {
    EXnokiaNat_t *nokiaNat = (EXnokiaNat_t *)recordHandle->extensionList[EXnokiaNatID];

    fprintf(stream, "%u", nokiaNat ? nokiaNat->inServiceID : 0);
}  // End of String_inServiceID

static void String_outServiceID(FILE *stream, recordHandle_t *recordHandle) {
    EXnokiaNat_t *nokiaNat = (EXnokiaNat_t *)recordHandle->extensionList[EXnokiaNatID];

    fprintf(stream, "%u", nokiaNat ? nokiaNat->outServiceID : 0);
}  // End of String_outServiceID

static void String_natString(FILE *stream, recordHandle_t *recordHandle) {
    char *natString = (char *)recordHandle->extensionList[EXnokiaNatStringID];

    fprintf(stream, "%s", natString ? natString : "<unknown>");
}  // End of String_natString
