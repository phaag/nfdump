/*
 *  Copyright (c) 2009-2024, Peter Haag
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

#include "nfstat.h"

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

#include "blocksort.h"
#include "config.h"
#include "ja3/ja3.h"
#include "ja4/ja4.h"
#include "khash.h"
#include "maxmind/maxmind.h"
#include "nfdump.h"
#include "nfxV3.h"
#include "output_fmt.h"
#include "output_util.h"
#include "userio.h"
#include "util.h"

typedef enum {
    IS_NULL = 0,
    IS_NUMBER,
    IS_HEXNUMBER,
    IS_IPADDR,
    IS_MACADDR,
    IS_MPLS_LBL,
    IS_LATENCY,
    IS_EVENT,
    IS_HEX,
    IS_NBAR,
    IS_JA3,
    IS_JA4,
    IS_GEO
} elementType_t;

typedef enum { NOPROC = 0,
               SRC_GEO,
               DST_GEO,
               SRC_AS,
               DST_AS,
               PREV_AS,
               NEXT_AS,
               JA3,
               JA4 } preprocess_t;

typedef enum { DESCENDING = 0,
               ASCENDING } direction_t;

typedef struct flow_element_s {
    uint32_t extID;   // extension ID
    uint32_t offset;  // offset in extension
    uint32_t length;  // size of element in bytes
    uint32_t af;      // af family, or 0 if not applicable
} flow_element_t;

typedef struct SortElement {
    void *record;
    uint64_t count;
} SortElement_t;

/*
 *
 */
struct StatParameter_s {
    char *statname;           // name of -s option
    char *HeaderInfo;         // How to name the field in the output header line
    flow_element_t element;   // what element in flow record is used for statistics.
    elementType_t type;       // Type of element: Number, IP address, MAC address etc.
    preprocess_t preprocess;  // value may need some preprocessing
} StatParameters[] = {
    // flow record stat
    {"record", "", {0, 0, 0, 0}, 0},

    {"srcip", "Src IP Addr", {EXipv4FlowID, OFFsrc4Addr, SIZEsrc4Addr, AF_INET}, IS_IPADDR, NOPROC},
    {"srcip", NULL, {EXipv6FlowID, OFFsrc6Addr, SIZEsrc6Addr, AF_INET6}, IS_IPADDR, NOPROC},
    {"dstip", "Dst IP Addr", {EXipv4FlowID, OFFdst4Addr, SIZEdst4Addr, AF_INET}, IS_IPADDR, NOPROC},
    {"srcip", NULL, {EXipv6FlowID, OFFdst6Addr, SIZEdst6Addr, AF_INET6}, IS_IPADDR, NOPROC},
    {"ip", "    IP Addr", {EXipv4FlowID, OFFsrc4Addr, SIZEsrc4Addr, AF_INET}, IS_IPADDR, NOPROC},
    {"ip", NULL, {EXipv4FlowID, OFFdst4Addr, SIZEdst4Addr, AF_INET}, IS_IPADDR, NOPROC},
    {"ip", NULL, {EXipv6FlowID, OFFsrc6Addr, SIZEsrc6Addr, AF_INET6}, IS_IPADDR, NOPROC},
    {"ip", NULL, {EXipv6FlowID, OFFdst6Addr, SIZEdst6Addr, AF_INET6}, IS_IPADDR, NOPROC},
    {"srcgeo", "Src Geo", {EXlocal, OFFgeoSrcIP, SizeGEOloc, 0}, IS_GEO, SRC_GEO},
    {"dstgeo", "Dst Geo", {EXlocal, OFFgeoDstIP, SizeGEOloc, 0}, IS_GEO, DST_GEO},
    {"geo", " Geo", {EXlocal, OFFgeoSrcIP, SizeGEOloc, 0}, IS_GEO, SRC_GEO},
    {"geo", NULL, {EXlocal, OFFgeoDstIP, SizeGEOloc, 0}, IS_GEO, DST_GEO},
    {"nhip", "Nexthop IP", {EXipNextHopV4ID, OFFNextHopV4IP, SIZENextHopV4IP, AF_INET}, IS_IPADDR, NOPROC},
    {"nhip", NULL, {EXipNextHopV6ID, OFFNextHopV6IP, SIZENextHopV6IP, AF_INET6}, IS_IPADDR, NOPROC},
    {"nhbip", "Nexthop BGP IP", {EXbgpNextHopV4ID, OFFbgp4NextIP, SIZEbgp4NextIP, AF_INET}, IS_IPADDR, NOPROC},
    {"nhbip", NULL, {EXbgpNextHopV6ID, OFFbgp6NextIP, SIZEbgp6NextIP, AF_INET}, IS_IPADDR, NOPROC},
    {"router", "Router IP", {EXipReceivedV4ID, OFFReceived4IP, SIZEReceived4IP, AF_INET}, IS_IPADDR, NOPROC},
    {"router", NULL, {EXipReceivedV6ID, OFFReceived4IP, SIZEReceived4IP, AF_INET}, IS_IPADDR, NOPROC},
    {"srcport", "Src Port", {EXgenericFlowID, OFFsrcPort, SIZEsrcPort, 0}, IS_NUMBER, NOPROC},
    {"dstport", "Dst Port", {EXgenericFlowID, OFFdstPort, SIZEdstPort, 0}, IS_NUMBER, NOPROC},
    {"port", "Port", {EXgenericFlowID, OFFsrcPort, SIZEsrcPort, 0}, IS_NUMBER, NOPROC},
    {"port", NULL, {EXgenericFlowID, OFFdstPort, SIZEdstPort, 0}, IS_NUMBER, NOPROC},
    {"proto", "Protocol", {EXgenericFlowID, OFFproto, SIZEproto, 0}, IS_NUMBER, NOPROC},
    {"srctos", "Src Tos", {EXgenericFlowID, OFFsrcTos, SIZEsrcTos, 0}, IS_NUMBER, NOPROC},
    {"dsttos", "Dst Tos", {EXflowMiscID, OFFdstTos, SIZEdstTos, 0}, IS_NUMBER, NOPROC},
    {"tos", "Tos", {EXgenericFlowID, OFFsrcTos, SIZEsrcTos, 0}, IS_NUMBER, NOPROC},
    {"tos", NULL, {EXflowMiscID, OFFdstTos, SIZEdstTos, 0}, IS_NUMBER, NOPROC},
    {"dir", "Dir", {EXgenericFlowID, OFFdir, SIZEdir, 0}, IS_NUMBER, NOPROC},
    {"srcas", "Src AS", {EXasRoutingID, OFFsrcAS, SIZEsrcAS, 0}, IS_NUMBER, SRC_AS},
    {"dstas", "Dst AS", {EXasRoutingID, OFFdstAS, SIZEdstAS, 0}, IS_NUMBER, DST_AS},
    {"as", "AS", {EXasRoutingID, OFFsrcAS, SIZEsrcAS, 0}, IS_NUMBER, SRC_AS},
    {"as", NULL, {EXasRoutingID, OFFdstAS, SIZEdstAS, 0}, IS_NUMBER, DST_AS},
    {"prevas", "Prev AS", {EXasAdjacentID, OFFprevAdjacentAS, SIZEprevAdjacentAS, 0}, IS_NUMBER, PREV_AS},
    {"nextas", "Next AS", {EXasAdjacentID, OFFnextAdjacentAS, SIZEnextAdjacentAS, 0}, IS_NUMBER, NEXT_AS},
    {"inif", "Input If", {EXflowMiscID, OFFinput, SIZEinput, 0}, IS_NUMBER, NOPROC},
    {"outif", "Output If", {EXflowMiscID, OFFoutput, SIZEoutput, 0}, IS_NUMBER, NOPROC},
    {"if", "Interface", {EXflowMiscID, OFFinput, SIZEinput, 0}, IS_NUMBER, NOPROC},
    {"if", NULL, {EXflowMiscID, OFFoutput, SIZEoutput, 0}, IS_NUMBER, NOPROC},
    {"srcmask", "Src Mask", {EXflowMiscID, OFFsrcMask, SIZEsrcMask, 0}, IS_NUMBER, NOPROC},
    {"dstmask", "Dst Mask", {EXflowMiscID, OFFdstMask, SIZEdstMask, 0}, IS_NUMBER, NOPROC},
    {"mask", "Mask", {EXflowMiscID, OFFsrcMask, SIZEsrcMask, 0}, IS_NUMBER, NOPROC},
    {"mask", NULL, {EXflowMiscID, OFFdstMask, SIZEdstMask, 0}, IS_NUMBER, NOPROC},
    {"srcvlan", "Src Vlan", {EXvLanID, OFFsrcVlan, SIZEsrcVlan, 0}, IS_NUMBER, NOPROC},
    {"dstvlan", "Dst Vlan", {EXvLanID, OFFdstVlan, SIZEdstVlan, 0}, IS_NUMBER, NOPROC},
    {"vlan", "Vlan", {EXvLanID, OFFsrcVlan, SIZEsrcVlan, 0}, IS_NUMBER, NOPROC},
    {"vlan", NULL, {EXvLanID, OFFdstVlan, SIZEdstVlan, 0}, IS_NUMBER, NOPROC},
    {"insrcmac", "In Src Mac", {EXmacAddrID, OFFinSrcMac, SIZEinSrcMac, 0}, IS_MACADDR, NOPROC},
    {"outdstmac", "Out Dst Mac", {EXmacAddrID, OFFoutDstMac, SIZEoutDstMac, 0}, IS_MACADDR, NOPROC},
    {"indstmac", "In Dst Mac", {EXmacAddrID, OFFinDstMac, SIZEinDstMac, 0}, IS_MACADDR, NOPROC},
    {"outsrcmac", "Out Src Mac", {EXmacAddrID, OFFoutSrcMac, SIZEoutSrcMac, 0}, IS_MACADDR, NOPROC},
    {"srcmac", "Src Mac", {EXmacAddrID, OFFinSrcMac, SIZEinSrcMac, 0}, IS_MACADDR, NOPROC},
    {"srcmac", NULL, {EXmacAddrID, OFFoutSrcMac, SIZEoutSrcMac, 0}, IS_MACADDR, NOPROC},
    {"dstmac", "Dst Mac", {EXmacAddrID, OFFinDstMac, SIZEinDstMac, 0}, IS_MACADDR, NOPROC},
    {"dstmac", NULL, {EXmacAddrID, OFFoutDstMac, SIZEoutDstMac, 0}, IS_MACADDR, NOPROC},
    {"inmac", "In Mac", {EXmacAddrID, OFFinSrcMac, SIZEinSrcMac, 0}, IS_MACADDR, NOPROC},
    {"inmac", NULL, {EXmacAddrID, OFFinDstMac, SIZEinDstMac, 0}, IS_MACADDR, NOPROC},
    {"outmac", "Out Mac", {EXmacAddrID, OFFoutDstMac, SIZEoutDstMac, 0}, IS_MACADDR, NOPROC},
    {"outmac", NULL, {EXmacAddrID, OFFoutSrcMac, SIZEoutSrcMac, 0}, IS_MACADDR, NOPROC},
    {"mac", "Mac Addr", {EXmacAddrID, OFFinSrcMac, SIZEinSrcMac, 0}, IS_MACADDR, NOPROC},
    {"mac", NULL, {EXmacAddrID, OFFoutDstMac, SIZEoutDstMac, 0}, IS_MACADDR, NOPROC},
    {"mac", NULL, {EXmacAddrID, OFFinDstMac, SIZEinDstMac, 0}, IS_MACADDR, NOPROC},
    {"mac", NULL, {EXmacAddrID, OFFoutSrcMac, SIZEoutSrcMac, 0}, IS_MACADDR, NOPROC},
    {"mpls1", "MPLS label 1", {EXmplsLabelID, OFFmplsLabel1, SIZEmplsLabel1, 0}, IS_MPLS_LBL, NOPROC},
    {"mpls2", "MPLS label 2", {EXmplsLabelID, OFFmplsLabel2, SIZEmplsLabel2, 0}, IS_MPLS_LBL, NOPROC},
    {"mpls3", "MPLS label 3", {EXmplsLabelID, OFFmplsLabel3, SIZEmplsLabel3, 0}, IS_MPLS_LBL, NOPROC},
    {"mpls4", "MPLS label 4", {EXmplsLabelID, OFFmplsLabel4, SIZEmplsLabel4, 0}, IS_MPLS_LBL, NOPROC},
    {"mpls5", "MPLS label 5", {EXmplsLabelID, OFFmplsLabel5, SIZEmplsLabel5, 0}, IS_MPLS_LBL, NOPROC},
    {"mpls6", "MPLS label 6", {EXmplsLabelID, OFFmplsLabel6, SIZEmplsLabel6, 0}, IS_MPLS_LBL, NOPROC},
    {"mpls7", "MPLS label 7", {EXmplsLabelID, OFFmplsLabel7, SIZEmplsLabel7, 0}, IS_MPLS_LBL, NOPROC},
    {"mpls8", "MPLS label 8", {EXmplsLabelID, OFFmplsLabel8, SIZEmplsLabel8, 0}, IS_MPLS_LBL, NOPROC},
    {"mpls9", "MPLS label 9", {EXmplsLabelID, OFFmplsLabel9, SIZEmplsLabel9, 0}, IS_MPLS_LBL, NOPROC},
    {"mpls10", "MPLS label 10", {EXmplsLabelID, OFFmplsLabel10, SIZEmplsLabel10, 0}, IS_MPLS_LBL, NOPROC},
    {"cl", "Client Latency", {EXlatencyID, OFFusecClientNwDelay, SIZEusecClientNwDelay, 0}, IS_LATENCY, NOPROC},
    {"sl", "Server Latency", {EXlatencyID, OFFusecServerNwDelay, SIZEusecServerNwDelay, 0}, IS_LATENCY, NOPROC},
    {"al", "Application Latency", {EXlatencyID, OFFusecApplLatency, SIZEusecApplLatency, 0}, IS_LATENCY, NOPROC},
    {"nbar", "Nbar", {EXnbarAppID, OFFnbarAppID, SIZEnbarAppID, 0}, IS_NBAR, NOPROC},
    {"ja3", "                             ja3", {JA3index, OFFja3String, SIZEja3String + 1, 0}, IS_JA3, JA3},
    {"ja4", "                             ja4", {JA4index, OFFja4String, SIZEja4String + 1, 0}, IS_JA4, JA4},
    {"odid", "Obs DomainID", {EXobservationID, OFFdomainID, SIZEdomainID, 0}, IS_HEXNUMBER, NOPROC},
    {"opid", "Obs PointID", {EXobservationID, OFFpointID, SIZEpointID, 0}, IS_HEXNUMBER, NOPROC},
    {"event", " Event", {EXnselCommonID, OFFfwEvent, SIZEfwEvent, 0}, IS_EVENT, NOPROC},
    {"xevent", " Event", {EXnselCommonID, OFFfwXevent, SIZEfwXevent, 0}, IS_NUMBER, NOPROC},
    {"nat", "NAT Event", {EXnelCommonID, OFFnatEvent, SIZEnatEvent, 0}, IS_EVENT, NOPROC},
    {"xsrcip", "X-Src IP Addr", {EXnselXlateIPv4ID, OFFxlateSrc4Addr, SIZExlateSrc4Addr, AF_INET}, IS_IPADDR, NOPROC},
    {"xsrcip", NULL, {EXnselXlateIPv6ID, OFFxlateSrc6Addr, SIZExlateSrc6Addr, AF_INET6}, IS_IPADDR, NOPROC},
    {"xdstip", "X-Dst IP Addr", {EXnselXlateIPv4ID, OFFxlateDst4Addr, SIZExlateDst4Addr, AF_INET}, IS_IPADDR, NOPROC},
    {"xdstip", NULL, {EXnselXlateIPv6ID, OFFxlateDst6Addr, SIZExlateDst6Addr, AF_INET6}, IS_IPADDR, NOPROC},
    {"xip", "X-IP Addr", {EXnselXlateIPv4ID, OFFxlateSrc4Addr, SIZExlateSrc4Addr, AF_INET}, IS_IPADDR, NOPROC},
    {"xip", NULL, {EXnselXlateIPv6ID, OFFxlateSrc6Addr, SIZExlateSrc6Addr, AF_INET6}, IS_IPADDR, NOPROC},
    {"xip", NULL, {EXnselXlateIPv4ID, OFFxlateDst4Addr, SIZExlateDst4Addr, AF_INET}, IS_IPADDR, NOPROC},
    {"xip", NULL, {EXnselXlateIPv6ID, OFFxlateDst6Addr, SIZExlateDst6Addr, AF_INET6}, IS_IPADDR, NOPROC},
    {"xsrcport", "X-Src Port", {EXnselXlatePortID, OFFxlateSrcPort, SIZExlateSrcPort, 0}, IS_NUMBER, NOPROC},
    {"xdstport", "X-Dst Port", {EXnselXlatePortID, OFFxlateDstPort, SIZExlateDstPort, 0}, IS_NUMBER, NOPROC},
    {"xport", "X-Port", {EXnselXlatePortID, OFFxlateSrcPort, SIZExlateSrcPort, 0}, IS_NUMBER, NOPROC},
    {"xport", NULL, {EXnselXlatePortID, OFFxlateDstPort, SIZExlateDstPort, 0}, IS_NUMBER, NOPROC},
    {"iacl", "Ingress ACL", {EXnselAclID, OFFingressAcl, SIZEingressAcl, 0}, IS_HEX, NOPROC},
    {"eacl", "Egress ACL", {EXnselAclID, OFFegressAcl, SIZEegressAcl, 0}, IS_HEX, NOPROC},
    // {"iace", "Ingress ACL", {EXnselAclID, OFFingressAcl, SIZEingressAcl, 0}, IS_HEX, NOPROC},
    // {"eace", "Egress ACL", {EXnselAclID, OFFegressAcl, SIZEegressAcl, 0}, IS_HEX, NOPROC},
    // {"ixace", "Ingress ACL", {EXnselAclID, OFFingressAcl, SIZEingressAcl, 0}, IS_HEX, NOPROC},
    // {"exace", "Egress ACL", {EXnselAclID, OFFegressAcl, SIZEegressAcl, 0}, IS_HEX, NOPROC},
    {"ivrf", "I-vrf ID", {EXvrfID, OFFingressVrf, SIZEingressVrf, 0}, IS_NUMBER, NOPROC},
    {"evrf", "E-vrf ID", {EXvrfID, OFFegressVrf, SIZEegressVrf, 0}, IS_NUMBER, NOPROC},

    {NULL, NULL, {0, 0, 0, 0}, 0, NOPROC}};

// key for element stat
typedef struct hashkey_s {
    union {
        void *ptr;
        khint64_t v0;
    };
    khint64_t v1;
    uint8_t proto;
    uint8_t ptrSize;
} hashkey_t;

// khash record for element stat
typedef struct StatRecord {
    uint64_t msecFirst;
    uint64_t msecLast;
    uint64_t inBytes;
    uint64_t inPackets;
    uint64_t outBytes;
    uint64_t outPackets;
    uint64_t flows;

    // add key for output processing
    hashkey_t hashkey;
} StatRecord_t;

/*
 * pps, bps and bpp are not directly available in the flow/stat record
 * therefore we need a function to calculate these values
 */
typedef enum flowDir { IN = 0,
                       OUT,
                       INOUT } flowDir_t;
typedef uint64_t (*order_proc_element_t)(StatRecord_t *, flowDir_t);

static inline uint64_t null_element(StatRecord_t *record, flowDir_t inout);
static inline uint64_t flows_element(StatRecord_t *record, flowDir_t inout);
static inline uint64_t packets_element(StatRecord_t *record, flowDir_t inout);
static inline uint64_t bytes_element(StatRecord_t *record, flowDir_t inout);
static inline uint64_t pps_element(StatRecord_t *record, flowDir_t inout);
static inline uint64_t bps_element(StatRecord_t *record, flowDir_t inout);
static inline uint64_t bpp_element(StatRecord_t *record, flowDir_t inout);

static struct orderByTable_s {
    char *string;                            // Stat name
    flowDir_t inout;                         // use IN or OUT or INOUT packets/bytes
    order_proc_element_t element_function;   // Function to call for element stats
} orderByTable[] = {{"-", 0, null_element},  // empty entry 0
                    {"flows", IN, flows_element},
                    {"packets", INOUT, packets_element},
                    {"ipkg", IN, packets_element},
                    {"opkg", OUT, packets_element},
                    {"bytes", INOUT, bytes_element},
                    {"ibyte", IN, bytes_element},
                    {"obyte", OUT, bytes_element},
                    {"pps", INOUT, pps_element},
                    {"ipps", IN, pps_element},
                    {"opps", OUT, pps_element},
                    {"bps", INOUT, bps_element},
                    {"ibps", IN, bps_element},
                    {"obps", OUT, bps_element},
                    {"bpp", INOUT, bpp_element},
                    {"ibpp", IN, bpp_element},
                    {"obpp", OUT, bpp_element},
                    {NULL, 0, NULL}};

#define MaxStats 8
static struct StatRequest_s {
    uint32_t orderBy;     // bit field for multiple orders
    uint32_t direction;   // bit field for sorting ascending/descending
    uint8_t StatType;     // index into StatParameters
    uint8_t order_proto;  // protocol separated statistics
} StatRequest[MaxStats];  // This number should do it for a single run

static uint32_t NumStats = 0;  // number of stats in StatRequest

static int HasGeoDB = 0;

// definitions for khash element stat
#define kh_key_hash_func(key) (khint32_t)((key.v1) >> 33 ^ (key.v1) ^ (key.v1) << 11)

// up to 16 bytes (hashkey.v0, hashkey.v1) use faster compare.
// if > 16 bytes ( ptrSize != 0 ) use memcmp for var length
#define kh_key_hash_equal(a, b)                                                              \
    ((a).ptrSize == 0 ? (((a).v1 == (b).v1) && ((a).v0 == (b).v0) && (a).proto == (b).proto) \
                      : ((a).ptrSize == (b).ptrSize && memcmp((a).ptr, (b).ptr, (a).ptrSize) == 0))

KHASH_INIT(ElementHash, hashkey_t, StatRecord_t, 1, kh_key_hash_func, kh_key_hash_equal)

static khash_t(ElementHash) * ElementKHash[MaxStats];

/* function prototypes */
static int ParseListOrder(char *orderBy, struct StatRequest_s *request);

static void PrintStatLine(stat_record_t *stat, outputParams_t *outputParams, StatRecord_t *StatData, int type, int order_proto, int inout);

static void PrintCvsStatLine(stat_record_t *stat, int printPlain, StatRecord_t *StatData, int type, int order_proto, int tag, int inout);

static SortElement_t *StatTopN(int topN, uint32_t *count, int hash_num, int order, direction_t direction);

#include "heapsort_inline.c"
#include "memhandle.c"

static uint64_t null_element(StatRecord_t *record, flowDir_t inout) { return 0; }

static uint64_t flows_element(StatRecord_t *record, flowDir_t inout) { return record->flows; }

static uint64_t packets_element(StatRecord_t *record, flowDir_t inout) {
    if (inout == IN)
        return record->inPackets;
    else if (inout == OUT)
        return record->outPackets;
    else
        return record->inPackets + record->outPackets;
}

static uint64_t bytes_element(StatRecord_t *record, flowDir_t inout) {
    if (inout == IN)
        return record->inBytes;
    else if (inout == OUT)
        return record->outBytes;
    else
        return record->inBytes + record->outBytes;
}

static uint64_t pps_element(StatRecord_t *record, flowDir_t inout) {
    uint64_t duration;
    uint64_t packets;

    /* duration in msec */
    duration = record->msecLast ? record->msecLast - record->msecFirst : 0;
    if (duration == 0)
        return 0;
    else {
        packets = packets_element(record, inout);
        return (1000LL * packets) / duration;
    }

}  // End of pps_element

static uint64_t bps_element(StatRecord_t *record, flowDir_t inout) {
    uint64_t duration;
    uint64_t bytes;

    duration = record->msecLast ? record->msecLast - record->msecFirst : 0;
    if (duration == 0)
        return 0;
    else {
        bytes = bytes_element(record, inout);
        return (8000LL * bytes) / duration; /* 8 bits per Octet - x 1000 for msec */
    }

}  // End of bps_element

static uint64_t bpp_element(StatRecord_t *record, flowDir_t inout) {
    uint64_t packets = packets_element(record, inout);
    uint64_t bytes = bytes_element(record, inout);

    return packets ? bytes / packets : 0;

}  // End of bpp_element

int Init_StatTable(int hasGeoDB) {
    if (!nfalloc_Init(8 * 1024 * 1024)) return 0;

    for (int i = 0; i < MaxStats; i++) {
        ElementKHash[i] = kh_init(ElementHash);
    }

    HasGeoDB = hasGeoDB;
    return 1;

}  // End of Init_StatTable

void Dispose_StatTable(void) { nfalloc_free(); }  // End of Dispose_Tables

static int ParseListOrder(char *orderBy, struct StatRequest_s *request) {
    request->orderBy = 0;

    // default order mode
    if (orderBy == NULL) orderBy = "flows";

    while (orderBy) {
        char *q = strchr(orderBy, '/');
        if (q) *q = 0;

        char *r = strchr(orderBy, ':');
        direction_t direction;
        if (r) {
            *r++ = 0;
            switch (*r) {
                case 'a':
                    direction = ASCENDING;
                    break;
                case 'd':
                    direction = DESCENDING;
                    break;
                default:
                    return -1;
            }
        } else {
            direction = DESCENDING;
        }

        int i = 0;
        while (orderByTable[i].string) {
            if (strcasecmp(orderByTable[i].string, orderBy) == 0) break;
            i++;
        }
        if (orderByTable[i].string == NULL) {
            LogError("Unknown order option /%s", orderBy);
            return 0;
        }
        request->orderBy |= (1 << i);
        request->direction |= (direction << i);
        if (q == NULL) {
            return 1;
        }
        orderBy = ++q;
    }

    // not reached
    return 1;

}  // End of ParseListOrder

/*
 * an stat string -s <stat> looks like
 * -s <elem>[:p][/orderby[:<dir]]
 * elem: any statname string in StatParameters
 *  optional :p split statistic into protocols tcp/udp/icmp etc.
 *  optional orderBy: order statistic by string in orderByTable
 *  optional :dir a: ascending d:descending
 */
int SetElementStat(char *elementStat, char *orderBy) {
    if (NumStats == MaxStats) {
        LogError("Too many stat options! Stats are limited to %i stats per single run", MaxStats);
        return 0;
    }

    struct StatRequest_s *request = &StatRequest[NumStats++];
    request->order_proto = 0;
    char *optProto = strchr(elementStat, ':');
    if (optProto) {
        *optProto++ = 0;
        if (optProto[0] == 'p' && optProto[1] == '\0') {
            request->order_proto = 1;
        } else {
            LogError("Unknown statistic option :%s in %s", optProto, elementStat);
            return 0;
        }
    }

    if (strcasecmp(elementStat, "proto") == 0) request->order_proto = 1;

    int i = 0;
    while (StatParameters[i].statname) {
        if (strcasecmp(elementStat, StatParameters[i].statname) == 0) {
            request->StatType = i;
            break;
        }
        i++;
    }

    if (StatParameters[i].statname == NULL) {
        LogError("Unknown statistic: %s", elementStat);
        return 0;
    }

    // check if one or more orders are given
    if (ParseListOrder(orderBy, request) == 0) {
        LogError("Unknown statistic option /%s in %s", orderBy, elementStat);
        return 0;
    }

    return 1;

}  // End of SetElementStat

static inline void *PreProcess(void *inPtr, preprocess_t process, recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    switch (process) {
        case NOPROC:
            return inPtr;
            break;
        case SRC_GEO: {
            char *geo = (char *)inPtr;
            if (HasGeoDB == 0 || geo[0]) return inPtr;
            if (ipv4Flow)
                LookupV4Country(ipv4Flow->srcAddr, geo);
            else if (ipv6Flow)
                LookupV6Country(ipv6Flow->srcAddr, geo);
        } break;
        case DST_GEO: {
            char *geo = (char *)inPtr;
            if (HasGeoDB == 0 || geo[0]) return inPtr;
            if (ipv4Flow)
                LookupV4Country(ipv4Flow->dstAddr, inPtr);
            else if (ipv6Flow)
                LookupV6Country(ipv6Flow->dstAddr, inPtr);
        } break;
        case SRC_AS: {
            uint32_t *as = (uint32_t *)inPtr;
            if (HasGeoDB == 0 || *as) return inPtr;
            *as = ipv4Flow ? LookupV4AS(ipv4Flow->srcAddr) : (ipv6Flow ? LookupV6AS(ipv6Flow->srcAddr) : 0);
        } break;
        case DST_AS: {
            uint32_t *as = (uint32_t *)inPtr;
            if (HasGeoDB == 0 || *as) return inPtr;
            *as = ipv4Flow ? LookupV4AS(ipv4Flow->dstAddr) : (ipv6Flow ? LookupV6AS(ipv6Flow->dstAddr) : 0);
        } break;
        case PREV_AS: {
        } break;
        case NEXT_AS: {
        } break;
        case JA3: {
            const uint8_t *payload = (const uint8_t *)recordHandle->extensionList[EXinPayloadID];
            if (payload == NULL || genericFlow->proto != IPPROTO_TCP || inPtr) return inPtr;

            ssl_t *ssl = recordHandle->extensionList[SSLindex];
            if (ssl == NULL) {
                uint32_t payloadLength = ExtensionLength(payload);
                ssl = sslProcess(payload, payloadLength);
                recordHandle->extensionList[SSLindex] = ssl;
                if (ssl == NULL) {
                    return NULL;
                }
            }
            // ssl is defined
            char *ja3 = ja3Process(ssl, NULL);
            recordHandle->extensionList[JA3index] = ja3;
            return ja3;
        } break;
        case JA4: {
            EXinPayload_t *payload = (EXinPayload_t *)recordHandle->extensionList[EXinPayloadID];
            if (payload == NULL || genericFlow->proto != IPPROTO_TCP) return NULL;

            ssl_t *ssl = recordHandle->extensionList[SSLindex];
            if (ssl == NULL) {
                uint32_t payloadLength = ExtensionLength(payload);
                ssl = sslProcess(payload, payloadLength);
                recordHandle->extensionList[SSLindex] = ssl;
                if (ssl == NULL) {
                    return NULL;
                }
            }
            // ssl is defined
            ja4_t *ja4 = NULL;
            if (ssl->type == CLIENTssl) {
                ja4 = ja4Process(ssl, genericFlow->proto);
            } else {
                ja4 = ja4sProcess(ssl, genericFlow->proto);
            }
            recordHandle->extensionList[JA4index] = ja4;
            return ja4;

        } break;
    }

    return inPtr;
}  // End of PreProcess

void AddElementStat(recordHandle_t *recordHandle) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    if (!genericFlow) return;

    // for every requested -s stat do
    for (int i = 0; i < NumStats; i++) {
        hashkey_t hashkey = {0};
        hashkey.proto = StatRequest[i].order_proto ? genericFlow->proto : 0;
        int index = StatRequest[i].StatType;
        // for the number of elements in this stat type
        do {
            uint32_t extID = StatParameters[index].element.extID;
            size_t offset = StatParameters[index].element.offset;

            void *inPtr = recordHandle->extensionList[extID];
            if (inPtr == NULL) {
                if (extID <= MAXEXTENSIONS) {
                    index++;
                    continue;
                }
            }

            preprocess_t lookup = StatParameters[index].preprocess;
            inPtr = PreProcess(inPtr, lookup, recordHandle);
            if (inPtr == NULL) {
                index++;
                continue;
            }

            inPtr += offset;
            uint32_t length = StatParameters[index].element.length;
            switch (length) {
                case 0:
                    break;
                case 1: {
                    hashkey.v1 = *((uint8_t *)inPtr);
                } break;
                case 2: {
                    hashkey.v1 = *((uint16_t *)inPtr);
                } break;
                case 4: {
                    hashkey.v1 = *((uint32_t *)inPtr);
                } break;
                case 8: {
                    hashkey.v1 = *((uint64_t *)inPtr);
                } break;
                case 16: {
                    hashkey.v0 = ((uint64_t *)inPtr)[0];
                    hashkey.v1 = ((uint64_t *)inPtr)[1];
                } break;
                default: {
                    void *p = nfmalloc(length);
                    hashkey.ptr = p;
                    memcpy((void *)p, inPtr, length);
                    hashkey.ptrSize = length;
                }
            }

            EXcntFlow_t *cntFlow = (EXcntFlow_t *)recordHandle->extensionList[EXcntFlowID];
            uint64_t outBytes = 0;
            uint64_t outPackets = 0;
            uint64_t numFlows = 1;
            if (cntFlow) {
                outBytes = cntFlow->outBytes;
                outPackets = cntFlow->outPackets;
                numFlows = cntFlow->flows ? cntFlow->flows : 1;
            }
            int ret;
            khiter_t k = kh_put(ElementHash, ElementKHash[i], hashkey, &ret);
            if (ret == 0) {
                kh_value(ElementKHash[i], k).inBytes += genericFlow->inBytes;
                kh_value(ElementKHash[i], k).inPackets += genericFlow->inPackets;
                kh_value(ElementKHash[i], k).outBytes += outBytes;
                kh_value(ElementKHash[i], k).outPackets += outPackets;

                if (genericFlow->msecFirst < kh_value(ElementKHash[i], k).msecFirst) {
                    kh_value(ElementKHash[i], k).msecFirst = genericFlow->msecFirst;
                }
                if (genericFlow->msecLast > kh_value(ElementKHash[i], k).msecLast) {
                    kh_value(ElementKHash[i], k).msecLast = genericFlow->msecLast;
                }
                kh_value(ElementKHash[i], k).flows += numFlows;

            } else {
                kh_value(ElementKHash[i], k).inBytes = genericFlow->inBytes;
                kh_value(ElementKHash[i], k).inPackets = genericFlow->inPackets;
                kh_value(ElementKHash[i], k).outBytes = outBytes;
                kh_value(ElementKHash[i], k).outPackets = outPackets;
                kh_value(ElementKHash[i], k).msecFirst = genericFlow->msecFirst;
                kh_value(ElementKHash[i], k).msecLast = genericFlow->msecLast;
                kh_value(ElementKHash[i], k).flows = numFlows;
                kh_value(ElementKHash[i], k).hashkey = hashkey;
            }
            index++;
        } while (StatParameters[index].HeaderInfo == NULL);
    }  // for every requested -s stat
}  // AddElementStat

static void PrintStatLine(stat_record_t *stat, outputParams_t *outputParams, StatRecord_t *StatData, int type, int order_proto, int inout) {
    char valstr[64];
    valstr[0] = '\0';

    char tag_string[2] = {'\0', '\0'};
    switch (type) {
        case IS_NULL:
            break;
        case IS_NUMBER:
            snprintf(valstr, 64, "%llu", (unsigned long long)StatData->hashkey.v1);
            break;
        case IS_HEXNUMBER:
            snprintf(valstr, 64, "0x%llx", (unsigned long long)StatData->hashkey.v1);
            break;
        case IS_IPADDR:
            tag_string[0] = outputParams->doTag ? TAG_CHAR : '\0';
            if (StatData->hashkey.v0 == 0) {  // IPv4
                uint32_t ipv4 = htonl(StatData->hashkey.v1);
                if (outputParams->hasGeoDB) {
                    char ipstr[16], country[4] = {0};
                    inet_ntop(AF_INET, &ipv4, ipstr, sizeof(ipstr));
                    LookupV4Country(StatData->hashkey.v1, country);
                    snprintf(valstr, 40, "%s(%s)", ipstr, country);
                } else {
                    inet_ntop(AF_INET, &ipv4, valstr, sizeof(valstr));
                }
            } else {  // IPv6
                uint64_t _key[2] = {htonll(StatData->hashkey.v0), htonll(StatData->hashkey.v1)};
                if (outputParams->hasGeoDB) {
                    char ipstr[40], country[4] = {0};
                    uint64_t ip[2] = {StatData->hashkey.v0, StatData->hashkey.v1};
                    LookupV6Country(ip, country);
                    inet_ntop(AF_INET6, _key, ipstr, sizeof(ipstr));
                    if (!Getv6Mode()) CondenseV6(ipstr);
                    snprintf(valstr, 64, "%s(%s)", ipstr, country);
                } else {
                    inet_ntop(AF_INET6, _key, valstr, sizeof(valstr));
                    if (!Getv6Mode()) CondenseV6(valstr);
                }
            }
            break;
        case IS_MACADDR: {
            uint8_t mac[6];
            for (int i = 0; i < 6; i++) {
                mac[i] = ((unsigned long long)StatData->hashkey.v1 >> (i * 8)) & 0xFF;
            }
            snprintf(valstr, 64, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);
        } break;
        case IS_MPLS_LBL: {
            snprintf(valstr, 64, "%llu", (unsigned long long)StatData->hashkey.v1);
            snprintf(valstr, 64, "%8llu-%1llu-%1llu", (unsigned long long)StatData->hashkey.v1 >> 4,
                     ((unsigned long long)StatData->hashkey.v1 & 0xF) >> 1, (unsigned long long)StatData->hashkey.v1 & 1);
        } break;
        case IS_LATENCY: {
            snprintf(valstr, 64, "      %9.3f", (double)((double)StatData->hashkey.v1 / 1000.0));
        } break;
        case IS_EVENT: {
            long long unsigned event = StatData->hashkey.v1;
            char *s;
            switch (event) {
                case 0:
                    s = "ignore";
                    break;
                case 1:
                    s = "CREATE";
                    break;
                case 2:
                    s = "DELETE";
                    break;
                case 3:
                    s = "DENIED";
                    break;
                default:
                    s = "UNKNOWN";
            }
            snprintf(valstr, 64, "      %6s", s);
        } break;
        case IS_HEX: {
            snprintf(valstr, 64, "0x%llx", (unsigned long long)StatData->hashkey.v1);
        } break;
        case IS_NBAR: {
            union {
                uint8_t val8[4];
                uint32_t val32;
            } conv;
            conv.val32 = StatData->hashkey.v1;
            uint8_t u = conv.val8[0];
            conv.val8[0] = 0;
            /*
                                    conv.val8[1] = r->nbarAppID[1];
                                    conv.val8[2] = r->nbarAppID[2];
                                    conv.val8[3] = r->nbarAppID[3];
            */
            snprintf(valstr, 64, "%2u..%u", u, ntohl(conv.val32));

        } break;
        case IS_JA3: {
            char *s = (char *)StatData->hashkey.ptr;
            strcpy(valstr, s);
        } break;
        case IS_JA4: {
            char *s = (char *)StatData->hashkey.ptr;
            strcpy(valstr, s);
        } break;
        case IS_GEO: {
            snprintf(valstr, 64, "%s", (char *)&(StatData->hashkey.v1));
        }
    }
    valstr[63] = 0;

    uint64_t count_flows = StatData->flows;
    uint64_t count_packets = packets_element(StatData, inout);
    uint64_t count_bytes = bytes_element(StatData, inout);
    numStr flows_str, byte_str, packets_str;
    format_number(count_flows, flows_str, outputParams->printPlain, FIXED_WIDTH);
    format_number(count_packets, packets_str, outputParams->printPlain, FIXED_WIDTH);
    format_number(count_bytes, byte_str, outputParams->printPlain, FIXED_WIDTH);

    double flows_percent = stat->numflows ? (double)(count_flows * 100) / (double)stat->numflows : 0;
    double packets_percent, bytes_percent;
    if (stat->numpackets) {
        packets_percent = (double)(count_packets * 100) / (double)stat->numpackets;
    } else {
        packets_percent = 0;
    }

    if (stat->numbytes) {
        bytes_percent = (double)(count_bytes * 100) / (double)stat->numbytes;
    } else {
        bytes_percent = 0;
    }

    uint64_t pps = 0;
    uint64_t bps = 0;
    double duration = StatData->msecLast ? (StatData->msecLast - StatData->msecFirst) / 1000.0 : 0;
    if (duration != 0) {
        // duration in sec
        pps = (count_packets) / duration;
        bps = (8 * count_bytes) / duration;
    }

    uint32_t bpp = 0;
    if (count_packets) {
        bpp = count_bytes / count_packets;
    }

    numStr pps_str, bps_str;
    format_number(pps, pps_str, outputParams->printPlain, FIXED_WIDTH);
    format_number(bps, bps_str, outputParams->printPlain, FIXED_WIDTH);

    time_t first = StatData->msecFirst / 1000LL;
    struct tm *tbuff = localtime(&first);
    if (!tbuff) {
        LogError("localtime() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
        return;
    }
    char datestr[64];
    strftime(datestr, 63, "%Y-%m-%d %H:%M:%S", tbuff);

    char *protoStr = order_proto ? ProtoString(StatData->hashkey.proto, outputParams->printPlain) : "any";
    char dStr[64];
    if (outputParams->printPlain)
        snprintf(dStr, 64, "%16.3f", duration);
    else
        snprintf(dStr, 64, "%s", DurationString(duration));

    if (Getv6Mode() && (type == IS_IPADDR)) {
        printf("%s.%03u %9.3f %-5s %s%39s %8s(%4.1f) %8s(%4.1f) %8s(%4.1f) %8s %8s %5u\n", datestr, (unsigned)(StatData->msecFirst % 1000), duration,
               protoStr, tag_string, valstr, flows_str, flows_percent, packets_str, packets_percent, byte_str, bytes_percent, pps_str, bps_str, bpp);
    } else {
        if (outputParams->hasGeoDB) {
            printf("%s.%03u %9s %-5s %s%21s %8s(%4.1f) %8s(%4.1f) %8s(%4.1f) %8s %8s %5u\n", datestr, (unsigned)(StatData->msecFirst % 1000), dStr,
                   protoStr, tag_string, valstr, flows_str, flows_percent, packets_str, packets_percent, byte_str, bytes_percent, pps_str, bps_str,
                   bpp);
        } else {
            printf("%s.%03u %9s %-5s %s%17s %8s(%4.1f) %8s(%4.1f) %8s(%4.1f) %8s %8s %5u\n", datestr, (unsigned)(StatData->msecFirst % 1000), dStr,
                   protoStr, tag_string, valstr, flows_str, flows_percent, packets_str, packets_percent, byte_str, bytes_percent, pps_str, bps_str,
                   bpp);
        }
    }

}  // End of PrintStatLine

static void PrintCvsStatLine(stat_record_t *stat, int printPlain, StatRecord_t *StatData, int type, int order_proto, int tag, int inout) {
    char valstr[40];

    switch (type) {
        case IS_NULL:
            break;
        case IS_NUMBER:
            snprintf(valstr, 40, "%llu", (unsigned long long)StatData->hashkey.v1);
            break;
        case IS_IPADDR:
            if (StatData->hashkey.v0 != 0) {  // IPv6
                uint64_t _key[2];
                _key[0] = htonll(StatData->hashkey.v0);
                _key[1] = htonll(StatData->hashkey.v1);
                inet_ntop(AF_INET6, _key, valstr, sizeof(valstr));

            } else {  // IPv4
                uint32_t ipv4;
                ipv4 = htonl(StatData->hashkey.v1);
                inet_ntop(AF_INET, &ipv4, valstr, sizeof(valstr));
            }
            break;
        case IS_MACADDR: {
            int i;
            uint8_t mac[6];
            for (i = 0; i < 6; i++) {
                mac[i] = ((unsigned long long)StatData->hashkey.v1 >> (i * 8)) & 0xFF;
            }
            snprintf(valstr, 40, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);
        } break;
        case IS_MPLS_LBL: {
            snprintf(valstr, 40, "%llu", (unsigned long long)StatData->hashkey.v1);
            snprintf(valstr, 40, "%8llu-%1llu-%1llu", (unsigned long long)StatData->hashkey.v1 >> 4,
                     ((unsigned long long)StatData->hashkey.v1 & 0xF) >> 1, (unsigned long long)StatData->hashkey.v1 & 1);
        } break;
    }

    valstr[39] = 0;

    uint64_t count_flows = StatData->flows;
    uint64_t count_packets = packets_element(StatData, inout);
    uint64_t count_bytes = bytes_element(StatData, inout);

    double flows_percent = stat->numflows ? (double)(count_flows * 100) / (double)stat->numflows : 0;
    double packets_percent = stat->numpackets ? (double)(count_packets * 100) / (double)stat->numpackets : 0;
    double bytes_percent = stat->numbytes ? (double)(count_bytes * 100) / (double)stat->numbytes : 0;

    double duration = StatData->msecLast ? (StatData->msecLast - StatData->msecFirst) / 1000.0 : 0;

    uint64_t pps, bps;
    if (duration != 0) {
        pps = (uint64_t)((double)count_packets / duration);
        bps = (uint64_t)((double)(8 * count_bytes) / duration);
    } else {
        pps = bps = 0;
    }

    uint32_t bpp;
    if (count_packets) {
        bpp = count_bytes / count_packets;
    } else {
        bpp = 0;
    }

    time_t when = StatData->msecFirst / 1000;
    struct tm *tbuff = localtime(&when);
    if (!tbuff) {
        perror("Error time convert");
        exit(250);
    }
    char datestr1[64];
    strftime(datestr1, 63, "%Y-%m-%d %H:%M:%S", tbuff);

    when = StatData->msecLast / 1000;
    tbuff = localtime(&when);
    if (!tbuff) {
        perror("Error time convert");
        exit(250);
    }
    char datestr2[64];
    strftime(datestr2, 63, "%Y-%m-%d %H:%M:%S", tbuff);

    printf("%s,%s,%.3f,%s,%s,%llu,%.1f,%llu,%.1f,%llu,%.1f,%llu,%llu,%u\n", datestr1, datestr2, duration,
           order_proto ? ProtoString(StatData->hashkey.proto, printPlain) : "any", valstr, (long long unsigned)count_flows, flows_percent,
           (long long unsigned)count_packets, packets_percent, (long long unsigned)count_bytes, bytes_percent, (long long unsigned)pps,
           (long long unsigned)bps, bpp);

}  // End of PrintCvsStatLine

void PrintElementStat(stat_record_t *sum_stat, outputParams_t *outputParams, RecordPrinter_t print_record) {
    uint32_t numflows = 0;

    // for every requested -s stat do
    for (int hash_num = 0; hash_num < NumStats; hash_num++) {
        int stat = StatRequest[hash_num].StatType;
        int order = StatRequest[hash_num].orderBy;
        int type = StatParameters[stat].type;
        for (int order_index = 0; orderByTable[order_index].string != NULL; order_index++) {
            unsigned int order_bit = (1 << order_index);
            if (order & order_bit) {
                int direction = (StatRequest[hash_num].direction & order_bit) == 0 ? DESCENDING : ASCENDING;
                dbg_printf("Get direction: %s\n", direction == ASCENDING ? "ASCENDING" : "DESCENDING");
                SortElement_t *topN_element_list = StatTopN(outputParams->topN, &numflows, hash_num, order_index, direction);

                // this output formatting is pretty ugly - and needs to be cleaned up - improved
                if (outputParams->mode == MODE_PLAIN && !outputParams->quiet) {
                    if (outputParams->topN != 0) {
                        printf("Top %i %s ordered by %s:\n", outputParams->topN, StatParameters[stat].HeaderInfo, orderByTable[order_index].string);
                    } else {
                        printf("Top %s ordered by %s:\n", StatParameters[stat].HeaderInfo, orderByTable[order_index].string);
                    }
                    if (Getv6Mode() && (type == IS_IPADDR)) {
                        printf(
                            "Date first seen                 Duration Proto %39s    Flows(%%)     Packets(%%)       Bytes(%%)         pps      bps   "
                            "bpp\n",
                            StatParameters[stat].HeaderInfo);
                    } else {
                        if (outputParams->hasGeoDB) {
                            printf(
                                "Date first seen                 Duration Proto %21s    Flows(%%)     Packets(%%)       Bytes(%%)         pps      "
                                "bps   "
                                "bpp\n",
                                StatParameters[stat].HeaderInfo);
                        } else {
                            printf(
                                "Date first seen                 Duration Proto %17s    Flows(%%)     Packets(%%)       Bytes(%%)         pps      "
                                "bps   "
                                "bpp\n",
                                StatParameters[stat].HeaderInfo);
                        }
                    }
                }

                if (outputParams->mode == MODE_CSV) {
                    if (orderByTable[order_index].inout == IN)
                        printf("ts,te,td,pr,val,fl,flP,ipkt,ipktP,ibyt,ibytP,ipps,ibps,ibpp\n");
                    else if (orderByTable[order_index].inout == OUT)
                        printf("ts,te,td,pr,val,fl,flP,opkt,opktP,obyt,obytP,opps,obps,obpp\n");
                    else
                        printf("ts,te,td,pr,val,fl,flP,pkt,pktP,byt,bytP,pps,bps,bpp\n");
                }

                int startIndex, endIndex, increment;
                if (direction == ASCENDING) {
                    startIndex = 0;
                    endIndex = outputParams->topN;
                    if (endIndex > numflows || (outputParams->topN == 0)) endIndex = numflows;
                    increment = 1;
                } else {
                    startIndex = numflows - 1;
                    endIndex = numflows - 1 - outputParams->topN;
                    if (endIndex < 0 || (outputParams->topN == 0)) endIndex = -1;
                    increment = -1;
                }
                dbg_printf("Print stat table: start: %d, end: %d, incr: %d\n", startIndex, endIndex, increment);
                int index = startIndex;
                while (index != endIndex) {
                    switch (outputParams->mode) {
                        case MODE_PLAIN:
                            PrintStatLine(sum_stat, outputParams, (StatRecord_t *)topN_element_list[index].record, type,
                                          StatRequest[hash_num].order_proto, orderByTable[order_index].inout);
                            break;
                        case MODE_CSV:
                            PrintCvsStatLine(sum_stat, outputParams->printPlain, (StatRecord_t *)topN_element_list[index].record, type,
                                             StatRequest[hash_num].order_proto, outputParams->doTag, orderByTable[order_index].inout);
                            break;
                        case MODE_JSON:
                            printf("Not yet implemented output format\n");
                            break;
                        case MODE_JSON_LOG:
                            printf("Not yet implemented output format\n");
                            break;
                    }
                    index += increment;
                }
                free((void *)topN_element_list);
            }
        }  // for every requested order
    }      // for every requested -s stat do
}  // End of PrintElementStat

static SortElement_t *StatTopN(int topN, uint32_t *count, int hash_num, int order, direction_t direction) {
    SortElement_t *topN_list;
    uint32_t c, maxindex;

    maxindex = kh_size(ElementKHash[hash_num]);
    dbg_printf("StatTopN sort %u records\n", maxindex);
    topN_list = (SortElement_t *)calloc(maxindex, sizeof(SortElement_t));

    if (!topN_list) {
        perror("Can't allocate Top N lists: \n");
        return NULL;
    }

    // preset topN_list table - still unsorted
    c = 0;
    // Iterate through all buckets
    for (khiter_t k = kh_begin(ElementKHash[hash_num]); k != kh_end(ElementKHash[hash_num]); ++k) {  // traverse
        if (kh_exist(ElementKHash[hash_num], k)) {
            StatRecord_t *r = &kh_value(ElementKHash[hash_num], k);
            topN_list[c].count = orderByTable[order].element_function(r, orderByTable[order].inout);
            topN_list[c].record = (void *)r;
            c++;
        }
    }

    *count = c;
    dbg_printf("Sort %u flows\n", c);

#ifdef DEVEL
    for (int i = 0; i < maxindex; i++) printf("%i, %llu %p\n", i, topN_list[i].count, topN_list[i].record);
#endif

    // Sorting makes only sense, when 2 or more flows are left
    if (c >= 2) {
        if (c < 100)
            heapSort(topN_list, c, topN, DESCENDING);
        else
            blocksort((SortRecord_t *)topN_list, c);
    }

#ifdef DEVEL
    for (int i = 0; i < maxindex; i++) printf("%i, %llu %llx\n", i, topN_list[i].count, (unsigned long long)topN_list[i].record);
#endif

    return topN_list;

}  // End of StatTopN

void ListPrintOrder(void) {
    printf("Available print order:\n");
    for (int i = 0; orderByTable[i].string != NULL; i++) {
        printf("%s ", orderByTable[i].string);
    }
    printf("- See also nfdump(1)\n");
}  // End of ListPrintOrder

void ListStatTypes(void) {
    int cnt = 0;
    printf("Available element statistics:");
    for (int i = 0; StatParameters[i].statname != NULL; i++) {
        if ((cnt & 0x7) == 0) {
            cnt++;
            printf("\n");
        }
        if (StatParameters[i].HeaderInfo) {
            cnt++;
            printf("%s ", StatParameters[i].statname);
        };
    }
    printf("- See also nfdump(1)\n");
}  // End of ListStatTypes