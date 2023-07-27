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
#include "bookkeeper.h"
#include "collector.h"
#include "config.h"
#include "khash.h"
#include "maxmind.h"
#include "nfdump.h"
#include "nffile.h"
#include "nflowcache.h"
#include "nfxV3.h"
#include "output_fmt.h"
#include "output_util.h"
#include "util.h"

enum { IS_NUMBER = 1, IS_HEXNUMBER, IS_IPADDR, IS_MACADDR, IS_MPLS_LBL, IS_LATENCY, IS_EVENT, IS_HEX, IS_NBAR, IS_JA3, IS_GEO };

struct flow_element_s {
    uint32_t offset0;
    uint32_t offset1;  // offset in master record block, as uint64_t array
    uint64_t mask;     // mask for value in 64bit word
    uint32_t shift;    // number of bits to shift right to get final value
};

struct StatParameter_s {
    char *statname;                    // name of -s option
    char *HeaderInfo;                  // How to name the field in the output header line
    struct flow_element_s element[2];  // what element(s) in flow record is used for statistics.
                                       // need 2 elements to be able to get src/dst stats in one stat record
    uint8_t num_elem;                  // number of elements used. 1 or 2
    uint8_t type;                      // Type of element: Number, IP address, MAC address etc.
} StatParameters[] = {
    // flow record stat
    {"record", "", {{0, 0, 0, 0}, {0, 0, 0, 0}}, 1, 0},

    // 9 possible flow element stats
    {"srcip", "Src IP Addr", {{OffsetSrcIPv6a, OffsetSrcIPv6b, MaskIPv6, 0}, {0, 0, 0, 0}}, 1, IS_IPADDR},

    {"dstip", "Dst IP Addr", {{OffsetDstIPv6a, OffsetDstIPv6b, MaskIPv6, 0}, {0, 0, 0, 0}}, 1, IS_IPADDR},

    {"ip", "IP Addr", {{OffsetSrcIPv6a, OffsetSrcIPv6b, MaskIPv6, 0}, {OffsetDstIPv6a, OffsetDstIPv6b, MaskIPv6}}, 2, IS_IPADDR},

    {"srcgeo", "Src Geo", {{0, OffsetGeo, MaskSrcGeo, ShiftSrcGeo}, {0, 0, 0, 0}}, 1, IS_GEO},

    {"dstgeo", "Dst Geo", {{0, OffsetGeo, MaskDstGeo, ShiftDstGeo}, {0, 0, 0, 0}}, 1, IS_GEO},

    {"geo", "Geo", {{0, OffsetGeo, MaskSrcGeo, ShiftSrcGeo}, {0, OffsetGeo, MaskDstGeo, ShiftDstGeo}}, 2, IS_GEO},

    {"nhip", "Nexthop IP", {{OffsetNexthopv6a, OffsetNexthopv6b, MaskIPv6, 0}, {0, 0, 0, 0}}, 1, IS_IPADDR},

    {"nhbip", "Nexthop BGP IP", {{OffsetBGPNexthopv6a, OffsetBGPNexthopv6b, MaskIPv6, 0}, {0, 0, 0, 0}}, 1, IS_IPADDR},

    {"router", "Router IP", {{OffsetRouterv6a, OffsetRouterv6b, MaskIPv6, 0}, {0, 0, 0, 0}}, 1, IS_IPADDR},

    {"srcport", "Src Port", {{0, OffsetPort, MaskSrcPort, ShiftSrcPort}, {0, 0, 0, 0}}, 1, IS_NUMBER},

    {"dstport", "Dst Port", {{0, OffsetPort, MaskDstPort, ShiftDstPort}, {0, 0, 0, 0}}, 1, IS_NUMBER},

    {"port", "Port", {{0, OffsetPort, MaskSrcPort, ShiftSrcPort}, {0, OffsetPort, MaskDstPort, ShiftDstPort}}, 2, IS_NUMBER},

    {"proto", "Protocol", {{0, OffsetProto, MaskProto, ShiftProto}, {0, 0, 0, 0}}, 1, IS_NUMBER},

    {"tos", "Tos", {{0, OffsetTos, MaskTos, ShiftTos}, {0, 0, 0, 0}}, 1, IS_NUMBER},

    {"srctos", "Tos", {{0, OffsetTos, MaskTos, ShiftTos}, {0, 0, 0, 0}}, 1, IS_NUMBER},

    {"dsttos", "Dst Tos", {{0, OffsetDstTos, MaskDstTos, ShiftDstTos}, {0, 0, 0, 0}}, 1, IS_NUMBER},

    {"dir", "Dir", {{0, OffsetDir, MaskDir, ShiftDir}, {0, 0, 0, 0}}, 1, IS_NUMBER},

    {"srcas", "Src AS", {{0, OffsetAS, MaskSrcAS, ShiftSrcAS}, {0, 0, 0, 0}}, 1, IS_NUMBER},

    {"dstas", "Dst AS", {{0, OffsetAS, MaskDstAS, ShiftDstAS}, {0, 0, 0, 0}}, 1, IS_NUMBER},

    {"prevas", "Prev AS", {{0, OffsetBGPadj, MaskBGPadjPrev, ShiftBGPadjPrev}, {0, 0, 0, 0}}, 1, IS_NUMBER},

    {"nextas", "Next AS", {{0, OffsetBGPadj, MaskBGPadjNext, ShiftBGPadjNext}, {0, 0, 0, 0}}, 1, IS_NUMBER},

    {"as", "AS", {{0, OffsetAS, MaskSrcAS, ShiftSrcAS}, {0, OffsetAS, MaskDstAS, ShiftDstAS}}, 2, IS_NUMBER},

    {"inif", "Input If", {{0, OffsetInOut, MaskInput, ShiftInput}, {0, 0, 0, 0}}, 1, IS_NUMBER},

    {"outif", "Output If", {{0, OffsetInOut, MaskOutput, ShiftOutput}, {0, 0, 0, 0}}, 1, IS_NUMBER},

    {"if", "In/Out If", {{0, OffsetInOut, MaskInput, ShiftInput}, {0, OffsetInOut, MaskOutput, ShiftOutput}}, 2, IS_NUMBER},

    {"srcmask", "Src Mask", {{0, OffsetMask, MaskSrcMask, ShiftSrcMask}, {0, 0, 0, 0}}, 1, IS_NUMBER},

    {"dstmask", "Dst Mask", {{0, OffsetMask, MaskDstMask, ShiftDstMask}, {0, 0, 0, 0}}, 1, IS_NUMBER},

    {"mask", "Mask", {{0, OffsetMask, MaskSrcMask, ShiftSrcMask}, {0, OffsetMask, MaskDstMask, ShiftDstMask}}, 2, IS_NUMBER},

    {"srcvlan", "Src Vlan", {{0, OffsetVlan, MaskSrcVlan, ShiftSrcVlan}, {0, 0, 0, 0}}, 1, IS_NUMBER},

    {"dstvlan", "Dst Vlan", {{0, OffsetVlan, MaskDstVlan, ShiftDstVlan}, {0, 0, 0, 0}}, 1, IS_NUMBER},

    {"vlan", "Vlan", {{0, OffsetVlan, MaskSrcVlan, ShiftSrcVlan}, {0, OffsetVlan, MaskDstVlan, ShiftDstVlan}}, 2, IS_NUMBER},

    {"insrcmac", "In Src Mac", {{0, OffsetInSrcMAC, MaskMac, 0}, {0, 0, 0, 0}}, 1, IS_MACADDR},

    {"outdstmac", "Out Dst Mac", {{0, OffsetOutDstMAC, MaskMac, 0}, {0, 0, 0, 0}}, 1, IS_MACADDR},

    {"indstmac", "In Dst Mac", {{0, OffsetInDstMAC, MaskMac, 0}, {0, 0, 0, 0}}, 1, IS_MACADDR},

    {"outsrcmac", "Out Src Mac", {{0, OffsetOutSrcMAC, MaskMac, 0}, {0, 0, 0, 0}}, 1, IS_MACADDR},

    {"srcmac", "Src Mac", {{0, OffsetInSrcMAC, MaskMac, 0}, {0, OffsetOutSrcMAC, MaskMac, 0}}, 2, IS_MACADDR},

    {"dstmac", "Dst Mac", {{0, OffsetOutDstMAC, MaskMac, 0}, {0, OffsetInDstMAC, MaskMac, 0}}, 2, IS_MACADDR},

    {"inmac", "In Src Mac", {{0, OffsetInSrcMAC, MaskMac, 0}, {0, OffsetInDstMAC, MaskMac, 0}}, 1, IS_MACADDR},

    {"outmac", "Out Src Mac", {{0, OffsetOutSrcMAC, MaskMac, 0}, {0, OffsetOutDstMAC, MaskMac, 0}}, 2, IS_MACADDR},

    {"mpls1", " MPLS lab 1", {{0, OffsetMPLS12, MaskMPLSlabelOdd, 0}, {0, 0, 0, 0}}, 1, IS_MPLS_LBL},

    {"mpls2", " MPLS lab 2", {{0, OffsetMPLS12, MaskMPLSlabelEven, 0}, {0, 0, 0, 0}}, 1, IS_MPLS_LBL},

    {"mpls3", " MPLS lab 3", {{0, OffsetMPLS34, MaskMPLSlabelOdd, 0}, {0, 0, 0, 0}}, 1, IS_MPLS_LBL},

    {"mpls4", " MPLS lab 4", {{0, OffsetMPLS34, MaskMPLSlabelEven, 0}, {0, 0, 0, 0}}, 1, IS_MPLS_LBL},

    {"mpls5", " MPLS lab 5", {{0, OffsetMPLS56, MaskMPLSlabelOdd, 0}, {0, 0, 0, 0}}, 1, IS_MPLS_LBL},

    {"mpls6", " MPLS lab 6", {{0, OffsetMPLS56, MaskMPLSlabelEven, 0}, {0, 0, 0, 0}}, 1, IS_MPLS_LBL},

    {"mpls7", " MPLS lab 7", {{0, OffsetMPLS78, MaskMPLSlabelOdd, 0}, {0, 0, 0, 0}}, 1, IS_MPLS_LBL},

    {"mpls8", " MPLS lab 8", {{0, OffsetMPLS78, MaskMPLSlabelEven, 0}, {0, 0, 0, 0}}, 1, IS_MPLS_LBL},

    {"mpls9", " MPLS lab 9", {{0, OffsetMPLS910, MaskMPLSlabelOdd, 0}, {0, 0, 0, 0}}, 1, IS_MPLS_LBL},

    {"mpls10", "MPLS lab 10", {{0, OffsetMPLS910, MaskMPLSlabelEven, 0}, {0, 0, 0, 0}}, 1, IS_MPLS_LBL},

    {"cl", "Client Latency", {{0, OffsetClientLatency, MaskLatency, 0}, {0, 0, 0, 0}}, 1, IS_LATENCY},

    {"sl", "Server Latency", {{0, OffsetServerLatency, MaskLatency, 0}, {0, 0, 0, 0}}, 1, IS_LATENCY},

    {"al", "  Appl Latency", {{0, OffsetAppLatency, MaskLatency, 0}, {0, 0, 0, 0}}, 1, IS_LATENCY},

    {"nbar", "nbar", {{0, OffsetNbarAppID, MaskNbarAppID, 0}, {0, 0, 0, 0}}, 1, IS_NBAR},

    {"ja3", "                             ja3", {{OffsetJA3, OffsetJA3 + 1, MaskJA3, 0}, {0, 0, 0, 0}}, 1, IS_JA3},

    {"odid", "obs domainID", {{0, OffsetObservationDomainID, MaskObservationDomainID, 0}, {0, 0, 0, 0}}, 1, IS_HEXNUMBER},

    {"opid", " obs PointID", {{0, OffsetObservationPointID, MaskObservationPointID, 0}, {0, 0, 0, 0}}, 1, IS_HEXNUMBER},

#ifdef NSEL
    {"event", " Event", {{0, OffsetConnID, MaskFWevent, ShiftFWevent}, {0, 0, 0, 0}}, 1, IS_EVENT},

    {"nevent", " Event", {{0, OffsetConnID, MaskFWevent, ShiftFWevent}, {0, 0, 0, 0}}, 1, IS_EVENT},

    {"xevent", "X-Event", {{0, OffsetConnID, MaskFWXevent, ShiftFWXevent}, {0, 0, 0, 0}}, 1, IS_NUMBER},

    {"xsrcip", "X-Src IP Addr", {{OffsetXLATESRCv6a, OffsetXLATESRCv6b, MaskIPv6, 0}, {0, 0, 0, 0}}, 1, IS_IPADDR},

    {"xdstip", "X-Dst IP Addr", {{OffsetXLATEDSTv6a, OffsetXLATEDSTv6b, MaskIPv6, 0}, {0, 0, 0, 0}}, 1, IS_IPADDR},

    {"xsrcport", " X-Src Port", {{0, OffsetXLATEPort, MaskXLATESRCPORT, ShiftXLATESRCPORT}, {0, 0, 0, 0}}, 1, IS_NUMBER},

    {"xdstport", " X-Dst Port", {{0, OffsetXLATEPort, MaskXLATEDSTPORT, ShiftXLATEDSTPORT}, {0, 0, 0, 0}}, 1, IS_NUMBER},

    {"iacl", "Ingress ACL", {{0, OffsetIngressAclId, MaskIngressAclId, ShiftIngressAclId}, {0, 0, 0, 0}}, 1, IS_HEX},

    {"iace", "Ingress ACE", {{0, OffsetIngressAceId, MaskIngressAceId, ShiftIngressAceId}, {0, 0, 0, 0}}, 1, IS_HEX},

    {"ixace", "Ingress xACE", {{0, OffsetIngressGrpId, MaskIngressGrpId, ShiftIngressGrpId}, {0, 0, 0, 0}}, 1, IS_HEX},

    {"eacl", "Egress ACL", {{0, OffsetEgressAclId, MaskEgressAclId, ShiftEgressAclId}, {0, 0, 0, 0}}, 1, IS_HEX},

    {"eace", "Egress ACE", {{0, OffsetEgressAceId, MaskEgressAceId, ShiftEgressAceId}, {0, 0, 0, 0}}, 1, IS_HEX},

    {"exace", "Egress xACE", {{0, OffsetEgressGrpId, MaskEgressGrpId, ShiftEgressGrpId}, {0, 0, 0, 0}}, 1, IS_HEX},

    {"ivrf", " I-vrf-ID", {{0, OffsetIVRFID, MaskIVRFID, ShiftIVRFID}, {0, 0, 0, 0}}, 1, IS_NUMBER},

    {"evrf", " E-vrf-ID", {{0, OffsetEVRFID, MaskEVRFID, ShiftEVRFID}, {0, 0, 0, 0}}, 1, IS_NUMBER},

    // keep the following stats strings for compate v1.6.10 -> merged NSEL
    {"nsrcip", "X-Src IP Addr", {{OffsetXLATESRCv6a, OffsetXLATESRCv6b, MaskIPv6, 0}, {0, 0, 0, 0}}, 1, IS_IPADDR},

    {"ndstip", "X-Dst IP Addr", {{OffsetXLATEDSTv6a, OffsetXLATEDSTv6b, MaskIPv6, 0}, {0, 0, 0, 0}}, 1, IS_IPADDR},

    {"nsrcport", " X-Src Port", {{0, OffsetXLATEPort, MaskXLATESRCPORT, ShiftXLATESRCPORT}, {0, 0, 0, 0}}, 1, IS_NUMBER},

    {"ndstport", " X-Dst Port", {{0, OffsetXLATEPort, MaskXLATEDSTPORT, ShiftXLATEDSTPORT}, {0, 0, 0, 0}}, 1, IS_NUMBER},

#endif

    {NULL, NULL, {{0, 0, 0, 0}, {0, 0, 0, 0}}, 1, 0}};

// key for element stat
typedef struct hashkey_s {
    khint64_t v0;
    khint64_t v1;
    uint8_t proto;
} hashkey_t;

// khash record for element stat
typedef struct StatRecord {
    uint64_t counter[5];  // flows ipkg ibyte opkg obyte
    uint64_t msecFirst;
    uint64_t msecLast;

    // add key for output processing
    hashkey_t hashkey;
} StatRecord_t;

/*
 * pps, bps and bpp are not directly available in the flow/stat record
 * therefore we need a function to calculate these values
 */
typedef uint64_t (*order_proc_element_t)(StatRecord_t *, int);

static inline uint64_t null_element(StatRecord_t *record, int inout);
static inline uint64_t flows_element(StatRecord_t *record, int inout);
static inline uint64_t packets_element(StatRecord_t *record, int inout);
static inline uint64_t bytes_element(StatRecord_t *record, int inout);
static inline uint64_t pps_element(StatRecord_t *record, int inout);
static inline uint64_t bps_element(StatRecord_t *record, int inout);
static inline uint64_t bpp_element(StatRecord_t *record, int inout);

enum CntIndices { FLOWS = 0, INPACKETS, INBYTES, OUTPACKETS, OUTBYTES };
enum FlowDir { IN = 0, OUT, INOUT };

static struct order_mode_s {
    char *string;                           // Stat name
    int inout;                              // use IN or OUT or INOUT packets/bytes
    order_proc_element_t element_function;  // Function to call for element stats
} order_mode[] = {{"-", 0, null_element},   // empty entry 0
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
struct StatRequest_s {
    uint32_t order_bits;  // bit field for multiple print orders
    int16_t StatType;     // index into StatParameters
    uint8_t order_proto;  // protocol separated statistics
    uint8_t direction;    // sort ascending/descending
} StatRequest[MaxStats];  // This number should do it for a single run

static uint32_t NumStats = 0;  // number of stats in StatRequest

// definitions for khash element stat
#define kh_key_hash_func(key) (khint32_t)((key.v1) >> 33 ^ (key.v1) ^ (key.v1) << 11)
#define kh_key_hash_equal(a, b) (((a).v1 == (b).v1) && ((a).v0 == (b).v0) && (a).proto == (b).proto)
KHASH_INIT(ElementHash, hashkey_t, StatRecord_t, 1, kh_key_hash_func, kh_key_hash_equal)

static khash_t(ElementHash) * ElementKHash[MaxStats];

static uint32_t LoadedGeoDB = 0;
static uint64_t byte_limit, packet_limit;
static int byte_mode, packet_mode;
enum { NONE = 0, LESS, MORE };

/* function prototypes */
static int ParseStatString(char *str, int16_t *StatType, int *flow_stat, uint16_t *order_proto, uint32_t *order_bits, uint32_t *direction);

static int ParseListOrder(char *s, uint32_t *order_bits, uint32_t *direction);

static void PrintStatLine(stat_record_t *stat, outputParams_t *outputParams, StatRecord_t *StatData, int type, int order_proto, int inout);

static void PrintPipeStatLine(StatRecord_t *StatData, int type, int order_proto, int tag, int inout);

static void PrintCvsStatLine(stat_record_t *stat, int printPlain, StatRecord_t *StatData, int type, int order_proto, int tag, int inout);

static SortElement_t *StatTopN(int topN, uint32_t *count, int hash_num, int order, int direction);

#include "applybits_inline.c"
#include "heapsort_inline.c"
#include "memhandle.c"

static uint64_t null_element(StatRecord_t *record, int inout) { return 0; }

static uint64_t flows_element(StatRecord_t *record, int inout) { return record->counter[FLOWS]; }

static uint64_t packets_element(StatRecord_t *record, int inout) {
    if (inout == IN)
        return record->counter[INPACKETS];
    else if (inout == OUT)
        return record->counter[OUTPACKETS];
    else
        return record->counter[INPACKETS] + record->counter[OUTPACKETS];
}

static uint64_t bytes_element(StatRecord_t *record, int inout) {
    if (inout == IN)
        return record->counter[INBYTES];
    else if (inout == OUT)
        return record->counter[OUTBYTES];
    else
        return record->counter[INBYTES] + record->counter[OUTBYTES];
}

static uint64_t pps_element(StatRecord_t *record, int inout) {
    uint64_t duration;
    uint64_t packets;

    /* duration in msec */
    duration = record->msecLast - record->msecFirst;
    if (duration == 0)
        return 0;
    else {
        packets = packets_element(record, inout);
        return (1000LL * packets) / duration;
    }

}  // End of pps_element

static uint64_t bps_element(StatRecord_t *record, int inout) {
    uint64_t duration;
    uint64_t bytes;

    duration = record->msecLast - record->msecFirst;
    if (duration == 0)
        return 0;
    else {
        bytes = bytes_element(record, inout);
        return (8000LL * bytes) / duration; /* 8 bits per Octet - x 1000 for msec */
    }

}  // End of bps_element

static uint64_t bpp_element(StatRecord_t *record, int inout) {
    uint64_t packets = packets_element(record, inout);
    uint64_t bytes = bytes_element(record, inout);

    return packets ? bytes / packets : 0;

}  // End of bpp_element

void SetLimits(int stat, char *packet_limit_string, char *byte_limit_string) {
    char *s, c;
    uint32_t len, scale;

    if ((stat == 0) && (packet_limit_string || byte_limit_string)) {
        fprintf(stderr, "Options -l and -L do not make sense for plain packet dumps.\n");
        fprintf(stderr, "Use -l and -L together with -s -S or -a.\n");
        fprintf(stderr, "Use netflow filter syntax to limit the number of packets and bytes in netflow records.\n");
        exit(250);
    }
    packet_limit = byte_limit = 0;
    if (packet_limit_string) {
        switch (packet_limit_string[0]) {
            case '-':
                packet_mode = LESS;
                s = &packet_limit_string[1];
                break;
            case '+':
                packet_mode = MORE;
                s = &packet_limit_string[1];
                break;
            default:
                if (!isdigit((int)packet_limit_string[0])) {
                    fprintf(stderr, "Can't understand '%s'\n", packet_limit_string);
                    exit(250);
                }
                packet_mode = MORE;
                s = packet_limit_string;
        }
        len = strlen(packet_limit_string);
        c = packet_limit_string[len - 1];
        switch (c) {
            case 'B':
            case 'b':
                scale = 1;
                break;
            case 'K':
            case 'k':
                scale = 1000;
                break;
            case 'M':
            case 'm':
                scale = 1000 * 1000;
                break;
            case 'G':
            case 'g':
                scale = 1000 * 1000 * 1000;
                break;
            default:
                scale = 1;
                if (isalpha((int)c)) {
                    fprintf(stderr, "Can't understand '%c' in '%s'\n", c, packet_limit_string);
                    exit(250);
                }
        }
        packet_limit = (uint64_t)atol(s) * (uint64_t)scale;
    }

    if (byte_limit_string) {
        switch (byte_limit_string[0]) {
            case '-':
                byte_mode = LESS;
                s = &byte_limit_string[1];
                break;
            case '+':
                byte_mode = MORE;
                s = &byte_limit_string[1];
                break;
            default:
                if (!isdigit((int)byte_limit_string[0])) {
                    fprintf(stderr, "Can't understand '%s'\n", byte_limit_string);
                    exit(250);
                }
                byte_mode = MORE;
                s = byte_limit_string;
        }
        len = strlen(byte_limit_string);
        c = byte_limit_string[len - 1];
        switch (c) {
            case 'B':
            case 'b':
                scale = 1;
                break;
            case 'K':
            case 'k':
                scale = 1000;
                break;
            case 'M':
            case 'm':
                scale = 1000 * 1000;
                break;
            case 'G':
            case 'g':
                scale = 1000 * 1000 * 1000;
                break;
            default:
                if (isalpha((int)c)) {
                    fprintf(stderr, "Can't understand '%c' in '%s'\n", c, byte_limit_string);
                    exit(250);
                }
                scale = 1;
        }
        byte_limit = (uint64_t)atol(s) * (uint64_t)scale;
    }

    if (byte_limit) printf("Byte limit: %c %llu bytes\n", byte_mode == LESS ? '<' : '>', (long long unsigned)byte_limit);

    if (packet_limit) printf("Packet limit: %c %llu packets\n", packet_mode == LESS ? '<' : '>', (long long unsigned)packet_limit);

}  // End of SetLimits

int Init_StatTable(void) {
    if (!nfalloc_Init(8 * 1024 * 1024)) return 0;

    for (int i = 0; i < NumStats; i++) {
        ElementKHash[i] = kh_init(ElementHash);
    }

    LoadedGeoDB = Loaded_MaxMind();

    return 1;

}  // End of Init_StatTable

void Dispose_StatTable(void) { nfalloc_free(); }  // End of Dispose_Tables

int SetStat(char *str, int *element_stat, int *flow_stat) {
    if (NumStats == MaxStats) {
        fprintf(stderr, "Too many stat options! Stats are limited to %i stats per single run!\n", MaxStats);
        return 0;
    }

    int is_flow_stat = 0;
    uint32_t direction = DESCENDING;
    int16_t StatType = 0;
    uint16_t order_proto = 0;
    uint32_t order_bits = 0;
    if (ParseStatString(str, &StatType, &is_flow_stat, &order_proto, &order_bits, &direction)) {
        if (is_flow_stat) {
            *flow_stat = 1;
            Add_FlowStatOrder(order_bits, direction);
        } else {
            StatRequest[NumStats].StatType = StatType;
            StatRequest[NumStats].order_bits = order_bits;
            StatRequest[NumStats].order_proto = order_proto;
            StatRequest[NumStats].direction = direction;
            NumStats++;
            SetFlag(*element_stat, FLAG_STAT);
            if (StatParameters[StatType].type == IS_JA3) SetFlag(*element_stat, FLAG_JA3);
            if (StatParameters[StatType].type == IS_GEO) SetFlag(*element_stat, FLAG_GEO);
            char *statArg = StatParameters[StatType].statname;
            size_t len = strlen(statArg);
            if (statArg[len - 2] == 'a' && statArg[len - 1] == 's') SetFlag(*element_stat, FLAG_GEO);
        }
        return 1;
    } else {
        fprintf(stderr, "Unknown stat: '%s'!\n", str);
        return 0;
    }

}  // End of SetStat

static int ParseListOrder(char *s, uint32_t *order_bits, uint32_t *direction) {
    char *q;
    uint32_t bitset;

    bitset = 0;
    while (s) {
        int i;
        q = strchr(s, '/');
        if (q) *q = 0;

        char *r = strchr(s, ':');
        if (r) {
            *r++ = 0;
            switch (*r) {
                case 'a':
                    *direction = ASCENDING;
                    break;
                case 'd':
                    *direction = DESCENDING;
                    break;
                default:
                    return -1;
            }
        } else {
            *direction = DESCENDING;
        }

        i = 0;
        while (order_mode[i].string) {
            if (strcasecmp(order_mode[i].string, s) == 0) break;
            i++;
        }
        if (order_mode[i].string) {
            bitset |= (1 << i);
        } else {
            return 0;
        }

        if (!q) {
            *order_bits = bitset;
            return 1;
        }
        s = ++q;
    }

    // not reached
    return 1;

}  // End of ParseListOrder

static int ParseStatString(char *str, int16_t *StatType, int *flow_stat, uint16_t *order_proto, uint32_t *order_bits, uint32_t *direction) {
    char *s, *p, *q, *r;
    int i = 0;

    if (NumStats >= MaxStats) return 0;

    s = strdup(str);
    q = strchr(s, '/');
    if (q) *q = 0;

    *order_proto = 0;
    p = strchr(s, ':');
    if (p) {
        *p = 0;
        *order_proto = 1;
    }

    i = 0;
    // check for a valid stat name
    while (StatParameters[i].statname) {
        if (strncasecmp(s, StatParameters[i].statname, 16) == 0) {
            // set flag if it's the flow record stat request
            *flow_stat = strncasecmp(s, "record", 16) == 0;
            break;
        }
        i++;
    }

    // if so - initialize type and order_bits
    if (StatParameters[i].statname) {
        *StatType = i;
        if (strncasecmp(StatParameters[i].statname, "proto", 16) == 0) *order_proto = 1;
    } else {
        free(s);
        return 0;
    }

    // no order is given - default order applies;
    if (!q) {
        q = "/flows";  // default to flows
    }

    // check if one or more orders are given
    r = ++q;
    if (ParseListOrder(r, order_bits, direction) == 1) {
        free(s);
        return 1;
    } else {
        free(s);
        return 0;
    }

}  // End of ParseStatString

void AddElementStat(master_record_t *flow_record) {
    int j, i;

    // for every requested -s stat do
    for (j = 0; j < NumStats; j++) {
        int stat = StatRequest[j].StatType;
        int order_proto = StatRequest[j].order_proto;
        // for the number of elements in this stat type
        for (i = 0; i < StatParameters[stat].num_elem; i++) {
            uint32_t offset = StatParameters[stat].element[i].offset1;
            uint64_t mask = StatParameters[stat].element[i].mask;
            uint32_t shift = StatParameters[stat].element[i].shift;

            hashkey_t hashkey;
            hashkey.v1 = (((uint64_t *)flow_record)[offset] & mask) >> shift;
            offset = StatParameters[stat].element[i].offset0;
            hashkey.v0 = offset ? ((uint64_t *)flow_record)[offset] : 0;
            hashkey.proto = order_proto ? flow_record->proto : 0;

            int ret;
            khiter_t k = kh_put(ElementHash, ElementKHash[j], hashkey, &ret);
            if (ret == 0) {
                kh_value(ElementKHash[j], k).counter[INBYTES] += flow_record->inBytes;
                kh_value(ElementKHash[j], k).counter[INPACKETS] += flow_record->inPackets;
                kh_value(ElementKHash[j], k).counter[OUTBYTES] += flow_record->out_bytes;
                kh_value(ElementKHash[j], k).counter[OUTPACKETS] += flow_record->out_pkts;

                if (flow_record->msecFirst < kh_value(ElementKHash[j], k).msecFirst) {
                    kh_value(ElementKHash[j], k).msecFirst = flow_record->msecFirst;
                }
                if (flow_record->msecLast > kh_value(ElementKHash[j], k).msecLast) {
                    kh_value(ElementKHash[j], k).msecLast = flow_record->msecLast;
                }
                kh_value(ElementKHash[j], k).counter[FLOWS] += flow_record->aggr_flows ? flow_record->aggr_flows : 1;

            } else {
                kh_value(ElementKHash[j], k).counter[INBYTES] = flow_record->inBytes;
                kh_value(ElementKHash[j], k).counter[INPACKETS] = flow_record->inPackets;
                kh_value(ElementKHash[j], k).counter[OUTBYTES] = flow_record->out_bytes;
                kh_value(ElementKHash[j], k).counter[OUTPACKETS] = flow_record->out_pkts;
                kh_value(ElementKHash[j], k).msecFirst = flow_record->msecFirst;
                kh_value(ElementKHash[j], k).msecLast = flow_record->msecLast;
                kh_value(ElementKHash[j], k).counter[FLOWS] = flow_record->aggr_flows ? flow_record->aggr_flows : 1;
                kh_value(ElementKHash[j], k).hashkey = hashkey;
            }
        }  // for the number of elements in this stat type
    }      // for every requested -s stat
}  // AddElementStat

static void PrintStatLine(stat_record_t *stat, outputParams_t *outputParams, StatRecord_t *StatData, int type, int order_proto, int inout) {
    char valstr[64];
    char tag_string[2];

    tag_string[0] = '\0';
    tag_string[1] = '\0';
    switch (type) {
        case NONE:
            break;
        case IS_NUMBER:
            snprintf(valstr, 64, "%llu", (unsigned long long)StatData->hashkey.v1);
            break;
        case IS_HEXNUMBER:
            snprintf(valstr, 64, "0x%llx", (unsigned long long)StatData->hashkey.v1);
            break;
        case IS_IPADDR:
            tag_string[0] = outputParams->doTag ? TAG_CHAR : '\0';
            uint64_t ip[2];
            if (StatData->hashkey.v0 != 0) {  // IPv6
                uint64_t _key[2];
                _key[0] = htonll(StatData->hashkey.v0);
                _key[1] = htonll(StatData->hashkey.v1);
                if (LoadedGeoDB) {
                    char ipstr[40], country[4];
                    ip[0] = StatData->hashkey.v0;
                    ip[1] = StatData->hashkey.v1;
                    LookupCountry(ip, country);
                    inet_ntop(AF_INET6, _key, ipstr, sizeof(ipstr));
                    if (!Getv6Mode()) CondenseV6(ipstr);
                    snprintf(valstr, 64, "%s(%s)", ipstr, country);
                } else {
                    inet_ntop(AF_INET6, _key, valstr, sizeof(valstr));
                    if (!Getv6Mode()) CondenseV6(valstr);
                }

            } else {  // IPv4
                uint32_t ipv4 = htonl(StatData->hashkey.v1);
                if (LoadedGeoDB) {
                    char ipstr[16], country[4];
                    inet_ntop(AF_INET, &ipv4, ipstr, sizeof(ipstr));
                    ip[0] = 0;
                    ip[1] = StatData->hashkey.v1;
                    LookupCountry(ip, country);
                    snprintf(valstr, 40, "%s(%s)", ipstr, country);
                } else {
                    inet_ntop(AF_INET, &ipv4, valstr, sizeof(valstr));
                }
            }
            break;
        case IS_MACADDR: {
            int i;
            uint8_t mac[6];
            for (i = 0; i < 6; i++) {
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
#ifdef NSEL
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
#endif
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
            uint8_t *u8 = (uint8_t *)&(StatData->hashkey.v0);
            int i, j;
            for (i = 0, j = 0; i < 16; i++, j += 2) {
                uint8_t ln = u8[i] & 0xF;
                uint8_t hn = (u8[i] >> 4) & 0xF;
                valstr[j + 1] = ln <= 9 ? ln + '0' : ln + 'a' - 10;
                valstr[j] = hn <= 9 ? hn + '0' : hn + 'a' - 10;
            }
            valstr[32] = '\0';

        } break;
        case IS_GEO: {
            snprintf(valstr, 64, "%s", (char *)&(StatData->hashkey.v1));
        }
    }
    valstr[63] = 0;

    uint64_t count_flows = StatData->counter[FLOWS];
    uint64_t count_packets = packets_element(StatData, inout);
    uint64_t count_bytes = bytes_element(StatData, inout);
    char flows_str[NUMBER_STRING_SIZE], byte_str[NUMBER_STRING_SIZE], packets_str[NUMBER_STRING_SIZE];
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

    uint32_t bpp;
    uint64_t pps, bps;
    double duration = (StatData->msecLast - StatData->msecFirst) / 1000.0;
    if (duration != 0) {
        // duration in sec
        pps = (count_packets) / duration;
        bps = (8 * count_bytes) / duration;
    } else {
        pps = bps = 0;
    }

    if (count_packets) {
        bpp = count_bytes / count_packets;
    } else {
        bpp = 0;
    }

    char pps_str[NUMBER_STRING_SIZE], bps_str[NUMBER_STRING_SIZE];
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
        if (LoadedGeoDB) {
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

static void PrintPipeStatLine(StatRecord_t *StatData, int type, int order_proto, int tag, int inout) {
    uint64_t count_flows, count_packets, count_bytes, _key[2];
    uint32_t pps, bps, bpp;
    uint32_t sa[4];
    int af;

    sa[0] = sa[1] = sa[2] = sa[3] = 0;
    af = AF_UNSPEC;
    _key[0] = StatData->hashkey.v0;
    _key[1] = StatData->hashkey.v1;
    if (type == IS_IPADDR) {
        if (StatData->hashkey.v0 != 0) {  // IPv6
            _key[0] = htonll(StatData->hashkey.v0);
            _key[1] = htonll(StatData->hashkey.v1);
            af = PF_INET6;

        } else {  // IPv4
            af = PF_INET;
        }
        // Make sure Endian does not screw us up
        sa[0] = (_key[0] >> 32) & 0xffffffffLL;
        sa[1] = _key[0] & 0xffffffffLL;
        sa[2] = (_key[1] >> 32) & 0xffffffffLL;
        sa[3] = _key[1] & 0xffffffffLL;
    }
    double duration = (StatData->msecLast - StatData->msecFirst) / 1000.0;

    count_flows = flows_element(StatData, inout);
    count_packets = packets_element(StatData, inout);
    count_bytes = bytes_element(StatData, inout);
    if (duration != 0) {
        pps = (uint32_t)((double)count_packets / duration);
        bps = (uint32_t)((double)(8 * count_bytes) / duration);
    } else {
        pps = bps = 0;
    }

    if (count_packets)
        bpp = count_bytes / count_packets;
    else
        bpp = 0;

    if (!order_proto) {
        StatData->hashkey.proto = 0;
    }

    if (type == IS_IPADDR)
        printf("%i|%llu|%llu|%u|%u|%u|%u|%u|%llu|%llu|%llu|%u|%u|%u\n", af, (long long unsigned)StatData->msecFirst,
               (long long unsigned)StatData->msecLast, StatData->hashkey.proto, sa[0], sa[1], sa[2], sa[3], (long long unsigned)count_flows,
               (long long unsigned)count_packets, (long long unsigned)count_bytes, pps, bps, bpp);
    else
        printf("%i|%llu|%llu|%u|%llu|%llu|%llu|%llu|%u|%u|%u\n", af, (long long unsigned)StatData->msecFirst, (long long unsigned)StatData->msecLast,
               StatData->hashkey.proto, (long long unsigned)_key[1], (long long unsigned)count_flows, (long long unsigned)count_packets,
               (long long unsigned)count_bytes, pps, bps, bpp);

}  // End of PrintPipeStatLine

static void PrintCvsStatLine(stat_record_t *stat, int printPlain, StatRecord_t *StatData, int type, int order_proto, int tag, int inout) {
    char valstr[40], datestr1[64], datestr2[64];
    uint64_t count_flows, count_packets, count_bytes;
    double flows_percent, packets_percent, bytes_percent;
    uint32_t bpp;
    uint64_t pps, bps;
    time_t when;
    struct tm *tbuff;

    switch (type) {
        case NONE:
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

    count_flows = StatData->counter[FLOWS];
    count_packets = packets_element(StatData, inout);
    count_bytes = bytes_element(StatData, inout);

    flows_percent = stat->numflows ? (double)(count_flows * 100) / (double)stat->numflows : 0;
    packets_percent = stat->numpackets ? (double)(count_packets * 100) / (double)stat->numpackets : 0;
    bytes_percent = stat->numbytes ? (double)(count_bytes * 100) / (double)stat->numbytes : 0;

    double duration = (StatData->msecLast - StatData->msecFirst) / 1000.0;

    if (duration != 0) {
        pps = (uint64_t)((double)count_packets / duration);
        bps = (uint64_t)((double)(8 * count_bytes) / duration);
    } else {
        pps = bps = 0;
    }

    if (count_packets) {
        bpp = count_bytes / count_packets;
    } else {
        bpp = 0;
    }

    when = StatData->msecFirst / 1000;
    tbuff = localtime(&when);
    if (!tbuff) {
        perror("Error time convert");
        exit(250);
    }
    strftime(datestr1, 63, "%Y-%m-%d %H:%M:%S", tbuff);

    when = StatData->msecLast / 1000;
    tbuff = localtime(&when);
    if (!tbuff) {
        perror("Error time convert");
        exit(250);
    }
    strftime(datestr2, 63, "%Y-%m-%d %H:%M:%S", tbuff);

    printf("%s,%s,%.3f,%s,%s,%llu,%.1f,%llu,%.1f,%llu,%.1f,%llu,%llu,%u\n", datestr1, datestr2, duration,
           order_proto ? ProtoString(StatData->hashkey.proto, printPlain) : "any", valstr, (long long unsigned)count_flows, flows_percent,
           (long long unsigned)count_packets, packets_percent, (long long unsigned)count_bytes, bytes_percent, (long long unsigned)pps,
           (long long unsigned)bps, bpp);

}  // End of PrintCvsStatLine

void PrintElementStat(stat_record_t *sum_stat, outputParams_t *outputParams, RecordPrinter_t print_record) {
    uint32_t numflows;

    numflows = 0;
    // for every requested -s stat do
    for (int hash_num = 0; hash_num < NumStats; hash_num++) {
        int stat = StatRequest[hash_num].StatType;
        int order = StatRequest[hash_num].order_bits;
        int direction = StatRequest[hash_num].direction;
        int type = StatParameters[stat].type;
        for (int order_index = 0; order_mode[order_index].string != NULL; order_index++) {
            unsigned int order_bit = (1 << order_index);
            if (order & order_bit) {
                SortElement_t *topN_element_list = StatTopN(outputParams->topN, &numflows, hash_num, order_index, direction);

                // this output formatting is pretty ugly - and needs to be cleaned up - improved
                if (outputParams->mode == MODE_PLAIN && !outputParams->quiet) {
                    if (outputParams->topN != 0) {
                        printf("Top %i %s ordered by %s:\n", outputParams->topN, StatParameters[stat].HeaderInfo, order_mode[order_index].string);
                    } else {
                        printf("Top %s ordered by %s:\n", StatParameters[stat].HeaderInfo, order_mode[order_index].string);
                    }
                    if (Getv6Mode() && (type == IS_IPADDR)) {
                        printf(
                            "Date first seen                 Duration Proto %39s    Flows(%%)     Packets(%%)       Bytes(%%)         pps      bps   "
                            "bpp\n",
                            StatParameters[stat].HeaderInfo);
                    } else {
                        if (LoadedGeoDB) {
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
                    if (order_mode[order_index].inout == IN)
                        printf("ts,te,td,pr,val,fl,flP,ipkt,ipktP,ibyt,ibytP,ipps,ibps,ibpp\n");
                    else if (order_mode[order_index].inout == OUT)
                        printf("ts,te,td,pr,val,fl,flP,opkt,opktP,obyt,obytP,opps,obps,obpp\n");
                    else
                        printf("ts,te,td,pr,val,fl,flP,pkt,pktP,byt,bytP,pps,bps,bpp\n");
                }

                int j = numflows - outputParams->topN;
                j = j < 0 ? 0 : j;
                if (outputParams->topN == 0) j = 0;
                for (int i = numflows - 1; i >= j; i--) {
                    switch (outputParams->mode) {
                        case MODE_PLAIN:
                            PrintStatLine(sum_stat, outputParams, (StatRecord_t *)topN_element_list[i].record, type,
                                          StatRequest[hash_num].order_proto, order_mode[order_index].inout);
                            break;
                        case MODE_PIPE:
                            PrintPipeStatLine((StatRecord_t *)topN_element_list[i].record, type, StatRequest[hash_num].order_proto,
                                              outputParams->doTag, order_mode[order_index].inout);
                            break;
                        case MODE_CSV:
                            PrintCvsStatLine(sum_stat, outputParams->printPlain, (StatRecord_t *)topN_element_list[i].record, type,
                                             StatRequest[hash_num].order_proto, outputParams->doTag, order_mode[order_index].inout);
                            break;
                        case MODE_JSON:
                            printf("Not yet implemented output format\n");
                            break;
                    }
                }
                free((void *)topN_element_list);
                printf("\n");
            }
        }  // for every requested order
    }      // for every requested -s stat do
}  // End of PrintElementStat

static SortElement_t *StatTopN(int topN, uint32_t *count, int hash_num, int order, int direction) {
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

            // we want to sort only those flows which pass the packet or byte limits
            if (byte_limit) {
                uint64_t value = bytes_element(r, order_mode[order].inout);
                if ((byte_mode == LESS && value >= byte_limit) || (byte_mode == MORE && value <= byte_limit)) {
                    continue;
                }
            }
            if (packet_limit) {
                uint64_t value = packets_element(r, order_mode[order].inout);
                if ((packet_mode == LESS && value >= packet_limit) || (packet_mode == MORE && value <= packet_limit)) {
                    continue;
                }
            }
            topN_list[c].count = order_mode[order].element_function(r, order_mode[order].inout);
            topN_list[c].record = (void *)r;
            c++;
        }
    }

    *count = c;
    dbg_printf("Sort %u flows\n", c);

#ifdef DEVEL
    for (int i = 0; i < maxindex; i++) printf("%i, %llu %llx\n", i, topN_list[i].count, (unsigned long long)topN_list[i].record);
#endif

    // Sorting makes only sense, when 2 or more flows are left
    if (c >= 2) {
        if (c < 100)
            heapSort(topN_list, c, topN, direction);
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
    for (int i = 0; order_mode[i].string != NULL; i++) {
        printf("%s ", order_mode[i].string);
    }
    printf("- See also nfdump(1)\n");
}  // End of ListPrintOrder

void ListStatTypes(void) {
    printf("Available element statistics:");
    for (int i = 0; StatParameters[i].statname != NULL; i++) {
        if ((i & 0xf) == 0) printf("\n");
        printf("%s ", StatParameters[i].statname);
    }
    printf("- See also nfdump(1)\n");
}  // End of ListStatTypes