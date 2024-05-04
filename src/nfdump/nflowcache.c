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

#include "nflowcache.h"

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include "blocksort.h"
#include "config.h"
#include "exporter.h"
#include "maxmind/maxmind.h"
#include "memhandle.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfxV3.h"
#include "output.h"
#include "util.h"

typedef enum { NOPREPROCESS = 0, SRC_GEO, DST_GEO, SRC_AS, DST_AS } preprocess_t;

typedef struct aggregate_param_s {
    uint32_t extID;   // extension ID
    uint32_t offset;  // offset in extension
    uint32_t length;  // size of element in bytes
    uint32_t af;      // af family, or 0 if not applicable
} aggregate_param_t;

#define MaxMaskArraySize 16
static struct maskArray_s {
    uint32_t v4Mask;
    uint64_t v6Mask[2];
} maskArray[MaxMaskArraySize] = {0};
// slot 0 empty
static uint32_t maskIndex = 1;

// For automatic output format generation in case of custom aggregation
#define AggrPrependFmt "%ts %td "
#define AggrAppendFmt "%pkt %byt %bps %bpp %fl"

static struct aggregationElement_s {
    char *aggrElement;        // name of aggregation parameter
    aggregate_param_t param;  // the parameter array
    uint8_t active;           // this entry will be applied
    preprocess_t preprocess;  // value may need some preprocessing
    uint8_t netmaskID;        // index into mask array for mask to apply
                              // 0xFF : use srcMask, dstMask from flow record
    uint8_t allowMask;        // element may have a netmask -> /prefix
    char *fmt;                // for automatic output format generation
} aggregationTable[] = {{"proto", {EXgenericFlowID, OFFproto, SIZEproto, 0}, 0, NOPREPROCESS, 0, 0, "%pr"},
                        {"srcport", {EXgenericFlowID, OFFsrcPort, SIZEsrcPort, 0}, 0, NOPREPROCESS, 0, 0, "%sp"},
                        {"dstport", {EXgenericFlowID, OFFdstPort, SIZEdstPort, 0}, 0, NOPREPROCESS, 0, 0, "%dp"},
                        {"tos", {EXgenericFlowID, OFFsrcTos, SIZEsrcTos, 0}, 0, NOPREPROCESS, 0, 0, "%tos"},
                        {"srctos", {EXgenericFlowID, OFFsrcTos, SIZEsrcTos, 0}, 0, NOPREPROCESS, 0, 0, "%stos"},
                        {"srcip4", {EXipv4FlowID, OFFsrc4Addr, SIZEsrc4Addr, AF_INET}, 0, NOPREPROCESS, 0, 1, "%sa"},
                        {"dstip4", {EXipv4FlowID, OFFdst4Addr, SIZEdst4Addr, AF_INET}, 0, NOPREPROCESS, 0, 2, "%da"},
                        {"srcip6", {EXipv6FlowID, OFFsrc6Addr, SIZEsrc4Addr, AF_INET6}, 0, NOPREPROCESS, 0, 1, "%sa"},
                        {"dstip6", {EXipv6FlowID, OFFdst6Addr, SIZEdst6Addr, AF_INET6}, 0, NOPREPROCESS, 0, 2, "%da"},
                        {"srcip", {EXipv4FlowID, OFFsrc4Addr, SIZEsrc4Addr, AF_INET}, 0, NOPREPROCESS, 0, 1, "%sa"},
                        {"srcip", {EXipv6FlowID, OFFsrc6Addr, SIZEsrc6Addr, AF_INET6}, 0, NOPREPROCESS, 0, 1, NULL},
                        {"dstip", {EXipv4FlowID, OFFdst4Addr, SIZEdst4Addr, AF_INET}, 0, NOPREPROCESS, 0, 2, "%da"},
                        {"dstip", {EXipv6FlowID, OFFdst6Addr, SIZEdst6Addr, AF_INET6}, 0, NOPREPROCESS, 0, 2, NULL},
                        {"srcnet", {EXipv4FlowID, OFFsrc4Addr, SIZEsrc4Addr, AF_INET}, 0, NOPREPROCESS, 0xFF, 0, "%sn"},
                        {"srcnet", {EXipv6FlowID, OFFsrc6Addr, SIZEsrc6Addr, AF_INET6}, 0, NOPREPROCESS, 0xFF, 0, NULL},
                        {"dstnet", {EXipv4FlowID, OFFdst4Addr, SIZEdst4Addr, AF_INET}, 0, NOPREPROCESS, 0xFF, 0, "%dn"},
                        {"dstnet", {EXipv6FlowID, OFFdst6Addr, SIZEdst6Addr, AF_INET6}, 0, NOPREPROCESS, 0xFF, 0, NULL},
                        {"xsrcip", {EXnselXlateIPv4ID, OFFxlateSrc4Addr, SIZExlateSrc4Addr, AF_INET}, 0, NOPREPROCESS, 0, 1, "%xsa"},
                        {"xsrcip", {EXnselXlateIPv6ID, OFFxlateSrc6Addr, SIZExlateSrc6Addr, AF_INET6}, 0, NOPREPROCESS, 0, 1, NULL},
                        {"xdstip", {EXnselXlateIPv4ID, OFFxlateDst4Addr, SIZExlateDst4Addr, AF_INET}, 0, NOPREPROCESS, 0, 2, "%xda"},
                        {"xdstip", {EXnselXlateIPv6ID, OFFxlateDst6Addr, SIZExlateDst6Addr, AF_INET6}, 0, NOPREPROCESS, 0, 2, NULL},
                        {"xsrcport", {EXnselXlatePortID, OFFxlateSrcPort, SIZExlateSrcPort, 0}, 0, NOPREPROCESS, 0, 0, "%xsp"},
                        {"xdstport", {EXnselXlatePortID, OFFxlateDstPort, SIZExlateDstPort, 0}, 0, NOPREPROCESS, 0, 0, "%xdp"},
                        {"next", {EXipNextHopV4ID, OFFNextHopV4IP, SIZENextHopV4IP, AF_INET}, 0, NOPREPROCESS, 0, 1, "%nh"},
                        {"next", {EXipNextHopV6ID, OFFNextHopV6IP, SIZENextHopV6IP, AF_INET6}, 0, NOPREPROCESS, 0, 1, NULL},
                        {"bgpnext", {EXbgpNextHopV4ID, OFFbgp4NextIP, SIZEbgp4NextIP, AF_INET}, 0, NOPREPROCESS, 0, 1, "%nhb"},
                        {"bgpnext", {EXbgpNextHopV6ID, OFFbgp6NextIP, SIZEbgp6NextIP, AF_INET6}, 0, NOPREPROCESS, 0, 1, NULL},
                        {"router", {EXipReceivedV4ID, OFFReceived4IP, SIZEReceived4IP, AF_INET}, 0, NOPREPROCESS, 0, 1, "%ra"},
                        {"router", {EXipReceivedV6ID, OFFReceived6IP, SIZEReceived6IP, AF_INET6}, 0, NOPREPROCESS, 0, 1, NULL},
                        {"insrcmac", {EXmacAddrID, OFFinSrcMac, SIZEinSrcMac, 0}, 0, NOPREPROCESS, 0, 0, "%ismc"},
                        {"outdstmac", {EXmacAddrID, OFFoutDstMac, SIZEoutDstMac, 0}, 0, NOPREPROCESS, 0, 0, "%odmc"},
                        {"indstmac", {EXmacAddrID, OFFinDstMac, SIZEinDstMac, 0}, 0, NOPREPROCESS, 0, 0, "%idmc"},
                        {"outsrcmac", {EXmacAddrID, OFFoutSrcMac, SIZEoutSrcMac, 0}, 0, NOPREPROCESS, 0, 0, "%osmc"},
                        {"srcas", {EXasRoutingID, OFFsrcAS, SIZEsrcAS, 0}, 0, SRC_AS, 0, 0, "%sas"},
                        {"dstas", {EXasRoutingID, OFFdstAS, SIZEdstAS, 0}, 0, DST_AS, 0, 0, "%das"},
                        {"nextas", {EXasAdjacentID, OFFnextAdjacentAS, SIZEnextAdjacentAS, 0}, 0, NOPREPROCESS, 0, 0, "%nas"},
                        {"prevas", {EXasAdjacentID, OFFprevAdjacentAS, SIZEprevAdjacentAS, 0}, 0, NOPREPROCESS, 0, 0, "%pas"},
                        {"inif", {EXflowMiscID, OFFinput, SIZEinput, 0}, 0, NOPREPROCESS, 0, 0, "%in"},
                        {"outif", {EXflowMiscID, OFFoutput, SIZEoutput, 0}, 0, NOPREPROCESS, 0, 0, "%out"},
                        {"srcmask", {EXflowMiscID, OFFsrcMask, SIZEsrcMask, 0}, 0, NOPREPROCESS, 0, 0, "%smk"},
                        {"dstmask", {EXflowMiscID, OFFdstMask, SIZEdstMask, 0}, 0, NOPREPROCESS, 0, 0, "%dmk"},
                        {"dsttos", {EXflowMiscID, OFFdstTos, SIZEdstTos, 0}, 0, NOPREPROCESS, 0, 0, "%dtos"},
                        {"mpls1", {EXmplsLabelID, OFFmplsLabel1, SIZEmplsLabel1, 0}, 0, NOPREPROCESS, 0, 0, "%mpls1"},
                        {"mpls2", {EXmplsLabelID, OFFmplsLabel2, SIZEmplsLabel2, 0}, 0, NOPREPROCESS, 0, 0, "%mpls2"},
                        {"mpls3", {EXmplsLabelID, OFFmplsLabel3, SIZEmplsLabel3, 0}, 0, NOPREPROCESS, 0, 0, "%mpls3"},
                        {"mpls4", {EXmplsLabelID, OFFmplsLabel4, SIZEmplsLabel4, 0}, 0, NOPREPROCESS, 0, 0, "%mpls4"},
                        {"mpls5", {EXmplsLabelID, OFFmplsLabel5, SIZEmplsLabel5, 0}, 0, NOPREPROCESS, 0, 0, "%mpls5"},
                        {"mpls6", {EXmplsLabelID, OFFmplsLabel6, SIZEmplsLabel6, 0}, 0, NOPREPROCESS, 0, 0, "%mpls6"},
                        {"mpls7", {EXmplsLabelID, OFFmplsLabel7, SIZEmplsLabel7, 0}, 0, NOPREPROCESS, 0, 0, "%mpls7"},
                        {"mpls8", {EXmplsLabelID, OFFmplsLabel8, SIZEmplsLabel8, 0}, 0, NOPREPROCESS, 0, 0, "%mpls8"},
                        {"mpls9", {EXmplsLabelID, OFFmplsLabel9, SIZEmplsLabel9, 0}, 0, NOPREPROCESS, 0, 0, "%mpls9"},
                        {"mpls10", {EXmplsLabelID, OFFmplsLabel10, SIZEmplsLabel10, 0}, 0, NOPREPROCESS, 0, 0, "%mpls10"},
                        {"srcvlan", {EXvLanID, OFFvlanID, SIZEvlanID, 0}, 0, NOPREPROCESS, 0, 0, "%svln"},
                        {"dstvlan", {EXvLanID, OFFpostVlanID, SIZEpostVlanID, 0}, 0, NOPREPROCESS, 0, 0, "%dvln"},
                        {"odid", {EXobservationID, OFFdomainID, SIZEdomainID, 0}, 0, NOPREPROCESS, 0, 0, "%odid"},
                        {"opid", {EXobservationID, OFFpointID, SIZEpointID, 0}, 0, NOPREPROCESS, 0, 0, "%opid"},
                        {"srcgeo", {EXlocal, OFFgeoSrcIP, SizeGEOloc, 0}, 0, SRC_GEO, 0, 0, "%sc"},
                        {"dstgeo", {EXlocal, OFFgeoDstIP, SizeGEOloc, 0}, 0, DST_GEO, 0, 0, "%dc"},
                        {"ethertype", {EXlayer2ID, OFFetherType, SIZEetherType, 0}, 0, NOPREPROCESS, 0, 0, "%eth"},
                        {NULL, {0, 0, 0}, 0, NOPREPROCESS, 0, 0, NULL}};

// FlowHash stat record, to aggregate flow counters in -A or -s stat/aggregate mode
// original flow record attached for later printing the record
// for -A -s hashkey points to the aggregation key in hash table
// for -O <sort> next points to next record in list
typedef struct FlowHashRecord {
    recordHeaderV3_t *flowrecord;  // orig flow record for printing
    struct FlowHashRecord *next;   // record chain for flow list, unused otherwise

    uint8_t inFlags;   // tcp in flags
    uint8_t outFlags;  // tcp out flags XXX unused currently
    uint8_t swap;      // swap flow direction, when printed
    uint8_t align;     // align 32bit

    // time info in msec
    uint64_t msecFirst;  // overall first seen timestamp
    uint64_t msecLast;   // overall last seen timestamp

    // overall aggregated counters
    uint64_t inPackets;
    uint64_t inBytes;
    uint64_t outPackets;
    uint64_t outBytes;
    uint64_t flows;

} FlowHashRecord_t;

// order functions prototype
// depending on the order mode -O, the appropriate function
// returns the value to be sorted - goes into SortElement record
typedef uint64_t (*order_proc_record_t)(FlowHashRecord_t *);

// prototypes for order functions
static inline uint64_t order_flows(FlowHashRecord_t *record);

static inline uint64_t order_packets_in(FlowHashRecord_t *record);
static inline uint64_t order_packets_out(FlowHashRecord_t *record);
static inline uint64_t order_packets_inout(FlowHashRecord_t *record);

static inline uint64_t order_bytes_in(FlowHashRecord_t *record);
static inline uint64_t order_bytes_out(FlowHashRecord_t *record);
static inline uint64_t order_bytes_inout(FlowHashRecord_t *record);

static inline uint64_t order_pps_in(FlowHashRecord_t *record);
static inline uint64_t order_pps_out(FlowHashRecord_t *record);
static inline uint64_t order_pps_inout(FlowHashRecord_t *record);

static inline uint64_t order_bps_in(FlowHashRecord_t *record);
static inline uint64_t order_bps_out(FlowHashRecord_t *record);
static inline uint64_t order_bps_inout(FlowHashRecord_t *record);

static inline uint64_t order_bpp_in(FlowHashRecord_t *record);
static inline uint64_t order_bpp_out(FlowHashRecord_t *record);
static inline uint64_t order_bpp_inout(FlowHashRecord_t *record);

static inline uint64_t order_tstart(FlowHashRecord_t *record);
static inline uint64_t order_tend(FlowHashRecord_t *record);
static inline uint64_t order_duration(FlowHashRecord_t *record);

// printing order definitions
typedef enum FlowDir { IN = 0, OUT, INOUT } flowDir_t;

#define ASCENDING 1
#define DESCENDING 0
static struct order_mode_s {
    char *string;                         // Stat name
    flowDir_t inout;                      // use IN or OUT or INOUT packets/bytes
    int direction;                        // ascending or descending
    order_proc_record_t record_function;  // Function to call, returns sorting value
} order_mode[] = {{"-", 0, 0, NULL},      // empty entry 0
                  {"flows", IN, DESCENDING, order_flows},
                  {"packets", INOUT, DESCENDING, order_packets_inout},
                  {"ipackets", IN, DESCENDING, order_packets_in},
                  {"opackets", OUT, DESCENDING, order_packets_out},
                  {"bytes", INOUT, DESCENDING, order_bytes_inout},
                  {"ibytes", IN, DESCENDING, order_bytes_in},
                  {"obytes", OUT, DESCENDING, order_bytes_out},
                  {"pps", INOUT, DESCENDING, order_pps_inout},
                  {"ipps", IN, DESCENDING, order_pps_in},
                  {"opps", OUT, DESCENDING, order_pps_out},
                  {"bps", INOUT, DESCENDING, order_bps_inout},
                  {"ibps", IN, DESCENDING, order_bps_in},
                  {"obps", OUT, DESCENDING, order_bps_out},
                  {"bpp", INOUT, DESCENDING, order_bpp_inout},
                  {"ibpp", IN, DESCENDING, order_bpp_in},
                  {"obpp", OUT, DESCENDING, order_bpp_out},
                  {"tstart", 0, ASCENDING, order_tstart},
                  {"tend", 0, ASCENDING, order_tend},
                  {"duration", 0, DESCENDING, order_duration},
                  {NULL, 0, 0, NULL}};  // terminating entry

#define MaxAggrStackSize 64
static int aggregateInfo[MaxAggrStackSize] = {0};

static uint32_t FlowStat_order = 0;  // bit field for multiple print orders
static uint32_t PrintOrder = 0;      // -O selected print order - index into order_mode
static uint32_t PrintDirection = 0;
static uint32_t GuessDirection = 0;
static uint32_t HasGeoDB = 0;

// predefined V6 hash key struct, used in -s record/..
typedef struct FlowKeyV6_s {
    uint16_t af;
    uint16_t srcPort;
    uint16_t dstPort;
    uint16_t proto;
    uint64_t srcAddr[2];
    uint64_t dstAddr[2];
} FlowKeyV6_t;

// predefined V4 hash key struct, used in -s record/..
typedef struct FlowKeyV4_s {
    uint16_t af;
    uint16_t srcPort;
    uint16_t dstPort;
    uint16_t proto;
    uint32_t srcAddr;
    uint32_t dstAddr;
} FlowKeyV4_t;

static inline void New_HashKey(void *keymem, recordHandle_t *recordHandle, int swap_flow);

/*
 * hash definition and implementation
 * hash inspired by https://hackmd.io/@heyfey/SJZ-3jbs5 "Designing a Fast, Efficient, Cache-friendly Hash Table"
 * implementation optimized for flow data, without SSE registers (ARM compatibility)
 */

// hash function to generate 32bit hash value from var length input hash key
static inline uint32_t SuperFastHash(const char *data, int len) {
    uint32_t hash = len;

    if (hash == 0 || data == NULL) return 0;

    int rem = len & 3;
    len >>= 2;

    // Main loop
    uint32_t tmp;
    for (; len > 0; len--) {
        hash += *((uint16_t *)data);
        tmp = (*((uint16_t *)(data + 2)) << 11) ^ hash;
        hash = (hash << 16) ^ tmp;
        data += 2 * sizeof(uint16_t);
        hash += hash >> 11;
    }

    // Handle end cases
    switch (rem) {
        case 3:
            hash += *((uint16_t *)data);
            hash ^= hash << 16;
            hash ^= data[sizeof(uint16_t)] << 18;
            hash += hash >> 11;
            break;
        case 2:
            hash += *((uint16_t *)data);
            hash ^= hash << 11;
            hash += hash >> 17;
            break;
        case 1:
            hash += *data;
            hash ^= hash << 10;
            hash += hash >> 1;
    }

    // Force "avalanching" of final 127 bits
    hash ^= hash << 3;
    hash += hash >> 5;
    hash ^= hash << 4;
    hash += hash >> 17;
    hash ^= hash << 25;
    hash += hash >> 6;

    return hash;
}  // End of SuperFastHash

// cell index calculation from 32bit hash, depending of hash bit size 'shift'
#define ___fib_hash(hash, shift) ((hash) * 2654435769U) >> (shift)

// flag macros
#define is_free(flag, i) (flag[i] == 0)
#define is_used(flag, i) (flag[i] != 0)

/*
 * 3way hash:
 * - flag array   - uint8_t flag 0x1hhh hhhh - lower 7 bits of 32 hash
 * - value array  - hashValue_t with dynamic hash key for -s or -A aggregation, with index points to record array
 * - record array - static stat record with flow record counters
 *
 * only keep hashValue (32bytes per entry) in hash table.
 * for normal IPv4 aggragation, a key size of 16bytes fit directly into the hashValue. Aggregations up to 16byte
 * hash values profit from fast CPU cache.
 * For aggregation values > 16 bytes, a valPtr points to the nmalloc() value
 */

// value type for hash
typedef struct hashValue_s {
    union {
        uint64_t val[2];  // 16 byte static hash value
        void *valPtr;     // value pointer if size > 16bytes
    };
    uint32_t allign;   // unused - 64bit alignment
    uint32_t hash;     // calculated 32bit hash
    uint32_t ptrSize;  // if > 0, valPtr points to value
    uint32_t index;    // index into record array for statistics values
} hashValue_t;

// compare two hash values
// if size == 0 - directly compare the 16byte local value as two uint64_t
// if size > 16 - compare calculated hash and memcmp the two valPtr
#define valCompare(v1, v2)                                                          \
    ((v1).ptrSize == 0 ? ((v1).val[0] == (v2).val[0] && (v1).val[1] == (v2).val[1]) \
                       : ((v1).hash == (v2).hash && (v1).ptrSize == (v2).ptrSize && memcmp((v1).valPtr, (v2).valPtr, (v1).ptrSize) == 0))

// hash definition
typedef struct flowHash_s {
    uint8_t *flags;             // 1 byte flag of hash:
                                // 0x0000 0000 - hash cell not in use
                                // 0x1... .... - hash cell in use
                                // 0x1hhh hhhh - lower 7 bits of hash
    hashValue_t *cells;         // hash cells
    FlowHashRecord_t *records;  // statistic records
    uint32_t count;             // number of used cells in hash
    uint32_t capacity;          // allocated cells
    uint32_t mask;              // mask for max index
    uint32_t load_factor;       // no more than load_factor until resize
    int shift;                  // 32 - shift = bit width of hash
} flowHash_t;

// FlowHash var
static flowHash_t *flowHash = NULL;

static flowHash_t *flowHash_init(uint32_t bitSize) {
    flowHash_t *flowHash = calloc(1, sizeof(flowHash_t));
    if (!flowHash) return NULL;

    flowHash->shift = bitSize;
    flowHash->capacity = 1 << (32 - bitSize);
    flowHash->mask = flowHash->capacity - 1;

    flowHash->count = 0;
    flowHash->load_factor = flowHash->capacity >> 1;
    flowHash->flags = calloc(flowHash->capacity, sizeof(uint8_t));
    flowHash->cells = calloc(flowHash->capacity, sizeof(hashValue_t));
    flowHash->records = calloc(flowHash->capacity, sizeof(FlowHashRecord_t));
    return flowHash->cells != NULL && flowHash->flags != NULL ? flowHash : NULL;

}  // End of flowHash_init

static void flowHash_free(void) {
    if (!flowHash) return;

    free(flowHash->flags);
    free(flowHash->cells);
    free(flowHash->records);
    free(flowHash);
    flowHash = NULL;

}  // End of flowHash_free

/*
 * resize hash:
 * resize flags and cell array and rearrange entries
 * records remain in same place, but memory gets resized
 */
static inline void flowHash_resize(flowHash_t *flowHash) {
    int oldCapacity = flowHash->load_factor = flowHash->capacity;
    flowHash->capacity = 1u << (32 - (--flowHash->shift));
    flowHash->mask = flowHash->capacity - 1;

    hashValue_t *oldCells = flowHash->cells;
    hashValue_t *newCells = calloc(flowHash->capacity, sizeof(hashValue_t));

    uint8_t *oldFlags = flowHash->flags;
    uint8_t *newFlags = calloc(flowHash->capacity, sizeof(uint8_t));

    FlowHashRecord_t *newRecords = realloc(flowHash->records, flowHash->capacity * sizeof(FlowHashRecord_t));
    assert(newFlags && newCells && newRecords);

    // rearrange cells and flags, according to hash and new bit width of hash table
    for (uint32_t i = 0; i < oldCapacity; i++) {
        if (is_used(oldFlags, i)) {
            uint32_t cell = ___fib_hash(oldCells[i].hash, flowHash->shift);
            while (is_used(newFlags, cell)) {
                cell = (cell + 1) & flowHash->mask;
            }
            newCells[cell] = oldCells[i];
            newFlags[cell] = oldFlags[i];
        }
    }
    flowHash->cells = newCells;
    flowHash->flags = newFlags;
    flowHash->records = newRecords;
    free(oldCells);
    free(oldFlags);

}  // End of flowHash_resize

/*
 * Adds new value to the hash table.
 * insert is set to
 *  0 - value exists already.
 *  1 - value was inserted.
 * returns the index into the stat record array of new or existing value
 */
static inline int flowHash_add(flowHash_t *flowHash, const hashValue_t value, int *insert) {
    if (flowHash->count == flowHash->load_factor) flowHash_resize(flowHash);

    uint32_t hash = value.hash;
    // cell address
    uint32_t cell = ___fib_hash(hash, flowHash->shift);

    uint8_t flag = 0x80 | (hash & 0x7F);
    // shortcut for likely unused cell - speed up
    if (is_free(flowHash->flags, cell)) {
        int index = flowHash->count++;
        flowHash->flags[cell] = flag;
        flowHash->cells[cell] = value;
        flowHash->cells[cell].index = index;
        *insert = 1;
        return index;
    }

    // loop until existing value or empty cell is found
    do {
        // find empty cell or cell with correct flags
        while (is_used(flowHash->flags, cell) && (flowHash->flags[cell] != flag))
            if (++cell == flowHash->capacity) cell = 0;

        if (is_free(flowHash->flags, cell)) {
            // free cell found
            int index = flowHash->count++;
            flowHash->flags[cell] = flag;
            flowHash->cells[cell] = value;
            flowHash->cells[cell].index = index;
            *insert = 1;
            return index;
        } else {
            // cell with matching flag
            if (valCompare(flowHash->cells[cell], value)) {
                // existing value found
                *insert = 0;
                return flowHash->cells[cell].index;
            }
        }
        // hash collision - cell used by another value
        if (++cell == flowHash->capacity) cell = 0;
    } while (1);

}  // End of flowHash_add

/*
 * Searches for an existing value in the hash table.
 * returns:
 *   index into the stat record array if found
 *   -1 if value does not exists
 */
static inline int flowHash_get(flowHash_t *flowHash, const hashValue_t value) {
    uint32_t hash = value.hash;
    // cell address
    uint32_t cell = ___fib_hash(hash, flowHash->shift);

    // shortcut to speed up if cell is empty
    if (is_free(flowHash->flags, cell)) return -1;

    uint8_t flag = 0x80 | (hash & 0x7F);
    // cell used, check for correct value
    do {
        // search for matching flag
        while (is_used(flowHash->flags, cell) && (flowHash->flags[cell] != flag))
            if (++cell == flowHash->capacity) cell = 0;

        if (is_free(flowHash->flags, cell)) return -1;
        if (valCompare(flowHash->cells[cell], value)) return flowHash->cells[cell].index;

        // collision - flag matches but compare does not - loop
        if (++cell == flowHash->capacity) cell = 0;
    } while (1);
}

// linear FlowList for -O sorting
static struct FlowList_s {
    FlowHashRecord_t *head;
    FlowHashRecord_t **tail;
    size_t NumRecords;
} FlowList = {0};

static void *keymemV4 = NULL;
static void *keymemV6 = NULL;
static size_t keymenV4Len = 0;
static size_t keymenV6Len = 0;

static uint32_t bidir_flows = 0;

#include "heapsort_inline.c"
#include "memhandle.c"
#include "nfdump_inline.c"
#include "nffile_inline.c"

#define NeedSwapGeneric(GuessDir, r)                                                                              \
    (GuessDir && ((r)->proto == IPPROTO_TCP || (r)->proto == IPPROTO_UDP) &&                                      \
     ((((r)->srcPort < 1024) && ((r)->dstPort >= 1024)) || (((r)->srcPort < 32768) && ((r)->dstPort >= 32768)) || \
      (((r)->srcPort < 49152) && ((r)->dstPort >= 49152))))

static inline int NeedSwap(void *genericFlowKey);

static SortElement_t *GetSortList(size_t *size);

static void ApplyAggregateMask(recordHandle_t *recordHandle, struct aggregationElement_s *aggregationElement);

static void ApplyNetMaskBits(recordHandle_t *recordHandle, struct aggregationElement_s *aggregationElement);

static void PrintSortList(SortElement_t *SortList, uint32_t maxindex, outputParams_t *outputParams, int GuessFlowDirection,
                          RecordPrinter_t print_record, int ascending);

static inline int NeedSwap(void *genericFlowKey) {
    if (likely(GuessDirection == 0)) return 0;

    uint16_t *af = (uint16_t *)genericFlowKey;
    if (likely(*af == AF_INET)) {
        FlowKeyV4_t *flowKey = (FlowKeyV4_t *)genericFlowKey;
        if ((flowKey->proto == IPPROTO_TCP || flowKey->proto == IPPROTO_UDP) &&
            (((flowKey->srcPort < 1024) && (flowKey->dstPort >= 1024)) || ((flowKey->srcPort < 32768) && (flowKey->dstPort >= 32768)) ||
             ((flowKey->srcPort < 49152) && (flowKey->dstPort >= 49152))))
            return 1;
        else
            return 0;
    } else if (*af == AF_INET6) {
        FlowKeyV6_t *flowKey = (FlowKeyV6_t *)genericFlowKey;
        if ((flowKey->proto == IPPROTO_TCP || flowKey->proto == IPPROTO_UDP) &&
            (((flowKey->srcPort < 1024) && (flowKey->dstPort >= 1024)) || ((flowKey->srcPort < 32768) && (flowKey->dstPort >= 32768)) ||
             ((flowKey->srcPort < 49152) && (flowKey->dstPort >= 49152))))
            return 1;
        else
            return 0;
    } else
        return 0;
}  // End of NeedSwap

static uint64_t order_flows(FlowHashRecord_t *record) { return record->flows; }

static uint64_t order_packets_in(FlowHashRecord_t *record) {
    return unlikely(record->swap) ? record->outPackets : record->inPackets;
}  // End of order_packets_in

static uint64_t order_packets_out(FlowHashRecord_t *record) {
    return unlikely(record->swap) ? record->inPackets : record->outPackets;
}  // End of order_packets_out

static uint64_t order_packets_inout(FlowHashRecord_t *record) {
    //
    return record->inPackets + record->outPackets;
}  // End of order_packets_inout

static uint64_t order_bytes_in(FlowHashRecord_t *record) {
    //
    return unlikely(record->swap) ? record->outBytes : record->inBytes;
}  // End of order_bytes_in

static uint64_t order_bytes_out(FlowHashRecord_t *record) {
    //
    return unlikely(record->swap) ? record->inBytes : record->outBytes;
}  // End of order_bytes_out

static uint64_t order_bytes_inout(FlowHashRecord_t *record) {
    //
    return record->inBytes + record->outBytes;
}  // End of order_bytes_inout

static uint64_t order_pps_in(FlowHashRecord_t *record) {
    /* duration in msec */
    if (unlikely(record->msecLast == 0)) return 0;

    uint64_t duration = record->msecLast - record->msecFirst;
    uint64_t packets = record->inPackets;
    return (1000LL * packets) / duration;

}  // End of order_pps_in

static uint64_t order_pps_out(FlowHashRecord_t *record) {
    /* duration in msec */
    if (unlikely(record->msecLast == 0)) return 0;

    uint64_t duration = record->msecLast - record->msecFirst;
    uint64_t packets = record->outPackets;
    return (1000LL * packets) / duration;

}  // End of order_pps_out

static uint64_t order_pps_inout(FlowHashRecord_t *record) {
    /* duration in msec */
    if (unlikely(record->msecLast == 0)) return 0;

    uint64_t duration = record->msecLast - record->msecFirst;
    uint64_t packets = record->inPackets + record->outPackets;
    return (1000LL * packets) / duration;

}  // End of order_pps_inout

static uint64_t order_bps_in(FlowHashRecord_t *record) {
    /* duration in msec */
    if (unlikely(record->msecLast == 0)) return 0;

    uint64_t duration = record->msecLast - record->msecFirst;
    uint64_t bytes = record->inBytes;
    return (8000LL * bytes) / duration; /* 8 bits per Octet - x 1000 for msec */

}  // End of order_bps_in

static uint64_t order_bps_out(FlowHashRecord_t *record) {
    /* duration in msec */
    if (unlikely(record->msecLast == 0)) return 0;

    uint64_t duration = record->msecLast - record->msecFirst;
    uint64_t bytes = record->outBytes;
    return (8000LL * bytes) / duration; /* 8 bits per Octet - x 1000 for msec */

}  // End of order_bps_out

static uint64_t order_bps_inout(FlowHashRecord_t *record) {
    /* duration in msec */
    if (unlikely(record->msecLast == 0)) return 0;

    uint64_t duration = record->msecLast - record->msecFirst;
    uint64_t bytes = record->inBytes + record->outBytes;
    return (8000LL * bytes) / duration; /* 8 bits per Octet - x 1000 for msec */

}  // End of order_bps_inout

static uint64_t order_bpp_in(FlowHashRecord_t *record) {
    uint64_t packets = record->inPackets;
    if (packets == 0) return 0;

    uint64_t bytes = record->inBytes;
    return bytes / packets;
}  // End of order_bpp_in

static uint64_t order_bpp_out(FlowHashRecord_t *record) {
    uint64_t packets = record->outPackets;
    if (packets == 0) return 0;

    uint64_t bytes = record->outBytes;
    return bytes / packets;
}  // End of order_bpp_out

static uint64_t order_bpp_inout(FlowHashRecord_t *record) {
    uint64_t packets = record->inPackets + record->outPackets;
    if (packets == 0) return 0;

    uint64_t bytes = record->outBytes + record->outBytes;
    return bytes / packets;
}  // End of order_bpp_inout

static uint64_t order_tstart(FlowHashRecord_t *record) {
    //
    return record->msecFirst;
}  // End of order_tstart

static uint64_t order_tend(FlowHashRecord_t *record) {
    //
    return record->msecLast;
}  // End of order_tend

static uint64_t order_duration(FlowHashRecord_t *record) {
    return record->msecLast ? (record->msecLast - record->msecFirst) : 0;
}  // End of order_duration

static inline void PreProcess(void *inPtr, preprocess_t process, recordHandle_t *recordHandle) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    switch (process) {
        case NOPREPROCESS:
            return;
            break;
        case SRC_GEO: {
            char *geo = (char *)inPtr;
            if (HasGeoDB == 0 || geo[0]) return;
            if (ipv4Flow)
                LookupV4Country(ipv4Flow->srcAddr, geo);
            else if (ipv6Flow)
                LookupV6Country(ipv6Flow->srcAddr, geo);
        } break;
        case DST_GEO: {
            char *geo = (char *)inPtr;
            if (HasGeoDB == 0 || geo[0]) return;
            if (ipv4Flow)
                LookupV4Country(ipv4Flow->dstAddr, geo);
            else if (ipv6Flow)
                LookupV6Country(ipv6Flow->dstAddr, geo);
        } break;
        case SRC_AS: {
            uint32_t *as = (uint32_t *)inPtr;
            if (HasGeoDB == 0 || *as) return;
            *as = ipv4Flow ? LookupV4AS(ipv4Flow->srcAddr) : (ipv6Flow ? LookupV6AS(ipv6Flow->srcAddr) : 0);
        } break;
        case DST_AS: {
            uint32_t *as = (uint32_t *)inPtr;
            if (HasGeoDB == 0 || *as) return;
            *as = ipv4Flow ? LookupV4AS(ipv4Flow->dstAddr) : (ipv6Flow ? LookupV6AS(ipv6Flow->dstAddr) : 0);
        } break;
    }
}  // End of PreProcess

/*
 * generate dynamic hash value for hast table, depending on -s or -A parameters
 */
static inline void New_HashKey(void *keymem, recordHandle_t *recordHandle, int swap_flow) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];

    dbg_printf("NewHash: %d\n", aggregateInfo[0]);
    if (aggregateInfo[0] >= 0) {
        // custom user aggregation
        for (int i = 0; aggregateInfo[i] >= 0; i++) {
            // apply src/dst mask bits if requested
            uint32_t tableIndex = aggregateInfo[i];
            if (aggregationTable[tableIndex].netmaskID == 0xFF) {
                ApplyNetMaskBits(recordHandle, &aggregationTable[tableIndex]);
            } else if (aggregationTable[tableIndex].netmaskID) {
                ApplyAggregateMask(recordHandle, &aggregationTable[tableIndex]);
            }
            aggregate_param_t *param = &aggregationTable[tableIndex].param;

            void *inPtr = recordHandle->extensionList[param->extID];
            if (inPtr == NULL) continue;
            inPtr += param->offset;

            preprocess_t preprocess = aggregationTable[tableIndex].preprocess;
            PreProcess(inPtr, preprocess, recordHandle);

            switch (param->length) {
                case 0:
                    break;
                case 1: {
                    *((uint8_t *)keymem) = *((uint8_t *)inPtr);
                    keymem += sizeof(uint8_t);
                } break;
                case 2: {
                    *((uint16_t *)keymem) = *((uint16_t *)inPtr);
                    dbg_printf("val16: %u\n", *((uint16_t *)inPtr));
                    keymem += sizeof(uint16_t);
                } break;
                case 4: {
                    *((uint32_t *)keymem) = *((uint32_t *)inPtr);
                    keymem += sizeof(uint32_t);
                } break;
                case 8: {
                    *((uint64_t *)keymem) = *((uint64_t *)inPtr);
                    keymem += sizeof(uint64_t);
                } break;
                case 16: {
                    ((uint64_t *)keymem)[0] = ((uint64_t *)inPtr)[0];
                    ((uint64_t *)keymem)[1] = ((uint64_t *)inPtr)[1];
                    keymem += sizeof(uint64_t);
                } break;
                default:
                    memcpy((void *)keymem, inPtr, param->length);
            }
        }

    } else if (swap_flow) {
        // default 5-tuple aggregation for bidirectional flows

        if (ipv4Flow) {
            FlowKeyV4_t *keyptr = (FlowKeyV4_t *)keymem;
            keyptr->srcAddr = ipv4Flow->dstAddr;
            keyptr->dstAddr = ipv4Flow->srcAddr;
            keyptr->srcPort = genericFlow->dstPort;
            keyptr->dstPort = genericFlow->srcPort;
            keyptr->proto = genericFlow->proto;
            keyptr->af = AF_INET;
            keymem += sizeof(FlowKeyV4_t);
        } else if (ipv6Flow) {
            FlowKeyV6_t *keyptr = (FlowKeyV6_t *)keymem;
            keyptr->srcAddr[0] = ipv6Flow->dstAddr[0];
            keyptr->srcAddr[1] = ipv6Flow->dstAddr[1];
            keyptr->dstAddr[0] = ipv6Flow->srcAddr[0];
            keyptr->dstAddr[1] = ipv6Flow->srcAddr[1];
            keyptr->srcPort = genericFlow->dstPort;
            keyptr->dstPort = genericFlow->srcPort;
            keyptr->proto = genericFlow->proto;
            keyptr->af = AF_INET6;
            keymem += sizeof(FlowKeyV6_t);
        }
    } else {
        // default 5-tuple aggregation
        if (ipv4Flow) {
            FlowKeyV4_t *keyptr = (FlowKeyV4_t *)keymem;
            keyptr->srcAddr = ipv4Flow->srcAddr;
            keyptr->dstAddr = ipv4Flow->dstAddr;
            keyptr->srcPort = genericFlow->srcPort;
            keyptr->dstPort = genericFlow->dstPort;
            keyptr->proto = genericFlow->proto;
            keyptr->af = AF_INET;
            keymem += sizeof(FlowKeyV4_t);
        } else if (ipv6Flow) {
            FlowKeyV6_t *keyptr = (FlowKeyV6_t *)keymem;
            keyptr->srcAddr[0] = ipv6Flow->srcAddr[0];
            keyptr->srcAddr[1] = ipv6Flow->srcAddr[1];
            keyptr->dstAddr[0] = ipv6Flow->dstAddr[0];
            keyptr->dstAddr[1] = ipv6Flow->dstAddr[1];
            keyptr->srcPort = genericFlow->srcPort;
            keyptr->dstPort = genericFlow->dstPort;
            keyptr->proto = genericFlow->proto;
            keyptr->af = AF_INET6;
            keymem += sizeof(FlowKeyV6_t);
        }
    }

}  // End of New_HashKey

static void ApplyAggregateMask(recordHandle_t *recordHandle, struct aggregationElement_s *aggregationElement) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    uint32_t maskIndex = aggregationElement->netmaskID;

    if (ipv4Flow) {
        if (aggregationElement->allowMask == 1) {
            ipv4Flow->srcAddr &= maskArray[maskIndex].v4Mask;
        } else if (aggregationElement->allowMask == 2) {
            ipv4Flow->dstAddr &= maskArray[maskIndex].v4Mask;
        }
    } else if (ipv6Flow) {
        if (aggregationElement->allowMask == 1) {
            ipv6Flow->srcAddr[0] &= maskArray[maskIndex].v6Mask[0];
            ipv6Flow->srcAddr[1] &= maskArray[maskIndex].v6Mask[1];
        } else if (aggregationElement->allowMask == 2) {
            ipv6Flow->dstAddr[0] &= maskArray[maskIndex].v6Mask[0];
            ipv6Flow->dstAddr[1] &= maskArray[maskIndex].v6Mask[1];
        }
    }

}  // End of ApplyAggregateMask

static void ApplyNetMaskBits(recordHandle_t *recordHandle, struct aggregationElement_s *aggregationElement) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)recordHandle->extensionList[EXflowMiscID];

    uint32_t srcMask = 0;
    uint32_t dstMask = 0;
    if (flowMisc) {
        srcMask = flowMisc->srcMask;
        dstMask = flowMisc->dstMask;
    }

    if (ipv4Flow && aggregationElement->param.extID == EXipv4FlowID) {
        if (aggregationElement->param.offset == OFFsrc4Addr) {
            uint32_t srcmask = 0xffffffff << (32 - srcMask);
            ipv4Flow->srcAddr &= srcmask;
        }
        if (aggregationElement->param.offset == OFFdst4Addr) {
            uint32_t dstmask = 0xffffffff << (32 - dstMask);
            ipv4Flow->dstAddr &= dstmask;
        }

    } else if (ipv6Flow && aggregationElement->param.extID == EXipv6FlowID) {
        if (aggregationElement->param.offset == OFFsrc6Addr) {
            uint32_t mask_bits = srcMask;
            if (mask_bits > 64) {
                uint64_t mask = 0xffffffffffffffffLL << (128 - mask_bits);
                ipv6Flow->srcAddr[1] &= mask;
            } else {
                uint64_t mask = 0xffffffffffffffffLL << (64 - mask_bits);
                ipv6Flow->srcAddr[0] &= mask;
                ipv6Flow->srcAddr[1] = 0;
            }
        }
        if (aggregationElement->param.offset == OFFdst6Addr) {
            uint32_t mask_bits = dstMask;
            if (mask_bits > 64) {
                uint64_t mask = 0xffffffffffffffffLL << (128 - mask_bits);
                ipv6Flow->dstAddr[1] &= mask;
            } else {
                uint64_t mask = 0xffffffffffffffffLL << (64 - mask_bits);
                ipv6Flow->dstAddr[0] &= mask;
                ipv6Flow->dstAddr[1] = 0;
            }
        }
    }

}  // End of ApplyNetMaskBits

void ListAggregationHelp(void) {
    printf("Available aggregation fields:");
    for (int i = 0; aggregationTable[i].aggrElement != NULL; i++) {
        if ((i & 0x7) == 0) printf("\n");
        printf("%-9s ", aggregationTable[i].aggrElement);
    }
    printf("\nSee also nfdump(1)\n");
}  // End of ListAggregationHelp

int Init_FlowCache(int hasGeoDB) {
    if (!nfalloc_Init(0)) return 0;

    flowHash = flowHash_init(InitFlowHashBits);
    FlowList = (struct FlowList_s){.head = NULL, .tail = &FlowList.head, .NumRecords = 0};
    keymenV4Len = sizeof(FlowKeyV4_t);
    keymenV6Len = sizeof(FlowKeyV6_t);

    HasGeoDB = hasGeoDB;
    aggregateInfo[0] = -1;
    return 1;

}  // End of Init_FlowCache

void Dispose_FlowTable(void) {
    flowHash_free();
    nfalloc_free();
}  // End of Dispose_FlowTable

// Parse flow cache print order -O
int Parse_PrintOrder(char *order) {
    dbg_printf("Enter %s\n", __func__);
    int direction = -1;
    char *r = strchr(order, ':');
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
    }

    PrintOrder = 0;
    while (order_mode[PrintOrder].string) {
        if (strcasecmp(order_mode[PrintOrder].string, order) == 0) break;
        PrintOrder++;
    }
    if (!order_mode[PrintOrder].string) {
        PrintOrder = 0;
        return -1;
    }

    PrintDirection = direction >= 0 ? direction : order_mode[PrintOrder].direction;

    return PrintOrder;

}  // End of Parse_PrintOrder

int SetRecordStat(char *statType, char *optOrder) {
    char *optProto = strchr(statType, ':');
    if (optProto) {
        *optProto++ = 0;
        if (optProto[0] == 'p' && optProto[1] == '\0') {
            // do nothing - compatibility only
        } else {
            LogError("Unknown statistic option :%s in %s", optProto, statType);
            return 0;
        }
    }

    // only record is supported
    if (strcasecmp(statType, "record") != 0) {
        LogError("Unknown statistic option :%s in %s", optProto, statType);
        return 0;
    }

    if (optOrder == NULL) optOrder = "flows";

    while (optOrder) {
        char *q = strchr(optOrder, '/');
        if (q) *q = 0;

        char *r = strchr(optOrder, ':');
        if (r) {
            *r++ = 0;
            switch (*r) {
                case 'a':
                    PrintDirection = ASCENDING;
                    break;
                case 'd':
                    PrintDirection = DESCENDING;
                    break;
                default:
                    return -1;
            }
        } else {
            PrintDirection = DESCENDING;
        }

        int i = 0;
        while (order_mode[i].string) {
            if (strcasecmp(order_mode[i].string, optOrder) == 0) break;
            i++;
        }
        if (order_mode[i].string == NULL) {
            LogError("Unknown order option /%s", optOrder);
            return 0;
        }
        FlowStat_order |= (1 << i);

        if (q == NULL) {
            return 1;
        }
        optOrder = ++q;
    }

    return 1;
}  // End of SetRecordStat

char *ParseAggregateMask(char *arg) {
    dbg_printf("Enter %s\n", __func__);
    if (bidir_flows) {
        LogError("Can not set custom aggregation in bidir mode");
        return NULL;
    }

    uint32_t elementCount = 0;
    aggregateInfo[0] = -1;

    keymenV4Len = 0;
    keymenV6Len = 0;
    memset((void *)&aggregateInfo, 0, sizeof(aggregateInfo));

    size_t fmt_len = 0;
    for (int i = 0; aggregationTable[i].aggrElement != NULL; i++) {
        if (HasGeoDB && aggregationTable[i].fmt) {
            if (strcmp(aggregationTable[i].fmt, "%sa") == 0) aggregationTable[i].fmt = "%gsa";
            if (strcmp(aggregationTable[i].fmt, "%da") == 0) aggregationTable[i].fmt = "%gda";
        }
        if (aggregationTable[i].fmt) fmt_len += (strlen(aggregationTable[i].fmt) + 1);
    }
    fmt_len++;  // max fmt string len incl. trailing '\0'

    // add format prepend and append length
    fmt_len += strlen(AggrPrependFmt) + strlen(AggrAppendFmt) + 6;  // +6 for 'fmt:', 2 spaces

    char *aggr_fmt = (char *)malloc(fmt_len);
    if (!aggr_fmt) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }
    aggr_fmt[0] = '\0';
    fmt_len -= snprintf(aggr_fmt, fmt_len, "fmt:%s ", AggrPrependFmt);

    uint32_t v4Mask = 0xffffffff;
    uint64_t v6Mask[2] = {0xffffffffffffffffLL, 0xffffffffffffffffLL};
    // separate tokens
    char *p = strtok(arg, ",");
    while (p) {
        uint32_t has_mask = 0;
        // check for subnet bits
        char *q = strchr(p, '/');
        if (q) {
            *q = 0;
            uint32_t subnet = atoi(q + 1);

            // get IP version
            char *n = &(p[strlen(p) - 1]);
            if (*n == '4') {
                // IPv4
                if (subnet < 1 || subnet > 32) {
                    LogError("Subnet mask length '%d' out of range for IPv4", subnet);
                    return NULL;
                }
                v4Mask = 0xffffffff << (32 - subnet);
                has_mask = 1;

            } else if (*n == '6') {
                // IPv6
                if (subnet < 1 || subnet > 128) {
                    LogError("Subnet mask length '%d' out of range for IPv4", subnet);
                    return NULL;
                }

                if (subnet > 64) {
                    v6Mask[0] = 0xffffffffffffffffLL;
                    v6Mask[1] = 0xffffffffffffffffLL << (64 - subnet);
                } else {
                    v6Mask[0] = 0xffffffffffffffffLL << (64 - subnet);
                    v6Mask[1] = 0;
                }
                has_mask = 1;
            } else {
                // rubbish
                *q = '/';
                LogError("Need src4/dst4 or src6/dst6 for IPv4 or IPv6 to aggregate with explicit netmask: '%s'", p);
                return NULL;
            }
        }

        int index = 0;
        while (aggregationTable[index].aggrElement && (strcasecmp(p, aggregationTable[index].aggrElement) != 0)) index++;

        if (aggregationTable[index].aggrElement == NULL) {
            LogError("Unknown aggregation field '%s'", p);
            return NULL;
        }

        if (aggregationTable[index].active) {
            LogError("Duplicate aggregation element: %s", p);
            return NULL;
        }

        if (has_mask) {
            if (aggregationTable[index].allowMask == 0) {
                LogError("Element %s does not take any netmask", p);
                return NULL;
            }
        }

        if (aggregationTable[index].fmt != NULL) {
            strncat(aggr_fmt, aggregationTable[index].fmt, fmt_len);
            fmt_len -= strlen(aggregationTable[index].fmt);
            strncat(aggr_fmt, " ", fmt_len);
            fmt_len -= 1;
        }

        do {
            // loop over alternate extensions v4/v6
            if (maskIndex >= MaxMaskArraySize) {
                LogError("Too many netmasks");
                return NULL;
            }
            if (has_mask) {
                maskArray[maskIndex].v4Mask = v4Mask;
                maskArray[maskIndex].v6Mask[0] = v6Mask[0];
                maskArray[maskIndex].v6Mask[1] = v6Mask[1];
                aggregationTable[index].netmaskID = maskIndex;
                maskIndex++;
            }
            aggregationTable[index].active = 1;
            aggregateInfo[elementCount++] = index;
            size_t len = aggregationTable[index].param.length;
            if (aggregationTable[index].param.af == AF_INET) {
                keymenV4Len += len;
            } else if (aggregationTable[index].param.af == AF_INET6) {
                keymenV6Len += len;
            } else {
                keymenV4Len += len;
                keymenV6Len += len;
            }
            index++;
        } while (aggregationTable[index].aggrElement && (strcasecmp(p, aggregationTable[index].aggrElement) == 0));

        p = strtok(NULL, ",");
    }

    if (elementCount == 0) {
        LogError("No aggregation specified!");
        return NULL;
    }
    aggregateInfo[elementCount] = -1;

#ifdef DEVEL
    printf("Aggregate key:  v4len: %zu, v6len: %zu bytes\n", keymenV4Len, keymenV6Len);
    printf("Aggregate format string: '%s'\n", aggr_fmt);

    printf("Aggregate stack:\n");
    for (int i = 0; aggregateInfo[i] >= 0; i++) {
        int32_t index = aggregateInfo[i];
        printf("Slot: %d, Element: %s, ExtID: %u, Offset: %u, Length: %u\n", index, aggregationTable[index].aggrElement,
               aggregationTable[index].param.extID, aggregationTable[index].param.offset, aggregationTable[index].param.length);
        if (aggregationTable[index].netmaskID) {
            printf("Has IP mask: %i\n", aggregationTable[index].netmaskID);
            if (aggregationTable[index].netmaskID && aggregationTable[index].netmaskID != 0xFF) {
                uint32_t maskIndex = aggregationTable[index].netmaskID;
                printf("v4mask  : 0x%x\n", maskArray[maskIndex].v4Mask);
                printf("v6mask  : 0x%llx 0x%llx\n", maskArray[maskIndex].v6Mask[0], maskArray[maskIndex].v6Mask[1]);
            }
        }
    }

#endif

    strncat(aggr_fmt, " ", fmt_len);
    fmt_len--;
    strncat(aggr_fmt, AggrAppendFmt, fmt_len);
    return aggr_fmt;
}  // End of ParseAggregateMask

void InsertFlow(recordHandle_t *recordHandle) {
    dbg_printf("Enter %s\n", __func__);
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    if (!genericFlow) return;

    recordHeaderV3_t *recordHeaderV3 = recordHandle->recordHeaderV3;

    FlowHashRecord_t *record = (FlowHashRecord_t *)nfmalloc(sizeof(FlowHashRecord_t));
    record->flowrecord = (recordHeaderV3_t *)nfmalloc(recordHeaderV3->size);
    memcpy((void *)record->flowrecord, (void *)recordHeaderV3, recordHeaderV3->size);

    record->msecFirst = genericFlow->msecFirst;
    record->msecLast = genericFlow->msecLast;

    EXcntFlow_t *cntFlow = (EXcntFlow_t *)recordHandle->extensionList[EXcntFlowID];

    record->inBytes = genericFlow->inBytes;
    record->inPackets = genericFlow->inPackets;
    if (cntFlow) {
        record->outBytes = cntFlow->outBytes;
        record->outPackets = cntFlow->outPackets;
        record->flows = cntFlow->flows;
    } else {
        record->outBytes = 0;
        record->outPackets = 0;
        record->flows = 1;
    }
    record->inFlags = genericFlow->tcpFlags;
    record->outFlags = 0;
    FlowList.NumRecords++;

    record->next = NULL;
    *FlowList.tail = record;
    FlowList.tail = &(record->next);

}  // End of InsertFlow

static void AddBidirFlow(recordHandle_t *recordHandle) {
    dbg_printf("Enter %s\n", __func__);
    recordHeaderV3_t *record = recordHandle->recordHeaderV3;
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];
    EXcntFlow_t *cntFlow = (EXcntFlow_t *)recordHandle->extensionList[EXcntFlowID];
    uint64_t inPackets = genericFlow->inPackets;
    uint64_t inBytes = genericFlow->inBytes;
    uint64_t outBytes = 0;
    uint64_t outPackets = 0;
    uint64_t aggrFlows = 1;
    if (cntFlow) {
        outPackets = cntFlow->outPackets;
        outBytes = cntFlow->outPackets;
        aggrFlows = cntFlow->flows;
    }

    size_t keyLen = 0;
    void **keymem = NULL;
    if (ipv4Flow) {
        keymem = &keymemV4;
        keyLen = keymenV4Len;
    } else if (ipv6Flow) {
        keymem = &keymemV6;
        keyLen = keymenV6Len;
    } else
        return;

    hashValue_t hashValue = {0};
    if (keyLen > 16) {
        if (*keymem == NULL) *keymem = nfmalloc(keyLen);
        hashValue.valPtr = *keymem;
        hashValue.ptrSize = keyLen;
    } else {
        *keymem = &hashValue.val;
    }

    // generate hash value from selected -s -A parameters
    New_HashKey(*keymem, recordHandle, 0);
    // generate 32bit hash from hash value
    hashValue.hash = SuperFastHash(*keymem, keyLen);

    int index = flowHash_get(flowHash, hashValue);
    if (index >= 0) {
        // flow record found - update all fields
        flowHash->records[index].inBytes += inBytes;
        flowHash->records[index].inPackets += inPackets;
        flowHash->records[index].outBytes += outBytes;
        flowHash->records[index].outPackets += outPackets;
        flowHash->records[index].inFlags |= genericFlow->tcpFlags;

        if (genericFlow->msecFirst < flowHash->records[index].msecFirst) {
            flowHash->records[index].msecFirst = genericFlow->msecFirst;
        }
        if (genericFlow->msecLast > flowHash->records[index].msecLast) {
            flowHash->records[index].msecLast = genericFlow->msecLast;
        }

        flowHash->records[index].flows += aggrFlows;
    } else if (genericFlow->proto != IPPROTO_TCP && genericFlow->proto != IPPROTO_UDP) {
        // no flow record found and no TCP/UDP bidir flows. Insert flow record into hash
        int insert;
        index = flowHash_add(flowHash, hashValue, &insert);
        flowHash->records[index].inBytes = inBytes;
        flowHash->records[index].inPackets = inPackets;
        flowHash->records[index].outBytes = outBytes;
        flowHash->records[index].outPackets = outPackets;
        flowHash->records[index].flows = aggrFlows;
        flowHash->records[index].inFlags = genericFlow->tcpFlags;
        flowHash->records[index].outFlags = 0;

        flowHash->records[index].msecFirst = genericFlow->msecFirst;
        flowHash->records[index].msecLast = genericFlow->msecLast;

        void *p = malloc(record->size);
        if (!p) {
            LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            exit(255);
        }
        memcpy((void *)p, record, record->size);
        flowHash->records[index].flowrecord = p;
        flowHash->records[index].swap = NeedSwap(*keymem);

        // keymen got part of the cache
        *keymem = NULL;
    } else {
        // for bidir flows do

        // generate reverse hash key to search for bidir flow
        New_HashKey(*keymem, recordHandle, 1);
        hashValue.hash = SuperFastHash(*keymem, keyLen);

        index = flowHash_get(flowHash, hashValue);
        if (index >= 0) {
            // we found a corresponding reverse flow - so update all fields in reverse direction
            flowHash->records[index].outBytes += inBytes;
            flowHash->records[index].outPackets += inPackets;
            flowHash->records[index].inBytes += outBytes;
            flowHash->records[index].inPackets += outPackets;
            flowHash->records[index].outFlags |= genericFlow->tcpFlags;

            if (genericFlow->msecFirst < flowHash->records[index].msecFirst) {
                flowHash->records[index].msecFirst = genericFlow->msecFirst;
            }
            if (genericFlow->msecLast > flowHash->records[index].msecLast) {
                flowHash->records[index].msecLast = genericFlow->msecLast;
            }

            flowHash->records[index].flows += aggrFlows;
        } else {
            // no bidir flow found
            // insert original flow into the cache
            New_HashKey(*keymem, recordHandle, 0);
            hashValue.hash = SuperFastHash(*keymem, keyLen);

            int insert;
            index = flowHash_add(flowHash, hashValue, &insert);
            flowHash->records[index].inBytes = inBytes;
            flowHash->records[index].inPackets = inPackets;
            flowHash->records[index].outBytes = outBytes;
            flowHash->records[index].outPackets = outPackets;
            flowHash->records[index].flows = aggrFlows;
            flowHash->records[index].inFlags = genericFlow->tcpFlags;
            flowHash->records[index].outFlags = 0;

            flowHash->records[index].msecFirst = genericFlow->msecFirst;
            flowHash->records[index].msecLast = genericFlow->msecLast;

            void *p = malloc(record->size);
            if (!p) {
                LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                exit(255);
            }
            memcpy((void *)p, record, record->size);
            flowHash->records[index].flowrecord = p;
            flowHash->records[index].swap = NeedSwap(*keymem);

            // keymen got part of the cache
            *keymem = NULL;
        }
    }

}  // End of AddBidirFlow

void AddFlowCache(recordHandle_t *recordHandle) {
    dbg_printf("Enter %s\n", __func__);
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    if (!genericFlow) return;

    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];
    EXcntFlow_t *cntFlow = (EXcntFlow_t *)recordHandle->extensionList[EXcntFlowID];
    uint64_t inPackets = genericFlow->inPackets;
    uint64_t inBytes = genericFlow->inBytes;
    uint64_t outBytes = 0;
    uint64_t outPackets = 0;
    uint64_t aggrFlows = 1;
    if (cntFlow) {
        outPackets = cntFlow->outPackets;
        outBytes = cntFlow->outPackets;
        aggrFlows = cntFlow->flows ? cntFlow->flows : 1;
    }

    recordHeaderV3_t *record = recordHandle->recordHeaderV3;

    if (bidir_flows) return AddBidirFlow(recordHandle);

    size_t keyLen = 0;
    void **keymem = NULL;
    if (ipv4Flow) {
        keymem = &keymemV4;
        keyLen = keymenV4Len;
    } else if (ipv6Flow) {
        keymem = &keymemV6;
        keyLen = keymenV6Len;
    } else {
        // if neither ipv4 nor ipv6 but keymemV4 defined
        // we aggregate elements outside a record with ip addresses
        // so use either
        if (keymenV4Len == 0) {
            LogError("Could not determine a valid aggregation");
            return;
        }
        keymem = &keymemV4;
        keyLen = keymenV4Len;
    }

    hashValue_t hashValue = {0};
    if (keyLen > 16) {
        if (*keymem == NULL) *keymem = nfmalloc(keyLen);
        hashValue.valPtr = *keymem;
        hashValue.ptrSize = keyLen;
    } else {
        *keymem = &hashValue.val;
    }

    New_HashKey(*keymem, recordHandle, 0);
    hashValue.hash = SuperFastHash(*keymem, keyLen);

    int insert;
    int index = flowHash_add(flowHash, hashValue, &insert);
    if (insert == 0) {
        // flow record found - update all fields
        flowHash->records[index].inBytes += inBytes;
        flowHash->records[index].inPackets += inPackets;
        flowHash->records[index].outBytes += outBytes;
        flowHash->records[index].outPackets += outPackets;
        flowHash->records[index].inFlags |= genericFlow->tcpFlags;

        if (genericFlow->msecFirst < flowHash->records[index].msecFirst) {
            flowHash->records[index].msecFirst = genericFlow->msecFirst;
        }
        if (genericFlow->msecLast > flowHash->records[index].msecLast) {
            flowHash->records[index].msecLast = genericFlow->msecLast;
        }

        flowHash->records[index].flows += aggrFlows;
    } else {
        // no flow record found and no TCP/UDP bidir flows. Insert flow record into hash
        flowHash->records[index].inBytes = inBytes;
        flowHash->records[index].inPackets = inPackets;
        flowHash->records[index].outBytes = outBytes;
        flowHash->records[index].outPackets = outPackets;
        flowHash->records[index].flows = aggrFlows;
        flowHash->records[index].inFlags = genericFlow->tcpFlags;
        flowHash->records[index].outFlags = 0;

        flowHash->records[index].msecFirst = genericFlow->msecFirst;
        flowHash->records[index].msecLast = genericFlow->msecLast;
        flowHash->records[index].swap = NeedSwap(*keymem);
        void *p = nfmalloc(record->size);
        memcpy((void *)p, record, record->size);
        flowHash->records[index].flowrecord = p;
        *keymem = NULL;
    }

}  // End of AddFlowCache

// return a linear list of aggregated/listed flows for later sorting
static SortElement_t *GetSortList(size_t *size) {
    dbg_printf("Enter %s\n", __func__);

    SortElement_t *list = NULL;
    *size = 0;

    uint32_t hashSize = flowHash->count;

    if (hashSize) {  // hash table
        list = (SortElement_t *)calloc(hashSize, sizeof(SortElement_t));
        if (!list) {
            LogError("calloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
            return NULL;
        }

        for (uint32_t i = 0; i < flowHash->count; i++) {
            list[i].record = (void *)&(flowHash->records[i]);
        }
        *size = hashSize;

    } else if (FlowList.NumRecords) {  // linear flow list
        size_t listSize = FlowList.NumRecords;
        if (!listSize) {
            return NULL;
        }
        list = (SortElement_t *)calloc(listSize, sizeof(SortElement_t));
        if (!list) {
            LogError("calloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
            return NULL;
        }

        FlowHashRecord_t *flowRecord = FlowList.head;
        for (int i = 0; i < listSize; i++) {
            list[i].record = (void *)flowRecord;
            flowRecord = flowRecord->next;
        }
        *size = listSize;
    }

    return list;

}  // End of GetSortList

// print SortList - apply possible aggregation mask to zero out aggregated fields
static inline void PrintSortList(SortElement_t *SortList, uint32_t maxindex, outputParams_t *outputParams, int GuessFlowDirection,
                                 RecordPrinter_t print_record, int ascending) {
    dbg_printf("Enter %s\n", __func__);
    int max = maxindex;
    if (outputParams->topN && outputParams->topN < maxindex) max = outputParams->topN;
    for (int i = 0; i < max; i++) {
        int j = ascending ? i : maxindex - 1 - i;

        FlowHashRecord_t *flowRecord = (FlowHashRecord_t *)SortList[j].record;
        recordHeaderV3_t *v3record = (flowRecord->flowrecord);

        recordHandle_t recordHandle = {0};
        MapRecordHandle(&recordHandle, v3record, i + 1);
        EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle.extensionList[EXgenericFlowID];
        EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle.extensionList[EXipv4FlowID];
        EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle.extensionList[EXipv6FlowID];
        EXasRouting_t *asRouting = (EXasRouting_t *)recordHandle.extensionList[EXasRoutingID];
        EXcntFlow_t *cntFlow = (EXcntFlow_t *)recordHandle.extensionList[EXcntFlowID];

        genericFlow->inPackets = flowRecord->inPackets;
        genericFlow->inBytes = flowRecord->inBytes;
        genericFlow->msecFirst = flowRecord->msecFirst;
        genericFlow->msecLast = flowRecord->msecLast;
        genericFlow->tcpFlags = flowRecord->inFlags;

        EXcntFlow_t tmpCntFlow = {0};
        if (cntFlow == NULL && (flowRecord->flows > 1 || flowRecord->outPackets)) {
            recordHandle.extensionList[EXcntFlowID] = &tmpCntFlow;
            cntFlow = &tmpCntFlow;
            cntFlow->outPackets = flowRecord->outPackets;
            cntFlow->outBytes = flowRecord->outBytes;
            cntFlow->flows = flowRecord->flows;
        }

        if (unlikely(NeedSwapGeneric(GuessFlowDirection, genericFlow))) {
            EXflowMisc_t *flowMisc = (EXflowMisc_t *)recordHandle.extensionList[EXflowMiscID];
            SwapRawFlow(genericFlow, ipv4Flow, ipv6Flow, flowMisc, cntFlow, asRouting);
        }

        print_record(stdout, &recordHandle, outputParams->doTag);
    }

}  // End of PrintSortList

// export SortList - apply possible aggregation mask to zero out aggregated fields
static inline void ExportSortList(SortElement_t *SortList, uint32_t maxindex, nffile_t *nffile, int GuessFlowDirection, int ascending) {
    dbg_printf("Enter %s\n", __func__);

    dataBlock_t *dataBlock = WriteBlock(nffile, NULL);
    dataBlock = ExportExporterList(nffile, dataBlock);

    for (int i = 0; i < maxindex; i++) {
        int j = ascending ? i : maxindex - 1 - i;

        FlowHashRecord_t *flowRecord = (FlowHashRecord_t *)SortList[j].record;
        recordHeaderV3_t *recordHeaderV3 = (flowRecord->flowrecord);

        // check, if we need cntFlow extension
        int exCntSize = 0;
        if (flowRecord->outPackets || flowRecord->outBytes || flowRecord->flows > 1) {
            exCntSize = EXcntFlowSize;
        }

        if (!IsAvailable(dataBlock, recordHeaderV3->size + exCntSize)) {
            // flush block - get an empty one
            dataBlock = WriteBlock(nffile, dataBlock);
        }

        // write record
        void *buffPtr = GetCurrentCursor(dataBlock);
        memcpy(buffPtr, (void *)recordHeaderV3, recordHeaderV3->size);

        // remap header to written memory
        recordHeaderV3 = (recordHeaderV3_t *)buffPtr;

        recordHandle_t recordHandle = {0};
        MapRecordHandle(&recordHandle, recordHeaderV3, i + 1);

        // check if cntFlow already exists
        EXcntFlow_t *cntFlow = (EXcntFlow_t *)recordHandle.extensionList[EXcntFlowID];

        if (cntFlow == NULL && exCntSize) {
            PushExtension(recordHeaderV3, EXcntFlow, extPtr);
            cntFlow = extPtr;
        }
        dataBlock->size += recordHeaderV3->size;
        dataBlock->NumRecords++;

        EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle.extensionList[EXgenericFlowID];
        if (genericFlow) {
            genericFlow->inPackets = flowRecord->inPackets;
            genericFlow->inBytes = flowRecord->inBytes;
            genericFlow->msecFirst = flowRecord->msecFirst;
            genericFlow->msecLast = flowRecord->msecLast;
            genericFlow->tcpFlags = flowRecord->inFlags;
        }
        if (cntFlow) {
            cntFlow->outPackets = flowRecord->outPackets;
            cntFlow->outBytes = flowRecord->outBytes;
            cntFlow->flows = flowRecord->flows;
        }

        if (unlikely(NeedSwapGeneric(GuessFlowDirection, genericFlow))) {
            EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle.extensionList[EXipv4FlowID];
            EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle.extensionList[EXipv6FlowID];
            EXflowMisc_t *flowMisc = (EXflowMisc_t *)recordHandle.extensionList[EXflowMiscID];
            EXasRouting_t *asRouting = (EXasRouting_t *)recordHandle.extensionList[EXasRoutingID];
            SwapRawFlow(genericFlow, ipv4Flow, ipv6Flow, flowMisc, cntFlow, asRouting);
        }

        // Update statistics
        UpdateRawStat(nffile->stat_record, genericFlow, cntFlow);
    }

    FlushBlock(nffile, dataBlock);

}  // End of ExportSortList

int SetBidirAggregation(void) {
    dbg_printf("Enter %s\n", __func__);

    if (aggregateInfo[0] != -1) {
        LogError("Can not set bidir mode with custom aggregation mask");
        return 0;
    }
    bidir_flows = 1;

    return 1;

}  // End of SetBidirAggregation

// print -s record/xx statistics with as many print orders as required
void PrintFlowStat(RecordPrinter_t print_record, outputParams_t *outputParams) {
    dbg_printf("Enter %s\n", __func__);
    size_t maxindex;

    // Get sort array
    SortElement_t *SortList = GetSortList(&maxindex);
    if (!SortList) {
        return;
    }

    // process all the remaining stats, if requested
    for (int order_index = 0; order_mode[order_index].string != NULL; order_index++) {
        unsigned int order_bit = 1 << order_index;
        if (FlowStat_order & order_bit) {
            for (int i = 0; i < maxindex; i++) {
                FlowHashRecord_t *r = (FlowHashRecord_t *)SortList[i].record;
                /* if we have some different sort orders, which are not directly available in the FlowHashRecord_t
                 * we need to calculate this value first - such as bpp, bps etc.
                 */
                SortList[i].count = order_mode[order_index].record_function(r);
            }

            if (maxindex > 2) {
                if (maxindex < 100) {
                    heapSort(SortList, maxindex, outputParams->topN, DESCENDING);
                } else {
                    blocksort(SortList, maxindex);
                }
            }
            if (!outputParams->quiet) {
                if (outputParams->mode == MODE_PLAIN) {
                    if (outputParams->topN != 0)
                        printf("Top %i flows ordered by %s:\n", outputParams->topN, order_mode[order_index].string);
                    else
                        printf("Top flows ordered by %s:\n", order_mode[order_index].string);
                }
            }
            PrintProlog(outputParams);
            PrintSortList(SortList, maxindex, outputParams, 0, print_record, PrintDirection);
        }
    }

}  // End of PrintFlowStat

// print Flow cache
void PrintFlowTable(RecordPrinter_t print_record, outputParams_t *outputParams, int GuessDir) {
    dbg_printf("Enter %s\n", __func__);
    GuessDirection = GuessDir;

    size_t maxindex;
    SortElement_t *SortList = GetSortList(&maxindex);
    if (!SortList) return;

    if (PrintOrder) {
        // for any -O print mode
        for (int i = 0; i < maxindex; i++) {
            FlowHashRecord_t *r = (FlowHashRecord_t *)SortList[i].record;
            SortList[i].count = order_mode[PrintOrder].record_function(r);
        }

        if (maxindex >= 2) {
            if (maxindex < 100) {
                heapSort(SortList, maxindex, 0, DESCENDING);
            } else {
                blocksort(SortList, maxindex);
            }
        }

        PrintSortList(SortList, maxindex, outputParams, GuessDir, print_record, PrintDirection);
    } else {
        // for -a and no -O sorting required
        PrintSortList(SortList, maxindex, outputParams, GuessDir, print_record, PrintDirection);
    }
}  // End of PrintFlowTable

int ExportFlowTable(nffile_t *nffile, int aggregate, int bidir, int GuessDir) {
    dbg_printf("Enter %s\n", __func__);
    GuessDirection = GuessDir;

    size_t maxindex;
    SortElement_t *SortList = GetSortList(&maxindex);
    if (!SortList) return 0;

    if (PrintOrder) {
        // for any -O print mode
        for (int i = 0; i < maxindex; i++) {
            FlowHashRecord_t *r = (FlowHashRecord_t *)SortList[i].record;
            SortList[i].count = order_mode[PrintOrder].record_function(r);
        }

        if (maxindex >= 2) {
            if (maxindex < 100) {
                heapSort(SortList, maxindex, 0, DESCENDING);
            } else {
                blocksort(SortList, maxindex);
            }
        }
    }
    ExportSortList(SortList, maxindex, nffile, GuessDir, PrintDirection);

    return 1;

}  // End of ExportFlowTable
