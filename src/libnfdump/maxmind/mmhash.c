/*
 *  Copyright (c) 2024-2025, Peter Haag
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

#include "mmhash.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "kbtree.h"
#include "khash.h"
#include "logging.h"
#include "maxmind.h"
#include "mmhash.h"
#include "util.h"

#define kh_hash_func(key) (khint32_t)(key.key)
#define kh_hash_equal(a, b) ((a.key) == (b.key))

KHASH_INIT(localMap, locationKey_t, locationInfo_t, 1, kh_hash_func, kh_hash_equal)

// localID -> interned timeZone index. RAM-only, built by BuildTZCache() after
// location data is loaded - not part of the on-disk format.
KHASH_MAP_INIT_INT(tzIndexMap, uint16_t)

// ipV4Tree node compare function
// nextmask = 0 => IP to search
// mask IP to search with netmask and compare network
static inline int ipV4Node_cmp(ipV4Node_t a, ipV4Node_t b) {
    if (a.netmask == 0) {
        uint32_t network = a.network & b.netmask;
        if (network == b.network) return 0;
        return network > b.network ? 1 : -1;
    } else {
        uint32_t network = b.network & a.netmask;
        if (network == a.network) return 0;
        return a.network > network ? 1 : -1;
    }
}

static inline int ipV6Node_cmp(ipV6Node_t a, ipV6Node_t b) {
    uint64_t network[2];
    if (a.netmask[0] == 0 && a.netmask[1] == 0) {
        network[0] = a.network[0] & b.netmask[0];
        network[1] = a.network[1] & b.netmask[1];
        if (network[0] == b.network[0] && network[1] == b.network[1]) return 0;
        if (network[0] == b.network[0]) return network[1] > b.network[1] ? 1 : -1;
        return (network[0] > b.network[0]) ? 1 : -1;
    } else {
        network[0] = b.network[0] & a.netmask[0];
        network[1] = b.network[1] & a.netmask[1];
        if (network[0] == a.network[0] && network[1] == a.network[1]) return 0;
        if (a.network[0] == network[0]) return a.network[1] > network[1] ? 1 : -1;
        return (a.network[0] > network[0]) ? 1 : -1;
    }
}

KBTREE_INIT(ipV4Tree, ipV4Node_t, ipV4Node_cmp);

KBTREE_INIT(ipV6Tree, ipV6Node_t, ipV6Node_cmp);

// asV4Tree node compare function
// nextmask = 0 => IP to search
// mask IP to search with netmask and compare network
static inline int asV4Node_cmp(asV4Node_t a, asV4Node_t b) {
    if (a.netmask == 0) {
        uint32_t network = a.network & b.netmask;
        if (network == b.network) return 0;
        return network > b.network ? 1 : -1;
    } else {
        uint32_t network = b.network & a.netmask;
        if (network == a.network) return 0;
        return a.network > network ? 1 : -1;
    }
}

static inline int asV6Node_cmp(asV6Node_t a, asV6Node_t b) {
    uint64_t network[2];
    if (a.netmask[0] == 0 && a.netmask[1] == 0) {
        network[0] = a.network[0] & b.netmask[0];
        network[1] = a.network[1] & b.netmask[1];
        if (network[0] == b.network[0] && network[1] == b.network[1]) return 0;
        if (network[0] == b.network[0]) return network[1] > b.network[1] ? 1 : -1;
        return (network[0] > b.network[0]) ? 1 : -1;
    } else {
        network[0] = b.network[0] & a.netmask[0];
        network[1] = b.network[1] & a.netmask[1];
        if (network[0] == a.network[0] && network[1] == a.network[1]) return 0;
        if (a.network[0] == network[0]) return a.network[1] > network[1] ? 1 : -1;
        return (a.network[0] > network[0]) ? 1 : -1;
    }
}

static inline int asOrgNode_cmp(asOrgNode_t a, asOrgNode_t b) {
    if (a.as == b.as) return 0;
    return a.as > b.as ? 1 : -1;
}  // End of asOrgNode_cmp

KBTREE_INIT(asV4Tree, asV4Node_t, asV4Node_cmp);

KBTREE_INIT(asV6Tree, asV6Node_t, asV6Node_cmp);

KBTREE_INIT(asOrgTree, asOrgNode_t, asOrgNode_cmp);

typedef struct mmHandle_s {
    khash_t(localMap) * localMap;
    kbtree_t(ipV4Tree) * ipV4Tree;
    kbtree_t(ipV6Tree) * ipV6Tree;
    kbtree_t(asV4Tree) * asV4Tree;
    kbtree_t(asV6Tree) * asV6Tree;
    kbtree_t(asOrgTree) * asOrgTree;
} mmHandle_t;

static mmHandle_t *mmHandle = NULL;

/* -----------------------------------------------------------------------
 * Flat sorted-array cache
 *
 * <nffile>.flat is a machine-local, uncompressed sibling of the portable
 * nffileV3 master geoDB (see maxmind.c) built once by WriteFlatCache() and
 * then mmap'd read-only on every subsequent LoadMaxMind() call, avoiding the
 * decompress-and-rebuild-the-trees cost every time nfdump starts. It is a
 * pure derived cache: safe to delete at any time, and LoadMaxMind()
 * transparently falls back to decompressing the master file and rewriting
 * this cache if it is missing, stale (older than the master file's mtime),
 * or fails validation.
 *
 * On-disk layout, all offsets relative to the start of the file:
 *
 *   [ mmFlatHeader_t ]                     fixed-size header (see below)
 *   [ locationInfo_t   locArr[locCount]  ]  section 0 - MMFLAT_SEC_LOC
 *   [ ipV4Node_t       ipV4Arr[ipV4Count]]  section 1 - MMFLAT_SEC_IPV4
 *   [ ipV6Node_t       ipV6Arr[ipV6Count]]  section 2 - MMFLAT_SEC_IPV6
 *   [ asV4Node_t       asV4Arr[asV4Count]]  section 3 - MMFLAT_SEC_ASV4
 *   [ asV6Node_t       asV6Arr[asV6Count]]  section 4 - MMFLAT_SEC_ASV6
 *   [ asOrgNode_t      asOrgArr[asOrgCount]]section 5 - MMFLAT_SEC_ASORG
 *
 * The header carries a magic/version pair plus, per section, its element
 * size, element count and byte offset (mmFlatSection_t) - so sections are
 * located by the header, not assumed to be contiguous/in this exact order,
 * though WriteFlatCache() always lays them out in this order with no gaps.
 * Each section is simply the raw, memcpy-able C array of the corresponding
 * struct, already sorted ascending by network/AS (SortFlatArrays()) so
 * flatSearchV4()/flatSearchAsV4()/etc. can binary-search it directly out of
 * the mapping with zero deserialization.
 *
 * Because sections are raw struct dumps, this file's layout is tied to the
 * exact struct definitions (and this build's padding/alignment) that wrote
 * it - LoadFlatCache() checks each section's recorded elemSize against
 * sizeof() of the corresponding struct and rejects the file on any mismatch,
 * which is what actually invalidates a stale cache after a struct change
 * (there is deliberately no separate format-version bump for that; see the
 * MMFLAT_VERSION comment below). LoadFlatCache() additionally verifies every
 * section's offset+count*elemSize fits inside the actual file size before
 * trusting it, since this file can be loaded directly (`-G foo.flat`) and a
 * truncated or corrupted one must not be able to walk the mmap out of bounds.
 * ----------------------------------------------------------------------- */
#define MMFLAT_MAGIC 0x4D4D464CU  // 'M','M','F','L'
#define MMFLAT_VERSION 1U

// section IDs (indices into mmFlatHeader_t.sec[])
#define MMFLAT_SEC_LOC 0
#define MMFLAT_SEC_IPV4 1
#define MMFLAT_SEC_IPV6 2
#define MMFLAT_SEC_ASV4 3
#define MMFLAT_SEC_ASV6 4
#define MMFLAT_SEC_ASORG 5
// number of sections
#define MMFLAT_NSECT 6U

typedef struct mmFlatSection_s {
    uint32_t elemSize;  // sizeof the element type
    uint32_t count;     // number of elements
    uint64_t offset;    // byte offset from file start
} mmFlatSection_t;

typedef struct mmFlatHeader_s {
    uint32_t magic;
    uint32_t version;
    uint32_t numSections;
    uint32_t reserved;
    mmFlatSection_t sec[MMFLAT_NSECT];
} mmFlatHeader_t;

// flat state — populated either from mmap or from malloc after slow load
typedef struct mmFlat_s {
    void *mmapBase;  // mmap state (NULL when data came from LoadMaxMind slow path)
    size_t mmapSize;

    // pointers into the sorted arrays (point into mmap or realloc'd memory)
    locationInfo_t *locArr;
    uint32_t locCount;
    ipV4Node_t *ipV4Arr;
    uint32_t ipV4Count;
    ipV6Node_t *ipV6Arr;
    uint32_t ipV6Count;
    asV4Node_t *asV4Arr;
    uint32_t asV4Count;
    asV6Node_t *asV6Arr;
    uint32_t asV6Count;
    asOrgNode_t *asOrgArr;
    uint32_t asOrgCount;
} mmFlat_t;

static mmFlat_t *mmFlat = NULL;

/* -----------------------------------------------------------------------
 * timeZone name interning, built once by BuildTZCache() after location data
 * is loaded (see LoadFlatCache() and LoadMaxMind()'s slow path). RAM-only -
 * not persisted, not part of the on-disk format. Lets per-flow lookups store
 * a small stable uint16_t index instead of repeatedly string-comparing the
 * full timeZone name.
 * ----------------------------------------------------------------------- */
#define MAX_TZ_CACHE 1024
static char tzNameTable[MAX_TZ_CACHE][TimeZoneLength] = {[0] = "unknown timezone"};
static uint16_t tzNameCount = 1;
static khash_t(tzIndexMap) *tzIndexByLocalID = NULL;

static uint16_t internTZname(const char *tzName) {
    for (uint16_t i = 0; i < tzNameCount; i++) {
        if (strcmp(tzNameTable[i], tzName) == 0) return i;
    }

    uint16_t index = tzNameCount;
    if (tzNameCount < MAX_TZ_CACHE) {
        strncpy(tzNameTable[tzNameCount], tzName, TimeZoneLength - 1);
        tzNameCount++;
    }
    return index;
}  // End of internTZname

void BuildTZCache(void) {
    if (tzIndexByLocalID) return;  // already built

    tzIndexByLocalID = kh_init(tzIndexMap);
    for (locationInfo_t *loc = NextLocation(FIRSTNODE); loc != NULL; loc = NextLocation(NEXTNODE)) {
        uint16_t tzIndex = internTZname(loc->timeZone);
        int absent;
        khint_t k = kh_put(tzIndexMap, tzIndexByLocalID, loc->localID, &absent);
        if (absent) kh_value(tzIndexByLocalID, k) = tzIndex;
    }
    dbg_printf("BuildTZCache: %u distinct time zones\n", tzNameCount);
}  // End of BuildTZCache

// comparators for qsort (sort by network address ascending)
static int cmpIpV4(const void *a, const void *b) {
    uint32_t x = ((const ipV4Node_t *)a)->network;
    uint32_t y = ((const ipV4Node_t *)b)->network;
    if (x < y) return -1;
    if (x > y) return 1;
    return 0;
}
static int cmpIpV6(const void *a, const void *b) {
    const ipV6Node_t *x = (const ipV6Node_t *)a;
    const ipV6Node_t *y = (const ipV6Node_t *)b;
    if (x->network[0] != y->network[0]) return x->network[0] < y->network[0] ? -1 : 1;
    if (x->network[1] != y->network[1]) return x->network[1] < y->network[1] ? -1 : 1;
    return 0;
}
static int cmpAsV4(const void *a, const void *b) {
    uint32_t x = ((const asV4Node_t *)a)->network;
    uint32_t y = ((const asV4Node_t *)b)->network;
    if (x < y) return -1;
    if (x > y) return 1;
    return 0;
}
static int cmpAsV6(const void *a, const void *b) {
    const asV6Node_t *x = (const asV6Node_t *)a;
    const asV6Node_t *y = (const asV6Node_t *)b;
    if (x->network[0] != y->network[0]) return x->network[0] < y->network[0] ? -1 : 1;
    if (x->network[1] != y->network[1]) return x->network[1] < y->network[1] ? -1 : 1;
    return 0;
}
static int cmpAsOrg(const void *a, const void *b) {
    uint32_t x = ((const asOrgNode_t *)a)->as;
    uint32_t y = ((const asOrgNode_t *)b)->as;
    if (x < y) return -1;
    if (x > y) return 1;
    return 0;
}

// asymmetric binary searches (netmask == 0 means "probe")
static inline ipV4Node_t *flatSearchV4(const ipV4Node_t *arr, uint32_t n, uint32_t ip) {
    uint32_t lo = 0, hi = n;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        uint32_t masked = ip & arr[mid].netmask;
        if (masked == arr[mid].network) return (ipV4Node_t *)&arr[mid];
        if (masked < arr[mid].network)
            hi = mid;
        else
            lo = mid + 1;
    }
    return NULL;
}
static inline ipV6Node_t *flatSearchV6(const ipV6Node_t *arr, uint32_t n, const uint64_t ip[2]) {
    uint32_t lo = 0, hi = n;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        uint64_t m0 = ip[0] & arr[mid].netmask[0];
        uint64_t m1 = ip[1] & arr[mid].netmask[1];
        if (m0 == arr[mid].network[0] && m1 == arr[mid].network[1]) return (ipV6Node_t *)&arr[mid];
        if (m0 < arr[mid].network[0] || (m0 == arr[mid].network[0] && m1 < arr[mid].network[1]))
            hi = mid;
        else
            lo = mid + 1;
    }
    return NULL;
}
static inline asV4Node_t *flatSearchAsV4(const asV4Node_t *arr, uint32_t n, uint32_t ip) {
    uint32_t lo = 0, hi = n;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        uint32_t masked = ip & arr[mid].netmask;
        if (masked == arr[mid].network) return (asV4Node_t *)&arr[mid];
        if (masked < arr[mid].network)
            hi = mid;
        else
            lo = mid + 1;
    }
    return NULL;
}
static inline asV6Node_t *flatSearchAsV6(const asV6Node_t *arr, uint32_t n, const uint64_t ip[2]) {
    uint32_t lo = 0, hi = n;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        uint64_t m0 = ip[0] & arr[mid].netmask[0];
        uint64_t m1 = ip[1] & arr[mid].netmask[1];
        if (m0 == arr[mid].network[0] && m1 == arr[mid].network[1]) return (asV6Node_t *)&arr[mid];
        if (m0 < arr[mid].network[0] || (m0 == arr[mid].network[0] && m1 < arr[mid].network[1]))
            hi = mid;
        else
            lo = mid + 1;
    }
    return NULL;
}
static inline asOrgNode_t *flatSearchAsOrg(const asOrgNode_t *arr, uint32_t n, uint32_t as) {
    uint32_t lo = 0, hi = n;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (as == arr[mid].as) return (asOrgNode_t *)&arr[mid];
        if (as < arr[mid].as)
            hi = mid;
        else
            lo = mid + 1;
    }
    return NULL;
}

int Init_MaxMind(void) {
    mmHandle = calloc(1, sizeof(mmHandle_t));
    if (!mmHandle) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    mmHandle->localMap = kh_init(localMap);
    mmHandle->ipV4Tree = kb_init(ipV4Tree, 10 * KB_DEFAULT_SIZE);
    mmHandle->ipV6Tree = kb_init(ipV6Tree, 10 * KB_DEFAULT_SIZE);
    mmHandle->asV4Tree = kb_init(asV4Tree, 10 * KB_DEFAULT_SIZE);
    mmHandle->asV6Tree = kb_init(asV6Tree, 10 * KB_DEFAULT_SIZE);
    mmHandle->asOrgTree = kb_init(asOrgTree, 10 * KB_DEFAULT_SIZE);

    if (!mmHandle->ipV4Tree || !mmHandle->ipV6Tree || !mmHandle->localMap || !mmHandle->asV4Tree || !mmHandle->asV6Tree || !mmHandle->asOrgTree) {
        LogError("Initialization of MaxMind module failed");
        return 0;
    }
    return 1;

}  // End of Init_MaxMind

void LoadLocalInfo(locationInfo_t *locationInfo, uint32_t NumRecords) {
    /* Store in khash for O(1) lookup by localID */
    for (int i = 0; i < (int)NumRecords; i++) {
        int absent;
        locationKey_t locationKey = {.key = locationInfo->localID};
        khint_t k = kh_put(localMap, mmHandle->localMap, locationKey, &absent);
        if (!absent) {
            LogError("Duplicate location entry: %u", locationInfo->localID);
        } else {
            kh_value(mmHandle->localMap, k) = *locationInfo;
        }
        locationInfo++;
    }

    /* Also append to flat locArr for flat-cache serialisation */
    if (!mmFlat) return;
    locationInfo_t *tmp = realloc(mmFlat->locArr, (mmFlat->locCount + NumRecords) * sizeof(locationInfo_t));
    if (!tmp) {
        LogError("realloc() failed in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return;
    }
    mmFlat->locArr = tmp;
    /* walk back to beginning of the block; locationInfo was advanced above */
    memcpy(mmFlat->locArr + mmFlat->locCount, locationInfo - NumRecords, NumRecords * sizeof(locationInfo_t));
    mmFlat->locCount += NumRecords;

}  // End of LoadLocalInfo

void LoadIPv4Tree(ipV4Node_t *ipV4Node, uint32_t NumRecords) {
    // Duplicates are already detected and reported by PutIPv4Node() when the
    // geo DB is built from the maxmind CSVs (mmcreate.c). The .nf file loaded
    // here was already vetted at that point, so skip the redundant get-before-put
    // lookup and insert directly - this halves the number of tree descents per record.
    kbtree_t(ipV4Tree) *ipV4Tree = mmHandle->ipV4Tree;
    for (int i = 0; i < (int)NumRecords; i++) {
        kb_putp(ipV4Tree, ipV4Tree, ipV4Node);
        ipV4Node++;
    }

    if (!mmFlat) return;
    ipV4Node_t *tmp = realloc(mmFlat->ipV4Arr, (mmFlat->ipV4Count + NumRecords) * sizeof(ipV4Node_t));
    if (!tmp) {
        LogError("realloc() failed in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return;
    }
    mmFlat->ipV4Arr = tmp;
    memcpy(mmFlat->ipV4Arr + mmFlat->ipV4Count, ipV4Node - NumRecords, NumRecords * sizeof(ipV4Node_t));
    mmFlat->ipV4Count += NumRecords;

}  // End of LoadIPv4Tree

void LoadIPv6Tree(ipV6Node_t *ipV6Node, uint32_t NumRecords) {
    // see LoadIPv4Tree() - duplicates already checked at DB build time
    kbtree_t(ipV6Tree) *ipV6Tree = mmHandle->ipV6Tree;
    for (int i = 0; i < (int)NumRecords; i++) {
        kb_putp(ipV6Tree, ipV6Tree, ipV6Node);
        ipV6Node++;
    }

    if (!mmFlat) return;
    ipV6Node_t *tmp = realloc(mmFlat->ipV6Arr, (mmFlat->ipV6Count + NumRecords) * sizeof(ipV6Node_t));
    if (!tmp) {
        LogError("realloc() failed in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return;
    }
    mmFlat->ipV6Arr = tmp;
    memcpy(mmFlat->ipV6Arr + mmFlat->ipV6Count, ipV6Node - NumRecords, NumRecords * sizeof(ipV6Node_t));
    mmFlat->ipV6Count += NumRecords;

}  // End of LoadIPv6Tree

void LoadASV4Tree(asV4Node_t *asV4Node, uint32_t NumRecords) {
    // see LoadIPv4Tree() - duplicates already checked at DB build time
    kbtree_t(asV4Tree) *asV4Tree = mmHandle->asV4Tree;
    for (int i = 0; i < (int)NumRecords; i++) {
        kb_putp(asV4Tree, asV4Tree, asV4Node);
        asV4Node++;
    }

    if (!mmFlat) return;
    asV4Node_t *tmp = realloc(mmFlat->asV4Arr, (mmFlat->asV4Count + NumRecords) * sizeof(asV4Node_t));
    if (!tmp) {
        LogError("realloc() failed in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return;
    }
    mmFlat->asV4Arr = tmp;
    memcpy(mmFlat->asV4Arr + mmFlat->asV4Count, asV4Node - NumRecords, NumRecords * sizeof(asV4Node_t));
    mmFlat->asV4Count += NumRecords;
}  // End of LoadASV4Tree

void LoadASV6Tree(asV6Node_t *asV6Node, uint32_t NumRecords) {
    // see LoadIPv4Tree() - duplicates already checked at DB build time
    kbtree_t(asV6Tree) *asV6Tree = mmHandle->asV6Tree;
    for (int i = 0; i < (int)NumRecords; i++) {
        kb_putp(asV6Tree, asV6Tree, asV6Node);
        asV6Node++;
    }

    if (!mmFlat) return;
    asV6Node_t *tmp = realloc(mmFlat->asV6Arr, (mmFlat->asV6Count + NumRecords) * sizeof(asV6Node_t));
    if (!tmp) {
        LogError("realloc() failed in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return;
    }
    mmFlat->asV6Arr = tmp;
    memcpy(mmFlat->asV6Arr + mmFlat->asV6Count, asV6Node - NumRecords, NumRecords * sizeof(asV6Node_t));
    mmFlat->asV6Count += NumRecords;

}  // End of LoadASV6Tree

void LoadASorgTree(asOrgNode_t *asOrgNode, uint32_t NumRecords) {
    // see LoadIPv4Tree() - duplicates already checked at DB build time
    kbtree_t(asOrgTree) *asOrgTree = mmHandle->asOrgTree;
    for (int i = 0; i < (int)NumRecords; i++) {
        kb_putp(asOrgTree, asOrgTree, asOrgNode);
        asOrgNode++;
    }

    if (!mmFlat) return;
    asOrgNode_t *tmp = realloc(mmFlat->asOrgArr, (mmFlat->asOrgCount + NumRecords) * sizeof(asOrgNode_t));
    if (!tmp) {
        LogError("realloc() failed in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return;
    }
    mmFlat->asOrgArr = tmp;
    memcpy(mmFlat->asOrgArr + mmFlat->asOrgCount, asOrgNode - NumRecords, NumRecords * sizeof(asOrgNode_t));
    mmFlat->asOrgCount += NumRecords;
}  // End of LoadASorgTree

void PutLocation(locationInfo_t *locationInfo) {
    khash_t(localMap) *localMap = mmHandle->localMap;

    int absent;
    locationKey_t locationKey = {.key = locationInfo->localID};
    khint_t k = kh_put(localMap, localMap, locationKey, &absent);
    if (!absent) {
        LogError("Duplicate entry: %u", locationInfo->localID);
    } else {
        kh_value(localMap, k) = *locationInfo;
    }

}  // End of PutLocation

void PutIPv4Node(ipV4Node_t *ipV4Node) {
    kbtree_t(ipV4Tree) *ipV4Tree = mmHandle->ipV4Tree;

    ipV4Node_t *node = kb_getp(ipV4Tree, ipV4Tree, ipV4Node);
    if (node) {
        uint32_t net = htonl(ipV4Node->network);
        char s[32] = {0};
        inet_ntop(AF_INET, &net, s, sizeof(s));
        LogError("Duplicate IPV4 node: ip: %s", s);
    } else {
        kb_putp(ipV4Tree, ipV4Tree, ipV4Node);
    }
}  // End of PutIPv4Node

void PutIPv6Node(ipV6Node_t *ipV6Node) {
    kbtree_t(ipV6Tree) *ipV6Tree = mmHandle->ipV6Tree;
    ipV6Node_t *node = kb_getp(ipV6Tree, ipV6Tree, ipV6Node);
    if (node) {
        uint64_t ipv6[2] = {htonll(ipV6Node->network[0]), htonll(ipV6Node->network[1])};
        char s[128];
        inet_ntop(AF_INET6, ipv6, s, sizeof(s));
        LogError("Duplicate IPV6 node: ip: %s", s);
    } else {
        kb_putp(ipV6Tree, ipV6Tree, ipV6Node);
    }
}  // End of PutIPv6Node

void PutasV4Node(asV4Node_t *asV4Node) {
    kbtree_t(asV4Tree) *asV4Tree = mmHandle->asV4Tree;
    asV4Node_t *node = kb_getp(asV4Tree, asV4Tree, asV4Node);
    if (node) {
        LogError("Duplicate ASv4 node: AS%u %s", asV4Node->as, asV4Node->orgName);
    } else {
        kb_putp(asV4Tree, asV4Tree, asV4Node);
    }
}  // End of PutasV4Node

void PutasV6Node(asV6Node_t *asV6Node) {
    kbtree_t(asV6Tree) *asV6Tree = mmHandle->asV6Tree;

    asV6Node_t *node = kb_getp(asV6Tree, asV6Tree, asV6Node);
    if (node) {
        LogError("Duplicate ASv6 node: AS%u %s", asV6Node->as, asV6Node->orgName);
    } else {
        kb_putp(asV6Tree, asV6Tree, asV6Node);
    }
}  // End of PutasV6Node

void PutASorgNode(asOrgNode_t *asOrgNode) {
    kbtree_t(asOrgTree) *asOrgTree = mmHandle->asOrgTree;

    asOrgNode_t *node = kb_getp(asOrgTree, asOrgTree, asOrgNode);
    if (node == NULL) {
        kb_putp(asOrgTree, asOrgTree, asOrgNode);
    }
}  // End of PutASorgNode

void LookupV4Country(uint32_t ip, char *country) {
    if (!mmFlat || !mmFlat->ipV4Arr) {
        country[0] = '.';
        country[1] = '.';
        return;
    }

    ipV4Node_t *ipV4Node = flatSearchV4(mmFlat->ipV4Arr, mmFlat->ipV4Count, ip);
    if (!ipV4Node) {
        country[0] = '.';
        country[1] = '.';
        return;
    }

    locationKey_t locationKey = {.key = ipV4Node->info.localID};
    khint_t k = kh_get(localMap, mmHandle->localMap, locationKey);
    if (k == kh_end(mmHandle->localMap)) {
        country[0] = '.';
        country[1] = '.';
        return;
    }

    locationInfo_t locationInfo = kh_value(mmHandle->localMap, k);
    country[0] = locationInfo.country[0];
    country[1] = locationInfo.country[1];

}  // End of LookupV4Country

void LookupV6Country(uint64_t ip[2], char *country) {
    if (!mmFlat || !mmFlat->ipV6Arr) {
        country[0] = '.';
        country[1] = '.';
        return;
    }

    ipV6Node_t *ipV6Node = flatSearchV6(mmFlat->ipV6Arr, mmFlat->ipV6Count, ip);
    if (!ipV6Node) {
        country[0] = '.';
        country[1] = '.';
        return;
    }

    locationKey_t locationKey = {.key = ipV6Node->info.localID};
    khint_t k = kh_get(localMap, mmHandle->localMap, locationKey);
    if (k == kh_end(mmHandle->localMap)) {
        country[0] = '.';
        country[1] = '.';
        return;
    }

    locationInfo_t locationInfo = kh_value(mmHandle->localMap, k);
    country[0] = locationInfo.country[0];
    country[1] = locationInfo.country[1];

}  // End of LookupV6Country

void LookupV4Location(uint32_t ip, char *location, size_t len) {
    location[0] = '\0';
    if (!mmFlat || !mmFlat->ipV4Arr) return;

    ipV4Node_t *ipV4Node = flatSearchV4(mmFlat->ipV4Arr, mmFlat->ipV4Count, ip);
    if (!ipV4Node) return;

    locationKey_t locationKey = {.key = ipV4Node->info.localID};
    khint_t k = kh_get(localMap, mmHandle->localMap, locationKey);
    if (k == kh_end(mmHandle->localMap)) return;

    locationInfo_t locationInfo = kh_value(mmHandle->localMap, k);
    snprintf(location, len, "%s/%s/%s long/lat: %.4f/%-.4f", locationInfo.continent, locationInfo.country, locationInfo.city,
             ipV4Node->info.longitude, ipV4Node->info.latitude);

}  // End of LookupV4Location

void LookupV6Location(uint64_t ip[2], char *location, size_t len) {
    location[0] = '\0';
    if (!mmFlat || !mmFlat->ipV6Arr) return;

    ipV6Node_t *ipV6Node = flatSearchV6(mmFlat->ipV6Arr, mmFlat->ipV6Count, ip);
    if (!ipV6Node) return;

    locationKey_t locationKey = {.key = ipV6Node->info.localID};
    khint_t k = kh_get(localMap, mmHandle->localMap, locationKey);
    if (k == kh_end(mmHandle->localMap)) return;

    locationInfo_t locationInfo = kh_value(mmHandle->localMap, k);
    snprintf(location, len, "%s/%s/%s long/lat: %.4f/%-.4f", locationInfo.continent, locationInfo.country, locationInfo.city,
             ipV6Node->info.longitude, ipV6Node->info.latitude);

}  // End of LookupV6Location

const char *LookupV4Timezone(uint32_t ip) {
    if (!mmFlat || !mmFlat->ipV4Arr) return NULL;

    ipV4Node_t *ipV4Node = flatSearchV4(mmFlat->ipV4Arr, mmFlat->ipV4Count, ip);
    if (!ipV4Node) return NULL;

    locationKey_t locationKey = {.key = ipV4Node->info.localID};
    khint_t k = kh_get(localMap, mmHandle->localMap, locationKey);
    if (k == kh_end(mmHandle->localMap)) return NULL;

    return kh_value(mmHandle->localMap, k).timeZone;

}  // End of LookupV4Timezone

int32_t LookupV4UtcOffset(uint32_t ip) {
    if (!mmFlat || !mmFlat->ipV4Arr) return UTC_OFFSET_UNKNOWN;

    ipV4Node_t *ipV4Node = flatSearchV4(mmFlat->ipV4Arr, mmFlat->ipV4Count, ip);
    if (!ipV4Node) return UTC_OFFSET_UNKNOWN;

    locationKey_t locationKey = {.key = ipV4Node->info.localID};
    khint_t k = kh_get(localMap, mmHandle->localMap, locationKey);
    if (k == kh_end(mmHandle->localMap)) return UTC_OFFSET_UNKNOWN;

    return kh_value(mmHandle->localMap, k).utcOffset;

}  // End of LookupV4UtcOffset

uint16_t LookupV4TZindex(uint32_t ip) {
    if (!mmFlat || !mmFlat->ipV4Arr || !tzIndexByLocalID) return 0;

    ipV4Node_t *ipV4Node = flatSearchV4(mmFlat->ipV4Arr, mmFlat->ipV4Count, ip);
    if (!ipV4Node) return 0;

    khint_t k = kh_get(tzIndexMap, tzIndexByLocalID, ipV4Node->info.localID);
    if (k == kh_end(tzIndexByLocalID)) return 0;

    return kh_value(tzIndexByLocalID, k);

}  // End of LookupV4TZindex

const char *LookupV6Timezone(uint64_t ip[2]) {
    if (!mmFlat || !mmFlat->ipV6Arr) return NULL;

    ipV6Node_t *ipV6Node = flatSearchV6(mmFlat->ipV6Arr, mmFlat->ipV6Count, ip);
    if (!ipV6Node) return NULL;

    locationKey_t locationKey = {.key = ipV6Node->info.localID};
    khint_t k = kh_get(localMap, mmHandle->localMap, locationKey);
    if (k == kh_end(mmHandle->localMap)) return NULL;

    return kh_value(mmHandle->localMap, k).timeZone;

}  // End of LookupV6Timezone

int32_t LookupV6UtcOffset(uint64_t ip[2]) {
    if (!mmFlat || !mmFlat->ipV6Arr) return UTC_OFFSET_UNKNOWN;

    ipV6Node_t *ipV6Node = flatSearchV6(mmFlat->ipV6Arr, mmFlat->ipV6Count, ip);
    if (!ipV6Node) return UTC_OFFSET_UNKNOWN;

    locationKey_t locationKey = {.key = ipV6Node->info.localID};
    khint_t k = kh_get(localMap, mmHandle->localMap, locationKey);
    if (k == kh_end(mmHandle->localMap)) return UTC_OFFSET_UNKNOWN;

    return kh_value(mmHandle->localMap, k).utcOffset;

}  // End of LookupV6UtcOffset

uint16_t LookupV6TZindex(uint64_t ip[2]) {
    if (!mmFlat || !mmFlat->ipV6Arr || !tzIndexByLocalID) return 0;

    ipV6Node_t *ipV6Node = flatSearchV6(mmFlat->ipV6Arr, mmFlat->ipV6Count, ip);
    if (!ipV6Node) return 0;

    khint_t k = kh_get(tzIndexMap, tzIndexByLocalID, ipV6Node->info.localID);
    if (k == kh_end(tzIndexByLocalID)) return 0;

    return kh_value(tzIndexByLocalID, k);

}  // End of LookupV6TZindex

uint16_t LookupTZindex(const char *tzName) {
    for (uint16_t i = 0; i < tzNameCount; i++) {
        if (strcmp(tzNameTable[i], tzName) == 0) return i;
    }
    return 0;

}  // End of LookupTZindex

const char *LookupTZname(uint16_t index) {
    if (index >= tzNameCount) return "invalid timezone";
    return tzNameTable[index];
}  // End of LookupTZname

uint32_t LookupV4AS(uint32_t ip) {
    if (!mmFlat || !mmFlat->asV4Arr) return 0;
    asV4Node_t *n = flatSearchAsV4(mmFlat->asV4Arr, mmFlat->asV4Count, ip);
    return n == NULL ? 0 : n->as;
}  // End of LookupV4AS

uint32_t LookupV6AS(uint64_t ip[2]) {
    if (!mmFlat || !mmFlat->asV6Arr) return 0;
    asV6Node_t *n = flatSearchAsV6(mmFlat->asV6Arr, mmFlat->asV6Count, ip);
    return n == NULL ? 0 : n->as;
}  // End of LookupV6AS

const char *LookupASorg(uint32_t as) {
    if (!mmFlat || !mmFlat->asOrgArr) return NULL;
    asOrgNode_t *n = flatSearchAsOrg(mmFlat->asOrgArr, mmFlat->asOrgCount, as);
    return n == NULL ? "not found" : n->orgName;
}  // End of LookupASorg

void LookupAS(char *asString) {
    long as = strtol(asString, (char **)NULL, 10);

    if (as == 0 || as > 0xFFFFFFFFL || as < 0) {
        printf("Invalid AS number: %s: %s\n", asString, strerror(errno));
    } else {
        const char *asOrg = LookupASorg(as);
        if (asOrg == NULL)
            printf("No DB available!\n");
        else
            printf("%-7lu | %s\n", as, LookupASorg(as));
    }

}  // End of LookupAS

const char *LookupV4ASorg(uint32_t ip) {
    if (!mmFlat || !mmFlat->asV4Arr) return "";
    asV4Node_t *n = flatSearchAsV4(mmFlat->asV4Arr, mmFlat->asV4Count, ip);
    return n == NULL ? "" : n->orgName;
}  // End of LookupV4ASorg

const char *LookupV6ASorg(uint64_t ip[2]) {
    if (!mmFlat || !mmFlat->asV6Arr) return "";
    asV6Node_t *n = flatSearchAsV6(mmFlat->asV6Arr, mmFlat->asV6Count, ip);
    return n == NULL ? "" : n->orgName;
}  // End of LookupV6ASorg

void LookupWhois(char *ip) {
    uint32_t as = 0;
    char *asOrg = NULL;
    ipV4Node_t *ipV4Node;
    ipV6Node_t *ipV6Node;
    ipLocationInfo_t info = {0};
    if (strchr(ip, ':') != NULL) {
        // IPv6
        uint64_t network[2];
        uint64_t ipnet[2];
        int ret = inet_pton(PF_INET6, ip, network);
        if (ret != 1) return;
        ipnet[0] = ntohll(network[0]);
        ipnet[1] = ntohll(network[1]);

        uint64_t testv4v6 = ipnet[1] & 0xFFFFFFFF00000000LL;
        if (ipnet[0] == 0 && (testv4v6 == 0LL || testv4v6 == 0x0000ffff00000000LL)) {
            uint32_t net = (uint32_t)ipnet[1];
            if (mmFlat && mmFlat->asV4Arr) {
                asV4Node_t *asV4Node = flatSearchAsV4(mmFlat->asV4Arr, mmFlat->asV4Count, net);
                if (asV4Node) {
                    as = asV4Node->as;
                    asOrg = asV4Node->orgName;
                }
            }
        } else {
            if (mmFlat && mmFlat->ipV6Arr) {
                ipV6Node = flatSearchV6(mmFlat->ipV6Arr, mmFlat->ipV6Count, ipnet);
                if (ipV6Node) info = ipV6Node->info;
            }
            if (mmFlat && mmFlat->asV6Arr) {
                asV6Node_t *asV6Node = flatSearchAsV6(mmFlat->asV6Arr, mmFlat->asV6Count, ipnet);
                if (asV6Node) {
                    as = asV6Node->as;
                    asOrg = asV6Node->orgName;
                }
            }
        }

    } else {
        // IPv4
        uint32_t net;
        int ret = inet_pton(PF_INET, ip, &net);
        if (ret != 1) return;
        uint32_t hnet = ntohl(net);

        if (mmFlat && mmFlat->ipV4Arr) {
            ipV4Node = flatSearchV4(mmFlat->ipV4Arr, mmFlat->ipV4Count, hnet);
            if (ipV4Node) info = ipV4Node->info;
        }
        if (mmFlat && mmFlat->asV4Arr) {
            asV4Node_t *asV4Node = flatSearchAsV4(mmFlat->asV4Arr, mmFlat->asV4Count, hnet);
            if (asV4Node) {
                as = asV4Node->as;
                asOrg = asV4Node->orgName;
            }
        }
    }

    locationKey_t locationKey = {.key = info.localID};
    khint_t k = kh_get(localMap, mmHandle->localMap, locationKey);
    if (k == kh_end(mmHandle->localMap)) {
        printf("%-7u | %-24s | %-32s | no information | TZ: %-20s | sat: %d\n", as, ip, asOrg == NULL ? "private" : asOrg, "-", info.sat);
    } else {
        locationInfo_t locationInfo = kh_value(mmHandle->localMap, k);
        printf("%-7u | %-24s | %-32s | %s/%s/%s long/lat: %8.4f/%-8.4f | TZ: %-20s | sat: %d\n", as, ip, asOrg == NULL ? "private" : asOrg,
               locationInfo.continent, locationInfo.country, locationInfo.city, info.longitude, info.latitude, locationInfo.timeZone, info.sat);
    }

}  // End of LookupWhois

locationInfo_t *NextLocation(int start) {
    static khint_t k = 0;
    static locationInfo_t locationInfo;

    khash_t(localMap) *localMap = mmHandle->localMap;
    if (start == FIRSTNODE) k = kh_begin(localMap);

    while (k != kh_end(localMap)) {
        if (kh_exist(localMap, k)) {  // test if a bucket contains data
            locationInfo = kh_value(localMap, k);
            k++;
            return &locationInfo;
        }
        k++;
    }

    return NULL;

}  // End of NextLocation

ipV4Node_t *NextIPv4Node(int start) {
    static kbitr_t itr = {0};
    static ipV4Node_t *ipV4Node = NULL;

    kbtree_t(ipV4Tree) *ipV4Tree = mmHandle->ipV4Tree;
    if (start == FIRSTNODE) kb_itr_first(ipV4Tree, ipV4Tree, &itr);  // get an iterator pointing to the first

    if (kb_itr_valid(&itr)) {
        ipV4Node = &kb_itr_key(ipV4Node_t, &itr);
        kb_itr_next(ipV4Tree, ipV4Tree, &itr);  // move on
        return ipV4Node;
    } else {
        return NULL;
    }

}  // End of NextIPv4Node

ipV6Node_t *NextIPv6Node(int start) {
    static kbitr_t itr = {0};
    static ipV6Node_t *ipV6Node = NULL;

    kbtree_t(ipV6Tree) *ipV6Tree = mmHandle->ipV6Tree;
    if (start == FIRSTNODE) kb_itr_first(ipV6Tree, ipV6Tree, &itr);  // get an iterator pointing to the first

    if (kb_itr_valid(&itr)) {
        ipV6Node = &kb_itr_key(ipV6Node_t, &itr);
        kb_itr_next(ipV6Tree, ipV6Tree, &itr);  // move on
        return ipV6Node;
    } else {
        return NULL;
    }

}  // End of NextIPv6Node

asV4Node_t *NextasV4Node(int start) {
    static kbitr_t itr = {0};
    static asV4Node_t *asV4Node = NULL;

    kbtree_t(asV4Tree) *asV4Tree = mmHandle->asV4Tree;
    if (start == FIRSTNODE) kb_itr_first(asV4Tree, asV4Tree, &itr);  // get an iterator pointing to the first

    if (kb_itr_valid(&itr)) {
        asV4Node = &kb_itr_key(asV4Node_t, &itr);
        kb_itr_next(asV4Tree, asV4Tree, &itr);  // move on
        return asV4Node;
    } else {
        return NULL;
    }

}  // End of NextasV4Node

asV6Node_t *NextasV6Node(int start) {
    static kbitr_t itr = {0};
    static asV6Node_t *asV6Node = NULL;

    kbtree_t(asV6Tree) *asV6Tree = mmHandle->asV6Tree;
    if (start == FIRSTNODE) kb_itr_first(asV6Tree, asV6Tree, &itr);  // get an iterator pointing to the first

    if (kb_itr_valid(&itr)) {
        asV6Node = &kb_itr_key(asV6Node_t, &itr);
        kb_itr_next(asV6Tree, asV6Tree, &itr);  // move on
        return asV6Node;
    } else {
        return NULL;
    }
}  // End of NextasV6Node

asOrgNode_t *NextasOrgNode(int start) {
    static kbitr_t itr = {0};
    static asOrgNode_t *asOrgNode = NULL;

    kbtree_t(asOrgTree) *asOrgTree = mmHandle->asOrgTree;
    if (start == FIRSTNODE) kb_itr_first(asOrgTree, asOrgTree, &itr);  // get an iterator pointing to the first

    if (kb_itr_valid(&itr)) {
        asOrgNode = &kb_itr_key(asOrgNode_t, &itr);
        kb_itr_next(asOrgTree, asOrgTree, &itr);  // move on
        return asOrgNode;
    } else {
        return NULL;
    }

}  // End of NextasOrgNode

/*
 * Flat cache write / load / free
 */

// Sort all flat arrays by network address (ascending).
// Must be called before any binary-search lookup and before WriteFlatCache.
void SortFlatArrays(void) {
    if (!mmFlat) return;
    if (mmFlat->ipV4Count) qsort(mmFlat->ipV4Arr, mmFlat->ipV4Count, sizeof(ipV4Node_t), cmpIpV4);
    if (mmFlat->ipV6Count) qsort(mmFlat->ipV6Arr, mmFlat->ipV6Count, sizeof(ipV6Node_t), cmpIpV6);
    if (mmFlat->asV4Count) qsort(mmFlat->asV4Arr, mmFlat->asV4Count, sizeof(asV4Node_t), cmpAsV4);
    if (mmFlat->asV6Count) qsort(mmFlat->asV6Arr, mmFlat->asV6Count, sizeof(asV6Node_t), cmpAsV6);
    if (mmFlat->asOrgCount) qsort(mmFlat->asOrgArr, mmFlat->asOrgCount, sizeof(asOrgNode_t), cmpAsOrg);
}  // End of SortFlatArrays

// Write a single binary flat-cache file.
// Caller must have called SortFlatArrays() beforehand.
void WriteFlatCache(const char *flatPath) {
    if (!mmFlat) return;

    // build header
    mmFlatHeader_t hdr = {
        .magic = MMFLAT_MAGIC,
        .version = MMFLAT_VERSION,
        .numSections = MMFLAT_NSECT,
        .reserved = 0,
    };

    uint64_t off = sizeof(mmFlatHeader_t);
#define FILL_SEC(IDX, arr, n, type)       \
    hdr.sec[IDX].elemSize = sizeof(type); \
    hdr.sec[IDX].count = (n);             \
    hdr.sec[IDX].offset = off;            \
    off += (uint64_t)(n) * sizeof(type)

    FILL_SEC(MMFLAT_SEC_LOC, mmFlat->locArr, mmFlat->locCount, locationInfo_t);
    FILL_SEC(MMFLAT_SEC_IPV4, mmFlat->ipV4Arr, mmFlat->ipV4Count, ipV4Node_t);
    FILL_SEC(MMFLAT_SEC_IPV6, mmFlat->ipV6Arr, mmFlat->ipV6Count, ipV6Node_t);
    FILL_SEC(MMFLAT_SEC_ASV4, mmFlat->asV4Arr, mmFlat->asV4Count, asV4Node_t);
    FILL_SEC(MMFLAT_SEC_ASV6, mmFlat->asV6Arr, mmFlat->asV6Count, asV6Node_t);
    FILL_SEC(MMFLAT_SEC_ASORG, mmFlat->asOrgArr, mmFlat->asOrgCount, asOrgNode_t);
#undef FILL_SEC

    char tmpPath[PATH_MAX];
    snprintf(tmpPath, sizeof(tmpPath), "%s.tmp", flatPath);
    // Remove any stale tmp file/symlink left over from a previous run, then
    // create fresh with O_EXCL so a pre-existing symlink at this path (e.g.
    // planted in a shared/world-writable cache dir) can't redirect the write.
    unlink(tmpPath);
    int fd = open(tmpPath, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0) {
        LogError("WriteFlatCache: open(%s): %s", tmpPath, strerror(errno));
        return;
    }

    int ok = 1;
#define WRITE_BUF(ptr, sz) \
    if (ok && write(fd, (ptr), (sz)) != (ssize_t)(sz)) ok = 0

    WRITE_BUF(&hdr, sizeof(hdr));
    WRITE_BUF(mmFlat->locArr, mmFlat->locCount * sizeof(locationInfo_t));
    WRITE_BUF(mmFlat->ipV4Arr, mmFlat->ipV4Count * sizeof(ipV4Node_t));
    WRITE_BUF(mmFlat->ipV6Arr, mmFlat->ipV6Count * sizeof(ipV6Node_t));
    WRITE_BUF(mmFlat->asV4Arr, mmFlat->asV4Count * sizeof(asV4Node_t));
    WRITE_BUF(mmFlat->asV6Arr, mmFlat->asV6Count * sizeof(asV6Node_t));
    WRITE_BUF(mmFlat->asOrgArr, mmFlat->asOrgCount * sizeof(asOrgNode_t));
#undef WRITE_BUF

    close(fd);
    if (!ok) {
        unlink(tmpPath);
        LogError("WriteFlatCache: write error");
        return;
    }
    if (rename(tmpPath, flatPath) != 0) {
        unlink(tmpPath);
    }
    dbg_printf("WriteFlatCache: wrote %s\n", flatPath);
}  // End of WriteFlatCache

/* Try to mmap an existing flat cache.  Returns 1 on success. */
int LoadFlatCache(const char *flatPath) {
    int fd = open(flatPath, O_RDONLY);
    if (fd < 0) {
        LogError("open() failed for %s: %s", flatPath, strerror(errno));
        return 0;
    }

    mmFlatHeader_t hdr;
    if (read(fd, &hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr)) {
        LogError("read() error for cache file header");
        close(fd);
        return 0;
    }
    if (hdr.magic != MMFLAT_MAGIC || hdr.version != MMFLAT_VERSION || hdr.numSections != MMFLAT_NSECT) {
        LogError("cache file header error magic/version mismatch");
        close(fd);
        return 0;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return 0;
    }
    size_t mapSize = (size_t)st.st_size;

    void *m = mmap(NULL, mapSize, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (m == MAP_FAILED) {
        LogError("mmap() failed for '%s': %s", flatPath, strerror(errno));
        return 0;
    }

    /* validate section elem sizes */
    if (hdr.sec[MMFLAT_SEC_LOC].elemSize != sizeof(locationInfo_t) || hdr.sec[MMFLAT_SEC_IPV4].elemSize != sizeof(ipV4Node_t) ||
        hdr.sec[MMFLAT_SEC_IPV6].elemSize != sizeof(ipV6Node_t) || hdr.sec[MMFLAT_SEC_ASV4].elemSize != sizeof(asV4Node_t) ||
        hdr.sec[MMFLAT_SEC_ASV6].elemSize != sizeof(asV6Node_t) || hdr.sec[MMFLAT_SEC_ASORG].elemSize != sizeof(asOrgNode_t)) {
        munmap(m, mapSize);
        return 0;
    }

    /* validate every section actually fits inside the mapped file before trusting
     * its offset/count to build pointers - a truncated or crafted .flat file
     * (loadable directly via -G foo.flat) must not let flatSearch*() walk past
     * the mapping. elemSize is already known-small at this point (checked above),
     * so count * elemSize cannot overflow; offset is checked first so the
     * subsequent "mapSize - offset" is always well-defined. */
#define CHECK_SEC(IDX)                                                                                      \
    if (hdr.sec[IDX].offset > mapSize || (uint64_t)hdr.sec[IDX].count * hdr.sec[IDX].elemSize > mapSize - hdr.sec[IDX].offset) { \
        LogError("LoadFlatCache: section %d exceeds file size - corrupt or truncated cache file '%s'", IDX, flatPath);          \
        munmap(m, mapSize);                                                                                                      \
        return 0;                                                                                                                \
    }

    CHECK_SEC(MMFLAT_SEC_LOC);
    CHECK_SEC(MMFLAT_SEC_IPV4);
    CHECK_SEC(MMFLAT_SEC_IPV6);
    CHECK_SEC(MMFLAT_SEC_ASV4);
    CHECK_SEC(MMFLAT_SEC_ASV6);
    CHECK_SEC(MMFLAT_SEC_ASORG);
#undef CHECK_SEC

    mmFlat = calloc(1, sizeof(mmFlat_t));
    if (!mmFlat) {
        munmap(m, mapSize);
        return 0;
    }

    mmFlat->mmapBase = m;
    mmFlat->mmapSize = mapSize;

#define MAP_SEC(IDX, field, countField, type)                  \
    mmFlat->field = (type *)((char *)m + hdr.sec[IDX].offset); \
    mmFlat->countField = hdr.sec[IDX].count

    MAP_SEC(MMFLAT_SEC_LOC, locArr, locCount, locationInfo_t);
    MAP_SEC(MMFLAT_SEC_IPV4, ipV4Arr, ipV4Count, ipV4Node_t);
    MAP_SEC(MMFLAT_SEC_IPV6, ipV6Arr, ipV6Count, ipV6Node_t);
    MAP_SEC(MMFLAT_SEC_ASV4, asV4Arr, asV4Count, asV4Node_t);
    MAP_SEC(MMFLAT_SEC_ASV6, asV6Arr, asV6Count, asV6Node_t);
    MAP_SEC(MMFLAT_SEC_ASORG, asOrgArr, asOrgCount, asOrgNode_t);
#undef MAP_SEC

    /* Rebuild khash localMap from the mmap'd locationInfo section */
    for (uint32_t i = 0; i < mmFlat->locCount; i++) {
        int absent;
        locationKey_t locationKey = {.key = mmFlat->locArr[i].localID};
        khint_t k = kh_put(localMap, mmHandle->localMap, locationKey, &absent);
        if (absent) kh_value(mmHandle->localMap, k) = mmFlat->locArr[i];
    }

    dbg_printf("LoadFlatCache: mmap'd %s: loc=%u ipv4=%u ipv6=%u asv4=%u asv6=%u asorg=%u\n", flatPath, mmFlat->locCount, mmFlat->ipV4Count,
               mmFlat->ipV6Count, mmFlat->asV4Count, mmFlat->asV6Count, mmFlat->asOrgCount);

    BuildTZCache();
    return 1;
}  // End of LoadFlatCache

/* Allocate an empty mmFlat for the slow (nffileV3 load) path */
int InitFlatArrays(void) {
    mmFlat = calloc(1, sizeof(mmFlat_t));
    if (!mmFlat) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }
    return 1;
}  // End of InitFlatArrays

void FreeMaxMind(void) {
    if (tzIndexByLocalID) {
        kh_destroy(tzIndexMap, tzIndexByLocalID);
        tzIndexByLocalID = NULL;
        tzNameCount = 1;
    }
    if (mmFlat) {
        if (mmFlat->mmapBase) {
            munmap(mmFlat->mmapBase, mmFlat->mmapSize);
        } else {
            free(mmFlat->locArr);
            free(mmFlat->ipV4Arr);
            free(mmFlat->ipV6Arr);
            free(mmFlat->asV4Arr);
            free(mmFlat->asV6Arr);
            free(mmFlat->asOrgArr);
        }
        free(mmFlat);
        mmFlat = NULL;
    }
    if (mmHandle) {
        kh_destroy(localMap, mmHandle->localMap);
        kb_destroy(ipV4Tree, mmHandle->ipV4Tree);
        kb_destroy(ipV6Tree, mmHandle->ipV6Tree);
        kb_destroy(asV4Tree, mmHandle->asV4Tree);
        kb_destroy(asV6Tree, mmHandle->asV6Tree);
        kb_destroy(asOrgTree, mmHandle->asOrgTree);
        free(mmHandle);
        mmHandle = NULL;
    }
}  // End of FreeMaxMind
