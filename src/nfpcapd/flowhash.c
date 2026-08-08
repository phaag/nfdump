/*
 *  Copyright (c) 2011-2026, Peter Haag
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

#include "flowhash.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#ifdef HAVE_LIBBSD
#include <bsd/stdlib.h>
#endif
#include "ip_frag.h"
#include "logging.h"
#include "nfdump.h"
#include "util.h"

/* hash slot */
typedef struct {
    uint64_t hash;
    struct FlowNode *node;
} FlowSlot;

/* open-addressing hash table */
#define LOAD_FACTOR_NUM 7
#define LOAD_FACTOR_DEN 10
#define DefaultHashSize 1024

typedef struct FlowHash_s {
    FlowSlot *slots;
    uint32_t capacity;   // power of two
    uint32_t mask;       // capacity - 1
    uint32_t size;       // active entries
    uint32_t resize_at;  // threshold
    uint32_t seed;
} FlowHash_t;

// Time wheel
typedef struct TimeWheelSlot {
    struct FlowNode *head;
} TimeWheelSlot;

typedef struct TimeWheel {
    TimeWheelSlot *slots;
    uint32_t size;     // number of slots
    uint32_t current;  // current slot index
} TimeWheel_t;

static FlowHash_t FlowHashTable = {0};
static TimeWheel_t FlowWheel = {0};

// hash
static int Hash_Init(FlowHash_t *h, uint32_t initial_capacity);

static void Hash_Destroy(FlowHash_t *h);

static int Hash_Resize(FlowHash_t *h, uint32_t new_cap);

static struct FlowNode *Hash_Lookup(FlowHash_t *h, const struct flowKey_s *key, uint64_t hash);

static struct FlowNode *Hash_Insert(FlowHash_t *h, struct FlowNode *node, const struct flowKey_s *key, uint64_t hash);

static void Hash_Remove(FlowHash_t *h, struct FlowNode *node, const struct flowKey_s *key, uint64_t hash);

// timewheel
static int TimeWheel_Init(TimeWheel_t *w, uint32_t size);

static void TimeWheel_Destroy(TimeWheel_t *tw);

static inline void TimeWheel_Insert(TimeWheel_t *tw, struct FlowNode *node, time_t now);

static inline void TimeWheel_Remove(TimeWheel_t *tw, struct FlowNode *node);

// node cache
static int Extend_NodeCache(uint32_t capacity);

static void DumpTreeStat(NodeList_t *NodeList);

static size_t NodeList_length(NodeList_t *NodeList);

// Flow Cache to store all nodes
#define DefaultExpireInterval 5
#define MaxExpireInterval 60
#define DefaultCacheSize 8192
#define DefaultMaxFlowNodes 262144
#define ExtentSize 4096
static uint32_t MaxFlowNodes = DefaultMaxFlowNodes;
static uint64_t MaxFlowPayloadBytes = 64ULL * 1024ULL * 1024ULL;
static time_t lastWheelTick = 0;
static time_t lastMaintenance = 0;
static bool wheelClockValid = false;
static uint32_t expireActiveTimeout = 300;
static uint32_t expireInactiveTimeout = 60;
static uint32_t expireInterval = DefaultExpireInterval;

static _Atomic uint32_t Allocated = 0;
static _Atomic uint64_t PayloadBytes = 0;
static _Atomic uint64_t PayloadHighWater = 0;
static _Atomic uint64_t PayloadDrops = 0;
static _Atomic uint64_t NodeLimitDrops = 0;

static struct FlowSlab *SlabList = NULL;
static struct FlowSlab *PreferredSlab = NULL;
static _Atomic(struct FlowNode *) GlobalFree = NULL;

static uint32_t FlowCacheSize = 0;
static pthread_t PacketThreadID;
static uint32_t LastExpireCount = 0;
static time_t LastShrinkCheck = 0;

static uint32_t expireRun = 0;
static uint32_t checkRun = 0;

/*
 * node cache
 * The node cache builds up on a list of slabs. Each slab has ExtentSize nodes.
 * The minimum node cache size is DefaultCacheSize nodes.
 * New slabs may be allocated, if more node are required (busy network, or packet peak)
 * Empty slabs are freed, if they are no longer needed.
 * The current implementation works under the current design:
 * 1 packet thread, 1 flow thread
 * All slab maintainance such as Extend_NodeCache Shrink_NodeCache, drain GlobalFree and
 * New_Node are touched exclusively by the packet thread and the flow thread exclusively
 * calls Free_node() and atomically add the freed node to GlobalFree. If this changes
 * the design needs to be adapted accordingly.
 */

// include hash function in same compiler unit
#include "metrohash.c"

static flowHashStat_t flowHashStat = {0};

int Init_FlowHash(uint32_t cacheSize, uint32_t expireActive, uint32_t expireInactive, uint32_t interval, uint32_t maxNodes,
                  uint64_t maxPayloadBytes) {
    if (expireActive) {
        expireActiveTimeout = expireActive;
        LogInfo("Set active flow expire timeout to %us", expireActiveTimeout);
    }

    if (expireInactive) {
        expireInactiveTimeout = expireInactive;
        LogInfo("Set inactive flow expire timeout to %us", expireInactiveTimeout);
    }

    if (interval == 0) interval = DefaultExpireInterval;
    uint32_t shortest_timeout = expireActiveTimeout < expireInactiveTimeout ? expireActiveTimeout : expireInactiveTimeout;
    if (interval > MaxExpireInterval || interval > shortest_timeout) {
        LogError("Invalid flow cache expire interval %us; allowed range is 1..%us", interval,
                 shortest_timeout < MaxExpireInterval ? shortest_timeout : MaxExpireInterval);
        return 0;
    }
    expireInterval = interval;
    LogInfo("Set flow cache expire interval to %us", expireInterval);

    if (maxNodes < DefaultCacheSize) {
        LogError("Flow cache maximum %u is below the minimum cache size %u", maxNodes, DefaultCacheSize);
        return 0;
    }
    MaxFlowNodes = maxNodes;
    MaxFlowPayloadBytes = maxPayloadBytes;
    atomic_store_explicit(&PayloadBytes, 0, memory_order_relaxed);
    atomic_store_explicit(&PayloadHighWater, 0, memory_order_relaxed);
    atomic_store_explicit(&PayloadDrops, 0, memory_order_relaxed);
    atomic_store_explicit(&NodeLimitDrops, 0, memory_order_relaxed);
    LogInfo("Set flow cache limits: nodes=%u, payload=%" PRIu64 " bytes", MaxFlowNodes, MaxFlowPayloadBytes);

    // flow hash
    uint32_t hashSize = DefaultHashSize;
    if (Hash_Init(&FlowHashTable, hashSize) == 0) return 0;

    uint32_t max_timeout = expireActiveTimeout > expireInactiveTimeout ? expireActiveTimeout : expireInactiveTimeout;
    // Timewheel
    if (!TimeWheel_Init(&FlowWheel, max_timeout)) return 0;

    // node cache
    if (cacheSize == 0) cacheSize = DefaultCacheSize;
    if (cacheSize > MaxFlowNodes) {
        LogError("Initial flow cache size %u exceeds configured maximum %u", cacheSize, MaxFlowNodes);
        return 0;
    }
    while (FlowCacheSize < cacheSize)
        if (!Extend_NodeCache(cacheSize - FlowCacheSize < ExtentSize ? cacheSize - FlowCacheSize : ExtentSize)) return 0;

    Allocated = 0;
    PreferredSlab = SlabList;

    LogInfo("Init flow hash: %u, node cache: %u", hashSize, FlowCacheSize);
    return 1;
}  // End of Init_FlowHash

static int Hash_Init(FlowHash_t *h, uint32_t cap) {
    if (cap < 1024) cap = 1024;
    if ((cap & (cap - 1)) != 0) return false;

    h->slots = calloc(cap, sizeof(FlowSlot));
    if (!h->slots) return false;

    h->capacity = cap;
    h->mask = cap - 1;
    h->size = 0;
    h->resize_at = (cap * LOAD_FACTOR_NUM) / LOAD_FACTOR_DEN;
    h->seed = arc4random();

    return 1;
}  // End of Hash_Init

static int Hash_Resize(FlowHash_t *h, uint32_t new_cap) {
    /* enforce power-of-two */
    if ((new_cap & (new_cap - 1)) != 0) return false;

    FlowSlot *old_slots = h->slots;
    uint32_t old_cap = h->capacity;

    LogVerbose("Hash resize: %u -> %u", old_cap, new_cap);

    FlowSlot *new_slots = calloc(new_cap, sizeof(FlowSlot));
    if (!new_slots) return 0;

    uint32_t new_mask = new_cap - 1;

    /* rehash all live entries */
    for (uint32_t i = 0; i < old_cap; i++) {
        FlowSlot *s = &old_slots[i];
        if (!s->node) continue;

        uint64_t hash = s->hash;
        uint32_t idx = hash & new_mask;

        for (;;) {
            FlowSlot *ns = &new_slots[idx];
            if (!ns->node) {
                ns->hash = hash;
                ns->node = s->node;
                break;
            }
            idx = (idx + 1) & new_mask;
        }
    }

    /* publish new table */
    h->slots = new_slots;
    h->capacity = new_cap;
    h->mask = new_mask;
    h->resize_at = (new_cap * LOAD_FACTOR_NUM) / LOAD_FACTOR_DEN;
    /* h->size unchanged */

    free(old_slots);
    return 1;
}  // End of Hash_Resize

static void Hash_Destroy(FlowHash_t *h) {
    free(h->slots);
    memset(h, 0, sizeof(*h));
}  // End of Hash_Destroy

/* lookup */
static struct FlowNode *Hash_Lookup(FlowHash_t *h, const struct flowKey_s *key, uint64_t hash) {
    size_t keylen = sizeof(struct flowKey_s);
    uint32_t idx = hash & h->mask;

    for (;;) {
        FlowSlot *s = &h->slots[idx];

        if (!s->node) return NULL;

        if (s->hash == hash && memcmp(&s->node->hotNode.flowKey, key, keylen) == 0) return s->node;

        idx = (idx + 1) & h->mask;
    }
}  // End of Hash_Lookup

/* insert */
static struct FlowNode *Hash_Insert(FlowHash_t *h, struct FlowNode *node, const struct flowKey_s *key, uint64_t hash) {
    size_t keylen = sizeof(struct flowKey_s);
    if (h->size >= h->resize_at) {
        if (!Hash_Resize(h, h->capacity * 2)) {
            LogError("Hash_Resize() failed");
            // treat as insertion failure: return existing node as non-NULL to indicate no insert
            return node;
        }
    }

    uint32_t idx = hash & h->mask;

    for (;;) {
        FlowSlot *s = &h->slots[idx];

        if (!s->node) {
            s->hash = hash;
            s->node = node;
            h->size++;

            return NULL;
        }

        if (s->hash == hash && memcmp(&s->node->hotNode.flowKey, key, keylen) == 0) return s->node;

        idx = (idx + 1) & h->mask;
    }
}  // End of Hash_Insert

/* backward-shift delete */
static void Hash_Remove(FlowHash_t *h, struct FlowNode *node, const struct flowKey_s *key, uint64_t hash) {
    uint32_t idx = hash & h->mask;

    for (;;) {
        FlowSlot *s = &h->slots[idx];
        // NULL entry node with hash not found in table
        if (!s->node) return;

        // node found - correct entry at idx
        if (s->node == node) break;

        idx = (idx + 1) & h->mask;
    }

    // remove slot
    uint32_t hole = idx;
    uint32_t next = (hole + 1) & h->mask;

    while (h->slots[next].node) {
        uint32_t ideal = h->slots[next].hash & h->mask;

        if ((ideal <= hole && hole < next) || (next < ideal && (ideal <= hole || hole < next))) {
            h->slots[hole] = h->slots[next];
            hole = next;
        }
        next = (next + 1) & h->mask;
    }

    h->slots[hole].node = NULL;
    h->size--;
}  // End of Hash_Remove

static int TimeWheel_Init(TimeWheel_t *tw, uint32_t max_timeout) {
    uint32_t size = max_timeout + 1;  // 2..300 → up to 301 slots
    tw->slots = calloc(size, sizeof(TimeWheelSlot));
    if (!tw->slots) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }
    tw->size = size;
    tw->current = 0;
    dbg_printf("Init time wheel: %u\n", size);
    return 1;
}  // End of TimeWheel_Init

static void TimeWheel_Destroy(TimeWheel_t *tw) {
    if (!tw) return;

    if (tw->slots) free(tw->slots);
    tw->size = 0;
    tw->current = 0;

}  // End of TimeWheel_Destroy

static inline time_t flow_next_expire(const struct FlowNode *node) {
    time_t inactive_expire = node->hotNode.t_last.tv_sec + expireInactiveTimeout;
    time_t active_expire = node->hotNode.t_first.tv_sec + expireActiveTimeout;

    return inactive_expire < active_expire ? inactive_expire : active_expire;
}  // End of flow_next_expire

static inline void TimeWheel_Insert(TimeWheel_t *tw, struct FlowNode *node, time_t now) {
    time_t expire_at = flow_next_expire(node);
    if (expire_at < now) expire_at = now;

    // dbg - node must ot be in wheel
    dbg_assert(node->wheel_prev_next == NULL);

    uint32_t slot = (uint32_t)(expire_at % tw->size);
    struct FlowNode *head = tw->slots[slot].head;

    node->wheel_next = head;
    node->wheel_prev_next = &tw->slots[slot].head;
    node->wheel_slot = slot;

    if (head) head->wheel_prev_next = &node->wheel_next;

    tw->slots[slot].head = node;
}  // End of TimeWheel_Insert

static inline void TimeWheel_Remove(TimeWheel_t *tw, struct FlowNode *node) {
    (void)tw;  // unused for now

    // Node is not in the wheel → nothing to do
    if (!node->wheel_prev_next) return;

    struct FlowNode *next = node->wheel_next;

    *node->wheel_prev_next = next;

    if (next) next->wheel_prev_next = node->wheel_prev_next;

    node->wheel_next = NULL;
    node->wheel_prev_next = NULL;
}  // End of TimeWheel_Remove

void TimeWheel_Reschedule(struct FlowNode *node, time_t now) {
    TimeWheel_t *tw = &FlowWheel;
    TimeWheel_Remove(tw, node);
    TimeWheel_Insert(tw, node, now);
}  // End of TimeWheel_Reschedule

void Init_NodeAllocator(void) {
    // self
    PacketThreadID = pthread_self();
}  // End of Init_NodeAllocator

static void drain_global_free(void) {
    struct FlowNode *list = atomic_exchange_explicit(&GlobalFree, NULL, memory_order_acquire);

    while (list) {
        struct FlowNode *n = list;
        list = n->next;

        struct FlowSlab *s = n->slab;

        n->next = s->local_free;
        s->local_free = n;

        atomic_fetch_sub_explicit(&s->free_pending, 1, memory_order_relaxed);
        atomic_fetch_sub_explicit(&s->in_use, 1, memory_order_relaxed);
        atomic_fetch_sub_explicit(&Allocated, 1, memory_order_relaxed);
    }
}  // End of drain_global_free

void Dispose_NodeAllocator(void) {
    // At this point both packet and flow threads are stopped.
    // It is now safe to drain the global free list one last time.
    drain_global_free();

    // Free all slabs in the main slab list
    struct FlowSlab *s = SlabList;
    while (s) {
        struct FlowSlab *next = s->next;

        uint32_t in_use = atomic_load_explicit(&s->in_use, memory_order_relaxed);
        uint32_t free_pending = atomic_load_explicit(&s->free_pending, memory_order_relaxed);

        if (in_use != 0 || free_pending != 0) {
            LogError("Dispose_NodeAllocator(): slab still has in_use=%u, free_pending=%u", in_use, free_pending);
        }

        free(s);
        s = next;
    }

    SlabList = NULL;
    PreferredSlab = NULL;

    // Global counters
    FlowCacheSize = 0;
    Allocated = 0;

    uint64_t payloadBytes = atomic_load_explicit(&PayloadBytes, memory_order_relaxed);
    if (payloadBytes != 0) LogError("Dispose_NodeAllocator(): %" PRIu64 " payload bytes still allocated", payloadBytes);
    LogInfo("Flow cache payload: limit=%" PRIu64 " high-water=%" PRIu64 " dropped=%" PRIu64, MaxFlowPayloadBytes,
            atomic_load_explicit(&PayloadHighWater, memory_order_relaxed), atomic_load_explicit(&PayloadDrops, memory_order_relaxed));
    if (atomic_load_explicit(&NodeLimitDrops, memory_order_relaxed))
        LogInfo("Flow cache node-limit drops: %" PRIu64, atomic_load_explicit(&NodeLimitDrops, memory_order_relaxed));

    // Global free list should be empty now
    struct FlowNode *leftover = atomic_load_explicit(&GlobalFree, memory_order_relaxed);
    if (leftover) {
        LogError("Dispose_NodeAllocator(): GlobalFree not empty at shutdown");
    }
    atomic_store_explicit(&GlobalFree, NULL, memory_order_relaxed);

    dbg_printf("CheckCache: %u, ExpireCache: %u\n", checkRun, expireRun);
}  // End of Dispose_NodeAllocator

void Dispose_FlowTree(void) {
    // when called all node should have been drained already by Hash_Flush()

    // return nodes in global free list
    drain_global_free();

    uint32_t allocated = atomic_load_explicit(&Allocated, memory_order_relaxed);
    dbg_printf("Hash stat - flow nodes: %zu, total: %zu\n", flowHashStat.flowNodes, flowHashStat.activeNodes);
    if (allocated != 0) {
        LogError("Dispose_FlowTree() left %u node unprocessed", allocated);
    }

    Dispose_NodeAllocator();
    Hash_Destroy(&FlowHashTable);
    TimeWheel_Destroy(&FlowWheel);

}  // End of Dispose_FlowTree

struct FlowNode *New_Node(void) {
    struct FlowSlab *s;

    // Packet thread only
    // Try preferred slab first
    s = PreferredSlab;
    if (s && s->local_free) {
        struct FlowNode *n = s->local_free;
        s->local_free = n->next;

        atomic_fetch_add_explicit(&s->in_use, 1, memory_order_relaxed);
        atomic_fetch_add_explicit(&Allocated, 1, memory_order_relaxed);

        n->next = NULL;
        n->memflag = NODE_IN_USE;
        n->nodeType = FLOW_NODE;
        return n;
    }

    // If preferred slab is empty, try draining global free list
    drain_global_free();

    // Try preferred slab again after draining
    s = PreferredSlab;
    if (s && s->local_free) {
        struct FlowNode *n = s->local_free;
        s->local_free = n->next;

        atomic_fetch_add_explicit(&s->in_use, 1, memory_order_relaxed);
        atomic_fetch_add_explicit(&Allocated, 1, memory_order_relaxed);

        n->next = NULL;
        n->memflag = NODE_IN_USE;
        n->nodeType = FLOW_NODE;
        return n;
    }

    // Fallback: scan all slabs
    for (s = SlabList; s; s = s->next) {
        if (!s->local_free) continue;

        PreferredSlab = s;

        struct FlowNode *n = s->local_free;
        s->local_free = n->next;

        atomic_fetch_add_explicit(&s->in_use, 1, memory_order_relaxed);
        atomic_fetch_add_explicit(&Allocated, 1, memory_order_relaxed);

        n->next = NULL;
        n->memflag = NODE_IN_USE;
        n->nodeType = FLOW_NODE;
        return n;
    }

    // No free nodes anywhere: extend cache within the configured budget.
    if (FlowCacheSize >= MaxFlowNodes) {
        atomic_fetch_add_explicit(&NodeLimitDrops, 1, memory_order_relaxed);
        // Packet thread only - a plain static is safe, and rate-limiting is
        // required here: under sustained overload this branch can be hit
        // millions of times per run (empirically confirmed under stress).
        static time_t lastNodeLimitLog = 0;
        time_t now = time(NULL);
        if (now != lastNodeLimitLog) {
            LogError(
                "Flow cache exhausted: %u active flows (limit flowcache.max_nodes=%u) - dropping new flows. "
                "Increase with -x flowcache.max_nodes=<n> or flowcache.max_nodes in nfdump.conf",
                FlowCacheSize, MaxFlowNodes);
            lastNodeLimitLog = now;
        }
        return NULL;
    }

    uint32_t available = MaxFlowNodes - FlowCacheSize;
    if (!Extend_NodeCache(available < ExtentSize ? available : ExtentSize)) return NULL;

    // New slab added at head of SlabList
    PreferredSlab = SlabList;

    // Guaranteed to succeed now
    s = PreferredSlab;
    struct FlowNode *n = s->local_free;
    s->local_free = n->next;

    atomic_fetch_add_explicit(&s->in_use, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&Allocated, 1, memory_order_relaxed);

    n->next = NULL;
    n->memflag = NODE_IN_USE;
    n->nodeType = FLOW_NODE;
    return n;
}  // ENd of New_Node

// return node into free list
void Free_Node(struct FlowNode *node) {
    dbg_printf("Enter %s\n", __func__);

    if (node->memflag != NODE_IN_USE) {
        LogError("Free_Node() Fatal: Tried to free a node not in use");
        abort();
    }

    // cleanup node
    if (node->coldNode.payload) {
        ReleaseFlowPayload(node->coldNode.payloadSize);
        free(node->coldNode.payload);
    }
    memset(&node->hotNode, 0, sizeof(hotNode_t));
    memset(&node->coldNode, 0, sizeof(coldNode_t));

    struct FlowSlab *s = node->slab;

    node->memflag = NODE_FREE;

    atomic_fetch_add_explicit(&s->free_pending, 1, memory_order_relaxed);

    // push to global free list
    struct FlowNode *old;
    do {
        old = atomic_load_explicit(&GlobalFree, memory_order_acquire);
        node->next = old;
    } while (!atomic_compare_exchange_weak_explicit(&GlobalFree, &old, node, memory_order_release, memory_order_relaxed));

}  // End of Free_Node

static int Extend_NodeCache(uint32_t capacity) {
    if (capacity == 0) return 0;

    struct FlowSlab *slab = calloc(1, sizeof(struct FlowSlab) + (size_t)capacity * sizeof(struct FlowNode));
    if (!slab) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    slab->capacity = capacity;
    atomic_init(&slab->in_use, 0);
    atomic_init(&slab->free_pending, 0);

    for (uint32_t i = 0; i < capacity; i++) {
        slab->nodes[i].slab = slab;
        slab->nodes[i].memflag = NODE_FREE;
        slab->nodes[i].next = slab->local_free;
        slab->local_free = &slab->nodes[i];
    }

    slab->next = SlabList;
    SlabList = slab;
    FlowCacheSize += capacity;

    LogVerbose("Extended cache slab: %u -> %u", FlowCacheSize - capacity, FlowCacheSize);
    return 1;
}  // End of Extend_NodeCache

bool ReserveFlowPayload(size_t payloadSize) {
    if (payloadSize == 0) return true;

    uint64_t requested = payloadSize;
    uint64_t used = atomic_load_explicit(&PayloadBytes, memory_order_relaxed);
    for (;;) {
        if (requested > MaxFlowPayloadBytes || used > MaxFlowPayloadBytes - requested) {
            atomic_fetch_add_explicit(&PayloadDrops, 1, memory_order_relaxed);
            // AddPayload() (pcaproc.c) is packet-thread only, so this plain
            // static is safe. Rate-limited for the same reason as the
            // node-limit log: this can be hit millions of times per run.
            static time_t lastPayloadLimitLog = 0;
            time_t now = time(NULL);
            if (now != lastPayloadLimitLog) {
                LogError(
                    "Flow payload budget exhausted: %" PRIu64 " bytes in use (limit flowcache.max_payload_bytes=%" PRIu64
                    ") - dropping payload capture for new flows. Increase with -x flowcache.max_payload_bytes=<n> or "
                    "flowcache.max_payload_bytes in nfdump.conf",
                    used, MaxFlowPayloadBytes);
                lastPayloadLimitLog = now;
            }
            return false;
        }
        if (atomic_compare_exchange_weak_explicit(&PayloadBytes, &used, used + requested, memory_order_relaxed, memory_order_relaxed)) {
            uint64_t highWater = atomic_load_explicit(&PayloadHighWater, memory_order_relaxed);
            while (used + requested > highWater &&
                   !atomic_compare_exchange_weak_explicit(&PayloadHighWater, &highWater, used + requested, memory_order_relaxed,
                                                          memory_order_relaxed)) {
            }
            return true;
        }
    }
}  // End of ReserveFlowPayload

void ReleaseFlowPayload(size_t payloadSize) {
    if (payloadSize) atomic_fetch_sub_explicit(&PayloadBytes, payloadSize, memory_order_relaxed);
}  // End of ReleaseFlowPayload

// packet thread only
static void Shrink_NodeCache(time_t now) {
    if ((now - LastShrinkCheck) < 30) return;
    LastShrinkCheck = now;

    // First reclaim all nodes freed by the flow thread
    drain_global_free();

    uint32_t allocated = atomic_load_explicit(&Allocated, memory_order_relaxed);
    uint32_t slack = FlowCacheSize - allocated;

    // Only shrink if we have at least one full slab of slack
    // and never shrink below the default cache size
    if (slack < ExtentSize || FlowCacheSize <= DefaultCacheSize) return;

    uint32_t min_size = DefaultCacheSize;

    struct FlowSlab **pp = &SlabList;
    uint32_t oldCacheSize = FlowCacheSize;
    uint32_t freedSlabs = 0;

    while (*pp && FlowCacheSize > min_size) {
        struct FlowSlab *s = *pp;

        uint32_t in_use = atomic_load_explicit(&s->in_use, memory_order_relaxed);
        uint32_t free_pending = atomic_load_explicit(&s->free_pending, memory_order_relaxed);

        if (in_use == 0 && free_pending == 0) {
            // Safe to free slab: no nodes in use, none in flight
            *pp = s->next;
            FlowCacheSize -= s->capacity;
            free(s);
            freedSlabs++;
            continue;
        }

        pp = &s->next;
    }

    LogVerbose("Adjust cache slab: %u -> %u. Slabs freed: %u", oldCacheSize, FlowCacheSize, freedSlabs);
}

/*
 * Detach a slot before processing it.  A flow which is not due (possible with
 * out-of-order packet timestamps) can then be inserted into its new slot
 * without changing the list currently being walked.
 */
static struct FlowNode *Detach_WheelSlot(uint32_t slot) {
    struct FlowNode *node = FlowWheel.slots[slot].head;
    FlowWheel.slots[slot].head = NULL;

    for (struct FlowNode *n = node; n; n = n->wheel_next) n->wheel_prev_next = NULL;

    return node;
}  // End of Detach_WheelSlot

static uint32_t Expire_FlowList(NodeList_t *NodeList, struct FlowNode *node, time_t when) {
    uint32_t flowCnt = 0;
    while (node) {
        struct FlowNode *next = node->wheel_next;

        time_t expire_at = flow_next_expire(node);

        if (when >= expire_at || when == 0) {
            // The node was detached from the wheel before this walk.
            Remove_Node(node);

            Push_Node(NodeList, node);
            flowCnt++;
        } else {
            // Not expired yet → reschedule into the correct future slot.
            TimeWheel_Insert(&FlowWheel, node, when);
        }

        node = next;
    }

    return flowCnt;
}  // End of Expire_FlowList

/*
 * Advance the wheel from the last processed timestamp through 'when'.  Under
 * normal traffic this touches one empty slot per elapsed second, rather than
 * scanning the full wheel on every maintenance run.  After a jump spanning a
 * complete wheel, detach every slot first so a future-dated flow cannot be
 * visited again after it is rescheduled.
 */
static uint32_t Expire_FlowTree(NodeList_t *NodeList, time_t from, time_t when) {
    if (when <= from || FlowWheel.size == 0) return 0;

    FlowWheel.current = (uint32_t)(when % FlowWheel.size);
    uint32_t flowCnt = 0;

    if ((uint64_t)(when - from) >= FlowWheel.size) {
        struct FlowNode *allNodes = NULL;

        for (uint32_t slot = 0; slot < FlowWheel.size; slot++) {
            struct FlowNode *node = Detach_WheelSlot(slot);
            while (node) {
                struct FlowNode *next = node->wheel_next;
                node->wheel_next = allNodes;
                allNodes = node;
                node = next;
            }
        }
        flowCnt = Expire_FlowList(NodeList, allNodes, when);
    } else {
        for (time_t tick = from; tick < when;) {
            tick++;
            uint32_t slot = (uint32_t)(tick % FlowWheel.size);
            flowCnt += Expire_FlowList(NodeList, Detach_WheelSlot(slot), when);
        }
    }

    if (flowCnt) {
        LogVerbose("Expired flow nodes: %u. Active flow nodes: %d", flowCnt, flowHashStat.flowNodes);
        LogVerbose("Node cache size: %u, allocated %u, cache size: %zd, queue size: %zu", FlowCacheSize, Allocated, flowHashStat.activeNodes,
                   NodeList_length(NodeList));
    }

    return flowCnt;
}  // End of Expire_FlowTree

void CacheCheck(NodeList_t *NodeList, time_t when) {
    if (!wheelClockValid) {
        MaintainIPFragments(when);
        lastWheelTick = when;
        lastMaintenance = when;
        wheelClockValid = true;
        return;
    }
    checkRun++;

    /* Offline pcaps can contain out-of-order timestamps. Never move the
     * wheel backwards: a later packet timestamp will advance it safely. */
    if (when < lastWheelTick) {
        dbg_printf("CacheCheck() - Ignore backward timestamp\n");
        return;
    }

    // Fragment reassembly has its own short, elapsed-time maintenance gate.
    // Keep it independent from the configurable flow expiry batch interval.
    MaintainIPFragments(when);

    if ((uint64_t)(when - lastMaintenance) < expireInterval) {
        dbg_printf("CacheCheck() - Skip cache check\n");
        return;
    }

    expireRun++;
    uint32_t expired = Expire_FlowTree(NodeList, lastWheelTick, when);
    dbg_printf("CacheCheck() expired: %u nodes\n", expired);
    LastExpireCount = expired;
    lastWheelTick = when;
    lastMaintenance = when;

    Shrink_NodeCache(when);
}  // End of CacheCheck

void printFlowKey(struct FlowNode *node) {
    char srcAddr[INET6_ADDRSTRLEN];
    char dstAddr[INET6_ADDRSTRLEN];
    ip128_2_str(&node->hotNode.flowKey.src_addr, srcAddr);
    ip128_2_str(&node->hotNode.flowKey.dst_addr, dstAddr);
    printf("IP: %u, proto: %u, src: %s %u, dst: %s %u, align: %u\n", node->hotNode.flowKey.version, node->hotNode.flowKey.proto, srcAddr,
           node->hotNode.flowKey.src_port, dstAddr, node->hotNode.flowKey.dst_port, node->hotNode.flowKey._ALIGN);
}

void printHash(void) {
    FlowHash_t *h = &FlowHashTable;
    printf("FlowHash %zu nodes:\n", flowHashStat.activeNodes);
    for (uint32_t i = 0; i < h->capacity; i++) {
        FlowSlot *s = &h->slots[i];
        if (!s->node) continue;

        printFlowKey(s->node);
    }
}  // End of printHash

struct FlowNode *Lookup_Node(struct FlowNode *node) {
    const uint8_t *key = (uint8_t *)&node->hotNode.flowKey;
    uint64_t hash = metrohash64_1(key, sizeof(struct flowKey_s), FlowHashTable.seed);
    return Hash_Lookup(&FlowHashTable, &node->hotNode.flowKey, hash);
}  // End of Lookup_FlowTree

struct FlowNode *Insert_Node(struct FlowNode *node) {
    const uint8_t *key = (uint8_t *)&node->hotNode.flowKey;
    uint64_t hash = metrohash64_1(key, sizeof(struct flowKey_s), FlowHashTable.seed);
    node->hotNode.hash = hash;

    dbg_assert(node->next == NULL);

    struct FlowNode *n = Hash_Insert(&FlowHashTable, node, &node->hotNode.flowKey, hash);
    if (n) {  // existing node
        return n;
    } else {
        flowHashStat.activeNodes++;
        flowHashStat.flowNodes++;
        node->inTree = 1;
        // schedule timewheel
        TimeWheel_Insert(&FlowWheel, node, node->hotNode.t_last.tv_sec);
        return NULL;
    }
}  // End of Insert_Node

void Remove_Node(struct FlowNode *node) {
    struct FlowNode *rev_node;

    assert(node->inTree == 1);

    dbg_assert(node->memflag == NODE_IN_USE);

    rev_node = node->coldNode.rev_node;
    if (rev_node) {
        // unlink rev node on both nodes
        dbg_assert(rev_node->coldNode.rev_node == node);
        rev_node->coldNode.rev_node = NULL;
        node->coldNode.rev_node = NULL;
    }

    Hash_Remove(&FlowHashTable, node, &node->hotNode.flowKey, node->hotNode.hash);
    TimeWheel_Remove(&FlowWheel, node);

    flowHashStat.activeNodes--;
    flowHashStat.flowNodes--;

    node->inTree = 0;

}  // End of Remove_Node

int Link_RevNode(struct FlowNode *node) {
    struct FlowNode lookup_node, *rev_node;

    dbg_printf("Link node: ");
    dbg_assert(node->coldNode.rev_node == NULL);
    lookup_node.hotNode.flowKey = (struct flowKey_s){.proto = node->hotNode.flowKey.proto,
                                                     .version = node->hotNode.flowKey.version,
                                                     // reverse lookup key to find reverse node
                                                     .src_addr = node->hotNode.flowKey.dst_addr,
                                                     .dst_addr = node->hotNode.flowKey.src_addr,
                                                     .src_port = node->hotNode.flowKey.dst_port,
                                                     .dst_port = node->hotNode.flowKey.src_port,
                                                     ._ALIGN = 0};
    rev_node = Lookup_Node(&lookup_node);
    if (rev_node) {
        dbg_printf("Found revnode ");
        // rev node must not be linked already - otherwise there is an inconsistency
        if (node->coldNode.rev_node == NULL) {
            // link both nodes
            node->coldNode.rev_node = rev_node;
            rev_node->coldNode.rev_node = node;
            dbg_printf(" - linked\n");
        } else {
            dbg_printf("Rev-node != NULL skip linking - inconsistency\n");
            LogError("Rev-node != NULL skip linking - inconsistency\n");
        }
        return 1;
    } else {
        dbg_printf("no revnode node\n");
        return 0;
    }

    /* not reached */

}  // End of Link_RevNode

uint32_t Hash_Flush(NodeList_t *NodeList, time_t when) {
    FlowHash_t *h = &FlowHashTable;

    uint32_t drained = 0;

    for (uint32_t i = 0; i < h->capacity; i++) {
        FlowSlot *s = &h->slots[i];
        if (!s->node) continue;

        struct FlowNode *node = s->node;
        s->node = NULL;

        struct FlowNode *rev_node = node->coldNode.rev_node;
        if (rev_node) {
            // unlink rev node on both nodes
            dbg_assert(rev_node->coldNode.rev_node == node);
            rev_node->coldNode.rev_node = NULL;
            node->coldNode.rev_node = NULL;
        }
        node->inTree = 0;

        TimeWheel_Remove(&FlowWheel, node);

        Push_Node(NodeList, node);
        flowHashStat.flowNodes--;
        flowHashStat.activeNodes--;
        drained++;
    }
    LogVerbose("Flushed flow table: %u flows", drained);

    h->size = 0;

    /* push final done signal */
    struct FlowNode *sig = New_Node();
    if (sig) {
        sig->timestamp = when;
        sig->nodeType = SIGNAL_NODE_DONE;
        Push_Node(NodeList, sig);
    } else {
        /* The active flows may consume the entire cache.  Closing the queue
         * still lets the consumer drain them and terminate without a signal
         * node. */
        LogError(
            "Flow cache exhausted: %u active flows (limit flowcache.max_nodes=%u) - closing flow queue without done node. "
            "Increase with -x flowcache.max_nodes=<n> or flowcache.max_nodes in nfdump.conf",
            FlowCacheSize, MaxFlowNodes);
        Close_NodeList(NodeList, when);
    }

    return drained;
}  // End of Hash_Flush

/* Node list functions */
NodeList_t *NewNodeList(size_t maxLength) {
    NodeList_t *NodeList;

    NodeList = (NodeList_t *)malloc(sizeof(NodeList_t));
    if (!NodeList) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }
    NodeList->list = NULL;
    NodeList->last = NULL;
    NodeList->length = 0;
    NodeList->maxLength = maxLength;
    NodeList->highWater = 0;
    NodeList->droppedFlowNodes = 0;
    NodeList->backpressureEvents = 0;
    NodeList->controlWaits = 0;
    NodeList->closed = 0;
    NodeList->closeTimestamp = 0;
    pthread_mutex_init(&NodeList->m_list, NULL);
    pthread_cond_init(&NodeList->c_list, NULL);

    return NodeList;

}  // End of NewNodeList

void DisposeNodeList(NodeList_t *NodeList) {
    if (!NodeList) return;

    if (NodeList->length) {
        LogError("Try to free non empty NodeList");
        return;
    }
    LogInfo("Flow output queue: limit=%zu high-water=%zu dropped=%" PRIu64 " backpressure=%" PRIu64 " control-waits=%" PRIu64,
            NodeList->maxLength, NodeList->highWater, NodeList->droppedFlowNodes, NodeList->backpressureEvents, NodeList->controlWaits);
    pthread_mutex_destroy(&NodeList->m_list);
    pthread_cond_destroy(&NodeList->c_list);
    free(NodeList);

}  // End of DisposeNodeList

static void DumpTreeStat(NodeList_t *NodeList) {
    LogVerbose("Node cache size: %u, in use %u, cache size: %zu, queue size: %zu", FlowCacheSize, Allocated, flowHashStat.activeNodes,
               NodeList_length(NodeList));
}  // End of DumpTreeStat

void Push_Node(NodeList_t *NodeList, struct FlowNode *node) {
    pthread_mutex_lock(&NodeList->m_list);

    dbg_assert(node->nodeType != 0);
    if (node->nodeType == FLOW_NODE && NodeList->length >= NodeList->maxLength) {
        NodeList->droppedFlowNodes++;
        NodeList->backpressureEvents++;
        size_t curLength = NodeList->length;
        size_t maxLength = NodeList->maxLength;
        pthread_mutex_unlock(&NodeList->m_list);

        // Push_Node() is called from the packet thread only (single
        // producer - see the node-cache design note above), so this plain
        // static is safe without extra synchronization. Rate-limited for
        // the same reason as the other two limits: sustained backpressure
        // can hit this branch millions of times per run.
        static time_t lastQueueLimitLog = 0;
        time_t now = time(NULL);
        if (now != lastQueueLimitLog) {
            LogError(
                "Flow output queue full: %zu records queued (limit flowcache.max_output_nodes=%zu) - dropping flow record. "
                "Increase with -x flowcache.max_output_nodes=<n> or flowcache.max_output_nodes in nfdump.conf, or check "
                "whether the writer/sender thread is keeping up",
                curLength, maxLength);
            lastQueueLimitLog = now;
        }
        Free_Node(node);
        return;
    }
    while (node->nodeType != FLOW_NODE && NodeList->length >= NodeList->maxLength && !NodeList->closed) {
        NodeList->backpressureEvents++;
        NodeList->controlWaits++;
        pthread_cond_wait(&NodeList->c_list, &NodeList->m_list);
    }
    if (NodeList->closed) {
        pthread_mutex_unlock(&NodeList->m_list);
        Free_Node(node);
        return;
    }
    if (NodeList->length == 0) {
        NodeList->list = node;
    } else {
        NodeList->last->next = node;
    }
    node->next = NULL;
    NodeList->last = node;
    NodeList->length++;
    if (NodeList->length > NodeList->highWater) NodeList->highWater = NodeList->length;

    pthread_cond_signal(&NodeList->c_list);
    pthread_mutex_unlock(&NodeList->m_list);

}  // End of Push_Node

void Close_NodeList(NodeList_t *NodeList, time_t timestamp) {
    pthread_mutex_lock(&NodeList->m_list);
    NodeList->closed = 1;
    NodeList->closeTimestamp = timestamp;
    pthread_cond_broadcast(&NodeList->c_list);
    pthread_mutex_unlock(&NodeList->m_list);
}  // End of Close_NodeList

struct FlowNode *Pop_Node(NodeList_t *NodeList) {
    struct FlowNode *node;

    pthread_mutex_lock(&NodeList->m_list);
    while (NodeList->length == 0 && !NodeList->closed) {
        pthread_cond_wait(&NodeList->c_list, &NodeList->m_list);
    }

    if (NodeList->length == 0) {
        pthread_mutex_unlock(&NodeList->m_list);
        return NULL;
    }

    node = NodeList->list;
    NodeList->list = node->next;
    node->next = NULL;

    if (NodeList->list == NULL) NodeList->last = NULL;

    NodeList->length--;
    pthread_cond_signal(&NodeList->c_list);
    pthread_mutex_unlock(&NodeList->m_list);

    return node;
}  // End of Pop_Node

static size_t NodeList_length(NodeList_t *NodeList) {
    size_t length = 0;
    pthread_mutex_lock(&NodeList->m_list);
    length = NodeList->length;
    pthread_mutex_unlock(&NodeList->m_list);
    return length;
}  // End of NodeList_length

size_t Pop_Batch(NodeList_t *NodeList, struct FlowNode **out, size_t max) {
    size_t n = 0;

    pthread_mutex_lock(&NodeList->m_list);
    while (NodeList->length == 0 && !NodeList->closed) {
        pthread_cond_wait(&NodeList->c_list, &NodeList->m_list);
    }

    while (n < max && NodeList->length > 0) {
        struct FlowNode *node = NodeList->list;
        NodeList->list = node->next;
        if (NodeList->list == NULL) NodeList->last = NULL;

        NodeList->length--;
        node->next = NULL;
        out[n++] = node;
    }
    if (n) pthread_cond_signal(&NodeList->c_list);
    pthread_mutex_unlock(&NodeList->m_list);

    return n;
}  // End of Pop_Batch

void Push_SyncNode(NodeList_t *NodeList, time_t timestamp) {
    struct FlowNode *Node = New_Node();
    if (!Node) {
        LogError(
            "Flow cache exhausted: %u active flows (limit flowcache.max_nodes=%u) - unable to rotate output. "
            "Increase with -x flowcache.max_nodes=<n> or flowcache.max_nodes in nfdump.conf",
            FlowCacheSize, MaxFlowNodes);
        return;
    }
    Node->timestamp = timestamp;
    Node->nodeType = SIGNAL_NODE_SYNC;
    dbg_printf("Push sync node\n");
    Push_Node(NodeList, Node);
    DumpTreeStat(NodeList);

}  // End of Push_SyncNode
