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
#include "nfdump.h"
#include "nffile.h"
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
static int Extend_NodeCache(void);

static void DumpTreeStat(NodeList_t *NodeList);

static size_t NodeList_length(NodeList_t *NodeList);

// Flow Cache to store all nodes
#define EXPIREINTERVALL 10
#define DefaultCacheSize 8192
#define ExtentSize 4096
#define MaxSize (1024 * 1024 * 512)
static time_t lastExpire = 0;
static uint32_t expireActiveTimeout = 300;
static uint32_t expireInactiveTimeout = 60;

static _Atomic uint32_t Allocated = 0;

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

int Init_FlowHash(uint32_t cacheSize, uint32_t expireActive, uint32_t expireInactive) {
    if (expireActive) {
        expireActiveTimeout = expireActive;
        LogInfo("Set active flow expire timeout to %us", expireActiveTimeout);
    }

    if (expireInactive) {
        expireInactiveTimeout = expireInactive;
        LogInfo("Set inactive flow expire timeout to %us", expireInactiveTimeout);
    }

    // flow hash
    uint32_t hashSize = DefaultHashSize;
    if (Hash_Init(&FlowHashTable, hashSize) == 0) return 0;

    uint32_t max_timeout = expireActiveTimeout > expireInactiveTimeout ? expireActiveTimeout : expireInactiveTimeout;
    // Timewheel
    if (!TimeWheel_Init(&FlowWheel, max_timeout)) return 0;

    // node cache
    if (cacheSize == 0) cacheSize = DefaultCacheSize;
    while (FlowCacheSize < cacheSize)
        if (!Extend_NodeCache()) return 0;

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

void Hash_Destroy(FlowHash_t *h) {
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
struct FlowNode *Hash_Insert(FlowHash_t *h, struct FlowNode *node, const struct flowKey_s *key, uint64_t hash) {
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
void Hash_Remove(FlowHash_t *h, struct FlowNode *node, const struct flowKey_s *key, uint64_t hash) {
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
    dbg_assert(node->wheel_prev_next != NULL);
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

    // No free nodes anywhere: extend cache
    if (FlowCacheSize >= MaxSize) return NULL;

    if (!Extend_NodeCache()) return NULL;

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
    if (node->coldNode.payload) free(node->coldNode.payload);
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

static int Extend_NodeCache(void) {
    struct FlowSlab *slab = calloc(1, sizeof(struct FlowSlab) + ExtentSize * sizeof(struct FlowNode));
    if (!slab) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    slab->capacity = ExtentSize;
    atomic_init(&slab->in_use, 0);
    atomic_init(&slab->free_pending, 0);

    for (uint32_t i = 0; i < ExtentSize; i++) {
        slab->nodes[i].slab = slab;
        slab->nodes[i].memflag = NODE_FREE;
        slab->nodes[i].next = slab->local_free;
        slab->local_free = &slab->nodes[i];
    }

    slab->next = SlabList;
    SlabList = slab;
    FlowCacheSize += ExtentSize;

    LogVerbose("Extended cache slab: %u -> %u", FlowCacheSize - ExtentSize, FlowCacheSize);
    return 1;
}  // End of Extend_NodeCache

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

static uint32_t Expire_FlowTree(NodeList_t *NodeList, time_t when) {
    if (flowHashStat.activeNodes == 0) return 0;

    uint32_t slot = (uint32_t)(when % FlowWheel.size);
    FlowWheel.current = slot;

#ifdef DEVEL
    char buff[20];
    struct tm tmBuff = {0};
    strftime(buff, 20, "%Y-%m-%d %H:%M:%S", localtime_r(&when, &tmBuff));
    printf("TimeWheel expires at: %s, slot: %u\n", buff, slot);
#endif

    // Detach the entire slot list
    struct FlowNode *node = FlowWheel.slots[slot].head;
    FlowWheel.slots[slot].head = NULL;

    uint32_t flowCnt = 0;
    while (node) {
        struct FlowNode *next = node->wheel_next;

        time_t expire_at = flow_next_expire(node);

        if (when >= expire_at || when == 0) {
            // Flow is expired: Remove_Node() will call TimeWheel_Remove()
            Remove_Node(node);

            Push_Node(NodeList, node);
            flowCnt++;
        } else {
            // Not expired yet → reschedule into correct future slot
            TimeWheel_Insert(&FlowWheel, node, when);
        }

        node = next;
    }

    if (flowCnt) {
        LogVerbose("Expired flow nodes: %u. Active flow nodes: %d", flowCnt, flowHashStat.flowNodes);
        LogVerbose("Node cache size: %u, allocated %u, cache size: %zd, queue size: %zu", FlowCacheSize, Allocated, flowHashStat.activeNodes,
                   NodeList_length(NodeList));
    }

    return flowCnt;
}  // End of Expire_FlowTree

void CacheCheck(NodeList_t *NodeList, time_t when) {
    if (lastExpire == 0) {
        lastExpire = when;
        return;
    }
    checkRun++;

    if ((when - lastExpire) > EXPIREINTERVALL) {
        expireRun++;
        uint32_t expired = Expire_FlowTree(NodeList, when);
        dbg_printf("CacheCheck() expired: %u nodes\n", expired);
        LastExpireCount = expired;
        lastExpire = when;

        Shrink_NodeCache(when);
    } else {
        dbg_printf("CacheCheck() - Skip cache check\n");
    }
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
    }

    return drained;
}  // End of Hash_Flush

/* Node list functions */
NodeList_t *NewNodeList(void) {
    NodeList_t *NodeList;

    NodeList = (NodeList_t *)malloc(sizeof(NodeList_t));
    if (!NodeList) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }
    NodeList->list = NULL;
    NodeList->last = NULL;
    NodeList->length = 0;
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
    free(NodeList);

}  // End of DisposeNodeList

static void DumpTreeStat(NodeList_t *NodeList) {
    LogVerbose("Node cache size: %u, in use %u, cache size: %zu, queue size: %zu", FlowCacheSize, Allocated, flowHashStat.activeNodes,
               NodeList_length(NodeList));
}  // End of DumpTreeStat

void Push_Node(NodeList_t *NodeList, struct FlowNode *node) {
    pthread_mutex_lock(&NodeList->m_list);

    dbg_assert(node->nodeType != 0);
    if (NodeList->length == 0) {
        NodeList->list = node;
    } else {
        NodeList->last->next = node;
    }
    node->next = NULL;
    NodeList->last = node;
    NodeList->length++;

    pthread_cond_signal(&NodeList->c_list);
    pthread_mutex_unlock(&NodeList->m_list);

}  // End of Push_Node

struct FlowNode *Pop_Node(NodeList_t *NodeList) {
    struct FlowNode *node;

    pthread_mutex_lock(&NodeList->m_list);
    while (NodeList->length == 0) {
        pthread_cond_wait(&NodeList->c_list, &NodeList->m_list);
    }

    node = NodeList->list;
    NodeList->list = node->next;
    node->next = NULL;

    if (NodeList->list == NULL) NodeList->last = NULL;

    NodeList->length--;
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
    while (NodeList->length == 0) {
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
    pthread_mutex_unlock(&NodeList->m_list);

    return n;
}  // End of Pop_Batch

void Push_SyncNode(NodeList_t *NodeList, time_t timestamp) {
    struct FlowNode *Node = New_Node();
    Node->timestamp = timestamp;
    Node->nodeType = SIGNAL_NODE_SYNC;
    dbg_printf("Push sync node\n");
    Push_Node(NodeList, Node);
    DumpTreeStat(NodeList);

}  // End of Push_SyncNode
