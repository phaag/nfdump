/*
 *  Copyright (c) 2024-2026, Peter Haag
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

/*
 * Block-level pre-filter.
 *
 * Two independent analyses run over the build-time filter tree:
 *
 * 1. Time-range constraint (walkTree / ncAND / ncOR):
 *    Abstract interpretation of the boolean tree deriving conservative
 *    bounds on block.msecFirst / block.msecLast.
 *
 * 2. IP address constraint (collectIPsFromTree):
 *    Collects up to BLOCK_IP_MAX exact host addresses from CMP_EQ and
 *    CMP_IPLIST atoms on EXipv4FlowID / EXipv6FlowID.  At query time
 *    these are probed against the per-block src/dst bloom filters.
 *    The block is skipped only when every address is definitively absent
 *    from the appropriate bloom.
 *
 *    OR / AND boolean structure of the filter is not tracked; all IPs
 *    are collected with OR probe semantics (any hit → keep block).
 *    This is always conservative: it may keep blocks unnecessarily but
 *    never skips a block that has a matching flow.
 *
 *    CIDR entries (CMP_NET) and inverted atoms are not extracted.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "filter_int.h"
#include "nfxV4.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * Block-level constraint extraction.
 *
 * Traverses the build-time filterElement_t tree recursively and derives a
 * conservative blockConstraint_t that can skip entire flow blocks.
 *
 * The constraint is conservative: it may produce false positives (keeping
 * blocks that ultimately yield no matching flows) but never false negatives
 * (skipping a block that would have yielded a match).
 *
 * Algorithm:
 *   Each tree node is either a leaf (single test) or an internal node that
 *   has children via OnTrue/OnFalse links built by Connect_AND / Connect_OR.
 *
 *   To determine whether two subtrees are AND-connected or OR-connected we
 *   inspect the parent node's links and the leaf's invert flag:
 *     - non-inverted leaf: OnTrue → child means AND, OnFalse → child means OR
 *     - inverted leaf:     OnFalse→ child means AND, OnTrue → child means OR
 *
 *   Merging rules:
 *     AND: take the TIGHTER (more restrictive) bound from both sides.
 *          An UNKNOWN arm (no time constraint) does not poison the AND –
 *          the other arm's constraint still applies.
 *     OR:  take the LOOSER (less restrictive) bound.
 *          An UNKNOWN arm on either side of OR forces UNKNOWN for the
 *          whole OR result – we cannot skip the block.
 *
 *   Negation (invert flag on a leaf):
 *     The invert flag is per-leaf and is already set by Invert() before
 *     this function is called.  We apply De Morgan's transformation:
 *       not (msecFirst > T)  →  msecFirst <= T
 *       not (msecFirst < T)  →  msecFirst >= T
 *     and so on for every comparator. The block-level constraint for the
 *     negated atom is derived from the flipped comparator.
 *
 *   Nodes that are neither msecFirst nor msecLast atoms yield UNKNOWN.
 *   Any OR branch with an UNKNOWN arm yields UNKNOWN for that OR.
 *
 * Future bloom filter extension:
 *   Add fields to blockConstraint_t and handle the relevant extID/offset
 *   combinations in the leaf analysis section below.  The AND/OR/NOT
 *   merge logic remains the same.
 * ═══════════════════════════════════════════════════════════════════════════ */

// Internal representation while traversing the tree.
typedef struct nodeConstraint_s {
    bool unknown;           // if true: no useful time constraint for this subtree
    uint64_t msecFirst_lt;  // keep if block.msecFirst < value  (0=unset)
    uint64_t msecFirst_gt;  // keep if block.msecLast  > value  (0=unset)
    uint64_t msecLast_lt;   // keep if block.msecFirst < value  (0=unset)
    uint64_t msecLast_gt;   // keep if block.msecLast  > value  (0=unset)
} nodeConstraint_t;

// UNKNOWN singleton for clarity
static const nodeConstraint_t NC_UNKNOWN = {.unknown = true};

// merge two constraints with AND semantics: take the tighter bound.
static nodeConstraint_t ncAND(nodeConstraint_t a, nodeConstraint_t b) {
    if (a.unknown && b.unknown) return NC_UNKNOWN;

    // AND with unknown: the known side still constrains
    if (a.unknown) return b;
    if (b.unknown) return a;

    nodeConstraint_t r = {.unknown = false};

    // msecFirst_lt: keep if block.msecFirst < value.
    // tighter = smaller value (harder to satisfy).
    if (a.msecFirst_lt && b.msecFirst_lt)
        r.msecFirst_lt = (a.msecFirst_lt < b.msecFirst_lt) ? a.msecFirst_lt : b.msecFirst_lt;
    else
        r.msecFirst_lt = a.msecFirst_lt ? a.msecFirst_lt : b.msecFirst_lt;

    // msecFirst_gt: keep if block.msecLast > value.
    // tighter = larger value.
    if (a.msecFirst_gt && b.msecFirst_gt)
        r.msecFirst_gt = (a.msecFirst_gt > b.msecFirst_gt) ? a.msecFirst_gt : b.msecFirst_gt;
    else
        r.msecFirst_gt = a.msecFirst_gt ? a.msecFirst_gt : b.msecFirst_gt;

    // msecLast_lt: keep if block.msecFirst < value. Tighter = smaller.
    if (a.msecLast_lt && b.msecLast_lt)
        r.msecLast_lt = (a.msecLast_lt < b.msecLast_lt) ? a.msecLast_lt : b.msecLast_lt;
    else
        r.msecLast_lt = a.msecLast_lt ? a.msecLast_lt : b.msecLast_lt;

    // msecLast_gt: keep if block.msecLast > value. Tighter = larger.
    if (a.msecLast_gt && b.msecLast_gt)
        r.msecLast_gt = (a.msecLast_gt > b.msecLast_gt) ? a.msecLast_gt : b.msecLast_gt;
    else
        r.msecLast_gt = a.msecLast_gt ? a.msecLast_gt : b.msecLast_gt;

    return r;
}  // End of ncAND

// Merge two constraints with OR semantics: take the looser bound.
// any UNKNOWN arm makes the whole OR UNKNOWN. */
static nodeConstraint_t ncOR(nodeConstraint_t a, nodeConstraint_t b) {
    if (a.unknown || b.unknown) return NC_UNKNOWN;

    nodeConstraint_t r = {.unknown = false};

    // msecFirst_lt: looser = larger value (easier to satisfy).
    if (a.msecFirst_lt && b.msecFirst_lt) r.msecFirst_lt = (a.msecFirst_lt > b.msecFirst_lt) ? a.msecFirst_lt : b.msecFirst_lt;
    // if only one side has the constraint, OR means we must keep always
    else if (a.msecFirst_lt || b.msecFirst_lt)
        return NC_UNKNOWN;

    // msecFirst_gt: looser = smaller value.
    if (a.msecFirst_gt && b.msecFirst_gt)
        r.msecFirst_gt = (a.msecFirst_gt < b.msecFirst_gt) ? a.msecFirst_gt : b.msecFirst_gt;
    else if (a.msecFirst_gt || b.msecFirst_gt)
        return NC_UNKNOWN;

    // msecLast_lt: looser = larger value.
    if (a.msecLast_lt && b.msecLast_lt)
        r.msecLast_lt = (a.msecLast_lt > b.msecLast_lt) ? a.msecLast_lt : b.msecLast_lt;
    else if (a.msecLast_lt || b.msecLast_lt)
        return NC_UNKNOWN;

    // msecLast_gt: looser = smaller value.
    if (a.msecLast_gt && b.msecLast_gt)
        r.msecLast_gt = (a.msecLast_gt < b.msecLast_gt) ? a.msecLast_gt : b.msecLast_gt;
    else if (a.msecLast_gt || b.msecLast_gt)
        return NC_UNKNOWN;

    return r;
}  // End of ncOR

/*
 * Analyse a single leaf node and return the conservative block constraint it
 * implies, taking the node's invert flag into account.
 *
 * Mapping from filter atom to block-level condition:
 *
 *  flow.msecFirst > T   → keep if block.msecLast  > T  (msecFirst_gt = T)
 *  flow.msecFirst >= T  → keep if block.msecLast  >= T (msecFirst_gt = T-1, use GT)
 *  flow.msecFirst < T   → keep if block.msecFirst < T  (msecFirst_lt = T)
 *  flow.msecFirst <= T  → keep if block.msecFirst <= T (msecFirst_lt = T+1, use LT)
 *  flow.msecFirst == T  → keep if block spans T:
 *                          msecFirst_gt = T-1  AND  msecFirst_lt = T+1
 *
 *  (same logic for msecLast with msecLast_gt / msecLast_lt)
 *
 * When the atom is inverted the effective comparator flips:
 *   not (field > T)  →  field <= T
 *   not (field < T)  →  field >= T
 *   not (field >= T) →  field <  T
 *   not (field <= T) →  field >  T
 *   not (field == T) →  field != T  → UNKNOWN (cannot derive a bound)
 */
static nodeConstraint_t analyseLeaf(const filterElement_t *e) {
    if (e->extID != EXgenericFlowID) return NC_UNKNOWN;
    if (e->function != FUNC_NONE) return NC_UNKNOWN;

    bool isMsecFirst = (e->offset == OFFmsecFirst);
    bool isMsecLast = (e->offset == OFFmsecLast);
    if (!isMsecFirst && !isMsecLast) return NC_UNKNOWN;

    // determine effective comparator after applying invert
    comparator_t comp = e->comp;
    if (e->invert) {
        switch (comp) {
            case CMP_GT:
                comp = CMP_LE;
                break;
            case CMP_LT:
                comp = CMP_GE;
                break;
            case CMP_GE:
                comp = CMP_LT;
                break;
            case CMP_LE:
                comp = CMP_GT;
                break;
            case CMP_EQ:
                return NC_UNKNOWN; /* not (field == T) → no useful bound */
            default:
                return NC_UNKNOWN;
        }
    }

    uint64_t T = e->value;
    nodeConstraint_t r = {.unknown = false};

    if (isMsecFirst) {
        switch (comp) {
            case CMP_GT:
                // msecFirst > T  → keep if bL > T
                r.msecFirst_gt = T;
                break;
            case CMP_GE:
                // msecFirst >= T → keep if bL >= T  ≡ bL > T-1
                r.msecFirst_gt = (T > 0) ? T - 1 : 0;
                break;
            case CMP_LT:
                // msecFirst < T  → keep if bF < T
                r.msecFirst_lt = T;
                break;
            case CMP_LE:
                // msecFirst <= T → keep if bF <= T  ≡ bF < T+1
                r.msecFirst_lt = T + 1;
                break;
            case CMP_EQ:
                // msecFirst == T → keep if bF <= T && bL >= T
                r.msecFirst_lt = T + 1;
                r.msecFirst_gt = (T > 0) ? T - 1 : 0;
                break;
            default:
                return NC_UNKNOWN;
        }
    } else {  // isMsecLast
        switch (comp) {
            case CMP_GT:
                // msecLast > T  → keep if bL > T
                r.msecLast_gt = T;
                break;
            case CMP_GE:
                // msecLast >= T → keep if bL >= T  ≡ bL > T-1
                r.msecLast_gt = (T > 0) ? T - 1 : 0;
                break;
            case CMP_LT:
                // msecLast < T  → keep if bF < T  (bF ≤ any msecLast)
                r.msecLast_lt = T;
                break;
            case CMP_LE:
                // msecLast <= T → keep if bF <= T  ≡ bF < T+1
                r.msecLast_lt = T + 1;
                break;
            case CMP_EQ:
                // msecLast == T → keep if bF <= T && bL >= T
                r.msecLast_lt = T + 1;
                r.msecLast_gt = (T > 0) ? T - 1 : 0;
                break;
            default:
                return NC_UNKNOWN;
        }
    }

    return r;
}  // End of analyseLeaf

/* ═══════════════════════════════════════════════════════════════════════════
 * IP address extraction.
 *
 * collectIPsFromTree() walks the build-time tree with a simple iterative
 * DFS and gathers exact host addresses for later bloom probing.
 *
 * Encoding of IP addresses in filter tree nodes (from grammar.y):
 *
 *   IPv4 exact (CMP_EQ):
 *     extID  = EXipv4FlowID
 *     offset = OFFsrc4Addr (src) or OFFdst4Addr (dst)
 *     length = SIZEsrc4Addr (4)
 *     value  = IPv4 address as uint64_t (low 32 bits, network byte order)
 *
 *   IPv6 exact (CMP_EQ): two AND-connected nodes per address
 *     Node A: extID=EXipv6FlowID, offset=OFFsrc6Addr, length=8,  value=high64
 *     Node B: extID=EXipv6FlowID, offset=OFFsrc6Addr+8, length=8, value=low64
 *     Node A's OnTrue points to Node B (non-inverted) or OnFalse (inverted).
 *
 *   IPv4/IPv6 list (CMP_IPLIST):
 *     extID  = EXipv4FlowID or EXipv6FlowID
 *     offset = OFFsrc4/6Addr (src) or OFFdst4/6Addr (dst)
 *     data.dataPtr = IPlist_t * (RB-tree of IPListNode) — valid before
 *                    generateByteCode() converts it to IPSet_t.
 *     The IPlist_t is shared between the IPv4 and IPv6 filter nodes;
 *     each node interprets the entries for its own address family.
 *
 *   Only non-inverted atoms are extracted (inverted = NOT conditions
 *   cannot be expressed as bloom probes).
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Append an IPv4 address to the constraint list, deduplicating by address.
 * If the same address already exists with a different direction, the
 * directions are merged (OR'd) into a single BLOOM_DIR_BOTH entry.
 */
static void addIPv4(blockConstraint_t *out, uint8_t dir, uint32_t v4) {
    for (int i = 0; i < out->ipCount; i++) {
        if (!out->ips[i].isIPv6 && out->ips[i].v4 == v4) {
            out->ips[i].dir |= dir;
            return;
        }
    }
    if (out->ipCount >= BLOCK_IP_MAX) return;
    out->ips[out->ipCount++] = (blockIPEntry_t){.dir = dir, .isIPv6 = 0, .v4 = v4};
    out->hasIPConstraint = true;
}

/*
 * Append an IPv6 address to the constraint list, deduplicating by address.
 * v6 points to 16 bytes in network byte order matching EXipv6Flow_t layout.
 */
static void addIPv6(blockConstraint_t *out, uint8_t dir, const uint8_t v6[16]) {
    for (int i = 0; i < out->ipCount; i++) {
        if (out->ips[i].isIPv6 && memcmp(out->ips[i].v6, v6, 16) == 0) {
            out->ips[i].dir |= dir;
            return;
        }
    }
    if (out->ipCount >= BLOCK_IP_MAX) return;
    blockIPEntry_t *e = &out->ips[out->ipCount++];
    e->dir = dir;
    e->isIPv6 = 1;
    memcpy(e->v6, v6, 16);
    out->hasIPConstraint = true;
}

/*
 * Iterate an IPlist_t RB-tree and extract exact-host entries for IPv4.
 * Entries where ip[0] != 0 (IPv6-only) are skipped: the IPv6 IPLIST node
 * will handle them.  CIDR entries (mask != all-ones) are skipped.
 */
static void extractFromIPListV4(const IPlist_t *list, uint8_t dir, blockConstraint_t *out) {
    struct IPListNode *node;
    RB_FOREACH(node, IPtree, (IPlist_t *)(uintptr_t)list) {
        if (out->ipCount >= BLOCK_IP_MAX) return;
        /* Only exact-host entries */
        if (node->mask[0] != 0xffffffffffffffffULL || node->mask[1] != 0xffffffffffffffffULL) continue;
        /* IPv4 entries have ip[0]==0; ip[1] holds the address in low 32 bits */
        if (node->ip[0] != 0) continue;
        addIPv4(out, dir, (uint32_t)(node->ip[1]));
    }
}

/*
 * Iterate an IPlist_t RB-tree and extract exact-host entries for IPv6.
 * Entries with ip[0]==0 are IPv4-style entries already handled by the
 * IPv4 node; skip them here.  CIDR entries are skipped.
 */
static void extractFromIPListV6(const IPlist_t *list, uint8_t dir, blockConstraint_t *out) {
    struct IPListNode *node;
    RB_FOREACH(node, IPtree, (IPlist_t *)(uintptr_t)list) {
        if (out->ipCount >= BLOCK_IP_MAX) return;
        if (node->mask[0] != 0xffffffffffffffffULL || node->mask[1] != 0xffffffffffffffffULL) continue;
        if (node->ip[0] == 0) continue; /* IPv4 entry — handled by IPv4 node */
        addIPv6(out, dir, (const uint8_t *)node->ip);
    }
}

/*
 * Examine one filter tree node and, if it is an extractable IP atom,
 * record the address(es) in *out.
 *
 * IPv4 CMP_EQ:   single node, value = address.
 * IPv6 CMP_EQ:   current node is the high-64-bit half; peek at its
 *                AND-connected child for the low half, then store both.
 * CMP_IPLIST:    iterate the shared IPlist_t for the matching family.
 *
 * Only non-inverted atoms are collected; inverted = NOT(ip == X) gives
 * no useful bloom bound.
 */
static void extractIPAtom(uint32_t idx, blockConstraint_t *out) {
    const filterElement_t *e = &FilterTree[idx];

    if (e->invert) return;           /* NOT conditions: no useful bound */
    if (e->function != FUNC_NONE) return; /* derived functions: skip   */

    /* ── IPv4 exact match ─────────────────────────────────────────── */
    if (e->extID == EXipv4FlowID && e->comp == CMP_EQ && e->length == SIZEsrc4Addr) {
        uint8_t dir = (e->offset == OFFsrc4Addr) ? BLOOM_DIR_SRC : BLOOM_DIR_DST;
        addIPv4(out, dir, (uint32_t)(e->value));
        return;
    }

    /* ── IPv6 exact match — high-64-bit half ─────────────────────── */
    /*
     * IPv6 addresses are split across two AND-connected nodes by the grammar:
     *   Node A: offset == OFFsrc6Addr,     value = ipaddr[0] (high 64 bits)
     *   Node B: offset == OFFsrc6Addr + 8, value = ipaddr[1] (low  64 bits)
     * Connect_AND sets A.OnTrue = B (non-inverted) before any outer connections
     * overwrite A's OnFalse.  We detect Node A, verify Node B via OnTrue, and
     * assemble the full 128-bit address.
     */
    if (e->extID == EXipv6FlowID && e->comp == CMP_EQ && e->length == sizeof(uint64_t) &&
        (e->offset == OFFsrc6Addr || e->offset == OFFdst6Addr)) {
        uint32_t loIdx = e->OnTrue; /* non-inverted: AND child is at OnTrue */
        if (loIdx == 0 || loIdx >= (uint32_t)(memblocks * MAXBLOCKS)) return;
        const filterElement_t *lo = &FilterTree[loIdx];
        /* Verify the child is the paired low-half node */
        if (lo->extID != EXipv6FlowID || lo->comp != CMP_EQ ||
            lo->length != sizeof(uint64_t) || lo->offset != e->offset + sizeof(uint64_t))
            return;
        uint8_t dir = (e->offset == OFFsrc6Addr) ? BLOOM_DIR_SRC : BLOOM_DIR_DST;
        /* Assemble 16-byte address: high half then low half, matching
         * EXipv6Flow_t layout (uint64_t[2] in native byte order).     */
        uint8_t v6[16];
        memcpy(v6,     &e->value,  8);
        memcpy(v6 + 8, &lo->value, 8);
        addIPv6(out, dir, v6);
        return;
    }

    /* ── IPv4 IP list ─────────────────────────────────────────────── */
    if (e->extID == EXipv4FlowID && e->comp == CMP_IPLIST && e->data.dataPtr != NULL) {
        uint8_t dir = (e->offset == OFFsrc4Addr) ? BLOOM_DIR_SRC : BLOOM_DIR_DST;
        extractFromIPListV4((const IPlist_t *)e->data.dataPtr, dir, out);
        return;
    }

    /* ── IPv6 IP list ─────────────────────────────────────────────── */
    if (e->extID == EXipv6FlowID && e->comp == CMP_IPLIST && e->data.dataPtr != NULL) {
        uint8_t dir = (e->offset == OFFsrc6Addr) ? BLOOM_DIR_SRC : BLOOM_DIR_DST;
        extractFromIPListV6((const IPlist_t *)e->data.dataPtr, dir, out);
        return;
    }
}

/*
 * Iterative DFS over the build-time filter tree starting at 'root'.
 * Visits every reachable node exactly once and calls extractIPAtom()
 * on each.  Stops early when BLOCK_IP_MAX addresses have been collected.
 *
 * Uses a heap-allocated visited array and stack to avoid unbounded
 * C-stack usage and to handle DAG sharing correctly.
 */
#define IP_COLLECT_STACK_MAX 2048

static void collectIPsFromTree(uint32_t root, blockConstraint_t *out) {
    if (root == 0 || FilterTree == NULL) return;

    uint32_t maxNodes = (uint32_t)(memblocks * MAXBLOCKS);

    uint8_t *visited = calloc(maxNodes, 1);
    if (!visited) return;

    /* Fixed-size stack is sufficient: real filter trees are always small. */
    uint32_t stack[IP_COLLECT_STACK_MAX];
    int top = 0;
    stack[top++] = root;

    while (top > 0 && out->ipCount < BLOCK_IP_MAX) {
        uint32_t idx = stack[--top];
        if (idx == 0 || idx >= maxNodes) continue;
        if (visited[idx]) continue;
        visited[idx] = 1;

        extractIPAtom(idx, out);

        const filterElement_t *e = &FilterTree[idx];
        if (e->OnFalse && top < IP_COLLECT_STACK_MAX - 1) stack[top++] = e->OnFalse;
        if (e->OnTrue  && top < IP_COLLECT_STACK_MAX - 1) stack[top++] = e->OnTrue;
    }

    free(visited);
}  /* End of collectIPsFromTree */

/*
 * Recursively walk the build-time filter tree rooted at node index 'idx'
 * and return the merged block constraint.
 *
 * To avoid infinite loops (the tree can form a DAG when nodes are shared),
 * 'visited' is a simple bit array tracking which node indices have been
 * started.  We use a depth bound as a safety net.
 */
#define EXTRACT_MAX_DEPTH 512

static nodeConstraint_t walkTree(uint32_t idx, uint8_t *visited, int depth) {
    if (idx == 0 || depth > EXTRACT_MAX_DEPTH) return NC_UNKNOWN;
    if (visited[idx]) return NC_UNKNOWN;  // back edge / shared node: be safe
    visited[idx] = 1;

    const filterElement_t *e = &FilterTree[idx];

    /*
     * Leaf node: no children connected yet (OnTrue == OnFalse == 0).
     * A "leaf" can also have children that were connected by Connect_AND/OR
     * after the grammar added it.  We check both cases.
     */
    bool hasOnTrue = (e->OnTrue != 0);
    bool hasOnFalse = (e->OnFalse != 0);

    // Derive this node's own leaf constraint
    nodeConstraint_t self = analyseLeaf(e);

    if (!hasOnTrue && !hasOnFalse) {
        // pure leaf
        visited[idx] = 0;  // allow revisit via different paths
        return self;
    }

    /*
     * Determine the connection type to children:
     *
     * For a non-inverted node:
     *   OnTrue  child → AND semantics  (the child is evaluated on success)
     *   OnFalse child → OR  semantics  (the child is evaluated on failure)
     *
     * For an inverted node the jump targets are swapped:
     *   OnFalse child → AND semantics
     *   OnTrue  child → OR  semantics
     */
    nodeConstraint_t result = self;

    if (!e->invert) {
        if (hasOnTrue) {
            nodeConstraint_t childNC = walkTree(e->OnTrue, visited, depth + 1);
            result = ncAND(result, childNC);
        }
        if (hasOnFalse) {
            nodeConstraint_t childNC = walkTree(e->OnFalse, visited, depth + 1);
            result = ncOR(result, childNC);
        }
    } else {
        if (hasOnFalse) {
            nodeConstraint_t childNC = walkTree(e->OnFalse, visited, depth + 1);
            result = ncAND(result, childNC);
        }
        if (hasOnTrue) {
            nodeConstraint_t childNC = walkTree(e->OnTrue, visited, depth + 1);
            result = ncOR(result, childNC);
        }
    }

    visited[idx] = 0;  // allow revisit via different paths if DAG */
    return result;
}  // End of walkTree

/*
 * ExtractBlockFilter – derive the block-level constraint from the
 * build-time filter tree.  Must be called after yyparse() and before
 * generateByteCode() (the tree is freed by generateByteCode()).
 *
 * Writes the result into *out.  On any error writes unknown=true.
 */
void ExtractBlockFilter(uint32_t root, blockConstraint_t *out) {
    *out = (blockConstraint_t){.unknown = true};
    if (root == 0 || FilterTree == NULL) return;

    /* ── Time-range constraint (abstract interpretation) ── */
    uint32_t maxNodes = memblocks * MAXBLOCKS;
    uint8_t *visited = calloc(maxNodes, sizeof(uint8_t));
    if (!visited) return;

    nodeConstraint_t nc = walkTree(root, visited, 0);
    free(visited);

    if (!nc.unknown) {
        out->unknown = false;
        out->msecFirst_lt = nc.msecFirst_lt;
        out->msecFirst_gt = nc.msecFirst_gt;
        out->msecLast_lt = nc.msecLast_lt;
        out->msecLast_gt = nc.msecLast_gt;
    }

    /* ── IP address extraction for bloom probing ── */
    collectIPsFromTree(root, out);
}  // End of ExtractBlockFilter

/*
 * GetBlockConstraint – return the block-level constraint stored in the engine.
 * The returned pointer is owned by the engine; do not free it.
 * Returns NULL if engine is NULL.
 */
const blockConstraint_t *GetBlockConstraint(const void *engine) {
    if (!engine) return NULL;
    return &((const FilterEngine_t *)engine)->blockConstraint;
}  // End of GetBlockConstraint

/*
 * FilterBlock – block-level pre-filter.
 *
 * Two checks are applied in order; either can independently reject the block.
 *
 * ── Time-range check ──
 * Only active when bc->unknown == false (a useful time constraint exists).
 * Skipped when blockMsecFirst == blockMsecLast == 0 (no time metadata) or
 * when blockMsecFirst > blockMsecLast (corrupt header: skip time check only).
 *
 * ── IP bloom check ──
 * Active when bc->hasIPConstraint == true AND bh != NULL.
 * Independent of bc->unknown: a filter "src ip 1.2.3.4" has no time atoms
 * (unknown==true) but does have an IP constraint.
 *
 * The block is skipped (return 0) only when EVERY queried IP is definitively
 * absent from all available bloom filters.  Conservative cases that keep the
 * block:
 *   • bh == NULL          (block carries no META bloom records)
 *   • all bloom ptrs NULL (META records not yet present for this block)
 *   • no bloom available for an entry's direction/family
 *   • any probe returns 1 ("probably present")
 */
int FilterBlock(const void *enginePtr, uint64_t blockMsecFirst, uint64_t blockMsecLast,
                const bloomHandle_t *bh) {
    if (!enginePtr) return 1;

    const FilterEngine_t *engine = (const FilterEngine_t *)enginePtr;
    const blockConstraint_t *bc = &engine->blockConstraint;

    /* ── Time-range checks ── */
    if (!bc->unknown && blockMsecFirst <= blockMsecLast) {
        if (blockMsecFirst != 0 || blockMsecLast != 0) {  // skip if no time metadata
            if (bc->msecFirst_lt && blockMsecFirst >= bc->msecFirst_lt) return 0;
            if (bc->msecFirst_gt && blockMsecLast  <= bc->msecFirst_gt) return 0;
            if (bc->msecLast_lt  && blockMsecFirst >= bc->msecLast_lt)  return 0;
            if (bc->msecLast_gt  && blockMsecLast  <= bc->msecLast_gt)  return 0;
        }
    }

    /* ── IP bloom checks ── */
    if (bc->hasIPConstraint && bh) {
        int anyPresent = 0;
        for (int i = 0; i < bc->ipCount && !anyPresent; i++) {
            const blockIPEntry_t *e = &bc->ips[i];
            int entryHasBloom = 0;

            if (!e->isIPv6) {
                if ((e->dir & BLOOM_DIR_SRC) && bh->srcIPv4bloom) {
                    entryHasBloom = 1;
                    if (BloomLookupIPv4(bh->srcIPv4bloom, e->v4)) anyPresent = 1;
                }
                if (!anyPresent && (e->dir & BLOOM_DIR_DST) && bh->dstIPv4bloom) {
                    entryHasBloom = 1;
                    if (BloomLookupIPv4(bh->dstIPv4bloom, e->v4)) anyPresent = 1;
                }
            } else {
                if ((e->dir & BLOOM_DIR_SRC) && bh->srcIPv6bloom) {
                    entryHasBloom = 1;
                    if (BloomLookupIPv6(bh->srcIPv6bloom, e->v6)) anyPresent = 1;
                }
                if (!anyPresent && (e->dir & BLOOM_DIR_DST) && bh->dstIPv6bloom) {
                    entryHasBloom = 1;
                    if (BloomLookupIPv6(bh->dstIPv6bloom, e->v6)) anyPresent = 1;
                }
            }
            /* No bloom available for this entry's direction/family:
             * cannot conclude the IP is absent — keep conservatively. */
            if (!entryHasBloom) anyPresent = 1;
        }
        if (!anyPresent) return 0;  // every IP definitively absent → skip
    }

    return 1;
}  // End of FilterBlock
