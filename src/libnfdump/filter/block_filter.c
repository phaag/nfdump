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
 * Derives a blockConstraint_t from the build-time filter tree by abstract
 * interpretation, and provides FilterBlock() to skip entire flow blocks
 * before decompression.
 *
 * Future bloom-filter support (per-block src/dst IP bloom filter probing)
 * should be added here.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

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

    // visited array: one byte per possible node index
    uint32_t maxNodes = memblocks * MAXBLOCKS;
    uint8_t *visited = calloc(maxNodes, sizeof(uint8_t));
    if (!visited) return;

    nodeConstraint_t nc = walkTree(root, visited, 0);
    free(visited);

    if (nc.unknown) return;  // leave out->unknown = true

    out->unknown = false;
    out->msecFirst_lt = nc.msecFirst_lt;
    out->msecFirst_gt = nc.msecFirst_gt;
    out->msecLast_lt = nc.msecLast_lt;
    out->msecLast_gt = nc.msecLast_gt;
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
 * Returns 0 (skip block) if the block's time boundaries guarantee that no
 * flow record inside can match the filter.  Returns 1 (keep block) in all
 * other cases, including when no useful constraint was derived (unknown).
 *
 * blockMsecFirst: min(flow.msecFirst) across all flows in the block.
 * blockMsecLast:  max(flow.msecLast)  across all flows in the block.
 *
 * Each constraint field is checked independently.  All checks must pass
 * (logical AND) for the block to be kept.  A field value of 0 means
 * "not constrained" and is skipped.
 *
 * Rule derivation (bF = blockMsecFirst, bL = blockMsecLast):
 *
 *  msecFirst_lt: derived from "flow.msecFirst < T" atoms.
 *    Any flow satisfying this has flow.msecFirst < T.
 *    The block's earliest start is bF, so if bF >= T no flow can satisfy.
 *    → skip if bF >= msecFirst_lt   (keep if bF < msecFirst_lt)
 *
 *  msecFirst_gt: derived from "flow.msecFirst > T" atoms.
 *    Any matching flow has flow.msecFirst > T.
 *    The block's latest end is bL >= flow.msecFirst, so if bL <= T no flow qualifies.
 *    → skip if bL <= msecFirst_gt   (keep if bL > msecFirst_gt)
 *
 *  msecLast_lt: derived from "flow.msecLast < T" atoms.
 *    Any matching flow has flow.msecLast < T.
 *    Since bF <= flow.msecLast, if bF >= T no flow can qualify.
 *    → skip if bF >= msecLast_lt    (keep if bF < msecLast_lt)
 *
 *  msecLast_gt: derived from "flow.msecLast > T" atoms.
 *    Any matching flow has flow.msecLast > T.
 *    Since bL >= flow.msecLast, if bL <= T no flow can qualify.
 *    → skip if bL <= msecLast_gt    (keep if bL > msecLast_gt)
 *
 * Future bloom filter fields would be evaluated here in an analogous way:
 * probe the bloom; if the answer is "definitely not present" return 0.
 */
int FilterBlock(const void *enginePtr, uint64_t blockMsecFirst, uint64_t blockMsecLast) {
    if (!enginePtr) return 1;  // no engine → keep

    // corrupt block
    if (blockMsecFirst > blockMsecLast) return 1;

    const FilterEngine_t *engine = (const FilterEngine_t *)enginePtr;
    const blockConstraint_t *bc = &engine->blockConstraint;

    if (bc->unknown) return 1;  // no useful constraint → keep

    // blockMsecFirst = 0 and blockMsecLast = 0: no time metadata, keep
    if (blockMsecFirst == 0 && blockMsecLast == 0) return 1;

    // flow start lower bound: keep if bF < msecFirst_lt
    if (bc->msecFirst_lt && blockMsecFirst >= bc->msecFirst_lt) return 0;

    // flow start upper bound: keep if bL > msecFirst_gt
    if (bc->msecFirst_gt && blockMsecLast <= bc->msecFirst_gt) return 0;

    // flow end lower bound: keep if bF < msecLast_lt
    if (bc->msecLast_lt && blockMsecFirst >= bc->msecLast_lt) return 0;

    // flow end upper bound: keep if bL > msecLast_gt
    if (bc->msecLast_gt && blockMsecLast <= bc->msecLast_gt) return 0;

    /* Future bloom filter checks go here */

    return 1;  // block may contain matching flows
}  // End of FilterBlock
