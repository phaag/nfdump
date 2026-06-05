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
 * Private internal header shared between filter.c and block_filter.c.
 * Not part of the public API – do not include from outside the filter/
 * subdirectory.
 */

#ifndef _FILTER_INT_H
#define _FILTER_INT_H 1

#include <stdbool.h>
#include <stdint.h>

#include "filter.h" /* comparator_t, filterFunction_t, data_t, blockConstraint_t, … */

#define MAXBLOCKS 1024

// build-time tree node (freed after generateByteCode)
typedef struct filterElement {
    uint32_t extID;
    uint32_t offset;
    uint32_t length;
    uint64_t value;
    uint32_t superblock;
    uint32_t *blocklist;
    uint32_t geoLookup;
    uint32_t numblocks;
    uint32_t OnTrue, OnFalse;
    int16_t invert;
    uint16_t option;
    comparator_t comp;
    filterFunction_t function;
    data_t data;
} filterElement_t;

/* ── Runtime instruction ───────────────────────────────────────────────── */
/*
 * 40 bytes on 64-bit, 36 bytes on 32-bit (= 32 + sizeof(void *)).
 *
 *  op        filterOp_t – selects computed-goto label (stored as uint16_t)
 *  extID     index into handle->extensionList[]
 *  fnID      filterFunction_t – index into flow_procs_map[] for FOP_FUNC_*
 *  length    field byte width (1/2/4/8); 0 = extension-present check
 *  option    filterOption_t – passed to preprocess for FOP_PREP_*
 *  offset    byte offset within the extension struct (fits in uint16_t)
 *  onTrue    program index to jump to when result == 1  (0 = ACCEPT)
 *  onFalse   program index to jump to when result == 0  (1 = REJECT)
 *  value     comparison value or pre-masked network address
 *  aux       data pointer: IPSet_t*, U64Set_t*, char*, srx_Context*, …
 *            – OR –
 *  dataVal   auxiliary integer: subnet mask, geo direction, fn data.dataVal
 *            (aux and dataVal are in a union; no op uses both)
 */
typedef struct filterInstr_s {
    const void *handler;  // direct-threaded label address – goto *inst->handler
    uint16_t op;          // opcode (kept for DumpEngine / DisposeFilter)
    uint8_t extID;
    uint8_t fnID;
    uint8_t length;
    uint8_t option;
    uint16_t offset;
    uint16_t onTrue;
    uint16_t onFalse;
    uint32_t _pad;  // explicit padding – keeps value 8-byte aligned
    uint64_t value;
    union {
        uintptr_t aux;    // data pointer
        int64_t dataVal;  // mask / direction / fnData.dataVal
    };
} filterInstr_t;

/*
 * runtime engine
 * prog[] is immutable after CompileFilter() and shared between the original
 * and all FilterCloneEngine() copies (thread-safe).
 * Only ident is per-clone (strdup'd).
 */
typedef struct FilterEngine_s {
    filterInstr_t *prog;  // bytecode program – shared, read-only
    uint32_t progLen;     // number of instructions (includes terminals)
    uint32_t startNode;
    int hasGeoDB;
    const char *ident;
    blockConstraint_t blockConstraint;  // derived block-level pre-filter
} FilterEngine_t;

// module globals defined in filter.c
extern filterElement_t *FilterTree;
extern uint32_t memblocks;

/* ── Internal API: called by filter.c, implemented in block_filter.c ──── */
/*
 * Derive the block-level constraint from the build-time filter tree.
 * Must be called after yyparse() and before generateByteCode().
 * Writes the result into *out; sets out->unknown = true on any error.
 */
void ExtractBlockFilter(uint32_t root, blockConstraint_t *out);

#endif /* _FILTER_INT_H */
