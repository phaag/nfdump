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
 */

/*
 * Conservative block-level interpretation of the record-filter bytecode.
 *
 * A metadata-supported instruction produces the raw outcomes that are still
 * possible for records in the block: false, true, or both. Unsupported
 * instructions and missing metadata always produce both outcomes. The
 * interpreter follows the corresponding bytecode edges and keeps the block as
 * soon as ACCEPT is reachable. Therefore a block is skipped only if every
 * possible path rejects it.
 *
 * Reusing the compiled control-flow graph is important: AND, OR, NOT, nested
 * expressions, and combinations of time/IP/record predicates retain exactly
 * the same short-circuit semantics as FilterRecord().
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "filter_int.h"
#include "nfxV4.h"

#define OUTCOME_FALSE 1u
#define OUTCOME_TRUE 2u
#define OUTCOME_BOTH (OUTCOME_FALSE | OUTCOME_TRUE)

/* Avoid an unbounded stack allocation for deliberately huge filters. Such a
 * filter remains correct; it simply receives no block-level pruning. */
#define BLOCK_PROGRAM_MAX 8192u

static bool isTimeInstruction(const filterInstr_t *inst) {
    if (inst->extID != EXgenericFlowID || (inst->offset != OFFmsecFirst && inst->offset != OFFmsecLast)) return false;

    switch ((filterOp_t)inst->op) {
        case FOP_EQ8:
        case FOP_GT8:
        case FOP_LT8:
        case FOP_GE8:
        case FOP_LE8:
            return true;
        default:
            return false;
    }
}  // End of isTimeInstruction

static bool isIPv4Instruction(const filterInstr_t *inst) {
    return inst->op == FOP_EQ4 && inst->extID == EXipv4FlowID &&
           (inst->offset == OFFsrc4Addr || inst->offset == OFFdst4Addr);
}  // End of isIPv4Instruction

/* Only the first half of an exact IPv6 comparison is considered. The second
 * half is verified through its bytecode target before a full-address Bloom
 * lookup is attempted. */
static bool isIPv6Instruction(const filterInstr_t *inst) {
    return inst->op == FOP_EQ8 && inst->extID == EXipv6FlowID &&
           (inst->offset == OFFsrc6Addr || inst->offset == OFFdst6Addr);
}  // End of isIPv6Instruction

void InitBlockFilter(blockConstraint_t *out, const filterInstr_t *prog, uint32_t progLen) {
    *out = (blockConstraint_t){0};
    if (!prog) return;

    for (uint32_t i = 0; i < progLen; i++) {
        const filterInstr_t *inst = &prog[i];
        if (isTimeInstruction(inst)) out->hasTimeConstraint = true;
        if (isIPv4Instruction(inst) || isIPv6Instruction(inst)) out->hasIPConstraint = true;
    }
}  // End of InitBlockFilter

static uint8_t timeOutcomes(const filterInstr_t *inst, uint64_t lower, uint64_t upper) {
    /* 0/0 denotes missing metadata. An inverted range is corrupt. In either
     * case the record-level result is completely unknown. */
    if ((lower == 0 && upper == 0) || lower > upper) return OUTCOME_BOTH;

    const uint64_t value = inst->value;
    bool canBeFalse = true;
    bool canBeTrue = true;

    switch ((filterOp_t)inst->op) {
        case FOP_EQ8:
            canBeTrue = lower <= value && value <= upper;
            canBeFalse = lower != value || upper != value;
            break;
        case FOP_GT8:
            canBeTrue = upper > value;
            canBeFalse = lower <= value;
            break;
        case FOP_LT8:
            canBeTrue = lower < value;
            canBeFalse = upper >= value;
            break;
        case FOP_GE8:
            canBeTrue = upper >= value;
            canBeFalse = lower < value;
            break;
        case FOP_LE8:
            canBeTrue = lower <= value;
            canBeFalse = upper > value;
            break;
        default:
            return OUTCOME_BOTH;
    }

    return (canBeFalse ? OUTCOME_FALSE : 0u) | (canBeTrue ? OUTCOME_TRUE : 0u);
}  // End of timeOutcomes

static uint8_t ipv4Outcomes(const filterInstr_t *inst, const bloomHandle_t *bh) {
    const bloomFilter_t *bloom = inst->offset == OFFsrc4Addr ? bh->srcIPv4bloom : bh->dstIPv4bloom;
    if (!bloom) return OUTCOME_BOTH;

    /* A hit may be a Bloom false positive. A miss proves that the comparison
     * cannot be true for any record in this block. */
    return BloomLookupIPv4(bloom, (uint32_t)inst->value) ? OUTCOME_BOTH : OUTCOME_FALSE;
}  // End of ipv4Outcomes

static uint8_t ipv6Outcomes(const filterInstr_t *inst, const filterInstr_t *prog, uint32_t progLen,
                            const bloomHandle_t *bh) {
    if (inst->onTrue >= progLen) return OUTCOME_BOTH;

    const filterInstr_t *low = &prog[inst->onTrue];
    if (low->op != FOP_EQ8 || low->extID != EXipv6FlowID || low->offset != inst->offset + sizeof(uint64_t) ||
        low->onFalse != inst->onFalse)
        return OUTCOME_BOTH;

    const bloomFilter_t *bloom = inst->offset == OFFsrc6Addr ? bh->srcIPv6bloom : bh->dstIPv6bloom;
    if (!bloom) return OUTCOME_BOTH;

    uint8_t address[16];
    memcpy(address, &inst->value, sizeof(inst->value));
    memcpy(address + sizeof(inst->value), &low->value, sizeof(low->value));
    return BloomLookupIPv6(bloom, address) ? OUTCOME_BOTH : OUTCOME_FALSE;
}  // End of ipv6Outcomes

static uint8_t instructionOutcomes(const filterInstr_t *inst, const filterInstr_t *prog, uint32_t progLen,
                                   uint64_t blockMsecFirst, uint64_t blockMsecLast, const bloomHandle_t *bh) {
    if (inst->op == FOP_ANY) return OUTCOME_TRUE;
    if (isTimeInstruction(inst)) return timeOutcomes(inst, blockMsecFirst, blockMsecLast);
    if (!bh) return OUTCOME_BOTH;
    if (isIPv4Instruction(inst)) return ipv4Outcomes(inst, bh);
    if (isIPv6Instruction(inst)) return ipv6Outcomes(inst, prog, progLen, bh);
    return OUTCOME_BOTH;
}  // End of instructionOutcomes

const blockConstraint_t *GetBlockConstraint(const void *engine) {
    if (!engine) return NULL;
    return &((const FilterEngine_t *)engine)->blockConstraint;
}  // End of GetBlockConstraint

int FilterBlock(const void *enginePtr, uint64_t blockMsecFirst, uint64_t blockMsecLast,
                const bloomHandle_t *bh) {
    if (!enginePtr) return 1;

    const FilterEngine_t *engine = (const FilterEngine_t *)enginePtr;
    const filterInstr_t *prog = engine->prog;
    const uint32_t progLen = engine->progLen;
    if (!prog || progLen == 0 || progLen > BLOCK_PROGRAM_MAX || engine->startNode >= progLen) return 1;

    /* The compiled program is a DAG, but different paths may converge. Queue
     * each instruction once; reachability, not the number of paths, matters. */
    uint8_t queued[progLen];
    uint16_t stack[progLen];
    memset(queued, 0, sizeof(queued));

    uint32_t top = 0;
    stack[top++] = (uint16_t)engine->startNode;
    queued[engine->startNode] = 1;

    while (top > 0) {
        const uint16_t index = stack[--top];
        const filterInstr_t *inst = &prog[index];

        if (inst->op == FOP_ACCEPT) return 1;
        if (inst->op == FOP_REJECT) continue;
        if (inst->op >= FOP__COUNT) return 1;

        const uint8_t outcomes = instructionOutcomes(inst, prog, progLen, blockMsecFirst, blockMsecLast, bh);
        const uint16_t targets[2] = {inst->onFalse, inst->onTrue};

        for (unsigned result = 0; result < 2; result++) {
            const uint8_t outcome = result ? OUTCOME_TRUE : OUTCOME_FALSE;
            if (!(outcomes & outcome)) continue;

            const uint16_t target = targets[result];
            if (target >= progLen) return 1;
            if (!queued[target]) {
                queued[target] = 1;
                stack[top++] = target;
            }
        }
    }

    return 0;
}  // End of FilterBlock
