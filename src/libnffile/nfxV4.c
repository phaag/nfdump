/*
 *  Copyright (c) 2026, Peter Haag
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

#include "nfxV4.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "id.h"
#include "logging.h"
#include "nfdump.h"
#include "util.h"

// sub template IDs
#define subTemplateListType 292
#define subTemplateMultiListType 293

static inline void CopyField(uint8_t *dst, const uint8_t *src, uint16_t inSize, uint16_t outSize) {
    uint16_t copy = (inSize < outSize) ? inSize : outSize;

    switch (copy) {
        case 0:
            break;
        case 1:
            __builtin_memcpy(dst, src, 1);
            break;
        case 2:
            __builtin_memcpy(dst, src, 2);
            break;
        case 3:
            __builtin_memcpy(dst, src, 3);
            break;
        case 4:
            __builtin_memcpy(dst, src, 4);
            break;
        case 5:
            __builtin_memcpy(dst, src, 5);
            break;
        case 6:
            __builtin_memcpy(dst, src, 6);
            break;
        case 7:
            __builtin_memcpy(dst, src, 7);
            break;
        case 8:
            __builtin_memcpy(dst, src, 8);
            break;
        case 12:
            __builtin_memcpy(dst, src, 12);
            break;
        case 16:
            __builtin_memcpy(dst, src, 16);
            break;
        case 24:
            __builtin_memcpy(dst, src, 24);
            break;
        default:
            memcpy(dst, src, copy);
            break;
    }

    if (outSize > copy) {
        // Hand-roll the most common clear sizes if needed
        uint16_t diff = outSize - copy;
        uint8_t *p = dst + copy;
        switch (diff) {
            case 1:
                *p = 0;
                break;
            case 2:
                __builtin_memset(p, 0, 2);
                break;
            case 3:
                __builtin_memset(p, 0, 3);
                break;
            case 4:
                __builtin_memset(p, 0, 4);
                break;
            default:
                memset(p, 0, diff);
                break;
        }
    }
}  // End of CopyField

static inline uint16_t ReadVarLength(const uint8_t *p, uint16_t *lenBytes) {
    uint8_t l = *p;

    if (l < 255) {
        *lenBytes = 1;
        return l;
    }

    *lenBytes = 3;
    return ntohs(*(uint16_t *)(p + 1));

}  // End of ReadVarLength

static int resolveNumber(pipelineInstr_t *instr) {
    if (instr->inLength == instr->outLength) {
        switch (instr->inLength) {
            case 1:
                instr->op = OP_COPY_1;
                break;
            case 2:
                instr->op = OP_COPY_BE_2;
                break;
            case 4:
                instr->op = OP_COPY_BE_4;
                break;
            case 8:
                instr->op = OP_COPY_BE_8;
                break;
            default:
                LogError("Pipeline compiler - illegal length: %u\n", instr->inLength);
                return 0;
        }
    } else if (instr->inLength == 2 && instr->outLength == 4) {
        instr->op = OP_COPY_BE_2_4;
    } else if (instr->inLength == 4 && instr->outLength == 8) {
        instr->op = OP_COPY_BE_4_8;
    } else if (instr->inLength == 6 && instr->outLength == 8) {
        instr->op = OP_COPY_BE_6_8;
    } else {
        instr->op = OP_COPY_N;
    }
    return 1;
}  // End of resolveNumber

static pipelineInstr_t *resolveRegister(pipelineInstr_t *instr, int rtRegister) {
    // add OP_LOAD_X
    switch (instr->inLength) {
        case 1:
            instr->op = OP_LOAD_1;
            break;
        case 2:
            instr->op = OP_LOAD_2;
            break;
        case 4:
            instr->op = OP_LOAD_4;
            break;
        case 8:
            instr->op = OP_LOAD_8;
            break;
        default:
            LogError("Register copy for length: %u not supported", instr->inLength);
            return NULL;
    }
    instr++;

    switch (rtRegister) {
        case 0:
            *instr = (pipelineInstr_t){.op = OP_STORE_0};
            break;
        case 1:
            *instr = (pipelineInstr_t){.op = OP_STORE_1};
            break;
        case 2:
            *instr = (pipelineInstr_t){.op = OP_STORE_2};
            break;
        default:
            LogError("Register copy for register: %u not supported", rtRegister);
            return NULL;
    }

    return instr;
}  // End of resolveRegister

pipeline_t *PipelineCompile(const pipelineInstr_t *instruction, uint32_t templateID, uint32_t numInstructions) {
    if (numInstructions == 0) return NULL;

    dbg_printf("\nCompile pipeline for ID: %u - Input: %u instructions\n", templateID, numInstructions);

    // prepare bitmap
    uint64_t bitMap = 0;
    uint32_t extraOps = 0;
    for (int i = 0; i < (int)numInstructions; i++) {
        uint32_t extID = instruction[i].extID;
        if (extID >= MAXEXTENSIONS) {
            LogError("PipelineCompile() - extension ID %u > max extension ID", extID);
            return NULL;
        }
        if (extID != EXnull) {
            BitMapSet(bitMap, extID);
        }
        switch (instruction[i].transform) {
            // these transforms need an extra OP to complete
            case MOVE_TIMESEC:
            case MOVE_IPFIX_TIME:
            case REGISTER_0:
            case REGISTER_1:
            case REGISTER_2:
                extraOps++;
                break;
            default:
                break;
        }
    }
    uint32_t numExtensions = __builtin_popcountll(bitMap);

    // pre-compute expected max record size for memory check
    uint32_t recordSize = ALIGN8(sizeof(recordHeaderV4_t) + numExtensions * sizeof(uint16_t));
    int hasVarLength = 0;

    // allocate enough memory for pipeline
    // instructions + extraOps + numExtensions * OP_ALLOC_EXT + OP_END
    uint32_t slots = numInstructions + numExtensions + extraOps + 1;  // +OP_END
    pipeline_t *pipeline = calloc(1, sizeof(pipeline_t) + slots * sizeof(pipelineInstr_t));
    if (!pipeline) {
        LogError("calloc(): error in %s:%d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    dbg_printf("Evaluated bitmap: 0x%llx -> %u extensions\n", bitMap, numExtensions);

    // generate final instruction set
    uint8_t allocated[MAXEXTENSIONS] = {0};
    pipelineInstr_t *instr = pipeline->instruction;
    for (int i = 0; i < (int)numInstructions && pipeline != NULL; i++) {
        uint32_t extID = instruction[i].extID;
        // VARLENGTH extensions allocate the offset table when adding VARLENGTH data
        if (extensionTable[extID].size == VARLENGTH) {
            hasVarLength = 1;
        } else if (extID != EXnull && allocated[extID] == 0 && extensionTable[extID].size != VARLENGTH) {
            dbg_printf("Add OP_ALLOC_EXT for ext: %s(%u), size: %u\n", extensionTable[extID].name, extID, extensionTable[extID].size);
            *instr = (pipelineInstr_t){
                .op = OP_ALLOC_EXT,
                .extID = extID,
                .outLength = extensionTable[extID].size,
            };
            allocated[extID] = 1;

            // precompute expected record size
            recordSize += extensionTable[extID].size;

            instr++;
        }

        // skip TR_ADD instruction as already processed above
        if (instruction[i].transform == RESERVE || instruction[i].transform == NOP) {
            dbg_printf("Skip instruction %s, Ext: %s\n", trTable[instruction[i].transform].trName, extensionTable[instruction[i].extID].name);
            continue;
        }

        *instr = instruction[i];

        // process instructions
        // Add up recordSize for fixed size extensions
        if (instr->outLength == VARLENGTH) {
            // VARLENGTH instruction
            hasVarLength = 1;
            instr->op = OP_COPY_VAR;
        } else {
            // fixed size instruction
            switch (instr->transform) {
                case NOP:
                    break;
                case SKIP_INPUT:  // skip input
                    if (instr->inLength == VARLENGTH)
                        instr->op = OP_SKIP_VAR;
                    else if (instr->inLength > 0)
                        instr->op = OP_SKIP;
                    else
                        instr->op = OP_NULL;
                    break;
                case RESERVE:  // add offset entry to offset table
                               // no copy op
                    break;
                case MOVE_NUMBER:  // byte aware copy
                    if (resolveNumber(instr) == 0) {
                        free(pipeline);
                        pipeline = NULL;
                    }
                    break;
                case MOVE_IPV6:
                    instr->op = OP_COPY_IPV6;
                    break;
                case MOVE_BYTES:
                    if (instr->inLength == 16)
                        instr->op = OP_COPY_16;
                    else
                        instr->op = OP_COPY_N;
                    instr->argument = (instr->inLength < instr->outLength) ? instr->inLength : instr->outLength;
                    break;
                case MOVE_V9_TIME:  // add sysup/unix time from runtime argument
                    instr->op = OP_COPY_V9_TIME;
                    break;
                case MOVE_IPFIX_TIME:  // add sysuptime from runtime argument
                    if (resolveNumber(instr) == 0) {
                        free(pipeline);
                        pipeline = NULL;
                    }
                    if (pipeline->numFixup < NUMFIXUPS) {
                        pipeline->fixUp[pipeline->numFixup++] = instr;
                    } else {
                        LogError("Fixup register overflow: %u", pipeline->numFixup);
                        free(pipeline);
                        pipeline = NULL;
                    }
                    break;
                case MOVE_SYSUP:  // copy sysuptime to runtime argument
                    if (instr->inLength != 8) {
                        LogError("Expected 8 byte sysupTime, found %u", instr->inLength);
                        free(pipeline);
                        pipeline = NULL;
                    }
                    instr->op = OP_COPY_SYSUP_TIME;
                    break;
                case MOVE_IPFIX_USEC:
                    if (instr->inLength != 4) {
                        LogError("Expected 4 bytes for delta usec, found %u", instr->inLength);
                        free(pipeline);
                        pipeline = NULL;
                    }
                    instr->op = OP_COPY_IPFIX_USEC;
                    break;
                case MOVE_IPV4_RVD:
                    instr->op = OP_COPY_IPV4_RVD;
                    break;
                case MOVE_IPV6_RVD:
                    instr->op = OP_COPY_IPV6_RVD;
                    break;
                case MOVE_TIME_RVD:
                    instr->op = OP_COPY_TIME_RVD;
                    break;
                case MOVE_TIMESEC: {
                    if (instr->inLength == 4)
                        instr->op = OP_COPY_BE_4_8;
                    else if (instr->inLength == 8)
                        instr->op = OP_COPY_BE_8;
                    else {
                        LogError("Unsupported copy length for time(sec): %u", instr->inLength);
                        free(pipeline);
                        pipeline = NULL;
                    }
                    dbg_printf("TR: %s, Add %s copy %u -> %u for ext: %s(%u)\n", trTable[instr->transform].trName, opTable[instr->op].opName,
                               instr->inLength, instr->outLength, extensionTable[instr->extID].name, instr->extID);
                    pipelineInstr_t opMul = *instr++;
                    opMul.op = OP_MUL_8;
                    opMul.argument = 1000;
                    *instr = opMul;
                } break;
                case REGISTER_0:
                    instr = resolveRegister(instr, 0);
                    if (instr == NULL) {
                        free(pipeline);
                        pipeline = NULL;
                    }
                    break;
                case REGISTER_1:
                    instr = resolveRegister(instr, 1);
                    if (instr == NULL) {
                        free(pipeline);
                        pipeline = NULL;
                    }
                    break;
                case REGISTER_2:
                    instr = resolveRegister(instr, 2);
                    if (instr == NULL) {
                        free(pipeline);
                        pipeline = NULL;
                    }
                    break;
                case SUBTEMPLATE:
                    // Sub-template IEs (RFC 6313) — skip content at runtime
                    instr->op = OP_CALL;
                    break;
                default:
                    LogError("Unknow transformation type: %u", instr->transform);
            }

            dbg(if (pipeline) printf("TR: %s, Add %s copy %u -> %u for ext: %s(%u)\n", trTable[instr->transform].trName, opTable[instr->op].opName,
                                     instr->inLength, instr->outLength, extensionTable[instr->extID].name, instr->extID));
        }
        instr++;
    }

    if (pipeline == NULL) return NULL;

    if (pipeline->numFixup) {
        for (int i = 0; i < (int)pipeline->numFixup; i++) {
            dbg_printf("Add fixup %d OP for IPFIX time\n", i);
            *instr++ = (pipelineInstr_t){
                .op = OP_ADD_SYSUP,
                .argument = i,
            };
        }
    }
    // last instruction
    dbg_printf("Finish pipline with OP_END\n");
    *instr = (pipelineInstr_t){
        .op = OP_END,
        .extID = EXnull,
    };

    pipeline->recordSize = hasVarLength ? VARLENGTH : recordSize;
    pipeline->templateID = templateID;
    pipeline->numInstructions = instr - pipeline->instruction;
    pipeline->extBitmap = bitMap;
    pipeline->numExtensions = __builtin_popcountll(bitMap);
    pipeline->baseOffset = ALIGN8(sizeof(recordHeaderV4_t) + pipeline->numExtensions * sizeof(uint16_t));

    return pipeline;
}  // End of PipelineCompile

/*
 * Run pipeline for input stream and copy bytes to output stream according instruction list
 * returns number of bytes read from input stream (>0) or error code (<0)
 *
 * Uses computed-goto dispatch (GCC/Clang extension) for better branch prediction:
 * each handler has its own indirect-jump site, so the BTB can predict per-opcode.
 */
ssize_t PipelineRun(const pipeline_t *restrict pipeline, const uint8_t *restrict in, size_t inSize, uint8_t *restrict out, size_t outSize,
                    pipelineRuntime_t *restrict runtime) {
    if (unlikely(runtime == NULL)) return PIP_ERR_RUNTIME_INPUT;

    dbg_printf("Run pipeline for template ID: %u, with %u instructions\n", pipeline->templateID, pipeline->numInstructions);

    // computed-goto dispatch table
    // indices must match the pipelineOp_t enum generated by PIPELINE_OP_LIST.
    static const void *const dispatchTable[NUM_PIPELINE_OPS] = {
        [OP_NULL] = &&L_NULL,
        [OP_COPY_1] = &&L_COPY_1,
        [OP_COPY_BE_2] = &&L_COPY_BE_2,
        [OP_COPY_BE_4] = &&L_COPY_BE_4,
        [OP_COPY_BE_8] = &&L_COPY_BE_8,
        [OP_COPY_BE_2_4] = &&L_COPY_BE_2_4,
        [OP_COPY_BE_4_8] = &&L_COPY_BE_4_8,
        [OP_COPY_BE_6_8] = &&L_COPY_BE_6_8,
        [OP_COPY_16] = &&L_COPY_16,
        [OP_COPY_IPV6] = &&L_COPY_IPV6,
        [OP_ALLOC_EXT] = &&L_ALLOC_EXT,
        [OP_COPY_N] = &&L_COPY_N,
        [OP_COPY_VAR] = &&L_COPY_VAR,
        [OP_COPY_V9_TIME] = &&L_COPY_V9_TIME,
        [OP_COPY_IPFIX_USEC] = &&L_COPY_IPFIX_USEC,
        [OP_COPY_SYSUP_TIME] = &&L_COPY_SYSUP_TIME,
        [OP_COPY_IPV4_RVD] = &&L_COPY_IPV4_RVD,
        [OP_COPY_IPV6_RVD] = &&L_COPY_IPV6_RVD,
        [OP_COPY_TIME_RVD] = &&L_COPY_TIME_RVD,
        [OP_SKIP] = &&L_SKIP,
        [OP_SKIP_VAR] = &&L_SKIP_VAR,
        [OP_INIT] = &&L_NULL,
        [OP_CALL] = &&L_CALL,
        [OP_ADD_8] = &&L_NULL,
        [OP_ADD_SYSUP] = &&L_ADD_SYSUP,
        [OP_MUL_8] = &&L_MUL_8,
        [OP_LOAD_1] = &&L_LOAD_1,
        [OP_LOAD_2] = &&L_LOAD_2,
        [OP_LOAD_4] = &&L_LOAD_4,
        [OP_LOAD_8] = &&L_LOAD_8,
        [OP_STORE_0] = &&L_STORE_0,
        [OP_STORE_1] = &&L_STORE_1,
        [OP_STORE_2] = &&L_STORE_2,
        [OP_END] = &&L_END,
    };

    const uint8_t *inEnd = in + inSize;

    recordHeaderV4_t *recordHeader = (recordHeaderV4_t *)out;

    // set offset table
    uint16_t *offsetTable = (uint16_t *)(out + sizeof(recordHeaderV4_t));
    uint32_t offsetTableSize = pipeline->baseOffset - sizeof(recordHeaderV4_t);
    memset(offsetTable, 0, offsetTableSize);

    uint64_t tmpRegister = 0;  // tmp register
    uint8_t *baseCache[MAXEXTENSIONS] = {0};
    // set nextOffset
    uint32_t nextOffset = pipeline->baseOffset;
    const uint8_t *inPtr = in;
    const pipelineInstr_t *inst = pipeline->instruction;

// advance to next instruction and jump directly to its handler
#define DISPATCH()                     \
    do {                               \
        inst++;                        \
        goto *dispatchTable[inst->op]; \
    } while (0)

    // first dispatch
    goto *dispatchTable[inst->op];

    // ── opcode handlers ──

L_ALLOC_EXT: {
    if (unlikely(nextOffset + inst->outLength > outSize)) return PIP_ERR_SHORT_OUTPUT;
    baseCache[inst->extID] = out + nextOffset;
    memset(out + nextOffset, 0, inst->outLength);
    if (inst->extID == EXgenericFlowID)
        runtime->genericRecord = baseCache[inst->extID];
    else if (inst->extID == EXcntFlowID)
        runtime->cntRecord = baseCache[inst->extID];
    nextOffset += inst->outLength;
    DISPATCH();
}

L_COPY_1:
    if (unlikely(inPtr + 1 > inEnd)) return PIP_ERR_SHORT_INPUT;
    *(uint8_t *)(baseCache[inst->extID] + inst->dstOffset) = *inPtr;
    inPtr += 1;
    DISPATCH();

L_COPY_BE_2: {
    if (unlikely(inPtr + 2 > inEnd)) return PIP_ERR_SHORT_INPUT;
    uint16_t v;
    __builtin_memcpy(&v, inPtr, 2);
    uint16_t *dst = (uint16_t *)(baseCache[inst->extID] + inst->dstOffset);
    *dst = ntohs(v);
    inPtr += 2;
    DISPATCH();
}

L_COPY_BE_2_4: {
    // 16-bit BE → 32-bit host, value in low 32 bits
    if (unlikely(inPtr + 2 > inEnd)) return PIP_ERR_SHORT_INPUT;
    uint16_t v;
    __builtin_memcpy(&v, inPtr, 2);
    uint32_t *dst = (uint32_t *)(baseCache[inst->extID] + inst->dstOffset);
    *dst = ntohs(v);
    inPtr += 2;
    DISPATCH();
}

L_COPY_BE_4: {
    if (unlikely(inPtr + 4 > inEnd)) return PIP_ERR_SHORT_INPUT;
    uint32_t v;
    __builtin_memcpy(&v, inPtr, 4);
    uint32_t *dst = (uint32_t *)(baseCache[inst->extID] + inst->dstOffset);
    *dst = ntohl(v);
    inPtr += 4;
    DISPATCH();
}

L_COPY_BE_4_8: {
    // 32-bit BE → 64-bit host, value in low 32 bits
    if (unlikely(inPtr + 4 > inEnd)) return PIP_ERR_SHORT_INPUT;
    uint32_t v;
    __builtin_memcpy(&v, inPtr, 4);
    uint64_t *dst = (uint64_t *)(baseCache[inst->extID] + inst->dstOffset);
    *dst = ntohl(v);
    inPtr += 4;
    DISPATCH();
}

L_COPY_BE_6_8: {
    // 48-bit BE → 64-bit host
    if (unlikely(inPtr + 6 > inEnd)) return PIP_ERR_SHORT_INPUT;
    uint64_t v = 0;
    __builtin_memcpy((uint8_t *)&v + 2, inPtr, 6);
    uint64_t *dst = (uint64_t *)(baseCache[inst->extID] + inst->dstOffset);
    *dst = ntohll(v);

    inPtr += 6;
    DISPATCH();
}

L_COPY_BE_8: {
    if (unlikely(inPtr + 8 > inEnd)) return PIP_ERR_SHORT_INPUT;
    uint64_t v;
    __builtin_memcpy(&v, inPtr, 8);
    uint64_t *dst = (uint64_t *)(baseCache[inst->extID] + inst->dstOffset);
    *dst = ntohll(v);
    inPtr += 8;
    DISPATCH();
}

L_COPY_16:
    if (unlikely(inPtr + 16 > inEnd)) return PIP_ERR_SHORT_INPUT;
    __builtin_memcpy(baseCache[inst->extID] + inst->dstOffset, inPtr, 16);
    inPtr += 16;
    DISPATCH();

L_COPY_IPV6: {
    if (unlikely(inPtr + 16 > inEnd)) return PIP_ERR_SHORT_INPUT;
    uint64_t ipv6[2];
    __builtin_memcpy(ipv6, inPtr, 16);
    uint64_t *dst = (uint64_t *)(baseCache[inst->extID] + inst->dstOffset);
    dst[0] = ntohll(ipv6[0]);
    dst[1] = ntohll(ipv6[1]);
    inPtr += 16;
    DISPATCH();
}

L_COPY_N: {
    if (unlikely(inPtr + inst->inLength > inEnd)) return PIP_ERR_SHORT_INPUT;
    CopyField(baseCache[inst->extID] + inst->dstOffset, inPtr, inst->inLength, inst->outLength);
    inPtr += inst->inLength;
    DISPATCH();
}

L_COPY_VAR: {
    uint16_t lenBytes = 0;
    uint32_t inLength;

    if (inst->inLength == VARLENGTH) {
        // variable-length encoding with length prefix
        if (unlikely(inPtr + 1 > inEnd)) return PIP_ERR_SHORT_INPUT;
        inLength = ReadVarLength(inPtr, &lenBytes);
        if (unlikely(inPtr + lenBytes + inLength > inEnd)) return PIP_ERR_SHORT_INPUT;
        inPtr += lenBytes;
    } else {
        // if field element is defined as varlength, but announced fix length
        inLength = inst->inLength;
        if (unlikely(inPtr + inLength > inEnd)) return PIP_ERR_SHORT_INPUT;
    }

    uint32_t copyLength = (inst->outLength == VARLENGTH) ? inLength : inst->outLength;
    // dynamic extension have only one part with dyn length
    // allocate space on first encounter
    if (likely(baseCache[inst->extID] == NULL)) {
        baseCache[inst->extID] = out + nextOffset;
        // varlength extension have a length field and the var length content
        nextOffset += sizeof(uint32_t) + copyLength;
        // make it 8 byte boundary aligned
        nextOffset = (nextOffset + 7) & ~7ULL;

        if (unlikely(nextOffset > outSize)) return PIP_ERR_SHORT_OUTPUT;
    }

    uint8_t *outPtr = baseCache[inst->extID];
    // copy uint32_t length at the top
    __builtin_memcpy(outPtr, &inLength, 4);
    outPtr += 4;

    memcpy(outPtr, inPtr, copyLength);
    inPtr += inLength;

    DISPATCH();
}

L_COPY_IPV4_RVD: {
    uint32_t ipv4;
    __builtin_memcpy(&ipv4, runtime->ipReceived.bytes + 12, 4);
    uint32_t *dst = (uint32_t *)(baseCache[inst->extID] + inst->dstOffset);
    *dst = ntohl(ipv4);
    DISPATCH();
}

L_COPY_IPV6_RVD: {
    uint64_t *ipv6 = (uint64_t *)runtime->ipReceived.bytes;
    uint64_t *dst = (uint64_t *)(baseCache[inst->extID] + inst->dstOffset);
    dst[0] = ntohll(ipv6[0]);
    dst[1] = ntohll(ipv6[1]);
    DISPATCH();
}

L_COPY_TIME_RVD: {
    uint64_t *dst = (uint64_t *)(baseCache[inst->extID] + inst->dstOffset);
    *dst = runtime->msecReceived;
    DISPATCH();
}

L_COPY_V9_TIME: {
    if (unlikely(inPtr + 4 > inEnd)) return PIP_ERR_SHORT_INPUT;

    uint32_t t;
    __builtin_memcpy(&t, inPtr, 4);
    t = ntohl(t);
    // handle 32bit roll over
    uint32_t SysUptime = (uint32_t)runtime->SysUptime;
    uint32_t offset = (uint32_t)SysUptime - (uint32_t)t;
    uint64_t export_time_ms = (uint64_t)runtime->unix_secs * 1000;
    uint64_t msecTime = export_time_ms - (uint64_t)offset;

    dbg_printf("OP_COPY_V9_TIME: t: %u, sysUptime: %u, UNIXtime: %u\n", t, SysUptime, runtime->unix_secs);
    dbg_printf("OP_COPY_V9_TIME: offset: %u, export_time_ms: %llu, msecTime: %llu\n", offset, export_time_ms, msecTime);

    uint64_t *dst = (uint64_t *)(baseCache[inst->extID] + inst->dstOffset);
    *dst = msecTime;
    inPtr += 4;
    DISPATCH();
}

L_COPY_IPFIX_USEC: {
    if (unlikely(inPtr + 4 > inEnd)) return PIP_ERR_SHORT_INPUT;

    uint32_t t;
    __builtin_memcpy(&t, inPtr, 4);
    t = ntohl(t);

    uint64_t *dst = (uint64_t *)(baseCache[inst->extID] + inst->dstOffset);
    *dst = (uint64_t)runtime->secExported * (uint64_t)1000 - (uint64_t)t / (uint64_t)1000;
    inPtr += 4;
    DISPATCH();
}

L_COPY_SYSUP_TIME: {
    if (unlikely(inPtr + 8 > inEnd)) return PIP_ERR_SHORT_INPUT;
    uint64_t v;
    __builtin_memcpy(&v, inPtr, 8);
    runtime->SysUptime = ntohll(v);
    inPtr += 8;
    DISPATCH();
}

L_ADD_SYSUP: {
    pipelineInstr_t *fixUp = pipeline->fixUp[inst->argument];
    uint64_t *dst = (uint64_t *)(baseCache[fixUp->extID] + fixUp->dstOffset);
    dbg_printf("Fixup time: %llu", *dst);
    *dst += runtime->SysUptime;
    dbg_printf(" --> %llu\n", *dst);
    DISPATCH();
}

L_SKIP:
    if (unlikely(inPtr + inst->inLength > inEnd)) return PIP_ERR_SHORT_INPUT;
#ifdef DEVEL
    printf("Skip fix %u bytes\n", inst->inLength);
    DumpHex(stdout, inPtr, inst->inLength);
#endif
    inPtr += inst->inLength;
    DISPATCH();

L_SKIP_VAR: {
    if (unlikely(inPtr + 1 > inEnd)) return PIP_ERR_SHORT_INPUT;

    uint16_t lenBytes;
    uint32_t inLength = ReadVarLength(inPtr, &lenBytes);
    if (unlikely(inPtr + lenBytes + inLength > inEnd)) return PIP_ERR_SHORT_INPUT;

#ifdef DEVEL
    printf("Skip var %u bytes\n", inLength);
    DumpHex(stdout, inPtr + lenBytes, inLength);
#endif

    inPtr += (lenBytes + inLength);
    DISPATCH();
}

L_LOAD_1:
    if (unlikely(inPtr + 1 > inEnd)) return PIP_ERR_SHORT_INPUT;
    tmpRegister = *inPtr;
    inPtr += 1;
    DISPATCH();

L_LOAD_2: {
    if (unlikely(inPtr + 2 > inEnd)) return PIP_ERR_SHORT_INPUT;
    uint16_t v;
    __builtin_memcpy(&v, inPtr, 2);
    tmpRegister = ntohs(v);
    inPtr += 2;
    DISPATCH();
}

L_LOAD_4: {
    if (unlikely(inPtr + 4 > inEnd)) return PIP_ERR_SHORT_INPUT;
    uint32_t v;
    __builtin_memcpy(&v, inPtr, 4);
    tmpRegister = ntohl(v);
    inPtr += 4;
    DISPATCH();
}

L_LOAD_8: {
    if (unlikely(inPtr + 8 > inEnd)) return PIP_ERR_SHORT_INPUT;
    uint64_t v;
    __builtin_memcpy(&v, inPtr, 8);
    tmpRegister = ntohll(v);
    inPtr += 8;
    DISPATCH();
}

L_STORE_0:
    runtime->rtRegister[0] = tmpRegister;
    DISPATCH();

L_STORE_1:
    runtime->rtRegister[1] = tmpRegister;
    DISPATCH();

L_STORE_2:
    runtime->rtRegister[2] = tmpRegister;
    DISPATCH();

L_CALL: {
    // Skip sub-template IE content (IE #292/#293)
    dbg_printf("Skip sub template\n");
    if (inst->inLength == VARLENGTH) {
        if (unlikely(inPtr + 1 > inEnd)) return PIP_ERR_SHORT_INPUT;
        uint16_t lenBytes;
        uint32_t inLength = ReadVarLength(inPtr, &lenBytes);
        if (unlikely(inPtr + lenBytes + inLength > inEnd)) return PIP_ERR_SHORT_INPUT;
        dbg(DumpHex(stdout, inPtr, inLength));
        inPtr += lenBytes + inLength;
    } else {
        if (unlikely(inPtr + inst->inLength > inEnd)) return PIP_ERR_SHORT_INPUT;
        dbg(DumpHex(stdout, inPtr, inst->inLength));
        inPtr += inst->inLength;
    }
    DISPATCH();
}

L_MUL_8: {
    uint64_t *dst = (uint64_t *)(baseCache[inst->extID] + inst->dstOffset);
    *dst *= (uint64_t)inst->argument;
    DISPATCH();
}

L_END: {
    // populate offset table from baseCache, walking the bitmap
    uint64_t bm = pipeline->extBitmap;
    uint16_t *offPtr = offsetTable;
    while (bm) {
        uint32_t extID = __builtin_ctzll(bm);
        bm &= bm - 1;
        *offPtr++ = (uint16_t)(baseCache[extID] - out);
    }
    recordHeader->size = nextOffset;
    recordHeader->extBitmap = pipeline->extBitmap;
    recordHeader->numExtensions = pipeline->numExtensions;
    if (unlikely(nextOffset > outSize))
        return PIP_ERR_SHORT_OUTPUT;
    else
        return inPtr - in;
}

L_NULL:
    DISPATCH();

#undef DISPATCH

    // unreached
    return PIP_ERR_RUNTIME_ERROR;
}  // End of PipelineRun

void PrintPipeline(pipeline_t *pipeline) {
    printf("TemplateID       : %u\n", pipeline->templateID);
    printf("Extension bitmap : 0x%llx\n", pipeline->extBitmap);
    printf("Num extensions   : %u\n", pipeline->numExtensions);
    printf("Num instructions : %i\n", pipeline->numInstructions);
    printf("BaseOffset       : %i\n", pipeline->baseOffset);
    if (pipeline->recordSize == VARLENGTH)
        printf("RecordSize       : VARLENGTH\n");
    else
        printf("RecordSize       : %i\n", pipeline->recordSize);

    printf("OPcodes\n");
    for (int i = 0; i < pipeline->numInstructions; i++) {
        int extID = pipeline->instruction[i].extID;
        uint32_t op = pipeline->instruction[i].op;
        printf("[%d] op: %s(%u), element: %u, inputLength: %d, extension: %s(%u), outLength: %u, outOffset: %u, transform: %u\n", i,
               opTable[op].opName, opTable[op].opID, pipeline->instruction[i].type, pipeline->instruction[i].inLength, extensionTable[extID].name,
               extID, pipeline->instruction[i].outLength, pipeline->instruction[i].dstOffset, pipeline->instruction[i].transform);
    }
    printf("\n");
}

// Verify a V4record
// return 1 if ok, 0 otherwise
int VerifyV4Record(const recordHeaderV4_t *hdr) {
    if (!hdr) return 0;

    LogInfo("\nVerifyV4 record:");
    if (hdr->type != V4Record) {
        LogError("Verify v4 record: wrong type: %u", hdr->type);
        return 0;
    }

    uint8_t *recordBase = (uint8_t *)hdr;
    uint8_t *eor = recordBase + hdr->size;

    // verify numExtensions
    uint32_t numExtensions = __builtin_popcountll(hdr->extBitmap);
    if (numExtensions != hdr->numExtensions) {
        LogError("Verify v4 record: num extensions missmatch");
        return 0;
    }

    // Offset table
    uint16_t *offsetTable = (uint16_t *)(recordBase + sizeof(recordHeaderV4_t));

    // offset table must fit
    uint8_t *offEnd = (uint8_t *)offsetTable + ALIGN8(hdr->numExtensions * sizeof(uint16_t));
    if (offEnd > eor) {
        LogError("Verify v4 record: offset table record boundaries");
        return 0;
    }

    // Validate each extension
    uint64_t bitMap = hdr->extBitmap;
    uint16_t *offPtr = offsetTable;
    while (bitMap) {
        uint64_t t = bitMap & -bitMap;
        uint32_t extID = __builtin_ctzll(bitMap);
        bitMap ^= t;

        if (extID >= MAXEXTENSIONS) {
            LogError("Verify v4 record: extension ID: %u out of range", extID);
            return 0;
        }

        uint32_t offset = *offPtr++;
        uint32_t extSize = extensionTable[extID].size;
        uint8_t *extension = recordBase + offset;

        if (extSize == VARLENGTH) {
            __builtin_memcpy(&extSize, extension, sizeof(uint32_t));
        }

        LogInfo("Extension: type= %s(%u), offset=%u, size=%u", extensionTable[extID].name, extID, offset, extSize);

        // Offset must be within record
        if (recordBase + offset > eor) {
            LogError("Verify v4 record: extension %u offset out of range", extID);
            return 0;
        }

        // Extension must fit entirely
        if ((recordBase + offset + extSize) > eor) {
            LogError("Verify v4 record: extension %u length %u out of range", extID, extSize);
            return 0;
        }

        // alignment check
        if ((offset & 7) != 0) {
            LogError("Verify v4 record: extension %u not 8-byte aligned", extID);
            return 0;
        }
    }

    return 1;
}  // End of VerifyV4Record