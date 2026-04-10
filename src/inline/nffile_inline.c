/*
 *  Copyright (c) 2009-2025, Peter Haag
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

#include <inttypes.h>

// Fix lazy exporters, sending both - IPv4 and IPv6 addresses in the same record
// lot of code for nothing!!
static inline void ResolveMultipleIPrecords(recordHandle_t *handle, uint64_t flowCount) {
    dbg_printf("ResolveMultipleIPrecords\n");
    // check, if the at least announce the ipVersion element
    EXlayer2_t *EXlayer2 = (EXlayer2_t *)handle->extensionList[EXlayer2ID];
    uint32_t skipID = 0;
    if (EXlayer2) {
        // Honor the IPversion flag and mask out the unneeded extension
        switch (EXlayer2->ipVersion) {
            case 0: {  // not present - guess which IP version
                uint64_t *ipv4SrcDst = (uint64_t *)handle->extensionList[EXipv4FlowID];
                if (*ipv4SrcDst == 0) {
                    // we have an ipv6 flow record
                    skipID = EXipv4FlowID;
                } else {
                    // we have an ipv4 flow record
                    skipID = EXipv6FlowID;
                }
            } break;
            case 4:
                skipID = EXipv6FlowID;
                break;
            case 6:
                skipID = EXipv4FlowID;
                break;
            default:
                LogError("Mapping record: %" PRIu64 "  - Error - unknown IP version: %d", flowCount, EXlayer2->ipVersion);
        }

    } else {
        // nope -  no layer 2 records - guess, which IP Extension to use
        // a 64bit uint64_t spans over src and dst ipv4 addr
        uint64_t *ipv4SrcDst = (uint64_t *)handle->extensionList[EXipv4FlowID];

        if (*ipv4SrcDst == 0) {
            // we have an ipv6 flow record
            skipID = EXipv4FlowID;
        } else {
            // we have an ipv4 flow record
            skipID = EXipv6FlowID;
        }
    }

    // mark element to skip as EXnull with length != 0
    if (skipID) {
        handle->extensionList[skipID] = NULL;
    }

#ifdef DEVEL
    if (handle->extensionList[EXipv4FlowID] == NULL) printf("Unmapped IPv4\n");
    if (handle->extensionList[EXipv6FlowID] == NULL) printf("Unmapped IPv6\n");
#endif

}  // End of ResolveMultipleIPrecords

static inline int MapV4RecordHandle(recordHandle_t *handle, recordHeaderV4_t *recordHeaderV4, uint64_t flowCount) {
    *handle = (recordHandle_t){.recordHeaderV4 = recordHeaderV4, .numElements = recordHeaderV4->numExtensions, .flowCount = flowCount};

    uint8_t *eor = (uint8_t *)recordHeaderV4 + recordHeaderV4->size;
    uint8_t *recordBase = (uint8_t *)recordHeaderV4;

    // offset table
    uint16_t *offset = (uint16_t *)(recordBase + sizeof(recordHeaderV4_t));

    // Validate each extension
    uint64_t bitMap = recordHeaderV4->extBitmap;
    while (bitMap) {
        // find lowest set bit (ctz) in bitMap
        uint32_t extID = __builtin_ctzll(bitMap);
        bitMap &= bitMap - 1;

        uint8_t *extension = recordBase + *offset++;

        // Offset must be within record
        if (extension > eor) {
            LogError("MapV4RecordHandle: extension %d offset out of bounds", extID);
            return 0;
        }

        if (extID < MAXEXTENSIONS) {
            handle->extensionList[extID] = extension;
        } else {
            LogError("Mapping record: %" PRIu64 " - Skip unknown extension Type: %u", flowCount, extID);
            dbg(DumpHex(stdout, (void *)recordHeaderV4, recordHeaderV4->size));
        }
    }

    handle->extensionList[EXheader] = (void *)recordHeaderV4;
    handle->extensionList[EXlocal] = (void *)handle;

    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)handle->extensionList[EXgenericFlowID];
    if (genericFlow && genericFlow->msecFirst == 0) {
        EXnselCommon_t *nselCommon = (EXnselCommon_t *)handle->extensionList[EXnselCommonID];
        if (nselCommon) {
            genericFlow->msecFirst = nselCommon->msecEvent;
        }
    }

    // Fix lazy exporters, sending both - IPv4 and IPv6 addresses in the same record
    // check first IPv6 as expected less often
    if (handle->extensionList[EXipv6FlowID] && handle->extensionList[EXipv4FlowID]) {
        ResolveMultipleIPrecords(handle, flowCount);
    }

    return 1;
}  // End of MapV4RecordHandle

static inline flowBlockV3_t *AppendToBuffer(nffileV3_t *nffile, flowBlockV3_t *dataBlock, void *record, size_t required) {
    if (!IsAvailable(dataBlock, nffile->fileHeader->blockSize, required)) {
        if (dataBlock->type != BLOCK_TYPE_FLOW) {
            printf("BlockType is %u\n", dataBlock->type);
            //  assert(dataBlock->type == BLOCK_TYPE_FLOW);
        }
        WriteBlockV3(nffile, dataBlock);
        InitDataBlock(dataBlock, nffile->fileHeader->blockSize);
        // map output memory buffer
    }
    void *cur = GetCursor(dataBlock);
    // enough buffer space available at this point
    memcpy(cur, record, required);

    // update stat
    dataBlock->numRecords++;
    dataBlock->rawSize += required;

    return dataBlock;
}  // End of AppendToBuffer
