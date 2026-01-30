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

static inline int MapRecordHandle(recordHandle_t *handle, recordHeaderV3_t *recordHeaderV3, uint64_t flowCount);

static inline dataBlock_t *AppendToBuffer(nffile_t *nffile, dataBlock_t *dataBlock, void *record, size_t required);

// Fix lazy exporters, sending both - IPv4 and IPv6 addresses in the same record
// lot of code for nothing!!
static inline void ResolveMultipleIPrecords(recordHandle_t *handle, recordHeaderV3_t *recordHeaderV3, uint64_t flowCount) {
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
        void *skipElement = handle->extensionList[skipID];
        elementHeader_t *elementHeader = (elementHeader_t *)(skipElement - sizeof(elementHeader_t));
        elementHeader->type = EXnull;
        handle->extensionList[skipID] = NULL;
        recordHeaderV3->numElements--;
    }

#ifdef DEVEL
    if (handle->extensionList[EXipv4FlowID] == NULL) printf("Unmapped IPv4\n");
    if (handle->extensionList[EXipv6FlowID] == NULL) printf("Unmapped IPv6\n");
#endif

}  // End of ResolveMultipleIPrecords

static inline int MapRecordHandle(recordHandle_t *handle, recordHeaderV3_t *recordHeaderV3, uint64_t flowCount) {
    memset((void *)handle, 0, sizeof(recordHandle_t));
    handle->recordHeaderV3 = recordHeaderV3;

    void *eor = (void *)recordHeaderV3 + recordHeaderV3->size;

    elementHeader_t *elementHeader = (elementHeader_t *)((void *)recordHeaderV3 + sizeof(recordHeaderV3_t));
    // map all extensions
    int num = 0;
    while (num < recordHeaderV3->numElements) {
        if ((void *)elementHeader > eor) {
            LogError("Mapping record: %" PRIu64 "  - Error - element %d out of bounds", flowCount, num);
            return 0;
        }
        if (elementHeader->length == 0) {
            LogInfo("Mapping record: %" PRIu64 " - Corrupt extension %d Type: %u with Length: %u", flowCount, num, elementHeader->type,
                    elementHeader->length);
            return 0;
        }
        if (elementHeader->type == 0) {
            // Skip this record - advance to next record
            elementHeader = (elementHeader_t *)((void *)elementHeader + elementHeader->length);
            continue;
        }
        if (elementHeader->type < MAXEXTENSIONS) {
            handle->extensionList[elementHeader->type] = (void *)elementHeader + sizeof(elementHeader_t);
        } else {
            LogInfo("Mapping record: %" PRIu64 " - Skip unknown extension %d Type: %u, Length: %u", flowCount, num, elementHeader->type,
                    elementHeader->length);
            DumpHex(stdout, (void *)recordHeaderV3, recordHeaderV3->size);
        }
        elementHeader = (elementHeader_t *)((void *)elementHeader + elementHeader->length);
        num++;
    }
    handle->extensionList[EXheader] = (void *)recordHeaderV3;
    handle->extensionList[EXlocal] = (void *)handle;
    handle->flowCount = flowCount;
    handle->numElements = recordHeaderV3->numElements;

    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)handle->extensionList[EXgenericFlowID];
    if (genericFlow && genericFlow->msecFirst == 0) {
        EXnselCommon_t *nselCommon = (EXnselCommon_t *)handle->extensionList[EXnselCommonID];
        if (nselCommon) {
            genericFlow->msecFirst = nselCommon->msecEvent;
        } else {
            EXnatCommon_t *natCommon = (EXnatCommon_t *)handle->extensionList[EXnatCommonID];
            if (natCommon) genericFlow->msecFirst = natCommon->msecEvent;
        }
    }

    // Fix lazy exporters, sending both - IPv4 and IPv6 addresses in the same record
    // check first IPv6 as expected less often
    if (handle->extensionList[EXipv6FlowID] && handle->extensionList[EXipv4FlowID]) {
        ResolveMultipleIPrecords(handle, recordHeaderV3, flowCount);
    }

    return 1;
}

static inline dataBlock_t *AppendToBuffer(nffile_t *nffile, dataBlock_t *dataBlock, void *record, size_t required) {
    if (!IsAvailable(dataBlock, required)) {
        // flush block - get an empty one
        dataBlock = WriteBlock(nffile, dataBlock);
        // map output memory buffer
    }
    void *cur = GetCurrentCursor(dataBlock);
    // enough buffer space available at this point
    memcpy(cur, record, required);

    // update stat
    dataBlock->NumRecords++;
    dataBlock->size += required;

    return dataBlock;
}  // End of AppendToBuffer
