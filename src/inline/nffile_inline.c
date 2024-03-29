/*
 *  Copyright (c) 2009-2024, Peter Haag
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

static inline int MapRecordHandle(recordHandle_t *handle, recordHeaderV3_t *recordHeaderV3, uint32_t flowCount);

static inline dataBlock_t *AppendToBuffer(nffile_t *nffile, dataBlock_t *dataBlock, void *record, size_t required);

static inline int MapRecordHandle(recordHandle_t *handle, recordHeaderV3_t *recordHeaderV3, uint32_t flowCount) {
    if (handle->extensionList[SSLindex]) free(handle->extensionList[SSLindex]);
    if (handle->extensionList[JA3index]) free(handle->extensionList[JA3index]);
    if (handle->extensionList[JA4index]) free(handle->extensionList[JA4index]);

    memset((void *)handle, 0, sizeof(recordHandle_t));
    handle->recordHeaderV3 = recordHeaderV3;

    elementHeader_t *elementHeader = (elementHeader_t *)((void *)recordHeaderV3 + sizeof(recordHeaderV3_t));
    // map all extensions
    for (int i = 0; i < recordHeaderV3->numElements; i++) {
        if ((elementHeader->type > 0 && elementHeader->type < MAXEXTENSIONS) && elementHeader->length != 0) {
            handle->extensionList[elementHeader->type] = (void *)elementHeader + sizeof(elementHeader_t);
            elementHeader = (elementHeader_t *)((void *)elementHeader + elementHeader->length);
        } else {
            LogError("Invalid extension Type: %u, Length: %u", elementHeader->type, elementHeader->length);
            return 0;
        }
    }
    handle->extensionList[EXnull] = (void *)recordHeaderV3;
    handle->extensionList[EXlocal] = (void *)handle;
    handle->flowCount = flowCount;
    handle->numElements = recordHeaderV3->numElements;

    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)handle->extensionList[EXgenericFlowID];
    if (genericFlow && genericFlow->msecFirst == 0) {
        EXnselCommon_t *nselCommon = (EXnselCommon_t *)handle->extensionList[EXnselCommonID];
        if (nselCommon) {
            genericFlow->msecFirst = nselCommon->msecEvent;
        } else {
            EXnelCommon_t *nelCommon = (EXnelCommon_t *)handle->extensionList[EXnelCommonID];
            if (nelCommon) genericFlow->msecFirst = nelCommon->msecEvent;
        }
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
