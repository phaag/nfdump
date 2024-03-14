/*
 *  Copyright (c) 2009-2023, Peter Haag
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

static inline size_t CheckBufferSpace(nffile_t *nffile, size_t required);

static inline int MapRecordHandle(recordHandle_t *handle, recordHeaderV3_t *recordHeaderV3, uint32_t flowCount);

static inline void AppendToBuffer(nffile_t *nffile, void *record, size_t required);

static inline size_t CheckBufferSpace(nffile_t *nffile, size_t required) {
    // if actual output size is unknown, make sure at least
    // MAXRECORDSIZE is available
    if (required == 0) {
        required = MAXRECORDSIZE;
    }
    dbg_printf("Buffer Size %u, check for %zu\n", nffile->block_header->size, required);

    // flush current buffer to disc
    if ((nffile->block_header->size + required) > WRITE_BUFFSIZE) {
        if (required > WRITE_BUFFSIZE) {
            // this should never happen, but catch it anyway
            LogError("Required buffer size %zu too big for output buffer!", required);
            return 0;
        }

        if (WriteBlock(nffile) <= 0) {
            LogError("Failed to write output buffer to disk: '%s'", strerror(errno));
            return 0;
        }
    }

    dbg_printf("CheckBuffer returns %u\n", WRITE_BUFFSIZE - nffile->block_header->size);
    return WRITE_BUFFSIZE - nffile->block_header->size;

}  // End of CheckBufferSpace

static inline int MapRecordHandle(recordHandle_t *handle, recordHeaderV3_t *recordHeaderV3, uint32_t flowCount) {
    if (handle->sslInfo) free(handle->sslInfo);
    if (handle->ja4Info) free(handle->ja4Info);
    memset((void *)handle, 0, sizeof(recordHandle_t));
    handle->recordHeaderV3 = recordHeaderV3;

    elementHeader_t *elementHeader = (elementHeader_t *)((void *)recordHeaderV3 + sizeof(recordHeaderV3_t));
    // map all extensions
    for (int i = 0; i < recordHeaderV3->numElements; i++) {
        if ((elementHeader->type > 0 && elementHeader->type < MAXEXTENSIONS) && elementHeader->length != 0) {
            handle->extensionList[elementHeader->type] = (void *)elementHeader + sizeof(elementHeader_t);
            elementHeader = (elementHeader_t *)((void *)elementHeader + elementHeader->length);
            handle->elementBits |= 1 << elementHeader->type;
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

static inline void AppendToBuffer(nffile_t *nffile, void *record, size_t required) {
    // flush current buffer to disc
    if (!CheckBufferSpace(nffile, required)) {
        return;
    }

    // enough buffer space available at this point
    memcpy(nffile->buff_ptr, record, required);

    // update stat
    nffile->block_header->NumRecords++;
    nffile->block_header->size += required;

    // advance write pointer
    nffile->buff_ptr = (void *)((pointer_addr_t)nffile->buff_ptr + required);

}  // End of AppendToBuffer
