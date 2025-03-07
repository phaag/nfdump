/*
 *  Copyright (c) 2021-2025, Peter Haag
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

#include "maxmind.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "maxmind.h"
#include "mmhash.h"
#include "nffile.h"
#include "nffileV2.h"
#include "nfxV3.h"
#include "util.h"

#define arrayElementSizeCheck(type)                                          \
    if (arrayHeader->size != sizeof(type##_t)) {                             \
        LogError("Size check failed for %s - rebuild nfdump geo DB", #type); \
        return 0;                                                            \
    }

#define PushArrayHeader(dataBlock, arrayType, arraySize)   \
    (dataBlock)->type = DATA_BLOCK_TYPE_4;                 \
    void *p = ((void *)(dataBlock) + sizeof(dataBlock_t)); \
    recordHeader_t *arrayHeader = (recordHeader_t *)p;     \
    arrayHeader->type = arrayType;                         \
    arrayHeader->size = arraySize;                         \
    (dataBlock)->size += sizeof(recordHeader_t);

static void StoreLocalMap(nffile_t *nffile) {
    // get new empty data block
    dataBlock_t *dataBlock = WriteBlock(nffile, NULL);
    dataBlock->type = DATA_BLOCK_TYPE_4;
    void *outBuff = GetCursor(dataBlock);

    // put array header on block
    PushArrayHeader(dataBlock, LocalInfoElementID, sizeof(locationInfo_t));
    outBuff = GetCurrentCursor(dataBlock);

    for (locationInfo_t *locationInfo = NextLocation(FIRSTNODE); locationInfo != NULL; locationInfo = NextLocation(NEXTNODE)) {
        if (!IsAvailable(dataBlock, sizeof(locationInfo_t))) {
            // flush block - get an empty one
            dataBlock = WriteBlock(nffile, dataBlock);

            // put array header on block
            PushArrayHeader(dataBlock, LocalInfoElementID, sizeof(locationInfo_t));
            outBuff = GetCurrentCursor(dataBlock);
        }

        memcpy(outBuff, locationInfo, sizeof(locationInfo_t));
        outBuff += sizeof(locationInfo_t);
        dataBlock->size += sizeof(locationInfo_t);
        dataBlock->NumRecords++;
    }
    // flush current datablock
    FlushBlock(nffile, dataBlock);

}  // End of StoreLocalMap

static void StoreIPV4tree(nffile_t *nffile) {
    // get new empty data block
    dataBlock_t *dataBlock = WriteBlock(nffile, NULL);
    dataBlock->type = DATA_BLOCK_TYPE_4;
    void *outBuff = GetCursor(dataBlock);

    // put array header on block
    PushArrayHeader(dataBlock, IPV4treeElementID, sizeof(ipV4Node_t));
    outBuff = GetCurrentCursor(dataBlock);

    for (ipV4Node_t *ipv4Node = NextIPv4Node(FIRSTNODE); ipv4Node != NULL; ipv4Node = NextIPv4Node(NEXTNODE)) {
        if (!IsAvailable(dataBlock, sizeof(ipV4Node_t))) {
            // flush block - get an empty one
            dataBlock = WriteBlock(nffile, dataBlock);

            // put array header on block
            PushArrayHeader(dataBlock, IPV4treeElementID, sizeof(ipV4Node_t));
            outBuff = GetCurrentCursor(dataBlock);
        }

        memcpy(outBuff, ipv4Node, sizeof(ipV4Node_t));
        outBuff += sizeof(ipV4Node_t);
        dataBlock->size += sizeof(ipV4Node_t);
        dataBlock->NumRecords++;
    }
    // flush current datablock
    FlushBlock(nffile, dataBlock);

}  // End of StoreIPtree

static void StoreIPV6tree(nffile_t *nffile) {
    // get new empty data block
    dataBlock_t *dataBlock = WriteBlock(nffile, NULL);
    dataBlock->type = DATA_BLOCK_TYPE_4;
    void *outBuff = GetCursor(dataBlock);

    // put array header on block
    PushArrayHeader(dataBlock, IPV6treeElementID, sizeof(ipV6Node_t));
    outBuff = GetCurrentCursor(dataBlock);

    for (ipV6Node_t *ipv6Node = NextIPv6Node(FIRSTNODE); ipv6Node != NULL; ipv6Node = NextIPv6Node(NEXTNODE)) {
        if (!IsAvailable(dataBlock, sizeof(ipV6Node_t))) {
            // flush block - get an empty one
            dataBlock = WriteBlock(nffile, dataBlock);

            // put array header on block
            PushArrayHeader(dataBlock, IPV6treeElementID, sizeof(ipV6Node_t));
            outBuff = GetCurrentCursor(dataBlock);
        }

        memcpy(outBuff, ipv6Node, sizeof(ipV6Node_t));
        outBuff += sizeof(ipV6Node_t);
        dataBlock->size += sizeof(ipV6Node_t);
        dataBlock->NumRecords++;
    }
    // flush current datablock
    FlushBlock(nffile, dataBlock);

}  // End of StoreIPtree

static void StoreASV4tree(nffile_t *nffile) {
    // get new empty data block
    dataBlock_t *dataBlock = WriteBlock(nffile, NULL);
    void *outBuff = GetCursor(dataBlock);

    // put array header on block
    PushArrayHeader(dataBlock, ASV4treeElementID, sizeof(asV4Node_t));
    outBuff = GetCurrentCursor(dataBlock);

    for (asV4Node_t *asV4Node = NextasV4Node(FIRSTNODE); asV4Node != NULL; asV4Node = NextasV4Node(NEXTNODE)) {
        if (!IsAvailable(dataBlock, sizeof(asV4Node_t))) {
            // flush block - get an empty one
            dataBlock = WriteBlock(nffile, dataBlock);

            // put array header on block
            PushArrayHeader(dataBlock, ASV4treeElementID, sizeof(asV4Node_t));
            outBuff = GetCurrentCursor(dataBlock);
        }

        memcpy(outBuff, asV4Node, sizeof(asV4Node_t));
        outBuff += sizeof(asV4Node_t);
        dataBlock->size += sizeof(asV4Node_t);
        dataBlock->NumRecords++;
    }
    // flush current datablock
    FlushBlock(nffile, dataBlock);

}  // End of StoreASV4tree

static void StoreASV6tree(nffile_t *nffile) {
    // get new empty data block
    dataBlock_t *dataBlock = WriteBlock(nffile, NULL);
    dataBlock->type = DATA_BLOCK_TYPE_4;
    void *outBuff = GetCursor(dataBlock);

    // put array header on block
    PushArrayHeader(dataBlock, ASV6treeElementID, sizeof(asV6Node_t));
    outBuff = GetCurrentCursor(dataBlock);

    for (asV6Node_t *asV6Node = NextasV6Node(FIRSTNODE); asV6Node != NULL; asV6Node = NextasV6Node(NEXTNODE)) {
        if (!IsAvailable(dataBlock, sizeof(asV6Node_t))) {
            // flush block - get an empty one
            dataBlock = WriteBlock(nffile, dataBlock);

            // put array header on block
            PushArrayHeader(dataBlock, ASV6treeElementID, sizeof(asV6Node_t));
            outBuff = GetCurrentCursor(dataBlock);
        }

        memcpy(outBuff, asV6Node, sizeof(asV6Node_t));
        outBuff += sizeof(asV6Node_t);
        dataBlock->size += sizeof(asV6Node_t);
        dataBlock->NumRecords++;
    }
    // flush current datablock
    FlushBlock(nffile, dataBlock);

}  // End of StoreASV6tree

static void StoreASorgtree(nffile_t *nffile) {
    // get new empty data block
    dataBlock_t *dataBlock = WriteBlock(nffile, NULL);
    void *outBuff = GetCursor(dataBlock);

    // put array header on block
    PushArrayHeader(dataBlock, ASOrgtreeElementID, sizeof(asOrgNode_t));
    outBuff = GetCurrentCursor(dataBlock);

    for (asOrgNode_t *asOrgNode = NextasOrgNode(FIRSTNODE); asOrgNode != NULL; asOrgNode = NextasOrgNode(NEXTNODE)) {
        if (!IsAvailable(dataBlock, sizeof(asOrgNode_t))) {
            // flush block - get an empty one
            dataBlock = WriteBlock(nffile, dataBlock);

            // put array header on block
            PushArrayHeader(dataBlock, ASOrgtreeElementID, sizeof(asOrgNode_t));
            outBuff = GetCurrentCursor(dataBlock);
        }

        memcpy(outBuff, asOrgNode, sizeof(asOrgNode_t));
        outBuff += sizeof(asOrgNode_t);
        dataBlock->size += sizeof(asOrgNode_t);
        dataBlock->NumRecords++;
    }
    // flush current datablock
    FlushBlock(nffile, dataBlock);

}  // End of StoreASorgtree

int SaveMaxMind(char *fileName) {
    nffile_t *nffile = OpenNewFile(fileName, NULL, CREATOR_LOOKUP, LZ4_COMPRESSED, NOT_ENCRYPTED);
    if (!nffile) {
        LogError("OpenNewFile(%s) failed", fileName);
        return 0;
    }
    // store all geo records
    StoreLocalMap(nffile);
    StoreIPV4tree(nffile);
    StoreIPV6tree(nffile);
    StoreASV4tree(nffile);
    StoreASV6tree(nffile);
    StoreASorgtree(nffile);
    return CloseUpdateFile(nffile);

}  // End of SaveMaxMind

int LoadMaxMind(char *fileName) {
    dbg_printf("Load MaxMind file %s\n", fileName);

    if (!Init_MaxMind()) return 0;

    nffile_t *nffile = OpenFile(fileName, NULL);
    if (!nffile) {
        return 0;
    }
    int done = 0;
    dataBlock_t *dataBlock = NULL;
    while (!done) {
        // get next data block from file
        dataBlock = ReadBlock(nffile, dataBlock);
        if (dataBlock == NULL) {
            done = 1;
            continue;
        }

        dbg_printf("Next block. type: %u, size: %u\n", dataBlock->type, dataBlock->size);
        if (dataBlock->type != DATA_BLOCK_TYPE_4) {
            LogError("Can't process block type %u. Skip block.\n", dataBlock->type);
            continue;
        }

        record_header_t *arrayHeader = GetCursor(dataBlock);
        void *arrayElement = (void *)arrayHeader + sizeof(record_header_t);
        size_t expected = (arrayHeader->size * dataBlock->NumRecords) + sizeof(record_header_t);
        if (expected != dataBlock->size) {
            LogError("Array size calculated: %zu != expected: %u for element: %u", expected, dataBlock->size, arrayHeader->type);
            return 0;
        }

        switch (arrayHeader->type) {
            case LocalInfoElementID: {
                locationInfo_t *locationInfo = (locationInfo_t *)arrayElement;
                arrayElementSizeCheck(locationInfo);
                LoadLocalInfo(locationInfo, dataBlock->NumRecords);
            } break;
            case IPV4treeElementID: {
                ipV4Node_t *ipV4Node = (ipV4Node_t *)arrayElement;
                arrayElementSizeCheck(ipV4Node);
                LoadIPv4Tree(ipV4Node, dataBlock->NumRecords);
            } break;
            case IPV6treeElementID: {
                ipV6Node_t *ipV6Node = (ipV6Node_t *)arrayElement;
                arrayElementSizeCheck(ipV6Node);
                LoadIPv6Tree(ipV6Node, dataBlock->NumRecords);
            } break;
            case ASV4treeElementID: {
                asV4Node_t *asV4Node = (asV4Node_t *)arrayElement;
                arrayElementSizeCheck(asV4Node);
                LoadASV4Tree(asV4Node, dataBlock->NumRecords);
            } break;
            case ASV6treeElementID: {
                asV6Node_t *asV6Node = (asV6Node_t *)arrayElement;
                arrayElementSizeCheck(asV6Node);
                LoadASV6Tree(asV6Node, dataBlock->NumRecords);
            } break;
            case ASOrgtreeElementID: {
                asOrgNode_t *asOrgNode = (asOrgNode_t *)arrayElement;
                arrayElementSizeCheck(asOrgNode);
                LoadASorgTree(asOrgNode, dataBlock->NumRecords);
            } break;
            default:
                LogError("Skip unknown array element: %u", arrayHeader->type);
        }
    }
    FreeDataBlock(dataBlock);
    DisposeFile(nffile);

    return 1;
}  // End of LoadMaxMind
