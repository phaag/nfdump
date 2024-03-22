/*
 *  Copyright (c) 2021-2024, Peter Haag
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

#define LocalInfoElementID 1
#define IPV4treeElementID 2
#define IPV6treeElementID 3
#define ASV4treeElementID 4
#define ASV6treeElementID 5

#define arrayElementSizeCheck(type)                                          \
    if (arrayHeader->size != sizeof(type##_t)) {                             \
        LogError("Size check failed for %s - rebuild nfdump geo DB", #type); \
        return 0;                                                            \
    }

#include "nffile_inline.c"

#define FIRSTRECORD 1
#define NEXTRECORD 0
static void StoreLocalMap(nffile_t *nffile) {
    void *outBuff = nffile->buff_ptr;

    size_t size = 0;
    locationInfo_t *locationInfo = NextLocation(FIRSTRECORD);
    while (locationInfo) {
        if (size < sizeof(locationInfo_t)) {
            nffile->buff_ptr = (void *)outBuff;
            size = CheckBufferSpace(nffile, sizeof(locationInfo_t));

            // make it an array block
            nffile->block_header->type = DATA_BLOCK_TYPE_4;

            outBuff = nffile->buff_ptr;
            recordHeader_t *arrayHeader = (recordHeader_t *)outBuff;
            // set array element info
            arrayHeader->type = LocalInfoElementID;
            arrayHeader->size = sizeof(locationInfo_t);
            nffile->block_header->size += sizeof(recordHeader_t);
            size -= sizeof(recordHeader_t);
            outBuff += sizeof(recordHeader_t);
        }
        memcpy(outBuff, locationInfo, sizeof(locationInfo_t));
        outBuff += sizeof(locationInfo_t);
        size -= sizeof(locationInfo_t);
        nffile->block_header->size += sizeof(locationInfo_t);
        nffile->block_header->NumRecords++;
        locationInfo = NextLocation(NEXTRECORD);
    }

}  // End of StoreLocalMap

static int StoreIPV4tree(nffile_t *nffile) {
    void *outBuff = nffile->buff_ptr;

    size_t size = 0;
    ipV4Node_t *ipv4Node = NextIPv4Node(FIRSTRECORD);
    while (ipv4Node) {
        if (size < sizeof(ipV4Node_t)) {
            nffile->buff_ptr = (void *)outBuff;
            size = CheckBufferSpace(nffile, sizeof(ipV4Node_t));

            // make it an array block
            nffile->block_header->type = DATA_BLOCK_TYPE_4;

            outBuff = nffile->buff_ptr;
            recordHeader_t *arrayHeader = (recordHeader_t *)outBuff;
            // set array element info
            arrayHeader->type = IPV4treeElementID;
            arrayHeader->size = sizeof(ipV4Node_t);
            nffile->block_header->size += sizeof(recordHeader_t);
            size -= sizeof(recordHeader_t);
            outBuff += sizeof(recordHeader_t);
        }
        memcpy(outBuff, ipv4Node, sizeof(ipV4Node_t));
        outBuff += sizeof(ipV4Node_t);
        size -= sizeof(ipV4Node_t);
        nffile->block_header->size += sizeof(ipV4Node_t);
        nffile->block_header->NumRecords++;
        ipv4Node = NextIPv4Node(NEXTRECORD);
    }

    return 1;

}  // End of StoreIPtree

static void StoreIPV6tree(nffile_t *nffile) {
    void *outBuff = nffile->buff_ptr;

    size_t size = 0;
    ipV6Node_t *ipv6Node = NextIPv6Node(FIRSTRECORD);
    while (ipv6Node) {
        if (size < sizeof(ipV6Node_t)) {
            nffile->buff_ptr = (void *)outBuff;
            size = CheckBufferSpace(nffile, sizeof(ipV6Node_t));

            // make it an array block
            nffile->block_header->type = DATA_BLOCK_TYPE_4;

            outBuff = nffile->buff_ptr;
            recordHeader_t *arrayHeader = (recordHeader_t *)outBuff;
            // set array element info
            arrayHeader->type = IPV6treeElementID;
            arrayHeader->size = sizeof(ipV6Node_t);
            nffile->block_header->size += sizeof(recordHeader_t);
            size -= sizeof(recordHeader_t);
            outBuff += sizeof(recordHeader_t);
        }
        memcpy(outBuff, ipv6Node, sizeof(ipV6Node_t));
        outBuff += sizeof(ipV6Node_t);
        size -= sizeof(ipV6Node_t);
        nffile->block_header->size += sizeof(ipV6Node_t);
        nffile->block_header->NumRecords++;
        ipv6Node = NextIPv6Node(NEXTRECORD);
    }

}  // End of StoreIPtree

static void StoreAStree(nffile_t *nffile) {
    void *outBuff = nffile->buff_ptr;

    size_t size = 0;
    asV4Node_t *asV4Node = NextasV4Node(FIRSTNODE);
    while (asV4Node) {
        if (size < sizeof(asV4Node_t)) {
            nffile->buff_ptr = (void *)outBuff;
            size = CheckBufferSpace(nffile, sizeof(asV4Node_t));

            // make it an array block
            nffile->block_header->type = DATA_BLOCK_TYPE_4;

            outBuff = nffile->buff_ptr;
            recordHeader_t *arrayHeader = (recordHeader_t *)outBuff;
            // set array element info
            arrayHeader->type = ASV4treeElementID;
            arrayHeader->size = sizeof(asV4Node_t);
            nffile->block_header->size += sizeof(recordHeader_t);
            size -= sizeof(recordHeader_t);
            outBuff += sizeof(recordHeader_t);
        }
        memcpy(outBuff, asV4Node, sizeof(asV4Node_t));
        outBuff += sizeof(asV4Node_t);
        size -= sizeof(asV4Node_t);
        nffile->block_header->size += sizeof(asV4Node_t);
        nffile->block_header->NumRecords++;
        asV4Node = NextasV4Node(NEXTNODE);
    }

}  // End of StoreAStree

static void StoreASV6tree(nffile_t *nffile) {
    void *outBuff = nffile->buff_ptr;

    size_t size = 0;
    asV6Node_t *asV6Node = NextasV6Node(FIRSTNODE);
    while (asV6Node) {
        if (size < sizeof(asV6Node_t)) {
            nffile->buff_ptr = (void *)outBuff;
            size = CheckBufferSpace(nffile, sizeof(asV6Node_t));

            // make it an array block
            nffile->block_header->type = DATA_BLOCK_TYPE_4;

            outBuff = nffile->buff_ptr;
            recordHeader_t *arrayHeader = (recordHeader_t *)outBuff;
            // set array element info
            arrayHeader->type = ASV6treeElementID;
            arrayHeader->size = sizeof(asV6Node_t);
            nffile->block_header->size += sizeof(recordHeader_t);
            size -= sizeof(recordHeader_t);
            outBuff += sizeof(recordHeader_t);
        }
        memcpy(outBuff, asV6Node, sizeof(asV6Node_t));
        outBuff += sizeof(asV6Node_t);
        size -= sizeof(asV6Node_t);
        nffile->block_header->size += sizeof(asV6Node_t);
        nffile->block_header->NumRecords++;
        asV6Node = NextasV6Node(NEXTNODE);
    }

}  // End of StoreASV6tree

int SaveMaxMind(char *fileName) {
    nffile_t *nffile = OpenNewFile(fileName, NULL, CREATOR_LOOKUP, LZ4_COMPRESSED, NOT_ENCRYPTED);
    if (!nffile) {
        LogError("OpenNewFile(%s) failed", fileName);
        return 0;
    }

    StoreLocalMap(nffile);
    WriteBlock(nffile);

    StoreIPV4tree(nffile);
    WriteBlock(nffile);

    StoreIPV6tree(nffile);
    WriteBlock(nffile);

    StoreAStree(nffile);
    WriteBlock(nffile);

    StoreASV6tree(nffile);
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
        if (dataBlock == NF_EOF) {
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
            LogError("Array size calculated: %u != expected: %u for element: %u", expected, dataBlock->size, arrayHeader->type);
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
            default:
                LogError("Skip unknown array element: %u", arrayHeader->type);
        }
    }
    FreeDataBlock(dataBlock);
    DisposeFile(nffile);

    return 1;
}  // End of LoadMaxMind
