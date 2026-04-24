/*
 *  Copyright (c) 2021-2026, Peter Haag
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
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "conf/nfconf.h"
#include "id.h"
#include "logging.h"
#include "maxmind.h"
#include "mmhash.h"
#include "nffileV3/nffileV3.h"
#include "util.h"

#define arrayElementSizeCheck(type)                                          \
    if (arrayHeader->rawSize != sizeof(type##_t)) {                          \
        LogError("Size check failed for %s - rebuild nfdump geo DB", #type); \
        return 0;                                                            \
    }

static void StoreLocalMap(nffileV3_t *nffile) {
    uint32_t blockSize = nffile->fileHeader->blockSize;

    // init new array block
    arrayBlockV3_t *dataBlock = NULL;
    InitDataBlock(dataBlock, blockSize);
    dataBlock->elementType = LocalInfoElementID;
    dataBlock->elementSize = sizeof(locationInfo_t);

    uint8_t *outBuff = GetCursor(dataBlock);

    for (locationInfo_t *locationInfo = NextLocation(FIRSTNODE); locationInfo != NULL; locationInfo = NextLocation(NEXTNODE)) {
        if (!IsAvailable(dataBlock, blockSize, sizeof(locationInfo_t))) {
            // flush block - get an empty one
            WriteBlockV3(nffile, dataBlock);
            dataBlock = NULL;
            InitDataBlock(dataBlock, blockSize);
            dataBlock->elementType = LocalInfoElementID;
            dataBlock->elementSize = sizeof(locationInfo_t);

            outBuff = GetCursor(dataBlock);
        }

        memcpy(outBuff, locationInfo, sizeof(locationInfo_t));
        outBuff += sizeof(locationInfo_t);
        dataBlock->rawSize += sizeof(locationInfo_t);
        dataBlock->numElements++;
    }
    // flush current datablock
    FlushBlockV3(nffile, dataBlock);

}  // End of StoreLocalMap

static void StoreIPV4tree(nffileV3_t *nffile) {
    uint32_t blockSize = nffile->fileHeader->blockSize;

    // init new array block
    arrayBlockV3_t *dataBlock = NULL;
    InitDataBlock(dataBlock, blockSize);
    dataBlock->elementType = IPV4treeElementID;
    dataBlock->elementSize = sizeof(ipV4Node_t);

    uint8_t *outBuff = GetCursor(dataBlock);

    for (ipV4Node_t *ipv4Node = NextIPv4Node(FIRSTNODE); ipv4Node != NULL; ipv4Node = NextIPv4Node(NEXTNODE)) {
        if (!IsAvailable(dataBlock, blockSize, sizeof(ipV4Node_t))) {
            // flush block - get an empty one
            WriteBlockV3(nffile, dataBlock);
            dataBlock = NULL;
            InitDataBlock(dataBlock, blockSize);
            dataBlock->elementType = IPV4treeElementID;
            dataBlock->elementSize = sizeof(ipV4Node_t);

            outBuff = GetCursor(dataBlock);
        }

        memcpy(outBuff, ipv4Node, sizeof(ipV4Node_t));
        outBuff += sizeof(ipV4Node_t);
        dataBlock->rawSize += sizeof(ipV4Node_t);
        dataBlock->numElements++;
    }
    // flush current datablock
    FlushBlockV3(nffile, dataBlock);

}  // End of StoreIPtree

static void StoreIPV6tree(nffileV3_t *nffile) {
    uint32_t blockSize = nffile->fileHeader->blockSize;
    // get new empty data block
    arrayBlockV3_t *dataBlock = NULL;
    InitDataBlock(dataBlock, blockSize);
    dataBlock->elementType = IPV6treeElementID;
    dataBlock->elementSize = sizeof(ipV6Node_t);

    uint8_t *outBuff = GetCursor(dataBlock);

    for (ipV6Node_t *ipv6Node = NextIPv6Node(FIRSTNODE); ipv6Node != NULL; ipv6Node = NextIPv6Node(NEXTNODE)) {
        if (!IsAvailable(dataBlock, blockSize, sizeof(ipV6Node_t))) {
            // flush block - get an empty one
            WriteBlockV3(nffile, dataBlock);
            dataBlock = NULL;
            InitDataBlock(dataBlock, blockSize);
            dataBlock->elementType = IPV6treeElementID;
            dataBlock->elementSize = sizeof(ipV6Node_t);

            outBuff = GetCursor(dataBlock);
        }

        memcpy(outBuff, ipv6Node, sizeof(ipV6Node_t));
        outBuff += sizeof(ipV6Node_t);
        dataBlock->rawSize += sizeof(ipV6Node_t);
        dataBlock->numElements++;
    }
    // flush current datablock
    FlushBlockV3(nffile, dataBlock);

}  // End of StoreIPtree

static void StoreASV4tree(nffileV3_t *nffile) {
    uint32_t blockSize = nffile->fileHeader->blockSize;
    // get new empty data block
    arrayBlockV3_t *dataBlock = NULL;
    InitDataBlock(dataBlock, blockSize);
    dataBlock->elementType = ASV4treeElementID;
    dataBlock->elementSize = sizeof(asV4Node_t);

    uint8_t *outBuff = GetCursor(dataBlock);

    for (asV4Node_t *asV4Node = NextasV4Node(FIRSTNODE); asV4Node != NULL; asV4Node = NextasV4Node(NEXTNODE)) {
        if (!IsAvailable(dataBlock, blockSize, sizeof(asV4Node_t))) {
            // flush block - get an empty one
            WriteBlockV3(nffile, dataBlock);
            dataBlock = NULL;
            InitDataBlock(dataBlock, blockSize);
            dataBlock->elementType = ASV4treeElementID;
            dataBlock->elementSize = sizeof(asV4Node_t);

            outBuff = GetCursor(dataBlock);
        }

        memcpy(outBuff, asV4Node, sizeof(asV4Node_t));
        outBuff += sizeof(asV4Node_t);
        dataBlock->rawSize += sizeof(asV4Node_t);
        dataBlock->numElements++;
    }
    // flush current datablock
    FlushBlockV3(nffile, dataBlock);

}  // End of StoreASV4tree

static void StoreASV6tree(nffileV3_t *nffile) {
    uint32_t blockSize = nffile->fileHeader->blockSize;
    // get new empty data block
    arrayBlockV3_t *dataBlock = NULL;
    InitDataBlock(dataBlock, blockSize);
    dataBlock->elementType = ASV6treeElementID;
    dataBlock->elementSize = sizeof(asV6Node_t);

    uint8_t *outBuff = GetCursor(dataBlock);

    for (asV6Node_t *asV6Node = NextasV6Node(FIRSTNODE); asV6Node != NULL; asV6Node = NextasV6Node(NEXTNODE)) {
        if (!IsAvailable(dataBlock, blockSize, sizeof(asV6Node_t))) {
            // flush block - get an empty one
            WriteBlockV3(nffile, dataBlock);
            dataBlock = NULL;
            InitDataBlock(dataBlock, blockSize);
            dataBlock->elementType = ASV6treeElementID;
            dataBlock->elementSize = sizeof(asV6Node_t);

            outBuff = GetCursor(dataBlock);
        }

        memcpy(outBuff, asV6Node, sizeof(asV6Node_t));
        outBuff += sizeof(asV6Node_t);
        dataBlock->rawSize += sizeof(asV6Node_t);
        dataBlock->numElements++;
    }
    // flush current datablock
    FlushBlockV3(nffile, dataBlock);

}  // End of StoreASV6tree

static void StoreASorgtree(nffileV3_t *nffile) {
    uint32_t blockSize = nffile->fileHeader->blockSize;
    // get new empty data block
    arrayBlockV3_t *dataBlock = NULL;
    InitDataBlock(dataBlock, blockSize);
    dataBlock->elementType = ASOrgtreeElementID;
    dataBlock->elementSize = sizeof(asOrgNode_t);

    uint8_t *outBuff = GetCursor(dataBlock);

    for (asOrgNode_t *asOrgNode = NextasOrgNode(FIRSTNODE); asOrgNode != NULL; asOrgNode = NextasOrgNode(NEXTNODE)) {
        if (!IsAvailable(dataBlock, blockSize, sizeof(asOrgNode_t))) {
            // flush block - get an empty one
            WriteBlockV3(nffile, dataBlock);
            dataBlock = NULL;
            InitDataBlock(dataBlock, blockSize);
            dataBlock->elementType = ASOrgtreeElementID;
            dataBlock->elementSize = sizeof(asOrgNode_t);

            outBuff = GetCursor(dataBlock);
        }

        memcpy(outBuff, asOrgNode, sizeof(asOrgNode_t));
        outBuff += sizeof(asOrgNode_t);
        dataBlock->rawSize += sizeof(asOrgNode_t);
        dataBlock->numElements++;
    }
    // flush current datablock
    FlushBlockV3(nffile, dataBlock);

}  // End of StoreASorgtree

int SaveMaxMind(char *fileName) {
    nffileV3_t *nffile = OpenNewFileV3(fileName, CREATOR_GEOLOOKUP, LZ4_COMPRESSED, LEVEL_0, NOT_ENCRYPTED);
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
    int ret = FlushFileV3(nffile);
    CloseFileV3(nffile);

    return ret;
}  // End of SaveMaxMind

int LoadMaxMind(char *fileName) {
    dbg_printf("Load MaxMind file %s\n", fileName);

    if (!Init_MaxMind()) return 0;

    /* ---- Fix 1: if the caller passed the .flat file directly, use it ---- */
    size_t fnLen = strlen(fileName);
    if (fnLen > 5 && strcmp(fileName + fnLen - 5, ".flat") == 0) {
        if (LoadFlatCache(fileName)) {
            dbg_printf("LoadMaxMind: direct flat file %s\n", fileName);
            return 1;
        }
        LogError("LoadMaxMind: cannot load flat file %s", fileName);
        return 0;
    }

    /* ---- Build flat path: respect geodb.flatpath config key (fix 2) ---- */
    char flatPath[PATH_MAX];
    char *flatDir = ConfGetString("geodb.flatpath");
    if (flatDir) {
        const char *base = strrchr(fileName, '/');
        base = base ? base + 1 : fileName;
        snprintf(flatPath, sizeof(flatPath), "%s/%s.flat", flatDir, base);
        free(flatDir);
    } else {
        snprintf(flatPath, sizeof(flatPath), "%s.flat", fileName);
    }

    /* ---- fast path: mmap existing flat cache if it is newer than nffileV3 ---- */
    struct stat stNf, stFlat;
    if (stat(fileName, &stNf) == 0 && stat(flatPath, &stFlat) == 0 && stFlat.st_mtime >= stNf.st_mtime) {
        if (LoadFlatCache(flatPath)) {
            dbg_printf("LoadMaxMind: fast path via %s\n", flatPath);
            return 1;
        }
        /* fall through to nffileV3 load if mmap fails */
    }

    /* ---- slow path: decompress nffileV3, build flat arrays, write cache ---- */
    if (!InitFlatArrays()) return 0;

    nffileV3_t *nffile = OpenFileV3(fileName);
    if (!nffile) {
        return 0;
    }
    int done = 0;
    arrayBlockV3_t *dataBlock = NULL;
    while (!done) {
        // get next data block from file
        dataBlock = ReadBlockV3(nffile);
        if (dataBlock == NULL) {
            done = 1;
            continue;
        }

        dbg_printf("Next block. type: %u, size: %u\n", dataBlock->type, dataBlock->rawSize);
        if (dataBlock->type != BLOCK_TYPE_ARRAY) {
            LogError("Can't process block type %u. Skip block.\n", dataBlock->type);
            FreeDataBlock(dataBlock);
            continue;
        }

        void *arrayElement = ResetCursor(dataBlock);

        size_t expected = (dataBlock->elementSize * dataBlock->numElements) + sizeof(arrayBlockV3_t);
        if (expected != dataBlock->rawSize) {
            LogError("Bad array block - size error - found: %zu, expected: %u for element: %u", expected, dataBlock->rawSize, dataBlock->elementType);
            FreeDataBlock(dataBlock);
            continue;
        }

        switch (dataBlock->elementType) {
            case LocalInfoElementID: {
                locationInfo_t *locationInfo = (locationInfo_t *)arrayElement;
                if (dataBlock->elementSize != sizeof(locationInfo_t)) {
                    LogError("Size check failed for location info - rebuild nfdump geo DB");
                } else {
                    LoadLocalInfo(locationInfo, dataBlock->numElements);
                }
            } break;
            case IPV4treeElementID: {
                ipV4Node_t *ipV4Node = (ipV4Node_t *)arrayElement;
                if (dataBlock->elementSize != sizeof(ipV4Node_t)) {
                    LogError("Size check failed for IPv4 node - rebuild nfdump geo DB");
                } else {
                    LoadIPv4Tree(ipV4Node, dataBlock->numElements);
                }
            } break;
            case IPV6treeElementID: {
                ipV6Node_t *ipV6Node = (ipV6Node_t *)arrayElement;
                if (dataBlock->elementSize != sizeof(ipV6Node_t)) {
                    LogError("Size check failed for IPv6 node - rebuild nfdump geo DB");
                } else {
                    LoadIPv6Tree(ipV6Node, dataBlock->numElements);
                }
            } break;
            case ASV4treeElementID: {
                asV4Node_t *asV4Node = (asV4Node_t *)arrayElement;
                if (dataBlock->elementSize != sizeof(asV4Node_t)) {
                    LogError("Size check failed for ASv4 node - rebuild nfdump geo DB");
                } else {
                    LoadASV4Tree(asV4Node, dataBlock->numElements);
                }
            } break;
            case ASV6treeElementID: {
                asV6Node_t *asV6Node = (asV6Node_t *)arrayElement;
                if (dataBlock->elementSize != sizeof(asV6Node_t)) {
                    LogError("Size check failed for ASv6 node - rebuild nfdump geo DB");
                } else {
                    LoadASV6Tree(asV6Node, dataBlock->numElements);
                }
            } break;
            case ASOrgtreeElementID: {
                asOrgNode_t *asOrgNode = (asOrgNode_t *)arrayElement;
                if (dataBlock->elementSize != sizeof(asOrgNode_t)) {
                    LogError("Size check failed for AS org node - rebuild nfdump geo DB");
                } else {
                    LoadASorgTree(asOrgNode, dataBlock->numElements);
                }
            } break;
            default:
                LogError("Skip unknown array element: %u", dataBlock->elementType);
        }
        FreeDataBlock(dataBlock);
    }
    FreeDataBlock(dataBlock);
    CloseFileV3(nffile);

    /* write flat cache for fast-path use next time (best effort) */
    WriteFlatCache(flatPath);

    return 1;
}  // End of LoadMaxMind
