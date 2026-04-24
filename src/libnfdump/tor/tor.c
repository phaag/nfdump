/*
 *  Copyright (c) 2025-2026, Peter Haag
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

#include "tor.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "conf/nfconf.h"
#include "id.h"
#include "logging.h"
#include "nffileV3/nffileV3.h"
#include "util.h"

// include after
#include "kbtree.h"

static inline int torNodeCMP(torNode_t a, torNode_t b) {
    if (a.ipaddr == b.ipaddr) return 0;
    return a.ipaddr > b.ipaddr ? 1 : -1;
}

KBTREE_INIT(torTree, torNode_t, torNodeCMP);

static kbtree_t(torTree) *torTree = NULL;

/*
 * Flat array state — used by LoadTorTree / LookupV4Tor / LookupIP.
 * The generation path (Init_TorLookup / UpdateTorNode / SaveTorTree)
 * continues to use the kbtree above.
 */
#define TORFLAT_MAGIC 0x544F5246U /* 'T','O','R','F' */
#define TORFLAT_VERSION 1U

typedef struct torFlatHeader_s {
    uint32_t magic;
    uint32_t version;
    uint32_t count;
    uint32_t reserved; /* pad to 16 bytes */
} torFlatHeader_t;

static torNode_t *torArray = NULL; /* base of sorted array           */
static uint32_t torCount = 0;      /* number of elements             */
static void *torMmap = NULL;       /* non-NULL when array is mmap'd  */
static size_t torMmapSize = 0;     /* length passed to munmap()      */

/* bsearch comparator: sort / search by ipaddr ascending */
static int torNodeCmpByIP(const void *a, const void *b) {
    uint32_t x = ((const torNode_t *)a)->ipaddr;
    uint32_t y = ((const torNode_t *)b)->ipaddr;
    if (x < y) return -1;
    if (x > y) return 1;
    return 0;
}

/*
 * Write a flat binary cache file for fast subsequent loads.
 * Uses write-to-temp + atomic rename so concurrent readers never see a
 * partial file.  Failures are non-fatal (next load simply re-reads nffileV3).
 */
static void torWriteFlatCache(const char *flatPath) {
    char tmpPath[PATH_MAX];
    snprintf(tmpPath, sizeof(tmpPath), "%s.tmp", flatPath);

    int fd = open(tmpPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        dbg_printf("torWriteFlatCache: cannot create %s: %s\n", tmpPath, strerror(errno));
        return;
    }

    torFlatHeader_t hdr = {
        .magic = TORFLAT_MAGIC,
        .version = TORFLAT_VERSION,
        .count = torCount,
        .reserved = 0,
    };
    ssize_t hdrWritten = write(fd, &hdr, sizeof(hdr));
    ssize_t dataWritten = (hdrWritten == (ssize_t)sizeof(hdr)) ? write(fd, torArray, torCount * sizeof(torNode_t)) : -1;
    close(fd);

    if (dataWritten != (ssize_t)(torCount * sizeof(torNode_t))) {
        unlink(tmpPath);
        dbg_printf("torWriteFlatCache: write error for %s\n", tmpPath);
        return;
    }
    if (rename(tmpPath, flatPath) != 0) {
        unlink(tmpPath);
        dbg_printf("torWriteFlatCache: rename failed for %s\n", tmpPath);
    }
}  // End of torWriteFlatCache

// returns ok
int Init_TorLookup(void) {
    torTree = kb_init(torTree, KB_DEFAULT_SIZE);

    return 1;
}  // End of Init_TorLookup

static char *tmString(time_t time, char *buff, size_t len) {
    struct tm tmTime_buf;
    struct tm *tmTime = localtime_r(&time, &tmTime_buf);
    snprintf(buff, len, "%4d-%02d-%02d %02d:%02d:%02d", tmTime->tm_year + 1900, tmTime->tm_mon + 1, tmTime->tm_mday, tmTime->tm_hour, tmTime->tm_min,
             tmTime->tm_sec);
    return buff;
}

static void printTorNode(torNode_t *node) {
    char first[64], last[64], published[64];
    char ip[32];
    uint32_t torIP = ntohl(node->ipaddr);
    inet_ntop(PF_INET, &torIP, ip, sizeof(ip));
    printf("Node: %s, last published: %s, intervals: %d\n", ip, tmString(node->lastPublished, published, sizeof(published)), node->gaps + 1);
    for (int i = 0; i <= node->intervalIndex; i++) {
        printf(" %d first: %s, last: %s\n", i, tmString(node->interval[i].firstSeen, first, sizeof(first)),
               tmString(node->interval[i].lastSeen, last, sizeof(last)));
    }
}

/*

Published
A node publishes as soon as it passes it's self test
Can also be read as meaning last published
A descriptor is published when changed or 18hrs passed
Doesn't consider if the node went down, for example the vm paused/network interruptions
Uptime must reset (to trigger a re-publish) by restart

LastStatus
Can be read as meaning the node is active, has the exit flag, and not marked bad
The exit is allowed to be bad when consensus method is less than 11
So in the interval [Published, LastStatus] having Published < LastStatus this means

the self test was passed, consensus was taken, and an exit-policy was published with the descriptor
the authority managed to connect to this node in the last 45 minutes from LastStatus
Be careful where Published > LastStatus such as this case

Published 2014-12-22 22:00:29
LastStatus 2014-12-22 20:03:07
ExitAddress xx.xx.xxx.xx 2014-12-22 22:14:11

The node may have given up the Exit flag, or may have gotten BadExit. Tor has many transient qualities so things like
this happen. The node was tested after re-publishing it's descriptor but didn't get consensus (but was still in the
cache of TorDNSEL).

A similar argument applies in the interval [Published, Test] except you know the node was an exit at the time of the
test. Consider another example from the CollecTor page.

Published 2010-12-28 07:35:55
LastStatus 2010-12-28 08:10:11
ExitAddress 91.102.152.236 2010-12-28 07:10:30
ExitAddress 91.102.152.227 2010-12-28 10:35:30

This node last updated it's descriptor at 07:35:55. It did this after the test at 7:10:30. The last consensus was at
08:10:11 and the last test was at 10:35:30. What conclusions can be drawn about both exit ip's? The first ip was
internal to tor and was also the exit. The second was found to be an exit. Maybe they've only got one ip address and it
changed. Maybe they run a multi-homed node. The point is what we know (and can guarantee) is limited compared to what we
can try to guess (and may be right but certainly not in general).

Even in case I can get no guarantees, I'd be happy to know if I can at least get a time interval for which the address
was probably an exit node. So then what's the answer? It's this -- hope for the best. A node that isn't in the consensus
can (but probably shouldn't) still be tested. For an arbitrary entry any time after the LastStatus (minus a max of 45
minutes) until you take the consensus as expired is such an interval. Depending on how you consider expired consensus
that means 1 - 3 hours (up to fresh-until, or, not past valid-until).

tl;dr, for a given LastStatus, 1 - 3 hours depending on your preferred view of expired consensus. This is based on
hoping for the best possible scenario in general. It would be best to consider the history of an exit across as many
sample points as possible.
*/
void UpdateTorNode(torNode_t *torNode) {
    torNode_t *node = kb_getp(torTree, torTree, torNode);
    if (node) {
        int index = node->intervalIndex;
        // printf("node updated\n");
        if (node->lastPublished <= torNode->lastPublished) {
            time_t diffPublishTime = torNode->lastPublished - node->lastPublished;
            if (diffPublishTime > (24 * 3600)) {
                time_t diffLastSeen = torNode->interval[0].lastSeen - node->interval[index].lastSeen;
                if (diffLastSeen > (24 * 3600)) {
                    dbg_printf("Last published gap > 18h %ld\n", diffPublishTime / 3600);
                    node->gaps++;
                    node->intervalIndex = (node->intervalIndex + 1) % MAXINTERVALS;
                    index = node->intervalIndex;
                    dbg_printf("Not seen in 24h - %ld. %d gaps, index: %d\n", diffLastSeen / 3600, node->gaps, index);
                    node->interval[index].firstSeen = torNode->lastPublished;
                }
            }

            node->lastPublished = torNode->lastPublished;
            if (torNode->interval[0].lastSeen > node->interval[index].lastSeen) node->interval[index].lastSeen = torNode->interval[0].lastSeen;
            if (torNode->interval[0].firstSeen < node->interval[index].firstSeen) abort();
        }

    } else {
        torNode->interval[0].firstSeen = torNode->lastPublished;
        kb_putp(torTree, torTree, torNode);
        // printf("node inserted\n");
    }
}

int SaveTorTree(char *fileName) {
    nffileV3_t *nffile = OpenNewFileV3(fileName, CREATOR_TORLOOKUP, LZ4_COMPRESSED, LEVEL_0, NOT_ENCRYPTED);
    if (!nffile) {
        LogError("OpenNewFileV3(%s) failed", fileName);
        return 0;
    }
    uint32_t blockSize = nffile->fileHeader->blockSize;

    // get new empty data block
    arrayBlockV3_t *dataBlock = NULL;
    InitDataBlock(dataBlock, blockSize);
    dataBlock->elementType = TorTreeElementID;
    dataBlock->elementSize = sizeof(torNode_t);

    uint8_t *outBuff = GetCursor(dataBlock);

    kbitr_t itr;
    kb_itr_first(torTree, torTree, &itr);                              // get an iterator pointing to the first
    for (; kb_itr_valid(&itr); kb_itr_next(torTree, torTree, &itr)) {  // move on
        torNode_t *torNode = &kb_itr_key(torNode_t, &itr);
        dbg_printf("ip: %u, first: %ld, last: %ld\n", torNode->ipaddr, torNode->interval[0].firstSeen, torNode->interval[0].lastSeen);
        if (!IsAvailable(dataBlock, blockSize, sizeof(torNode_t))) {
            // flush block - get an empty one
            WriteBlockV3(nffile, dataBlock);
            dataBlock = NULL;
            InitDataBlock(dataBlock, blockSize);
            dataBlock->elementType = TorTreeElementID;
            dataBlock->elementSize = sizeof(torNode_t);

            outBuff = GetCursor(dataBlock);
        }

        memcpy(outBuff, torNode, sizeof(torNode_t));
        outBuff += sizeof(torNode_t);
        dataBlock->rawSize += sizeof(torNode_t);
        dataBlock->numElements++;
    }
    // flush current datablock
    FlushBlockV3(nffile, dataBlock);
    int ret = FlushFileV3(nffile);
    CloseFileV3(nffile);

    return ret;
}  // End of SaveTorTree

/* Load (mmap) a flat binary cache file produced by torWriteFlatCache.
 * Returns 1 on success, 0 on any failure (caller falls back to slow path). */
static int torLoadFlatCache(const char *flatPath) {
    int fd = open(flatPath, O_RDONLY);
    if (fd < 0) return 0;

    torFlatHeader_t hdr;
    if (read(fd, &hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr) || hdr.magic != TORFLAT_MAGIC || hdr.version != TORFLAT_VERSION || hdr.count == 0) {
        close(fd);
        return 0;
    }

    size_t mapSize = sizeof(torFlatHeader_t) + (size_t)hdr.count * sizeof(torNode_t);
    void *m = mmap(NULL, mapSize, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (m == MAP_FAILED) return 0;

    torMmap = m;
    torMmapSize = mapSize;
    torArray = (torNode_t *)((char *)m + sizeof(torFlatHeader_t));
    torCount = hdr.count;
    dbg_printf("torLoadFlatCache: mmap'd %u nodes from %s\n", torCount, flatPath);
    return 1;
}  // End of torLoadFlatCache

int LoadTorTree(char *fileName) {
    dbg_printf("Load TorNode DB file %s\n", fileName);

    /* ---- Fix 1: if the caller passed the .flat file directly, use it ---- */
    size_t fnLen = strlen(fileName);
    if (fnLen > 5 && strcmp(fileName + fnLen - 5, ".flat") == 0) {
        if (torLoadFlatCache(fileName)) return 1;
        LogError("LoadTorTree: cannot load flat file %s", fileName);
        return 0;
    }

    /* ---- Build flat path: respect tordb.flatpath config key (fix 2) ---- */
    char flatPath[PATH_MAX];
    char *flatDir = ConfGetString("tordb.flatpath");
    if (flatDir) {
        const char *base = strrchr(fileName, '/');
        base = base ? base + 1 : fileName;
        snprintf(flatPath, sizeof(flatPath), "%s/%s.flat", flatDir, base);
        free(flatDir);
    } else {
        snprintf(flatPath, sizeof(flatPath), "%s.flat", fileName);
    }

    /* ---- fast path: mmap the flat binary cache if it is up-to-date ---- */
    struct stat stNf, stFlat;
    if (stat(fileName, &stNf) == 0 && stat(flatPath, &stFlat) == 0 && stFlat.st_mtime >= stNf.st_mtime) {
        if (torLoadFlatCache(flatPath)) return 1;
        LogError("open() tor lookup cache '%s' failed: %s", flatPath, strerror(errno));
    }

    /* ---- slow path: decompress nffileV3, build malloc'd array ---- */
    nffileV3_t *nffile = OpenFileV3(fileName);
    if (!nffile) {
        return 0;
    }

    arrayBlockV3_t *dataBlock = NULL;
    int done = 0;
    while (!done) {
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

        size_t expected = (dataBlock->elementSize * dataBlock->numElements) + sizeof(arrayBlockV3_t);
        if (expected != dataBlock->rawSize || dataBlock->elementType != TorTreeElementID || dataBlock->elementSize != sizeof(torNode_t)) {
            if (dataBlock->elementType == TorTreeElementID)
                LogError("Bad array block - size error - found: %zu, expected: %u", expected, dataBlock->rawSize);
            FreeDataBlock(dataBlock);
            continue;
        }

        uint32_t n = dataBlock->numElements;
        torNode_t *src = (torNode_t *)ResetCursor(dataBlock);
        torNode_t *tmp = realloc(torArray, (torCount + n) * sizeof(torNode_t));
        if (!tmp) {
            LogError("realloc() failed in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            FreeDataBlock(dataBlock);
            break;
        }
        torArray = tmp;
        memcpy(torArray + torCount, src, n * sizeof(torNode_t));
        torCount += n;
        FreeDataBlock(dataBlock);
    }
    CloseFileV3(nffile);

    if (torCount == 0) return 0;

    /* SaveTorTree writes records via in-order kbtree iteration, so the
     * nffileV3 blocks arrive sorted.  qsort is a defensive safety net. */
    qsort(torArray, torCount, sizeof(torNode_t), torNodeCmpByIP);

    /* write flat cache for fast-path use on the next invocation */
    torWriteFlatCache(flatPath);

    dbg_printf("LoadTorTree: loaded %u nodes from %s\n", torCount, fileName);
    return 1;
}  // End of LoadTorTree

// return 1 - if IP is tor exit node
// input nfdump IP addr, first/last in msec
int LookupV4Tor(uint32_t ip, uint64_t first, uint64_t last, char *torInfo) {
    if (!torArray) {
        torInfo[0] = '\0';
        return 0;
    }

    torNode_t key = {.ipaddr = ip};
    torNode_t *torNode = bsearch(&key, torArray, torCount, sizeof(torNode_t), torNodeCmpByIP);
    if (torNode) {
        first /= 1000;
        last /= 1000;
        for (int i = 0; i <= (int)torNode->intervalIndex; i++) {
            // allow 24h over last seen
            time_t graceLastSeen = torNode->interval[i].lastSeen + 24 * 3600;
            if ((first >= (uint64_t)torNode->interval[i].firstSeen && first <= (uint64_t)graceLastSeen) ||
                (last >= (uint64_t)torNode->interval[i].firstSeen && last <= (uint64_t)graceLastSeen)) {
                torInfo[0] = 'E';
                torInfo[1] = 'X';
                torInfo[2] = '\0';
                return 1;
            }
        }
        torInfo[0] = 'e';
        torInfo[1] = 'x';
        torInfo[2] = '\0';
        return 1;
    } else {
        // nothing found
        torInfo[0] = '.';
        torInfo[1] = '.';
        torInfo[2] = '\0';
    }

    return 0;

}  // End of LookupV4Tor

int LookupV6Tor(uint64_t ip[2], uint64_t first, uint64_t last, char *torInfo) {
    if (!torArray) {
        torInfo[0] = '\0';
        return 0;
    }

    // IPv6 not yet implemented
    torInfo[0] = '.';
    torInfo[1] = '.';
    torInfo[2] = '\0';

    return 0;

}  // End of LookupV6Tor

void LookupIP(char *ipstring) {
    if (!torArray) {
        printf("No torDB available");
        return;
    }
    // IPv4
    uint32_t ip;
    int ret = inet_pton(PF_INET, ipstring, &ip);
    if (ret != 1) return;
    torNode_t key = {.ipaddr = ntohl(ip)};
    torNode_t *torNode = bsearch(&key, torArray, torCount, sizeof(torNode_t), torNodeCmpByIP);
    if (torNode) {
        printTorNode(torNode);
    } else {
        printf("No tor exit node: %s\n", ipstring);
    }
}

void FreeTorTree(void) {
    if (torMmap) {
        munmap(torMmap, torMmapSize);
        torMmap = NULL;
        torMmapSize = 0;
    } else {
        free(torArray);
    }
    torArray = NULL;
    torCount = 0;
}  // End of FreeTorTree
