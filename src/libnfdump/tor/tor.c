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

static inline int torV4NodeCMP(torV4Node_t a, torV4Node_t b) {
    if (a.ipaddr == b.ipaddr) return 0;
    return a.ipaddr > b.ipaddr ? 1 : -1;
}

KBTREE_INIT(torV4Tree, torV4Node_t, torV4NodeCMP);

static kbtree_t(torV4Tree) *torV4Tree = NULL;

static inline int torV6NodeCMP(torV6Node_t a, torV6Node_t b) {
    if (a.network[0] != b.network[0]) return a.network[0] > b.network[0] ? 1 : -1;
    if (a.network[1] == b.network[1]) return 0;
    return a.network[1] > b.network[1] ? 1 : -1;
}

KBTREE_INIT(torV6Tree, torV6Node_t, torV6NodeCMP);

static kbtree_t(torV6Tree) *torV6Tree = NULL;

/*
 * Flat array state — used by LoadTorTree / LookupV4Tor / LookupV6Tor / LookupIP.
 * The generation path (Init_TorLookup / UpdateTorV4Node / UpdateTorV6Node / SaveTorTree)
 * continues to use the kbtrees above.
 */
#define TORFLAT_MAGIC 0x544F5246U /* 'T','O','R','F' */
#define TORFLAT_VERSION 2U

typedef struct torFlatHeader_s {
    uint32_t magic;
    uint32_t version;
    uint32_t v4count;
    uint32_t v6count;
} torFlatHeader_t;

static torV4Node_t *torV4Array = NULL;  // base of sorted IPv4 array
static uint32_t torV4Count = 0;
static torV6Node_t *torV6Array = NULL;  // base of sorted IPv6 array
static uint32_t torV6Count = 0;
static void *torMmap = NULL;  // non-NULL when arrays are mmap'd
static size_t torMmapSize = 0;

/* bsearch/qsort comparators for the flat arrays */
static int torV4NodeCmpByIP(const void *a, const void *b) {
    uint32_t x = ((const torV4Node_t *)a)->ipaddr;
    uint32_t y = ((const torV4Node_t *)b)->ipaddr;
    if (x < y) return -1;
    if (x > y) return 1;
    return 0;
}  // End of torV4NodeCmpByIP

static int torV6NodeCmpByNet(const void *a, const void *b) {
    const torV6Node_t *x = (const torV6Node_t *)a;
    const torV6Node_t *y = (const torV6Node_t *)b;
    if (x->network[0] != y->network[0]) return x->network[0] < y->network[0] ? -1 : 1;
    if (x->network[1] == y->network[1]) return 0;
    return x->network[1] < y->network[1] ? -1 : 1;
}  // End of torV6NodeCmpByNet

/* Convert network-byte-order in6_addr to host-order uint64_t[2] */
static inline void inet6_to_hostnet(const struct in6_addr *addr, uint64_t net[2]) {
    uint64_t tmp;
    __builtin_memcpy(&tmp, &addr->s6_addr[0], sizeof(tmp));
    net[0] = ntohll(tmp);
    __builtin_memcpy(&tmp, &addr->s6_addr[8], sizeof(tmp));
    net[1] = ntohll(tmp);
}  // End of inet6_to_hostnet

/* Convert host-order uint64_t[2] back to network-byte-order in6_addr for printing */
static inline void hostnet_to_inet6(const uint64_t net[2], struct in6_addr *addr) {
    uint64_t tmp = ntohll(net[0]);
    __builtin_memcpy(&addr->s6_addr[0], &tmp, sizeof(tmp));
    tmp = ntohll(net[1]);
    __builtin_memcpy(&addr->s6_addr[8], &tmp, sizeof(tmp));
}  // End of hostnet_to_inet6

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
        LogError("WriteFlatCache: open(%s): %s", tmpPath, strerror(errno));
        return;
    }

    torFlatHeader_t hdr = {
        .magic = TORFLAT_MAGIC,
        .version = TORFLAT_VERSION,
        .v4count = torV4Count,
        .v6count = torV6Count,
    };

    int ok = 1;
#define WRITE_BUF(ptr, sz) \
    if (ok && write(fd, (ptr), (sz)) != (ssize_t)(sz)) ok = 0

    WRITE_BUF(&hdr, sizeof(hdr));
    if (torV4Count) WRITE_BUF(torV4Array, torV4Count * sizeof(torV4Node_t));
    if (torV6Count) WRITE_BUF(torV6Array, torV6Count * sizeof(torV6Node_t));

#undef WRITE_BUF
    close(fd);

    if (!ok) {
        unlink(tmpPath);
        LogError("torWriteFlatCache: write error for %s", tmpPath);
        return;
    }
    if (rename(tmpPath, flatPath) != 0) {
        unlink(tmpPath);
        LogError("torWriteFlatCache: rename failed for %s", tmpPath);
    }
    dbg_printf("torWriteFlatCache: wrote %u v4 + %u v6 nodes to %s\n", torV4Count, torV6Count, flatPath);
}  // End of torWriteFlatCache

// returns ok
int Init_TorLookup(void) {
    torV4Tree = kb_init(torV4Tree, KB_DEFAULT_SIZE);
    /* torV6Node_t is 160 bytes; KB_DEFAULT_SIZE (512) yields t=1 < 2 and kb_init returns NULL.
     * Use 1024 which yields t=3. */
    torV6Tree = kb_init(torV6Tree, 1024);
    return 1;
}  // End of Init_TorLookup

static char *tmString(time_t time, char *buff, size_t len) {
    struct tm tmTime_buf;
    struct tm *tmTime = localtime_r(&time, &tmTime_buf);
    snprintf(buff, len, "%4d-%02d-%02d %02d:%02d:%02d", tmTime->tm_year + 1900, tmTime->tm_mon + 1, tmTime->tm_mday, tmTime->tm_hour, tmTime->tm_min,
             tmTime->tm_sec);
    return buff;
}

static void printTorV4Node(torV4Node_t *node) {
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

static void printTorV6Node(torV6Node_t *node) {
    char first[64], last[64], published[64];
    char ip[INET6_ADDRSTRLEN];
    struct in6_addr addr6;
    hostnet_to_inet6(node->network, &addr6);
    inet_ntop(AF_INET6, &addr6, ip, sizeof(ip));
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
void UpdateTorV4Node(torV4Node_t *torV4Node) {
    torV4Node_t *node = kb_getp(torV4Tree, torV4Tree, torV4Node);
    if (node) {
        int index = node->intervalIndex;
        // printf("node updated\n");
        if (node->lastPublished <= torV4Node->lastPublished) {
            time_t diffPublishTime = torV4Node->lastPublished - node->lastPublished;
            if (diffPublishTime > (24 * 3600)) {
                time_t diffLastSeen = torV4Node->interval[0].lastSeen - node->interval[index].lastSeen;
                if (diffLastSeen > (24 * 3600)) {
                    dbg_printf("Last published gap > 18h %ld\n", diffPublishTime / 3600);
                    node->gaps++;
                    node->intervalIndex = (node->intervalIndex + 1) % MAXINTERVALS;
                    index = node->intervalIndex;
                    dbg_printf("Not seen in 24h - %ld. %d gaps, index: %d\n", diffLastSeen / 3600, node->gaps, index);
                    node->interval[index].firstSeen = torV4Node->lastPublished;
                }
            }

            node->lastPublished = torV4Node->lastPublished;
            if (torV4Node->interval[0].lastSeen > node->interval[index].lastSeen) node->interval[index].lastSeen = torV4Node->interval[0].lastSeen;
            if (torV4Node->interval[0].firstSeen < node->interval[index].firstSeen) abort();
        }
        node->roles |= torV4Node->roles;
    } else {
        torV4Node->interval[0].firstSeen = torV4Node->lastPublished;
        kb_putp(torV4Tree, torV4Tree, torV4Node);
        // printf("node inserted\n");
    }
}

void UpdateTorV6Node(torV6Node_t *torV6Node) {
    torV6Node_t *node = kb_getp(torV6Tree, torV6Tree, torV6Node);
    if (node) {
        int index = node->intervalIndex;
        if (node->lastPublished <= torV6Node->lastPublished) {
            time_t diffPublishTime = torV6Node->lastPublished - node->lastPublished;
            if (diffPublishTime > (24 * 3600)) {
                time_t diffLastSeen = torV6Node->interval[0].lastSeen - node->interval[index].lastSeen;
                if (diffLastSeen > (24 * 3600)) {
                    node->gaps++;
                    node->intervalIndex = (node->intervalIndex + 1) % MAXINTERVALS;
                    index = node->intervalIndex;
                    node->interval[index].firstSeen = torV6Node->lastPublished;
                }
            }
            node->lastPublished = torV6Node->lastPublished;
            if (torV6Node->interval[0].lastSeen > node->interval[index].lastSeen) node->interval[index].lastSeen = torV6Node->interval[0].lastSeen;
            if (torV6Node->interval[0].firstSeen < node->interval[index].firstSeen) abort();
        }
        node->roles |= torV6Node->roles;
    } else {
        torV6Node->interval[0].firstSeen = torV6Node->lastPublished;
        kb_putp(torV6Tree, torV6Tree, torV6Node);
    }
}  // End of UpdateTorV6Node

int SaveTorTree(char *fileName) {
    nffileV3_t *nffile = OpenNewFileV3(fileName, CREATOR_TORLOOKUP, LZ4_COMPRESSED, LEVEL_0, NULL);
    if (!nffile) {
        LogError("OpenNewFileV3(%s) failed", fileName);
        return 0;
    }
    uint32_t blockSize = nffile->fileHeader->blockSize;

    // get new empty data block
    arrayBlockV3_t *dataBlock = NULL;
    InitDataBlock(dataBlock, blockSize);
    dataBlock->elementType = TorV4TreeElementID;
    dataBlock->elementSize = sizeof(torV4Node_t);

    uint8_t *outBuff = GetCursor(dataBlock);

    kbitr_t itr;
    kb_itr_first(torV4Tree, torV4Tree, &itr);                              // get an iterator pointing to the first
    for (; kb_itr_valid(&itr); kb_itr_next(torV4Tree, torV4Tree, &itr)) {  // move on
        torV4Node_t *torV4Node = &kb_itr_key(torV4Node_t, &itr);
        dbg_printf("ip: %u, first: %ld, last: %ld\n", torV4Node->ipaddr, torV4Node->interval[0].firstSeen, torV4Node->interval[0].lastSeen);
        if (!IsAvailable(dataBlock, blockSize, sizeof(torV4Node_t))) {
            // flush block - get an empty one
            PushBlockV3(nffile->processQueue, dataBlock);
            dataBlock = NULL;
            InitDataBlock(dataBlock, blockSize);
            dataBlock->elementType = TorV4TreeElementID;
            dataBlock->elementSize = sizeof(torV4Node_t);

            outBuff = GetCursor(dataBlock);
        }

        memcpy(outBuff, torV4Node, sizeof(torV4Node_t));
        outBuff += sizeof(torV4Node_t);
        dataBlock->rawSize += sizeof(torV4Node_t);
        dataBlock->numElements++;
    }
    // flush last v4 datablock
    FlushBlockV3(nffile, dataBlock);

    // write v6 blocks
    if (torV6Tree) {
        dataBlock = NULL;
        InitDataBlock(dataBlock, blockSize);
        dataBlock->elementType = TorV6TreeElementID;
        dataBlock->elementSize = sizeof(torV6Node_t);
        outBuff = GetCursor(dataBlock);

        kb_itr_first(torV6Tree, torV6Tree, &itr);
        for (; kb_itr_valid(&itr); kb_itr_next(torV6Tree, torV6Tree, &itr)) {
            torV6Node_t *torV6Node = &kb_itr_key(torV6Node_t, &itr);
            if (!IsAvailable(dataBlock, blockSize, sizeof(torV6Node_t))) {
                PushBlockV3(nffile->processQueue, dataBlock);
                dataBlock = NULL;
                InitDataBlock(dataBlock, blockSize);
                dataBlock->elementType = TorV6TreeElementID;
                dataBlock->elementSize = sizeof(torV6Node_t);
                outBuff = GetCursor(dataBlock);
            }
            memcpy(outBuff, torV6Node, sizeof(torV6Node_t));
            outBuff += sizeof(torV6Node_t);
            dataBlock->rawSize += sizeof(torV6Node_t);
            dataBlock->numElements++;
        }
        // flush last v6 datablock
        FlushBlockV3(nffile, dataBlock);
    }

    int ret = FlushFileV3(nffile);
    CloseFileV3(nffile);

    return ret;
}  // End of SaveTorTree

// Load (mmap) a flat binary cache file produced by torWriteFlatCache.
// Returns 1 on success, 0 on any failure (caller falls back to slow path)
static int torLoadFlatCache(const char *flatPath) {
    int fd = open(flatPath, O_RDONLY);
    if (fd < 0) {
        LogError("open() failed for %s: %s", flatPath, strerror(errno));
        return 0;
    }

    torFlatHeader_t hdr;
    if (read(fd, &hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr)) {
        LogError("read() error for cache file header");
        close(fd);
        return 0;
    }
    if (hdr.magic != TORFLAT_MAGIC || hdr.version != TORFLAT_VERSION) {
        LogError("cache file header error magic/version mismatch");
        close(fd);
        return 0;
    }

    size_t mapSize = sizeof(torFlatHeader_t) + (size_t)hdr.v4count * sizeof(torV4Node_t) + (size_t)hdr.v6count * sizeof(torV6Node_t);
    void *m = mmap(NULL, mapSize, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (m == MAP_FAILED) {
        LogError("mmap() failed for '%s': %s", flatPath, strerror(errno));
        return 0;
    }

    torMmap = m;
    torMmapSize = mapSize;
    char *base = (char *)m + sizeof(torFlatHeader_t);
    torV4Array = hdr.v4count ? (torV4Node_t *)base : NULL;
    torV4Count = hdr.v4count;
    torV6Array = hdr.v6count ? (torV6Node_t *)(base + (size_t)hdr.v4count * sizeof(torV4Node_t)) : NULL;
    torV6Count = hdr.v6count;
    dbg_printf("torLoadFlatCache: mmap'd %u v4 + %u v6 nodes from %s\n", torV4Count, torV6Count, flatPath);
    return 1;
}  // End of torLoadFlatCache

int LoadTorTree(char *fileName) {
    dbg_printf("Load TorNode DB file %s\n", fileName);

    // if the caller passed the .flat file directly, use it
    size_t fnLen = strlen(fileName);
    if (fnLen > 5 && strcmp(fileName + fnLen - 5, ".flat") == 0) {
        if (torLoadFlatCache(fileName)) return 1;
        LogError("LoadTorTree: cannot load flat file %s", fileName);
        return 0;
    }

    // flat path: respect tordb.flatpath config key
    char flatPath[PATH_MAX];
    char *flatDir = ConfGetString("tordb.flatpath");
    int useFlatCache = 1;
    if (flatDir) {
        if (strcmp(flatDir, "none") == 0) {
            useFlatCache = 0;
            free(flatDir);
        } else {
            if (!CheckPath(flatDir, S_IFDIR)) {
                LogError("Config value tordb.flatpath='%s' - is not a directory", flatDir);
                free(flatDir);
                return 0;
            }
            const char *base = strrchr(fileName, '/');
            base = base ? base + 1 : fileName;
            snprintf(flatPath, sizeof(flatPath), "%s/%s.flat", flatDir, base);
            free(flatDir);
        }
    } else {
        snprintf(flatPath, sizeof(flatPath), "%s.flat", fileName);
    }

    // fast path: mmap the flat binary cache if it is up-to-date
    struct stat stNf, stFlat;
    if (useFlatCache && stat(fileName, &stNf) == 0 && stat(flatPath, &stFlat) == 0 && stFlat.st_mtime >= stNf.st_mtime) {
        if (torLoadFlatCache(flatPath)) return 1;
        LogError("open() tor lookup cache '%s' failed: %s", flatPath, strerror(errno));
    }

    // slow path: decompress nffileV3, build malloc'd array
    nffileV3_t *nffile = OpenFileV3(fileName);
    if (!nffile) {
        LogError("LoadTorTree: Failed to open maxmind db file");
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
        if (dataBlock->elementType == TorV4TreeElementID) {
            if (expected != dataBlock->rawSize || dataBlock->elementSize != sizeof(torV4Node_t)) {
                LogError("Bad TorV4 array block - size error - found: %zu, expected: %u", expected, dataBlock->rawSize);
                FreeDataBlock(dataBlock);
                continue;
            }
            uint32_t n = dataBlock->numElements;
            torV4Node_t *src = (torV4Node_t *)ResetCursor(dataBlock);
            torV4Node_t *tmp = realloc(torV4Array, (torV4Count + n) * sizeof(torV4Node_t));
            if (!tmp) {
                LogError("realloc() failed in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                FreeDataBlock(dataBlock);
                break;
            }
            torV4Array = tmp;
            memcpy(torV4Array + torV4Count, src, n * sizeof(torV4Node_t));
            torV4Count += n;
        } else if (dataBlock->elementType == TorV6TreeElementID) {
            if (expected != dataBlock->rawSize || dataBlock->elementSize != sizeof(torV6Node_t)) {
                LogError("Bad TorV6 array block - size error - found: %zu, expected: %u", expected, dataBlock->rawSize);
                FreeDataBlock(dataBlock);
                continue;
            }
            uint32_t n = dataBlock->numElements;
            torV6Node_t *src6 = (torV6Node_t *)ResetCursor(dataBlock);
            torV6Node_t *tmp6 = realloc(torV6Array, (torV6Count + n) * sizeof(torV6Node_t));
            if (!tmp6) {
                LogError("realloc() failed in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                FreeDataBlock(dataBlock);
                break;
            }
            torV6Array = tmp6;
            memcpy(torV6Array + torV6Count, src6, n * sizeof(torV6Node_t));
            torV6Count += n;
        } else {
            FreeDataBlock(dataBlock);
            continue;
        }
        FreeDataBlock(dataBlock);
    }
    CloseFileV3(nffile);

    if (torV4Count == 0 && torV6Count == 0) return 0;

    if (torV4Count) qsort(torV4Array, torV4Count, sizeof(torV4Node_t), torV4NodeCmpByIP);
    if (torV6Count) qsort(torV6Array, torV6Count, sizeof(torV6Node_t), torV6NodeCmpByNet);

    // write flat cache for fast-path use on the next invocation
    if (useFlatCache) torWriteFlatCache(flatPath);

    dbg_printf("LoadTorTree: loaded %u v4 + %u v6 nodes from %s\n", torV4Count, torV6Count, fileName);
    return 1;
}  // End of LoadTorTree

// return 1 - if IP is tor exit node
// input nfdump IP addr, first/last in msec
int LookupV4Tor(uint32_t ip, uint64_t first, uint64_t last, char *torInfo) {
    if (!torV4Array) {
        torInfo[0] = '\0';
        return 0;
    }

    torV4Node_t key = {.ipaddr = ip};
    torV4Node_t *torV4Node = bsearch(&key, torV4Array, torV4Count, sizeof(torV4Node_t), torV4NodeCmpByIP);
    if (torV4Node && (torV4Node->roles & TOR_ROLE_EXIT)) {
        first /= 1000;
        last /= 1000;
        for (int i = 0; i <= (int)torV4Node->intervalIndex; i++) {
            // allow 24h over last seen
            time_t graceLastSeen = torV4Node->interval[i].lastSeen + 24 * 3600;
            if ((first >= (uint64_t)torV4Node->interval[i].firstSeen && first <= (uint64_t)graceLastSeen) ||
                (last >= (uint64_t)torV4Node->interval[i].firstSeen && last <= (uint64_t)graceLastSeen)) {
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
    if (!torV6Array) {
        torInfo[0] = '.';
        torInfo[1] = '.';
        torInfo[2] = '\0';
        return 0;
    }

    torV6Node_t key = {0};
    key.network[0] = ip[0];
    key.network[1] = ip[1];
    torV6Node_t *node = bsearch(&key, torV6Array, torV6Count, sizeof(torV6Node_t), torV6NodeCmpByNet);
    if (node && (node->roles & TOR_ROLE_EXIT)) {
        first /= 1000;
        last /= 1000;
        for (int i = 0; i <= (int)node->intervalIndex; i++) {
            time_t graceLastSeen = node->interval[i].lastSeen + 24 * 3600;
            if ((first >= (uint64_t)node->interval[i].firstSeen && first <= (uint64_t)graceLastSeen) ||
                (last >= (uint64_t)node->interval[i].firstSeen && last <= (uint64_t)graceLastSeen)) {
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
    }
    torInfo[0] = '.';
    torInfo[1] = '.';
    torInfo[2] = '\0';
    return 0;
}  // End of LookupV6Tor

void LookupIP(char *ipstring) {
    // IPv4
    uint32_t ip4;
    if (inet_pton(PF_INET, ipstring, &ip4) == 1) {
        if (!torV4Array) {
            printf("No torV4 DB available\n");
            return;
        }
        torV4Node_t key = {.ipaddr = ntohl(ip4)};
        torV4Node_t *torV4Node = bsearch(&key, torV4Array, torV4Count, sizeof(torV4Node_t), torV4NodeCmpByIP);
        if (torV4Node)
            printTorV4Node(torV4Node);
        else
            printf("No tor exit node: %s\n", ipstring);
        return;
    }
    // IPv6
    struct in6_addr addr6;
    if (inet_pton(AF_INET6, ipstring, &addr6) == 1) {
        if (!torV6Array) {
            printf("No torV6 DB available\n");
            return;
        }
        uint64_t net[2];
        inet6_to_hostnet(&addr6, net);
        torV6Node_t key = {0};
        key.network[0] = net[0];
        key.network[1] = net[1];
        torV6Node_t *node = bsearch(&key, torV6Array, torV6Count, sizeof(torV6Node_t), torV6NodeCmpByNet);
        if (node)
            printTorV6Node(node);
        else
            printf("No tor exit node: %s\n", ipstring);
        return;
    }
    printf("Not a valid IP address: %s\n", ipstring);
}

void FreeTorTree(void) {
    if (torMmap) {
        munmap(torMmap, torMmapSize);
        torMmap = NULL;
        torMmapSize = 0;
        torV4Array = NULL;
        torV6Array = NULL;
    } else {
        free(torV4Array);
        free(torV6Array);
        torV4Array = NULL;
        torV6Array = NULL;
    }
    torV4Count = 0;
    torV6Count = 0;
}  // End of FreeTorTree
