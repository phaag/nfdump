/*
 *  Copyright (c) 2025, Peter Haag
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nffile.h"
#include "nffileV2.h"
#include "nfxV3.h"
#include "util.h"

// include after
#include "kbtree.h"

#define PushArrayHeader(dataBlock, arrayType, arraySize)   \
    (dataBlock)->type = DATA_BLOCK_TYPE_4;                 \
    void *p = ((void *)(dataBlock) + sizeof(dataBlock_t)); \
    recordHeader_t *arrayHeader = (recordHeader_t *)p;     \
    arrayHeader->type = arrayType;                         \
    arrayHeader->size = arraySize;                         \
    (dataBlock)->size += sizeof(recordHeader_t);

static inline int torNodeCMP(torNode_t a, torNode_t b) {
    if (a.ipaddr == b.ipaddr) return 0;
    return a.ipaddr > b.ipaddr ? 1 : -1;
}

KBTREE_INIT(torTree, torNode_t, torNodeCMP);

static kbtree_t(torTree) *torTree = NULL;

// returns ok
int Init_TorLookup(void) {
    torTree = kb_init(torTree, KB_DEFAULT_SIZE);

    return 1;
}  // End of Init_TorLookup

static char *tmString(time_t time, char *buff, size_t len) {
    struct tm *tmTime = localtime(&time);
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
#ifdef DEVEL
        printTorNode(node);
        printTorNode(torNode);
        printf("--\n\n");
#endif
    } else {
        torNode->interval[0].firstSeen = torNode->lastPublished;
        kb_putp(torTree, torTree, torNode);
        // printf("node inserted\n");
    }
}

int SaveTorTree(char *fileName) {
    nffile_t *nffile = OpenNewFile(fileName, NULL, CREATOR_TORLOOKUP, LZ4_COMPRESSED, NOT_ENCRYPTED);

    // get new empty data block
    dataBlock_t *dataBlock = WriteBlock(nffile, NULL);

    // push array header
    PushArrayHeader(dataBlock, TorTreeElementID, sizeof(torNode_t));
    void *outBuff = GetCurrentCursor(dataBlock);

    kbitr_t itr;
    kb_itr_first(torTree, torTree, &itr);                              // get an iterator pointing to the first
    for (; kb_itr_valid(&itr); kb_itr_next(torTree, torTree, &itr)) {  // move on
        torNode_t *torNode = &kb_itr_key(torNode_t, &itr);
        dbg_printf("ip: %u, first: %ld, last: %ld\n", torNode->ipaddr, torNode->interval[0].firstSeen, torNode->interval[0].lastSeen);
        if (!IsAvailable(dataBlock, sizeof(torNode_t))) {
            // flush block - get an empty one
            dataBlock = WriteBlock(nffile, dataBlock);

            PushArrayHeader(dataBlock, TorTreeElementID, sizeof(torNode_t));
            outBuff = GetCurrentCursor(dataBlock);
        }

        memcpy(outBuff, torNode, sizeof(torNode_t));
        outBuff += sizeof(torNode_t);
        dataBlock->size += sizeof(torNode_t);
        dataBlock->NumRecords++;
    }
    // flush current datablock
    FlushBlock(nffile, dataBlock);

    int ret = FinaliseFile(nffile);
    CloseFile(nffile);

    return ret;
}  // End of SaveTorTree

int LoadTorTree(char *fileName) {
    dbg_printf("Load TorNode DB file %s\n", fileName);

    Init_TorLookup();
    nffile_t *nffile = OpenFile(fileName, NULL);
    if (!nffile) {
        return 0;
    }

    dataBlock_t *dataBlock = NULL;
    int done = 0;
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
        size_t expected = ((uint32_t)arrayHeader->size * dataBlock->NumRecords) + sizeof(record_header_t);
        if (expected != dataBlock->size) {
            LogError("Array size calculated: %zu != expected: %u for element: %u", expected, dataBlock->size, arrayHeader->type);
            continue;
        }

        switch (arrayHeader->type) {
            case TorTreeElementID: {
                torNode_t *torNode = (torNode_t *)arrayElement;
                for (int i = 0; i < dataBlock->NumRecords; i++) {
                    torNode_t *node = kb_getp(torTree, torTree, torNode);
                    if (node) {
                        LogError("Duplicate IP node: ip: 0x%x", torNode->ipaddr);
                    } else {
                        kb_putp(torTree, torTree, torNode);
                    }
                    torNode++;
                }
            } break;
            default:
                LogError("Skip unknown array element: %u", arrayHeader->type);
        }
    }
    FreeDataBlock(dataBlock);
    DisposeFile(nffile);

    return 1;
}  // End of LoadTorTree

// return 1 - if IP is tor exit node
// input nfdump IP addr, first/last in msec
int LookupV4Tor(uint32_t ip, uint64_t first, uint64_t last, char *torInfo) {
    if (!torTree) {
        torInfo[0] = '\0';
        return 0;
    }

    torNode_t searchNode = {.ipaddr = ip};
    torNode_t *torNode = kb_getp(torTree, torTree, &searchNode);
    if (torNode) {
        first /= 1000;
        last /= 1000;
        for (int i = 0; i <= torNode->intervalIndex; i++) {
            // allow 24h over last seen
            time_t graceLastSeen = torNode->interval[i].lastSeen + 24 * 3600;
            if ((first >= torNode->interval[i].firstSeen && first <= graceLastSeen) ||
                (last >= torNode->interval[i].firstSeen && last <= graceLastSeen)) {
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

}  // End of LookupTor

int LookupV6Tor(uint64_t ip[2], uint64_t first, uint64_t last, char *torInfo) {
    if (!torTree) {
        torInfo[0] = '\0';
        return 0;
    }

    // IPv6 not yet implemented
    torInfo[0] = '.';
    torInfo[1] = '.';
    torInfo[2] = '\0';

    return 0;

}  // End of LookupTor

void LookupIP(char *ipstring) {
    if (!torTree) {
        printf("No torDB available");
        return;
    }
    // IPv4
    uint32_t ip;
    int ret = inet_pton(PF_INET, ipstring, &ip);
    if (ret != 1) return;
    torNode_t searchNode = {.ipaddr = ntohl(ip)};
    torNode_t *torNode = kb_getp(torTree, torTree, &searchNode);
    if (torNode) {
        printTorNode(torNode);
    } else {
        printf("No tor exit node: %s\n", ipstring);
    }
}
