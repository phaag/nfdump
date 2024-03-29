/*
 *  Copyright (c) 2021, Peter Haag
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

#ifndef _TOR_H
#define _TOR_H 1

#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#include "config.h"
#include "kbtree.h"

typedef struct interval_s {
    time_t firstSeen;
    time_t lastSeen;
} interval_t;

#define MAXINTERVALS 8

typedef struct torNode_s {
    uint32_t ipaddr;
    uint16_t gaps;
    uint16_t intervalIndex;
    time_t lastPublished;
    interval_t interval[MAXINTERVALS];
} torNode_t;

int Init_TorLookup(void);

void UpdateTorNode(torNode_t *torNode);

int LoadTorTree(char *fileName);

int SaveTorTree(char *fileName);

int LookupV4Tor(uint32_t ip, uint64_t first, uint64_t last, char *torInfo);

int LookupV6Tor(uint64_t ip[2], uint64_t first, uint64_t last, char *torInfo);

void LookupIP(char *ipstring);

#endif