/*
 *  Copyright (c) 2024, Peter Haag
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

#ifndef _MMHASH_H
#define _MMHASH_H 1

#include <stdint.h>

#include "kbtree.h"
#include "khash.h"

typedef struct locationKey_s {
    khint32_t key;
} locationKey_t;

#define CityLength 36
typedef struct locationInfo_s {
    uint32_t localID;
    char continent[4];
    char country[4];
    char city[CityLength];
} locationInfo_t;

typedef struct ipLocationInfo_s {
    uint8_t ipVersion;
    uint8_t proxy;
    uint8_t sat;
    uint8_t fill;
    uint32_t localID;
    double latitude;
    double longitude;
    uint32_t accuracy;
} ipLocationInfo_t;

typedef struct ipV4Node_s {
    // key
    uint32_t network;
    uint32_t netmask;

    // value
    ipLocationInfo_t info;
} ipV4Node_t;

typedef struct ipV6Node_s {
    // key
    uint64_t network[2];
    uint64_t netmask[2];

    // value
    ipLocationInfo_t info;
} ipV6Node_t;

#define orgNameLength 96
typedef struct asV4Node_s {
    // key
    uint32_t network;
    uint32_t netmask;

    // value
    uint32_t as;
    char orgName[orgNameLength];
} asV4Node_t;

typedef struct asV6Node_s {
    // key
    // IPv6: [0] high 64bit, [1] low 64bit host representation
    uint64_t network[2];
    uint64_t netmask[2];

    // value
    uint32_t as;
    char orgName[orgNameLength];
} asV6Node_t;

void LoadLocalInfo(locationInfo_t *locationInfo, uint32_t NumRecords);

void LoadIPv4Tree(ipV4Node_t *ipV4Node, uint32_t NumRecords);

void LoadIPv6Tree(ipV6Node_t *ipV6Node, uint32_t NumRecords);

void LoadASV4Tree(asV4Node_t *asV4Node, uint32_t NumRecords);

void LoadASV6Tree(asV6Node_t *asV6Node, uint32_t NumRecords);

void PutLocation(locationInfo_t *locationInfo);

void PutIPv4Node(ipV4Node_t *ipV4Node);

void PutIPv6Node(ipV6Node_t *ipV6Node);

void PutasV4Node(asV4Node_t *asV4Node);

void PutasV6Node(asV6Node_t *asV6Node);

#define FIRSTNODE 1
#define NEXTNODE 0
locationInfo_t *NextLocation(int start);

ipV4Node_t *NextIPv4Node(int start);

ipV6Node_t *NextIPv6Node(int start);

asV4Node_t *NextasV4Node(int start);

asV6Node_t *NextasV6Node(int start);

int SaveMaxMind(char *fileName);

#endif