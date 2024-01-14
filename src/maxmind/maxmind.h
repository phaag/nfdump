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

#ifndef _MAXMIND_H
#define _MAXMIND_H 1

#include <stdint.h>
#include <sys/types.h>

#include "config.h"
#include "kbtree.h"
#include "khash.h"

typedef struct locationKey_s {
    khint32_t key;
    // uint32_t hash;	// the full 32bit hash value - cached for khash resize
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
    // IPv6: [0] high 64bit, [1] low 64bit host representation
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

#define LocalInfoElementID 1
#define IPV4treeElementID 2
#define IPV6treeElementID 3
#define ASV4treeElementID 4
#define ASV6treeElementID 5

int Init_MaxMind(void);

int Loaded_MaxMind(void);

int loadLocalMap(char *fileName);

int loadIPV4tree(char *fileName);

int loadIPV6tree(char *fileName);

int loadASV4tree(char *fileName);

int loadASV6tree(char *fileName);

int SaveMaxMind(char *fileName);

int LoadMaxMind(char *fileName);

void LookupV4Country(uint32_t ip, char *country);

void LookupV6Country(uint64_t ip[2], char *country);

void LookupV4Location(uint32_t ip, char *location, size_t len);

void LookupV6Location(uint64_t ip[2], char *location, size_t len);

uint32_t LookupV4AS(uint32_t ip);

uint32_t LookupV6AS(uint64_t ip[2]);

const char *LookupV4ASorg(uint32_t ip);

const char *LookupV6ASorg(uint64_t ip[2]);

void LookupWhois(char *ip);

#endif
