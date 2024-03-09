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

#include "mmhash.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#include "kbtree.h"
#include "khash.h"
#include "maxmind.h"
#include "mmhash.h"
#include "util.h"

#define kh_hash_func(key) (khint32_t)(key.key)
#define kh_hash_equal(a, b) ((a.key) == (b.key))

KHASH_INIT(localMap, locationKey_t, locationInfo_t, 1, kh_hash_func, kh_hash_equal)

// ipV4Tree node compare function
// nextmask = 0 => IP to search
// mask IP to search with netmask and compare network
static inline int ipV4Node_cmp(ipV4Node_t a, ipV4Node_t b) {
    if (a.netmask == 0) {
        uint32_t network = a.network & b.netmask;
        if (network == b.network) return 0;
        return network > b.network ? 1 : -1;
    } else {
        uint32_t network = b.network & a.netmask;
        if (network == a.network) return 0;
        return a.network > network ? 1 : -1;
    }
}

static inline int ipV6Node_cmp(ipV6Node_t a, ipV6Node_t b) {
    uint64_t network[2];
    if (a.netmask[0] == 0 && a.netmask[1] == 0) {
        network[0] = a.network[0] & b.netmask[0];
        network[1] = a.network[1] & b.netmask[1];
        if (network[0] == b.network[0] && network[1] == b.network[1]) return 0;
        if (network[0] == b.network[0]) return network[1] > b.network[1] ? 1 : -1;
        return (network[0] > b.network[0]) ? 1 : -1;
    } else {
        network[0] = b.network[0] & a.netmask[0];
        network[1] = b.network[1] & a.netmask[1];
        if (network[0] == a.network[0] && network[1] == a.network[1]) return 0;
        if (a.network[0] == network[0]) return a.network[1] > network[1] ? 1 : -1;
        return (a.network[0] > network[0]) ? 1 : -1;
    }
}

KBTREE_INIT(ipV4Tree, ipV4Node_t, ipV4Node_cmp);

KBTREE_INIT(ipV6Tree, ipV6Node_t, ipV6Node_cmp);

// asV4Tree node compare function
// nextmask = 0 => IP to search
// mask IP to search with netmask and compare network
static inline int asV4Node_cmp(asV4Node_t a, asV4Node_t b) {
    if (a.netmask == 0) {
        uint32_t network = a.network & b.netmask;
        if (network == b.network) return 0;
        return network > b.network ? 1 : -1;
    } else {
        uint32_t network = b.network & a.netmask;
        if (network == a.network) return 0;
        return a.network > network ? 1 : -1;
    }
}

static inline int asV6Node_cmp(asV6Node_t a, asV6Node_t b) {
    uint64_t network[2];
    if (a.netmask[0] == 0 && a.netmask[1] == 0) {
        network[0] = a.network[0] & b.netmask[0];
        network[1] = a.network[1] & b.netmask[1];
        if (network[0] == b.network[0] && network[1] == b.network[1]) return 0;
        if (network[0] == b.network[0]) return network[1] > b.network[1] ? 1 : -1;
        return (network[0] > b.network[0]) ? 1 : -1;
    } else {
        network[0] = b.network[0] & a.netmask[0];
        network[1] = b.network[1] & a.netmask[1];
        if (network[0] == a.network[0] && network[1] == a.network[1]) return 0;
        if (a.network[0] == network[0]) return a.network[1] > network[1] ? 1 : -1;
        return (a.network[0] > network[0]) ? 1 : -1;
    }
}

KBTREE_INIT(asV4Tree, asV4Node_t, asV4Node_cmp);

KBTREE_INIT(asV6Tree, asV6Node_t, asV6Node_cmp);

typedef struct mmHandle_s {
    khash_t(localMap) * localMap;
    kbtree_t(ipV4Tree) * ipV4Tree;
    kbtree_t(ipV6Tree) * ipV6Tree;
    kbtree_t(asV4Tree) * asV4Tree;
    kbtree_t(asV6Tree) * asV6Tree;
} mmHandle_t;

static mmHandle_t *mmHandle = NULL;

int Init_MaxMind(void) {
    mmHandle = calloc(1, sizeof(mmHandle_t));
    if (!mmHandle) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    mmHandle->localMap = kh_init(localMap);
    mmHandle->ipV4Tree = kb_init(ipV4Tree, 10 * KB_DEFAULT_SIZE);
    mmHandle->ipV6Tree = kb_init(ipV6Tree, 10 * KB_DEFAULT_SIZE);
    mmHandle->asV4Tree = kb_init(asV4Tree, 10 * KB_DEFAULT_SIZE);
    mmHandle->asV6Tree = kb_init(asV6Tree, 10 * KB_DEFAULT_SIZE);

    if (!mmHandle->ipV4Tree || !mmHandle->ipV6Tree || !mmHandle->localMap || !mmHandle->asV4Tree || !mmHandle->asV6Tree) {
        LogError("Initialization of MaxMind failed");
        return 0;
    }
    return 1;

}  // End of Init_MaxMind

void LoadLocalInfo(locationInfo_t *locationInfo, uint32_t NumRecords) {
    for (int i = 0; i < NumRecords; i++) {
        int absent;
        locationKey_t locationKey = {.key = locationInfo->localID};
        khint_t k = kh_put(localMap, mmHandle->localMap, locationKey, &absent);
        if (!absent) {
            LogError("Duplicate location entry: %u", locationInfo->localID);
        } else {
            kh_value(mmHandle->localMap, k) = *locationInfo;
        }
        locationInfo++;
    }

}  // End of LoadLocalInfo

void LoadIPv4Tree(ipV4Node_t *ipV4Node, uint32_t NumRecords) {
    kbtree_t(ipV4Tree) *ipV4Tree = mmHandle->ipV4Tree;
    for (int i = 0; i < NumRecords; i++) {
        ipV4Node_t *node = kb_getp(ipV4Tree, ipV4Tree, ipV4Node);
        if (node) {
            LogError("Duplicate IP node: ip: 0x%x, mask: 0x%x", ipV4Node->network, ipV4Node->netmask);
        } else {
            kb_putp(ipV4Tree, ipV4Tree, ipV4Node);
        }
        ipV4Node++;
    }

}  // End of LoadIPv4Tree

void LoadIPv6Tree(ipV6Node_t *ipV6Node, uint32_t NumRecords) {
    kbtree_t(ipV6Tree) *ipV6Tree = mmHandle->ipV6Tree;
    for (int i = 0; i < NumRecords; i++) {
        ipV6Node_t *node = kb_getp(ipV6Tree, ipV6Tree, ipV6Node);
        if (node) {
            LogError("Duplicate IPV6 node: ip: 0x%x %x, mask: 0x%x %x", ipV6Node->network[0], ipV6Node->network[1], ipV6Node->netmask[0],
                     ipV6Node->netmask[1]);
        } else {
            kb_putp(ipV6Tree, ipV6Tree, ipV6Node);
        }
        ipV6Node++;
    }

}  // End of LoadIPv6Tree

void LoadASV4Tree(asV4Node_t *asV4Node, uint32_t NumRecords) {
    kbtree_t(asV4Tree) *asV4Tree = mmHandle->asV4Tree;
    for (int i = 0; i < NumRecords; i++) {
        asV4Node_t *node = kb_getp(asV4Tree, asV4Tree, asV4Node);
        if (node) {
            LogError("Insert: %d Duplicate ASv4 node: ip: 0x%x, mask: 0x%x", i, asV4Node->network, asV4Node->netmask);
        } else {
            kb_putp(asV4Tree, asV4Tree, asV4Node);
        }
        asV4Node++;
    }
}  // End of LoadASV4Tree

void LoadASV6Tree(asV6Node_t *asV6Node, uint32_t NumRecords) {
    kbtree_t(asV6Tree) *asV6Tree = mmHandle->asV6Tree;
    for (int i = 0; i < NumRecords; i++) {
        asV6Node_t *node = kb_getp(asV6Tree, asV6Tree, asV6Node);
        if (node) {
            LogError("Insert: %d, Duplicate ASV6 node: ip: 0x%x %x, mask: 0x%x %x", i, asV6Node->network[0], asV6Node->network[1],
                     asV6Node->netmask[0], asV6Node->netmask[1]);
        } else {
            kb_putp(asV6Tree, asV6Tree, asV6Node);
        }
        asV6Node++;
    }

}  // End of LoadASV6Tree

void PutLocation(locationInfo_t *locationInfo) {
    khash_t(localMap) *localMap = mmHandle->localMap;

    int absent;
    locationKey_t locationKey = {.key = locationInfo->localID};
    khint_t k = kh_put(localMap, localMap, locationKey, &absent);
    if (!absent) {
        LogError("Duplicate entry: %u", locationInfo->localID);
    } else {
        kh_value(localMap, k) = *locationInfo;
    }

}  // End of PutLocation

void PutIPv4Node(ipV4Node_t *ipV4Node) {
    kbtree_t(ipV4Tree) *ipV4Tree = mmHandle->ipV4Tree;

    ipV4Node_t *node = kb_getp(ipV4Tree, ipV4Tree, ipV4Node);
    if (node) {
        uint32_t net = htonl(ipV4Node->network);
        char s[32] = {0};
        inet_ntop(AF_INET, &net, s, sizeof(s));
        LogError("Duplicate IPV4 node: ip: %s", s);
    } else {
        kb_putp(ipV4Tree, ipV4Tree, ipV4Node);
    }
}  // End of PutIPv4Node

void PutIPv6Node(ipV6Node_t *ipV6Node) {
    kbtree_t(ipV6Tree) *ipV6Tree = mmHandle->ipV6Tree;
    ipV6Node_t *node = kb_getp(ipV6Tree, ipV6Tree, ipV6Node);
    if (node) {
        uint64_t ipv6[2] = {htonll(ipV6Node->network[0]), htonll(ipV6Node->network[1])};
        char s[128];
        inet_ntop(AF_INET6, ipv6, s, sizeof(s));
        LogError("Duplicate IPV6 node: ip: %s", s);
    } else {
        kb_putp(ipV6Tree, ipV6Tree, ipV6Node);
    }
}  // End of PutIPv6Node

void PutasV4Node(asV4Node_t *asV4Node) {
    kbtree_t(asV4Tree) *asV4Tree = mmHandle->asV4Tree;
    asV4Node_t *node = kb_getp(asV4Tree, asV4Tree, asV4Node);
    if (node) {
        LogError("Duplicate ASv4 node: AS%u %s", asV4Node->as, asV4Node->orgName);
    } else {
        kb_putp(asV4Tree, asV4Tree, asV4Node);
    }
}  // End of PutasV4Node

void PutasV6Node(asV6Node_t *asV6Node) {
    kbtree_t(asV6Tree) *asV6Tree = mmHandle->asV6Tree;

    asV6Node_t *node = kb_getp(asV6Tree, asV6Tree, asV6Node);
    if (node) {
        LogError("Duplicate ASv6 node: AS%u %s", asV6Node->as, asV6Node->orgName);
    } else {
        kb_putp(asV6Tree, asV6Tree, asV6Node);
    }
}  // End of PutasV6Node

void LookupV4Country(uint32_t ip, char *country) {
    if (!mmHandle) {
        country[0] = '.';
        country[1] = '.';
        return;
    }

    ipLocationInfo_t info = {0};
    ipV4Node_t ipSearch = {.network = ip, .netmask = 0};
    ipV4Node_t *ipV4Node = kb_getp(ipV4Tree, mmHandle->ipV4Tree, &ipSearch);
    if (!ipV4Node) {
        country[0] = '.';
        country[1] = '.';
        return;
    }
    info = ipV4Node->info;

    locationKey_t locationKey = {.key = info.localID};
    khint_t k = kh_get(localMap, mmHandle->localMap, locationKey);
    if (k == kh_end(mmHandle->localMap)) {
        country[0] = '.';
        country[1] = '.';
        return;
    }

    locationInfo_t locationInfo = kh_value(mmHandle->localMap, k);
    country[0] = locationInfo.country[0];
    country[1] = locationInfo.country[1];

}  // End of LookupV4Country

void LookupV6Country(uint64_t ip[2], char *country) {
    if (!mmHandle) {
        country[0] = '.';
        country[1] = '.';
        return;
    }

    ipLocationInfo_t info = {0};
    ipV6Node_t ipSearch = {0};
    ipSearch.network[0] = ip[0];
    ipSearch.network[1] = ip[1];
    ipV6Node_t *ipV6Node = kb_getp(ipV6Tree, mmHandle->ipV6Tree, &ipSearch);
    if (!ipV6Node) {
        country[0] = '.';
        country[1] = '.';
        return;
    }
    info = ipV6Node->info;

    locationKey_t locationKey = {.key = info.localID};
    khint_t k = kh_get(localMap, mmHandle->localMap, locationKey);
    if (k == kh_end(mmHandle->localMap)) {
        country[0] = '.';
        country[1] = '.';
        return;
    }

    locationInfo_t locationInfo = kh_value(mmHandle->localMap, k);
    country[0] = locationInfo.country[0];
    country[1] = locationInfo.country[1];

    /*
            printf("localID: %d %s/%s/%s long/lat: %8.4f/%-8.4f, accuracy: %u, AS: %u\n",
                    locationInfo.localID, locationInfo.continent, locationInfo.country, locationInfo.city,
                    ipV4Node->longitude, ipV4Node->latitude, ipV4Node->accuracy, as);
            }
    */
}  // End of LookupV6Country

void LookupV4Location(uint32_t ip, char *location, size_t len) {
    location[0] = '\0';
    if (!mmHandle) {
        return;
    }

    ipLocationInfo_t info = {0};
    ipV4Node_t ipSearch = {.network = ip, .netmask = 0};
    ipV4Node_t *ipV4Node = kb_getp(ipV4Tree, mmHandle->ipV4Tree, &ipSearch);
    if (!ipV4Node) {
        return;
    }
    info = ipV4Node->info;

    locationKey_t locationKey = {.key = info.localID};
    khint_t k = kh_get(localMap, mmHandle->localMap, locationKey);
    if (k == kh_end(mmHandle->localMap)) {
        return;
    }

    locationInfo_t locationInfo = kh_value(mmHandle->localMap, k);
    snprintf(location, len, "%s/%s/%s long/lat: %.4f/%-.4f", locationInfo.continent, locationInfo.country, locationInfo.city, info.longitude,
             info.latitude);

}  // End of LookupV4Location

void LookupV6Location(uint64_t ip[2], char *location, size_t len) {
    location[0] = '\0';
    if (!mmHandle) {
        return;
    }

    ipLocationInfo_t info = {0};

    ipV6Node_t ipSearch = {0};
    ipSearch.network[0] = ip[0];
    ipSearch.network[1] = ip[1];
    ipV6Node_t *ipV6Node = kb_getp(ipV6Tree, mmHandle->ipV6Tree, &ipSearch);
    if (!ipV6Node) {
        return;
    }
    info = ipV6Node->info;

    locationKey_t locationKey = {.key = info.localID};
    khint_t k = kh_get(localMap, mmHandle->localMap, locationKey);
    if (k == kh_end(mmHandle->localMap)) {
        return;
    }

    locationInfo_t locationInfo = kh_value(mmHandle->localMap, k);
    snprintf(location, len, "%s/%s/%s long/lat: %.4f/%-.4f", locationInfo.continent, locationInfo.country, locationInfo.city, info.longitude,
             info.latitude);

}  // End of LookupV6Location

uint32_t LookupV4AS(uint32_t ip) {
    if (!mmHandle) {
        return 0;
    }

    asV4Node_t asSearch = {.network = ip, .netmask = 0};
    asV4Node_t *asV4Node = kb_getp(asV4Tree, mmHandle->asV4Tree, &asSearch);
    return asV4Node == NULL ? 0 : asV4Node->as;

}  // End of LookupV4AS

uint32_t LookupV6AS(uint64_t ip[2]) {
    if (!mmHandle) {
        return 0;
    }

    asV6Node_t asV6Search = {0};
    asV6Search.network[0] = ip[0];
    asV6Search.network[1] = ip[1];
    asV6Node_t *asV6Node = kb_getp(asV6Tree, mmHandle->asV6Tree, &asV6Search);
    return asV6Node == NULL ? 0 : asV6Node->as;

}  // End of LookupV6AS

const char *LookupV4ASorg(uint32_t ip) {
    if (!mmHandle) {
        return "";
    }

    asV4Node_t asSearch = {.network = ip, .netmask = 0};
    asV4Node_t *asV4Node = kb_getp(asV4Tree, mmHandle->asV4Tree, &asSearch);
    return asV4Node == NULL ? "" : asV4Node->orgName;
}  // End of LookupV4ASorg

const char *LookupV6ASorg(uint64_t ip[2]) {
    if (!mmHandle) {
        return "";
    }

    asV6Node_t asV6Search = {0};
    asV6Search.network[0] = ip[0];
    asV6Search.network[1] = ip[1];
    asV6Node_t *asV6Node = kb_getp(asV6Tree, mmHandle->asV6Tree, &asV6Search);
    return asV6Node == NULL ? "" : asV6Node->orgName;

}  // End of LookupV6ASorg

void LookupWhois(char *ip) {
    uint32_t as = 0;
    char *asOrg = NULL;
    ipV4Node_t *ipV4Node;
    ipV6Node_t *ipV6Node;
    ipLocationInfo_t info = {0};
    if (strchr(ip, ':') != NULL) {
        // IPv6
        uint64_t network[2];
        ipV6Node_t ipSearch = {0};
        asV6Node_t asSearch = {0};
        int ret = inet_pton(PF_INET6, ip, network);
        if (ret != 1) return;
        ipSearch.network[0] = ntohll(network[0]);
        asSearch.network[0] = ntohll(network[0]);
        ipSearch.network[1] = ntohll(network[1]);
        asSearch.network[1] = ntohll(network[1]);

        uint64_t testv4v6 = ipSearch.network[1] & 0xFFFFFFFF00000000LL;
        if (ipSearch.network[0] == 0 && (testv4v6 == 0LL || testv4v6 == 0x0000ffff00000000LL)) {
            uint32_t net = ipSearch.network[1];
            asV4Node_t asSearch = {.network = net, .netmask = 0};
            asV4Node_t *asV4Node = kb_getp(asV4Tree, mmHandle->asV4Tree, &asSearch);
            if (asV4Node) {
                as = asV4Node->as;
                asOrg = asV4Node->orgName;
            }
        } else {
            ipV6Node = kb_getp(ipV6Tree, mmHandle->ipV6Tree, &ipSearch);
            if (ipV6Node) {
                info = ipV6Node->info;
            }

            asV6Node_t *asV6Node = kb_getp(asV6Tree, mmHandle->asV6Tree, &asSearch);
            if (asV6Node) {
                as = asV6Node->as;
                asOrg = asV6Node->orgName;
            }
        }

    } else {
        // IPv4
        uint32_t net;
        int ret = inet_pton(PF_INET, ip, &net);
        if (ret != 1) return;
        ipV4Node_t ipSearch = {.network = ntohl(net), .netmask = 0};
        ipV4Node = kb_getp(ipV4Tree, mmHandle->ipV4Tree, &ipSearch);
        if (ipV4Node) {
            info = ipV4Node->info;
        }

        asV4Node_t asSearch = {.network = ntohl(net), .netmask = 0};
        asV4Node_t *asV4Node = kb_getp(asV4Tree, mmHandle->asV4Tree, &asSearch);
        if (asV4Node) {
            as = asV4Node->as;
            asOrg = asV4Node->orgName;
        }
    }

    locationKey_t locationKey = {.key = info.localID};
    khint_t k = kh_get(localMap, mmHandle->localMap, locationKey);
    if (k == kh_end(mmHandle->localMap)) {
        printf("%-7u | %-24s | %-32s | no information | sat: %d\n", as, ip, asOrg == NULL ? "private" : asOrg, info.sat);
    } else {
        locationInfo_t locationInfo = kh_value(mmHandle->localMap, k);
        printf("%-7u | %-24s | %-32s | %s/%s/%s long/lat: %8.4f/%-8.4f | sat: %d\n", as, ip, asOrg == NULL ? "private" : asOrg,
               locationInfo.continent, locationInfo.country, locationInfo.city, info.longitude, info.latitude, info.sat);
    }

}  // End of LookupWhois

locationInfo_t *NextLocation(int start) {
    static khint_t k = 0;
    static locationInfo_t locationInfo;

    khash_t(localMap) *localMap = mmHandle->localMap;
    if (start == FIRSTNODE) k = kh_begin(localMap);

    while (k != kh_end(localMap)) {
        if (kh_exist(localMap, k)) {  // test if a bucket contains data
            locationInfo = kh_value(localMap, k);
            k++;
            return &locationInfo;
        }
        k++;
    }

    return NULL;

}  // End of NextLocation

ipV4Node_t *NextIPv4Node(int start) {
    static kbitr_t itr = {0};
    static ipV4Node_t *ipV4Node = NULL;

    kbtree_t(ipV4Tree) *ipV4Tree = mmHandle->ipV4Tree;
    if (start == FIRSTNODE) kb_itr_first(ipV4Tree, ipV4Tree, &itr);  // get an iterator pointing to the first

    if (kb_itr_valid(&itr)) {
        ipV4Node = &kb_itr_key(ipV4Node_t, &itr);
        kb_itr_next(ipV4Tree, ipV4Tree, &itr);  // move on
        return ipV4Node;
    } else {
        return NULL;
    }

}  // End of NextIPv4Node

ipV6Node_t *NextIPv6Node(int start) {
    static kbitr_t itr = {0};
    static ipV6Node_t *ipV6Node = NULL;

    kbtree_t(ipV6Tree) *ipV6Tree = mmHandle->ipV6Tree;
    if (start == FIRSTNODE) kb_itr_first(ipV6Tree, ipV6Tree, &itr);  // get an iterator pointing to the first

    if (kb_itr_valid(&itr)) {
        ipV6Node = &kb_itr_key(ipV6Node_t, &itr);
        kb_itr_next(ipV6Tree, ipV6Tree, &itr);  // move on
        return ipV6Node;
    } else {
        return NULL;
    }

}  // End of NextIPv6Node

asV4Node_t *NextasV4Node(int start) {
    static kbitr_t itr = {0};
    static asV4Node_t *asV4Node = NULL;

    kbtree_t(asV4Tree) *asV4Tree = mmHandle->asV4Tree;
    if (start == FIRSTNODE) kb_itr_first(asV4Tree, asV4Tree, &itr);  // get an iterator pointing to the first

    if (kb_itr_valid(&itr)) {
        asV4Node = &kb_itr_key(asV4Node_t, &itr);
        kb_itr_next(asV4Tree, asV4Tree, &itr);  // move on
        return asV4Node;
    } else {
        return NULL;
    }

}  // End of NextasV4Node

asV6Node_t *NextasV6Node(int start) {
    static kbitr_t itr = {0};
    static asV6Node_t *asV6Node = NULL;

    kbtree_t(asV6Tree) *asV6Tree = mmHandle->asV6Tree;
    if (start == FIRSTNODE) kb_itr_first(asV6Tree, asV6Tree, &itr);  // get an iterator pointing to the first

    if (kb_itr_valid(&itr)) {
        asV6Node = &kb_itr_key(asV6Node_t, &itr);
        kb_itr_next(asV6Tree, asV6Tree, &itr);  // move on
        return asV6Node;
    } else {
        return NULL;
    }
}  // End of NextasV6Node