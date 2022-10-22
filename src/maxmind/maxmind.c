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

#include "nffile.h"
#include "nffileV2.h"
#include "nfxV3.h"
#include "util.h"

// include after
#include "kbtree.h"
#include "khash.h"

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

char *asFieldNames[] = {"network", "autonomous_system_number", "autonomous_system_organization", NULL};

// field names of GeoLite2-City-Locations-en
char *localFieldNames[] = {"geoname_id",
                           "locale_code",
                           "continent_code",
                           "continent_name",
                           "country_iso_code",
                           "country_name",
                           "subdivision_1_iso_code",
                           "subdivision_1_name",
                           "subdivision_2_iso_code",
                           "subdivision_2_name",
                           "city_name",
                           "metro_code",
                           "time_zone",
                           "is_in_european_union",
                           NULL};

char *ipFieldNames[] = {"network",
                        "geoname_id",
                        "registered_country_geoname_id",
                        "represented_country_geoname_id",
                        "is_anonymous_proxy",
                        "is_satellite_provider",
                        "postal_code",
                        "latitude",
                        "longitude",
                        "accuracy_radius",
                        NULL};

#include "nffile_inline.c"

static FILE *checkFile(char *fileName, char **fieldNames) {
    FILE *fp = fopen(fileName, "r");
    if (!fp) {
        LogError("open() error: %s", strerror(errno));
        return NULL;
    }

    char *line = NULL;
    size_t linecap = 0;
    ssize_t lineLen;

    // get and parse header line
    lineLen = getline(&line, &linecap, fp);
    if (lineLen < 0) {
        LogError("getline() error: %s", strerror(errno));
        return NULL;
    }
    char *eol = strchr(line, '\n');
    *eol = '\0';

    // parse and check header line
    int i = 0;
    char *field = NULL;
    char *l = line;
    while ((field = strsep(&l, ",")) != NULL) {
        if (fieldNames[i] == NULL || strcmp(field, fieldNames[i]) != 0) {
            LogError("header check failed at index: %d, '%s' - '%s'", i, fieldNames[i], field);
            fclose(fp);
            return NULL;
        }
        i++;
    }

    free(line);
    return fp;

}  // End of checkFile

int Init_MaxMind(void) {
    mmHandle = calloc(1, sizeof(mmHandle_t));
    if (!mmHandle) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
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

int Loaded_MaxMind(void) { return mmHandle != NULL; }  // End of Loaded_MaxMind

int loadLocalMap(char *fileName) {
    FILE *fp = checkFile(fileName, localFieldNames);
    if (!fp) {
        LogError("open() error: %s", strerror(errno));
        return 0;
    }

    khash_t(localMap) *localMap = mmHandle->localMap;

    char *line = NULL;
    size_t linecap = 0;
    ssize_t lineLen;
    while ((lineLen = getline(&line, &linecap, fp)) > 0) {
        locationInfo_t locationInfo;
        char *eol = strchr(line, '\n');
        *eol = '\0';
        char *countryName = NULL;
        char *divisionName = NULL;
        char *l = line;
        char *field = NULL;
        int i = 0;
        while ((field = strsep(&l, ",")) != NULL) {
            switch (i) {
                case 0:  // geoname_id
                    locationInfo.localID = atoi(field);
                    break;
                case 2:  // continent_code
                    if (strlen(field) > 3) {
                        LogError("Unexpected continent_code length: %lu", strlen(field));
                        locationInfo.continent[0] = '\0';
                    } else {
                        strcpy(locationInfo.continent, field);
                    }
                    break;
                case 4:  // country_iso_code
                    if (strlen(field) > 3) {
                        LogError("Unexpected country_iso_code length: %lu", strlen(field));
                        locationInfo.continent[0] = '\0';
                    } else {
                        strcpy(locationInfo.country, field);
                    }
                    break;
                case 5:  // country_name
                    countryName = field;
                    if (strlen(field) > (CityLength - 1)) {
                        field[CityLength - 1] = '\0';
                    }
                    break;
                case 7:  // subdivision_1_name
                    divisionName = field;
                    if (strlen(field) > (CityLength - 1)) {
                        field[CityLength - 1] = '\0';
                    }
                    break;
                case 10:  // city_name
                    if (strlen(field) > (CityLength - 1)) {
                        field[CityLength - 1] = '\0';
                    }
                    if (strlen(field) > 0) {
                        strcpy(locationInfo.city, field);
                    } else if (divisionName && strlen(divisionName) > 0) {
                        strcpy(locationInfo.city, divisionName);
                    } else if (countryName && strlen(countryName) > 0) {
                        strcpy(locationInfo.city, countryName);
                    } else {
                        strcpy(locationInfo.city, "unknown");
                    }
                    break;
            }
            i++;
        }

        int absent;
        locationKey_t locationKey = {.key = locationInfo.localID};
        khint_t k = kh_put(localMap, localMap, locationKey, &absent);
        if (!absent) {
            LogError("Duplicate entry: %u", locationInfo.localID);
        } else {
            kh_value(localMap, k) = locationInfo;
        }
    }

    fclose(fp);
    return 1;

}  // End of loadLocalMap

int loadIPV4tree(char *fileName) {
    FILE *fp = checkFile(fileName, ipFieldNames);
    if (!fp) {
        LogError("open() error: %s", strerror(errno));
        return 0;
    }

    kbtree_t(ipV4Tree) *ipV4Tree = mmHandle->ipV4Tree;

    uint32_t cnt = 0;
    char *line = NULL;
    size_t linecap = 0;
    ssize_t lineLen;
    while ((lineLen = getline(&line, &linecap, fp)) > 0) {
        char *eol = strchr(line, '\n');
        *eol = '\0';
        // printf("%s\n", line);
        ipV4Node_t ipV4Node;
        char *l = line;
        char *field = NULL;
        int i = 0;
        while ((field = strsep(&l, ",")) != NULL) {
            // printf("field: %s\n", field);
            switch (i) {
                case (0): {
                    char *cidr = strchr(field, '/');
                    *cidr = '\0';
                    uint32_t net, netBits, mask;
                    int ret = inet_pton(PF_INET, field, &net);
                    if (ret != 1) {
                        LogError("Not an IPv4 network: %s\n", field);
                        continue;
                    }
                    netBits = atoi(++cidr);
                    mask = 0xffffffff << (32 - netBits);
                    ipV4Node.network = ntohl(net);
                    ipV4Node.netmask = mask;
                } break;
                case 1:  // geoname_id
                    ipV4Node.info.localID = atoi(field);
                    break;
                case 4:  // is_proxy
                    ipV4Node.info.proxy = strcmp(field, "1") == 0 ? 1 : 0;
                    break;
                case 5:  // is_sat
                    ipV4Node.info.sat = strcmp(field, "1") == 0 ? 1 : 0;
                    break;
                case 7:  // longitude
                    ipV4Node.info.longitude = atof(field);
                    break;
                case 8:  // latitude
                    ipV4Node.info.latitude = atof(field);
                    break;
                case 9:  // accuracy
                    ipV4Node.info.accuracy = atoi(field);
                    break;
            }
            i++;
        }
        cnt++;
        ipV4Node_t *node = kb_getp(ipV4Tree, ipV4Tree, &ipV4Node);
        if (node) {
            LogError("Duplicate IPV4 node: ip: %s", field);
        } else {
            kb_putp(ipV4Tree, ipV4Tree, &ipV4Node);
        }
    }
    printf("Loaded %u entries into IPV4 tree\n", cnt);

    fclose(fp);
    return 1;

}  // End of loadIPV4tree

int loadIPV6tree(char *fileName) {
    FILE *fp = checkFile(fileName, ipFieldNames);
    if (!fp) {
        LogError("open() error: %s", strerror(errno));
        return 0;
    }

    kbtree_t(ipV6Tree) *ipV6Tree = mmHandle->ipV6Tree;

    uint32_t cnt = 0;
    char *line = NULL;
    size_t linecap = 0;
    ssize_t lineLen;
    while ((lineLen = getline(&line, &linecap, fp)) > 0) {
        char *eol = strchr(line, '\n');
        *eol = '\0';
        // printf("%s\n", line);
        ipV6Node_t ipV6Node;
        char *l = line;
        char *field = NULL;
        int i = 0;
        while ((field = strsep(&l, ",")) != NULL) {
            // printf("field: %s\n", field);
            switch (i) {
                case (0): {
                    char *cidr = strchr(field, '/');
                    *cidr = '\0';
                    uint32_t netBits;
                    uint64_t net[2], mask[2];
                    int ret = inet_pton(PF_INET6, field, net);
                    if (ret != 1) {
                        LogError("Not an IPv6 network: %s\n", field);
                        continue;
                    }
                    netBits = atoi(++cidr);

                    if (netBits > 64) {
                        mask[0] = 0xffffffffffffffffLL;
                        mask[1] = 0xffffffffffffffffLL << (64 - netBits);
                    } else {
                        mask[0] = 0xffffffffffffffffLL << (64 - netBits);
                        mask[1] = 0;
                    }

                    // printf("ip: 0x%x, bits: %u, mask: 0x%x\n", net, netBits, mask);
                    ipV6Node.network[0] = ntohll(net[0]);
                    ipV6Node.network[1] = ntohll(net[1]);
                    ipV6Node.netmask[0] = mask[0];
                    ipV6Node.netmask[1] = mask[1];
                } break;
                case 1:  // geoname_id
                    ipV6Node.info.localID = atoi(field);
                    break;
                case 4:  // is_proxy
                    ipV6Node.info.proxy = strcmp(field, "1") == 0 ? 1 : 0;
                    break;
                case 5:  // is_sat
                    ipV6Node.info.sat = strcmp(field, "1") == 0 ? 1 : 0;
                    break;
                case 7:  // longitude
                    ipV6Node.info.longitude = atof(field);
                    break;
                case 8:  // latitude
                    ipV6Node.info.latitude = atof(field);
                    break;
                case 9:  // accuracy
                    ipV6Node.info.accuracy = atoi(field);
                    break;
            }
            i++;
        }

        cnt++;
        ipV6Node_t *node = kb_getp(ipV6Tree, ipV6Tree, &ipV6Node);
        if (node) {
            LogError("Duplicate IPV6 node: ip: %s", field);
        } else {
            kb_putp(ipV6Tree, ipV6Tree, &ipV6Node);
        }
    }
    printf("Loaded %u entries into IPV6 tree\n", cnt);

    fclose(fp);
    return 1;

}  // End of loadIPV6tree

int loadASV4tree(char *fileName) {
    FILE *fp = checkFile(fileName, asFieldNames);
    if (!fp) {
        LogError("open() error: %s", strerror(errno));
        return 0;
    }

    kbtree_t(asV4Tree) *asV4Tree = mmHandle->asV4Tree;

    uint32_t cnt = 0;
    char *line = NULL;
    size_t linecap = 0;
    ssize_t lineLen;
    while ((lineLen = getline(&line, &linecap, fp)) > 0) {
        char *eol = strchr(line, '\n');
        *eol = '\0';
        // printf("%s\n", line);
        asV4Node_t asV4Node;
        char *l = line;
        char *field = NULL;
        int i = 0;
        while ((field = strsep(&l, ",")) != NULL) {
            // printf("field: %s\n", field);
            switch (i) {
                case (0): {  // cidr
                    char *cidr = strchr(field, '/');
                    *cidr = '\0';
                    uint32_t net, netBits, mask;
                    int ret = inet_pton(PF_INET, field, &net);
                    if (ret != 1) {
                        LogError("Not an IPv4 network: %s\n", field);
                        continue;
                    }
                    netBits = atoi(++cidr);
                    mask = 0xffffffff << (32 - netBits);
                    // printf("ip: 0x%x, bits: %u, mask: 0x%x\n", net, netBits, mask);
                    asV4Node.network = ntohl(net);
                    asV4Node.netmask = mask;
                } break;
                case 1:  // AS
                    asV4Node.as = atoi(field);
                    break;
                case 2:  // org name
                    strncpy(asV4Node.orgName, field, 64);
                    asV4Node.orgName[63] = '\0';
                    break;
            }
            i++;
        }

        cnt++;
        asV4Node_t *node = kb_getp(asV4Tree, asV4Tree, &asV4Node);
        if (node) {
            LogError("Duplicate AS node: ip: %s", field);
        } else {
            kb_putp(asV4Tree, asV4Tree, &asV4Node);
        }
    }
    printf("Loaded %u entries into ASV4 tree\n", cnt);

    fclose(fp);
    return 1;

}  // End of loadASV4tree

int loadASV6tree(char *fileName) {
    FILE *fp = checkFile(fileName, asFieldNames);
    if (!fp) {
        LogError("open() error: %s", strerror(errno));
        return 0;
    }

    kbtree_t(asV6Tree) *asV6Tree = mmHandle->asV6Tree;

    uint32_t cnt = 0;
    char *line = NULL;
    size_t linecap = 0;
    ssize_t lineLen;
    while ((lineLen = getline(&line, &linecap, fp)) > 0) {
        char *eol = strchr(line, '\n');
        *eol = '\0';
        // printf("%s\n", line);
        asV6Node_t asV6Node;
        char *l = line;
        char *field = NULL;
        int i = 0;
        while ((field = strsep(&l, ",")) != NULL) {
            // printf("field: %s\n", field);
            switch (i) {
                case (0): {
                    char *cidr = strchr(field, '/');
                    *cidr = '\0';
                    uint32_t netBits;
                    uint64_t net[2], mask[2];
                    int ret = inet_pton(PF_INET6, field, net);
                    if (ret != 1) {
                        LogError("Not an IPv4 network: %s\n", field);
                        continue;
                    }
                    netBits = atoi(++cidr);

                    if (netBits > 64) {
                        mask[0] = 0xffffffffffffffffLL;
                        mask[1] = 0xffffffffffffffffLL << (64 - netBits);
                    } else {
                        mask[0] = 0xffffffffffffffffLL << (64 - netBits);
                        mask[1] = 0;
                    }

                    // printf("ip: 0x%x, bits: %u, mask: 0x%x\n", net, netBits, mask);
                    asV6Node.network[0] = ntohll(net[0]);
                    asV6Node.network[1] = ntohll(net[1]);
                    asV6Node.netmask[0] = mask[0];
                    asV6Node.netmask[1] = mask[1];
                } break;
                case 1:  // geoname_id
                    asV6Node.as = atoi(field);
                    break;
                case 2:  // org name
                    strncpy(asV6Node.orgName, field, 64);
                    asV6Node.orgName[63] = '\0';
                    break;
            }
            i++;
        }

        cnt++;
        asV6Node_t *node = kb_getp(asV6Tree, asV6Tree, &asV6Node);
        if (node) {
            LogError("Duplicate ASV6 node: ip: %s", field);
        } else {
            kb_putp(asV6Tree, asV6Tree, &asV6Node);
        }
    }
    printf("Loaded %u entries into ASV6 tree\n", cnt);

    fclose(fp);
    return 1;

}  // End of loadASV6tree

static int StoreLocalMap(nffile_t *nffile) {
    khash_t(localMap) *localMap = mmHandle->localMap;

    void *outBuff = nffile->buff_ptr;
    size_t size = 0;
    unsigned cnt = 0;
    for (khint_t k = kh_begin(localMap); k != kh_end(localMap); ++k) {  // traverse
        locationInfo_t locationInfo;
        if (kh_exist(localMap, k)) {  // test if a bucket contains data
            locationInfo = kh_value(localMap, k);
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
            memcpy(outBuff, &locationInfo, sizeof(locationInfo));
            cnt++;
            outBuff += sizeof(locationInfo_t);
            size -= sizeof(locationInfo_t);
            nffile->block_header->size += sizeof(locationInfo_t);
            nffile->block_header->NumRecords++;
        }
    }
    return 1;

}  // End of StoreLocalMap

static int StoreIPV4tree(nffile_t *nffile) {
    kbtree_t(ipV4Tree) *ipV4Tree = mmHandle->ipV4Tree;

    void *outBuff = nffile->buff_ptr;
    size_t size = 0;

    kbitr_t itr;
    kb_itr_first(ipV4Tree, ipV4Tree, &itr);                              // get an iterator pointing to the first
    for (; kb_itr_valid(&itr); kb_itr_next(ipV4Tree, ipV4Tree, &itr)) {  // move on
        ipV4Node_t *ipV4Node = &kb_itr_key(ipV4Node_t, &itr);
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
        memcpy(outBuff, ipV4Node, sizeof(ipV4Node_t));
        outBuff += sizeof(ipV4Node_t);
        size -= sizeof(ipV4Node_t);
        nffile->block_header->size += sizeof(ipV4Node_t);
        nffile->block_header->NumRecords++;
    }

    return 1;

}  // End of StoreIPtree

static int StoreIPV6tree(nffile_t *nffile) {
    kbtree_t(ipV6Tree) *ipV6Tree = mmHandle->ipV6Tree;

    void *outBuff = nffile->buff_ptr;
    size_t size = 0;

    kbitr_t itr;
    kb_itr_first(ipV6Tree, ipV6Tree, &itr);                              // get an iterator pointing to the first
    for (; kb_itr_valid(&itr); kb_itr_next(ipV6Tree, ipV6Tree, &itr)) {  // move on
        ipV6Node_t *ipV6Node = &kb_itr_key(ipV6Node_t, &itr);
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
        memcpy(outBuff, ipV6Node, sizeof(ipV6Node_t));
        outBuff += sizeof(ipV6Node_t);
        size -= sizeof(ipV6Node_t);
        nffile->block_header->size += sizeof(ipV6Node_t);
        nffile->block_header->NumRecords++;
    }

    return 1;

}  // End of StoreIPtree

static int StoreAStree(nffile_t *nffile) {
    kbtree_t(asV4Tree) *asV4Tree = mmHandle->asV4Tree;

    void *outBuff = nffile->buff_ptr;
    size_t size = 0;

    kbitr_t itr;
    kb_itr_first(asV4Tree, asV4Tree, &itr);                              // get an iterator pointing to the first
    for (; kb_itr_valid(&itr); kb_itr_next(asV4Tree, asV4Tree, &itr)) {  // move on
        asV4Node_t *asV4Node = &kb_itr_key(asV4Node_t, &itr);
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
    }

    return 1;

}  // End of StoreAStree

static int StoreASV6tree(nffile_t *nffile) {
    kbtree_t(asV6Tree) *asV6Tree = mmHandle->asV6Tree;

    void *outBuff = nffile->buff_ptr;
    size_t size = 0;

    kbitr_t itr;
    kb_itr_first(asV6Tree, asV6Tree, &itr);                              // get an iterator pointing to the first
    for (; kb_itr_valid(&itr); kb_itr_next(asV6Tree, asV6Tree, &itr)) {  // move on
        asV6Node_t *asV6Node = &kb_itr_key(asV6Node_t, &itr);
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
    }

    return 1;

}  // End of StoreASV6tree

int SaveMaxMind(char *fileName) {
    nffile_t *nffile = OpenNewFile(fileName, NULL, LZ4_COMPRESSED, NOT_ENCRYPTED);

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
    nffile_t *nffile = OpenFile(fileName, NULL);
    if (!nffile) {
        return 0;
    }
    unsigned cnt = 0;
    int done = 0;
    while (!done) {
        // get next data block from file
        int ret = ReadBlock(nffile);

        switch (ret) {
            case NF_CORRUPT:
            case NF_ERROR:
                if (ret == NF_CORRUPT)
                    LogError("Skip corrupt data file '%s'\n", nffile->fileName);
                else
                    LogError("Read error in file '%s': %s\n", nffile->fileName, strerror(errno));
                // fall through - get next file in chain
            case NF_EOF:
                done = 1;
                continue;
                break;  // not really needed
        }

        dbg_printf("Next block. type: %u, size: %u\n", nffile->block_header->type, nffile->block_header->size);
        if (nffile->block_header->type != DATA_BLOCK_TYPE_4) {
            LogError("Can't process block type %u. Skip block.\n", nffile->block_header->type);
            continue;
        }

        record_header_t *arrayHeader = nffile->buff_ptr;
        void *arrayElement = (void *)nffile->buff_ptr + sizeof(record_header_t);
        size_t expected = (arrayHeader->size * nffile->block_header->NumRecords) + sizeof(record_header_t);
        if (expected != nffile->block_header->size) {
            LogError("Array size calculated: %u != expected: %u for element: %u", expected, nffile->block_header->size, arrayHeader->type);
            continue;
        }

        switch (arrayHeader->type) {
            case LocalInfoElementID: {
                // khash_t(localMap) *localMap = mmHandle->localMap;
                locationInfo_t *locationInfo = (locationInfo_t *)arrayElement;
                for (int i = 0; i < nffile->block_header->NumRecords; i++) {
                    int absent;
                    locationKey_t locationKey = {.key = locationInfo->localID};
                    khint_t k = kh_put(localMap, mmHandle->localMap, locationKey, &absent);
                    if (!absent) {
                        LogError("Duplicate location entry: %u", locationInfo->localID);
                    } else {
                        kh_value(mmHandle->localMap, k) = *locationInfo;
                    }
                    locationInfo++;
                    cnt++;
                }
            } break;
            case IPV4treeElementID: {
                kbtree_t(ipV4Tree) *ipV4Tree = mmHandle->ipV4Tree;
                ipV4Node_t *ipV4Node = (ipV4Node_t *)arrayElement;
                for (int i = 0; i < nffile->block_header->NumRecords; i++) {
                    ipV4Node_t *node = kb_getp(ipV4Tree, ipV4Tree, ipV4Node);
                    if (node) {
                        LogError("Duplicate IP node: ip: 0x%x, mask: 0x%x", ipV4Node->network, ipV4Node->netmask);
                    } else {
                        kb_putp(ipV4Tree, ipV4Tree, ipV4Node);
                    }
                    ipV4Node++;
                }
            } break;
            case IPV6treeElementID: {
                kbtree_t(ipV6Tree) *ipV6Tree = mmHandle->ipV6Tree;
                ipV6Node_t *ipV6Node = (ipV6Node_t *)arrayElement;
                for (int i = 0; i < nffile->block_header->NumRecords; i++) {
                    ipV6Node_t *node = kb_getp(ipV6Tree, ipV6Tree, ipV6Node);
                    if (node) {
                        LogError("Duplicate IPV6 node: ip: 0x%x %x, mask: 0x%x %x", ipV6Node->network[0], ipV6Node->network[1], ipV6Node->netmask[0],
                                 ipV6Node->netmask[1]);
                    } else {
                        kb_putp(ipV6Tree, ipV6Tree, ipV6Node);
                    }
                    ipV6Node++;
                }
            } break;
            case ASV4treeElementID: {
                kbtree_t(asV4Tree) *asV4Tree = mmHandle->asV4Tree;
                asV4Node_t *asV4Node = (asV4Node_t *)arrayElement;
                for (int i = 0; i < nffile->block_header->NumRecords; i++) {
                    asV4Node_t *node = kb_getp(asV4Tree, asV4Tree, asV4Node);
                    if (node) {
                        LogError("Duplicate AS node: ip: 0x%x, mask: 0x%x", asV4Node->network, asV4Node->netmask);
                    } else {
                        kb_putp(asV4Tree, asV4Tree, asV4Node);
                    }
                    asV4Node++;
                }
            } break;
            case ASV6treeElementID: {
                kbtree_t(asV6Tree) *asV6Tree = mmHandle->asV6Tree;
                asV6Node_t *asV6Node = (asV6Node_t *)arrayElement;
                for (int i = 0; i < nffile->block_header->NumRecords; i++) {
                    asV6Node_t *node = kb_getp(asV6Tree, asV6Tree, asV6Node);
                    if (node) {
                        LogError("Duplicate ASV6 node: ip: 0x%x %x, mask: 0x%x %x", asV6Node->network[0], asV6Node->network[1], asV6Node->netmask[0],
                                 asV6Node->netmask[1]);
                    } else {
                        kb_putp(asV6Tree, asV6Tree, asV6Node);
                    }
                    asV6Node++;
                }
            } break;
            default:
                LogError("Skip unknown array element: %u", arrayHeader->type);
        }
    }
    DisposeFile(nffile);

    return 1;
}  // End of LoadMaxMind

void LookupCountry(uint64_t ip[2], char *country) {
    if (!mmHandle) {
        country[0] = '.';
        country[1] = '.';
        country[2] = '\0';
        return;
    }

    ipLocationInfo_t info = {0};
    if (ip[0] == 0) {  // IPv4
        ipV4Node_t ipSearch = {.network = ip[1], .netmask = 0};
        ipV4Node_t *ipV4Node = kb_getp(ipV4Tree, mmHandle->ipV4Tree, &ipSearch);
        if (!ipV4Node) {
            country[0] = '.';
            country[1] = '.';
            country[2] = '\0';
            return;
        }
        info = ipV4Node->info;
    } else {
        ipV6Node_t ipSearch = {0};
        ipSearch.network[0] = ip[0];
        ipSearch.network[1] = ip[1];
        ipV6Node_t *ipV6Node = kb_getp(ipV6Tree, mmHandle->ipV6Tree, &ipSearch);
        if (!ipV6Node) {
            country[0] = '.';
            country[1] = '.';
            country[2] = '\0';
            return;
        }
        info = ipV6Node->info;
    }
    locationKey_t locationKey = {.key = info.localID};
    khint_t k = kh_get(localMap, mmHandle->localMap, locationKey);
    if (k == kh_end(mmHandle->localMap)) {
        country[0] = '.';
        country[1] = '.';
        country[2] = '\0';
        return;
    }

    locationInfo_t locationInfo = kh_value(mmHandle->localMap, k);
    country[0] = locationInfo.country[0];
    country[1] = locationInfo.country[1];
    country[2] = '\0';

    /*
            printf("localID: %d %s/%s/%s long/lat: %8.4f/%-8.4f, accuracy: %u, AS: %u\n",
                    locationInfo.localID, locationInfo.continent, locationInfo.country, locationInfo.city,
                    ipV4Node->longitude, ipV4Node->latitude, ipV4Node->accuracy, as);
            }
    */
}  // End of LookupCountry

void LookupLocation(uint64_t ip[2], char *location, size_t len) {
    location[0] = '\0';
    if (!mmHandle) {
        return;
    }

    ipLocationInfo_t info = {0};
    if (ip[0] == 0) {  // IPv4
        ipV4Node_t ipSearch = {.network = ip[1], .netmask = 0};
        ipV4Node_t *ipV4Node = kb_getp(ipV4Tree, mmHandle->ipV4Tree, &ipSearch);
        if (!ipV4Node) {
            return;
        }
        info = ipV4Node->info;
    } else {
        ipV6Node_t ipSearch = {0};
        ipSearch.network[0] = ip[0];
        ipSearch.network[1] = ip[1];
        ipV6Node_t *ipV6Node = kb_getp(ipV6Tree, mmHandle->ipV6Tree, &ipSearch);
        if (!ipV6Node) {
            return;
        }
        info = ipV6Node->info;
    }

    locationKey_t locationKey = {.key = info.localID};
    khint_t k = kh_get(localMap, mmHandle->localMap, locationKey);
    if (k == kh_end(mmHandle->localMap)) {
        return;
    }

    locationInfo_t locationInfo = kh_value(mmHandle->localMap, k);
    snprintf(location, len, "%s/%s/%s long/lat: %.4f/%-.4f", locationInfo.continent, locationInfo.country, locationInfo.city, info.longitude,
             info.latitude);

}  // End of LookupLocation

uint32_t LookupAS(uint64_t ip[2]) {
    if (!mmHandle) {
        return 0;
    }

    if (ip[0] == 0) {  // IPv4
        asV4Node_t asSearch = {.network = ip[1], .netmask = 0};
        asV4Node_t *asV4Node = kb_getp(asV4Tree, mmHandle->asV4Tree, &asSearch);
        return asV4Node == NULL ? 0 : asV4Node->as;
    } else {  // IPv6
        asV6Node_t asV6Search = {0};
        asV6Search.network[0] = ip[0];
        asV6Search.network[1] = ip[1];
        asV6Node_t *asV6Node = kb_getp(asV6Tree, mmHandle->asV6Tree, &asV6Search);
        return asV6Node == NULL ? 0 : asV6Node->as;
    }

}  // End of LookupAS

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

        ipV6Node = kb_getp(ipV6Tree, mmHandle->ipV6Tree, &ipSearch);
        if (ipV6Node) {
            info = ipV6Node->info;
        }

        asV6Node_t *asV6Node = kb_getp(asV6Tree, mmHandle->asV6Tree, &asSearch);
        if (asV6Node) {
            as = asV6Node->as;
            asOrg = asV6Node->orgName;
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
