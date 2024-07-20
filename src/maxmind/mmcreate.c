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

#include "mmcreate.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "maxmind/mmhash.h"
#include "mmcreate.h"
#include "util.h"

static char *asFieldNames[] = {"network", "autonomous_system_number", "autonomous_system_organization", NULL};

// field names of GeoLite2-City-Locations-en
static char *localFieldNames[] = {"geoname_id",
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

static char *ipFieldNames[] = {"network",
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

static void stripLine(char *line) {
    char *eol = strchr(line, '\r');
    if (eol) *eol = '\0';
    eol = strchr(line, '\n');
    if (eol) *eol = '\0';
}  // End of stripLine

static FILE *checkFile(char *fileName, char **fieldNames) {
    FILE *fp = fopen(fileName, "r");
    if (!fp) {
        LogError("open(%s) error in %s line %d: %s", fileName, __FILE__, __LINE__, strerror(errno));
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
    stripLine(line);
    // parse and check header line
    int i = 0;
    char *field = NULL;
    char *l = line;
    while ((field = strsep(&l, ",")) != NULL) {
        if (fieldNames[i] == NULL) {
            LogError("Field check for %s: Found extra field '%s'", fileName, field);
        } else if (strcmp(field, fieldNames[i]) != 0) {
            LogError("Field check failed in %s at index: %d, expected: '%s', found: '%s'", fileName, i, fieldNames[i], field);
            fclose(fp);
            return NULL;
        }
        i++;
    }

    free(line);
    return fp;

}  // End of checkFile

static int loadLocalMap(char *fileName) {
    FILE *fp = checkFile(fileName, localFieldNames);
    if (!fp) {
        LogError("loadLocalMap(%s) failed", fileName);
        return 0;
    }

    uint32_t cnt = 0;
    char *line = NULL;
    size_t linecap = 0;
    ssize_t lineLen;
    while ((lineLen = getline(&line, &linecap, fp)) > 0) {
        locationInfo_t locationInfo = {0};
        stripLine(line);
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
                    // default: do nothing - skip extra (new?) fields
            }
            i++;
        }
        PutLocation(&locationInfo);
        cnt++;
    }
    printf("Loaded %u location records\n", cnt);

    fclose(fp);
    return 1;

}  // End of loadLocalMap

static int loadIPV4tree(char *fileName) {
    FILE *fp = checkFile(fileName, ipFieldNames);
    if (!fp) {
        LogError("loadIPV4tree(%s) failed", fileName);
        return 0;
    }

    uint32_t cnt = 0;
    char *line = NULL;
    size_t linecap = 0;
    ssize_t lineLen;
    while ((lineLen = getline(&line, &linecap, fp)) > 0) {
        stripLine(line);
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
        PutIPv4Node(&ipV4Node);
        cnt++;
    }
    printf("Loaded %u entries into IPV4 tree\n", cnt);

    fclose(fp);
    return 1;

}  // End of loadIPV4tree

static int loadIPV6tree(char *fileName) {
    FILE *fp = checkFile(fileName, ipFieldNames);
    if (!fp) {
        LogError("loadIPV6tree(%s) failed", fileName);
        return 0;
    }

    uint32_t cnt = 0;
    char *line = NULL;
    size_t linecap = 0;
    ssize_t lineLen;
    while ((lineLen = getline(&line, &linecap, fp)) > 0) {
        stripLine(line);
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

        PutIPv6Node(&ipV6Node);
        cnt++;
    }
    printf("Loaded %u entries into IPV6 tree\n", cnt);

    fclose(fp);
    return 1;

}  // End of loadIPV6tree

static int loadASV4tree(char *fileName) {
    FILE *fp = checkFile(fileName, asFieldNames);
    if (!fp) {
        LogError("loadASV4tree(%s) failed", fileName);
        return 0;
    }

    uint32_t cnt = 0;
    char *line = NULL;
    size_t linecap = 0;
    ssize_t lineLen;
    while ((lineLen = getline(&line, &linecap, fp)) > 0) {
        stripLine(line);
        // printf("%s\n", line);
        char *field = line;
        char *sep = NULL;

        // extract cidr
        sep = strchr(field, ',');
        if (!sep) {
            LogError("Parse cidr in ASv4 file: %s: failed", fileName);
            return 0;
        }
        *sep++ = '\0';

        // cidr
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
        asV4Node_t asV4Node = {.network = ntohl(net), .netmask = mask};
        field = sep;

        // extract AS
        sep = strchr(field, ',');
        if (!sep) {
            LogError("Parse AS in ASv4 file: %s: failed", fileName);
            return 0;
        }
        *sep++ = '\0';
        asV4Node.as = atoi(field);
        asOrgNode_t asOrgNode = {.as = asV4Node.as};
        field = sep;

        // extract org name
        strncpy(asV4Node.orgName, field, orgNameLength);
        asV4Node.orgName[orgNameLength - 1] = '\0';
        strncpy(asOrgNode.orgName, field, orgNameLength);
        asOrgNode.orgName[orgNameLength - 1] = '\0';

        // insert node
        PutasV4Node(&asV4Node);
        PutASorgNode(&asOrgNode);

        cnt++;
    }
    printf("Loaded %u entries into ASV4 tree\n", cnt);

    fclose(fp);
    return 1;

}  // End of loadASV4tree

static int loadASV6tree(char *fileName) {
    FILE *fp = checkFile(fileName, asFieldNames);
    if (!fp) {
        LogError("loadASV6tree(%s) failed", fileName);
        return 0;
    }

    uint32_t cnt = 0;
    char *line = NULL;
    size_t linecap = 0;
    ssize_t lineLen;
    while ((lineLen = getline(&line, &linecap, fp)) > 0) {
        stripLine(line);
        // printf("%s\n", line);
        char *field = line;
        char *sep = NULL;

        // extract cidr
        sep = strchr(field, ',');
        if (!sep) {
            LogError("Parse cidr in ASv6 file: %s: failed", fileName);
            return 0;
        }
        *sep++ = '\0';

        // cidr
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
        asV6Node_t asV6Node = {.network[0] = ntohll(net[0]), .network[1] = ntohll(net[1]), .netmask[0] = mask[0], .netmask[1] = mask[1]};
        field = sep;

        // extract AS
        sep = strchr(field, ',');
        if (!sep) {
            LogError("Parse AS in ASv4 file: %s: failed", fileName);
            return 0;
        }
        *sep++ = '\0';
        asV6Node.as = atoi(field);
        asOrgNode_t asOrgNode = {.as = asV6Node.as};
        field = sep;

        // extract org name
        strncpy(asV6Node.orgName, field, orgNameLength);
        asV6Node.orgName[orgNameLength - 1] = '\0';
        strncpy(asOrgNode.orgName, field, orgNameLength);
        asOrgNode.orgName[orgNameLength - 1] = '\0';

        PutasV6Node(&asV6Node);
        PutASorgNode(&asOrgNode);
        cnt++;
    }
    printf("Loaded %u entries into ASV6 tree\n", cnt);

    fclose(fp);
    return 1;

}  // End of loadASV6tree

int LoadMaps(char *dirName) {
    DIR *dp = opendir(dirName);
    if (dp == NULL) {
        LogError("opendir() error: %s", strerror(errno));
        return 0;
    }
    char *cwd = getcwd(NULL, 0);
    if (cwd == NULL) {
        LogError("getcwd() error: %s", strerror(errno));
        return 0;
    }
    if (chdir(dirName) < 0) {
        LogError("chdir() error: %s", strerror(errno));
        return 0;
    }
    char *CityLocationFile = NULL;
    char *CityBlocksIPv4File = NULL;
    char *CityBlocksIPv6File = NULL;
    char *ASNBlocksIPv4File = NULL;
    char *ASNBlocksIPv6File = NULL;
    struct dirent *ep;
    for (ep = readdir(dp); ep != NULL; ep = readdir(dp)) {
        struct stat stat_buf;
        if (stat(ep->d_name, &stat_buf) < 0) {
            LogError("stat() error: %s", strerror(errno));
            return 0;
        }
        if (!S_ISREG(stat_buf.st_mode)) {
            LogError("Skip non file entry: %s", ep->d_name);
            continue;
        }
        char *extension = strstr(ep->d_name, ".csv");
        if (extension == NULL) {
            LogError("Skip non .csv file: %s", ep->d_name);
            continue;
        }
        if (strstr(ep->d_name, "-City-Locations-") != NULL)
            CityLocationFile = strdup(ep->d_name);
        else if (strstr(ep->d_name, "-City-Blocks-IPv4.csv") != NULL)
            CityBlocksIPv4File = strdup(ep->d_name);
        else if (strstr(ep->d_name, "-City-Blocks-IPv6.csv") != NULL)
            CityBlocksIPv6File = strdup(ep->d_name);
        else if (strstr(ep->d_name, "-ASN-Blocks-IPv4.csv") != NULL)
            ASNBlocksIPv4File = strdup(ep->d_name);
        else if (strstr(ep->d_name, "-ASN-Blocks-IPv6.csv") != NULL)
            ASNBlocksIPv6File = strdup(ep->d_name);
    }
    closedir(dp);

    if (CityLocationFile) {
        printf("Process file: %s\n", CityLocationFile);
        loadLocalMap(CityLocationFile);
    }
    if (CityBlocksIPv4File) {
        printf("Process file: %s\n", CityBlocksIPv4File);
        loadIPV4tree(CityBlocksIPv4File);
    }
    if (CityBlocksIPv6File) {
        printf("Process file: %s\n", CityBlocksIPv6File);
        loadIPV6tree(CityBlocksIPv6File);
    }
    if (ASNBlocksIPv4File) {
        printf("Process file: %s\n", ASNBlocksIPv4File);
        loadASV4tree(ASNBlocksIPv4File);
    }
    if (ASNBlocksIPv6File) {
        printf("Process file: %s\n", ASNBlocksIPv6File);
        loadASV6tree(ASNBlocksIPv6File);
    }

    if (chdir(cwd) < 0) {
        LogError("chdir() error: %s", strerror(errno));
        return 0;
    }

    return 1;

}  // End of LoadMaps