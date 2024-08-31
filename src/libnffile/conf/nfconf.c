/*
 *  Copyright (c) 2022, Peter Haag
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

#include "nfconf.h"

#include <arpa/nameser.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "config.h"

#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif

#include "toml.h"
#include "util.h"

#define NFCONF_FILE SYSCONFDIR "/nfdump.conf"

typedef struct nfconfFile_s {
    int valid;                  // flag
    toml_table_t *conf;         // handle to top toml table
    toml_table_t *sectionConf;  // handle to nfdump section
} nfconfFile_t;

static nfconfFile_t nfconfFile = {0};

/*
 * Open config file provided
 * returns:
 * -1 error
 *  0 no config file
 *  1 successfully read config
 */
int ConfOpen(char *filename, char *section) {
    // if read prevented
    if (filename && strcmp(filename, NOCONF) == 0) return 0;

    // try to read NFCONF environment
    if (filename == NULL) filename = getenv("NFCONF");

    // if no config file is given, check for default
    // silently return if not found
    if (filename == NULL) {
#ifdef CONFIGDIR
        // supplied at compile time
        size_t len = sizeof(CONFIGDIR) + 1 + 11 + 1;  // path + '/' + nfdump.conf + '\0'
        filename = calloc(1, len);
        snprintf(filename, len, "%s/%s", CONFIGDIR, "nfdump.conf");
#else
        // hard coded default
        filename = NFCONF_FILE;
#endif
        if (TestPath(NFCONF_FILE, S_IFREG) == PATH_NOTEXISTS) {
            return 0;
        }
    }

    // path must exist
    if (!CheckPath(filename, S_IFREG)) return -1;

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        return errno;
    }
    char errbuf[256];
    toml_table_t *conf = toml_parse_file(fp, errbuf, sizeof(errbuf));
    fclose(fp);

    if (!conf) {
        printf("Failed to parse config file %s: %s\n", filename, errbuf);
        return -1;
    }

    toml_table_t *sectionConf = toml_table_table(conf, section);
    if (!sectionConf) {
        // printf("Failed to parse config file %s: No section [%s] found\n", filename, section);
        free(conf);
        return 0;
    }

    nfconfFile.valid = 1;
    nfconfFile.conf = conf;
    nfconfFile.sectionConf = sectionConf;

    // ConfInventory();
    return 1;
}  // ConfOpen

// recursive iterate fmt or csv entries from config file
// return
//     0 if end of list
//     i for entry
//    -1 for error
int ConfGetFormatEntry(char *format, char **key, char **value) {
    static toml_table_t *fmtConf = NULL;
    static int i = 0;
    if (!nfconfFile.valid) return 0;

    if (!fmtConf) {
        fmtConf = toml_table_table(nfconfFile.sectionConf, format);
        if (!fmtConf) {
            *key = NULL;
            *value = NULL;
            return -1;
        }
    }

    int keylen;
    const char *fmtName = toml_table_key(fmtConf, i, &keylen);
    if (!fmtName) {
        i = 0;
        *key = NULL;
        *value = NULL;
        fmtConf = NULL;
        i = 0;
        return 0;
    }

    toml_value_t fmtData = toml_table_string(fmtConf, fmtName);
    if (fmtData.ok) {
        dbg_printf("Config %s: %s -> %s\n", format, fmtName, fmtData.u.s);
        *value = strdup(fmtData.u.s);
    } else {
        i = 0;
        *key = NULL;
        *value = NULL;
        fmtConf = NULL;
        i = 0;
        return 0;
    }

    *key = strdup(fmtName);
    i++;
    return i;

}  // End of ConfGetFMTentry

#define RETURN_FAILED \
    *ident = NULL;    \
    *ip = NULL;       \
    *flowdir = NULL;  \
    return -1;
// recursive iterate exporter entries from config file
// return
//     0 if end of list
//     i for entry
//    -1 for error
int ConfGetExporter(char **ident, char **ip, char **flowdir) {
    static toml_table_t *exporterList = NULL;
    static int i = 0;

    if (!nfconfFile.valid) return 0;

    if (!exporterList) {
        exporterList = toml_table_table(nfconfFile.sectionConf, "exporter");
        if (!exporterList) {
            RETURN_FAILED;
        }
    }

    // get next config
    int keylen;
    const char *exporterName = toml_table_key(exporterList, i, &keylen);
    if (!exporterName) {
        i = 0;
        *ident = NULL;
        *ip = NULL;
        *flowdir = NULL;
        return 0;
    }

    // get array of exporter
    toml_array_t *exporterArray = toml_table_array(exporterList, exporterName);
    if (!exporterArray) {
        RETURN_FAILED;
    }

    toml_value_t ipData = toml_array_string(exporterArray, 0);
    if (ipData.ok) {
        *ip = strdup(ipData.u.s);
    } else {
        RETURN_FAILED;
    }

    toml_value_t flowDirData = toml_array_string(exporterArray, 1);
    if (flowDirData.ok) {
        *flowdir = strdup(flowDirData.u.s);
    } else {
        RETURN_FAILED;
    }
    *ident = strdup(exporterName);
    i++;
    return i;

}  // end of ConfGetExporter

char *ConfGetString(char *key) {
    if (!nfconfFile.valid) return NULL;

    char *k = strdup(key);
    key = k;

    toml_table_t *table = nfconfFile.sectionConf;
    char *p = strchr(key, '.');
    while (p) {
        *p = '\0';
        table = toml_table_table(table, key);
        if (!table) {
            free(k);
            return NULL;
        }
        key = p + 1;
        p = strchr(key, '.');
    }
    if (strlen(key) == 0) {
        free(k);
        return NULL;
    }

    toml_value_t Data = toml_table_string(table, key);
    free(k);
    if (Data.ok) {
        return strdup(Data.u.s);
    }
    return NULL;

}  // End of ConfGetString

int ConfGetValue(char *key) {
    if (!nfconfFile.valid) return 0;

    char *k = strdup(key);
    key = k;

    toml_table_t *table = nfconfFile.sectionConf;
    char *p = strchr(key, '.');
    while (p) {
        *p = '\0';
        table = toml_table_table(table, key);
        if (!table) {
            free(k);
            return 0;
        }
        key = p + 1;
        p = strchr(key, '.');
    }
    if (strlen(key) == 0) {
        free(k);
        return 0;
    }

    toml_value_t Data = toml_table_int(table, key);
    free(k);
    if (Data.ok) {
        return Data.u.i;
    }

    return 0;

}  // End of ConfGetValue

static void ConfPrintTableValue(toml_table_t *sectionConf, const char *tableName, const char *entry) {
    toml_value_t val;
    val = toml_table_string(sectionConf, entry);
    if (val.ok) {
        printf("%s:%-10s string : %s\n", tableName, entry, val.u.s);
    }
    val = toml_table_bool(sectionConf, entry);
    if (val.ok) {
        printf("%s:%-10s bool   : %i\n", tableName, entry, val.u.b);
    }
    val = toml_table_int(sectionConf, entry);
    if (val.ok) {
        printf("%s:%-10s int    : %" PRIi64 "\n", tableName, entry, val.u.i);
    }
    val = toml_table_double(sectionConf, entry);
    if (val.ok) {
        printf("%s:%-10s double : %f\n", tableName, entry, val.u.d);
    }
    val = toml_table_timestamp(sectionConf, entry);
    if (val.ok) {
        // printf("%10s time   : %s\n", entry, val.u.ts);
    }

}  // End of ConfTablePrintValue

static void ConfPrintArrayValue(toml_array_t *sectionConf, const char *arrayName, int entry) {
    toml_value_t val;
    val = toml_array_string(sectionConf, entry);
    if (val.ok) {
        printf("%s:[%d] string : %s\n", arrayName, entry, val.u.s);
    }
    val = toml_array_bool(sectionConf, entry);
    if (val.ok) {
        printf("%s:[%d] bool   : %i\n", arrayName, entry, val.u.b);
    }
    val = toml_array_int(sectionConf, entry);
    if (val.ok) {
        printf("%s:[%d] int    : %" PRIi64 "\n", arrayName, entry, val.u.i);
    }
    val = toml_array_double(sectionConf, entry);
    if (val.ok) {
        printf("%s:[%d] double : %f\n", arrayName, entry, val.u.d);
    }
    val = toml_array_timestamp(sectionConf, entry);
    if (val.ok) {
        // printf("%10s time   : %s\n", entry, val.u.ts);
    }

}  // End of ConfPrintArrayValue

static void ConfPrintArray(toml_array_t *sectionConf, const char *arrayName);

static void ConfPrintTable(toml_table_t *sectionConf, const char *tableName) {
    int len = toml_table_len(sectionConf);
    printf("with %d entries:\n", len);
    for (int i = 0; i < len; i++) {
        int keylen;
        const char *entry = toml_table_key(sectionConf, i, &keylen);
        if (!entry) break;

        toml_array_t *a = toml_table_array(sectionConf, entry);
        toml_table_t *t = toml_table_table(sectionConf, entry);
        if (a) {
            printf("%s:%s is an array ", tableName, entry);
            ConfPrintArray(a, entry);
        } else if (t) {
            printf("\n%s:%s is a table ", tableName, entry);
            ConfPrintTable(t, entry);
        } else {
            ConfPrintTableValue(sectionConf, tableName, entry);
        }
    }
}  // End of ConfPrintTable

static void ConfPrintArray(toml_array_t *sectionConf, const char *arrayName) {
    int len = toml_array_len(sectionConf);
    printf("with %d entries:\n", len);
    for (int i = 0; i < len; i++) {
        toml_array_t *a = toml_array_array(sectionConf, i);
        toml_table_t *t = toml_array_table(sectionConf, i);
        if (a) {
            printf("%s:[%d] is an array ", arrayName, i);
        } else if (t) {
            printf("\n%s:[%d] is a table ", arrayName, i);
            ConfPrintTable(t, "anonymous");
        } else {
            ConfPrintArrayValue(sectionConf, arrayName, i);
        }
    }
}  // End of ConfPrintArray

void ConfInventory(char *confFile) {
    if (!confFile) return;

    FILE *fp = fopen(confFile, "r");
    if (!fp) {
        printf("Failed to open config file %s: %s\n", confFile, strerror(errno));
        return;
    }

    printf("Check config file: %s\n", confFile);
    char errbuf[256];
    toml_table_t *conf = toml_parse_file(fp, errbuf, sizeof(errbuf));
    fclose(fp);

    if (!conf) {
        printf("Failed to parse config file %s: %s\n", confFile, errbuf);
        return;
    }

    int len = toml_table_len(conf);
    printf("Config file %s has %d sections\n", confFile, len);
    printf("Toplevel table ");
    ConfPrintTable(conf, "topLevel");

}  // End of ConfInventory

int SetNameserver(char *ns) {
    struct hostent *host;

    res_init();
    host = gethostbyname(ns);
    if (host == NULL) {
        (void)fprintf(stderr, "Can not resolv nameserver %s: %s\n", ns, hstrerror(h_errno));
        return 0;
    }
    (void)memcpy((void *)&_res.nsaddr_list[0].sin_addr, (void *)host->h_addr_list[0], (size_t)host->h_length);
    _res.nscount = 1;
    return 1;

}  // End of set_nameserver