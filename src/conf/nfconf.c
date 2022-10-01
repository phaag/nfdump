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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "toml.h"
#include "util.h"

static void tableInfo(int spaces, toml_table_t *table);

__attribute__((unused)) static void tableInfo(int spaces, toml_table_t *table) {
    const char *key = toml_table_key(table);
    int kvPairs = toml_table_nkval(table);
    int numArrays = toml_table_narr(table);
    int subTables = toml_table_ntab(table);
    printf("%*s key: %s, kv pairs: %d, arrays: %d, subTables: %d\n", spaces, "", key ? key : "<null>", kvPairs, numArrays, subTables);
}

#define NFCONF_FILE "/usr/local/etc/nfdump.conf"

typedef struct nfconfFile_s {
    int valid;                  // flag
    toml_table_t *conf;         // handle to top toml table
    toml_table_t *sectionConf;  // handle to nfdump section
} nfconfFile_t;

static nfconfFile_t nfconfFile = {0};

static void ConfInventory(void);

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
        if (TestPath(NFCONF_FILE, S_IFREG) == PATH_NOTEXIST) {
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

    toml_table_t *sectionConf = toml_table_in(conf, section);
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

// recursive iterate fmt entries from config file
// return
//     0 if end of list
//     i for entry
//    -1 for error
int ConfGetFMTentry(char **key, char **value) {
    static toml_table_t *fmtConf = NULL;
    static int i = 0;

    if (!nfconfFile.valid) return 0;

    if (!fmtConf) {
        fmtConf = toml_table_in(nfconfFile.sectionConf, "fmt");
        if (!fmtConf) {
            *key = NULL;
            *value = NULL;
            return -1;
        }
    }

    const char *fmtName = toml_key_in(fmtConf, i);
    if (!fmtName) {
        i = 0;
        *key = NULL;
        *value = NULL;
        return 0;
    }
    toml_datum_t fmtData = toml_string_in(fmtConf, fmtName);
    if (fmtData.ok) {
        dbg_printf("fmt: %s -> %s\n", fmtName, fmtData.u.s);
        *value = strdup(fmtData.u.s);
    } else {
        i = 0;
        *key = NULL;
        *value = NULL;
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
        exporterList = toml_table_in(nfconfFile.sectionConf, "exporter");
        if (!exporterList) {
            RETURN_FAILED;
        }
    }

    // get next config
    const char *exporterName = toml_key_in(exporterList, i);
    if (!exporterName) {
        i = 0;
        *ident = NULL;
        *ip = NULL;
        *flowdir = NULL;
        return 0;
    }

    // get array of exporter
    toml_array_t *exporterArray = toml_array_in(exporterList, exporterName);
    if (!exporterArray) {
        RETURN_FAILED;
    }

    toml_datum_t ipData = toml_string_at(exporterArray, 0);
    if (ipData.ok) {
        *ip = strdup(ipData.u.s);
    } else {
        RETURN_FAILED;
    }

    toml_datum_t flowDirData = toml_string_at(exporterArray, 1);
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
        table = toml_table_in(table, key);
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

    toml_datum_t Data = toml_string_in(table, key);
    free(k);
    if (Data.ok) {
        return strdup(Data.u.s);
    } else
        return NULL;

    // unreached
}  // End of ConfGetString

__attribute__((unused)) void ConfInventory(void) {
    if (!nfconfFile.conf) return;

    toml_table_t *conf = nfconfFile.conf;
    printf("Config file top level:\n");
    tableInfo(0, conf);

    for (int i = 0;; i++) {
        const char *sectionName = toml_key_in(conf, i);
        if (!sectionName) break;
        printf("  Section %d: %s\n", i, sectionName);
        toml_table_t *sectionConf = toml_table_in(conf, sectionName);
        if (!sectionConf) {
            printf("no SectionConf for %s\n", sectionName);
            return;
        }
        tableInfo(2, sectionConf);

        for (int j = 0;; j++) {
            const char *entry = toml_key_in(sectionConf, j);
            if (!entry) break;
            printf("    entry %d: %s\n", i, entry);
            toml_table_t *groupConf = toml_table_in(sectionConf, entry);
            if (!groupConf) {
                printf("no groupConf for %s\n", entry);
                return;
            }
            tableInfo(4, groupConf);

            for (int k = 0;; k++) {
                const char *key = toml_key_in(groupConf, k);
                if (!key) break;
                printf("      key %d: %s\n", i, key);
            }
        }
    }
}  // End of ConfInventory