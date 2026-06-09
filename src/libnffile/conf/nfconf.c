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

#include "nfconf.h"

#include <arpa/nameser.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "config.h"

#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif

#include "logging.h"
#include "toml.h"
#include "util.h"

#define NFCONF_FILE SYSCONFDIR "/nfdump.conf"

typedef struct nfconfFile_s {
    int valid;                  // flag
    toml_table_t *conf;         // handle to top toml table
    toml_table_t *sectionConf;  // handle to requested section
    toml_table_t *commonConf;   // handle to [common] section (fallback)
    option_t *defaultConf;      // program-supplied defaults (lowest priority)
} nfconfFile_t;

static nfconfFile_t nfconfFile = {0};

// CLI overrides stored as CONF_STRING; converted to the requested type on access.
#define CONF_MAX_OVERRIDES 32
static option_t confOverrides[CONF_MAX_OVERRIDES];
static int numConfOverrides = 0;

static bool confKeyExists(const char *key);
static bool confTableGetBool(toml_table_t *root, const char *key, bool *out);

/*
 * Open config file provided
 * returns:
 * -1 error
 *  0 no config file
 *  1 successfully read config
 */
int ConfOpen(char *filename, char *section, option_t *defaultConf) {
    // if read prevented
    if (filename && strcmp(filename, NOCONF) == 0) return 0;

    // try to read NFCONF environment
    if (filename == NULL) filename = getenv("NFCONF");

    // if no config file is given, check for default
    // silently return if not found
    if (filename == NULL) {
        // NFCONF_FILE expands to SYSCONFDIR "/nfdump.conf" at compile time
        filename = NFCONF_FILE;
        if (TestPath(filename, S_IFREG) == PATH_NOTEXISTS) {
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
    toml_table_t *commonConf = toml_table_table(conf, "common");
    if (!sectionConf && !commonConf) {
        // Neither the requested section nor [common] was found
        free(conf);
        return 0;
    }

    nfconfFile.valid = 1;
    nfconfFile.conf = conf;
    nfconfFile.sectionConf = sectionConf;  // may be NULL when only [common] exists
    nfconfFile.commonConf = commonConf;
    nfconfFile.defaultConf = defaultConf;  // may be NULL

    // Verify override table — warn for keys absent from both file and defaults
    for (int i = 0; i < numConfOverrides; i++) {
        if (!confKeyExists(confOverrides[i].key)) LogInfo("Config override: unknown key '%s' - using it anyway", confOverrides[i].key);
    }

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

// Walk a dot-separated key path inside a TOML table and return the leaf string value.
// Returns true and sets *out (caller must free) on success; false on any miss.
static bool confTableGetString(toml_table_t *root, const char *key, char **out) {
    if (!root) return false;
    char *k = strdup(key);
    char *cur = k;
    toml_table_t *table = root;
    char *p = strchr(cur, '.');
    while (p) {
        *p = '\0';
        table = toml_table_table(table, cur);
        if (!table) {
            free(k);
            return false;
        }
        cur = p + 1;
        p = strchr(cur, '.');
    }
    if (*cur == '\0') {
        free(k);
        return false;
    }
    toml_value_t v = toml_table_string(table, cur);
    free(k);
    if (v.ok) {
        *out = strdup(v.u.s);
        return true;
    }
    return false;
}  // End of confTableGetString

// Walk a dot-separated key path inside a TOML table and return the leaf int64 value.
// Returns true and sets *out on success; false on any miss.
static bool confTableGetInt64(toml_table_t *root, const char *key, int64_t *out) {
    if (!root) return false;
    char *k = strdup(key);
    char *cur = k;
    toml_table_t *table = root;
    char *p = strchr(cur, '.');
    while (p) {
        *p = '\0';
        table = toml_table_table(table, cur);
        if (!table) {
            free(k);
            return false;
        }
        cur = p + 1;
        p = strchr(cur, '.');
    }
    if (*cur == '\0') {
        free(k);
        return false;
    }
    toml_value_t v = toml_table_int(table, cur);
    free(k);
    if (v.ok) {
        *out = v.u.i;
        return true;
    }
    return false;
}  // End of confTableGetInt64

// Check if a key exists in the config file or in the program defaults.
// Used to decide whether to warn about an unknown -x override.
static bool confKeyExists(const char *key) {
    // check program defaults (always available, even without a config file)
    if (nfconfFile.defaultConf) {
        for (int i = 0; nfconfFile.defaultConf[i].key != NULL; i++)
            if (strcmp(nfconfFile.defaultConf[i].key, key) == 0) return true;
    }
    if (!nfconfFile.valid) return false;
    char *s;
    if (confTableGetString(nfconfFile.sectionConf, key, &s)) {
        free(s);
        return true;
    }
    if (confTableGetString(nfconfFile.commonConf, key, &s)) {
        free(s);
        return true;
    }
    int64_t i;
    if (confTableGetInt64(nfconfFile.sectionConf, key, &i)) return true;
    if (confTableGetInt64(nfconfFile.commonConf, key, &i)) return true;
    bool b;
    if (confTableGetBool(nfconfFile.sectionConf, key, &b)) return true;
    if (confTableGetBool(nfconfFile.commonConf, key, &b)) return true;
    return false;
}  // End of confKeyExists

int ConfSetOverride(const char *confString) {
    char *dup = strdup(confString);
    char *eq = strchr(dup, '=');
    if (!eq) {
        LogError("Invalid config override '%s': expected key=value", confString);
        free(dup);
        return 0;
    }
    *eq = '\0';
    char *key = dup;
    char *value = eq + 1;

    // update if the key is already in the override table
    for (int i = 0; i < numConfOverrides; i++) {
        if (strcmp(confOverrides[i].key, key) == 0) {
            free(confOverrides[i].valString);
            confOverrides[i].valString = strdup(value);
            free(dup);
            return 1;
        }
    }

    if (numConfOverrides >= CONF_MAX_OVERRIDES) {
        LogError("Config override table full - cannot add key '%s'", key);
        free(dup);
        return 0;
    }
    confOverrides[numConfOverrides].key = strdup(key);
    confOverrides[numConfOverrides].type = CONF_STRING;
    confOverrides[numConfOverrides].valString = strdup(value);
    numConfOverrides++;
    free(dup);
    return 1;
}  // End of ConfSetOverride

// Scan the defaultConf array for key; return the entry or NULL.
static const option_t *confDefaultFind(const char *key) {
    if (!nfconfFile.defaultConf) return NULL;
    for (int i = 0; nfconfFile.defaultConf[i].key != NULL; i++)
        if (strcmp(nfconfFile.defaultConf[i].key, key) == 0) return &nfconfFile.defaultConf[i];
    return NULL;
}  // End of confDefaultFind

// Walk a dot-separated key path inside a TOML table and return the leaf bool.
// Accepts both TOML bool (true/false) and TOML int (0/1).
static bool confTableGetBool(toml_table_t *root, const char *key, bool *out) {
    if (!root) return false;
    char *k = strdup(key);
    char *cur = k;
    toml_table_t *table = root;
    char *p = strchr(cur, '.');
    while (p) {
        *p = '\0';
        table = toml_table_table(table, cur);
        if (!table) {
            free(k);
            return false;
        }
        cur = p + 1;
        p = strchr(cur, '.');
    }
    if (*cur == '\0') {
        free(k);
        return false;
    }
    toml_value_t v = toml_table_bool(table, cur);
    if (v.ok) {
        free(k);
        *out = v.u.b;
        return true;
    }
    v = toml_table_int(table, cur);
    free(k);
    if (v.ok) {
        *out = v.u.i != 0;
        return true;
    }
    return false;
}  // End of confTableGetBool

char *ConfGetString(char *key) {
    // 1. CLI override
    for (int i = 0; i < numConfOverrides; i++)
        if (strcmp(confOverrides[i].key, key) == 0) return strdup(confOverrides[i].valString);
    // 2. config file
    if (nfconfFile.valid) {
        char *val;
        if (confTableGetString(nfconfFile.sectionConf, key, &val)) return val;
        if (confTableGetString(nfconfFile.commonConf, key, &val)) return val;
    }
    // 3. program defaults
    const option_t *d = confDefaultFind(key);
    if (d && d->type == CONF_STRING) return strdup(d->valString);
    return NULL;
}  // End of ConfGetString

int64_t ConfGetValue(char *key) {
    // 1. CLI override
    for (int i = 0; i < numConfOverrides; i++)
        if (strcmp(confOverrides[i].key, key) == 0) return (int64_t)strtoll(confOverrides[i].valString, NULL, 0);
    // 2. config file
    if (nfconfFile.valid) {
        int64_t val;
        if (confTableGetInt64(nfconfFile.sectionConf, key, &val)) return val;
        if (confTableGetInt64(nfconfFile.commonConf, key, &val)) return val;
    }
    // 3. program defaults
    const option_t *d = confDefaultFind(key);
    if (d) {
        switch (d->type) {
            case CONF_INT64:
                return d->valInt64;
            case CONF_UINT64:
                return (int64_t)d->valUint64;
            case CONF_BOOL:
                return d->valBool ? 1 : 0;
            case CONF_STRING:
                return (int64_t)strtoll(d->valString, NULL, 0);
        }
    }
    return 0;
}  // End of ConfGetValue

bool ConfGetBool(char *key) {
    // 1. CLI override
    for (int i = 0; i < numConfOverrides; i++)
        if (strcmp(confOverrides[i].key, key) == 0) return strtoll(confOverrides[i].valString, NULL, 0) != 0;

    // 2. config file
    if (nfconfFile.valid) {
        bool val;
        if (confTableGetBool(nfconfFile.sectionConf, key, &val)) return val;
        if (confTableGetBool(nfconfFile.commonConf, key, &val)) return val;
    }
    // 3. program defaults
    const option_t *d = confDefaultFind(key);
    if (d) {
        switch (d->type) {
            case CONF_BOOL:
                return d->valBool;
            case CONF_INT64:
                return d->valInt64 != 0;
            case CONF_UINT64:
                return d->valUint64 != 0;
            case CONF_STRING:
                return d->valString && strcmp(d->valString, "0") != 0;
        }
    }
    return false;
}  // End of ConfGetBool

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
