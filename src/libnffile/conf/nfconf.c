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
#include <ctype.h>
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
#include <strings.h>
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

typedef struct confTag_s {
    const char *key;
    confType_t type;
} confTag_t;

static const confTag_t *confFindTag(const char *key);
static const char *confTypeName(confType_t type);
static bool confValueIsValid(const char *value, confType_t type);
static bool confValidateConfTable(toml_table_t *table, const char *pathPrefix);
static bool confTableGetBool(toml_table_t *root, const char *key, bool *out);

static bool confOverrideGetBool(const char *value) {
    if (strcasecmp(value, "true") == 0) return true;
    if (strcasecmp(value, "false") == 0) return false;
    return strtoll(value, NULL, 0) != 0;
}  // End of confOverrideGetBool

static bool ConfValidateOverrides(void) {
    bool allValid = true;
    for (int i = 0; i < numConfOverrides; i++) {
        const confTag_t *tag = confFindTag(confOverrides[i].key);
        if (!tag) {
            LogError("Invalid config override: unknown key '%s'", confOverrides[i].key);
            allValid = false;
        } else if (!confValueIsValid(confOverrides[i].valString, tag->type)) {
            LogError("Invalid config override: key '%s' requires %s value", confOverrides[i].key, confTypeName(tag->type));
            allValid = false;
        }
    }
    return allValid;
}  // End of ConfValidateOverrides

/*
 * Open config file provided
 * returns:
 * -1 error - includes an unknown/invalid -x override
 *  0 no config file
 *  1 successfully read config
 */
int ConfOpen(char *filename, char *section, option_t *defaultConf) {
    // Program defaults remain available even when configuration-file loading
    // is disabled or no file exists.
    nfconfFile.defaultConf = defaultConf;
    if (!ConfValidateOverrides()) return -1;

    // if read prevented
    if (filename && strcmp(filename, NOCONF) == 0) return 0;

    // try to read NFCONF environment
    if (filename == NULL) filename = getenv("NFCONF");

    // if no config file is given, check for default
    // silently continue without a file if not found
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
        toml_free(conf);
        return 0;
    }
    if (!confValidateConfTable(sectionConf, NULL) || !confValidateConfTable(commonConf, NULL)) {
        toml_free(conf);
        return -1;
    }

    nfconfFile.valid = 1;
    nfconfFile.conf = conf;
    nfconfFile.sectionConf = sectionConf;
    nfconfFile.commonConf = commonConf;
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

// Flat list of scalar configuration keys accepted by -x and checked in the
// active TOML section. Section applicability remains the application's job.
static const confTag_t confTags[] = {
    {"threads.readers", CONF_UINT64},
    {"threads.writers", CONF_UINT64},
    {"threads.workers", CONF_UINT64},
    {"limitCores", CONF_UINT64},
    {"maxworkers", CONF_UINT64},
    {"xxhash", CONF_BOOL},
    {"crypt.salt", CONF_STRING},
    {"crypt.rekeyIntervalSecs", CONF_UINT64},
    {"crypt.antiReplayWindowBits", CONF_UINT64},
    {"udp.sendThreshold", CONF_UINT64},
    {"geodb.path", CONF_STRING},
    {"geodb.flatpath", CONF_STRING},
    {"tordb.path", CONF_STRING},
    {"tordb.flatpath", CONF_STRING},
    {"dyn_max_sources", CONF_UINT64},
    {"opt.tun", CONF_BOOL},
    {"opt.fat", CONF_BOOL},
    {"opt.payload", CONF_BOOL},
    {"flowcache.expireinterval", CONF_UINT64},
    {"flowcache.max_nodes", CONF_UINT64},
    {"flowcache.max_payload_bytes", CONF_UINT64},
    {"flowcache.max_output_nodes", CONF_UINT64},
    {"buffSize", CONF_UINT64},
    {NULL, CONF_BOOL},
};

static const confTag_t *confFindTag(const char *key) {
    for (const confTag_t *tag = confTags; tag->key != NULL; tag++)
        if (strcmp(tag->key, key) == 0) return tag;
    return NULL;
}  // End of confFindTag

static const char *confTypeName(confType_t type) {
    switch (type) {
        case CONF_BOOL:
            return "a boolean (true, false, 0, or 1)";
        case CONF_STRING:
            return "a string";
        case CONF_INT64:
        case CONF_UINT64:
            return "an integer";
    }
    return "a valid value";
}  // End of confTypeName

static bool confValueIsValid(const char *value, confType_t type) {
    if (type == CONF_STRING) return true;
    if (!value || !*value || isspace((unsigned char)value[0])) return false;
    if (type == CONF_BOOL)
        return strcasecmp(value, "true") == 0 || strcasecmp(value, "false") == 0 || strcmp(value, "0") == 0 || strcmp(value, "1") == 0;

    char *end;
    errno = 0;
    if (type == CONF_UINT64) {
        if (value[0] == '-') return false;
        (void)strtoull(value, &end, 0);
    } else {
        (void)strtoll(value, &end, 0);
    }
    return errno == 0 && *end == '\0';
}  // End of confValueIsValid

static bool confValidateScalar(toml_table_t *table, const char *entry, const char *path, confType_t type) {
    bool valid = false;
    toml_value_t value = {0};
    switch (type) {
        case CONF_BOOL:
            value = toml_table_bool(table, entry);
            if (value.ok) {
                valid = true;
            } else {
                value = toml_table_int(table, entry);
                valid = value.ok && (value.u.i == 0 || value.u.i == 1);
            }
            break;
        case CONF_INT64:
            valid = toml_table_int(table, entry).ok;
            break;
        case CONF_UINT64:
            value = toml_table_int(table, entry);
            valid = value.ok && value.u.i >= 0;
            break;
        case CONF_STRING:
            value = toml_table_string(table, entry);
            valid = value.ok;
            if (value.ok) free(value.u.s);
            break;
    }
    if (!valid) LogError("Invalid config file entry '%s': requires %s value", path, confTypeName(type));
    return valid;
}  // End of confValidateScalar

static bool confIsDynamicTable(const char *entry) {
    return strcmp(entry, "fmt") == 0 || strcmp(entry, "csv") == 0 || strcmp(entry, "exporter") == 0;
}  // End of confIsDynamicTable

static bool confValidateConfTable(toml_table_t *table, const char *pathPrefix) {
    if (!table) return true;

    bool allValid = true;
    for (int i = 0; i < toml_table_len(table); i++) {
        int keylen;
        const char *entry = toml_table_key(table, i, &keylen);
        if (!entry) break;

        char path[256];
        int written = pathPrefix ? snprintf(path, sizeof(path), "%s.%s", pathPrefix, entry) : snprintf(path, sizeof(path), "%s", entry);
        if (written < 0 || (size_t)written >= sizeof(path)) {
            LogError("Invalid config file entry: key path is too long");
            allValid = false;
            continue;
        }

        toml_table_t *subTable = toml_table_table(table, entry);
        if (subTable) {
            if (!confIsDynamicTable(entry) && !confValidateConfTable(subTable, path)) allValid = false;
            continue;
        }
        if (toml_table_array(table, entry)) continue;

        const confTag_t *tag = confFindTag(path);
        if (!tag) {
            LogError("Invalid config file entry: unknown key '%s'", path);
            allValid = false;
        } else if (!confValidateScalar(table, entry, path, tag->type)) {
            allValid = false;
        }
    }
    return allValid;
}  // End of confValidateConfTable

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

char *ConfGetString(const char *key) {
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

int64_t ConfGetValue(const char *key) {
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

bool ConfGetBool(const char *key) {
    // 1. CLI override
    for (int i = 0; i < numConfOverrides; i++)
        if (strcmp(confOverrides[i].key, key) == 0) return confOverrideGetBool(confOverrides[i].valString);

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
    // Check types in specificity order: bool, int, double, string.
    // Use else-if so that integers are not also printed as doubles.
    val = toml_table_bool(sectionConf, entry);
    if (val.ok) {
        printf("%s:%-10s bool   : %s\n", tableName, entry, val.u.b ? "true" : "false");
    } else {
        val = toml_table_int(sectionConf, entry);
        if (val.ok) {
            printf("%s:%-10s int    : %" PRIi64 "\n", tableName, entry, val.u.i);
        } else {
            val = toml_table_double(sectionConf, entry);
            if (val.ok) {
                printf("%s:%-10s double : %f\n", tableName, entry, val.u.d);
            } else {
                val = toml_table_string(sectionConf, entry);
                if (val.ok) {
                    printf("%s:%-10s string : %s\n", tableName, entry, val.u.s);
                }
            }
        }
    }
}  // End of ConfPrintTableValue

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

void ConfInventory(const char *confFile) {
    // --- 1. Program defaults (lowest priority) ---
    printf("=== Program defaults ===\n");
    if (nfconfFile.defaultConf && nfconfFile.defaultConf[0].key != NULL) {
        for (int i = 0; nfconfFile.defaultConf[i].key != NULL; i++) {
            const option_t *o = &nfconfFile.defaultConf[i];
            switch (o->type) {
                case CONF_BOOL:
                    printf("  %-28s bool   : %s\n", o->key, o->valBool ? "true" : "false");
                    break;
                case CONF_INT64:
                    printf("  %-28s int    : %" PRIi64 "\n", o->key, o->valInt64);
                    break;
                case CONF_UINT64:
                    printf("  %-28s uint   : %" PRIu64 "\n", o->key, o->valUint64);
                    break;
                case CONF_STRING:
                    printf("  %-28s string : \"%s\"\n", o->key, o->valString ? o->valString : "");
                    break;
            }
        }
    } else {
        printf("  (none defined)\n");
    }

    // --- 2. Config file ---
    printf("\n=== Config file ===\n");
    if (confFile) {
        FILE *fp = fopen(confFile, "r");
        if (!fp) {
            printf("  Failed to open %s: %s\n", confFile, strerror(errno));
        } else {
            printf("  File: %s\n", confFile);
            char errbuf[256];
            toml_table_t *conf = toml_parse_file(fp, errbuf, sizeof(errbuf));
            fclose(fp);
            if (!conf) {
                printf("  Parse error: %s\n", errbuf);
            } else {
                printf("  Sections: ");
                ConfPrintTable(conf, "config");
            }
        }
    } else {
        printf("  (none specified)\n");
    }

    // --- 3. CLI overrides (highest priority) ---
    printf("\n=== CLI overrides (-x) ===\n");
    if (numConfOverrides > 0) {
        for (int i = 0; i < numConfOverrides; i++) printf("  %-28s = \"%s\"\n", confOverrides[i].key, confOverrides[i].valString);
    } else {
        printf("  (none)\n");
    }
    printf("\n");

}  // End of ConfInventory

static int OptSetBool(option_t *optionList, char *name, bool valBool) {
    int i = 0;
    char optName[64] = "opt.";
    strncat(optName, name, 59);
    while (optionList[i].key != NULL) {
        if (strcmp(optionList[i].key, optName) == 0) {
            optionList[i].valBool = valBool;
            return 1;
        }
        i++;
    }
    return 0;
}  // End of OptSetBool

int scanOptions(option_t *optionList, char *options) {
    if (options == NULL) return 1;

    char *option = strtok(options, ",");
    while (option != NULL) {
        int valBool = 1;
        char *eq = strchr(option, '=');
        if (eq) {
            *eq++ = '\0';
            switch (eq[0]) {
                case '0':
                    valBool = 0;
                    break;
                case '1':
                    valBool = 1;
                    break;
                default:
                    LogError("Invalid bool value: %s", eq[0] ? eq : "empty value");
            }
        }
        if (OptSetBool(optionList, option, valBool) == 0) {
            LogError("Unknown option: %s", option);
            return 0;
        }
        option = strtok(NULL, ",");
    }
    return 1;

}  // End of scanOption
