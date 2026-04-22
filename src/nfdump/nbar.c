/*
 *  Copyright (c) 2020-2025, Peter Haag
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

/* implements Next Generation Network-Based Application Recognition (NBAR2)
 * see also https://www.cisco.com/c/en/us/td/docs/routers/access/ISRG2/AVC/api/guide/AVC_Metric_Definition_Guide/5_AVC_Metric_Def.html
 */

#include "nbar.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "khash.h"
#include "logging.h"
#include "util.h"

typedef struct AppInfoHash_s {
    uint16_t app_id_length;
    uint16_t app_name_length;
    uint16_t app_desc_length;
    uint8_t *data;
} AppInfoHash_t;

// List compare
static kh_inline khint_t __HashEqual(AppInfoHash_t h1, AppInfoHash_t h2) {
    if (h1.app_id_length == h2.app_id_length) {
        return memcmp(h1.data, h2.data, h1.app_id_length) == 0;
    } else {
        return (h1.app_id_length < h2.app_id_length ? -1 : 1);
    }
}  // End of __HashEqual

static kh_inline khint_t __HashFunc(const AppInfoHash_t record) {
    if (record.app_id_length == 4) {
        return *((khint_t *)(record.data));
    } else if (record.app_id_length == 0) {
        return 0;
    } else {
        uint8_t *s = record.data;
        khint_t h = 0;
        for (int i = 0; i < record.app_id_length; i++, s++) h = (h << 5) - h + (khint_t)*s;
        return h;
    }
}  // End of __HashFunc

// insert FlowHash definitions/code
KHASH_INIT(NbarAppInfoHash, AppInfoHash_t, char, 0, __HashFunc, __HashEqual)
static khash_t(NbarAppInfoHash) *NbarAppInfoHash = NULL;

static void InsertNbarAppInfo(uint8_t *nbarData) {
    uint32_t idLen = nbarData[0];
    uint32_t nameLen = nbarData[1];
    uint32_t descLen = nbarData[2];
    nbarData += 3;

    size_t dataSize = idLen + nameLen + descLen;
    if (dataSize == 0 || dataSize > 4096) {
        LogError("InsertNbarAppInfo(): in %s line %d: data size error %zu", __FILE__, __LINE__, dataSize);
        return;
    }

    // Allocate and copy data BEFORE hash lookup to avoid use-after-free
    uint8_t *data = malloc(dataSize);
    if (!data) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return;
    }
    memcpy(data, nbarData, dataSize);

#ifdef DEVEL
    printf("NBAR: id - len: %u 0x", idLen);
    for (int i = 0; i < (int)idLen; i++) printf("%x ", nbarData[i]);
    if (nameLen)
        printf(" name - len: %u '%s'", nameLen, (char *)(nbarData + idLen));
    else
        printf(" name - len: 0 NULL");
    if (descLen)
        printf(" desc - len: %u '%s'\n", descLen, (char *)(nbarData + idLen + nameLen));
    else
        printf(" desc - len: 0 NULL\n");
#endif

    AppInfoHash_t AppInfoHash = {
        .app_id_length = idLen,
        .app_name_length = nameLen,
        .app_desc_length = descLen,
        .data = data,  // Use newly allocated copy for hash lookup
    };

    int ret;
    khiter_t k;
    k = kh_put(NbarAppInfoHash, NbarAppInfoHash, AppInfoHash, &ret);
    if (ret == 0) {  // existing entry
        dbg_printf("KHASH existing entry: %u %d\n", k, ret);
        // Save old pointer, update key, then free old data
        uint8_t *oldData = kh_key(NbarAppInfoHash, k).data;
        kh_key(NbarAppInfoHash, k) = AppInfoHash;
        free(oldData);
    } else {
        dbg_printf("KHASH new entry: %u\n", k);
        // kh_put already set the key for new entries
    }

}  // end of InsertNbarAppInfo

int AddNbarRecords(arrayBlockV3_t *arrayBlock) {
    if (NbarAppInfoHash == NULL) {
        NbarAppInfoHash = kh_init(NbarAppInfoHash);
        if (!NbarAppInfoHash) {
            LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return 0;
        }
    }

    uint8_t *nbarData = ResetCursor(arrayBlock);
    for (int i = 0; i < (int)arrayBlock->numElements; i++) {
        InsertNbarAppInfo(nbarData);
        nbarData += arrayBlock->elementSize;
    }

    return 0;

    return 1;
}  // End of AddNbarRecord

char *GetNbarInfo(uint8_t *id, size_t size, char *name) {
    AppInfoHash_t AppInfoHash = {0};
    AppInfoHash.app_id_length = size;
    AppInfoHash.data = id;

    if (NbarAppInfoHash == NULL) {
        return NULL;
    }

    khiter_t k;
    k = kh_get(NbarAppInfoHash, NbarAppInfoHash, AppInfoHash);
    if (k == kh_end(NbarAppInfoHash)) {
        // not found
        return NULL;
    }

    name[0] = '\0';
    if ((kh_key(NbarAppInfoHash, k).app_name_length + kh_key(NbarAppInfoHash, k).app_desc_length) > 253) {
        LogError("Error nbar lookup in %s line %d: string length error", __FILE__, __LINE__);
        return NULL;
    }
    if (kh_key(NbarAppInfoHash, k).app_name_length) {
        snprintf(name, 255, "%s", kh_key(NbarAppInfoHash, k).data + kh_key(NbarAppInfoHash, k).app_id_length);
    }
    if (kh_key(NbarAppInfoHash, k).app_desc_length) {
        snprintf(name + strlen(name), 255 - strlen(name), "/%s",
                 kh_key(NbarAppInfoHash, k).data + kh_key(NbarAppInfoHash, k).app_id_length + kh_key(NbarAppInfoHash, k).app_name_length);
    }
    name[254] = '\0';
    return name;

}  // End of GetNbarInfo

void DumpNbarList(void) {
    if (NbarAppInfoHash == NULL) return;

    size_t hashSize = kh_size(NbarAppInfoHash);
    printf("\n==DUMP==\nnbar applist info length: %zu\n", hashSize);
    for (khiter_t k = kh_begin(NbarAppInfoHash); k != kh_end(NbarAppInfoHash); ++k) {  // traverse
        if (kh_exist(NbarAppInfoHash, k)) {
            AppInfoHash_t *r = &kh_key(NbarAppInfoHash, k);
            uint8_t *p = r->data;
            printf("id   length: %xu\n", r->app_id_length);
            printf("name length: %u\n", r->app_name_length);
            printf("desc length: %u\n", r->app_desc_length);
            printf("ID: ");
            if (r->app_id_length) {
                for (int i = 0; i < r->app_id_length; i++) printf("%02X ", *((uint8_t *)p++));
            } else {
                printf("<zero length ID ");
            }
            printf(" ");

            if (r->app_name_length)
                printf("Name: %s ", p);
            else
                printf("<zero length name> ");

            p += r->app_name_length;
            if (r->app_desc_length)
                printf("Desc: %s\n", p);
            else
                printf("<zero length description>\n");
        }
    }

}  // End of DumpNbarList

/*
void PrintNbarRecord(arrayRecordHeader_t *nbarRecord) {
    dbg_printf("Nbar record: %u elements\n", nbarRecord->numElements);
    dbg_printf("Nbar Element size: %u\n", nbarRecord->elementSize);
    if (nbarRecord->elementSize == 0) {
        dbg_printf("Old nbar record");
        return;
    }

    NbarAppInfo_t *NbarAppInfo = (NbarAppInfo_t *)((void *)nbarRecord + sizeof(arrayRecordHeader_t));
    printf("id   length: %u\n", NbarAppInfo->app_id_length);
    printf("name length: %u\n", NbarAppInfo->app_name_length);
    printf("desc length: %u\n", NbarAppInfo->app_desc_length);
    uint8_t *nbarData = (uint8_t *)((void *)NbarAppInfo + sizeof(NbarAppInfo_t));
    for (int i = 0; i < nbarRecord->numElements; i++) {
        uint8_t *p = nbarData + i * nbarRecord->elementSize;
        printf("ID: ");
        for (int i = 0; i < NbarAppInfo->app_id_length; i++) printf("%02X ", *((uint8_t *)p++));
        printf("\n");

        printf("Name: %s\n", NbarAppInfo->app_name_length ? (char *)p : "<zero length>");
        p += NbarAppInfo->app_name_length;
        printf("Desc: %s\n\n", NbarAppInfo->app_desc_length ? (char *)p : "<zero length>");
    }

}  // End of PrintNbarRecord
*/
