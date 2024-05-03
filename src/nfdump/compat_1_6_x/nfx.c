/*
 *  Copyright (c) 2009-2024, Peter Haag
 *  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
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

#include "nfx.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "nfdump.h"
#include "nffile.h"
#include "util.h"

/* global vars */

/*
 * see nffile.h for detailed extension description
 */
static extension_descriptor_t const extension_descriptor[] = {
    // fill indices 0 - 3
    {COMMON_BLOCK_ID, 0, 0, 1, "Required extension: Common record"},
    {EX_IPv4v6, 0, 0, 1, "Required extension: IPv4/IPv6 src/dst address"},
    {EX_PACKET_4_8, 0, 0, 1, "Required extension: 4/8 byte input packets"},
    {EX_BYTE_4_8, 0, 0, 1, "Required extension: 4/8 byte input bytes"},

    // the optional extension
    {EX_IO_SNMP_2, 4, 1, 1, "2 byte input/output interface index"},
    {EX_IO_SNMP_4, 8, 1, 1, "4 byte input/output interface index"},
    {EX_AS_2, 4, 2, 1, "2 byte src/dst AS number"},
    {EX_AS_4, 8, 2, 1, "4 byte src/dst AS number"},
    {EX_MULIPLE, 4, 3, 0, "dst tos, direction, src/dst mask"},
    {EX_NEXT_HOP_v4, 4, 4, 0, "IPv4 next hop"},
    {EX_NEXT_HOP_v6, 16, 4, 0, "IPv6 next hop"},
    {EX_NEXT_HOP_BGP_v4, 4, 5, 0, "IPv4 BGP next IP"},
    {EX_NEXT_HOP_BGP_v6, 16, 5, 0, "IPv6 BGP next IP"},
    {EX_VLAN, 4, 6, 0, "src/dst vlan id"},
    {EX_OUT_PKG_4, 4, 7, 0, "4 byte output packets"},
    {EX_OUT_PKG_8, 8, 7, 0, "8 byte output packets"},
    {EX_OUT_BYTES_4, 4, 8, 0, "4 byte output bytes"},
    {EX_OUT_BYTES_8, 8, 8, 0, "8 byte output bytes"},
    {EX_AGGR_FLOWS_4, 4, 9, 0, "4 byte aggregated flows"},
    {EX_AGGR_FLOWS_8, 8, 9, 0, "8 byte aggregated flows"},
    {EX_MAC_1, 16, 10, 0, "in src/out dst mac address"},
    {EX_MAC_2, 16, 11, 0, "in dst/out src mac address"},
    {EX_MPLS, 40, 12, 0, "MPLS Labels"},
    {EX_ROUTER_IP_v4, 4, 13, 0, "IPv4 router IP addr"},
    {EX_ROUTER_IP_v6, 16, 13, 0, "IPv6 router IP addr"},
    {EX_ROUTER_ID, 4, 14, 0, "router ID"},

    {EX_BGPADJ, 8, 15, 0, "BGP adjacent prev/next AS"},
    {EX_RECEIVED, 8, 16, 0, "time packet received"},

    // reserved for more v9/IPFIX
    {EX_RESERVED_1, 0, 0, 0, NULL},
    {EX_RESERVED_2, 0, 0, 0, NULL},
    {EX_RESERVED_3, 0, 0, 0, NULL},
    {EX_RESERVED_4, 0, 0, 0, NULL},
    {EX_RESERVED_5, 0, 0, 0, NULL},
    {EX_RESERVED_6, 0, 0, 0, NULL},
    {EX_RESERVED_7, 0, 0, 0, NULL},
    {EX_RESERVED_8, 0, 0, 0, NULL},
    {EX_RESERVED_9, 0, 0, 0, NULL},

    // ASA - Network Security Event Logging NSEL extensions
    {EX_NSEL_COMMON, 20, 26, 0, "NSEL Common block"},
    {EX_NSEL_XLATE_PORTS, 4, 27, 0, "NSEL xlate ports"},
    {EX_NSEL_XLATE_IP_v4, 8, 28, 0, "NSEL xlate IPv4 addr"},
    {EX_NSEL_XLATE_IP_v6, 32, 28, 0, "NSEL xlate IPv6 addr"},
    {EX_NSEL_ACL, 24, 29, 0, "NSEL ACL ingress/egress acl ID"},
    {EX_NSEL_USER, 24, 30, 0, "NSEL username"},
    {EX_NSEL_USER_MAX, 72, 30, 0, "NSEL max username"},

    {EX_NSEL_RESERVED, 0, 0, 0, NULL},

    // latency extension for nfpcapd and nprobe
    {EX_LATENCY, 24, 64, 0, "nprobe/nfpcapd latency"},

    // NAT - Network Event Logging
    {EX_NEL_COMMON, 12, 31, 0, "NEL Common block"},
    {EX_NEL_GLOBAL_IP_v4, 0, 0, 0, "Compat NEL IPv4"},
    {EX_PORT_BLOCK_ALLOC, 8, 32, 0, "NAT Port Block Allocation"},
    {EX_NEL_RESERVED_1, 0, 0, 0, NULL},

    // last entry
    {0, 0, 0, 0, NULL}};

uint32_t Max_num_extensions;

static int VerifyExtensionMap(extension_map_t *map);

extension_map_list_t *InitExtensionMaps(int AllocateList) {
    extension_map_list_t *list = NULL;
    int i;

    if (AllocateList) {
        list = (extension_map_list_t *)calloc(1, sizeof(extension_map_list_t));
        if (!list) {
            LogError("calloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
            exit(255);
        }
        list->last_map = &list->map_list;
    }

    Max_num_extensions = 0;
    i = 1;
    while (extension_descriptor[i++].id) {
        Max_num_extensions++;
    }
#ifdef DEVEL
    i = 1;
    while (extension_descriptor[i].id) {
        if (extension_descriptor[i].id != i) {
            printf("*** ERROR *** Init extension_descriptors at index %i: ID: %i, %s\n", i, extension_descriptor[i].id,
                   extension_descriptor[i].description);
        }
        i++;
    }
#endif

    return list;

}  // End of InitExtensionMaps

void FreeExtensionMaps(extension_map_list_t *extension_map_list) {
    if (extension_map_list == NULL) return;

    // free all extension infos
    extension_info_t *l = extension_map_list->map_list;
    while (l) {
        extension_info_t *tmp = l;
        l = l->next;
        free(tmp->map);
        free(tmp);
    }
    free(extension_map_list);

}  // End of FreeExtensionMaps

int Insert_Extension_Map(extension_map_list_t *extension_map_list, extension_map_t *map) {
    extension_info_t *l;
    uint16_t map_id;

    if (map->size < sizeof(extension_map_t)) {  // at least 1 extension required
        LogError("Corrupt extension map in %s line %d\n", __FILE__, __LINE__);
        return -1;
    }

    if (!VerifyExtensionMap(map)) {
        LogError("Corrupt extension map in %s line %d\n", __FILE__, __LINE__);
        return -1;
    }

    map_id = map->map_id;
    dbg_printf("Insert Extension Map:\n");

#ifdef DEVEL
    PrintExtensionMap(map);
#endif
    // is this slot free
    if (extension_map_list->slot[map_id]) {
        int i;
        dbg_printf("Extension info in slot %d already exists: 0x%llu\n", map_id, (long long unsigned)extension_map_list->slot[map_id]);
        // no - check if same map already in slot
        if (extension_map_list->slot[map_id]->map->size == map->size) {
            // existing map and new map have the same size
            dbg_printf("New map has same size, as existing:\n");

            // we must compare the maps
            i = 0;
            while (extension_map_list->slot[map_id]->map->ex_id[i] && (extension_map_list->slot[map_id]->map->ex_id[i] == map->ex_id[i])) i++;

            // if last entry == 0 => last map entry => maps are the same
            if (extension_map_list->slot[map_id]->map->ex_id[i] == 0) {
                dbg_printf("Same map => nothing to do\n");
                // same map
                return 0;
            }
        }
        dbg_printf("Different map => continue\n");
    }
#ifdef DEVEL
    else
        printf("Extension info in slot %d free\n", map_id);
#endif

    dbg_printf("Search if extension info exists in extension page_list\n");
    // new map is different but has same id - search for map in page list
    for (l = extension_map_list->map_list; l != NULL; l = l->next) {
        int i = 0;
        dbg_printf("Check map: %u\n", l->map->map_id);
        if (l->map->size == map->size && (l->map->extension_size == map->extension_size)) {
            while ((l->map->ex_id[i] || map->ex_id[i]) && (l->map->ex_id[i] == map->ex_id[i])) i++;
            if (l->map->ex_id[i] == 0) {
                dbg_printf("Map found: 0x%llu ID: %u\n", (long long unsigned)l, l->map->map_id);
                break;
            }
        }
    }

    // if found l is our extension
    if (!l) {
        // no extension found in page_list
        dbg_printf("Map not found in extension page list\n");
        l = (extension_info_t *)malloc(sizeof(extension_info_t));
        if (!l) {
            fprintf(stderr, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
            exit(255);
        }
        l->ref_count = 0;
        l->next = NULL;
        l->exportMap = NULL;

        l->map = (extension_map_t *)malloc((ssize_t)map->size);
        if (!l->map) {
            fprintf(stderr, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
            return -1;
        }
        memcpy((void *)l->map, (void *)map, map->size);

        // append new extension to list
        *(extension_map_list->last_map) = l;
        extension_map_list->last_map = &l->next;
    }

    // l is now our valid extension
    dbg_printf("Insert extension into slot %i: 0x%llu\n\n", map_id, (long long unsigned)l);

    // remove map from lookup list, if it exists
    if (extension_map_list->slot[map_id]) extension_map_list->slot[map_id]->map->map_id = 0;

    // place existing extension_info into lookup list
    extension_map_list->slot[map_id] = l;
    l->map->map_id = map_id;

    if (map_id > extension_map_list->max_used) {
        extension_map_list->max_used = map_id;
    }

    // extension changed
    return 1;

}  // End of Insert_Extension_Map

void PrintExtensionMap(extension_map_t *map) {
    int i;

    printf("Extension Map:\n");
    printf("  Map ID   = %u\n", map->map_id);
    printf("  Map Size = %u\n", map->size);
    printf("  Ext Size = %u\n", map->extension_size);
    i = 0;
    while (map->ex_id[i]) {
        int id = map->ex_id[i++];
        printf("  ID %3i, ext %3u = %s\n", extension_descriptor[id].user_index, id, extension_descriptor[id].description);
    }
    printf("\n");

}  // End of PrintExtensionMap

static int VerifyExtensionMap(extension_map_t *map) {
    int i, extension_size, max_elements;

    if ((map->size & 0x3) != 0) {
        LogError("Verify map id %i: WARNING: map size %i not aligned!", map->map_id, map->size);
        return 0;
    }

    if (map->size <= sizeof(extension_map_t)) {
        LogError("Verify map id %i: ERROR: map size %i too small", map->map_id, map->size);
        return 0;
    }

    max_elements = (map->size - sizeof(extension_map_t)) / sizeof(uint16_t);
    extension_size = 0;
    i = 0;
    while (map->ex_id[i] && i <= max_elements) {
        int id = map->ex_id[i];
        if (id > Max_num_extensions) {
            LogError("Verify map id %i: ERROR: element id %i out of range [%i]", map->map_id, id, Max_num_extensions);
            return 0;
        }
        extension_size += extension_descriptor[id].size;
        i++;
    }

    if (i != max_elements && (i + 1) != max_elements) {
        LogError("Verify map id %i: map has a zero element", map->map_id);
        return 0;
    }

    if (map->ex_id[i] != 0) {
        LogError("Verify map id %i: ERROR: no zero element", map->map_id);
        return 0;
    }

    if ((extension_size != map->extension_size)) {
        LogError("Verify map id %i: ERROR: extension size: Expected %i, Map reports: %i", map->map_id, extension_size, map->extension_size);
        return 0;
    }

    return 1;

}  // End of VerifyExtensionMap

void DumpExMaps(void) {
    nffile_t *nffile;

    printf("\nDump all extension maps:\n");
    printf("========================\n");

    nffile = GetNextFile(NULL);
    if (!nffile) {
        return;
    }

    dataBlock_t *dataBlock = NULL;
    int cnt = 0;
    int done = 0;
    while (!done) {
        // get next data block from file
        dataBlock = ReadBlock(nffile, dataBlock);
        if (dataBlock == NULL) {
            done = 1;
            continue;
        }

        if (dataBlock->type != DATA_BLOCK_TYPE_2) {
            continue;
        }

        // block type = 2
        common_record_t *flow_record = GetCursor(dataBlock);
        for (int i = 0; i < dataBlock->NumRecords; i++) {
            if (flow_record->type == ExtensionMapType) {
                extension_map_t *map = (extension_map_t *)flow_record;
                if (!VerifyExtensionMap(map)) return;
                PrintExtensionMap(map);
                cnt++;
            }

            // Advance pointer by number of bytes for netflow record
            flow_record = (common_record_t *)((void *)flow_record + flow_record->size);
        }
    }
    if (cnt == 0) {
        printf("No 1.6.x extension definition records\n");
    }

    FreeDataBlock(dataBlock);
    CloseFile(nffile);
    DisposeFile(nffile);

}  // End of DumpExMaps
