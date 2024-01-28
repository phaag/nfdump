/*
 *  Copyright (c) 2020, Peter Haag
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

#include "ifvrf.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "kbtree.h"
#include "util.h"

typedef struct nameNode_s {
    uint32_t ingress;
    char *name;
} nameNode_t;

static inline int nodeCMP(nameNode_t a, nameNode_t b) {
    if (a.ingress == b.ingress) return 0;
    return a.ingress > b.ingress ? 1 : -1;
}

KBTREE_INIT(ifTree, nameNode_t, nodeCMP)
KBTREE_INIT(vrfTree, nameNode_t, nodeCMP)

static kbtree_t(ifTree) *ifTree = NULL;
static kbtree_t(vrfTree) *vrfTree = NULL;

int AddIfNameRecord(arrayRecordHeader_t *arrayRecordHeader) {
    if (ifTree == NULL) {
        ifTree = kb_init(ifTree, KB_DEFAULT_SIZE);
        if (!ifTree) {
            LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
            return 0;
        }
    }

    dbg_printf("If name array, type: %u, size: %u, elemSize: %u, numElem: %u\n", arrayRecordHeader->type, arrayRecordHeader->size,
               arrayRecordHeader->elementSize, arrayRecordHeader->numElements);
    uint32_t *val = ((void *)arrayRecordHeader + sizeof(arrayRecordHeader_t));
    void *p = (void *)((void *)val + 4);
    for (int i = 0; i < arrayRecordHeader->numElements; i++) {
        uint32_t *ingress = (uint32_t *)p;
        char *name = (char *)(p + 4);
        nameNode_t nameNode = {.ingress = *ingress, .name = NULL};
        nameNode_t *node = kb_getp(ifTree, ifTree, &nameNode);
        if (node) {
            free(node->name);
            node->name = strdup(name);
        } else {
            nameNode.name = strdup(name);
            kb_putp(ifTree, ifTree, &nameNode);
        }

        p += arrayRecordHeader->elementSize;
    }

    return 0;

}  // End of AddIfNameRecord

int AddVrfNameRecord(arrayRecordHeader_t *arrayRecordHeader) {
    if (vrfTree == NULL) {
        vrfTree = kb_init(vrfTree, KB_DEFAULT_SIZE);
        if (!vrfTree) {
            LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
            return 0;
        }
    }

    dbg_printf("Vrf name array, type: %u, size: %u, elemSize: %u, numElem: %u\n", arrayRecordHeader->type, arrayRecordHeader->size,
               arrayRecordHeader->elementSize, arrayRecordHeader->numElements);
    uint32_t *val = ((void *)arrayRecordHeader + sizeof(arrayRecordHeader_t));
    void *p = (void *)((void *)val + 4);
    for (int i = 0; i < arrayRecordHeader->numElements; i++) {
        uint32_t *ingress = (uint32_t *)p;
        char *name = (char *)(p + 4);
        nameNode_t nameNode = {.ingress = *ingress, .name = NULL};
        nameNode_t *node = kb_getp(vrfTree, vrfTree, &nameNode);
        if (node) {
            free(node->name);
            node->name = strdup(name);
        } else {
            nameNode.name = strdup(name);
            kb_putp(vrfTree, vrfTree, &nameNode);
        }

        p += arrayRecordHeader->elementSize;
    }

    return 0;

}  // End of AddVrfNameRecord

char *GetIfName(uint32_t ingress, char *name, size_t len) {
    name[0] = '\0';
    if (ifTree && ingress != 0) {
        nameNode_t nameNode = {.ingress = ingress, .name = NULL};
        nameNode_t *node = kb_getp(ifTree, ifTree, &nameNode);
        if (node) {
            snprintf(name, len, " %s", node->name);
        } else {
            strncpy(name, " <ingress not found>", len);
        }
    } else {
        strncpy(name, " <no if name>", len);
    }
    return name;
}

char *GetVrfName(uint32_t ingress, char *name, size_t len) {
    name[0] = '\0';
    if (vrfTree && ingress != 0) {
        nameNode_t nameNode = {.ingress = ingress, .name = NULL};
        nameNode_t *node = kb_getp(vrfTree, vrfTree, &nameNode);
        if (node) {
            snprintf(name, len, " %s", node->name);
        } else {
            strncpy(name, " <ingress not found>", len);
        }
    } else {
        strncpy(name, " <no vrf name>", len);
    }
    return name;
}
