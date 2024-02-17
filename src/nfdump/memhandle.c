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

#ifdef __x86_64
#define ALIGN_MASK 0xFFFFFFF8
#else
#define ALIGN_MASK 0xFFFFFFFC
#endif

#include "spin_lock.h"

#define GetLock(a) spin_lock(((a)->lock))
#define ReleaseLock(a) spin_unlock(((a)->lock))

#define ALIGN_BYTES      \
    (offsetof(           \
         struct {        \
             char x;     \
             uint64_t y; \
         },              \
         y) -            \
     1)

// Each pre-allocated memory block is 10M
#define DefaultMemBlockSize 10 * 1024 * 1024

typedef struct MemHandler_s {
    size_t BlockSize; /* max size of each pre-allocated memblock */

    /* memory blocks - containing the flow records and keys */
    void **memblock;     /* array holding all NumBlocks allocated memory blocks */
    size_t MaxBlocks;    /* Size of memblock array */
    size_t NumBlocks;    /* number of allocated flow blocks in memblock array */
    size_t CurrentBlock; /* Index of current memblock to allocate memory from */
    size_t Allocted;     /* Number of bytes already allocated in memblock */

    atomic_int lock;

} MemHandler_t;

static MemHandler_t *MemHandler = NULL;

#define MaxMemBlocks 256

static int nfalloc_Init(uint32_t memBlockSize) {
    MemHandler = calloc(1, sizeof(MemHandler_t));
    if (!MemHandler) {
        LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    MemHandler->memblock = (void **)calloc(MaxMemBlocks, sizeof(void *));
    if (!MemHandler->memblock) {
        LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    if (memBlockSize == 0) memBlockSize = DefaultMemBlockSize;

    MemHandler->BlockSize = memBlockSize;

    MemHandler->memblock[0] = calloc(1, memBlockSize);
    if (!MemHandler->memblock[0]) {
        LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    MemHandler->MaxBlocks = MaxMemBlocks;
    MemHandler->NumBlocks = 1;
    MemHandler->CurrentBlock = 0;
    MemHandler->Allocted = 0;
    MemHandler->lock = 0;

    return 1;

}  // End of nfalloc_Init

static void nfalloc_free(void) {
    if (!MemHandler) return;

    for (int i = 0; i < MemHandler->NumBlocks; i++) {
        free(MemHandler->memblock[i]);
    }
    MemHandler->NumBlocks = 0;
    MemHandler->CurrentBlock = 0;
    MemHandler->Allocted = 0;

    free((void *)MemHandler->memblock);
    MemHandler->memblock = NULL;
    MemHandler->MaxBlocks = 0;
    free((void *)MemHandler);

}  // End of nfalloc_free

static inline void *nfmalloc(size_t size) {
    // make sure size of memory is aligned
    size_t aligned_size = (((size) + ALIGN_BYTES) & ~ALIGN_BYTES);

    GetLock(MemHandler);
    if ((MemHandler->Allocted + aligned_size) <= MemHandler->BlockSize) {
        // enough space available in current memblock
        void *p = MemHandler->memblock[MemHandler->CurrentBlock] + MemHandler->Allocted;
        MemHandler->Allocted += aligned_size;
        dbg_printf("Mem Handle: Requested: %zu, aligned: %zu, ptr: %lx\n", size, aligned_size, (long unsigned)p);
        ReleaseLock(MemHandler);
        return p;
    }

    // not enough space - allocate a new memblock

    MemHandler->CurrentBlock++;
    if (MemHandler->CurrentBlock >= MemHandler->MaxBlocks) {
        // we run out in memblock array - re-allocate memblock array
        MemHandler->MaxBlocks += MaxMemBlocks;
        MemHandler->memblock = (void **)realloc(MemHandler->memblock, MemHandler->MaxBlocks * sizeof(void *));
        if (!MemHandler->memblock) {
            LogError("realloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            exit(255);
        }
    }

    // allocate new memblock
    void *p = malloc(MemHandler->BlockSize);
    if (!p) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        exit(255);
    }
    MemHandler->memblock[MemHandler->CurrentBlock] = p;
    MemHandler->Allocted = aligned_size;
    MemHandler->NumBlocks++;
    ReleaseLock(MemHandler);
    dbg_printf("Mem Handle: Requested: %zu, aligned: %zu, ptr: %lu\n", size, aligned_size, (long unsigned)p);
    return p;

}  // End of nfmalloc

static inline void *nfcalloc(size_t count, size_t size) {
    void *p = nfmalloc(count * size);
    memset(p, 0, count * size);
    return p;

}  // nfcalloc

static inline void nffree(void *p) {
    // not implemented
}
