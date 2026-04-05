/*
 *  Copyright (c) 2026, Peter Haag
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

#include "nffileV3.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "id.h"
#include "logging.h"
#include "nfcompress.h"
#include "nfdump.h"
#include "nfxV4.h"
#include "queue.h"
#include "util.h"
#include "vcs_track.h"

static _Atomic int blocksInUse;

// default workers
uint32_t NumWorkers = 2;

static queue_t *fileQueue = NULL;

int Init_nffile(uint32_t workers, queue_t *fileList) {
    fileQueue = fileList;

    if (!InitCompression()) {
        LogError("Failed to initialize compression libraries");
        return 0;
    }

    atomic_init(&blocksInUse, 0);

    NumWorkers = workers;

    return 1;

}  // End of Init_nffile

nffileV3_t *GetNextFile(void) {
    if (!fileQueue) {
        LogError("GetNextFile() no file queue to process");
        return NULL;
    }

    while (1) {
        char *nextFile = queue_pop(fileQueue);
        if (nextFile == QUEUE_CLOSED) {
            // no or no more files available
            return NULL;
        }

        dbg_printf("Process: '%s'\n", nextFile);
        nffileV3_t *nffile = OpenFileV3(nextFile);  // Open the file
        free(nextFile);
        return nffile;
    }

    /* NOTREACHED */

}  // End of GetNextFile

int ReportBlocks(void) {
    int inUse = atomic_load(&blocksInUse);
    return inUse;
}  // End of ReportBlocks

dataBlockV3_t *NewDataBlock(uint32_t blockSize) {
    dbg_printf("Enter %s\n", __func__);
    if (blockSize == 0) blockSize = BLOCK_SIZE_V3;
    dataBlockV3_t *dataBlock = malloc(blockSize);
    if (!dataBlock) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    memset(dataBlock, 0, sizeof(dataBlockV3_t));
    dataBlock->discSize = sizeof(dataBlockV3_t);

    atomic_fetch_add(&blocksInUse, 1);
    return dataBlock;

}  // End of NewDataBlock

void FreeDataBlock(void *block) {
    dbg_printf("Enter %s\n", __func__);

    if (block) {
        free(block);
        atomic_fetch_sub(&blocksInUse, 1);
    }
}  // End of FreeDataBlock

nffileV3_t *NewFile(uint32_t num_workers, uint32_t queueSize) {
    dbg_printf("NewFile() %d workers\n", num_workers);
    size_t alloc_size = sizeof(nffileV3_t) + num_workers * sizeof(pthread_t);

    // Create struct
    nffileV3_t *nffile = malloc(alloc_size);
    if (!nffile) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }
    *nffile = (nffileV3_t){
        .numWorkers = num_workers,
        .fd = -1,
        .processQueue = queue_init(queueSize),
    };

    if (!nffile->processQueue) {
        free(nffile);
        return NULL;
    }

    pthread_mutex_init(&nffile->wlock, NULL);
    return nffile;

}  // End of NewFile

int AddBlock(blockListV3_t *blockList, uint32_t type, uint64_t offset, uint32_t diskSize) {
    if (blockList->count >= blockList->capacity) {
        uint32_t newCap = blockList->capacity * 2;
        directoryEntryV3_t *newEntries = realloc(blockList->entries, newCap * sizeof(directoryEntryV3_t));
        if (!newEntries) {
            LogError("realloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return 0;
        }
        blockList->entries = newEntries;
        blockList->capacity = newCap;
    }
    blockList->entries[blockList->count] = (directoryEntryV3_t){
        .type = type,
        .size = diskSize,
        .offset = offset,
    };
    blockList->count++;

    return 1;

}  // End of AddBlock

int PreallocateDirectory(blockListV3_t *blockList, uint32_t expectedBlocks) {
    if (expectedBlocks <= blockList->capacity) return 1;

    directoryEntryV3_t *newEntries = realloc(blockList->entries, expectedBlocks * sizeof(directoryEntryV3_t));
    if (!newEntries) {
        LogError("realloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }
    blockList->entries = newEntries;
    blockList->capacity = expectedBlocks;

    return 1;

}  // End of PreallocateDirectory

void joinWorkers(nffileV3_t *nffile) {
    for (int i = 0; i < (int)nffile->numWorkers; i++) {
        if (nffile->worker[i]) {
            dbg_printf("Join worker %d:%p for %s\n", i, (void *)nffile->worker[i], nffile->fileName);
            int err = pthread_join(nffile->worker[i], NULL);
            if (err && err != ESRCH) {
                LogError("pthread_join() error in %s line %d: %s", __FILE__, __LINE__, strerror(err));
            }
            nffile->worker[i] = 0;
        }
    }

}  // End of joinWorkers

void TerminateWorkers(nffileV3_t *nffile) {
    // closing the queue signals the workers to terminate
    queue_close(nffile->processQueue);
    joinWorkers(nffile);
}  // End of TerminateWorkers

void DeleteFileV3(nffileV3_t *nffile) {
    if (!nffile) return;

    char *fileName = nffile->fileName;
    nffile->fileName = NULL;

    CloseFileV3(nffile);

    if (fileName) {
        unlink(fileName);
        free(fileName);
    }

}  // End of DeleteFileV3

void CloseFileV3(nffileV3_t *nffile) {
    if (!nffile) return;

    TerminateWorkers(nffile);
    if (nffile->map) {
        // mmap() file for readers
        munmap((void *)nffile->map, nffile->mapSize);
    } else {
        // direct write for writers
        if (nffile->fileHeader) free(nffile->fileHeader);
    }
    if (nffile->fd >= 0) close(nffile->fd);
    if (nffile->fileName) free(nffile->fileName);
    if (nffile->stat_record) free(nffile->stat_record);
    if (nffile->ident) free(nffile->ident);
    if (nffile->blockList.entries) free(nffile->blockList.entries);

    pthread_mutex_destroy(&nffile->wlock);

    if (nffile->processQueue) {
        queue_clear(nffile->processQueue, (void (*)(void *))FreeDataBlock);
        queue_free(nffile->processQueue);
    }
    free(nffile);

}  // End of CloseFileV3

static void SumStatRecords(stat_record_t *s1, stat_record_t *s2) {
    s1->numflows += s2->numflows;
    s1->numbytes += s2->numbytes;
    s1->numpackets += s2->numpackets;
    s1->numflows_tcp += s2->numflows_tcp;
    s1->numflows_udp += s2->numflows_udp;
    s1->numflows_icmp += s2->numflows_icmp;
    s1->numflows_other += s2->numflows_other;
    s1->numbytes_tcp += s2->numbytes_tcp;
    s1->numbytes_udp += s2->numbytes_udp;
    s1->numbytes_icmp += s2->numbytes_icmp;
    s1->numbytes_other += s2->numbytes_other;
    s1->numpackets_tcp += s2->numpackets_tcp;
    s1->numpackets_udp += s2->numpackets_udp;
    s1->numpackets_icmp += s2->numpackets_icmp;
    s1->numpackets_other += s2->numpackets_other;
    s1->sequence_failure += s2->sequence_failure;

    if (s2->msecFirstSeen < s1->msecFirstSeen) {
        s1->msecFirstSeen = s2->msecFirstSeen;
    }
    if (s2->msecLastSeen > s1->msecLastSeen) {
        s1->msecLastSeen = s2->msecLastSeen;
    }

}  // End of SumStatRecords

/*
 * RenameAppendV3:
 *  - If newName does not exist: rename oldName -> newName.
 *  - If newName exists: append data blocks from oldName into newName
 *    without decompressing/recompressing.  Merge directories and stats,
 *    then remove oldName.
 *
 * The append works at the file level:
 *  1. mmap both files read-only, validate headers + directories.
 *  2. Open dst for read-write, truncate after its last data block
 *     (chop off old STATS, IDENT, directory + footer).
 *  3. Copy src data blocks (raw, compressed bytes) to the end of dst.
 *  4. Build a merged directory: dst entries (unchanged) + src entries
 *     (offsets adjusted by the dst data end position).  Skip STATS and
 *     IDENT blocks from src — they'll be replaced by merged versions.
 *  5. Sum stat records, write merged stats + ident blocks.
 *  6. Write new directory + footer, rewrite header.
 *  7. Unlink oldName.
 *
 *  Returns 0 on success, -1 on error.
 */
int RenameAppendV3(const char *oldName, const char *newName) {
    if (access(newName, F_OK) != 0) {
        // destination does not exist — simple rename
        return rename(oldName, newName);
    }

    // --- open source (tmp) file via mmap ---
    nffileV3_t *src = mmapFileV3(oldName);
    if (!src) {
        LogError("RenameAppendV3: cannot open source '%s'", oldName);
        return -1;
    }

    // --- open destination file via mmap ---
    nffileV3_t *dst = mmapFileV3(newName);
    if (!dst) {
        LogError("RenameAppendV3: cannot open destination '%s'", newName);
        CloseFileV3(src);
        return -1;
    }

    // verify blockSize match
    if (dst->fileHeader->blockSize != src->fileHeader->blockSize) {
        LogError("RenameAppendV3: blockSize mismatch dst=%u src=%u", dst->fileHeader->blockSize, src->fileHeader->blockSize);
        CloseFileV3(src);
        CloseFileV3(dst);
        return -1;
    }
    const blockDirectoryV3_t *srcDir = src->blockDirectory;
    const blockDirectoryV3_t *dstDir = dst->blockDirectory;

    // all blocks (including STATS/IDENT) sit between header and directory;
    // old STATS/IDENT become dead bytes, unreferenced by the merged directory
    off_t dstDataEnd = (off_t)dst->fileHeader->offDirectory;

    // src blocks start right after header, directory follows last block
    size_t srcCopySize = (size_t)(src->fileHeader->offDirectory - sizeof(fileHeaderV3_t));
    uint64_t srcFirstOffset = sizeof(fileHeaderV3_t);

    // -2 skip dst STATS/IDENT, -2 skip src STATS/IDENT, +2 new merged STATS/IDENT
    uint32_t totalEntries = dstDir->numEntries + srcDir->numEntries - 2;

    // allocate merged directory
    directoryEntryV3_t *mergedEntries = malloc(totalEntries * sizeof(directoryEntryV3_t));
    if (!mergedEntries) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        CloseFileV3(src);
        CloseFileV3(dst);
        return -1;
    }

    // fill dst entries (skip STATS/IDENT — offsets unchanged)
    uint32_t idx = 0;
    for (uint32_t i = 0; i < dstDir->numEntries; i++) {
        uint32_t t = dstDir->entries[i].type;
        if (t != BLOCK_TYPE_STATS && t != BLOCK_TYPE_IDENT) {
            mergedEntries[idx++] = dstDir->entries[i];
        }
    }

    // fill src entries with adjusted offsets
    // src block at original offset X becomes dstDataEnd + (X - srcFirstOffset)
    for (uint32_t i = 0; i < srcDir->numEntries; i++) {
        uint32_t t = srcDir->entries[i].type;
        if (t == BLOCK_TYPE_STATS || t == BLOCK_TYPE_IDENT) continue;
        mergedEntries[idx] = srcDir->entries[i];
        mergedEntries[idx].offset = (uint64_t)dstDataEnd + (srcDir->entries[i].offset - srcFirstOffset);
        idx++;
    }

    // merge stat records
    stat_record_t mergedStats;
    if (dst->stat_record) {
        mergedStats = *dst->stat_record;
    } else {
        memset(&mergedStats, 0, sizeof(mergedStats));
    }
    if (src->stat_record) SumStatRecords(&mergedStats, src->stat_record);

    // keep dst ident — must copy since CloseFileV3 frees dst->ident
    char *ident = strdup(dst->ident ? dst->ident : "none");
    if (!ident) {
        LogError("strdup() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        free(mergedEntries);
        CloseFileV3(src);
        CloseFileV3(dst);
        return -1;
    }

    // --- we have everything we need from the mmap'd data; now do I/O ---

    // copy header to stack before we close the mmap
    fileHeaderV3_t savedHeader = *dst->fileHeader;

    // get pointer to src raw data before we close anything
    const uint8_t *srcData = NULL;
    if (srcCopySize > 0) {
        srcData = src->map + srcFirstOffset;
    }

    // open dst file for writing (separate fd — mmap stays valid for srcData read)
    int wfd = open(newName, O_RDWR);
    if (wfd < 0) {
        LogError("open(rw) '%s': %s", newName, strerror(errno));
        free(mergedEntries);
        CloseFileV3(src);
        CloseFileV3(dst);
        return -1;
    }

    // truncate dst at directory offset — removes old directory + footer
    // After this, dst mmap pages beyond dstDataEnd are invalid (SIGBUS).
    // All dst mmap data was consumed above; only src->map is accessed below.
    if (ftruncate(wfd, dstDataEnd) < 0) {
        LogError("ftruncate() '%s': %s", newName, strerror(errno));
        close(wfd);
        free(mergedEntries);
        CloseFileV3(src);
        CloseFileV3(dst);
        return -1;
    }

    // append src data blocks as raw bytes — no decompress/recompress
    off_t writePos = dstDataEnd;
    if (srcCopySize > 0) {
        ssize_t ret = pwrite(wfd, srcData, srcCopySize, writePos);
        if (ret != (ssize_t)srcCopySize) {
            LogError("pwrite() src data: %s", strerror(errno));
            close(wfd);
            free(mergedEntries);
            CloseFileV3(src);
            CloseFileV3(dst);
            return -1;
        }
        writePos += (off_t)srcCopySize;
    }

    // all mmap data consumed — release both mappings
    CloseFileV3(src);
    CloseFileV3(dst);

    // write merged STATS block
    uint32_t statsBlockSize = sizeof(dataBlockV3_t) + sizeof(stat_record_t);
    dataBlockV3_t statsHdr = {
        .type = BLOCK_TYPE_STATS,
        .discSize = statsBlockSize,
        .rawSize = statsBlockSize,
        .compression = NOT_COMPRESSED,
        .encryption = NOT_ENCRYPTED,
    };
    ssize_t ret = pwrite(wfd, &statsHdr, sizeof(dataBlockV3_t), writePos);
    if (ret != (ssize_t)sizeof(dataBlockV3_t)) {
        LogError("pwrite() stats header: %s", strerror(errno));
        close(wfd);
        free(mergedEntries);
        free(ident);
        return -1;
    }
    mergedEntries[idx++] = (directoryEntryV3_t){
        .type = BLOCK_TYPE_STATS,
        .size = statsBlockSize,
        .offset = (uint64_t)writePos,
    };
    ret = pwrite(wfd, &mergedStats, sizeof(stat_record_t), writePos + sizeof(dataBlockV3_t));
    if (ret != (ssize_t)sizeof(stat_record_t)) {
        LogError("pwrite() stats payload: %s", strerror(errno));
        close(wfd);
        free(mergedEntries);
        free(ident);
        return -1;
    }
    writePos += statsBlockSize;

    // write IDENT block
    uint32_t identLen = (uint32_t)strlen(ident) + 1;
    uint32_t identPadded = (identLen + 7) & ~7u;
    uint32_t identBlockSize = sizeof(dataBlockV3_t) + identPadded;
    dataBlockV3_t identHdr = {
        .type = BLOCK_TYPE_IDENT,
        .discSize = identBlockSize,
        .rawSize = identBlockSize,
        .compression = NOT_COMPRESSED,
        .encryption = NOT_ENCRYPTED,
    };

    // assemble ident block in a small stack buffer
    uint8_t identBuf[sizeof(dataBlockV3_t) + 256];
    memset(identBuf, 0, sizeof(identBuf));
    memcpy(identBuf, &identHdr, sizeof(dataBlockV3_t));
    memcpy(identBuf + sizeof(dataBlockV3_t), ident, identLen);

    ret = pwrite(wfd, identBuf, identBlockSize, writePos);
    if (ret != (ssize_t)identBlockSize) {
        LogError("pwrite() ident block: %s", strerror(errno));
        close(wfd);
        free(mergedEntries);
        free(ident);
        return -1;
    }
    mergedEntries[idx++] = (directoryEntryV3_t){
        .type = BLOCK_TYPE_IDENT,
        .size = identBlockSize,
        .offset = (uint64_t)writePos,
    };
    writePos += identBlockSize;

    // --- write merged directory ---
    off_t dirOffset = writePos;
    uint32_t numEntries = idx;  // should == totalEntries

    blockDirectoryV3_t dirHdr = {
        .magic = DIRECTORY_MAGIC,
        .numEntries = numEntries,
    };
    ret = pwrite(wfd, &dirHdr, sizeof(blockDirectoryV3_t), dirOffset);
    if (ret != (ssize_t)sizeof(blockDirectoryV3_t)) {
        LogError("pwrite() directory header: %s", strerror(errno));
        close(wfd);
        free(mergedEntries);
        free(ident);
        return -1;
    }

    size_t entriesSize = numEntries * sizeof(directoryEntryV3_t);
    off_t pos = dirOffset + sizeof(blockDirectoryV3_t);
    if (entriesSize > 0) {
        ret = pwrite(wfd, mergedEntries, entriesSize, pos);
        if (ret != (ssize_t)entriesSize) {
            LogError("pwrite() directory entries: %s", strerror(errno));
            close(wfd);
            free(mergedEntries);
            free(ident);
            return -1;
        }
        pos += entriesSize;
    }
    free(mergedEntries);

    uint32_t dirSize = (uint32_t)(sizeof(blockDirectoryV3_t) + entriesSize);

    // --- write footer ---
    fileFooterV3_t footer = {
        .magic = FOOTER_MAGIC_V3,
        .dirSize = dirSize,
        .offDirectory = (uint64_t)dirOffset,
        .checksum = 0,
    };
    ret = pwrite(wfd, &footer, sizeof(fileFooterV3_t), pos);
    if (ret != (ssize_t)sizeof(fileFooterV3_t)) {
        LogError("pwrite() footer: %s", strerror(errno));
        close(wfd);
        free(ident);
        return -1;
    }

    // --- rewrite header with new directory offset ---
    savedHeader.offDirectory = (uint64_t)dirOffset;
    savedHeader.dirSize = dirSize;

    ret = pwrite(wfd, &savedHeader, sizeof(fileHeaderV3_t), 0);
    if (ret != (ssize_t)sizeof(fileHeaderV3_t)) {
        LogError("pwrite() header: %s", strerror(errno));
        close(wfd);
        free(ident);
        return -1;
    }

    fsync(wfd);
    close(wfd);
    free(ident);

    // remove source tmp file
    return unlink(oldName);

}  // End of RenameAppendV3

void ModifyCompressFile(uint32_t compressType, uint32_t compressLevel) {
    while (1) {
        nffileV3_t *nffile_r = GetNextFile();

        // XXX FIX! implement modify compression
    }

}  // End of ModifyCompressFile
