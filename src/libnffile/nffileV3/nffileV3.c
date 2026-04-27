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
#include <sys/param.h>
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

void *NewGenericDataBlock(uint32_t blockSize, uint32_t blockType, uint32_t headerSize) {
    dbg_printf("Enter %s\n", __func__);
    if (blockSize == 0) blockSize = BLOCK_SIZE_V3;
    dataBlockV3_t *dataBlock = malloc(blockSize);
    if (!dataBlock) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    memset(dataBlock, 0, headerSize);
    dataBlock->rawSize = headerSize;
    dataBlock->type = blockType;

    atomic_fetch_add(&blocksInUse, 1);
    return (void *)dataBlock;
}  // End of NewGenericDataBlock

dataBlockV3_t *NewDataBlock(uint32_t blockSize) {
    arrayBlockV3_t *a = NULL;
    InitDataBlock(a, blockSize);

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

flowBlockV3_t *NewFlowBlock(uint32_t blockSize) {
    dbg_printf("Enter %s\n", __func__);
    if (blockSize == 0) blockSize = BLOCK_SIZE_V3;
    flowBlockV3_t *flowBlock = malloc(blockSize);
    if (!flowBlock) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    *flowBlock = (flowBlockV3_t){.type = BLOCK_TYPE_FLOW, .rawSize = sizeof(flowBlockV3_t)};

    atomic_fetch_add(&blocksInUse, 1);
    return flowBlock;

}  // End of NewFlowBlock

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
    for (int i = 0; i < (int)num_workers; i++) nffile->worker[i] = 0;

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

void SetIdent(nffileV3_t *nffile, char *Ident) {
    if (Ident && strlen(Ident) > 0) {
        if (nffile->ident) free(nffile->ident);
        nffile->ident = strdup(Ident);
    }

}  // End of SetIdent

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

void SumStatRecords(stat_record_t *s1, stat_record_t *s2) {
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
 * copyDataBlocks: copy all non-STATS/IDENT blocks from nffile into wfd,
 * appending directory entries to entries[*idx] and advancing *writePos.
 * Returns 0 on success, -1 on error.
 */
static int copyDataBlocks(const nffileV3_t *nffile, int wfd, directoryEntryV3_t *entries, uint32_t *idx, off_t *writePos,
                          const char *tag) {
    const blockDirectoryV3_t *dir = nffile->blockDirectory;
    for (uint32_t i = 0; i < dir->numEntries; i++) {
        const directoryEntryV3_t *e = &dir->entries[i];
        if (e->type == BLOCK_TYPE_STATS || e->type == BLOCK_TYPE_IDENT) continue;
        if (e->offset + e->size > nffile->mapSize) {
            LogError("RenameAppendV3: %s entry[%u] out of bounds", tag, i);
            return -1;
        }
        ssize_t n = pwrite(wfd, nffile->map + e->offset, e->size, *writePos);
        if (n != (ssize_t)e->size) {
            LogError("RenameAppendV3: pwrite() %s block[%u]: %s", tag, i, strerror(errno));
            return -1;
        }
        entries[(*idx)++] = (directoryEntryV3_t){.type = e->type, .size = e->size, .offset = (uint64_t)*writePos};
        *writePos += (off_t)e->size;
    }
    return 0;
}  // End of copyDataBlocks

/*
 * writeMergedStats: write a STATS block and append its directory entry.
 * Skips silently when no flows were recorded (sentinel msecFirstSeen value).
 * Returns 0 on success, -1 on error.
 */
static int writeMergedStats(int wfd, const stat_record_t *stats, directoryEntryV3_t *entries, uint32_t *idx, off_t *writePos) {
    if (stats->msecFirstSeen == 0x7fffffffffffffffLL) return 0;

    const uint32_t size = (uint32_t)(sizeof(dataBlockV3_t) + sizeof(stat_record_t));
    const dataBlockV3_t hdr = {
        .type = BLOCK_TYPE_STATS, .discSize = size, .rawSize = size, .compression = NOT_COMPRESSED, .encryption = NOT_ENCRYPTED,
    };
    ssize_t n = pwrite(wfd, &hdr, sizeof(hdr), *writePos);
    if (n != (ssize_t)sizeof(hdr)) {
        LogError("RenameAppendV3: pwrite() stats header: %s", strerror(errno));
        return -1;
    }
    n = pwrite(wfd, stats, sizeof(stat_record_t), *writePos + (off_t)sizeof(hdr));
    if (n != (ssize_t)sizeof(stat_record_t)) {
        LogError("RenameAppendV3: pwrite() stats payload: %s", strerror(errno));
        return -1;
    }
    entries[(*idx)++] = (directoryEntryV3_t){.type = BLOCK_TYPE_STATS, .size = size, .offset = (uint64_t)*writePos};
    *writePos += (off_t)size;
    return 0;
}  // End of writeMergedStats

/*
 * writeMergedIdent: write an IDENT block of fixed size IDENTLEN and append
 * its directory entry.  Skips silently when ident is NULL.
 * Returns 0 on success, -1 on error.
 */
static int writeMergedIdent(int wfd, const char *ident, directoryEntryV3_t *entries, uint32_t *idx, off_t *writePos) {
    if (!ident) return 0;

    const uint32_t size = (uint32_t)(sizeof(dataBlockV3_t) + IDENTLEN);
    const dataBlockV3_t hdr = {
        .type = BLOCK_TYPE_IDENT, .discSize = size, .rawSize = size, .compression = NOT_COMPRESSED, .encryption = NOT_ENCRYPTED,
    };
    ssize_t n = pwrite(wfd, &hdr, sizeof(hdr), *writePos);
    if (n != (ssize_t)sizeof(hdr)) {
        LogError("RenameAppendV3: pwrite() ident header: %s", strerror(errno));
        return -1;
    }
    char buf[IDENTLEN];
    strncpy(buf, ident, IDENTLEN);
    n = pwrite(wfd, buf, IDENTLEN, *writePos + (off_t)sizeof(hdr));
    if (n != IDENTLEN) {
        LogError("RenameAppendV3: pwrite() ident payload: %s", strerror(errno));
        return -1;
    }
    entries[(*idx)++] = (directoryEntryV3_t){.type = BLOCK_TYPE_IDENT, .size = size, .offset = (uint64_t)*writePos};
    *writePos += (off_t)size;
    return 0;
}  // End of writeMergedIdent

/*
 * writeDirectoryFooter: write the block directory, the file footer, and
 * rewrite the file header with the final directory location.
 * header->offDirectory and header->dirSize are updated in place.
 * Returns 0 on success, -1 on error.
 */
static int writeDirectoryFooter(int wfd, fileHeaderV3_t *header, const directoryEntryV3_t *entries, uint32_t numEntries,
                                off_t dirOffset) {
    const size_t entriesSize = numEntries * sizeof(directoryEntryV3_t);
    const uint32_t dirSize = (uint32_t)(sizeof(blockDirectoryV3_t) + entriesSize);

    const blockDirectoryV3_t dirHdr = {.magic = DIRECTORY_MAGIC, .numEntries = numEntries};
    ssize_t n = pwrite(wfd, &dirHdr, sizeof(dirHdr), dirOffset);
    if (n != (ssize_t)sizeof(dirHdr)) {
        LogError("RenameAppendV3: pwrite() directory header: %s", strerror(errno));
        return -1;
    }
    off_t pos = dirOffset + (off_t)sizeof(dirHdr);
    if (entriesSize > 0) {
        n = pwrite(wfd, entries, entriesSize, pos);
        if (n != (ssize_t)entriesSize) {
            LogError("RenameAppendV3: pwrite() directory entries: %s", strerror(errno));
            return -1;
        }
        pos += (off_t)entriesSize;
    }

    const fileFooterV3_t footer = {
        .magic = FOOTER_MAGIC_V3, .dirSize = dirSize, .offDirectory = (uint64_t)dirOffset, .checksum = 0,
    };
    n = pwrite(wfd, &footer, sizeof(footer), pos);
    if (n != (ssize_t)sizeof(footer)) {
        LogError("RenameAppendV3: pwrite() footer: %s", strerror(errno));
        return -1;
    }

    header->offDirectory = (uint64_t)dirOffset;
    header->dirSize = dirSize;
    n = pwrite(wfd, header, sizeof(*header), 0);
    if (n != (ssize_t)sizeof(*header)) {
        LogError("RenameAppendV3: pwrite() final header: %s", strerror(errno));
        return -1;
    }
    return 0;
}  // End of writeDirectoryFooter

/*
 * buildMergedTempFile: write the merged content of dst and src into a new
 * temp file created in the same directory as newName.
 * Closes src and dst before returning (on both success and failure paths).
 * Returns a malloc'd path to the temp file on success, NULL on failure.
 * The caller must rename() the temp file to its final destination and free()
 * the returned string.
 */
static char *buildMergedTempFile(nffileV3_t *src, nffileV3_t *dst, const char *newName) {
    // worst case: all dst entries + all src entries + 2 (STATS + IDENT)
    uint32_t totalEntries = dst->blockDirectory->numEntries + src->blockDirectory->numEntries + 2;
    directoryEntryV3_t *entries = malloc(totalEntries * sizeof(directoryEntryV3_t));
    if (!entries) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        CloseFileV3(src);
        CloseFileV3(dst);
        return NULL;
    }

    // merge stat records
    stat_record_t mergedStats;
    if (dst->stat_record) {
        mergedStats = *dst->stat_record;
    } else {
        memset(&mergedStats, 0, sizeof(mergedStats));
        mergedStats.msecFirstSeen = 0x7fffffffffffffffLL;
    }
    if (src->stat_record) SumStatRecords(&mergedStats, src->stat_record);

    // keep dst ident, fall back to src ident
    const char *rawIdent = dst->ident ? dst->ident : src->ident;
    char *ident = rawIdent ? strdup(rawIdent) : NULL;
    if (rawIdent && !ident) {
        LogError("strdup() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        free(entries);
        CloseFileV3(src);
        CloseFileV3(dst);
        return NULL;
    }

    fileHeaderV3_t header = *dst->fileHeader;

    // create temp file in the same directory as newName
    size_t nameLen = strlen(newName);
    char *tmpName = malloc(nameLen + 8);
    if (!tmpName) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        free(ident);
        free(entries);
        CloseFileV3(src);
        CloseFileV3(dst);
        return NULL;
    }
    snprintf(tmpName, nameLen + 8, "%s.XXXXXX", newName);
    int wfd = mkstemp(tmpName);
    if (wfd < 0) {
        LogError("RenameAppendV3: mkstemp('%s'): %s", tmpName, strerror(errno));
        free(tmpName);
        free(ident);
        free(entries);
        CloseFileV3(src);
        CloseFileV3(dst);
        return NULL;
    }
    fchmod(wfd, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

    // write placeholder header (rewritten at end with final offDirectory)
    ssize_t n = pwrite(wfd, &header, sizeof(header), 0);
    int ok = (n == (ssize_t)sizeof(header));
    if (!ok) LogError("RenameAppendV3: pwrite() header: %s", strerror(errno));

    off_t writePos = (off_t)sizeof(fileHeaderV3_t);
    uint32_t idx = 0;

    // copy non-STATS/IDENT blocks from dst, then src
    // (directory entries are always in file-offset order -- see nfwriter mutex)
    ok = ok && (copyDataBlocks(dst, wfd, entries, &idx, &writePos, "dst") == 0);
    ok = ok && (copyDataBlocks(src, wfd, entries, &idx, &writePos, "src") == 0);

    CloseFileV3(dst);
    CloseFileV3(src);

    // append merged STATS and IDENT blocks
    ok = ok && (writeMergedStats(wfd, &mergedStats, entries, &idx, &writePos) == 0);
    ok = ok && (writeMergedIdent(wfd, ident, entries, &idx, &writePos) == 0);

    // write directory, footer, and rewrite header
    ok = ok && (writeDirectoryFooter(wfd, &header, entries, idx, writePos) == 0);

    free(entries);
    free(ident);

    if (ok) {
        fsync(wfd);
        close(wfd);
        return tmpName;
    }

    close(wfd);
    unlink(tmpName);
    free(tmpName);
    return NULL;
}  // End of buildMergedTempFile

/*
 * RenameAppendV3:
 *  - If newName does not exist: rename oldName -> newName.
 *  - If newName exists: merge data blocks from oldName into newName
 *    without decompressing/recompressing, then remove oldName.
 *
 * Blocks are copied individually (not as a raw byte range) to avoid
 * orphan STATS/IDENT bytes that would cause nfdump -v check to fail.
 *
 * Returns 0 on success, -1 on error.
 */
int RenameAppendV3(const char *oldName, const char *newName) {
    if (access(newName, F_OK) != 0) return rename(oldName, newName);

    nffileV3_t *src = mmapFileV3(oldName);
    if (!src) {
        LogError("RenameAppendV3: cannot open source '%s'", oldName);
        return -1;
    }

    nffileV3_t *dst = mmapFileV3(newName);
    if (!dst) {
        LogError("RenameAppendV3: cannot open destination '%s'", newName);
        CloseFileV3(src);
        return -1;
    }

    if (dst->fileHeader->blockSize != src->fileHeader->blockSize) {
        LogError("RenameAppendV3: blockSize mismatch dst=%u src=%u", dst->fileHeader->blockSize, src->fileHeader->blockSize);
        CloseFileV3(src);
        CloseFileV3(dst);
        return -1;
    }

    // buildMergedTempFile closes src and dst before returning
    char *tmpName = buildMergedTempFile(src, dst, newName);
    if (!tmpName) return -1;

    int rc = rename(tmpName, newName);
    if (rc != 0) {
        LogError("RenameAppendV3: rename('%s','%s'): %s", tmpName, newName, strerror(errno));
        unlink(tmpName);
    } else {
        unlink(oldName);
    }
    free(tmpName);
    return rc;
}  // End of RenameAppendV3

// Check if all data blocks in file already have target compression
static int FileHasCompression(nffileV3_t *nffile, uint32_t compressType) {
    if (!nffile->blockDirectory || !nffile->map) return 0;

    for (uint32_t i = 0; i < nffile->blockDirectory->numEntries; i++) {
        const directoryEntryV3_t *e = &nffile->blockDirectory->entries[i];
        // Only check data blocks (FLOW/ARRAY), skip metadata (STATS, IDENT, etc.)
        if (e->type != BLOCK_TYPE_FLOW && e->type != BLOCK_TYPE_ARRAY) continue;

        // bounds check
        if (e->offset + sizeof(dataBlockV3_t) > nffile->mapSize) continue;

        const dataBlockV3_t *blk = (const dataBlockV3_t *)(nffile->map + e->offset);
        if (blk->compression == compressType) return 1;
    }
    return 0;
}

void ModifyCompressFile(uint32_t compressType, uint32_t compressLevel) {
    while (1) {
        nffileV3_t *nffile_r = GetNextFile();

        // last file
        if (nffile_r == NULL) break;

        // skip files where all data blocks already have target compression
        if (FileHasCompression(nffile_r, compressType)) {
            printf("File %s already at target compression, skipped\n", nffile_r->fileName);
            CloseFileV3(nffile_r);
            continue;
        }

        // save fileName before closing (CloseFileV3 frees it)
        char srcFile[MAXPATHLEN];
        strncpy(srcFile, nffile_r->fileName, MAXPATHLEN - 1);
        srcFile[MAXPATHLEN - 1] = '\0';

        // tmp filename for new output file
        char outfile[MAXPATHLEN];
        snprintf(outfile, MAXPATHLEN, "%s.XXXXXXX", srcFile);
        outfile[MAXPATHLEN - 1] = '\0';

        // allocate output file
        nffileV3_t *nffile_w = OpenNewFileTmpV3(outfile, nffile_r->fileHeader->creator, compressType, compressLevel, NOT_ENCRYPTED);
        if (!nffile_w) {
            CloseFileV3(nffile_r);
            break;
        }

        SetIdent(nffile_w, nffile_r->ident);

        // swap stat records :)
        stat_record_t *_s = nffile_r->stat_record;
        nffile_r->stat_record = nffile_w->stat_record;
        nffile_w->stat_record = _s;

        // push blocks to new file
        while (1) {
            dataBlockV3_t *block_header = queue_pop(nffile_r->processQueue);
            if (block_header == QUEUE_CLOSED)  // EOF
                break;
            // keep BLOCK_TYPE_STATS and BLOCK_TYPE_IDENT uncompressed
            if (block_header->type != BLOCK_TYPE_STATS && block_header->type != BLOCK_TYPE_IDENT) {
                // compression is base on block level - UNDEF_COMPRESSED uses default file compression
                block_header->compression = UNDEF_COMPRESSED;
            }
            queue_push(nffile_w->processQueue, block_header);
        }

        CloseFileV3(nffile_r);

        if (FlushFileV3(nffile_w)) {
            printf("File %s compression changed\n", srcFile);
            char *fileName = strdup(nffile_w->fileName);
            CloseFileV3(nffile_w);
            if (unlink(srcFile)) {
                LogError("unlink() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            } else if (rename(fileName, srcFile)) {
                LogError("rename() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            }
            free(fileName);
        } else {
            printf("Failed to change file compression for: %s\n", srcFile);
            CloseFileV3(nffile_w);
            unlink(outfile);
        }
    }

}  // End of ModifyCompressFile
