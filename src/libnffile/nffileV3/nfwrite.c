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

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
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
#include "nffileV3.h"
#include "nfxV4.h"
#include "queue.h"
#include "util.h"
#include "vcs_track.h"

// NumWorkers is set from nffileV3.c via Init_nffile
extern uint32_t NumWorkers;

static void DeleteFile(nffileV3_t *nffile) {
    if (nffile == NULL) return;

    TerminateWorkers(nffile);
    if (nffile->fd >= 0) {
        close(nffile->fd);
        unlink(nffile->fileName);
    }

    if (nffile->fileName) free(nffile->fileName);
    if (nffile->stat_record) free(nffile->stat_record);
    if (nffile->ident) free(nffile->ident);
    if (nffile->blockList.entries) free(nffile->blockList.entries);

    if (nffile->processQueue) {
        // Free all pending blocks even if queue was aborted
        queue_clear(nffile->processQueue, (void (*)(void *))FreeDataBlock);
        queue_free(nffile->processQueue);
    }
    free(nffile);

}  // End of DeleteFile

static int nfwrite(nffileV3_t *nffile, dataBlockV3_t *block_header) {
    if (block_header->rawSize == 0) {
        return 1;
    }

    dbg_printf("nfwrite - write: %u\n", block_header->rawSize);

    uint32_t blockSize = nffile->fileHeader->blockSize;
    dataBlockV3_t *buff = NULL;
    dataBlockV3_t *wptr = NULL;
    // resolve compression: block-level overrides file default
    int compression = (block_header->compression == UNDEF_COMPRESSED) ? nffile->compression : block_header->compression;
    int level = nffile->compressionLevel;
    dbg_printf("nfwrite - compression: %u\n", compression);
    switch (compression) {
        case NOT_COMPRESSED:
            wptr = block_header;
            wptr->discSize = wptr->rawSize;
            break;
        case LZO_COMPRESSED:
            buff = NewDataBlock(blockSize);
            if (Compress_Block_LZO(block_header, buff, nffile->fileHeader->blockSize) < 0) {
                FreeDataBlock(buff);
                return 0;
            }
            wptr = buff;
            break;
        case LZ4_COMPRESSED:
            buff = NewDataBlock(blockSize);
            if (Compress_Block_LZ4(block_header, buff, nffile->fileHeader->blockSize, level) < 0) {
                FreeDataBlock(buff);
                return 0;
            }
            wptr = buff;
            break;
        case BZ2_COMPRESSED:
            buff = NewDataBlock(blockSize);
            if (Compress_Block_BZ2(block_header, buff, nffile->fileHeader->blockSize) < 0) {
                FreeDataBlock(buff);
                return 0;
            }
            wptr = buff;
            break;
        case ZSTD_COMPRESSED:
            buff = NewDataBlock(blockSize);
            if (Compress_Block_ZSTD(block_header, buff, nffile->fileHeader->blockSize, level) < 0) {
                FreeDataBlock(buff);
                return 0;
            }
            wptr = buff;
            break;
        default:
            LogError("Unknown compression type: %u - use no compression", compression);
            wptr = block_header;
            wptr->discSize = wptr->rawSize;
            compression = NOT_COMPRESSED;
            break;
    }

    wptr->compression = compression;

    dbg_printf("WriteBlock - type: %u, size: %u, compressed: %u\n", wptr->type, wptr->rawSize, wptr->discSize);

    // reserve file space and record directory entry atomically
    // guarantees directory order matches file offset order
    pthread_mutex_lock(&nffile->wlock);
    off_t dstOffset = atomic_fetch_add(&nffile->blockOffset, wptr->discSize);
    int ok = AddBlock(&nffile->blockList, wptr->type, (uint64_t)dstOffset, wptr->discSize);
    pthread_mutex_unlock(&nffile->wlock);

    // write at reserved offset — parallel, no lock needed
    ssize_t writeSize = wptr->discSize;
    ssize_t ret = pwrite(nffile->fd, (void *)wptr, writeSize, dstOffset);
    FreeDataBlock(buff);
    if (ret != writeSize) {
        LogError("pwrite() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    return ok;

}  // End of nfwrite

/*
 * nfwriter worker thread.
 * Reads blocks from processQueue, compress and writes them to file
 * blocks are processed as generic blocks
 */
static void *nfwriter(void *arg) {
    nffileV3_t *nffile = (nffileV3_t *)arg;

    dbg_printf("nfwriter %p enter\n", (void *)pthread_self());
    /* disable signal handling */
    sigset_t set = {0};
    sigfillset(&set);
    pthread_sigmask(SIG_SETMASK, &set, NULL);

    dataBlockV3_t *block_header;
    while (1) {
        block_header = queue_pop(nffile->processQueue);
        if (block_header == QUEUE_CLOSED) break;

        dbg_printf("nfwriter - next block - type: %u, size: %u\n", block_header->type, block_header->rawSize);
        int ok = 1;
        if (block_header->rawSize) {
            // block with data
            dbg_printf("nfwriter %p write\n", (void *)pthread_self());
            ok = nfwrite(nffile, block_header);
        }
        FreeDataBlock(block_header);

        if (!ok) break;
    }

    dbg_printf("nfwriter %p exit\n", (void *)pthread_self());
    pthread_exit(NULL);

    /* UNREACHED */

}  // End of nfwriter

// Common setup for a freshly opened write fd.
// Takes ownership of fd and fileName on success.
// On failure, closes fd, unlinks fileName, and returns NULL.
static nffileV3_t *InitNewFileV3(int fd, char *fileName, uint32_t creator, uint16_t compression, uint16_t compressionLevel) {
    // if file is not compressed, 2 workers are fine.
    uint32_t NumThreads = compression == NOT_COMPRESSED ? 2 : NumWorkers;

    nffileV3_t *nffile = NewFile(NumThreads, DefaultQueueSize);
    if (!nffile) {
        LogError("NewFile() failed");
        close(fd);
        unlink(fileName);
        free(fileName);
        return NULL;
    }

    nffile->fd = fd;
    nffile->fileName = fileName;
    nffile->compression = compression;
    nffile->compressionLevel = compressionLevel;

    nffile->map = NULL;
    nffile->mapSize = 0;
    nffile->stat_record = calloc(1, sizeof(stat_record_t));
    nffile->fileHeader = calloc(1, sizeof(fileHeaderV3_t));
    nffile->blockList.entries = malloc(DIR_INIT_CAPACITY * sizeof(directoryEntryV3_t));

    if (!nffile->stat_record || !nffile->blockList.entries || !nffile->fileHeader) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        DeleteFile(nffile);
        return NULL;
    }

    nffile->stat_record->msecFirstSeen = 0x7fffffffffffffffLL;
    nffile->blockList.capacity = DIR_INIT_CAPACITY;

    // init header — offDirectory = 0 marks "not yet finalized"
    *nffile->fileHeader = (fileHeaderV3_t){
        .magic = HEADER_MAGIC_V3,
        .layoutVersion = LAYOUT_VERSION_3,
        .nfdVersion = NFDVERSION,
        .created = (uint64_t)time(NULL),
        .creator = creator,
        .flags = 0,
        .blockSize = BLOCK_SIZE_V3,
        .dirSize = 0,
        .offDirectory = 0,
        .reserved = 0,
    };

    ssize_t ret = write(fd, nffile->fileHeader, sizeof(fileHeaderV3_t));
    if (ret != (ssize_t)sizeof(fileHeaderV3_t)) {
        LogError("write() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        DeleteFile(nffile);
        return NULL;
    }

    // initialize atomic write offset past the header
    atomic_init(&nffile->blockOffset, (off_t)sizeof(fileHeaderV3_t));

    dbg_printf("InitNewFile: %s, compression: %d, level: %d, workers: %u\n", fileName, nffile->compression, nffile->compressionLevel, NumThreads);

    // kick off nfwriter
    for (int i = 0; i < (int)NumThreads; i++) {
        pthread_t tid;
        int err = pthread_create(&tid, NULL, nfwriter, (void *)nffile);
        if (err) {
            nffile->worker[i] = 0;
            LogError("pthread_create() error in %s line %d: %s", __FILE__, __LINE__, strerror(err));
            DeleteFile(nffile);
            return NULL;
        }
        nffile->worker[i] = tid;
    }

    return nffile;

}  // End of InitNewFileV3

// Create a new nffileV3 for writing
nffileV3_t *OpenNewFileV3(const char *filename, uint32_t creator, uint16_t compression, uint16_t compressionLevel, uint32_t encryption) {
    (void)encryption;

    if (!filename) return NULL;

#ifndef HAVE_ZSTD
    if (compression == ZSTD_COMPRESSED) {
        LogError("ZSTD compression not compiled in");
        return NULL;
    }
#endif
#ifndef HAVE_BZ2
    if (compression == BZ2_COMPRESSED) {
        LogError("BZIP2 compression not compiled in");
        return NULL;
    }
#endif

    int fd = open(filename, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0) {
        LogError("open() '%s': %s", filename, strerror(errno));
        return NULL;
    }

    char *name = strdup(filename);
    if (!name) {
        LogError("strdup() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        close(fd);
        unlink(filename);
        return NULL;
    }

    return InitNewFileV3(fd, name, creator, compression, compressionLevel);

}  // End of OpenNewFileV3

// Create a new temporary nffileV3 for writing.
// template must be a writable string ending with "XXXXXX" (per mkstemp).
// On success, template is modified in-place to the actual filename.
nffileV3_t *OpenNewFileTmpV3(const char *tmplate, uint32_t creator, uint16_t compression, uint16_t compressionLevel, uint32_t encryption) {
    (void)encryption;

    if (!tmplate) return NULL;

#ifndef HAVE_ZSTD
    if (compression == ZSTD_COMPRESSED) {
        LogError("ZSTD compression not compiled in");
        return NULL;
    }
#endif
#ifndef HAVE_BZ2
    if (compression == BZ2_COMPRESSED) {
        LogError("BZIP2 compression not compiled in");
        return NULL;
    }
#endif

    char *tmp = strdup(tmplate);
    if (!tmp) {
        LogError("strdup() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    int fd = mkstemp(tmp);
    if (fd < 0) {
        LogError("mkstemp() '%s': %s", tmplate, strerror(errno));
        free(tmp);
        return NULL;
    }

    // mkstemp creates with 0600 — adjust to match OpenNewFileV3 permissions
    if (fchmod(fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) < 0) {
        LogError("fchmod() '%s': %s", tmp, strerror(errno));
        close(fd);
        unlink(tmp);
        free(tmp);
        return NULL;
    }

    return InitNewFileV3(fd, tmp, creator, compression, compressionLevel);

}  // End of OpenNewFileTmpV3

//
// WriteBlockV3 — pushes a block onto the processQueue of nffileV3
// Returns a new empty defult datablock
void *WriteBlockV3(nffileV3_t *nffile, void *blockHeader) {
    if (blockHeader == NULL) {
        return NewDataBlock(nffile->fileHeader->blockSize);
    }

    dataBlockV3_t *dataBlock = (dataBlockV3_t *)blockHeader;
    if (dataBlock->rawSize != 0) {
        // empty blocks need not to be written
        dbg_printf("WriteBlock - push block with size: %u\n", dataBlock->rawSize);
        queue_push(nffile->processQueue, dataBlock);
        dataBlock = NewDataBlock(nffile->fileHeader->blockSize);
    }
    return dataBlock;

}  // End of WriteBlockV3

//
// WriteBlockV3 — pushes a block onto the processQueue of nffileV3
// Returns a new empty defult datablock
flowBlockV3_t *PushBlockV3(queue_t *queue, flowBlockV3_t *blockHeader) {
    if (blockHeader == NULL) {
        return NewFlowBlock(BLOCK_SIZE_V3);
    }

    if (blockHeader->rawSize != 0) {
        // empty blocks need not to be written
        dbg_printf("PushBlockV3 - push block with size: %u\n", blockHeader->rawSize);
        queue_push(queue, blockHeader);
        blockHeader = NewFlowBlock(BLOCK_SIZE_V3);
    } else {
        dbg_printf("PushBlockV3 - skip push block with size: %u\n", blockHeader->rawSize);
    }
    return blockHeader;

}  // End of PushBlockV3

/*
 * FlushBlockV3 - pushes a block onto the processQueue of nffileV3
 * if empty, frees block
 */
void FlushBlockV3(nffileV3_t *nffile, void *blockHeader) {
    if (blockHeader != NULL) {
        dataBlockV3_t *dataBlock = (dataBlockV3_t *)blockHeader;
        if (dataBlock->rawSize != 0) {
            dbg_printf("Flush block of size: %u\n", dataBlock->rawSize);
            queue_push(nffile->processQueue, dataBlock);
        } else {
            dbg_printf("Skip Flush block of size: %u\n", dataBlock->rawSize);
            FreeDataBlock(blockHeader);
        }
    }
}  // End of FlushBlock

// Called during FlushFileV3(), after all data blocks are written.
static void WriteStatsBlock(nffileV3_t *nffile) {
    // fix empty stat record
    if (nffile->stat_record->msecFirstSeen == 0x7fffffffffffffffLL) nffile->stat_record->msecFirstSeen = 0;

    dataBlockV3_t *dataBlock = NewDataBlock(nffile->fileHeader->blockSize);
    *dataBlock = (dataBlockV3_t){
        .type = BLOCK_TYPE_STATS,
        .discSize = sizeof(dataBlockV3_t) + sizeof(stat_record_t),
        .rawSize = sizeof(dataBlockV3_t) + sizeof(stat_record_t),
        .compression = NOT_COMPRESSED,
        .encryption = NOT_ENCRYPTED,
    };
    uint8_t *buf = (uint8_t *)dataBlock + sizeof(dataBlockV3_t);
    memcpy(buf, nffile->stat_record, sizeof(stat_record_t));

    queue_push(nffile->processQueue, dataBlock);

}  // End of WriteStatsBlock

static void WriteIdentBlock(nffileV3_t *nffile) {
    const char *ident = nffile->ident ? nffile->ident : "none";
    uint32_t len = (uint32_t)strlen(ident) + 1;  // include NUL
    uint32_t paddedLen = (len + 7) & ~7u;        // 8-byte aligned

    dataBlockV3_t *dataBlock = NewDataBlock(nffile->fileHeader->blockSize);
    *dataBlock = (dataBlockV3_t){
        .type = BLOCK_TYPE_IDENT,
        .discSize = sizeof(dataBlockV3_t) + paddedLen,
        .rawSize = sizeof(dataBlockV3_t) + paddedLen,
        .compression = NOT_COMPRESSED,
        .encryption = NOT_ENCRYPTED,
    };
    char *buf = (char *)dataBlock + sizeof(dataBlockV3_t);
    memcpy(buf, ident, len);

    queue_push(nffile->processQueue, dataBlock);

}  // End of WriteIdentBlock

/*
 * Called at end of FlushFileV3():
 *   1. Write blockDirectoryV3_t header + entries[]
 *   2. Write fileFooterV3_t
 *   3. Rewrite fileHeaderV3_t at offset 0 with final offDirectory/dirSize
 */
static int WriteDirectory(nffileV3_t *nffile) {
    // get blockdirectory offset from atomic write position
    off_t dirOffset = atomic_load(&nffile->blockOffset);

    // --- write directory header + entries ---
    blockDirectoryV3_t dirHdr = {
        .magic = DIRECTORY_MAGIC,
        .numEntries = nffile->blockList.count,
    };

    ssize_t ret = pwrite(nffile->fd, &dirHdr, sizeof(blockDirectoryV3_t), dirOffset);
    if (ret != (ssize_t)sizeof(blockDirectoryV3_t)) return 0;

    off_t pos = dirOffset + sizeof(blockDirectoryV3_t);
    size_t entriesSize = nffile->blockList.count * sizeof(directoryEntryV3_t);
    if (entriesSize > 0) {
        ret = pwrite(nffile->fd, nffile->blockList.entries, entriesSize, pos);
        if (ret != (ssize_t)entriesSize) return 0;
        pos += entriesSize;
    }

    uint32_t dirSize = (uint32_t)(sizeof(blockDirectoryV3_t) + entriesSize);

    // --- write footer ---
    fileFooterV3_t footer = {
        .magic = FOOTER_MAGIC_V3,
        .dirSize = dirSize,
        .offDirectory = (uint64_t)dirOffset,
        .checksum = 0,  // TODO: xxHash64 over directory region
    };

    ret = pwrite(nffile->fd, &footer, sizeof(fileFooterV3_t), pos);
    if (ret != (ssize_t)sizeof(fileFooterV3_t)) return 0;

    // --- update header with final directory location ---
    nffile->fileHeader->offDirectory = (uint64_t)dirOffset;
    nffile->fileHeader->dirSize = dirSize;

    ret = pwrite(nffile->fd, nffile->fileHeader, sizeof(fileHeaderV3_t), 0);
    if (ret != (ssize_t)sizeof(fileHeaderV3_t)) return 0;

    return 1;

}  // End of WriteDirectory

/*
 *  FlushFileV3 — finalize a file opened for writing.
 *  Caller flushes last data block via WriteBlockV3() before calling this.
 *    1. Write stats block
 *    2. Write directory + footer + rewrite header
 *    3. fsync
 */
int FlushFileV3(nffileV3_t *nffile) {
    // push stat record in processQueue
    WriteStatsBlock(nffile);
    WriteIdentBlock(nffile);

    // done - close queue
    queue_close(nffile->processQueue);

    // wait for queue to be empty
    queue_sync(nffile->processQueue);

    // writers terminate, on queue closed and empty
    joinWorkers(nffile);

    // nffile is quiet now - add directory and footer
    if (!WriteDirectory(nffile)) {
        LogError("Failed to write block directory - file may be corrupted");
    }

    fsync(nffile->fd);

    return 1;

} /* End of FlushFile */
