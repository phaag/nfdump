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
#include "nfconvert.h"
#include "nfdump.h"
#include "nffileV3.h"
#include "nfxV4.h"
#include "queue.h"
#include "util.h"

// Decompress a single data block located at entry offset/size in the mmap.
// Returns a newly allocated block (caller must FreeDataBlock), or NULL on error.
static dataBlockV3_t *nfread(nffileV3_t *nffile, const directoryEntryV3_t *entry) {
    // bounds check: entry must fit inside the mapped region
    if ((size_t)entry->offset + entry->size > nffile->mapSize) {
        LogError("Corrupt data file: block at offset %" PRIu64 " extends beyond EOF", entry->offset);
        return NULL;
    }

    dataBlockV3_t *dataBlock = (dataBlockV3_t *)(nffile->map + entry->offset);

    // validate on-disk size
    if (dataBlock->discSize < sizeof(dataBlockV3_t) || dataBlock->discSize != entry->size) {
        LogError("Block size mismatch at offset %" PRIu64 ": header=%u, dir=%u", entry->offset, dataBlock->discSize, entry->size);
        return NULL;
    }

    if (dataBlock->rawSize > nffile->fileHeader->blockSize || dataBlock->rawSize == 0) {
        LogError("Block rawSize error %u at offset %" PRIu64, dataBlock->rawSize, entry->offset);
        return NULL;
    }

    dbg_printf("ReadBlock - type: %u, size: %u, compression: %u\n", dataBlock->type, dataBlock->discSize, dataBlock->compression);

    uint32_t blockSize = nffile->fileHeader->blockSize;
    int compression = dataBlock->compression;
    dataBlockV3_t *outBlock = NULL;

    switch (compression) {
        case UNDEF_COMPRESSED:
        case NOT_COMPRESSED: {
            // uncompressed block — copy out of mmap so consumer can free() it normally
            outBlock = NewDataBlock(blockSize);
            if (!outBlock) return NULL;
            memcpy(outBlock, dataBlock, dataBlock->discSize);
            break;
        }
        case LZO_COMPRESSED:
            outBlock = NewDataBlock(blockSize);
            if (!outBlock) return NULL;
            if (Uncompress_Block_LZO(dataBlock, outBlock, blockSize) < 0) {
                FreeDataBlock(outBlock);
                return NULL;
            }
            break;
        case LZ4_COMPRESSED:
            outBlock = NewDataBlock(blockSize);
            if (!outBlock) return NULL;
            if (Uncompress_Block_LZ4(dataBlock, outBlock, blockSize) < 0) {
                FreeDataBlock(outBlock);
                return NULL;
            }
            break;
        case BZ2_COMPRESSED:
            outBlock = NewDataBlock(blockSize);
            if (!outBlock) return NULL;
            if (Uncompress_Block_BZ2(dataBlock, outBlock, blockSize) < 0) {
                FreeDataBlock(outBlock);
                return NULL;
            }
            break;
        case ZSTD_COMPRESSED:
            outBlock = NewDataBlock(blockSize);
            if (!outBlock) return NULL;
            if (Uncompress_Block_ZSTD(dataBlock, outBlock, blockSize) < 0) {
                FreeDataBlock(outBlock);
                return NULL;
            }
            break;
        default:
            LogError("Unknown compression type: %u - skip block", compression);
            return NULL;
    }

    return outBlock;

}  // End of nfread

static void *nfreader(void *arg) {
    nffileV3_t *nffile = (nffileV3_t *)arg;

    dbg_printf("nfreader enter: %p\n", (void *)pthread_self());
    /* Signal handling */
    sigset_t set = {0};
    sigfillset(&set);
    pthread_sigmask(SIG_SETMASK, &set, NULL);

    const blockDirectoryV3_t *dir = nffile->blockDirectory;
    unsigned blockCount = 0;
    const long pageSize = sysconf(_SC_PAGESIZE);

    for (uint32_t i = 0; i < dir->numEntries; i++) {
        const directoryEntryV3_t *entry = &dir->entries[i];

        // skip metadata blocks — already extracted in OpenFileV3
        if (entry->type == BLOCK_TYPE_STATS || entry->type == BLOCK_TYPE_IDENT) {
            dbg_printf("Skip block type: %u\n", entry->type);
            continue;
        }

        dataBlockV3_t *dataBlock = nfread(nffile, entry);
        if (!dataBlock) {
            LogError("nfreader: failed to read block %u at offset %" PRIu64, i, entry->offset);
            break;
        }

        if (queue_push(nffile->processQueue, (void *)dataBlock) == QUEUE_CLOSED) {
            FreeDataBlock(dataBlock);
            dbg_printf("nfreader - processQueue closed\n");
            break;
        }

        blockCount++;
        dbg_printf("Blocks: %u\n", blockCount);

        // release mmap pages for this block — data has been copied/decompressed
        if (pageSize > 0) {
            uintptr_t bstart = (uintptr_t)(nffile->map + entry->offset);
            uintptr_t aligned = bstart & ~((uintptr_t)pageSize - 1);
            size_t len = ((bstart + entry->size) - aligned + pageSize - 1) & ~((uintptr_t)pageSize - 1);
            madvise((void *)aligned, len, MADV_DONTNEED);
        }
    }

    // done — close queue so consumer sees EOF
    queue_close(nffile->processQueue);

    dbg_printf("nfreader done - read %u blocks\n", blockCount);
    dbg_printf("nfreader exit: %p\n", (void *)pthread_self());

    pthread_exit(NULL);

}  // End of nfreader

void *ReadBlockV3(nffileV3_t *nffile) {
    void *dataBlock = queue_pop(nffile->processQueue);
    if (dataBlock == QUEUE_CLOSED) {  // EOF
        return NULL;
    }

    dbg_printf("ReadBlock - type: %u, size: %u, rawSize: %u\n", ((dataBlockV3_t *)dataBlock)->type, ((dataBlockV3_t *)dataBlock)->discSize,
               ((dataBlockV3_t *)dataBlock)->rawSize);

    return dataBlock;

}  // End of ReadBlockV3

/*
 * Maps the entire file read-only and accesses header, directory, footer,
 * Verify header, directory, footer
 * return nffileV3_t *, if file is valid, NULL otherwise
 */
nffileV3_t *mmapFileV3(const char *filename) {
    if (!filename) return NULL;

    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        LogError("open() failed for '%s': %s", filename, strerror(errno));
        return NULL;
    }

    struct stat sb;
    if (fstat(fd, &sb) < 0) {
        LogError("fstat() failed for '%s': %s", filename, strerror(errno));
        close(fd);
        return NULL;
    }

    size_t fileSize = (size_t)sb.st_size;
    if (fileSize < sizeof(fileHeaderV3_t)) {
        LogError("File size error for '%s': too small for header (%zu bytes)", filename, fileSize);
        close(fd);
        return NULL;
    }

    // map entire file read-only
    const uint8_t *map = mmap(NULL, fileSize, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        LogError("mmap() failed for '%s': %s", filename, strerror(errno));
        close(fd);
        return NULL;
    }

    // hint: sequential read pattern — enable readahead, release pages behind
    madvise((void *)map, fileSize, MADV_SEQUENTIAL);

    // validate header
    fileHeaderV3_t *fileHeader = (fileHeaderV3_t *)map;
    if (fileHeader->magic != HEADER_MAGIC_V3) {
        LogError("Bad magic 0x%X in '%s'", fileHeader->magic, filename);
        munmap((void *)map, fileSize);
        close(fd);
        return NULL;
    }

    if (fileHeader->layoutVersion == LAYOUT_VERSION_2) {
        munmap((void *)map, fileSize);
        close(fd);
        return ConvertFileV2(filename);
    }
    if (fileHeader->layoutVersion != LAYOUT_VERSION_3) {
        LogError("Unsupported layout version %u in '%s'", fileHeader->layoutVersion, filename);
        munmap((void *)map, fileSize);
        close(fd);
        return NULL;
    }

    if (fileHeader->blockSize == 0 || fileHeader->blockSize > 64 * ONE_MB) {
        LogError("Invalid blockSize %u in '%s'", fileHeader->blockSize, filename);
        munmap((void *)map, fileSize);
        close(fd);
        return NULL;
    }

    // validate footer
    fileFooterV3_t *footer = (fileFooterV3_t *)(map + fileSize - sizeof(fileFooterV3_t));
    if (footer->magic != FOOTER_MAGIC_V3) {
        LogError("Bad magic 0x%X for footer in '%s'", footer->magic, filename);
        footer = NULL;
    }

    // get blockDirectory
    blockDirectoryV3_t *blockDirectory = NULL;
    uint32_t dirSize = 0;
    if (fileHeader->offDirectory && (fileHeader->offDirectory < fileSize)) {
        blockDirectory = (blockDirectoryV3_t *)(map + fileHeader->offDirectory);
        if (blockDirectory->magic != DIRECTORY_MAGIC) {
            LogError("Bad directory magic 0x%X in header for '%s'", blockDirectory->magic, filename);
            blockDirectory = NULL;
        } else {
            // check directory size
            if ((fileHeader->offDirectory + fileHeader->dirSize) > fileSize) {
                LogError("Bad directory in header for '%s' - extends beyond EOF", filename);
                blockDirectory = NULL;
            } else {
                // valid blockDirectory
                dirSize = fileHeader->dirSize;
            }
        }
    } else {
        LogError("File '%s' not cleanly closed - try to recover", filename);
    }

    if (blockDirectory == NULL) {
        // no valid block directory found - try to recover from footer, if it is valid
        if (footer && footer->offDirectory && (footer->offDirectory < fileSize)) {
            blockDirectory = (blockDirectoryV3_t *)(map + footer->offDirectory);
        } else {
            LogError("Unable to recover - skip file: '%s'", filename);
            munmap((void *)map, fileSize);
            close(fd);
            return NULL;
        }
        if (blockDirectory->magic != DIRECTORY_MAGIC) {
            LogError("Bad directory magic 0x%X in footer for '%s'", blockDirectory->magic, filename);
            blockDirectory = NULL;
            munmap((void *)map, fileSize);
            close(fd);
            return NULL;
        }
        if ((footer->offDirectory + footer->dirSize) > fileSize) {
            LogError("Bad directory in footer for '%s' - extends beyond EOF", filename);
            munmap((void *)map, fileSize);
            close(fd);
            return NULL;
        } else {
            dirSize = footer->dirSize;
        }
    }

    // verify directory
    // TODO: verify ftr->checksum (xxHash64 over directory region)

    // verify directory entries fit
    size_t expectedDirSize = sizeof(blockDirectoryV3_t) + blockDirectory->numEntries * sizeof(directoryEntryV3_t);
    if (expectedDirSize > dirSize) {
        LogError("Directory numEntries %u exceeds dirSize in '%s'", blockDirectory->numEntries, filename);
        munmap((void *)map, fileSize);
        close(fd);
        return NULL;
    }

    // allocate handle
    nffileV3_t *nffile = NewFile(1, DefaultQueueSize);
    if (!nffile) {
        LogError("NewFile() error");
        munmap((void *)map, fileSize);
        close(fd);
        return NULL;
    }

    nffile->map = map;
    nffile->mapSize = fileSize;
    nffile->fd = fd;
    nffile->fileName = strdup(filename);
    nffile->fileHeader = fileHeader;
    nffile->fileFooter = footer;
    nffile->blockDirectory = blockDirectory;

    nffile->stat_record = calloc(1, sizeof(stat_record_t));
    if (!nffile->stat_record) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        CloseFileV3(nffile);
        return NULL;
    }

    // --- load metadata blocks via directory (pointer access, no I/O) ---
    for (uint32_t i = 0; i < blockDirectory->numEntries; i++) {
        const directoryEntryV3_t *e = &blockDirectory->entries[i];

        // bounds check: entry must fit inside the data region
        if (e->offset + e->size > fileSize) continue;

        const uint8_t *blockBase = map + e->offset;
        const dataBlockV3_t *blk = (const dataBlockV3_t *)blockBase;

        if (e->type == BLOCK_TYPE_STATS) {
            size_t payloadOff = sizeof(dataBlockV3_t);
            if (payloadOff + sizeof(stat_record_t) <= e->size && blk->rawSize == sizeof(dataBlockV3_t) + sizeof(stat_record_t)) {
                memcpy(nffile->stat_record, blockBase + payloadOff, sizeof(stat_record_t));
            }
        } else if (e->type == BLOCK_TYPE_IDENT) {
            size_t payloadOff = sizeof(dataBlockV3_t);
            size_t payloadSize = blk->rawSize - sizeof(dataBlockV3_t);
            if (payloadSize > 0 && payloadSize < 256 && payloadOff + payloadSize <= e->size) {
                // ident string is NUL-terminated in the block
                nffile->ident = strndup((const char *)(blockBase + payloadOff), payloadSize);
            }
        }
    }

    return nffile;

}  // End of mmapFileV3

nffileV3_t *OpenFileV3(const char *filename) {
    dbg_printf("OpenFile: %s\n", filename);
    // open and mmap() the file
    nffileV3_t *nffile = mmapFileV3(filename);
    if (!nffile) {
        dbg_printf("OpenFile mmap failed\n");
        return NULL;
    }

    // V2 conversion already started its own reader thread
    if (nffile->worker[0]) {
        dbg_printf("Skip nfreader as worker active\n");
        return nffile;
    }

    // kick off nfreader
    dbg_printf("Kick off nfreader\n");
    // there is only 1 reader thread -> slot 0
    pthread_t tid;
    int err = pthread_create(&tid, NULL, nfreader, (void *)nffile);
    if (err) {
        nffile->worker[0] = 0;
        LogError("pthread_create() error in %s line %d: %s", __FILE__, __LINE__, strerror(err));
        CloseFileV3(nffile);
        return NULL;
    }
    nffile->worker[0] = tid;
    return nffile;

}  // End of OpenFileV3