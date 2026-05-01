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
#include "nfconf.h"
#include "nfdump.h"
#include "nffileV3.h"
#include "nfxV4.h"
#include "queue.h"
#include "util.h"
#include "vcs_track.h"

#define XXH_INLINE_ALL
#include "xxhash.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef HAVE_LIBSODIUM
#include <sodium.h>
#endif

#include "nfcrypto.h"

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
    if (nffile->crypto) {
#ifdef HAVE_LIBSODIUM
        sodium_memzero(nffile->crypto->encKey, sizeof(nffile->crypto->encKey));
#endif
        free(nffile->crypto);
    }

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
    dataBlockV3_t *encBuf = NULL;
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

    /* ----------------------------------------------------------------
     * Option A: reserve the file offset BEFORE encrypting so we can use
     * dstOffset as the nonce differentiator.
     *
     * On-disk size with encryption = compressed discSize + 16-byte AEAD tag.
     * Without encryption on-disk size = compressed discSize.
     * ---------------------------------------------------------------- */
    uint32_t onDiskSize = wptr->discSize;
#ifdef HAVE_LIBSODIUM
    if (nffile->crypto) {
        onDiskSize += (uint32_t)crypto_aead_chacha20poly1305_ietf_ABYTES; /* +16 */
    }
#endif

    // reserve file space and record directory entry atomically
    pthread_mutex_lock(&nffile->wlock);
    off_t dstOffset = atomic_fetch_add(&nffile->blockOffset, onDiskSize);
    int ok = AddBlock(&nffile->blockList, wptr->type, (uint64_t)dstOffset, onDiskSize);
    pthread_mutex_unlock(&nffile->wlock);

#ifdef HAVE_LIBSODIUM
    if (nffile->crypto) {
        /*
         * Allocate an output buffer large enough for the full on-disk block:
         * header (24 bytes) + plaintext payload + 16-byte AEAD tag.
         * Heap-allocated because nfwriter workers run in parallel.
         */
        encBuf = (dataBlockV3_t *)malloc(onDiskSize);
        if (!encBuf) {
            LogError("nfwrite: malloc(%u) for encrypt buffer: %s", onDiskSize, strerror(errno));
            FreeDataBlock(buff);
            return 0;
        }

        /* Build per-block nonce: rootNonce XOR le64(dstOffset) */
        uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES]; /* 12 bytes */
        memcpy(nonce, nffile->crypto->rootNonce, sizeof(nonce));
        uint64_t offsetLE = (uint64_t)dstOffset;
        for (int bi = 0; bi < 8; bi++) {
            nonce[bi] ^= (uint8_t)(offsetLE >> (bi * 8));
        }

        const uint8_t *plaintext = (const uint8_t *)wptr + sizeof(dataBlockV3_t);
        uint32_t plainLen = wptr->discSize - (uint32_t)sizeof(dataBlockV3_t);
        uint8_t *ciphertext = (uint8_t *)encBuf + sizeof(dataBlockV3_t);
        unsigned long long cipherLen = 0;

        int rc = crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, &cipherLen, plaintext, plainLen, NULL, 0, NULL, nonce, nffile->crypto->encKey);
        if (rc != 0) {
            LogError("nfwrite: encryption failed at offset %" PRId64, (int64_t)dstOffset);
            free(encBuf);
            FreeDataBlock(buff);
            return 0;
        }

        memcpy(encBuf, wptr, sizeof(dataBlockV3_t));
        encBuf->discSize = (uint32_t)(sizeof(dataBlockV3_t) + cipherLen);
        encBuf->encryption = CHACHA20_POLY1305;
        wptr = encBuf;
    }
#endif /* HAVE_LIBSODIUM */

    // compute XXH3_64bits checksum over the final on-disk payload bytes
    // (covers encrypted ciphertext + tag when encryption is active)
    wptr->checksum = 0;
    if (nffile->xxHash && wptr->discSize > (uint32_t)sizeof(dataBlockV3_t)) {
        const uint8_t *payload = (const uint8_t *)wptr + sizeof(dataBlockV3_t);
        uint32_t payloadSize = wptr->discSize - (uint32_t)sizeof(dataBlockV3_t);
        wptr->checksum = XXH3_64bits(payload, payloadSize);
    }

    // write at reserved offset — parallel, no lock needed
    ssize_t writeSize = (ssize_t)wptr->discSize;
    ssize_t ret = pwrite(nffile->fd, (void *)wptr, (size_t)writeSize, dstOffset);
    FreeDataBlock(buff);
    if (encBuf) free(encBuf);
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

static uint32_t ceil_power_of_2(uint32_t num) {
    if (num <= 1) return 1;
    if ((num & (num - 1)) == 0) return num;

    // __builtin_clz returns number of leading zeros
    return 1u << (32 - __builtin_clz(num - 1));
}  // End of ceil_power_of_2

// Common setup for a freshly opened write fd.
// Takes ownership of fd and fileName on success.
// On failure, closes fd, unlinks fileName, and returns NULL.
static nffileV3_t *InitNewFileV3(int fd, char *fileName, uint32_t creator, uint16_t compression, uint16_t compressionLevel,
                                 const crypto_ctx_t *crypto_ctx) {
    /*
     * Worker and queue sizing:
     * - Uncompressed + unencrypted: 2 workers sufficient (I/O bound).
     * - Compressed only: use the user-configured NumWorkers.
     * - Encrypted: ChaCha20-Poly1305 is ~3× slower than compression alone.
     *   Use at least 4 workers; deepen the queue proportionally so the
     *   collector never blocks waiting for a free slot.
     */
    int useEncryption = (crypto_ctx != NULL);
    uint32_t NumThreads;
    uint32_t queueDepth;
    if (useEncryption) {
        NumThreads = NumWorkers < 4 ? 4 : NumWorkers;
        queueDepth = ceil_power_of_2(NumThreads * DefaultQueueSize);
        if (compression <= NOT_COMPRESSED) {
#ifdef HAVE_ZSTD
            compression = ZSTD_COMPRESSED;
            compressionLevel = 1;
#else
            compression = LZ4_COMPRESSED;
            compressionLevel = 0;  // LZ4_compress_default — fast path, no HC
#endif
        }
    } else {
        // no encryption
        if (compression == NOT_COMPRESSED) {
            NumThreads = 2;
            queueDepth = DefaultQueueSize;
        } else {
            NumThreads = NumWorkers;
            queueDepth = DefaultQueueSize;
        }
    }

    nffileV3_t *nffile = NewFile(NumThreads, queueDepth);
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
    nffile->crypto = NULL;
    nffile->xxHash = ConfGetValue("xxhash") ? 1 : 0;

#ifdef HAVE_LIBSODIUM
    nffile->xxHash = 1;  // force xxHash with encryption
    /* freshSalt is populated by DeriveKeyForNewFile() and written to the
     * cryptoHeaderBlock so the reader can re-derive the same key. */
    uint8_t freshSalt[32] = {0};
    if (crypto_ctx) {
        nffile->crypto = calloc(1, sizeof(nffile_crypto_t));
        if (!nffile->crypto) {
            LogError("InitNewFileV3: calloc(nffile_crypto_t) failed: %s", strerror(errno));
            DeleteFile(nffile);
            return NULL;
        }
        if (!DeriveKeyForNewFile(crypto_ctx, nffile->crypto, freshSalt)) {
            LogError("InitNewFileV3: key derivation failed for '%s'", fileName);
            DeleteFile(nffile);
            return NULL;
        }
    }
#endif

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

    if (nffile->crypto) {
        nffile->fileHeader->flags |= FILE_FLAG_ENCRYPTED;
    }

    ssize_t ret = write(fd, nffile->fileHeader, sizeof(fileHeaderV3_t));
    if (ret != (ssize_t)sizeof(fileHeaderV3_t)) {
        LogError("write() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        DeleteFile(nffile);
        return NULL;
    }

    // initialize atomic write offset past the header
    atomic_init(&nffile->blockOffset, (off_t)sizeof(fileHeaderV3_t));

#ifdef HAVE_LIBSODIUM
    /*
     * Write the cryptoHeaderBlock immediately after the file header.
     * Always plaintext + uncompressed so the reader can extract KDF
     * parameters and derive the key before reading any data block.
     */
    if (nffile->crypto) {
        cryptoHeaderBlock_t cryptoHdr = {
            .type = BLOCK_TYPE_META,
            .discSize = sizeof(cryptoHeaderBlock_t),
            .rawSize = sizeof(cryptoHeaderBlock_t),
            .compression = NOT_COMPRESSED,
            .encryption = NOT_ENCRYPTED,
            .algorithm = (uint16_t)nffile->crypto->algorithm,
            .kdfType = (uint16_t)CRYPTO_KDF_ARGON2ID,
            .kdfIterations = 0,  //
        };
        memcpy(cryptoHdr.salt, freshSalt, sizeof(cryptoHdr.salt));
        memcpy(cryptoHdr.rootNonce, nffile->crypto->rootNonce, sizeof(cryptoHdr.rootNonce));

        /* keyCheck = AEAD tag of encrypting 16 zero bytes under derived key + rootNonce */
        static const uint8_t plain[16] = {0};
        uint8_t out[16 + crypto_aead_chacha20poly1305_ietf_ABYTES];
        unsigned long long outlen = 0;
        crypto_aead_chacha20poly1305_ietf_encrypt(out, &outlen, plain, sizeof(plain), NULL, 0, NULL, nffile->crypto->rootNonce,
                                                  nffile->crypto->encKey);
        memcpy(cryptoHdr.keyCheck, out + 16, 16);

        cryptoHdr.checksum = 0;
        if (nffile->xxHash) {
            const uint8_t *p = (const uint8_t *)&cryptoHdr + sizeof(dataBlockV3_t);
            uint32_t psz = cryptoHdr.discSize - (uint32_t)sizeof(dataBlockV3_t);
            cryptoHdr.checksum = XXH3_64bits(p, psz);
        }

        off_t hdrOff = atomic_fetch_add(&nffile->blockOffset, sizeof(cryptoHeaderBlock_t));
        (void)AddBlock(&nffile->blockList, BLOCK_TYPE_META, (uint64_t)hdrOff, sizeof(cryptoHeaderBlock_t));
        ret = pwrite(fd, &cryptoHdr, sizeof(cryptoHeaderBlock_t), hdrOff);
        if (ret != (ssize_t)sizeof(cryptoHeaderBlock_t)) {
            LogError("write() crypto header error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            DeleteFile(nffile);
            return NULL;
        }
    }
#endif /* HAVE_LIBSODIUM */

    dbg_printf("InitNewFile: %s, compression: %d, level: %d, workers: %u, %s\n", fileName, nffile->compression, nffile->compressionLevel, NumThreads,
               crypto_ctx ? "encrypted" : "not encrypted");

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
nffileV3_t *OpenNewFileV3(const char *filename, uint32_t creator, uint16_t compression, uint16_t compressionLevel, const crypto_ctx_t *crypto_ctx) {
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

    return InitNewFileV3(fd, name, creator, compression, compressionLevel, crypto_ctx);

}  // End of OpenNewFileV3

// Create a new temporary nffileV3 for writing.
// template must be a writable string ending with "XXXXXX" (per mkstemp).
// On success, template is modified in-place to the actual filename.
nffileV3_t *OpenNewFileTmpV3(const char *tmplate, uint32_t creator, uint16_t compression, uint16_t compressionLevel, const crypto_ctx_t *crypto_ctx) {
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

    return InitNewFileV3(fd, tmp, creator, compression, compressionLevel, crypto_ctx);

}  // End of OpenNewFileTmpV3

//
// WriteBlockV3 — pushes a block onto the processQueue of nffileV3
// Returns a new empty defult datablock
void WriteBlockV3(nffileV3_t *nffile, void *blockHeader) {
    if (blockHeader == NULL) return;

    dataBlockV3_t *dataBlock = (dataBlockV3_t *)blockHeader;
    if (dataBlock->rawSize != 0) {
        // empty blocks need not to be written
        dbg_printf("WriteBlock - push block type: %u, with size: %u\n", dataBlock->type, dataBlock->rawSize);
        queue_push(nffile->processQueue, dataBlock);
    }

}  // End of WriteBlockV3

//
// PushBlockV3 — pushes a block onto the processQueue of nffileV3
// Returns a new empty defult datablock
void PushBlockV3(queue_t *queue, void *blockHeader) {
    if (blockHeader == NULL) return;

    dataBlockV3_t *dataBlockV3 = (dataBlockV3_t *)blockHeader;
    if (dataBlockV3->rawSize != 0) {
        // empty blocks need not to be written
        dbg_printf("PushBlockV3 - push block type: %u, with size: %u\n", dataBlockV3->type, dataBlockV3->rawSize);
        queue_push(queue, blockHeader);
    }

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
    // Skip stats block for non-flow files (maxmind, tor, etc.) that never
    // accumulate any stats — identified by the sentinel set in NewFile().
    if (nffile->stat_record->msecFirstSeen == 0x7fffffffffffffffLL) return;

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

// Total on-disk size of every IDENT block — fixed so ChangeIdent() is a
// simple in-place payload overwrite with no size arithmetic.
// IDENTLEN (128) is already a multiple of 8, so no padding is required.
#define IDENT_BLOCK_SIZE ((uint32_t)(sizeof(dataBlockV3_t) + IDENTLEN))

static void WriteIdentBlock(nffileV3_t *nffile) {
    // Skip ident block for non-flow files (maxmind, tor, etc.) that have no
    // source identity.  ChangeIdent() will reject such files as well.
    if (!nffile->ident) return;

    dataBlockV3_t *dataBlock = NewDataBlock(nffile->fileHeader->blockSize);
    *dataBlock = (dataBlockV3_t){
        .type = BLOCK_TYPE_IDENT,
        .discSize = IDENT_BLOCK_SIZE,
        .rawSize = IDENT_BLOCK_SIZE,
        .compression = NOT_COMPRESSED,
        .encryption = NOT_ENCRYPTED,
    };
    // strncpy zero-fills the entire IDENTLEN region when ident is shorter
    char *buf = (char *)dataBlock + sizeof(dataBlockV3_t);
    strncpy(buf, nffile->ident, IDENTLEN);

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

    // --- compute directory checksum over the serialized directory in memory ---
    // uses the same two regions already written to disk: dirHdr + entries[]
    uint64_t dirChecksum = 0;
    if (nffile->xxHash) {
        XXH3_state_t hashState;
        XXH3_64bits_reset(&hashState);
        XXH3_64bits_update(&hashState, &dirHdr, sizeof(blockDirectoryV3_t));
        if (entriesSize > 0) XXH3_64bits_update(&hashState, nffile->blockList.entries, entriesSize);
        dirChecksum = XXH3_64bits_digest(&hashState);
    }

    // --- write footer ---
    fileFooterV3_t footer = {
        .magic = FOOTER_MAGIC_V3,
        .dirSize = dirSize,
        .offDirectory = (uint64_t)dirOffset,
        .checksum = dirChecksum,
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

/*
 * ChangeIdent — replace the ident string in a closed nffile v3.
 *
 * WriteIdentBlock() always allocates a fixed IDENT_BLOCK_SIZE on-disk block
 * (sizeof(dataBlockV3_t) + IDENTLEN bytes).  The block header fields are
 * therefore constant for any ident value, so ChangeIdent only needs to
 * overwrite the IDENTLEN-byte payload region — no block header rewrite, no
 * size arithmetic, no heap allocation.
 *
 * Algorithm:
 *   1. Open the file R/W.
 *   2. Read and validate the file header.
 *   3. Read the block directory header.
 *   4. Scan directory entries one-by-one to find BLOCK_TYPE_IDENT.
 *   5. pwrite IDENTLEN zero-filled bytes (new ident, NUL-padded) at
 *      entry.offset + sizeof(dataBlockV3_t).  Block header is untouched.
 *   6. fsync and close.
 *
 * Returns 1 on success, 0 on error.
 */
int ChangeIdent(const char *filename, const char *ident) {
    if (!filename || !ident) return 0;

    if (strlen(ident) >= IDENTLEN) {
        LogError("ChangeIdent: ident '%s' too long (max %u characters)", ident, IDENTLEN - 1);
        return 0;
    }

    // --- open file for read/write ---
    int fd = open(filename, O_RDWR);
    if (fd < 0) {
        LogError("ChangeIdent open() '%s': %s", filename, strerror(errno));
        return 0;
    }

    struct stat sb;
    if (fstat(fd, &sb) < 0) {
        LogError("ChangeIdent fstat() '%s': %s", filename, strerror(errno));
        close(fd);
        return 0;
    }
    size_t fileSize = (size_t)sb.st_size;

    // --- read and validate file header ---
    fileHeaderV3_t fileHeader;
    ssize_t ret = pread(fd, &fileHeader, sizeof(fileHeaderV3_t), 0);
    if (ret != (ssize_t)sizeof(fileHeaderV3_t)) {
        LogError("ChangeIdent: failed to read header from '%s'", filename);
        close(fd);
        return 0;
    }
    if (fileHeader.magic != HEADER_MAGIC_V3 || fileHeader.layoutVersion != LAYOUT_VERSION_3) {
        LogError("ChangeIdent: bad magic or version in '%s'", filename);
        close(fd);
        return 0;
    }
    if (fileHeader.flags & FILE_FLAG_ENCRYPTED) {
        LogError("ChangeIdent: cannot modify ident in encrypted file '%s'", filename);
        close(fd);
        return 0;
    }
    if (fileHeader.offDirectory == 0 || fileHeader.offDirectory >= fileSize) {
        LogError("ChangeIdent: invalid directory offset in '%s'", filename);
        close(fd);
        return 0;
    }

    // --- read block directory header ---
    blockDirectoryV3_t dirHdr;
    ret = pread(fd, &dirHdr, sizeof(blockDirectoryV3_t), (off_t)fileHeader.offDirectory);
    if (ret != (ssize_t)sizeof(blockDirectoryV3_t) || dirHdr.magic != DIRECTORY_MAGIC) {
        LogError("ChangeIdent: failed to read directory from '%s'", filename);
        close(fd);
        return 0;
    }

    if (dirHdr.numEntries == 0) {
        LogError("ChangeIdent: empty directory in '%s'", filename);
        close(fd);
        return 0;
    }

    // --- scan directory entries one-by-one to find the IDENT block ---
    // No heap allocation: entries are small and we stop at the first hit.
    off_t entryBase = (off_t)fileHeader.offDirectory + (off_t)sizeof(blockDirectoryV3_t);
    off_t identPayloadOffset = -1;
    for (uint32_t i = 0; i < dirHdr.numEntries; i++) {
        directoryEntryV3_t entry;
        ret = pread(fd, &entry, sizeof(directoryEntryV3_t), entryBase + (off_t)(i * sizeof(directoryEntryV3_t)));
        if (ret != (ssize_t)sizeof(directoryEntryV3_t)) {
            LogError("ChangeIdent: failed to read directory entry %u from '%s'", i, filename);
            close(fd);
            return 0;
        }
        if (entry.type == BLOCK_TYPE_IDENT) {
            // Verify the on-disk block was written by the current code, which
            // always allocates IDENT_BLOCK_SIZE bytes.  Older files have a
            // variable-size block that cannot safely receive a full IDENTLEN
            // payload write; tell the user to rewrite the file first.
            if (entry.size < IDENT_BLOCK_SIZE) {
                LogError(
                    "ChangeIdent: IDENT block in '%s' is %u bytes (need %u); "
                    "rewrite with 'nfdump -r <in> -w <out>' to upgrade the file first",
                    filename, entry.size, IDENT_BLOCK_SIZE);
                close(fd);
                return 0;
            }
            identPayloadOffset = (off_t)entry.offset + (off_t)sizeof(dataBlockV3_t);
            break;
        }
    }
    if (identPayloadOffset < 0) {
        LogError("ChangeIdent: no IDENT block found in '%s' - not a flow file", filename);
        close(fd);
        return 0;
    }

    // --- overwrite only the payload bytes ---
    // WriteIdentBlock() always writes a fixed IDENT_BLOCK_SIZE block, so the
    // block header (type, discSize, rawSize, compression, encryption) is
    // identical for every possible ident string — no need to touch it.
    // strncpy zero-fills the remainder, giving a clean NUL-padded payload.
    char buf[IDENTLEN];
    strncpy(buf, ident, IDENTLEN);
    ret = pwrite(fd, buf, IDENTLEN, identPayloadOffset);
    if (ret != IDENTLEN) {
        LogError("ChangeIdent: pwrite() ident payload '%s': %s", filename, strerror(errno));
        close(fd);
        return 0;
    }

    fsync(fd);
    close(fd);

    return 1;

}  // End of ChangeIdent
