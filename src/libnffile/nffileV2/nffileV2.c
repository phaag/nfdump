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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_BZ2
#include <bzlib.h>
#endif

#ifdef HAVE_ZSTD
#include <zstd.h>
#endif

#ifdef HAVE_LZ4
#include <lz4.h>
#include <lz4hc.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include "id.h"
#include "logging.h"
#include "nffileV2.h"
#include "nffileV2_def.h"
#include "nfxV3.h"
#include "queue.h"
#include "uncompress.h"
#include "unistd.h"
#include "util.h"

// know layout version to v2
#define LAYOUT_VERSION_1 1
#define LAYOUT_VERSION_2 2

// known creators to v2
enum {
    CREATOR_UNKNOWN = 0,
    CREATOR_NFCAPD,
    CREATOR_NFPCAPD,
    CREATOR_SFCAPD,
    CREATOR_NFDUMP,
    CREATOR_NFANON,
    CREATOR_NFPROFILE,
    CREATOR_GEOLOOKUP,
    CREATOR_FT2NFDUMP,
    CREATOR_TORLOOKUP,
    MAX_CREATOR
};

static const char *nf_creator[MAX_CREATOR] = {
    [CREATOR_UNKNOWN] = "unknown",     [CREATOR_NFCAPD] = "nfcapd",       [CREATOR_NFPCAPD] = "nfpcapd",     [CREATOR_SFCAPD] = "sfcapd",
    [CREATOR_NFDUMP] = "nfdump",       [CREATOR_NFANON] = "nfanon",       [CREATOR_NFPROFILE] = "nfprofile", [CREATOR_GEOLOOKUP] = "geolookup",
    [CREATOR_FT2NFDUMP] = "ft2nfdump", [CREATOR_TORLOOKUP] = "torlookup",
};

/*
 * Generic data record
 * Contains any type of data, specified by type
 */
typedef struct recordHeader_s {
    // record header
    uint16_t type;  // type of data
    uint16_t size;  // size of record including this header
} recordHeader_t;

// stat_record know to v2
typedef struct stat_record_s {
    // overall stat
    uint64_t numflows;
    uint64_t numbytes;
    uint64_t numpackets;
    // flow stat
    uint64_t numflows_tcp;
    uint64_t numflows_udp;
    uint64_t numflows_icmp;
    uint64_t numflows_other;
    // bytes stat
    uint64_t numbytes_tcp;
    uint64_t numbytes_udp;
    uint64_t numbytes_icmp;
    uint64_t numbytes_other;
    // packet stat
    uint64_t numpackets_tcp;
    uint64_t numpackets_udp;
    uint64_t numpackets_icmp;
    uint64_t numpackets_other;
    // time window
    uint64_t msecFirstSeen;
    uint64_t msecLastSeen;
    // other
    uint64_t sequence_failure;
} stat_record_t;

typedef struct fileHeaderV2_s {
    uint16_t magic;  // magic to recognize nfdump file type and endian type

    uint16_t version;  // version of binary file layout

    uint32_t nfdversion;  // version of nfdump created this file
                          // #define NFDVERSION 0xF1070600
                          // created by gen_version.sh script automatically
                          // 4bytes 1.7.1-1 0x01070101
                          // 4bytes 1.7.1-1 0xF1070101 - git repo based on 1.7.1
    time_t created;       // file create time

    uint8_t compression;
    // note: v2 compression type do not match v3 types
    // constants defined in nffileV2_def.h

    uint8_t encryption;
#define NOT_ENCRYPTED 0
    uint16_t appendixBlocks;  // number of blocks to read from appendix
                              // on open file for internal data structs
    uint32_t creator;         // program created this file

    off_t offAppendix;  // offset in file for appendix blocks with additional data

    uint32_t BlockSize;  // max block size of data blocks
    uint32_t NumBlocks;  // number of data blocks in file
} fileHeaderV2_t;

/*
 * Generic file handle for reading/writing files
 * if a file is read only writeto and block_header are NULL
 */
typedef struct nffile_s {
    fileHeaderV2_t *file_header;  // file header

    int fd;                      // associated file descriptor
    char *ident;                 // source identifier
    char *fileName;              // file name
    size_t buff_size;            // buff_size, used in this file
    uint32_t numWorkers;         // number of workers for this handle
    uint16_t compression;        // type of compression
    uint16_t compressionLevel;   // compression level, if available.
    stat_record_t *stat_record;  // flow stat record

    queue_t *processQueue;  // blocks ready to be processed. Connects consumer/producer threads
    pthread_mutex_t wlock;  // writer lock
    pthread_t worker[];     // nfread/nfwrite worker thread;
} nffileV2_t;

static nffileV2_t *NewFile(uint32_t num_workers) {
    int compression = 0;
    int encryption = 0;

    dbg_printf("NewFile() %d workers\n", num_workers);
    size_t alloc_size = sizeof(nffileV2_t) + num_workers * sizeof(pthread_t);

    // Create struct
    nffileV2_t *nffile = calloc(1, alloc_size);
    if (!nffile) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }
    nffile->numWorkers = num_workers;

    // Init file header
    nffile->file_header = calloc(1, sizeof(fileHeaderV2_t));
    if (!nffile->file_header) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        free(nffile);
        return NULL;
    }

    nffile->stat_record = calloc(1, sizeof(stat_record_t));
    if (!nffile->stat_record) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        free(nffile);
        free(nffile->file_header);
        return NULL;
    }

    // init data buffer
    nffile->buff_size = BUFFSIZE;

    //
    uint32_t QueueSize = 8;
    nffile->processQueue = queue_init(QueueSize);
    if (!nffile->processQueue) {
        free(nffile);
        free(nffile->file_header);
        free(nffile->stat_record);
        return NULL;
    }

    nffile->file_header->magic = MAGIC;
    nffile->file_header->version = LAYOUT_VERSION_2;
    nffile->file_header->compression = compression;
    nffile->file_header->encryption = encryption;

    nffile->fd = 0;

    nffile->stat_record->msecFirstSeen = 0x7fffffffffffffff;

    pthread_mutex_init(&nffile->wlock, NULL);
    return nffile;

}  // End of NewFile

static dataBlockV2_t *NewDataBlockV2(void) {
    dbg_printf("Call NewDataBlockV2\n");
    dataBlockV2_t *dataBlock = malloc(BUFFSIZE);
    if (!dataBlock) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }
    InitDataBlock(dataBlock);
    return dataBlock;

}  // End of NewDataBlockV2

static void FreeDataBlockV2(dataBlockV2_t *dataBlock) {
    // Release block
    if (dataBlock) {
        dbg_printf("Call FreeDataBlockV2\n");
        free((void *)dataBlock);
    }
}  // End of FreeDataBlockV2

int VerifyFileV2(const char *filename, int verbose) {
    dbg_printf("Query mode verbose: %d\n", verbose);
    if (!InitUncompress_V2()) return 0;

    uint32_t totalRecords, numBlocks, type1, type2, type3, type4;
    type1 = type2 = type3 = type4 = 0;
    totalRecords = numBlocks = 0;

    if (access(filename, R_OK) < 0) {
        LogError("Can't read '%s': %s", filename, strerror(errno));
        return 0;
    }

    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        LogError("Error open file: %s", strerror(errno));
        return 0;
    }

    struct stat stat_buf;
    if (fstat(fd, &stat_buf)) {
        LogError("stat() error on '%s': %s", filename, strerror(errno));
        return 0;
    }

    // assume fileHeaderV2_t
    fileHeaderV2_t fileHeader;
    ssize_t ret = read(fd, (void *)&fileHeader, sizeof(fileHeaderV2_t));
    if (ret < 1) {
        LogError("read() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        close(fd);
        return 0;
    }

    if (fileHeader.magic != MAGIC) {
        LogError("Open file '%s': bad magic: 0x%X", filename, fileHeader.magic);
        close(fd);
        return 0;
    }

    printf("File       : %s\n", filename);
    printf("Size       : %" PRIi64 "\n", (int64_t)stat_buf.st_size);
    if (fileHeader.version == LAYOUT_VERSION_1) {
        printf("Version    : %u\n", fileHeader.version);
        LogError("Layout version 1 no longer supported");
        close(fd);
        return 0;
    } else {
        if (fileHeader.version != LAYOUT_VERSION_2) {
            LogError("Unknown layout version: %u", fileHeader.version);
            close(fd);
            return 0;
        }

        if (fileHeader.compression > ZSTD_COMPRESSED_V2) {
            LogError("Unknown compression: %u", fileHeader.compression);
            close(fd);
            return 0;
        }

        printf("Version    : %u - %s\n", fileHeader.version,
               fileHeader.compression == LZO_COMPRESSED_V2    ? "lzo compressed"
               : fileHeader.compression == LZ4_COMPRESSED_V2  ? "lz4 compressed"
               : fileHeader.compression == ZSTD_COMPRESSED_V2 ? "zstd compressed"
               : fileHeader.compression == BZ2_COMPRESSED_V2  ? "bz2 compressed"
                                                              : "not compressed");

        if (fileHeader.encryption != NOT_ENCRYPTED) {
            LogError("Unknown encryption: %u", fileHeader.encryption);
            close(fd);
            return 0;
        }

        if (fileHeader.creator >= MAX_CREATOR) {
            LogError("Creator ID %u out of range - set creator to unknown.", fileHeader.creator);
            fileHeader.creator = CREATOR_UNKNOWN;
        }

        struct tm tbuff_buf;
        struct tm *tbuff = localtime_r(&fileHeader.created, &tbuff_buf);
        char t1[64];
        strftime(t1, 63, "%Y-%m-%d %H:%M:%S", tbuff);
        printf("Created    : %s\n", t1);
        printf("Created by : %s\n", nf_creator[fileHeader.creator]);
        printf("nfdump     : %x\n", fileHeader.nfdversion);
        printf("encryption : %s\n", fileHeader.encryption ? "yes" : "no");
        printf("Appdx blks : %u\n", fileHeader.appendixBlocks);
        printf("Data blks  : %u\n", fileHeader.NumBlocks);

        if (verbose) {
            printf("Blocksize  : %u\n", fileHeader.BlockSize);
            printf("OffsetApp  : %lld\n", (long long)fileHeader.offAppendix);
        }

        if (fileHeader.offAppendix >= stat_buf.st_size) {
            LogError("Invalid appendix offset: %lld, file size: %lld", (long long)fileHeader.offAppendix, stat_buf.st_size);
            close(fd);
            return 0;
        }
    }

#ifndef HAVE_ZSTD
    if (fileHeader.compression == ZSTD_COMPRESSED_V2) {
        LogError("ZSTD compression not compiled in. Skip checking.");
        close(fd);
        return 0;
    }
#endif
#ifndef HAVE_BZ2
    if (fileHeader.compression == BZ2_COMPRESSED_V2) {
        LogError("BZIP2 compression not compiled in. Skip checking.");
        close(fd);
        return 0;
    }
#endif

    // read buffer
    dataBlockV2_t *readBlock = NewDataBlockV2();
    // tmp uncompress buffer
    dataBlockV2_t *buff = NewDataBlockV2();

    // V2 files often have BlockSize == 0 (field was added late, never written)
    // Default to WRITE_BUFFSIZE which is the standard V2 max uncompressed payload
    uint32_t blockSize = fileHeader.BlockSize ? fileHeader.BlockSize : WRITE_BUFFSIZE;

    printf("Checking data blocks\n");
    if (verbose == 0) setvbuf(stdout, (char *)NULL, _IONBF, 0);

    for (int i = 0; i < (int)(fileHeader.NumBlocks + fileHeader.appendixBlocks); i++) {
        if (verbose == 0) {
            char spinner[] = {'|', '/', '-', '\\'};
            if (verbose == 0 && ((numBlocks & 0x7) == 0)) printf(" %c\r", spinner[(numBlocks >> 3) & 0x2]);
        }
        off_t fpos = lseek(fd, 0, SEEK_CUR);
        if ((fpos + sizeof(dataBlockV2_t)) > stat_buf.st_size) {
            LogError("Unexpected read beyond EOF! File corrupted");
            LogError("Expected %u blocks, counted %i", fileHeader.NumBlocks, i);
            break;
        }
        ret = read(fd, readBlock, sizeof(dataBlockV2_t));
        if (ret < 0) {
            LogError("Error reading block %i: %s", numBlocks, strerror(errno));
            FreeDataBlockV2(readBlock);
            close(fd);
            return 0;
        }

        // Should never happen, as caught already in first check, but test it anyway ..
        if (ret == 0) {
            LogError("Unexpected eof. Expected %u blocks, counted %i", fileHeader.NumBlocks, i);
            close(fd);
            return 0;
        }
        if (ret < (ssize_t)sizeof(dataBlockV2_t)) {
            LogError("Short read: Expected %lu bytes, read: %zd", sizeof(dataBlockV2_t), ret);
            close(fd);
            return 0;
        }
        numBlocks++;

        switch (readBlock->type) {
            case DATA_BLOCK_TYPE_1:
                type1++;
                break;
            case DATA_BLOCK_TYPE_2:
                type2++;
                break;
            case DATA_BLOCK_TYPE_3:
                type3++;
                break;
            case DATA_BLOCK_TYPE_4:
                type4++;
                break;
            default:
                printf("block %i has unknown type %u\n", numBlocks, readBlock->type);
                close(fd);
                return 0;
        }

        if ((readBlock->size) > (BUFFSIZE - sizeof(dataBlockV2_t))) {
            LogError("Expected to seek beyond EOF! File corrupted");
            close(fd);
            return 0;
        }

        if ((fpos + sizeof(dataBlockV2_t) + readBlock->size) > stat_buf.st_size) {
            LogError("Expected to seek beyond EOF! File corrupted");
            close(fd);
            return 0;
        }

        if (verbose) {
            printf("Checking block %i, offset: %lld, type: %u, size: %u, flags: 0x%x, records: %u\n", numBlocks, (long long)fpos, readBlock->type,
                   readBlock->size, readBlock->flags, readBlock->NumRecords);
        }
        int compression = fileHeader.compression;
        if (TestFlag(readBlock->flags, FLAG_BLOCK_UNCOMPRESSED)) {
            compression = NOT_COMPRESSED_V2;
        }

        void *read_ptr = GetCursorV2(readBlock);
        ret = read(fd, read_ptr, readBlock->size);
        if (ret < 0) {
            LogError("Error reading block %i: %s", numBlocks, strerror(errno));
            close(fd);
            return 0;
        }

        if (ret == 0) {
            LogError("Unexpected eof. Expected %u blocks, counted %i", fileHeader.NumBlocks, numBlocks);
            close(fd);
            return 0;
        }
        if (ret != readBlock->size) {
            LogError("Short read: Expected %u bytes, read: %zd", readBlock->size, ret);
            close(fd);
            return 0;
        }

        int failed = 0;
        switch (compression) {
            case NOT_COMPRESSED_V2:
                break;
            case LZO_COMPRESSED_V2: {
                dataBlockV2_t *b = readBlock;
                readBlock = buff;
                buff = b;
                if (Uncompress_BlockV2_LZO(buff, readBlock, blockSize) < 0) {
                    LogError("LZO decompress failed");
                    failed = 1;
                }
            } break;
            case LZ4_COMPRESSED_V2: {
                dataBlockV2_t *b = readBlock;
                readBlock = buff;
                buff = b;
                if (Uncompress_BlockV2_LZ4(buff, readBlock, blockSize) < 0) {
                    LogError("LZ4 decompress failed");
                    failed = 1;
                }
            } break;
            case BZ2_COMPRESSED_V2: {
                dataBlockV2_t *b = readBlock;
                readBlock = buff;
                buff = b;
                if (Uncompress_BlockV2_BZ2(buff, readBlock, blockSize) < 0) {
                    LogError("Bzip2 decompress failed");
                    failed = 1;
                }
            } break;
            case ZSTD_COMPRESSED_V2: {
                dataBlockV2_t *b = readBlock;
                readBlock = buff;
                buff = b;
                if (Uncompress_BlockV2_ZSTD(buff, readBlock, blockSize) < 0) {
                    LogError("Zstd decompress failed");
                    failed = 1;
                }
            } break;
            default:
                LogError("Unknown compression ID: %d", compression);
                failed = 1;
        }

        if (failed) continue;

        if (verbose)
            printf("Uncompressed block %i, type: %u, size: %u, flags: 0x%x, records: %u\n", numBlocks, readBlock->type, readBlock->size,
                   readBlock->flags, readBlock->NumRecords);

        read_ptr = GetCursorV2(readBlock);

        // record counting
        unsigned blockSize = 0;
        unsigned numRecords = 0;
        if (readBlock->type == DATA_BLOCK_TYPE_4) {  // array block
            recordHeader_t *recordHeader = (recordHeader_t *)read_ptr;
            blockSize += sizeof(recordHeader_t);
            LogError("Array block: Record type: %u, size: %u", recordHeader->type, recordHeader->size);
            while (blockSize < readBlock->size) {
                blockSize += recordHeader->size;
                numRecords++;
            }
            if (blockSize != readBlock->size) {
                LogError("Error in block: %u, counted array size: %u != header size: %u\n", numBlocks, blockSize, readBlock->size);
                close(fd);
                return 0;
            }
        } else {
            while (blockSize < readBlock->size) {
                recordHeader_t *recordHeader = (recordHeader_t *)read_ptr;
                numRecords++;
                if ((blockSize + recordHeader->size) > readBlock->size) {
                    LogError("Record size %u extends beyond block size: %u", blockSize + recordHeader->size, readBlock->size);
                    close(fd);
                    return 0;
                }

                if (recordHeader->type > MaxRecordID && recordHeader->type < 32767) {
                    LogError("Unknown record type %u", recordHeader->type);
                }

                if (verbose) {
                    printf("Record %i, type: %u, size: %u - block offset: %u", numRecords, recordHeader->type, recordHeader->size, blockSize);
                    if (recordHeader->type == V3Record) {
                        if (VerifyV3Record((recordHeaderV3_t *)recordHeader) == 0) {
                            printf(" ** malformed v3 record**");
                        }
                    }
                    if (recordHeader->type == TYPE_IDENT) {
                        char *ident = (char *)((char *)recordHeader + sizeof(recordHeader_t));
                        size_t len = strlen(ident);
                        if (len > IDENTLEN) {
                            printf(" ** malformed ident with len: %zu **", len);
                        } else {
                            printf("  Ident: %s", ident);
                        }
                    }
                    if (recordHeader->type == SlackRecord) {
                        printf(" skip slack record **");
                    }
                    printf("\n");
                }
                blockSize += recordHeader->size;

                if (recordHeader->size < sizeof(recordHeader_t)) {
                    LogError("Error in block: %u, record: %u: record size %u below header size", numBlocks, numRecords, recordHeader->size);
                    LogError("Record %i, type: %u, size: %u - block size: %u\n", numRecords, recordHeader->type, recordHeader->size, blockSize);
                    close(fd);
                    return 0;
                }
                read_ptr += recordHeader->size;
            }
        }
        if (numRecords != readBlock->NumRecords) {
            LogError("Block %u num records %u != counted records: %u", i, readBlock->NumRecords, numRecords);
            close(fd);
            return 0;
        }
        totalRecords += numRecords;

        if (blockSize != readBlock->size) {
            LogError("block size %u != sum record size: %u", blockSize, readBlock->size);
            close(fd);
            return 0;
        }

        if (i + 1 == (int)fileHeader.NumBlocks) {
            off_t fsize = lseek(fd, 0, SEEK_CUR);
            if (fileHeader.appendixBlocks && fsize != fileHeader.offAppendix) {
                LogError("Invalid appendix offset - Expected: %ld, found: %ld", fileHeader.offAppendix, fsize);
                close(fd);
                return 0;
            }
            if (fileHeader.appendixBlocks) printf("Checking appendix blocks\n");
        }
    }

    FreeDataBlockV2(readBlock);
    FreeDataBlockV2(buff);

    off_t fsize = lseek(fd, 0, SEEK_CUR);
    if (fsize < stat_buf.st_size) {
        LogError("Extra data detected after regular blocks: %ld bytes", stat_buf.st_size - fsize);
    }

    printf("\nTotal\n");
    if (type1) printf("Type 1 blocks : %u\n", type1);
    if (type2) printf("Type 2 blocks : %u\n", type2);
    if (type3) printf("Type 3 blocks : %u\n", type3);
    if (type4) printf("Type 4 blocks : %u\n", type4);
    printf("Records       : %u\n", totalRecords);

    return 1;

}  // End of VerifyFileV2
