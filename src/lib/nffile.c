/*
 *  Copyright (c) 2004-2023, Peter Haag
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

#include "nffile.h"

#include <arpa/inet.h>
#include <assert.h>
#ifdef HAVE_BZLIB_H
#include <bzlib.h>
#endif
#ifdef HAVE_ZSTDLIB
#include <zstd.h>
#endif
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "flist.h"
#include "lz4.h"
#include "lz4hc.h"
#include "minilzo.h"
#include "nfconf.h"
#include "nfdump.h"
#include "nffileV2.h"
#include "util.h"

// LZO params
#define HEAP_ALLOC(var, size) lzo_align_t __LZO_MMODEL var[((size) + (sizeof(lzo_align_t) - 1)) / sizeof(lzo_align_t)]

#define InitDataBlock(a) \
    (a)->NumRecords = 0; \
    (a)->size = 0;       \
    (a)->flags = 0;      \
    (a)->type = DATA_BLOCK_TYPE_3;

static const char *nf_creator[MAX_CREATOR] = {"unknown", "nfcapd", "nfpcapd", "sfcapd", "nfdump", "nfanon", "nfprofile", "geolookup", "ft2nfdump"};

static unsigned NumWorkers = DEFAULTWORKERS;

/* function prototypes */
static int LZO_initialize(void);

static int LZ4_initialize(void);

static int BZ2_initialize(void);

#ifdef HAVE_ZSTDLIB
static int ZSTD_initialize(void);
#endif

static void BZ2_prep_stream(bz_stream *);

static int Compress_Block_LZO(dataBlock_t *in_block, dataBlock_t *out_block, size_t block_size);

static int Uncompress_Block_LZO(dataBlock_t *in_block, dataBlock_t *out_block, size_t block_size);

static int Compress_Block_LZ4(dataBlock_t *in_block, dataBlock_t *out_block, size_t block_size, int level);

static int Uncompress_Block_LZ4(dataBlock_t *in_block, dataBlock_t *out_block, size_t block_size);

static int Compress_Block_BZ2(dataBlock_t *in_block, dataBlock_t *out_block, size_t block_size);

#ifdef HAVE_ZSTDLIB
static int Compress_Block_ZSTD(dataBlock_t *in_block, dataBlock_t *out_block, size_t block_size, int level);

static int Uncompress_Block_ZSTD(dataBlock_t *in_block, dataBlock_t *out_block, size_t block_size);
#endif

static int Uncompress_Block_BZ2(dataBlock_t *in_block, dataBlock_t *out_block, size_t block_size);

static dataBlock_t *NewDataBlock(void);

static void FreeDataBlock(dataBlock_t *dataBlock);

static nffile_t *NewFile(nffile_t *nffile);

static dataBlock_t *nfread(nffile_t *nffile);

static int nfwrite(nffile_t *nffile, dataBlock_t *block_header);

static int ReadAppendix(nffile_t *nffile);

static int WriteAppendix(nffile_t *nffile);

static int SignalTerminate(nffile_t *nffile);

static void FlushFile(nffile_t *nffile);

static int QueryFileV1(int fd, fileHeaderV2_t *fileHeaderV2);

static void UpdateStat(stat_record_t *s, stat_recordV1_t *sv1);

static queue_t *fileQueue = NULL;

/* function definitions */

#define QueueSize 4

static _Atomic unsigned blocksInUse;

int Init_nffile(int workers, queue_t *fileList) {
    fileQueue = fileList;
    if (!LZO_initialize()) {
        LogError("Failed to initialize LZO");
        return 0;
    }
    if (!LZ4_initialize()) {
        LogError("Failed to initialize LZ4");
        return 0;
    }
    if (!BZ2_initialize()) {
        LogError("Failed to initialize BZ2");
        return 0;
    }
#ifdef HAVE_ZSTDLIB
    if (!ZSTD_initialize()) {
        LogError("Failed to initialize ZSTD");
        return 0;
    }
#endif

    atomic_init(&blocksInUse, 0);
    long CoresOnline;
    if (workers)
        CoresOnline = workers;
    else
        CoresOnline = sysconf(_SC_NPROCESSORS_ONLN);

    if (CoresOnline < 0) {
        LogError("sysconf() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        CoresOnline = DEFAULTWORKERS;
    }

    int confMaxWorkers = ConfGetValue("maxworkers");
    dbg_printf("MAXWORKERS: %d\n", confMaxWorkers);

    if (confMaxWorkers <= 0) confMaxWorkers = MAXWORKERS;

    NumWorkers = CoresOnline > confMaxWorkers ? confMaxWorkers : CoresOnline;
    return 1;

}  // End of Init_nffile

int ParseCompression(char *arg) {
    if (arg == NULL) {
        return LZO_COMPRESSED;
    }

    if (arg[0] == '=') arg++;

    if (strlen(arg) > 16) {
        return -1;
    }

    int level = 0;
    char *s = strchr(arg, ':');
    if (s) {
        *s++ = '\0';
        while (*s && isdigit(*s)) {
            level = 10 * level + (*s++ - 0x30);
        }
        if (*s) {
            LogError("Invalid compression level: %s", s);
            return -1;
        }
        if (level > 100) {
            LogError("Invalid compression level: %u", level);
            return -1;
        }
    }

    for (int i = 0; arg[i]; i++) {
        arg[i] = tolower(arg[i]);
    }

    if (strcmp(arg, "0") == 0) return NOT_COMPRESSED;
    if (strcmp(arg, "lzo") == 0 || strcmp(arg, "1") == 0) return LZO_COMPRESSED;
    if (strcmp(arg, "lz4") == 0 || strcmp(arg, "3") == 0) {
        if (level <= LZ4HC_CLEVEL_MAX) {
            return (level << 16) | LZ4_COMPRESSED;
        } else {
            LogError("LZ4 max compression level is %d", LZ4HC_CLEVEL_MAX);
            return -1;
        }
    }
    if (strcmp(arg, "bz2") == 0 || strcmp(arg, "bzip2") == 0 || strcmp(arg, "2") == 0) return BZ2_COMPRESSED;
#ifdef HAVE_ZSTDLIB
    if (strcmp(arg, "zstd") == 0 || strcmp(arg, "4") == 0) {
        if (level <= ZSTD_maxCLevel()) {
            return (level << 16) | ZSTD_COMPRESSED;
        } else {
            LogError("ZSTD max compression level is %d", ZSTD_maxCLevel());
            return -1;
        }
    }
#else
    if (strcmp(arg, "zstd") == 0) {
        LogError("ZSTD compression not enabled");
        return -1;
    }
#endif

    // anything else is invalid
    return -1;

}  // End of ParseCompression

unsigned ReportBlocks(void) {
    unsigned inUse = atomic_load(&blocksInUse);
    return inUse;
}

static int LZO_initialize(void) {
    if (lzo_init() != LZO_E_OK) {
        // this usually indicates a compiler bug - try recompiling
        // without optimizations, and enable `-DLZO_DEBUG' for diagnostics
        LogError("Compression lzo_init() failed.");
        return 0;
    }

    return 1;

}  // End of LZO_initialize

static int LZ4_initialize(void) {
    int lz4_buff_size = LZ4_compressBound(WRITE_BUFFSIZE);
    if (lz4_buff_size > (BUFFSIZE - sizeof(dataBlock_t))) {
        LogError("LZ4_compressBound() error in %s line %d: Buffer too small", __FILE__, __LINE__);
        return 0;
    }
    return 1;

}  // End of LZ4_initialize

static int BZ2_initialize(void) { return 1; }  // End of BZ2_initialize

static void BZ2_prep_stream(bz_stream *bs) {
    bs->bzalloc = NULL;
    bs->bzfree = NULL;
    bs->opaque = NULL;
}  // End of BZ2_prep_stream

#ifdef HAVE_ZSTDLIB
static int ZSTD_initialize(void) {
    size_t const cBuffSize = ZSTD_compressBound(WRITE_BUFFSIZE);
    if (cBuffSize > (BUFFSIZE - sizeof(dataBlock_t))) {
        LogError("LZSTD_compressBound() error in %s line %d: Buffer too small", __FILE__, __LINE__);
        return 0;
    }
    return 1;

}  // End of ZSTD_initialize
#endif

static int Compress_Block_LZO(dataBlock_t *in_block, dataBlock_t *out_block, size_t block_size) {
    unsigned char __LZO_MMODEL *in;
    unsigned char __LZO_MMODEL *out;
    int r;

    in = (unsigned char __LZO_MMODEL *)((void *)in_block + sizeof(dataBlock_t));
    out = (unsigned char __LZO_MMODEL *)((void *)out_block + sizeof(dataBlock_t));
    lzo_uint in_len = in_block->size;
    lzo_uint out_len = 0;

    HEAP_ALLOC(wrkmem, LZO1X_1_MEM_COMPRESS);
    r = lzo1x_1_compress(in, in_len, out, &out_len, wrkmem);

    if (r != LZO_E_OK) {
        LogError("Compress_Block_LZO() error compression failed in %s line %d: LZ4 : %d", __FILE__, __LINE__, r);
        return -1;
    }

    // copy header
    *out_block = *in_block;
    out_block->size = out_len;

    return 1;

}  // End of Compress_Block_LZO

static int Uncompress_Block_LZO(dataBlock_t *in_block, dataBlock_t *out_block, size_t block_size) {
    unsigned char __LZO_MMODEL *in;
    unsigned char __LZO_MMODEL *out;
    lzo_uint in_len;
    lzo_uint out_len;
    int r;

    in = (unsigned char __LZO_MMODEL *)((void *)in_block + sizeof(dataBlock_t));
    out = (unsigned char __LZO_MMODEL *)((void *)out_block + sizeof(dataBlock_t));
    in_len = in_block->size;
    out_len = block_size;

    if (in_len == 0) {
        LogError("Uncompress_Block_LZO() header length error in %s line %d", __FILE__, __LINE__);
        return -1;
    }
    r = lzo1x_decompress_safe(in, in_len, out, &out_len, NULL);
    if (r != LZO_E_OK) {
        LogError("Uncompress_Block_LZO() error decompression failed in %s line %d: LZO error: %d", __FILE__, __LINE__, r);
        return -1;
    }

    // copy header
    *out_block = *in_block;
    out_block->size = out_len;

    return 1;

}  // End of Uncompress_Block_LZO

static int Compress_Block_LZ4(dataBlock_t *in_block, dataBlock_t *out_block, size_t block_size, int level) {
    const char *in = (const char *)((void *)in_block + sizeof(dataBlock_t));
    char *out = (char *)((void *)out_block + sizeof(dataBlock_t));
    int in_len = in_block->size;

    int out_len;
    if (level > LZ4HC_CLEVEL_MIN)
        out_len = LZ4_compress_HC(in, out, in_len, block_size, level);
    else
        out_len = LZ4_compress_default(in, out, in_len, block_size);

    if (out_len == 0) {
        LogError("Compress_Block_LZ4() error compression aborted in %s line %d: LZ4 : buffer too small", __FILE__, __LINE__);
        return -1;
    }
    if (out_len < 0) {
        LogError("Compress_Block_LZ4() error compression failed in %s line %d: LZ4 : %d", __FILE__, __LINE__, out_len);
        return -1;
    }

    // copy header
    *out_block = *in_block;
    out_block->size = out_len;

    return 1;

}  // End of Compress_Block_LZ4

static int Uncompress_Block_LZ4(dataBlock_t *in_block, dataBlock_t *out_block, size_t block_size) {
    const char *in = (const char *)((void *)in_block + sizeof(dataBlock_t));
    char *out = (char *)((void *)out_block + sizeof(dataBlock_t));
    int in_len = in_block->size;

    int out_len = LZ4_decompress_safe(in, out, in_len, block_size);
    if (out_len == 0) {
        LogError("LZ4_decompress_safe() error compression aborted in %s line %d: LZ4 : buffer too small", __FILE__, __LINE__);
        return -1;
    }
    if (out_len < 0) {
        LogError("LZ4_decompress_safe() error compression failed in %s line %d: LZ4 : %d", __FILE__, __LINE__, out_len);
        return -1;
    }

    // copy header
    *out_block = *in_block;
    out_block->size = out_len;

    return 1;

}  // End of Uncompress_Block_LZ4

#ifdef HAVE_BZLIB_H
static int Compress_Block_BZ2(dataBlock_t *in_block, dataBlock_t *out_block, size_t block_size) {
    bz_stream bs;

    BZ2_prep_stream(&bs);
    BZ2_bzCompressInit(&bs, 9, 0, 0);

    bs.next_in = (char *)((void *)in_block + sizeof(dataBlock_t));
    bs.next_out = (char *)((void *)out_block + sizeof(dataBlock_t));
    bs.avail_in = in_block->size;
    bs.avail_out = block_size;

    for (;;) {
        int r = BZ2_bzCompress(&bs, BZ_FINISH);
        if (r == BZ_FINISH_OK) continue;
        if (r != BZ_STREAM_END) {
            LogError("Compress_Block_BZ2() error compression failed in %s line %d: LZ4 : %d", __FILE__, __LINE__, r);
            return -1;
        }
        break;
    }

    // copy header
    *out_block = *in_block;
    out_block->size = bs.total_out_lo32;

    BZ2_bzCompressEnd(&bs);

    return 1;

}  // End of Compress_Block_BZ2

static int Uncompress_Block_BZ2(dataBlock_t *in_block, dataBlock_t *out_block, size_t block_size) {
    bz_stream bs;

    BZ2_prep_stream(&bs);
    BZ2_bzDecompressInit(&bs, 0, 0);

    bs.next_in = (char *)((void *)in_block + sizeof(dataBlock_t));
    bs.next_out = (char *)((void *)out_block + sizeof(dataBlock_t));
    bs.avail_in = in_block->size;
    bs.avail_out = block_size;

    for (;;) {
        int r = BZ2_bzDecompress(&bs);
        if (r == BZ_OK) {
            continue;
        } else if (r != BZ_STREAM_END) {
            BZ2_bzDecompressEnd(&bs);
            return NF_CORRUPT;
        } else {
            break;
        }
    }

    // copy header
    *out_block = *in_block;
    out_block->size = bs.total_out_lo32;

    BZ2_bzDecompressEnd(&bs);

    return 1;

}  // End of Uncompress_Block_BZ2
#endif

#ifdef HAVE_ZSTDLIB
static int Compress_Block_ZSTD(dataBlock_t *in_block, dataBlock_t *out_block, size_t block_size, int level) {
    const char *in = (const char *)((void *)in_block + sizeof(dataBlock_t));
    char *out = (char *)((void *)out_block + sizeof(dataBlock_t));
    int in_len = in_block->size;

    if (level == 0) level = ZSTD_CLEVEL_DEFAULT;
    int out_len = ZSTD_compress(out, block_size, in, in_len, level);

    if (ZSTD_isError(out_len)) {
        LogError("Compress_Block_ZSTD() error compression aborted in %s line %d: LZ4 : buffer too small", __FILE__, __LINE__);
        return -1;
    }

    // copy header
    *out_block = *in_block;
    out_block->size = out_len;

    return 1;

}  // End of Compress_Block_ZSTD

static int Uncompress_Block_ZSTD(dataBlock_t *in_block, dataBlock_t *out_block, size_t block_size) {
    const char *in = (const char *)((void *)in_block + sizeof(dataBlock_t));
    char *out = (char *)((void *)out_block + sizeof(dataBlock_t));
    int in_len = in_block->size;

    size_t out_len = ZSTD_decompress(out, block_size, in, in_len);
    if (ZSTD_isError(out_len)) {
        LogError("LZ4_decompress_safe() error compression aborted in %s line %d: LZ4 : buffer too small", __FILE__, __LINE__);
        return -1;
    }

    // copy header
    *out_block = *in_block;
    out_block->size = out_len;

    return 1;
}  // End of Uncompress_Block_ZSTD
#endif

static dataBlock_t *NewDataBlock(void) {
    dataBlock_t *dataBlock = malloc(BUFFSIZE);
    if (!dataBlock) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }
    InitDataBlock(dataBlock);
    atomic_fetch_add(&blocksInUse, 1);
    return dataBlock;

}  // End of NewDataBlock

static void FreeDataBlock(dataBlock_t *dataBlock) {
    // Release block
    if (dataBlock) {
        free((void *)dataBlock);
        atomic_fetch_sub(&blocksInUse, 1);
    }
}  // End of FreeDataBlock

static int ReadAppendix(nffile_t *nffile) {
    dbg_printf("Process appendix ..\n");
    off_t currentPos = lseek(nffile->fd, 0, SEEK_CUR);
    if (currentPos < 0) {
        LogError("lseek() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    // seek to Appendix
    if (lseek(nffile->fd, nffile->file_header->offAppendix, SEEK_SET) < 0) {
        LogError("lseek() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    dbg_printf("Num of appendix records: %u\n", nffile->file_header->appendixBlocks);
    for (int i = 0; i < nffile->file_header->appendixBlocks; i++) {
        size_t processed = 0;
        dataBlock_t *block_header = nfread(nffile);
        if (!block_header) {
            LogError("Unable to read appendix block of file: %s", nffile->fileName);
            lseek(nffile->fd, currentPos, SEEK_SET);
            return 0;
        }
        void *buff_ptr = (void *)((void *)block_header + sizeof(dataBlock_t));

        for (int j = 0; j < block_header->NumRecords; j++) {
            record_header_t *record_header = (record_header_t *)buff_ptr;
            void *data = (void *)record_header + sizeof(record_header_t);
            uint16_t dataSize = record_header->size - sizeof(record_header_t);
            dbg_printf("appendix record: %u - type: %u, size: %u\n", j, record_header->type, record_header->size);
            switch (record_header->type) {
                case TYPE_IDENT:
                    dbg_printf("Read ident from appendix block\n");
                    if (nffile->ident) free(nffile->ident);
                    if (record_header->size < IDENTLEN) {
                        nffile->ident = strdup(data);
                    } else {
                        nffile->ident = NULL;
                        LogError("Error processing appendix ident record");
                    }
                    break;
                case TYPE_STAT:
                    dbg_printf("Read stat record from appendix block\n");
                    if (dataSize == sizeof(stat_record_t)) {
                        memcpy(nffile->stat_record, data, sizeof(stat_record_t));
                    } else {
                        LogError("Error processing appendix stat record");
                    }
                    break;
                default:
                    LogError("Error process appendix record type: %u", record_header->type);
            }
            processed += record_header->size;
            buff_ptr += record_header->size;
            if (processed > block_header->size) {
                LogError("Error processing appendix records: processed %u > block size %u", processed, block_header->size);
                FreeDataBlock(block_header);
                return 0;
            }
        }
        FreeDataBlock(block_header);
    }

    // seek back to currentPos
    off_t backPosition = lseek(nffile->fd, currentPos, SEEK_SET);
    dbg_printf("Reset position to %llu -> %llu\n", currentPos, backPosition);
    if (backPosition < 0) {
        LogError("lseek() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }
    return 1;

}  // End of ReadAppendix

// Write appendix - assume current file pos is end of data blocks
static int WriteAppendix(nffile_t *nffile) {
    dbg_printf("Write Appendix\n");
    // add appendix to end of data
    off_t currentPos = lseek(nffile->fd, 0, SEEK_CUR);
    if (currentPos < 0) {
        LogError("lseek() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    // set appendx info
    nffile->file_header->offAppendix = currentPos;
    nffile->file_header->appendixBlocks = 1;

    // make sure ident is set
    if (nffile->ident == NULL) nffile->ident = strdup("none");

    dataBlock_t *block_header = NewDataBlock();
    void *buff_ptr = (void *)((void *)block_header + sizeof(dataBlock_t));

    // write ident
    recordHeader_t *recordHeader = (recordHeader_t *)buff_ptr;
    void *data = (void *)recordHeader + sizeof(recordHeader_t);

    recordHeader->type = TYPE_IDENT;
    recordHeader->size = sizeof(recordHeader_t) + strlen(nffile->ident) + 1;
    strcpy(data, nffile->ident);

    block_header->NumRecords++;
    block_header->size += recordHeader->size;
    buff_ptr += recordHeader->size;

    // write stat record
    recordHeader = (recordHeader_t *)buff_ptr;
    data = (void *)recordHeader + sizeof(recordHeader_t);

    recordHeader->type = TYPE_STAT;
    recordHeader->size = sizeof(recordHeader_t) + sizeof(stat_record_t);
    memcpy(data, nffile->stat_record, sizeof(stat_record_t));

    block_header->NumRecords++;
    block_header->size += recordHeader->size;
    buff_ptr += recordHeader->size;

    nfwrite(nffile, block_header);
    FreeDataBlock(block_header);

    return 1;

}  // End of WriteAppendix

static nffile_t *NewFile(nffile_t *nffile) {
    // Create struct
    if (!nffile) {
        nffile = calloc(1, sizeof(nffile_t));
        if (!nffile) {
            LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return NULL;
        }

        // Init file header
        nffile->file_header = calloc(1, sizeof(fileHeaderV2_t));
        if (!nffile->file_header) {
            LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return NULL;
        }

        nffile->stat_record = calloc(1, sizeof(stat_record_t));
        if (!nffile->stat_record) {
            LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return NULL;
        }

        // init data buffer
        nffile->buff_size = BUFFSIZE;

        //
        nffile->processQueue = queue_init(QueueSize);
        if (!nffile->processQueue) {
            return NULL;
        }
    }

    memset((void *)nffile->file_header, 0, sizeof(fileHeaderV2_t));
    nffile->file_header->magic = MAGIC;
    nffile->file_header->version = LAYOUT_VERSION_2;

    nffile->buff_ptr = NULL;
    nffile->fd = 0;
    nffile->compat16 = 0;

    if (nffile->fileName) {
        free(nffile->fileName);
        nffile->fileName = NULL;
    }
    if (nffile->ident) {
        free(nffile->ident);
        nffile->ident = NULL;
    }
    memset((void *)nffile->stat_record, 0, sizeof(stat_record_t));
    nffile->stat_record->firstseen = 0x7fffffffffffffff;

    nffile->block_header = NULL;
    nffile->buff_ptr = NULL;

    for (int i = 0; i < MAXWORKERS; i++) nffile->worker[i] = 0;
    atomic_store(&nffile->terminate, 0);
    pthread_mutex_init(&nffile->wlock, NULL);
    return nffile;

}  // End of NewFile

static nffile_t *OpenFileStatic(char *filename, nffile_t *nffile) {
    struct stat stat_buf;
    int fd = 0;

    if (filename == NULL) {
        return NULL;
    } else {
        // regular file
        if (stat(filename, &stat_buf)) {
            LogError("stat() '%s': %s", filename, strerror(errno));
            return NULL;
        }

        if (!S_ISREG(stat_buf.st_mode)) {
            LogError("'%s' is not a file", filename);
            return NULL;
        }

        fd = open(filename, O_RDONLY);
        if (fd < 0) {
            LogError("Error open file: %s", strerror(errno));
            return NULL;
        }
    }

    // initialise and/or allocate new nffile handle
    nffile = NewFile(nffile);
    if (nffile == NULL) {
        return NULL;
    }
    nffile->fd = fd;
    if (nffile->fileName) free(nffile->fileName);
    nffile->fileName = strdup(filename);

    // assume file layout V2
    ssize_t ret = read(nffile->fd, (void *)nffile->file_header, sizeof(fileHeaderV2_t));
    if (ret < 1) {
        LogError("read() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        CloseFile(nffile);
        return NULL;
    }

    if (ret != sizeof(fileHeaderV2_t)) {
        LogError("Short read from file: %s", filename);
        CloseFile(nffile);
        return NULL;
    }

    if (nffile->file_header->magic != MAGIC) {
        LogError("Open file '%s': bad magic: 0x%X", filename ? filename : "<stdin>", nffile->file_header->magic);
        CloseFile(nffile);
        return NULL;
    }

    if (nffile->file_header->version != LAYOUT_VERSION_2) {
        if (nffile->file_header->version == LAYOUT_VERSION_1) {
            dbg_printf("Found layout type 1 => convert\n");
            // transparent read old v1 layout
            // convert old layout
            fileHeaderV1_t fileHeaderV1;

            // re-read file header - assume layout V1
            if (lseek(nffile->fd, 0, SEEK_SET) < 0) {
                LogError("lseek() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                CloseFile(nffile);
                return NULL;
            }

            ret = read(nffile->fd, (void *)&fileHeaderV1, sizeof(fileHeaderV1_t));
            if (ret < 1) {
                LogError("read() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                CloseFile(nffile);
                return NULL;
            }

            if (ret != sizeof(fileHeaderV1_t)) {
                LogError("Short read from file: %s", filename);
                CloseFile(nffile);
                return NULL;
            }

            if (fileHeaderV1.version != LAYOUT_VERSION_1) {
                LogError("Open file %s: bad version: %u", filename, fileHeaderV1.version);
                CloseFile(nffile);
                return NULL;
            }

            nffile->compat16 = 1;

            // initialize V2 header
            memset((void *)nffile->file_header, 0, sizeof(fileHeaderV2_t));
            nffile->file_header->magic = MAGIC;
            nffile->file_header->version = LAYOUT_VERSION_2;
            nffile->file_header->nfdversion = NFDVERSION;
#ifdef __APPLE__
#define st_mtim st_mtimespec
#endif
            nffile->file_header->created = stat_buf.st_mtim.tv_sec;
            nffile->file_header->compression = FILEV1_COMPRESSION(&fileHeaderV1);
            nffile->compression = nffile->file_header->compression;
            nffile->compression_level = 0;
            nffile->file_header->encryption = NOT_ENCRYPTED;
            nffile->file_header->NumBlocks = fileHeaderV1.NumBlocks;
            if (strlen(fileHeaderV1.ident) > 0) nffile->ident = strdup(fileHeaderV1.ident);

            // read v1 stat record
            stat_recordV1_t stat_recordV1;
            ret = read(nffile->fd, (void *)&stat_recordV1, sizeof(stat_recordV1_t));
            if (ret < 0) {
                LogError("read() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                CloseFile(nffile);
                return NULL;
            }
            UpdateStat(nffile->stat_record, &stat_recordV1);
        } else {
            LogError("Open file %s: bad version: %u", filename, nffile->file_header->version);
            CloseFile(nffile);
            return NULL;
        }
    } else {
        nffile->compression = nffile->file_header->compression;
    }
    nffile->compat16 = 0;

    if (FILE_ENCRYPTION(nffile)) {
        LogError("Open file %s: Can not handle encrypted files", filename);
        CloseFile(nffile);
        return NULL;
    }

#ifndef HAVE_ZSTDLIB
    if (nffile->file_header->compression == ZSTD_COMPRESSED) {
        LogError("ZSTD compression not enabled. Skip file: %s", filename);
        CloseFile(nffile);
        return NULL;
    }
#endif

    if (nffile->file_header->appendixBlocks) {
        if (nffile->file_header->offAppendix < stat_buf.st_size) {
            ReadAppendix(nffile);
        } else {
            LogError("Open file %s: appendix offset error", filename);
            CloseFile(nffile);
            return NULL;
        }
    }

    return nffile;

}  // End of OpenFileStatic

nffile_t *OpenFile(char *filename, nffile_t *nffile) {
    nffile = OpenFileStatic(filename, nffile);  // Open the file
    if (!nffile) {
        return NULL;
    }

    // kick off nfreader
    // there is only 1 reader thread -> slot 0
    pthread_t tid;
    atomic_store(&nffile->terminate, 0);
    queue_open(nffile->processQueue);
    int err = pthread_create(&tid, NULL, nfreader, (void *)nffile);
    if (err) {
        nffile->worker[0] = 0;
        LogError("pthread_create() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }
    nffile->worker[0] = tid;
    return nffile;

}  // End of OpenFile

// Create a new nffile
//  filename   : full path of file to create
//  nffile     : Use nffile handle and initialize it accordingly. If NULL a new handle is alocated
//  creater    : Creator ID
//  compress   : Compression alforithm and level. Lower 16bit: algo. Upper 16bit level
//  encryption : Encryption algorithm used.
nffile_t *OpenNewFile(char *filename, nffile_t *nffile, int creator, int compress, int encryption) {
    int fd;

    if (encryption != NOT_ENCRYPTED) {
        LogError("Unknown encryption ID: %i", encryption);
        return NULL;
    }

#ifndef HAVE_ZSTDLIB
    if ((compress & 0xFFFF) == ZSTD_COMPRESSED) {
        LogError("Open file %s: ZSTD compressionnot enabled");
        CloseFile(nffile);
        return NULL;
    }
#endif

    fd = open(filename, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0) {
        LogError("Failed to open file %s: '%s'", filename, strerror(errno));
        return NULL;
    }

    // Allocate/Init nffile struct
    nffile = NewFile(nffile);
    if (nffile == NULL) {
        return NULL;
    }
    nffile->fd = fd;
    nffile->fileName = strdup(filename);

    memset((void *)nffile->file_header, 0, sizeof(fileHeaderV2_t));
    nffile->file_header->magic = MAGIC;
    nffile->file_header->version = LAYOUT_VERSION_2;
    nffile->file_header->nfdversion = NFDVERSION;
    nffile->file_header->created = time(NULL);
    nffile->file_header->compression = compress & 0xFFFF;
    nffile->compression = nffile->file_header->compression;
    nffile->compression_level = (compress >> 16) & 0xFFFF;
    nffile->file_header->encryption = encryption;
    nffile->file_header->creator = creator;

    if (write(nffile->fd, (void *)nffile->file_header, sizeof(fileHeaderV2_t)) < sizeof(fileHeaderV2_t)) {
        LogError("write() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        close(nffile->fd);
        nffile->fd = 0;
        return NULL;
    }

    // prepare buffer to write to
    nffile->block_header = NewDataBlock();
    nffile->buff_ptr = (void *)((pointer_addr_t)nffile->block_header + sizeof(dataBlock_t));

    // kick off nfwriter
    atomic_store(&nffile->terminate, 0);
    queue_open(nffile->processQueue);

    // if file is not compressed, 1 worker is fine.
    unsigned NumThreads = nffile->file_header->compression == 0 ? 1 : NumWorkers;
    for (unsigned i = 0; i < NumThreads; i++) {
        pthread_t tid;
        int err = pthread_create(&tid, NULL, nfwriter, (void *)nffile);
        if (err) {
            nffile->worker[i] = 0;
            LogError("pthread_create() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return NULL;
        }
        nffile->worker[i] = tid;
    }
    return nffile;

} /* End of OpenNewFile */

nffile_t *AppendFile(char *filename) {
    nffile_t *nffile;

    // try to open the existing file
    nffile = OpenFileStatic(filename, NULL);
    if (!nffile) return NULL;

    // file is valid - re-open the file mode RDWR
    close(nffile->fd);
    nffile->fd = open(filename, O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (nffile->fd < 0) {
        LogError("Failed to open file (rw) %s: '%s'", filename, strerror(errno));
        DisposeFile(nffile);
        return NULL;
    }

    if (nffile->file_header->offAppendix) {
        // seek to  end of data blocks => append new blocks
        if (lseek(nffile->fd, nffile->file_header->offAppendix, SEEK_SET) < 0) {
            LogError("lseek() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            DisposeFile(nffile);
            return NULL;
        }
        // cut off old appendix
        if (ftruncate(nffile->fd, nffile->file_header->offAppendix) < 0) {
            LogError("ftruncate() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            DisposeFile(nffile);
            return NULL;
        }

    } else {
        // if no appendix
        if (lseek(nffile->fd, 0, SEEK_END) < 0) {
            LogError("lseek() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            DisposeFile(nffile);
            return NULL;
        }
    }

    // appending needs no block header
    nffile->block_header = NULL;

    // kick off NumWorkers nfwriter threads
    atomic_store(&nffile->terminate, 0);
    queue_open(nffile->processQueue);

    unsigned NumThreads = nffile->file_header->compression == 0 ? 1 : NumWorkers;
    for (unsigned i = 0; i < NumThreads; i++) {
        pthread_t tid;
        int err = pthread_create(&tid, NULL, nfwriter, (void *)nffile);
        if (err) {
            nffile->worker[i] = 0;
            LogError("pthread_create() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return NULL;
        }
        nffile->worker[i] = tid;
    }
    return nffile;

} /* End of AppendFile */

int RenameAppend(char *oldName, char *newName) {
    struct stat fstat;

    int ret = stat(newName, &fstat);
    if (ret == 0) {
        // path exists
        if (S_ISREG(fstat.st_mode)) {
            // file exists already - concat them
            nffile_t *nffile_w = AppendFile(newName);
            if (!nffile_w) return -1;

            nffile_t *nffile_r = OpenFile(oldName, NULL);
            if (!nffile_r) return 0;

            // append data blocks
            while (1) {
                dataBlock_t *block_header = queue_pop(nffile_r->processQueue);
                if (block_header == QUEUE_CLOSED)  // EOF
                    break;
                queue_push(nffile_w->processQueue, block_header);
            }
            CloseFile(nffile_r);

            // sum stat_records
            SumStatRecords(nffile_w->stat_record, nffile_r->stat_record);
            DisposeFile(nffile_r);

            CloseUpdateFile(nffile_w);
            DisposeFile(nffile_w);

            return unlink(oldName);
        } else {
            LogError("Path exists and is not a regular file: %s", newName);
            return -1;
        }
    } else {
        // does not exist
        return rename(oldName, newName);
    }

    // unreached
    return 0;

}  // End of RenameAppend

static void FlushFile(nffile_t *nffile) {
    // push current block, let writers flush it to disk
    if (nffile->block_header && nffile->block_header->size) {
        queue_push(nffile->processQueue, nffile->block_header);
        nffile->block_header = NULL;
        nffile->buff_ptr = NULL;
    }
    // done - close queue
    queue_close(nffile->processQueue);
    // wait for queue to be empty
    queue_sync(nffile->processQueue);
    // writers terminate, on queue closed and empty

    // wait for all nfwriter threads to exit
    for (unsigned i = 0; i < NumWorkers; i++) {
        if (nffile->worker[i]) {
            int err = pthread_join(nffile->worker[i], NULL);
            if (err) {
                LogError("pthread_join() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            }
            nffile->worker[i] = 0;
        }
    }
    fsync(nffile->fd);

}  // End of FlushFile

void CloseFile(nffile_t *nffile) {
    if (!nffile || nffile->fd == 0) return;

    // make sure all workers are gone
    for (unsigned i = 0; i < NumWorkers; i++) {
        if (nffile->worker[i]) {
            SignalTerminate(nffile);
        }
    }

    close(nffile->fd);
    nffile->fd = 0;

    if (nffile->fileName) {
        free(nffile->fileName);
        nffile->fileName = NULL;
    }

    if (nffile->ident) {
        free(nffile->ident);
        nffile->ident = NULL;
    }

    // clean queue
    queue_close(nffile->processQueue);
    while (queue_length(nffile->processQueue)) {
        dataBlock_t *block_header = queue_pop(nffile->processQueue);
        FreeDataBlock(block_header);
    }

    nffile->file_header->NumBlocks = 0;
}  // End of CloseFile

int CloseUpdateFile(nffile_t *nffile) {
    FlushFile(nffile);

    if (!WriteAppendix(nffile)) {
        LogError("Failed to write appendix");
    }

    if (lseek(nffile->fd, 0, SEEK_SET) < 0) {
        LogError("lseek() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        close(nffile->fd);
        return 0;
    }

    // NumBlocks are plain data blocks - subtract appendix blocks
    nffile->file_header->NumBlocks -= nffile->file_header->appendixBlocks;

    if (write(nffile->fd, (void *)nffile->file_header, sizeof(fileHeaderV2_t)) <= 0) {
        LogError("write() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    if (nffile->block_header) {
        FreeDataBlock(nffile->block_header);
        nffile->block_header = NULL;
    }

    if (lseek(nffile->fd, 0, SEEK_END) < 0) {
        LogError("lseek() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        close(nffile->fd);
        return 0;
    }
    fsync(nffile->fd);
    CloseFile(nffile);

    return 1;

} /* End of CloseUpdateFile */

void DisposeFile(nffile_t *nffile) {
    if (nffile->fd > 0) CloseFile(nffile);
    if (nffile->block_header) FreeDataBlock(nffile->block_header);
    if (nffile->file_header) free(nffile->file_header);
    if (nffile->stat_record) free(nffile->stat_record);
    if (nffile->ident) free(nffile->ident);
    if (nffile->fileName) free(nffile->fileName);

    for (size_t queueLen = queue_length(nffile->processQueue); queueLen > 0; queueLen--) {
        void *p = queue_pop(nffile->processQueue);
        FreeDataBlock(p);
    }

    queue_free(nffile->processQueue);
    free(nffile);

}  // End of DisposeFile

nffile_t *GetNextFile(nffile_t *nffile) {
    // close current file before open the next one
    // stdin ( current = 0 ) is not closed
    if (nffile) {
        CloseFile(nffile);
    } else {
        nffile = NewFile(NULL);
    }

    if (!fileQueue) {
        LogError("GetNextFile() no file queue to process");
        return NULL;
    }

    while (1) {
        char *nextFile = queue_pop(fileQueue);
        if (nextFile == QUEUE_CLOSED) {
            // no or no more files available
            return EMPTY_LIST;
        }

        dbg_printf("Process: '%s'\n", nextFile);
        nffile = OpenFile(nextFile, nffile);  // Open the file
        free(nextFile);
        return nffile;
    }

    /* NOTREACHED */

}  // End of GetNextFile

int ReadBlock(nffile_t *nffile) {
    if (nffile->block_header) {
        FreeDataBlock(nffile->block_header);
        nffile->block_header = NULL;
    }

    nffile->block_header = queue_pop(nffile->processQueue);
    if (nffile->block_header == QUEUE_CLOSED) {  // EOF
        nffile->block_header = NULL;
        return NF_EOF;
    }

    // set read ptr
    nffile->buff_ptr = (void *)((pointer_addr_t)nffile->block_header + sizeof(dataBlock_t));
    dbg_printf("ReadBlock - read: %u\n", nffile->block_header->size);

    return nffile->block_header->size;

}  // End of ReadBlock

// generic read und uncompress a data block from current position
static dataBlock_t *nfread(nffile_t *nffile) {
    dataBlock_t *buff = NewDataBlock();
    ssize_t ret = read(nffile->fd, buff, sizeof(dataBlock_t));
    if (ret == 0) {  // EOF
        FreeDataBlock(buff);
        return NULL;
    }

    if (ret == -1) {  // Error
        FreeDataBlock(buff);
        LogError("read() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    // Check for sane buffer size
    if (ret != sizeof(dataBlock_t)) {
        // this is most likely a corrupt file
        FreeDataBlock(buff);
        LogError("Corrupt data file: Read %i bytes, requested %u", ret, sizeof(dataBlock_t));
        return NULL;
    }

    dbg_printf("ReadBlock - type: %u, size: %u, numRecords: %u, flags: %u\n", buff->type, buff->size, buff->NumRecords, buff->flags);

    if (buff->size > (BUFFSIZE - sizeof(dataBlock_t)) || buff->size == 0 || buff->NumRecords == 0) {
        // this is most likely a corrupt file
        LogError("Corrupt data file: Error buffer size %u", buff->size);
        FreeDataBlock(buff);
        return NULL;
    }

    int compression = nffile->file_header->compression;

    void *p = (void *)((void *)buff + sizeof(dataBlock_t));
    dbg_printf("ReadBlock - read: %u\n", buff->size);
    ret = read(nffile->fd, p, buff->size);
    if (ret == buff->size) {
        dataBlock_t *block_header = NULL;
        int failed = 0;
        // we have the whole record and are done for now
        switch (compression) {
            case NOT_COMPRESSED:
                block_header = buff;
                break;
            case LZO_COMPRESSED:
                block_header = NewDataBlock();
                if (Uncompress_Block_LZO(buff, block_header, nffile->buff_size) < 0) failed = 1;
                FreeDataBlock(buff);
                break;
            case LZ4_COMPRESSED:
                block_header = NewDataBlock();
                if (Uncompress_Block_LZ4(buff, block_header, nffile->buff_size) < 0) failed = 1;
                FreeDataBlock(buff);
                break;
            case BZ2_COMPRESSED:
                block_header = NewDataBlock();
                if (Uncompress_Block_BZ2(buff, block_header, nffile->buff_size) < 0) failed = 1;
                FreeDataBlock(buff);
                break;
#ifdef HAVE_ZSTDLIB
            case ZSTD_COMPRESSED:
                block_header = NewDataBlock();
                if (Uncompress_Block_ZSTD(buff, block_header, nffile->buff_size) < 0) failed = 1;
                FreeDataBlock(buff);
                break;
#endif
        }

        if (failed) {
            FreeDataBlock(block_header);
            return NULL;
        }
        // success - done
        return block_header;

    } else if (ret == 0) {
        LogError("ReadBlock() Corrupt data file: Unexpected EOF while reading data block");
    } else if (ret == -1) {  // ERROR
        LogError("read() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
    } else {
        LogError("read() error: Short read: Expected: %u, received: %u\n", buff->size, ret);
    }

    FreeDataBlock(buff);
    return NULL;

}  // End of nfread

__attribute__((noreturn)) void *nfreader(void *arg) {
    nffile_t *nffile = (nffile_t *)arg;

    /* Signal handling */
    sigset_t set = {0};
    sigfillset(&set);
    pthread_sigmask(SIG_SETMASK, &set, NULL);

    int terminate = atomic_load(&nffile->terminate);
    int blockCount = 0;
    dataBlock_t *block_header = NULL;
    while (!terminate && blockCount < nffile->file_header->NumBlocks) {
        block_header = nfread(nffile);
        if (!block_header) {
            dbg_printf("block_header == NULL\n");
            break;
        }

        if (queue_push(nffile->processQueue, (void *)block_header) == QUEUE_CLOSED) {
            FreeDataBlock(block_header);
            dbg_printf("nfreader - processQueue closed\n");
            terminate = 1;
        } else {
            blockCount++;
            terminate = atomic_load(&nffile->terminate);
            dbg_printf("ReadBlock - expanded: %u\n", block_header->size);
            dbg_printf("Blocks: %u\n", blockCount);
        }

#ifdef DEVEL
        if (terminate) {
            printf("Terminate nfreader by signal\n");
        }
#endif
    }

    // eof or error ends processing
    queue_close(nffile->processQueue);

    dbg_printf("nfreader done - read %u blocks\n", blockCount);
    dbg_printf("nfreader exit\n");

    atomic_store(&nffile->terminate, 2);
    pthread_exit(NULL);

}  // End of nfreader

int WriteBlock(nffile_t *nffile) {
    // empty blocks need not to be written
    if (nffile->block_header->size != 0) {
        dbg_printf("WriteBlock - push block with size: %u\n", nffile->block_header->size);
        queue_push(nffile->processQueue, nffile->block_header);

        nffile->block_header = NewDataBlock();
    } else {
        // re-init empty block
        InitDataBlock(nffile->block_header);
    }
    nffile->buff_ptr = (void *)((void *)nffile->block_header + sizeof(dataBlock_t));

    return 1;

}  // End of WriteBlock

static int nfwrite(nffile_t *nffile, dataBlock_t *block_header) {
    if (block_header->size == 0) {
        return 1;
    }

    dbg_printf("nfwrite - write: %u\n", block_header->size);

    dataBlock_t *buff = NULL;
    dataBlock_t *wptr = NULL;
    int failed = 0;
    // compress according file compression
    int compression = nffile->compression;
    int level = nffile->compression_level;
    dbg_printf("nfwrite - compression: %u\n", compression);
    switch (compression) {
        case NOT_COMPRESSED:
            wptr = block_header;
            break;
        case LZO_COMPRESSED:
            buff = NewDataBlock();
            if (Compress_Block_LZO(block_header, buff, nffile->buff_size) < 0) failed = 1;
            wptr = buff;
            break;
        case LZ4_COMPRESSED:
            buff = NewDataBlock();
            if (Compress_Block_LZ4(block_header, buff, nffile->buff_size, level) < 0) failed = 1;
            wptr = buff;
            break;
        case BZ2_COMPRESSED:
            buff = NewDataBlock();
            if (Compress_Block_BZ2(block_header, buff, nffile->buff_size) < 0) failed = 1;
            wptr = buff;
            break;
#ifdef HAVE_ZSTDLIB
        case ZSTD_COMPRESSED:
            buff = NewDataBlock();
            if (Compress_Block_ZSTD(block_header, buff, nffile->buff_size, level) < 0) failed = 1;
            wptr = buff;
            break;
#endif
    }

    if (failed) {  // error
        FreeDataBlock(buff);
        return 0;
    }

    dbg_printf("WriteBlock - type: %u, size: %u, compressed: %u, numRecords: %u, flags: %u\n", wptr->type, block_header->size, compression,
               wptr->NumRecords, wptr->flags);

    pthread_mutex_lock(&nffile->wlock);
    ssize_t ret = write(nffile->fd, (void *)wptr, sizeof(dataBlock_t) + wptr->size);
    FreeDataBlock(buff);
    if (ret < 0) {
        pthread_mutex_unlock(&nffile->wlock);
        LogError("write() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    nffile->file_header->NumBlocks++;
    pthread_mutex_unlock(&nffile->wlock);
    return 1;

}  // End of nfwrite

__attribute__((noreturn)) void *nfwriter(void *arg) {
    nffile_t *nffile = (nffile_t *)arg;

    dbg_printf("nfwriter enter\n");
    /* disable signal handling */
    sigset_t set = {0};
    sigfillset(&set);
    pthread_sigmask(SIG_SETMASK, &set, NULL);

    dataBlock_t *block_header;
    while (1) {
        block_header = queue_pop(nffile->processQueue);
        if (block_header == QUEUE_CLOSED) break;

        int ok = 1;
        if (block_header->size) {
            // block with data
            dbg_printf("nfwriter write\n");
            ok = nfwrite(nffile, block_header);
        }
        FreeDataBlock(block_header);

        if (!ok) break;
    }

    dbg_printf("nfwriter exit\n");
    pthread_exit(NULL);

    /* UNREACHED */

}  // End of nfwriter

static int SignalTerminate(nffile_t *nffile) {
    // set terminate
    atomic_store(&nffile->terminate, 1);
    queue_close(nffile->processQueue);

    pthread_cond_broadcast(&(nffile->processQueue->cond));
    for (unsigned i = 0; i < NumWorkers; i++) {
        if (nffile->worker[i]) {
            int err = pthread_join(nffile->worker[i], NULL);
            if (err && err != ESRCH) {
                LogError("pthread_join() error in %s line %d: %s", __FILE__, __LINE__, strerror(err));
            }
            nffile->worker[i] = 0;
        }
    }
    atomic_store(&nffile->terminate, 0);

    return 1;

}  // End of SignalTerminate

void SetIdent(nffile_t *nffile, char *Ident) {
    if (Ident && strlen(Ident) > 0) {
        if (nffile->ident) free(nffile->ident);
        nffile->ident = strdup(Ident);
    }

}  // End of SetIdent

int ChangeIdent(char *filename, char *Ident) {
    nffile_t *nffile = OpenFileStatic(filename, NULL);
    if (!nffile) {
        return 0;
    }

    // file is valid - re-open the file mode RDWR
    close(nffile->fd);
    nffile->fd = open(filename, O_RDWR | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (nffile->fd < 0) {
        LogError("Failed to open file %s: '%s'", filename, strerror(errno));
        DisposeFile(nffile);
        return 0;
    }

    printf("%s ident: %s -> %s\n", filename, nffile->ident ? nffile->ident : "<null>", Ident);
    SetIdent(nffile, Ident);

    // seek to end of data
    if (nffile->file_header->offAppendix) {
        // seek to  end of data blocks
        if (lseek(nffile->fd, nffile->file_header->offAppendix, SEEK_SET) < 0) {
            LogError("lseek() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            DisposeFile(nffile);
            return 0;
        }
    } else {
        // if no appendix
        if (lseek(nffile->fd, 0, SEEK_END) < 0) {
            LogError("lseek() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            DisposeFile(nffile);
            return 0;
        }
    }

    if (!WriteAppendix(nffile)) {
        LogError("Failed to write appendix");
    }

    if (!CloseUpdateFile(nffile)) {
        return 0;
    }

    DisposeFile(nffile);

    return 1;

}  // End of ChangeIdent

void ModifyCompressFile(int compress) {
    nffile_t *nffile_r, *nffile_w;
    stat_record_t *_s;
    char outfile[MAXPATHLEN];

    nffile_r = NULL;
    while (1) {
        nffile_r = GetNextFile(nffile_r);

        // last file
        if (!nffile_r || (nffile_r == EMPTY_LIST)) break;

        if (nffile_r->file_header->compression == (compress & 0xFFFF)) {
            printf("File %s is already same compression method\n", nffile_r->fileName);
            continue;
        }

        // tmp filename for new output file
        snprintf(outfile, MAXPATHLEN, "%s-tmp", nffile_r->fileName);
        outfile[MAXPATHLEN - 1] = '\0';

        // compat 1.6.x files must read extensions first. With many writers
        // this is not guaranteed. Therefore limit writers to 1
        if (nffile_r->compat16) {
            NumWorkers = 1;
        }
        // allocate output file
        nffile_w = OpenNewFile(outfile, NULL, FILE_CREATOR(nffile_r), compress, NOT_ENCRYPTED);
        if (!nffile_w) {
            DisposeFile(nffile_r);
            break;
        }

        SetIdent(nffile_w, nffile_r->ident);

        // swap stat records :)
        _s = nffile_r->stat_record;
        nffile_r->stat_record = nffile_w->stat_record;
        nffile_w->stat_record = _s;

        // push blocks to new file
        while (1) {
            dataBlock_t *block_header = queue_pop(nffile_r->processQueue);
            if (block_header == QUEUE_CLOSED)  // EOF
                break;
            queue_push(nffile_w->processQueue, block_header);
        }

        printf("File %s compression changed\n", nffile_r->fileName);
        if (!CloseUpdateFile(nffile_w)) {
            unlink(outfile);
            LogError("Failed to close file: '%s'", strerror(errno));
        } else {
            if (unlink(nffile_r->fileName)) {
                LogError("unlink() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            } else if (rename(outfile, nffile_r->fileName)) {
                LogError("rename() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            }
        }

        DisposeFile(nffile_w);
    }

}  // End of ModifyCompressFile

int QueryFile(char *filename, int verbose) {
    int fd;
    uint32_t totalRecords, numBlocks, type1, type2, type3, type4;
    struct stat stat_buf;
    ssize_t ret;

    dbg_printf("Query mode verbose: %d\n", verbose);
    if (!Init_nffile(1, NULL)) return 0;

    type1 = type2 = type3 = type4 = 0;
    totalRecords = numBlocks = 0;

    if (stat(filename, &stat_buf)) {
        LogError("Can't stat '%s': %s", filename, strerror(errno));
        return 0;
    }

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        LogError("Error open file: %s", strerror(errno));
        return 0;
    }

    // assume fileHeaderV2_t
    fileHeaderV2_t fileHeader;
    ret = read(fd, (void *)&fileHeader, sizeof(fileHeaderV2_t));
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
    if (fileHeader.version == LAYOUT_VERSION_1) {
        if (lseek(fd, 0, SEEK_SET) < 0) {
            LogError("lseek() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            close(fd);
            return 0;
        }
        if (!QueryFileV1(fd, &fileHeader)) {
            close(fd);
            return 0;
        }
    } else {
        if (fileHeader.version != LAYOUT_VERSION_2) {
            LogError("Unknown layout version: %u", fileHeader.version);
            close(fd);
            return 0;
        }

        if (fileHeader.compression > ZSTD_COMPRESSED) {
            LogError("Unknown compression: %u", fileHeader.compression);
            close(fd);
            return 0;
        }

        printf("Version    : %u - %s\n", fileHeader.version,
               fileHeader.compression == LZO_COMPRESSED    ? "lzo compressed"
               : fileHeader.compression == LZ4_COMPRESSED  ? "lz4 compressed"
               : fileHeader.compression == ZSTD_COMPRESSED ? "zstd compressed"
               : fileHeader.compression == BZ2_COMPRESSED  ? "bz2 compressed"
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

        struct tm *tbuff = localtime(&fileHeader.created);
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

#ifndef HAVE_ZSTDLIB
    if (fileHeader.compression == ZSTD_COMPRESSED) {
        LogError("ZSTD compression not enabled. Skip checking.");
        close(fd);
        return 0;
    }
#endif
    // first check ok - abstract nffile level
    nffile_t *nffile = NewFile(NULL);
    if (!nffile) {
        close(fd);
        return 0;
    }
    nffile->fd = fd;
    nffile->fileName = strdup(filename);
    nffile->block_header = NewDataBlock();
    memcpy(nffile->file_header, &fileHeader, sizeof(fileHeader));

    dataBlock_t *buff = NewDataBlock();

    printf("Checking data blocks\n");
    if (verbose == 0) setvbuf(stdout, (char *)NULL, _IONBF, 0);

    for (int i = 0; i < fileHeader.NumBlocks + fileHeader.appendixBlocks; i++) {
        if (verbose == 0) {
            char spinner[] = {'|', '/', '-', '\\'};
            if (verbose == 0 && ((numBlocks & 0x7) == 0)) printf(" %c\r", spinner[(numBlocks >> 3) & 0x2]);
        }
        off_t fpos = lseek(fd, 0, SEEK_CUR);
        if ((fpos + sizeof(dataBlock_t)) > stat_buf.st_size) {
            LogError("Unexpected read beyond EOF! File corrupted");
            LogError("Expected %u blocks, counted %i", fileHeader.NumBlocks, i);
            break;
        }
        ret = read(fd, nffile->block_header, sizeof(dataBlock_t));
        if (ret < 0) {
            LogError("Error reading block %i: %s", numBlocks, strerror(errno));
            close(fd);
            return 0;
        }

        // Should never happen, as caught already in first check, but test it anyway ..
        if (ret == 0) {
            LogError("Unexpected eof. Expected %u blocks, counted %i", fileHeader.NumBlocks, i);
            close(fd);
            return 0;
        }
        if (ret < sizeof(dataBlock_t)) {
            LogError("Short read: Expected %u bytes, read: %i", sizeof(dataBlock_t), ret);
            close(fd);
            return 0;
        }
        numBlocks++;

        switch (nffile->block_header->type) {
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
                printf("block %i has unknown type %u\n", numBlocks, nffile->block_header->type);
                close(fd);
                return 0;
        }

        if ((nffile->block_header->size) > (BUFFSIZE - sizeof(dataBlock_t))) {
            LogError("Expected to seek beyond EOF! File corrupted");
            close(fd);
            return 0;
        }

        if ((fpos + sizeof(dataBlock_t) + nffile->block_header->size) > stat_buf.st_size) {
            LogError("Expected to seek beyond EOF! File corrupted");
            close(fd);
            return 0;
        }

        if (verbose) {
            printf("Checking block %i, offset: %lld, type: %u, size: %u, flags: 0x%x, records: %u\n", numBlocks, (long long)fpos,
                   nffile->block_header->type, nffile->block_header->size, nffile->block_header->flags, nffile->block_header->NumRecords);
        }
        int compression = nffile->file_header->compression;
        if (TestFlag(nffile->block_header->flags, FLAG_BLOCK_UNCOMPRESSED)) {
            compression = NOT_COMPRESSED;
        }

        nffile->buff_ptr = (void *)((pointer_addr_t)nffile->block_header + sizeof(dataBlock_t));
        ret = read(nffile->fd, nffile->buff_ptr, nffile->block_header->size);
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
        if (ret != nffile->block_header->size) {
            LogError("Short read: Expected %u bytes, read: %i", nffile->block_header->size, ret);
            close(fd);
            return 0;
        }

        int failed = 0;
        switch (compression) {
            case NOT_COMPRESSED:
                break;
            case LZO_COMPRESSED: {
                dataBlock_t *b = nffile->block_header;
                nffile->block_header = buff;
                buff = b;
                if (Uncompress_Block_LZO(buff, nffile->block_header, nffile->buff_size) < 0) {
                    LogError("LZO decompress failed");
                    failed = 1;
                }
            } break;
            case LZ4_COMPRESSED: {
                dataBlock_t *b = nffile->block_header;
                nffile->block_header = buff;
                buff = b;
                if (Uncompress_Block_LZ4(buff, nffile->block_header, nffile->buff_size) < 0) {
                    LogError("LZ4 decompress failed");
                    failed = 1;
                }
            } break;
            case BZ2_COMPRESSED: {
                dataBlock_t *b = nffile->block_header;
                nffile->block_header = buff;
                buff = b;
                if (Uncompress_Block_BZ2(buff, nffile->block_header, nffile->buff_size) < 0) {
                    LogError("Bzip2 decompress failed");
                    failed = 1;
                }
            } break;
            case ZSTD_COMPRESSED: {
#ifdef HAVE_ZSTDLIB
                dataBlock_t *b = nffile->block_header;
                nffile->block_header = buff;
                buff = b;
                if (Uncompress_Block_ZSTD(buff, nffile->block_header, nffile->buff_size) < 0) {
                    LogError("Zstd decompress failed");
                    failed = 1;
                }
#else
                LogError("Zstd compression not enabled");
#endif
            } break;
            default:
                LogError("Unknown compression: %d", compression);
                failed = 1;
        }

        if (failed) continue;

        if (verbose)
            printf("Uncompressed block %i, type: %u, size: %u, flags: 0x%x, records: %u\n", numBlocks, nffile->block_header->type,
                   nffile->block_header->size, nffile->block_header->flags, nffile->block_header->NumRecords);

        nffile->buff_ptr = (void *)((pointer_addr_t)nffile->block_header + sizeof(dataBlock_t));

        // record counting
        int blockSize = 0;
        int numRecords = 0;
        if (nffile->block_header->type == DATA_BLOCK_TYPE_4) {  // array block
            recordHeader_t *recordHeader = (recordHeader_t *)nffile->buff_ptr;
            blockSize += sizeof(recordHeader_t);
            LogError("Array block: Record type: %u, size: %u", recordHeader->type, recordHeader->size);
            while (blockSize < nffile->block_header->size) {
                blockSize += recordHeader->size;
                numRecords++;
            }
            if (blockSize != nffile->block_header->size) {
                LogError("Error in block: %u, counted array size: %u != header size: %u\n", numBlocks, blockSize, nffile->block_header->size);
                close(fd);
                return 0;
            }
        } else {
            while (blockSize < nffile->block_header->size) {
                recordHeader_t *recordHeader = (recordHeader_t *)nffile->buff_ptr;
                numRecords++;
                if ((blockSize + recordHeader->size) > nffile->block_header->size) {
                    LogError("Record size %u extends beyond block size: %u", blockSize + recordHeader->size, nffile->block_header->size);
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
                            printf(" ** malformed **");
                        }
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
                nffile->buff_ptr += recordHeader->size;
            }
        }
        if (numRecords != nffile->block_header->NumRecords) {
            LogError("Block %u num records %u != counted records: %u", i, nffile->block_header->NumRecords, numRecords);
            close(fd);
            return 0;
        }
        totalRecords += numRecords;

        if (blockSize != nffile->block_header->size) {
            LogError("block size %u != sum record size: %u", blockSize, nffile->block_header->size);
            close(fd);
            return 0;
        }

        if (i + 1 == fileHeader.NumBlocks) {
            off_t fsize = lseek(fd, 0, SEEK_CUR);
            if (fileHeader.appendixBlocks && fsize != fileHeader.offAppendix) {
                LogError("Invalid appendix offset - Expected: %u, found: %u", fileHeader.offAppendix, fsize);
                close(fd);
                return 0;
            }
            if (fileHeader.appendixBlocks) printf("Checking appendix blocks\n");
        }
    }

    FreeDataBlock(buff);

    off_t fsize = lseek(fd, 0, SEEK_CUR);
    if (fsize < stat_buf.st_size) {
        LogError("Extra data detected after regular blocks: %i bytes", stat_buf.st_size - fsize);
    }

    printf("\nTotal\n");
    if (type1) printf("Type 1 blocks : %u\n", type1);
    if (type2) printf("Type 2 blocks : %u\n", type2);
    if (type3) printf("Type 3 blocks : %u\n", type3);
    if (type4) printf("Type 4 blocks : %u\n", type4);
    printf("Records       : %u\n", totalRecords);

    DisposeFile(nffile);

    return 1;

}  // End of QueryFile

static int QueryFileV1(int fd, fileHeaderV2_t *fileHeaderV2) {
    struct stat stat_buf;

    if (fstat(fd, &stat_buf)) {
        LogError("Can't fstat: %s", strerror(errno));
        return 0;
    }

    fileHeaderV1_t fileHeader;
    // set file size to current position ( file header )
    ssize_t ret = read(fd, (void *)&fileHeader, sizeof(fileHeaderV1_t));
    if (ret < 1) {
        LogError("read() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    // magic and version already checked
    fileHeaderV2->version = fileHeader.version;
    fileHeaderV2->magic = fileHeader.magic;
    fileHeaderV2->encryption = NOT_ENCRYPTED;
    fileHeaderV2->appendixBlocks = 0;
    fileHeaderV2->offAppendix = 0;
    fileHeaderV2->NumBlocks = fileHeader.NumBlocks;

    int anon = TestFlag(fileHeader.flags, FLAG_ANONYMIZED);
    ClearFlag(fileHeader.flags, FLAG_ANONYMIZED);

    if ((TestFlag(fileHeader.flags, FLAG_LZO_COMPRESSED) + TestFlag(fileHeader.flags, FLAG_LZ4_COMPRESSED) +
         TestFlag(fileHeader.flags, FLAG_BZ2_COMPRESSED)) > FLAG_LZ4_COMPRESSED) {
        LogError("Multiple v1 compression flags: 0x%x", fileHeader.flags & COMPRESSION_MASK);
        return 0;
    }
    int compression = NOT_COMPRESSED;
    char *s = "not compressed";
    if (TestFlag(fileHeader.flags, FLAG_LZO_COMPRESSED)) {
        compression = LZO_COMPRESSED;
        s = "lzo compressed";
    }
    if (TestFlag(fileHeader.flags, FLAG_LZ4_COMPRESSED)) {
        compression = LZ4_COMPRESSED;
        s = "lz4 compressed";
    }
    if (TestFlag(fileHeader.flags, FLAG_BZ2_COMPRESSED)) {
        compression = BZ2_COMPRESSED;
        s = "bz2 compressed";
    }
    fileHeaderV2->compression = compression;

    printf("Version    : %u - %s %s\n", fileHeader.version, s, anon ? "anonymized" : "");
    printf("Blocks     : %u\n", fileHeader.NumBlocks);

    stat_recordV1_t stat_recordV1;
    ret = read(fd, (void *)&stat_recordV1, sizeof(stat_recordV1_t));
    if (ret < 0) {
        LogError("read() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }
    if (ret != sizeof(stat_recordV1_t)) {
        LogError("Error reading v1 stat record - short read. Expected: %u, get %u", sizeof(stat_recordV1_t), ret);
        return 0;
    }

    return 1;
}  // End of QueryFileV1

static void UpdateStat(stat_record_t *s, stat_recordV1_t *sv1) {
    s->numflows = sv1->numflows;
    s->numbytes = sv1->numbytes;
    s->numpackets = sv1->numpackets;
    s->numflows_tcp = sv1->numflows_tcp;
    s->numflows_udp = sv1->numflows_udp;
    s->numflows_icmp = sv1->numflows_icmp;
    s->numflows_other = sv1->numflows_other;
    s->numbytes_tcp = sv1->numbytes_tcp;
    s->numbytes_udp = sv1->numbytes_udp;
    s->numbytes_icmp = sv1->numbytes_icmp;
    s->numbytes_other = sv1->numbytes_other;
    s->numpackets_tcp = sv1->numpackets_tcp;
    s->numpackets_udp = sv1->numpackets_udp;
    s->numpackets_icmp = sv1->numpackets_icmp;
    s->numpackets_other = sv1->numpackets_other;
    s->firstseen = 1000LL * (uint64_t)sv1->first_seen + (uint64_t)sv1->msec_first;
    s->lastseen = 1000LL * (uint64_t)sv1->last_seen + (uint64_t)sv1->msec_last;
    s->sequence_failure = sv1->sequence_failure;
}  // End of UpdateStat

// simple interface to get a stat record
int GetStatRecord(char *filename, stat_record_t *stat_record) {
    nffile_t *nffile = OpenFileStatic(filename, NULL);
    if (!nffile) {
        return 0;
    }

    memcpy((void *)stat_record, nffile->stat_record, sizeof(stat_record_t));
    DisposeFile(nffile);

    return 1;

}  // End of GetStatRecord

void PrintStat(stat_record_t *s, char *ident) {
    if (s == NULL) return;

    // format info: make compiler happy with conversion to (unsigned long long),
    // which does not change the size of the parameter
    printf("Ident: %s\n", ident);
    printf("Flows: %llu\n", (unsigned long long)s->numflows);
    printf("Flows_tcp: %llu\n", (unsigned long long)s->numflows_tcp);
    printf("Flows_udp: %llu\n", (unsigned long long)s->numflows_udp);
    printf("Flows_icmp: %llu\n", (unsigned long long)s->numflows_icmp);
    printf("Flows_other: %llu\n", (unsigned long long)s->numflows_other);
    printf("Packets: %llu\n", (unsigned long long)s->numpackets);
    printf("Packets_tcp: %llu\n", (unsigned long long)s->numpackets_tcp);
    printf("Packets_udp: %llu\n", (unsigned long long)s->numpackets_udp);
    printf("Packets_icmp: %llu\n", (unsigned long long)s->numpackets_icmp);
    printf("Packets_other: %llu\n", (unsigned long long)s->numpackets_other);
    printf("Bytes: %llu\n", (unsigned long long)s->numbytes);
    printf("Bytes_tcp: %llu\n", (unsigned long long)s->numbytes_tcp);
    printf("Bytes_udp: %llu\n", (unsigned long long)s->numbytes_udp);
    printf("Bytes_icmp: %llu\n", (unsigned long long)s->numbytes_icmp);
    printf("Bytes_other: %llu\n", (unsigned long long)s->numbytes_other);
    printf("First: %llu\n", s->firstseen / 1000LL);
    printf("Last: %llu\n", s->lastseen / 1000LL);
    printf("msec_first: %llu\n", s->firstseen % 1000LL);
    printf("msec_last: %llu\n", s->lastseen % 1000LL);
    printf("Sequence failures: %llu\n", (unsigned long long)s->sequence_failure);
}  // End of PrintStat

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

    if (s2->firstseen < s1->firstseen) {
        s1->firstseen = s2->firstseen;
    }
    if (s2->lastseen > s1->lastseen) {
        s1->lastseen = s2->lastseen;
    }

}  // End of SumStatRecords

void PrintGNUplotSumStat(nffile_t *nffile) {
    char *dateString = strstr(nffile->fileName, "nfcapd.");
    if (dateString) {
        dateString += 7;
        time_t when = ISO2UNIX(dateString);
        struct tm *ts = localtime(&when);
        char datestr[64];
        strftime(datestr, 63, "%Y-%m-%d %H:%M:%S", ts);
        printf("%s,%llu,%llu,%llu\n", datestr, (long long unsigned)nffile->stat_record->numflows, (long long unsigned)nffile->stat_record->numpackets,
               (long long unsigned)nffile->stat_record->numbytes);
    } else {
        printf("No datstring\n");
    }
}  // End of PrintGNUplotSumStat