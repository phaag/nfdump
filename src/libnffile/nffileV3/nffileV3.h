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

#ifndef _NFFILEV3_H
#define _NFFILEV3_H 1

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "nfdump.h"
#include "queue.h"

/*
 * The file format v3 of nffile is based on the previous v2 format.
 * In order to gain more flexibility and future proof stability,
 * the v3 format is still a container based format as v2.
 * The goal is to preserve datablocks, compression, heterogeneous
 * block types, while modernizing the metadata, block headers, and
 * options for indexing so that analytics and an optional V4 columnar
 * conversion becomes dramatically faster and simpler.
 *
 * File layout:
 * +-----------+-------------+-------------+-----+------------------+---------+
 * | Header    | DataBlocks  | ...         | ... | Block Directory  | Footer  |
 * +-----------+-------------+-------------+-----+------------------+---------+
 *
 * The header and footer have a pointer to the directory
 *
 * Metadata region (appendix 2.0) - optionall follows after datablocks
 * The metadata region may stores data along the record data such es:
 * - exporter table
 * - statistics
 * - schema versions
 * - optional columnar summaries
 *
 * The block directory lists the number, type and offsets of blocks
 *
 */

typedef struct fileHeaderV3_s {
#define HEADER_MAGIC_V3 0xA50C
    uint16_t magic;
#define LAYOUT_VERSION_3 3
    uint16_t layoutVersion;  // layout v3 with new header
    uint32_t nfdVersion;     // version of nfdump that wrote this file

    uint64_t created;  // file creation timestamp
    uint32_t creator;  // program created this file

    uint32_t flags;      // flags - future use
    uint32_t blockSize;  // max uncompressed block size

    uint32_t dirSize;       // size of directory
    uint64_t offDirectory;  // offset to block directory
    uint64_t reserved;      // reserved for future use
} fileHeaderV3_t;
_Static_assert((sizeof(fileHeaderV3_t) & 7) == 0, "fileHeaderV3_t for 8 byte aligned");

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
 * Required footer:
 * Redundant entry to block directory
 */
typedef struct fileFooterV3_s {
    uint32_t magic;  // FOOTER_MAGIC
#define FOOTER_MAGIC_V3 0xA50F
    uint32_t dirSize;       // size of directory
    uint64_t offDirectory;  // offset to block directory
    uint64_t checksum;      // optional checksum xxHash64
                            // checksum covers the directory region from offDirectory to offDirectory + dirSize
} fileFooterV3_t;
_Static_assert((sizeof(fileFooterV3_t) & 7) == 0, "fileFooterV3_t for 8 byte aligned");

/*
 * directory entry:
 * for each datablock, a directory entry exists.
 */
typedef struct directoryEntryV3_s {
    uint32_t type;    // type of datablock
    uint32_t size;    // on-disk size of datablock, raw or compressed
    uint64_t offset;  // offset of this datablock
} directoryEntryV3_t;

typedef struct blockDirectoryV3_s {
#define DIRECTORY_MAGIC 0xB10CB10C
    uint32_t magic;       // magic for the directory block
    uint32_t numEntries;  // number of entries

    directoryEntryV3_t entries[];
} blockDirectoryV3_t;

// block array while writing a file
typedef struct blockListV3_s {
    uint32_t count;
    uint32_t capacity;

    directoryEntryV3_t *entries;
} blockListV3_t;

/*
 * Generic block header for each data block, independant of the type
 */
#define BLOCKHEADER                                                       \
    struct {                                                              \
        uint32_t type;        /* Block type */                            \
        uint32_t discSize;    /* on-disc payload size with this header */ \
        uint32_t rawSize;     /* uncompressed payload size with header */ \
        uint16_t compression; /* block-level compression */               \
        uint16_t encryption;  /* block-level encryption */                \
    }

#define MESSAGEHEADER                         \
    struct {                                  \
        uint32_t type;   /* message type */   \
        uint32_t length; /* message length */ \
    }

/*
 * possible compression methods
 * UNDEF_COMPRESSED (0) is the default for fresh blocks (memset/calloc).
 * nfwrite() applies the file-level default compression for UNDEF blocks.
 * Any other value overrides the file default on a per-block basis.
 */
#define UNDEF_COMPRESSED 0
#define NOT_COMPRESSED 1
#define LZO_COMPRESSED 2
#define BZ2_COMPRESSED 3
#define LZ4_COMPRESSED 4
#define ZSTD_COMPRESSED 5

#define LEVEL_0 0

/*
 * possible encryption methods
 */
#define NOT_ENCRYPTED 0

/*
 * Generic data block
 */
typedef struct dataBlockV3_s {
    BLOCKHEADER;
} dataBlockV3_t;
_Static_assert((sizeof(dataBlockV3_t) & 7) == 0, "dataBlockV3_t for 8 byte aligned");

enum {
    BLOCK_TYPE_NULL = 0,  // unused - undefined
    BLOCK_TYPE_FLOW,      // V4 flow records (heterogeneous sizes)
    BLOCK_TYPE_ARRAY,     // homogeneous fixed-size elements
    BLOCK_TYPE_STATS,     // stat_record_t
    BLOCK_TYPE_IDENT,     // source identifier
    BLOCK_TYPE_META,      // metadata (schema, exporter table, etc.)
    BLOCK_TYPE_MSG,       // message block
    BLOCK_TYPE_EXP,       // exporter meta data
    BLOCK_MAX_TYPES       // max + 1 block types
};

/*
 * generic data record.
 * Store NumRecords of v4 flow records. Each may have a different length
 * The max size of dataBlockV3_t uncompressed is blockSize of fileHeaderV3_t
 */
typedef struct flowBlockV3_s {
    BLOCKHEADER;

    uint32_t numRecords;       // number of flow records in this block
    uint64_t extensionBitmap;  // or'ed bitmask of extID values present in this block
    uint64_t minTimestamp;     // earliest record timestamp
    uint64_t maxTimestamp;     // latest record timestamp
    uint64_t checksum;         // xxHash64
} flowBlockV3_t;
_Static_assert((sizeof(flowBlockV3_t) & 7) == 0, "flowBlockV3_t for 8 byte aligned");

/*
 * array block header
 * Stores numElements, each of elementSize.
 * Example - type: nbar, ifname, vrf name, geo db, tor db records etc.
 */
typedef struct arrayBlock_s {
    BLOCKHEADER;

    uint32_t numElements;  // number of elements in array block
    uint16_t elementSize;  // size of each element
    uint16_t elementType;  // type of element
} arrayBlockV3_t;
_Static_assert((sizeof(arrayBlockV3_t) & 7) == 0, "arrayBlockV3_t for 8 byte aligned");

/*
 * message block to transport messages
 */
typedef struct msgBlock_s {
    BLOCKHEADER;

    uint32_t numMessages;  // number of elements in array block
    uint32_t align;        // 8-bytes alignment
} msgBlockV3_t;
_Static_assert((sizeof(msgBlockV3_t) & 7) == 0, "msgBlockV3_t for 8 byte aligned");

/*
 * message block to transport messages
 */
typedef struct expBlock_s {
    BLOCKHEADER;

    uint32_t numExporter;  // number of elements in array block
    uint32_t align;        // 8-bytes alignment
} expBlockV3_t;
_Static_assert((sizeof(expBlockV3_t) & 7) == 0, "expBlockV3_t for 8 byte aligned");

// file handle for v3 type fle
typedef struct nffileV3_s {
    const uint8_t *map;  // mmap base pointer
    size_t mapSize;      // file size = mapping length
    int fd;              // fd open while mapped
    char *fileName;      // filename

    // Read file : pointers into the mapped region (read-only)
    // Write file: pointers to allocated memory or NULL
    fileHeaderV3_t *fileHeader;          // file header
    blockDirectoryV3_t *blockDirectory;  // block directory
    fileFooterV3_t *fileFooter;          // footer

    blockListV3_t blockList;  // to write a file, keep blockupdates

    // metadata copied out of the mapping
    stat_record_t *stat_record;
    char *ident;

    uint32_t numWorkers;        // number of workers for this handle
    uint32_t compression;       // default type of compression
    uint32_t compressionLevel;  // default compression level, if available.
    uint32_t encryption;        // default encryption for blocks
    _Atomic off_t blockOffset;  // atomic block I/O offset (read: mmap scan pos, write: pwrite pos)
    queue_t *processQueue;      // blocks ready to be processed. Connects consumer/producer threads
    pthread_mutex_t wlock;      // writer lock
    pthread_t worker[];         // nfread/nfwrite worker thread;
} nffileV3_t;

#define DefaultQueueSize 8

#define ONE_MB 1048576
#define BLOCK_SIZE_V3 4 * ONE_MB  // 1MB total allocation

#define DIR_INIT_CAPACITY 256

#define InitDataBlock(ptr, size)                                                                \
    ((ptr) = _Generic((ptr),                                                                    \
         dataBlockV3_t *: NewGenericDataBlock(size, BLOCK_TYPE_NULL, sizeof(dataBlockV3_t)),    \
         flowBlockV3_t *: NewGenericDataBlock(size, BLOCK_TYPE_FLOW, sizeof(flowBlockV3_t)),    \
         arrayBlockV3_t *: NewGenericDataBlock(size, BLOCK_TYPE_ARRAY, sizeof(arrayBlockV3_t)), \
         msgBlockV3_t *: NewGenericDataBlock(size, BLOCK_TYPE_MSG, sizeof(msgBlockV3_t)),       \
         expBlockV3_t *: NewGenericDataBlock(size, BLOCK_TYPE_EXP, sizeof(expBlockV3_t))))

#define ResetCursor(ptr)                                                       \
    _Generic((ptr),                                                            \
        dataBlockV3_t *: (void *)((uint8_t *)(ptr) + sizeof(dataBlockV3_t)),   \
        flowBlockV3_t *: (void *)((uint8_t *)(ptr) + sizeof(flowBlockV3_t)),   \
        arrayBlockV3_t *: (void *)((uint8_t *)(ptr) + sizeof(arrayBlockV3_t)), \
        msgBlockV3_t *: (void *)((uint8_t *)(ptr) + sizeof(msgBlockV3_t)),     \
        expBlockV3_t *: (void *)((uint8_t *)(ptr) + sizeof(expBlockV3_t)),     \
        const expBlockV3_t *: (void *)((uint8_t *)(ptr) + sizeof(expBlockV3_t)))

#define GetCursor(block) ((void *)block + ((dataBlockV3_t *)block)->rawSize)

#define IsAvailable(block, blockSize, requested) (((block)->rawSize + (requested)) < (blockSize))

// shared functions — nffileV3.c
int Init_nffile(uint32_t workers, queue_t *fileList);

nffileV3_t *GetNextFile(void);

int ReportBlocks(void);

nffileV3_t *NewFile(uint32_t num_workers, uint32_t queueSize);

void *NewGenericDataBlock(uint32_t blockSize, uint32_t blockType, uint32_t headerSize);

dataBlockV3_t *NewDataBlock(uint32_t blockSize);

flowBlockV3_t *NewFlowBlock(uint32_t blockSize);

void FreeDataBlock(void *dataBlock);

int AddBlock(blockListV3_t *blockList, uint32_t type, uint64_t offset, uint32_t diskSize);

int PreallocateDirectory(blockListV3_t *blockList, uint32_t expectedBlocks);

void joinWorkers(nffileV3_t *nffile);

void TerminateWorkers(nffileV3_t *nffile);

void SetIdent(nffileV3_t *nffile, char *Ident);

void CloseFileV3(nffileV3_t *nffile);

void DeleteFileV3(nffileV3_t *nffile);

int RenameAppendV3(const char *oldName, const char *newName);

void ModifyCompressFile(uint32_t compressType, uint32_t compressLevel);

// nfread.c
nffileV3_t *mmapFileV3(const char *filename);

nffileV3_t *OpenFileV3(const char *filename);

void *ReadBlockV3(nffileV3_t *nffile);

const expBlockV3_t *getNextExporter(nffileV3_t *nffile, uint32_t *nextOffset);

// nfwrite.c
nffileV3_t *OpenNewFileV3(const char *filename, uint32_t creator, uint16_t compression, uint16_t compressionLevel, uint32_t encryption);

nffileV3_t *OpenNewFileTmpV3(const char *tmplate, uint32_t creator, uint16_t compression, uint16_t compressionLevel, uint32_t encryption);

void WriteBlockV3(nffileV3_t *nffile, void *blockHeader);

void PushBlockV3(queue_t *queue, void *blockHeader);

void FlushBlockV3(nffileV3_t *nffile, void *blockHeader);

int FlushFileV3(nffileV3_t *nffile);

// nfcheck.c
int VerifyFileV3(const char *filename, int verbose);

int ReWriteV3(const char *filename);

#endif