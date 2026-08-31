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
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "bloom.h"
#include "conf/nfconf.h"
#include "exporter.h"
#include "id.h"
#include "logging.h"
#include "nfcompress.h"
#include "nfdump.h"
#include "nffileV2/nffileV2.h"
#include "nffileV3.h"
#include "nfxV4.h"
#include "queue.h"
#include "util.h"
#include "vcs_track.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef HAVE_LIBSODIUM
#include <sodium.h>

#include "nfcrypto.h"
#endif

#define XXH_INLINE_ALL
#include "xxhash.h"

#define LAYOUT_VERSION_1 1
#define LAYOUT_VERSION_2 2

static const char *nf_creator[MAX_CREATOR] = {
    [CREATOR_UNKNOWN] = "unknown",     [CREATOR_NFCAPD] = "nfcapd",       [CREATOR_NFPCAPD] = "nfpcapd",     [CREATOR_SFCAPD] = "sfcapd",
    [CREATOR_NFDUMP] = "nfdump",       [CREATOR_NFANON] = "nfanon",       [CREATOR_NFPROFILE] = "nfprofile", [CREATOR_GEOLOOKUP] = "geolookup",
    [CREATOR_FT2NFDUMP] = "ft2nfdump", [CREATOR_TORLOOKUP] = "torlookup",
};

static const char *CompressionType(uint32_t compression) {
    return compression == NOT_COMPRESSED    ? "not compressed"
           : compression == LZO_COMPRESSED  ? "lzo compressed"
           : compression == LZ4_COMPRESSED  ? "lz4 compressed"
           : compression == ZSTD_COMPRESSED ? "zstd compressed"
           : compression == BZ2_COMPRESSED  ? "bz2 compressed"
                                            : "unknown compression";
}  // End of CompressionType

static int VerifyExporterInfoRecord(const exporter_info_record_v4_t *exporter, size_t available) {
    if (available < sizeof(*exporter) || exporter->type != ExporterInfoRecordV4Type || exporter->size < sizeof(*exporter) ||
        exporter->size > available) {
        return 0;
    }

    if (exporter->sampler_count > exporter->sampler_capacity) return 0;

    size_t expectedSize = sizeof(*exporter) + (size_t)exporter->sampler_capacity * sizeof(sampler_record_v4_t);
    return exporter->size == expectedSize;
}  // End of VerifyExporterInfoRecord

/* Bloom metadata is a fixed, ordered four-record prefix. nfdump's fast
 * block-filter path maps these records directly, so accepting a truncated,
 * duplicate, or misplaced record would make that path unsafe or incorrect. */
static int BloomMetaIndex(uint16_t metaType) {
    switch (metaType) {
        case META_TYPE_BLOOM_SRC_IPV4:
            return 0;
        case META_TYPE_BLOOM_DST_IPV4:
            return 1;
        case META_TYPE_BLOOM_SRC_IPV6:
            return 2;
        case META_TYPE_BLOOM_DST_IPV6:
            return 3;
        default:
            return -1;
    }
}  // End of BloomMetaIndex

static int VerifyBloomMetaRecord(const metaRecordHeader_t *meta, size_t available) {
    return available >= sizeof(*meta) && meta->type == METARecord && meta->align == 0 && meta->size == sizeof(*meta) + sizeof(bloomFilter_t);
}  // End of VerifyBloomMetaRecord

/* Validate a decoded flow block. Record boundaries are always checked;
 * check-verbose additionally validates every V4 extension directory.
 * bloomBlocks counts blocks with a complete bloom metadata prefix and
 * flowRecords counts actual V4 flow records, excluding metadata records. */
static int VerifyFlowBlock(const flowBlockV3_t *flowBlock, uint32_t blockNum, v4RecordCheck_t checkLevel, uint32_t *bloomBlocks,
                           uint64_t *flowRecords) {
    if (flowBlock->rawSize < sizeof(*flowBlock)) {
        printf("Flow block %u: rawSize %u is smaller than its header\n", blockNum, flowBlock->rawSize);
        return 0;
    }
    if (flowBlock->numRecords == 0) {
        printf("Flow block %u: contains no records\n", blockNum);
        return 0;
    }

    const uint8_t *recordPtr = (const uint8_t *)flowBlock + sizeof(*flowBlock);
    const uint8_t *endPtr = (const uint8_t *)flowBlock + flowBlock->rawSize;
    uint8_t bloomMask = 0;
    uint32_t blockFlowRecords = 0;
    for (uint32_t i = 0; i < flowBlock->numRecords; i++) {
        size_t remaining = (size_t)(endPtr - recordPtr);
        if (remaining < sizeof(recordHeader_t)) {
            printf("Flow block %u: record %u header exceeds block size\n", blockNum, i);
            return 0;
        }

        const recordHeader_t *record = (const recordHeader_t *)recordPtr;
        if (record->size < sizeof(*record) || record->size > remaining) {
            printf("Flow block %u: record %u has invalid size %u\n", blockNum, i, record->size);
            return 0;
        }

        if (record->type == V4Record) {
            if (!VerifyV4Record((const recordHeaderV4_t *)record, record->size, checkLevel)) {
                printf("Flow block %u: invalid V4 record %u\n", blockNum, i);
                return 0;
            }
            blockFlowRecords++;
        } else if (record->type == ExporterInfoRecordV4Type) {
            if (!VerifyExporterInfoRecord((const exporter_info_record_v4_t *)record, record->size)) {
                printf("Flow block %u: invalid exporter record %u\n", blockNum, i);
                return 0;
            }
        } else if (record->type == METARecord) {
            if (record->size < sizeof(metaRecordHeader_t)) {
                printf("Flow block %u: metadata record %u is smaller than its header\n", blockNum, i);
                return 0;
            }

            const metaRecordHeader_t *meta = (const metaRecordHeader_t *)record;
            int bloomIndex = BloomMetaIndex(meta->metaType);
            if (bloomIndex >= 0) {
                uint8_t bloomBit = (uint8_t)(1u << bloomIndex);
                if (i != (uint32_t)bloomIndex || (bloomMask & bloomBit) || !VerifyBloomMetaRecord(meta, record->size)) {
                    printf("Flow block %u: invalid bloom metadata record %u\n", blockNum, i);
                    return 0;
                }
                bloomMask |= bloomBit;
            }
        }

        recordPtr += record->size;
    }

    if (recordPtr != endPtr) {
        printf("Flow block %u: records do not fill the decoded block\n", blockNum);
        return 0;
    }

    if (bloomMask != 0 && bloomMask != 0x0f) {
        printf("Flow block %u: incomplete bloom metadata prefix\n", blockNum);
        return 0;
    }

    if (bloomMask == 0x0f) (*bloomBlocks)++;
    *flowRecords += blockFlowRecords;

    return 1;
}  // End of VerifyFlowBlock

#ifdef HAVE_LIBSODIUM
static const char *EncryptionType(uint32_t enc) {
    return enc == NOT_ENCRYPTED ? "not encrypted" : enc == CHACHA20_POLY1305 ? "ChaCha20-Poly1305" : "unknown encryption";
}  // End of EncryptionType
#endif

// =========================================================================
//  4. VERIFY FILE CONSISTENCY
// =========================================================================
//
// Phase 1 — Header validation (magic, version, blockSize)
// Phase 2 — Sequential block scan: read each block header, validate
//           type/size/rawSize, count blocks by type
// Phase 3 — Directory validation: read directory, verify entry count
//           matches scanned blocks, verify each entry offset/size
// Phase 4 — Footer validation: verify magic, cross-check offDirectory
// Phase 5 — Check no trailing garbage after footer

int VerifyFileV3(const char *filename, int verbose) {
    if (!filename) return 0;

    int fd = open(filename, O_RDWR);
    if (fd < 0) {
        LogError("open() failed for '%s': %s", filename, strerror(errno));
        return 0;
    }

    printf("Verify file: '%s' ...\n", filename);

    struct stat sb;
    if (fstat(fd, &sb) < 0) {
        LogError("fstat() failed for '%s': %s", filename, strerror(errno));
        close(fd);
        return 0;
    }

    size_t fileSize = (size_t)sb.st_size;
    if (fileSize < sizeof(fileHeaderV3_t)) {
        LogError("File size error for '%s': too small for header (%zu bytes)", filename, fileSize);
        close(fd);
        return 0;
    }

    // map entire file read/write, in case we need to fix something
    uint8_t *map = mmap(NULL, fileSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        LogError("mmap() failed for '%s': %s", filename, strerror(errno));
        close(fd);
        return 0;
    }

    // validate header
    fileHeaderV3_t *fileHeader = (fileHeaderV3_t *)map;

    if (fileHeader->magic != HEADER_MAGIC_V3) {
        LogError("Bad magic 0x%X in '%s' - not an nfdump file", fileHeader->magic, filename);
        munmap((void *)map, fileSize);
        close(fd);
        return 0;
    }

    if (fileHeader->layoutVersion == LAYOUT_VERSION_1) {
        LogError("Layout version 1 no longer supported. Use nfdump 1.7.x to process this file");
        munmap((void *)map, fileSize);
        close(fd);
        return 0;
    }

    if (fileHeader->layoutVersion == LAYOUT_VERSION_2) {
        munmap((void *)map, fileSize);
        close(fd);
        return VerifyFileV2(filename, verbose);
    }

    if (fileHeader->layoutVersion != LAYOUT_VERSION_3) {
        LogError("Unknown layout version %u in '%s'. Cannot process this file", fileHeader->layoutVersion, filename);
        munmap((void *)map, fileSize);
        close(fd);
        return 0;
    }

    if (fileHeader->creator >= MAX_CREATOR) {
        LogError("Creator tag %u out of range - set to unknown", fileHeader->creator);
        fileHeader->creator = CREATOR_UNKNOWN;
    }

    printf("=== Phase 1: Header validation ===\n");
    printf("File        : %s\n", filename);
    printf("Size        : %zu\n", fileSize);
    printf("Version     : %u\n", fileHeader->layoutVersion);
    printf("Block size  : %u\n", fileHeader->blockSize);
    printf("Compression : %s\n", CompressionType(fileHeader->compression));
    printf("Creator     : %s(ID:%u)\n", nf_creator[fileHeader->creator], fileHeader->creator);

    time_t created = (time_t)fileHeader->created;
    struct tm tbuf;
    struct tm *t = localtime_r(&created, &tbuf);
    char tstr[64];
    strftime(tstr, sizeof(tstr), "%Y-%m-%d %H:%M:%S", t);
    printf("Created     : %s\n", tstr);
    printf("Encrypted   : %s\n", (fileHeader->flags & FILE_FLAG_ENCRYPTED) ? "yes" : "no");

    uint32_t blockSize = fileHeader->blockSize;
    if (blockSize == 0 || blockSize > 64 * ONE_MB) {
        printf("Invalid blockSize %u in '%s' - using default\n", fileHeader->blockSize, filename);
        // set max block size and continue scanning
        blockSize = 64 * ONE_MB;
    }

    // validate footer
    fileFooterV3_t *footer = NULL;
    if (fileSize >= sizeof(fileFooterV3_t)) {
        footer = (fileFooterV3_t *)(map + fileSize - sizeof(fileFooterV3_t));
        if (footer->magic != FOOTER_MAGIC_V3) {
            printf("Bad magic 0x%X for footer in '%s'\n", footer->magic, filename);
            footer = NULL;
        }
    }

    if (fileHeader->offDirectory == 0) {
        printf("File '%s' not cleanly closed (offDirectory == 0)\n", filename);
    }

    // get blockDirectory
    const blockDirectoryV3_t *blockDirectory = NULL;
    uint32_t dirSize = 0;
    int checksumFailed = 0;
    if (fileHeader->offDirectory >= sizeof(fileHeaderV3_t) && fileHeader->offDirectory <= fileSize - sizeof(blockDirectoryV3_t)) {
        blockDirectory = (const blockDirectoryV3_t *)(map + fileHeader->offDirectory);
        if (blockDirectory->magic != DIRECTORY_MAGIC) {
            printf("Bad directory magic 0x%X in header for '%s'\n", blockDirectory->magic, filename);
            blockDirectory = NULL;
        } else {
            // check directory size
            if (fileHeader->dirSize < sizeof(*blockDirectory) || fileHeader->dirSize > fileSize - fileHeader->offDirectory) {
                printf("Bad directory in header for '%s' - extends beyond EOF\n", filename);
                blockDirectory = NULL;
            } else {
                // valid blockDirectory
                dirSize = fileHeader->dirSize;
            }
        }
    } else {
        printf("File '%s' not cleanly closed - try to recover\n", filename);
    }

    if (footer) {
        if (footer->checksum) printf("Checksum    : 0x%" PRIx64 "\n", footer->checksum);
        do {
            if (blockDirectory == NULL) {
                // no valid block directory found - try to recover from footer, if it is valid
                if (footer && footer->offDirectory >= sizeof(fileHeaderV3_t) && footer->offDirectory <= fileSize - sizeof(blockDirectoryV3_t)) {
                    // block directory within file
                    blockDirectory = (const blockDirectoryV3_t *)(map + footer->offDirectory);
                } else {
                    break;
                }
                if (blockDirectory->magic != DIRECTORY_MAGIC) {
                    printf("Bad directory magic 0x%X in footer for '%s'\n", blockDirectory->magic, filename);
                    blockDirectory = NULL;
                    break;
                }
                // valid block directory
                if (footer->dirSize < sizeof(*blockDirectory) || footer->dirSize > fileSize - footer->offDirectory) {
                    // block directory valid but extends beyond EOF
                    printf("Bad directory in footer for '%s' - extends beyond EOF\n", filename);
                    blockDirectory = NULL;
                    break;
                } else {
                    // finally valid block directory found
                    dirSize = footer->dirSize;
                }
            }
        } while (0);
    }

    // verify directory checksum if present
    if (footer && blockDirectory && footer->checksum != 0) {
        uint64_t computed = XXH3_64bits(blockDirectory, dirSize);
        if (computed != footer->checksum) {
            printf("Directory checksum mismatch: stored %016" PRIx64 " computed %016" PRIx64 "\n", footer->checksum, computed);
            checksumFailed = 1;
        }
    }

    if (blockDirectory == NULL) {
        printf("Failed to read or recover a valid block directory in '%s'\n", filename);
    } else {
        // verify directory entries fit
        if (blockDirectory->numEntries > (dirSize - sizeof(*blockDirectory)) / sizeof(directoryEntryV3_t)) {
            printf("Directory numEntries %u exceeds dirSize\n", blockDirectory->numEntries);
            printf("Failed to read/recover a valid block directory in '%s'\n", filename);
            blockDirectory = NULL;
            dirSize = 0;
        }
    }

    // align header/footer eintries, if needed
    if (footer && footer->offDirectory != fileHeader->offDirectory) {
        printf("Missmatch for directory entry in header/footer\n");
        if (blockDirectory) {
            printf("Recovered valid block directory\n");
            printf("Fix block directory offset\n");
            off_t dirOffset = (uint8_t *)blockDirectory - map;
            fileHeader->offDirectory = dirOffset;
            fileHeader->dirSize = dirSize;
            if (footer) {
                footer->offDirectory = dirOffset;
                footer->dirSize = dirSize;
            }
        }
    }

#ifdef HAVE_LIBSODIUM
    /* -----------------------------------------------------------------------
     * Encryption handling: find cryptoHeaderBlock, derive and verify key.
     * Must happen before the block scan so we can decrypt blocks for deeper
     * validation (block-count checks etc.).
     * ----------------------------------------------------------------------- */
    int fileEncrypted = (fileHeader->flags & FILE_FLAG_ENCRYPTED) != 0;
    int keyVerified = 0;
    nffile_crypto_t verifyCrypto = {0};
    const nffile_crypto_t *verifyCryptoPtr = NULL;

    if (fileEncrypted && blockDirectory) {
        const cryptoHeaderBlock_t *cryptoHdr = NULL;

        for (uint32_t i = 0; i < blockDirectory->numEntries; i++) {
            const directoryEntryV3_t *e = &blockDirectory->entries[i];
            if (e->type != BLOCK_TYPE_META) continue;
            if (e->offset > fileSize || e->size > fileSize - e->offset) continue;
            if (e->size < sizeof(cryptoHeaderBlock_t)) continue;
            const cryptoHeaderBlock_t *cand = (const cryptoHeaderBlock_t *)(map + e->offset);
            // identify by size and plaintext marker
            if (cand->discSize == sizeof(cryptoHeaderBlock_t) && cand->encryption == NOT_ENCRYPTED && cand->compression == NOT_COMPRESSED) {
                cryptoHdr = cand;
                break;
            }
        }

        printf("\n=== Encryption header ===\n");
        if (!cryptoHdr) {
            printf("  ERROR: FILE_FLAG_ENCRYPTED set but no crypto header block found\n");
        } else {
            printf("  Version     : %u%s\n", cryptoHdr->version, cryptoHdr->version == CRYPTO_HEADER_V1 ? "" : " (UNSUPPORTED)");
            printf("  Algorithm   : %s\n", EncryptionType(cryptoHdr->algorithm));
            printf("  KDF         : %s\n", cryptoHdr->kdfType == KDF_PBKDF2_SHA256 ? "Argon2id (labelled PBKDF2-SHA256)" : "unknown");
            printf("  KDF iters   : %u%s\n", cryptoHdr->kdfIterations, cryptoHdr->kdfIterations == 0 ? " (use default)" : "");
            if (cryptoHdr->version != CRYPTO_HEADER_V1) {
                printf("  ERROR: unsupported crypto header version — cannot verify\n");
                checksumFailed = 1;
            } else {
                if (!DeriveKeyFromFile(cryptoHdr, &verifyCrypto)) {
                    printf("  Key         : derivation FAILED\n");
                } else if (!VerifyEncryptionKey(cryptoHdr, &verifyCrypto)) {
                    printf("  Key         : WRONG passphrase or corrupt key-check\n");
                } else {
                    printf("  Key         : verified OK\n");
                    keyVerified = 1;
                    verifyCryptoPtr = &verifyCrypto;
                }

                // verify file-structure MAC (non-zero = MAC present)
                if (keyVerified && footer != NULL) {
                    static const uint8_t zeroMac[32] = {0};
                    if (sodium_memcmp(footer->fileMac, zeroMac, 32) == 0) {
                        printf("  File MAC    : absent (all-zero) — pre-release or unencrypted\n");
                    } else if (VerifyFileMac(&verifyCrypto, fileHeader, cryptoHdr, blockDirectory->entries, blockDirectory->numEntries,
                                             footer->fileMac)) {
                        printf("  File MAC    : verified OK\n");
                    } else {
                        printf("  File MAC    : FAILED — file structure may have been tampered with\n");
                        checksumFailed = 1;
                    }
                }
            }
        }
    }
#else
    int fileEncrypted = (fileHeader->flags & FILE_FLAG_ENCRYPTED) != 0;
    int keyVerified = 0;
    const nffile_crypto_t *verifyCryptoPtr = NULL;
    if (fileHeader->flags & FILE_FLAG_ENCRYPTED) {
        printf("\n=== Encryption info ===\n");
        printf("  File is encrypted but encryption support not compiled in (libsodium missing)\n");
        printf("  Encrypted blocks cannot be validated\n");
    }
#endif /* HAVE_LIBSODIUM */

    // collect a blocklint while parsing
    blockListV3_t blockList = {0};
    blockList.entries = malloc(DIR_INIT_CAPACITY * sizeof(directoryEntryV3_t));
    if (!blockList.entries) {
        printf("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
#ifdef HAVE_LIBSODIUM
        sodium_memzero(&verifyCrypto, sizeof(verifyCrypto));
#endif
        munmap((void *)map, fileSize);
        close(fd);
        return 0;
    }
    blockList.capacity = DIR_INIT_CAPACITY;

    printf("\n=== Phase 2: Sequential block scan ===\n");
    struct {
        uint32_t numBlocks;
        uint32_t compression;
    } blockStat[BLOCK_MAX_TYPES] = {0};

    uint32_t blockSizeFound = 0;
    int blockCheckFailed = 0;
    uint32_t totalBlocks = 0;
    uint32_t unknownBlocks = 0;
    uint32_t bloomBlocks = 0;
    uint64_t totalFlowRecords = 0;
    const v4RecordCheck_t v4CheckLevel = verbose ? V4RECORD_CHECK_EXTENSIONS : V4RECORD_CHECK_BASIC;

    off_t scanEnd = fileHeader->offDirectory ? (off_t)fileHeader->offDirectory : fileSize;
    off_t nextOffset = sizeof(fileHeaderV3_t);

    // const char spinner[4] = {'|', '/', '-', '\\'};
    //  setvbuf(stdout, (char *)NULL, _IONBF, 0);

    while ((nextOffset + (off_t)sizeof(dataBlockV3_t)) <= scanEnd) {
        dataBlockV3_t *dataBlock = (dataBlockV3_t *)(map + nextOffset);
        //    printf("\r%c %5u", spinner[totalBlocks & 0x3], totalBlocks);

        // block size on disk
        if (dataBlock->discSize < sizeof(dataBlockV3_t)) {
            printf("Block %u: invalid discSize %u at offset %jd\n", totalBlocks, dataBlock->discSize, (intmax_t)nextOffset);
            blockCheckFailed = 1;
            break;
        }

        // Verify potential corrupted discSize
        if ((off_t)dataBlock->discSize > (scanEnd - nextOffset)) {
            printf("Block %u: payload size %u extends beyond file at offset %jd\n", totalBlocks, dataBlock->discSize, (intmax_t)nextOffset);
            blockCheckFailed = 1;
            break;
        }
        // raw blocksize
        if (dataBlock->rawSize > blockSizeFound) {
            blockSizeFound = dataBlock->rawSize;
        }

        directoryEntryV3_t scanEntry = {.type = dataBlock->type, .size = dataBlock->discSize, .offset = (uint64_t)nextOffset};
        dataBlockV3_t *decodedBlock = DecodeBlockV3(map, fileSize, blockSize, &scanEntry, verifyCryptoPtr);
        if (!decodedBlock) {
            printf("Block %u: could not decode or validate block at offset %jd\n", totalBlocks, (intmax_t)nextOffset);
            blockCheckFailed = 1;
            break;
        }

        if (verbose)
            printf("Checkblock: type: %u, offset: %jd, rawSize: %u, discSize: %u, compression: %u, encryption: %u, checksum: 0x%" PRIx64 "\n",
                   dataBlock->type, (intmax_t)nextOffset, dataBlock->rawSize, dataBlock->discSize, dataBlock->compression, dataBlock->encryption,
                   dataBlock->checksum);

        switch (dataBlock->type) {
            case BLOCK_TYPE_FLOW: {
                blockStat[BLOCK_TYPE_FLOW].numBlocks++;
                blockStat[BLOCK_TYPE_FLOW].compression = dataBlock->compression;
                if (!VerifyFlowBlock((const flowBlockV3_t *)decodedBlock, totalBlocks, v4CheckLevel, &bloomBlocks, &totalFlowRecords)) {
                    blockCheckFailed = 1;
                }
            } break;
            case BLOCK_TYPE_ARRAY:
                blockStat[BLOCK_TYPE_ARRAY].numBlocks++;
                blockStat[BLOCK_TYPE_ARRAY].compression = dataBlock->compression;
                break;
            case BLOCK_TYPE_STATS:
                blockStat[BLOCK_TYPE_STATS].numBlocks++;
                blockStat[BLOCK_TYPE_STATS].compression = dataBlock->compression;
                break;
            case BLOCK_TYPE_IDENT:
                blockStat[BLOCK_TYPE_IDENT].numBlocks++;
                blockStat[BLOCK_TYPE_IDENT].compression = dataBlock->compression;
                break;
            case BLOCK_TYPE_META:
                blockStat[BLOCK_TYPE_META].numBlocks++;
                blockStat[BLOCK_TYPE_META].compression = dataBlock->compression;
                break;
            case BLOCK_TYPE_EXP:
                blockStat[BLOCK_TYPE_EXP].numBlocks++;
                blockStat[BLOCK_TYPE_EXP].compression = dataBlock->compression;
                break;
            default:
                printf("Block %u: unknown type %u at offset %jd\n", totalBlocks, dataBlock->type, (intmax_t)nextOffset);
                unknownBlocks++;
                break;
        }
        FreeDataBlock(decodedBlock);
        if (!AddBlock(&blockList, dataBlock->type, nextOffset, dataBlock->discSize)) {
            blockCheckFailed = 1;
            break;
        }

        totalBlocks++;
        nextOffset += dataBlock->discSize;
    }
    // printf("\n");

    if (blockCheckFailed) {
        printf("Found bad data blocks\n");
    } else {
        printf("Found %u valid data blocks\n", totalBlocks);
    }

    if (blockSizeFound > blockSize) {
        uint32_t roundedSize = ((blockSizeFound + ONE_MB - 1) / ONE_MB) * ONE_MB;
        if (roundedSize > BLOCK_SIZE_V3 && roundedSize < (64 * ONE_MB)) {
            fileHeader->blockSize = roundedSize;
            printf("Fix blocksize to %u MB\n", roundedSize / ONE_MB);
        }
    }

    // try to verify the block directory and compare it with out blocklist
    // === Phase 3: Directory validation ===
    printf("\n=== Phase 3: Directory validation ===\n");
    uint32_t directoryEntriesFailed = blockDirectory == NULL;
    if (blockCheckFailed == 0 && blockDirectory) {
        if (blockList.count != blockDirectory->numEntries) {
            printf("Block directory count missmatch\n");
            directoryEntriesFailed = 1;
        }
        uint32_t blockCnt = blockList.count < blockDirectory->numEntries ? blockList.count : blockDirectory->numEntries;
        directoryEntryV3_t *listEntry = blockList.entries;
        const directoryEntryV3_t *dirEntry = blockDirectory->entries;
        for (uint32_t i = 0; i < blockCnt; i++) {
            // the corresponding entries must be identical
            if (verbose) {
                printf("[%u] type: %u, size: %u, offset: %" PRIu64 "\n", i, dirEntry[i].type, dirEntry[i].size, dirEntry[i].offset);
            }
            if (memcmp(&listEntry[i], &dirEntry[i], sizeof(directoryEntryV3_t)) != 0) {
                printf("Missmatch on directory entry [%u]: found/expected - type: %u/%u, size: %u/%u, offset: %" PRIu64 "/%" PRIu64 "\n", i,
                       listEntry[i].type, dirEntry[i].type, listEntry[i].size, dirEntry[i].size, listEntry[i].offset, dirEntry[i].offset);
                directoryEntriesFailed = 1;
            }
        }
    }
    if (directoryEntriesFailed == 0) {
        printf("Found %u valid entries\n", blockDirectory->numEntries);
    }

    // --- Summary ---
    printf("\nSummary:\n");
    if (blockCheckFailed) {
        printf("  Total blocks    : block check failed\n");
    } else {
        printf("  Total blocks    : %u\n", totalBlocks);
        if (blockStat[BLOCK_TYPE_FLOW].numBlocks)
            printf("  Flow blocks     : %u - %s\n", blockStat[BLOCK_TYPE_FLOW].numBlocks, CompressionType(blockStat[BLOCK_TYPE_FLOW].compression));
        if (blockStat[BLOCK_TYPE_FLOW].numBlocks)
            printf("  Flow records    : %" PRIu64 " - avg. %.1f/flows block\n", totalFlowRecords,
                   (double)totalFlowRecords / blockStat[BLOCK_TYPE_FLOW].numBlocks);
        if (blockStat[BLOCK_TYPE_FLOW].numBlocks)
            printf("  Bloom metadata  : %s (%u/%u flow blocks)\n", bloomBlocks ? "present" : "absent", bloomBlocks,
                   blockStat[BLOCK_TYPE_FLOW].numBlocks);
        if (blockStat[BLOCK_TYPE_ARRAY].numBlocks)
            printf("  Array blocks    : %u - %s\n", blockStat[BLOCK_TYPE_ARRAY].numBlocks, CompressionType(blockStat[BLOCK_TYPE_ARRAY].compression));
        if (blockStat[BLOCK_TYPE_STATS].numBlocks)
            printf("  Stats blocks    : %u - %s\n", blockStat[BLOCK_TYPE_STATS].numBlocks, CompressionType(blockStat[BLOCK_TYPE_STATS].compression));
        if (blockStat[BLOCK_TYPE_IDENT].numBlocks)
            printf("  Ident blocks    : %u - %s\n", blockStat[BLOCK_TYPE_IDENT].numBlocks, CompressionType(blockStat[BLOCK_TYPE_IDENT].compression));
        if (blockStat[BLOCK_TYPE_META].numBlocks)
            printf("  Meta blocks     : %u - %s\n", blockStat[BLOCK_TYPE_META].numBlocks, CompressionType(blockStat[BLOCK_TYPE_META].compression));
        if (blockStat[BLOCK_TYPE_EXP].numBlocks)
            printf("  Exporter blocks : %u - %s\n", blockStat[BLOCK_TYPE_EXP].numBlocks, CompressionType(blockStat[BLOCK_TYPE_EXP].compression));
        if (unknownBlocks) printf("  Unknown      : %u\n", unknownBlocks);
    }
    printf("  Directory       : %s\n", directoryEntriesFailed == 0 ? "OK" : "FAILED or absent");
    printf("  Checksums       : %s\n", checksumFailed == 0 ? "OK" : "FAILED");
    if (fileEncrypted) {
        printf("  Encryption      : %s\n", keyVerified ? "key verified" : "could not verify key");
    }

    free(blockList.entries);
#ifdef HAVE_LIBSODIUM
    sodium_memzero(&verifyCrypto, sizeof(verifyCrypto));
#endif
    msync(map, fileSize, MS_SYNC);
    munmap(map, fileSize);
    close(fd);

    int encryptionFailed = fileEncrypted && keyVerified == 0;
    return blockCheckFailed == 0 && directoryEntriesFailed == 0 && checksumFailed == 0 && encryptionFailed == 0;

}  // End of VerifyFileV3

// =========================================================================
//  5. REWRITE / REPAIR A CORRUPT V3 FILE
// =========================================================================
//
// ReWriteV3 — salvage a corrupt nffileV3:
//   1. mmap() the original file read-only.
//   2. Validate the header (must be readable).
//   3. Sequential scan of data blocks; copy each valid block to a new
//      temporary file.  Stop at the first invalid block.
//   4. Write a valid block directory for whatever blocks were copied.
//   5. Write a valid footer and rewrite the header with the final
//      directory offset.
//   6. fsync, close, and atomically rename the temp file over the
//      original.
//
// Returns 1 on success, 0 on failure.

// helper: scan blocks, copy to dst, finalize directory/footer/header
static int ReWriteBlocks(const uint8_t *map, size_t fileSize, const fileHeaderV3_t *srcHeader, int dstFd, const char *filename) {
    uint32_t blockSize = srcHeader->blockSize;
    if (blockSize == 0 || blockSize > 64 * ONE_MB) {
        blockSize = BLOCK_SIZE_V3;
    }

    bool xxHash = ConfGetBool("xxhash");

    // determine scan region of corrupted file
    off_t scanEnd;
    if (srcHeader->offDirectory && srcHeader->offDirectory < fileSize) {
        scanEnd = (off_t)srcHeader->offDirectory;
    } else if (fileSize > sizeof(fileFooterV3_t)) {
        const fileFooterV3_t *ftr = (const fileFooterV3_t *)(map + fileSize - sizeof(fileFooterV3_t));
        if (ftr->magic == FOOTER_MAGIC_V3 && ftr->offDirectory && ftr->offDirectory < fileSize) {
            scanEnd = (off_t)ftr->offDirectory;
        } else {
            scanEnd = (off_t)fileSize;
        }
    } else {
        scanEnd = (off_t)fileSize;
    }

    // allocate block list for directory
    blockListV3_t blockList = {0};
    blockList.entries = malloc(256 * sizeof(directoryEntryV3_t));
    if (!blockList.entries) {
        LogError("ReWriteV3: malloc() error: %s", strerror(errno));
        return 0;
    }
    blockList.capacity = 256;

    // sequential scan: copy valid blocks
    off_t srcOffset = sizeof(fileHeaderV3_t);
    uint32_t blocksCopied = 0;
    int writeError = 0;
    ssize_t ret;

    while (srcOffset + (off_t)sizeof(dataBlockV3_t) <= scanEnd) {
        const dataBlockV3_t *blk = (const dataBlockV3_t *)(map + srcOffset);

        if (blk->discSize == 0) {
            printf("ReWriteV3: block %u has zero size at offset %lld - stopping\n", blocksCopied, (long long)srcOffset);
            break;
        }
        if (blk->discSize > blockSize) {
            printf("ReWriteV3: block %u size %u exceeds blockSize %u - stopping\n", blocksCopied, blk->discSize, blockSize);
            break;
        }
        if (srcOffset + (off_t)blk->discSize > scanEnd) {
            printf("ReWriteV3: block %u extends beyond data region - stopping\n", blocksCopied);
            break;
        }
        if (blk->type < BLOCK_TYPE_FLOW || blk->type > BLOCK_TYPE_META) {
            printf("ReWriteV3: block %u has unknown type %u - stopping\n", blocksCopied, blk->type);
            break;
        }
        if (blk->rawSize > blockSize) {
            printf("ReWriteV3: block %u rawSize %u exceeds blockSize %u - stopping\n", blocksCopied, blk->rawSize, blockSize);
            break;
        }

        off_t dstOffset = lseek(dstFd, 0, SEEK_CUR);
        if (dstOffset < 0) {
            LogError("ReWriteV3: lseek() error: %s", strerror(errno));
            writeError = 1;
            break;
        }

        {
            const uint8_t *payload = (const uint8_t *)blk + sizeof(dataBlockV3_t);
            uint32_t payloadSize = blk->discSize - (uint32_t)sizeof(dataBlockV3_t);
            dataBlockV3_t hdr = *blk;
            if (xxHash && payloadSize > 0) {
                hdr.checksum = XXH3_64bits(payload, payloadSize);
            } else {
                hdr.checksum = 0;
            }
            ret = write(dstFd, &hdr, sizeof(dataBlockV3_t));
            if (ret != (ssize_t)sizeof(dataBlockV3_t)) {
                LogError("ReWriteV3: write block %u header error: %s", blocksCopied, strerror(errno));
                writeError = 1;
                break;
            }
            if (payloadSize > 0) {
                ret = write(dstFd, payload, payloadSize);
                if (ret != (ssize_t)payloadSize) {
                    LogError("ReWriteV3: write block %u payload error: %s", blocksCopied, strerror(errno));
                    writeError = 1;
                    break;
                }
            }
        }

        if (!AddBlock(&blockList, blk->type, (uint64_t)dstOffset, blk->discSize)) {
            writeError = 1;
            break;
        }

        blocksCopied++;
        srcOffset += blk->discSize;
    }

    if (writeError) {
        free(blockList.entries);
        return 0;
    }

    printf("ReWriteV3: copied %u valid blocks from '%s'\n", blocksCopied, filename);

    // write block directory
    off_t dirOffset = lseek(dstFd, 0, SEEK_CUR);
    if (dirOffset < 0) {
        LogError("ReWriteV3: lseek() error: %s", strerror(errno));
        free(blockList.entries);
        return 0;
    }

    blockDirectoryV3_t dirHdr = {
        .magic = DIRECTORY_MAGIC,
        .numEntries = blockList.count,
    };
    ret = write(dstFd, &dirHdr, sizeof(blockDirectoryV3_t));
    if (ret != (ssize_t)sizeof(blockDirectoryV3_t)) {
        LogError("ReWriteV3: write directory header error: %s", strerror(errno));
        free(blockList.entries);
        return 0;
    }

    size_t entriesSize = blockList.count * sizeof(directoryEntryV3_t);
    if (entriesSize > 0) {
        ret = write(dstFd, blockList.entries, entriesSize);
        if (ret != (ssize_t)entriesSize) {
            LogError("ReWriteV3: write directory entries error: %s", strerror(errno));
            free(blockList.entries);
            return 0;
        }
    }

    uint32_t dirSize = (uint32_t)(sizeof(blockDirectoryV3_t) + entriesSize);

    // compute directory checksum if xxHash is enabled
    uint64_t dirChecksum = 0;
    if (xxHash) {
        XXH3_state_t *state = XXH3_createState();
        XXH3_64bits_reset(state);
        XXH3_64bits_update(state, &dirHdr, sizeof(blockDirectoryV3_t));
        if (entriesSize > 0) XXH3_64bits_update(state, blockList.entries, entriesSize);
        dirChecksum = XXH3_64bits_digest(state);
        XXH3_freeState(state);
    }
    free(blockList.entries);

    // write footer
    fileFooterV3_t footer = {
        .magic = FOOTER_MAGIC_V3,
        .dirSize = dirSize,
        .offDirectory = (uint64_t)dirOffset,
        .checksum = dirChecksum,
    };
    ret = write(dstFd, &footer, sizeof(fileFooterV3_t));
    if (ret != (ssize_t)sizeof(fileFooterV3_t)) {
        LogError("ReWriteV3: write footer error: %s", strerror(errno));
        return 0;
    }

    // rewrite header with final directory offset
    fileHeaderV3_t newHeader = *srcHeader;
    newHeader.nfdVersion = NFDVERSION;
    newHeader.offDirectory = (uint64_t)dirOffset;
    newHeader.dirSize = dirSize;

    if (lseek(dstFd, 0, SEEK_SET) < 0) {
        LogError("ReWriteV3: lseek() to rewrite header error: %s", strerror(errno));
        return 0;
    }
    ret = write(dstFd, &newHeader, sizeof(fileHeaderV3_t));
    if (ret != (ssize_t)sizeof(fileHeaderV3_t)) {
        LogError("ReWriteV3: rewrite header error: %s", strerror(errno));
        return 0;
    }

    return 1;

}  // End of ReWriteBlocks

int ReWriteV3(const char *filename) {
    if (!filename) return 0;

    int srcFd = open(filename, O_RDONLY);
    if (srcFd < 0) {
        LogError("ReWriteV3: open() failed for '%s': %s", filename, strerror(errno));
        return 0;
    }

    struct stat sb;
    if (fstat(srcFd, &sb) < 0) {
        LogError("ReWriteV3: fstat() failed for '%s': %s", filename, strerror(errno));
        close(srcFd);
        return 0;
    }

    size_t fileSize = (size_t)sb.st_size;
    if (fileSize < sizeof(fileHeaderV3_t)) {
        LogError("ReWriteV3: file too small (%zu bytes): '%s'", fileSize, filename);
        close(srcFd);
        return 0;
    }

    const uint8_t *map = mmap(NULL, fileSize, PROT_READ, MAP_PRIVATE, srcFd, 0);
    if (map == MAP_FAILED) {
        LogError("ReWriteV3: mmap() failed for '%s': %s", filename, strerror(errno));
        close(srcFd);
        return 0;
    }

    const fileHeaderV3_t *srcHeader = (const fileHeaderV3_t *)map;
    if (srcHeader->magic != HEADER_MAGIC_V3 || srcHeader->layoutVersion != LAYOUT_VERSION_3) {
        LogError("ReWriteV3: bad header magic/version in '%s'", filename);
        munmap((void *)map, fileSize);
        close(srcFd);
        return 0;
    }
    if (srcHeader->flags & FILE_FLAG_ENCRYPTED) {
        LogError("ReWriteV3: Cannot rewrite encrypted file '%s'", filename);
        munmap((void *)map, fileSize);
        close(srcFd);
        return 0;
    }

    // create temporary output file
    size_t nameLen = strlen(filename);
    char *tmpName = malloc(nameLen + 16);
    if (!tmpName) {
        LogError("ReWriteV3: malloc() error: %s", strerror(errno));
        munmap((void *)map, fileSize);
        close(srcFd);
        return 0;
    }
    snprintf(tmpName, nameLen + 16, "%s.XXXXXX", filename);

    int dstFd = mkstemp(tmpName);
    if (dstFd < 0) {
        LogError("ReWriteV3: mkstemp() failed for '%s': %s", tmpName, strerror(errno));
        free(tmpName);
        munmap((void *)map, fileSize);
        close(srcFd);
        return 0;
    }
    fchmod(dstFd, sb.st_mode & 0777);

    // write placeholder header
    fileHeaderV3_t placeholderHeader = *srcHeader;
    placeholderHeader.nfdVersion = NFDVERSION;
    placeholderHeader.offDirectory = 0;
    placeholderHeader.dirSize = 0;

    ssize_t ret = write(dstFd, &placeholderHeader, sizeof(fileHeaderV3_t));
    if (ret != (ssize_t)sizeof(fileHeaderV3_t)) {
        LogError("ReWriteV3: write header error: %s", strerror(errno));
        close(dstFd);
        unlink(tmpName);
        free(tmpName);
        munmap((void *)map, fileSize);
        close(srcFd);
        return 0;
    }

    // scan, copy blocks, write directory/footer/header
    int ok = ReWriteBlocks(map, fileSize, srcHeader, dstFd, filename);

    if (!ok) {
        close(dstFd);
        unlink(tmpName);
        free(tmpName);
        munmap((void *)map, fileSize);
        close(srcFd);
        return 0;
    }

    // finalize
    fsync(dstFd);
    close(dstFd);
    munmap((void *)map, fileSize);
    close(srcFd);

    // atomically replace original with repaired file
    if (rename(tmpName, filename) < 0) {
        LogError("ReWriteV3: rename('%s' -> '%s') failed: %s", tmpName, filename, strerror(errno));
        free(tmpName);
        return 0;
    }

    printf("ReWriteV3: repaired file written as '%s'\n", filename);
    free(tmpName);
    return 1;

}  // End of ReWriteV3
