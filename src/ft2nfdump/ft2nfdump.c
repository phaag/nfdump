/*
 *  All rights reserved.
 *  Copyright (c) 2009-2026, Peter Haag
 *  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
 *  Copyright (c) 2001 Mark Fullmer and The Ohio State University
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *	   this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice,
 *	   this list of conditions and the following disclaimer in the documentation
 *	   and/or other materials provided with the distribution.
 *   * Neither the name of the author nor the names of its contributors may be
 *	   used to endorse or promote products derived from this software without
 *	   specific prior written permission.
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
 *  Flow-Tools related code taken from flow-tools-0.67 created by Mark Fullmer
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "barrier.h"
#include "ftlib.h"
#include "id.h"
#include "logging.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfxV4.h"
#include "output_short.h"
#include "util.h"
#include "version.h"

/* prototypes */
void usage(char *name);

static int flows2nfdump(struct ftio *ftio, char *wfile, int compress, int extended, uint32_t limitflows);

void usage(char *name) {
    printf(
        "usage %s [options] \n"
        "-h\t\tthis text you see right here.\n"
        "-E\t\tDump records in ASCII extended format to stdout.\n"
        "-c\t\tLimit number of records to convert.\n"
        "-V\t\tPrint version and exit.\n"
        "-r <file>\tread flow-tools records from file\n"
        "-w <file>\twrite nfdump records to file\n"
        "-z=lzo\t\tLZO compress flows in output file.\n"
        "-z=bz2\t\tBZIP2 compress flows in output file.\n"
        "-z=lz4[:level]\tLZ4 compress flows in output file.\n"
        "-z=zstd[:level]\tZSTD compress flows in output file.\n"
        "Convert flow-tools format to nfdump format:\n"
        "ft2nfdump -r <flow-tools-data-file> -w <nfdump-file> [-z]\n",
        name);

}  // End of usage

static uint32_t GenExtensionList(struct ftio *ftio, uint64_t *bitMap) {
    uint32_t extension_size = 0;
    uint64_t bitmap = 0;
    if (!ftio_check_xfield(ftio, FT_XFIELD_SRCPORT | FT_XFIELD_DSTPORT | FT_XFIELD_TCP_FLAGS | FT_XFIELD_PROT | FT_XFIELD_UNIX_SECS |
                                     FT_XFIELD_UNIX_NSECS | FT_XFIELD_SYSUPTIME | FT_XFIELD_DOCTETS | FT_XFIELD_DPKTS)) {
        BitMapSet(bitmap, EXgenericFlowID);
        extension_size += EXgenericFlowSize;
    }
    if (!ftio_check_xfield(ftio, FT_XFIELD_SRCADDR | FT_XFIELD_DSTADDR)) {
        BitMapSet(bitmap, EXipv4FlowID);
        extension_size += EXipv4FlowSize;
    }
    if (!ftio_check_xfield(ftio, FT_XFIELD_INPUT | FT_XFIELD_OUTPUT)) {
        BitMapSet(bitmap, EXinterfaceID);
        extension_size += EXinterfaceSize;
    }
    if (!ftio_check_xfield(ftio, FT_XFIELD_SRC_MASK | FT_XFIELD_DST_MASK)) {
        BitMapSet(bitmap, EXflowMiscID);
        extension_size += EXflowMiscSize;
    }
    if (!ftio_check_xfield(ftio, FT_XFIELD_DFLOWS)) {
        BitMapSet(bitmap, EXcntFlowID);
        extension_size += EXcntFlowSize;
    }
    if (!ftio_check_xfield(ftio, FT_XFIELD_SRC_AS | FT_XFIELD_DST_AS)) {
        BitMapSet(bitmap, EXasInfoID);
        extension_size += EXasInfoSize;
    }
    if (!ftio_check_xfield(ftio, FT_XFIELD_NEXTHOP) || !ftio_check_xfield(ftio, FT_XFIELD_PEER_NEXTHOP)) {
        BitMapSet(bitmap, EXasRoutingV4ID);
        extension_size += EXasRoutingV4Size;
    }
    if (!ftio_check_xfield(ftio, FT_XFIELD_EXADDR)) {
        BitMapSet(bitmap, EXipReceivedV4ID);
        extension_size += EXipReceivedV4Size;
    }

    *bitMap = bitmap;
    return extension_size;

}  // End of GenExtensionList

static int flows2nfdump(struct ftio *ftio, char *wfile, int compress, int extended, uint32_t limitflows) {
    // required flow tools variables
    struct fttime ftt;
    struct fts3rec_offsets fo;
    struct ftver ftv;
    char *rec;
    // nfdump variables

    char *ident = "flow-tools";
    nffile_t *nffile = OpenNewFile(wfile, CREATOR_FT2NFDUMP, compress, NOT_ENCRYPTED);
    if (!nffile) {
        LogError("OpenNewFile() failed.");
        return 1;
    }
    dataBlock_t *dataBlock = WriteBlock(nffile, NULL);

    ftio_get_ver(ftio, &ftv);
    memset((void *)&fo, 0xFF, sizeof(fo));
    fts3rec_compute_offsets(&fo, &ftv);

    uint64_t bitMap = 0;
    uint16_t extensionSize = GenExtensionList(ftio, &bitMap);
    if (bitMap == 0) {
        LogError("No usable fields found it flowtools file");
        return 1;
    }

    uint32_t numExtensions = __builtin_popcountll(bitMap);
    uint32_t tableSize = ALIGN8(numExtensions * sizeof(uint16_t));
    uint32_t recordSize = sizeof(recordHeaderV4_t) + tableSize + extensionSize;
    dbg_printf("GenExtensionList: numExtensions: %u, recordSize: %u\n", numExtensions, recordSize);

    uint64_t savedBitMap = bitMap;
    int cnt = 0;
    while ((rec = ftio_read(ftio))) {
        dbg_printf("FT record %u\n", cnt);
        if (!IsAvailable(dataBlock, recordSize)) {
            // flush block - get an empty one
            dataBlock = WriteBlock(nffile, dataBlock);
        }

        void *buffPtr = GetCurrentCursor(dataBlock);
        recordHeaderV4_t *recordHeader = (recordHeaderV4_t *)buffPtr;
        *recordHeader = (recordHeaderV4_t){.type = V4Record,
                                           .size = recordSize,
                                           .engineType = *((uint8_t *)(rec + fo.engine_type)),
                                           .exporterID = *((uint8_t *)(rec + fo.engine_id)),
                                           .nfVersion = 5,
                                           .extBitmap = savedBitMap,
                                           .numExtensions = numExtensions};

        uint8_t *recordBase = buffPtr;
        uint16_t *offset = (uint16_t *)(buffPtr + sizeof(recordHeaderV4_t));
        memset(offset, 0, tableSize);
        uint32_t nextOffset = sizeof(recordHeaderV4_t) + tableSize;

        bitMap = savedBitMap;
        while (bitMap) {
            uint64_t t = bitMap & -bitMap;
            uint32_t extID = __builtin_ctzll(bitMap);
            bitMap ^= t;

            *offset++ = nextOffset;
            uint32_t extSize = extensionTable[extID].size;
            uint8_t *extension = recordBase + nextOffset;
            nextOffset += extSize;

            switch (extID) {
                case EXgenericFlowID: {
                    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)extension;
                    *genericFlow = (EXgenericFlow_t){
                        .inPackets = *((uint32_t *)(rec + fo.dPkts)),
                        .inBytes = *((uint32_t *)(rec + fo.dOctets)),
                        .srcPort = *((uint16_t *)(rec + fo.srcport)),
                        .dstPort = *((uint16_t *)(rec + fo.dstport)),
                        .proto = *((uint8_t *)(rec + fo.prot)),
                        .tcpFlags = *((uint8_t *)(rec + fo.tcp_flags)),
                        .srcTos = *((uint8_t *)(rec + fo.tos)),
                    };
                    uint32_t unix_secs = *((uint32_t *)(rec + fo.unix_secs));
                    uint32_t unix_nsecs = *((uint32_t *)(rec + fo.unix_nsecs));
                    uint32_t sysUpTime = *((uint32_t *)(rec + fo.sysUpTime));

                    uint32_t when = *((uint32_t *)(rec + fo.First));
                    ftt = ftltime(sysUpTime, unix_secs, unix_nsecs, when);
                    genericFlow->msecFirst = (1000LL * (uint64_t)ftt.secs) + (uint64_t)ftt.msecs;

                    when = *((uint32_t *)(rec + fo.Last));
                    ftt = ftltime(sysUpTime, unix_secs, unix_nsecs, when);
                    genericFlow->msecLast = (1000LL * (uint64_t)ftt.secs) + (uint64_t)ftt.msecs;

                } break;
                case EXipv4FlowID: {
                    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)extension;
                    ipv4Flow->srcAddr = *((uint32_t *)(rec + fo.srcaddr));
                    ipv4Flow->dstAddr = *((uint32_t *)(rec + fo.dstaddr));
                } break;
                case EXinterfaceID: {
                    EXinterface_t *interface = (EXinterface_t *)extension;
                    interface->input = *((uint16_t *)(rec + fo.input));
                    interface->output = *((uint16_t *)(rec + fo.output));
                } break;
                case EXflowMiscID: {
                    EXflowMisc_t *flowMisc = (EXflowMisc_t *)extension;
                    *flowMisc = (EXflowMisc_t){
                        .srcMask = *((uint8_t *)(rec + fo.src_mask)),
                        .dstMask = *((uint8_t *)(rec + fo.dst_mask)),
                    };
                } break;
                case EXcntFlowID: {
                    EXcntFlow_t *cntFlow = (EXcntFlow_t *)extension;
                    *cntFlow = (EXcntFlow_t){
                        .flows = *((uint32_t *)(rec + fo.dFlows)),
                    };
                } break;
                case EXasInfoID: {
                    EXasInfo_t *asInfo = (EXasInfo_t *)extension;
                    asInfo->srcAS = *((uint16_t *)(rec + fo.src_as));
                    asInfo->dstAS = *((uint16_t *)(rec + fo.dst_as));
                } break;
                case EXasRoutingV4ID: {
                    EXasRoutingV4_t *asRouting = (EXasRoutingV4_t *)extension;
                    asRouting->nextHop = !ftio_check_xfield(ftio, FT_XFIELD_NEXTHOP) ? *((uint32_t *)(rec + fo.nexthop)) : 0;
                    asRouting->bgpNextHop = !ftio_check_xfield(ftio, FT_XFIELD_PEER_NEXTHOP) ? *((uint32_t *)(rec + fo.peer_nexthop)) : 0;
                } break;
                case EXipReceivedV4ID: {
                    EXipReceivedV4_t *ipReceived = (EXipReceivedV4_t *)extension;
                    ipReceived->ip = *((uint32_t *)(rec + fo.exaddr));
                } break;
            }
        }

        // update file record size ( -> output buffer size )
        dataBlock->NumRecords++;
        dataBlock->size += recordSize;

        dbg_assert(recordHeader->size == recordSize);

        if (extended) {
            flow_record_short(stdout, recordHeader);
        }

        cnt++;
        if (cnt == (int)limitflows) break;

    } /* while */

    SetIdent(nffile, ident);
    FlushBlock(nffile, dataBlock);
    FlushFile(nffile);
    DisposeFile(nffile);
    return 0;

}  // End of flows2nfdump

int main(int argc, char **argv) {
    struct ftio ftio;
    struct stat statbuf;
    uint32_t limitflows;
    int extended, ret, fd, compress;

    /* init fterr */
    fterr_setid(argv[0]);

    extended = 0;
    limitflows = 0;
    char *ftfile = NULL;
    char *wfile = NULL;
    compress = NOT_COMPRESSED;

    int c;
    while ((c = getopt(argc, argv, "z::jyzEVc:hr:w:")) != EOF) {
        switch (c) {
            case 'h': /* help */
                usage(argv[0]);
                exit(0);
                break;
            case 'V':
                printf("%s: %s\n", argv[0], versionString());
                exit(0);
                break;
            case 'E':
                extended = 1;
                break;
            case 'c':
                limitflows = atoi(optarg);
                if (!limitflows) {
                    LogError("Option -c needs a number > 0");
                    exit(255);
                }
                break;
            case 'j':
                if (compress) {
                    LogError("Use one compression: -z for LZO, -j for BZ2 or -y for LZ4 compression");
                    exit(EXIT_FAILURE);
                }
                compress = BZ2_COMPRESSED;
                break;
            case 'y':
                if (compress) {
                    LogError("Use one compression: -z for LZO, -j for BZ2 or -y for LZ4 compression");
                    exit(EXIT_FAILURE);
                }
                compress = LZ4_COMPRESSED;
                break;
            case 'z':
                if (compress) {
                    LogError("Use one compression: -z for LZO, -j for BZ2 or -y for LZ4 compression");
                    exit(EXIT_FAILURE);
                }
                if (optarg == NULL) {
                    compress = LZO_COMPRESSED;
                    LogInfo("Legacy option -z defaults to -z=lzo. Use -z=lzo, -z=lz4, -z=bz2 or z=zstd for valid compression formats");
                } else {
                    int ret = ParseCompression(optarg);
                    if (ret == -1) {
                        LogError("Usage for option -z: set -z=lzo, -z=lz4, -z=bz2 or z=zstd for valid compression formats");
                        exit(EXIT_FAILURE);
                    }
                    compress = (unsigned)ret;
                }
                break;
            case 'r':
                ftfile = optarg;
                if ((stat(ftfile, &statbuf) < 0) || !(statbuf.st_mode & S_IFREG)) {
                    LogError("No such file: '%s'", ftfile);
                    exit(255);
                }
                break;
            case 'w':
                CheckArgLen(optarg, MAXPATHLEN);
                wfile = optarg;
                break;

            default:
                usage(argv[0]);
                exit(1);
                break;

        } /* switch */
    }  // End while

    if (argc - optind) fterr_errx(1, "Extra arguments starting with %s.", argv[optind]);

    if (ftfile) {
        fd = open(ftfile, O_RDONLY, 0);
        if (fd < 0) {
            LogError("Can't open file '%s': %s.", ftfile, strerror(errno));
            exit(255);
        }
    } else {
        fd = 0;
    }

    if (!wfile) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    int numWorkers = GetNumWorkers(0);
    if (!Init_nffile(numWorkers, NULL)) exit(EXIT_FAILURE);

    /* read from fd */
    if (ftio_init(&ftio, fd, FT_IO_FLAG_READ) < 0) fterr_errx(1, "ftio_init(): failed");

    ret = flows2nfdump(&ftio, wfile, compress, extended, limitflows);

    return ret;

}  // End of main
