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

#include "ftlib.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfxV3.h"
#include "output_short.h"
#include "util.h"
#include "version.h"

/* Global defines */
#define MAXRECORDS 30

static bool HasFlows = false;

typedef struct v5_block_s {
    uint32_t srcaddr;
    uint32_t dstaddr;
    uint32_t dPkts;
    uint32_t dOctets;
    uint8_t data[4];  // link to next record
} v5_block_t;

/* externals */
extern uint32_t Max_num_extensions;

/* prototypes */
void usage(char *name);

static int flows2nfdump(struct ftio *ftio, char *wfile, int compress, int extended, uint32_t limitflows);

#include "nffile_inline.c"

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

static uint16_t *GenExtensionList(struct ftio *ftio, uint32_t *extensionSize, uint32_t *numExtensions) {
    int i;

// maximux of extensions + terminating ExNULL
#define FTMAXEXTENSIONS 10
    uint16_t *extensionList = calloc(FTMAXEXTENSIONS, sizeof(uint16_t));
    if (!extensionList) {
        LogError("malloc() error in %s:%d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    *extensionSize = 0;
    *numExtensions = 0;
    i = 0;
    if (!ftio_check_xfield(ftio, FT_XFIELD_SRCPORT | FT_XFIELD_DSTPORT | FT_XFIELD_TCP_FLAGS | FT_XFIELD_PROT | FT_XFIELD_UNIX_SECS |
                                     FT_XFIELD_UNIX_NSECS | FT_XFIELD_SYSUPTIME | FT_XFIELD_DOCTETS | FT_XFIELD_DPKTS)) {
        extensionList[i++] = EXgenericFlowID;
        *extensionSize += EXgenericFlowSize;
        (*numExtensions)++;
    }
    if (!ftio_check_xfield(ftio, FT_XFIELD_SRCADDR | FT_XFIELD_DSTADDR)) {
        extensionList[i++] = EXipv4FlowID;
        *extensionSize += EXipv4FlowSize;
        (*numExtensions)++;
    }
    if (!ftio_check_xfield(ftio, FT_XFIELD_INPUT | FT_XFIELD_OUTPUT | FT_XFIELD_SRC_MASK | FT_XFIELD_DST_MASK)) {
        extensionList[i++] = EXflowMiscID;
        *extensionSize += EXflowMiscSize;
        (*numExtensions)++;
    }
    if (!ftio_check_xfield(ftio, FT_XFIELD_DFLOWS)) {
        HasFlows = true;
    }
    if (!ftio_check_xfield(ftio, FT_XFIELD_SRC_AS | FT_XFIELD_DST_AS)) {
        extensionList[i++] = EXasRoutingID;
        *extensionSize += EXasRoutingSize;
        (*numExtensions)++;
    }
    if (ftio_check_xfield(ftio, FT_XFIELD_PEER_NEXTHOP) == 0) {
        extensionList[i++] = EXipNextHopV4ID;
        *extensionSize += EXipNextHopV4Size;
        (*numExtensions)++;
    }
    if (!ftio_check_xfield(ftio, FT_XFIELD_EXADDR)) {
        extensionList[i++] = EXipReceivedV4ID;
        *extensionSize += EXipReceivedV4Size;
        (*numExtensions)++;
    }
    extensionList[i] = EXnull;

    return extensionList;

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

    uint32_t recordSize = 0;
    uint32_t numElements = 0;
    uint16_t *extensionInfo = GenExtensionList(ftio, &recordSize, &numElements);
    dbg_printf("GenExtensionList: numElements: %u, recordSize: %u\n", numElements, recordSize);
    if (numElements == 0) {
        LogError("No usable fields found it flowtools file");
        return 1;
    }
    recordSize += sizeof(recordHeaderV3_t);

    int cnt = 0;
    while ((rec = ftio_read(ftio))) {
        int i, exID;
        dbg_printf("FT record %u\n", cnt);
        if (!IsAvailable(dataBlock, recordSize)) {
            // flush block - get an empty one
            dataBlock = WriteBlock(nffile, dataBlock);
        }

        void *buffPtr = GetCurrentCursor(dataBlock);
        AddV3Header(buffPtr, recordHeader);

        // header data
        recordHeader->engineType = *((uint8_t *)(rec + fo.engine_type));
        recordHeader->engineID = *((uint8_t *)(rec + fo.engine_id));

        i = 0;
        while ((exID = extensionInfo[i]) != EXnull) {
            dbg_printf("Process slot %i extension %u - %s\n", i, exID, extensionTable[exID].name);
            switch (exID) {
                case EXgenericFlowID: {
                    uint32_t when, unix_secs, unix_nsecs, sysUpTime;
                    unix_secs = *((uint32_t *)(rec + fo.unix_secs));
                    unix_nsecs = *((uint32_t *)(rec + fo.unix_nsecs));
                    sysUpTime = *((uint32_t *)(rec + fo.sysUpTime));

                    PushExtension(recordHeader, EXgenericFlow, genericFlow);
                    when = *((uint32_t *)(rec + fo.First));
                    ftt = ftltime(sysUpTime, unix_secs, unix_nsecs, when);
                    genericFlow->msecFirst = (1000LL * (uint64_t)ftt.secs) + (uint64_t)ftt.msecs;

                    when = *((uint32_t *)(rec + fo.Last));
                    ftt = ftltime(sysUpTime, unix_secs, unix_nsecs, when);
                    genericFlow->msecLast = (1000LL * (uint64_t)ftt.secs) + (uint64_t)ftt.msecs;

                    genericFlow->inPackets = *((uint32_t *)(rec + fo.dPkts));
                    genericFlow->inBytes = *((uint32_t *)(rec + fo.dOctets));
                    genericFlow->srcPort = *((uint16_t *)(rec + fo.srcport));
                    genericFlow->dstPort = *((uint16_t *)(rec + fo.dstport));
                    genericFlow->proto = *((uint8_t *)(rec + fo.prot));
                    genericFlow->tcpFlags = *((uint8_t *)(rec + fo.tcp_flags));
                    genericFlow->srcTos = *((uint8_t *)(rec + fo.tos));
                    genericFlow->fwdStatus = 0;
                } break;
                case EXipv4FlowID:
                    PushExtension(recordHeader, EXipv4Flow, ipv4Flow);
                    ipv4Flow->srcAddr = *((uint32_t *)(rec + fo.srcaddr));
                    ipv4Flow->dstAddr = *((uint32_t *)(rec + fo.dstaddr));
                    break;
                case EXflowMiscID:
                    PushExtension(recordHeader, EXflowMisc, flowMisc);
                    flowMisc->input = *((uint16_t *)(rec + fo.input));
                    flowMisc->output = *((uint16_t *)(rec + fo.output));
                    flowMisc->srcMask = *((uint8_t *)(rec + fo.src_mask));
                    flowMisc->dstMask = *((uint8_t *)(rec + fo.dst_mask));
                    flowMisc->dir = 0;
                    flowMisc->dstTos = 0;
                    break;
                case EXasRoutingID:
                    PushExtension(recordHeader, EXasRouting, asRouting);
                    asRouting->srcAS = *((uint16_t *)(rec + fo.src_as));
                    asRouting->dstAS = *((uint16_t *)(rec + fo.dst_as));
                    break;
                case EXipNextHopV4ID:
                    PushExtension(recordHeader, EXipNextHopV4, ipNextHopV4);
                    ipNextHopV4->ip = *((uint32_t *)(rec + fo.peer_nexthop));
                    break;
                case EXipReceivedV4ID:
                    PushExtension(recordHeader, EXipReceivedV4, received);
                    received->ip = *((uint32_t *)(rec + fo.exaddr));
                    break;
            }
            i++;
        }

        // update file record size ( -> output buffer size )
        dataBlock->NumRecords++;
        dataBlock->size += recordSize;

        dbg_assert(recordHeader->size == recordSize);

        if (extended) {
            flow_record_short(stdout, recordHeader);
        }

        cnt++;
        if (cnt == limitflows) break;

    } /* while */

    SetIdent(nffile, ident);
    FlushBlock(nffile, dataBlock);
    FinaliseFile(nffile);
    DisposeFile(nffile);
    return 0;

}  // End of flows2nfdump

int main(int argc, char **argv) {
    struct ftio ftio;
    struct stat statbuf;
    uint32_t limitflows;
    int i, extended, ret, fd, compress;

    /* init fterr */
    fterr_setid(argv[0]);

    extended = 0;
    limitflows = 0;
    char *ftfile = NULL;
    char *wfile = NULL;
    compress = LZ4_COMPRESSED;

    while ((i = getopt(argc, argv, "jyzEVc:hr:w:?")) != -1) switch (i) {
            case 'h': /* help */
            case '?':
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
                } else {
                    compress = ParseCompression(optarg);
                }
                if (compress == -1) {
                    LogError("Usage for option -z: set -z=lzo, -z=lz4, -z=bz2 or z=zstd for valid compression formats");
                    exit(EXIT_FAILURE);
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
                wfile = optarg;
                break;

            default:
                usage(argv[0]);
                exit(1);
                break;

        } /* switch */
    // End while

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

    if (!Init_nffile(0, NULL)) exit(EXIT_FAILURE);

    /* read from fd */
    if (ftio_init(&ftio, fd, FT_IO_FLAG_READ) < 0) fterr_errx(1, "ftio_init(): failed");

    ret = flows2nfdump(&ftio, wfile, compress, extended, limitflows);

    return ret;

}  // End of main
