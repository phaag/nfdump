/*
 *  Copyright (c) 2009-2023, Peter Haag
 *  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
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

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "flist.h"
#include "nbar.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfxV3.h"
#include "panonymizer.h"
#include "util.h"

/* Function Prototypes */
static void usage(char *name);

static inline void AnonRecord(recordHeaderV3_t *v3Record);

static inline void WriteAnonRecord(nffile_t *wfile, recordHeaderV3_t *v3Record);

static void process_data(void *wfile, int verbose);

/* Functions */

#include "nffile_inline.c"

static void usage(char *name) {
    printf(
        "usage %s [options] \n"
        "-h\t\tthis text you see right here.\n"
        "-K <key>\tAnonymize IP addresses using CryptoPAn with key <key>.\n"
        "-q\t\tDo not print progress spinnen and filenames.\n"
        "-r <path>\tread input from single file or all files in directory.\n"
        "-w <file>\tName of output file. Defaults to input file.\n",
        name);
} /* usage */

static inline void AnonRecord(recordHeaderV3_t *v3Record) {
    elementHeader_t *elementHeader;
    uint32_t size = sizeof(recordHeaderV3_t);

    void *p = (void *)v3Record;
    void *eor = p + v3Record->size;

    if (v3Record->size < size) {
        LogError("ExpandRecord_v3() Unexpected size: '%u'", v3Record->size);
        return;
    }

    SetFlag(v3Record->flags, V3_FLAG_ANON);
    dbg_printf("Record announces %u extensions with total size %u\n", v3Record->numElements, v3Record->size);
    // first record header
    elementHeader = (elementHeader_t *)(p + sizeof(recordHeaderV3_t));
    for (int i = 0; i < v3Record->numElements; i++) {
        uint64_t anon_ip[2];
        dbg_printf("[%i] next extension: %u: %s\n", i, elementHeader->type,
                   elementHeader->type < MAXEXTENSIONS ? extensionTable[elementHeader->type].name : "<unknown>");
        switch (elementHeader->type) {
            case EXnull:
                break;
            case EXgenericFlowID:
                break;
            case EXipv4FlowID: {
                EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)((void *)elementHeader + sizeof(elementHeader_t));
                ipv4Flow->srcAddr = anonymize(ipv4Flow->srcAddr);
                ipv4Flow->dstAddr = anonymize(ipv4Flow->dstAddr);
            } break;
            case EXipv6FlowID: {
                EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)((void *)elementHeader + sizeof(elementHeader_t));
                anonymize_v6(ipv6Flow->srcAddr, anon_ip);
                ipv6Flow->srcAddr[0] = anon_ip[0];
                ipv6Flow->srcAddr[1] = anon_ip[1];

                anonymize_v6(ipv6Flow->srcAddr, anon_ip);
                ipv6Flow->dstAddr[0] = anon_ip[0];
                ipv6Flow->dstAddr[1] = anon_ip[1];
            } break;
            case EXflowMiscID:
                break;
            case EXcntFlowID:
                break;
            case EXvLanID:
                break;
            case EXasRoutingID: {
                EXasRouting_t *asRouting = (EXasRouting_t *)((void *)elementHeader + sizeof(elementHeader_t));
                asRouting->srcAS = 0;
                asRouting->dstAS = 0;
            } break;
            case EXbgpNextHopV4ID: {
                EXbgpNextHopV4_t *bgpNextHopV4 = (EXbgpNextHopV4_t *)((void *)elementHeader + sizeof(elementHeader_t));
                bgpNextHopV4->ip = anonymize(bgpNextHopV4->ip);
            } break;
            case EXbgpNextHopV6ID: {
                EXbgpNextHopV6_t *bgpNextHopV6 = (EXbgpNextHopV6_t *)((void *)elementHeader + sizeof(elementHeader_t));
                anonymize_v6(bgpNextHopV6->ip, anon_ip);
                bgpNextHopV6->ip[0] = anon_ip[0];
                bgpNextHopV6->ip[1] = anon_ip[1];
            } break;
            case EXipNextHopV4ID: {
                EXipNextHopV4_t *ipNextHopV4 = (EXipNextHopV4_t *)((void *)elementHeader + sizeof(elementHeader_t));
                ipNextHopV4->ip = anonymize(ipNextHopV4->ip);
            } break;
            case EXipNextHopV6ID: {
                EXipNextHopV6_t *ipNextHopV6 = (EXipNextHopV6_t *)((void *)elementHeader + sizeof(elementHeader_t));
                anonymize_v6(ipNextHopV6->ip, anon_ip);
                ipNextHopV6->ip[0] = anon_ip[0];
                ipNextHopV6->ip[1] = anon_ip[1];
            } break;
            case EXipReceivedV4ID: {
                EXipNextHopV4_t *ipNextHopV4 = (EXipNextHopV4_t *)((void *)elementHeader + sizeof(elementHeader_t));
                ipNextHopV4->ip = anonymize(ipNextHopV4->ip);
            } break;
            case EXipReceivedV6ID: {
                EXipReceivedV6_t *ipReceivedV6 = (EXipReceivedV6_t *)((void *)elementHeader + sizeof(elementHeader_t));
                anonymize_v6(ipReceivedV6->ip, anon_ip);
                ipReceivedV6->ip[0] = anon_ip[0];
                ipReceivedV6->ip[1] = anon_ip[1];
            } break;
            case EXmplsLabelID:
                break;
            case EXmacAddrID:
                break;
            case EXasAdjacentID: {
                EXasAdjacent_t *asAdjacent = (EXasAdjacent_t *)((void *)elementHeader + sizeof(elementHeader_t));
                asAdjacent->nextAdjacentAS = 0;
                asAdjacent->prevAdjacentAS = 0;
            } break;
            case EXlatencyID:
                break;
#ifdef NSEL
            case EXnselCommonID:
                break;
            case EXnselXlateIPv4ID: {
                EXnselXlateIPv4_t *nselXlateIPv4 = (EXnselXlateIPv4_t *)((void *)elementHeader + sizeof(elementHeader_t));
                nselXlateIPv4->xlateSrcAddr = anonymize(nselXlateIPv4->xlateSrcAddr);
                nselXlateIPv4->xlateDstAddr = anonymize(nselXlateIPv4->xlateDstAddr);
            } break;
            case EXnselXlateIPv6ID: {
                EXnselXlateIPv6_t *nselXlateIPv6 = (EXnselXlateIPv6_t *)((void *)elementHeader + sizeof(elementHeader_t));
                anonymize_v6(nselXlateIPv6->xlateSrcAddr, anon_ip);
                nselXlateIPv6->xlateSrcAddr[0] = anon_ip[0];
                nselXlateIPv6->xlateSrcAddr[1] = anon_ip[1];

                anonymize_v6(nselXlateIPv6->xlateDstAddr, anon_ip);
                nselXlateIPv6->xlateDstAddr[0] = anon_ip[0];
                nselXlateIPv6->xlateDstAddr[1] = anon_ip[1];
            } break;
            case EXnselXlatePortID:
                break;
            case EXnselAclID:
                break;
            case EXnselUserID:
                break;
            case EXnelCommonID:
                break;
            case EXnelXlatePortID:
                break;
#endif
            case EXnbarAppID:
                break;
            case EXinPayloadID:
                break;
            case EXoutPayloadID:
                break;
            default:
                LogError("Unknown extension '%u'", elementHeader->type);
        }

        size += elementHeader->length;
        elementHeader = (elementHeader_t *)((void *)elementHeader + elementHeader->length);

        if ((void *)elementHeader > eor) {
            LogError("ptr error - elementHeader > eor");
            exit(255);
        }
    }

}  // End of AnonRecord

static inline void WriteAnonRecord(nffile_t *wfile, recordHeaderV3_t *v3Record) {
    // output buffer size check for all expected records
    if (!CheckBufferSpace(wfile, v3Record->size)) {
        LogError("WriteAnonRecord(): output buffer size error");
        return;
    }

    memcpy(wfile->buff_ptr, (void *)v3Record, v3Record->size);

    wfile->block_header->NumRecords++;
    wfile->block_header->size += v3Record->size;
    wfile->buff_ptr += v3Record->size;

}  // End of WriteAnonRecord

static void process_data(void *wfile, int verbose) {
    const char spinner[4] = {'|', '/', '-', '\\'};
    nffile_t *nffile_r;
    nffile_t *nffile_w;
    char outfile[MAXPATHLEN], *cfile;

    // Get the first file handle
    nffile_r = GetNextFile(NULL);
    if (!nffile_r) {
        LogError("GetNextFile() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
        return;
    }
    if (nffile_r == EMPTY_LIST) {
        LogError("Empty file list. No files to process\n");
        return;
    }

    int cnt = 1;
    cfile = nffile_r->fileName;
    if (!cfile) {
        LogError("(NULL) input file name error in %s line %d\n", __FILE__, __LINE__);
        return;
    } else {
        // prepare output file
        snprintf(outfile, MAXPATHLEN - 1, "%s-tmp", cfile);
        outfile[MAXPATHLEN - 1] = '\0';
        if (verbose) printf(" %i Processing %s\r", cnt++, cfile);
    }

    if (wfile)
        nffile_w = OpenNewFile(wfile, NULL, CREATOR_NFANON, FILE_COMPRESSION(nffile_r), NOT_ENCRYPTED);
    else
        nffile_w = OpenNewFile(outfile, NULL, CREATOR_NFANON, FILE_COMPRESSION(nffile_r), NOT_ENCRYPTED);

    if (!nffile_w) {
        if (nffile_r) {
            CloseFile(nffile_r);
            DisposeFile(nffile_r);
        }
        return;
    }

    SetIdent(nffile_w, FILE_IDENT(nffile_r));
    memcpy((void *)nffile_w->stat_record, (void *)nffile_r->stat_record, sizeof(stat_record_t));

    int blk_count = 0;
    int done = 0;
    while (!done) {
        // get next data block from file
        int ret = ReadBlock(nffile_r);
        if (verbose) {
            printf("\r%c", spinner[blk_count & 0x3]);
            blk_count++;
        }
        switch (ret) {
            case NF_CORRUPT:
            case NF_ERROR:
                if (ret == NF_CORRUPT)
                    LogError("Skip corrupt data file '%s'\n", cfile);
                else
                    LogError("Read error in file '%s': %s\n", cfile, strerror(errno));
                // fall through - get next file in chain
            case NF_EOF: {
                nffile_t *next;
                if (wfile == NULL) {
                    CloseUpdateFile(nffile_w);
                    if (rename(outfile, cfile) < 0) {
                        LogError("rename() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                        return;
                    }
                }

                next = GetNextFile(nffile_r);
                if (next == EMPTY_LIST || next == NULL) {
                    done = 1;
                    printf("\nDone\n");
                    continue;
                }

                cfile = nffile_r->fileName;
                if (!cfile) {
                    LogError("(NULL) input file name error in %s line %d\n", __FILE__, __LINE__);
                    return;
                }
                if (verbose) printf(" %i Processing %s\r", cnt++, cfile);

                if (wfile == NULL) {
                    snprintf(outfile, MAXPATHLEN - 1, "%s-tmp", cfile);
                    outfile[MAXPATHLEN - 1] = '\0';

                    nffile_w = OpenNewFile(outfile, nffile_w, CREATOR_NFANON, FILE_COMPRESSION(nffile_r), NOT_ENCRYPTED);
                    if (!nffile_w) {
                        if (nffile_r) {
                            DisposeFile(nffile_r);
                        }
                        return;
                    }
                    memcpy((void *)nffile_w->stat_record, (void *)nffile_r->stat_record, sizeof(stat_record_t));
                } else {
                    SumStatRecords(nffile_w->stat_record, nffile_r->stat_record);
                }

                // continue with next file
                continue;

            } break;  // not really needed
        }

        if (nffile_r->block_header->type != DATA_BLOCK_TYPE_2 && nffile_r->block_header->type != DATA_BLOCK_TYPE_3) {
            LogError("Can't process block type %u. Skip block", nffile_r->block_header->type);
            continue;
        }

        record_header_t *record_ptr = nffile_r->buff_ptr;
        uint32_t sumSize = 0;
        for (int i = 0; i < nffile_r->block_header->NumRecords; i++) {
            if ((sumSize + record_ptr->size) > ret || (record_ptr->size < sizeof(record_header_t))) {
                LogError("Corrupt data file. Inconsistent block size in %s line %d\n", __FILE__, __LINE__);
                exit(255);
            }
            sumSize += record_ptr->size;

            switch (record_ptr->type) {
                case V3Record:
                    AnonRecord((recordHeaderV3_t *)record_ptr);
                    WriteAnonRecord(nffile_w, (recordHeaderV3_t *)record_ptr);
                    break;
                case ExporterInfoRecordType:
                case ExporterStatRecordType:
                case SamplerRecordType:
                case NbarRecordType:
                    // Silently skip exporter/sampler records
                    break;

                default: {
                    LogError("Skip unknown record type %i", record_ptr->type);
                }
            }
            // Advance pointer by number of bytes for netflow record
            record_ptr = (record_header_t *)((void *)record_ptr + record_ptr->size);

        }  // for all records

    }  // while

    if (wfile != NULL) CloseUpdateFile(nffile_w);
    DisposeFile(nffile_w);

    if (nffile_r) {
        CloseFile(nffile_r);
        DisposeFile(nffile_r);
    }

    if (verbose) LogError("Processed %i files", --cnt);

}  // End of process_data

int main(int argc, char **argv) {
    char *wfile = NULL;
    char CryptoPAnKey[32] = {0};
    flist_t flist = {0};

    int verbose = 1;
    int c;
    while ((c = getopt(argc, argv, "hK:L:qr:w:")) != EOF) {
        switch (c) {
            case 'h':
                usage(argv[0]);
                exit(0);
                break;
                break;
            case 'K':
                CheckArgLen(optarg, 66);
                if (!ParseCryptoPAnKey(optarg, CryptoPAnKey)) {
                    LogError("Invalid key '%s' for CryptoPAn", optarg);
                    exit(255);
                }
                PAnonymizer_Init((uint8_t *)CryptoPAnKey);
                break;
            case 'L':
                if (!InitLog(0, "argv[0]", optarg, 0)) exit(255);
                break;
            case 'q':
                verbose = 0;
                break;
            case 'r':
                CheckArgLen(optarg, MAXPATHLEN);
                if (TestPath(optarg, S_IFREG) == PATH_OK) {
                    flist.single_file = strdup(optarg);
                } else if (TestPath(optarg, S_IFDIR) == PATH_OK) {
                    flist.multiple_files = strdup(optarg);
                } else {
                    LogError("%s is not a file or directory", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'w':
                wfile = optarg;
                break;
            default:
                usage(argv[0]);
                exit(0);
        }
    }

    if (CryptoPAnKey[0] == '\0') {
        LogError("Expect -K <key>");
        usage(argv[0]);
        exit(255);
    }

    queue_t *fileList = SetupInputFileSequence(&flist);
    if (!fileList || !Init_nffile(fileList)) exit(255);

    // make stdout unbuffered for progress pointer
    setvbuf(stdout, (char *)NULL, _IONBF, 0);
    process_data(wfile, verbose);

    return 0;
}
