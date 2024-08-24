/*
 *  Copyright (c) 2009-2024, Peter Haag
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

/*
 * nfreader is sample code for reading nfdump binary files.
 * It accepts the standard nfdump file select options -r, -M and -R
 * Therefore it allows you to loop over multiple files to process all netflow records.
 *
 * Insert your code in the process_data function
 * To build the binary: first compile nfdump as usual.
 * Then compile nfreader:
 *
 * make nfreader
 *
 * This compiles this code and links the required nfdump files
 * If you do it by hand:
 *
 * gcc -I.. -std=c11 -O3 -o nfreader nfreader.c -lnfdump
 *
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <flist.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "nfdump.h"
#include "nffile.h"
#include "nfxV3.h"
#include "util.h"

/* Function Prototypes */
static void usage(char *name);

#define IP_STRING_LEN 32
static void print_record(recordHandle_t *recordHandle);

static void process_data(void);

/* Functions */

#include "nffile_inline.c"

static void usage(char *name) {
    printf(
        "usage %s [options] \n"
        "-h\t\tthis text you see right here\n"
        "-r\t\tread input from file\n"
        "-M <expr>\tRead input from multiple directories.\n"
        "-R <expr>\tRead input from sequence of files.\n",
        name);
} /* usage */

// simple record printer
static void print_record(recordHandle_t *recordHandle) {
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];

    // for now only print IPV4 flows in brief
    if (genericFlow == NULL || ipv4Flow == NULL) return;

    char datestr1[64], datestr2[64], datestr3[64];
    struct tm *ts;
    time_t when = genericFlow->msecFirst / 1000LL;
    if (when == 0) {
        strncpy(datestr1, "<unknown>", 63);
    } else {
        ts = localtime(&when);
        strftime(datestr1, 63, "%Y-%m-%d %H:%M:%S", ts);
    }

    when = genericFlow->msecLast / 1000LL;
    if (when == 0) {
        strncpy(datestr2, "<unknown>", 63);
    } else {
        ts = localtime(&when);
        strftime(datestr2, 63, "%Y-%m-%d %H:%M:%S", ts);
    }

    if (genericFlow->msecReceived) {
        when = genericFlow->msecReceived / 1000LL;
        ts = localtime(&when);
        strftime(datestr3, 63, "%Y-%m-%d %H:%M:%S", ts);
    } else {
        datestr3[0] = '0';
        datestr3[1] = '\0';
    }

    printf(
        "  first        =     %13llu [%s.%03llu]\n"
        "  last         =     %13llu [%s.%03llu]\n"
        "  received at  =     %13llu [%s.%03llu]\n"
        "  proto        =                 %3u\n"
        "  tcp flags    =              0x%.2x\n",
        (long long unsigned)genericFlow->msecFirst, datestr1, genericFlow->msecFirst % 1000LL, (long long unsigned)genericFlow->msecLast, datestr2,
        genericFlow->msecLast % 1000LL, (long long unsigned)genericFlow->msecReceived, datestr3,
        (long long unsigned)genericFlow->msecReceived % 1000L, genericFlow->proto, genericFlow->tcpFlags);

    if (genericFlow->proto == IPPROTO_ICMP) {
        printf("  ICMP         =              %2u.%-2u type.code\n", genericFlow->icmpType, genericFlow->icmpCode);
    } else {
        printf(
            "  src port     =             %5u\n"
            "  dst port     =             %5u\n"
            "  src tos      =               %3u\n",
            genericFlow->srcPort, genericFlow->dstPort, genericFlow->srcTos);
    }

    printf(
        "  in packets   =        %10llu\n"
        "  in bytes     =        %10llu\n",
        (unsigned long long)genericFlow->inPackets, (unsigned long long)genericFlow->inBytes);

    char as[IP_STRING_LEN], ds[IP_STRING_LEN];
    uint32_t src = htonl(ipv4Flow->srcAddr);
    uint32_t dst = htonl(ipv4Flow->dstAddr);
    inet_ntop(AF_INET, &src, as, sizeof(as));
    inet_ntop(AF_INET, &dst, ds, sizeof(ds));

    printf(
        "  src addr     =  %16s\n"
        "  dst addr     =  %16s\n",
        as, ds);

    printf("\n");
}

static void process_data(void) {
    // Get the first file handle
    nffile_t *nffile = GetNextFile(NULL);
    if (nffile == NULL) {
        LogError("Empty file list. No files to process\n");
        return;
    }

    recordHandle_t *recordHandle = calloc(1, sizeof(recordHandle_t));
    if (!recordHandle) {
        LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
        return;
    }

    dataBlock_t *dataBlock = NULL;
    int done = 0;
    while (!done) {
        // get next data block from file
        dataBlock = ReadBlock(nffile, dataBlock);

        if (dataBlock == NULL) {
            if (GetNextFile(nffile) == NULL) {
                done = 1;
                printf("\nDone\n");
                continue;
            }
        }

        if (dataBlock->type != DATA_BLOCK_TYPE_2 && dataBlock->type != DATA_BLOCK_TYPE_3) {
            LogError("Skip block type %u. Write block unmodified", dataBlock->type);
            continue;
        }

        record_header_t *record_ptr = GetCursor(dataBlock);
        uint32_t sumSize = 0;
        uint64_t processed = 0;
        for (int i = 0; i < dataBlock->NumRecords; i++) {
            if ((sumSize + record_ptr->size) > dataBlock->size || (record_ptr->size < sizeof(record_header_t))) {
                LogError("Corrupt data file. Inconsistent block size in %s line %d\n", __FILE__, __LINE__);
                exit(255);
            }
            sumSize += record_ptr->size;

            switch (record_ptr->type) {
                case V3Record:
                    MapRecordHandle(recordHandle, (recordHeaderV3_t *)record_ptr, ++processed);

                    /*
                     * insert hier your calls to your processing routine
                     * recordHandle now contains the mapped flow record
                     * for example you can print each record:
                     */

                    print_record(recordHandle);
                    break;
                default: {
                    // Silently skip unknown records
                }
            }

            // Advance pointer by number of bytes for netflow record
            record_ptr = (record_header_t *)((void *)record_ptr + record_ptr->size);

        }  // for all records

    }  // while

    FreeDataBlock(dataBlock);
    DisposeFile(nffile);

}  // End of process_data

int main(int argc, char **argv) {
    flist_t flist = {0};

    int c = 0;
    while ((c = getopt(argc, argv, "r:M:R:")) != EOF) {
        switch (c) {
            case 'h':
                usage(argv[0]);
                exit(0);
                break;
            case 'r':
                if (!CheckPath(optarg, S_IFREG)) exit(255);
                flist.single_file = strdup(optarg);
                break;
            case 'M':
                if (!CheckPath(optarg, S_IFDIR)) exit(255);
                flist.multiple_dirs = strdup(optarg);
                break;
            case 'R':
                if (!CheckPath(optarg, S_IFDIR)) exit(255);
                flist.multiple_files = strdup(optarg);
                break;
            default:
                usage(argv[0]);
                exit(0);
        }
    }

    queue_t *fileList = SetupInputFileSequence(&flist);
    if (!fileList || !Init_nffile(1, fileList)) exit(255);

    process_data();

    return 0;
}
