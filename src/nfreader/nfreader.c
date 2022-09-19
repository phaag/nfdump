/*
 *  Copyright (c) 2009-2022, Peter Haag
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
 * Therefore it allows you to loop over multiple files and process the netflow record.
 *
 * Insert your code in the process_data function after the call to ExpandRecord
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
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nfdump.h"
#include "nffile.h"
#include "nfxV3.h"
#include "util.h"

/* Function Prototypes */
static void usage(char *name);

static void print_record(void *record, char *s);

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

static void print_record(void *record, char *s) {
    char as[40], ds[40], datestr1[64], datestr2[64];
    time_t when;
    struct tm *ts;
    master_record_t *r = (master_record_t *)record;

    if (TestFlag(r->mflags, V3_FLAG_IPV6_ADDR)) {
        r->V6.srcaddr[0] = htonll(r->V6.srcaddr[0]);
        r->V6.srcaddr[1] = htonll(r->V6.srcaddr[1]);
        r->V6.dstaddr[0] = htonll(r->V6.dstaddr[0]);
        r->V6.dstaddr[1] = htonll(r->V6.dstaddr[1]);
        inet_ntop(AF_INET6, r->V6.srcaddr, as, sizeof(as));
        inet_ntop(AF_INET6, r->V6.dstaddr, ds, sizeof(ds));
    } else {  // IPv4
        r->V4.srcaddr = htonl(r->V4.srcaddr);
        r->V4.dstaddr = htonl(r->V4.dstaddr);
        inet_ntop(AF_INET, &r->V4.srcaddr, as, sizeof(as));
        inet_ntop(AF_INET, &r->V4.dstaddr, ds, sizeof(ds));
    }
    as[40 - 1] = 0;
    ds[40 - 1] = 0;

    when = r->msecFirst / 1000LL;
    ts = localtime(&when);
    strftime(datestr1, 63, "%Y-%m-%d %H:%M:%S", ts);

    when = r->msecLast / 1000LL;
    ts = localtime(&when);
    strftime(datestr2, 63, "%Y-%m-%d %H:%M:%S", ts);

    snprintf(s, 1023,
             "\n"
             "Flow Record: \n"
             "  srcaddr     = %16s\n"
             "  dstaddr     = %16s\n"
             "  first        =     %13llu [%s.%03llu]\n"
             "  last         =     %13llu [%s.%03llu]\n"
             "  prot        =              %3u\n"
             "  srcPort     =            %5u\n"
             "  dstPort     =            %5u\n"
             "  dPkts       =       %10llu\n"
             "  dOctets     =       %10llu\n",
             as, ds, r->msecFirst, datestr1, r->msecFirst % 1000LL, r->msecLast, datestr2, r->msecFirst % 1000LL, r->proto, r->srcPort, r->dstPort,
             (unsigned long long)r->inPackets, (unsigned long long)r->inBytes);

    s[1024 - 1] = 0;

}  // End of print_record

static void process_data(void) {
    nffile_t *nffile;
    int i, done, ret;

    // Get the first file handle
    nffile = GetNextFile(NULL);
    if (!nffile) {
        LogError("GetNextFile() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
        return;
    }
    if (nffile == EMPTY_LIST) {
        LogError("Empty file list. No files to process\n");
        return;
    }

    master_record_t *master_record = malloc(sizeof(master_record_t));
    if (!master_record) {
        LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
        return;
    }

    done = 0;
    while (!done) {
        // get next data block from file
        ret = ReadBlock(nffile);

        switch (ret) {
            case NF_CORRUPT:
            case NF_ERROR:
                if (ret == NF_CORRUPT)
                    fprintf(stderr, "Skip corrupt data file '%s'\n", nffile->fileName);
                else
                    fprintf(stderr, "Read error in file '%s': %s\n", nffile->fileName, strerror(errno));
                // fall through - get next file in chain
            case NF_EOF: {
                nffile_t *next = GetNextFile(nffile);
                if (next == EMPTY_LIST) {
                    done = 1;
                }
                if (next == NULL) {
                    done = 1;
                    LogError("Unexpected end of file list\n");
                }
                // else continue with next file
                continue;

            } break;  // not really needed
        }

        if (nffile->block_header->type != DATA_BLOCK_TYPE_2 && nffile->block_header->type != DATA_BLOCK_TYPE_3) {
            fprintf(stderr, "Can't process block type %u. Skip block.\n", nffile->block_header->type);
            continue;
        }

        record_header_t *record_ptr = nffile->buff_ptr;
        uint32_t sumSize = 0;
        for (i = 0; i < nffile->block_header->NumRecords; i++) {
            char string[1024];
            if ((sumSize + record_ptr->size) > ret || (record_ptr->size < sizeof(record_header_t))) {
                LogError("Corrupt data file. Inconsistent block size in %s line %d\n", __FILE__, __LINE__);
                exit(255);
            }
            sumSize += record_ptr->size;

            switch (record_ptr->type) {
                case V3Record:
                    memset((void *)master_record, 0, sizeof(master_record_t));
                    ExpandRecord_v3((recordHeaderV3_t *)record_ptr, master_record);

                    /*
                     * insert hier your calls to your processing routine
                     * master_record now contains the next flow record as specified in nffile.c
                     * for example you can print each record:
                     *
                     */
                    print_record(&master_record, string);
                    printf("%s\n", string);
                    break;
                case ExporterInfoRecordType:
                case ExporterStatRecordType:
                    // Silently skip exporter records
                    break;
                default: {
                    fprintf(stderr, "Skip unknown record type %i\n", record_ptr->type);
                }
            }

            // Advance pointer by number of bytes for netflow record
            record_ptr = (record_header_t *)((void *)record_ptr + record_ptr->size);

        }  // for all records

    }  // while

    CloseFile(nffile);
    DisposeFile(nffile);

}  // End of process_data

int main(int argc, char **argv) {
    flist_t flist;
    int c;

    memset((void *)&flist, 0, sizeof(flist));
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
    if (!fileList || !Init_nffile(fileList)) exit(255);

    process_data();

    return 0;
}
