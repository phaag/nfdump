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

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "config.h"

#ifdef HAVE_STDIO_EXT_H
#include <stdio_ext.h>
#endif

#include "filter/filter.h"
#include "flist.h"
#include "nbar.h"
#include "nfd_raw.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfxV3.h"
#include "send_net.h"
#include "send_v5.h"
#include "send_v9.h"
#include "util.h"
#include "version.h"

#define DEFAULTCISCOPORT "9995"
#define DEFAULTHOSTNAME "127.0.0.1"

#undef FPURGE
#ifdef HAVE___FPURGE
#define FPURGE __fpurge
#endif
#ifdef HAVE_FPURGE
#define FPURGE fpurge
#endif

/* Local Variables */
static int verbose = 0;

static send_peer_t peer;
static uint32_t recordCnt = 0;
static uint32_t sequence = 0;

/* Function Prototypes */
static void usage(char *name);

static void send_data(void *engine, timeWindow_t *timeWindow, uint32_t count, unsigned int delay, int confirm, int netflow_version, int distribution);

static int FlushBuffer(int confirm);

static void Close_nfd_output(send_peer_t *peer);

static int Add_nfd_output_record(record_header_t *record_header, send_peer_t *peer);

/* Functions */

#include "nfdump_inline.c"
#include "nffile_inline.c"

static void usage(char *name) {
    printf(
        "usage %s [options] [\"filter\"]\n"
        "-h\t\tthis text you see right here\n"
        "-V\t\tPrint version and exit.\n"
        "-E\t\tPrint verbose messages. For debugging purpose only.\n"
        "-H <Host/ip>\tTarget IP address default: 127.0.0.1\n"
        "-j <mcast>\tSend packets to multicast group\n"
        "-4\t\tForce IPv4 protocol.\n"
        "-6\t\tForce IPv6 protocol.\n"
        "-L <log>\tLog to syslog facility <log>\n"
        "-p <port>\tTarget port default 9995\n"
        "-S <ip>\tSource IP address for sending flows\n"
        "-d <usec>\tDelay in usec between packets. default 10\n"
        "-c <cnt>\tPacket count. default send all packets\n"
        "-b <bsize>\tSend buffer size.\n"
        "-r <input>\tread from file. default: stdin\n"
        "-f <filter>\tfilter syntaxfile\n"
        "-v <version>\tUse netflow version to send flows. Either 5 or 9\n"
        "-z <distribution>\tSimulate real time distribution with coefficient\n"
        "-t <time>\ttime window for sending packets\n"
        "\t\tyyyy/MM/dd.hh:mm:ss[-yyyy/MM/dd.hh:mm:ss]\n",
        name);
} /* usage */

void Close_nfd_output(send_peer_t *peer) {
    size_t len = (pointer_addr_t)peer->buff_ptr - (pointer_addr_t)peer->send_buffer;
    if (len > 0) {
        // flush last packet
        nfd_header_t *nfd_header = (nfd_header_t *)peer->send_buffer;
        nfd_header->version = htons(NFD_PROTOCOL);
        nfd_header->length = htons(len);
        sequence++;
        dbg_printf("Flush buffer: size: %zu, count: %u, sequence: %u\n", len, recordCnt, sequence);
        nfd_header->lastSequence = htonl(sequence);
        nfd_header->numRecord = htonl(recordCnt);
        recordCnt = 0;
        peer->flush = 1;
    } else {
        peer->flush = 0;
    }

}  // End of Close_nfd_output

int Add_nfd_output_record(record_header_t *record_header, send_peer_t *peer) {
#ifdef DEVEL
    size_t len = (pointer_addr_t)peer->buff_ptr - (pointer_addr_t)peer->send_buffer;
    printf("Buffer size: %zu, Record count: %u\n", len, recordCnt);
#endif

    if (peer->buff_ptr == peer->send_buffer) {
        // empty buffer - add nfd_header
        peer->buff_ptr = peer->buff_ptr + sizeof(nfd_header_t);
    }

    // record_header == NULL -> no record to add, but flush buffer
    if ((peer->buff_ptr + record_header->size) >= peer->endp) {
        // flush packet first
        size_t len = (pointer_addr_t)peer->buff_ptr - (pointer_addr_t)peer->send_buffer;

        nfd_header_t *nfd_header = (nfd_header_t *)peer->send_buffer;
        nfd_header->version = htons(NFD_PROTOCOL);
        nfd_header->length = htons(len);
        sequence++;
        dbg_printf("Flush buffer: size: %zu, count: %u, sequence: %u\n", len, recordCnt, sequence);
        nfd_header->lastSequence = htonl(sequence);
        nfd_header->numRecord = htonl(recordCnt);
        recordCnt = 0;
        peer->flush = 1;
        return 1;
    }
    dbg_printf("Add record - type: %u, size: %u\n", record_header->type, record_header->size);
    memcpy(peer->buff_ptr, (void *)record_header, record_header->size);
    peer->buff_ptr += record_header->size;
    recordCnt++;
    return 0;

}  // End of Add_nfd_output_record

static int FlushBuffer(int confirm) {
    static unsigned long cnt = 1;

    size_t len = (pointer_addr_t)peer.buff_ptr - (pointer_addr_t)peer.send_buffer;
    if (len == 0) return 0;

    peer.flush = 0;
    peer.buff_ptr = peer.send_buffer;
    if (confirm) {
        FPURGE(stdin);
        printf("Press any key to send next UDP packet [%lu] ", cnt++);
        fflush(stdout);
        fgetc(stdin);
    }
    return sendto(peer.sockfd, peer.send_buffer, len, 0, (struct sockaddr *)&(peer.dstaddr), peer.addrlen);
}  // End of FlushBuffer

static void send_data(void *engine, timeWindow_t *timeWindow, uint32_t limitRecords, unsigned int delay, int confirm, int netflow_version,
                      int distribution) {
    nffile_t *nffile;
    uint64_t twin_msecFirst, twin_msecLast;

    // z-parameter variables
    struct timeval todayTime, currentTime;
    double today = 0, reftime = 0;
    int reducer = 0;

    if (timeWindow) {
        twin_msecFirst = timeWindow->first * 1000LL;
        if (timeWindow->last)
            twin_msecLast = timeWindow->last * 1000LL;
        else
            twin_msecLast = 0x7FFFFFFFFFFFFFFFLL;
    } else {
        twin_msecFirst = twin_msecLast = 0;
    }

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
    FilterSetParam(engine, nffile->ident, NOGEODB);

    peer.send_buffer = malloc(UDP_PACKET_SIZE);
    peer.flush = 0;
    if (!peer.send_buffer) {
        LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
        CloseFile(nffile);
        DisposeFile(nffile);
        return;
    }
    peer.buff_ptr = peer.send_buffer;
    peer.endp = (void *)((pointer_addr_t)peer.send_buffer + UDP_PACKET_SIZE - 1);

    dbg_printf("Init output protocol version: %u\n", netflow_version);
    switch (netflow_version) {
        case 5:
            Init_v5_v7_output(&peer);
            break;
        case 9:
            if (!Init_v9_output(&peer)) return;
            break;
    }

    recordHandle_t *recordHandle = calloc(1, sizeof(recordHandle_t));
    if (!recordHandle) {
        LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
        return;
    }

    uint32_t numflows = 0;
    uint32_t processed = 0;
    int done = 0;
    while (!done) {
        // get next data block from file
        int ret = ReadBlock(nffile);

        switch (ret) {
            case NF_CORRUPT:
            case NF_ERROR:
                if (ret == NF_CORRUPT)
                    LogError("Skip corrupt data file '%s'\n", nffile->fileName);
                else
                    LogError("Read error in file '%s': %s\n", nffile->fileName, strerror(errno));
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
                FilterSetParam(engine, nffile->ident, NOGEODB);
                // else continue with next file
                continue;

            } break;  // not really needed
        }

        if (nffile->block_header->type != DATA_BLOCK_TYPE_2 && nffile->block_header->type != DATA_BLOCK_TYPE_3) {
            LogError("Can't process block type %u. Skip block.\n", nffile->block_header->type);
            continue;
        }

        // cnt is the number of blocks, which matched the filter
        // and added to the output buffer
        record_header_t *record_ptr = nffile->buff_ptr;
        uint32_t sumSize = 0;
        for (int i = 0; i < nffile->block_header->NumRecords; i++) {
            if ((sumSize + record_ptr->size) > ret || (record_ptr->size < sizeof(record_header_t))) {
                LogError("Corrupt data file. Inconsistent block size in %s line %d\n", __FILE__, __LINE__);
                exit(255);
            }
            sumSize += record_ptr->size;

            switch (record_ptr->type) {
                case V3Record: {
                    int match;
                    processed++;
                    MapRecordHandle(recordHandle, (recordHeaderV3_t *)record_ptr, processed);

                    // Time based filter
                    // if no time filter is given, the result is always true
                    if (twin_msecFirst) {
                        EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
                        match = (genericFlow->msecFirst < twin_msecFirst || genericFlow->msecLast > twin_msecLast) ? 0 : 1;
                    } else {
                        match = 1;
                    }

                    // limit recordcount
                    match &= limitRecords ? numflows < limitRecords : 1;

                    // filter netflow record with user supplied filter
                    // XXX if (match) match = (*Engine->FilterEngine)(Engine);
                    if (match) match = FilterRecord(engine, recordHandle);

                    if (match == 0) {  // record failed to pass all filters
                        // go to next record
                        goto NEXT;
                    }
                    // Records passed filter -> continue record processing

                    int again = 0;
                    switch (netflow_version) {
                        case 5:
                            again = Add_v5_output_record(recordHandle, &peer);
                            break;
                        case 9:
                            again = Add_v9_output_record(recordHandle, &peer);
                            break;
                        case 250:
                            again = Add_nfd_output_record(record_ptr, &peer);
                            break;
                    }

                    numflows++;

                    if (peer.flush) {
                        int err = FlushBuffer(confirm);

                        if (err < 0) {
                            perror("Error sending data");
                            CloseFile(nffile);
                            DisposeFile(nffile);
                            return;
                        }

                        if (delay) {
                            // sleep as specified
                            usleep(delay);
                        }
                    }

                    if (again) {
                        switch (netflow_version) {
                            case 5:
                                again = Add_v5_output_record(recordHandle, &peer);
                                break;
                            case 9:
                                again = Add_v9_output_record(recordHandle, &peer);
                                break;
                            case 250:
                                again = Add_nfd_output_record(record_ptr, &peer);
                                break;
                        }
                    }

                } break;
                case LegacyRecordType1:
                case LegacyRecordType2:
                case ExporterInfoRecordType:
                case ExporterStatRecordType:
                case SamplerRecordType:
                case NbarRecordType:
                    // Silently skip exporter/sampler records
                    break;
                default: {
                    LogError("Skip unknown record type %i\n", record_ptr->type);
                }
            }

            // z-parameter
            // first and last are line (tstart and tend) timestamp with milliseconds
            // first = (double)genericFlow->msecFirst / 1000.0;
            double last = 0.0;
            EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
            if (genericFlow) last = (double)genericFlow->msecLast / 1000.0;

            gettimeofday(&currentTime, NULL);
            double now = (double)currentTime.tv_sec + (double)currentTime.tv_usec / 1000000;

            // remove incoherent values
            if (reftime == 0 && last > 1000000000 && last < 2000000000) {
                reftime = last;
                gettimeofday(&todayTime, NULL);
                today = (double)todayTime.tv_sec + (double)todayTime.tv_usec / 1000000;
            }

            // Reducer avoid to have too much computation: It takes 1 over 3 line to regulate sending time
            if (reducer % 3 == 0 && distribution != 0 && reftime != 0 && last > 1000000000) {
                while (last - reftime > distribution * (now - today)) {
                    gettimeofday(&currentTime, NULL);
                    now = (double)currentTime.tv_sec + (double)currentTime.tv_usec / 1000000;
                }
            }
            reducer++;

        NEXT:
            // Advance pointer by number of bytes for netflow record
            record_ptr = (record_header_t *)((pointer_addr_t)record_ptr + record_ptr->size);
        }
    }  // while

    // flush still remaining records
    switch (netflow_version) {
        case 5:
            break;
        case 9:
            Close_v9_output(&peer);
            break;
        case 250:
            Close_nfd_output(&peer);
            break;
    }
    int ret = FlushBuffer(confirm);
    if (ret < 0) {
        LogError("Error flushing send buffer");
    }

    if (nffile) {
        CloseFile(nffile);
        DisposeFile(nffile);
    }

    close(peer.sockfd);

    return;

}  // End of send_data

int main(int argc, char **argv) {
    struct stat stat_buff;
    char *ffile, *filter, *tstring;
    int c, confirm, ffd, ret, netflow_version, distribution;
    unsigned int delay, count, sockbuff_size;
    timeWindow_t *timeWindow;
    flist_t flist;

    memset((void *)&flist, 0, sizeof(flist));
    ffile = filter = tstring = NULL;
    timeWindow = NULL;

    peer.hostname = NULL;
    peer.shostname = NULL;
    peer.port = DEFAULTCISCOPORT;
    peer.mcast = 0;
    peer.family = AF_UNSPEC;
    peer.sockfd = 0;

    delay = 1;
    count = 0;
    sockbuff_size = 0;
    netflow_version = 9;
    verbose = 0;
    confirm = 0;
    distribution = 0;
    while ((c = getopt(argc, argv, "46EhH:i:K:L:p:S:d:c:b:j:r:f:t:v:z:VY")) != EOF) {
        switch (c) {
            case 'h':
                usage(argv[0]);
                exit(0);
                break;
            case 'E':
                verbose = 1;
                break;
            case 'V':
                printf("%s: %s\n", argv[0], versionString());
                exit(0);
                break;
            case 'Y':
                confirm = 1;
                break;
            case 'H':
            case 'i':  // compatibility with old version
                peer.hostname = strdup(optarg);
                peer.mcast = 0;
                break;
            case 'j':
                if (peer.hostname == NULL) {
                    peer.hostname = strdup(optarg);
                    peer.mcast = 1;
                } else {
                    LogError("ERROR, -H(-i) and -j are mutually exclusive!!\n");
                    exit(255);
                }
                break;
            case 'K':
                LogError("*** Anonymization moved! Use nfanon to anonymize flows first!\n");
                exit(255);
                break;
            case 'L':
                if (!InitLog(0, argv[0], optarg, verbose)) exit(255);
                break;
            case 'p':
                peer.port = strdup(optarg);
                break;
            case 'S':
                peer.shostname = strdup(optarg);
                break;
            case 'd':
                delay = atoi(optarg);
                break;
            case 'v':
                netflow_version = atoi(optarg);
                if (netflow_version != 5 && netflow_version != 9 && netflow_version != 250) {
                    LogError("Invalid netflow version: %s. Accept only 5 or 9 or 250", optarg);
                    exit(255);
                }
                break;
            case 'c':
                count = atoi(optarg);
                break;
            case 'b':
                sockbuff_size = atoi(optarg);
                break;
            case 'f':
                ffile = optarg;
                break;
            case 't':
                tstring = optarg;
                break;
            case 'r':
                if (!CheckPath(optarg, S_IFREG)) exit(255);
                flist.single_file = strdup(optarg);
                break;
            case 'z':
                distribution = atoi(optarg);
                break;
            case '4':
                if (peer.family == AF_UNSPEC)
                    peer.family = AF_INET;
                else {
                    LogError("ERROR, Accepts only one protocol IPv4 or IPv6!\n");
                    exit(255);
                }
                break;
            case '6':
                if (peer.family == AF_UNSPEC)
                    peer.family = AF_INET6;
                else {
                    LogError("ERROR, Accepts only one protocol IPv4 or IPv6!\n");
                    exit(255);
                }
                break;
            default:
                usage(argv[0]);
                exit(0);
        }
    }
    if (argc - optind > 1) {
        usage(argv[0]);
        exit(255);
    } else {
        /* user specified a pcap filter */
        filter = argv[optind];
    }

    if (peer.hostname == NULL) peer.hostname = DEFAULTHOSTNAME;

    if (!filter && ffile) {
        if (stat(ffile, &stat_buff)) {
            perror("Can't stat file");
            exit(255);
        }
        filter = (char *)malloc(stat_buff.st_size);
        if (!filter) {
            perror("Memory error");
            exit(255);
        }
        ffd = open(ffile, O_RDONLY);
        if (ffd < 0) {
            perror("Can't open file");
            exit(255);
        }
        ret = read(ffd, (void *)filter, stat_buff.st_size);
        if (ret < 0) {
            perror("Error reading file");
            close(ffd);
            exit(255);
        }
        close(ffd);
    }

    if (!filter) filter = "any";

    void *engine = CompileFilter(filter);
    if (!engine) exit(254);

    if (peer.mcast)
        peer.sockfd =
            Multicast_send_socket(peer.shostname, peer.hostname, peer.port, peer.family, sockbuff_size, &peer.srcaddr, &peer.dstaddr, &peer.addrlen);
    else
        peer.sockfd =
            Unicast_send_socket(peer.shostname, peer.hostname, peer.port, peer.family, sockbuff_size, &peer.srcaddr, &peer.dstaddr, &peer.addrlen);
    if (peer.sockfd <= 0) {
        exit(255);
    }

    if (tstring) {
        flist.timeWindow = ScanTimeFrame(tstring);
        if (!flist.timeWindow) exit(255);
    }

    queue_t *fileList = SetupInputFileSequence(&flist);
    if (!Init_nffile(1, fileList)) exit(254);

    send_data(engine, timeWindow, count, delay, confirm, netflow_version, distribution);

    return 0;
}
