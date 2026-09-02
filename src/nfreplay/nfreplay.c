/*
 *  Copyright (c) 2009-2026, Peter Haag
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
#include <inttypes.h>
#include <limits.h>
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
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "config.h"

#ifdef HAVE_STDIO_EXT_H
#include <stdio_ext.h>
#endif

#include "conf/nfconf.h"
#include "filter/filter.h"
#include "flist.h"
#include "id.h"
#include "logging.h"
#include "nbar.h"
#include "nfd_raw.h"
#include "nfcommon.h"
#include "nffileV3/nffileV3.h"
#include "nfthread.h"
#include "nfxV4.h"
#include "send_net.h"
#include "send_v5.h"
#include "send_v9_ipfix.h"
#include "ssl/ssl.h"
#include "util.h"
#include "version.h"

#ifdef HAVE_LIBSODIUM
#include "network/nfd_udp_crypto.h"
#include "nffileV3/nfcrypto.h"
#endif

#define DEFAULTCISCOPORT "9995"
#define DEFAULTHOSTNAME "127.0.0.1"

#undef FPURGE
#ifdef HAVE___FPURGE
#define FPURGE __fpurge
#endif
#ifndef FPURGE
#ifdef HAVE_FPURGE
#define FPURGE fpurge
#endif
#endif
#ifndef FPURGE
#define FPURGE(x) ((void)(x))
#endif

/* Local Variables */
static send_peer_t peer;
static uint32_t recordCnt = 0;
static uint32_t sequence = 0;
/* NfdWireEncode() is also used by the crypto=NONE native path in builds
 * without libsodium. It receives NULL unless -k has derived a key. */
static uint8_t *sessionKey = NULL;

/* Function Prototypes */
static void usage(char *name);

static int send_data(void *engine, uint64_t count, unsigned int delay, int confirm, int netflow_version, int distribution);

static int FlushBuffer(int confirm, int netflow_version);

static void Close_nfd_output(send_peer_t *peer);

static int Add_nfd_output_record(recordHeader_t *record_header, send_peer_t *peer);

/* Logical raw packing limit for native output. The allocation itself is
 * always large enough for a maximum transfer_record_header_t packet so that an otherwise
 * valid record which exceeds this preferred limit can be sent on its own. */
static uint32_t nfdRawPackLimit;

/* Sleep until an absolute CLOCK_MONOTONIC deadline.  clock_nanosleep() is
 * preferable because an interrupted sleep can be retried without recalculating
 * the deadline.  macOS does not provide it, so retain the same absolute-time
 * behaviour with nanosleep() there. */
static int SleepUntilMonotonic(const struct timespec *deadline) {
#ifdef HAVE_CLOCK_NANOSLEEP
    int err;
    do {
        err = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, deadline, NULL);
    } while (err == EINTR);
    if (err != 0) {
        LogError("clock_nanosleep() failed: %s", strerror(err));
        return 0;
    }
#else
    struct timespec now;
    struct timespec remaining;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        LogError("clock_gettime(CLOCK_MONOTONIC) failed: %s", strerror(errno));
        return 0;
    }
    if (now.tv_sec > deadline->tv_sec || (now.tv_sec == deadline->tv_sec && now.tv_nsec >= deadline->tv_nsec)) return 1;

    remaining.tv_sec = deadline->tv_sec - now.tv_sec;
    remaining.tv_nsec = deadline->tv_nsec - now.tv_nsec;
    if (remaining.tv_nsec < 0) {
        remaining.tv_sec--;
        remaining.tv_nsec += 1000000000L;
    }
    while (nanosleep(&remaining, &remaining) != 0) {
        if (errno != EINTR) {
            LogError("nanosleep() failed: %s", strerror(errno));
            return 0;
        }
    }
#endif
    return 1;
}  // End of SleepUntilMonotonic

static int PaceReplay(uint64_t msecLast, uint64_t *referenceMsec, const struct timespec *start, int distribution) {
    const uint64_t minValidMsec = 1000000000000ULL;
    const uint64_t maxValidMsec = 2000000000000ULL;

    if (distribution == 0 || msecLast < minValidMsec || msecLast >= maxValidMsec) return 1;
    if (*referenceMsec == 0) {
        *referenceMsec = msecLast;
        return 1;
    }
    /* Input may not be sorted by time.  A timestamp before the reference is
     * already due and must never delay replay. */
    if (msecLast <= *referenceMsec) return 1;

    uint64_t elapsedUsec = ((msecLast - *referenceMsec) * 1000ULL) / (uint64_t)distribution;
    struct timespec deadline = {
        .tv_sec = start->tv_sec + (time_t)(elapsedUsec / 1000000ULL),
        .tv_nsec = start->tv_nsec + (long)((elapsedUsec % 1000000ULL) * 1000ULL),
    };
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }
    return SleepUntilMonotonic(&deadline);
}  // End of PaceReplay

/* Parse command-line quantities strictly.  atoi() accepts malformed values
 * as zero and may overflow, which is especially unsafe for replay pacing. */
static int ParseUnsignedOption(const char *option, const char *argument, uint64_t maximum, uint64_t *value) {
    char *end = NULL;
    unsigned long long parsed;

    if (argument == NULL || *argument == '\0' || *argument == '-') {
        LogError("Invalid value for %s: %s", option, argument ? argument : "(null)");
        return 0;
    }

    errno = 0;
    parsed = strtoull(argument, &end, 10);
    if (errno == ERANGE || end == argument || *end != '\0' || parsed > maximum) {
        LogError("Invalid value for %s: %s", option, argument);
        return 0;
    }

    *value = (uint64_t)parsed;
    return 1;
}  // End of ParseUnsignedOption

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
        "-r <input>\tRead input from a regular nfdump file (required).\n"
        "-f <filter>\tfilter syntaxfile\n"
        "-v <version>\tUse netflow version to send flows. Either 5, 9, 10 (IPFIX) or 251 (nfdump native).\n"
        "-z <factor>\tSimulate recorded timing; 1 = real time, N = N times faster.\n"
        "-C <file>\tRead optional config file.\n"
        "-x <key>=<value>\tOverride a config parameter for this invocation only. May be repeated.\n",
        name);
#ifdef HAVE_LIBSODIUM
    printf(
        "-k[=<passphrase>|@<keyfile>]\tAuthenticate/encrypt forwarded flows using the nfdump UDP transport protocol.\n"
        "\t\t\t\tPassphrase from argument, @keyfile, or interactive prompt.\n"
        "\t\t\t\tUse together with -v 251.\n");
#endif
    printf(
        "-Y\t\tConfirm each UDP packet before sending.\n"
        "With -v 251, forwarded packets use the nfdump UDP transport protocol: opportunistically\n"
        "compressed (zstd if available, else LZ4) independent of -k, and the target wire packet\n"
        "size follows udp.sendThreshold in nfdump.conf(5) (default 1200 bytes), same as nfcapd/\n"
        "nfpcapd/sfcapd -H.\n");
} /* usage */

static void Flush_nfd_header(send_peer_t *peer) {
    size_t len = (ptrdiff_t)peer->buff_ptr - (ptrdiff_t)peer->send_buffer;
    transfer_record_header_t *transfer_record_header = (transfer_record_header_t *)peer->send_buffer;
    transfer_record_header->recordType = htons(V4Record);
    transfer_record_header->exportTime = htonl((uint32_t)time(NULL));
    transfer_record_header->length = htons(len);
    sequence++;
    dbg_printf("Flush buffer: size: %zu, count: %u, sequence: %u\n", len, recordCnt, sequence);
    transfer_record_header->lastSequence = htonl(sequence);
    transfer_record_header->numRecord = htonl(recordCnt);
    recordCnt = 0;
}  // End of Flush_nfd_header

void Close_nfd_output(send_peer_t *peer) {
    size_t len = (ptrdiff_t)peer->buff_ptr - (ptrdiff_t)peer->send_buffer;
    if (len > 0) {
        Flush_nfd_header(peer);
        peer->flush = 1;
    } else {
        peer->flush = 0;
    }

}  // End of Close_nfd_output

static int Add_nfd_output_record(recordHeader_t *record_header, send_peer_t *peer) {
#ifdef DEVEL
    size_t len = (ptrdiff_t)peer->buff_ptr - (ptrdiff_t)peer->send_buffer;
    printf("Buffer size: %zu, Record count: %u\n", len, recordCnt);
#endif

    if (record_header == NULL) return 0;
    if (record_header->size > UINT16_MAX - sizeof(transfer_record_header_t)) {
        LogError("nfreplay: record size %u exceeds nfd UDP payload limit", record_header->size);
        return -1;
    }

    if (peer->buff_ptr == peer->send_buffer) {
        // empty buffer - add nfd_header
        peer->buff_ptr = peer->buff_ptr + sizeof(transfer_record_header_t);
    }

    size_t used = (size_t)((uint8_t *)peer->buff_ptr - (uint8_t *)peer->send_buffer);
    if (recordCnt && used + record_header->size > nfdRawPackLimit) {
        // Flush the accumulated packet. The caller retries this record.
        Flush_nfd_header(peer);
        peer->flush = 1;
        return 1;
    }

    /* Empty packet: permit one record larger than the preferred packing
     * limit. The physical buffer remains a full nfd UDP payload. */
    if (used + record_header->size > UINT16_MAX) {
        LogError("nfreplay: record size %u exceeds nfd UDP payload limit", record_header->size);
        return -1;
    }
    dbg_printf("Add record - type: %u, size: %u\n", record_header->type, record_header->size);
    memcpy(peer->buff_ptr, (void *)record_header, record_header->size);
    peer->buff_ptr += record_header->size;
    recordCnt++;
    return 0;

}  // End of Add_nfd_output_record

/*
 * NfdRawPackSize — raw (pre-compression) accumulation buffer size for the
 * nfdump-native (-v 251) -H output path: 2x udp.sendThreshold (nfdump.conf(5)),
 * clamped to 65535 since transfer_record_header_t.length is a uint16_t field — matches
 * remote_backend.c's PackFlowBlock() design (see nfd_udp_crypto.h's shared
 * NFD_SEND_THRESHOLD_* constants). Only meaningful for NFD_WIRE_VERSION output;
 * v5/v9/IPFIX keep the fixed UDP_PACKET_SIZE buffer, unaffected by this key.
 */
static uint32_t NfdRawPackSize(void) {
    uint32_t sendThreshold = NFD_SEND_THRESHOLD_DEFAULT;
    int64_t confThreshold = ConfGetValue("udp.sendThreshold");
    if (confThreshold != 0) {
        if (confThreshold < NFD_SEND_THRESHOLD_MIN || confThreshold > NFD_SEND_THRESHOLD_MAX) {
            LogError("nfreplay: udp.sendThreshold %" PRId64 " out of range [%u, %u] — using default %u", confThreshold, NFD_SEND_THRESHOLD_MIN,
                     NFD_SEND_THRESHOLD_MAX, NFD_SEND_THRESHOLD_DEFAULT);
        } else {
            sendThreshold = (uint32_t)confThreshold;
        }
    }
    uint64_t raw = (uint64_t)sendThreshold * 2;
    return raw > 65535u ? 65535u : (uint32_t)raw;
}  // End of NfdRawPackSize

static int FlushBuffer(int confirm, int netflow_version) {
    static unsigned long cnt = 1;

    size_t len = (ptrdiff_t)peer.buff_ptr - (ptrdiff_t)peer.send_buffer;
    if (len == 0) return 0;

    peer.flush = 0;
    peer.buff_ptr = peer.send_buffer;
    if (confirm) {
        FPURGE(stdin);
        printf("Press any key to send next UDP packet [%lu] ", cnt++);
        fflush(stdout);
        fgetc(stdin);
    }

    // Only the nfdump-native output format (-v 251) is nfd wire traffic —
    // v5/v9/IPFIX output must stay byte-for-byte what a real exporter would
    // send, verbatim, for interop with any standard collector.  The
    // universal wire envelope (and its optional compression/encryption)
    // applies only to NFD_WIRE_VERSION.
    if (netflow_version != NFD_WIRE_VERSION) {
        return sendto(peer.sockfd, peer.send_buffer, len, 0, (struct sockaddr *)&(peer.dstaddr), peer.addrlen);
    }

    // crypto=NONE when no sessionKey (works without libsodium), crypto=
    // XCHACHA otherwise. Either way, NfdWireEncode() opportunistically
    // compresses first. Sized for the worst case (NfdRawPackSize()'s own
    // 65535 ceiling), independent of the actual configured threshold.
    static uint8_t wireBuf[65535 + NFD_WIRE_HDR_SIZE + NFD_AEAD_TAG_SIZE];
    ssize_t wireLen = NfdWireEncode(wireBuf, sizeof(wireBuf), peer.send_buffer, len, sessionKey);
    if (wireLen < 0) {
        LogError("NfdWireEncode() failed");
        return -1;
    }
    return sendto(peer.sockfd, wireBuf, (size_t)wireLen, 0, (struct sockaddr *)&(peer.dstaddr), peer.addrlen);
}  // End of FlushBuffer

static int send_data(void *engine, uint64_t limitRecords, unsigned int delay, int confirm, int netflow_version, int distribution) {
    nffileV3_t *nffile = NULL;
    uint64_t twin_msecFirst, twin_msecLast;

    // z-parameter variables
    struct timespec replayStart;
    uint64_t referenceMsec = 0;
    int status = 0;
    recordHandle_t *recordHandle = NULL;

    twin_msecFirst = twin_msecLast = 0;
    const blockConstraint_t *bc = GetBlockConstraint(engine);
    int hasBlockFilter = bc && (!bc->unknown || bc->hasIPConstraint);

    // Get the first file handle
    nffile = GetNextFile();
    if (!nffile) {
        LogError("GetNextFile() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        goto done;
    }
    FilterSetParam(engine, nffile->ident, NOGEODB);

    // Only NFD_WIRE_VERSION (nfd-native, -H) output follows udp.sendThreshold —
    // v5/v9/IPFIX output is genuine wire-format traffic and keeps the fixed
    // UDP_PACKET_SIZE buffer regardless of that key.
    uint32_t sendBufferSize = netflow_version == NFD_WIRE_VERSION ? UINT16_MAX : UDP_PACKET_SIZE;
    nfdRawPackLimit = netflow_version == NFD_WIRE_VERSION ? NfdRawPackSize() : 0;

    peer.send_buffer = malloc(sendBufferSize);
    peer.flush = 0;
    if (!peer.send_buffer) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        goto done;
    }
    peer.buff_ptr = peer.send_buffer;
    peer.endp = (void *)((uint8_t *)peer.send_buffer + sendBufferSize);

    dbg_printf("Init output protocol version: %u\n", netflow_version);
    switch (netflow_version) {
        case VERSION_NETFLOW_V5:
            Init_v5_v7_output(&peer);
            break;
        case VERSION_NETFLOW_V9:
            if (!Init_v9_output(&peer)) {
                goto done;
            }
            break;
        case VERSION_IPFIX:
            if (!Init_ipfix_output(&peer)) {
                goto done;
            }
            break;
        case NFD_WIRE_VERSION:
            // init is lazy — Add_nfd_output_record reserves header space on first record
            break;
    }

    recordHandle = calloc(1, sizeof(recordHandle_t));
    if (!recordHandle) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        goto done;
    }

    if (distribution != 0 && clock_gettime(CLOCK_MONOTONIC, &replayStart) != 0) {
        LogError("clock_gettime(CLOCK_MONOTONIC) failed: %s", strerror(errno));
        goto done;
    }

    uint64_t numflows = 0;
    uint64_t processed = 0;
    status = 1;
    int done = 0;
    while (!done) {
        // get next data block from file
        flowBlockV3_t *dataBlock = ReadBlockV3(nffile);
        if (dataBlock == NULL) {
            CloseFileV3(nffile);
            nffile = GetNextFile();
            if (nffile == NULL) {
                if (GetNextFileFailed()) {
                    LogError("Aborting: a subsequent input file failed to open");
                    status = 0;
                }
                done = 1;
            } else {
                FilterSetParam(engine, nffile->ident, NOGEODB);
            }
            // else continue with next file
            continue;
        }

        if (dataBlock->type != BLOCK_TYPE_FLOW) {
            FreeDataBlock(dataBlock);
            continue;
        }

        if (hasBlockFilter) {
            bloomHandle_t bh = {0};
            if (bc->hasIPConstraint) scanBlockBlooms(dataBlock, &bh);
            if (!FilterBlock(engine, dataBlock->msecFirst, dataBlock->msecLast, &bh)) {
                dbg_printf("filter block: skip block (block constraint)\n");
                FreeDataBlock(dataBlock);
                continue;
            }
        }

        // cnt is the number of blocks, which matched the filter
        // and added to the output buffer
        recordHeader_t *record_ptr = ResetCursor(dataBlock);
        uint32_t sumSize = 0;
        for (int i = 0; i < (int)dataBlock->numRecords; i++) {
            if ((sumSize + record_ptr->size) > dataBlock->rawSize || (record_ptr->size < sizeof(recordHeader_t))) {
                LogError("Corrupt data file. Inconsistent block size in %s line %d", __FILE__, __LINE__);
                status = 0;
                FreeDataBlock(dataBlock);
                goto done;
            }
            sumSize += record_ptr->size;

            switch (record_ptr->type) {
                case V4Record: {
                    int match;
                    processed++;
                    MapV4RecordHandle(recordHandle, (recordHeaderV4_t *)record_ptr, processed);

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
                    if (match) match = FilterRecord(engine, recordHandle);

                    if (match == 0) {  // record failed to pass all filters
                        // go to next record
                        goto NEXT;
                    }
                    // Records passed filter -> continue record processing

                    int again = 0;
                    switch (netflow_version) {
                        case VERSION_NETFLOW_V5:
                            again = Add_v5_output_record(recordHandle, &peer);
                            break;
                        case VERSION_NETFLOW_V9:
                            again = Add_v9_output_record(recordHandle, &peer);
                            break;
                        case VERSION_IPFIX:
                            again = Add_ipfix_output_record(recordHandle, &peer);
                            break;
                        case NFD_WIRE_VERSION:  // nfd raw format
                            again = Add_nfd_output_record(record_ptr, &peer);
                            break;
                    }

                    if (again < 0) {
                        LogError("Cannot add flow record to UDP packet");
                        status = 0;
                        FreeDataBlock(dataBlock);
                        goto done;
                    }

                    numflows++;

                    if (peer.flush) {
                        int err = FlushBuffer(confirm, netflow_version);

                        if (err < 0) {
                            LogError("Error sending data");
                            status = 0;
                            FreeDataBlock(dataBlock);
                            goto done;
                        }

                        if (delay) {
                            // sleep as specified
                            usleep(delay);
                        }
                    }

                    if (again) {
                        switch (netflow_version) {
                            case VERSION_NETFLOW_V5:
                                again = Add_v5_output_record(recordHandle, &peer);
                                break;
                            case VERSION_NETFLOW_V9:
                                again = Add_v9_output_record(recordHandle, &peer);
                                break;
                            case VERSION_IPFIX:
                                again = Add_ipfix_output_record(recordHandle, &peer);
                                break;
                            case NFD_WIRE_VERSION:  // nfd raw format
                                again = Add_nfd_output_record(record_ptr, &peer);
                                break;
                        }
                        if (again != 0) {
                            LogError("Cannot add flow record to an empty UDP packet");
                            status = 0;
                            FreeDataBlock(dataBlock);
                            goto done;
                        }
                    }

                    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
                    if (genericFlow && !PaceReplay(genericFlow->msecLast, &referenceMsec, &replayStart, distribution)) {
                        status = 0;
                        FreeDataBlock(dataBlock);
                        goto done;
                    }

                } break;
                case METARecord:
                    /* bloom META records: consumed by the block-level pre-filter; skip here */
                    break;
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

        NEXT:
            FreeRecordHandle(recordHandle);
            // Advance pointer by number of bytes for netflow record
            record_ptr = (recordHeader_t *)((ptrdiff_t)record_ptr + record_ptr->size);
        }
        FreeDataBlock(dataBlock);
    }  // while

    // flush still remaining records
    switch (netflow_version) {
        case VERSION_NETFLOW_V5:
            break;
        case VERSION_NETFLOW_V9:
            Close_v9_output(&peer);
            break;
        case VERSION_IPFIX:
            Close_ipfix_output(&peer);
            break;
        case NFD_WIRE_VERSION:  // nfd raw format
            Close_nfd_output(&peer);
            break;
    }
    int ret = FlushBuffer(confirm, netflow_version);
    if (ret < 0) {
        LogError("Error flushing send buffer");
        status = 0;
    }

done:
    if (recordHandle) {
        FreeRecordHandle(recordHandle);
        free(recordHandle);
    }
    if (nffile) {
        CloseFileV3(nffile);
    }
    free(peer.send_buffer);
    peer.send_buffer = peer.buff_ptr = peer.endp = NULL;
    if (peer.sockfd >= 0) {
        close(peer.sockfd);
        peer.sockfd = -1;
    }

    return status;

}  // End of send_data

int main(int argc, char **argv) {
    char *ffile, *filter;
    unsigned int delay, sockbuff_size;
    flist_t flist;

    memset((void *)&flist, 0, sizeof(flist));
    ffile = filter = NULL;

    peer.hostname = NULL;
    peer.shostname = NULL;
    peer.port = DEFAULTCISCOPORT;
    peer.mcast = 0;
    peer.family = AF_UNSPEC;
    peer.sockfd = -1;

    delay = 10;
    sockbuff_size = 0;
    int verbose = -1;
    int netflow_version = VERSION_NETFLOW_V9;
    uint64_t count = 0;
    int confirm = 0;
    int distribution = 0;
    char *configFile = NULL;
#ifdef HAVE_LIBSODIUM
    crypto_ctx_t *transfer_ctx = NULL;  // -k: UDP transport encryption
#endif

    int c = 0;
    while ((c = getopt(argc, argv, "46EhH:L:p:S:d:c:b:j:r:f:v:z:VYk::C:x:")) != EOF) {
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
                if (peer.mcast) {
                    LogError("ERROR, -H and -j are mutually exclusive!!\n");
                    exit(EXIT_FAILURE);
                }
                peer.hostname = strdup(optarg);
                break;
            case 'j':
                if (peer.hostname == NULL) {
                    peer.hostname = strdup(optarg);
                    peer.mcast = 1;
                } else {
                    LogError("ERROR, -H and -j are mutually exclusive!!\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'L':
                if (!InitLog(0, argv[0], optarg, verbose)) exit(EXIT_FAILURE);
                break;
            case 'p':
                peer.port = strdup(optarg);
                break;
            case 'S':
                peer.shostname = strdup(optarg);
                break;
            case 'd': {
                uint64_t value;
                if (!ParseUnsignedOption("-d", optarg, UINT_MAX, &value)) exit(EXIT_FAILURE);
                delay = (unsigned int)value;
            } break;
            case 'v': {
                uint64_t value;
                if (!ParseUnsignedOption("-v", optarg, INT_MAX, &value)) exit(EXIT_FAILURE);
                netflow_version = (int)value;
                if (netflow_version == NFD_LEGACY_UDP_VERSION) {
                    // 1.7.x's bare, unwrapped wire format — not supported
                    LogError("legacy UDP version %d no longer supported. Use -v %d for the nfdump native protocol.", NFD_LEGACY_UDP_VERSION,
                             NFD_WIRE_VERSION);
                    exit(EXIT_FAILURE);
                }
                if (netflow_version != 5 && netflow_version != 9 && netflow_version != VERSION_IPFIX && netflow_version != NFD_WIRE_VERSION) {
                    LogError("Invalid netflow version: %s. Accept only 5, 9, 10 (IPFIX) or %d", optarg, NFD_WIRE_VERSION);
                    exit(EXIT_FAILURE);
                }
            } break;
            case 'c': {
                if (!ParseUnsignedOption("-c", optarg, UINT64_MAX, &count)) exit(EXIT_FAILURE);
            } break;
            case 'b': {
                uint64_t value;
                if (!ParseUnsignedOption("-b", optarg, INT_MAX, &value)) exit(EXIT_FAILURE);
                sockbuff_size = (unsigned int)value;
            } break;
            case 'f':
                if (!CheckPath(optarg, S_IFREG)) exit(EXIT_FAILURE);
                ffile = optarg;
                break;
            case 'r':
                if (!CheckPath(optarg, S_IFREG)) exit(EXIT_FAILURE);
                flist.single_file = strdup(optarg);
                break;
            case 'z': {
                uint64_t value;
                if (!ParseUnsignedOption("-z", optarg, INT_MAX, &value)) exit(EXIT_FAILURE);
                distribution = (int)value;
            } break;
            case '4':
                if (peer.family == AF_UNSPEC)
                    peer.family = AF_INET;
                else {
                    LogError("ERROR, Accepts only one protocol IPv4 or IPv6!\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case '6':
                if (peer.family == AF_UNSPEC)
                    peer.family = AF_INET6;
                else {
                    LogError("ERROR, Accepts only one protocol IPv4 or IPv6!\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'k': {
#ifdef HAVE_LIBSODIUM
                char *pp = ParsePassphrase(optarg, "Enter UDP transfer passphrase: ");
                if (!pp) exit(EXIT_FAILURE);
                transfer_ctx = NewCryptoCtx(pp);
                memset(pp, 0, strlen(pp));
                free(pp);
                if (!transfer_ctx) {
                    LogError("Failed to initialize UDP transfer encryption context");
                    exit(EXIT_FAILURE);
                }
#else
                LogError("-k requires a build with libsodium support");
                exit(EXIT_FAILURE);
#endif
                break;
            }
            case 'C':
                if (strcmp(optarg, NOCONF) == 0) {
                    configFile = optarg;
                } else {
                    if (!CheckPath(optarg, S_IFREG)) exit(EXIT_FAILURE);
                    configFile = optarg;
                }
                break;
            case 'x':
                if (!ConfSetOverride(optarg)) exit(EXIT_FAILURE);
                break;
            default:
                usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    if (argc - optind > 1) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    } else {
        // user specified filter */
        filter = argv[optind];
    }

    // No registered defaults needed — udp.sendThreshold is read directly via
    // ConfGetValue(), same idiom as threads.* elsewhere.
    if (ConfOpen(configFile, "nfreplay", NULL) < 0) exit(EXIT_FAILURE);

#ifdef HAVE_LIBSODIUM
    if (transfer_ctx) {
        if (netflow_version != NFD_WIRE_VERSION) {
            LogError("-k requires -v %d (nfdump native protocol)", NFD_WIRE_VERSION);
            exit(EXIT_FAILURE);
        }

        char *confSalt = ConfGetString("crypt.salt");
        if (confSalt) {
            SetUdpSalt(confSalt);
            free(confSalt);
        }

        uint32_t rekeyIntervalSecs = REKEY_INTERVALSECS_DEFAULT;
        int64_t confRekey = ConfGetValue("crypt.rekeyIntervalSecs");
        if (confRekey < 0 || confRekey > 86400 * 7) {
            LogError("nfreplay: nfdump.conf crypt.rekeyIntervalSecs %" PRId64 " out of range [0, 604800]; using default %u", confRekey,
                     REKEY_INTERVALSECS_DEFAULT);
        } else {
            rekeyIntervalSecs = (uint32_t)confRekey;
        }
        SetUdpRekeyInterval(rekeyIntervalSecs);

        sessionKey = DeriveUdpSessionKey(transfer_ctx);
        if (!sessionKey) {
            LogError("Failed to derive UDP session key");
            exit(EXIT_FAILURE);
        }
    }
#endif
    if (peer.hostname == NULL) peer.hostname = DEFAULTHOSTNAME;

    if (!filter && ffile) {
        filter = ReadFilter(ffile);
        if (filter == NULL) {
            exit(EXIT_FAILURE);
        }
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
    if (peer.sockfd < 0) {
        exit(EXIT_FAILURE);
    }

    queue_t *fileList = SetupInputFileSequence(&flist);
    if (!fileList) exit(EXIT_FAILURE);
    threadPipeline_t pipeline = {
        .role = TC_ROLE_ANALYZE,
        .hasReaders = true,   // nffile reader threads decompress input
        .hasWriters = false,  // flows replayed over network, no nffile output
        .hasWorkers = false,  // single-threaded replay
        .fixedThreads = 1,    // main replay loop thread
    };
    threadConfig_t threadConfig = GetThreadConfig(0, UNDEF_COMPRESSED, pipeline);

    if (!Init_nffile(threadConfig, fileList)) exit(EXIT_FAILURE);

    int status = send_data(engine, count, delay, confirm, netflow_version, distribution);
    DisposeFilter(engine);

#ifdef HAVE_LIBSODIUM
    FreeUdpSessionKey(sessionKey);
    FreeCryptoCtx(transfer_ctx);
#endif
    return status ? EXIT_SUCCESS : EXIT_FAILURE;
}
