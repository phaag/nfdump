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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>

#include "config.h"

#ifdef ENABLE_READPCAP
#include "pcap_reader.h"
#endif

#ifdef HAVE_LIBSODIUM
#include <sodium.h>
#endif

#include "backend.h"
#include "barrier.h"
#include "collector.h"
#include "compress/nfcompress.h"
#include "conf/nfconf.h"
#include "daemon.h"
#include "flist.h"
#include "flowsource.h"
#include "ip128.h"
#include "ipfix.h"
#include "launch.h"
#include "logging.h"
#include "metric.h"
#include "netflow_v1.h"
#include "netflow_v5_v7.h"
#include "netflow_v9.h"
#include "nfd_raw.h"
#include "nfdump.h"
#include "nffileV3/nffileV3.h"
#include "nfnet.h"
#include "nfxV4.h"
#include "pidfile.h"
#include "repeater.h"
#include "util.h"
#include "version.h"
#include "yaf_reader.h"

#define DEFAULTLISTENPORT "9995"

// packet function prototype for yaf or pcap reader
typedef ssize_t (*packet_function_t)(void *, size_t, struct sockaddr_storage *, socklen_t *, struct timeval *);

/* module limited globals */
static volatile sig_atomic_t done = 0;

/* Local function Prototypes */
static void usage(char *name);

static void IntHandler(int signal);

/* Functions */
static void usage(char *name) {
    printf(
        "usage %s [options] \n"
        "-h\t\tthis text you see right here\n"
        "-u userid\tChange user to username\n"
        "-g groupid\tChange group to groupname\n"
        "-t interval\tset the interval to rotate nfcapd files\n"
        "-b host\t\tbind socket to host/IP addr\n"
        "-J mcastgroup\tJoin multicast group <mcastgroup>\n"
        "-p portnum\tlisten on port portnum\n"
#ifdef ENABLE_READPCAP
        "-f pcapfile\tRead network data from pcap file.\n"
        "-d device\tRead network data from device (interface).\n"
#endif
        "-Y yaffile \tRead ipfix yaf file.\n"
        "-w flowdir \tset the output directory to store the flows.\n"
        "-C <file>\tRead optional config file.\n"
        "-S subdir\tSub directory format. see nfcapd(1) for format\n"
        "-I Ident\tset the ident string for stat file. (default 'none')\n"
        "-n Ident,IP,flowdir\tAdd this flow source - multiple streams\n"
        "-i interval\tMetric interval in s for metric exporter\n"
        "-m socket\tEnable metric exporter on socket.\n"
        "-M dir \tSet the output directory for dynamic sources.\n"
        "-P pidfile\tset the PID file\n"
        "-R IP[/port]\tRepeat incoming packets to IP address/port.\n"
        "-A\t\tEnable source address spoofing for packet repeater -R.\n"
        "-s rate\tset default sampling rate (default 1)\n"
        "-x process\tlaunch process after a new file becomes available\n"
        "-W workers\toptionally set the number of workers to compress flows\n"
        "-z=lzo\t\tLZO compress flows in output file.\n"
        "-z=bz2\t\tBZIP2 compress flows in output file.\n"
        "-z=lz4[:level]\tLZ4 compress flows in output file.\n"
        "-z=zstd[:level]\tZSTD compress flows in output file.\n"
        "-B bufflen\tSet socket buffer to bufflen bytes\n"
        "-e\t\tExpire data at each cycle.\n"
        "-D\t\tFork to background\n"
        "-E\t\tDeprecated. Use -v 3 to print raw records. For debugging purpose only.\n"
        "-v level\tSet verbose level.\n"
        "-4\t\tListen on IPv4 only.\n"
        "-6\t\tListen on IPv6 only\n"
        "-X <extlist>\t',' separated list of extensions (numbers). Default all extensions.\n"
        "-V\t\tPrint version and exit.\n"
        "-Z\t\tAdd timezone offset to filename.\n"
#ifdef HAVE_LIBSODIUM
        "-K[=passphrase|@keyfile]\tEncrypt output files. Passphrase from argument, key file, or interactive prompt.\n"
#endif
        ,
        name);
}  // End of usage

#include "nffile_inline.c"
#include "collector_run_inline.c"

static inline void process_packet(collector_ctx_t *ctx, const nffile_backend_ctx_t *nffile_backend_ctx, PacketCtx_t *pkt_ctx, ssize_t cnt,
                                  struct timeval tv, uint64_t *packets, uint32_t *ignored_packets) {
    char sa_address[INET6_ADDRSTRLEN];
    const common_flow_header_t *nf_header = (const common_flow_header_t *)pkt_ctx->buffer;

    dbg_printf("Received packet from: %s, size: %zd\n", GetClientIPstring(&pkt_ctx->sender, sa_address), cnt);

    // in case of reading from file EOF => -2
    if (cnt == -2) {
        done = 1;
        return;
    }
    if (cnt == 0) {
        (*ignored_packets)++;
        (*packets)++;
        return;
    }

    if (cnt < 0) {
        // recvmsg error already logged by caller if needed
        return;
    }

    (*packets)++;

    // get flow source record for current packet, identified by sender IP address
    FlowSource_t *fs = GetFlowSource(ctx, &pkt_ctx->sender);
    if (fs == NULL) {
        // check, if we have dynamic flowsources configured
        fs = NewDynFlowSource(ctx, &pkt_ctx->sender);
        if (fs == NULL) {
            (*ignored_packets)++;
            LogError("Skip UDP packet from: %s. Ignored packets: %u", GetClientIPstring(&pkt_ctx->sender, sa_address), *ignored_packets);
            return;
        }

        if (!Init_nffile_backend(fs, nffile_backend_ctx)) {
            LogError("Failed to initialise backend for new source");
            // XXX should free this flow source
            queue_abort(fs->blockQueue);
            return;
        }
        if (!Launch_nffile_backend(fs)) {
            LogError("Launch_nffile_backend() failed");
            done = 1;
            return;
        }
    }

    /* check for too little data - cnt must be > 0 at this point */
    if (cnt < (ssize_t)sizeof(common_flow_header_t)) {
        LogError("Ident: %s, Data size error: not enough data for netflow header - cnt: %i", fs->Ident, (int)cnt);
        fs->bad_packets++;
        return;
    }

    fs->received = tv;
    /* Process data - have a look at the common header */
    uint16_t version = ntohs(nf_header->version);
    switch (version) {
        case VERSION_NETFLOW_V1:
            Process_v1(pkt_ctx->buffer, cnt, fs);
            break;
        case VERSION_NETFLOW_V5:  // fall through
        case VERSION_NETFLOW_V7:
            Process_v5_v7(pkt_ctx->buffer, cnt, fs);
            break;
        case VERSION_NETFLOW_V9:
            Process_v9(pkt_ctx->buffer, cnt, fs);
            break;
        case VERSION_IPFIX:
            Process_IPFIX(pkt_ctx->buffer, cnt, fs);
            break;
        case VERSION_NFDUMP:
            Process_nfd(pkt_ctx->buffer, cnt, fs);
            break;
        default: {
            LogError(
                "Error packet %llu: Ident: %s reading netflow header: "
                "Unexpected netflow version %i from: %s",
                *packets, fs->Ident, version, GetClientIPstring(&pkt_ctx->sender, sa_address));
            fs->bad_packets++;
            return;
        } break;
    }

}  // End of process_packet

// live network mode
static void run_network(collector_ctx_t *ctx, const nffile_backend_ctx_t *nffile_backend_ctx, repeater_ctx_t *repeater_ctx, int *socks, int nsocks,
                        time_t t_win) {
    // prepare socket msg struct
    PacketCtx_t *pkt_ctx = init_packet_ctx(NETWORK_INPUT_BUFF_SIZE);
    if (!pkt_ctx) return;

    for (FlowSource_t *fs = NextFlowSource(ctx); fs; fs = NextFlowSource(NULL)) {
        fs->dataBlock = NewFlowBlock(BLOCK_SIZE_V3);
        if (!fs->dataBlock) {
            LogError("run_network: out of memory allocating data block for ident: %s", fs->Ident);
            free(pkt_ctx);
            return;
        }
        fs->bad_packets = 0;
    }

    uint32_t ignored_packets = 0;
    uint64_t packets = 0;

    time_t now = time(NULL);
    time_t t_start = now - (now % t_win);
    time_t next_rotate = t_start + t_win;

    // Block shutdown signals once here; pselect() unblocks them atomically
    // during each wait.  Restored after the loop.
    sigset_t blockmask, origmask;
    sigemptyset(&blockmask);
    sigaddset(&blockmask, SIGTERM);
    sigaddset(&blockmask, SIGINT);
    sigaddset(&blockmask, SIGHUP);
    sigprocmask(SIG_BLOCK, &blockmask, &origmask);

    uint32_t repeaterDropped = 0;
    while (!done) {
        // wait for packet or timeout
        int ret = poll_for_packet(socks, nsocks, next_rotate, &origmask);

        if (ret >= 0) {
            // packet ready on socks[ret]
            struct timeval tv = {0};
            ssize_t cnt = recv_packet(socks[ret], pkt_ctx, &tv);

            now = tv.tv_sec;
            if (cnt > 0) {
                process_packet(ctx, nffile_backend_ctx, pkt_ctx, cnt, tv, &packets, &ignored_packets);

                // packet received
                // repeat this packet
                if (unlikely(repeater_ctx != NULL)) {
                    // push context
                    if (queue_try_push(repeater_ctx->packetQueue, pkt_ctx) == NULL) {
                        // successfully pushed packet context - get next free context
                        PacketCtx_t *next = queue_try_pop(repeater_ctx->bufferQueue);
                        if (next == NULL || next == QUEUE_EMPTY) {
                            // pool exhausted - allocate a fresh context
                            next = init_packet_ctx(NETWORK_INPUT_BUFF_SIZE);
                            if (!next) {
                                LogError("run_network() out of memory in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                                done = 1;
                                pkt_ctx = NULL;
                                continue;
                            }
                        } else if (next == QUEUE_CLOSED) {
                            LogError("run_network() fatal error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                            done = 1;
                            pkt_ctx = NULL;
                            continue;
                        }
                        pkt_ctx = next;
                    } else {
                        // else queue full - re-use current context - drop this packet for repeater
                        repeaterDropped++;
                    }
                }

            } else if (cnt == 0) {
                // Zero-length packet - ignore
                ignored_packets++;
                packets++;
            } else if (cnt == -2) {
                // EINTR + done
            } else {
                // recvmsg error */
                LogError("recvmsg() failed: %s", strerror(errno));
                continue;
            }
        } else if (ret == -3) {
            // poll timeout -> rotate
            now = time(NULL);
        } else if (ret == -2) {
            // EINTR + done
            now = time(NULL);
        } else {
            // poll error
            LogError("poll() failed: %s", strerror(errno));
            break;
        }

        // rotation check
        if (now >= next_rotate || done) {
            dbg(char ctime_buf[26]);
            dbg_printf("Periodic cycle - done: %u, for slot: %s\n", done, ctime_r(&t_start, ctime_buf));

            if (!PeriodicCycle(ctx, t_start, done)) {
                LogError("run loop terminated due to serious errors");
                break;
            }

            double interval = (double)t_win;
            if (interval <= 0.0) interval = 1.0;

            if (repeaterDropped) {
                LogInfo("Total packets received: %llu avg: %3.2f/s ignored packets: %u, dropped repeater packet: %u", packets,
                        (double)packets / interval, ignored_packets, repeaterDropped);
            } else {
                LogInfo("Total packets received: %llu avg: %3.2f/s ignored packets: %u", packets, (double)packets / interval, ignored_packets);
            }
            packets = ignored_packets = repeaterDropped = 0;

            if (done) break;

            t_start = next_rotate;
            next_rotate += t_win;
        }
    }

    sigprocmask(SIG_SETMASK, &origmask, NULL);
    if (pkt_ctx) free(pkt_ctx);
}  // End of run_network

// file mode for pcap/yaf files
static void run_file_mode(collector_ctx_t *ctx, const nffile_backend_ctx_t *nffile_backend_ctx, packet_function_t receive_packet, time_t t_win) {
    PacketCtx_t *pkt_ctx = init_packet_ctx(NETWORK_INPUT_BUFF_SIZE);
    if (!pkt_ctx) return;

    for (FlowSource_t *fs = NextFlowSource(ctx); fs; fs = NextFlowSource(NULL)) {
        fs->dataBlock = NewFlowBlock(BLOCK_SIZE_V3);
        if (!fs->dataBlock) {
            LogError("run_file_mode: out of memory allocating data block for ident: %s", fs->Ident);
            free(pkt_ctx);
            return;
        }
        fs->bad_packets = 0;
    }

    uint32_t ignored_packets = 0;
    uint64_t packets = 0;

    int first_packet = 1;  // used to adapt time from pcap file
    time_t now = time(NULL);
    time_t t_start = now - (now % t_win);
    time_t next_rotate = t_start + t_win;

    while (!done) {
        /* Phase 1: Read next record */
        struct timeval tv = {0};

        ssize_t cnt = receive_packet(pkt_ctx->buffer, NETWORK_INPUT_BUFF_SIZE, &pkt_ctx->sender, &pkt_ctx->msg.msg_namelen, &tv);

        if (cnt == -2) { /* EOF */
            done = 1;
            now = tv.tv_sec;
        } else if (cnt < 0) {
            /* malformed or unsupported packet */
            continue;
        } else {
            /* valid packet */
            now = tv.tv_sec;
            if (first_packet) {
                first_packet = 0;
                t_start = now - (now % t_win);
                next_rotate = t_start + t_win;
            }
            process_packet(ctx, nffile_backend_ctx, pkt_ctx, cnt, tv, &packets, &ignored_packets);
        }

        /* Phase 2: Check rotation condition */
        if (now >= next_rotate || done) {
            dbg(char ctime_buf[26]);
            dbg_printf("Periodic cycle - done: %u, for slot: %s\n", done, ctime_r(&t_start, ctime_buf));

            if (!PeriodicCycle(ctx, t_start, done)) {
                LogError("run loop terminated due to serious errors");
                break;
            }

            double interval = (double)t_win;
            if (interval <= 0.0) interval = 1.0;

            LogInfo("Total packets received: %llu avg: %3.2f/s ignored packets: %u", packets, (double)packets / interval, ignored_packets);

            packets = 0;
            ignored_packets = 0;

            if (done) break;

            t_start = next_rotate;
            next_rotate += t_win;
        }
    }

    free(pkt_ctx);
}  // End of run_file_mode

// Close all open receive sockets (safe to call with nsocks == 0 or socks[i] == -1)
static void close_sockets(int *socks, int nsocks) {
    for (int i = 0; i < nsocks; i++)
        if (socks[i] >= 0) { close(socks[i]); socks[i] = -1; }
}  // End of close_sockets

int main(int argc, char **argv) {
    char *bindhost, *launch_process;
    char *userid, *groupid, *mcastgroup;
    char *Ident, *dynFlowDir, *time_extension, *pidfile, *configFile, *metricSocket;
    char *extensionList;
    packet_function_t receive_packet;
    unsigned bufflen, metricInterval;
    time_t twin;
    int numWorkers, sampling_rate, spec_time_extension;
    int socks[2], nsocks, family, do_daemonize, expire, verbose;
    unsigned subdir_index;
    char *pcap_file = NULL;
#ifdef ENABLE_READPCAP
    char *pcap_device = NULL;
#endif

    unsigned srcSpoofing = 0;
    repeater_host_t repeater_host = {0};

    collector_ctx_t collector_ctx = {0};
    stringlist_t sourceList = {0};
    char *dataDir = NULL;

    char *yaf_file = NULL;
    char *listenport = DEFAULTLISTENPORT;
    crypto_ctx_t *crypto_ctx = NULL;
    uint32_t compressType = NOT_COMPRESSED;
    uint32_t compressLevel = LEVEL_0;
    receive_packet = NULL;
    verbose = -1;
    do_daemonize = 0;
    bufflen = 0;
    family = AF_UNSPEC;
    bindhost = NULL;
    mcastgroup = NULL;
    pidfile = NULL;
    launch_process = NULL;
    userid = groupid = NULL;
    twin = TIME_WINDOW;
    subdir_index = 0;
    time_extension = "%Y%m%d%H%M";
    spec_time_extension = 0;
    expire = 0;
    sampling_rate = 1;
    configFile = NULL;
    Ident = "none";
    dynFlowDir = NULL;
    metricSocket = NULL;
    metricInterval = 60;
    extensionList = NULL;
    numWorkers = 0;

    int c;
    while ((c = getopt(argc, argv, "46AB:b:C:d:DeEf:g:hI:i:J:K::l:m:M:n:p:P:R:s:S:t:u:v:VW:w:x:X:Y:z::Z")) != EOF) {
        switch (c) {
            case 'h':
                usage(argv[0]);
                exit(EXIT_SUCCESS);
                break;
            case 'u':
                userid = optarg;
                break;
            case 'g':
                groupid = optarg;
                break;
            case 'C':
                CheckArgLen(optarg, MAXPATHLEN);
                if (strcmp(optarg, NOCONF) == 0) {
                    configFile = optarg;
                } else {
                    if (!CheckPath(optarg, S_IFREG)) exit(EXIT_FAILURE);
                    configFile = optarg;
                }
                break;
            case 'e':
                expire = 1;
                break;
#ifdef ENABLE_READPCAP
            case 'f': {
                if (!CheckPath(optarg, S_IFREG)) exit(EXIT_FAILURE);
                pcap_file = optarg;
            } break;
            case 'd':
                CheckArgLen(optarg, 32);
                pcap_device = strdup(optarg);
                break;
#else
            case 'f':
            case 'd':
                LogError("Reading data from pcap file/device not compiled in!");
                exit(255);
                break;
#endif
            case 'Y':
                if (!CheckPath(optarg, S_IFREG)) exit(EXIT_FAILURE);
                yaf_file = optarg;
                break;
            case 'E':
                verbose = 3;
                printf("Option -E is deprecated. Use -v 3\n");
                break;
            case 'v':
                verbose = ParseVerbose(verbose, optarg);
                if (verbose < 0) {
                    exit(EXIT_FAILURE);
                }
                break;
            case 'V':
                printf("%s: %s\n", argv[0], versionString());
                exit(EXIT_SUCCESS);
                break;
            case 'D':
                do_daemonize = 1;
                break;
            case 'I':
                CheckArgLen(optarg, 128);
                Ident = strdup(optarg);
                break;
            case 'i': {
                int m = atoi(optarg);
                if (m < 10) {
                    LogError("metric interval < 10s not allowed");
                    exit(EXIT_FAILURE);
                }
                metricInterval = (unsigned)m;
                if (metricInterval > twin) {
                    LogInfo("metric interval %u > twin %ld", metricInterval, (long)twin);
                }
            } break;
            case 'm':
                CheckArgLen(optarg, MAXPATHLEN);
                metricSocket = strdup(optarg);
                break;
            case 'M':
                if (!CheckPath(optarg, S_IFDIR)) {
                    LogError("Invalid directory: %s for -M", dynFlowDir);
                    exit(EXIT_FAILURE);
                }
                dynFlowDir = strdup(optarg);
                break;
            case 'n':
                CheckArgLen(optarg, MAXPATHLEN);
                InsertString(&sourceList, optarg);
                break;
            case 'B': {
                CheckArgLen(optarg, 16);
                int b = atoi(optarg);
                if (b <= 0 || b > (1024 * 1024 * 100)) {
                    LogError("Invalid argument %s for -B", optarg);
                    exit(EXIT_FAILURE);
                }
                bufflen = (unsigned)b;
            } break;
            case 'b':
                bindhost = optarg;
                break;
            case 'J':
                mcastgroup = optarg;
                break;
            case 'p':
                CheckArgLen(optarg, 16);
                listenport = optarg;
                break;
            case 'P':
                pidfile = verify_pid(optarg);
                if (!pidfile) {
                    exit(EXIT_FAILURE);
                }
                break;
            case 'R': {
                CheckArgLen(optarg, 128);
                char *hostname = strdup(optarg);
                char *port = DEFAULTLISTENPORT;
                char *p = strchr(hostname, '/');
                if (p) {
                    *p++ = '\0';
                    port = p;
                }
                if (repeater_host.hostname) {
                    LogError("Only one packet repeater is supported");
                    exit(EXIT_FAILURE);
                }
                repeater_host.hostname = hostname;
                repeater_host.port = port;

                break;
            }
            case 'A':
                srcSpoofing = 1;
                if (RunAsRoot() == 0) {
                    LogError("Src IP spoofing requires process to start as root");
                    exit(EXIT_FAILURE);
                }
                break;
            case 's':
                // a negative sampling rate is set as the overwrite sampling rate
                sampling_rate = (int)strtol(optarg, (char **)NULL, 10);
                if ((sampling_rate == 0) || (sampling_rate < 0 && sampling_rate < -10000000) || (sampling_rate > 0 && sampling_rate > 10000000)) {
                    LogError("Invalid sampling rate: %s", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'l':
                LogError("Option -l is deprecated. Use -w");
                exit(EXIT_FAILURE);
                break;
            case 'w':
                if (!CheckPath(optarg, S_IFDIR)) {
                    LogError("No valid directory: %s", optarg);
                    exit(EXIT_FAILURE);
                }
                dataDir = realpath(optarg, NULL);
                if (!dataDir) {
                    LogError("realpath() failed on %s: %s", optarg, strerror(errno));
                    exit(EXIT_FAILURE);
                }
                break;
            case 'S': {
                int s = atoi(optarg);
                if (s < 0) {
                    LogError("Invalid number for subdir index: %s", optarg);
                    exit(EXIT_FAILURE);
                }
                subdir_index = (unsigned)s;
            } break;
            case 't':
                twin = atoi(optarg);
                if (twin < 1) {
                    LogError("time interval <= 1s not allowed");
                    exit(EXIT_FAILURE);
                }
                if (twin < 60) {
                    time_extension = "%Y%m%d%H%M%S";
                }
                break;
            case 'x':
                CheckArgLen(optarg, 256);
                launch_process = strdup(optarg);
                break;
            case 'X':
                CheckArgLen(optarg, 128);
                extensionList = strdup(optarg);
                break;
            case 'W':
                CheckArgLen(optarg, 16);
                numWorkers = atoi(optarg);
                if (numWorkers < 0) {
                    LogError("Invalid number of working threads: %d", numWorkers);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'z':
                if (compressType != NOT_COMPRESSED) {
                    LogError("Only one compression methode is allowed");
                    exit(EXIT_FAILURE);
                }
                if (optarg == NULL) {
                    compressType = LZO_COMPRESSED;
                    LogInfo("Deprecated option -z defaults to -z=lzo. Use -z=lzo, -z=lz4, -z=bz2 or z=zstd for valid compression formats");
                } else {
                    if (!ParseCompression(optarg, &compressType, &compressLevel)) {
                        LogError("Usage for option -z: set -z=lzo, -z=lz4, -z=bz2 or z=zstd for valid compression formats");
                        exit(EXIT_FAILURE);
                    }
                }
                break;
            case 'Z':
                time_extension = "%Y%m%d%H%M%z";
                spec_time_extension = 1;
                break;
            case '4':
                // one or multiple -4 options
                if (family == AF_UNSPEC || family == AF_INET)
                    family = AF_INET;
                else {
                    // in case of -4 -6, use AF_UNSPEC for default dual stack
                    family = AF_UNSPEC;
                }
                break;
            case '6':
                // one or multiple -6 options
                if (family == AF_UNSPEC || family == AF_INET6)
                    family = AF_INET6;
                else {
                    // in case of -4 -6, use AF_UNSPEC for default dual stack
                    family = AF_UNSPEC;
                }
                break;
            case 'K': {
                char *pp = ParsePassphrase(optarg, "Enter encryption passphrase: ");
                if (!pp) exit(EXIT_FAILURE);
                crypto_ctx = NewCryptoCtx(pp);
                memset(pp, 0, strlen(pp));
                free(pp);
                if (!crypto_ctx) {
                    LogError("Failed to initialize encryption context");
                    exit(EXIT_FAILURE);
                }
                break;
            }
            default:
                usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (!InitLog(do_daemonize, argv[0], SYSLOG_FACILITY, verbose)) {
        exit(EXIT_FAILURE);
    }

    if (argc == 1) {
        usage(argv[0]);
        exit(EXIT_SUCCESS);
    }

    if (ConfOpen(configFile, "nfcapd") < 0) exit(EXIT_FAILURE);

    if (init_collector_ctx(&collector_ctx) == 0) {
        exit(EXIT_FAILURE);
    }

    if ((ConfigureDefaultFlowSource(&collector_ctx, Ident, dataDir, subdir_index) == 0) &&
        (ConfigureFixedFlowSource(&collector_ctx, &sourceList, subdir_index) == 0) &&
        (ConfigureDynFlowSource(&collector_ctx, dynFlowDir, subdir_index) == 0)) {
        LogError("Failed to configure a flow source model");
        exit(EXIT_FAILURE);
    }

    if (bindhost && mcastgroup) {
        LogError("ERROR, -b and -j are mutually exclusive!!");
        exit(EXIT_FAILURE);
    }

    numWorkers = GetNumWorkers(numWorkers);
    if (!Init_nffile(numWorkers, NULL)) exit(EXIT_FAILURE);

    if (expire && spec_time_extension) {
        LogError("ERROR, -Z timezone extension breaks expire -e");
        exit(EXIT_FAILURE);
    }

    // Read from yaf file instead of the network
    socks[0] = socks[1] = -1;
    nsocks = 0;
    if (yaf_file) {
        if (!setup_yaf(yaf_file)) exit(EXIT_FAILURE);
        receive_packet = NextYafRecord;
        LogInfo("Reading offline yaffile");
    } else
#ifdef ENABLE_READPCAP
        // Debug code to read from pcap file
        if (pcap_file) {
            printf("Setup pcap file reader\n");
            if (!setup_pcap_offline(pcap_file, NULL)) {
                LogError("Setup pcap offline failed.");
                exit(EXIT_FAILURE);
            }
            receive_packet = NextPacket;
        } else if (pcap_device) {
            printf("Setup pcap device reader\n");
            if (!setup_pcap_live(pcap_device, NULL, bufflen)) {
                LogError("Setup pcap device failed.");
                exit(EXIT_FAILURE);
            }
            receive_packet = NextPacket;
        } else
#endif
        {
            if (mcastgroup) {
                socks[0] = Multicast_receive_socket(mcastgroup, listenport, family, bufflen);
                nsocks = (socks[0] >= 0) ? 1 : 0;
            } else {
                nsocks = Unicast_receive_sockets(bindhost, listenport, family, bufflen, socks);
            }

            if (nsocks <= 0) {
                LogError("Terminated due to errors");
                exit(EXIT_FAILURE);
            }
        }

    if ((pcap_file || yaf_file) && expire) {
        LogError("Disable expire mode when reading from a file");
        expire = 0;
    }

    // before we drop our privileges, check for srcSpoofing and a repeater
    if (nsocks <= 0 && repeater_host.hostname) {
        LogError("Packet repeaters can be used only together with a live network socket");
        exit(EXIT_FAILURE);
    }

    repeater_ctx_t *repeater_ctx = NULL;
    if (srcSpoofing && repeater_host.hostname) {
        if (!RunAsRoot()) {
            LogError("Packet repeater with src spoofing enabled need to run as root");
            exit(EXIT_FAILURE);
        }
        repeater_ctx = RepeaterInit(&repeater_host, REPEATER_QUEUE_CAPACITY, srcSpoofing);
    }
    // drop privileges
    SetPriv(userid, groupid);

    if (srcSpoofing == 0 && repeater_host.hostname) {
        repeater_ctx = RepeaterInit(&repeater_host, REPEATER_QUEUE_CAPACITY, srcSpoofing);
    }

    launcher_ctx_t *launcher_ctx = NULL;
    if (launch_process || expire) {
        launcher_ctx = LauncherInit(launch_process, expire);
    }

    if (!Init_v1(verbose) || !Init_v5_v7(verbose, sampling_rate) || !Init_pcapd(verbose) || !Init_v9(verbose, sampling_rate, extensionList) ||
        !Init_IPFIX(verbose, sampling_rate, extensionList)) {
        close_sockets(socks, nsocks);
        exit(EXIT_FAILURE);
    }

    if (!CheckSubDir(subdir_index)) {
        close_sockets(socks, nsocks);
        exit(EXIT_FAILURE);
    }

    if (do_daemonize) {
        daemonize();
    }

    if (pidfile) {
        pid_t pid = check_pid(pidfile);
        if (pid != 0) {
            LogError("Another process with pid %lu is holding the pidfile: %s", (long unsigned)pid, pidfile);
            close_sockets(socks, nsocks);
            exit(255);
        }
        if (write_pid(pidfile) == 0) exit(EXIT_FAILURE);
    }

    if (metricSocket && !OpenMetric(metricSocket, metricInterval)) {
        close_sockets(socks, nsocks);
        remove_pid(pidfile);
        exit(EXIT_FAILURE);
    }

    const nffile_backend_ctx_t nffile_backend_ctx = {.creator = CREATOR_NFCAPD,
                                                     .compressType = compressType,
                                                     .compressLevel = compressLevel,
                                                     .crypto_ctx = crypto_ctx,
                                                     .subdir = subdir_index,
                                                     .time_extension = time_extension,
                                                     .msgQueue = launcher_ctx ? launcher_ctx->msgQueue : NULL};

    if (InitBackend(&collector_ctx, &nffile_backend_ctx) == 0) {
        LogError("Failed to initialized nffile backend");
        close_sockets(socks, nsocks);
        CloseMetric();
        remove_pid(pidfile);
        exit(EXIT_FAILURE);
    }

    if (!LaunchBackend(&collector_ctx)) {
        close_sockets(socks, nsocks);
        CloseMetric();
        remove_pid(pidfile);
        exit(EXIT_FAILURE);
    }

    pthread_t repeater_tid = 0;
    if (repeater_ctx && (repeater_tid = RepeaterStart(repeater_ctx)) == 0) {
        CloseMetric();
        close_sockets(socks, nsocks);
        remove_pid(pidfile);
        exit(EXIT_FAILURE);
    }

    pthread_t launcher_tid = 0;
    if (launcher_ctx && (launcher_tid = LauncherStart(launcher_ctx)) == 0) {
        RepeaterShutdown(repeater_ctx);
        CloseMetric();
        close_sockets(socks, nsocks);
        remove_pid(pidfile);
        exit(EXIT_FAILURE);
    }

    /* Signal handling */
    struct sigaction act;
    memset((void *)&act, 0, sizeof(struct sigaction));
    act.sa_handler = IntHandler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGHUP, &act, NULL);

    if (nsocks <= 0 && receive_packet == NULL) {
        LogError("No packet source defined");
        CloseMetric();
        remove_pid(pidfile);
        exit(EXIT_FAILURE);
    }

    LogInfo("Startup nfcapd.");
    if (nsocks > 0) {
        run_network(&collector_ctx, &nffile_backend_ctx, repeater_ctx, socks, nsocks, twin);
        close_sockets(socks, nsocks);
    } else {
        run_file_mode(&collector_ctx, &nffile_backend_ctx, receive_packet, twin);
    }

    // shutdown
    CloseBackend(&collector_ctx, expire);
    CloseMetric();

    if (repeater_tid) RepeaterShutdown(repeater_ctx);
    if (launcher_tid) LauncherShutdown(launcher_ctx);

    CleanupCollector(&collector_ctx);

    LogInfo("Terminating nfcapd.");
    remove_pid(pidfile);
    FreeCryptoCtx(crypto_ctx);

    EndLog();
    return 0;

}  // End of main