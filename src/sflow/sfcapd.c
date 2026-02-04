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
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
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

#include "barrier.h"
#include "bookkeeper.h"
#include "collector.h"
#include "conf/nfconf.h"
#include "daemon.h"
#include "expire.h"
#include "flist.h"
#include "flowsource.h"
#include "ip128.h"
#include "launch.h"
#include "metric.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfnet.h"
#include "nfstatfile.h"
#include "nfxV3.h"
#include "pidfile.h"
#include "privsep.h"
#include "repeater.h"
#include "sflow_nfdump.h"
#include "util.h"
#include "version.h"

#define DEFAULTSFLOWPORT "6343"

static int verbose = 0;

// Define a generic type to get data from socket or pcap file
typedef ssize_t (*packet_function_t)(int, void *, size_t, int, struct sockaddr *, socklen_t *);

static option_t sfcapdConfig[] = {
    {.name = "tun", .valBool = 0, .flags = OPTDEFAULT}, {.name = "maxworkers", .valUint64 = 2, .flags = OPTDEFAULT}, {.name = NULL}};

/* module limited globals */
static int done = 0;
static int periodic_trigger;
static int gotSIGCHLD = 0;

/* Local function Prototypes */
static void usage(char *name);

static void signalPrivsepChild(pid_t child_pid, int pfd);

static void IntHandler(int signal);

static void run(collector_ctx_t *ctx, packet_function_t receive_packet, int socket, post_args_t *post_args, int rfd, time_t twin, time_t t_begin,
                unsigned compress, int parse_tun);

/* Functions */
static void usage(char *name) {
    printf(
        "usage %s [options] \n"
        "-h\t\tthis text you see right here\n"
        "-u userid\tChange user to username\n"
        "-g groupid\tChange group to groupname\n"
        "-t interval\tset the interval to rotate sfcapd files\n"
        "-b host\t\tbind socket to host/IP addr\n"
        "-J mcastgroup\tJoin multicast group <mcastgroup>\n"
        "-p portnum\tlisten on port portnum\n"
#ifdef ENABLE_READPCAP
        "-f pcapfile\tRead network data from pcap file.\n"
        "-d device\tRead network data from device (interface).\n"
#endif
        "-w flowdir \tset the output directory to store the flows.\n"
        "-C <file>\tRead optional config file.\n"
        "-S subdir\tSub directory format. see nfcapd(1) for format\n"
        "-I Ident\tset the ident string for stat file. (default 'none')\n"
        "-n Ident,IP,flowdir\tAdd this flow source - multiple streams\n"
        "-i interval\tMetric interval in s for metric exporter\n"
        "-m socket\t\tEnable metric exporter on socket.\n"
        "-M dir \t\tSet the output directory for dynamic sources.\n"
        "-o options \tAdd sfcpad options, separated with ','. Available: 'tun'\n"
        "-P pidfile\tset the PID file\n"
        "-R IP[/port]\tRepeat incoming packets to IP address/port. Max 8 repeaters.\n"
        "-A\t\tEnable source address spoofing for packet repeater -R.\n"
        "-x process\tlaunch process after a new file becomes available\n"
        "-W workers\toptionally set the number of workers to compress flows\n"
        "-z=lzo\t\tLZO compress flows in output file.\n"
        "-z=bz2\t\tBZIP2 compress flows in output file.\n"
        "-z=lz4[:level]\tLZ4 compress flows in output file.\n"
        "-z=zstd[:level]\tZSTD compress flows in output file.\n"
        "-B bufflen\tSet socket buffer to bufflen bytes\n"
        "-e\t\tExpire data at each cycle.\n"
        "-D\t\tFork to background\n"
        "-E\t\tPrint extended format of sflow data. For debugging purpose only.\n"
        "-v\t\tIncrease verbose level.\n"
        "-4\t\tListen on IPv4 only.\n"
        "-6\t\tListen on IPv6 only\n"
        "-X <extlist>\t',' separated list of extensions (numbers). Default all extensions.\n"
        "-V\t\tPrint version and exit.\n"
        "-Z\t\tAdd timezone offset to filename.\n",
        name);
}  // End of usage

static void signalPrivsepChild(pid_t child_pid, int pfd) {
    if (pfd == 0) return;

    message_t message;
    message.type = PRIVMSG_EXIT;
    message.length = sizeof(message);
    ssize_t ret = write(pfd, &message, sizeof(message));

    if (ret < 0) {
        LogError("Failed to send exit message for privsep child. pipe write: %s", strerror(errno));
        kill(child_pid, SIGTERM);
    }

    int stat = 0;
    if ((ret = waitpid(child_pid, &stat, 0)) == -1) {
        if (!gotSIGCHLD) LogError("wait for privsep child failed: %s", strerror(errno));
    } else {
        if (WIFEXITED(stat)) {
            LogInfo("privsep child exit status: %i", WEXITSTATUS(stat));
        }
        if (WIFSIGNALED(stat)) {
            LogError("privsep child terminated due to signal %i", WTERMSIG(stat));
        }
        LogVerbose("privsep child terminated with status: 0x%x", stat);
    }

}  // End of signalPrivsepChild

static void IntHandler(int signal) {
    switch (signal) {
        case SIGALRM:
            periodic_trigger = 1;
            break;
        case SIGHUP:
        case SIGINT:
        case SIGTERM:
            done = 1;
            break;
        case SIGCHLD:
            gotSIGCHLD++;
            break;
        case SIGPIPE:
            break;
        default:
            // ignore everything we don't know
            break;
    }

} /* End of IntHandler */

static void ChildDied(void) {
    if (gotSIGCHLD) {
        int stat = 0;
        pid_t pid = waitpid(-1, &stat, 0);
        if (pid == -1) {
            if (!gotSIGCHLD) LogError("wait for privsep child failed: %s", strerror(errno));
        } else {
            if (WIFEXITED(stat)) {
                LogInfo("privsep child[%u] exit status: %i", pid, WEXITSTATUS(stat));
            }
            if (WIFSIGNALED(stat)) {
                LogError("privsep child[%u] terminated due to signal %i", pid, WTERMSIG(stat));
            }
            LogError("privsep child[%u] terminated with status: pid, 0x%x", pid, stat);
        }
        gotSIGCHLD--;
    }

}  // End of ChildDied

#include "nffile_inline.c"

static int SendRepeaterMessage(int fd, void *in_buff, size_t cnt, struct sockaddr_storage *sender, socklen_t sender_size) {
    message_t message;
    message.type = PRIVMSG_REPEAT;
    message.length = cnt + sizeof(message_t);

    repeater_message_t repeater_message;
    repeater_message.packet_size = cnt;
    repeater_message.storage_size = sender_size;
    repeater_message.addr = *sender;

    struct iovec vector[3];
    size_t len;
    vector[0].iov_base = &message;
    vector[0].iov_len = sizeof(message_t);
    len = sizeof(message_t);

    vector[1].iov_base = &repeater_message;
    vector[1].iov_len = sizeof(repeater_message_t);
    len += sizeof(repeater_message_t);

    vector[2].iov_base = in_buff;
    vector[2].iov_len = cnt;
    len += cnt;

    message.length = len;
    ssize_t ret = writev(fd, vector, 3);
    if (ret < 0) {
        LogError("Failed to send repeater message: %s", strerror(errno));
        return errno;
    } else {
        dbg_printf("Sent message to repeater: %u\n", message.length);
    }
    return 0;
}  // End of SendRepeaterMessage

static void run(collector_ctx_t *ctx, packet_function_t receive_packet, int socket, post_args_t *post_args, int rfd, time_t twin, time_t t_begin,
                unsigned compress, int parse_tun) {
    struct sockaddr_storage sf_sender;
    socklen_t sf_sender_size = sizeof(sf_sender);

    void *in_buff = malloc(NETWORK_INPUT_BUFF_SIZE);
    if (!in_buff) {
        LogError("malloc() allocation error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return;
    }

    // Init each netflow source output data buffer
    for (FlowSource_t *fs = NextFlowSource(ctx); fs != NULL; fs = NextFlowSource(NULL)) {
        // prepare file
        fs->nffile = OpenNewFile(SetUniqueTmpName(fs->tmpFileName), CREATOR_SFCAPD, compress, NOT_ENCRYPTED);
        fs->swap_nffile = OpenNewFile(SetUniqueTmpName(fs->tmpFileName), CREATOR_SFCAPD, compress, NOT_ENCRYPTED);
        if (!fs->nffile || !fs->swap_nffile) {
            return;
        }
        SetIdent(fs->nffile, fs->Ident);
        SetIdent(fs->swap_nffile, fs->Ident);

        // init flow source
        fs->dataBlock = WriteBlock(fs->nffile, NULL);
        fs->bad_packets = 0;
    }

    time_t t_start = t_begin;

    periodic_trigger = 0;
    ssize_t cnt = 0;
    uint32_t ignored_packets = 0;
    uint64_t packets = 0;

    // wake up at next time slot (twin) for precise rotation
    alarm(t_start + twin - time(NULL));
    /*
     * Main processing loop:
     * this loop, continues until  = 1, set by the signal handler
     * The while loop will be broken by the periodic file renaming code
     * for proper cleanup
     */
    while (1) {
        struct timeval tv;
        char sa_address[INET6_ADDRSTRLEN];

        /* read next bunch of data into begin of input buffer */
        if (!done) {
            // Debug code to read from pcap file, or from socket
            cnt = receive_packet(socket, in_buff, NETWORK_INPUT_BUFF_SIZE, 0, (struct sockaddr *)&sf_sender, &sf_sender_size);

            dbg_printf("Received packet from: %s, size: %zd\n", GetClientIPstring(&sf_sender, sa_address), cnt);

            // in case of reading from file EOF => -2
            if (cnt == -2) done = 1;
            if (cnt == 0) {
                ignored_packets++;
                packets++;
                continue;
            }

            if (cnt == -1) {
                if (errno != EINTR) {
                    LogError("recvfrom() error in '%s', line '%d', cnt: %d:, %s", __FILE__, __LINE__, cnt, strerror(errno));
                    continue;
                }
            } else {
                packets++;
            }
        }

        /* Periodic file renaming, if time limit reached or if we are done.  */
        gettimeofday(&tv, NULL);
        time_t t_now = tv.tv_sec;

        if (((t_now - t_start) >= twin) || done) {
            // rotate cycle
            alarm(0);

            if (RotateCycle(ctx, post_args, t_start, done) != 0) {
                LogError("run loop terminated due to serious errors");
                break;
            }

            LogInfo("Total packets received: %llu avg: %3.2f ignored packets: %u", packets, (double)packets / (double)twin, ignored_packets);
            packets = ignored_packets = 0;
            periodic_trigger = 0;

            if (done) break;

            /*
             * update alarm for next cycle
             * t_start = filename time stamp: begin of slot
             * + twin = end of next time interval
             * - t_now = difference value to now
             */
            t_start += twin;
            alarm(t_start + twin - t_now);
        }

        /* check for EINTR and continue */
        if (cnt < 0) {
            // Check if a child could have died
            ChildDied();
            continue;
        }

        // repeat this packet
        if (rfd) {
            if (SendRepeaterMessage(rfd, in_buff, (size_t)cnt, &sf_sender, sf_sender_size) != 0) {
                LogError("Disable packet repeater due to errors");
                close(rfd);
                rfd = 0;
            }
        }

        // get flow source record for current packet, identified by sender IP address
        FlowSource_t *fs = GetFlowSource(ctx, &sf_sender);
        if (fs == NULL) {
            // check, if we have dynamic flowsources configured
            fs = NewDynFlowSource(ctx, &sf_sender);
            if (fs == NULL) {
                ignored_packets++;
                LogError("Skip UDP packet from: %s. Ignored packets: %u", GetClientIPstring(&sf_sender, sa_address), ignored_packets);
                continue;
            }

            // setup new dynamic source
            if (InitBookkeeper(&fs->bookkeeper, fs->datadir, getpid()) != BOOKKEEPER_OK) {
                LogError("Failed to initialise bookkeeper for new source");
                // fatal error
                return;
            }
            fs->nffile = OpenNewFile(SetUniqueTmpName(fs->tmpFileName), CREATOR_SFCAPD, compress, NOT_ENCRYPTED);
            if (!fs->nffile) {
                LogError("Failed to open new collector file");
                return;
            }
            fs->dataBlock = WriteBlock(fs->nffile, NULL);
            SetIdent(fs->nffile, fs->Ident);
        }

        /* check for too little data - cnt must be > 0 at this point */
        if (cnt < (ssize_t)sizeof(common_flow_header_t)) {
            LogError("Ident: %s, Data length error: too little data for common netflow header. cnt: %i", fs->Ident, (int)cnt);
            fs->bad_packets++;
            continue;
        }

        fs->received = tv;
        /* Process data - have a look at the common header */
        Process_sflow(in_buff, cnt, fs, parse_tun);

        // each Process_xx function has to process the entire input buffer, therefore it's empty
        // now.
    }

    free(in_buff);

    CleanupCollector(ctx, post_args);

} /* End of run */

int main(int argc, char **argv) {
    char *bindhost, *launch_process;
    char *userid, *groupid, *listenport, *mcastgroup;
    char *Ident, *dynFlowDir, *time_extension, *pidfile, *configFile, *metricSocket;
    char *extensionList, *options;
    packet_function_t receive_packet;
    repeater_t repeater[MAX_REPEATERS];
    unsigned bufflen, metricInterval;
    time_t twin;
    int sock, family, do_daemonize, expire, spec_time_extension;
    bool parse_tun;
    unsigned subdir_index, compress, srcSpoofing;
    int numWorkers;
#ifdef ENABLE_READPCAP
    char *pcap_file = NULL;
    char *pcap_device = NULL;
#endif

    collector_ctx_t collector_ctx = {0};
    stringlist_t sourceList = {0};
    char *dataDir = NULL;

    receive_packet = recvfrom;
    verbose = do_daemonize = 0;
    bufflen = 0;
    family = AF_UNSPEC;
    listenport = DEFAULTSFLOWPORT;
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
    compress = NOT_COMPRESSED;
    memset((void *)&repeater, 0, sizeof(repeater));
    srcSpoofing = 0;
    configFile = NULL;
    Ident = "none";
    dynFlowDir = NULL;
    metricSocket = NULL;
    metricInterval = 60;
    extensionList = NULL;
    options = NULL;
    numWorkers = 0;
    parse_tun = false;

    int c;
    while ((c = getopt(argc, argv, "46AB:b:C:d:DeEf:g:hI:i:jJ:l:m:M:n:o:p:P:R:S:T:t:u:vVW:w:x:X:yz::Z:")) != EOF) {
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
                struct stat fstat;
                pcap_file = optarg;
                stat(pcap_file, &fstat);
                if (!S_ISREG(fstat.st_mode)) {
                    LogError("Not a regular file: %s", pcap_file);
                    exit(254);
                }
            } break;
            case 'd':
                CheckArgLen(optarg, 32);
                pcap_device = strdup(optarg);
                break;
#else
            case 'f':
            case 'd':
                LogError("Reading data from pcap file/device not compiled! Option ignored!");
                break;
#endif
            case 'E':
                verbose = 3;
                break;
            case 'v':
                if (verbose < 4) verbose++;
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
                CheckArgLen(optarg, MAXPATHLEN);
                dynFlowDir = strdup(optarg);
                if (!CheckPath(dynFlowDir, S_IFDIR)) {
                    LogError("Invalid directory: %s for -M", dynFlowDir);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'n':
                CheckArgLen(optarg, MAXPATHLEN);
                InsertString(&sourceList, optarg);
                break;
            case 'B': {
                char *checkptr = NULL;
                bufflen = strtol(optarg, &checkptr, 10);
                if ((checkptr != NULL && *checkptr == 0) && bufflen > 0) break;
                LogError("Argument error for -B");
                exit(EXIT_FAILURE);
            } break;
            case 'b':
                bindhost = optarg;
                break;
            case 'J':
                mcastgroup = optarg;
                break;
            case 'o':
                if (strlen(optarg) > 64) {
                    LogError("ERROR:, option string size error");
                    exit(EXIT_FAILURE);
                }
                options = strdup(optarg);
                break;
            case 'p':
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
                char *port = DEFAULTSFLOWPORT;
                char *p = strchr(hostname, '/');
                if (p) {
                    *p++ = '\0';
                    port = p;
                }
                int i = 0;
                while (repeater[i].hostname && (i < MAX_REPEATERS)) i++;
                if (i == MAX_REPEATERS) {
                    LogError("Too many packet repeaters! Max: %i repeaters allowed", MAX_REPEATERS);
                    exit(EXIT_FAILURE);
                }
                repeater[i].hostname = hostname;
                repeater[i].port = port;

                break;
            }
            case 'A':
                srcSpoofing = 1;
                if (RunAsRoot() == 0) {
                    LogError("Src IP spoofing requires process to start as root");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'l':
                LogError("-l is a legacy option and may get removed in future. Please use -w to set output directory");
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
            case 'T':
                printf("Option -T no longer supported and ignored\n");
                break;
            case 't':
                twin = atoi(optarg);
                if (twin < 1) {
                    LogError("time interval < 1s not allowed");
                    exit(EXIT_FAILURE);
                }
                if (twin < 60) {
                    time_extension = "%Y%m%d%H%M%S";
                }
                break;
            case 'x':
                CheckArgLen(optarg, 256);
                launch_process = optarg;
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
            case 'Z':
                time_extension = "%Y%m%d%H%M%z";
                spec_time_extension = 1;
                break;
            case '4':
                if (family == AF_UNSPEC)
                    family = AF_INET;
                else {
                    LogError("ERROR, Accepts only one protocol IPv4 or IPv6!");
                    exit(EXIT_FAILURE);
                }
                break;
            case '6':
                if (family == AF_UNSPEC)
                    family = AF_INET6;
                else {
                    LogError("ERROR, Accepts only one protocol IPv4 or IPv6!");
                    exit(EXIT_FAILURE);
                }
                break;
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

    if ((argc - optind) >= 2) {
        if (strcmp(argv[optind], "privsep") == 0) {
            if (strcmp(argv[optind + 1], "launcher") == 0) {
                dbg_printf("sfcapd privsep launched\n");
                int ret = StartupLauncher(launch_process, expire);
                exit(ret);
            } else if (strcmp(argv[optind + 1], "repeater") == 0) {
                dbg_printf("sfcapd repeater launched\n");
                int ret = StartupRepeater(repeater, bufflen, srcSpoofing, userid, groupid);
                exit(ret);
            } else {
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
        } else {
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (ConfOpen(configFile, "sfcapd") < 0) exit(EXIT_FAILURE);

    if (init_collector_ctx(&collector_ctx) == 0) {
        exit(EXIT_FAILURE);
    }

    if (scanOptions(sfcapdConfig, options) == 0) {
        exit(EXIT_FAILURE);
    }
    OptGetBool(sfcapdConfig, "tun", &parse_tun);

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
    if (!Init_nffile(numWorkers, NULL)) exit(254);

    if (expire && spec_time_extension) {
        LogError("ERROR, -Z timezone extension breaks expire -e");
        exit(EXIT_FAILURE);
    }

    post_args_t *post_args = malloc(sizeof(post_args_t));
    if (post_args == NULL) {
        LogError("malloc() allocation error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        exit(EXIT_FAILURE);
    }

// Debug code to read from pcap file
#ifdef ENABLE_READPCAP
    sock = 0;
    if (pcap_file) {
        printf("Setup pcap reader\n");
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
        if (mcastgroup)
        sock = Multicast_receive_socket(mcastgroup, listenport, family, bufflen);
    else
        sock = Unicast_receive_socket(bindhost, listenport, family, bufflen);

    if (sock == -1) {
        LogError("Terminated due to errors");
        exit(EXIT_FAILURE);
    }

    pid_t repeater_pid = 0;
    int rfd = 0;
    if (repeater[0].hostname) {
        rfd = PrivsepFork(argc, argv, &repeater_pid, "repeater");
    }

    SetPriv(userid, groupid);

    if (!Init_sflow(verbose, extensionList)) {
        LogError("Init_sflow() failed");
        exit(EXIT_FAILURE);
    }

    if (!CheckSubDir(subdir_index)) {
        close(sock);
        exit(EXIT_FAILURE);
    }

    time_t t_start = time(NULL);
    t_start = t_start - (t_start % twin);

    if (do_daemonize) {
        verbose = 0;
        daemonize();
    }

    if (pidfile) {
        if (check_pid(pidfile) != 0 || write_pid(pidfile) == 0) exit(EXIT_FAILURE);
    }

    if (metricSocket && !OpenMetric(metricSocket, metricInterval)) {
        close(sock);
        exit(EXIT_FAILURE);
    }

    int launcher_pid = 0;
    int pfd = 0;
    if (launch_process || expire) {
        pfd = PrivsepFork(argc, argv, &launcher_pid, "launcher");
    }

    *post_args = (post_args_t){
        .ctx = &collector_ctx,
        .pfd = pfd,
        .time_extension = time_extension,
        .done = 0,
        .creator = CREATOR_SFCAPD,
        .compress = compress,
        .encryption = NOT_ENCRYPTED,
    };

    if (Lauch_postprocessor(post_args) == 0) {
        close(sock);
        remove_pid(pidfile);
        exit(EXIT_FAILURE);
    }

    int failed = 0;
    for (FlowSource_t *fs = NextFlowSource(&collector_ctx); fs != NULL; fs = NextFlowSource(NULL)) {
        if (InitBookkeeper(&fs->bookkeeper, fs->datadir, getpid()) != BOOKKEEPER_OK) {
            failed = 1;
            LogError("initialize bookkeeper failed");
            break;
        }
        fs->subdir = subdir_index;
    }

    if (failed) {
        // release all already allocated bookkeepers
        for (FlowSource_t *fs = NextFlowSource(&collector_ctx); fs != NULL; fs = NextFlowSource(NULL)) {
            if (fs->bookkeeper) ReleaseBookkeeper(fs->bookkeeper, DESTROY_BOOKKEEPER);
        }
        close(sock);
        signalPrivsepChild(launcher_pid, pfd);
        signalPrivsepChild(repeater_pid, rfd);
        if (pidfile) remove_pid(pidfile);
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
    sigaction(SIGALRM, &act, NULL);
    sigaction(SIGCHLD, &act, NULL);
    sigaction(SIGPIPE, &act, NULL);

    LogInfo("Startup sfcapd.");
    run(&collector_ctx, receive_packet, sock, post_args, rfd, twin, t_start, compress, parse_tun);

    // shutdown
    close(sock);
    signalPrivsepChild(launcher_pid, pfd);
    signalPrivsepChild(repeater_pid, rfd);
    CloseMetric();

    for (FlowSource_t *fs = NextFlowSource(&collector_ctx); fs != NULL; fs = NextFlowSource(NULL)) {
        dirstat_t *dirstat;
        // if we do not auto expire and there is a stat file, update the stats before we leave
        if (expire == 0 && ReadStatInfo(fs->datadir, &dirstat, LOCK_IF_EXISTS) == STATFILE_OK) {
            UpdateDirStat(dirstat, fs->bookkeeper);
            WriteStatInfo(dirstat);
            LogVerbose("Updating statinfo in directory '%s'", fs->datadir);
        }

        ReleaseBookkeeper(fs->bookkeeper, DESTROY_BOOKKEEPER);
    }

    LogInfo("Terminating sfcapd.");
    if (pidfile) remove_pid(pidfile);

    EndLog();
    return 0;

} /* End of main */
