/*
 *  Copyright (c) 2013-2022, Peter Haag
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
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <pthread.h>
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
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "bookkeeper.h"
#include "collector.h"
#include "config.h"
#include "daemon.h"
#include "expire.h"
#include "exporter.h"
#include "flist.h"
#include "flowdump.h"
#include "flowsend.h"
#include "flowtree.h"
#include "metric.h"
#include "nfconf.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfnet.h"
#include "nfstatfile.h"
#include "pcapdump.h"
#include "pcaproc.h"
#include "pidfile.h"
#include "repeater.h"
#include "util.h"

#define TIME_WINDOW 300
#define PROMISC 1
#define TIMEOUT 500
#define FILTER "ip"
#define TO_MS 100

static int verbose = 0;
static int done = 0;
/*
 * global static var: used by interrupt routine
 */
#define PCAP_DUMPFILE "pcap.current"

static const char *nfdump_version = VERSION;

static int launcher_pid;
static pthread_mutex_t m_done = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t terminate = PTHREAD_COND_INITIALIZER;

uint32_t linktype;
uint32_t linkoffset;

/*
 * Function prototypes
 */
static void usage(char *name);

static void Interrupt_handler(int sig);

static int setup_pcap_file(packetParam_t *param, char *pcap_file, char *filter, int snaplen);

static void WaitDone(void);

static int scanOptions(flowParam_t *flowParam, char *options);

/*
 * Functions
 */

static void usage(char *name) {
    printf(
        "usage %s [options] [\"pcap filter\"]\n"
        "-h\t\tthis text you see right here\n"
        "-u userid\tChange user to username\n"
        "-g groupid\tChange group to groupname\n"
        "-i interface\tread packets from interface\n"
        "-r pcapfile\tread packets from file\n"
        "-b num\tset socket buffer size in MB. (default 20MB)\n"
        "-B num\tset the node cache size. (default 524288)\n"
        "-s snaplen\tset the snapshot length - default 1522\n"
        "-e active,inactive\tset the active,inactive flow expire time (s) - default 300,60\n"
        "-o options \tAdd flow options, separated with ','. Available: 'fat', 'payload'\n"
        "-w flowdir \tset the flow output directory. (no default) \n"
        "-C <file>\tRead optional config file.\n"
        "-H host[/port]\tSend flows to host or IP address/port. Default port 9995.\n"
        "-m socket\t\tEnable metric exporter on socket.\n"
        "-p pcapdir \tset the pcapdir directory. (optional) \n"
        "-S subdir\tSub directory format. see nfcapd(1) for format\n"
        "-I Ident\tset the ident string for stat file. (default 'none')\n"
        "-P pidfile\tset the PID file\n"
        "-t time frame\tset the time window to rotate pcap/nfcapd file\n"
        "-z\t\tLZO compress flows in output file.\n"
        "-y\t\tLZ4 compress flows in output file.\n"
        "-j\t\tBZ2 compress flows in output file.\n"
        "-v\t\tverbose logging.\n"
        "-D\t\tdetach from terminal (daemonize)\n",
        name);
}  // End of usage

static void Interrupt_handler(int sig) {
#ifdef DEVEL
    pthread_t tid = pthread_self();

    printf("[%lu] Interrupt handler. Signal %d\n", (long unsigned)tid, sig);
#endif
    done = 1;

}  // End of signal_handler

static int setup_pcap_file(packetParam_t *param, char *pcap_file, char *filter, int snaplen) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */

    dbg_printf("Enter function: %s\n", __FUNCTION__);

    errbuf[0] = '\0';
    handle = pcap_open_offline(pcap_file, errbuf);
    if (handle == NULL) {
        LogError("pcap_open_offline() failed: %s", errbuf);
        return -1;
    }

    if (filter) {
        struct bpf_program filter_code;
        bpf_u_int32 netmask = 0;
        // Compile and apply the filter
        if (pcap_compile(handle, &filter_code, filter, 0, netmask) == -1) {
            LogError("Couldn't parse filter %s: %s", filter, pcap_geterr(handle));
            return -1;
        }
        if (pcap_setfilter(handle, &filter_code) == -1) {
            LogError("Couldn't install filter %s: %s", filter, pcap_geterr(handle));
            return -1;
        }
    }

    linkoffset = 0;
    linktype = pcap_datalink(handle);
    switch (linktype) {
        case DLT_RAW:
            linkoffset = 0;
            break;
        case DLT_PPP:
            linkoffset = 2;
            break;
        case DLT_PPP_SERIAL:
            linkoffset = 4;
            break;
        case DLT_NULL:
            linkoffset = 4;
            break;
        case DLT_LOOP:
            linkoffset = 14;
            break;
        case DLT_EN10MB:
            linkoffset = 14;
            break;
        case DLT_LINUX_SLL:
            linkoffset = 16;
            break;
        case DLT_IEEE802_11:
            linkoffset = 22;
            break;
        case DLT_NFLOG:
            linkoffset = 0;
            break;
        case DLT_PFLOG:
            linkoffset = 0;
            break;
        default:
            LogError("Unsupported data link type %i", linktype);
            return -1;
    }

    param->pcap_dev = handle;
    param->linkoffset = linkoffset;
    param->snaplen = snaplen;
    param->linktype = linktype;

    return 0;

}  // End of setup_pcap_file

static void WaitDone(void) {
    sigset_t signal_set;
    int done, sig;
#ifdef DEVEL
    pthread_t tid = pthread_self();
    printf("[%lu] WaitDone() waiting\n", (long unsigned)tid);
#endif

    sigemptyset(&signal_set);
    sigaddset(&signal_set, SIGINT);
    sigaddset(&signal_set, SIGHUP);
    sigaddset(&signal_set, SIGTERM);
    sigaddset(&signal_set, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &signal_set, NULL);

    done = 0;
    while (!done) {
        sigwait(&signal_set, &sig);
        dbg_printf("[%lu] WaitDone() signal %i\n", (long unsigned)tid, sig);
        switch (sig) {
            case SIGHUP:
                break;
            case SIGINT:
            case SIGTERM:
                pthread_mutex_lock(&m_done);
                done = 1;
                pthread_mutex_unlock(&m_done);
                pthread_cond_signal(&terminate);
                break;
            case SIGUSR1:
                // child signals end of job
                done = 1;
                break;
                // default:
                // empty
        }
    }

}  // End of WaitDone

static int scanOptions(flowParam_t *flowParam, char *options) {
    char *option = strtok(options, ",");
    while (option != NULL) {
        if (strncasecmp(option, "fat", 4) == 0) {
            flowParam->extendedFlow = 1;
            dbg_printf("Found extended flow option\n");
        } else if (strncasecmp(option, "payload", 8) == 0) {
            flowParam->addPayload = 1;
            dbg_printf("Found payload option\n");
        } else {
            LogError("Unknown option: %s", option);
            return -1;
        }
        option = strtok(NULL, ",");
    }

    return 0;

}  // End of scanOption

int main(int argc, char *argv[]) {
    sigset_t signal_set;
    struct sigaction sa;
    int c, snaplen, bufflen, err, do_daemonize;
    int subdir_index, compress, expire, cache_size, buff_size;
    int activeTimeout, inactiveTimeout, metricInterval;
    dirstat_t *dirstat;
    repeater_t *sendHost;
    time_t t_win;
    char *device, *pcapfile, *filter, *datadir, *pcap_datadir, *pidfile, *configFile, *options;
    char *Ident, *userid, *groupid, *metricsocket;
    char *time_extension;

    snaplen = 1522;
    bufflen = 0;
    do_daemonize = 0;
    launcher_pid = 0;
    device = NULL;
    pcapfile = NULL;
    filter = FILTER;
    pidfile = NULL;
    t_win = TIME_WINDOW;
    datadir = NULL;
    pcap_datadir = NULL;
    options = NULL;
    sendHost = NULL;
    metricsocket = NULL;
    metricInterval = 60;
    userid = groupid = NULL;
    configFile = NULL;
    Ident = "none";
    time_extension = "%Y%m%d%H%M";
    subdir_index = 0;
    compress = NOT_COMPRESSED;
    verbose = 0;
    expire = 0;
    cache_size = 0;
    buff_size = 20;
    activeTimeout = 0;
    inactiveTimeout = 0;
    while ((c = getopt(argc, argv, "b:B:C:De:g:hH:I:i:j:l:m:o:p:P:r:s:S:T:t:u:vVw:yz")) != EOF) {
        switch (c) {
            struct stat fstat;
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
                if (strcmp(optarg, "null") == 0) {
                    configFile = optarg;
                } else {
                    if (!CheckPath(optarg, S_IFREG)) exit(EXIT_FAILURE);
                    configFile = optarg;
                }
                break;
            case 'D':
                do_daemonize = 1;
                break;
            case 'B':
                cache_size = atoi(optarg);
                if (cache_size <= 0) {
                    LogError("ERROR: Cache size must not be < 0");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'I':
                if (strlen(optarg) < 128) {
                    Ident = strdup(optarg);
                } else {
                    LogError("ERROR: Ident length > 128");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'm':
                if (strlen(optarg) > MAXPATHLEN) {
                    LogError("ERROR: Path too long!");
                    exit(EXIT_FAILURE);
                }
                metricsocket = strdup(optarg);
                break;
            case 'b':
                buff_size = atoi(optarg);
                if (buff_size <= 0 || buff_size > 2047) {
                    LogError("ERROR: Buffer size in MB must be betwee 0..2047 (2GB max)");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'H': {
                if (sendHost) {
                    LogError("ERROR: Host to send flows already defined.");
                    exit(EXIT_FAILURE);
                }
                if (strlen(optarg) > 255) {
                    LogError("ERROR: Argument size error.");
                    exit(EXIT_FAILURE);
                }
                sendHost = calloc(1, sizeof(repeater_t));
                char *port;
                char *sep = strchr(optarg, '/');
                if (sep) {
                    *sep = '\0';
                    port = sep + 1;
                } else {
                    port = "9995";
                }
                sendHost->family = AF_UNSPEC;
                sendHost->hostname = strdup(optarg);
                sendHost->port = strdup(port);
            } break;
            case 'i':
                device = optarg;
                break;
            case 'l':
                LogError("-l is a legacy option and may get removed in future. Please use -w to set output directory");
            case 'w':
                datadir = optarg;
                err = stat(datadir, &fstat);
                if (!(fstat.st_mode & S_IFDIR)) {
                    LogError("No valid directory: '%s'", datadir);
                    break;
                }
                break;
            case 'o':
                if (strlen(optarg) > 64) {
                    LogError("ERROR:, option string size error");
                    exit(EXIT_FAILURE);
                }
                options = strdup(optarg);
                break;
            case 'p':
                pcap_datadir = optarg;
                err = stat(pcap_datadir, &fstat);
                if (!(fstat.st_mode & S_IFDIR)) {
                    LogError(
                        "No such directory: "
                        "'%s'",
                        pcap_datadir);
                    break;
                }
                break;
            case 'r': {
                struct stat stat_buf;
                pcapfile = optarg;
                if (stat(pcapfile, &stat_buf)) {
                    LogError("Can't stat '%s': %s", pcapfile, strerror(errno));
                    exit(EXIT_FAILURE);
                }
                if (!S_ISREG(stat_buf.st_mode)) {
                    LogError("'%s' is not a file", pcapfile);
                    exit(EXIT_FAILURE);
                }
            } break;
            case 's':
                snaplen = atoi(optarg);
                if (snaplen < 14 + 20 + 20) {  // ethernet, IP , TCP, no payload
                    LogError("ERROR:, snaplen < sizeof IPv4 - Need 54 bytes for TCP/IPv4");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'e': {
                if (strlen(optarg) > 16) {
                    LogError("ERROR:, size timeout values too big");
                    exit(EXIT_FAILURE);
                }
                char *s = strdup(optarg);
                char *sep = strchr(s, ',');
                if (!sep) {
                    LogError("ERROR:, timeout values format error");
                    exit(EXIT_FAILURE);
                }
                *sep = '\0';
                sep++;
                activeTimeout = atoi(s);
                inactiveTimeout = atoi(sep);
                if (snaplen < 14 + 20 + 20) {  // ethernet, IP , TCP, no payload
                    LogError("ERROR:, snaplen < sizeof IPv4 - Need 54 bytes for TCP/IPv4");
                    exit(EXIT_FAILURE);
                }
            } break;
            case 't':
                t_win = atoi(optarg);
                if (t_win < 2) {
                    LogError("time interval <= 2s not allowed");
                    exit(EXIT_FAILURE);
                }
                if (t_win < 60) {
                    time_extension = "%Y%m%d%H%M%S";
                }
                break;
            case 'j':
                if (compress) {
                    LogError("Use either -z for LZO or -j for BZ2 compression, but not both");
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
                    LogError("Use either -z for LZO or -j for BZ2 compression, but not both");
                    exit(EXIT_FAILURE);
                }
                compress = LZO_COMPRESSED;
                break;
            case 'P':
                pidfile = verify_pid(optarg);
                if (!pidfile) {
                    exit(EXIT_FAILURE);
                }
                break;
            case 'S':
                subdir_index = atoi(optarg);
                break;
            case 'T':
                printf("Option -T no longer supported and ignored\n");
                break;
            case 'v':
                if (verbose < 4) verbose++;
                break;
            case 'V':
                printf("%s: Version: %s", argv[0], nfdump_version);
                exit(EXIT_SUCCESS);
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
        /* user specified a pcap filter */
        filter = argv[optind];
    }

    if (ConfOpen(configFile, "nfpcapd") < 0) exit(EXIT_FAILURE);

    if (filter) {
        filter = strdup(filter);
        if (!filter) {
            LogError("strdup() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    if ((device && pcapfile) || (!device && !pcapfile)) {
        LogError("Specify either a device or a pcapfile");
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    flushParam_t flushParam = {0};
    packetParam_t packetParam = {0};
    flowParam_t flowParam = {0};
    flushParam.extensionFormat = time_extension;
    flowParam.extensionFormat = time_extension;

    if (options && scanOptions(&flowParam, options) < 0) {
        exit(EXIT_FAILURE);
    }

    if ((datadir && sendHost) || (!datadir && !sendHost)) {
        LogError("Specify either a local directory or a remote host to dump flows.");
        exit(EXIT_FAILURE);
    }

    if (sendHost) {
        int p = atoi(sendHost->port);
        if (p <= 0 || p > 655535) {
            LogError("ERROR: Port to send flows is not a regular port.");
            exit(EXIT_FAILURE);
        }
        sendHost->sockfd =
            Unicast_send_socket(sendHost->hostname, sendHost->port, sendHost->family, bufflen, &(sendHost->addr), &(sendHost->addrlen));
        if (sendHost->sockfd <= 0) exit(EXIT_FAILURE);
        dbg_printf("Replay flows to host: %s port: %s\n", sendHost->hostname, sendHost->port);
        flowParam.sendHost = sendHost;
    }

    int buffsize = 64 * 1024;
    int ret;
    void *(*packet_thread)(void *) = NULL;
    if (pcapfile) {
        packetParam.live = 0;
        ret = setup_pcap_file(&packetParam, pcapfile, filter, snaplen);
        packet_thread = pcap_packet_thread;
    } else {
        packetParam.live = 1;
#ifdef USE_BPFSOCKET
        packetParam.bpfBufferSize = buffsize;
        ret = setup_bpf_live(&packetParam, device, filter, snaplen, buffsize, TO_MS);
        packet_thread = bpf_packet_thread;
#elif USE_TPACKETV3
        ret = setup_linux_live(&packetParam, device, filter, snaplen, buffsize, TO_MS);
        packet_thread = linux_packet_thread;
#else
        ret = setup_pcap_live(&packetParam, device, filter, snaplen, buffsize, TO_MS);
        packet_thread = pcap_packet_thread;
#endif
    }
    if (ret < 0) {
        LogError("Setup failed. Exit");
        exit(EXIT_FAILURE);
    }

    SetPriv(userid, groupid);

    FlowSource_t *fs = NULL;
    if (datadir) {
        if (pcap_datadir && access(pcap_datadir, W_OK) < 0) {
            LogError("access() failed for %s: %s", pcap_datadir, strerror(errno));
            exit(EXIT_FAILURE);
        }

        if (access(datadir, W_OK) < 0) {
            LogError("access() failed for %s: %s", datadir, strerror(errno));
            exit(EXIT_FAILURE);
        }

        if (datadir && !AddFlowSource(&fs, Ident, ANYIP, datadir)) {
            LogError("Failed to add default data collector directory");
            exit(EXIT_FAILURE);
        }

        if (!Init_nffile(NULL)) exit(EXIT_FAILURE);

        if (subdir_index && !InitHierPath(subdir_index)) {
            pcap_close(packetParam.pcap_dev);
            exit(EXIT_FAILURE);
        }

        if (InitBookkeeper(&fs->bookkeeper, fs->datadir, getpid()) != BOOKKEEPER_OK) {
            LogError("initialize bookkeeper failed.");
            exit(EXIT_FAILURE);
        }
    }

    if (!Init_FlowTree(cache_size, activeTimeout, inactiveTimeout)) {
        LogError("Init_FlowTree() failed.");
        exit(EXIT_FAILURE);
    }

    if (!InitLog(do_daemonize, argv[0], SYSLOG_FACILITY, verbose)) {
        pcap_close(packetParam.pcap_dev);
        exit(EXIT_FAILURE);
    }

    if (do_daemonize) {
        daemonize();
    }

    if (pidfile) {
        if (check_pid(pidfile) != 0 || write_pid(pidfile) == 0) pcap_close(packetParam.pcap_dev);
        exit(EXIT_FAILURE);
    }

    if (metricsocket && !OpenMetric(metricsocket, metricInterval)) {
        exit(EXIT_FAILURE);
    }

    LogInfo("Startup nfpcapd.");
    // prepare signal mask for all threads
    // block signals, as they are handled by the main thread
    // mask is inherited by all threads
    sigemptyset(&signal_set);
    sigaddset(&signal_set, SIGINT);
    sigaddset(&signal_set, SIGHUP);
    sigaddset(&signal_set, SIGTERM);
    sigaddset(&signal_set, SIGUSR1);
    sigaddset(&signal_set, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &signal_set, NULL);

    // for USR2 set a signal handler, which interrupts blocking
    // system calls - and signals done event
    // handler applies for all threads in a process
    sa.sa_handler = Interrupt_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGPIPE, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);

    // fire pcap dump flush thread
    if (pcap_datadir) {
        flushParam.pcap_dev = packetParam.pcap_dev;
        flushParam.archivedir = pcap_datadir;
        flushParam.subdir_index = subdir_index;
        if (InitBufferQueues(&flushParam) < 0) {
            exit(EXIT_FAILURE);
        }
        packetParam.bufferQueue = flushParam.bufferQueue;
        packetParam.flushQueue = flushParam.flushQueue;
        flushParam.parent = pthread_self();

        int err = pthread_create(&flushParam.tid, NULL, flush_thread, (void *)&flushParam);
        if (err) {
            LogError("pthread_create() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            exit(EXIT_FAILURE);
        }
        dbg_printf("Started flush thread[%lu]", (long unsigned)flushParam.tid);
    }

    // fire off flow handling thread
    flowParam.done = &done;
    flowParam.fs = fs;
    flowParam.t_win = t_win;
    flowParam.compress = compress;
    flowParam.subdir_index = subdir_index;
    flowParam.parent = pthread_self();
    flowParam.NodeList = NewNodeList();
    flowParam.printRecord = (do_daemonize == 0) && (verbose > 2);
    if (sendHost) {
        err = pthread_create(&flowParam.tid, NULL, sendflow_thread, (void *)&flowParam);
    } else {
        err = pthread_create(&flowParam.tid, NULL, flow_thread, (void *)&flowParam);
    }
    if (err) {
        LogError("pthread_create() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        exit(EXIT_FAILURE);
    }
    dbg_printf("Started flow thread[%lu]", (long unsigned)flowParam.tid);

    packetParam.parent = pthread_self();
    packetParam.NodeList = flowParam.NodeList;
    packetParam.extendedFlow = flowParam.extendedFlow;
    packetParam.addPayload = flowParam.addPayload;
    packetParam.t_win = t_win;
    packetParam.done = &done;
    err = pthread_create(&packetParam.tid, NULL, packet_thread, (void *)&packetParam);
    if (err) {
        LogError("pthread_create() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        exit(EXIT_FAILURE);
    }
    dbg_printf("Started packet thread[%lu]\n", (long unsigned)packetParam.tid);

    // Wait till done
    WaitDone();

    dbg_printf("Signal packet thread to terminate\n");
    pthread_kill(packetParam.tid, SIGUSR2);
    pthread_join(packetParam.tid, NULL);
    dbg_printf("Packet thread joined\n");

    if (pcap_datadir) {
        pthread_join(flushParam.tid, NULL);
        dbg_printf("Pcap flush thread joined\n");
    }

    dbg_printf("Flush flow tree\n");
    Flush_FlowTree(flowParam.NodeList, packetParam.t_win);

    // flow thread terminates on end of node queue
    pthread_join(flowParam.tid, NULL);
    dbg_printf("Flow thread joined\n");

    if (datadir) {
        if (expire == 0 && ReadStatInfo(fs->datadir, &dirstat, LOCK_IF_EXISTS) == STATFILE_OK) {
            UpdateDirStat(dirstat, fs->bookkeeper);
            WriteStatInfo(dirstat);
            LogVerbose("Updating statinfo in directory '%s'", datadir);
        }
        ReleaseBookkeeper(fs->bookkeeper, DESTROY_BOOKKEEPER);
    }

    CloseMetric();

    LogInfo("Total: Processed: %u, skipped: %u, short caplen: %u, unknown: %u\n", packetParam.proc_stat.packets, packetParam.proc_stat.skipped,
            packetParam.proc_stat.short_snap, packetParam.proc_stat.unknown);

    if (pidfile) remove_pid(pidfile);

    LogInfo("Terminating nfpcapd.");
    EndLog();

    exit(EXIT_SUCCESS);
} /* End of main */
