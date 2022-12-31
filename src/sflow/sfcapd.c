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

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
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

#include "config.h"

#ifdef PCAP
#include "pcap_reader.h"
#endif

#include "bookkeeper.h"
#include "collector.h"
#include "daemon.h"
#include "flist.h"
#include "launch.h"
#include "metric.h"
#include "nfconf.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfnet.h"
#include "nfstatfile.h"
#include "nfxV3.h"
#include "pidfile.h"
#include "privsep.h"
#include "util.h"

#ifdef HAVE_FTS_H
#include <fts.h>
#else
#include "fts_compat.h"
#define fts_children fts_children_compat
#define fts_close fts_close_compat
#define fts_open fts_open_compat
#define fts_read fts_read_compat
#define fts_set fts_set_compat
#endif

#include "expire.h"
#include "sflow_nfdump.h"

#define DEFAULTSFLOWPORT "6343"

static int verbose = 0;

// Define a generic type to get data from socket or pcap file
typedef ssize_t (*packet_function_t)(int, void *, size_t, int, struct sockaddr *, socklen_t *);

/* module limited globals */
static FlowSource_t *FlowSource;

static int done = 0;
static int gotSIGCHLD = 0;
static int periodic_trigger, launcher_pid;

static const char *nfdump_version = VERSION;

/* Local function Prototypes */
static void usage(char *name);

static void kill_launcher(pid_t launcher_pid, int pfd);

static void IntHandler(int signal);

static inline FlowSource_t *GetFlowSource(struct sockaddr_storage *ss);

static void run(packet_function_t receive_packet, int socket, int pfd, repeater_t *repeater, time_t twin, time_t t_begin, int report_seq,
                int use_subdirs, char *time_extension, int compress);

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
        "-w flowdir \tset the output directory to store the flows.\n"
        "-C <file>\tRead optional config file.\n"
        "-S subdir\tSub directory format. see nfcapd(1) for format\n"
        "-I Ident\tset the ident string for stat file. (default 'none')\n"
        "-n Ident,IP,flowdir\tAdd this flow source - multiple streams\n"
        "-i interval\tMetric interval in s for metric exporter\n"
        "-m socket\t\tEnable metric exporter on socket.\n"
        "-M dir \t\tSet the output directory for dynamic sources.\n"
        "-P pidfile\tset the PID file\n"
        "-R IP[/port]\tRepeat incoming packets to IP address/port. Max 8 repeaters.\n"
        "-x process\tlaunch process after a new file becomes available\n"
        "-z\t\tLZO compress flows in output file.\n"
        "-y\t\tLZ4 compress flows in output file.\n"
        "-j\t\tBZ2 compress flows in output file.\n"
        "-B bufflen\tSet socket buffer to bufflen bytes\n"
        "-e\t\tExpire data at each cycle.\n"
        "-D\t\tFork to background\n"
        "-E\t\tPrint extended format of sflow data. For debugging purpose only.\n"
        "-v\t\tIncrease verbose level.\n"
        "-4\t\tListen on IPv4 (default).\n"
        "-6\t\tListen on IPv6.\n"
        "-V\t\tPrint version and exit.\n"
        "-Z\t\tAdd timezone offset to filename.\n",
        name);
}  // End of usage

static void kill_launcher(pid_t launcher_pid, int pfd) {
    if (pfd == 0) return;

    message_t message;
    message.type = PRIVMSG_EXIT;
    message.length = sizeof(message);
    ssize_t ret = write(pfd, &message, sizeof(message));

    if (ret < 0) {
        LogError("Failed to send exit message for launcher. pipe write: %s", strerror(errno));
        kill(launcher_pid, SIGTERM);
    }

    int stat = 0;
    if ((ret = waitpid(launcher_pid, &stat, 0)) == -1) {
        if (!gotSIGCHLD) LogError("wait for launcher failed: %s %i", strerror(errno), ret);
    } else {
        if (WIFEXITED(stat)) {
            LogInfo("launcher exit status: %i", WEXITSTATUS(stat));
        }
        if (WIFSIGNALED(stat)) {
            LogError("launcher terminated due to signal %i", WTERMSIG(stat));
        }
        LogVerbose("Launcher terminated with status: 0x%x", stat);
    }

}  // End of kill_launcher

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
            gotSIGCHLD = 0;
            break;
        default:
            // ignore everything we don't know
            break;
    }

} /* End of IntHandler */

static void format_file_block_header(dataBlock_t *header) {
    printf("File Block Header: type: %u, size: %u, NumRecords: %u\n", header->type, header->size, header->NumRecords);
}  // End of format_file_block_header

#include "collector_inline.c"
#include "nffile_inline.c"

static void run(packet_function_t receive_packet, int socket, int pfd, repeater_t *repeater, time_t twin, time_t t_begin, int report_seq,
                int use_subdirs, char *time_extension, int compress) {
    FlowSource_t *fs;
    struct sockaddr_storage sf_sender;
    socklen_t sf_sender_size = sizeof(sf_sender);
    time_t t_start, t_now;
    uint64_t export_packets;
    uint32_t blast_cnt, blast_failures, ignored_packets;
    ssize_t cnt;
    void *in_buff;

    in_buff = malloc(NETWORK_INPUT_BUFF_SIZE);
    if (!in_buff) {
        LogError("malloc() allocation error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return;
    }

    // Init each sflow source output data buffer
    fs = FlowSource;
    while (fs) {
        // prepare file
        fs->nffile = OpenNewFile(fs->current, NULL, compress, NOT_ENCRYPTED);
        if (!fs->nffile) {
            return;
        }
        SetIdent(fs->nffile, fs->Ident);

        // init vars
        fs->bad_packets = 0;
        fs->msecFirst = 0xffffffffffffLL;
        fs->msecLast = 0;

        // next source
        fs = fs->next;
    }

    export_packets = blast_cnt = blast_failures = 0;
    t_start = t_begin;

    cnt = 0;
    periodic_trigger = 0;
    ignored_packets = 0;

    // wake up at least at next time slot (twin) + 1s
    alarm(t_start + twin + 1 - time(NULL));
    /*
     * Main processing loop:
     * this loop, continues until done = 1, set by the signal handler
     * The while loop will be breaked by the periodic file renaming code
     * for proper cleanup
     */
    while (1) {
        struct timeval tv;
        int i;

        /* read next bunch of data into beginn of input buffer */
        if (!done) {
#ifdef PCAP
            // Debug code to read from pcap file, or from socket
            cnt = receive_packet(socket, in_buff, NETWORK_INPUT_BUFF_SIZE, 0, (struct sockaddr *)&sf_sender, &sf_sender_size);

            // in case of reading from file EOF => -2
            if (cnt == -2) done = 1;
#else
            cnt = recvfrom(socket, in_buff, NETWORK_INPUT_BUFF_SIZE, 0, (struct sockaddr *)&sf_sender, &sf_sender_size);
#endif

            if (cnt == -1 && errno != EINTR) {
                LogError("ERROR: recvfrom: %s", strerror(errno));
                continue;
            }

            i = 0;
            while (repeater[i].hostname && (i < MAX_REPEATERS)) {
                ssize_t len;
                len = sendto(repeater[i].sockfd, in_buff, cnt, 0, (struct sockaddr *)&(repeater[i].addr), repeater[i].addrlen);
                if (len < 0) {
                    LogError("ERROR: sendto(): %s", strerror(errno));
                }
                i++;
            }
        }

        /* Periodic file renaming, if time limit reached or if we are done.  */
        // t_now = time(NULL);
        gettimeofday(&tv, NULL);
        t_now = tv.tv_sec;

        if (((t_now - t_start) >= twin) || done) {
            struct tm *now;
            char *subdir, fmt[32];

            alarm(0);
            now = localtime(&t_start);
            strftime(fmt, sizeof(fmt), time_extension, now);

            // prepare sub dir hierarchy
            if (use_subdirs) {
                subdir = GetSubDir(now);
                if (!subdir) {
                    // failed to generate subdir path - put flows into base directory
                    LogError("Failed to create subdir path!");

                    // failed to generate subdir path - put flows into base directory
                    subdir = NULL;
                }
            } else {
                subdir = NULL;
            }

            // for each flow source update the stats, close the file and re-initialize the new file
            fs = FlowSource;
            while (fs) {
                char nfcapd_filename[MAXPATHLEN];
                char error[255];
                nffile_t *nffile = fs->nffile;

                if (verbose > 1) {
                    format_file_block_header(nffile->block_header);
                }

                // prepare filename
                if (subdir) {
                    if (SetupSubDir(fs->datadir, subdir, error, 255)) {
                        snprintf(nfcapd_filename, MAXPATHLEN - 1, "%s/%s/nfcapd.%s", fs->datadir, subdir, fmt);
                    } else {
                        LogError("Ident: %s, Failed to create sub hier directories: %s", fs->Ident, error);
                        // skip subdir - put flows directly into current directory
                        snprintf(nfcapd_filename, MAXPATHLEN - 1, "%s/nfcapd.%s", fs->datadir, fmt);
                    }
                } else {
                    snprintf(nfcapd_filename, MAXPATHLEN - 1, "%s/nfcapd.%s", fs->datadir, fmt);
                }
                nfcapd_filename[MAXPATHLEN - 1] = '\0';

                // update stat record
                // if no flows were collected, fs->msecLast is still 0
                // set first_seen to start of this time slot, with twin window size.
                if (fs->msecLast == 0) {
                    fs->msecFirst = 1000LL * (uint64_t)t_start;
                    fs->msecLast = 1000LL * (uint64_t)(t_start + twin);
                }
                nffile->stat_record->firstseen = fs->msecFirst;
                nffile->stat_record->lastseen = fs->msecLast;

                // Flush Exporter Stat to file
                FlushExporterStats(fs);
                // Close file
                CloseUpdateFile(nffile);

                // if rename fails, we are in big trouble, as we need to get rid of the old .current
                // file otherwise, we will loose flows and can not continue collecting new flows
                if (RenameAppend(fs->current, nfcapd_filename) < 0) {
                    LogError("Ident: %s, Can't rename dump file: %s", fs->Ident, strerror(errno));

                    // we do not update the books here, as the file failed to rename properly
                    // otherwise the books may be wrong
                } else {
                    struct stat fstat;

                    // Update books
                    stat(nfcapd_filename, &fstat);
                    UpdateBooks(fs->bookkeeper, t_start, 512 * fstat.st_blocks);
                }

                // log stats
                LogInfo(
                    "Ident: '%s' Flows: %llu, Packets: %llu, Bytes: %llu, Sequence Errors: %u, Bad "
                    "Packets: %u",
                    fs->Ident, (unsigned long long)nffile->stat_record->numflows, (unsigned long long)nffile->stat_record->numpackets,
                    (unsigned long long)nffile->stat_record->numbytes, nffile->stat_record->sequence_failure, fs->bad_packets);

                // reset stats
                fs->bad_packets = 0;
                fs->msecFirst = 0xffffffffffffLL;
                fs->msecLast = 0;

                if (!done) {
                    fs->nffile = OpenNewFile(fs->current, fs->nffile, compress, NOT_ENCRYPTED);
                    if (!fs->nffile) {
                        LogError("killed due to fatal error: ident: %s", fs->Ident);
                        break;
                    }
                    SetIdent(fs->nffile, fs->Ident);

                    // Dump all exporters/samplers to the buffer
                    FlushStdRecords(fs);
                }

                // trigger launcher if required
                if (pfd) {
                    // Send launcher message
                    if (SendLauncherMessage(pfd, t_start, subdir, fmt, fs->datadir, fs->Ident) < 0) {
                        LogError("Failed to send launcher message");
                    } else {
                        LogVerbose("Send launcher message");
                    }
                }

                // next flow source
                fs = fs->next;

            }  // end of while (fs)

            if (ignored_packets) LogInfo("Total ignored packets: %u", ignored_packets);
            ignored_packets = 0;

            if (done) break;

            // update alarm for next cycle
            t_start += twin;
            /* t_start = filename time stamp: begin of slot
             * + twin = end of next time interval
             * + 1 = act at least 1s after time window expired
             * - t_now = difference value to now
             */
            alarm(t_start + twin + 1 - t_now);
        }

        /* check for error condition or done . errno may only be EINTR */
        if (cnt < 0) {
            if (periodic_trigger) {
                // alarm triggered, no new flow data
                periodic_trigger = 0;
                continue;
            }
            if (done)
                // signaled to terminate - exit from loop
                break;
            else {
                /* this should never be executed as it should be caught in other places */
                LogError("error condition in '%s', line '%d', cnt: %i", __FILE__, __LINE__, (int)cnt);
                continue;
            }
        }

        /* enough data? */
        if (cnt == 0) continue;

        // get flow source record for current packet, identified by sender IP address
        fs = GetFlowSource(&sf_sender);
        if (fs == NULL) {
            fs = AddDynamicSource(&FlowSource, &sf_sender);
            if (fs == NULL) {
                LogError("Skip UDP packet. Ignored packets so far %u packets", ignored_packets);
                ignored_packets++;
                continue;
            }
            if (InitBookkeeper(&fs->bookkeeper, fs->datadir, getpid(), launcher_pid) != BOOKKEEPER_OK) {
                LogError("Failed to initialise bookkeeper for new source");
                // fatal error
                return;
            }
            fs->nffile = OpenNewFile(fs->current, NULL, compress, NOT_ENCRYPTED);
            if (!fs->nffile) {
                LogError("Failed to open new collector file");
                return;
            }
            SetIdent(fs->nffile, fs->Ident);
        }

        /* check for too little data - cnt must be > 0 at this point */
        if (cnt < sizeof(common_flow_header_t)) {
            LogError("Ident: %s, Data length error: too little data for common netflow header. cnt: %i", fs->Ident, (int)cnt);
            fs->bad_packets++;
            continue;
        }

        fs->received = tv;
        /* Process data - have a look at the common header */
        Process_sflow(in_buff, cnt, fs);

        // each Process_xx function has to process the entire input buffer, therefore it's empty
        // now.
        export_packets++;
    }

    if (verbose && blast_failures) {
        LogError("Total missed packets: %u", blast_failures);
    }
    free(in_buff);

    fs = FlowSource;
    while (fs) {
        DisposeFile(fs->nffile);
        fs->nffile = NULL;
        fs = fs->next;
    }

} /* End of run */

int main(int argc, char **argv) {
    char *bindhost, *datadir, *launch_process;
    char *userid, *groupid, *listenport, *mcastgroup;
    char *Ident, *dynFlowDir, *time_extension, *pidfile, *configFile, *metricSocket;
    packet_function_t receive_packet;
    repeater_t repeater[MAX_REPEATERS];
    FlowSource_t *fs;
    int family, bufflen, metricInterval;
    time_t twin;
    int sock, do_daemonize, expire, spec_time_extension, report_sequence;
    int subdir_index, compress;
#ifdef PCAP
    char *pcap_file = NULL;
#endif

    receive_packet = recvfrom;
    verbose = do_daemonize = 0;
    bufflen = 0;
    family = AF_UNSPEC;
    launcher_pid = 0;
    report_sequence = 0;
    listenport = DEFAULTSFLOWPORT;
    bindhost = NULL;
    mcastgroup = NULL;
    pidfile = NULL;
    launch_process = NULL;
    userid = groupid = NULL;
    twin = TIME_WINDOW;
    datadir = NULL;
    subdir_index = 0;
    time_extension = "%Y%m%d%H%M";
    spec_time_extension = 0;
    expire = 0;
    compress = NOT_COMPRESSED;
    memset((void *)&repeater, 0, sizeof(repeater));
    for (int i = 0; i < MAX_REPEATERS; i++) {
        repeater[i].family = AF_UNSPEC;
    }
    configFile = NULL;
    Ident = "none";
    FlowSource = NULL;
    dynFlowDir = NULL;
    metricSocket = NULL;
    metricInterval = 60;

    int c;
    while ((c = getopt(argc, argv, "46b:B:C:DeEf:g:hI:i:jJ:l:m:M:n:p:P:rR:S:T:t:u:vVw:x:yzZ")) != EOF) {
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
            case 'f': {
#ifdef PCAP
                struct stat fstat;
                pcap_file = optarg;
                stat(pcap_file, &fstat);
                if (!S_ISREG(fstat.st_mode)) {
                    LogError("Not a regular file: %s", pcap_file);
                    exit(254);
                }
#else
                LogError("PCAP reader not compiled! Option ignored!");
#endif
            } break;
            case 'E':
                verbose = 3;
                break;
            case 'v':
                if (verbose < 4) verbose++;
                break;
            case 'V':
                printf("%s: Version: %s\n", argv[0], nfdump_version);
                exit(EXIT_SUCCESS);
                break;
            case 'D':
                do_daemonize = 1;
                break;
            case 'I':
                CheckArgLen(optarg, 128);
                Ident = strdup(optarg);
                break;
            case 'i':
                metricInterval = atoi(optarg);
                if (metricInterval < 10) {
                    LogError("metric interval < 10s not allowed");
                    exit(EXIT_FAILURE);
                }
                if (metricInterval > twin) {
                    LogInfo("metric interval %d > twin %d", metricInterval, twin);
                }
                break;
            case 'm':
                CheckArgLen(optarg, MAXPATHLEN);
                metricSocket = strdup(optarg);
                break;
            case 'M':
                CheckArgLen(optarg, MAXPATHLEN);
                dynFlowDir = strdup(optarg);
                if (!CheckPath(dynFlowDir, S_IFDIR)) {
                    LogError("No valid directory: %s", dynFlowDir);
                    exit(EXIT_FAILURE);
                }
                if (!SetDynamicSourcesDir(&FlowSource, dynFlowDir)) {
                    LogError("Failed to add dynamic flowdir");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'n':
                if (!AddFlowSourceString(&FlowSource, optarg)) {
                    LogError("Failed to add flow source");
                    exit(EXIT_FAILURE);
                }
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
                char *port, *hostname;
                char *p = strchr(optarg, '/');
                int i = 0;
                if (p) {
                    *p++ = '\0';
                    port = strdup(p);
                } else {
                    port = DEFAULTSFLOWPORT;
                }
                hostname = strdup(optarg);
                while (repeater[i].hostname && (i < MAX_REPEATERS)) i++;
                if (i == MAX_REPEATERS) {
                    LogError("Too many packet repeaters! Max: %i repeaters allowed", MAX_REPEATERS);
                    exit(EXIT_FAILURE);
                }
                repeater[i].hostname = hostname;
                repeater[i].port = port;

                break;
            }
            case 'r':
                report_sequence = 1;
                break;
            case 'l':
                LogError("-l is a legacy option and may get removed in future. Please use -w to set output directory");
            case 'w':
                if (!CheckPath(optarg, S_IFDIR)) {
                    LogError("No valid directory: %s", optarg);
                    exit(EXIT_FAILURE);
                }
                datadir = realpath(optarg, NULL);
                if (!datadir) {
                    LogError("realpath() failed on %s: %s", optarg, strerror(errno));
                    exit(EXIT_FAILURE);
                }
                break;
            case 'S':
                subdir_index = atoi(optarg);
                break;
            case 'T':
                printf("Option -T no longer supported and ignored\n");
                break;
            case 't':
                twin = atoi(optarg);
                if (twin < 2) {
                    LogError("time interval <= 2s not allowed");
                    exit(EXIT_FAILURE);
                }
                if (twin < 60) {
                    time_extension = "%Y%m%d%H%M%S";
                }
                break;
            case 'x':
                launch_process = optarg;
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
                compress = LZO_COMPRESSED;
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

    if (argc > optind) {
        if (strcmp(argv[optind], "privsep") == 0) {
            dbg_printf("sfcapd privsep launched\n");
            int ret = StartupLauncher(launch_process, expire);
            exit(ret);
        } else {
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (ConfOpen(configFile, "sfcapd") < 0) exit(EXIT_FAILURE);

    if (datadir && !AddFlowSource(&FlowSource, Ident, ANYIP, datadir)) {
        LogError("Failed to add default data collector directory");
        exit(EXIT_FAILURE);
    }

    if (!AddFlowSourceConfig(&FlowSource)) {
        LogError("Failed to add exporter from config file");
        exit(EXIT_FAILURE);
    }

    if (FlowSource == NULL && datadir == NULL && dynFlowDir == NULL) {
        LogError("ERROR, No source configurations found");
        exit(EXIT_FAILURE);
    }

    if (bindhost && mcastgroup) {
        LogError("ERROR, -b and -j are mutually exclusive!!");
        exit(EXIT_FAILURE);
    }

    if (!InitLog(do_daemonize, argv[0], SYSLOG_FACILITY, verbose)) {
        exit(EXIT_FAILURE);
    }

    if (!Init_nffile(NULL)) exit(254);

    if (expire && spec_time_extension) {
        LogError("ERROR, -Z timezone extension breaks expire -e");
        exit(EXIT_FAILURE);
    }

    // Debug code to read from pcap file
#ifdef PCAP
    sock = 0;
    if (pcap_file) {
        printf("Setup pcap reader\n");
        setup_packethandler(pcap_file, NULL);
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

    int i = 0;
    while (repeater[i].hostname && (i < MAX_REPEATERS)) {
        repeater[i].sockfd =
            Unicast_send_socket(repeater[i].hostname, repeater[i].port, repeater[i].family, bufflen, &repeater[i].addr, &repeater[i].addrlen);
        if (repeater[i].sockfd <= 0) exit(EXIT_FAILURE);
        LogInfo("Replay flows to host: %s port: %s", repeater[i].hostname, repeater[i].port);
        i++;
    }

    SetPriv(userid, groupid);

    Init_sflow(verbose);

    if (subdir_index && !InitHierPath(subdir_index)) {
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

    int pfd[2] = {0};
    if (launch_process || expire) {
        pipe(pfd);

        if ((launcher_pid = fork()) == -1) {
            LogError("fork() error in '%s', line '%d'", __FILE__, __LINE__);
            exit(1);
        }

        if (launcher_pid == 0) {
            // child
            close(pfd[1]);
            close(0);
            dup(pfd[0]);
            int i;
            char **privargv = calloc(argc + 3, sizeof(char *));
            privargv[0] = argv[0];
            for (i = 1; i < argc; i++) privargv[i] = argv[i];
            privargv[i++] = "privsep";
            privargv[i++] = NULL;
            execvp(privargv[0], privargv);
            LogError("execvp() privsep '%s' failed: %s\n", privargv[0], strerror(errno));
            _exit(errno);
        }

        // parent
        close(pfd[0]);
        LogVerbose("Launcher child forked: %d\n", launcher_pid);
    }

    fs = FlowSource;
    while (fs) {
        if (InitBookkeeper(&fs->bookkeeper, fs->datadir, getpid(), launcher_pid) != BOOKKEEPER_OK) {
            LogError("initialize bookkeeper failed");

            // release all already allocated bookkeepers
            fs = FlowSource;
            while (fs && fs->bookkeeper) {
                ReleaseBookkeeper(fs->bookkeeper, DESTROY_BOOKKEEPER);
                fs = fs->next;
            }
            close(sock);
            kill_launcher(launcher_pid, pfd[1]);
            if (pidfile) remove_pid(pidfile);
            exit(EXIT_FAILURE);
        }

        fs = fs->next;
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

    LogInfo("Startup sfcapd.");
    run(receive_packet, sock, pfd[1], repeater, twin, t_start, report_sequence, subdir_index, time_extension, compress);

    // shutdown
    close(sock);
    kill_launcher(launcher_pid, pfd[1]);
    CloseMetric();

    fs = FlowSource;
    while (fs && fs->bookkeeper) {
        dirstat_t *dirstat;
        // if we do not auto expire and there is a stat file, update the stats before we leave
        if (expire == 0 && ReadStatInfo(fs->datadir, &dirstat, LOCK_IF_EXISTS) == STATFILE_OK) {
            UpdateDirStat(dirstat, fs->bookkeeper);
            WriteStatInfo(dirstat);
            LogVerbose("Updating statinfo in directory '%s'", datadir);
        }

        ReleaseBookkeeper(fs->bookkeeper, DESTROY_BOOKKEEPER);
        fs = fs->next;
    }

    LogInfo("Terminating sfcapd.");
    if (pidfile) remove_pid(pidfile);

    EndLog();
    return 0;

} /* End of main */
