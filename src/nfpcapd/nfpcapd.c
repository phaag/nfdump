/*
 *  Copyright (c) 2013-2021, Peter Haag
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <assert.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>


#include <pcap.h>

#include "util.h"
#include "nfdump.h"
#include "nffile.h"
#include "expire.h"
#include "nfnet.h"
#include "flist.h"
#include "nfstatfile.h"
#include "bookkeeper.h"
#include "collector.h"
#include "exporter.h"
#include "flowtree.h"
#include "pcapdump.h"
#include "flowdump.h"
#include "pcaproc.h"

#define TIME_WINDOW     300
#define PROMISC         1
#define TIMEOUT         500
#define FILTER          "ip"
#define TO_MS			100
#define DEFAULT_DIR     "/var/tmp"

#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL   113
#endif

static int verbose = 0;
static int done = 0;
/*
 * global static var: used by interrupt routine
 */
#define PCAP_DUMPFILE "pcap.current"

static const char *nfdump_version = VERSION;

static int launcher_pid;
static pthread_mutex_t  m_done  = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t terminate = PTHREAD_COND_INITIALIZER;

uint32_t linktype;
uint32_t linkoffset;

/*
 * Function prototypes
 */
static void usage(char *name);

static void daemonize(void);

static void Interrupt_handler(int sig);

static void SetPriv(char *userid, char *groupid );

static int setup_pcap_file(packetParam_t *param, char *pcap_file, char *filter, int snaplen);

static void WaitDone(void);

/*
 * Functions
 */

static void usage(char *name) {
	printf("usage %s [options] [\"pcap filter\"]\n"
					"-h\t\tthis text you see right here\n"
					"-u userid\tChange user to username\n"
					"-g groupid\tChange group to groupname\n"
					"-i interface\tread packets from interface\n"
					"-r pcapfile\tread packets from file\n"
					"-b num\tset socket buffer size in MB. (default 20MB)\n"
					"-B num\tset the node cache size. (default 524288)\n"
					"-s snaplen\tset the snapshot length - default 1526\n"
					"-e active,inactive\tset the active,inactive flow expire time (s) - default 300,60\n"
					"-l flowdir \tset the flow output directory. (no default) \n"
					"-p pcapdir \tset the pcapdir directory. (optional) \n"
					"-S subdir\tSub directory format. see nfcapd(1) for format\n"
					"-I Ident\tset the ident string for stat file. (default 'none')\n"
					"-P pidfile\tset the PID file\n"
					"-t time frame\tset the time window to rotate pcap/nfcapd file\n"
					"-z\t\tLZO compress flows in output file.\n"
					"-y\t\tLZ4 compress flows in output file.\n"
					"-j\t\tBZ2 compress flows in output file.\n"
					"-E\t\tPrint extended format of netflow data. for debugging purpose only.\n"
					"-D\t\tdetach from terminal (daemonize)\n"
	, name);
} // End of usage

static void Interrupt_handler(int sig) {
#ifdef DEVEL
pthread_t tid		 = pthread_self();

	printf("[%lu] Interrupt handler. Signal %d\n", (long unsigned)tid, sig);
#endif
	done = 1;

} // End of signal_handler

static void daemonize(void) {
int fd;
	switch (fork()) {
		case 0:
			// child
			break;
		case -1:
			// error
			fprintf(stderr, "fork() error: %s\n", strerror(errno));
			exit(0);
			break;
		default:
			// parent
			_exit(0);
	}

	if (setsid() < 0) {
		fprintf(stderr, "setsid() error: %s\n", strerror(errno));
		exit(0);
	}

	// Double fork
	switch (fork()) {
		case 0:
			// child
			break;
		case -1:
			// error
			fprintf(stderr, "fork() error: %s\n", strerror(errno));
			exit(0);
			break;
		default:
			// parent
			_exit(0);
	}

	fd = open("/dev/null", O_RDONLY);
	if (fd != 0) {
		dup2(fd, 0);
		close(fd);
	}
	fd = open("/dev/null", O_WRONLY);
	if (fd != 1) {
		dup2(fd, 1);
		close(fd);
	}
	fd = open("/dev/null", O_WRONLY);
	if (fd != 2) {
		dup2(fd, 2);
		close(fd);
	}

} // End of daemonize

static void SetPriv(char *userid, char *groupid ) {
struct 	passwd *pw_entry;
struct 	group *gr_entry;
uid_t	myuid, newuid, newgid;
int		err;

	if ( userid == 0 && groupid == 0 )
		return;

	newuid = newgid = 0;
	myuid = getuid();
	if ( myuid != 0 ) {
		LogError("Only root wants to change uid/gid");
		fprintf(stderr, "ERROR: Only root wants to change uid/gid\n");
		exit(255);
	}

	if ( userid ) {
		pw_entry = getpwnam(userid);
		newuid = pw_entry ? pw_entry->pw_uid : atol(userid);

		if ( newuid == 0 ) {
			fprintf (stderr,"Invalid user '%s'\n", userid);
			exit(255);
		}
	}

	if ( groupid ) {
		gr_entry = getgrnam(groupid);
		newgid = gr_entry ? gr_entry->gr_gid : atol(groupid);

		if ( newgid == 0 ) {
			fprintf (stderr,"Invalid group '%s'\n", groupid);
			exit(255);
		}

		err = setgid(newgid);
		if ( err ) {
			LogError("Can't set group id %ld for group '%s': %s",   (long)newgid, groupid, strerror(errno));
			fprintf (stderr,"Can't set group id %ld for group '%s': %s\n", (long)newgid, groupid, strerror(errno));
			exit(255);
		}

	}

	if ( newuid ) {
		err = setuid(newuid);
		if ( err ) {
			LogError("Can't set user id %ld for user '%s': %s",   (long)newuid, userid, strerror(errno));
			fprintf (stderr,"Can't set user id %ld for user '%s': %s\n", (long)newuid, userid, strerror(errno));
			exit(255);
		}
	}

} // End of SetPriv

static int setup_pcap_file(packetParam_t *param, char *pcap_file, char *filter, int snaplen) {
pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */

	dbg_printf("Enter function: %s\n", __FUNCTION__);

	errbuf[0] = '\0';
	handle = pcap_open_offline(pcap_file, errbuf);
	if (handle == NULL) {
		LogError("pcap_open_offline() failed: %s", errbuf);
		return -1;
	}


	if ( filter ) {
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
	linktype   = pcap_datalink(handle);
	switch ( linktype ) {
		case DLT_RAW: 
			linkoffset = 0; 
			break;
		case DLT_PPP: 
			linkoffset = 2;
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
		default:
			LogError("Unsupported data link type %i", linktype);
			return -1;
	}

	param->pcap_dev = handle;
	param->linkoffset = linkoffset;
	param->snaplen	 = snaplen;
	param->linktype	 = linktype;

	return 0;

} // End of setup_pcap_file

static void WaitDone(void) {
sigset_t signal_set;
int done, sig;
pthread_t tid   = pthread_self();

	LogVerbose("[%lu] WaitDone() waiting", (long unsigned)tid);

	sigemptyset(&signal_set);
	sigaddset(&signal_set, SIGINT);
	sigaddset(&signal_set, SIGHUP);
	sigaddset(&signal_set, SIGTERM);
	sigaddset(&signal_set, SIGUSR1);
	pthread_sigmask(SIG_BLOCK, &signal_set, NULL);

	done = 0;
	while ( !done ) {
		sigwait(&signal_set, &sig);
		LogVerbose("[%lu] WaitDone() signal %i", (long unsigned)tid, sig);
		switch ( sig ) {
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
	
} // End of WaitDone

int main(int argc, char *argv[]) {
sigset_t			signal_set;
struct sigaction	sa;
int c, snaplen, err, do_daemonize;
int subdir_index, compress, expire, fatFlows, cache_size, buff_size;
int activeTineout, inactiveTineout;
dirstat_t 		*dirstat;
time_t 			t_win;
char 			*device, *pcapfile, *filter, *datadir, *pcap_datadir, pidfile[MAXPATHLEN], pidstr[32];
char			*Ident, *userid, *groupid;
char			*time_extension;

	snaplen			= 65535;
	do_daemonize	= 0;
	launcher_pid	= 0;
	device			= NULL;
	pcapfile		= NULL;
	filter			= FILTER;
	pidfile[0]		= '\0';
	t_win			= TIME_WINDOW;
	datadir			= DEFAULT_DIR;
	pcap_datadir	= NULL;
	userid			= groupid = NULL;
	Ident			= "none";
	time_extension	= "%Y%m%d%H%M";
	subdir_index	= 0;
	compress		= NOT_COMPRESSED;
	verbose			= 0;
	expire			= 0;
	cache_size		= 0;
	buff_size		= 20;
	activeTineout	= 0;
	inactiveTineout	= 0;
	fatFlows		= 0;
	while ((c = getopt(argc, argv, "B:DEFI:b:e:g:hi:j:r:s:l:p:P:t:u:S:Vyz")) != EOF) {
		switch (c) {
			struct stat fstat;
			case 'h':
				usage(argv[0]);
				exit(0);
				break;
			case 'u':
				userid  = optarg;
				break;
			case 'g':
				groupid  = optarg;
				break;
			case 'D':
				do_daemonize = 1;
				break;
			case 'F':
				fatFlows = 1;
				break;
			case 'B':
				cache_size = atoi(optarg);
				if (cache_size <= 0) {
					LogError("ERROR: Cache size must not be < 0");
					exit(EXIT_FAILURE);
				}
				break;
			case 'I':
				Ident = strdup(optarg);
				break;
			case 'b':
				buff_size = atoi(optarg);
				if (buff_size <= 0 || buff_size > 2047 ) {
					LogError("ERROR: Buffer size in MB must be betwee 0..2047 (2GB max)");
					exit(EXIT_FAILURE);
				}
				break;
			case 'i':
				device = optarg;
				break;
			case 'l':
				datadir = optarg;
				err  = stat(datadir, &fstat);
				if (!(fstat.st_mode & S_IFDIR)) {
					LogError("No such directory: " "'%s'", datadir);
					break;
				}
				break;
			case 'p':
				pcap_datadir = optarg;
				err  = stat(pcap_datadir, &fstat);
				if (!(fstat.st_mode & S_IFDIR)) {
					LogError("No such directory: " "'%s'", pcap_datadir);
					break;
				}
				break;
			case 'r': {
				struct stat stat_buf;
				pcapfile = optarg;
				if ( stat(pcapfile, &stat_buf) ) {
					LogError("Can't stat '%s': %s", pcapfile, strerror(errno));
					exit(EXIT_FAILURE);
				}
				if (!S_ISREG(stat_buf.st_mode) ) {
					LogError("'%s' is not a file", pcapfile);
					exit(EXIT_FAILURE);
				}
				} break;
			case 's':
				snaplen = atoi(optarg);
				if (snaplen < 14 + 20 + 20) { // ethernet, IP , TCP, no payload
					LogError("ERROR:, snaplen < sizeof IPv4 - Need 54 bytes for TCP/IPv4");
					exit(EXIT_FAILURE);
				}
				break;
			case 'e': {
				if ( strlen(optarg) > 16 ) {
					LogError("ERROR:, size timeout values too big");
					exit(EXIT_FAILURE);
				}
				char *s = strdup(optarg);
				char *sep = strchr(s, ',');
				if ( !sep ) {
					LogError("ERROR:, timeout values format error");
					exit(EXIT_FAILURE);
				}
				*sep = '\0';
				sep++;
				activeTineout   = atoi(s);
				inactiveTineout = atoi(sep);
				if (snaplen < 14 + 20 + 20) { // ethernet, IP , TCP, no payload
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
					time_extension	= "%Y%m%d%H%M%S";
				}
				break;
			case 'j':
				if ( compress ) {
					LogError("Use either -z for LZO or -j for BZ2 compression, but not both\n");
					exit(255);
				}
				compress = BZ2_COMPRESSED;
				break;
			case 'y':
				if ( compress ) {
					LogError("Use one compression: -z for LZO, -j for BZ2 or -y for LZ4 compression\n");
					exit(255);
				}
				compress = LZ4_COMPRESSED;
				break;
			case 'z':
				if ( compress ) {
					LogError("Use either -z for LZO or -j for BZ2 compression, but not both\n");
					exit(255);
				}
				compress = LZO_COMPRESSED;
				break;
			case 'P':
				if ( optarg[0] == '/' ) { 	// absolute path given
					strncpy(pidfile, optarg, MAXPATHLEN-1);
				} else {					// path relative to current working directory
					char tmp[MAXPATHLEN];
					if ( !getcwd(tmp, MAXPATHLEN-1) ) {
						fprintf(stderr, "Failed to get current working directory: %s\n", strerror(errno));
						exit(255);
					}
					tmp[MAXPATHLEN-1] = 0;
					if ( (strlen(tmp) + strlen(optarg) + 3) < MAXPATHLEN ) {
						snprintf(pidfile, MAXPATHLEN - 3 - strlen(tmp), "%s/%s", tmp, optarg);
					} else {
						fprintf(stderr, "pidfile MAXPATHLEN error:\n");
						exit(255);
					}
				}
				// pidfile now absolute path
				pidfile[MAXPATHLEN-1] = 0;
				break;
			case 'S':
				subdir_index = atoi(optarg);
				break;
			case 'E':
				verbose = 1;
				break;
			case 'V':
				printf("%s: Version: %s\n",argv[0], nfdump_version);
				exit(0);
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

	if ( (device && pcapfile) || (!device && !pcapfile)) {
		LogError("Specify either a device or a pcapfile");
		exit(EXIT_FAILURE);
	}

	flushParam_t flushParam   = {0};
	packetParam_t packetParam = {0};

	int buffsize = 64*1024;
	int ret;
	void *(*packet_thread)(void *) = NULL;

	if ( pcapfile ) {
		ret = setup_pcap_file(&packetParam, pcapfile, filter, snaplen);
		packet_thread = pcap_packet_thread;
	} else {
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
		LogError("Setup failed. Exit.");
		exit(EXIT_FAILURE);
	}

	SetPriv(userid, groupid);

	if (pcap_datadir && access(pcap_datadir, W_OK) < 0) {
		LogError("access() failed for %s: %s", pcap_datadir, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (access(datadir, W_OK) < 0) {
		LogError("access() failed for %s: %s", datadir, strerror(errno));
		exit(EXIT_FAILURE);
	}

	FlowSource_t *fs = NULL;
	if ( datadir != NULL && !AddDefaultFlowSource(&fs, Ident, datadir) ) {
		fprintf(stderr, "Failed to add default data collector directory\n");
		exit(EXIT_FAILURE);
	}

	if ( !Init_FlowTree(cache_size, activeTineout, inactiveTineout, fatFlows)) {
		LogError("Init_FlowTree() failed.");
		exit(EXIT_FAILURE);
	}

	if ( !InitLog(do_daemonize, argv[0], SYSLOG_FACILITY, verbose) ) {
		pcap_close(packetParam.pcap_dev);
		exit(EXIT_FAILURE);
	}

	if ( !Init_nffile(NULL) )
		exit(EXIT_FAILURE);


	if ( subdir_index && !InitHierPath(subdir_index) ) {
		pcap_close(packetParam.pcap_dev);
		exit(EXIT_FAILURE);
	}

	// check if pid file exists and if so, if a process with registered pid is running
	if ( strlen(pidfile) ) {
		int pidf;
		pidf = open(pidfile, O_RDONLY, 0);
		if ( pidf > 0 ) {
			// pid file exists
			char s[32];
			ssize_t len;
			len = read(pidf, (void *)s, 31);
			close(pidf);
			s[31] = '\0';
			if ( len < 0 ) {
				fprintf(stderr, "read() error existing pid file: %s\n", strerror(errno));
				pcap_close(packetParam.pcap_dev);
				exit(255);
			} else {
				unsigned long pid = atol(s);
				if ( pid == 0 ) {
					// garbage - use this file
					unlink(pidfile);
				} else {
					if ( kill(pid, 0) == 0 ) {
						// process exists
						fprintf(stderr, "A process with pid %lu registered in pidfile %s is already running!\n", 
							pid, strerror(errno));
						pcap_close(packetParam.pcap_dev);
						exit(255);
					} else {
						// no such process - use this file
						unlink(pidfile);
					}
				}
			}
		} else {
			if ( errno != ENOENT ) {
				fprintf(stderr, "open() error existing pid file: %s\n", strerror(errno));
				pcap_close(packetParam.pcap_dev);
				exit(255);
			} // else errno == ENOENT - no file - this is fine
		}
	}

	if ( do_daemonize ) {
		verbose = 0;
		daemonize();
	}

	if (strlen(pidfile)) {
		pid_t pid = getpid();
		int pidf  = open(pidfile, O_RDWR|O_TRUNC|O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		if ( pidf == -1 ) {
			LogError("Error opening pid file: '%s' %s", pidfile, strerror(errno));
			pcap_close(packetParam.pcap_dev);
			exit(255);
		}
		snprintf(pidstr,31,"%lu\n", (unsigned long)pid);
		if ( write(pidf, pidstr, strlen(pidstr)) <= 0 ) {
			LogError("Error write pid file: '%s' %s", pidfile, strerror(errno));
		}
		close(pidf);
	}

	if ( InitBookkeeper(&fs->bookkeeper, fs->datadir, getpid(), launcher_pid) != BOOKKEEPER_OK ) {
			LogError("initialize bookkeeper failed.");
			pcap_close(packetParam.pcap_dev);
			exit(255);
	}

	LogInfo("Startup.");
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
	if ( pcap_datadir ) {
		flushParam.pcap_dev = packetParam.pcap_dev;
		flushParam.archivedir = pcap_datadir;
		flushParam.use_UTC = 0;
		if (InitBufferQueues(&flushParam) < 0) {
			exit(EXIT_FAILURE);
		}
		packetParam.bufferQueue = flushParam.bufferQueue;
		packetParam.flushQueue  = flushParam.flushQueue;
		flushParam.parent		= pthread_self();

		int err = pthread_create(&flushParam.tid, NULL, flush_thread, (void *)&flushParam);
		if (err) {
			LogError("pthread_create() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
			exit(255);
		}
		dbg_printf("Started flush thread[%lu]\n", (long unsigned)flushParam.tid);
	}

	// fire off flow handling thread
	flowParam_t flowParam	  = {0};
	flowParam.done			  = &done;
	flowParam.fs			  = fs;
	flowParam.t_win			  = t_win;
	flowParam.compress		  = compress;
	flowParam.subdir_index	  = subdir_index;
	flowParam.parent		  = pthread_self();
	flowParam.NodeList	   	  = NewNodeList();
	err = pthread_create(&flowParam.tid, NULL, flow_thread, (void *)&flowParam);
	if ( err ) {
		LogError("pthread_create() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(255);
	}
	dbg_printf("Started flow thread[%lu]\n", (long unsigned)flowParam.tid);

	packetParam.parent	  = pthread_self();
	packetParam.NodeList  = flowParam.NodeList;
	packetParam.t_win 	  = t_win;
	packetParam.done 	  = &done;
	err = pthread_create(&packetParam.tid, NULL, packet_thread, (void *)&packetParam);
	if ( err ) {
		LogError("pthread_create() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(255);
	}
	dbg_printf("Started packet thread[%lu]\n", (long unsigned)packetParam.tid);

	// Wait till done
	WaitDone();

	dbg_printf("Signal packet thread to terminate\n");
	pthread_kill(packetParam.tid, SIGUSR2);
   	pthread_join(packetParam.tid, NULL);
	dbg_printf("Packet thread joined\n");

	if ( pcap_datadir ) {
   		pthread_join(flushParam.tid, NULL);
		dbg_printf("Pcap flush thread joined\n");
	}

	dbg_printf("Flush flow tree\n");
	Flush_FlowTree(flowParam.NodeList, packetParam.t_win);

	// flow thread terminates on end of node queue
   	pthread_join(flowParam.tid, NULL);
	dbg_printf("Flow thread joined\n");

	if ( expire == 0 && ReadStatInfo(fs->datadir, &dirstat, LOCK_IF_EXISTS) == STATFILE_OK ) {
		UpdateBookStat(dirstat, fs->bookkeeper);
		WriteStatInfo(dirstat);
		LogInfo("Updating statinfo in directory '%s'", datadir);
	}

	ReleaseBookkeeper(fs->bookkeeper, DESTROY_BOOKKEEPER);
	pcap_close(packetParam.pcap_dev);

	if ( strlen(pidfile) )
		unlink(pidfile);

	LogInfo("Terminating nfpcapd.");
	EndLog();

	exit(EXIT_SUCCESS);
} /* End of main */

