/*
 *  Copyright (c) 2009-2021, Peter Haag
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <string.h>
#include <libgen.h>
#include <errno.h>
#include <dirent.h>

#ifdef PCAP
#include "pcap_reader.h"
#endif


#include "util.h"
#include "nfdump.h"
#include "flist.h"
#include "pidfile.h"
#include "nffile.h"
#include "nfxV3.h"
#include "nfnet.h"
#include "bookkeeper.h"
#include "collector.h"
#include "launch.h"
#include "nfstatfile.h"

#ifdef HAVE_FTS_H
#   include <fts.h>
#else
#   include "fts_compat.h"
#define fts_children fts_children_compat
#define fts_close fts_close_compat
#define fts_open  fts_open_compat
#define fts_read  fts_read_compat
#define fts_set   fts_set_compat
#endif

#include "expire.h"

#include "sflow_nfdump.h"

#define DEFAULTSFLOWPORT "6343"

static void *shmem;
static int verbose = 0;

// Define a generic type to get data from socket or pcap file
typedef ssize_t (*packet_function_t)(int, void *, size_t, int, struct sockaddr *, socklen_t *);

/* module limited globals */
static FlowSource_t *FlowSource;

static int done, launcher_alive, periodic_trigger, launcher_pid;

static const char *nfdump_version = VERSION;

/* Local function Prototypes */
static void usage(char *name);

static void kill_launcher(int pid);

static void IntHandler(int signal);

static inline FlowSource_t *GetFlowSource(struct sockaddr_storage *ss);

static void daemonize(void);

static void SetPriv(char *userid, char *groupid );

static void run(packet_function_t receive_packet, int socket, repeater_t *repeater,
	time_t twin, time_t t_begin, int report_seq, int use_subdirs, char *time_extension, int compress);

/* Functions */
static void usage(char *name) {
		printf("usage %s [options] \n"
					"-h\t\tthis text you see right here\n"
					"-u userid\tChange user to userid\n"
					"-g groupid\tChange group to groupid\n"
					"-t interval\tset the interval to rotate sfcapd files\n"
					"-b host\t\tbind socket to host/IP addr\n"
					"-J mcastgroup\tJoin multicast group <mcastgroup>\n"
					"-p portnum\tlisten on port portnum\n"
					"-l logdir \tset the output directory. (no default) \n"
					"-S subdir\tSub directory format. see nfcapd(1) for format\n"
					"-I Ident\tset the ident string for stat file. (default 'none')\n"
					"-H Add port histogram data to flow file.(default 'no')\n"
					"-n Ident,IP,logdir\tAdd this flow source - multiple streams\n" 
					"-N sourceFile\tAdd flows from sourceFile\n"
					"-P pidfile\tset the PID file\n"
					"-R IP[/port]\tRepeat incoming packets to IP address/port. Max 8 repeaters\n"
					"-x process\tlaunch process after a new file becomes available\n"
					"-z\t\tLZO compress flows in output file.\n"
					"-y\t\tLZ4 compress flows in output file.\n"
					"-j\t\tBZ2 compress flows in output file.\n"
					"-B bufflen\tSet socket buffer to bufflen bytes\n"
					"-e\t\tExpire data at each cycle.\n"
					"-D\t\tFork to background\n"
					"-E\t\tPrint extended format of sflow data. for debugging purpose only.\n"
					"-4\t\tListen on IPv4 (default).\n"
					"-6\t\tListen on IPv6.\n"
					"-V\t\tPrint version and exit.\n"
					"-Z\t\tAdd timezone offset to filename.\n"
					, name);
} // End of usage

void kill_launcher(int pid) {
int stat, i;
pid_t ret;

	if ( pid == 0 )
		return;

	if ( launcher_alive ) {
		LogInfo("Signal launcher[%i] to terminate.", pid);
		kill(pid, SIGTERM);

		// wait for launcher to teminate
		for ( i=0; i<LAUNCHER_TIMEOUT; i++ ) {
			if ( !launcher_alive ) 
				break;
			sleep(1);
		}
		if ( i >= LAUNCHER_TIMEOUT ) {
			LogError("Launcher does not want to terminate - signal again");
			kill(pid, SIGTERM);
			sleep(1);
		}
	} else {
		LogError("launcher[%i] already dead", pid);
	}

	if ( (ret = waitpid (pid, &stat, 0)) == -1 ) {
		LogError("wait for launcher failed: %s %i", strerror(errno), ret);
	} else {
		if ( WIFEXITED(stat) ) {
			LogInfo("launcher exit status: %i", WEXITSTATUS(stat));
		}
		if (  WIFSIGNALED(stat) ) {
			LogError("launcher terminated due to signal %i", WTERMSIG(stat));
		}
	}

} // End of kill_launcher

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
			launcher_alive = 0;
			break;
		default:
			// ignore everything we don't know
			break;
	}

} /* End of IntHandler */

static void daemonize(void) {
int fd;
	switch (fork()) {
		case 0:
			// child
			break;
		case -1:
			// error
			LogError("fork() error: %s", strerror(errno));
			exit(EXIT_FAILURE);
			break;
		default:
			// parent
			_exit(EXIT_FAILURE);
	}

	if (setsid() < 0) {
		LogError("setsid() error: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	// Double fork
	switch (fork()) {
		case 0:
			// child
			break;
		case -1:
			// error
			LogError("fork() error: %s", strerror(errno));
			exit(EXIT_FAILURE);
			break;
		default:
			_exit(EXIT_FAILURE);
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
		exit(EXIT_FAILURE);
	}

	if ( userid ) {
		pw_entry = getpwnam(userid);
		newuid = pw_entry ? pw_entry->pw_uid : atol(userid);

		if ( newuid == 0 ) {
			LogError("Invalid user '%s", userid);
			exit(EXIT_FAILURE);
		}
	}

	if ( groupid ) {
		gr_entry = getgrnam(groupid);
		newgid = gr_entry ? gr_entry->gr_gid : atol(groupid);

		if ( newgid == 0 ) {
			LogError("Invalid group '%s'", groupid);
			exit(EXIT_FAILURE);
		}

		err = setgid(newgid);
		if ( err ) {
			LogError("Can't set group id %ld for group '%s': %s",   (long)newgid, groupid, strerror(errno));
			exit(EXIT_FAILURE);
		}

	}

	if ( newuid ) {
		err = setuid(newuid);
		if ( err ) {
			LogError("Can't set user id %ld for user '%s': %s",   (long)newuid, userid, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

} // End of SetPriv

#include "nffile_inline.c"
#include "collector_inline.c"

static void run(packet_function_t receive_packet, int socket, repeater_t *repeater,
	time_t twin, time_t t_begin, int report_seq, int use_subdirs, char *time_extension, int compress) {
FlowSource_t			*fs;
struct sockaddr_storage sf_sender;
socklen_t 	sf_sender_size = sizeof(sf_sender);
time_t 		t_start, t_now;
uint64_t	export_packets;
uint32_t	blast_cnt, blast_failures, ignored_packets;
ssize_t		cnt;
void 		*in_buff;
srecord_t	*commbuff;

	Init_sflow(verbose);

	in_buff  = malloc(NETWORK_INPUT_BUFF_SIZE);
	if ( !in_buff ) {
		LogError("malloc() buffer allocation error: %s", strerror(errno));
		return;
	}

	// init vars
	commbuff = (srecord_t *)shmem;

	// Init each netflow source output data buffer
	fs = FlowSource;
	while ( fs ) {

		// prepare file
		fs->nffile = OpenNewFile(fs->current, NULL, compress, NOT_ENCRYPTED);
		if ( !fs->nffile ) {
			return;
		}
		SetIdent(fs->nffile, fs->Ident);

		// init stat vars
		fs->bad_packets		= 0;
		fs->msecFirst	= 0xffffffffffffLL;
		fs->msecLast	= 0;

		// next source
		fs = fs->next;
	}

	export_packets = blast_cnt = blast_failures = 0;
	t_start = t_begin;

	cnt = 0;
	ignored_packets  = 0;

	// wake up at least at next time slot (twin) + 1s
	alarm(t_start + twin + 1 - time(NULL));
	/*
	 * Main processing loop:
	 * this loop, continues until done = 1, set by the signal handler
	 * The while loop will be breaked by the periodic file renaming code
	 * for proper cleanup 
	 */
	while ( 1 ) {
		struct timeval tv;
		int i;

		/* read next bunch of data into beginn of input buffer */
		if ( !done) {

#ifdef PCAP

			// Debug code to read from pcap file
			// cnt = NextPacket(in_buff, NETWORK_INPUT_BUFF_SIZE);
			cnt = receive_packet (socket, in_buff, NETWORK_INPUT_BUFF_SIZE , 0, 
				(struct sockaddr *)&sf_sender, &sf_sender_size);
			if ( cnt == -2 )
				done = 1;
#else

			cnt = recvfrom (socket, in_buff, NETWORK_INPUT_BUFF_SIZE , 0, 
				(struct sockaddr *)&sf_sender, &sf_sender_size);
#endif
			if ( cnt == -1 && errno != EINTR ) {
				LogError("ERROR: recvfrom: %s", strerror(errno));
				continue;
			}

			i = 0;
			while ( repeater[i].hostname && (i < MAX_REPEATERS)) {
				ssize_t len;
				len = sendto(repeater[i].sockfd, in_buff, cnt, 0, 
						(struct sockaddr *)&(repeater[i].addr), repeater[i].addrlen);
				if ( len < 0 ) {
					LogError("ERROR: sendto(): %s", strerror(errno));
				}
				i++;
			}
		}

		/* Periodic file renaming, if time limit reached or if we are done.  */
		gettimeofday(&tv, NULL);
		t_now = tv.tv_sec;

		if ( ((t_now - t_start) >= twin) || done ) {
			struct  tm *now;
			char	*subdir, fmt[MAXTIMESTRING];

			alarm(0);
			now = localtime(&t_start);
			strftime(fmt, sizeof(fmt), time_extension, now);

			// prepare sub dir hierarchy
			if ( use_subdirs ) {
				subdir = GetSubDir(now);
				if ( !subdir ) {
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
			while ( fs ) {
				char nfcapd_filename[MAXPATHLEN];
				char error[255];
				nffile_t *nffile = fs->nffile;

				// prepare filename
				if ( subdir ) {
					if ( SetupSubDir(fs->datadir, subdir, error, 255) ) {
						snprintf(nfcapd_filename, MAXPATHLEN-1, "%s/%s/nfcapd.%s", fs->datadir, subdir, fmt);
					} else {
						LogError("Ident: %s, Failed to create sub hier directories: %s", fs->Ident, error );
						// skip subdir - put flows directly into current directory
						snprintf(nfcapd_filename, MAXPATHLEN-1, "%s/nfcapd.%s", fs->datadir, fmt);
					}
				} else {
					snprintf(nfcapd_filename, MAXPATHLEN-1, "%s/nfcapd.%s", fs->datadir, fmt);
				}
				nfcapd_filename[MAXPATHLEN-1] = '\0';

				// update stat record
				if ( fs->msecLast == 0 ) {
					fs->msecFirst = 1000LL * (uint64_t)t_start;
					fs->msecLast  = 1000LL * (uint64_t)(t_start + twin);
				}
				nffile->stat_record->firstseen = fs->msecFirst;
				nffile->stat_record->lastseen  = fs->msecLast;

				// Flush Exporter Stat to file
				FlushExporterStats(fs);
				// Write Stat record and close file
				CloseUpdateFile(nffile);

				if ( rename(fs->current, nfcapd_filename) < 0 ) {
					LogError("Ident: %s, Can't rename dump file: %s", fs->Ident,  strerror(errno));
					LogError("Ident: %s, Serious Problem! Fix manually", fs->Ident);
					if ( launcher_pid )
						commbuff->failed = 1;

					// we do not update the books here, as the file failed to rename properly
					// otherwise the books may be wrong
				} else {
					struct stat	fstat;
					if ( launcher_pid )
						commbuff->failed = 0;

					// Update books
					stat(nfcapd_filename, &fstat);
					UpdateBooks(fs->bookkeeper, t_start, 512*fstat.st_blocks);
				}

				// log stats
				LogInfo("Ident: '%s' Flows: %llu, Packets: %llu, Bytes: %llu, Sequence Errors: %u, Bad Packets: %u", 
					fs->Ident, (unsigned long long)nffile->stat_record->numflows,
					(unsigned long long)nffile->stat_record->numpackets, 
					(unsigned long long)nffile->stat_record->numbytes, nffile->stat_record->sequence_failure, fs->bad_packets);

				// reset stat record
				fs->bad_packets = 0;
				fs->msecFirst	= 0xffffffffffffLL;
				fs->msecLast	= 0;


				if ( !done ) {
					fs->nffile = OpenNewFile(fs->current, fs->nffile, compress, NOT_ENCRYPTED);
					if ( !fs->nffile ) {
						LogError("killed due to fatal error: ident: %s", fs->Ident);
						break;
					}

					// Dump all extension maps to the buffer
					FlushStdRecords(fs);
				}

				// next flow source
				fs = fs->next;
			} // end of while (fs)

			// All flow sources updated - signal launcher if required
			if ( launcher_pid ) {
				// Signal launcher
		
				strncpy(commbuff->tstring, fmt, MAXTIMESTRING);
				commbuff->tstring[MAXTIMESTRING-1] = '\0';

				commbuff->tstamp = t_start;
				if ( subdir ) {
					snprintf(commbuff->fname, MAXPATHLEN-1, "%s/nfcapd.%s", subdir, fmt);
				} else {
					snprintf(commbuff->fname, MAXPATHLEN-1, "nfcapd.%s", fmt);
				}
				commbuff->fname[MAXPATHLEN-1] = '\0';

				if ( launcher_alive ) {
					LogInfo("Signal launcher");
					kill(launcher_pid, SIGHUP);
				} else 
					LogError("ERROR: Launcher died unexpectedly!");

			}
			
			LogInfo("Total ignored packets: %u", ignored_packets);
			ignored_packets = 0;

			if ( done )
				break;

			// update alarm for next cycle
			t_start += twin;
			/* t_start = filename time stamp: begin of slot
		 	* + twin = end of next time interval
		 	* + 1 = if no data is collected, this is at latest to act
		 	* - t_now = difference value to now
		 	*/
			alarm(t_start + twin + 1 - t_now);
		}

		/* check for error condition or done . errno may only be EINTR */
		if ( cnt < 0 ) {
			if ( periodic_trigger ) {	
				// alarm triggered, no new flow data 
				periodic_trigger = 0;
				continue;
			}
			if ( done ) 
				// signaled to terminate - exit from loop
				break;
			else {
				/* this should never be executed as it should be caught in other places */
				LogError("error condition in '%s', line '%d', cnt: %i", __FILE__, __LINE__ ,(int)cnt);
				continue;
			}
		}

		/* enough data? */
		if ( cnt == 0 )
			continue;

		// get flow source record for current packet, identified by sender IP address

		fs = GetFlowSource(&sf_sender);
		if ( fs == NULL ) {
			LogError("Skip UDP packet. Ignored packets so far %u packets", ignored_packets);
			ignored_packets++;
			continue;
		}


		/* check for too little data - cnt must be > 0 at this point */
		if ( cnt < sizeof(common_flow_header_t) ) {
			LogError("Ident: %s, Data length error: too little data for common netflow header. cnt: %i",fs->Ident, (int)cnt);
			fs->bad_packets++;
			continue;
		}
		fs->received = tv;

		/* Process data - have a look at the common header */
		Process_sflow(in_buff, cnt, fs);

		// each Process_xx function has to process the entire input buffer, therefore it's empty now.
		export_packets++;

	}

	if ( verbose && blast_failures ) {
		LogError("Total missed packets: %u", blast_failures);
	}
	free(in_buff);

	fs = FlowSource;
	while ( fs ) {
		DisposeFile(fs->nffile);
		fs->nffile= NULL;
		fs = fs->next;
	}

} /* End of run */

int main(int argc, char **argv) {
 
char	*bindhost, *datadir, *launch_process;
char	*userid, *groupid, *checkptr, *listenport, *mcastgroup;
char	*Ident, *time_extension, *pidfile;
packet_function_t receive_packet;
repeater_t repeater[MAX_REPEATERS];
FlowSource_t *fs;
struct sigaction act;
int		family, bufflen;
time_t 	twin, t_start;
int		sock, do_daemonize, expire, spec_time_extension, report_sequence;
int		subdir_index, compress;
int		c, i;
#ifdef PCAP
char	*pcap_file = NULL;
#endif

	receive_packet 	= recvfrom;
	verbose = do_daemonize = 0;
	bufflen  		= 0;
	family			= AF_UNSPEC;
	launcher_pid	= 0;
	launcher_alive	= 0;
	report_sequence	= 0;
	listenport		= DEFAULTSFLOWPORT;
	bindhost 		= NULL;
	mcastgroup		= NULL;
	pidfile			= NULL;
	launch_process	= NULL;
	userid 			= groupid = NULL;
	twin	 		= TIME_WINDOW;
	datadir	 		= NULL;
	subdir_index	= 0;
	time_extension	= "%Y%m%d%H%M";
	spec_time_extension = 0;
	expire			= 0;
	compress		= NOT_COMPRESSED;
	memset((void *)&repeater, 0, sizeof(repeater));
	for ( i = 0; i < MAX_REPEATERS; i++ ) {
		repeater[i].family = AF_UNSPEC;
	}
	Ident			= "none";
	FlowSource		= NULL;

	while ((c = getopt(argc, argv, "46ehEVI:DB:b:f:jl:n:N:p:J:P:R:S:T:t:x:ru:g:yzZ")) != EOF) {
		switch (c) {
			case 'h':
				usage(argv[0]);
				exit(EXIT_SUCCESS);
				break;
			case 'u':
				userid  = optarg;
				break;
			case 'g':
				groupid  = optarg;
				break;
			case 'e':
				expire = 1;
				break;
			case 'E':
				verbose = 1;
				break;
			case 'f': {
#ifdef PCAP
				struct stat	fstat;
				pcap_file = optarg;
				stat(pcap_file, &fstat);
				if ( !S_ISREG(fstat.st_mode) ) {
					LogError("Not a regular file: %s", pcap_file);
					exit(254);
				}
#else
				LogError("PCAP reader not compiled! Option ignored");
#endif
				} break;
			case 'V':
				printf("%s: Version: %s\n",argv[0], nfdump_version);
				exit(EXIT_SUCCESS);
				break;
			case 'D':
				do_daemonize = 1;
				break;
			case 'I':
				Ident = strdup(optarg);
				break;
			case 'n':
				if ( AddFlowSource(&FlowSource, optarg) != 1 ) 
					exit(EXIT_FAILURE);
				break;
			case 'N':
				if ( AddFlowSourceFromFile(&FlowSource, optarg) )
					exit(EXIT_FAILURE);
				break;
			case 'j':
				if ( compress ) {
					LogError("Use one compression: -z for LZO, -j for BZ2 or -y for LZ4 compression");
					exit(EXIT_FAILURE);
				}
				compress = BZ2_COMPRESSED;
				break;
			case 'y':
				if ( compress ) {
					LogError("Use one compression: -z for LZO, -j for BZ2 or -y for LZ4 compression");
					exit(EXIT_FAILURE);
				}
				compress = LZ4_COMPRESSED;
				break;
			case 'z':
				if ( compress ) {
					LogError("Use one compression: -z for LZO, -j for BZ2 or -y for LZ4 compression");
					exit(EXIT_FAILURE);
				}
				compress = LZO_COMPRESSED;
				break;
			case 'B':
				bufflen = strtol(optarg, &checkptr, 10);
				if ( (checkptr != NULL && *checkptr == 0) && bufflen > 0 )
					break;
				LogError("Argument error for -B");
				exit(EXIT_FAILURE);
			case 'b':
				bindhost = optarg;
				break;
			case 'J':
				mcastgroup = optarg;
				break;
			case 'p':
				listenport = optarg;
				break;
			case 'P': {
				if (strlen(optarg) > PATH_MAX) {
					LogError("Length error for pid fie");
					exit(EXIT_FAILURE);
				}
				char *dirc = strdup(optarg);
				char *basec = strdup(optarg);
				char *dirName  = dirname(dirc);
				char *fileName = basename(basec);
				dirName = realpath(dirName, NULL);
				if ( !dirName ) {
					LogError("realpath() pid file: %s", strerror(errno));
					exit(EXIT_FAILURE);
				}
				size_t len = strlen(dirName) + strlen(fileName) + 2;
				pidfile = malloc(len);
				if ( !pidfile ) {
					LogError("malloc() allocation error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
					exit(EXIT_FAILURE);
				}
				snprintf(pidfile, len, "%s/%s", dirName, fileName);
				free(dirc);
				free(basec);
				} break;
			case 'R': {
				char *port, *hostname;
				char *p = strchr(optarg, '/');
				int i = 0;
				if ( p ) { 
					*p++ = '\0';
					port = strdup(p);
				} else {
					port = DEFAULTSFLOWPORT;
				}
				hostname = strdup(optarg);
				while ( repeater[i].hostname && (i < MAX_REPEATERS) ) i++;
				if ( i == MAX_REPEATERS ) {
					LogError("Too many packet repeaters! Max: %i repeaters allowed", MAX_REPEATERS);
					exit(EXIT_FAILURE);
				}
				repeater[i].hostname = hostname;
				repeater[i].port 	 = port;

				break; }
			case 'r':
				report_sequence = 1;
				break;
			case 'l':
				if ( !CheckPath(optarg, S_IFDIR) )
					exit(EXIT_FAILURE);

				datadir = realpath(optarg, NULL);
				if ( !datadir ) {
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
				if ( twin < 2 ) {
					LogError("time interval <= 2s not allowed");
					exit(EXIT_FAILURE);
				}
				if (twin < 60) {
					time_extension	= "%Y%m%d%H%M%S";
				}
				break;
			case 'x':
				launch_process = optarg;
				break;
			case 'Z':
				time_extension	= "%Y%m%d%H%M%z";
				spec_time_extension = 1;
				break;
			case '4':
				if ( family == AF_UNSPEC )
					family = AF_INET;
				else {
					LogError("ERROR, Accepts only one protocol IPv4 or IPv6");
					exit(EXIT_FAILURE);
				}
				break;
			case '6':
				if ( family == AF_UNSPEC )
					family = AF_INET6;
				else {
					LogError("ERROR, Accepts only one protocol IPv4 or IPv6");
					exit(EXIT_FAILURE);
				}
				break;
			default:
				usage(argv[0]);
				exit(EXIT_FAILURE);
		}
	}

	if (argc - optind > 1) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	} 

	if ( expire && spec_time_extension ) {
		LogError("ERROR, -Z timezone extension breaks expire -e");
		exit(EXIT_FAILURE);
	}

	if ( FlowSource == NULL && datadir == NULL ) {
		LogError("ERROR, Missing -n (-l/-I) source definitions");
		exit(EXIT_FAILURE);
	}

	if ( FlowSource == NULL && !AddDefaultFlowSource(&FlowSource, Ident, datadir) )
		exit(EXIT_FAILURE);

	if ( bindhost && mcastgroup ) {
		LogError("ERROR, -b and -j are mutually exclusive");
		exit(EXIT_FAILURE);
	}

	if ( !InitLog(do_daemonize, argv[0], SYSLOG_FACILITY, verbose) ) {
		exit(EXIT_FAILURE);
	}

	if ( !Init_nffile(NULL) )
		exit(254);

#ifdef PCAP
	// Debug code to read from pcap file
	sock = 0;
	if ( pcap_file ) {
		printf("Setup pcap reader");
		setup_packethandler(pcap_file, NULL);
		receive_packet 	= NextPacket;
	} else 
#endif
	if ( mcastgroup ) 
		sock = Multicast_receive_socket (mcastgroup, listenport, family, bufflen);
	else 
		sock = Unicast_receive_socket(bindhost, listenport, family, bufflen );

	if ( sock == -1 ) {
		LogError("Terminated due to errors");
		exit(EXIT_FAILURE);
	}

	i = 0;
	while ( repeater[i].hostname && (i < MAX_REPEATERS) ) {
		repeater[i].sockfd = Unicast_send_socket (repeater[i].hostname, repeater[i].port, repeater[i].family, bufflen, 
											&repeater[i].addr, &repeater[i].addrlen );
		if ( repeater[i].sockfd <= 0 )
			exit(EXIT_FAILURE);
		LogInfo("Replay flows to host: %s port: %s", repeater[i].hostname, repeater[i].port);
		i++;
	}

	SetPriv(userid, groupid);

	if ( subdir_index && !InitHierPath(subdir_index) ) {
		close(sock);
		exit(EXIT_FAILURE);
	}

	t_start = time(NULL);
	t_start = t_start - ( t_start % twin);

	if ( do_daemonize ) {
		verbose = 0;
		daemonize();
	}

	if ( pidfile ) {
		if ( check_pid(pidfile) != 0 || write_pid(pidfile) == 0 )
		exit(EXIT_FAILURE);
	}

	done = 0;
	if ( launch_process || expire ) {
		// for efficiency reason, the process collecting the data
		// and the process launching processes, when a new file becomes
		// available are separated. Communication is done using signals
		// as well as shared memory
		// prepare shared memory
		shmem = mmap(0, sizeof(srecord_t), PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
		if ( shmem == MAP_FAILED ) {
			LogError("mmap() error: %s", strerror(errno));
			close(sock);
			exit(EXIT_FAILURE);
		}

		launcher_pid = fork();
		switch (launcher_pid) {
			case 0:
				// child
				close(sock);
				launcher(shmem, FlowSource, launch_process, expire);
				exit(EXIT_SUCCESS);
				break;
			case -1:
				LogError("fork() error: %s", strerror(errno));
				if ( pidfile )
					remove_pid(pidfile);
				exit(EXIT_FAILURE);
				break;
			default:
				// parent
			launcher_alive = 1;
			LogInfo("Launcher[%i] forked", launcher_pid);
		}
	}

	fs = FlowSource;
	while ( fs ) {
		if ( InitBookkeeper(&fs->bookkeeper, fs->datadir, getpid(), launcher_pid) != BOOKKEEPER_OK ) {
			LogError("initialize bookkeeper failed.");

			// release all already allocated bookkeepers
			fs = FlowSource;
			while ( fs && fs->bookkeeper ) {
				ReleaseBookkeeper(fs->bookkeeper, DESTROY_BOOKKEEPER);
				fs = fs->next;
			}
			close(sock);
			if ( launcher_pid )
				kill_launcher(launcher_pid);
			if ( pidfile )
				remove_pid(pidfile);
			exit(EXIT_FAILURE);
		}

		fs = fs->next;
	}

	/* Signal handling */
	memset((void *)&act,0,sizeof(struct sigaction));
	act.sa_handler = IntHandler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGCHLD, &act, NULL);

	LogInfo("Startup.");
	run(receive_packet, sock, repeater, twin, t_start, report_sequence, subdir_index, 
		time_extension, compress);
	close(sock);
	kill_launcher(launcher_pid);

	fs = FlowSource;
	while ( fs && fs->bookkeeper ) {
		dirstat_t 	*dirstat;
		// if we do not auto expire and there is a stat file, update the stats before we leave
		if ( expire == 0 && ReadStatInfo(fs->datadir, &dirstat, LOCK_IF_EXISTS) == STATFILE_OK ) {
			UpdateBookStat(dirstat, fs->bookkeeper);
			WriteStatInfo(dirstat);
			LogInfo("Updating statinfo in directory '%s'", datadir);
		}

		ReleaseBookkeeper(fs->bookkeeper, DESTROY_BOOKKEEPER);
		fs = fs->next;
	}

	LogInfo("Terminating sfcapd.");
	EndLog();

	if ( pidfile )
		remove_pid(pidfile);

	return 0;

} /* End of main */
