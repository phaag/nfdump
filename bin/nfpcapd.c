/*
 *  Copyright (c) 2014, Peter Haag
 *  Copyright (c) 2013, Peter Haag
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
 *  $Author$
 *
 *  $Id$
 *
 *  $LastChangedRevision$
 *  
 */

/* $Id: pcapd.c 2778 2012-03-19 09:23:26Z roethlis $ */

#include "config.h"

#ifdef HAVE_FEATURES_H
#include <features.h>
#endif

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdarg.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <string.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>


#ifdef HAVE_NET_BPF_H
# include <net/bpf.h>
#else 
#ifdef HAVE_PCAP_BPF_H
# include <pcap-bpf.h>
#else
# error missing bpf header
#endif 
#endif 

#include <pcap.h>

#include "util.h"
#include "nffile.h"
#include "nfx.h"
#include "nf_common.h"
#include "nfnet.h"
#include "flist.h"
#include "nfstatfile.h"
#include "bookkeeper.h"
#include "nfxstat.h"
#include "collector.h"
#include "exporter.h"
#include "rbtree.h"
#include "ipfrag.h"

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

#include "flowtree.h"
#include "netflow_pcap.h"
#include "pcaproc.h"

#define TIME_WINDOW     300
#define SNAPLEN         200
#define PROMISC         1
#define TIMEOUT         500
#define FILTER          ""
#define DEFAULT_DIR     "/var/tmp"

#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL   113
#endif

#ifndef DEVEL
#   define dbg_printf(...) /* printf(__VA_ARGS__) */
#else
#   define dbg_printf(...) printf(__VA_ARGS__)
#endif

int verbose = 0;

/*
 * global static var: used by interrupt routine
 */
#define PCAP_DUMPFILE "pcap.current"

static const char *nfdump_version = VERSION;

static int launcher_alive, periodic_trigger, launcher_pid;
static pthread_mutex_t  m_done  = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t terminate = PTHREAD_COND_INITIALIZER;
static pthread_key_t buffer_key;

uint32_t linktype;
uint32_t linkoffset;

// Common thread info struct
typedef struct thread_info_s {
	pthread_t tid;
	int		  done;
	int		  exit;
} thread_info_t;

typedef struct p_pcap_flush_thread_args_s {
	// common thread info struct
	pthread_t tid;
	int		  done;
	int		  exit;

	// the parent
	pthread_t parent;

	// arguments
	int		subdir_index;
	char	*pcap_datadir;
	pcap_dev_t *pcap_dev; 
	pcapfile_t *pcapfile;
} p_pcap_flush_thread_args_t;

typedef struct p_packet_thread_args_s {
	// common thread info struct
	pthread_t tid;
	int		  done;
	int		  exit;

	// the parent
	pthread_t parent;

	// arguments
	NodeList_t *NodeList;		// push new nodes into this list
	pcap_dev_t *pcap_dev; 
	time_t	t_win;
	int		subdir_index;
	char	*pcap_datadir;
	int		live;
} p_packet_thread_args_t;

typedef struct p_flow_thread_args_s {
	// common thread info struct
	pthread_t tid;
	int		  done;
	int		  exit;

	// the parent
	pthread_t parent;

	// arguments
	NodeList_t *NodeList;		// pop new nodes from this list
	FlowSource_t *fs;
	time_t	t_win;
	int		subdir_index;
	int		compress;
} p_flow_thread_args_t;

/*
 * Function prototypes
 */
static void usage(char *name);

static void daemonize(void);

static void Interrupt_handler(int sig);

static void SetPriv(char *userid, char *groupid );

static pcap_dev_t *setup_pcap_live(char *device, char *filter, int snaplen);

static pcap_dev_t *setup_pcap_Ffile(FILE *fp, char *filter, int snaplen);

static pcap_dev_t *setup_pcap_file(char *pcap_file, char *filter, int snaplen);

static void WaitDone(void);

static void SignalThreadTerminate(thread_info_t *thread_info, pthread_cond_t *thread_cond );

static void *p_pcap_flush_thread(void *thread_data);

static void *p_flow_thread(void *thread_data);

static void *p_packet_thread(void *thread_data);

/*
 * Functions
 */

static void usage(char *name) {
	printf("usage %s [options] [\"pcap filter\"]\n"
					"-h\t\tthis text you see right here\n"
					"-u userid\tChange user to username\n"
					"-g groupid\tChange group to groupname\n"
					"-i device\tspecify a device\n"
					"-r pcapfile\tspecify a file to read from\n"
					"-B cache buckets\tset the number of cache buckets. (default 1048576)\n"
					"-s snaplen\tset the snapshot length\n"
					"-l flowdir \tset the flow output directory. (no default) \n"
					"-l pcapdir \tset the pcapdir directory. (optional) \n"
					"-S subdir\tSub directory format. see nfcapd(1) for format\n"
					"-I Ident\tset the ident string for stat file. (default 'none')\n"
					"-P pidfile\tset the PID file\n"
					"-t time frame\tset the time window to rotate pcap/nfcapd file\n"
					"-z\t\tCompress flows in output file.\n"
					"-E\t\tPrint extended format of netflow data. for debugging purpose only.\n"
					"-T\t\tInclude extension tags in records.\n"
					"-D\t\tdetach from terminal (daemonize)\n"
	, name);
} // End of usage

static void Interrupt_handler(int sig) {
pthread_t tid		 = pthread_self();
thread_info_t	*thread_info;

	LogInfo("[%lu] Signal handler: %i", (long unsigned)tid, sig);
	thread_info = (thread_info_t *)pthread_getspecific(buffer_key);
	if ( !thread_info ) {
		LogError("[%lu] Interrupt_handler() failed to get thread specific data block\n", (long unsigned)tid);
	} else {
		if ( thread_info->tid != tid ) {
			LogError("[%lu] Interrupt_handler() missmatch tid in thread_info\n", (long unsigned)tid);
		} else {
			thread_info->done = 1;
		}
	}

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

static pcap_dev_t *setup_pcap_live(char *device, char *filter, int snaplen) {
pcap_t 		*handle;
pcap_dev_t	*pcap_dev;
char errbuf[PCAP_ERRBUF_SIZE];
bpf_u_int32 mask;		/* Our netmask */
bpf_u_int32 net;		/* Our IP */
struct bpf_program filter_code;	
uint32_t	linkoffset, linktype;

	dbg_printf("Enter function: %s\n", __FUNCTION__);

	if (device == NULL) {
		device = pcap_lookupdev(errbuf);
		if (device == NULL) {
			LogError("Couldn't find default device: %s", errbuf);
			return NULL;
		}
	}

	/* Find the properties for the device */
	if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
		LogError("Couldn't get netmask for device %s: %s", device, errbuf);
		net = 0;
		mask = 0;
	}

	/*
	 *  Open the packet capturing device with the following values:
	 *
	 *  SNAPLEN: User defined or 200 bytes
	 *  PROMISC: on
	 *  The interface needs to be in promiscuous mode to capture all
	 *  network traffic on the localnet.
	 *  TIMEOUT: 500ms
	 *  A 500 ms timeout is probably fine for most networks.  For
	 *  architectures that support it, you might want tune this value
	 *  depending on how much traffic you're seeing on the network.
	 */
	handle = pcap_open_live(device, snaplen, PROMISC, TIMEOUT, errbuf);
	if (handle == NULL) {
		LogError("Couldn't open device %s: %s", device, errbuf);
		return NULL;
	}

	// XXX
	// int pcap_set_buffer_size(pcap_t *p, int buffer_size);

	if ( filter ) {
		/* Compile and apply the filter */
		if (pcap_compile(handle, &filter_code, filter, 0, net) == -1) {
			LogError("Couldn't parse filter %s: %s", filter, pcap_geterr(handle));
			return NULL;
		}
		if (pcap_setfilter(handle, &filter_code) == -1) {
			LogError("Couldn't install filter %s: %s", filter, pcap_geterr(handle));
			return NULL;
		}
	}

	pcap_dev = (pcap_dev_t *)calloc(1, sizeof(pcap_dev_t));
	if ( !pcap_dev ) {
		LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return NULL;
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
			return NULL;
	}

	pcap_dev->handle	 = handle;
	pcap_dev->snaplen	 = snaplen;
	pcap_dev->linkoffset = linkoffset;
	pcap_dev->linktype 	 = linktype;

	return pcap_dev;

} // End of setup_pcap_live

static pcap_dev_t *setup_pcap_file(char *pcap_file, char *filter, int snaplen) {
FILE *fp;

	fp = fopen(pcap_file, "rb");
	if ( !fp ) {
		LogError("Couldn't open file: %s: %s", pcap_file, strerror(errno));
		return NULL;
	}
	return setup_pcap_Ffile(fp, filter, snaplen);

} // End of setup_pcap_file

static pcap_dev_t *setup_pcap_Ffile(FILE *fp, char *filter, int snaplen) {
pcap_t 		*handle;
pcap_dev_t	*pcap_dev;
char errbuf[PCAP_ERRBUF_SIZE];
uint32_t	linkoffset, linktype;

	dbg_printf("Enter function: %s\n", __FUNCTION__);
	
	if ( !fp ) 
		return NULL;

	handle = pcap_fopen_offline(fp, errbuf);
	if (handle == NULL) {
		LogError("Couldn't attach FILE handle %s", errbuf);
		return NULL;
	}

	if ( filter ) {
		struct bpf_program filter_code;
		bpf_u_int32 netmask = 0;
		// Compile and apply the filter
		if (pcap_compile(handle, &filter_code, filter, 0, netmask) == -1) {
			LogError("Couldn't parse filter %s: %s", filter, pcap_geterr(handle));
			return NULL;
		}
		if (pcap_setfilter(handle, &filter_code) == -1) {
			LogError("Couldn't install filter %s: %s", filter, pcap_geterr(handle));
			return NULL;
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
			return NULL;
	}

	pcap_dev = (pcap_dev_t *)calloc(1, sizeof(pcap_dev_t));
	if ( !pcap_dev ) {
		LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return NULL;
	}	

	pcap_dev->handle	 = handle;
	pcap_dev->snaplen	 = snaplen;
	pcap_dev->linkoffset = linkoffset;
	pcap_dev->linktype	 = linktype;

	return pcap_dev;

} // End of setup_pcap_file

static void SignalThreadTerminate(thread_info_t *thread_info, pthread_cond_t *thread_cond ) {

	if ( !thread_info->done ) {
		dbg_printf("Signal thread[%lu] to terminate\n", (long unsigned)thread_info->tid);
    	if ( pthread_kill(thread_info->tid, SIGUSR2) != 0 ) {
			dbg_printf("Failed to signal thread[%lu]\n", (long unsigned)thread_info->tid);
		} 

		// in case of a condition - signal condition
		if ( thread_cond ) 
			pthread_cond_signal(thread_cond);

	} else {
		dbg_printf("thread[%lu] gone already\n", (long unsigned)thread_info->tid);
	}

   	if( pthread_join(thread_info->tid, NULL) == 0 ) {
       	dbg_printf("thread %lu joined\n", (long unsigned)thread_info->tid);
	} else {
       	dbg_printf("thread %lu no join\n", (long unsigned)thread_info->tid);
	}

	LogInfo("Exit status thread[%lu]: %i", thread_info->tid, thread_info->exit);

} // End of SignalThreadEnd

__attribute__((noreturn)) static void *p_flow_thread(void *thread_data) {
// argument dispatching
p_flow_thread_args_t *args = (p_flow_thread_args_t *)thread_data;
time_t t_win				 = args->t_win;
int subdir_index			 = args->subdir_index;
int compress				 = args->compress;
FlowSource_t *fs			 = args->fs;

// locals
time_t t_start, t_clock, t_udp_flush;
int err, done;

	done 	   = 0;
	args->done = 0;
	args->exit = 0;

	err = pthread_setspecific( buffer_key, (void *)args );
	if ( err ) {
		LogError("[%lu] pthread_setspecific() error in %s line %d: %s\n", 
			(long unsigned)args->tid, __FILE__, __LINE__, strerror(errno) );
		args->done = 1;
		args->exit = 255;
   		pthread_kill(args->parent, SIGUSR1);
		pthread_exit((void *)args);
	}

	if ( !Init_pcap2nf() ) {
		args->done = 1;
		args->exit = 255;
   		pthread_kill(args->parent, SIGUSR1);
		pthread_exit((void *)args);
	}

	// prepare file
	fs->nffile = OpenNewFile(fs->current, NULL, compress, 0, NULL);
	if ( !fs->nffile ) {
		args->done = 1;
		args->exit = 255;
   		pthread_kill(args->parent, SIGUSR1);
		pthread_exit((void *)args);
	}
	fs->xstat = NULL;

	// init vars
	fs->bad_packets		= 0;
	fs->first_seen      = 0xffffffffffffLL;
	fs->last_seen 		= 0;

	t_start = 0;
	t_clock = 0;
	t_udp_flush = 0;
	while ( 1 ) {
		struct FlowNode	*Node;

		Node = Pop_Node(args->NodeList, &args->done);
		if ( Node ) {
			t_clock = Node->t_last.tv_sec;
			dbg_printf("p_flow_thread() Next Node\n");
		} else {
			done = args->done;
			dbg_printf("p_flow_thread() NULL Node\n");
		}

		if ( t_start == 0 ) {
			t_udp_flush = t_start = t_clock - (t_clock % t_win);
		}

		if (((t_clock - t_start) >= t_win) || done) { /* rotate file */
			struct tm *when;
			nffile_t *nffile;
			char FullName[MAXPATHLEN];
			char netflowFname[128];
			char error[256];
			char *subdir;

			// flush all flows to disk
			DumpNodeStat();
			uint32_t NumFlows  = Flush_FlowTree(fs);

			when = localtime(&t_start);
			nffile = fs->nffile;

			// prepare sub dir hierarchy
			if ( subdir_index ) {
				subdir = GetSubDir(when);
				if ( !subdir ) {
					// failed to generate subdir path - put flows into base directory
					LogError("Failed to create subdir path!");
				
					// failed to generate subdir path - put flows into base directory
					subdir = NULL;
					snprintf(netflowFname, 127, "nfcapd.%i%02i%02i%02i%02i",
						when->tm_year + 1900, when->tm_mon + 1, when->tm_mday, when->tm_hour, when->tm_min);
				} else {
					snprintf(netflowFname, 127, "%s/nfcapd.%i%02i%02i%02i%02i", subdir,
						when->tm_year + 1900, when->tm_mon + 1, when->tm_mday, when->tm_hour, when->tm_min);
				}

			} else {
				subdir = NULL;
				snprintf(netflowFname, 127, "nfcapd.%i%02i%02i%02i%02i",
					when->tm_year + 1900, when->tm_mon + 1, when->tm_mday, when->tm_hour, when->tm_min);
			}
			netflowFname[127] = '\0';
	
			if ( subdir && !SetupSubDir(fs->datadir, subdir, error, 255) ) {
				// in this case the flows get lost! - the rename will fail
				// but this should not happen anyway, unless i/o problems, inode problems etc.
				LogError("Ident: %s, Failed to create sub hier directories: %s", fs->Ident, error );
			}

			if ( nffile->block_header->NumRecords ) {
				// flush current buffer to disc
				if ( WriteBlock(nffile) <= 0 )
					LogError("Ident: %s, failed to write output buffer to disk: '%s'" , fs->Ident, strerror(errno));
			} // else - no new records in current block

			// prepare full filename
			snprintf(FullName, MAXPATHLEN-1, "%s/%s", fs->datadir, netflowFname);
			FullName[MAXPATHLEN-1] = '\0';

			// update stat record
			// if no flows were collected, fs->last_seen is still 0
			// set first_seen to start of this time slot, with twin window size.
			if ( fs->last_seen == 0 ) {
				fs->first_seen = (uint64_t)1000 * (uint64_t)t_start;
				fs->last_seen  = (uint64_t)1000 * (uint64_t)(t_start + t_win);
			}
			nffile->stat_record->first_seen = fs->first_seen/1000;
			nffile->stat_record->msec_first	= fs->first_seen - nffile->stat_record->first_seen*1000;
			nffile->stat_record->last_seen 	= fs->last_seen/1000;
			nffile->stat_record->msec_last	= fs->last_seen - nffile->stat_record->last_seen*1000;
	
			// Flush Exporter Stat to file
			FlushExporterStats(fs);
			// Close file
			CloseUpdateFile(nffile, fs->Ident);
	
			// if rename fails, we are in big trouble, as we need to get rid of the old .current file
			// otherwise, we will loose flows and can not continue collecting new flows
			if ( !RenameAppend(fs->current, FullName) ) {
				LogError("Ident: %s, Can't rename dump file: %s", fs->Ident,  strerror(errno));
				LogError("Ident: %s, Serious Problem! Fix manually", fs->Ident);
	/* XXX
				if ( launcher_pid )
					commbuff->failed = 1;
	*/
				// we do not update the books here, as the file failed to rename properly
				// otherwise the books may be wrong
			} else {
				struct stat	fstat;
	/* XXX
				if ( launcher_pid )
					commbuff->failed = 0;
	*/
				// Update books
				stat(FullName, &fstat);
				UpdateBooks(fs->bookkeeper, t_start, 512*fstat.st_blocks);
			}

			LogInfo("Ident: '%s' Flows: %llu, Packets: %llu, Bytes: %llu, Max Flows: %u", 
				fs->Ident, (unsigned long long)nffile->stat_record->numflows, (unsigned long long)nffile->stat_record->numpackets, 
				(unsigned long long)nffile->stat_record->numbytes, NumFlows);

			// reset stats
			fs->bad_packets = 0;
			fs->first_seen  = 0xffffffffffffLL;
			fs->last_seen 	= 0;
	
			// Dump all extension maps and exporters to the buffer
			FlushStdRecords(fs);

			if ( done ) 
				break;
	
			t_start = t_clock - (t_clock % t_win);

			nffile = OpenNewFile(fs->current, nffile, compress, 0, NULL);
			if ( !nffile ) {
				LogError("Fatal: OpenNewFile() failed for ident: %s", fs->Ident);
				args->done = 1;
				args->exit = 255;
   				pthread_kill(args->parent, SIGUSR1);
				break;
			}
		}

		if (((t_clock - t_udp_flush) >= 10) || !done) { /* flush inactive UDP list */
			UDPexpire(fs, t_clock - 10 );
			t_udp_flush = t_clock;
		}

		if ( Node->fin != SIGNAL_NODE )
			// Process the Node
			ProcessFlowNode(fs, Node);

	}

	while ( fs ) {
		DisposeFile(fs->nffile);
		fs = fs->next;
	}
	LogInfo("Terminating flow processng: exit: %i", args->exit);
	dbg_printf("End flow thread[%lu]\n", (long unsigned)args->tid);

	pthread_exit((void *)args);
	/* NOTREACHED */

} // End of p_flow_thread

__attribute__((noreturn)) static void *p_pcap_flush_thread(void *thread_data) {
// argument dispatching
p_pcap_flush_thread_args_t *args = (p_pcap_flush_thread_args_t *)thread_data;
char *pcap_datadir	 = args->pcap_datadir;
pcap_dev_t *pcap_dev = args->pcap_dev;
pcapfile_t *pcapfile = args->pcapfile;
char pcap_dumpfile[MAXPATHLEN];
int err;
int runs = 0;

	dbg_printf("New flush thread[%lu]\n", (long unsigned)args->tid);
	args->done = 0;
	args->exit = 0;

	err = pthread_setspecific( buffer_key, (void *)args );
	if ( err ) {
		LogError("[%lu] pthread_setspecific() error in %s line %d: %s\n", 
			(long unsigned)args->tid, __FILE__, __LINE__, strerror(errno) );
		args->done = 1;
		args->exit = 255;
   		pthread_kill(args->parent, SIGUSR1);
		pthread_exit((void *)args);
	}

	snprintf(pcap_dumpfile, MAXPATHLEN-1, "%s/%s.%lu", pcap_datadir , PCAP_DUMPFILE, (unsigned long)getpid() );
	pcapfile = OpenNewPcapFile(pcap_dev->handle, pcap_dumpfile, pcapfile);
	if ( !pcapfile ) {
		args->done = 1;
		args->exit = 255;
   		pthread_kill(args->parent, SIGUSR1);
		pthread_exit((void *)args);
		/* NOTREACHED */
	}


	// wait for alternate buffer to be ready to flush
	while ( 1 ) {
    	pthread_mutex_lock(&pcapfile->m_pbuff);
    	while ( pcapfile->alternate_size == 0 && !args->done ) {
        	pthread_cond_wait(&pcapfile->c_pbuff, &pcapfile->m_pbuff);
    	}
		dbg_printf("Flush cycle\n");
		runs++;
		// try to flush alternate buffer
		if ( pcapfile->alternate_size ) {
			// flush alternate buffer
			dbg_printf("Flush alternate\n");
    		if ( write(pcapfile->pfd, (void *)pcapfile->alternate_buffer, pcapfile->alternate_size) <= 0 ) {
        		LogError("write() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
    		}
			pcapfile->alternate_size = 0;
		}

		// if we are done, try to flsuh main data buffer
		if ( args->done && pcapfile->data_size ) {
			dbg_printf("Done: Flush all buffers\n");
			// flush alternate buffer
    		if ( write(pcapfile->pfd, (void *)pcapfile->data_buffer, pcapfile->data_size) <= 0 ) {
        		LogError("write() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
    		}
			pcapfile->data_size = 0;
			pcapfile->data_ptr  = pcapfile->data_buffer;
		}

		// check if we need to rotate/close the file
		if ( args->done || pcapfile->t_CloseRename ) { /* rotate file */
			struct tm *when;
			char FullName[MAXPATHLEN];
			char pcapFname[128];
			char error[256];
			char *subdir;
			int err;

			dbg_printf("Flush rotate file\n");
			when = localtime(&pcapfile->t_CloseRename);
			pcapfile->t_CloseRename = 0;

			// prepare sub dir hierarchy
			if ( args->subdir_index ) {
				subdir = GetSubDir(when);
				if ( !subdir ) {
					// failed to generate subdir path - put flows into base directory
					LogError("Failed to create subdir path!");
				
					// failed to generate subdir path - put flows into base directory
					subdir = NULL;
					snprintf(pcapFname, 127, "pcapd.%i%02i%02i%02i%02i",
						when->tm_year + 1900, when->tm_mon + 1, when->tm_mday, when->tm_hour, when->tm_min);
				} else {
					snprintf(pcapFname, 127, "%s/pcapd.%i%02i%02i%02i%02i", subdir,
						when->tm_year + 1900, when->tm_mon + 1, when->tm_mday, when->tm_hour, when->tm_min);
				}

			} else {
				subdir = NULL;
				snprintf(pcapFname, 127, "pcapd.%i%02i%02i%02i%02i",
					when->tm_year + 1900, when->tm_mon + 1, when->tm_mday, when->tm_hour, when->tm_min);
			}
			pcapFname[127] 	  = '\0';
	
			if ( subdir && !SetupSubDir(pcap_datadir, subdir, error, 255) ) {
				// in this case the flows get lost! - the rename will fail
				// but this should not happen anyway, unless i/o problems, inode problems etc.
				LogError("p_packet_thread() Failed to create sub hier directories: %s", error );
			}

			// prepare full filename
			snprintf(FullName, MAXPATHLEN-1, "%s/%s", pcap_datadir, pcapFname);
			FullName[MAXPATHLEN-1] = '\0';
	
			ClosePcapFile(pcapfile);
			err = rename(pcap_dumpfile, FullName);
			if (err) {
				LogError("rename() pcap failed in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
			}
			dbg_printf("Rotate file: %s -> %s\n", pcap_dumpfile, FullName);

			if ( args->done ) {
    			pthread_mutex_unlock(&pcapfile->m_pbuff);
				pthread_cond_signal(&pcapfile->c_pbuff);
				break;
			}

			// open new files
			pcapfile = OpenNewPcapFile(pcap_dev->handle, pcap_dumpfile, pcapfile);
			if (!pcapfile) {
				args->done = 1;
				args->exit = 255;
   				pthread_kill(args->parent, SIGUSR1);
    			pthread_mutex_unlock(&pcapfile->m_pbuff);
				pthread_cond_signal(&pcapfile->c_pbuff);
				break;
			}

		}
		dbg_printf("Flush cycle done\n");
    	pthread_mutex_unlock(&pcapfile->m_pbuff);
		pthread_cond_signal(&pcapfile->c_pbuff);
	}

	dbg_printf("End flush thread[%lu]: %i runs\n", (long unsigned)args->tid, runs);
	pthread_exit((void *)args);
	/* NOTREACHED */

} // End of p_pcap_flush_thread

__attribute__((noreturn)) static void *p_packet_thread(void *thread_data) {
// argument dispatching
p_packet_thread_args_t *args = (p_packet_thread_args_t *)thread_data;
pcap_dev_t *pcap_dev = args->pcap_dev;
time_t t_win		 = args->t_win;
char *pcap_datadir 	 = args->pcap_datadir;
int subdir_index	 = args->subdir_index;
int live		 	 = args->live;
// locals
p_pcap_flush_thread_args_t p_flush_thread_args;
pcapfile_t *pcapfile;
time_t t_start;
int err;

	dbg_printf("New packet thread[%lu]\n", (long unsigned)args->tid);
	args->done = 0;
	args->exit = 0;

	err = pthread_setspecific( buffer_key, (void *)args );
	if ( err ) {
		LogError("[%lu] pthread_setspecific() error in %s line %d: %s\n", 
			(long unsigned)args->tid, __FILE__, __LINE__, strerror(errno) );
		args->done = 1;
		args->exit = 255;
   		pthread_kill(args->parent, SIGUSR1);
		pthread_exit((void *)args);
		/* NOTREACHED */
	}

	/* start flush and pcap file handler thread */
	if ( pcap_datadir ) {
		// just allocate pcapfile and buffers - we need to share pcapfile
		pcapfile = OpenNewPcapFile(pcap_dev->handle, NULL, NULL);
		if ( !pcapfile ) {
			args->done = 1;
			args->exit = 255;
   			pthread_kill(args->parent, SIGUSR1);
			pthread_exit((void *)args);
			/* NOTREACHED */
		}

		p_flush_thread_args.done 	 	 = 0;
		p_flush_thread_args.exit 	 	 = 0;
		p_flush_thread_args.parent 	 	 = args->tid;
		p_flush_thread_args.pcap_dev 	 = args->pcap_dev;
		p_flush_thread_args.subdir_index = subdir_index;
		p_flush_thread_args.pcap_datadir = pcap_datadir;
		p_flush_thread_args.pcapfile 	 = pcapfile;

		err = pthread_create(&p_flush_thread_args.tid, NULL, p_pcap_flush_thread, (void *)&p_flush_thread_args);
		if ( err ) {
			LogError("pthread_create() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			args->done = 1;
			args->exit = 255;
   			pthread_kill(args->parent, SIGUSR1);
			pthread_exit((void *)args);
		}
		dbg_printf("Started flush thread[%lu]\n", (long unsigned)p_flush_thread_args.tid);

	} else {
		pcapfile = NULL;
	}

	err = 0;
	t_start = 0;
	while ( 1 ) {
		struct pcap_pkthdr *hdr; 
		const u_char 	   *data;
		struct timeval tv;
		time_t t_clock;
		int ret;

		if ( !args->done ) {
			ret = pcap_next_ex(pcap_dev->handle, &hdr, &data);
			t_clock = 0;
			switch (ret) {
				case 1: {
					// packet read ok
					t_clock = hdr->ts.tv_sec;
					// process packet for flow cache
					ProcessPacket(args->NodeList, pcap_dev, hdr, data);
					if ( pcap_datadir ) {
						// keep the packet
						if (((t_clock - t_start) >= t_win)) { 
							// first packet or rotate file
							if ( t_start != 0 ) {
								RotateFile(pcapfile, t_start, live);
							}
							// if first packet - set t_start here
							t_start = t_clock - (t_clock % t_win);
						} 
						PcapDump(pcapfile, hdr, data);
					} 
					} break;
				case 0: {
					// live capture idle cycle
					dbg_printf("pcap_next_ex() read live - timeout\n");	
					gettimeofday(&tv, NULL);
					t_clock = tv.tv_sec;
					if ((t_clock - t_start) >= t_win) { /* rotate file */
						if ( t_start ) {
							// if not first packet, where t_start = 0
							struct FlowNode	*Node = New_Node();
							Node->t_first = tv;
							Node->t_last  = tv;
							Node->fin  	  = SIGNAL_NODE;
							Push_Node(args->NodeList, Node);
							if ( pcap_datadir )
							// keep the packet
								RotateFile(pcapfile, t_start, live);
							LogInfo("Packet processing stats: Total: %u, Skipped: %u, Unknown: %u, Short snaplen: %u", 
								pcap_dev->proc_stat.packets, pcap_dev->proc_stat.skipped, 
								pcap_dev->proc_stat.unknown, pcap_dev->proc_stat.short_snap);
						}
						t_start = t_clock - (t_clock % t_win);
						memset((void *)&(pcap_dev->proc_stat), 0, sizeof(proc_stat_t));
					} 
					} break;
				case -1:
					// signal error reading the packet
    				err = 1;
					LogError("pcap_next_ex() read error: '%s'", pcap_geterr(pcap_dev->handle));	
					args->done = 1;
					continue;
					break;
				case -2: // End of packet file
					// signal parent, job is done
    				err = 1;
					LogInfo("pcap_next_ex() end of file");	
					args->done = 1;
					LogInfo("Packet processing stats: Total: %u, Skipped: %u, Unknown: %u, Short snaplen: %u", 
						pcap_dev->proc_stat.packets, pcap_dev->proc_stat.skipped, 
						pcap_dev->proc_stat.unknown, pcap_dev->proc_stat.short_snap);
					continue;
					break;
				default:
    				err = 1;
					pcap_breakloop(pcap_dev->handle);
					LogError("Unexpected pcap_next_ex() return value: %i", ret);
					args->done = 1;
					continue;
			}

		}

		if ( args->done ) 
			break;

	}

	if ( pcap_datadir ) {
		dbg_printf("Wait for flush thread to complete\n");
   		pthread_mutex_lock(&pcapfile->m_pbuff);
    	while ( pcapfile->alternate_size ) {
        	pthread_cond_wait(&pcapfile->c_pbuff, &pcapfile->m_pbuff);
    	}
		pcapfile->t_CloseRename = t_start;
   		pthread_mutex_unlock(&pcapfile->m_pbuff);
		dbg_printf("Wait done.\n");

		LogInfo("Signal flush thread[%lu] to terminate", p_flush_thread_args.tid);
		SignalThreadTerminate((thread_info_t *)&p_flush_thread_args, &pcapfile->c_pbuff);
	}

	if ( err ) 
  		pthread_kill(args->parent, SIGUSR1);

	LogInfo("Packet processing stats: Total: %u, Skipped: %u, Unknown: %u, Short snaplen: %u", 
		pcap_dev->proc_stat.packets, pcap_dev->proc_stat.skipped, 
		pcap_dev->proc_stat.unknown, pcap_dev->proc_stat.short_snap);
	LogInfo("Terminating packet dumping: exit: %i", args->exit);
	dbg_printf("End packet thread[%lu]\n", (long unsigned)args->tid);

	pthread_exit((void *)args);
	/* NOTREACHED */

} /* End of p_packet_thread */

static void WaitDone(void) {
sigset_t signal_set;
int done, sig;
pthread_t tid   = pthread_self();

	LogInfo("[%lu] WaitDone() waiting", (long unsigned)tid);

	sigemptyset(&signal_set);
	sigaddset(&signal_set, SIGINT);
	sigaddset(&signal_set, SIGHUP);
	sigaddset(&signal_set, SIGTERM);
	sigaddset(&signal_set, SIGUSR1);
	pthread_sigmask(SIG_BLOCK, &signal_set, NULL);

	done = 0;
	while ( !done ) {
		sigwait(&signal_set, &sig);
		LogInfo("[%lu] WaitDone() signal %i", (long unsigned)tid, sig);
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
int subdir_index, compress, expire, cache_size;
FlowSource_t	*fs;
dirstat_t 		*dirstat;
time_t 			t_win;
char 			*device, *pcapfile, *filter, *datadir, *pcap_datadir, *extension_tags, pidfile[MAXPATHLEN], pidstr[32];
char			*Ident, *userid, *groupid;
pcap_dev_t 		*pcap_dev;
p_packet_thread_args_t *p_packet_thread_args;
p_flow_thread_args_t *p_flow_thread_args;

	snaplen			= 100;
	do_daemonize	= 0;
	launcher_pid	= 0;
	device			= NULL;
	pcapfile		= NULL;
	filter			= NULL;
	pidfile[0]		= '\0';
	t_win			= TIME_WINDOW;
	datadir			= DEFAULT_DIR;
	pcap_datadir	= NULL;
	userid			= groupid = NULL;
	Ident			= "none";
	fs				= NULL;
	extension_tags	= DefaultExtensions;
	subdir_index	= 0;
	compress		= 0;
	verbose			= 0;
	expire			= 0;
	cache_size		= 0;
	while ((c = getopt(argc, argv, "B:DEI:g:hi:r:s:l:p:P:t:u:S:T:e:Vz")) != EOF) {
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
			case 't':
				t_win = atoi(optarg);
				if (t_win < 60) {
					LogError("WARNING, very small time frame (< 60)!");
				}
				if (t_win <= 0) {
					LogError("ERROR: time frame too small (<= 0)");
					exit(EXIT_FAILURE);
				}
				break;
			case 'z':
				compress = 1;
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
					snprintf(pidfile, MAXPATHLEN - 1 - strlen(tmp), "%s/%s", tmp, optarg);
				}
				// pidfile now absolute path
				pidfile[MAXPATHLEN-1] = 0;
				break;
			case 'S':
				subdir_index = atoi(optarg);
				break;
			case 'T': {
				size_t len = strlen(optarg);
				extension_tags = optarg;
				if ( len == 0 || len > 128 ) {
					fprintf(stderr, "Extension length error. Unexpected option '%s'\n", extension_tags);
					exit(255);
				}
				break; }
			case 'E':
				verbose = 1;
				Setv6Mode(1);
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

	if ( fs == NULL && datadir != NULL && !AddDefaultFlowSource(&fs, Ident, datadir) ) {
		fprintf(stderr, "Failed to add default data collector directory\n");
		exit(255);
	}

	if ( device && pcapfile ) {
		LogError("Specify either a device or a pcapfile, but not both");
		exit(EXIT_FAILURE);
	}

	if ( !device && !pcapfile ) {
		LogError("Specify either a device or a pcapfile to read packets from");
		exit(EXIT_FAILURE);
	}

	
	if ( !Init_FlowTree(cache_size)) {
		LogError("Init_FlowTree() failed.");
		exit(EXIT_FAILURE);
	}

	InitExtensionMaps(NO_EXTENSION_LIST);
	SetupExtensionDescriptors(strdup(extension_tags));

	if ( pcapfile ) {
		pcap_dev = setup_pcap_file(pcapfile, filter, snaplen);
	} else {
		pcap_dev = setup_pcap_live(device, filter, snaplen);
	}
	if (!pcap_dev) {
		exit(EXIT_FAILURE);
	}

	SetPriv(userid, groupid);

	if ( subdir_index && !InitHierPath(subdir_index) ) {
		pcap_close(pcap_dev->handle);
		exit(255);
	}

	if ( do_daemonize && !InitLog(argv[0], SYSLOG_FACILITY)) {
		pcap_close(pcap_dev->handle);
		exit(255);
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
				pcap_close(pcap_dev->handle);
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
						pcap_close(pcap_dev->handle);
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
				pcap_close(pcap_dev->handle);
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
			pcap_close(pcap_dev->handle);
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
			pcap_close(pcap_dev->handle);
			exit(255);
	}

	// Init the extension map list
	if ( !InitExtensionMapList(fs) ) {
		// error message goes to syslog
		pcap_close(pcap_dev->handle);
		exit(255);
	}

	IPFragTree_init();

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

	// key for each thread
	err = pthread_key_create(&buffer_key, NULL);
	if ( err ) {
		LogError("pthread_key() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(255);
	}

	// prepare flow thread args
	p_flow_thread_args = (p_flow_thread_args_t *)malloc(sizeof(p_flow_thread_args_t));
	if ( !p_flow_thread_args ) {
		LogError("malloc() error in %s line %d: %s\n", 
			__FILE__, __LINE__, strerror(errno) );
		exit(255);
	}	
	p_flow_thread_args->fs 	   	   = fs;
	p_flow_thread_args->t_win 	   = t_win;
	p_flow_thread_args->compress   = compress;
	p_flow_thread_args->subdir_index = subdir_index;
	p_flow_thread_args->parent	   = pthread_self();
	p_flow_thread_args->NodeList   = NewNodeList();

	err = 0;
	err = pthread_create(&p_flow_thread_args->tid, NULL, p_flow_thread, (void *)p_flow_thread_args);
	if ( err ) {
		LogError("pthread_create() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(255);
	}
	dbg_printf("Started flow thread[%lu]\n", (long unsigned)p_flow_thread_args->tid);

	// prepare packet thread args
	p_packet_thread_args = (p_packet_thread_args_t *)malloc(sizeof(p_packet_thread_args_t));
	if ( !p_packet_thread_args ) {
		LogError("malloc() error in %s line %d: %s\n", 
			__FILE__, __LINE__, strerror(errno) );
		exit(255);
	}	
	p_packet_thread_args->pcap_dev 	   = pcap_dev;
	p_packet_thread_args->t_win 	   = t_win;
	p_packet_thread_args->subdir_index = subdir_index;
	p_packet_thread_args->pcap_datadir = pcap_datadir;
	p_packet_thread_args->live 	   	   = device != NULL;
	p_packet_thread_args->parent	   = pthread_self();
	p_packet_thread_args->NodeList	   = p_flow_thread_args->NodeList;

	err = pthread_create(&p_packet_thread_args->tid, NULL, p_packet_thread, (void *)p_packet_thread_args);
	if ( err ) {
		LogError("pthread_create() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(255);
	}
	dbg_printf("Started packet thread[%lu]\n", (long unsigned)p_packet_thread_args->tid);

	// Wait till done
	WaitDone();

	dbg_printf("Signal packet thread to terminate\n");
	SignalThreadTerminate((thread_info_t *)p_packet_thread_args, NULL);

	dbg_printf("Signal flow thread to terminate\n");
	SignalThreadTerminate((thread_info_t *)p_flow_thread_args, &p_packet_thread_args->NodeList->c_list);

	// free arg list
	free((void *)p_packet_thread_args);
	free((void *)p_flow_thread_args);

	LogInfo("Terminating nfpcapd.");

	if ( expire == 0 && ReadStatInfo(fs->datadir, &dirstat, LOCK_IF_EXISTS) == STATFILE_OK ) {
		UpdateBookStat(dirstat, fs->bookkeeper);
		WriteStatInfo(dirstat);
		LogInfo("Updating statinfo in directory '%s'", datadir);
	}

	ReleaseBookkeeper(fs->bookkeeper, DESTROY_BOOKKEEPER);
	pcap_close(pcap_dev->handle);

	if ( strlen(pidfile) )
		unlink(pidfile);

	EndLog();

	exit(EXIT_SUCCESS);
} /* End of main */

