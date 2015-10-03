/*
 *  Copyright (c) 2014, Peter Haag
 *  Copyright (c) 2009, Peter Haag
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
 *  $Author: haag $
 *
 *  $Id: profile.c 41 2009-12-31 14:46:28Z haag $
 *
 *  $LastChangedRevision: 41 $
 *      
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <rrd.h>

#include "nf_common.h"
#include "rbtree.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfstatfile.h"
#include "nfxstat.h"
#include "flist.h"
#include "util.h"
#include "nftree.h"
#include "profile.h"

/* imported vars */
extern char yyerror_buff[256];
extern uint32_t is_anonymized;
extern char Ident[IDENTLEN];

static profile_channel_info_t *profile_channels;
static unsigned int num_channels;

static inline int AppendString(char *stack, char *string, size_t	*buff_size);

static void SetupProfileChannels(char *profile_datadir, char *profile_statdir, profile_param_info_t *profile_param, 
	int subdir_index, char *filterfile, char *filename, int verify_only, int compress, int do_xstat);

profile_channel_info_t	*GetChannelInfoList(void) {
	return profile_channels;
} // End of GetProfiles

static inline int AppendString(char *stack, char *string, size_t *buff_size) {
size_t len = strlen(string);

	if ( *buff_size <= len ) {
		LogError("string append error in %s line %d: %s\n", __FILE__, __LINE__, "buffer size error");
		return 0;
	}

	strncat(stack, string, len);
	*buff_size -= len;

	return 1;

} // End of AppendString

unsigned int InitChannels(char *profile_datadir, char *profile_statdir, profile_param_info_t *profile_list, 
	char *filterfile, char *filename, int subdir_index, int verify_only, int compress, int do_xstat) {
profile_param_info_t	*profile_param;

	num_channels = 0;
	profile_param = profile_list;
	while ( profile_param ) {
	LogInfo("Setup channel '%s' in profile '%s' group '%s', channellist '%s'\n", 
		profile_param->channelname, profile_param->profilename, profile_param->profilegroup, 
		profile_param->channel_sourcelist);

		SetupProfileChannels(profile_datadir, profile_statdir, profile_param, subdir_index, filterfile, filename, verify_only, compress, do_xstat);

		profile_param = profile_param->next;
	}
	return num_channels;

} // End of InitChannels

static void SetupProfileChannels(char *profile_datadir, char *profile_statdir, profile_param_info_t *profile_param, 
	int subdir_index, char *filterfile, char *filename, int verify_only, int compress, int do_xstat ) {
FilterEngine_data_t	*engine;
struct 	stat stat_buf;
char 	*p, *filter, *subdir, *wfile, *ofile, *rrdfile, *source_filter;
char	path[MAXPATHLEN];
int		ffd, ret;
size_t	filter_size;
nffile_t *nffile;
xstat_t	 *xstat;

	ofile = wfile = NULL;
	nffile = NULL;
	xstat  = NULL;

	/* 
	 * Compile the complete filter:
	 * this consists of the source list and the filter stored in the file
	 */
	snprintf(path, MAXPATHLEN-1, "%s/%s/%s/%s-%s", 
		profile_statdir, profile_param->profilegroup, profile_param->profilename, profile_param->channelname, filterfile);
	path[MAXPATHLEN-1] = '\0';

	if ( stat(path, &stat_buf) || !S_ISREG(stat_buf.st_mode) ) {
		LogError("Skipping channel %s in profile '%s' group '%s'. No profile filter found.\n", 
			profile_param->channelname, profile_param->profilename, profile_param->profilegroup);
		return;
	}

	// prepare source filter for this channel
	if ( profile_param->channel_sourcelist ) {
		// we have a channel_sourcelist: channel1|channel2|channel3
		// source filter - therefore pattern is '( sourcefilter ) and ( filter )'
		// where sourcefilter is 'ident source1 or ident source2 ... '
		char *q;
		size_t	len = strlen(profile_param->channel_sourcelist);
		int num_sources = 1;	// at least one source, otherwise we would not be in this code

		q = profile_param->channel_sourcelist;
		while ( (p = strchr(q, '|')) != NULL  ) {
			num_sources++;
			q = p;
			q++;
		}
		// allocate a temp buffer for the source filter. 
		// for each source add 'ident <source>  or ', which makes 10 char per sources, including '()\0 and ' = 8
		len += 10 * num_sources + 8;
		source_filter = (char *)malloc(len);
		if ( !source_filter ) {
			LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			exit(255);
		}

		source_filter[0] = '(';
		source_filter[1] = '\0';
		len--;
		q = profile_param->channel_sourcelist;
		do {
			p = strchr(q, '|');
			if (p) 
				*p = '\0';

			if ( !AppendString(source_filter, "ident ", &len) ) 
				return;

			if ( !AppendString(source_filter, q, &len) ) 
				return;

			if ( p ) {
				// there is another source waiting behind *p
				if ( !AppendString(source_filter, " or ", &len) )
					return;
				q = p;
				q++;
			}
		} while (p);

		if ( !AppendString(source_filter, ") and (", &len) ) 
			return;
	} else 
		// no source filter - therefore pattern is '(' filter ')'
		source_filter = "(";

	filter_size = stat_buf.st_size + strlen(source_filter) + 2;	// +2 : ')\0' at the end of the filter

	filter = (char *)malloc(filter_size);
	if ( !filter ) {
		LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(255);
	}
	ffd = open(path, O_RDONLY);
	if ( ffd < 0 ) {
		LogError("Can't open file '%s' for reading: %s\n",path, strerror(errno) );
		return;
	}

	strncpy(filter, source_filter, strlen(source_filter));
	p = filter + strlen(source_filter);

	ret = read(ffd, (void *)p, stat_buf.st_size);
	if ( ret < 0   ) {
		LogError("Can't read from file '%s': %s\n",path, strerror(errno) );
		close(ffd);
		return;
	}
	close(ffd);

	p[stat_buf.st_size]   = ')';
	p[stat_buf.st_size+1] = '\0';


	// compile profile filter
	if ( verify_only )
		printf("Check filter for channel %s in profile '%s' in group '%s': ", 
			profile_param->channelname, profile_param->profilename, profile_param->profilegroup);
	engine = CompileFilter(filter);

	if ( !engine ) {
		printf("\n");
		LogError("*** Compiling filter failed for channel %s in profile '%s' in group '%s'.",
			profile_param->channelname, profile_param->profilename, profile_param->profilegroup);
		LogError("*** File: %s", path);
		LogError("*** Error: %s\n", yyerror_buff);
		LogError("*** Failed Filter: %s", filter);			
		free(filter);
		return;
	}
	free(filter);

	if ( verify_only ) {
		printf("ok.\n");
		return;
	}

	// path to the channel
	// channel exists and is a directory - checked in ParseParams
	snprintf(path, MAXPATHLEN-1, "%s/%s/%s/%s", 
		profile_datadir, profile_param->profilegroup, profile_param->profilename, profile_param->channelname);
	path[MAXPATHLEN-1] = '\0';

	if ( chdir(path)) {
		LogError("Error can't chdir to '%s': %s", path, strerror(errno));
		exit(255);
	}

	// check for subdir hierarchy
	subdir = NULL;
	if ( (profile_param->profiletype & 4) ==  0  ) { // no shadow profile
		int is_alert = (profile_param->profiletype & 8) ==  8;
		if ( !is_alert && subdir_index && strlen(filename) == 19 && (strncmp(filename, "nfcapd.", 7) == 0) ) {
			char *p = &filename[7];	// points to ISO timstamp in filename
			time_t	t = ISO2UNIX(p);
			struct  tm *t_tm = localtime(&t);
			char error[255];
	
			subdir = GetSubDir(t_tm);
			if ( !subdir ) {
				// failed to generate subdir path - put flows into base directory
				LogError( "Failed to create subdir path!");
			}
			if ( !SetupSubDir(path, subdir, error, 255) ) {
				LogError( "Failed to create subdir path: '%s'" , error);
				// nothing else need to be done, as subdir == NULL means put files into channel directory
			}
		}

		if ( is_alert ) { // alert
			snprintf(path, MAXPATHLEN, "%s/%s/%s/%s/%s", 
				profile_datadir, profile_param->profilegroup, profile_param->profilename, profile_param->channelname, filename);
		} else {
			// prepare output file for profile types != shadow
			if ( subdir ) 
				snprintf(path, MAXPATHLEN, "%s/%s/%s/%s/%s/%s", 
					profile_datadir, profile_param->profilegroup, profile_param->profilename, 
					profile_param->channelname, subdir, filename);
			else
				snprintf(path, MAXPATHLEN, "%s/%s/%s/%s/%s", 
					profile_datadir, profile_param->profilegroup, profile_param->profilename, profile_param->channelname, filename);
		}
		path[MAXPATHLEN-1] = '\0';
		wfile = strdup(path);

		// ofile: file while profiling
		snprintf(path, MAXPATHLEN, "%s/%s/%s/%s/nfprofile.%llu", 
			profile_datadir, profile_param->profilegroup, profile_param->profilename, profile_param->channelname, 
			(unsigned long long)getpid());
		path[MAXPATHLEN-1] = '\0';

		ofile = strdup(path);
	
		nffile = OpenNewFile(path, NULL, compress, 0, NULL);
		if ( !nffile ) {
			return;
		}
		if ( do_xstat ) {
			xstat = InitXStat(nffile);
			if ( !xstat ) {
				return;
			}
		}
	} 

	snprintf(path, MAXPATHLEN-1, "%s/%s/%s/%s.rrd", 
		profile_statdir, profile_param->profilegroup, profile_param->profilename, profile_param->channelname);
	path[MAXPATHLEN-1] = '\0';
	rrdfile = strdup(path);

	snprintf(path, MAXPATHLEN, "%s/%s/%s/%s", profile_datadir, profile_param->profilegroup, 
		profile_param->profilename, profile_param->channelname );
	path[MAXPATHLEN-1] = '\0';

	// collect all channel info
	profile_channels = realloc(profile_channels, (num_channels+1) * sizeof(profile_channel_info_t) );
	if ( !profile_channels ) {
		LogError("Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(255);
	}

	memset(&profile_channels[num_channels], 0, sizeof(profile_channel_info_t));

	profile_channels[num_channels].engine					= engine;
	profile_channels[num_channels].group 	 				= profile_param->profilegroup;
	profile_channels[num_channels].profile 	 				= profile_param->profilename;
	profile_channels[num_channels].channel 	 				= profile_param->channelname;
	profile_channels[num_channels].wfile 					= wfile;
	profile_channels[num_channels].ofile 					= ofile;
	profile_channels[num_channels].rrdfile 					= rrdfile;
	profile_channels[num_channels].dirstat_path 			= strdup(path);
	profile_channels[num_channels].type						= profile_param->profiletype;
	profile_channels[num_channels].nffile					= nffile;
	profile_channels[num_channels].xstat					= xstat;

	memset((void *)&profile_channels[num_channels].stat_record, 0, sizeof(stat_record_t));

	profile_channels[num_channels].stat_record.first_seen	= 0x7fffffff;
	profile_channels[num_channels].stat_record.last_seen	= 0;

	num_channels++;

	return;

} // End of SetupProfileChannels

void CloseChannels (time_t tslot, int compress) {
dirstat_t	*dirstat;
struct stat fstat;
unsigned int num;
int ret, update_ok;

	for ( num = 0; num < num_channels; num++ ) {
		if ( profile_channels[num].ofile ) {
			if ( profile_channels[num].xstat ) {
				if ( WriteExtraBlock(profile_channels[num].nffile, profile_channels[num].xstat->block_header ) <= 0 ) {
					LogError("Failed to write xstat buffer to disk: '%s'" , strerror(errno));
				} 
			}

			if ( is_anonymized ) 
				SetFlag(profile_channels[num].nffile->file_header->flags, FLAG_ANONYMIZED);
			CloseUpdateFile(profile_channels[num].nffile, Ident);
			profile_channels[num].nffile = DisposeFile(profile_channels[num].nffile);

			stat(profile_channels[num].ofile, &fstat);

			ret = ReadStatInfo(profile_channels[num].dirstat_path, &dirstat, CREATE_AND_LOCK);
			update_ok = ret == STATFILE_OK;

	
			if ( rename(profile_channels[num].ofile, profile_channels[num].wfile) < 0 ) {
				LogError("Failed to rename file %s to %s: %s\n", 
					profile_channels[num].ofile, profile_channels[num].wfile, strerror(errno) );
			} else if ( dirstat && tslot > dirstat->last ) {
				dirstat->filesize += 512 * fstat.st_blocks;
				dirstat->numfiles++;
				dirstat->last = tslot;
			}

			if ( dirstat ) {
				WriteStatInfo(dirstat);
			}
		}
		if ( ((profile_channels[num].type & 0x8) == 0) && tslot > 0 ) {
			UpdateRRD(tslot, &profile_channels[num]);
		}
	}

} // End of CloseChannels

void UpdateRRD( time_t tslot, profile_channel_info_t *channel ) {
char	*rrd_arg[10], buff[1024];
char	*template, *s;
int		i, len, argc, buffsize;
stat_record_t stat_record = channel->stat_record;
	
	template = 	"flows:flows_tcp:flows_udp:flows_icmp:flows_other:packets:packets_tcp:packets_udp:packets_icmp:packets_other:traffic:traffic_tcp:traffic_udp:traffic_icmp:traffic_other";

	argc = 0;

	buffsize = 1024;
	s = buff;
	len = snprintf(s, buffsize , "%llu:", (long long unsigned)tslot);
	buffsize -= len; s += len;
	len = snprintf(s, buffsize , "%llu:", (long long unsigned)stat_record.numflows);
	buffsize -= len; s += len;
	len = snprintf(s, buffsize , "%llu:", (long long unsigned)stat_record.numflows_tcp);
	buffsize -= len; s += len;
	len = snprintf(s, buffsize , "%llu:", (long long unsigned)stat_record.numflows_udp);
	buffsize -= len; s += len;
	len = snprintf(s, buffsize , "%llu:", (long long unsigned)stat_record.numflows_icmp);
	buffsize -= len; s += len;
	len = snprintf(s, buffsize , "%llu:", (long long unsigned)stat_record.numflows_other);
	buffsize -= len; s += len;

	len = snprintf(s, buffsize , "%llu:", (long long unsigned)stat_record.numpackets);
	buffsize -= len; s += len;
	len = snprintf(s, buffsize , "%llu:", (long long unsigned)stat_record.numpackets_tcp);
	buffsize -= len; s += len;
	len = snprintf(s, buffsize , "%llu:", (long long unsigned)stat_record.numpackets_udp);
	buffsize -= len; s += len;
	len = snprintf(s, buffsize , "%llu:", (long long unsigned)stat_record.numpackets_icmp);
	buffsize -= len; s += len;
	len = snprintf(s, buffsize , "%llu:", (long long unsigned)stat_record.numpackets_other);
	buffsize -= len; s += len;

	len = snprintf(s, buffsize , "%llu:", (long long unsigned)stat_record.numbytes);
	buffsize -= len; s += len;
	len = snprintf(s, buffsize , "%llu:", (long long unsigned)stat_record.numbytes_tcp);
	buffsize -= len; s += len;
	len = snprintf(s, buffsize , "%llu:", (long long unsigned)stat_record.numbytes_udp);
	buffsize -= len; s += len;
	len = snprintf(s, buffsize , "%llu:", (long long unsigned)stat_record.numbytes_icmp);
	buffsize -= len; s += len;
	len = snprintf(s, buffsize , "%llu", (long long unsigned)stat_record.numbytes_other);
	buffsize -= len; s += len;

	buff[1023] = '\0';
	// Create arg vector
	argc = 0;
	rrd_arg[argc++] = "update";
	rrd_arg[argc++] = channel->rrdfile;
	rrd_arg[argc++] = "--template";
	rrd_arg[argc++] = strdup(template);
	rrd_arg[argc++] = buff;
	rrd_arg[argc]   = NULL;
	
	optind = 0; opterr = 0;
	rrd_clear_error();
	if ( ( i=rrd_update(argc, rrd_arg))) {
		LogError("RRD: %s Insert Error: %d %s\n", channel->rrdfile, i, rrd_get_error());
	}

} // End of UpdateRRD
