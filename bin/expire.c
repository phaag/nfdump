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
 *  $Id: expire.c 39 2009-11-25 08:11:15Z haag $
 *
 *  $LastChangedRevision: 39 $
 *  
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>

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

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "util.h"
#include "bookkeeper.h"
#include "nfstatfile.h"
#include "expire.h"

static uint32_t timeout = 0;

/* 
 * expire.c is needed for daemon code as well as normal stdio code 
 * therefore a generic LogError is defined, which maps to the 
 * approriate logging channel - either stderr or syslog
 */
void LogError(char *format, ...);

static void PrepareDirLists(channel_t *channel);

static int compare(const FTSENT **f1, const FTSENT **f2);

#if 0
#define unlink unlink_debug

static int unlink_debug (const char *path) {
	printf("Unlink %s\n", path);
	return 0;
} // End of unlink_debug
#endif

static void IntHandler(int signal) {

	switch (signal) {
		case SIGALRM:
			timeout = 1;
			break;
		case SIGHUP:
		case SIGINT:
		case SIGTERM:
			timeout = 1;
			break;
			break;
		case SIGCHLD:
		default:
			// ignore everything we don't know
			break;
	}

} /* End of IntHandler */

static void SetupSignalHandler(void) {
struct sigaction act;

	memset((void *)&act,0,sizeof(struct sigaction));
	act.sa_handler = IntHandler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGCHLD, &act, NULL);

} // End of SetupSignalHandler

uint64_t ParseSizeDef(char *s, uint64_t *value) {
char *p;
uint64_t fac;
int		dot;

	dot = 0;
	*value = 0;
	p = s;
	while ( *p ) {
		if ( *p < '0' || *p > '9' ) {
			if ( *p == '.' ) {
				if ( dot ) {
					break;
				} else {
					dot = 1;
				}
			} else 
				break;
		}
		p++;
	}
	if ( p == s ) {
		fprintf(stderr, "Missing number in '%s'\n", s);
		return 0;
	}

	fac = 0;
	switch (*p) {
		case '\0': 
		case 'b': 
		case 'B': 
			fac = 1;
			break;
		case 'k':
		case 'K':
			fac = 1024;
			break;
		case 'm':
		case 'M':
			fac = 1024 * 1024;
			break;
		case 'g':
		case 'G':
			fac = 1024 * 1024 * 1024;
			break;
		case 't':
		case 'T':
			fac = 1024LL * 1024LL * 1024LL * 1024LL;
			break;
		default:
			fprintf(stderr, "Garbage character(s) '%s' in '%s'\n", p, s);
			return 0;
	}

	if ( *p ) {
		char *r = p++;

		// skip optional 'B' for Bytes in KB etc. 
		if ( fac != 1 && (*p == 'B' || *p == 'b') ) p++;

		if ( *p ) {
			// extra garbage after factor
			fprintf(stderr, "Garbage character(s) '%s''in '%s'\n", p, s);
			return 0;
		}
		*r = '\0';
	}

	// *value = strtoll(s, NULL, 10) * fac;
	*value = (uint64_t)(atof(s) * (double)fac);

	return 1;

} // End of ParseSizeDef

/*
 * Accepted time scales
 *
 * w    week
 * d    day
 * H    hour
 * M    minute
 */
uint64_t ParseTimeDef(char *s, uint64_t *value) {
char *p;
uint64_t	weeks, days, hours, minutes;

	*value = 0;
	weeks=days=hours=minutes=0;

	p = s;
	while ( *p ) {
		char *q = p;
		while ( *p ) {
			if ( *p < '0' || *p > '9' ) {
				break;
			}
			p++;
		}
		if ( p == q ) {
			fprintf(stderr, "Missing number before '%s'\n", q);
			return 0;
		}
		switch (*p) {
			case 'w':
				*p++ = '\0';
				if ( weeks ) {
					fprintf(stderr, "Ambiguous weeks %sw\n", q);
					return 0;
				}
				weeks = strtoll(q, NULL, 10);
				break;
			case 'd':
				*p++ = '\0';
				if ( days ) {
					fprintf(stderr, "Ambiguous days %sD\n", q);
					return 0;
				}
				days = strtoll(q, NULL, 10);
				break;
			case '\0':	// without any units, assume hours
			case 'H':
				if ( *p ) *p++ = '\0';
				if ( hours ) {
					fprintf(stderr, "Ambiguous hours %sH\n", q);
					return 0;
				}
				hours = strtoll(q, NULL, 10);
				break;
			case 'M':
				*p++ = '\0';
				if ( minutes ) {
					fprintf(stderr, "Ambiguous minutes %sM\n", q);
					return 0;
				}
				minutes = strtoll(q, NULL, 10);
				break;
			default:
				fprintf(stderr, "Unknown time unit '%s'\n", q);
				return 0;

		}
	}

	*value = minutes*60 + hours*3600 + days*24*3600 + weeks*7*24*3600;

	return 1;

} // End of ParseTimeDef

static int compare(const FTSENT **f1, const FTSENT **f2) {
	return strcmp( (*f1)->fts_name, (*f2)->fts_name);
} // End of compare

void RescanDir(char *dir, dirstat_t *dirstat) {
FTS 		*fts;
FTSENT 		*ftsent;
char *const path[] = { dir, NULL };
char		first_timestring[16], last_timestring[16];

	dirstat->filesize = dirstat->numfiles = 0;
	dirstat->first = 0;
	dirstat->last  = 0;
	strncpy(first_timestring, "999999999999", 15);
	strncpy(last_timestring,  "000000000000", 15);
	
	fts = fts_open(path, FTS_LOGICAL,  compare);
	if ( !fts ) {
		LogError( "fts_open() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return;
	}
	while ( (ftsent = fts_read(fts)) != NULL) {
		if ( ftsent->fts_info == FTS_F && ftsent->fts_namelen == 19 ) {
			// nfcapd.200604301200 strlen = 19
			if ( strncmp(ftsent->fts_name, "nfcapd.", 7) == 0 ) {
				char *s, *p = &(ftsent->fts_name[7]);

				// make sure, we have only digits
				s = p;
				while ( *s ) {
					if ( *s < '0' || *s > '9' ) 
						break;
					s++;
				}
				// otherwise skip
				if ( *s )
					continue;

				if ( strcmp(p, first_timestring) < 0 ) {
					first_timestring[0] = '\0';
					strncat(first_timestring, p, 15);
				}
				if ( strcmp(p, last_timestring) > 0 ) {
					last_timestring[0] = '\0';
					strncat(last_timestring, p, 15);
				}

				dirstat->filesize += 512 * ftsent->fts_statp->st_blocks;
				dirstat->numfiles++;
			}
		} else {
			switch (ftsent->fts_info) {
				case FTS_D:
					// skip all '.' entries as well as hidden directories
					if ( ftsent->fts_level > 0 && ftsent->fts_name[0] == '.' ) 
						fts_set(fts, ftsent, FTS_SKIP);
					// any valid dirctory need to start with a digit ( %Y -> year )
					if ( ftsent->fts_level > 0 && !isdigit(ftsent->fts_name[0]) )
						fts_set(fts, ftsent, FTS_SKIP);
					break;
				case FTS_DP:
					break;
			}
		}
	}
	fts_close(fts);

	// no files means do rebuild next time, otherwise the stat record may not be accurate 
	if ( dirstat->numfiles == 0 ) {
		dirstat->first  = dirstat->last = time(NULL);
		dirstat->status = FORCE_REBUILD;
	} else {
		dirstat->first  = ISO2UNIX(first_timestring);	
		dirstat->last   = ISO2UNIX(last_timestring);	
		dirstat->status = STATFILE_OK;
	}

} // End of RescanDir

void ExpireDir(char *dir, dirstat_t *dirstat, uint64_t maxsize, uint64_t maxlife, uint32_t runtime ) {
FTS 		*fts;
FTSENT 		*ftsent;
uint64_t	sizelimit, num_expired;
int			done, size_done, lifetime_done, dir_files;
char *const path[] = { dir, NULL };
char		*expire_timelimit = NULL;
time_t 		now = time(NULL);

	dir_files = 0;
	if ( dirstat->low_water == 0 )
		dirstat->low_water = 95;

	if ( runtime ) {
		SetupSignalHandler();
		alarm(runtime);
	}

	if ( maxlife ) {
		// build an appropriate string for comparing
		time_t t_expire = now - maxlife;
		
		time_t t_watermark = now - (time_t)((maxlife * dirstat->low_water)/100);

// printf("Expire files before %s", ctime(&t_expire));
		expire_timelimit = strdup(UNIX2ISO(t_watermark));
// printf("down to %s", ctime(&t_watermark));
// printf("Diff: %i\n", t_watermark - t_expire );

		if ( dirstat->last < t_expire && (isatty(STDIN_FILENO) ) ) {
			// this means all files will get expired - are you sure ?
			char *s, s1[32], s2[32];
			time_t	t;
			struct tm *when;

			t = t_expire;
			when = localtime(&t);
			strftime(s1, 31, "%Y-%m-%d %H:%M:%S", when);
			s1[31] = '\0';
			
			t = dirstat->last;
			when = localtime(&t);
			strftime(s2, 31, "%Y-%m-%d %H:%M:%S", when);
			s2[31] = '\0';
			
			printf("Your max lifetime of %s will expire all file before %s\n", ScaleTime(maxlife), s1);
			printf("Your latest files are dated %s. This means all files will be deleted!\n", s2);
			printf("Are you sure? yes/[no] ");
			s = fgets(s1, 31, stdin);
			s1[31] = '\0';
			if ( s && strncasecmp(s1, "yes\n", 31) == 0 ) {
				printf("Ok - you've beeen warned!\n");
			} else {
				printf("Expire canceled!\n");
				return;
			}
		}
	}

	done 		  = 0;
	size_done 	  = maxsize == 0 || dirstat->filesize < maxsize;
	lifetime_done = maxlife == 0 || ( now - dirstat->first ) < maxlife;
	sizelimit = (dirstat->low_water * maxsize)/100;
	num_expired = 0;
	fts = fts_open(path, FTS_LOGICAL,  compare);
	while ( !done && ((ftsent = fts_read(fts)) != NULL) ) {
		if ( ftsent->fts_info == FTS_F ) {
			dir_files++;	// count files in directories
			if ( ftsent->fts_namelen == 19 && strncmp(ftsent->fts_name, "nfcapd.", 7) == 0 ) {
				// nfcapd.200604301200 strlen = 19
				char *s, *p = &(ftsent->fts_name[7]);
	
				// process only nfcapd. files
				// make sure it's really an nfcapd. file and we have 
				// only digits in the rest of the file name
				s = p;
				while ( *s ) {
					if ( *s < '0' || *s > '9' ) 
						break;
					s++;
				}
				// otherwise skip
				if ( *s )
					continue;

				// expire size-wise if needed
				if ( !size_done ) {
					if ( dirstat->filesize > sizelimit ) {
						if ( unlink(ftsent->fts_path) == 0 ) {
							dirstat->filesize -= 512 * ftsent->fts_statp->st_blocks;
							num_expired++;
							dir_files--;
						} else {
							LogError( "unlink() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
						}
						continue;	// next file if file was unlinked
					} else {
						dirstat->first = ISO2UNIX(p);	// time of first file not expired
						size_done = 1;
					}
				}

				// expire time-wise if needed
				// this part of the code is executed only when size-wise is fullfilled
				if ( !lifetime_done ) {
					if ( expire_timelimit && strcmp(p, expire_timelimit) < 0  ) {
						if ( unlink(ftsent->fts_path) == 0 ) {
							dirstat->filesize -= 512 * ftsent->fts_statp->st_blocks;
							num_expired++;
							dir_files--;
						} else {
							LogError( "unlink() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
						}
						lifetime_done = 0;
					} else {
						dirstat->first = ISO2UNIX(p);	// time of first file not expired
						lifetime_done = 1;
					}
				}
				done = (size_done && lifetime_done) || timeout;

			}
		} else {
			switch (ftsent->fts_info) {
				case FTS_D:
					// set pre-order flag
					dir_files = 0;
					// skip all '.' entries as well as hidden directories
					if ( ftsent->fts_level > 0 && ftsent->fts_name[0] == '.' ) 
						fts_set(fts, ftsent, FTS_SKIP);
					// any valid directory needs to start with a digit ( %Y -> year )
					if ( ftsent->fts_level > 0 && !isdigit(ftsent->fts_name[0]) ) 
						fts_set(fts, ftsent, FTS_SKIP);
					break;
				case FTS_DP:
					// do not delete base data directory ( level == 0 )
					if ( dir_files == 0 && ftsent->fts_level > 0 ) {
						// directory is empty and can be deleted
// printf("Will remove directory %s\n", ftsent->fts_path);
						if ( rmdir(ftsent->fts_path) != 0 ) {
							LogError( "rmdir() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
						}
					}
					break;
			}
		}
	}
	fts_close(fts);
	if ( !done ) {
		// all files expired and limits not reached
		// this may be possible, when files get time-wise expired and
		// the time limit is shorter than the latest file
		dirstat->first = dirstat->last;
	}
	if ( runtime )
		alarm(0);
	if ( timeout ) {
		LogError( "Maximum execution time reached! Interrupt expire.\n");
	}
	if ( num_expired > dirstat->numfiles ) {
		LogError( "Error updating stat record: Number of files inconsistent!\n");
		LogError( "Will automatically rebuild this directory next time\n");
		dirstat->numfiles = 0;
		dirstat->status = FORCE_REBUILD;
	} else {
		dirstat->numfiles -= num_expired;
	}
	if ( dirstat->numfiles == 0 ) {
		dirstat->first  = dirstat->last = time(NULL);
		dirstat->status = FORCE_REBUILD;
	}

	free(expire_timelimit);

} // End of ExpireDir

static void PrepareDirLists(channel_t *channel) {
channel_t *current_channel = channel;

	while ( current_channel ) {
		char *const path[] = { current_channel->datadir, NULL };

		current_channel->fts = fts_open(path, FTS_LOGICAL|FTS_NOCHDIR,  compare);
		if ( !current_channel->fts ) {
			LogError( "fts_open() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			continue;
		}

		// get first entry
		current_channel->ftsent = fts_read(current_channel->fts);
		if ( current_channel->ftsent ) 
			// use fts_number as the number of files already seen in this directory.
			current_channel->ftsent->fts_number = 0;

		while ( current_channel->ftsent ) {

/*
			FTSENT *ftsent = current_channel->ftsent;
			char *finfo;
			switch (ftsent->fts_info) {
				case FTS_ERR:
				case FTS_NS:
					LogError( "fts_read() %s error in %s line %d: %s\n", 
						current_channel->ftsent->fts_path, __FILE__, __LINE__, strerror(current_channel->ftsent->fts_errno) );
					break;
				case FTS_D:
					finfo = "DIR pre ";
					break;
				case FTS_DP:
					finfo = "DIR post";
					break;
				case FTS_F:
					finfo = "FILE    ";
					break;
				default:
					finfo = "<undef> ";
			}
			printf("%u %i %s %s %s\n", ftsent->fts_info, ftsent->fts_level, finfo, ftsent->fts_path, ftsent->fts_name);
*/
		 	if ( current_channel->ftsent->fts_info == FTS_ERR ||
				 current_channel->ftsent->fts_info == FTS_NS) {
				LogError( "fts_read() %s error in %s line %d: %s\n", 
					current_channel->ftsent->fts_path, __FILE__, __LINE__, strerror(current_channel->ftsent->fts_errno) );
				continue;
			}
			if ( current_channel->ftsent->fts_info != FTS_F ) {
				current_channel->ftsent = fts_read(current_channel->fts);
				continue;
			}
			// it's now FTS_F
			current_channel->ftsent->fts_number++;

			// if ftsent points to first valid file, break
			if ( current_channel->ftsent->fts_namelen == 19 && strncmp(current_channel->ftsent->fts_name, "nfcapd.", 7) == 0 )
				break;

			// otherwise loop
			current_channel->ftsent = fts_read(current_channel->fts);
		}
		current_channel = current_channel->next;
	}

} // End of PrepareDirLists

void ExpireProfile(channel_t *channel, dirstat_t *current_stat, uint64_t maxsize, uint64_t maxlife, uint32_t runtime ) {
int  		size_done, lifetime_done, done;
char 		*expire_timelimit = "";
time_t		now = time(NULL);
uint64_t	sizelimit, num_expired;

	if ( !channel ) 
		return;

	done = 0;
	SetupSignalHandler();

	if ( maxlife ) {
//		time_t t_expire = now - maxlife;
		// build an appropriate string for comparing
		time_t t_watermark = now - (time_t)((maxlife * current_stat->low_water)/100);

//	printf("Expire files before %s", ctime(&t_expire));
		expire_timelimit = strdup(UNIX2ISO(t_watermark));
//	printf("down to %s", ctime(&t_watermark));
//	printf("Diff: %i\n", t_watermark - t_expire );

	}

	size_done 		= maxsize == 0 || current_stat->filesize < maxsize;
	sizelimit 		= (current_stat->low_water * maxsize)/100;
	lifetime_done 	= maxlife == 0 || ( now - current_stat->first ) < maxlife;

	num_expired = 0;

	PrepareDirLists(channel);
	if ( runtime )
		alarm(runtime);
	while ( !done ) {
		char *p;
		int file_removed;

		// search for the channel with oldest file. If all channel have same age, 
		// get the last in the list
		channel_t *expire_channel  = channel;
		channel_t *compare_channel = expire_channel->next;
		while ( compare_channel ) {
			if ( expire_channel->ftsent == NULL ) {
				expire_channel = compare_channel;
			}
			if ( compare_channel->ftsent == NULL ) {
				compare_channel = compare_channel->next;
				continue;
			}
			// at this point expire_channel and current_channel fts entries are valid
			if ( strcmp(expire_channel->ftsent->fts_name, compare_channel->ftsent->fts_name) >= 0 ) {
				expire_channel = compare_channel;
			}
			compare_channel = compare_channel->next;
		}
		if ( !expire_channel->ftsent ) {
			// no more entries in any channel - we are done
			done = 1;
			continue;
		}

		// flag is file got removed
		file_removed = 0;

		// expire_channel now points to the channel with oldest file
		// do expire
		p = &(expire_channel->ftsent->fts_name[7]);
//	printf("File: %s\n", expire_channel->ftsent->fts_path);

		if ( !size_done ) {
			// expire size-wise if needed
//	printf("	Size expire %llu %llu\n", current_stat->filesize, sizelimit);
			if ( current_stat->filesize > sizelimit ) {
				// need to delete this file
				if ( unlink(expire_channel->ftsent->fts_path) == 0 ) {
					// Update profile stat
					current_stat->filesize 			  -= 512 * expire_channel->ftsent->fts_statp->st_blocks;
					current_stat->numfiles--;

					// Update channel stat
					expire_channel->dirstat->filesize -= 512 * expire_channel->ftsent->fts_statp->st_blocks;
					expire_channel->dirstat->numfiles--;

					// decrement number of files seen in this directory
					expire_channel->ftsent->fts_number--;

					file_removed = 1;
					num_expired++;
				} else {
					LogError( "unlink() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
				}
			} else {
				// we are done size-wise
				// time of first file not expired = start time of channel/profile
				expire_channel->dirstat->first = current_stat->first = ISO2UNIX(p);	
				size_done = 1;
			}
		} else if ( !lifetime_done ) {
//	printf("	Time expire \n");
			// expire time-wise if needed
			// this part of the code is executed only when size-wise is already fullfilled
			if ( strcmp(p, expire_timelimit) < 0  ) {
				// need to delete this file
				if ( unlink(expire_channel->ftsent->fts_path) == 0 ) {
					// Update profile stat
					current_stat->filesize -= 512 * expire_channel->ftsent->fts_statp->st_blocks;
					current_stat->numfiles--;

					// Update channel stat
					expire_channel->dirstat->filesize -= 512 * expire_channel->ftsent->fts_statp->st_blocks;
					expire_channel->dirstat->numfiles--;

					// decrement number of files seen in this directory
					expire_channel->ftsent->fts_number--;

					file_removed = 1;
					num_expired++;
				} else {
					LogError( "unlink() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
				}
			} else {
				// we are done time-wise
				// time of first file not expired = start time of channel/profile
				expire_channel->dirstat->first = current_stat->first = ISO2UNIX(p);	
				lifetime_done = 1;
			}
		} else 
			// all done
			done = 1;
		if ( timeout ) 
			done = 1;

		// advance fts entry in expire channel to next file, if file was removed
		if ( file_removed ) {
			expire_channel->ftsent = fts_read(expire_channel->fts);
			while ( expire_channel->ftsent ) {
				if ( expire_channel->ftsent->fts_info == FTS_F ) { // entry is a file
					expire_channel->ftsent->fts_number++;
					if ( expire_channel->ftsent->fts_namelen == 19 && 
					 	strncmp(expire_channel->ftsent->fts_name, "nfcapd.", 7) == 0 ) {
						// if ftsent points to next valid file
						char *p = &(expire_channel->ftsent->fts_name[7]);
						// next file is first (oldest) for channel and for profile - update first mark
						expire_channel->dirstat->first = current_stat->first = ISO2UNIX(p);	
						break;
					}
				} else {
	
					switch (expire_channel->ftsent->fts_info) {
						case FTS_D:	// entry is a directory
							// set number of files seen in this directory = 0
							expire_channel->ftsent->fts_number = 0;
							// skip all '.' entries as well as hidden directories
							if ( expire_channel->ftsent->fts_level > 0 && expire_channel->ftsent->fts_name[0] == '.' ) 
								fts_set(expire_channel->fts, expire_channel->ftsent, FTS_SKIP);
							// any valid directory needs to start with a digit ( %Y -> year )
							if ( expire_channel->ftsent->fts_level > 0 && !isdigit(expire_channel->ftsent->fts_name[0]) ) 
								fts_set(expire_channel->fts, expire_channel->ftsent, FTS_SKIP);
							break;
						case FTS_DP:
							// do not delete base data directory ( level == 0 )
							if ( expire_channel->ftsent->fts_number == 0 && expire_channel->ftsent->fts_level > 0 ) {
								// directory is empty and can be deleted
//	printf("Will remove directory %s\n", expire_channel->ftsent->fts_path);
								if ( rmdir(expire_channel->ftsent->fts_path) != 0 ) {
									LogError( "rmdir() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
								}
							}
							break;
					}
				}
				// otherwise loop
				expire_channel->ftsent = fts_read(expire_channel->fts);
			} // end advance fts entry
			file_removed = 0;
		}

		if ( expire_channel->ftsent == NULL ) {
			// this channel has no more files now
			expire_channel->dirstat->first 			= expire_channel->dirstat->last;
			if ( expire_channel->dirstat->numfiles ) {	
				// if channel is empty, no files must be reported, but rebuild is done anyway
				LogError( "Inconsitency detected in channel %s. Will rebuild automatically.\n", expire_channel->datadir);
				LogError( "No more files found, but %llu expected.\n", expire_channel->dirstat->numfiles);
			}
			expire_channel->dirstat->numfiles 	= 0;
			expire_channel->dirstat->status		= FORCE_REBUILD;
		}
	} // while ( !done )

	if ( runtime )
		alarm(0);
	if ( timeout ) {
		LogError( "Maximum execution time reached! Interrupt expire.\n");
	}

} // End of ExpireProfile

void UpdateBookStat(dirstat_t *dirstat, bookkeeper_t *books) {

	if ( books->numfiles ) {
		/* prevent some faults and dublicates:
		 * book records can never be timewise smaller than directory records => fishy!
		 * in case book records == directory records, the user stopped and restarted nfcapd
		 * this is not necessarily wrong, but results in overwriting an existing file
		 * which results in wrong stats => rescan needed
		 */
		if ( books->last <= dirstat->last || books->first <= dirstat->first) {
			dirstat->status = FORCE_REBUILD;
			return;
		}
		dirstat->last      = books->last;
		dirstat->numfiles  += books->numfiles;
		dirstat->filesize  += books->filesize;
	}

} // End of UpdateBookStat


