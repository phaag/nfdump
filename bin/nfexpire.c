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
 *  $Id: nfexpire.c 51 2010-01-29 09:01:54Z haag $
 *
 *  $LastChangedRevision: 51 $
 *  
 */

#include "config.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/param.h>
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

#include "bookkeeper.h"
#include "nfstatfile.h"
#include "expire.h"
#include "util.h"

static void usage(char *name);

void CheckDataDir( char *datadir);

channel_t *GetChannelList(char *datadir, int is_profile, int do_rescan);

static void usage(char *name) {
		printf("usage %s [options] \n"
					"-h\t\tThis text\n"
					"-l datadir\tList stat from directory\n"
					"-e datadir\tExpire data in directory\n"
					"-r datadir\tRescan data directory\n"
					"-u datadir\tUpdate expire params from collector logging at <datadir>\n"
					"-s size\t\tmax size: scales b bytes, k kilo, m mega, g giga t tera\n"
					"-t lifetime\tmaximum life time of data: scales: w week, d day, H hour, M minute\n"
					"-w watermark\tlow water mark in %% for expire.\n"
					, name);

} // End of usage

void CheckDataDir( char *datadir) {
	if ( datadir ) {
		fprintf(stderr, "Specify only one option out of -l -e -r -u or -p \n");
		exit(250);
	}
} // End of CheckDataDir

static char *AbsolutePath(char *dirname) {
char *path;

	if ( !dirname )
		return NULL;

	if ( dirname[0] == '/' ) // it's already absolute path
		return dirname;

	path = (char *)malloc(MAXPATHLEN);
	if ( !path ) {
		LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return NULL;
	}
	memset((void *)path, 0, MAXPATHLEN);
	getcwd(path, MAXPATHLEN-strlen(dirname)-2);	// -2: one for '/' and one for '\0'
	strncat(path, "/", 1);
	strncat(path, dirname, strlen(dirname));
	path[MAXPATHLEN-1] = '\0';
	
	return path;

} // End of AbsolutePath

channel_t *GetChannelList(char *datadir, int is_profile, int do_rescan) {
channel_t **c, *channel;
stringlist_t dirlist;
struct stat stat_buf;
int i;

	// Generate list of directories 
	InitStringlist(&dirlist, 32);
	if ( is_profile ) {
		DIR *PDIR = opendir(datadir);
		struct dirent *entry;
		if ( !PDIR ) {
			fprintf(stderr, "Can't read profiledir '%s': %s\n",datadir, strerror(errno) );
			return NULL;
		}
		while ( ( entry = readdir(PDIR)) != NULL ) {
			char	stringbuf[MAXPATHLEN];
			snprintf(stringbuf, MAXPATHLEN-1, "%s/%s", datadir, entry->d_name);
			stringbuf[MAXPATHLEN-1] = '\0';

			if ( stat(stringbuf, &stat_buf) ) {
				fprintf(stderr, "Can't stat '%s': %s\n",stringbuf, strerror(errno) );
				continue;
			}
			if ( !S_ISDIR(stat_buf.st_mode) ) 
				continue;
	
			// skip all '.' entries -> make .anything invisible to nfprofile
			if ( entry->d_name[0] == '.' )
				continue;
	
			InsertString(&dirlist, stringbuf);
		}
		closedir(PDIR);
	} else {
		InsertString(&dirlist, datadir);
	}

	channel = NULL;
	c = &channel;
	for ( i=0; i<dirlist.num_strings; i++ ) {
		int ret;

		*c = (channel_t *)malloc(sizeof(channel_t));
		if ( !*c ) {
			LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			return NULL;
		}
		memset((void *)*c, 0, sizeof(channel_t));
		(*c)->next = NULL;
		(*c)->datadir = dirlist.list[i];
		(*c)->do_rescan = do_rescan;

		ret = ReadStatInfo((*c)->datadir, &(*c)->dirstat, CREATE_AND_LOCK);
		switch (ret) {
			case FORCE_REBUILD:
				printf("Force rebuild requested by stat record in %s\n", (*c)->datadir);
				(*c)->do_rescan = 1;		// file corrupt - rescan
				break;
			case STATFILE_OK:
				break;
			case ERR_NOSTATFILE:	// first rescan bevore expire, if no file exists
				if ( do_rescan == 0 ) {
					printf("Force rebuild to create stat record in %s\n", (*c)->datadir);
					(*c)->do_rescan = 1;
				} // else do_rescan is already set - do not report
				break;
			default:
				exit(250);
		}

		(*c)->books_stat = AccessBookkeeper(&((*c)->books), (*c)->datadir);
		if ( (*c)->books_stat == ERR_FAILED ) {
			fprintf(stderr, "Failed to access bookkeeping record.\n");
			exit(250);
		}

		c = &(*c)->next;
	}

	return channel;

} // End of GetChannelList

int main( int argc, char **argv ) {
struct stat fstat;
int 		c, err, maxsize_set, maxlife_set;
int			do_rescan, do_expire, do_list, print_stat, do_update_param, print_books, is_profile, nfsen_format;
char		*maxsize_string, *lifetime_string, *datadir;
uint64_t	maxsize, lifetime, low_water;
uint32_t	runtime;
channel_t	*channel, *current_channel;

	maxsize_string = lifetime_string = NULL;
	datadir = NULL;
	maxsize = lifetime = 0;
	do_rescan  		= 0;
	do_expire  		= 0;
	do_list	   		= 0;
	do_update_param = 0;
	is_profile		= 0;
	print_stat		= 0;
	print_books		= 0;
	maxsize_set 	= 0;
	maxlife_set 	= 0;
	low_water		= 0;
	nfsen_format	= 0;
	runtime			= 0;

	while ((c = getopt(argc, argv, "e:hl:L:T:Ypr:s:t:u:w:")) != EOF) {
		switch (c) {
			case 'h':
				usage(argv[0]);
				exit(0);
				break;
			case 'l':
				CheckDataDir(datadir);
				datadir = optarg;
				do_list = 1;
				print_stat = 1;
				break;
			case 'L':
				CheckDataDir(datadir);
				datadir = optarg;
				print_stat  = 1;
				print_books = 1;
				break;
			case 'p':
				is_profile = 1;
				break;
			case 'r':
				CheckDataDir(datadir);
				do_rescan = 1;
				print_stat = 1;
				datadir = optarg;
				break;
			case 'e':
				CheckDataDir(datadir);
				datadir = optarg;
				do_expire = 1;
				print_stat = 1;
				break;
			case 's':
				if ( ParseSizeDef(optarg, &maxsize ) == 0 )
					exit(250);
				maxsize_set = 1;
				break;
			case 't':
				if ( ParseTimeDef(optarg, &lifetime ) == 0 )
					exit(250);
				maxlife_set = 1;
				break;
			case 'u':
				CheckDataDir(datadir);
				datadir = optarg;
				do_update_param = 1;
				break;
			case 'w':
				low_water = strtoll(optarg, NULL, 10);
				if ( low_water > 100 ) {
					fprintf(stderr, "Water mark > 100%%\n");
					exit(250);
				}
				if ( low_water == 0 )
					low_water = 100;
				break;
			case 'T':
				runtime = strtoll(optarg, NULL, 10);
				if ( runtime > 3600 ) {
					fprintf(stderr, "Runtime > 3600 (1h)\n");
					exit(250);
				}
				break;
			case 'Y':
				nfsen_format = 1;
				break;
			default:
				usage(argv[0]);
				exit(250);
		}

	}
	
	datadir = AbsolutePath(datadir);

	if ( !datadir ) {
		fprintf(stderr, "Missing data directory\n");
		usage(argv[0]);
		exit(250);
	}

	err  = stat(datadir, &fstat);
	if ( !(fstat.st_mode & S_IFDIR) ) {
		fprintf(stderr, "No such directory: %s\n", datadir);
		exit(250);
	}

	channel = GetChannelList(datadir, is_profile, do_rescan);
	// GetChannelList(datadir, is_profile, do_rescan);
	if ( !channel ) {
		exit(250);
	}

// printf("Size: %llu, time: %llu\n", maxsize, lifetime);

	// update water mark only, when not listing 
	if ( !is_profile && !do_list && low_water ) 
		channel->dirstat->low_water = low_water;

	/* process do_list first: if the UpdateBookStat results in a FORCE_REBUILD, 
	 * this will immediately done afterwards
	 * do_expire will need accurate books as well, so update the books here as well
	 */
	if ( do_list || do_expire ) {
		current_channel = channel;
		while ( current_channel ) {
			if ( current_channel->books_stat == BOOKKEEPER_OK ) {
				bookkeeper_t	tmp_books;
				printf("Include nfcapd bookeeping record in %s\n", current_channel->datadir);
				ClearBooks(current_channel->books, &tmp_books);
				UpdateBookStat(current_channel->dirstat, &tmp_books);
				if ( current_channel->dirstat->status == FORCE_REBUILD ) 
					current_channel->do_rescan = 1;
			}
			current_channel = current_channel->next;
		}
	}

	// process do_rescan: make sure stats are up to date, if required 
	current_channel = channel;
	while ( current_channel ) {
		if ( current_channel->do_rescan ) {
			int	 i;
			uint64_t last_sequence;
	
			/* detect new files: If nfcapd adds a new file while we are rescanning the directory
		 	* this results in inconsistent data for the rescan. Therefore check at the begin and end
		 	* of the rescan for the sequence number, which reflects the accesss/change to the bookkeeping record
		 	* It's assumed, that such an event does not occure more than once. However, loop 3 times max
		 	*/
			for ( i=0; i<3; i++ ) {
				last_sequence = BookSequence(current_channel->books);
				printf("Scanning files in %s .. ", current_channel->datadir);
				RescanDir(current_channel->datadir, current_channel->dirstat);
				if ( current_channel->dirstat->numfiles == 0 ) { //nothing found
					current_channel->status = NOFILES;
				}
				if ( BookSequence(current_channel->books) == last_sequence ) 
					break;
				printf("Rescan again, due to file changes in directory!\n");
			}
			if ( BookSequence(current_channel->books) != last_sequence ) {
				fprintf(stderr, "Could not savely rescan the directory. Data is not consistent.\n");
				ReleaseBookkeeper(current_channel->books, DETACH_ONLY);
				if ( current_channel->status == OK )
					WriteStatInfo(current_channel->dirstat);
				exit(250);
			}
			printf("done.\n");
			if ( current_channel->books_stat == BOOKKEEPER_OK ) {
				printf("Updating nfcapd bookeeping records\n");
				ClearBooks(channel->books, NULL);
			}
		}
		current_channel = current_channel->next;
	}

	// now process do_expire if required
	if ( do_expire ) {
		dirstat_t	old_stat, current_stat;

		if ( is_profile ) {
			current_stat.status = 0;
			current_stat.max_lifetime 	= lifetime;
			current_stat.max_size  		= maxsize;
			current_stat.low_water 		= low_water ? low_water : 98;

			// sum up all channels in the profile
			current_channel = channel;
			current_stat.numfiles = current_channel->dirstat->numfiles;
			current_stat.filesize = current_channel->dirstat->filesize;
			current_stat.first 	  = current_channel->dirstat->first;
			current_stat.last 	  = current_channel->dirstat->last;
			current_channel = current_channel->next;
			while ( current_channel ) {
				current_stat.numfiles += current_channel->dirstat->numfiles;
				current_stat.filesize += current_channel->dirstat->filesize;
				if ( current_channel->dirstat->first && (current_channel->dirstat->first < current_stat.first) ) 
					current_stat.first = current_channel->dirstat->first;
				if ( current_channel->dirstat->last > current_stat.last ) 
					current_stat.last = current_channel->dirstat->last;
				
				current_channel = current_channel->next;
			}
			old_stat = current_stat;
			ExpireProfile(channel, &current_stat, maxsize, lifetime, runtime);

		} else {
			// cmd args override dirstat values
			if ( maxsize_set ) 
				channel->dirstat->max_size     = maxsize;
			else 
				maxsize = channel->dirstat->max_size;
			if ( maxlife_set ) 
				channel->dirstat->max_lifetime = lifetime;
			else 
				lifetime = channel->dirstat->max_lifetime;
	
		
			old_stat = *(channel->dirstat);
			ExpireDir(channel->datadir, channel->dirstat, maxsize, lifetime, runtime);
			current_stat = *(channel->dirstat);

		}
		// Report, what we have done
		printf("Expired files:      %llu\n", (unsigned long long)(old_stat.numfiles - current_stat.numfiles));
		printf("Expired file size:  %s\n", ScaleValue(old_stat.filesize - current_stat.filesize));
		printf("Expired time range: %s\n\n", ScaleTime(current_stat.first - old_stat.first));
	}

	if ( !is_profile && do_update_param ) {
		switch (channel->books_stat) {
			case BOOKKEEPER_OK:
				if ( maxsize_set ) 
					channel->dirstat->max_size = maxsize;
				else 
					maxsize = channel->dirstat->max_size;
				if ( maxlife_set ) 
					channel->dirstat->max_lifetime = lifetime;
				else 
					lifetime = channel->dirstat->max_lifetime;
				printf("Update collector process running for directory: '%s'\n", datadir);
				UpdateBooksParam(channel->books, (time_t)lifetime, maxsize);
				print_stat = 1;
				break;
			case ERR_NOTEXISTS:
				if ( maxsize_set ) 
					channel->dirstat->max_size = maxsize;
				if ( maxlife_set ) 
					channel->dirstat->max_lifetime = lifetime;
				print_stat = 1;
				break;
			default:
				// should never be reached as already cought earlier
				printf("Error %i while connecting to collector\n", channel->books_stat);
		}
		if ( channel->status == OK || channel->status == NOFILES  )
			WriteStatInfo(channel->dirstat);
	}

	if ( !is_profile && print_books ) {
		switch (channel->books_stat) {
			case BOOKKEEPER_OK:
				PrintBooks(channel->books);
				break;
			case ERR_NOTEXISTS:
				printf("No collector process running for directory: '%s'\n", channel->datadir);
				break;
			default:
				// should never be reached as already cought earlier
				printf("Error %i while connecting to collector\n", channel->books_stat);
		}

	}

	if ( print_stat ) {
		if ( is_profile ) {
			dirstat_t	current_stat;

			current_stat.status = 0;
			current_stat.max_lifetime 	= lifetime;
			current_stat.max_size  		= maxsize;
			current_stat.low_water 		= low_water ? low_water : 98;

			// sum up all channels in the profile
			current_channel = channel;
			current_stat.numfiles = current_channel->dirstat->numfiles;
			current_stat.filesize = current_channel->dirstat->filesize;
			current_stat.first 	  = current_channel->dirstat->first;
			current_stat.last 	  = current_channel->dirstat->last;
			current_channel = current_channel->next;
			while ( current_channel ) {
				current_stat.numfiles += current_channel->dirstat->numfiles;
				current_stat.filesize += current_channel->dirstat->filesize;
				if ( current_channel->dirstat->first && (current_channel->dirstat->first < current_stat.first) ) 
					current_stat.first = current_channel->dirstat->first;
				if ( current_channel->dirstat->last > current_stat.last ) 
					current_stat.last = current_channel->dirstat->last;
				
				current_channel = current_channel->next;
			}
			if ( nfsen_format ) {
				printf("Stat|%llu|%llu|%llu\n", 
					(unsigned long long)current_stat.filesize, 
					(unsigned long long)current_stat.first, (unsigned long long)current_stat.last);
			} else 
				PrintDirStat(&current_stat);
	} else
			if ( nfsen_format )
				printf("Stat|%llu|%llu|%llu\n", 
					(unsigned long long)channel->dirstat->filesize, 
					(unsigned long long)channel->dirstat->first, (unsigned long long)channel->dirstat->last );
			else 
				PrintDirStat(channel->dirstat);
			
	}

	current_channel = channel;
	while ( current_channel ) {
		ReleaseBookkeeper(current_channel->books, DETACH_ONLY);
		if ( current_channel->status == OK )
			WriteStatInfo(current_channel->dirstat);

		current_channel = current_channel->next;
	}

	return 0;
} 
