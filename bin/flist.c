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
 *  $Id: flist.c 39 2009-11-25 08:11:15Z haag $
 *
 *  $LastChangedRevision: 39 $
 *	
 */

#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <fcntl.h>
#include <ctype.h>
#include <netinet/in.h>

#ifdef HAVE_STDINT_H
#	include <stdint.h>
#endif

#ifdef HAVE_FTS_H
#	include <fts.h>
#else
#	include "fts_compat.h"
#define fts_children fts_children_compat
#define fts_close fts_close_compat
#define fts_open  fts_open_compat
#define fts_read  fts_read_compat
#define fts_set   fts_set_compat
#endif

#include "nffile.h"
#include "util.h"
#include "flist.h"

/*
 * Select a single file
 * --------------------
 * -r [/]path/to/single_file
 * Select a single file: absolute or relativ path to a single file.
 * Recursive: no
 *
 * Selecting a range of files
 * --------------------------
 * -R [/]path/to/first_file
 *  Select a range of files in directory specified by absolut or relative path [/]path/to/
 *  Files are selected in alphabetical order starting with 'first_file' to the end of 
 *  the directory.
 *
 * -R [/]path/to/first_file:last_file
 *  Select a range of files in directory specified by absolut or relative path [/]path/to/
 *  Files are selected in alphabetical order starting with 'first_file' and ending with 
 *  'last_file'.
 *
 * -R [/]path/to/directory
 *	Select all files in alphabetical order in directory specified by absolut or relative 
 *	path [/]path/to/directory
 *
 * Selecting files over multiple sources
 * -------------------------------------
 * -M /path/to/multiple/source1:source2[:..:sourceN]
 * It is assumed, that each source directory 'source1', 'source2' etc. exists in directory
 * /path/to/multiple. This will expand to multiple directories:
 * 	/path/to/multiple/source1
 * 	/path/to/multiple/source2
 * 	..
 * 	/path/to/multiple/sourceN
 * 	Each of these directories contain the same files.
 * Used in combination with -r and -R to prepend file selections.
 *
 * Select a single file from multiple directories
 * ----------------------------------------------
 *  -M /path/to/source1:source2	-r single_file	
 *  Select the same file 'single_file' from each source directory: e.g.
 *  /path/to/source1/single_file	
 *  /path/to/source2/single_file	
 *
 *
 * Select a range of files from multiple directories
 * -------------------------------------------------
 *  -M /path/to/source1:source2[:..] -R first_file	
 *  For each expanded directory specified by -M /path/to/source1:source2
 *	select a range of files as described above. Would be identical to
 *	-R /path/to/source1/first_file -R /path/to/source2/first_file
 *
 *  -M /path/to/source1:source2[:..] -R first_file:last_file
 *  For each expanded directory specified by -M /path/to/source1:source2
 *	select a range of files as described above. Would be identical to
 *	-R /path/to/source1/first_file:last_file -R /path/to/source2/first_file:last_file [-R .. ]
 *
 *  -M /path/to/source1:source2[:..] -R .
 *  For each expanded directory specified by -M /path/to/source1:source2
 *  select all files of the directory as described above. Would be to
 *	-R /path/to/source1 -R /path/to/source2 [-R ...]
 *
 *
 * Hierarchical file organinisation:
 * For performance reasons, files may be store in various sub directries instead of a 
 * single directory. These sub directories are assumed to be created in alpabetical order.
 * For example daily sub directories: 2006/04/01 .. 2006/04/30 as created by nfcapd with
 * option -S %y/%m/%d 
 *
 * Single file selection is identical to the flat file layout:
 * -r [/]path/to/sub1/sub2/sub3/single_file
 *
 * Selecting a range of files in a hierarchical file layout
 * --------------------------------------------------------
 * -R [/]path/to/sub1/sub2/first_file
 *  Select a range of files in directory specified by absolut or relative path 
 *  [/]path/to/sub1/sub2/. Files are selected in alphabetical order starting with 
 *  'first_file' to the end of the directory. The hierarchy has no impact here.
 *
 * -R [/]path/to/first_sub1/first_sub2/first_file:last_sub1/last_sub2/last_file
 *  Select a range of files over multiple sub directories starting at absolut or 
 *  relative path [/]path/to/first_sub1/first_sub2/first_file up to and including 
 *  [/]path/to/last_sub1/last_sub2/last_file. Files are selected in alphabetical 
 *  order by iterating over the required sub directory hierachy
 *	Example:
 *	-R /path/to/2006/03/31/nfcapd.200603312300:2006/04/01/nfcapd.200604010600
 *	
 * -R [/]path/to/directory
 *	Select all files in alphabetical order in directory specified by absolut or relative 
 *	path [/]path/to/directory, identical to flat layout
 *
 * The same methode applies for selecting a range of files over multiple sub directories
 * and multiple sources.
 *
 * Example:
 * -M /path/to/source1:source2 -R 2006/03/31/nfcapd.200603312300:2006/04/01/nfcapd.200604010600
 *
 */

/*
 * syntax for possible sub dir definitions:
 *
 * %Y    is replaced by the year with century as a decimal number.
 * %y    is replaced by the year without century as a decimal number (00-99).
 * %m    is replaced by the month as a decimal number (01-12).
 * %d    is replaced by the day of the month as a decimal number (01-31).
 * %j    is replaced by the day of the year as a decimal number (001-366).
 * %H    is replaced by the hour (24-hour clock) as a decimal number (00-23).
 * %M    is replaced by the minute as a decimal number (00-59).
 * %s    is replaced by the number of seconds since the Epoch, UTC
 * %U    is replaced by the week number of the year (Sunday as the first day
 *       of the week) as a decimal number (00-53).
 * %W    is replaced by the week number of the year (Monday as the first day
 *       of the week) as a decimal number (00-53).
 * %w    is replaced by the weekday (Sunday as the first day of the week) as
 *       a decimal number (0-6).
 * %u    is replaced by the weekday (Monday as the first day of the week) as
 *       a decimal number (1-7).
 * %F    is equivalent to ``%Y-%m-%d''.
 */

// predefined and accpeted formats
static const char *subdir_def[] = {
	"",				// default index 0 - no subdir hierarchy
	"%Y/%m/%d",
	"%Y/%m/%d/%H",
	"%Y/%W/%u",
	"%Y/%W/%u/%H",
	"%Y/%j",
	"%Y/%j/%H",
	"%F",
	"%F/%H",
	NULL
};


// all accpeted char in a string
#define AcceptedFormatChar "YymdjHMsUWwuF"

static mode_t mode, dir_mode;
static const char *subdir_format;

static struct entry_filter_s {
	char	*first_entry;
	char	*last_entry;
	int		list_files;
} *dir_entry_filter;

#define NUM_PTR 16

// globals
extern uint32_t	twin_first, twin_last;

static char		*first_file, *last_file;
static char		*current_file = NULL;
static stringlist_t source_dirs, file_list;

/* Function prototypes */
static inline int CheckTimeWindow(uint32_t t_start, uint32_t t_end, stat_record_t *stat_record);

static void GetFileList(char *path);

static void CleanPath(char *entry);

static void Getsource_dirs(char *dirs);

static int mkpath(char *path, char *p, mode_t mode, mode_t dir_mode, char *error, size_t errlen);

static char *GuessSubDir(char *channeldir, char *filename);

static char *VerifyFileRange(char *path, char *last_file);

/* Functions */

static int compare(const FTSENT **f1, const FTSENT **f2) {
    return strcmp( (*f1)->fts_name, (*f2)->fts_name);
} // End of compare

static void CleanPath(char *entry) {
char *p, *q;
size_t	len;

	// wash out any '//' in entry
	while ( (p = strstr(entry, "//")) != NULL ) {
		p++;
		q = p+1;	// q points to first char after '//'
		while ( *p )
			*p++ = *q++;
	}

	// remove trailing '/'
	len = strlen(entry);
	if ( entry[len-1] == '/' )
		entry[len-1] = '\0';

	// wash out any '/./' in entry
	while ( (p = strstr(entry, "/./")) != NULL ) {
		p++;
		q = p+2;	// q points to first char after '/./'
		while ( *p )
			*p++ = *q++;
	}

	// remove leading './' in entry
	if ( strstr(entry, "./") == entry ) {
		p = entry;
		q = p + 2;
		while ( *p )
			*p++ = *q++;
	}

} // End of CleanPath

static inline int CheckTimeWindow(uint32_t t_start, uint32_t t_end, stat_record_t *stat_record) {

/*
	printf("t start %u %s", t_start, ctime(&t_start));
	printf("t end   %u %s", t_end, ctime(&t_end));
	printf("f start %u %s", NetflowStat.first_seen, ctime(&NetflowStat.first_seen));
	printf("f end   %u %s", NetflowStat.last_seen, ctime(&NetflowStat.last_seen));
*/

	// if no time window is set, return true
	if ( t_start == 0 )
		return 1;

	if ( stat_record->first_seen == 0 )
		return 0;

	if ( t_start >= stat_record->first_seen  && t_start <= stat_record->last_seen ) 
		return 1;

	if ( t_end >= stat_record->first_seen  && t_end <= stat_record->last_seen ) 
		return 1;

	if ( t_start < stat_record->first_seen  && t_end > stat_record->last_seen ) 
		return 1;

	return 0;

} // End of CheckTimeWindow

// file filter for scandir function

static int dirlevels(char *dir) {
int num;

	if ( !dir )
		return 0;
	
	num = 0;
	if ( dir[0] == '/' )
		dir++;

	while ( *dir ) {
		if ( *dir == '/' )
			num++;
		dir++;
	}

	return num;

} // End of dirlevels

static void CreateDirListFilter(char *first_path, char *last_path, int file_list_level) {
int i;
char *p, *q, *first_mark, *last_mark;

//	printf("First Dir: '%s', first_path: '%s', last_path '%s', first_file '%s', last_file '%s', list_level: %i\n", 
//			source_dirs.list[0], first_path, last_path, first_file, last_file, file_list_level);

	if ( file_list_level == 0 )
		return;

	if ( file_list_level < 0 ) {
		fprintf(stderr, "software error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(250);
	}

	dir_entry_filter = (struct entry_filter_s *)malloc((file_list_level+1) * sizeof(struct entry_filter_s));
	if ( !dir_entry_filter ) {
		fprintf(stderr, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(250);
	}

	// first default entry - the directory itself
	dir_entry_filter[0].first_entry = NULL;
	dir_entry_filter[0].last_entry  = NULL;
	dir_entry_filter[0].list_files  = 0;

	first_mark = first_path;
	last_mark  = last_path;
	// intermediate directory level filters
	for ( i=1; i<file_list_level; i++ ) {
		if ( first_mark ) {
			p = strchr(first_mark, '/');
			if ( p ) {
				*p = '\0';
				dir_entry_filter[i].first_entry = strdup(first_path);
				*p++ = '/';
				first_mark = p;
			} else {
				dir_entry_filter[i].first_entry = strdup(first_path);
				first_mark = NULL;
			}
		} else {
			dir_entry_filter[i].first_entry = NULL;
		}
		dir_entry_filter[i].list_files  = 0;

		if ( last_mark ) {
			q = strchr(last_mark, '/');
			if ( q ) {
				*q = '\0';
				dir_entry_filter[i].last_entry = strdup(last_path);
				*q++ = '/';
				last_mark = q;
			} else {
				dir_entry_filter[i].last_entry = strdup(last_path);
				last_mark = NULL;
			}
		} else {
			dir_entry_filter[i].last_entry = NULL;
		}
		if ( dir_entry_filter[i].first_entry && dir_entry_filter[i].last_entry &&
			 strcmp(dir_entry_filter[i].first_entry, dir_entry_filter[i].last_entry) > 0 )
			fprintf(stderr, "WARNING: Entry '%s' > '%s'. Will not match anything!\n",
					dir_entry_filter[i].first_entry, dir_entry_filter[i].last_entry);

//		printf("%i first: '%s', last: '%s'\n", 
//			i, dir_entry_filter[i].first_entry, dir_entry_filter[i].last_entry);
	}

	// the last level - files are listed here
	dir_entry_filter[file_list_level].first_entry = first_file;
	dir_entry_filter[file_list_level].last_entry  = last_file;
	dir_entry_filter[file_list_level].list_files  = 1;

	if ( dir_entry_filter[file_list_level].first_entry && dir_entry_filter[file_list_level].last_entry &&
		 strcmp(dir_entry_filter[file_list_level].first_entry, dir_entry_filter[file_list_level].last_entry) > 0 )
		fprintf(stderr, "WARNING: File '%s' > '%s'. Will not match anything!\n",
				dir_entry_filter[file_list_level].first_entry, dir_entry_filter[file_list_level].last_entry);

//	printf("%i first: '%s', last: '%s'\n", 
//		file_list_level, dir_entry_filter[file_list_level].first_entry, dir_entry_filter[file_list_level].last_entry);

} // End of CreateDirListFilter

static void GetFileList(char *path) {
struct stat stat_buf;
char *last_file_ptr, *first_path, *last_path;
int levels_first_file, levels_last_file, file_list_level;
int	sub_index;

FTS *fts;
FTSENT *ftsent;

	CleanPath(path);

	// Check for last_file option
	last_file_ptr = strchr(path, ':');
	first_path = last_path = NULL;
	levels_first_file =  levels_last_file = 0;
	if ( last_file_ptr ) {
		// make sure we have only a single ':' in path
		if ( strrchr(path, ':') != last_file_ptr ) {
			fprintf(stderr, "Multiple file separators ':' in path not allowed!\n");
			exit(250);
		}
		*last_file_ptr++ = '\0';
		// last_file_ptr points to last_file

		if ( strlen(last_file_ptr) == 0 ) {
			fprintf(stderr, "Missing last file option after ':'!\n");
			exit(250);
		}
	
		CleanPath(last_file_ptr);
		// make sure last_file option is not a full path
		if ( last_file_ptr[0] == '/') {
			fprintf(stderr, "Last file name in -R list must not start with '/'\n");
			exit(250);
		}
		// how may sub dir levels has last_file option?
		levels_last_file  = dirlevels(last_file_ptr);

		// if no subdirs are given for last_file, try to find out, if the last_file
		// exists in any possible subdirs
		if ( levels_last_file == 0 ) {
			char s[MAXPATHLEN];
			char *r = VerifyFileRange(path, last_file_ptr);

			if ( r != last_file_ptr && r[0] != '\0' ) {
				snprintf(s, MAXPATHLEN-1, "%s/%s", r, last_file_ptr);
				s[MAXPATHLEN-1] = '\0';
				last_file_ptr = strdup(s);
				levels_last_file  = dirlevels(last_file_ptr);
			}
		}

	}

	levels_first_file = dirlevels(path);

	if ( source_dirs.num_strings == 0 ) {
		// No multiple sources option -M

		// path contains the path to a file/directory
		// stat this entry
		if ( stat(path, &stat_buf) ) {
			fprintf(stderr, "stat() error '%s': %s\n", path, strerror(errno));
			exit(250);
		}
		if ( !S_ISDIR(stat_buf.st_mode) && !S_ISREG(stat_buf.st_mode) ) {
			fprintf(stderr, "Not a file or directory: '%s'\n", path);
			exit(250);
		}

		// Check, how many levels of directory in path
		levels_first_file = dirlevels(path);

		if ( last_file_ptr ) {
			// path is [/]path/to/any/dir|file:last_file_ptr

			// make sure first_file is a file
			if ( S_ISDIR(stat_buf.st_mode) ) {
				fprintf(stderr, "Not a file: '%s'\n", path);
				exit(250);
			}

			if ( levels_last_file ) {
				// we have levels_last_file number of sub dirs 
	
				// sub dir levels of first_file mus have at least the same number of levels as last_file
				if ( levels_first_file < levels_last_file ) {
					fprintf(stderr, "Number of sub dirs for sub level hierarchy for file list -R do not match\n");
					exit(250);
				}
				if ( levels_first_file == levels_last_file ) {
					char *p, *q;
					// path = [/]sub1[/..]/first_file:sub1[/...]/last_file
					if ( path[0] == '/' ) {
						// this is rather strange, but strctly spoken, valid anyway
						InsertString(&source_dirs, "/");
						path++;
					} else {
						InsertString(&source_dirs, ".");
					}

					// path = sub_first[/..]/first_file:sub_last[/...]/last_file
					p = strrchr(path, '/');
					q = strrchr(last_file_ptr, '/');
					if ( !p || !q ) {
						// this should never happen
						fprintf(stderr, "software error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
						exit(250);
					}
					*p++ = '\0';
					*q++ = '\0';
					first_file = strdup(p);
					last_file = strdup(q);
					file_list_level = levels_last_file + 1;
					first_path = path;
					last_path  = last_file_ptr;
					
				} else {
					// path = [/]path/to/sub_first[/..]/first_file:sub_last[/...]/last_file
					int i;
					char *p, *r, *s;

					p = strrchr(path, '/');
					// levels_first_file > levels_last_file

					// step back the number of sub dirs in first_file
					for ( i=0; i<levels_last_file; i++ ) {
						do {
							p--;
						} while ( p >= path && *p != '/');
					}
					*p++ = '\0';
					
					InsertString(&source_dirs, path);

					r = strrchr(p, '/');
					s = strrchr(last_file_ptr, '/');
					if ( !r || !s ) {
						// this must never happen
						fprintf(stderr, "software error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
						exit(250);
					}
					*r++ = '\0';
					*s++ = '\0';
					first_file = strdup(r);
					last_file = strdup(s);
					// files are listed at this sub dir level
					file_list_level = levels_last_file + 1;
					first_path = p;
					last_path  = last_file_ptr;

				}

			} else {
				// we have no sub dir levels given

				// path is [/]path/to/any/file
				char *p = strrchr(path, '/');

				if ( p ) {
					// path is [/]path/to/any/first_file:last_file
					*p++ = '\0';
					// path is the direcory containing all the files
					InsertString(&source_dirs, path);
					first_file = strdup(p);
				} else {
					// path is first_file:last_file
					InsertString(&source_dirs, ".");
					first_file = strdup(path);
				}
				// set last_file filter
				last_file  = strdup(last_file_ptr);
				// in any case we list the files of directory level 1
				file_list_level = 1;
			}
		} else {
			// path is [/]path/to/any/dir|file
			if ( S_ISDIR(stat_buf.st_mode) ) {
				// path is [/]path/to/any/dir
				// list all files in this directory
				InsertString(&source_dirs, path);
				first_file = NULL;
				file_list_level = 0;
			} else {
				// path is [/]path/to/any/file
				char *p = strrchr(path, '/');
				if ( p ) {
					// path is [/]path/to/any/file
					*p++ = '\0';
					// path is the direcory containing all the files
					InsertString(&source_dirs, path);
					first_file = strdup(p);
				} else {
					// path is file
					InsertString(&source_dirs, ".");
					first_file = strdup(path);
				}
				// in any case we list the files of directory level 1
				file_list_level = 1;
			}
			// in any case, no last_file filter
			last_file  = NULL;
		}

	} else {
		char pathbuff[MAXPATHLEN];
		// multiple sources option -M given
		if ( path[0] == '/') {
			fprintf(stderr, "File list -R must not start with '/' when combined with a source list -M\n");
			exit(250);
		}

		// special case for all files in directory
		if ( strcmp(path, ".") == 0 ) {
			first_file = NULL;
			last_file  = NULL;
			file_list_level = 0;
		} else {
			// pathbuff contains the path to a file/directory, compiled using the first entry
			// in the source_dirs
			snprintf(pathbuff, MAXPATHLEN-1, "%s/%s", source_dirs.list[0], path);
			pathbuff[MAXPATHLEN-1] = '\0';
	
			// pathbuff must point to a file
			if ( stat(pathbuff, &stat_buf) ) {
				if ( errno == ENOENT ) {
					// file not found - try to guess a possible subdir
					char *sub_dir = GuessSubDir(source_dirs.list[0], path);
					if ( sub_dir ) {	// subdir found
						snprintf(pathbuff, MAXPATHLEN-1, "%s/%s", sub_dir, path);
						pathbuff[MAXPATHLEN-1] = '\0';
						// update path
						path = strdup(pathbuff);
						free(sub_dir);
	
						// need guessing subdir with last_file too
						if ( last_file_ptr ) {
							sub_dir = GuessSubDir(source_dirs.list[0], last_file_ptr);
							if ( sub_dir ) {	// subdir found
								snprintf(pathbuff, MAXPATHLEN-1, "%s/%s", sub_dir, last_file_ptr);
								pathbuff[MAXPATHLEN-1] = '\0';
								last_file_ptr = strdup(pathbuff);
								free(sub_dir);
	
								// update dir levels of extended file path
								levels_last_file  = dirlevels(last_file_ptr);
							} else {
								fprintf(stderr, "'%s': %s\n", last_file_ptr, "File not found!");
								exit(250);
							}
						}
	
					} else {	// no file in any possible subdir found
						fprintf(stderr, "stat() error '%s': %s\n", pathbuff, "File not found!");
						exit(250);
					}
				} else {	// Any other stat error
					fprintf(stderr, "stat() error '%s': %s\n", pathbuff, strerror(errno));
					exit(250);
				}
			} else if ( !S_ISREG(stat_buf.st_mode) ) {
				fprintf(stderr, "Not a file : '%s'\n", pathbuff);
				exit(250);
			}

			// Check, how many levels of directory in path
			levels_first_file = dirlevels(path);

			if ( last_file_ptr ) {
				// path is path/to/any/first_file:last_file_ptr
				char *p, *q;
	
				// the number of sub dirs must be eqal for first_file and last_file
				if ( levels_first_file != levels_last_file ) {
					fprintf(stderr, "Number of sub dirs must agree in '%s' and '%s'\n", path, last_file_ptr);
					exit(250);
				}
	
				p = strrchr(path, '/');
				if ( p ) {
					// path is fist_sub/to/any/first_file
					// recursive all files in sub dirs
					file_list_level = dirlevels(path) + 1;
					*p++ = '\0';
					first_file = strdup(p);
					first_path = path;
				} else {
					// path is first_file
					first_file = strdup(path);
					file_list_level = 1;
				}

				q = strrchr(last_file_ptr, '/');
				if ( q ) {
					*q++ = '\0';
					last_file = strdup(q);
					last_path  = last_file_ptr;
				} else {
					last_file = strdup(last_file_ptr);
				}
	
			} else {
				// path is path/to/any/first_file
				char *p = strrchr(path, '/');
				if ( p ) {
					// path is fist_sub/to/any/first_file
					// recursive all files in sub dirs
					file_list_level = dirlevels(path) + 1;
					*p++ = '\0';
					first_file = strdup(p);
					first_path = path;
				} else {
					// path is first_file
					first_file = strdup(path);
					file_list_level = 1;
				}
				last_file  = NULL;
			}
		}
	}

/*
printf("first_file %s\n", first_file ? first_file : "<none>");
printf("last_file %s\n", last_file ? last_file : "<none>");
printf("first_path %s\n", first_path ? first_path : "<none>");
printf("last_path %s\n", last_path ? last_path : "<none>");
printf("file_list_level: %i\n", file_list_level);
*/
	CreateDirListFilter(first_path, last_path, file_list_level );

	// last entry must be NULL
	InsertString(&source_dirs, NULL);
	fts = fts_open(source_dirs.list, FTS_LOGICAL,  compare);
	sub_index = 0;
	while ( (ftsent = fts_read(fts)) != NULL) {
		int fts_level = ftsent->fts_level;
		char *fts_path;

// printf("DBG: %u %i %s %s\n", ftsent->fts_info, ftsent->fts_level, ftsent->fts_path, ftsent->fts_name);

		if ( fts_level == 0 ) {
			sub_index = ftsent->fts_pathlen + 1;
			continue;
		}

		if ( ftsent->fts_pathlen < sub_index ) {
			printf("ERROR: fts_pathlen error at %s line %d\n", __FILE__, __LINE__);
			exit(250);
		}
		fts_path = &ftsent->fts_path[sub_index];

/*
if ( file_list_level ) 
printf("DGB: short fts: '%s', filer_first: '%s', filter_last: '%s'\n", 
					fts_path, dir_entry_filter[fts_level].first_entry , dir_entry_filter[fts_level].last_entry);
*/
		switch (ftsent->fts_info) {
			case FTS_D:
				// dir entry pre descend
				if ( file_list_level && file_list_level && (
					( dir_entry_filter[fts_level].first_entry &&
						( strcmp(fts_path, dir_entry_filter[fts_level].first_entry ) < 0 ) ) ||
					( dir_entry_filter[fts_level].last_entry && 
					  	( strcmp(fts_path, dir_entry_filter[fts_level].last_entry ) > 0 ) ) 
				   ))
					fts_set(fts, ftsent, FTS_SKIP );

				break;
			case FTS_DP:
				break;
			case FTS_F:
				// file entry
// printf("==> Check: %s\n", ftsent->fts_name);

				// skip stat file
				if ( strcmp(ftsent->fts_name, ".nfstat") == 0 ||
					 strncmp(ftsent->fts_name, NF_DUMPFILE , strlen(NF_DUMPFILE)) == 0)
					continue;
				if ( strstr(ftsent->fts_name, ".stat") != NULL )
					continue;
				// skip pcap file
				if ( strstr(ftsent->fts_name, "pcap") != NULL )
					continue;

				if ( file_list_level && (
					( fts_level != file_list_level ) ||
					( dir_entry_filter[fts_level].first_entry && 
						( strcmp(ftsent->fts_name, dir_entry_filter[fts_level].first_entry) < 0 ) ) ||
					( dir_entry_filter[fts_level].last_entry &&
					  	( strcmp(ftsent->fts_name, dir_entry_filter[fts_level].last_entry) > 0 ) )
				   ) )
					continue;

// printf("==> Listed: %s\n", ftsent->fts_path);
				InsertString(&file_list, ftsent->fts_path);

				break;
		}

	}
    fts_close(fts);

} // End of GetFileList

/*
 * Get the list of directories 
 * dirs: user supplied parameter: /any/path/dir1:dir2:dir3:...
 * 		source_dirs must result in 
 * 		/any/path/dir1
 * 		/any/path/dir2
 * 		/any/path/dir3
 * 	/any/path is dir prefix, which may be NULL e.g. dir1:dir2:dir3:...
 * 	dir1, dir2 etc entrys
 */
void Getsource_dirs(char *dirs) {
struct stat stat_buf;
char	*p, *q, *dirprefix;
char	path[MAXPATHLEN];

	q = strchr(dirs, ':');
	if ( q ) { // we have /path/to/firstdir:dir1:dir2:...
		*q = 0;
		p = strrchr(dirs, '/');
		if ( p ) {
			*p++ = 0;	// p points now to the first name in the dir list
			dirprefix = dirs;
		} else  { // we have a source_dirs in current directory
			p = dirs;	// p points now to the first name in the dir list
			dirprefix = ".";	// current directory
		}
		*q = ':';	// restore ':' in source_dirs

		while ( p ) { // iterate over all elements in the dir list
			q = strchr(p, ':');
			if ( q ) 
				*q = 0;

			// p point to a dir name
			snprintf(path, 1023, "%s/%s", dirprefix, p);
			path[MAXPATHLEN-1] = 0;
			if ( stat(dirs, &stat_buf) ) {
				fprintf(stderr, "Can't stat '%s': %s\n", path, strerror(errno));
				return;
			}
			if ( !S_ISDIR(stat_buf.st_mode) ) {
				fprintf(stderr, "Not a directory: '%s'\n", path);
				return;
			}

			// save path into source_dirs
			InsertString(&source_dirs, path);

			p = q ? q + 1 : NULL;
		}

	} else { // we have only one directory
		if ( stat(dirs, &stat_buf) ) {
			fprintf(stderr, "Can't stat '%s': %s\n", dirs, strerror(errno));
			return;
		}
		if ( !S_ISDIR(stat_buf.st_mode) ) {
			fprintf(stderr, "Not a directory: '%s'\n", dirs);
			return;
		}

		// save the path into source_dirs
		InsertString(&source_dirs, dirs);
	}

} // End of Getsource_dirs

void SetupInputFileSequence(char *multiple_dirs, char *single_file, char *multiple_files) {

	twin_first  = 0;
	twin_last   = 0xffffffff;

	first_file 	= NULL;
	last_file  	= NULL;

	InitStringlist(&source_dirs, NUM_PTR);
	InitStringlist(&file_list, 64);

	if ( multiple_dirs ) 
		Getsource_dirs(multiple_dirs);

	if ( multiple_files ) {
		// use multiple files
		GetFileList(multiple_files);

		// get time window spanning all the files 
		if ( file_list.num_strings ) {
			stat_record_t stat_ptr;

			// read the stat record
			if ( !GetStatRecord(file_list.list[0], &stat_ptr) ) {
				exit(250);
			}
			twin_first = stat_ptr.first_seen;

			// read the stat record of last file
			if ( !GetStatRecord(file_list.list[file_list.num_strings-1], &stat_ptr) ) {
				exit(250);
			}
			twin_last  = stat_ptr.last_seen;
		}

	} else if ( single_file ) {
		CleanPath(single_file);

		if ( source_dirs.num_strings == 0 ) {
			stat_record_t stat_ptr;
			InsertString(&file_list, single_file);
			if ( !GetStatRecord(single_file, &stat_ptr) ) {
				exit(250);
			}
			twin_first = stat_ptr.first_seen;
			twin_last  = stat_ptr.last_seen;

		} else {
			int i;

			if ( single_file[0] == '/' ) {
				fprintf(stderr, "File -r must not start with '/', when combined with a source list -M\n");
				exit(250);
			}

			for ( i=0; i<source_dirs.num_strings; i++ ) {
				char s[MAXPATHLEN];
				struct stat stat_buf;

				snprintf(s, MAXPATHLEN-1, "%s/%s", source_dirs.list[i], single_file);
				s[MAXPATHLEN-1] = '\0';
				if ( stat(s, &stat_buf) ) {
					if ( errno == ENOENT ) {
						// file not found - try to guess subdir
						char *sub_dir = GuessSubDir(source_dirs.list[i], single_file);
						if ( sub_dir ) {	// subdir found
							stat_record_t stat_ptr;
							snprintf(s, MAXPATHLEN-1, "%s/%s/%s", source_dirs.list[i], sub_dir, single_file);
							s[MAXPATHLEN-1] = '\0';
							InsertString(&file_list, s);
							if ( !GetStatRecord(s, &stat_ptr) ) {
								exit(250);
							}
							twin_first = stat_ptr.first_seen;
							twin_last  = stat_ptr.last_seen;
						} else {	// no subdir found
							fprintf(stderr, "stat() error '%s': %s\n", s, "File not found!");
						}
					} else {	// Any other stat error
						fprintf(stderr, "stat() error '%s': %s\n", s, strerror(errno));
						exit(250);
					}
				} else {	// stat() successful
					if ( !S_ISREG(stat_buf.st_mode) ) {
						fprintf(stderr, "Skip non file entry: '%s'\n", s);
					} else {
						stat_record_t stat_ptr;
						InsertString(&file_list, s);
						if ( !GetStatRecord(s, &stat_ptr) ) {
							exit(250);
						}
						twin_first = stat_ptr.first_seen;
						twin_last  = stat_ptr.last_seen;
				
					}
				}
			}
		}

	} else // else use stdin
		InsertString(&file_list, NULL);

} // End of SetupInputFileSequence

char *GetCurrentFilename(void) {
	return current_file;
} // End of GetCurrentFilename

nffile_t *GetNextFile(nffile_t *nffile, time_t twin_start, time_t twin_end) {
static int cnt;

	// close current file before open the next one
	// stdin ( current = 0 ) is not closed
	if ( nffile ) {
		CloseFile(nffile);
		current_file = NULL;
	} else {
		// is it first time init ?
		cnt  = 0;
	}

	// no or no more files available
	if ( file_list.num_strings == cnt ) {
		current_file = NULL;
		return EMPTY_LIST;
	}
	

	while ( cnt < file_list.num_strings ) {
#ifdef DEVEL
		printf("Process: '%s'\n", file_list.list[cnt] ? file_list.list[cnt] : "<stdin>");
#endif
		nffile = OpenFile(file_list.list[cnt], nffile);	// Open the file
		if ( !nffile ) {
			return NULL;
		}
		current_file = file_list.list[cnt];
		cnt++;

		// stdin
		if ( nffile->fd == STDIN_FILENO ) {
			current_file = NULL;
			return nffile;
		}

		if ( CheckTimeWindow(twin_start, twin_end, nffile->stat_record) ) {
			// printf("Return file: %s\n", string);
			return nffile;
		} 
		CloseFile(nffile);
	}

	current_file = NULL;
	return EMPTY_LIST;

} // End of GetNextFile


int InitHierPath(int num) {
int i;

	subdir_format = NULL;

	i=0;
	while ( subdir_def[i] != NULL ) {
		if ( i == num )
			break;
		i++;
	}
	if ( subdir_def[i] == NULL ) {
		fprintf(stderr, "No such subdir level %i\n", num);
		return 0;
	}

	subdir_format = subdir_def[i];

    /*
     * The default file mode is a=rwx (0777) with selected permissions
     * removed in accordance with the file mode creation mask.  For
     * intermediate path name components, the mode is the default modified
     * by u+wx so that the subdirectories can always be created.
     */

	// get umask
	mode = umask(0);
	umask(mode);

    mode = 0777 & ~mode;
    dir_mode = mode | S_IWUSR | S_IXUSR;

	return 1;

} // End of InitHierPath

static char *VerifyFileRange(char *path, char *last_file) {
char *p, *q, *r;

	r = strdup(path);
	p = strrchr(r, '/');
	while ( p ) {
		*p = '\0';
	
		q = GuessSubDir(r, last_file);
		if ( q ) {
			free(r);
			return q;
		}
		p = strrchr(r, '/');
	}

	free(r);
	return last_file;

} // End of VerifyFileRange

static char *GuessSubDir(char *channeldir, char *filename) {
char s[MAXPATHLEN];
struct  tm *t_tm;
int	i;

	if ( strlen(filename) == 19 && (strncmp(filename, "nfcapd.", 7) == 0) ) {
		char *p  = &filename[7];
		time_t t = ISO2UNIX(p);
		t_tm = localtime(&t);
	} else
		return NULL;

	i = 0;
	// if the file exists, it must be in any of the possible subdirs
	// so try one after the next - one will match
	while ( subdir_def[i] ) {
		char const *sub_fmt = subdir_def[i];
		char subpath[255];
		struct stat stat_buf;
		strftime(subpath, 254, sub_fmt, t_tm);
		subpath[254] = '\0';

		snprintf(s, MAXPATHLEN-1, "%s/%s/%s", channeldir, subpath, filename);
		if ( stat(s, &stat_buf) == 0 && S_ISREG(stat_buf.st_mode) ) {
			// found file in subdir 
			return strdup(subpath);
		}
		i++;
	}

	return NULL;

} // End of GuessSubDir

char *GetSubDir(struct  tm *now ) {
static char subpath[255];
size_t sublen;

	sublen = strftime(subpath, 254, subdir_format, now);

	return sublen == 0 ? NULL : subpath;

} // End of GetSubDir

int SetupSubDir(char *dir, char *subdir, char *error, size_t errlen ) {
char *p, path[MAXPATHLEN];
struct stat stat_buf;
size_t	sublen, pathlen;
int err;

	error[0] = '\0';

	path[0] = '\0';
	strncat(path, dir, MAXPATHLEN-1);
	path[MAXPATHLEN-1] = '\0';

	sublen  = strlen(subdir);
	pathlen = strlen(path);
	// set p as reference between path and subdir
	if ( (sublen + pathlen + 2) >= (MAXPATHLEN-1) ) {	// +2 : add 1 for '/'
		snprintf(error, errlen, "Path '%s': too long", path);
		return 0;
	}

	p = path + pathlen;	// points to '\0' of path
	*p++ = '/';
	*p   = '\0';

	strncat(path, subdir, MAXPATHLEN-pathlen-2);	// +2: add 1 for '/'

	// our cwd is basedir ( -l ) so test if, dir exists
	if ( stat(path, &stat_buf) == 0 ) {
		if ( S_ISDIR(stat_buf.st_mode) ) {
			// sub directory already exists
			return 1;
		} else {
			// an entry with this name exists, but it's not a directory
			snprintf(error, errlen, "Path '%s': %s ", path, strerror(ENOTDIR));
			return 0;
		}
	}

	// no such entry exists - try to create the directory, assuming path below exists
	err = mkdir(path, dir_mode);
	if ( err == 0 ) // success
		return 1;

	// else errno is set
	if ( errno == ENOENT ) { // we need to create intermediate directories as well
		err = mkpath(path, p, mode, dir_mode, error, errlen);
		if ( err == 0 ) // creation was successful
			return 1;
	} else {
		snprintf(error, errlen, "mkdir() error for '%s': %s\n", path, strerror(errno));
	}

	// anything else failed and error string is set
	return 0;

} // End of SetupSubDir

/*
 * mkpath -- create directories.
 *  path     - path
 *  p        - separator path/subpath
 *  mode     - file mode of terminal directory
 *  dir_mode - file mode of intermediate directories
 */
static int mkpath(char *path, char *p, mode_t mode, mode_t dir_mode, char *error, size_t errlen) {
struct stat sb;
char *slash;
int done = 0;

    slash = p;

    while (!done) {
        slash += strspn(slash, "/");
        slash += strcspn(slash, "/");

        done = (*slash == '\0');
        *slash = '\0';

        if (stat(path, &sb)) {
            if (errno != ENOENT || (mkdir(path, done ? mode : dir_mode) && errno != EEXIST)) {
				snprintf(error, errlen, "mkdir() error for '%s': %s\n", path, strerror(errno));
                return (-1);
            }
        } else if (!S_ISDIR(sb.st_mode)) {
			snprintf(error, errlen, "Path '%s': %s ", path, strerror(ENOTDIR));
            return (-1);
        }

        *slash = '/';
    }

    return (0);

} // End of mkpath

