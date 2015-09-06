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
 *  $Id: nfstatfile.c 39 2009-11-25 08:11:15Z haag $
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
#include <sys/file.h>
#include <sys/param.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nfstatfile.h"

#define stat_filename ".nfstat"

typedef struct config_def_s {
	char		*name;
	// int			type;
	uint64_t	*value;
} config_def_t;

static dirstat_t dirstat_tmpl;

static config_def_t config_def[] = {
	{ "first", 	   &dirstat_tmpl.first},
	{ "last",	   &dirstat_tmpl.last },
	{ "size",	   &dirstat_tmpl.filesize },
	{ "maxsize",   &dirstat_tmpl.max_size  },
	{ "numfiles",  &dirstat_tmpl.numfiles  },
	{ "lifetime",  &dirstat_tmpl.max_lifetime },
	{ "watermark", &dirstat_tmpl.low_water },
	{ "status",    &dirstat_tmpl.status },
	{ NULL, 	NULL },
};


#define STACK_BLOCK_SIZE 32

static int	stack_max_entries = 0;
static dirstat_env_t *dirstat_stack = NULL;

static const double _1K = 1024.0;
static const double _1M = 1024.0 * 1024.0;
static const double _1G = 1024.0 * 1024.0 * 1024.0;
static const double _1T = 1024.0 * 1024.0 * 1024.0 * 1024.0;

static const double _1min  = 60.0;
static const double _1hour = 3600.0;
static const double _1day  = 86400.0;
static const double _1week = 604800.0;

/* 
 * expire.c is needed for daemon code as well as normal stdio code 
 * therefore a generic LogError is defined, which maps to the 
 * approriate logging channel - either stderr or syslog
 */
void LogError(char *format, ...);

static inline uint64_t string2uint64(char *s);

static int ParseString(char *str, char **key, char **value);

static void VerifyStatInfo(dirstat_t *statinfo);

char *ScaleValue(uint64_t v) {
double f = v;
static char s[64];

	if ( f < _1K ) {	// 1 K 1024
		snprintf(s, 63, "%llu B", (unsigned long long)v);
	} else if ( f < _1M ) {	
		snprintf(s, 63, "%llu = %.1f KB", (unsigned long long)v, f / _1K );
	} else if ( f < _1G ) {
		snprintf(s, 63, "%llu = %.1f MB", (unsigned long long)v, f / _1M );
	} else if ( f < _1T ) {
		snprintf(s, 63, "%llu = %.1f GB", (unsigned long long)v, f / _1G );
	} else {	// everything else in T
		snprintf(s, 63, "%llu = %.1f TB", (unsigned long long)v, f / _1T );
	}
	s[63] = '\0';
	
	return s;

} // End of ScaleValue

char *ScaleTime(uint64_t v) {
double f = v;
static char s[64];

	if ( f < _1min ) {	
		snprintf(s, 63, "%llu sec", (unsigned long long)v);
	} else if ( f < _1hour ) {	
		snprintf(s, 63, "%llu = %.1f min", (unsigned long long)v, f / _1min );
	} else if ( f < _1day ) {
		snprintf(s, 63, "%llu = %.1f hours", (unsigned long long)v, f / _1hour );
	} else if ( f < _1week ) {
		snprintf(s, 63, "%llu = %.1f days", (unsigned long long)v, f / _1day );
	} else {	// everything else in weeks
		snprintf(s, 63, "%llu = %.1f weeks", (unsigned long long)v, f / _1week );
	}
	s[63] = '\0';
	
	return s;

} // End of ScaleValue


static inline uint64_t string2uint64(char *s) {
uint64_t	u=0;
char 		*p = s;

	while( *p ) {
		if ( *p < '0' || *p > '9' ) 
			*p = '0';
		u = 10LL*u + (*p++ - 48);
	}
	return u;

} // End of string2uint64

static int SetFileLock(int fd) {
    struct flock fl;

    fl.l_type   = F_WRLCK;  /* F_RDLCK, F_WRLCK, F_UNLCK    */
    fl.l_whence = SEEK_SET; /* SEEK_SET, SEEK_CUR, SEEK_END */
    fl.l_start  = 0;        /* Offset from l_whence         */
    fl.l_len    = 0;        /* length, 0 = to EOF           */
    fl.l_pid    = getpid(); /* our PID                      */

    return fcntl(fd, F_SETLKW, &fl);  /* F_GETLK, F_SETLK, F_SETLKW */

} // End of SetFileLock

static int ReleaseFileLock(int fd) {
    struct flock fl;

    fl.l_type   = F_UNLCK;  /* F_RDLCK, F_WRLCK, F_UNLCK    */
    fl.l_whence = SEEK_SET; /* SEEK_SET, SEEK_CUR, SEEK_END */
    fl.l_start  = 0;        /* Offset from l_whence         */
    fl.l_len    = 0;        /* length, 0 = to EOF           */
    fl.l_pid    = getpid(); /* our PID                      */

	return fcntl(fd, F_SETLK, &fl); /* set the region to unlocked */

} // End of SetFileLock

static int ParseString(char *str, char **key, char **value) {
char *k, *v, *w;

	k = str;
	v = strpbrk(str, "=");	
	if ( !v ) {
		printf("Invalid config line: '%s'\n", str);
		*key   = NULL;
		*value = NULL;
		return 0;
	}

	*v++ = '\0';

	// strip white spaces from end of key
	w = strpbrk(k, " ");
	if ( w )
		*w = '\0';

	// strip white spaces from start of value
	while ( *v == ' ' ) {
		v++;
	}

	*key   = k;
	*value = v;

	return 1;

} // End of ParseString

static void VerifyStatInfo(dirstat_t *statinfo) {

	if ( ( statinfo->first == 0 ) 			  || ( statinfo->first > statinfo->last || 
		 ( statinfo->status > FORCE_REBUILD ) || ( statinfo->low_water > 100 ) ) )
		statinfo->status = FORCE_REBUILD;	// -> fishy

} // End of VerifyStatInfo

/*
 * Reads the stat record from .nfstat file
 *	dirname: 	directory to read the .nfstat file
 *	dirstat_p:	Assign a point of the result to this pointer
 *	lock:		READ_ONLY file is locked while reading, and unlocked and closed thereafter
 *				CREATE_AND_LOCK if file does not exists, create it - continue as LOCK_IF_EXISTS
 *				LOCK_IF_EXISTS: lock the file if it exists - file remains open
 * If file does not exists, an empty record is returned.
 */
int ReadStatInfo(char *dirname, dirstat_t **dirstat_p, int lock ) {
struct stat filestat;
char *in_buff, *s, *p, *k, *v;
char filename[MAXPATHLEN];
int fd, err, r_size, next_free;

	*dirstat_p = NULL;

	// if the dirstack does not exist, creat it
	if ( !dirstat_stack ) {
		int i;
		dirstat_stack = (dirstat_env_t *)malloc(STACK_BLOCK_SIZE * sizeof(dirstat_env_t));
		if ( !dirstat_stack ) {
			LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			return ERR_FAIL;
		}
		for ( i=0; i<STACK_BLOCK_SIZE; i++ ) {
			dirstat_stack[i].dirstat = NULL;
		}
		stack_max_entries = STACK_BLOCK_SIZE;
	}

	// search for next free slot
	next_free = 0;
	while ( next_free < stack_max_entries && (dirstat_stack[next_free].dirstat != NULL) )
		next_free++;

	// if too many entries exist, expand the stack
	if ( next_free >= stack_max_entries ) {
		dirstat_env_t *tmp;
		int i;
		tmp = realloc((void *)dirstat_stack, (stack_max_entries+STACK_BLOCK_SIZE) * sizeof(dirstat_env_t));
		if ( !tmp ) {
			LogError("ralloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			return ERR_FAIL;
		}
		dirstat_stack = tmp;
		for ( i=stack_max_entries; i<stack_max_entries+STACK_BLOCK_SIZE; i++ ) {
			dirstat_stack[i].dirstat = NULL;
		}
		next_free = stack_max_entries;
		stack_max_entries += STACK_BLOCK_SIZE;
	}

	dirstat_stack[next_free].dirstat = (dirstat_t *)malloc(sizeof(dirstat_t));
	if ( !dirstat_stack[next_free].dirstat ) {
		LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return ERR_FAIL;
	}

	// Initialize config
	snprintf(filename, MAXPATHLEN-1, "%s/%s", dirname, stat_filename);
	filename[MAXPATHLEN-1] = '\0';

	memset((void *)dirstat_stack[next_free].dirstat, 0, sizeof(dirstat_t));
	memset((void *)&dirstat_tmpl, 0, sizeof(dirstat_t));
	dirstat_tmpl.low_water = 95;	// defaults to 95%
	dirstat_tmpl.status = FORCE_REBUILD;	// in case status is not set -> fishy
	*dirstat_p = dirstat_stack[next_free].dirstat;
	dirstat_stack[next_free].fd = 0;
	dirstat_stack[next_free].filename = strdup(filename);


	fd =  open(filename, O_RDWR, 0);
    if ( fd < 0 ) {
		if ( errno == ENOENT ) {
			if ( lock == READ_ONLY || lock == LOCK_IF_EXISTS) {	// no lock need
				return ERR_NOSTATFILE;
			} else {	// create the file, to and lock the file
				fd =  open(filename, O_RDWR|O_TRUNC|O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
				if ( fd < 0 ) {
					LogError("open() error on '%s' in %s line %d: %s\n", filename, __FILE__, __LINE__, strerror(errno) );
					free(dirstat_stack[next_free].dirstat);
					dirstat_stack[next_free].dirstat = NULL;
					return ERR_FAIL;
				}
				err = SetFileLock(fd);
				if ( err != 0 ) {
					LogError("ioctl(F_WRLCK) error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
					close(fd);
					free(dirstat_stack[next_free].dirstat);
					dirstat_stack[next_free].dirstat = NULL;
					return ERR_FAIL;
				}
				dirstat_stack[next_free].fd = fd;
				return ERR_NOSTATFILE;
			}
		} else {
			LogError("open() error on '%s' in %s line %d: %s\n", filename, __FILE__, __LINE__, strerror(errno) );
			free(dirstat_stack[next_free].dirstat);
			dirstat_stack[next_free].dirstat = NULL;
			return ERR_FAIL;
		}
    }
	
	err = SetFileLock(fd);
	if ( err != 0 ) {
		LogError("ioctl(F_WRLCK) error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		close(fd);
		free(dirstat_stack[next_free].dirstat);
		dirstat_stack[next_free].dirstat = NULL;
		return ERR_FAIL;
	}

	fstat(fd, &filestat);
	// the file is not assumed to be larger than 1MB, otherwise it is likely corrupt
	if ( filestat.st_size > 1024*1024 ) {
		LogError("File size error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		ReleaseFileLock(fd);
		close(fd);
		free(dirstat_stack[next_free].dirstat);
		dirstat_stack[next_free].dirstat = NULL;
		return ERR_FAIL;
	}

	in_buff = (char *)malloc(filestat.st_size+1);	// +1 for trailing '\0'
	if ( !in_buff ) {
		LogError("mallow() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		ReleaseFileLock(fd);
		close(fd);
		free(dirstat_stack[next_free].dirstat);
		dirstat_stack[next_free].dirstat = NULL;
		return ERR_FAIL;
	}

	r_size = read(fd, (void *)in_buff, filestat.st_size);
	if ( r_size < 0 ) {
		LogError("read() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		ReleaseFileLock(fd);
		close(fd);
		free(in_buff);
		free(dirstat_stack[next_free].dirstat);
		dirstat_stack[next_free].dirstat = NULL;
		return ERR_FAIL;
	}
	in_buff[filestat.st_size] = '\0';

	if ( r_size != filestat.st_size ) {
		LogError("read() requested size error in %s line %d\n", __FILE__, __LINE__);
		ReleaseFileLock(fd);
		close(fd);
		free(in_buff);
		free(dirstat_stack[next_free].dirstat);
		dirstat_stack[next_free].dirstat = NULL;
		return ERR_FAIL;
	}

	if ( lock == READ_ONLY ) {
		ReleaseFileLock(fd);
		close(fd);
	} else {
		dirstat_stack[next_free].fd = fd;
	}

	p = in_buff;
	while ( p && *p ) {
		if ( *p == '#' ) { // skip comments
			s = strpbrk(p, "\n");
			if ( s ) { // "\n" found - advance p
				*s = '\0';
				printf("comment: '%s'\n",p);
				p = s+1;
				continue;	// next line
			}
		}

		// get gext key=value pair
		s = strpbrk(p, "\n");	
		if ( s )
			*s = '\0';

		if ( ParseString(p, &k, &v) ) {	
			uint32_t	i;
			i = 0;
			while ( config_def[i].name ) {
				if ( strcmp(config_def[i].name, k) == 0 ) {
					*(config_def[i].value) = string2uint64(v);
//					printf("key: '%s', value '%s' int: %llu\n", k,v, *(config_def[i].value));
					break;
				}
				i++;
			}
			if ( config_def[i].name == NULL ) {
				printf("Invalid config key: '%s'\n", k);
			}
		}
		p = s;
		if ( p )
			p++;
	}
	VerifyStatInfo(&dirstat_tmpl);
	*dirstat_stack[next_free].dirstat = dirstat_tmpl;

	free(in_buff);
	return dirstat_tmpl.status;

} // End of ReadStatInfo

int WriteStatInfo(dirstat_t *dirstat) {
int i, index, fd, err;
char *filename, line[256];

	// search for entry in dirstat stack
	for (i=0; dirstat_stack[i].dirstat != dirstat && i < stack_max_entries; i++ ) {}

	if ( i >= stack_max_entries ) {
		LogError( "WriteStatInfo(): dirstat entry not found in %s line %d\n", __FILE__, __LINE__ );
		return ERR_FAIL;
	}

	index = i;

	fd = dirstat_stack[index].fd;
	filename = dirstat_stack[index].filename;

	if ( fd == 0 ) {
		fd =  open(filename, O_RDWR|O_TRUNC|O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    	if ( fd < 0 ) {
			LogError( "open() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			return ERR_FAIL;
    	}

		err = SetFileLock(fd);
		if ( err != 0 ) {
			LogError( "ioctl(F_WRLCK) error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			close(fd);
			return ERR_FAIL;
		}
	} else {
		err = lseek(fd, SEEK_SET, 0);
		if ( err == -1 ) {
			LogError( "lseek() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			ReleaseFileLock(fd);
			close(fd);
			return ERR_FAIL;
		}
		if ( ftruncate(fd, 0) < 0 ) {
			LogError( "ftruncate() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		}
	}

	dirstat_tmpl = *dirstat_stack[index].dirstat;
	i = 0;
	while ( config_def[i].name ) {
		size_t len;
		snprintf(line, 255, "%s=%llu\n", config_def[i].name, (unsigned long long)*(config_def[i].value));
		line[255] = '\0';
		len = strlen(line);
		if ( write(fd, line, len) < 0 ) {
			LogError( "write() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		}
		i++;
	}

	ReleaseFileLock(fd);
	err = close(fd);
	dirstat_stack[index].fd = 0;
	if ( err == -1 ) {
		LogError( "close() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return ERR_FAIL;
	}

	return STATFILE_OK;

} // End of WriteStatInfo

int ReleaseStatInfo(dirstat_t *dirstat) {
int i, index;

	// search for entry in dirstat stack
	for (i=0; dirstat_stack[i].dirstat != dirstat && i < stack_max_entries; i++ ) {}

	if ( i >= stack_max_entries ) {
		LogError( "ReleaseStatInfo() error in %s line %d: %s\n", __FILE__, __LINE__, "dirstat entry not found" );
		return ERR_FAIL;
	}

	index = i;
	if ( dirstat_stack[index].filename == NULL ) {
		LogError( "ReleaseStatInfo() error in %s line %d: %s\n", __FILE__, __LINE__, "Attempted to free NULL pointer" );
		return ERR_FAIL;
	}
	free(dirstat_stack[index].filename);

	free(dirstat_stack[index].dirstat);
	dirstat_stack[index].dirstat = NULL;

	return 0;

} // End of ReleaseStatInfo

void PrintDirStat(dirstat_t *dirstat) {
struct tm *ts;
time_t	t;
char	string[32];

	t = dirstat->first;
    ts = localtime(&t);
    strftime(string, 31, "%Y-%m-%d %H:%M:%S", ts);
	string[31] = '\0';
	printf("First:     %s\n", string);

	t = dirstat->last;
    ts = localtime(&t);
    strftime(string, 31, "%Y-%m-%d %H:%M:%S", ts);
	string[31] = '\0';
	printf("Last:      %s\n", string);

	printf("Lifetime:  %s\n", ScaleTime(dirstat->last - dirstat->first));
 
	printf("Numfiles:  %llu\n", (unsigned long long)dirstat->numfiles);
	printf("Filesize:  %s\n", ScaleValue(dirstat->filesize));

	if ( dirstat->max_size ) 
		printf("Max Size:  %s\n", ScaleValue(dirstat->max_size));
	else
		printf("Max Size:  <none>\n");

	if ( dirstat->max_lifetime )
		printf("Max Life:  %s\n", ScaleTime(dirstat->max_lifetime));
	else
		printf("Max Life:  <none>\n");

	printf("Watermark: %llu%%\n", (unsigned long long)dirstat->low_water);

	switch(dirstat->status) {
		case STATFILE_OK:
			printf("Status:    OK\n");
			break;
		case FORCE_REBUILD:
			printf("Status:    Force rebuild\n");
			break;
		default:
			printf("Status:    Unexpected: %llu\n", (unsigned long long)dirstat->status);
			break;
	}
} // End of PrintDirStat


