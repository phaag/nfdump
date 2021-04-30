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
 *  $Author: peter $
 *
 *  $Id: nftrack_rrd.c 224 2014-02-16 12:59:29Z peter $
 *
 *  $LastChangedRevision: 224 $
 *  
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "rrd.h"
#include "nftrack_stat.h"
#include "nftrack_rrd.h"

#define BUFF_CHECK(num,buffsize) if ( (num) >= (buffsize) ) { \
 fprintf(stderr, "No enough space to create RRD arg\n");	\
 exit(0);	\
}

// temporary RRD file
#define TMPRRD	"ports.rrd"

#define MAXBUFF 15 * 1024;

/* global const */
static const char *proto[] = { "tcp", "udp" };
static const char *type[]  = { "flows", "packets", "bytes" };

/* Local prototypes */

static void CreateRRDB (char *filename, time_t when);

/* Functions */

static void CreateRRDB (char *filename, time_t when) {
char *buff, *s, *rrd_arg[1100];
long i, num, buffsize, argc;

	optind = 0; opterr = 0;
	argc   = 0;
	/* 	
		Create bufferspace for create args:
		1024 DS records: each ~ 23 bytes in average +
		3 RRA records + filename + start time => 512 bytes should be more than enough
	 */
	buffsize = 23 * 1024 + 512;
	buff = (char *)malloc(buffsize);
	if ( !buff ) {
		perror("Memory error!");
		exit(0);
	}

	s = buff;

	unlink(filename);

	rrd_arg[argc++] = "create";
	
	// add DB name
	rrd_arg[argc++] = filename;

	// Add start time
	num = snprintf(s, buffsize, "--start=%lld", (long long)when);
	num++;	// include '\0'
	BUFF_CHECK(num,buffsize);
	rrd_arg[argc++] = s;

	buffsize -= num;
	s += num;
	
	/* Add the DS strings */
	for ( i=0; i<1024; i++) {
		num = snprintf(s, buffsize, "DS:p%ld:GAUGE:600:0:U", i);
		num++;	// include '\0'
		// printf("I: %ld ", i);
		BUFF_CHECK(num,buffsize);
		rrd_arg[argc++] = s;
	
		buffsize -= num;
		s += num;
	}

	/* 
		RRD DB layout:
	  	  1 x 5min =  5 min samples	 7 * 288 ( per day ) = 2016 => 7 days
	 	 24 x 5min =  2 hour samples   60 *  12 ( per day ) = 720  => 60 days
		288 x 5min =  1 day samples   180 *   1 ( per day ) = 180  => 180 days
	*/

	num = snprintf(s, buffsize, "RRA:AVERAGE:0.5:1:2016");
	num++;	// include '\0'
	BUFF_CHECK(num,buffsize);
	rrd_arg[argc++] = s;

	buffsize -= num;
	s += num;

	num = snprintf(s, buffsize, "RRA:AVERAGE:0.5:24:720");
	num++;	// include '\0'
	BUFF_CHECK(num,buffsize);
	rrd_arg[argc++] = s;

	buffsize -= num;
	s += num;

	num = snprintf(s, buffsize, "RRA:AVERAGE:0.5:288:180");
	num++;	// include '\0'
	BUFF_CHECK(num,buffsize);
	rrd_arg[argc] = s;

/*
	for ( i=0; i<=argc; i++ ) {
		printf("I:%ld %s\n", i, rrd_arg[i]);
	}
*/

	rrd_clear_error();
	if ( ( i=rrd_create(argc, rrd_arg))) {
		fprintf(stderr, "Create DB Error: %ld %s\n", i, rrd_get_error());
	}

} // End of CreateRRDB

int CreateRRDBs (char *path, time_t when) {
const char progress[]	= { '|', '/', '-', '|', '\\', '-' };
char rrd_filename[1024];
int fd, i, p, t, len, total;
struct stat statbuf;
void	*buff;

	// Check if path exists
	if ( (stat(path, &statbuf) < 0 ) || !(statbuf.st_mode & S_IFDIR) ) {
		fprintf(stderr, "No such directory: '%s'\n", path);
		return 0;
	}

	// make stdout unbuffered for progress pointer
	setvbuf(stdout, (char *)NULL, _IONBF, 0);

	printf("Create DBs ... ");

	/* 
	 * we create an RRD DB file and will copy this file 
	 * that many time as required - so every RRD file looks the
	 * same. They only distinguish by their name
	 */
	len = snprintf(rrd_filename, 1024, "%s/%s", path, TMPRRD);
	if ( len >= 1024 ) {
		fprintf(stderr, "Failed to concat RRD filename: string overflow");
		return 0;
	}

	CreateRRDB(rrd_filename, when);
	if ( (i = stat(rrd_filename, &statbuf) < 0 )) {
		fprintf(stderr, "Can't create RRD file '%s': %s\n", rrd_filename, strerror(errno));
		return 0;
	}
	buff = malloc(statbuf.st_size);
	if ( !buff ) {
		perror("Buffer allocation failed");
		unlink(rrd_filename);
		return 0;
	}
	fd = open(rrd_filename, O_RDONLY, 0);
	if ( fd < 0 ) {
		perror("Failed to open RRD file");
		unlink(rrd_filename);
		return 0;
	}
	if ( read(fd, buff, statbuf.st_size) != statbuf.st_size ) {
		perror("Failed to read data from RRD file");
		close(fd);
		unlink(rrd_filename);
		return 0;
	}
	close(fd);
	unlink(rrd_filename);
	printf("\n");

	// we are now ready to multiplicate the DB files
	total = 384;	// 2 * 3 * 64 files total
	for (p=tcp; p<=udp; p++) {	// for TCP and UDP
		for (t=flows; t<=bytes; t++) {	// for flows, packets and bytes
			for (i=0; i<64; i++) {	// Create 64 times an RRD DB - each for 1024 ports
				printf("Creating %s:%s %c Left: %d files	   \r", proto[p], type[t], progress[i % 6], total );
				len = snprintf(rrd_filename, 1024, "%s/%s-%s-%d.rrd", path, proto[p], type[t], i);
				if ( len >= 1024 ) {
					fprintf(stderr, "Failed to concat RRD filename: string overflow");
					free(buff);
					return 0;
				}
				fd = open(rrd_filename, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );
				if ( fd < 0 ) {
					fprintf(stderr, "Failed to create RRD file '%s': %s\n", rrd_filename, strerror(errno));
					free(buff);
					return 0;
				}
				if ( write(fd, buff, statbuf.st_size) != statbuf.st_size ) {
					fprintf(stderr, "Failed to write RRD file '%s': %s\n", rrd_filename, strerror(errno));
					free(buff);
					return 0;
				}
				close(fd);
				total--;
			}
		}
	}

	printf("\n");
	return 1;

} // End of CreateRRDBs

int RRD_StoreDataRow(char *path, char *iso_time, data_row *row) {
char 	rrd_filename[1024], *buff, *s;
char	*rrd_arg[10];
time_t	when, frag;
int 	i, j, len, p, t, buffsize, argc;
uint32_t	pnum;
struct stat statbuf;

	buffsize = MAXBUFF;
	buff = (char *)malloc(buffsize);
	if ( !buff ) {
		perror("Memory error!");
		return 0;
	}

	when = ISO2UNIX(iso_time);
	if ( !when ) 
		return 0;

	// make sure, we are at a 5min boundary
	frag = when % 300;
	if ( frag ) {
		fprintf(stderr, "Round to next timeslot: offset %lld\n", (long long)frag);
		when -= frag;
	}

	for ( p=tcp; p<=udp; p++ ) {
		// for every protocol TCP - UDP
		for ( t=flows; t<=bytes; t++ ) {
			// for every type flows - packets - bytes
			for (j=0; j<64; j++) {	
				// for all 64 RRD files in proto - type
				len = snprintf(rrd_filename, 1024, "%s/%s-%s-%d.rrd", path, proto[p], type[t], j);
				if ( len >= 1024 ) {
					fprintf(stderr, "Failed to concat RRD filename: string overflow");
					return 0;
				}
		
				// Check if RRD file exists
				if ( (stat(rrd_filename, &statbuf) < 0 ) || !(statbuf.st_mode & S_IFREG) ) {
					fprintf(stderr, "No such RRD file: '%s'\n", rrd_filename);
					return 0;
				}

				buffsize = MAXBUFF;
				s = buff;
		
				/* add time to RRD arg string */
				len = snprintf(s, buffsize, "%lld:", (long long)when);
				buffsize -= len;
				s += len;
		
				/* add port data to RRD arg string */
				for ( i=0; i<1024; i++) {
					pnum = ( j << 10 ) + i;
/*
if ( row[pnum].proto[p].type[t] ) {
	fprintf(stderr, "%d %d %d\n", pnum, p, t);
}
*/
					len = snprintf(s, buffsize, "%llu:", (long long unsigned)row[pnum].proto[p].type[t]);
					if ( len >= buffsize ) {
						fprintf(stderr, "No enough space to create RRD arg\n");
						return 0;
					}
					buffsize -= len;
					s += len;
				}
				s--;
				*s = '\0';

				// Create arg vector
				argc = 0;
				rrd_arg[argc++] = "update";
				rrd_arg[argc++] = rrd_filename;
				rrd_arg[argc++] = buff;
				rrd_arg[argc]   = NULL;
			
				optind = 0; opterr = 0;
				rrd_clear_error();
				if ( ( i=rrd_update(argc, rrd_arg))) {
					fprintf(stderr, "RRD: %s Insert Error: %d %s\n", rrd_filename, i, rrd_get_error());
				}
			} // for all 64 rrd files
		} // for every type flows - packets - bytes
	} // for every protocol TCP - UDP

	return 1;
} // End of RRD_StoreDataRow

data_row *RRD_GetDataRow(char *path, time_t when) {
time_t	last, frag;
struct tm * t1, *t2;
struct stat statbuf;
char 	datestr1[64] , datestr2[64], rrd_filename[1024];
char	*rrd_arg[10];
char 	**ds_namv;
int 	ret, i, j, p, t, len, argc;
unsigned long step, ds_cnt, pnum;
data_row	*row;
rrd_value_t   *data;
uint64_t	dummy;

	data = NULL;
	frag = when % 300;
	if ( frag ) {
		fprintf(stderr, "Round to next timeslot: offset %lld\n", (long long)frag);
		when -= frag;
	}

	last = RRD_LastUpdate(path);
	if ( when > last ) {
		t1 = localtime(&when);
		strftime(datestr1, 63, "%b %d %Y %T", t1);

		t2 = localtime(&last);
		strftime(datestr2, 63, "%b %d %Y %T", t2);

		fprintf(stderr, "Error get data: Requested time slot '%s' later then last available time slot '%s'\n",
			datestr1, datestr2);

		return NULL;
	}

	row = (data_row *)calloc(65536, sizeof(data_row));
	if ( !row ) {
		perror("Memory allocation error");
		return NULL;
	}
	
	len = snprintf(datestr1, 64, "--start=%lld", (long long)when);
	if ( len >= 64 ) {
		fprintf(stderr, "String overflow --start\n");
		free(row);
		return NULL;
	}
	len = snprintf(datestr2, 64, "--end=%lld", (long long)when);
	if ( len >= 64 ) {
		fprintf(stderr, "String overflow --end\n");
		free(row);
		return NULL;
	}

	for ( p=tcp; p<=udp; p++ ) {
		// for every protocol TCP - UDP
		for ( t=flows; t<=bytes; t++ ) {
			// for every type flows - packets - bytes
			for (j=0; j<64; j++) {	
				// for all 64 RRD files in proto - type
				len = snprintf(rrd_filename, 1024, "%s/%s-%s-%d.rrd", path, proto[p], type[t], j);
				if ( len >= 1024 ) {
					fprintf(stderr, "Failed to concat RRD filename: string overflow");
					free(row);
					return NULL;
				}
		
				// Check if RRD file exists
				if ( (stat(rrd_filename, &statbuf) < 0 ) || !(statbuf.st_mode & S_IFREG) ) {
					fprintf(stderr, "No such RRD file: '%s'\n", rrd_filename);
					free(row);
					return NULL;
				}


				// Create arg vector
				argc = 0;
				rrd_arg[argc++] = "fetch";
				rrd_arg[argc++] = rrd_filename;
				rrd_arg[argc++] = "AVERAGE";
				rrd_arg[argc++] = datestr1;
				rrd_arg[argc++] = datestr2;
				rrd_arg[argc]   = NULL;
			
				optind = 0; opterr = 0;
				rrd_clear_error();
				if ( ( ret=rrd_fetch(argc, rrd_arg, &when, &when, &step, &ds_cnt, &ds_namv, &data))) {
					fprintf(stderr, "RRD: %s Fetch Error: %d %s\n", rrd_filename, ret, rrd_get_error());
				}
				if ( ds_cnt != 1024 ) {
					fprintf(stderr, "RRD: %s Fetch Error: Short read: Expected 1024 records got %lu\n", 
						rrd_filename, ds_cnt);
					free(row);
					return NULL;
				}

				for ( i=0; i<1024; i++) {
					pnum = ( j << 10 ) + i;
					dummy = data[0];
					row[pnum].proto[p].type[t] = dummy;
				}

				free(ds_namv);
				free(data);

			} // for all 64 rrd files
		} // for every type flows - packets - bytes
	} // for every protocol TCP - UDP

	return row;

} // End of RRD_GetDataRow

time_t	RRD_LastUpdate(char *path) {
struct stat statbuf;
char 	rrd_filename[1024];
char	*rrd_arg[10];
time_t	when;
int 	len, argc;

	// Get timestamp from the first file
	len = snprintf(rrd_filename, 1024, "%s/%s-%s-%d.rrd", path, "tcp", "flows", 0);
	if ( len >= 1024 ) {
		fprintf(stderr, "Failed to concat RRD filename: string overflow");
		return 0;
	}
		
	// Check if RRD file exists
	if ( (stat(rrd_filename, &statbuf) < 0 ) || !(statbuf.st_mode & S_IFREG) ) {
		fprintf(stderr, "RRD files not found in '%s'\n", path);
		return 0;
	}

	argc = 0;
	rrd_arg[argc++] = "last";
	rrd_arg[argc++] = rrd_filename;
	rrd_arg[argc]   = NULL;

	when = rrd_last(argc, rrd_arg);
	
	return when;

} // End of RRD_LastUpdate

/*
int main () {
	char *buff, *s, *rrd_arg[10];
	long i, num, buffsize, argc;
	time_t	now;

	CreateRRDBs("/data/rrd-db");
	exit(0);

	buffsize = 15 * 1024;
	buff = (char *)malloc(buffsize);
	if ( !buff ) {
		perror("Memory error!");
		exit(0);
	}

	s = buff;
	now = time(NULL);
	now -= now % 300;

	num = snprintf(s, buffsize, "%ld:", now);
	// num = snprintf(s, buffsize, "N:");
	buffsize -= num;
	s += num;

	for ( i=0; i<1024; i++) {
		num = snprintf(s, buffsize, "%ld:", i);
		if ( num >= buffsize ) {
			fprintf(stderr, "No enough space to create RRD arg\n");
			exit(0);
		}
		buffsize -= num;
		s += num;
	}
	s--;
	*s = '\0';
	printf("String: %s\n", buff);

	argc = 0;
	rrd_arg[argc++] = "update";
	rrd_arg[argc++] = "ports.rrd";
	rrd_arg[argc++] = buff;
	rrd_arg[argc]   = NULL;

	rrd_clear_error();
	if ( ( i=rrd_update(argc, rrd_arg))) {
		fprintf(stderr, "Insert Error: %ld %s\n", i, rrd_get_error());
	}

	return 0;
}

*/
