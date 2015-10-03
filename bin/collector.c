/*
 *  Copyright (c) 2014, Peter Haag
 *  Copyright (c) 2009, Peter Haag
 *  Copyright (c) 2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
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
 *  $Id: collector.c 69 2010-09-09 07:17:43Z haag $
 *
 *  $LastChangedRevision: 69 $
 *	
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>

#include <time.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifndef DEVEL
#   define dbg_printf(...) /* printf(__VA_ARGS__) */
#else
#   define dbg_printf(...) printf(__VA_ARGS__)
#endif

#include "util.h"
#include "nf_common.h"
#include "nffile.h"
#include "nfxstat.h"
#include "bookkeeper.h"
#include "collector.h"
#include "nfx.h"

#include "nffile_inline.c"

/* globals */
uint32_t default_sampling   = 1;
uint32_t overwrite_sampling = 0;

/* local variables */
static uint32_t	exporter_sysid = 0;
static char *DynamicSourcesDir = NULL;

/* local prototypes */
static uint32_t AssignExporterID(void);

/* local functions */
static uint32_t AssignExporterID(void) {

	if ( exporter_sysid >= 0xFFFF ) {
		LogError("Too many exporters (id > 65535). Flow records collected but without reference to exporter");
		return 0;
	}

	return ++exporter_sysid;

} // End of AssignExporterID

/* global functions */

int SetDynamicSourcesDir(FlowSource_t **FlowSource, char *dir) {

	if ( *FlowSource ) 
		return 0;

	DynamicSourcesDir = dir;
	return 1;

} // End of SetDynamicSourcesDir

int AddFlowSource(FlowSource_t **FlowSource, char *ident) {
FlowSource_t	**source;
struct 	stat 	fstat;
char *p, *q, s[MAXPATHLEN];
int	 has_any_source = 0;
int ok;

	if ( DynamicSourcesDir ) 
		return 0;

	source = FlowSource;
	while ( *source ) {
		has_any_source |= (*source)->any_source;
		source = &((*source)->next);
	}
	if ( has_any_source ) {
		fprintf(stderr, "Ambiguous idents not allowed\n");
		return 0;
	}

	*source = (FlowSource_t *)calloc(1, sizeof(FlowSource_t));
	if ( !*source ) {
		LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return 0;
	} 
	(*source)->next 	  	  	  = NULL;
	(*source)->bookkeeper 	  	  = NULL;
	(*source)->any_source 	  	  = 0;
	(*source)->exporter_data  	  = NULL;
	(*source)->xstat 		  	  = NULL;
	(*FlowSource)->exporter_count = 0;

	// separate IP address from ident
	if ( ( p = strchr(ident, ',')) == NULL  ) {
		fprintf(stderr, "Syntax error for netflow source definition. Expect -n ident,IP,path\n");
		return 0;
	}
	*p++ = '\0';

	// separate path from IP
	if ( ( q = strchr(p, ',')) == NULL  ) {
		fprintf(stderr, "Syntax error for netflow source definition. Expect -n ident,IP,path\n");
		return 0;
	}
	*q++ = '\0';

	if ( strchr(p, ':') != NULL ) {
		uint64_t _ip[2];
		ok = inet_pton(PF_INET6, p, _ip);
		(*source)->sa_family = PF_INET6;
		(*source)->ip.v6[0] = ntohll(_ip[0]);
		(*source)->ip.v6[1] = ntohll(_ip[1]);
	} else {
		uint32_t _ip;
		ok = inet_pton(PF_INET, p, &_ip);
		(*source)->sa_family = PF_INET;
		(*source)->ip.v6[0] = 0;
		(*source)->ip.v6[1] = 0;
		(*source)->ip.v4 = ntohl(_ip);
	}
	switch (ok) {
		case 0:
			fprintf(stderr, "Unparsable IP address: %s\n", p);
			return 0;
		case 1:
			// success
			break;
		case -1:
			fprintf(stderr, "Error while parsing IP address: %s\n", strerror(errno));
			return 0;
			break;
	}

	// fill in ident
	if ( strlen(ident) >= IDENTLEN ) {
		fprintf(stderr, "Source identifier too long: %s\n", ident);
		return 0;
	}
	if ( strchr(ident, ' ') ) {
		fprintf(stderr,"Illegal characters in ident %s\n", ident);
		exit(255);
	}
	strncpy((*source)->Ident, ident, IDENTLEN-1 );
	(*source)->Ident[IDENTLEN-1] = '\0';

	if ( strlen(q) >= MAXPATHLEN ) {
		fprintf(stderr,"Path too long: %s\n", q);
		exit(255);
	}

	// check for existing path
	if ( stat(q, &fstat) ) {
		fprintf(stderr, "stat() error %s: %s\n", q, strerror(errno));
		return 0;
	}
	if ( !(fstat.st_mode & S_IFDIR) ) {
		fprintf(stderr, "No such directory: %s\n", q);
		return 0;
	}

	// remember path
	(*source)->datadir = strdup(q);
	if ( !(*source)->datadir ) {
		fprintf(stderr, "strdup() error: %s\n", strerror(errno));
		return 0;
	}

	// cache current collector file
	if ( snprintf(s, MAXPATHLEN-1, "%s/%s.%lu", (*source)->datadir , NF_DUMPFILE, (unsigned long)getpid() ) >= (MAXPATHLEN-1)) {
		fprintf(stderr, "Path too long: %s\n", q);
		return 0;
	}
	(*source)->current = strdup(s);
	if ( !(*source)->current ) {
		fprintf(stderr, "strdup() error: %s\n", strerror(errno));
		return 0;
	}

	return 1;

} // End of AddFlowSource

int AddDefaultFlowSource(FlowSource_t **FlowSource, char *ident, char *path) {
struct 	stat 	fstat;
char s[MAXPATHLEN];

	if ( DynamicSourcesDir ) 
		return 0;

	*FlowSource = (FlowSource_t *)calloc(1,sizeof(FlowSource_t));
	if ( !*FlowSource ) {
		fprintf(stderr, "calloc() allocation error: %s\n", strerror(errno));
		return 0;
	} 
	(*FlowSource)->next 	  	  = NULL;
	(*FlowSource)->bookkeeper 	  = NULL;
	(*FlowSource)->any_source 	  = 1;
	(*FlowSource)->exporter_data  = NULL;
	(*FlowSource)->xstat 	  	  = NULL;
	(*FlowSource)->exporter_count = 0;

	// fill in ident
	if ( strlen(ident) >= IDENTLEN ) {
		fprintf(stderr, "Source identifier too long: %s\n", ident);
		return 0;
	}
	if ( strchr(ident, ' ') ) {
		fprintf(stderr,"Illegal characters in ident %s\n", ident);
		return 0;
	}
	strncpy((*FlowSource)->Ident, ident, IDENTLEN-1 );
	(*FlowSource)->Ident[IDENTLEN-1] = '\0';

	if ( strlen(path) >= MAXPATHLEN ) {
		fprintf(stderr,"Path too long: %s\n",path);
		return 0;
	}

	// check for existing path
	if ( stat(path, &fstat) ) {
		fprintf(stderr, "stat() error %s: %s\n", path, strerror(errno));
		return 0;
	}
	if ( !(fstat.st_mode & S_IFDIR) ) {
		fprintf(stderr, "No such directory: %s\n", path);
		return 0;
	}

	// remember path
	(*FlowSource)->datadir = strdup(path);
	if ( !(*FlowSource)->datadir ) {
		fprintf(stderr, "strdup() error: %s\n", strerror(errno));
		return 0;
	}

	// cache current collector file
	if ( snprintf(s, MAXPATHLEN-1, "%s/%s.%lu", (*FlowSource)->datadir , NF_DUMPFILE, (unsigned long)getpid() ) >= (MAXPATHLEN-1)) {
		fprintf(stderr, "Path too long: %s\n", path);
		return 0;
	}
	(*FlowSource)->current = strdup(s);
	if ( !(*FlowSource)->current ) {
		fprintf(stderr, "strdup() error: %s\n", strerror(errno));
		return 0;
	}

	return 1;

} // End of AddDefaultFlowSource

FlowSource_t *AddDynamicSource(FlowSource_t **FlowSource, struct sockaddr_storage *ss) {
FlowSource_t	**source;
void			*ptr;
char			*s, ident[100], path[MAXPATHLEN];
int				err;

    union {
        struct sockaddr_storage	*ss;
        struct sockaddr			*sa;
        struct sockaddr_in		*sa_in;
        struct sockaddr_in6		*sa_in6;
    } u;
    u.ss = ss;

	if ( !DynamicSourcesDir ) 
		return NULL;

	source = FlowSource;
	while ( *source ) {
		source = &((*source)->next);
	}

	*source = (FlowSource_t *)calloc(1, sizeof(FlowSource_t));
	if ( !*source ) {
		LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return NULL;
	} 
	(*source)->next 	  	  	  = NULL;
	(*source)->bookkeeper 	  	  = NULL;
	(*source)->any_source 	  	  = 0;
	(*source)->exporter_data  	  = NULL;
	(*source)->xstat 		  	  = NULL;
	(*FlowSource)->exporter_count = 0;

	switch (ss->ss_family) {
		case PF_INET: {
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN
			if (ss->ss_len != sizeof(struct sockaddr_in) ) {
				// malformed struct
				LogError("Malformed IPv4 socket struct in '%s', line '%d'", __FILE__, __LINE__ );
				free(*source);
				*source = NULL;
				return NULL;
			}
#endif
			(*source)->sa_family = PF_INET;
			(*source)->ip.v6[0] = 0;
			(*source)->ip.v6[1] = 0;
			(*source)->ip.v4 = ntohl(u.sa_in->sin_addr.s_addr);
			ptr 	   = &u.sa_in->sin_addr;
			} break;
		case PF_INET6: {
			uint64_t *ip_ptr = (uint64_t *)u.sa_in6->sin6_addr.s6_addr;
			
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN
			if (ss->ss_len != sizeof(struct sockaddr_in6) ) {
				// malformed struct
				LogError("Malformed IPv6 socket struct in '%s', line '%d'", __FILE__, __LINE__ );
				free(*source);
				*source = NULL;
				return NULL;
			}
#endif
			// ptr = &((struct sockaddr_in6 *)sa)->sin6_addr;
			(*source)->sa_family = PF_INET6;
			(*source)->ip.v6[0] = ntohll(ip_ptr[0]);
			(*source)->ip.v6[1] = ntohll(ip_ptr[1]);
			ptr = &u.sa_in6->sin6_addr;
			} break;
		default:
			// keep compiler happy
			(*source)->ip.v6[0] = 0;
			(*source)->ip.v6[1] = 0;
			ptr   = NULL;

			LogError("Unknown sa fanily: %d in '%s', line '%d'", ss->ss_family, __FILE__, __LINE__ );
			free(*source);
			*source = NULL;
			return NULL;
	}

	if ( !ptr ) {
		free(*source);
		*source = NULL;
		return NULL;
	}

	inet_ntop(ss->ss_family, ptr, ident, sizeof(ident));
	ident[99] = '\0';
	dbg_printf("Dynamic Flow Source IP: %s\n", ident);

	if ( strchr(ident, ':') ) { // condense IPv6 addresses
		condense_v6(ident);
	}

	s = ident;
	while ( *s != '\0' ) {
		if ( *s == '.' || *s == ':' ) 
			*s = '-';
		s++;
	}
	dbg_printf("Dynamic Flow Source ident: %s\n", ident);

	strncpy((*source)->Ident, ident, IDENTLEN-1 );
	(*source)->Ident[IDENTLEN-1] = '\0';

	snprintf(path, MAXPATHLEN-1, "%s/%s", DynamicSourcesDir, ident);
	path[MAXPATHLEN-1] = '\0';

	err = mkdir(path, 0755);
	if ( err != 0 && errno != EEXIST ) {
		LogError("mkdir() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		free(*source);
		*source = NULL;
		return NULL;
	}
	(*source)->datadir = strdup(path);

	if ( snprintf(path, MAXPATHLEN-1, "%s/%s.%lu", (*source)->datadir, NF_DUMPFILE, (unsigned long)getpid() ) >= (MAXPATHLEN-1)) {
		fprintf(stderr, "Path too long: %s\n", path);
		free(*source);
		*source = NULL;
		return NULL;
	}
	(*source)->current = strdup(path);

	LogInfo("Dynamically add source ident: %s in directory: %s", ident, path);
	return *source;

} // End of AddDynamicSource

int InitExtensionMapList(FlowSource_t *fs) {

	fs->extension_map_list.maps = (extension_map_t **)calloc(BLOCK_SIZE, sizeof(extension_map_t *));
	if ( !fs->extension_map_list.maps ) {
		LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return 0;
	}
	fs->extension_map_list.max_maps  = BLOCK_SIZE;
	fs->extension_map_list.next_free = 0;
	fs->extension_map_list.num_maps  = 0;

	return 1;

} // End of InitExtensionMapList

int ReInitExtensionMapList(FlowSource_t *fs) {

	dbg_printf("Flush all extension maps!\n");
	free(fs->extension_map_list.maps);
	fs->extension_map_list.maps = NULL;

	return InitExtensionMapList(fs);

} // End of ReInitExtensionMapList

int RemoveExtensionMap(FlowSource_t *fs, extension_map_t *map) {
int slot = map->map_id;

	dbg_printf("Remove extension map ID: %d\n", slot);
	if ( slot >= fs->extension_map_list.max_maps ) {
		// XXX hmm .. is simply return correct ///
		LogError("*** software error *** Try to remove extension map %d, while only %d slots are available\n", slot, fs->extension_map_list.max_maps);
		return 0;
	}
	fs->extension_map_list.maps[slot] = NULL;

	return 1;

} // End of RemoveExtensionMap

int AddExtensionMap(FlowSource_t *fs, extension_map_t *map) {
int next_slot = fs->extension_map_list.next_free;

	dbg_printf("Add extension map\n");
	// is it a new map, we have not yet in the list
	if ( map->map_id == INIT_ID ) {
		if ( next_slot >= fs->extension_map_list.max_maps ) {
			// extend map list
			dbg_printf("List full - extend extension list to %d slots\n", fs->extension_map_list.max_maps + BLOCK_SIZE);
			extension_map_t **p = realloc((void *)fs->extension_map_list.maps, 
				(fs->extension_map_list.max_maps + BLOCK_SIZE ) * sizeof(extension_map_t *));
			if ( !p ) {
				LogError("realloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
				return 0;
			}
			fs->extension_map_list.maps 	= p;
			fs->extension_map_list.max_maps += BLOCK_SIZE;
		}
	
		dbg_printf("Add map to slot %d\n", next_slot);
		fs->extension_map_list.maps[next_slot] = map;
		map->map_id = next_slot;
		fs->extension_map_list.num_maps++;

		if ( (next_slot + 1) == fs->extension_map_list.num_maps ) {
			// sequencially filled slots
			// next free is next slot
			fs->extension_map_list.next_free++;
			dbg_printf("Next slot is sequential: %d\n", fs->extension_map_list.next_free);
		} else {
			// fill gap in list - search for next free
			int i;
			dbg_printf("Search next slot ... \n");
			for ( i = (next_slot + 1); i < fs->extension_map_list.max_maps; i++ ) {
				if ( fs->extension_map_list.maps[i] == NULL ) {
					// empty slot found
					dbg_printf("Empty slot found at %d\n", i);
					break;
				}
			} 
			// assign next_free - if none found up to max, the list will get extended
			// in the next round
			dbg_printf("Set next free to %d\n", i);
			fs->extension_map_list.next_free = i;
		}
		
	}

	AppendToBuffer(fs->nffile, (void *)map, map->size);

	return 1;

} // End of AddExtensionMap

int FlushInfoExporter(FlowSource_t *fs, exporter_info_record_t *exporter) {

	exporter->sysid = AssignExporterID();
	fs->exporter_count++;
	AppendToBuffer(fs->nffile, (void *)exporter, exporter->header.size);

#ifdef DEVEL
	{
		#define IP_STRING_LEN   40
		char ipstr[IP_STRING_LEN];
		printf("Flush Exporter: ");
		if ( exporter->sa_family == AF_INET ) {
			uint32_t _ip = htonl(exporter->ip.v4);
			inet_ntop(AF_INET, &_ip, ipstr, sizeof(ipstr));
			printf("SysID: %u, IP: %16s, version: %u, ID: %2u\n", exporter->sysid,
				ipstr, exporter->version, exporter->id);
		} else if ( exporter->sa_family == AF_INET6 ) {
			uint64_t _ip[2];
			_ip[0] = htonll(exporter->ip.v6[0]);
			_ip[1] = htonll(exporter->ip.v6[1]);
			inet_ntop(AF_INET6, &_ip, ipstr, sizeof(ipstr));
			printf("SysID: %u, IP: %40s, version: %u, ID: %2u\n", exporter->sysid,
				ipstr, exporter->version, exporter->id);
		} else {
			strncpy(ipstr, "<unknown>", IP_STRING_LEN);
			printf("**** Exporter IP version unknown ****\n");
		}
	}
#endif

	return 1;

} // End of FlushInfoExporter

int FlushInfoSampler(FlowSource_t *fs, sampler_info_record_t *sampler) {

	AppendToBuffer(fs->nffile, (void *)sampler, sampler->header.size);

#ifdef DEVEL
	{
		printf("Flush Sampler: ");
		if ( sampler->id < 0 ) {
			printf("Exporter SysID: %u,	Generic Sampler: mode: %u, interval: %u\n",
				sampler->exporter_sysid, sampler->mode, sampler->interval);
		} else {
			printf("Exporter SysID: %u, Sampler: id: %i, mode: %u, interval: %u\n",
				sampler->exporter_sysid, sampler->id, sampler->mode, sampler->interval);
		}
	}
#endif

	return 1;

} // End of FlushInfoSampler

void FlushStdRecords(FlowSource_t *fs) {
generic_exporter_t *e = fs->exporter_data;
int i;

	while ( e ) {
		generic_sampler_t *sampler = e->sampler;
		AppendToBuffer(fs->nffile, (void *)&(e->info), e->info.header.size);
		while ( sampler ) {
			AppendToBuffer(fs->nffile, (void *)&(sampler->info), sampler->info.header.size);
			sampler = sampler->next;
		}
		e = e->next;
	}

    for ( i=0; i<fs->extension_map_list.next_free; i++ ) {
        extension_map_t *map = fs->extension_map_list.maps[i];
		if ( map ) 
			AppendToBuffer(fs->nffile, (void *)map, map->size);
    }

} // End of FlushStdRecords

void FlushExporterStats(FlowSource_t *fs) {
generic_exporter_t *e = fs->exporter_data;
exporter_stats_record_t	*exporter_stats;
uint32_t i, size;

	// idle collector ..
	if ( !fs->exporter_count ) 
		return;

	size = sizeof(exporter_stats_record_t) + (fs->exporter_count -1) * sizeof(struct exporter_stat_s);
	exporter_stats = ( exporter_stats_record_t *)malloc(size);
	if ( !exporter_stats ) {
		LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return;
	} 
	exporter_stats->header.type = ExporterStatRecordType;
	exporter_stats->header.size = size;
	exporter_stats->stat_count	= fs->exporter_count;

#ifdef DEVEL
	printf("Flush Exporter Stats: %u exporters, size: %u\n", fs->exporter_count, size);
#endif
	i = 0;
	while ( e ) {
		// prevent memory corruption - just in case .. should not happen anyway
		// continue loop for error reporting after while
		if ( i >= fs->exporter_count ) {
			i++;
			e = e->next;
			continue;
		}
		exporter_stats->stat[i].sysid 			 = e->info.sysid;
		exporter_stats->stat[i].sequence_failure = e->sequence_failure;
		exporter_stats->stat[i].packets 		 = e->packets;
		exporter_stats->stat[i].flows 			 = e->flows;
#ifdef DEVEL
		printf("Stat: SysID: %u, version: %u, ID: %2u, Packets: %llu, Flows: %llu, Sequence Failures: %u\n", e->info.sysid,
			e->info.version, e->info.id, e->packets, e->flows, e->sequence_failure);

#endif
		// reset counters
		e->sequence_failure = 0;
		e->packets 			= 0;
		e->flows 			= 0;

		i++;
		e = e->next;
	}
	AppendToBuffer(fs->nffile, (void *)exporter_stats, size);
	free(exporter_stats);

	if ( i != fs->exporter_count ) {
		LogError("ERROR: exporter stats: Expected %u records, but found %u in %s line %d: %s\n", 
			fs->exporter_count, i, __FILE__, __LINE__, strerror(errno) );
	}
 
} // End of FlushExporterStats



int HasOptionTable(FlowSource_t *fs, uint16_t id ) {
option_offset_t *t;

	t = fs->option_offset_table;
	while ( t && t->id != id )
		t = t->next;

	dbg_printf("Has option table: %s\n", t == NULL ? "not found" : "found");

	return t != NULL;

} // End of HasOptionTable
