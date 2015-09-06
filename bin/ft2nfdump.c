/*
 *  All rights reserved.
 *  Copyright (c) 2014, Peter Haag
 *  Copyright (c) 2009, Peter Haag
 *  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
 *  Copyright (c) 2001 Mark Fullmer and The Ohio State University
 *  All rights reserved.
 *  
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *  
 *   * Redistributions of source code must retain the above copyright notice, 
 *	   this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice, 
 *	   this list of conditions and the following disclaimer in the documentation 
 *	   and/or other materials provided with the distribution.
 *   * Neither the name of the author nor the names of its contributors may be 
 *	   used to endorse or promote products derived from this software without 
 *	   specific prior written permission.
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
 *  Flow-Tools related code taken from flow-tools-0.67 cretated by Mark Fullmer
 *
 *  $Author: haag $
 *
 *  $Id: ft2nfdump.c 69 2010-09-09 07:17:43Z haag $
 *
 *  $LastChangedRevision: 69 $
 *	
 *
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "ftlib.h"
#include "nf_common.h"
#include "nffile.h"
#include "nfx.h"
#include "launch.h"

/* Global defines */
#define MAXRECORDS 30

/* Global consts */
extern extension_descriptor_t extension_descriptor[];

const char *nfdump_version = VERSION;

typedef struct v5_block_s {
	uint32_t	srcaddr;
	uint32_t	dstaddr;
	uint32_t	dPkts;
	uint32_t	dOctets;
	uint8_t		data[4];	// link to next record
} v5_block_t;

/* externals */
extern uint32_t Max_num_extensions;

/* prototypes */
void usage(char *name);

extension_info_t *GenExtensionMap(struct ftio *ftio);

int flows2nfdump(struct ftio *ftio, extension_info_t *extension_info, int extended, uint32_t limitflows);

#define NEED_PACKRECORD
#include "nffile_inline.c"
#undef NEED_PACKRECORD

void usage(char *name) {
		printf("usage %s [options] \n"
					"-h\t\tthis text you see right here.\n"
					"-E\t\tDump records in ASCII extended format to stdout.\n"
					"-c\t\tLimit number of records to convert.\n"
					"-m\t\tPrint the extension map and exit.\n"
					"-V\t\tPrint version and exit.\n"
					"-r\t\tread input from file\n"
					"Convert flow-tools format to nfdump format:\n"
					"ft2nfdump -r <flow-tools-data-file> | nfdump -z -w <nfdump-file>\n"
				, name);

} // End of usage

extension_info_t *GenExtensionMap(struct ftio *ftio) {
extension_info_t *extension_info;
int	i;

   	if (ftio_check_xfield(ftio, FT_XFIELD_DPKTS |
		FT_XFIELD_DOCTETS | FT_XFIELD_FIRST | FT_XFIELD_LAST | 
		FT_XFIELD_SRCADDR | FT_XFIELD_DSTADDR |
		FT_XFIELD_SRCPORT | FT_XFIELD_DSTPORT | 
		FT_XFIELD_UNIX_SECS | FT_XFIELD_UNIX_NSECS | FT_XFIELD_SYSUPTIME |
		FT_XFIELD_TOS | FT_XFIELD_TCP_FLAGS | FT_XFIELD_PROT)) {
		fprintf(stderr,"Flow-tools record missing required fields.");
		return NULL;
	}

	InitExtensionMaps(NO_EXTENSION_LIST);
	extension_info = (extension_info_t *)malloc(sizeof(extension_info_t));
	if ( !extension_info  ) {
		fprintf(stderr, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
		return NULL;
	}
	memset((void *)extension_info, 0, sizeof(extension_info_t));

	extension_info->map  = (extension_map_t *)malloc(sizeof(extension_map_t) + Max_num_extensions * sizeof(uint16_t));
	if ( !extension_info->map  ) {
		fprintf(stderr, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
		return NULL;
	}

	i = 0;
	extension_info->map->type 		= ExtensionMapType;
	extension_info->map->map_id 	= 0;

   	if ( !ftio_check_xfield(ftio, FT_XFIELD_INPUT | FT_XFIELD_OUTPUT )) {
		extension_info->map->ex_id[i++] = EX_IO_SNMP_2;
	}

   	if (!ftio_check_xfield(ftio, FT_XFIELD_SRC_AS | FT_XFIELD_DST_AS)) {
		extension_info->map->ex_id[i++] = EX_AS_2;
	}

   	if (!ftio_check_xfield(ftio, FT_XFIELD_SRC_MASK | FT_XFIELD_DST_MASK)) {
		extension_info->map->ex_id[i++] = EX_MULIPLE;
	}

   	if (!ftio_check_xfield(ftio, FT_XFIELD_NEXTHOP )) {
		extension_info->map->ex_id[i++] = EX_NEXT_HOP_v4;
	}

   	if (!ftio_check_xfield(ftio, FT_XFIELD_EXADDR )) {
		extension_info->map->ex_id[i++] = EX_ROUTER_IP_v4;
	}

   	if (!ftio_check_xfield(ftio, FT_XFIELD_ENGINE_TYPE )) {
		extension_info->map->ex_id[i++] = EX_ROUTER_ID;
	}

	extension_info->map->ex_id[i++] = 0;
	extension_info->map->size       = sizeof(extension_map_t) + i * sizeof(uint16_t);

	// align 32bits
	if (( extension_info->map->size & 0x3 ) != 0 ) {
		extension_info->map->size += 4 - ( extension_info->map->size & 0x3 );
	}

	extension_info->map->extension_size = 0;
	i=0;
	while (extension_info->map->ex_id[i]) {
		int id = extension_info->map->ex_id[i];
		extension_info->map->extension_size += extension_descriptor[id].size;
		i++;
	}

	return extension_info;

} // End of GenExtensionMap

int flows2nfdump(struct ftio *ftio, extension_info_t *extension_info, int extended, uint32_t limitflows) {
// required flow tools variables
struct fttime 		ftt;
struct fts3rec_offsets fo;
struct ftver 		ftv;
char				*rec;
// nfdump variables
nffile_t			*nffile;
master_record_t	 record;
char				*s;
uint32_t			cnt;

	s = "flow-tools";
	nffile = OpenNewFile( "-", NULL, 0, 0, s);
	if ( !nffile ) {
		fprintf(stderr, "%s\n", s);
		return 1;
	}

	AppendToBuffer(nffile, (void *)extension_info->map, extension_info->map->size);
	
	ftio_get_ver(ftio, &ftv);
	fts3rec_compute_offsets(&fo, &ftv);

	memset((void *)&record, 0, sizeof(record));
	record.map_ref 		  = extension_info->map;
	record.type 		  = CommonRecordType;
	record.exporter_sysid = 0;

	// only v4 addresses
	ClearFlag(record.flags, FLAG_IPV6_ADDR);

	cnt = 0;
	while ((rec = ftio_read(ftio))) {
		uint32_t when, unix_secs, unix_nsecs, sysUpTime;
		int i, id;

		unix_secs  = *((uint32_t*)(rec+fo.unix_secs));
		unix_nsecs = *((uint32_t*)(rec+fo.unix_nsecs));
		sysUpTime  = *((uint32_t*)(rec+fo.sysUpTime));

		when	   = *((uint32_t*)(rec+fo.First));
		ftt = ftltime(sysUpTime, unix_secs, unix_nsecs, when);
		record.first 		= ftt.secs;
		record.msec_first 	= ftt.msecs;
	
		when	   = *((uint32_t*)(rec+fo.Last));
		ftt = ftltime(sysUpTime, unix_secs, unix_nsecs, when);
		record.last 		= ftt.secs;
		record.msec_last 	= ftt.msecs;
	
		record.v4.srcaddr 	= *((uint32_t*)(rec+fo.srcaddr));
		record.v4.dstaddr 	= *((uint32_t*)(rec+fo.dstaddr));
		record.srcport 		= *((uint16_t*)(rec+fo.srcport));
		record.dstport 		= *((uint16_t*)(rec+fo.dstport));

		record.prot 		= *((uint8_t*)(rec+fo.prot));
		record.tcp_flags	= *((uint8_t*)(rec+fo.tcp_flags));
		record.tos 			= *((uint8_t*)(rec+fo.tos));

		record.dOctets 		= *((uint32_t*)(rec+fo.dOctets));
		record.dPkts 		= *((uint32_t*)(rec+fo.dPkts));

		i = 0;
		while ( (id = extension_info->map->ex_id[i]) != 0 ) {
			switch (id) {
				case EX_IO_SNMP_2:
					record.input 		= *((uint16_t*)(rec+fo.input));
					record.output 		= *((uint16_t*)(rec+fo.output));
					break;
				case EX_AS_2:
					record.srcas 		= *((uint16_t*)(rec+fo.src_as));
					record.dstas 		= *((uint16_t*)(rec+fo.dst_as));
					break;
				case EX_MULIPLE:
    				record.src_mask 	= *((uint8_t*)(rec+fo.src_mask));
    				record.dst_mask 	= *((uint8_t*)(rec+fo.dst_mask));
					record.dir			= 0;
					record.dst_tos  	= 0;
					break;
				case EX_ROUTER_IP_v4:
					record.ip_nexthop.v4 = *((uint32_t*)(rec+fo.peer_nexthop));
					break;
				case EX_NEXT_HOP_v4:
					record.ip_router.v4 = *((uint32_t*)(rec+fo.router_sc));
					break;
				case EX_ROUTER_ID:
					record.engine_type = *((uint8_t*)(rec+fo.engine_type));
					record.engine_id   = *((uint8_t*)(rec+fo.engine_id));
					break;
				// default: Other extensions can not be sent with v5
			}
			i++;
		}

		PackRecord(&record, nffile);

		if ( extended ) {
			char *string;
			format_file_block_record(&record, &string, 0);
			fprintf(stderr, "%s\n", string);
		} 

		cnt++;
		if ( cnt == limitflows )
			break;

	} /* while */

	// write the last records in buffer
	if ( nffile->block_header->NumRecords ) {
		if ( WriteBlock(nffile) <= 0 ) {
			fprintf(stderr, "Failed to write output buffer: '%s'" , strerror(errno));
		} 
	}

	free((void *)extension_info->map);
	free((void *)extension_info);
	DisposeFile(nffile);

	return 0;

} // End of flows2nfdump

int main(int argc, char **argv) {
struct ftio ftio;
extension_info_t *extension_info;
struct stat statbuf;
uint32_t	limitflows;
int i, extended, printmap, ret, fd;
char   *ftfile;

	/* init fterr */
	fterr_setid(argv[0]);

	extended 	= 0;
	printmap 	= 0;
	limitflows 	= 0;
	ftfile   	= NULL;

	while ((i = getopt(argc, argv, "EVc:hmr:?")) != -1)
		switch (i) {
			case 'h': /* help */
				case '?':
				usage(argv[0]);
				exit (0);
				break;
		
			case 'V':
				printf("%s: Version: %s\n",argv[0], nfdump_version);
				exit(0);
				break;

			case 'E':
				extended = 1;
				break;
		
			case 'c':	
				limitflows = atoi(optarg);
				if ( !limitflows ) {
					fprintf(stderr, "Option -c needs a number > 0\n");
					exit(255);
				}
				break;

			case 'm':
				printmap = 1;
				break;

			case 'r':
				ftfile = optarg;
				if ( (stat(ftfile, &statbuf) < 0 ) || !(statbuf.st_mode & S_IFREG) ) {
					fprintf(stderr, "No such file: '%s'\n", ftfile);
					exit(255);
				}
				break;
		
			default:
				usage(argv[0]);
				exit (1);
				break;
	
		} /* switch */
	// End while

	if (argc - optind)
	fterr_errx(1, "Extra arguments starting with %s.", argv[optind]);
	
	if ( ftfile ) {
		fd = open(ftfile, O_RDONLY, 0);
		if ( fd < 0 ) {
			fprintf(stderr, "Can't open file '%s': %s.", ftfile, strerror(errno));
			exit(255);
		}
	} else {
		fd = 0;
	}

	/* read from fd */
	if (ftio_init(&ftio, fd, FT_IO_FLAG_READ) < 0)
		fterr_errx(1, "ftio_init(): failed");

	extension_info = GenExtensionMap(&ftio);
	if ( !extension_info ) 
		exit(255);

	if ( printmap ) {
		PrintExtensionMap(extension_info->map);
		exit(255);
	} 

	ret = flows2nfdump(&ftio, extension_info, extended, limitflows);

	return ret;

} // End of main

