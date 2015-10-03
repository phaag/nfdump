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
 *  $Id:$
 *
 *  $LastChangedRevision: 48 $
 *	
 *
 */

#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nffile.h"
#include "nfx.h"
#include "util.h"
#include "flist.h"
#include "panonymizer.h"

#if ( SIZEOF_VOID_P == 8 )
typedef uint64_t    pointer_addr_t;
#else
typedef uint32_t    pointer_addr_t;
#endif

// module limited globals
extension_map_list_t *extension_map_list;

/* Function Prototypes */
static void usage(char *name);

static inline void AnonRecord(master_record_t *master_record);

static void process_data(void *wfile);

/* Functions */

#define NEED_PACKRECORD 1
#include "nffile_inline.c"
#undef NEED_PACKRECORD

static void usage(char *name) {
		printf("usage %s [options] \n"
					"-h\t\tthis text you see right here\n"
					"-K <key>\tAnonymize IP addressses using CryptoPAn with key <key>.\n"
					"-r\t\tread input from file\n"
					"-M <expr>\tRead input from multiple directories.\n"
					"-R <expr>\tRead input from sequence of files.\n"
					"-w <file>\tName of output file. Defaults to input file.\n"
					, name);
} /* usage */

static inline void AnonRecord(master_record_t *master_record) {
extension_map_t *extension_map = master_record->map_ref;
int		i;

	// Required extension 1 - IP addresses
	if ( (master_record->flags & FLAG_IPV6_ADDR) != 0 )	{ // IPv6
		// IPv6
		uint64_t    anon_ip[2];
		anonymize_v6(master_record->v6.srcaddr, anon_ip);
		master_record->v6.srcaddr[0] = anon_ip[0];
		master_record->v6.srcaddr[1] = anon_ip[1];
    
		anonymize_v6(master_record->v6.dstaddr, anon_ip);
		master_record->v6.dstaddr[0] = anon_ip[0];
		master_record->v6.dstaddr[1] = anon_ip[1];

	} else { 	
		// IPv4
		master_record->v4.srcaddr = anonymize(master_record->v4.srcaddr);
		master_record->v4.dstaddr = anonymize(master_record->v4.dstaddr);
	}

	// Process optional extensions
	i=0;
	while ( extension_map->ex_id[i] ) {
		switch (extension_map->ex_id[i++]) {
			case EX_AS_2: // srcas/dstas 2 byte
				master_record->srcas = 0;
				master_record->dstas = 0;
				break;
			case EX_AS_4: // srcas/dstas 4 byte
				master_record->srcas = 0;
				master_record->dstas = 0;
				break;
			case EX_NEXT_HOP_v4:
				master_record->ip_nexthop.v4 = anonymize(master_record->ip_nexthop.v4);
				break;
			case EX_NEXT_HOP_v6: {
				uint64_t    anon_ip[2];
				anonymize_v6(master_record->ip_nexthop.v6, anon_ip);
				master_record->ip_nexthop.v6[0] = anon_ip[0];
				master_record->ip_nexthop.v6[1] = anon_ip[1];
				} break;
			case EX_NEXT_HOP_BGP_v4: 
				master_record->bgp_nexthop.v4 = anonymize(master_record->bgp_nexthop.v4);
				break;
			case EX_NEXT_HOP_BGP_v6: {
				uint64_t    anon_ip[2];
				anonymize_v6(master_record->bgp_nexthop.v6, anon_ip);
				master_record->bgp_nexthop.v6[0] = anon_ip[0];
				master_record->bgp_nexthop.v6[1] = anon_ip[1];
				} break;
			case EX_ROUTER_IP_v4:
				master_record->ip_router.v4 = anonymize(master_record->ip_router.v4);
				break;
			case EX_ROUTER_IP_v6: {
				uint64_t    anon_ip[2];
				anonymize_v6(master_record->ip_router.v6, anon_ip);
				master_record->ip_router.v6[0] = anon_ip[0];
				master_record->ip_router.v6[1] = anon_ip[1];
				} break;
#ifdef NSEL
			case EX_NSEL_XLATE_IP_v4:
				master_record->xlate_src_ip.v4 = anonymize(master_record->xlate_src_ip.v4);
				master_record->xlate_dst_ip.v4 = anonymize(master_record->xlate_dst_ip.v4);
				break;
			case EX_NSEL_XLATE_IP_v6: {
				uint64_t    anon_ip[2];
				anonymize_v6(master_record->xlate_src_ip.v6, anon_ip);
				master_record->xlate_src_ip.v6[0] = anon_ip[0];
				master_record->xlate_src_ip.v6[1] = anon_ip[1];
				anonymize_v6(master_record->xlate_dst_ip.v6, anon_ip);
				master_record->xlate_dst_ip.v6[0] = anon_ip[0];
				master_record->xlate_dst_ip.v6[1] = anon_ip[1];
				} break;
#endif
		}
	}

} // End of AnonRecord


static void process_data(void *wfile) {
master_record_t		master_record;
common_record_t     *flow_record;
nffile_t			*nffile_r;
nffile_t			*nffile_w;
int 		i, done, ret, cnt, verbose;
char		outfile[MAXPATHLEN], *cfile;
#ifdef COMPAT15
int	v1_map_done = 0;
#endif


	setbuf(stderr, NULL);
	cnt 	= 1;
	verbose = 1;

	// Get the first file handle
	nffile_r = GetNextFile(NULL, 0, 0);
	if ( !nffile_r ) {
		LogError("GetNextFile() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return;
	}
	if ( nffile_r == EMPTY_LIST ) {
		LogError("Empty file list. No files to process\n");
		return;
	}

	cfile = GetCurrentFilename();
	if ( !cfile ) {
		if ( nffile_r->fd == 0 ) { // stdin
			outfile[0] = '-';
			outfile[1] = '\0';
			verbose = 0;
		} else {
			LogError("(NULL) input file name error in %s line %d\n", __FILE__, __LINE__);
			return;
		}
	} else {
		// prepare output file
		snprintf(outfile,MAXPATHLEN-1, "%s-tmp", cfile);
		outfile[MAXPATHLEN-1] = '\0';
		if ( verbose )
			fprintf(stderr, " %i Processing %s\r", cnt++, cfile);
	}

	if ( wfile )
		nffile_w = OpenNewFile(wfile, NULL, FILE_IS_COMPRESSED(nffile_r), 1, NULL);
	else
		nffile_w = OpenNewFile(outfile, NULL, FILE_IS_COMPRESSED(nffile_r), 1, NULL);

	if ( !nffile_w ) {
		if ( nffile_r ) {
			CloseFile(nffile_r);
			DisposeFile(nffile_r);
		}
		return;
	}

	memcpy((void *)nffile_w->stat_record, (void *)nffile_r->stat_record, sizeof(stat_record_t));

	done = 0;
	while ( !done ) {
		// get next data block from file
		ret = ReadBlock(nffile_r);

		switch (ret) {
			case NF_CORRUPT:
			case NF_ERROR:
				if ( ret == NF_CORRUPT ) 
					LogError("Skip corrupt data file '%s'\n",GetCurrentFilename());
				else 
					LogError("Read error in file '%s': %s\n",GetCurrentFilename(), strerror(errno) );
				// fall through - get next file in chain
			case NF_EOF: {
				nffile_t *next;
    			if ( nffile_w->block_header->NumRecords ) {
        			if ( WriteBlock(nffile_w) <= 0 ) {
            			LogError("Failed to write output buffer to disk: '%s'" , strerror(errno));
        			} 
    			}
				if ( wfile == NULL ) {
					CloseUpdateFile(nffile_w, nffile_r->file_header->ident);
					if ( rename(outfile, cfile) < 0 ) {
						LogError("\nrename() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
						LogError("Abort processing.\n");
						return;
					}
				}

				next = GetNextFile(nffile_r, 0, 0);
				if ( next == EMPTY_LIST ) {
					done = 1;
					continue;
				}
				if ( next == NULL ) {
					LogError("Unexpected end of file list\n");
					done = 1;
					continue;
				}

				cfile = GetCurrentFilename();
				if ( !cfile ) {
					LogError("(NULL) input file name error in %s line %d\n", __FILE__, __LINE__);
					return;
				}
				LogError(" %i Processing %s\r", cnt++, cfile);

				if ( wfile == NULL ) {
					snprintf(outfile,MAXPATHLEN-1, "%s-tmp", cfile);
					outfile[MAXPATHLEN-1] = '\0';

					nffile_w = OpenNewFile(outfile, nffile_w, FILE_IS_COMPRESSED(nffile_r), 1, NULL);
					if ( !nffile_w ) {
						if ( nffile_r ) {
							CloseFile(nffile_r);
							DisposeFile(nffile_r);
						}
						return;
					}
					memcpy((void *)nffile_w->stat_record, (void *)&nffile_r->stat_record, sizeof(stat_record_t));
				} else {
					SumStatRecords(nffile_w->stat_record, nffile_r->stat_record);
				}

				// continue with next file
				continue;
	
				} break; // not really needed
		}

#ifdef COMPAT15
		if ( nffile_r->block_header->id == DATA_BLOCK_TYPE_1 ) {
			common_record_v1_t *v1_record = (common_record_v1_t *)nffile_r->buff_ptr;
			// create an extension map for v1 blocks
			if ( v1_map_done == 0 ) {
				extension_map_t *map = malloc(sizeof(extension_map_t) + 2 * sizeof(uint16_t) );
				if ( ! map ) {
					LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
					exit(255);
				}
				map->type 	= ExtensionMapType;
				map->size 	= sizeof(extension_map_t) + 2 * sizeof(uint16_t);
				map->map_id = 0;
				map->ex_id[0]  = EX_IO_SNMP_2;
				map->ex_id[1]  = EX_AS_2;
				map->ex_id[2]  = 0;

				Insert_Extension_Map(extension_map_list, map);
				AppendToBuffer(nffile_w, (void *)map, map->size);

				v1_map_done = 1;
			}

			// convert the records to v2
			for ( i=0; i < nffile_r->block_header->NumRecords; i++ ) {
				common_record_t *v2_record = (common_record_t *)v1_record;
				Convert_v1_to_v2((void *)v1_record);
				// now we have a v2 record -> use size of v2_record->size
				v1_record = (common_record_v1_t *)((pointer_addr_t)v1_record + v2_record->size);
			}
			nffile_r->block_header->id = DATA_BLOCK_TYPE_2;
		}
#endif

		if ( nffile_r->block_header->id == Large_BLOCK_Type ) {
			// skip
			continue;
		}

		if ( nffile_r->block_header->id != DATA_BLOCK_TYPE_2 ) {
			fprintf(stderr, "Can't process block type %u. Skip block.\n", nffile_r->block_header->id);
			continue;
		}

		flow_record = nffile_r->buff_ptr;
		for ( i=0; i < nffile_r->block_header->NumRecords; i++ ) {
			switch ( flow_record->type ) { 
				case CommonRecordV0Type:
				case CommonRecordType: {
					uint32_t map_id = flow_record->ext_map;
					if ( extension_map_list->slot[map_id] == NULL ) {
						LogError("Corrupt data file! No such extension map id: %u. Skip record", flow_record->ext_map );
					} else {
						ExpandRecord_v2( flow_record, extension_map_list->slot[flow_record->ext_map], NULL, &master_record);
	
						// update number of flows matching a given map
						extension_map_list->slot[map_id]->ref_count++;
			
						AnonRecord(&master_record);
						PackRecord(&master_record, nffile_w);
					}

					} break;
				case ExtensionMapType: {
					extension_map_t *map = (extension_map_t *)flow_record;

					if ( Insert_Extension_Map(extension_map_list, map) ) {
					 	// flush new map
					} // else map already known and flushed
					AppendToBuffer(nffile_w, (void *)map, map->size);

					} break; 
				case ExporterRecordType:
				case SamplerRecordype:
				case ExporterInfoRecordType:
				case ExporterStatRecordType:
				case SamplerInfoRecordype:
						// Silently skip exporter/sampler records
					break;

				default: {
					fprintf(stderr, "Skip unknown record type %i\n", flow_record->type);
				}
			}
			// Advance pointer by number of bytes for netflow record
			flow_record = (common_record_t *)((pointer_addr_t)flow_record + flow_record->size);	

		} // for all records

	} // while

	PackExtensionMapList(extension_map_list);
	if ( wfile != NULL )
		CloseUpdateFile(nffile_w, nffile_r->file_header->ident);

	if ( nffile_r ) {
		CloseFile(nffile_r);
		DisposeFile(nffile_r);
	}

	DisposeFile(nffile_w);

	LogError("\n");
	LogError("Processed %i files.\n", --cnt);

} // End of process_data


int main( int argc, char **argv ) {
char 		*rfile, *Rfile, *wfile, *Mdirs;
int			c;
char		CryptoPAnKey[32];

	rfile = Rfile = Mdirs = wfile = NULL;
	while ((c = getopt(argc, argv, "K:L:r:M:R:w:")) != EOF) {
		switch (c) {
			case 'h':
				usage(argv[0]);
				exit(0);
				break;
				break;
			case 'K':
				if ( !ParseCryptoPAnKey(optarg, CryptoPAnKey) ) {
					fprintf(stderr, "Invalid key '%s' for CryptoPAn!\n", optarg);
					exit(255);
				}
				PAnonymizer_Init((uint8_t *)CryptoPAnKey);
				break;
			case 'L':
				if ( !InitLog("argv[0]", optarg) )
					exit(255);
				break;
			case 'r':
				rfile = optarg;
				if ( strcmp(rfile, "-") == 0 )
					rfile = NULL;
				break;
			case 'M':
				Mdirs = optarg;
				break;
			case 'R':
				Rfile = optarg;
				break;
			case 'w':
				wfile = optarg;
				break;
			default:
				usage(argv[0]);
				exit(0);
		}
	}

	if ( rfile && Rfile ) {
		fprintf(stderr, "-r and -R are mutually exclusive. Please specify either -r or -R\n");
		exit(255);
	}
	if ( Mdirs && !(rfile || Rfile) ) {
		fprintf(stderr, "-M needs either -r or -R to specify the file or file list. Add '-R .' for all files in the directories.\n");
		exit(255);
	}

	extension_map_list = InitExtensionMaps(NEEDS_EXTENSION_LIST);

	SetupInputFileSequence(Mdirs, rfile, Rfile);

	process_data(wfile);

	FreeExtensionMaps(extension_map_list);

	return 0;
}
