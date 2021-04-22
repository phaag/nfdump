/*
 *  Copyright (c) 2009-2020, Peter Haag
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

#include "util.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfx.h"
#include "exporter.h"
#include "flist.h"
#include "panonymizer.h"

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
					"-K <key>\tAnonymize IP addresses using CryptoPAn with key <key>.\n"
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
		anonymize_v6(master_record->V6.srcaddr, anon_ip);
		master_record->V6.srcaddr[0] = anon_ip[0];
		master_record->V6.srcaddr[1] = anon_ip[1];
    
		anonymize_v6(master_record->V6.dstaddr, anon_ip);
		master_record->V6.dstaddr[0] = anon_ip[0];
		master_record->V6.dstaddr[1] = anon_ip[1];

	} else { 	
		// IPv4
		master_record->V4.srcaddr = anonymize(master_record->V4.srcaddr);
		master_record->V4.dstaddr = anonymize(master_record->V4.dstaddr);
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
				master_record->ip_nexthop.V4 = anonymize(master_record->ip_nexthop.V4);
				break;
			case EX_NEXT_HOP_v6: {
				uint64_t    anon_ip[2];
				anonymize_v6(master_record->ip_nexthop.V6, anon_ip);
				master_record->ip_nexthop.V6[0] = anon_ip[0];
				master_record->ip_nexthop.V6[1] = anon_ip[1];
				} break;
			case EX_NEXT_HOP_BGP_v4: 
				master_record->bgp_nexthop.V4 = anonymize(master_record->bgp_nexthop.V4);
				break;
			case EX_NEXT_HOP_BGP_v6: {
				uint64_t    anon_ip[2];
				anonymize_v6(master_record->bgp_nexthop.V6, anon_ip);
				master_record->bgp_nexthop.V6[0] = anon_ip[0];
				master_record->bgp_nexthop.V6[1] = anon_ip[1];
				} break;
			case EX_ROUTER_IP_v4:
				master_record->ip_router.V4 = anonymize(master_record->ip_router.V4);
				break;
			case EX_ROUTER_IP_v6: {
				uint64_t    anon_ip[2];
				anonymize_v6(master_record->ip_router.V6, anon_ip);
				master_record->ip_router.V6[0] = anon_ip[0];
				master_record->ip_router.V6[1] = anon_ip[1];
				} break;
#ifdef NSEL
			case EX_NSEL_XLATE_IP_v4:
				master_record->xlate_src_ip.V4 = anonymize(master_record->xlate_src_ip.V4);
				master_record->xlate_dst_ip.V4 = anonymize(master_record->xlate_dst_ip.V4);
				break;
			case EX_NSEL_XLATE_IP_v6: {
				uint64_t    anon_ip[2];
				anonymize_v6(master_record->xlate_src_ip.V6, anon_ip);
				master_record->xlate_src_ip.V6[0] = anon_ip[0];
				master_record->xlate_src_ip.V6[1] = anon_ip[1];
				anonymize_v6(master_record->xlate_dst_ip.V6, anon_ip);
				master_record->xlate_dst_ip.V6[0] = anon_ip[0];
				master_record->xlate_dst_ip.V6[1] = anon_ip[1];
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
			LogInfo(" %i Processing %s", cnt++, cfile);
	}

	if ( wfile )
		nffile_w = OpenNewFile(wfile, NULL, FILE_COMPRESSION(nffile_r), 1, NULL);
	else
		nffile_w = OpenNewFile(outfile, NULL, FILE_COMPRESSION(nffile_r), 1, NULL);

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
				printf(" %i Processing %s\r", cnt++, cfile);

				if ( wfile == NULL ) {
					snprintf(outfile,MAXPATHLEN-1, "%s-tmp", cfile);
					outfile[MAXPATHLEN-1] = '\0';

					nffile_w = OpenNewFile(outfile, nffile_w, FILE_COMPRESSION(nffile_r), 1, NULL);
					if ( !nffile_w ) {
						if ( nffile_r ) {
							CloseFile(nffile_r);
							DisposeFile(nffile_r);
						}
						return;
					}
					memcpy((void *)nffile_w->stat_record, (void *)nffile_r->stat_record, sizeof(stat_record_t));
				} else {
					SumStatRecords(nffile_w->stat_record, nffile_r->stat_record);
				}

				// continue with next file
				continue;
	
				} break; // not really needed
		}

		if ( nffile_r->block_header->id != DATA_BLOCK_TYPE_2 ) {
			LogError("Can't process block type %u. Skip block", nffile_r->block_header->id);
			continue;
		}

		flow_record = nffile_r->buff_ptr;
		uint32_t sumSize = 0;
		for ( i=0; i < nffile_r->block_header->NumRecords; i++ ) {
			if ( (sumSize + flow_record->size) > ret ) {
				LogError("Corrupt data file. Inconsistent block size in %s line %d\n", __FILE__, __LINE__);
				exit(255);
			}
			sumSize += flow_record->size;

			switch ( flow_record->type ) { 
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

					int ret = Insert_Extension_Map(extension_map_list, map);
					switch (ret) {
						case 0:
							break; // map already known and flushed
						case 1:
							AppendToBuffer(nffile_w, (void *)map, map->size);
							break;
						default:
							LogError("Corrupt data file. Unable to decode at %s line %d\n", __FILE__, __LINE__);
							exit(255);
					}
					} break; 
				case LegacyRecordType1:
				case LegacyRecordType2:
				case ExporterInfoRecordType:
				case ExporterStatRecordType:
				case SamplerInfoRecordype:
						// Silently skip exporter/sampler records
					break;

				default: {
					LogError("Skip unknown record type %i", flow_record->type);
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

	LogError("Processed %i files", --cnt);

} // End of process_data


int main( int argc, char **argv ) {
char 		*rfile, *Rfile, *wfile, *Mdirs;
int			c;
char		CryptoPAnKey[32];

	memset((void *)CryptoPAnKey, 0, sizeof(CryptoPAnKey));
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
					LogError("Invalid key '%s' for CryptoPAn", optarg);
					exit(255);
				}
				PAnonymizer_Init((uint8_t *)CryptoPAnKey);
				break;
			case 'L':
				if ( !InitLog(0, "argv[0]", optarg, 0) )
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

	if ( CryptoPAnKey[0] == '\0' ) {
		LogError("Expect -K <key> - 32 bytes key");
		exit(255);
	}

	if ( rfile && Rfile ) {
		LogError("-r and -R are mutually exclusive. Please specify either -r or -R");
		exit(255);
	}
	if ( Mdirs && !(rfile || Rfile) ) {
		LogError("-M needs either -r or -R to specify the file or file list. Add '-R .' for all files in the directories");
		exit(255);
	}

	extension_map_list = InitExtensionMaps(NEEDS_EXTENSION_LIST);

	SetupInputFileSequence(Mdirs, rfile, Rfile);

	process_data(wfile);

	FreeExtensionMaps(extension_map_list);

	return 0;
}
