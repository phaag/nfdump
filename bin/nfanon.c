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
#include "nfxV3.h"
#include "exporter.h"
#include "flist.h"
#include "panonymizer.h"

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

	if ( TestFlag(master_record->mflags, V3_FLAG_IPV6_ADDR ) != 0 ) {
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

/* XXX fix
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
*/
} // End of AnonRecord


static void process_data(void *wfile) {
nffile_t			*nffile_r;
nffile_t			*nffile_w;
int 		i, done, ret, cnt, verbose;
char		outfile[MAXPATHLEN], *cfile;

	setbuf(stderr, NULL);
	cnt 	= 1;
	verbose = 1;

	// Get the first file handle
	nffile_r = GetNextFile(NULL);
	if ( !nffile_r ) {
		LogError("GetNextFile() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return;
	}
	if ( nffile_r == EMPTY_LIST ) {
		LogError("Empty file list. No files to process\n");
		return;
	}

	cfile = nffile_r->fileName;
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

	// XXX fix anon flag
	if ( wfile )
		nffile_w = OpenNewFile(wfile, NULL, FILE_COMPRESSION(nffile_r), NOT_ENCRYPTED);
	else
		nffile_w = OpenNewFile(outfile, NULL, FILE_COMPRESSION(nffile_r), NOT_ENCRYPTED);

	if ( !nffile_w ) {
		if ( nffile_r ) {
			CloseFile(nffile_r);
			DisposeFile(nffile_r);
		}
		return;
	}

	master_record_t *master_record = malloc(sizeof(master_record_t));
	if ( !master_record ) {
		LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return;
	}

	SetIdent(nffile_w, FILE_IDENT(nffile_r));
	memcpy((void *)nffile_w->stat_record, (void *)nffile_r->stat_record, sizeof(stat_record_t));

	done = 0;
	while ( !done ) {
		// get next data block from file
		ret = ReadBlock(nffile_r);

		switch (ret) {
			case NF_CORRUPT:
			case NF_ERROR:
				if ( ret == NF_CORRUPT ) 
					LogError("Skip corrupt data file '%s'\n",cfile);
				else 
					LogError("Read error in file '%s': %s\n",cfile, strerror(errno) );
				// fall through - get next file in chain
			case NF_EOF: {
				nffile_t *next;
    			if ( nffile_w->block_header->NumRecords ) {
        			if ( WriteBlock(nffile_w) <= 0 ) {
            			LogError("Failed to write output buffer to disk: '%s'" , strerror(errno));
        			} 
    			}
				if ( wfile == NULL ) {
					CloseUpdateFile(nffile_w);
					if ( rename(outfile, cfile) < 0 ) {
						LogError("\nrename() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
						LogError("Abort processing.\n");
						return;
					}
				}

				next = GetNextFile(nffile_r);
				if ( next == EMPTY_LIST ) {
					done = 1;
					continue;
				}
				if ( next == NULL ) {
					LogError("Unexpected end of file list\n");
					done = 1;
					continue;
				}

				cfile = nffile_r->fileName;
				if ( !cfile ) {
					LogError("(NULL) input file name error in %s line %d\n", __FILE__, __LINE__);
					return;
				}
				LogError(" %i Processing %s\r", cnt++, cfile);

				if ( wfile == NULL ) {
					snprintf(outfile,MAXPATHLEN-1, "%s-tmp", cfile);
					outfile[MAXPATHLEN-1] = '\0';

					nffile_w = OpenNewFile(outfile, nffile_w, FILE_COMPRESSION(nffile_r), NOT_ENCRYPTED);
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

		if ( nffile_r->block_header->type != DATA_BLOCK_TYPE_2 && 
			 nffile_r->block_header->type != DATA_BLOCK_TYPE_3) {
			fprintf(stderr, "Can't process block type %u. Skip block.\n", nffile_r->block_header->type);
			continue;
		}

		record_header_t	*record_ptr = nffile_r->buff_ptr;
		uint32_t sumSize = 0;
		for ( i=0; i < nffile_r->block_header->NumRecords; i++ ) {
			if ( (sumSize + record_ptr->size) > ret || (record_ptr->size < sizeof(record_header_t)) ) {
				LogError("Corrupt data file. Inconsistent block size in %s line %d\n", __FILE__, __LINE__);
				exit(255);
			}
			sumSize += record_ptr->size;

			switch ( record_ptr->type ) { 
				case V3Record: {
					memset((void *)master_record, 0, sizeof(master_record_t));
					ExpandRecord_v3((recordHeaderV3_t *)record_ptr, master_record);
					AnonRecord(master_record);
					PackRecordV3(master_record, nffile_w);

					} break;
				case ExporterInfoRecordType:
				case ExporterStatRecordType:
				case SamplerInfoRecordype:
						// Silently skip exporter/sampler records
					break;

				default: {
					fprintf(stderr, "Skip unknown record type %i\n", record_ptr->type);
				}
			}
			// Advance pointer by number of bytes for netflow record
			record_ptr = (record_header_t *)((void *)record_ptr + record_ptr->size);	

		} // for all records

	} // while

	if ( wfile != NULL )
		CloseUpdateFile(nffile_w);

	if ( nffile_r ) {
		CloseFile(nffile_r);
		DisposeFile(nffile_r);
	}

	DisposeFile(nffile_w);

	LogError("\n");
	LogError("Processed %i files.\n", --cnt);

} // End of process_data


int main( int argc, char **argv ) {
char 		*wfile;
int			c;
char		CryptoPAnKey[32];
flist_t flist;

	memset((void *)&flist, 0, sizeof(flist));
	wfile = NULL;
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
				if ( !InitLog(0, "argv[0]", optarg, 0) )
					exit(255);
				break;
			case 'r':
				if ( !CheckPath(optarg, S_IFREG) )
					exit(255);
				flist.single_file = strdup(optarg);
				break;
			case 'M':
				if ( !CheckPath(optarg, S_IFDIR) )
					exit(255);
				flist.multiple_dirs = strdup(optarg);
				break;
			case 'R':
				if ( !CheckPath(optarg, S_IFDIR) )
					exit(255);
				flist.multiple_files = strdup(optarg);
				break;
			case 'w':
				wfile = optarg;
				break;
			default:
				usage(argv[0]);
				exit(0);
		}
	}


	queue_t *fileList = SetupInputFileSequence(&flist);
	if ( !fileList || !Init_nffile(fileList) )
		exit(255);

	process_data(wfile);

	return 0;
}
