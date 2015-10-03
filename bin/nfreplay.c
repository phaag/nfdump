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
 *  $Id: nfreplay.c 39 2009-11-25 08:11:15Z haag $
 *
 *  $LastChangedRevision: 39 $
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
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/resource.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nffile.h"
#include "nfx.h"
#include "nf_common.h"
#include "rbtree.h"
#include "nftree.h"
#include "nfdump.h"
#include "nfnet.h"
#include "bookkeeper.h"
#include "nfxstat.h"
#include "collector.h"
#include "exporter.h"
#include "netflow_v5_v7.h"
#include "netflow_v9.h"
#include "nfprof.h"
#include "flist.h"
#include "util.h"
#include "grammar.h"

#define DEFAULTCISCOPORT "9995"
#define DEFAULTHOSTNAME "127.0.0.1"

#undef	FPURGE
#ifdef	HAVE___FPURGE
#define	FPURGE	__fpurge
#endif
#ifdef	HAVE_FPURGE
#define	FPURGE	fpurge
#endif

/* Externals */
extern int yydebug;

#ifdef COMPAT15
extern extension_descriptor_t extension_descriptor[];
#endif

/* Global Variables */
FilterEngine_data_t	*Engine;
int 		verbose;

/* Local Variables */
static const char *nfdump_version = VERSION;

send_peer_t peer;

extension_map_list_t *extension_map_list;

generic_exporter_t **exporter_list;

/* Function Prototypes */
static void usage(char *name);

static void send_blast(unsigned int delay );

static void send_data(char *rfile, time_t twin_start, time_t twin_end, uint32_t count, 
				unsigned int delay,  int confirm, int netflow_version);

static int FlushBuffer(int confirm);

/* Functions */

#include "nffile_inline.c"
#include "nfdump_inline.c"

static void usage(char *name) {
		printf("usage %s [options] [\"filter\"]\n"
					"-h\t\tthis text you see right here\n"
					"-V\t\tPrint version and exit.\n"
					"-H <Host/ip>\tTarget IP address default: 127.0.0.1\n"
					"-j <mcast>\tSend packets to multicast group\n"
					"-4\t\tForce IPv4 protocol.\n"
					"-6\t\tForce IPv6 protocol.\n"
					"-L <log>\tLog to syslog facility <log>\n"
					"-p <port>\tTarget port default 9995\n"
					"-d <usec>\tDelay in usec between packets. default 10\n"
					"-c <cnt>\tPacket count. default send all packets\n"
					"-b <bsize>\tSend buffer size.\n"
					"-r <input>\tread from file. default: stdin\n"
					"-f <filter>\tfilter syntaxfile\n"
					"-t <time>\ttime window for sending packets\n"
					"\t\tyyyy/MM/dd.hh:mm:ss[-yyyy/MM/dd.hh:mm:ss]\n"
					, name);
} /* usage */

static int FlushBuffer(int confirm) {
size_t len = (pointer_addr_t)peer.buff_ptr - (pointer_addr_t)peer.send_buffer;
static unsigned long cnt = 1;

	peer.flush = 0;
	peer.buff_ptr = peer.send_buffer;
	if ( confirm ) {
		FPURGE(stdin);
		printf("Press any key to send next UDP packet [%lu] ", cnt++);
		fflush(stdout);
		fgetc(stdin);
	}
	return sendto(peer.sockfd, peer.send_buffer, len, 0, (struct sockaddr *)&(peer.addr), peer.addrlen);
} // End of FlushBuffer


static void send_blast(unsigned int delay ) {
common_flow_header_t	*header;
nfprof_t    			profile_data;
int						i, ret;
u_long	 				usec, sec;
double 					fps;

	peer.send_buffer = malloc(1400);
	if ( !peer.send_buffer ) {
		perror("Memory allocation error");
		close(peer.sockfd);
		return;
	}
	header = (common_flow_header_t *)peer.send_buffer;
	header->version = htons(255);
	nfprof_start(&profile_data);
	for ( i = 0; i < 65535; i++ ) {
		header->count = htons(i);
		ret = sendto(peer.sockfd, peer.send_buffer, 1400, 0, (struct sockaddr *)&peer.addr, peer.addrlen);
		if ( ret < 0 || ret != 1400 ) {
			perror("Error sending data");
		}

		if ( delay ) {
			// sleep as specified
			usleep(delay);
		}
	}
	nfprof_end(&profile_data, 8*65535*1400);


	usec = profile_data.used.ru_utime.tv_usec + profile_data.used.ru_stime.tv_usec;
	sec = profile_data.used.ru_utime.tv_sec + profile_data.used.ru_stime.tv_sec;

	if (usec > 1000000)
		usec -= 1000000, ++sec;

	if (profile_data.tend.tv_usec < profile_data.tstart.tv_usec) 
		profile_data.tend.tv_usec += 1000000, --profile_data.tend.tv_sec;

	usec = profile_data.tend.tv_usec - profile_data.tstart.tv_usec;
	sec = profile_data.tend.tv_sec - profile_data.tstart.tv_sec;
	fps = (double)profile_data.numflows / ((double)sec + ((double)usec/1000000));

	fprintf(stdout, "Wall: %lu.%-3.3lus bps: %-10.1f\n", sec, usec/1000, fps);


} // End of send_blast

static void send_data(char *rfile, time_t twin_start, 
			time_t twin_end, uint32_t count, unsigned int delay, int confirm, int netflow_version) {
master_record_t	master_record;
common_record_t	*flow_record;
nffile_t		*nffile;
int 			i, done, ret, again;
uint32_t		numflows, cnt;

#ifdef COMPAT15
int	v1_map_done = 0;
#endif
	
	// Get the first file handle
	nffile = GetNextFile(NULL, twin_start, twin_end);
	if ( !nffile ) {
		LogError("GetNextFile() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return;
	}
	if ( nffile == EMPTY_LIST ) {
		LogError("Empty file list. No files to process\n");
		return;
	}

	peer.send_buffer   	= malloc(UDP_PACKET_SIZE);
	peer.flush			= 0;
	if ( !peer.send_buffer ) {
		LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		CloseFile(nffile);
		DisposeFile(nffile);
		return;
	}
	peer.buff_ptr = peer.send_buffer;
	peer.endp  	  = (void *)((pointer_addr_t)peer.send_buffer + UDP_PACKET_SIZE - 1);

	if ( netflow_version == 5 ) 
		Init_v5_v7_output(&peer);
	else 
		Init_v9_output(&peer);

	numflows	= 0;
	done	 	= 0;

	// setup Filter Engine to point to master_record, as any record read from file
	// is expanded into this record
	Engine->nfrecord = (uint64_t *)&master_record;

	cnt = 0;
	while ( !done ) {
		// get next data block from file
		ret = ReadBlock(nffile);

		switch (ret) {
			case NF_CORRUPT:
			case NF_ERROR:
				if ( ret == NF_CORRUPT ) 
					LogError("Skip corrupt data file '%s'\n",GetCurrentFilename());
				else 
					LogError("Read error in file '%s': %s\n",GetCurrentFilename(), strerror(errno) );
				// fall through - get next file in chain
			case NF_EOF: {
				nffile_t *next = GetNextFile(nffile, twin_start, twin_end);
				if ( next == EMPTY_LIST ) {
					done = 1;
				}
				if ( next == NULL ) {
					done = 1;
					LogError("Unexpected end of file list\n");
				}
				// else continue with next file
				continue;
	
				} break; // not really needed
		}

#ifdef COMPAT15
		if ( nffile->block_header->id == DATA_BLOCK_TYPE_1 ) {
			common_record_v1_t *v1_record = (common_record_v1_t *)nffile->buff_ptr;
			// create an extension map for v1 blocks
			if ( v1_map_done == 0 ) {
				extension_map_t *map = malloc(sizeof(extension_map_t) + 2 * sizeof(uint16_t) );
				if ( ! map ) {
					perror("Memory allocation error");
					exit(255);
				}
				map->type 	= ExtensionMapType;
				map->size 	= sizeof(extension_map_t) + 2 * sizeof(uint16_t);
				if (( map->size & 0x3 ) != 0 ) {
					map->size += 4 - ( map->size & 0x3 );
				}
				map->map_id = INIT_ID;
				map->ex_id[0]  = EX_IO_SNMP_2;
				map->ex_id[1]  = EX_AS_2;
				map->ex_id[2]  = 0;
				
				map->extension_size  = 0;
				map->extension_size += extension_descriptor[EX_IO_SNMP_2].size;
				map->extension_size += extension_descriptor[EX_AS_2].size;
					
				Insert_Extension_Map(extension_map_list, map);
				v1_map_done = 1;
			}

			// convert the records to v2
			for ( i=0; i < nffile->block_header->NumRecords; i++ ) {
				common_record_t *v2_record = (common_record_t *)v1_record;
				Convert_v1_to_v2((void *)v1_record);
				// now we have a v2 record -> use size of v2_record->size
				v1_record = (common_record_v1_t *)((pointer_addr_t)v1_record + v2_record->size);
			}
			nffile->block_header->id = DATA_BLOCK_TYPE_2;
		}
#endif

		if ( nffile->block_header->id != DATA_BLOCK_TYPE_2 ) {
			LogError("Can't process block type %u. Skip block.\n", nffile->block_header->id);
			continue;
		}

		// cnt is the number of blocks, which survived the filter
		// and added to the output buffer
		flow_record = nffile->buff_ptr;

		for ( i=0; i < nffile->block_header->NumRecords; i++ ) {
			int match;

			switch ( flow_record->type ) {
				case CommonRecordV0Type:
				case CommonRecordType: {
					if ( extension_map_list->slot[flow_record->ext_map] == NULL ) {
						LogError("Corrupt data file. Missing extension map %u. Skip record.\n", flow_record->ext_map);
						flow_record = (common_record_t *)((pointer_addr_t)flow_record + flow_record->size);	
						continue;
					} 

					// if no filter is given, the result is always true
					ExpandRecord_v2( flow_record, extension_map_list->slot[flow_record->ext_map], NULL, &master_record);

					match = twin_start && (master_record.first < twin_start || master_record.last > twin_end) ? 0 : 1;

					// filter netflow record with user supplied filter
					if ( match ) 
						match = (*Engine->FilterEngine)(Engine);
	
					if ( match == 0 ) { // record failed to pass all filters
						// increment pointer by number of bytes for netflow record
						flow_record = (common_record_t *)((pointer_addr_t)flow_record + flow_record->size);	
						// go to next record
						continue;
					}
					// Records passed filter -> continue record processing

					if ( netflow_version == 5 ) 
						again = Add_v5_output_record(&master_record, &peer);
					else
						again = Add_v9_output_record(&master_record, &peer);
	
					cnt++;
					numflows++;

					if ( peer.flush ) {
						ret = FlushBuffer(confirm);
	
						if ( ret < 0 ) {
							perror("Error sending data");
							CloseFile(nffile);
							DisposeFile(nffile);
							return;
						}
			
						if ( delay ) {
							// sleep as specified
							usleep(delay);
						}
						cnt = 0;
					}
	
					if ( again ) {
						if ( netflow_version == 5 ) 
							Add_v5_output_record(&master_record, &peer);
						else
							Add_v9_output_record(&master_record, &peer);
						cnt++;
					}

					} break;
				case ExtensionMapType: {
					extension_map_t *map = (extension_map_t *)flow_record;
	
					if ( Insert_Extension_Map(extension_map_list, map) ) {
						// flush new map
						
					} // else map already known and flushed
	
					} break;
				case ExporterRecordType:
				case SamplerRecordype:
				case ExporterInfoRecordType:
				case ExporterStatRecordType:
				case SamplerInfoRecordype:
						// Silently skip exporter/sampler records
					break;
			 	default: {
					LogError("Skip unknown record type %i\n", flow_record->type);
				}
			}
			// Advance pointer by number of bytes for netflow record
			flow_record = (common_record_t *)((pointer_addr_t)flow_record + flow_record->size);	

		}
	} // while

	// flush still remaining records
	if ( cnt ) {
		ret = FlushBuffer(confirm);

		if ( ret < 0 ) {
			perror("Error sending data");
		}

	} // if cnt 

	if (nffile) {
		CloseFile(nffile);
		DisposeFile(nffile);
	}

	close(peer.sockfd);

	return;

} // End of send_data


int main( int argc, char **argv ) {
struct stat stat_buff;
char *rfile, *ffile, *filter, *tstring;
int c, confirm, ffd, ret, blast, netflow_version;
unsigned int delay, count, sockbuff_size;
time_t t_start, t_end;

	rfile = ffile = filter = tstring = NULL;
	t_start = t_end = 0;

	peer.hostname 	= NULL;
	peer.port 		= DEFAULTCISCOPORT;
	peer.mcast		= 0;
	peer.family		= AF_UNSPEC;
	peer.sockfd		= 0;

	delay 	  		= 1;
	count	  		= 0xFFFFFFFF;
	sockbuff_size  	= 0;
	netflow_version	= 5;
	blast			= 0;
	verbose			= 0;
	confirm			= 0;
	while ((c = getopt(argc, argv, "46BhH:i:K:L:p:d:c:b:j:r:f:t:v:VY")) != EOF) {
		switch (c) {
			case 'h':
				usage(argv[0]);
				exit(0);
				break;
			case 'B':
				blast = 1;
				break;
			case 'V':
				printf("%s: Version: %s\n",argv[0], nfdump_version);
				exit(0);
				break;
			case 'Y':
				confirm = 1;
				break;
			case 'H':
			case 'i':	// compatibility with old version
				peer.hostname = strdup(optarg);
				peer.mcast	  = 0;
				break;
			case 'j':	
				if ( peer.hostname == NULL ) {
					peer.hostname = strdup(optarg);
					peer.mcast	  = 1;
				} else {
        			LogError("ERROR, -H(-i) and -j are mutually exclusive!!\n");
        			exit(255);
				}
				break;
			case 'K':
				LogError("*** Anonymization moved! Use nfanon to anonymize flows first!\n");
				exit(255);
				break;
			case 'L':
				if ( !InitLog(argv[0], optarg) )
					exit(255);
				break;
			case 'p':
				peer.port = strdup(optarg);
				break;
			case 'd':
				delay = atoi(optarg);
				break;
			case 'v':
				netflow_version = atoi(optarg);
				if ( netflow_version != 5 && netflow_version != 9 ) {
					LogError("Invalid netflow version: %s. Accept only 5 or 9!\n", optarg);
					exit(255);
				}
				break;
			case 'c':
				count = atoi(optarg);
				break;
			case 'b':
				sockbuff_size = atoi(optarg);
				break;
			case 'f':
				ffile = optarg;
				break;
			case 't':
				tstring = optarg;
				break;
			case 'r':
				rfile = optarg;
				break;
			case '4':
				if ( peer.family == AF_UNSPEC )
					peer.family = AF_INET;
				else {
					LogError("ERROR, Accepts only one protocol IPv4 or IPv6!\n");
					exit(255);
				}
				break;
			case '6':
				if ( peer.family == AF_UNSPEC )
					peer.family = AF_INET6;
				else {
					LogError("ERROR, Accepts only one protocol IPv4 or IPv6!\n");
					exit(255);
				}
				break;
			default:
				usage(argv[0]);
				exit(0);
		}
	}
	if (argc - optind > 1) {
		usage(argv[0]);
		exit(255);
	} else {
		/* user specified a pcap filter */
		filter = argv[optind];
	}

	if ( peer.hostname == NULL )
		peer.hostname 	= DEFAULTHOSTNAME;

	if ( !filter && ffile ) {
		if ( stat(ffile, &stat_buff) ) {
			perror("Can't stat file");
			exit(255);
		}
		filter = (char *)malloc(stat_buff.st_size);
		if ( !filter ) {
			perror("Memory error");
			exit(255);
		}
		ffd = open(ffile, O_RDONLY);
		if ( ffd < 0 ) {
			perror("Can't open file");
			exit(255);
		}
		ret = read(ffd, (void *)filter, stat_buff.st_size);
		if ( ret < 0   ) {
			perror("Error reading file");
			close(ffd);
			exit(255);
		}
		close(ffd);
	}

	if ( !filter )
		filter = "any";

	Engine = CompileFilter(filter);
	if ( !Engine ) 
		exit(254);
	
	if ( peer.mcast )
		peer.sockfd = Multicast_send_socket (peer.hostname, peer.port, peer.family, sockbuff_size, 
											&peer.addr, &peer.addrlen );
	else 
		peer.sockfd = Unicast_send_socket (peer.hostname, peer.port, peer.family, sockbuff_size, 
											&peer.addr, &peer.addrlen );
	if ( peer.sockfd <= 0 ) {
		exit(255);
	}

	if ( blast ) {
		send_blast(delay );
		exit(0);
	}

	extension_map_list = InitExtensionMaps(NEEDS_EXTENSION_LIST);

	SetupInputFileSequence(NULL,rfile, NULL);

	if ( tstring ) {
		if ( !ScanTimeFrame(tstring, &t_start, &t_end) )
			exit(255);
	}

	send_data(rfile, t_start, t_end, count, delay, confirm, netflow_version);

	FreeExtensionMaps(extension_map_list);

	return 0;
}
