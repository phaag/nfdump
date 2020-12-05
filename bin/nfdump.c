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
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "util.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfx.h"
#include "flist.h"
#include "nfnet.h"
#include "bookkeeper.h"
#include "collector.h"
#include "exporter.h"
#include "output_util.h"
#include "output_raw.h"
#include "output_pipe.h"
#include "output_csv.h"
#include "output_json.h"
#include "netflow_v5_v7.h"
#include "netflow_v9.h"
#include "nftree.h"
#include "nfprof.h"
#include "nflowcache.h"
#include "nfstat.h"
#include "nfexport.h"
#include "ipconv.h"

/* hash parameters */
#define NumPrealloc 128000

#define AGGR_SIZE 7

/* Global Variables */
FilterEngine_t	*Engine;

extern char	*FilterFilename;
extern uint32_t loopcnt;

/* Local Variables */
const char *nfdump_version = VERSION;

static uint64_t total_bytes;
static uint32_t recordCount;
static uint32_t skipped_blocks;
static uint32_t	is_anonymized;
static time_t 	t_first_flow, t_last_flow;
static char		Ident[IDENTLEN];


int hash_hit = 0; 
int hash_miss = 0;
int hash_skip = 0;

extension_map_list_t *extension_map_list;

extern exporter_t **exporter_list;
/*
 * Output Formats:
 * User defined output formats can be compiled into nfdump, for easy access
 * The format has the same syntax as describe in nfdump(1) -o fmt:<format>
 *
 * A format description consists of a single line containing arbitrary strings
 * and format specifier as described below:
 *
 * 	%ts		// Start Time - first seen
 * 	%te		// End Time	- last seen
 * 	%td		// Duration
 * 	%pr		// Protocol
 * 	%sa		// Source Address
 * 	%da		// Destination Address
 * 	%sap	// Source Address:Port
 * 	%dap	// Destination Address:Port
 * 	%sp		// Source Port
 * 	%dp		// Destination Port
 *  %nh		// Next-hop IP Address
 *  %nhb	// BGP Next-hop IP Address
 * 	%sas	// Source AS
 * 	%das	// Destination AS
 * 	%in		// Input Interface num
 * 	%out	// Output Interface num
 * 	%pkt	// Packets - default input
 * 	%ipkt	// Input Packets
 * 	%opkt	// Output Packets
 * 	%byt	// Bytes - default input
 * 	%ibyt	// Input Bytes
 * 	%obyt	// Output Bytes
 * 	%fl		// Flows
 * 	%flg	// TCP Flags
 * 	%tos	// Tos - Default src
 * 	%stos	// Src Tos
 * 	%dtos	// Dst Tos
 * 	%dir	// Direction: ingress, egress
 * 	%smk	// Src mask
 * 	%dmk	// Dst mask
 * 	%fwd	// Forwarding Status
 * 	%svln	// Src Vlan
 * 	%dvln	// Dst Vlan
 * 	%ismc	// Input Src Mac Addr
 * 	%odmc	// Output Dst Mac Addr
 * 	%idmc	// Output Src Mac Addr
 * 	%osmc	// Input Dst Mac Addr
 * 	%mpls1	// MPLS label 1
 * 	%mpls2	// MPLS label 2
 * 	%mpls3	// MPLS label 3
 * 	%mpls4	// MPLS label 4
 * 	%mpls5	// MPLS label 5
 * 	%mpls6	// MPLS label 6
 * 	%mpls7	// MPLS label 7
 * 	%mpls8	// MPLS label 8
 * 	%mpls9	// MPLS label 9
 * 	%mpls10	// MPLS label 10
 *
 * 	%bps	// bps - bits per second
 * 	%pps	// pps - packets per second
 * 	%bpp	// bps - Bytes per package
 *
 * The nfdump standard output formats line, long and extended are defined as follows:
 */

#define FORMAT_line "%ts %td %pr %sap -> %dap %pkt %byt %fl"

#define FORMAT_long "%ts %td %pr %sap -> %dap %flg %tos %pkt %byt %fl"

#define FORMAT_extended "%ts %td %pr %sap -> %dap %flg %tos %pkt %byt %pps %bps %bpp %fl"

#define FORMAT_biline "%ts %td %pr %sap <-> %dap %opkt %ipkt %obyt %ibyt %fl"

#define FORMAT_bilong "%ts %td %pr %sap <-> %dap %flg %tos %opkt %ipkt %obyt %ibyt %fl"

#define FORMAT_nsel "%ts %evt %xevt %pr %sap -> %dap %xsap -> %xdap %ibyt %obyt"

#define FORMAT_nel "%ts %nevt %pr %sap -> %dap %nsap -> %ndap"

#ifdef NSEL
#	define DefaultMode "nsel"
#else 
#	define DefaultMode "line"
#endif

/* The appropriate header line is compiled automatically.
 *
 * For each defined output format a v6 long format automatically exists as well e.g.
 * line -> line6, long -> long6, extended -> extended6
 * v6 long formats need more space to print IP addresses, as IPv6 addresses are printed in full length,
 * where as in standard output format IPv6 addresses are condensed for better readability.
 * 
 * Define your own output format and compile it into nfdumnp:
 * 1. Define your output format string.
 * 2. Test the format using standard syntax -o "fmt:<your format>"
 * 3. Create a #define statement for your output format, similar than the standard output formats above.
 * 4. Add another line into the printmap[] struct below BEFORE the last NULL line for you format:
 *    { "formatname", format_special, FORMAT_definition, NULL },
 *   The first parameter is the name of your format as recognized on the command line as -o <formatname>
 *   The second parameter is always 'format_special' - the printing function.
 *   The third parameter is your format definition as defined in #define.
 *   The forth parameter is always NULL for user defined formats.
 * 5. Recompile nfdump
 */

static void flow_record_to_null(void *record, char ** s, int tag);

// Assign print functions for all output options -o
// Teminated with a NULL record
printmap_t printmap[] = {
	{ "raw",		flow_record_to_raw,  		raw_prolog, raw_epilog, NULL },
	{ "line", 		format_special,      		text_prolog, text_epilog, FORMAT_line },
	{ "long", 		format_special, 			text_prolog, text_epilog, FORMAT_long },
	{ "extended",	format_special, 			text_prolog, text_epilog, FORMAT_extended },
	{ "biline", 	format_special,      		text_prolog, text_epilog, FORMAT_biline	},
	{ "bilong", 	format_special,      		text_prolog, text_epilog, FORMAT_bilong	},
	{ "pipe", 		flow_record_to_pipe,      	pipe_prolog, pipe_epilog, NULL },
	{ "json", 		flow_record_to_json,      	json_prolog, json_epilog, NULL },
	{ "csv", 		flow_record_to_csv,      	csv_prolog,  csv_epilog,  NULL },
	{ "null", 		flow_record_to_null,      	text_prolog, text_epilog, NULL },
#ifdef NSEL
	{ "nsel",		format_special, 			text_prolog, text_epilog, FORMAT_nsel },
	{ "nel",		format_special, 			text_prolog, text_epilog, FORMAT_nel },
#endif

// add your formats here

// This is always the last line
	{ NULL, NULL, NULL, NULL, "" }
};

// For automatic output format generation in case of custom aggregation
#define AggrPrependFmt	"%ts %td "
#define AggrAppendFmt	"%pkt %byt %bps %bpp %fl"

// compare at most 16 chars
#define MAXMODELEN	16	

/* Function Prototypes */
static void usage(char *name);

static void PrintSummary(stat_record_t *stat_record, outputParams_t *outputParams);

static stat_record_t process_data(char *wfile, int element_stat, int flow_stat, int sort_flows,
	printer_t print_record, time_t twin_start, time_t twin_end, 
	uint64_t limitRecords, outputParams_t *outputParams, int compress);

/* Functions */

#include "nfdump_inline.c"
#include "nffile_inline.c"

static void usage(char *name) {
		printf("usage %s [options] [\"filter\"]\n"
					"-h\t\tthis text you see right here\n"
					"-V\t\tPrint version and exit.\n"
					"-a\t\tAggregate netflow data.\n"
					"-A <expr>[/net]\tHow to aggregate: ',' sep list of tags see nfdump(1)\n"
					"\t\tor subnet aggregation: srcip4/24, srcip6/64.\n"
					"-b\t\tAggregate netflow records as bidirectional flows.\n"
					"-B\t\tAggregate netflow records as bidirectional flows - Guess direction.\n"
					"-r <file>\tread input from file\n"
					"-w <file>\twrite output to file\n"
					"-f\t\tread netflow filter from file\n"
					"-n\t\tDefine number of top N for stat or sorted output.\n"
					"-c\t\tLimit number of matching records\n"
					"-D <dns>\tUse nameserver <dns> for host lookup.\n"
					"-N\t\tPrint plain numbers\n"
					"-s <expr>[/<order>]\tGenerate statistics for <expr> any valid record element.\n"
					"\t\tand ordered by <order>: packets, bytes, flows, bps pps and bpp.\n"
					"-q\t\tQuiet: Do not print the header and bottom stat lines.\n"
					"-i <ident>\tChange Ident to <ident> in file given by -r.\n"
					"-J <num>\tModify file compression: 0: uncompressed - 1: LZO - 2: BZ2 - 3: LZ4 compressed.\n"
					"-z\t\tLZO compress flows in output file. Used in combination with -w.\n"
					"-y\t\tLZ4 compress flows in output file. Used in combination with -w.\n"
					"-j\t\tBZ2 compress flows in output file. Used in combination with -w.\n"
					"-l <expr>\tSet limit on packets for line and packed output format.\n"
					"\t\tkey: 32 character string or 64 digit hex string starting with 0x.\n"
					"-L <expr>\tSet limit on bytes for line and packed output format.\n"
					"-I \t\tPrint netflow summary statistics info from file, specified by -r.\n"
					"-M <expr>\tRead input from multiple directories.\n"
					"\t\t/dir/dir1:dir2:dir3 Read the same files from '/dir/dir1' '/dir/dir2' and '/dir/dir3'.\n"
					"\t\trequests either -r filename or -R firstfile:lastfile without pathnames\n"
					"-m\t\tdeprecated\n"
					"-O <order> Sort order for aggregated flows - tstart, tend, flows, packets bps pps bbp etc.\n"
					"-R <expr>\tRead input from sequence of files.\n"
					"\t\t/any/dir  Read all files in that directory.\n"
					"\t\t/dir/file Read all files beginning with 'file'.\n"
					"\t\t/dir/file1:file2: Read all files from 'file1' to file2.\n"
					"-o <mode>\tUse <mode> to print out netflow records:\n"
					"\t\t raw      Raw record dump.\n"
					"\t\t line     Standard output line format.\n"
					"\t\t long     Standard output line format with additional fields.\n"
					"\t\t extended Even more information.\n"
					"\t\t csv      ',' separated, machine parseable output format.\n"
					"\t\t json     json output format.\n"
					"\t\t pipe     '|' separated legacy machine parseable output format.\n"
					"\t\t null     no flow records, but statistics output.\n"
					"\t\t\tmode may be extended by '6' for full IPv6 listing. e.g.long6, extended6.\n"
					"-E <file>\tPrint exporter and sampling info for collected flows.\n"
					"-v <file>\tverify netflow data file. Print version and blocks.\n"
					"-x <file>\tverify extension records in netflow data file.\n"
					"-X\t\tDump Filtertable and exit (debug option).\n"
					"-Z\t\tCheck filter syntax and exit.\n"
					"-t <time>\ttime window for filtering packets\n"
					"\t\tyyyy/MM/dd.hh:mm:ss[-yyyy/MM/dd.hh:mm:ss]\n", name);
} /* usage */

static void flow_record_to_null(void *record, char ** s, int tag) {
	// empty - do not list any flows
} // End of flow_record_to_null

static void PrintSummary(stat_record_t *stat_record, outputParams_t *outputParams) {
static double	duration;
uint64_t	bps, pps, bpp;
char 		byte_str[NUMBER_STRING_SIZE], packet_str[NUMBER_STRING_SIZE];
char 		bps_str[NUMBER_STRING_SIZE], pps_str[NUMBER_STRING_SIZE], bpp_str[NUMBER_STRING_SIZE];

	bps = pps = bpp = 0;
	if ( stat_record->last_seen ) {
		duration = stat_record->last_seen - stat_record->first_seen;
		duration += ((double)stat_record->msec_last - (double)stat_record->msec_first) / 1000.0;
	} else {
		// no flows to report
		duration = 0;
	}
	if ( duration > 0 && stat_record->last_seen > 0 ) {
		bps = ( stat_record->numbytes << 3 ) / duration;	// bits per second. ( >> 3 ) -> * 8 to convert octets into bits
		pps = stat_record->numpackets / duration;			// packets per second
		bpp = stat_record->numpackets ? stat_record->numbytes / stat_record->numpackets : 0;    // Bytes per Packet
	}
	if ( outputParams->modeCsv ) {
		printf("Summary\n");
		printf("flows,bytes,packets,avg_bps,avg_pps,avg_bpp\n");
		printf("%llu,%llu,%llu,%llu,%llu,%llu\n",
			(long long unsigned)stat_record->numflows, (long long unsigned)stat_record->numbytes, 
			(long long unsigned)stat_record->numpackets, (long long unsigned)bps, 
			(long long unsigned)pps, (long long unsigned)bpp );
	} else {
		format_number(stat_record->numbytes, byte_str, outputParams->printPlain, VAR_LENGTH);
		format_number(stat_record->numpackets, packet_str, outputParams->printPlain, VAR_LENGTH);
		format_number(bps, bps_str, outputParams->printPlain, VAR_LENGTH);
		format_number(pps, pps_str, outputParams->printPlain, VAR_LENGTH);
		format_number(bpp, bpp_str, outputParams->printPlain, VAR_LENGTH);
		printf("Summary: total flows: %llu, total bytes: %s, total packets: %s, avg bps: %s, avg pps: %s, avg bpp: %s\n",
		(unsigned long long)stat_record->numflows, byte_str, packet_str, bps_str, pps_str, bpp_str );
	}

} // End of PrintSummary

stat_record_t process_data(char *wfile, int element_stat, int flow_stat, int sort_flows,
	printer_t print_record, time_t twin_start, time_t twin_end, 
	uint64_t limitRecords, outputParams_t *outputParams, int compress) {
common_record_t 	*flow_record, *record_ptr;
master_record_t		*master_record;
nffile_t			*nffile_w, *nffile_r;
stat_record_t 		stat_record;
int 				done, write_file;

	// time window of all matched flows
	memset((void *)&stat_record, 0, sizeof(stat_record_t));
	stat_record.first_seen = 0x7fffffff;
	stat_record.msec_first = 999;

	// Do the logic first

	// do not print flows when doing any stats are sorting
	if ( sort_flows || flow_stat || element_stat ) {
		print_record = NULL;
	}

	// do not write flows to file, when doing any stats
	// -w may apply for flow_stats later
	write_file = !(sort_flows || flow_stat || element_stat) && wfile;
	nffile_r = NULL;
	nffile_w = NULL;

	// Get the first file handle
	nffile_r = GetNextFile(NULL, twin_start, twin_end);
	if ( !nffile_r ) {
		LogError("GetNextFile() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return stat_record;
	}
	if ( nffile_r == EMPTY_LIST ) {
		LogError("Empty file list. No files to process\n");
		return stat_record;
	}

	// preset time window of all processed flows to the stat record in first flow file
	t_first_flow = nffile_r->stat_record->first_seen;
	t_last_flow  = nffile_r->stat_record->last_seen;

	// store infos away for later use
	// although multiple files may be processed, it is assumed that all 
	// have the same settings
	is_anonymized = IP_ANONYMIZED(nffile_r);
	strncpy(Ident, nffile_r->file_header->ident, IDENTLEN);
	Ident[IDENTLEN-1] = '\0';

	// prepare output file if requested
	if ( write_file ) {
		nffile_w = OpenNewFile(wfile, NULL, compress, IP_ANONYMIZED(nffile_r), NULL );
		if ( !nffile_w ) {
			if ( nffile_r ) {
				CloseFile(nffile_r);
				DisposeFile(nffile_r);
			}
			return stat_record;
		}
	}

	// setup Filter Engine to point to master_record, as any record read from file
	// is expanded into this record
	// Engine->nfrecord = (uint64_t *)master_record;

	done = 0;
	while ( !done ) {
	int i, ret;
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
				nffile_t *next = GetNextFile(nffile_r, twin_start, twin_end);
				if ( next == EMPTY_LIST ) {
					done = 1;
				} else if ( next == NULL ) {
					done = 1;
					LogError("Unexpected end of file list\n");
				} else {
					// Update global time span window
					if ( next->stat_record->first_seen < t_first_flow )
						t_first_flow = next->stat_record->first_seen;
					if ( next->stat_record->last_seen > t_last_flow ) 
						t_last_flow = next->stat_record->last_seen;
					// continue with next file
				}
				continue;

				} break; // not really needed
			default:
				// successfully read block
				total_bytes += ret;
		}

		if ( nffile_r->block_header->id != DATA_BLOCK_TYPE_2 ) {
			if ( nffile_r->block_header->id == DATA_BLOCK_TYPE_1 ) {
				LogError("nfdump 1.5.x block type 1 no longer supported. Skip block.\n");
			} else {
				LogError("Can't process block type %u. Skip block.\n", nffile_r->block_header->id);
			}
			skipped_blocks++;
			continue;
		}

		uint32_t sumSize = 0;
		record_ptr = nffile_r->buff_ptr;
		for ( i=0; i < nffile_r->block_header->NumRecords && !done; i++ ) {
			flow_record = record_ptr;
			if ( (sumSize + record_ptr->size) > ret || (record_ptr->size < sizeof(record_header_t)) ) {
				LogError("Corrupt data file. Inconsistent block size in %s line %d\n", __FILE__, __LINE__);
				exit(255);
			}
			sumSize += record_ptr->size;
			switch ( record_ptr->type ) {
				case CommonRecordV0Type: 
					LogError("Old common v0 records no longer supported - skipped");
					break;
				case CommonRecordType: {
					int match;
					uint32_t map_id;
					exporter_t *exp_info;

					// valid flow_record converted if needed
					map_id = flow_record->ext_map;
					exp_info = exporter_list[flow_record->exporter_sysid];

					if ( map_id >= MAX_EXTENSION_MAPS ) {
						LogError("Corrupt data file. Extension map id %u too big.\n", flow_record->ext_map);
						exit(255);
					}
					if ( extension_map_list->slot[map_id] == NULL ) {
						LogError("Corrupt data file. Missing extension map %u. Skip record.\n", flow_record->ext_map);
						record_ptr = (common_record_t *)((pointer_addr_t)record_ptr + record_ptr->size);	
						continue;
					} 

					master_record = &(extension_map_list->slot[map_id]->master_record);
					Engine->nfrecord = (uint64_t *)master_record;
					ExpandRecord_v2( flow_record, extension_map_list->slot[map_id], 
						exp_info ? &(exp_info->info) : NULL, master_record);

					// Time based filter
					// if no time filter is given, the result is always true
					match  = twin_start && (master_record->first < twin_start || master_record->last > twin_end) ? 0 : 1;
					match &= limitRecords ? stat_record.numflows < limitRecords : 1;

					// filter netflow record with user supplied filter
					if ( match ) 
						match = (*Engine->FilterEngine)(Engine);
	
					if ( match == 0 ) { // record failed to pass all filters
						// increment pointer by number of bytes for netflow record
						record_ptr = (common_record_t *)((pointer_addr_t)record_ptr + record_ptr->size);	
						// go to next record
						continue;
					}
					recordCount++;

					// Records passed filter -> continue record processing
					// Update statistics
					master_record->label = Engine->label;
#ifdef DEVEL
					if ( Engine->label )
						printf("Flow has label: %s\n", Engine->label);
#endif
					UpdateStat(&stat_record, master_record);

					// update number of flows matching a given map
					extension_map_list->slot[map_id]->ref_count++;
	
					if ( flow_stat ) {
						AddFlow(flow_record, master_record, extension_map_list->slot[map_id]);
						if ( element_stat ) {
							AddStat(flow_record, master_record);
						} 
					} else if ( element_stat ) {
						AddStat(flow_record, master_record);
					} else if ( sort_flows ) {
						InsertFlow(flow_record, master_record, extension_map_list->slot[map_id]);
					} else {
						if ( write_file ) {
							AppendToBuffer(nffile_w, (void *)flow_record, flow_record->size);
						} else if ( print_record ) {
							char *string;
							// if we need to print out this record
							print_record(master_record, &string, outputParams->doTag);
							if ( string ) {
								printf("%s\n", string);
							}
						} else { 
							// mutually exclusive conditions should prevent executing this code
							// this is buggy!
							printf("Bug! - this code should never get executed in file %s line %d\n", __FILE__, __LINE__);
						}
					} // sort_flows - else
					} break; 
				case ExtensionMapType: {
					extension_map_t *map = (extension_map_t *)record_ptr;
	
					int ret = Insert_Extension_Map(extension_map_list, map);
					switch (ret) {
						case 0:
							break; // map already known and flushed
						case 1:
							if ( write_file ) 
								AppendToBuffer(nffile_w, (void *)map, map->size);
							break;
						default:
							LogError("Corrupt data file. Unable to decode at %s line %d\n", __FILE__, __LINE__);
							exit(255);
					}
					} break;
				case LegacyRecordType1:
				case LegacyRecordType2:
						// Silently skip legacy records
					break;
				case ExporterInfoRecordType: {
					int ret = AddExporterInfo((exporter_info_record_t *)record_ptr);
					if ( ret != 0 ) {
						if ( write_file && ret == 1 ) 
							AppendToBuffer(nffile_w, (void *)record_ptr, record_ptr->size);
					} else {
						LogError("Failed to add Exporter Record\n");
					}
					} break;
				case ExporterStatRecordType:
					AddExporterStat((exporter_stats_record_t *)record_ptr);
					break;
				case SamplerInfoRecordype: {
					int ret = AddSamplerInfo((sampler_info_record_t *)record_ptr);
					if ( ret != 0 ) {
						if ( write_file && ret == 1 ) 
							AppendToBuffer(nffile_w, (void *)flow_record, flow_record->size);
					} else {
						LogError("Failed to add Sampler Record\n");
					}
					} break;
				default: {
					LogError("Skip unknown record type %i\n", record_ptr->type);
				}
			}

			// Advance pointer by number of bytes for netflow record
			record_ptr = (common_record_t *)((pointer_addr_t)record_ptr + record_ptr->size);	

			// check if we are done, due to -c option 
			if ( limitRecords ) 
				done = recordCount >= limitRecords;

		} // for all records


	} // while

	CloseFile(nffile_r);

	// flush output file
	if ( write_file ) {
		// flush current buffer to disc
		if ( nffile_w->block_header->NumRecords ) {
			if ( WriteBlock(nffile_w) <= 0 ) {
				LogError("Failed to write output buffer to disk: '%s'" , strerror(errno));
			} 
		}

		/* Stat info */
		if ( write_file ) {
			/* Copy stat info and close file */
			memcpy((void *)nffile_w->stat_record, (void *)&stat_record, sizeof(stat_record_t));
			CloseUpdateFile(nffile_w, nffile_r->file_header->ident );
			nffile_w = DisposeFile(nffile_w);
		} // else stdout
	}	 

	PackExtensionMapList(extension_map_list);

	DisposeFile(nffile_r);
	return stat_record;

} // End of process_data


int main( int argc, char **argv ) {
struct stat stat_buff;
stat_record_t	sum_stat;
outputParams_t *outputParams;
printer_t	   print_record;
func_prolog_t  print_prolog;
func_epilog_t  print_epilog;
nfprof_t 	profile_data;
char 		*rfile, *Rfile, *Mdirs, *wfile, *ffile, *filter, *tstring, *stat_type;
char		*byte_limit_string, *packet_limit_string, *print_format;
char		*print_order, *query_file, *nameserver, *aggr_fmt;
int 		c, ffd, ret, element_stat, fdump;
int 		i, flow_stat, aggregate, aggregate_mask, bidir;
int 		print_stat, syntax_only, date_sorted, compress;
int			GuessDir, ModifyCompress;
time_t 		t_start, t_end;
uint32_t	limitRecords;
char 		Ident[IDENTLEN];

	rfile = Rfile = Mdirs = wfile = ffile = filter = tstring = stat_type = NULL;
	byte_limit_string = packet_limit_string = NULL;
	fdump = aggregate = 0;
	aggregate_mask	= 0;
	bidir			= 0;
	t_start = t_end = 0;
	syntax_only	    = 0;
	flow_stat       = 0;
	print_stat      = 0;
	element_stat  	= 0;
	limitRecords	= 0;
	date_sorted		= 0;
	total_bytes		= 0;
	recordCount		= 0;
	skipped_blocks	= 0;
	compress		= NOT_COMPRESSED;
	is_anonymized	= 0;
	GuessDir		= 0;
	nameserver		= NULL;

	print_format    = NULL;
	print_record  	= NULL;
	print_prolog	= NULL;
	print_epilog	= NULL;
	print_order  	= NULL;
	query_file		= NULL;
	ModifyCompress	= -1;
	aggr_fmt		= NULL;

	outputParams	= calloc(1, sizeof(outputParams_t));
	if ( !outputParams ) {
		LogError("calloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(255);
	}
	outputParams->topN = -1;

	Ident[0] = '\0';

	while ((c = getopt(argc, argv, "6aA:Bbc:D:E:s:hn:i:jf:qyzr:v:w:J:K:M:NImO:R:XZt:TVv:x:l:L:o:")) != EOF) {
		switch (c) {
			case 'h':
				usage(argv[0]);
				exit(0);
				break;
			case 'a':
				aggregate = 1;
				break;
			case 'A':
				if ( !ParseAggregateMask(optarg, &aggr_fmt ) ) {
					exit(255);
				}
				aggregate_mask = 1;
				break;
			case 'B':
				GuessDir = 1;
			case 'b':
				if ( !SetBidirAggregation() ) {
					exit(255);
				}
				bidir	  = 1;
				// implies
				aggregate = 1;
				break;
			case 'D':
				nameserver = optarg;
				if ( !set_nameserver(nameserver) ) {
					exit(255);
				}
				break;
			case 'E':
				query_file = optarg;
				if ( !InitExporterList() ) {
					exit(255);
				}
				PrintExporters(query_file);
				exit(0);
				break;
			case 'X':
				fdump = 1;
				break;
			case 'Z':
				syntax_only = 1;
				break;
			case 'q':
				outputParams->quiet = true;
				break;
			case 'j':
				if ( compress ) {
					LogError("Use one compression: -z for LZO, -j for BZ2 or -y for LZ4 compression\n");
					exit(255);
				}
				compress = BZ2_COMPRESSED;
				break;
			case 'y':
				if ( compress ) {
					LogError("Use one compression: -z for LZO, -j for BZ2 or -y for LZ4 compression\n");
					exit(255);
				}
				compress = LZ4_COMPRESSED;
				break;
			case 'z':
				if ( compress ) {
					LogError("Use one compression: -z for LZO, -j for BZ2 or -y for LZ4 compression\n");
					exit(255);
				}
				compress = LZO_COMPRESSED;
				break;
			case 'c':	
				limitRecords = atoi(optarg);
				if ( !limitRecords ) {
					LogError("Option -c needs a number > 0\n");
					exit(255);
				}
				break;
			case 's':
				stat_type = optarg;
                if ( !SetStat(stat_type, &element_stat, &flow_stat) ) {
                    exit(255);
                } 
				break;
			case 'V': {
				char *e1, *e2;
				e1 = "";
				e2 = "";
#ifdef NSEL
				e1 = "NSEL-NEL";
#endif
				printf("%s: Version: %s%s%s\n",argv[0], e1, e2, nfdump_version);
				exit(0);
				} break;
			case 'l':
				packet_limit_string = optarg;
				break;
			case 'K':
				LogError("*** Anonymisation moved! Use nfanon to anonymise flows!\n");
				exit(255);
				break;
			case 'L':
				byte_limit_string = optarg;
				break;
			case 'N':
				outputParams->printPlain = 1;
				break;
			case 'f':
				ffile = optarg;
				break;
			case 't':
				tstring = optarg;
				break;
			case 'r':
				rfile = optarg;
				if ( strcmp(rfile, "-") == 0 )
					rfile = NULL;
				break;
			case 'm':
				print_order = "tstart";
				Parse_PrintOrder(print_order);
				date_sorted = 1;
				LogError("Option -m deprecated. Use '-O tstart' instead\n");
				break;
			case 'M':
				Mdirs = optarg;
				break;
			case 'I':
				print_stat++;
				break;
			case 'o':	// output mode
				print_format = optarg;
				// limit input chars
				if ( strlen(print_format) > 512 ) {
					LogError("Length of ouput format string too big - > 512\n");
					exit(255);
				}
				break;
			case 'O': {	// stat order by
				int ret;
				print_order = optarg;
				ret = Parse_PrintOrder(print_order);
				if ( ret < 0 ) {
					LogError("Unknown print order '%s'\n", print_order);
					exit(255);
				}
				date_sorted = ret == 17;		// index into order_mode
				} break;
			case 'R':
				Rfile = optarg;
				break;
			case 'w':
				wfile = optarg;
				break;
			case 'n':
				outputParams->topN = atoi(optarg);
				if ( outputParams->topN < 0 ) {
					LogError("TopN number %i out of range\n", outputParams->topN);
					exit(255);
				}
				break;
			case 'T':
				outputParams->doTag = true;
				break;
			case 'i':
				strncpy(Ident, optarg, IDENTLEN);
				Ident[IDENTLEN - 1] = 0;
				if ( strchr(Ident, ' ') ) {
					LogError("Ident must not contain spaces\n");
					exit(255);
				}
				break;
			case 'J':
				ModifyCompress = atoi(optarg);
				if ( (ModifyCompress < 0) || (ModifyCompress > 3) ) {
					LogError("Expected -J <num>, 0: uncompressed, 1: LZO, 2: BZ2, 3: LZ4 compressed.\n");
					exit(255);
				}
				break;
			case 'x':
				query_file = optarg;
				InitExtensionMaps(NO_EXTENSION_LIST);
				DumpExMaps(query_file);
				exit(0);
				break;
			case 'v':
				query_file = optarg;
				QueryFile(query_file);
				exit(0);
				break;
			case '6':	// print long IPv6 addr
				Setv6Mode(1);
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
		FilterFilename = NULL;
	}
	
	// Modify compression
	if ( ModifyCompress >= 0 ) {
		if ( !rfile && !Rfile ) {
			LogError("Expected -r <file> or -R <dir> to change compression\n");
			exit(255);
		}
		ModifyCompressFile(rfile, Rfile, ModifyCompress);
		exit(0);
	}

	// Change Ident only
	if ( rfile && strlen(Ident) > 0 ) {
		ChangeIdent(rfile, Ident);
		exit(0);
	}

	if ( outputParams->topN < 0 ) {
		if ( flow_stat || element_stat ) {
			outputParams->topN = 10;
		} else {
			outputParams->topN = 0;
		}
	}

	if ( (element_stat && !flow_stat) && aggregate_mask ) {
		LogError("Warning: Aggregation ignored for element statistics\n");
		aggregate_mask = 0;
	}

	if ( !flow_stat && aggregate_mask ) {
		aggregate = 1;
	}

	if ( rfile && Rfile ) {
		LogError("-r and -R are mutually exclusive. Please specify either -r or -R\n");
		exit(255);
	}
	if ( Mdirs && !(rfile || Rfile) ) {
		LogError("-M needs either -r or -R to specify the file or file list. Add '-R .' for all files in the directories.\n");
		exit(255);
	}

	extension_map_list = InitExtensionMaps(NEEDS_EXTENSION_LIST);
	if ( !InitExporterList() ) {
		exit(255);
	}

	SetupInputFileSequence(Mdirs, rfile, Rfile);

	if ( print_stat ) {
		nffile_t *nffile;
		if ( !rfile && !Rfile && !Mdirs) {
			LogError("Expect data file(s).\n");
			exit(255);
		}

		memset((void *)&sum_stat, 0, sizeof(stat_record_t));
		sum_stat.first_seen = 0x7fffffff;
		sum_stat.msec_first = 999;
		nffile = GetNextFile(NULL, 0, 0);
		if ( !nffile ) {
			LogError("Error open file: %s\n", strerror(errno));
			exit(250);
		}
		while ( nffile && nffile != EMPTY_LIST ) {
			SumStatRecords(&sum_stat, nffile->stat_record);
			nffile = GetNextFile(nffile, 0, 0);
		}
		PrintStat(&sum_stat);
		exit(0);
	}

	// handle print mode
	if ( !print_format ) {
		// automatically select an appropriate output format for custom aggregation
		// aggr_fmt is compiled by ParseAggregateMask
		if ( aggr_fmt ) {
			int len = strlen(AggrPrependFmt) + strlen(aggr_fmt) + strlen(AggrAppendFmt) + 7;	// +7 for 'fmt:', 2 spaces and '\0'
			print_format = malloc(len);
			if ( !print_format ) {
				LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
				exit(255);
			}
			snprintf(print_format, len, "fmt:%s %s %s",AggrPrependFmt, aggr_fmt, AggrAppendFmt );
			print_format[len-1] = '\0';
		} else if ( bidir ) {
			print_format = "biline";
		} else
			print_format = DefaultMode;
	}

	if ( strncasecmp(print_format, "fmt:", 4) == 0 ) {
		// special user defined output format
		char *format = &print_format[4];
		if ( strlen(format) ) {
			if ( !ParseOutputFormat(format, outputParams->printPlain, printmap) )
				exit(255);
			print_record  = format_special;
			print_prolog  = text_prolog;
		} else {
			LogError("Missing format description for user defined output format!\n");
			exit(255);
		}
	} else {
		// predefined output format

		// Check for long_v6 mode
		i = strlen(print_format);
		if ( i > 2 ) {
			if ( print_format[i-1] == '6' ) {
				Setv6Mode(1);
				print_format[i-1] = '\0';
			} else 
				Setv6Mode(0);
		}

		i = 0;
		while ( printmap[i].printmode ) {
			if ( strncasecmp(print_format, printmap[i].printmode, MAXMODELEN) == 0 ) {
				if ( printmap[i].Format ) {
					if ( !ParseOutputFormat(printmap[i].Format, outputParams->printPlain, printmap) )
						exit(255);
					// predefined custom format
					print_record  = printmap[i].func_record;
					print_prolog  = printmap[i].func_prolog;
					print_epilog  = printmap[i].func_epilog;
				} else {
					// To support the pipe output format for element stats - check for pipe, and remember this
					if ( strncasecmp(print_format, "pipe", MAXMODELEN) == 0 ) {
						outputParams->modePipe = true;
					}
					if ( strncasecmp(print_format, "csv", MAXMODELEN) == 0 ) {
						outputParams->modeCsv = true;
					}
					if ( strncasecmp(print_format, "json", MAXMODELEN) == 0 ) {
						outputParams->modeJson = true;
					}
					// predefined static format
					print_record  = printmap[i].func_record;
					print_prolog  = printmap[i].func_prolog;
					print_epilog  = printmap[i].func_epilog;
				}
				break;
			}
			i++;
		}
	}

	if ( !print_record ) {
		LogError("Unknown output mode '%s'\n", print_format);
		exit(255);
	}

	if ( aggregate && (flow_stat || element_stat) ) {
		aggregate = 0;
		LogError("Command line switch -s overwrites -a\n");
	}

	if ( !filter && ffile ) {
		if ( stat(ffile, &stat_buff) ) {
			LogError("Can't stat filter file '%s': %s\n", ffile, strerror(errno));
			exit(255);
		}
		filter = (char *)malloc(stat_buff.st_size+1);
		if ( !filter ) {
			LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			exit(255);
		}
		ffd = open(ffile, O_RDONLY);
		if ( ffd < 0 ) {
			LogError("Can't open filter file '%s': %s\n", ffile, strerror(errno));
			exit(255);
		}
		ret = read(ffd, (void *)filter, stat_buff.st_size);
		if ( ret < 0   ) {
			perror("Error reading filter file");
			close(ffd);
			exit(255);
		}
		total_bytes += ret;
		filter[stat_buff.st_size] = 0;
		close(ffd);

		FilterFilename = ffile;
	}

	// if no filter is given, set the default ip filter which passes through every flow
	if ( !filter  || strlen(filter) == 0 ) 
		filter = "any";

	Engine = CompileFilter(filter);
	if ( !Engine ) 
		exit(254);

	if ( fdump ) {
		printf("StartNode: %i Engine: %s\n", Engine->StartNode, Engine->Extended ? "Extended" : "Fast");
		DumpEngine(Engine);
		exit(0);
	}

	if ( syntax_only )
		exit(0);

	if ( print_order && flow_stat ) {
		printf("-s record and -O (-m) are mutually exclusive options\n");
		exit(255);
	}

	if ((aggregate || flow_stat || print_order)  && !Init_FlowTable() )
			exit(250);

	if (element_stat && !Init_StatTable(HashBits, NumPrealloc) )
			exit(250);

	SetLimits(element_stat || aggregate || flow_stat, packet_limit_string, byte_limit_string);

	if ( tstring ) {
		if ( !ScanTimeFrame(tstring, &t_start, &t_end) )
			exit(255);
	}


	if ( !(flow_stat || element_stat || wfile || outputParams->quiet ) && print_prolog ) {
		print_prolog();
	}

	nfprof_start(&profile_data);
	sum_stat = process_data(wfile, element_stat, aggregate || flow_stat, print_order != NULL,
						print_record, t_start, t_end, 
						limitRecords, outputParams, compress);
	nfprof_end(&profile_data, recordCount);
	
	if ( total_bytes == 0 ) {
		printf("No matched flows\n");
		exit(0);
	}

	if (aggregate || print_order) {
		if ( wfile ) {
			nffile_t *nffile = OpenNewFile(wfile, NULL, compress, is_anonymized, NULL);
			if ( !nffile ) 
				exit(255);
			if ( ExportFlowTable(nffile, aggregate, bidir, GuessDir, date_sorted, extension_map_list) ) {
				CloseUpdateFile(nffile, Ident );	
			} else {
				CloseFile(nffile);
				unlink(wfile);
			}
			DisposeFile(nffile);
		} else {
			PrintFlowTable(print_record, outputParams, GuessDir, extension_map_list);
		}
	}

	if (flow_stat) {
		PrintFlowStat(print_prolog, print_record, outputParams, extension_map_list);
#ifdef DEVEL
		printf("Loopcnt: %u\n", loopcnt);
#endif
	} 

	if (element_stat) {
		PrintElementStat(&sum_stat, outputParams, print_record);
	} 

	if ( print_epilog ) {
		print_epilog();
	}
	if ( !outputParams->quiet && !outputParams->modeJson ) {
		if ( outputParams->modeCsv ) {
			PrintSummary(&sum_stat, outputParams);
		} else if ( !wfile ) {
			if (is_anonymized)
				printf("IP addresses anonymised\n");
			PrintSummary(&sum_stat, outputParams);
			if ( t_last_flow == 0 ) {
				// in case of a pre 1.6.6 collected and empty flow file
 				printf("Time window: <unknown>\n");
			} else {
 				printf("Time window: %s\n", TimeString(t_first_flow, t_last_flow));
			}
			printf("Total flows processed: %u, Blocks skipped: %u, Bytes read: %llu\n", 
				recordCount, skipped_blocks, (unsigned long long)total_bytes);
			nfprof_print(&profile_data, stdout);
		}
	}

	Dispose_FlowTable();
	Dispose_StatTable();
	FreeExtensionMaps(extension_map_list);

#ifdef DEVEL
	if ( hash_hit || hash_miss )
		printf("Hash hit: %i, miss: %i, skip: %i, ratio: %5.3f\n", hash_hit, hash_miss, hash_skip, (float)hash_hit/((float)(hash_hit+hash_miss)));
#endif

	return 0;
}
