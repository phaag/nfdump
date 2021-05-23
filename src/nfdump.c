/*
 *  Copyright (c) 2009-2021, Peter Haag
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
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "util.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfx.h"
#include "nfxV3.h"
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
#include "maxmind.h"
#include "nbar.h"
#include "nflowcache.h"
#include "nfstat.h"
#include "ipconv.h"

extern char	*FilterFilename;

/* Local Variables */
static FilterEngine_t	*Engine;
const char *nfdump_version = VERSION;

static uint64_t total_bytes = 0;
static uint32_t processed = 0;
static uint32_t passed	  = 0;
static uint32_t HasGeoDB  = 0;
static uint32_t skipped_blocks;
static time_t 	t_first_flow, t_last_flow;

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

#define FORMAT_gline "%ts %td %pr %gsap -> %gdap %pkt %byt %fl"

#define FORMAT_long "%ts %td %pr %sap -> %dap %flg %tos %pkt %byt %fl"

#define FORMAT_glong "%ts %td %pr %gsap -> %gdap %flg %tos %pkt %byt %fl"

#define FORMAT_extended "%ts %td %pr %sap -> %dap %flg %tos %pkt %byt %pps %bps %bpp %fl"

#define FORMAT_biline "%ts %td %pr %sap <-> %dap %opkt %ipkt %obyt %ibyt %fl"

#define FORMAT_bilong "%ts %td %pr %sap <-> %dap %flg %tos %opkt %ipkt %obyt %ibyt %fl"

#define FORMAT_nsel "%tevt %evt %xevt %pr %sap -> %dap %xsap -> %xdap %ibyt %obyt"

#define FORMAT_nel "%tevt %nevt %pr %sap -> %dap %nsap -> %ndap"

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

static void flow_record_to_null(FILE *stream, void *record, int tag);

// Assign print functions for all output options -o
// Teminated with a NULL record
printmap_t printmap[] = {
	{ "raw",		flow_record_to_raw,  		raw_prolog, raw_epilog, NULL },
	{ "line", 		format_special,      		text_prolog, text_epilog, FORMAT_line },
	{ "gline", 		format_special,      		text_prolog, text_epilog, FORMAT_gline },
	{ "long", 		format_special, 			text_prolog, text_epilog, FORMAT_long },
	{ "glong", 		format_special, 			text_prolog, text_epilog, FORMAT_glong },
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
	printer_t print_record, timeWindow_t *timeWindow,
	uint64_t limitRecords, outputParams_t *outputParams, int compress);

/* Functions */

#include "nfdump_inline.c"
#include "nffile_inline.c"
#include "nffile_compat.c"

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

static void flow_record_to_null(FILE *stream, void *record, int tag) {
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
	if ( outputParams->mode == MODE_CSV ) {
		printf("Summary\n");
		printf("flows,bytes,packets,avg_bps,avg_pps,avg_bpp\n");
		printf("%llu,%llu,%llu,%llu,%llu,%llu\n",
			(long long unsigned)stat_record->numflows, (long long unsigned)stat_record->numbytes, 
			(long long unsigned)stat_record->numpackets, (long long unsigned)bps, 
			(long long unsigned)pps, (long long unsigned)bpp );
	}  else {
		format_number(stat_record->numbytes, byte_str, outputParams->printPlain, VAR_LENGTH);
		format_number(stat_record->numpackets, packet_str, outputParams->printPlain, VAR_LENGTH);
		format_number(bps, bps_str, outputParams->printPlain, VAR_LENGTH);
		format_number(pps, pps_str, outputParams->printPlain, VAR_LENGTH);
		format_number(bpp, bpp_str, outputParams->printPlain, VAR_LENGTH);
		printf("Summary: total flows: %llu, total bytes: %s, total packets: %s, avg bps: %s, avg pps: %s, avg bpp: %s\n",
		(unsigned long long)stat_record->numflows, byte_str, packet_str, bps_str, pps_str, bpp_str );
	}

} // End of PrintSummary

__attribute__((noinline, unused)) static int dofilter(master_record_t *master_record);
static int dofilter(master_record_t *master_record) {
return (master_record->srcPort == 107 || master_record->dstPort == 107 ||
master_record->srcPort == 106 || master_record->dstPort == 106 ||
master_record->srcPort == 105 || master_record->dstPort == 105);
}

static inline void AddGeoInfo(master_record_t *master_record) {

	LookupCountry(master_record->V6.srcaddr, master_record->src_geo);
	LookupCountry(master_record->V6.dstaddr, master_record->dst_geo);
	if ( master_record->srcas == 0 )
		master_record->srcas = LookupAS(master_record->V6.srcaddr);
	if ( master_record->dstas == 0 )
		master_record->dstas = LookupAS(master_record->V6.dstaddr);
	// insert AS element in order to list
	int j = 0;
	uint32_t val = EXasRoutingID;
	while ( j < master_record->numElements ) {
		if ( EXasRoutingID == master_record->exElementList[j] ) {
			break;
		}
		if ( val < master_record->exElementList[j] ) {
			uint32_t _tmp = master_record->exElementList[j];
			master_record->exElementList[j] = val;
			val = _tmp;
		}
		j++;
	}
	if ( val != EXasRoutingID ) {
		master_record->exElementList[j] = val;
		master_record->numElements++;
	}

} // End of AddGeoInfo

static stat_record_t process_data(char *wfile, int element_stat, int flow_stat, int sort_flows,
	printer_t print_record, timeWindow_t *timeWindow, uint64_t limitRecords, 
	outputParams_t *outputParams, int compress) {
nffile_t			*nffile_w, *nffile_r;
stat_record_t 		stat_record;
uint64_t twin_msecFirst, twin_msecLast;

	// time window of all matched flows
	memset((void *)&stat_record, 0, sizeof(stat_record_t));
	stat_record.first_seen = 0x7fffffff;
	stat_record.msec_first = 999;

	if ( timeWindow ) {
		twin_msecFirst = timeWindow->first * 1000LL;
		if ( timeWindow->last ) 
			twin_msecLast  = timeWindow->last * 1000LL;
		else
			twin_msecLast  = 0x7FFFFFFFFFFFFFFFLL;
	} else {
		twin_msecFirst = twin_msecLast = 0;
	}

	// do not print flows when doing any stats are sorting
	if ( sort_flows || flow_stat || element_stat ) {
		print_record = NULL;
	}

	// do not write flows to file, when doing any stats
	// -w may apply for flow_stats later
	int write_file = !(sort_flows || flow_stat || element_stat) && wfile;
	nffile_r = NULL;
	nffile_w = NULL;

	// Get the first file handle
	nffile_r = GetNextFile(NULL);
	if ( !nffile_r ) {
		LogError("GetNextFile() error in %s line %d", __FILE__, __LINE__);
		return stat_record;
	}
	if ( nffile_r == EMPTY_LIST ) {
		LogError("Empty file list. No files to process\n");
		return stat_record;
	}

	// preset time window of all processed flows to the stat record in first flow file
	t_first_flow = nffile_r->stat_record->first_seen;
	t_last_flow  = nffile_r->stat_record->last_seen;

	// prepare output file if requested
	if ( write_file ) {
		nffile_w = OpenNewFile(wfile, NULL, compress, NOT_ENCRYPTED );
		if ( !nffile_w ) {
			if ( nffile_r ) {
				CloseFile(nffile_r);
				DisposeFile(nffile_r);
			}
			return stat_record;
		}
		SetIdent(nffile_w, nffile_r->ident);
	}
	Engine->ident = nffile_r->ident;

	master_record_t *master_record = malloc(sizeof(master_record_t));
	if ( !master_record ) {
		LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return stat_record;
	}

	Engine->nfrecord = (uint64_t *)master_record;

	// do we need to convert old v2 records?
	record_header_t	*convertedV2 = NULL;
	int convertV2 = flow_stat || sort_flows || write_file;
	if ( convertV2 ) {
		convertedV2 = calloc(1, 4096);	// one size fits all
		if ( !convertedV2 ) {
			LogError("calloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			exit(EXIT_FAILURE);
		}
	}

	int done = 0;
	while ( !done ) {
	int i, ret;
		// get next data block from file
		ret = ReadBlock(nffile_r);

		switch (ret) {
			case NF_CORRUPT:
			case NF_ERROR:
				if ( ret == NF_CORRUPT ) 
					LogError("Skip corrupt data file '%s'\n",nffile_r->fileName);
				else 
					LogError("Read error in file '%s': %s\n",nffile_r->fileName, strerror(errno) );
				// fall through - get next file in chain
			case NF_EOF: {
				nffile_t *next = GetNextFile(nffile_r);
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
				Engine->ident = nffile_r->ident;
				continue;

				} break; // not really needed
			default:
				// successfully read block
				total_bytes += ret;
		}

		if ( nffile_r->block_header->type != DATA_BLOCK_TYPE_2 &&
			 nffile_r->block_header->type != DATA_BLOCK_TYPE_3) {
			if ( nffile_r->block_header->type != DATA_BLOCK_TYPE_4 ) {	// skip array blocks
				if ( nffile_r->block_header->type == DATA_BLOCK_TYPE_1 )
					LogError("nfdump 1.5.x block type 1 no longer supported. Skip block");
				else
					LogError("Unknown block type %u. Skip block", nffile_r->block_header->type);
			}
			skipped_blocks++;
			continue;
		}

		uint32_t sumSize = 0;
		record_header_t	*record_ptr = nffile_r->buff_ptr;
		dbg_printf("Block has %i records\n", nffile_r->block_header->NumRecords);
		for ( i=0; i < nffile_r->block_header->NumRecords && !done; i++ ) {
			record_header_t	*process_ptr = record_ptr;
			if ( (sumSize + record_ptr->size) > ret || (record_ptr->size < sizeof(record_header_t)) ) {
				LogError("Corrupt data file. Inconsistent block size in %s line %d\n", __FILE__, __LINE__);
				exit(EXIT_FAILURE);
			}
			sumSize += record_ptr->size;

			switch ( record_ptr->type ) {
				case V3Record:
				case CommonRecordType: {
					int match;
					memset((void *)master_record, 0, sizeof(master_record_t));
					if (__builtin_expect(record_ptr->type == CommonRecordType, 0) ) {
						if ( !ExpandRecord_v2(record_ptr, master_record)) {
							goto NEXT;
						}
						if ( convertV2 ) {
							dbg_printf("Convert v2 record\n");
							if ( !ConvertRecordV2((common_record_t *)record_ptr, convertedV2))
								goto NEXT;
							process_ptr = convertedV2;
						}
					} else {
						ExpandRecord_v3((recordHeaderV3_t *)record_ptr, master_record);
					}

					processed++;
					if ( Engine->geoFilter ) {
						AddGeoInfo(master_record);
					}
					// Time based filter
					// if no time filter is given, the result is always true
					match = twin_msecFirst && 
						(master_record->msecFirst < twin_msecFirst ||  master_record->msecLast > twin_msecLast) ? 0 : 1;

					// filter netflow record with user supplied filter
					if ( match ) 
						match = (*Engine->FilterEngine)(Engine);
//						match = dofilter(master_record);

					if ( match == 0 ) { // record failed to pass all filters
						// go to next record
						goto NEXT;
					}

					passed++;
					// check if we are done, if -c option was set
					if ( limitRecords ) 
						done = passed >= limitRecords;

					// Records passed filter -> continue record processing
					// Update statistics
					master_record->label = Engine->label;
#ifdef DEVEL
					if ( Engine->label )
						printf("Flow has label: %s\n", Engine->label);
#endif
					UpdateStat(&stat_record, master_record);

					if ( flow_stat ) {
						AddFlowCache(process_ptr, master_record);
						if ( element_stat ) {
							AddElementStat(master_record);
						} 
					} else if ( element_stat ) {
						AddElementStat(master_record);
					} else if ( sort_flows ) {
						InsertFlow(process_ptr, master_record);
					} else {
						if ( write_file ) {
							AppendToBuffer(nffile_w, (void *)process_ptr, process_ptr->size);
						} else if ( print_record ) {
							// if we need to print out this record
							print_record(stdout, master_record, outputParams->doTag);
						} else { 
							// mutually exclusive conditions should prevent executing this code
							// this is buggy!
							printf("Bug! - this code should never get executed in file %s line %d\n", __FILE__, __LINE__);
							exit(EXIT_FAILURE);
						}
					} // sort_flows - else
					} break; 
				case ExtensionMapType: {
					extension_map_t *map = (extension_map_t *)record_ptr;
					if ( Insert_Extension_Map(extension_map_list, map) < 0 ) {
						LogError("Corrupt data file. Unable to decode at %s line %d\n", __FILE__, __LINE__);
						exit(EXIT_FAILURE);
					}
					} break;
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
				case SamplerInfoRecordType: {
					int ret = AddSamplerInfo((sampler_info_record_t *)record_ptr);
					if ( ret != 0 ) {
						if ( write_file && ret == 1 ) 
							AppendToBuffer(nffile_w, (void *)record_ptr, record_ptr->size);
					} else {
						LogError("Failed to add Sampler Record\n");
					}
					} break;
				case NbarRecordType: {
					nbarRecordHeader_t *nbarRecord = (nbarRecordHeader_t *)record_ptr;
					printf("Found nbar record: %u elements\n", nbarRecord->numElements);
					PrintNbarRecord(nbarRecord);
					AddNbarRecord(nbarRecord);
					} break;
				case LegacyRecordType1:
				case LegacyRecordType2:
				case CommonRecordV0Type: 
					LogError("Skip lagecy record type: %d", record_ptr->type);
					break;
				default: {
					LogError("Skip unknown record type %i\n", record_ptr->type);
				}
			}

			NEXT:
			// Advance pointer by number of bytes for netflow record
			record_ptr = (record_header_t *)((pointer_addr_t)record_ptr + record_ptr->size);	

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
			CloseUpdateFile(nffile_w);
			DisposeFile(nffile_w);
		} // else stdout
	}	 

	DisposeFile(nffile_r);
	return stat_record;

} // End of process_data


int main( int argc, char **argv ) {
struct stat stat_buff;
stat_record_t	sum_stat;
outputParams_t *outputParams;
printer_t 	   print_record;
func_prolog_t  print_prolog;
func_epilog_t  print_epilog;
nfprof_t 	profile_data;
timeWindow_t *timeWindow;
char 		*wfile, *ffile, *filter, *tstring, *stat_type;
char		*byte_limit_string, *packet_limit_string, *print_format;
char		*print_order, *query_file, *geo_file, *nameserver, *aggr_fmt;
int 		c, ffd, ret, element_stat, fdump;
int 		i, flow_stat, aggregate, aggregate_mask, bidir;
int 		print_stat, syntax_only, compress;
int			GuessDir, ModifyCompress;
uint32_t	limitRecords;
char 		Ident[IDENTLEN];
flist_t 	flist;

	memset((void *)&flist, 0, sizeof(flist));
	wfile = ffile = filter = tstring = stat_type = NULL;
	byte_limit_string = packet_limit_string = NULL;
	fdump = aggregate = 0;
	aggregate_mask	= 0;
	bidir			= 0;
	timeWindow		= NULL;
	syntax_only	    = 0;
	flow_stat       = 0;
	print_stat      = 0;
	element_stat  	= 0;
	limitRecords	= 0;
	skipped_blocks	= 0;
	compress		= NOT_COMPRESSED;
	GuessDir		= 0;
	nameserver		= NULL;

	print_format    = NULL;
	print_record  	= NULL;
	print_prolog	= NULL;
	print_epilog	= NULL;
	print_order  	= NULL;
	query_file		= NULL;
	geo_file		= NULL;
	ModifyCompress	= -1;
	aggr_fmt		= NULL;

	outputParams	= calloc(1, sizeof(outputParams_t));
	if ( !outputParams ) {
		LogError("calloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(EXIT_FAILURE);
	}
	outputParams->topN = -1;

	Ident[0] = '\0';
	while ((c = getopt(argc, argv, "6aA:Bbc:D:E:G:s:hn:i:jf:qyzr:v:w:J:K:M:NImO:R:XZt:TVv:x:l:L:o:")) != EOF) {
		switch (c) {
			case 'h':
				usage(argv[0]);
				exit(EXIT_SUCCESS);
				break;
			case 'a':
				aggregate = 1;
				break;
			case 'A':
				if (strlen(optarg) > 64) {
					LogError("Aggregate mask format length error");
					exit(EXIT_FAILURE);
				}
				if (aggregate_mask) {
					LogError("Multiple aggregation masks not allowed");
					exit(EXIT_FAILURE);
				}
				aggr_fmt = ParseAggregateMask(optarg);
				if (!aggr_fmt) {
					exit(EXIT_FAILURE);
				}
				aggregate_mask = 1;
				break;
			case 'B':
				GuessDir = 1;
			case 'b':
				if ( !SetBidirAggregation() ) {
					exit(EXIT_FAILURE);
				}
				bidir	  = 1;
				// implies
				aggregate = 1;
				break;
			case 'D':
				nameserver = optarg;
				if ( !set_nameserver(nameserver) ) {
					exit(EXIT_FAILURE);
				}
				break;
			case 'E': {
				if ( !InitExporterList() ) {
					exit(EXIT_FAILURE);
				}
				flist.single_file = strdup(optarg);
				queue_t *fileList = SetupInputFileSequence(&flist);
				if ( !fileList || !Init_nffile(fileList) )
					exit(EXIT_FAILURE);
				PrintExporters();
				exit(EXIT_SUCCESS);
				} break;
			case 'G':
				if ( !CheckPath(optarg, S_IFREG) )
					exit(EXIT_FAILURE);
				geo_file = strdup(optarg);
				break;
			case 'X':
				fdump = 1;
				break;
			case 'Z':
				syntax_only = 1;
				break;
			case 'q':
				outputParams->quiet = 1;
				break;
			case 'j':
				if ( compress ) {
					LogError("Use one compression: -z for LZO, -j for BZ2 or -y for LZ4 compression");
					exit(EXIT_FAILURE);
				}
				compress = BZ2_COMPRESSED;
				break;
			case 'y':
				if ( compress ) {
					LogError("Use one compression: -z for LZO, -j for BZ2 or -y for LZ4 compression");
					exit(EXIT_FAILURE);
				}
				compress = LZ4_COMPRESSED;
				break;
			case 'z':
				if ( compress ) {
					LogError("Use one compression: -z for LZO, -j for BZ2 or -y for LZ4 compression");
					exit(EXIT_FAILURE);
				}
				compress = LZO_COMPRESSED;
				break;
			case 'c':	
				limitRecords = atoi(optarg);
				if ( !limitRecords ) {
					LogError("Option -c needs a number > 0\n");
					exit(EXIT_FAILURE);
				}
				break;
			case 's':
				stat_type = optarg;
                if ( !SetStat(stat_type, &element_stat, &flow_stat) ) {
                    exit(EXIT_FAILURE);
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
				exit(EXIT_SUCCESS);
				} break;
			case 'l':
				packet_limit_string = optarg;
				break;
			case 'K':
				LogError("*** Anonymisation moved! Use nfanon to anonymise flows!");
				exit(EXIT_FAILURE);
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
				if ( !CheckPath(optarg, S_IFREG) )
					exit(EXIT_FAILURE);
				flist.single_file = strdup(optarg);
				break;
			case 'm':
				print_order = "tstart";
				Parse_PrintOrder(print_order);
				LogError("Option -m deprecated. Use '-O tstart' instead");
				break;
			case 'M':
				if ( strlen(optarg) > MAXPATHLEN )
					exit(EXIT_FAILURE);
				flist.multiple_dirs = strdup(optarg);
				break;
			case 'I':
				print_stat++;
				break;
			case 'o':	// output mode
				print_format = optarg;
				// limit input chars
				if ( strlen(print_format) > 512 ) {
					LogError("Length of ouput format string too big - > 512");
					exit(EXIT_FAILURE);
				}
				break;
			case 'O': {	// stat order by
				int ret;
				print_order = optarg;
				ret = Parse_PrintOrder(print_order);
				if ( ret < 0 ) {
					LogError("Unknown print order '%s'", print_order);
					exit(EXIT_FAILURE);
				}
				} break;
			case 'R':
				if ( strlen(optarg) > MAXPATHLEN )
					exit(EXIT_FAILURE);
				flist.multiple_files = strdup(optarg);
				break;
			case 'w':
				wfile = optarg;
				break;
			case 'n':
				outputParams->topN = atoi(optarg);
				if ( outputParams->topN < 0 ) {
					LogError("TopnN number %i out of range", outputParams->topN);
					exit(EXIT_FAILURE);
				}
				break;
			case 'T':
				outputParams->doTag = 1;
				break;
			case 'i':
				strncpy(Ident, optarg, IDENTLEN);
				Ident[IDENTLEN - 1] = 0;
				if ( strchr(Ident, ' ') ) {
					LogError("Ident must not contain spaces");
					exit(EXIT_FAILURE);
				}
				break;
			case 'J':
				ModifyCompress = atoi(optarg);
				if ( (ModifyCompress < 0) || (ModifyCompress > 3) ) {
					LogError("Expected -J <num>, 0: uncompressed, 1: LZO, 2: BZ2, 3: LZ4 compressed");
					exit(EXIT_FAILURE);
				}
				break;
			case 'x': {
				InitExtensionMaps(NO_EXTENSION_LIST);
				flist.single_file = strdup(optarg);
				queue_t *fileList = SetupInputFileSequence(&flist);
				if ( !fileList || !Init_nffile(fileList) )
					exit(EXIT_FAILURE);
				DumpExMaps();
				exit(EXIT_SUCCESS);
				} break;
			case 'v':
				query_file = optarg;
				if ( !QueryFile(query_file))
					exit(EXIT_FAILURE);
				else
					exit(EXIT_SUCCESS);
				break;
			case '6':	// print long IPv6 addr
				Setv6Mode(1);
				break;
			default:
				usage(argv[0]);
				exit(EXIT_SUCCESS);
		}
	}
	if (argc - optind > 1) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	} else {
		filter = argv[optind];
		FilterFilename = NULL;
	}

	if ( !filter && ffile ) {
		if ( stat(ffile, &stat_buff) ) {
			LogError("Can't stat filter file '%s': %s", ffile, strerror(errno));
			exit(EXIT_FAILURE);
		}
		filter = (char *)malloc(stat_buff.st_size+1);
		if ( !filter ) {
			LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
			exit(EXIT_FAILURE);
		}
		ffd = open(ffile, O_RDONLY);
		if ( ffd < 0 ) {
			LogError("Can't open filter file '%s': %s", ffile, strerror(errno));
			exit(EXIT_FAILURE);
		}
		ret = read(ffd, (void *)filter, stat_buff.st_size);
		if ( ret < 0   ) {
			LogError("Error reading filter file %s: %s", ffile, strerror(errno));
			close(ffd);
			exit(EXIT_FAILURE);
		}
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
		exit(EXIT_SUCCESS);
	}

	if ( syntax_only )
		exit(EXIT_SUCCESS);
	
	if ( outputParams->topN < 0 ) {
		if ( flow_stat || element_stat ) {
			outputParams->topN = 10;
		} else {
			outputParams->topN = 0;
		}
	}
	if ( wfile ) 
		outputParams->quiet = 1;

	if ( (element_stat && !flow_stat) && aggregate_mask ) {
		LogError("Warning: Aggregation ignored for element statistics\n");
		aggregate_mask = 0;
	}

	if ( !flow_stat && aggregate_mask ) {
		aggregate = 1;
	}

	extension_map_list = InitExtensionMaps(NEEDS_EXTENSION_LIST);
	if ( !InitExporterList() ) {
		exit(EXIT_FAILURE);
	}

	if ( tstring ) {
		flist.timeWindow = ScanTimeFrame(tstring);
		if ( !flist.timeWindow ) 
			exit(EXIT_FAILURE);
	}

	if ( flist.multiple_dirs == NULL && flist.single_file == NULL &&
		 flist.multiple_files == NULL ) {
		usage(argv[0]);
		exit(EXIT_SUCCESS);
	}

	queue_t *fileList = SetupInputFileSequence(&flist);
	if ( !fileList || !Init_nffile(fileList) )
		exit(EXIT_FAILURE);

	if (geo_file == NULL) {
		char *f = getenv("NFGEODB");
		if ( f && !CheckPath(f, S_IFREG) ) {
			LogError("Error reading geo location DB file %s", f);
			exit(EXIT_FAILURE);
		}
		geo_file = f;
	}
	if ( geo_file ) {
		if ( !Init_MaxMind() || !LoadMaxMind(geo_file) ) {
			LogError("Error reading geo location DB file %s", geo_file);
			exit(EXIT_FAILURE);
		}
		HasGeoDB = 1;
	}
	if ( HasGeoDB == 0 && Engine->geoFilter ) {
		LogError("Can not filter according geo elements without a geo location DB");
		exit(EXIT_FAILURE);
	}
	// Modify compression
	if ( ModifyCompress >= 0 ) {
		if ( !flist.single_file && !flist.multiple_files ) {
			LogError("Expected -r <file> or -R <dir> to change compression\n");
			exit(EXIT_FAILURE);
		}
		ModifyCompressFile(ModifyCompress);
		exit(EXIT_SUCCESS);
	}

	// Change Ident only
	if ( flist.single_file && strlen(Ident) > 0 ) {
		ChangeIdent(flist.single_file, Ident);
		exit(EXIT_SUCCESS);
	}

	if ( print_stat ) {
		nffile_t *nffile;
		if ( !flist.single_file && !flist.multiple_files && !flist.multiple_dirs) {
			LogError("Expect data file(s).\n");
			exit(EXIT_FAILURE);
		}

		memset((void *)&sum_stat, 0, sizeof(stat_record_t));
		sum_stat.first_seen = 0x7fffffff;
		sum_stat.msec_first = 999;
		nffile = GetNextFile(NULL);
		if ( !nffile ) {
			LogError("Error open file: %s\n", strerror(errno));
			exit(250);
		}
		char *ident = NULL;
		if ( nffile->ident ) {
			ident = strdup(nffile->ident);
		}
		while ( nffile && nffile != EMPTY_LIST ) {
			SumStatRecords(&sum_stat, nffile->stat_record);
			nffile = GetNextFile(nffile);
		}
		PrintStat(&sum_stat, ident);
		exit(EXIT_SUCCESS);
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
				exit(EXIT_FAILURE);
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
				exit(EXIT_FAILURE);
			print_record  = format_special;
			print_prolog  = text_prolog;
		} else {
			LogError("Missing format description for user defined output format!\n");
			exit(EXIT_FAILURE);
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
						exit(EXIT_FAILURE);
					// predefined custom format
					print_record  = printmap[i].func_record;
					print_prolog  = printmap[i].func_prolog;
					print_epilog  = printmap[i].func_epilog;
				} else {
					// To support the pipe output format for element stats - check for pipe, and remember this
					if ( strncasecmp(print_format, "pipe", MAXMODELEN) == 0 ) {
						outputParams->mode = MODE_PIPE;
					} else if ( strncasecmp(print_format, "csv", MAXMODELEN) == 0 ) {
						outputParams->mode = MODE_CSV;
					} else if ( strncasecmp(print_format, "json", MAXMODELEN) == 0 ) {
						outputParams->mode = MODE_JSON;
					} else {
						outputParams->mode = MODE_PLAIN;
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
		exit(EXIT_FAILURE);
	}

	if ( aggregate && (flow_stat || element_stat) ) {
		aggregate = 0;
		LogError("Command line switch -s overwrites -a\n");
	}

	if ( print_order && flow_stat ) {
		printf("-s record and -O (-m) are mutually exclusive options\n");
		exit(EXIT_FAILURE);
	}

	if ((aggregate || flow_stat || print_order)  && !Init_FlowCache() )
			exit(250);

	if (element_stat && !Init_StatTable() )
			exit(250);

	SetLimits(element_stat || aggregate || flow_stat, packet_limit_string, byte_limit_string);

	if ( !(flow_stat || element_stat || outputParams->quiet ) && print_prolog ) {
		print_prolog();
	}

	nfprof_start(&profile_data);
	sum_stat = process_data(wfile, element_stat, aggregate || flow_stat, print_order != NULL,
						print_record, timeWindow, 
						limitRecords, outputParams, compress);
	nfprof_end(&profile_data, processed);
	
	if ( passed == 0 ) {
		printf("No matching flows\n");
	}

	if (aggregate || print_order) {
		if ( wfile ) {
			nffile_t *nffile = OpenNewFile(wfile, NULL, compress, NOT_ENCRYPTED );
			if ( !nffile ) 
				exit(EXIT_FAILURE);
			if ( ExportFlowTable(nffile, aggregate, bidir, GuessDir) ) {
				CloseUpdateFile(nffile);	
			} else {
				CloseFile(nffile);
				unlink(wfile);
			}
			DisposeFile(nffile);
		} else {
			PrintFlowTable(print_record, outputParams, GuessDir);
		}
	}

	if (flow_stat) {
		PrintFlowStat(print_prolog, print_record, outputParams);
	} 

	if (element_stat) {
		PrintElementStat(&sum_stat, outputParams, print_record);
	} 

	if ( print_epilog ) {
		print_epilog();
	}
	if ( !outputParams->quiet ) {
		switch (outputParams->mode) {
			case MODE_PLAIN:
				PrintSummary(&sum_stat, outputParams);
				if ( t_last_flow == 0 ) {
 					printf("Time window: <unknown>\n");
				} else {
					if ( timeWindow ) {
						if ( timeWindow->first && (timeWindow->first > t_first_flow))
							t_first_flow = timeWindow->first;
						if ( timeWindow->last && (timeWindow->last < t_last_flow))
							t_last_flow = timeWindow->last;
					}
 					printf("Time window: %s\n", TimeString(t_first_flow, t_last_flow));
				}
				printf("Total flows processed: %u, passed: %u, Blocks skipped: %u, Bytes read: %llu\n", 
					processed, passed, skipped_blocks, (unsigned long long)total_bytes);
				nfprof_print(&profile_data, stdout);
				break;
			case MODE_PIPE:
				break;
			case MODE_CSV:
				PrintSummary(&sum_stat, outputParams);
				break;
			case MODE_JSON:
				break;
		}

	} // else - no output

	DumpNbarList();

	Dispose_FlowTable();
	Dispose_StatTable();
	FreeExtensionMaps(extension_map_list);

	return 0;
}
