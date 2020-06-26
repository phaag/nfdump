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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <fcntl.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "util.h"
#include "nfdump.h"
#include "nftree.h"
#include "nffile.h"
#include "nfx.h"
#include "nfxV3.h"
#include "nfstat.h"
#include "nfstatfile.h"
#include "bookkeeper.h"
#include "collector.h"
#include "exporter.h"
#include "ipconv.h"
#include "flist.h"
#include "profile.h"

/* Global */
char Ident[IDENTLEN];

/* Local Variables */
static const char *nfdump_version = VERSION;

#ifdef HAVE_INFLUXDB
	char influxdb_url[1024]="";
#endif

/* Function Prototypes */
static void usage(char *name);

static profile_param_info_t *ParseParams (char *profile_datadir);

static void process_data(profile_channel_info_t *channels, unsigned int num_channels, time_t tslot);

/* Functions */

#include "nfdump_inline.c"
#include "nffile_inline.c"

static void usage(char *name) {
		printf("usage %s [options] \n"
					"-h\t\tthis text you see right here\n"
					"-V\t\tPrint version and exit.\n"
					"-D <dns>\tUse nameserver <dns> for host lookup.\n"
					"-M <expr>\tRead input from multiple directories.\n"
					"-r\t\tread input from file\n"
					"-f\t\tfilename with filter syntaxfile\n"
					"-p\t\tprofile data dir.\n"
					"-P\t\tprofile stat dir.\n"
					"-s\t\tprofile subdir.\n"
					"-Z\t\tCheck filter syntax and exit.\n"
					"-S subdir\tSub directory format. see nfcapd(1) for format\n"
					"-z\t\tCompress flows in output file.\n"
#ifdef HAVE_INFLUXDB
					"-i <influxurl>\tInfluxdb url for stats (example: http://localhost:8086/write?db=mydb&u=pippo&p=paperino)\n"
#endif
					"-t <time>\ttime for RRD update\n", name);
} /* usage */

static void process_data(profile_channel_info_t *channels, unsigned int num_channels, time_t tslot) {
nffile_t		*nffile;
FilterEngine_t	*engine;
int 		i, j, done, ret ;

	nffile = GetNextFile(NULL);
	if ( !nffile ) {
		LogError("GetNextFile() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return;
	}
	if ( nffile == EMPTY_LIST ) {
		LogError("Empty file list. No files to process\n");
		return;
	}

    strncpy(Ident, FILE_IDENT(nffile), IDENTLEN);
    Ident[IDENTLEN-1] = '\0';
	for ( int j=0; j < num_channels; j++ ) {
		(channels[j].engine)->ident = Ident;
	}

	master_record_t *master_record = malloc(sizeof(master_record_t));
	if ( !master_record ) {
		LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return;
	}

	done = 0;
	while ( !done ) {

		// get next data block from file
		ret = ReadBlock(nffile);

		switch (ret) {
			case NF_CORRUPT:
			case NF_ERROR:
				if ( ret == NF_CORRUPT ) 
					LogError("Skip corrupt data file '%s'\n", nffile->fileName);
				else 
					LogError("Read error in file '%s': %s\n", nffile->fileName, strerror(errno) );
				// fall through - get next file in chain
			case NF_EOF: {
				nffile_t *next = GetNextFile(nffile);
				if ( next == EMPTY_LIST ) {
					done = 1;
				}
				if ( next == NULL ) {
					done = 1;
					LogError("Unexpected end of file list\n");
				}
    			strncpy(Ident, FILE_IDENT(nffile), IDENTLEN);
    			Ident[IDENTLEN-1] = '\0';
				for ( int j=0; j < num_channels; j++ ) {
					(channels[j].engine)->ident = Ident;
				}
				continue;
	
				} break; // not really needed
		}

		if ( nffile->block_header->type != DATA_BLOCK_TYPE_2 && 
			 nffile->block_header->type != DATA_BLOCK_TYPE_3) {
			LogError("Can't process block type %u. Skip block.\n", nffile->block_header->type);
			continue;
		}

		record_header_t	*record_ptr = nffile->buff_ptr;
		uint32_t sumSize = 0;
		for ( i=0; i < nffile->block_header->NumRecords; i++ ) {
			if ( (sumSize + record_ptr->size) > ret || (record_ptr->size < sizeof(record_header_t)) ) {
				LogError("Corrupt data file. Inconsistent block size in %s line %d\n", __FILE__, __LINE__);
				exit(255);
			}
			sumSize += record_ptr->size;

			switch ( record_ptr->type ) { 
				case V3Record:
					memset((void *)master_record, 0, sizeof(master_record_t));
					ExpandRecord_v3((recordHeaderV3_t *)record_ptr, master_record);

					for ( j=0; j < num_channels; j++ ) {
						int match;
	
						// apply profile filter
						(channels[j].engine)->nfrecord 	= (uint64_t *)master_record;
						engine = channels[j].engine;
						match = (*engine->FilterEngine)(engine);
	
						// if profile filter failed -> next profile
						if ( !match )
							continue;
	
						// filter was successful -> continue record processing
	
						// update statistics
						UpdateStat(&channels[j].stat_record, master_record);
						if ( channels[j].nffile ) 
							UpdateStat(channels[j].nffile->stat_record, master_record);
	
						// do we need to write data to new file - shadow profiles do not have files.
						// check if we need to flush the output buffer
						if ( channels[j].nffile != NULL ) {
							// write record to output buffer
							AppendToBuffer(channels[j].nffile, (void *)record_ptr, record_ptr->size);
						} 
	
					} // End of for all channels
	
					break;
				case ExporterInfoRecordType: {
					int err = AddExporterInfo((exporter_info_record_t *)record_ptr);
					if ( err != 0 ) {
						int j;
						for ( j=0; j < num_channels; j++ ) {
							if ( channels[j].nffile != NULL && err == 1) {
								// flush new exporter
								AppendToBuffer(channels[j].nffile, (void *)record_ptr, record_ptr->size);
							}
						}
					} else {
						LogError("Failed to add Exporter Record\n");
					}
					} break;
				case SamplerInfoRecordype: {
					int err = AddSamplerInfo((sampler_info_record_t *)record_ptr);
					if ( err != 0 ) {
						int j;
						for ( j=0; j < num_channels; j++ ) {
							if ( channels[j].nffile != NULL && err == 1 ) {
								// flush new map
								AppendToBuffer(channels[j].nffile, (void *)record_ptr, record_ptr->size);
							}
						}
					} else {
						LogError("Failed to add Sampler Record\n");
					}
					} break;
				case LegacyRecordType1:
				case LegacyRecordType2:
				case ExporterStatRecordType:
						// Silently skip exporter records
					break;
				default:  {
					LogError("Skip unknown record type %i\n", record_ptr->type);
				}
			}
			// Advance pointer by number of bytes for netflow record
			record_ptr = (record_header_t *)((pointer_addr_t)record_ptr + record_ptr->size);	

		} // End of for all umRecords
	} // End of while !done

	// do we need to write data to new file - shadow profiles do not have files.
	for ( j=0; j < num_channels; j++ ) {
		if ( channels[j].nffile != NULL ) {
			// flush output buffer
			if ( channels[j].nffile->block_header->NumRecords ) {
				if ( WriteBlock(channels[j].nffile) <= 0 ) {
					LogError("Failed to write output buffer to disk: '%s'" , strerror(errno));
				} 
			} 
		}
	}
	CloseFile(nffile);
	DisposeFile(nffile);

} // End of process_data

static profile_param_info_t *ParseParams (char *profile_datadir) {
struct stat stat_buf;
char line[512], path[MAXPATHLEN], *p, *q, *s;
profile_param_info_t *profile_list;
profile_param_info_t **list = &profile_list;

	profile_list = NULL;
	while ( ( fgets(line, 512, stdin) != NULL )) {
		line[511] = '\0';

		if ( *list == NULL ) 
			*list = (profile_param_info_t *)malloc(sizeof(profile_param_info_t));
		// else we come from a continue statement with illegal data - overwrite

		if ( !*list) {
			LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			return NULL;
		}

		(*list)->next 		  = NULL;
		(*list)->profilegroup = NULL;
		(*list)->profilename  = NULL;
		(*list)->channelname  = NULL;
		(*list)->channel_sourcelist = NULL;
		(*list)->profiletype  = 0;

		// delete '\n' at the end of line
		// format of stdin config line:
		// <profilegroup>#<profilename>#<profiletype>#<channelname>#<channel_sourcelist>
		p = strchr(line, '\n');
		if ( p ) *p = '\0';
		LogInfo("Process line '%s'\n", line);

		q = line;
		p = strchr(q, '#');
		if ( p ) 
			*p = '\0';

		s = line;

		// savety check: if no separator found loop to next line
		if ( !p ) {
			LogError("Incomplete line - channel skipped.\n");
			continue;
		}

		q = p;
		q++;

		p = strchr(q, '#');
		if ( p ) 
			*p = '\0';

		snprintf(path, MAXPATHLEN-1, "%s/%s/%s", profile_datadir, s, q);
		path[MAXPATHLEN-1] = '\0';
		if ( stat(path, &stat_buf) || !S_ISDIR(stat_buf.st_mode) ) {
			LogError("profile '%s' not found in group %s. Skipped.\n", q, s);
			continue;
		}

		(*list)->profilegroup = strdup(s);
		(*list)->profilename  = strdup(q);

		// savety check: if no separator found loop to next line
		if ( !p ) {
			LogError("Incomplete line - channel skipped.\n");
			continue;
		}

		q = p;
		q++;

		p = strchr(q, '#');
		if ( p ) 
			*p = '\0';

		s = q;
		while ( *s ) {
			if ( *s < '0' || *s > '9' ) {
				LogError("Not a valid number: %s\n", q);
				s = NULL;
				break;
			}
			s++;
		}
		if ( s == NULL )
			continue;

		(*list)->profiletype = (int)strtol(q, (char **)NULL, 10);

		// savety check: if no separator found loop to next line
		if ( !p ) {
			LogError("Incomplete line - channel skipped.\n");
			continue;
		}

		q = p;
		q++;

		p = strchr(q, '#');
		if ( p ) 
			*p = '\0';

		snprintf(path, MAXPATHLEN-1, "%s/%s/%s/%s", profile_datadir, (*list)->profilegroup, (*list)->profilename, q);
		path[MAXPATHLEN-1] = '\0';
		if ( stat(path, &stat_buf) || !S_ISDIR(stat_buf.st_mode) ) {
			LogError("channel '%s' in profile '%s' not found. Skipped.\n", q, (*list)->profilename);
			continue;
		}

		(*list)->channelname = strdup(q);

		if ( !p ) {
			LogError("Incomplete line - Skipped.\n");
			continue;
		}

		q = p;
		q++;

		p = strchr(q, '#');
		if ( p ) 
			*p = '\0';

		// Skip leading '| chars
		while ( *q && *q == '|' ) {
			q++;
		}
		s = q;

		// if q is already empty ( '\0' ) loop is not processed
		while ( *s ) {
			// as s[0] is not '\0' s[1] may be '\0' but still valid and in range
			if ( s[0] == '|' && s[1] == '|' ) {
				char *t = s;
				t++;
				while ( *t ) {	// delete this empty channel name
					t[0] = t[1];
					t++;
				}
			} else
				s++;
		}
		// we have no doublicate '|' here any more
		// check if last char is an extra '|' 
		if ( *q && (q[strlen(q)-1] == '|') )
			q[strlen(q)-1] = '\0';

		if ( *q && (strcmp(q, "*") != 0) ) 
			(*list)->channel_sourcelist = strdup(q);

		list = &((*list)->next);
	}

	if ( *list != NULL ) {
		free(*list);
		*list = NULL;
	}

	if ( ferror(stdin) ) {
		LogError("fgets() error: %s", strerror(errno));
		return NULL;
	}

	return profile_list;

} // End of ParseParams

int main( int argc, char **argv ) {
unsigned int		num_channels, compress;
struct stat stat_buf;
profile_param_info_t *profile_list;
char *rfile, *ffile, *filename, *Mdirs;
char	*profile_datadir, *profile_statdir, *nameserver;
int c, syntax_only, subdir_index, stdin_profile_params;
time_t tslot;

	profile_datadir = NULL;
	profile_statdir = NULL;
	Mdirs 			= NULL;
	tslot 			= 0;
	syntax_only	    = 0;
	compress		= NOT_COMPRESSED;
	subdir_index	= 0;
	profile_list	= NULL;
	nameserver		= NULL;
	stdin_profile_params = 0;

	// default file names
	ffile = "filter.txt";
	rfile = NULL;
	while ((c = getopt(argc, argv, "D:HIL:p:P:hi:f:J;r:n:M:S:t:VzZ")) != EOF) {
		switch (c) {
			case 'h':
				usage(argv[0]);
				exit(0);
				break;
			case 'D':
				nameserver = optarg;
				if ( !set_nameserver(nameserver) ) {
					exit(255);
				}
				break;
			case 'I':
				stdin_profile_params = 1;
				break;
			case 'L':
				if ( !InitLog(0, "nfprofile", optarg, 0) )
					exit(255);
				break;
			case 'Z':
				syntax_only = 1;
				break;
			case 'p':
				profile_datadir = optarg;
				break;
			case 'P':
				profile_statdir = optarg;
				break;
			case 'S':
				subdir_index = atoi(optarg);
				break;
			case 'V':
				printf("%s: Version: %s\n",argv[0], nfdump_version);
				exit(0);
				break;
			case 'f':
				ffile = optarg;
				break;
			case 't':
				tslot = atoi(optarg);
				break;
			case 'M':
				Mdirs = optarg;
				break;
			case 'r':
				rfile = optarg;
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
#ifdef HAVE_INFLUXDB
			case 'i': 
				if ( optarg != NULL ) 
					strncpy(influxdb_url, optarg, 1024);
				else {
					LogError("Missing argument for -i <influx URL>\n");
					exit(255);
				}
				influxdb_url[1023] = '\0';
				break;
#endif
			default:
				usage(argv[0]);
				exit(0);
		}
	}

	if ( subdir_index && !InitHierPath(subdir_index) ) {
		exit(255);
	}

	if ( !profile_datadir ) {
		LogError("Profile data directory required!\n");
		exit(255);
	}

	if ( !profile_statdir ) {
		profile_statdir = profile_datadir;
	}

	if ( stat(profile_datadir, &stat_buf) || !S_ISDIR(stat_buf.st_mode) ) {
		LogError("'%s' not a directory\n", profile_datadir);
		exit(255);
	}

	if ( stdin_profile_params ) {
		profile_list = ParseParams(profile_datadir);
		if ( !profile_list ) {
			exit(254);
		}
	}

	if ( syntax_only ) {
		filename = NULL;
		rfile = NULL;
	} else {
		char *p;
		if ( rfile == NULL ) {
			LogError("-r filename required!\n");
			exit(255);
		}
		p = strrchr(rfile, '/');
		filename = p == NULL ? rfile : ++p;
		if ( strlen(filename) == 0 ) {
			LogError("Filename error: zero length filename\n");
			exit(254);
		}
	} 

	if ( chdir(profile_datadir)) {
		LogError("Error can't chdir to '%s': %s", profile_datadir, strerror(errno));
		exit(255);
	}

	num_channels = InitChannels(profile_datadir, profile_statdir, profile_list, ffile, filename, subdir_index, syntax_only, compress);

	// nothing to do
	if ( num_channels == 0 ) {
		LogInfo("No channels to process.\n");
		return 0;
	}

	if ( syntax_only ) {
		printf("Syntax check done.\n");
		return 0;
	}

	if ( !rfile ) {
		LogError("Input file (-r) required!\n");
		exit(255);
	}

	if ( !InitExporterList() ) {
		exit(255);
	}

	SetupInputFileSequence(Mdirs,rfile, NULL, NULL);

	process_data(GetChannelInfoList(), num_channels, tslot);

	CloseChannels(tslot, compress);

	return 0;
}
