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
 *  $Id: nfprofile.c 39 2009-11-25 08:11:15Z haag $
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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <fcntl.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nf_common.h"
#include "rbtree.h"
#include "nftree.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfx.h"
#include "nfstat.h"
#include "nfstatfile.h"
#include "bookkeeper.h"
#include "nfxstat.h"
#include "collector.h"
#include "exporter.h"
#include "ipconv.h"
#include "flist.h"
#include "util.h"
#include "profile.h"

/* externals */
extern generic_exporter_t **exporter_list;

#ifdef COMPAT15
extern extension_descriptor_t extension_descriptor[];
#endif

/* Local Variables */
static const char *nfdump_version = VERSION;


extension_map_list_t *extension_map_list;
uint32_t is_anonymized;
char Ident[IDENTLEN];

/* Function Prototypes */
static void usage(char *name);

static profile_param_info_t *ParseParams (char *profile_datadir);

static void process_data(profile_channel_info_t *channels, unsigned int num_channels, time_t tslot, int do_xstat);


/* Functions */

#include "nfdump_inline.c"
#include "nffile_inline.c"

static void usage(char *name) {
		printf("usage %s [options] \n"
					"-h\t\tthis text you see right here\n"
					"-V\t\tPrint version and exit.\n"
					"-D <dns>\tUse nameserver <dns> for host lookup.\n"
					"-H Add xstat histogram data to flow file.(default 'no')\n"
					"-M <expr>\tRead input from multiple directories.\n"
					"-r\t\tread input from file\n"
					"-f\t\tfilename with filter syntaxfile\n"
					"-p\t\tprofile data dir.\n"
					"-P\t\tprofile stat dir.\n"
					"-s\t\tprofile subdir.\n"
					"-Z\t\tCheck filter syntax and exit.\n"
					"-S subdir\tSub directory format. see nfcapd(1) for format\n"
					"-z\t\tCompress flows in output file.\n"
					"-t <time>\ttime for RRD update\n", name);
} /* usage */


static void process_data(profile_channel_info_t *channels, unsigned int num_channels, time_t tslot, int do_xstat) {
common_record_t	*flow_record;
nffile_t		*nffile;
FilterEngine_data_t	*engine;
int 		i, j, done, ret ;
#ifdef COMPAT15
int	v1_map_done = 0;
#endif

	nffile = GetNextFile(NULL, 0, 0);
	if ( !nffile ) {
		LogError("GetNextFile() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return;
	}
	if ( nffile == EMPTY_LIST ) {
		LogError("Empty file list. No files to process\n");
		return;
	}

	// store infos away for later use
	// although multiple files may be processed, it is assumed that all 
	// have the same settings
	is_anonymized = IP_ANONYMIZED(nffile);
	strncpy(Ident, nffile->file_header->ident, IDENTLEN);
	Ident[IDENTLEN-1] = '\0';

	done = 0;
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
				nffile_t *next = GetNextFile(nffile, 0, 0);
				if ( next == EMPTY_LIST ) {
					done = 1;
				}
				if ( next == NULL ) {
					done = 1;
					LogError("Unexpected end of file list\n");
				}
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
					LogError("malloc() allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
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
				
				if ( Insert_Extension_Map(extension_map_list, map) ) {
					int j;
					for ( j=0; j < num_channels; j++ ) {
						if ( channels[j].nffile != NULL) {
							// flush new map
							AppendToBuffer(channels[j].nffile, (void *)map, map->size);
						}
					}
				} // else map already known and flushed
			
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

		if ( nffile->block_header->id == Large_BLOCK_Type ) {
			// skip
			continue;
		}

		if ( nffile->block_header->id != DATA_BLOCK_TYPE_2 ) {
			LogError("Can't process block type %u. Skip block.\n", nffile->block_header->id);
			continue;
		}

		flow_record = nffile->buff_ptr;
		for ( i=0; i < nffile->block_header->NumRecords; i++ ) {
			switch ( flow_record->type ) { 
					case CommonRecordV0Type:
					case CommonRecordType: {
					generic_exporter_t *exp_info = exporter_list[flow_record->exporter_sysid];
					uint32_t map_id = flow_record->ext_map;
					master_record_t	*master_record;

					if ( extension_map_list->slot[map_id] == NULL ) {
						LogError("Corrupt data file. Missing extension map %u. Skip record.\n", flow_record->ext_map);
						flow_record = (common_record_t *)((pointer_addr_t)flow_record + flow_record->size);	
						continue;
					} 
	
					master_record = &(extension_map_list->slot[map_id]->master_record);
					ExpandRecord_v2( flow_record, extension_map_list->slot[flow_record->ext_map], 
						exp_info ? &(exp_info->info) : NULL, master_record);

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
	
						if ( channels[j].xstat ) 
							UpdateXStat(channels[j].xstat, master_record);
	
						// do we need to write data to new file - shadow profiles do not have files.
						// check if we need to flush the output buffer
						if ( channels[j].nffile != NULL ) {
							// write record to output buffer
							AppendToBuffer(channels[j].nffile, (void *)flow_record, flow_record->size);
						} 
	
					} // End of for all channels
	
					} break;
				case ExtensionMapType: {
					extension_map_t *map = (extension_map_t *)flow_record;
	
					if ( Insert_Extension_Map(extension_map_list, map) ) {
						int j;
						for ( j=0; j < num_channels; j++ ) {
							if ( channels[j].nffile != NULL ) {
								// flush new map
								AppendToBuffer(channels[j].nffile, (void *)map, map->size);
							}
						}
					} // else map already known and flushed
	
					} break; 
				case ExporterInfoRecordType: {
					int ret = AddExporterInfo((exporter_info_record_t *)flow_record);
					if ( ret != 0 ) {
						int j;
						for ( j=0; j < num_channels; j++ ) {
							if ( channels[j].nffile != NULL && ret == 1) {
								// flush new exporter
								AppendToBuffer(channels[j].nffile, (void *)flow_record, flow_record->size);
							}
						}
					} else {
						LogError("Failed to add Exporter Record\n");
					}
					} break;
				case SamplerInfoRecordype: {
					int ret = AddSamplerInfo((sampler_info_record_t *)flow_record);
					if ( ret != 0 ) {
						int j;
						for ( j=0; j < num_channels; j++ ) {
							if ( channels[j].nffile != NULL && ret == 1 ) {
								// flush new map
								AppendToBuffer(channels[j].nffile, (void *)flow_record, flow_record->size);
							}
						}
					} else {
						LogError("Failed to add Sampler Record\n");
					}
					} break;
				case ExporterRecordType:
				case SamplerRecordype:
				case ExporterStatRecordType:
						// Silently skip exporter records
					break;
				default:  {
					LogError("Skip unknown record type %i\n", flow_record->type);
				}
			}
			// Advance pointer by number of bytes for netflow record
			flow_record = (common_record_t *)((pointer_addr_t)flow_record + flow_record->size);

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
		LogInfo("Process line '%s'\n", line);
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
char *rfile, *ffile, *filename, *Mdirs, *tstring;
char	*profile_datadir, *profile_statdir, *nameserver;
int c, syntax_only, subdir_index, stdin_profile_params, do_xstat;
time_t tslot;

	tstring 		= NULL;
	profile_datadir = NULL;
	profile_statdir = NULL;
	Mdirs 			= NULL;
	tslot 			= 0;
	syntax_only	    = 0;
	do_xstat	    = 0;
	compress		= 0;
	subdir_index	= 0;
	profile_list	= NULL;
	nameserver		= NULL;
	stdin_profile_params = 0;
	is_anonymized	= 0;

	strncpy(Ident, "none", IDENTLEN);
	Ident[IDENTLEN-1] = '\0';

	// default file names
	ffile = "filter.txt";
	rfile = NULL;
	while ((c = getopt(argc, argv, "D:HIL:p:P:hf:r:n:M:S:t:VzZ")) != EOF) {
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
			case 'H':
				do_xstat = 1;
				break;
			case 'L':
				if ( !InitLog("nfprofile", optarg) )
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
			case 'z':
				compress = 1;
				break;
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

	num_channels = InitChannels(profile_datadir, profile_statdir, profile_list, ffile, filename, subdir_index, syntax_only, compress, do_xstat);

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

	extension_map_list = InitExtensionMaps(NEEDS_EXTENSION_LIST);
	if ( !InitExporterList() ) {
		exit(255);
	}

	SetupInputFileSequence(Mdirs,rfile, NULL);

	process_data(GetChannelInfoList(), num_channels, tslot, do_xstat);

	CloseChannels(tslot, compress);

	FreeExtensionMaps(extension_map_list);

	return 0;
}
