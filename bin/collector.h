/*
 *  Copyright (c) 2009-2019, Peter Haag
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
 */

#ifndef _COLLECTOR_H
#define _COLLECTOR_H 1

#include "config.h"

#include <sys/types.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <sys/socket.h>

#include "exporter.h"
#include "bookkeeper.h"
#include "nffile.h"

#define FNAME_SIZE  256

typedef struct FlowSource_s {
	// link
	struct FlowSource_s *next;

	// exporter identifiers
	char 				Ident[IDENTLEN];
	ip_addr_t			ip;
	uint32_t			sa_family;

	int					any_source;
	bookkeeper_t 		*bookkeeper;

	// all about data storage
	char				*datadir;		// where to store data for this source
	char				*current;		// current file name - typically nfcad.current.pid
	nffile_t			*nffile;		// the writing file handle

	// statistical data per source
	uint32_t			bad_packets;
	uint64_t			first_seen;		// in msec 
	uint64_t			last_seen;		// in msec

	// Any exporter specific data
	exporter_t			*exporter_data;
	uint32_t			exporter_count;
	struct timeval		received;

	// extension map list
	struct {
#define BLOCK_SIZE	16
		int	next_free;
		int	max_maps;
		int num_maps;
		extension_map_t	**maps;
	} extension_map_list;

} FlowSource_t;

/* input buffer size, to read data from the network */
#define NETWORK_INPUT_BUFF_SIZE 65535	// Maximum UDP message size

// prototypes
int AddFlowSource(FlowSource_t **FlowSource, char *ident);

int AddDefaultFlowSource(FlowSource_t **FlowSource, char *ident, char *path);

int SetDynamicSourcesDir(FlowSource_t **FlowSource, char *dir);

FlowSource_t *AddDynamicSource(FlowSource_t **FlowSource, struct sockaddr_storage *ss);

int InitExtensionMapList(FlowSource_t *fs);

int ReInitExtensionMapList(FlowSource_t *fs);

int RemoveExtensionMap(FlowSource_t *fs, extension_map_t *map);

int AddExtensionMap(FlowSource_t *fs, extension_map_t *map);

void FlushStdRecords(FlowSource_t *fs);

void FlushExporterStats(FlowSource_t *fs);

int FlushInfoExporter(FlowSource_t *fs, exporter_info_record_t *exporter);

int FlushInfoSampler(FlowSource_t *fs, sampler_info_record_t *sampler);

/* Default time window in seconds to rotate files */
#define TIME_WINDOW	  	300

/* overdue time: 
 * if nfcapd does not get any data, wake up the receive system call
 * at least after OVERDUE_TIME seconds after the time window
 */
#define OVERDUE_TIME	10

// time nfcapd will wait for launcher to terminate
#define LAUNCHER_TIMEOUT 60

#define SYSLOG_FACILITY "daemon"

#endif //_COLLECTOR_H
