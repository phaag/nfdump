/*
 *  Copyright (c) 2012-2019, Peter Haag
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

#ifndef _EXPORTER_H
#define _EXPORTER_H 1

#include "config.h"

#include <sys/types.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nffile.h"

typedef struct optionTag_s {
	uint16_t offset;
	uint16_t length;
} optionTag_t;

typedef struct samplerOption_s {
	struct samplerOption_s *next;
	uint32_t	tableID;	// table id
#define STDSAMPLING34	1
#define STDSAMPLING35	2
#define STDMASK			0x3
#define STDFLAGS		0x3

#define SAMPLER302		4
#define SAMPLER304		8
#define SAMPLER305		16
#define SAMPLERMASK		0x1C
#define SAMPLERFLAGS	0x1C

	uint32_t	flags;		// info about this map

	// sampling offset/length values
	optionTag_t id;
	optionTag_t mode;
	optionTag_t interval;

} samplerOption_t;

typedef struct sampler_s {
	struct sampler_s *next;
	sampler_info_record_t	info;	// sampler record nffile
} sampler_t;

typedef struct exporter_s {
	// linked chain
	struct exporter_s *next;

	// exporter information
	exporter_info_record_t info;	// exporter record nffile

	uint64_t	packets;			// number of packets sent by this exporter
	uint64_t	flows;				// number of flow records sent by this exporter
	uint32_t	sequence_failure;	// number of sequence failues
	uint32_t	padding_errors;		// number of sequence failues

	sampler_t *sampler;				// list of samplers associated with this exporter

} exporter_t;

int InitExporterList(void);

int AddExporterInfo(exporter_info_record_t *exporter_record);

int AddSamplerInfo(sampler_info_record_t *sampler_record);

int AddExporterStat(exporter_stats_record_t *stat_record);

void ExportExporterList( nffile_t *nffile );

void PrintExporters(char *filename);

#endif //_EXPORTER_H

