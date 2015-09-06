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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGE.
 * 
 * $Author: haag $
 *
 * $Id: nfstatfile.h 39 2009-11-25 08:11:15Z haag $
 *
 * $LastChangedRevision: 39 $
 * 
 */

#ifndef _NFSTATFILE_H
#define _NFSTATFILE_H 1

typedef struct dirstat_s {
	uint64_t	first;		// for more easy parsing and assigning, take a uint64_t also for the time_t type
	uint64_t	last;
	uint64_t	numfiles;
	uint64_t	filesize;
	uint64_t	max_size;
	uint64_t	max_lifetime;
	uint64_t	low_water;
	uint64_t	status;
} dirstat_t;

typedef struct dirstat_env_s {
	dirstat_t	*dirstat;
	int			fd;
	char		*filename;
	int			index;
} dirstat_env_t;

enum { STATFILE_OK = 0, ERR_FAIL, ERR_NOSTATFILE, FORCE_REBUILD };

#define READ_ONLY	0
#define CREATE_AND_LOCK	1
#define LOCK_IF_EXISTS	2

#define stat_filename ".nfstat"

char *ScaleValue(uint64_t v);

char *ScaleTime(uint64_t v);

void PrintDirStat(dirstat_t *dirstat);

int ReadStatInfo(char *dirname, dirstat_t **dirstat_p, int lock );

int WriteStatInfo(dirstat_t *dirstat);

int ReleaseStatInfo(dirstat_t *dirstat);

#endif //_NFSTATFILE_H
