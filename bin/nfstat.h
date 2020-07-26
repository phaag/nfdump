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

#ifndef _NFSTAT_H
#define _NFSTAT_H 1

#include "config.h"

#include <sys/types.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "output_util.h"
#include "output_fmt.h"
#include "nfx.h"
#include "nffile.h"

/*
typedef struct SortElement {
	void 		*record;
    uint64_t	count;
} SortElement_t;
*/

#define ASCENDING 1
#define DESCENDING 0

/* Function prototypes */
void SetLimits(int stat, char *packet_limit_string, char *byte_limit_string );

int Init_StatTable(void);

void Dispose_StatTable(void);

int SetStat(char *str, int *element_stat, int *flow_stat);

void AddElementStat(master_record_t *flow_record );

void PrintElementStat(stat_record_t	*sum_stat, outputParams_t *outputParams, printer_t print_record);

void PrintSortedFlows(printer_t print_record, uint32_t limitflows, int tag);

#endif //_NFSTAT_H
