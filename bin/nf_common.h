/*
 *  Copyright (c) 2009-2019, Peter Haag
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

#ifndef _NF_COMMON_H
#define _NF_COMMON_H 1

#include "config.h"

#include <sys/types.h>
#include <time.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

typedef void (*printer_t)(void *, char **, int);
typedef void (*func_prolog_t)(void);
typedef void (*func_epilog_t)(void);

typedef struct msec_time_s {
	time_t		sec;
	uint16_t	msec;
} msec_time_tt;

/* common minimum netflow header for all versions */
typedef struct common_flow_header {
  uint16_t  version;
  uint16_t  count;
} common_flow_header_t;

typedef struct printmap_s {
	char		  *printmode;	// name of the output format
	printer_t	  func_record;			// prints the record
	func_prolog_t func_prolog;	// prints the output prolog
	func_epilog_t func_epilog;	// prints the output epilog
	char		  *Format;		// output format definition
} printmap_t;

#define NSEL_EVENT_IGNORE 0LL
#define NSEL_EVENT_CREATE 1LL
#define NSEL_EVENT_DELETE 2LL
#define NSEL_EVENT_DENIED 3LL
#define NSEL_EVENT_ALERT  4LL
#define NSEL_EVENT_UPDATE 5LL

#define NEL_EVENT_INVALID 0LL
#define NEL_EVENT_ADD	  1LL
#define NEL_EVENT_DELETE  2LL

/* prototypes */

void Setv6Mode(int mode);

int Getv6Mode(void);

int Proto_num(char *protostr);

void text_prolog(void);

void text_epilog(void);

void format_file_block_record(void *record, char **s, int tag);

void flow_record_to_null(void *record, char ** s, int tag);

int ParseOutputFormat(char *format, int plain_numbers, printmap_t *printmap);

void format_special(void *record, char ** s, int tag);

void Proto_string(uint8_t protonum, char *protostr);

void condense_v6(char *s);

#define TAG_CHAR ''

#endif //_NF_COMMON_H

