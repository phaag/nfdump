/*
 *  Copyright (c) 2019-2021, Peter Haag
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
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nfdump.h"
#include "nffile.h"
#include "nfx.h"
#include "output_pipe.h"

#define STRINGSIZE 10240
#define IP_STRING_LEN (INET6_ADDRSTRLEN)

static char data_string[STRINGSIZE];

// record counter 
static uint32_t recordCount;

void pipe_prolog(bool quiet) {
	recordCount = 0;
	memset(data_string, 0, STRINGSIZE);
} // End of pipe_prolog

void pipe_epilog(bool quiet) {
	// empty
} // End of pipe_epilog

void flow_record_to_pipe(void *record, char ** s, int tag) {
uint32_t	sa[4], da[4];
int			af;
master_record_t *r = (master_record_t *)record;

	if ( (r->flags & FLAG_IPV6_ADDR ) != 0 ) { // IPv6
		af = PF_INET6;
	} else {	// IPv4
		af = PF_INET;
	}

	// Make sure Endian does not screw us up
    sa[0] = ( r->V6.srcaddr[0] >> 32 ) & 0xffffffffLL;
    sa[1] = r->V6.srcaddr[0] & 0xffffffffLL;
    sa[2] = ( r->V6.srcaddr[1] >> 32 ) & 0xffffffffLL;
    sa[3] = r->V6.srcaddr[1] & 0xffffffffLL;

    da[0] = ( r->V6.dstaddr[0] >> 32 ) & 0xffffffffLL;
    da[1] = r->V6.dstaddr[0] & 0xffffffffLL;
    da[2] = ( r->V6.dstaddr[1] >> 32 ) & 0xffffffffLL;
    da[3] = r->V6.dstaddr[1] & 0xffffffffLL;

	snprintf(data_string, STRINGSIZE-1 ,"%i|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%llu|%llu",
		af, r->first, r->msec_first ,r->last, r->msec_last, r->prot, 
		sa[0], sa[1], sa[2], sa[3], r->srcport, da[0], da[1], da[2], da[3], r->dstport, 
		r->srcas, r->dstas, r->input, r->output,
		r->tcp_flags, r->tos, (unsigned long long)r->dPkts, (unsigned long long)r->dOctets);

	data_string[STRINGSIZE-1] = 0;

	*s = data_string;

} // End of flow_record_to_pipe
