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
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>

#include "nfdump.h"
#include "nffile.h"
#include "nfxV3.h"
#include "output_pipe.h"

#define IP_STRING_LEN (INET6_ADDRSTRLEN)

// record counter 
static uint32_t recordCount;

void pipe_prolog(bool quiet) {
	recordCount = 0;
} // End of pipe_prolog

void pipe_epilog(bool quiet) {
	// empty
} // End of pipe_epilog

void flow_record_to_pipe(FILE *stream, void *record, int tag) {
uint32_t	sa[4], da[4];
int			af;
master_record_t *r = (master_record_t *)record;

	// if this flow is a tunnel, add a flow line with the tunnel IPs
	if ( r->tun_ip_version ) {
		master_record_t _r = {0};
		_r.proto = r->tun_proto;
		memcpy((void *)_r.tun_src_ip.V6, r->tun_src_ip.V6, 16);
		memcpy((void *)_r.tun_dst_ip.V6, r->tun_dst_ip.V6, 16);
		_r.msecFirst  = r->msecFirst;
		_r.msecLast   = r->msecLast;
		if ( r->tun_ip_version == 6 )
			_r.mflags = V3_FLAG_IPV6_ADDR;
		flow_record_to_pipe(stream, (void *)&_r, tag);
	}

	if ( TestFlag(r->mflags, V3_FLAG_IPV6_ADDR ) != 0 ) {
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

	fprintf(stream, "%i|%llu|%llu|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%llu|%llu\n",
		af, (long long unsigned)r->msecFirst, (long long unsigned)r->msecLast, r->proto, 
		sa[0], sa[1], sa[2], sa[3], r->srcPort, da[0], da[1], da[2], da[3], r->dstPort, 
		r->srcas, r->dstas, r->input, r->output,
		r->tcp_flags, r->tos, (unsigned long long)r->inPackets, (unsigned long long)r->inBytes);

} // End of flow_record_to_pipe
