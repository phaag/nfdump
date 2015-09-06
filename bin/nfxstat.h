/*
 *  Copyright (c) 2014, Peter Haag
 *  Copyright (c) 2011, Peter Haag
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
 *  $Author: peter $
 *
 *  $Id: nfxstat.h 25 2011-02-26 13:22:31Z peter $
 *
 *  $LastChangedRevision: 25 $
 *	
 */


typedef struct port_histogram_s {
	uint32_t	count;
	uint32_t	port[65536];
} port_histogram_t;

typedef struct bpp_histogram_s {
	uint32_t	count;
#define MAX_BPP 9000
	uint32_t	bpp[MAX_BPP];
} bpp_histogram_t;

typedef struct flow_port_histogram_s {
	// type = PortHistogramType
	L_record_header_t record_header;
	port_histogram_t src_tcp;
	port_histogram_t dst_tcp;
	port_histogram_t src_udp;
	port_histogram_t dst_udp;
	uint8_t		data[4];	// .. more data below
} flow_port_histogram_t;

typedef struct flow_bpp_histogram_s {
	// type = BppHistogramType
	L_record_header_t record_header;
	bpp_histogram_t tcp;
	bpp_histogram_t udp;
	uint8_t		data[4];	// .. more data below
} flow_bpp_histogram_t;

// Extended stat record
typedef struct xstat_s {
	data_block_header_t   *block_header;
	flow_port_histogram_t *port_histogram;
	flow_bpp_histogram_t  *bpp_histogram;
} xstat_t;


xstat_t *InitXStat(nffile_t *nffile);

void ResetPortHistogram(flow_port_histogram_t *port_histogram);

void ResetBppHistogram(flow_bpp_histogram_t *bpp_histogram);


