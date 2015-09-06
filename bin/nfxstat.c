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
 *  $Id: nfxstat.c 25 2011-02-26 13:22:31Z peter $
 *
 *  $LastChangedRevision: 25 $
 *	
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifndef DEVEL
#   define dbg_printf(...) /* printf(__VA_ARGS__) */
#else
#   define dbg_printf(...) printf(__VA_ARGS__)
#endif

#include "util.h"
#include "nf_common.h"
#include "nffile.h"
#include "nfxstat.h"


xstat_t *InitXStat(nffile_t *nffile) {
xstat_t	*xs;
size_t	block_size;

	// extended by the record link 2*data[4], but does no harm
	block_size = sizeof(xstat_t) + sizeof(data_block_header_t) + sizeof(flow_port_histogram_t) + sizeof(flow_bpp_histogram_t); 

	xs = (xstat_t *)malloc(block_size);
	if ( !xs ) {
		LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return NULL;
	}

	xs->block_header = (data_block_header_t *)((pointer_addr_t)xs + sizeof(xstat_t));
	// preset the fields
	xs->block_header->NumRecords = 2;	// 2 histogram records are included
	xs->block_header->size 		 = block_size;
	xs->block_header->id 		 = Large_BLOCK_Type;
	xs->block_header->flags 	 = 0;

	xs->port_histogram = (flow_port_histogram_t *)((pointer_addr_t)xs + sizeof(xstat_t) + sizeof(data_block_header_t));
	xs->bpp_histogram  = (flow_bpp_histogram_t *)((pointer_addr_t)xs + sizeof(xstat_t) + sizeof(data_block_header_t) + sizeof(flow_port_histogram_t) - 4); // without link pointer data[4]

	// XXX add catalog entry
	// SetFlag(nffile->file_header->flags, FLAG_EXTENDED_STATS);

	ResetPortHistogram(xs->port_histogram);
	ResetBppHistogram(xs->bpp_histogram);

	return xs;

} // End of InitXStat

void ResetPortHistogram(flow_port_histogram_t *port_histogram) {

	memset((void *)port_histogram, 0, sizeof(flow_port_histogram_t) - 4); // without link pointer data[4]
	port_histogram->record_header.type	= PortHistogramType;
	port_histogram->record_header.size	= sizeof(flow_port_histogram_t) - 4;
	
} // End of ResetPortHistogram

void ResetBppHistogram(flow_bpp_histogram_t *bpp_histogram) {

	memset((void *)bpp_histogram, 0, sizeof(bpp_histogram_t) - 4); // without link pointer data[4]
	bpp_histogram->record_header.type	= BppHistogramType;
	bpp_histogram->record_header.size	= sizeof(flow_port_histogram_t) - 4;
	
} // End of ResetBppHistogram

