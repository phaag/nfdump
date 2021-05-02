/*
 *  Copyright (c) 2016, Peter Haag
 *  Copyright (c) 2014, Peter Haag
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

#ifndef _PCAPROC_H
#define _PCAPROC_H 1

#ifdef HAVE_CONFIG_H 
#include "config.h"
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <time.h>
#include <pthread.h>
#include <pcap.h>

#include "collector.h"
#include "packet_pcap.h"

typedef struct pcapfile_s {
	void			*data_buffer;
	void			*data_ptr;
	uint32_t		data_size;
	void			*alternate_buffer;
	uint32_t		alternate_size;
	int				pfd;
	time_t			t_CloseRename;
	pcap_dumper_t	*pd;
	pcap_t 			*p;
	pthread_mutex_t m_pbuff;
	pthread_cond_t  c_pbuff;
} pcapfile_t;

pcapfile_t *OpenNewPcapFile(pcap_t *p, char *filename, pcapfile_t *pcapfile);

int ClosePcapFile(pcapfile_t *pcapfile);

void RotateFile(pcapfile_t *pcapfile, time_t t_CloseRename, int live);

void ProcessFlowNode(FlowSource_t *fs, struct FlowNode *node);

void ProcessPacket(packetParam_t *packetParam, const struct pcap_pkthdr *hdr, const u_char *data);

#endif // _PCAPROC_H
