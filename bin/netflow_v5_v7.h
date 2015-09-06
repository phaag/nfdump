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
 *  $Author: haag $
 *
 *  $Id: netflow_v5_v7.h 39 2009-11-25 08:11:15Z haag $
 *
 *  $LastChangedRevision: 39 $
 *	
 */

#ifndef _NETFLOW_V5_V7_H
#define _NETFLOW_V5_V7_H 1

#define NETFLOW_V5_HEADER_LENGTH 24
#define NETFLOW_V5_RECORD_LENGTH 48
#define NETFLOW_V5_MAX_RECORDS	 30

#define NETFLOW_V7_HEADER_LENGTH 24
#define NETFLOW_V7_RECORD_LENGTH 52
#define NETFLOW_V7_MAX_RECORDS   28

/* v5 structures */
typedef struct netflow_v5_header {
  uint16_t  version;
  uint16_t  count;
  uint32_t  SysUptime;
  uint32_t  unix_secs;
  uint32_t  unix_nsecs;
  uint32_t  flow_sequence;
  uint16_t	engine_tag;
  uint16_t  sampling_interval;
} netflow_v5_header_t;

typedef struct netflow_v5_record {
  uint32_t  srcaddr;
  uint32_t  dstaddr;
  uint32_t  nexthop;
  uint16_t  input;
  uint16_t  output;
  uint32_t  dPkts;
  uint32_t  dOctets;
  uint32_t  First;
  uint32_t  Last;
  uint16_t  srcport;
  uint16_t  dstport;
  uint8_t   pad1;
  uint8_t   tcp_flags;
  uint8_t   prot;
  uint8_t   tos;
  uint16_t  src_as;
  uint16_t  dst_as;
  uint8_t   src_mask;
  uint8_t   dst_mask;
  uint16_t  pad2;
} netflow_v5_record_t;


/* v7 structures */
typedef struct netflow_v7_header {
  uint16_t  version;
  uint16_t  count;
  uint32_t  SysUptime;
  uint32_t  unix_secs;
  uint32_t  unix_nsecs;
  uint32_t  flow_sequence;
  uint32_t  reserved;
} netflow_v7_header_t;

typedef struct netflow_v7_record {
  uint32_t  srcaddr;
  uint32_t  dstaddr;
  uint32_t  nexthop;
  uint16_t  input;
  uint16_t  output;
  uint32_t  dPkts;
  uint32_t  dOctets;
  uint32_t  First;
  uint32_t  Last;
  uint16_t  srcport;
  uint16_t  dstport;
  uint8_t   flags;
  uint8_t   tcp_flags;
  uint8_t   prot;
  uint8_t   tos;
  uint16_t  src_as;
  uint16_t  dst_as;
  uint8_t   src_mask;
  uint8_t   dst_mask;
  uint16_t  pad;
  uint32_t  router_sc;
} netflow_v7_record_t;

/* prototypes */
int Init_v5_v7_input(void);

void Process_v5_v7(void *in_buff, ssize_t in_buff_cnt, FlowSource_t *fs);

void Init_v5_v7_output(send_peer_t *peer);

int Add_v5_output_record(master_record_t *master_record, send_peer_t *peer);

/*
 * Extension map for v5/v7
 *
 * Required extensions:
 *
 *       4 byte byte counter
 *       | 4byte packet counter
 *       | | IPv4 
 *       | | |
 * xxxx x0 0 0
 *
 * Optional extensions:
 *
 * 4	: 2 byte input/output interface id
 * 6	: 2 byte src/dst as
 * 8	: srcmask/dst mask dst tos = 0, dir = 0
 * 9	: IPv4 next hop
 */

#endif //_NETFLOW_V5_V7_H
