/*
 *  Copyright (c) 2017-2024, Peter Haag
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

#ifndef _SFLOW_NFDUMP_H
#define _SFLOW_NFDUMP_H 1

#include <stdint.h>
#include <sys/types.h>

#include "collector.h"
#include "sflow_process.h"

int Init_sflow(int verbose, char *extensionList);

void Process_sflow(void *in_buff, ssize_t in_buff_cnt, FlowSource_t *fs, int parse_gre, int parse_6in4);

void StoreSflowRecord(SFSample *sample, FlowSource_t *fs);

/*
 * Extension map for sflow ( compatibility for now )
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
 */

#endif  // _SFLOW_NFDUMP_H
