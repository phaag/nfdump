/*
 *  Copyright (c) 2014-2023, Peter Haag
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

#ifdef FIX_INCLUDE
#include <sys/types.h>
#endif
#include <stdint.h>

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif
#ifdef HAVE_NET_ETHERTYPES_H
#include <net/ethertypes.h>
#endif

#include <pcap.h>
#include <pthread.h>
#include <time.h>

#include "collector.h"
#include "packet_pcap.h"

// define potential missing types
#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL 113
#endif

#ifndef DLT_NFLOG
#define DLT_NFLOG 239
#endif

#ifndef DLT_PFLOG
#define DLT_PFLOG 117
#endif

#ifndef ETHERTYPE_TRANSETHER
#define ETHERTYPE_TRANSETHER 0x6558
#endif

#ifndef ETHERTYPE_MPLS
#define ETHERTYPE_MPLS 0x8847
#endif

#ifndef ETHERTYPE_PPPOE
#define ETHERTYPE_PPPOE 0x8864
#endif

#ifndef ETHERTYPE_PPPOEDISC
#define ETHERTYPE_PPPOEDISC 0x8863
#endif

#ifndef ETHERTYPE_LLDP
#define ETHERTYPE_LLDP 0x88CC
#endif

#ifndef ETHERTYPE_LOOPBACK
#define ETHERTYPE_LOOPBACK 0x9000
#endif

#define PROTO_ERSPAN 0x88be

typedef struct pcapfile_s {
    void *data_buffer;
    void *data_ptr;
    uint32_t data_size;
    void *alternate_buffer;
    uint32_t alternate_size;
    int pfd;
    time_t t_CloseRename;
    pcap_dumper_t *pd;
    pcap_t *p;
    pthread_mutex_t m_pbuff;
    pthread_cond_t c_pbuff;
} pcapfile_t;

pcapfile_t *OpenNewPcapFile(pcap_t *p, char *filename, pcapfile_t *pcapfile);

int ClosePcapFile(pcapfile_t *pcapfile);

void RotateFile(pcapfile_t *pcapfile, time_t t_CloseRename, int live);

void ProcessFlowNode(FlowSource_t *fs, struct FlowNode *node);

void ProcessPacket(packetParam_t *packetParam, const struct pcap_pkthdr *hdr, const u_char *data);

#endif  // _PCAPROC_H
