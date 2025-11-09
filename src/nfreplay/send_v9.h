/*
 *  Copyright (c) 2022-2024, Peter Haag
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

#ifndef _SEND_V9_H
#define _SEND_V5_H 1

#include "nfdump.h"
#include "send_net.h"

#define NF_F_FLOW_CREATE_TIME_MSEC 152
#define NF_F_FLOW_END_TIME_MSEC 153

#define NF9_IN_BYTES 1
#define NF9_IN_PACKETS 2
#define NF9_FLOWS_AGGR 3
#define NF9_IN_PROTOCOL 4
#define NF9_SRC_TOS 5
#define NF9_TCP_FLAGS 6
#define NF9_L4_SRC_PORT 7
#define NF9_IPV4_SRC_ADDR 8
#define NF9_SRC_MASK 9
#define NF9_INPUT_SNMP 10
#define NF9_L4_DST_PORT 11
#define NF9_IPV4_DST_ADDR 12
#define NF9_DST_MASK 13
#define NF9_OUTPUT_SNMP 14
#define NF9_V4_NEXT_HOP 15
#define NF9_SRC_AS 16
#define NF9_DST_AS 17
#define NF9_BGP_V4_NEXT_HOP 18

#define NF9_LAST_SWITCHED 21
#define NF9_FIRST_SWITCHED 22
#define NF9_OUT_BYTES 23
#define NF9_OUT_PKTS 24

#define NF9_IPV6_SRC_ADDR 27
#define NF9_IPV6_DST_ADDR 28
#define NF9_IPV6_SRC_MASK 29
#define NF9_IPV6_DST_MASK 30
#define NF9_IPV6_FLOW_LABEL 31
#define NF9_ICMP 32

#define NF9_ENGINE_TYPE 38
#define NF9_ENGINE_ID 39

#define NF9_DST_TOS 55
#define NF9_IN_SRC_MAC 56
#define NF9_OUT_DST_MAC 57
#define NF9_SRC_VLAN 58
#define NF9_DST_VLAN 59
#define NF_9_IP_PROTOCOL_VERSION 60
#define NF9_DIRECTION 61
#define NF9_V6_NEXT_HOP 62
#define NF9_BPG_V6_NEXT_HOP 63

#define NF9_MPLS_LABEL_1 70
#define NF9_MPLS_LABEL_2 71
#define NF9_MPLS_LABEL_3 72
#define NF9_MPLS_LABEL_4 73
#define NF9_MPLS_LABEL_5 74
#define NF9_MPLS_LABEL_6 75
#define NF9_MPLS_LABEL_7 76
#define NF9_MPLS_LABEL_8 77
#define NF9_MPLS_LABEL_9 78
#define NF9_MPLS_LABEL_10 79
#define NF9_IN_DST_MAC 80
#define NF9_OUT_SRC_MAC 81

#define NF9_FORWARDING_STATUS 89

#define NF_F_BGP_ADJ_NEXT_AS 128
#define NF_F_BGP_ADJ_PREV_AS 129

#define NF_F_dot1qVlanId 243
#define NF_F_postDot1qVlanId 254
#define NF_F_dot1qCustomerVlanId 245
#define NF_F_postDot1qCustomerVlanId 255

#define NF_F_ingressPhysicalInterface 252
#define NF_F_egressPhysicalInterface 253

int Init_v9_output(send_peer_t *peer);

int Close_v9_output(send_peer_t *peer);

int Add_v9_output_record(recordHandle_t *recordHandle, send_peer_t *peer);

#endif  // _SEND_V9_H