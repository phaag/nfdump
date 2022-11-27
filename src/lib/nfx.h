/*
 *  Copyright (c) 2009-2020, Peter Haag
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

#ifndef _NFX_H
#define _NFX_H 1

#include <sys/types.h>

#include "config.h"
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "id.h"
#include "nffile.h"

// MAX_EXTENSION_MAPS must be a power of 2
#define MAX_EXTENSION_MAPS 65536
#define EXTENSION_MAP_MASK (MAX_EXTENSION_MAPS - 1)

#ifdef NSEL
// Defaults for NSEL
#define DefaultExtensions "1,8,26,27,28,29,30,31"
#else
// Collector netflow defaults
#define DefaultExtensions "1,2"
#endif

#define NEEDS_EXTENSION_LIST 1
#define NO_EXTENSION_LIST 0

/*
* All records are 32bit aligned and layouted in a 64bit array. The numbers placed in () refer to the netflow v9 type id.
*
* Record type 1
* =============
* The record type 1 describes a netflow data record incl. all optional extensions for this record.
* A netflow data record requires at least the first 3 extensions 1..3. All other extensions are optional
* and described in the extensiion map. The common record contains a reference to the extension map which
* applies for this record.
*
* flags:
* bit  0:	0: IPv4				 1: IPv6
* bit  1:	0: 32bit dPkts		 1: 64bit dPkts
* bit  2:	0: 32bit dOctets	 1: 64bit dOctets
* bit  3:  0: IPv4 next hop     1: IPv6 next hop
* bit  4:  0: IPv4 BGP next hop 1: BGP IPv6 next hop
* bit  5:  0: IPv4 exporter IP  1: IPv6 exporter IP
* bit  6:  0: flow              1: event
* bit  7:  0: unsampled         1: sampled flow - sampling applied
*
* Required extensions: 1,2,3
* ------------------------------
* A netflow record consists at least of a common record ( extension 0 ) and 3  required extension:
*
* Extension 1: IPv4 or IPv4 src and dst addresses	Flags bit 0: 0: IPv4,  1: IPv6
* Extension 2: 32 or 64 bit packet counter         Flags bit 1: 0: 32bit, 1: 64bit
* Extension 3: 32 or 64 bit byte counter           Flags bit 2: 0: 32bit, 1: 64bit
*
* Commmon record - extension 0
* +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
* |  - |       0      |      1       |      2       |      3       |      4       |      5       |      6       |      7       |
* +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
* |  0 |         record type == 1    |             size            |    flags     |    tag       |           ext. map          |
* +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
* |  1 |          msec_first         |           msec_last         |                          first (22)                       |
* +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
* |  2 |                          last (21)                        |fwd_status(89)| tcpflags (6) |  proto (4)   |  src tos (5) |
* +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
* |  3 |           srcPort (7)       |   dstPort(11)/ICMP (32)     |
* +----+--------------+--------------+--------------+--------------+
*
* Commmon record - extension 0 - Type 10
* required for larger exporter ID reference
* +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
* |  - |       0      |      1       |      2       |      3       |      4       |      5       |      6       |      7       |
* +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
* |  0 |         record type == 10   |             size            |            flags            |           ext. map          |
* +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
* |  1 |          msec_first         |           msec_last         |                          first (22)                       |
* +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
* |  2 |                          last (21)                        |fwd_status(89)| tcpflags (6) |  proto (4)   |  src tos (5) |
* +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
* |  3 |           srcPort (7)       |   dstPort(11)/ICMP (32)     |          exporter ID        |  reserved icmp type/code    |
* +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+

*
*/

#define COMMON_BLOCK_ID 0

typedef struct common_record_s {
    // record head
    uint16_t type;
    uint16_t size;

    // record meta data
    uint16_t flags;
#define FLAG_IPV6_ADDR 1
#define FLAG_PKG_64 2
#define FLAG_BYTES_64 4
#define FLAG_IPV6_NH 8
#define FLAG_IPV6_NHB 16
#define FLAG_IPV6_EXP 32
#define FLAG_EVENT 64
#define FLAG_SAMPLED 128

    uint16_t ext_map;

    // netflow common record
    uint16_t msec_first;
    uint16_t msec_last;
#define BYTE_OFFSET_first 12
    uint32_t first;
    uint32_t last;

    uint8_t fwd_status;
    uint8_t tcp_flags;
    uint8_t prot;
    uint8_t tos;
    uint16_t srcPort;
    uint16_t dstPort;

    uint16_t exporter_sysid;
    uint8_t biFlowDir;
    uint8_t flowEndReason;

    // link to extensions
    uint32_t data[1];
} common_record_t;

#define COMMON_BLOCK 0

/*
 * Required extensions:
 * --------------------
 * Extension 1:
 * IPv4/v6 address type
 *                IP version: IPv4
 *                |
 * Flags: xxxx xxx0
 * IPv4:
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                           srcip (8)                       |                           dstip (12)                      |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 *
 * IPv6:
 *                IP version: IPv6
 *                |
 * Flags: xxxx xxx1
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                                         srcip (27)                                                    |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |                                                         srcip (27)                                                    |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  2 |                                                         dstip (28)                                                    |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  3 |                                                         dstip (28)                                                    |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 *
 */

#define EX_IPv4v6 1

typedef struct ipv4_block_s {
    uint32_t srcaddr;
    uint32_t dstaddr;
    uint8_t data[4];  // .. more data below
} ipv4_block_t;

typedef struct ipv6_block_s {
    uint64_t srcaddr[2];
    uint64_t dstaddr[2];
    uint8_t data[4];  // .. more data below
} ipv6_block_t;

/*
 * Extension 2:
 * In packet counter size
 *
 *               In packet counter size 4byte
 *               |
 * Flags: xxxx xx0x
 * +---++--------------+--------------+--------------+--------------+
 * |  0 |                         in pkts (2)                       |
 * +---++--------------+--------------+--------------+--------------+
 *
 *               In packet counter size 8byte
 *               |
 * Flags: xxxx xx1x
 * +---++--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                                       in pkts (2)                                                     |
 * +---++--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 *
 */

#define EX_PACKET_4_8 2

typedef struct value32_s {
    uint32_t val;
    uint8_t data[4];  // .. more data below
} value32_t;

typedef struct value64_s {
    union val_s {
        uint64_t val64;
        uint32_t val32[2];
    } val;
    uint8_t data[4];  // .. more data below
} value64_t;

/* Extension 3:
 * in byte counter size
 *              In byte counter size 4byte
 *              |
 * Flags: xxxx x0xx
 *
 * +---++--------------+--------------+--------------+--------------+
 * |  0 |                        in bytes (1)                       |
 * +---++--------------+--------------+--------------+--------------+
 *
 *              In byte counter size 8byte
 *              |
 * Flags: xxxx x1xx
 * +---++--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                                        in bytes (1)                                                   |
 * +---++--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */

#define EX_BYTE_4_8 3

/*
 *
 * Optional extension:
 * ===================
 *
 * Interface record
 * ----------------
 * Interface records are optional and accepted as either 2 or 4 bytes numbers
 * Extension 4:
 * +---++--------------+--------------+--------------+--------------+
 * |  0 |            input (10)       |            output (14)      |
 * +---++--------------+--------------+--------------+--------------+
 */
#define EX_IO_SNMP_2 4
typedef struct tpl_ext_4_s {
    uint16_t input;
    uint16_t output;
    uint8_t data[4];  // points to further data
} tpl_ext_4_t;

/*
 * Extension 5:
 * +---++--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                           input (10)                      |                           output (14)                     |
 * +---++--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * Extension 4 and 5 are mutually exclusive in the extension map
 */
#define EX_IO_SNMP_4 5
typedef struct tpl_ext_5_s {
    uint32_t input;
    uint32_t output;
    uint8_t data[4];  // points to further data
} tpl_ext_5_t;

/*
 * AS record
 * ---------
 * AS records are optional and accepted as either 2 or 4 bytes numbers
 * Extension 6:
 * +---++--------------+--------------+--------------+--------------+
 * |  0 |            src as (16)      |            dst as (17)      |
 * +---++--------------+--------------+--------------+--------------+
 */
#define EX_AS_2 6
typedef struct tpl_ext_6_s {
    uint16_t src_as;
    uint16_t dst_as;
    uint8_t data[4];  // points to further data
} tpl_ext_6_t;

/*
 * Extension 7:
 * +---++--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                         src as (16)                       |                          dst as (17)                      |
 * +---++--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * Extension 6 and 7 are mutually exclusive in the extension map
 */
#define EX_AS_4 7
typedef struct tpl_ext_7_s {
    uint32_t src_as;
    uint32_t dst_as;
    uint8_t data[4];  // points to further data
} tpl_ext_7_t;

/*
 * Multiple fields record
 * ----------------------
 * These 4 different fields are grouped together in a 32bit value.
 * Extension 8:
 * +---++--------------+--------------+--------------+--------------+
 * |  3 |  dst tos(55) |   dir(61)    | srcmask(9,29)|dstmask(13,30)|
 * +---++--------------+--------------+--------------+--------------+
 */
#define EX_MULIPLE 8
typedef struct tpl_ext_8_s {
    union {
        struct {
            uint8_t dst_tos;
            uint8_t dir;
            uint8_t src_mask;
            uint8_t dst_mask;
        };
        uint32_t any;
    };
    uint8_t data[4];  // points to further data
} tpl_ext_8_t;

/*
 * IP next hop
 * -------------
 * IPv4:
 * Extension 9:
 *             IP version: IPv6
 *             |
 * Flags: xxxx 0xxx
 * +----+--------------+--------------+--------------+--------------+
 * |  0 |                       next hop ip (15)                    |
 * +----+--------------+--------------+--------------+--------------+
 */
#define EX_NEXT_HOP_v4 9
typedef struct tpl_ext_9_s {
    uint32_t nexthop;
    uint8_t data[4];  // points to further data
} tpl_ext_9_t;

/*
 * IPv6:
 * Extension 10:
 *             IP version: IPv6
 *             |
 * Flags: xxxx 1xxx
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                                     next hop ip (62)                                                  |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |                                                     next hop ip (62)                                                  |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * Extension 9 and 10 are mutually exclusive in the extension map
 */
#define EX_NEXT_HOP_v6 10
typedef struct tpl_ext_10_s {
    uint64_t nexthop[2];
    uint8_t data[4];  // points to further data
} tpl_ext_10_t;

/*
 * BGP next hop IP
 * ------------------
 * IPv4:
 * Extension 11:
 *           IP version: IPv6
 *           |
 * Flags: xxx0 xxxx
 * +----+--------------+--------------+--------------+--------------+
 * |  0 |                       bgp next ip (18)                    |
 * +----+--------------+--------------+--------------+--------------+
 */
#define EX_NEXT_HOP_BGP_v4 11
typedef struct tpl_ext_11_s {
    uint32_t bgp_nexthop;
    uint8_t data[4];  // points to further data
} tpl_ext_11_t;

/*
 * IPv6:
 * Extension 12:
 *           IP version: IPv6
 *           |
 * Flags: xxx1 xxxx
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                                     bgp next ip (63)                                                  |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |                                                     bgp next ip (63)                                                  |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */
#define EX_NEXT_HOP_BGP_v6 12
typedef struct tpl_ext_12_s {
    uint64_t bgp_nexthop[2];
    uint8_t data[4];  // points to further data
} tpl_ext_12_t;

/*
 * VLAN record
 * -----------
 * Extension 13:
 * +----+--------------+--------------+--------------+--------------+
 * |  0 |           src vlan(58)      |          dst vlan (59)      |
 * +----+--------------+--------------+--------------+--------------+
 */
#define EX_VLAN 13
typedef struct tpl_ext_13_s {
    uint16_t src_vlan;
    uint16_t dst_vlan;
    uint8_t data[4];  // points to further data
} tpl_ext_13_t;

/*
 * Out packet counter size
 * ------------------------
 * 4 byte
 * Extension 14:
 * +----+--------------+--------------+--------------+--------------+
 * |  0 |                        out pkts (24)                      |
 * +----+--------------+--------------+--------------+--------------+
 */
#define EX_OUT_PKG_4 14
typedef struct tpl_ext_14_s {
    uint32_t out_pkts;
    uint8_t data[4];  // points to further data
} tpl_ext_14_t;

/*
 * 4 byte
 * Extension 15:
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                                      out pkts (24)                                                    |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * Extension 14 and 15 are mutually exclusive in the extension map
 */
#define EX_OUT_PKG_8 15
typedef struct tpl_ext_15_s {
    union {
        uint64_t out_pkts;
        uint32_t v[2];  // for strict alignment use 2x32bits
    };
    uint8_t data[4];  // points to further data
} tpl_ext_15_t;

/*
 * Out byte counter size
 * ---------------------
 * 4 byte
 * Extension 16:
 * +----+--------------+--------------+--------------+--------------+
 * |  0 |                        out bytes (23)                     |
 * +----+--------------+--------------+--------------+--------------+
 */
#define EX_OUT_BYTES_4 16
typedef struct tpl_ext_16_s {
    uint32_t out_bytes;
    uint8_t data[4];  // points to further data
} tpl_ext_16_t;

/* 8 byte
 * Extension 17:
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                                      out bytes (23)                                                   |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * Extension 16 and 17 are mutually exclusive in the extension map
 */
#define EX_OUT_BYTES_8 17
typedef struct tpl_ext_17_s {
    union {
        uint64_t out_bytes;
        uint32_t v[2];  // potential 32bit alignment
    };
    uint8_t data[4];  // points to further data
} tpl_ext_17_t;

/*
 * Aggr flows
 * ----------
 * 4 byte
 * Extension 18:
 * +----+--------------+--------------+--------------+--------------+
 * |  0 |                        aggr flows (3)                     |
 * +----+--------------+--------------+--------------+--------------+
 */
#define EX_AGGR_FLOWS_4 18
typedef struct tpl_ext_18_s {
    uint32_t aggr_flows;
    uint8_t data[4];  // points to further data
} tpl_ext_18_t;

/* 8 byte
 * Extension 19:
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                                      aggr flows (3)                                                   |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * Extension 18 and 19 are mutually exclusive in the extension map
 */
#define EX_AGGR_FLOWS_8 19
typedef struct tpl_ext_19_s {
    union {
        uint64_t aggr_flows;
        uint32_t v[2];  // 32bit alignment
    };
    uint8_t data[4];  // points to further data
} tpl_ext_19_t;

/* 16 byte
 * Extension 20:
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |              0              |                                     in src mac (56)                                     |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |              0              |                                     out dst mac (57)                                    |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */
#define EX_MAC_1 20
typedef struct tpl_ext_20_s {
    union {
        uint64_t in_src_mac;
        uint32_t v1[2];
    };
    union {
        uint64_t out_dst_mac;
        uint32_t v2[2];
    };
    uint8_t data[4];  // points to further data
} tpl_ext_20_t;

/* 16 byte
 * Extension 21:
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |              0              |                                     in dst mac (80)                                     |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |              0              |                                     out src mac (81)                                    |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */
#define EX_MAC_2 21
typedef struct tpl_ext_21_s {
    union {
        uint64_t in_dst_mac;
        uint32_t v1[2];
    };
    union {
        uint64_t out_src_mac;
        uint32_t v2[2];
    };
    uint8_t data[4];  // points to further data
} tpl_ext_21_t;

/* 40 byte
 * Extension 22:
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |      0       |             MPLS_LABEL_2 (71)              |       0      |              MPLS_LABEL_1 (70)             |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |      0       |             MPLS_LABEL_4 (73)              |       0      |              MPLS_LABEL_3 (72)             |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  2 |      0       |             MPLS_LABEL_6 (75)              |       0      |              MPLS_LABEL_5 (74)             |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  3 |      0       |             MPLS_LABEL_8 (77)              |       0      |              MPLS_LABEL_7 (76)             |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  4 |      0       |             MPLS_LABEL_10 (79)             |       0      |              MPLS_LABEL_9 (78)             |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */
#define EX_MPLS 22
typedef struct tpl_ext_22_s {
    uint32_t mpls_label[10];
    uint8_t data[4];  // points to further data
} tpl_ext_22_t;

/*
 * Sending router IP
 * -----------------
 * IPv4:
 * Extension 23:
 *          IP version: IPv6
 *          |
 * Flags: xx0x xxxx
 * +----+--------------+--------------+--------------+--------------+
 * |  0 |                       router ipv4 ()                      |
 * +----+--------------+--------------+--------------+--------------+
 */
#define EX_ROUTER_IP_v4 23
typedef struct tpl_ext_23_s {
    uint32_t router_ip;
    uint8_t data[4];  // points to further data
} tpl_ext_23_t;

/*
 * IPv6:
 * Extension 24:
 *          IP version: IPv6
 *          |
 * Flags: xx1x xxxx
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                                     router ip v6 ()                                                   |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |                                                     router ip v6 ()                                                   |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * Extension 23 and 24 are mutually exclusive in the extension map
 */
#define EX_ROUTER_IP_v6 24
typedef struct tpl_ext_24_s {
    uint64_t router_ip[2];
    uint8_t data[4];  // points to further data
} tpl_ext_24_t;

/*
 * router source ID
 * ----------------
 * For v5 netflow, it's engine type/engine ID
 * for v9 it's the source_id
 * Extension 25:
 * +----+--------------+--------------+--------------+--------------+
 * |  0 |            fill             |engine tpe(38)|engine ID(39) |
 * +----+--------------+--------------+--------------+--------------+
 */
#define EX_ROUTER_ID 25
typedef struct tpl_ext_25_s {
    uint16_t fill;
    uint8_t engine_type;
    uint8_t engine_id;
    uint8_t data[4];  // points to further data
} tpl_ext_25_t;

/*
 * BGP prev/next adjacent AS
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                  bgpNextAdjacentAsNumber(128)             |                bgpPrevAdjacentAsNumber(129)               |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */
#define EX_BGPADJ 26
typedef struct tpl_ext_26_s {
    uint32_t bgpNextAdjacentAS;
    uint32_t bgpPrevAdjacentAS;
    uint8_t data[4];  // points to further data
} tpl_ext_26_t;

/*
 * time flow received in ms
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                                    T received()                                                       |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */
#define EX_RECEIVED 27
typedef struct tpl_ext_27_s {
    union {
        uint64_t received;
        uint32_t v[2];
    };
    uint8_t data[4];  // points to further data
} tpl_ext_27_t;

#define EX_RESERVED_1 28
#define EX_RESERVED_2 29
#define EX_RESERVED_3 30
#define EX_RESERVED_4 31
#define EX_RESERVED_5 32
#define EX_RESERVED_6 33
#define EX_RESERVED_7 34
#define EX_RESERVED_8 35
#define EX_RESERVED_9 36

/*
 * NSEL Common block
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                              NF_F_EVENT_TIME_MSEC(323)                                                |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |                      NF_F_CONN_ID(148)                    |i type(176/8) |i code(177/9) |EVT(40005/233)|    fill      |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  2 |   NF_F_FW_EXT_EVENT(33002)  |   FW_CTS_SRC_SGT(34000)     |
 * +----+--------------+--------------+--------------+--------------+
 * * EVT: NF_F_FW_EVENT
 * * XEVT: NF_F_FW_EXT_EVENT
 */
#define EX_NSEL_COMMON 37
typedef struct tpl_ext_37_s {
    union {
        uint64_t event_time;
        uint32_t v[2];
    };
    uint32_t conn_id;
    union {
        struct {
#ifdef WORDS_BIGENDIAN
            uint8_t icmp_type;
            uint8_t icmp_code;
#else
            uint8_t icmp_code;
            uint8_t icmp_type;
#endif
        };
        uint16_t nsel_icmp;
    };
    uint8_t fw_event;
    uint8_t fill;
    uint16_t fw_xevent;
    uint16_t sec_group_tag;
    uint8_t data[4];  // points to further data
} tpl_ext_37_t;

/*
 * NSEL/NEL xlate ports
 * +----+--------------+--------------+--------------+--------------+
 * |  0 |  NF_F_XLATE_SRC_PORT(227)   |  NF_F_XLATE_DST_PORT(228)   |
 * +----+--------------+--------------+--------------+--------------+
 * ASA 8.4 compatibility mapping 40003 -> 227
 * ASA 8.4 compatibility mapping 40004 -> 228
 */
#define EX_NSEL_XLATE_PORTS 38
typedef struct tpl_ext_38_s {
    uint16_t xlate_src_port;
    uint16_t xlate_dst_port;
    uint8_t data[4];  // points to further data
} tpl_ext_38_t;

/*
 * NSEL xlate v4 IP address
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                NF_F_XLATE_SRC_ADDR_IPV4(225)              |                NF_F_XLATE_DST_ADDR_IPV4(226)              |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * ASA 8.4 compatibility mapping 40001 -> 225
 * ASA 8.4 compatibility mapping 40002 -> 226
 */
#define EX_NSEL_XLATE_IP_v4 39
typedef struct tpl_ext_39_s {
    uint32_t xlate_src_ip;
    uint32_t xlate_dst_ip;
    uint8_t data[4];  // points to further data
} tpl_ext_39_t;

/*
 * NSEL xlate v6 IP address - not yet implemented by CISCO
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                                         xlate src ip (281)                                            |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |                                                         xlate src ip (281)                                            |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  2 |                                                         xlate dst ip (282)                                            |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  3 |                                                         xlate dst ip (282)                                            |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */
#define EX_NSEL_XLATE_IP_v6 40
typedef struct tpl_ext_40_s {
    uint64_t xlate_src_ip[2];
    uint64_t xlate_dst_ip[2];
    uint8_t data[4];  // points to further data
} tpl_ext_40_t;

/*
 * NSEL ACL ingress/egress acl ID
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                            NF_F_INGRESS_ACL_ID(33000)                                                 |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |                 NF_F_INGRESS_ACL_ID(33000)                |               NF_F_EGRESS_ACL_ID(33001)                   |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  2 |                                            NF_F_EGRESS_ACL_ID(33001)                                                  |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */
#define EX_NSEL_ACL 41
typedef struct tpl_ext_41_s {
    uint32_t ingress_acl_id[3];
    uint32_t egress_acl_id[3];
    uint8_t data[4];  // points to further data
} tpl_ext_41_t;

/*
 * NSEL ACL username
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                                  NF_F_USERNAME(40000)                                                 |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |                                                                                                                       |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  2 |                                                                                                                       |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */
#define EX_NSEL_USER 42
typedef struct tpl_ext_42_s {
    char username[24];
    uint8_t data[4];  // points to further data
} tpl_ext_42_t;

/*
 * NSEL ACL username max
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                                  NF_F_USERNAME(40000)                                                 |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * | .. |                                                                                                                       |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  8 |                                                                                                                       |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */
#define EX_NSEL_USER_MAX 43
typedef struct tpl_ext_43_s {
    char username[72];
    uint8_t data[4];  // points to further data
} tpl_ext_43_t;

#define EX_NSEL_RESERVED 44

/*
 * latency extensions, used by nprobe and nfpcapd
 */

/*
 * latency extension
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                           client_nw_delay_usec (57554/57554)                                          |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |                                           server_nw_delay_usec (57556/57557)                                          |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  2 |                                           appl_latency_usec (57558/57559)                                             |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */
#define EX_LATENCY 45
typedef struct tpl_ext_latency_s {
    uint64_t client_nw_delay_usec;
    uint64_t server_nw_delay_usec;
    uint64_t appl_latency_usec;
    uint8_t data[4];  // points to further data
} tpl_ext_latency_t;

/*
 * NEL xlate ports
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |NAT_EVENT(230)|     flags    |            fill             |                  NF_N_EGRESS_VRFID(235)                   |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |                 NF_N_INGRESS_VRFID(234)                   |
 * +----+--------------+--------------+--------------+--------------+
 */
#define EX_NEL_COMMON 46
typedef struct tpl_ext_46_s {
    uint8_t nat_event;
    uint8_t flags;
    uint16_t fill;
    uint32_t egress_vrfid;
    uint32_t ingress_vrfid;
    uint8_t data[4];  // points to further data
} tpl_ext_46_t;

#define EX_NEL_GLOBAL_IP_v4 47
/*
 * no longer used. Mapped to NSEL extension EX_NSEL_XLATE_IP_v4
 */
typedef struct tpl_ext_47_s {
    uint32_t nat_inside;
    uint32_t nat_outside;
    uint8_t data[4];  // points to further data
} tpl_ext_47_t;

/*
 * NEL Port Block Allocation
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 | NF_F_XLATE_PORT_BLOCK_START |  NF_F_XLATE_PORT_BLOCK_END  |  NF_F_XLATE_PORT_BLOCK_STEP |  NF_F_XLATE_PORT_BLOCK_SIZE |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */
#define EX_PORT_BLOCK_ALLOC 48
typedef struct tpl_ext_48_s {
    uint16_t block_start;
    uint16_t block_end;
    uint16_t block_step;
    uint16_t block_size;
    uint8_t data[4];  // points to further data
} tpl_ext_48_t;

#define EX_NEL_RESERVED_1 49

/*
 * V1 Extension map:
 * =================
 * The extension map replaces the individual flags in v1 layout. With many possible extensions and combination of extensions
 * an extension map is more efficient and flexible while reading and decoding the record.
 * In current version of nfdump, up to 65535 individual extension maps are supported, which is considered to be enough.
 *
 * For each available extension record, the ids are recorded in the extension map in the order they appear.
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  - |	     0     |      1       |      2       |      3       |      4       |      5       |      6       |      7       |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |       record type == 2      |             size            |            map id           |      extension size         |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |       extension id 1        |      extension id 2         |      extension id 3         |       extension id 4        |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * ...
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |       extension id n        |      extension id n+1       |      extension id n+2       |       extension id n+3      |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * ...
 * +----+--------------+--------------+--------------+--------------+
 * |  0 |              0              | opt. 32bit alignment: 0     |
 * +----+--------------+--------------+--------------+--------------+
 */

typedef struct extension_map_s {
    // record head
    uint16_t type;  // is ExtensionMapType
    uint16_t size;  // size of full map incl. header

    // map data
#define INIT_ID 0xFFFF
    uint16_t map_id;          // identifies this map
    uint16_t extension_size;  // size of all extensions
    uint16_t ex_id[1];        // extension id array
} extension_map_t;

typedef struct extension_descriptor_s {
    uint16_t id;          // id number
    uint16_t size;        // number of bytes
    uint32_t user_index;  // index specified by the user to enable this extension
    uint32_t enabled;     // extension is enabled or not
    char *description;
} extension_descriptor_t;

typedef struct extension_info_s {
    struct extension_info_s *next;
    extension_map_t *map;
    extension_map_t *exportMap;
    uint32_t ref_count;
    uint32_t *offset_cache;
    master_record_t master_record;
} extension_info_t;

typedef struct extension_map_list_s {
    extension_info_t *slot[MAX_EXTENSION_MAPS];
    extension_info_t *map_list;
    extension_info_t **last_map;
    uint32_t max_used;
} extension_map_list_t;

extension_map_list_t *InitExtensionMaps(int AllocateList);

void FreeExtensionMaps(extension_map_list_t *extension_map_list);

int Insert_Extension_Map(extension_map_list_t *extension_map_list, extension_map_t *map);

void PrintExtensionMap(extension_map_t *map);

void DumpExMaps(void);

#endif  //_NFX_H
