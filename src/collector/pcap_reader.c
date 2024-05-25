/*
 *  Copyright (c) 2009-2023, Peter Haag
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

#ifdef HAVE_NET_ETHERNET_H
// FreeBSD needs sys/types in include ethernet.h
#if defined __FreeBSD__
#include <sys/types.h>
#endif
#include <net/ethernet.h>
#endif

#ifdef HAVE_NET_ETHERTYPES_H
#include <net/ethertypes.h>
#endif

#define __FAVOR_BSD 1

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "pcap_reader.h"
#include "util.h"

// define potential missing types
#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL 113
#endif

#ifndef DLT_LINUX_SLL2
#define DLT_LINUX_SLL2 276
#endif

#ifndef DLT_NFLOG
#define DLT_NFLOG 239
#endif

#ifndef DLT_PFLOG
#define DLT_PFLOG 117
#endif

#define PROTO_ERSPAN 0x88be
#define PROTO_ERSPANIII 0x22be

static pcap_t *pcap_handle;
static int linktype = 0;
static int linkoffset = 0;

typedef struct vlan_hdr_s {
    uint16_t vlan_id;
    uint16_t type;
} vlan_hdr_t;

typedef struct gre_hdr_s {
    uint16_t flags;
    uint16_t type;
} gre_hdr_t;

/*
 * Function prototypes
 */

static int setup_pcap(char *filter);

static ssize_t decode_packet(struct pcap_pkthdr *hdr, u_char *pcap_pkgdata, void *buffer, size_t buffer_size, struct sockaddr *sock);

/*
 * function definitions
 */

// set filter if requested
// set linktype and offset
static int setup_pcap(char *filter) {
    struct bpf_program filter_code;

    bpf_u_int32 netmask;

    netmask = 0;
    /* apply filters if any are requested */
    if (filter) {
        if (pcap_compile(pcap_handle, &filter_code, filter, 1, netmask) == -1) {
            /* pcap does not fill in the error code on pcap_compile */
            LogError("pcap_compile() failed: %s\n", pcap_geterr(pcap_handle));
            pcap_close(pcap_handle);
            return 0;
        }
        if (pcap_setfilter(pcap_handle, &filter_code) == -1) {
            /* pcap does not fill in the error code on pcap_compile */
            LogError("pcap_setfilter() failed: %s\n", pcap_geterr(pcap_handle));
            pcap_close(pcap_handle);
            return 0;
        }
    }

    /*
     *  We need to make sure this is Ethernet.  The DLTEN10MB specifies
     *  standard 10MB and higher Ethernet.
     */
    linktype = pcap_datalink(pcap_handle);
    switch (linktype) {
        case DLT_RAW:
            linkoffset = 0;
            break;
        case DLT_PPP:
            linkoffset = 2;
            break;
        case DLT_PPP_SERIAL:
            linkoffset = 4;
            break;
        case DLT_NULL:
            linkoffset = 4;
            break;
        case DLT_LOOP:
            linkoffset = 14;
            break;
        case DLT_EN10MB:
            linkoffset = 14;
            break;
        case DLT_LINUX_SLL:
            linkoffset = 16;
            break;
        case DLT_LINUX_SLL2:
            linkoffset = 20;
            break;
        case DLT_IEEE802_11:
            linkoffset = 22;
            break;
        case DLT_NFLOG:
            linkoffset = 0;
            break;
        case DLT_PFLOG:
            linkoffset = 0;
            break;
        default:
            LogError("Unknown pcap linktype: %u", linktype);
            pcap_close(pcap_handle);
            return 0;
    }
    return 1;

} /* setup_pcap */

static ssize_t decode_packet(struct pcap_pkthdr *hdr, u_char *pcap_pkgdata, void *buffer, size_t buffer_size, struct sockaddr *sock) {
    struct sockaddr_in *in_sock = (struct sockaddr_in *)sock;
    static unsigned pkg_cnt = 0;

    pkg_cnt++;

    // snaplen is minimum 54 bytes
    uint8_t *data = (uint8_t *)pcap_pkgdata;
    uint8_t *eodata = (uint8_t *)pcap_pkgdata + hdr->caplen;

    // make sure, we have full packate capture
    if (hdr->len > hdr->caplen) {
        printf("Short packet - missing: %u bytes\n", hdr->len - hdr->caplen);
        return -1;
    }

    uint16_t protocol = 0;

    int nextType = linktype;
    int nextOffset = linkoffset;

REDO_LINK:
    // link layer processing
    switch (nextType) {
        case DLT_EN10MB:
            // 0 - 11 mac addr
            protocol = data[12] << 0x08 | data[13];
            int IEEE802 = protocol <= 1500;
            if (IEEE802) {
                return 0;
            }
            break;
        case DLT_RAW:
            protocol = 0x800;
            break;
        case DLT_PPP:
            protocol = 0x800;
            break;
        case DLT_PPP_SERIAL:
            protocol = 0x800;
            break;
        case DLT_LOOP:
        case DLT_NULL: {
            uint32_t header;
            if (linktype == DLT_LOOP)
                header = ntohl(*((uint32_t *)data));
            else
                header = *((uint32_t *)data);
            switch (header) {
                case 2:
                    protocol = 0x800;
                    break;
                case 24:
                case 28:
                case 30:
                    protocol = 0x86DD;
                    break;
                default:
                    LogInfo("Packet: %u: unsupported DLT_NULL protocol: 0x%x, packet: %u", pkg_cnt, header);
                    return 0;
            }
        } break;
        case DLT_LINUX_SLL:
            protocol = data[14] << 8 | data[15];
            break;
        case DLT_LINUX_SLL2:
            protocol = data[0] << 8 | data[1];
            break;
        case DLT_IEEE802_11:
            protocol = 0x800;
            break;
        default:
            LogInfo("Packet: %u: unsupported link type: 0x%x, packet: %u", pkg_cnt, linktype);
            return 0;
    }

    // adjust data after link
    data += nextOffset;

    struct ip *ip = NULL;
REDO_PROTO:
    if (data >= eodata) {
        dbg_printf("Short packet: %u, Check line: %u", hdr->caplen, __LINE__);
        return -1;
    }
    switch (protocol) {
        case ETHERTYPE_IP:
            /* IPv4 */
            ip = (struct ip *)data;  // offset points to end of link layer
            in_sock->sin_family = AF_INET;
            in_sock->sin_addr = ip->ip_src;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
            in_sock->sin_len = sizeof(struct sockaddr_in);
#endif
            break;
        case ETHERTYPE_VLAN:  // VLAN
            do {
                vlan_hdr_t *vlan_hdr = (vlan_hdr_t *)data;
                protocol = ntohs(vlan_hdr->type);
                data += 4;
            } while ((data < eodata) && protocol == 0x8100);

            goto REDO_PROTO;
            break;
        default:
            /* We're not bothering with 802.3 or anything else */
            printf("PCAP unknown protocol %u\n", protocol);
            break;
    }

    /* for the moment we handle only IPv4 */
    if (!ip || ip->ip_v != 4) return 0;

    // u_int version = ip->ip_v; /* ip version */

    /* check header length */
    if (ip->ip_hl < 5) {
        LogError("bad-hlen %d", ip->ip_hl);
        return 0;
    }

    // add IP header length
    data += (ip->ip_hl << 0x02);
    switch (ip->ip_p) {
        case IPPROTO_UDP: {
            struct udphdr *udp = (struct udphdr *)((void *)data);
            unsigned int packet_len = ntohs(udp->uh_ulen) - 8;
            void *payload = (void *)((void *)udp + sizeof(struct udphdr));

            if (packet_len > buffer_size) {
                LogError("Buffer size error: %u > %zu", packet_len, buffer_size);
                return -1;
            }
            memcpy(buffer, payload, packet_len);
            in_sock->sin_port = udp->uh_sport;
            return packet_len;
            // unreached
        } break;
        case IPPROTO_GRE: {
            gre_hdr_t *gre_hdr = (gre_hdr_t *)((void *)data);

            uint16_t gre_flags = ntohs(gre_hdr->flags);
            protocol = ntohs(gre_hdr->type);
            data += sizeof(gre_hdr_t);

            dbg_printf("GRE proto encapsulation: type: 0x%x\n", protocol);
            uint32_t *sequence = NULL;
            if (gre_flags & 0x1000) {  // Sequence supplied
                sequence = (uint32_t *)(data);
                dbg_printf("GRE sequence: %u\n", ntohl(*sequence));
                data += 4;
            }

            if (protocol == PROTO_ERSPAN) {
                if (sequence) {
                    // erspan_hdr = (erspan_hdr_t *)data;
#ifdef DEVEL
                    dbg_printf("ERSPAN II found\n");
                    uint16_t erspanHdr = ntohs(*((uint16_t *)data));
                    uint16_t version = (erspanHdr & 0xF000) >> 12;
                    uint16_t vlanID = erspanHdr & 0x0FFF;
                    dbg_printf("GRE sequence: %u, Version: %u, vladID: %u\n", *sequence, version, vlanID);
#endif
                    // erspan header size for type II = 8 bytes
                    data += 8;
                } else {
                    dbg_printf("ERSPAN found\n");
                }
                nextType = DLT_EN10MB;
                goto REDO_LINK;
            }
        } break;
        default:
            /* no default */
            break;
    }

    return 0;

} /* decode_packet */

// live device
int setup_pcap_live(char *device, char *filter, int bufflen) {
    pcap_t *p;
    char errbuf[PCAP_ERRBUF_SIZE];

    errbuf[0] = '\0';
    pcap_handle = NULL;

    /*
     *  Open the packet capturing device with the following values:
     *
     *  SNAPLEN: User defined or 1600 bytes
     *  PROMISC: on
     *  The interface needs to be in promiscuous mode to capture all
     *		network traffic on the localnet.
     *  TO_MS: 100ms
     *		this value specifies how long to wait, if a packet arrives
     *		until the application may request it. longer time have the advantage
     * 		in processing multiple packets - less interrupts but more packet loss
     */
    p = pcap_create(device, errbuf);
    if (!p) {
        LogError("pcap_create() failed on %s: %s", device, errbuf);
        return 0;
    }

    int snaplen = 1900;
    if (pcap_set_snaplen(p, snaplen)) {
        LogError("pcap_set_snaplen() failed: %s", pcap_geterr(p));
        pcap_close(p);
        return 0;
    }

    int promisc = 1;
    if (pcap_set_promisc(p, promisc)) {
        LogError("pcap_set_promisc() failed: %s", pcap_geterr(p));
        pcap_close(p);
        return 0;
    }

    int to_ms = 100;
    if (pcap_set_timeout(p, to_ms)) {
        LogError("pcap_set_timeout() failed: %s", pcap_geterr(p));
        pcap_close(p);
        return 0;
    }

    int buffsize = 256 * 1024;
    if (bufflen) buffsize = bufflen;
    if (pcap_set_buffer_size(p, buffsize) < 0) {
        LogError("pcap_set_buffer_size() failed: %s", pcap_geterr(p));
        pcap_close(p);
        return 0;
    }

    if (pcap_activate(p)) {
        LogError("pcap_activate() failed: %s", pcap_geterr(p));
        pcap_close(p);
        return 0;
    }
    pcap_handle = p;

    return setup_pcap(filter);

} /* setup_pcap_live */

int setup_pcap_offline(char *fname, char *filter) {
    char errbuf[PCAP_ERRBUF_SIZE];

    /*
     *  Open the packet capturing file
     */
    pcap_handle = pcap_open_offline(fname, errbuf);
    if (!pcap_handle) {
        LogError("pcap_open_offline(): %s", errbuf);
        return 0;
    }

    return setup_pcap(filter);

} /* End of setup_pcap_offline */

ssize_t NextPacket(int fill1, void *buffer, size_t buffer_size, int fill2, struct sockaddr *sock, socklen_t *size) {
    // ssize_t NextPacket(void *buffer, size_t buffer_size) {
    struct pcap_pkthdr *header;
    u_char *pkt_data;
    int i;

    i = pcap_next_ex(pcap_handle, &header, (const u_char **)&pkt_data);
    if (i != 1) return -2;

    *size = sizeof(struct sockaddr_in);
    return decode_packet(header, pkt_data, buffer, buffer_size, sock);
}