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
#include <net/ethernet.h>
#include <sys/types.h>
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

#ifndef DLT_NFLOG
#define DLT_NFLOG 239
#endif

#ifndef DLT_PFLOG
#define DLT_PFLOG 117
#endif

#define PROTO_ERSPAN 0x88be

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

static pcap_t *setup_pcap(char *fname, char *filter, char *errbuf);

static ssize_t decode_packet(struct pcap_pkthdr *hdr, u_char *pkt, void *buffer, struct sockaddr *sock);

/*
 * function definitions
 */

static pcap_t *setup_pcap(char *fname, char *filter, char *errbuf) {
    struct bpf_program filter_code;

    bpf_u_int32 netmask;

    /*
     *  Open the packet capturing file
     */
    pcap_handle = pcap_open_offline(fname, errbuf);
    if (!pcap_handle) return NULL;

    netmask = 0;
    /* apply filters if any are requested */
    if (filter) {
        if (pcap_compile(pcap_handle, &filter_code, filter, 1, netmask) == -1) {
            /* pcap does not fill in the error code on pcap_compile */
            snprintf(errbuf, PCAP_ERRBUF_SIZE, "pcap_compile() failed: %s\n", pcap_geterr(pcap_handle));
            pcap_close(pcap_handle);
            return NULL;
        }
        if (pcap_setfilter(pcap_handle, &filter_code) == -1) {
            /* pcap does not fill in the error code on pcap_compile */
            snprintf(errbuf, PCAP_ERRBUF_SIZE, "pcap_setfilter() failed: %s\n", pcap_geterr(pcap_handle));
            pcap_close(pcap_handle);
            return NULL;
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
            snprintf(errbuf, PCAP_ERRBUF_SIZE - 1, "Snooping not on an ethernet.\n");
            pcap_close(pcap_handle);
            return NULL;
    }
    return pcap_handle;

} /* setup_pcap */

static ssize_t decode_packet(struct pcap_pkthdr *hdr, u_char *data, void *buffer, struct sockaddr *sock) {
    struct sockaddr_in *in_sock = (struct sockaddr_in *)sock;
    static unsigned pkg_cnt = 0;

    pkg_cnt++;

    // snaplen is minimum 54 bytes
    void *dataptr = (void *)data + linkoffset;  // after link header
    void *eodata = (void *)data + hdr->caplen;

    u_int length = hdr->len;
    if (hdr->len > hdr->caplen) {
        printf("Short packet - missing: %u bytes\n", hdr->len - hdr->caplen);
        return 0;
    }

    uint16_t protocol = 0;

REDO_LINK:
    // link layer processing
    switch (linktype) {
        case DLT_EN10MB:
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
        case DLT_IEEE802_11:
            protocol = 0x800;
            break;
        default:
            LogInfo("Packet: %u: unsupported link type: 0x%x, packet: %u", pkg_cnt, linktype);
            return 0;
    }

    struct ip *ip = NULL;
REDO_PROTO:
    switch (protocol) {
        case ETHERTYPE_IP:
            /* IPv4 */
            ip = (struct ip *)dataptr;  // offset points to end of link layer
            length -= linkoffset;
            in_sock->sin_family = AF_INET;
            in_sock->sin_addr = ip->ip_src;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
            in_sock->sin_len = sizeof(struct sockaddr_in);
#endif
            break;
        case ETHERTYPE_VLAN:  // VLAN
            do {
                vlan_hdr_t *vlan_hdr = (vlan_hdr_t *)dataptr;
                protocol = ntohs(vlan_hdr->type);
                dataptr += 4;
            } while ((dataptr < eodata) && protocol == 0x8100);

            goto REDO_PROTO;
            break;
        default:
            /* We're not bothering with 802.3 or anything else */
            printf("PCAP unknown protocol %u\n", protocol);
            break;
    }

    /* for the moment we handle only IPv4 */
    if (!ip || ip->ip_v != 4) return 0;

    u_short len = ntohs(ip->ip_len);
    u_int hlen = ip->ip_hl; /* header length */
    // u_int version = ip->ip_v; /* ip version */

    /* check header length */
    if (hlen < 5) {
        LogError("bad-hlen %d", hlen);
        return 0;
    }

    /* see if we have as much packet as we should */
    if (length < len) {
        LogError("\ntruncated IP - %d bytes missing", len - length);
        return 0;
    }

    switch (ip->ip_p) {
        case IPPROTO_UDP: {
            struct udphdr *udp = (struct udphdr *)((void *)ip + (ip->ip_hl << 0x02));
            unsigned int packet_len = ntohs(udp->uh_ulen) - 8;
            void *payload = (void *)((void *)udp + sizeof(struct udphdr));

            memcpy(buffer, payload, packet_len);
            in_sock->sin_port = udp->uh_sport;
            return packet_len;
            // unreached
        } break;
        case IPPROTO_GRE: {
            gre_hdr_t *gre_hdr = (gre_hdr_t *)((void *)ip + (ip->ip_hl << 0x02));
            protocol = ntohs(gre_hdr->type);
            if (protocol == PROTO_ERSPAN) {
                dbg_printf("ERSPAN found\n");
                linktype = DLT_EN10MB;
                data = ((void *)ip + (ip->ip_hl << 0x02)) + 4;
                dataptr = data + 14;
                goto REDO_LINK;
            }
            dbg_printf("  GRE proto encapsulation: type: 0x%x\n", protocol);
        } break;
        default:
            /* no default */
            break;
    }

    return 0;

} /* decode_packet */

void setup_packethandler(char *fname, char *filter) {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_handle = setup_pcap(fname, filter, errbuf);
    if (!pcap_handle) {
        LogError("Can't init pcap: %s", errbuf);
        exit(255);
    }

} /* End of setup_packethandler */

ssize_t NextPacket(int fill1, void *buffer, size_t buffer_size, int fill2, struct sockaddr *sock, socklen_t *size) {
    // ssize_t NextPacket(void *buffer, size_t buffer_size) {
    struct pcap_pkthdr *header;
    u_char *pkt_data;
    int i;

    i = pcap_next_ex(pcap_handle, &header, (const u_char **)&pkt_data);
    if (i != 1) return -2;

    *size = sizeof(struct sockaddr_in);
    return decode_packet(header, pkt_data, buffer, sock);
}