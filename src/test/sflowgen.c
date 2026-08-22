/*
 *  This file is part of the nfdump project.
 *
 *  Copyright (c) 2026, Peter Haag
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
 *   * Neither the name of Peter Haag nor the names of its contributors may be
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

/*
 * Generate the small, self-contained sFlow v5 PCAP fixture used by
 * test_sfcapd.sh. Keeping the wire fixture in source form avoids a binary
 * repository artifact while retaining an exact, reproducible input packet.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void put_be16(uint8_t **p, uint16_t value) {
    *(*p)++ = (uint8_t)(value >> 8);
    *(*p)++ = (uint8_t)value;
}

static void put_be32(uint8_t **p, uint32_t value) {
    *(*p)++ = (uint8_t)(value >> 24);
    *(*p)++ = (uint8_t)(value >> 16);
    *(*p)++ = (uint8_t)(value >> 8);
    *(*p)++ = (uint8_t)value;
}

static void put_le16(uint8_t **p, uint16_t value) {
    *(*p)++ = (uint8_t)value;
    *(*p)++ = (uint8_t)(value >> 8);
}

static void put_le32(uint8_t **p, uint32_t value) {
    *(*p)++ = (uint8_t)value;
    *(*p)++ = (uint8_t)(value >> 8);
    *(*p)++ = (uint8_t)(value >> 16);
    *(*p)++ = (uint8_t)(value >> 24);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s output.pcap\n", argv[0]);
        return 1;
    }

    /*
     * One Ethernet/IPv4/UDP packet carrying one compact sFlow v5 flow sample:
     * TCP 203.0.113.10:12345 -> 198.51.100.20:443, length 128, sampled 1:1000.
     */
    uint8_t packet[256];
    uint8_t *p = packet;

    const uint8_t dst_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t src_mac[6] = {0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    memcpy(p, dst_mac, sizeof(dst_mac));
    p += sizeof(dst_mac);
    memcpy(p, src_mac, sizeof(src_mac));
    p += sizeof(src_mac);
    put_be16(&p, 0x0800);  // IPv4 EtherType

    uint8_t *ip = p;
    *p++ = 0x45;  // IPv4, 20-byte header
    *p++ = 0;
    p += 2;  // total length, set after writing sFlow payload
    put_be16(&p, 1);
    put_be16(&p, 0);
    *p++ = 64;
    *p++ = 17;  // UDP
    put_be16(&p, 0);  // checksum is not validated by the offline reader
    put_be32(&p, 0xc0000201);  // 192.0.2.1, transport sender
    put_be32(&p, 0x7f000001);  // 127.0.0.1

    put_be16(&p, 6343);
    put_be16(&p, 6343);
    uint8_t *udp_length = p;
    p += 2;
    put_be16(&p, 0);  // UDP checksum is not validated by the offline reader

    uint8_t *sflow = p;
    put_be32(&p, 5);           // sFlow v5
    put_be32(&p, 1);           // agent address type: IPv4
    put_be32(&p, 0xc6336401);  // agent address: 198.51.100.1
    put_be32(&p, 0);           // agent sub-id
    put_be32(&p, 1);           // datagram sequence
    put_be32(&p, 100);         // agent uptime
    put_be32(&p, 1);           // one sample
    put_be32(&p, 1);           // compact flow sample
    uint8_t *sample_length = p;
    p += 4;
    uint8_t *sample = p;
    put_be32(&p, 1);     // sample sequence
    put_be32(&p, 0);     // data-source class/index
    put_be32(&p, 1000);  // sampling rate
    put_be32(&p, 1000);  // sample pool
    put_be32(&p, 0);     // drop events
    put_be32(&p, 1);     // input interface
    put_be32(&p, 2);     // output interface
    put_be32(&p, 1);     // one flow element
    put_be32(&p, 3);     // IPv4 flow element
    put_be32(&p, 32);    // IPv4 flow element size
    put_be32(&p, 128);         // sampled packet length
    put_be32(&p, 6);           // TCP
    put_be32(&p, 0xcb00710a);  // 203.0.113.10
    put_be32(&p, 0xc6336414);  // 198.51.100.20
    put_be32(&p, 12345);
    put_be32(&p, 443);
    put_be32(&p, 0x12);  // SYN|ACK
    put_be32(&p, 0);

    uint32_t sample_size = (uint32_t)(p - sample);
    sample_length[0] = (uint8_t)(sample_size >> 24);
    sample_length[1] = (uint8_t)(sample_size >> 16);
    sample_length[2] = (uint8_t)(sample_size >> 8);
    sample_length[3] = (uint8_t)sample_size;

    uint32_t sflow_size = (uint32_t)(p - sflow);
    uint32_t udp_size = 8u + sflow_size;
    udp_length[0] = (uint8_t)(udp_size >> 8);
    udp_length[1] = (uint8_t)udp_size;
    uint32_t ip_size = 20u + udp_size;
    ip[2] = (uint8_t)(ip_size >> 8);
    ip[3] = (uint8_t)ip_size;

    uint32_t packet_size = (uint32_t)(p - packet);
    uint8_t pcap_header[24];
    uint8_t *h = pcap_header;
    put_le32(&h, 0xa1b2c3d4);  // microsecond-resolution, little-endian PCAP
    put_le16(&h, 2);
    put_le16(&h, 4);
    put_le32(&h, 0);
    put_le32(&h, 0);
    put_le32(&h, 65535);
    put_le32(&h, 1);  // Ethernet

    uint8_t record_header[16];
    h = record_header;
    put_le32(&h, 1700000000);  // stable timestamp: 2023-11-14 22:13:20 UTC
    put_le32(&h, 0);
    put_le32(&h, packet_size);
    put_le32(&h, packet_size);

    FILE *stream = fopen(argv[1], "wb");
    if (!stream) {
        fprintf(stderr, "%s: %s\n", argv[1], strerror(errno));
        return 1;
    }
    if (fwrite(pcap_header, 1, sizeof(pcap_header), stream) != sizeof(pcap_header) ||
        fwrite(record_header, 1, sizeof(record_header), stream) != sizeof(record_header) || fwrite(packet, 1, packet_size, stream) != packet_size) {
        fprintf(stderr, "%s: %s\n", argv[1], ferror(stream) ? strerror(errno) : "short write");
        fclose(stream);
        return 1;
    }
    if (fclose(stream) != 0) {
        fprintf(stderr, "%s: %s\n", argv[1], strerror(errno));
        return 1;
    }
    return 0;
}
