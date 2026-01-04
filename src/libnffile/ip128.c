/*
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

#include "ip128.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "util.h"

char *ip128_2_str(const ip128_t *ip) {
    static char ipstr[INET6_ADDRSTRLEN];
    ipstr[0] = '\0';

    static const uint8_t prefix[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};

    if (memcmp(ip->bytes, prefix, 12) == 0) {
        // mapped IPv4
        uint32_t ipv4;
        memcpy(&ipv4, ip->bytes + 12, 4);
        inet_ntop(AF_INET, &ipv4, ipstr, sizeof(ipstr));
    } else {
        inet_ntop(AF_INET6, ip->bytes, ipstr, sizeof(ipstr));
    }
    return ipstr;

}  // End of ip128_2_str

ip128_t ip128_2_bin(const char *ipStr) {
    ip128_t ip = {0};
    if (ipStr == NULL) return ip;

    int ret = 0;
    if (strchr(ipStr, ':') != NULL) {
        // IPv6
        ret = inet_pton(PF_INET6, ipStr, ip.bytes);
    } else {
        // IPv4 - map into unified ipAddr
        uint32_t ipv4 = 0;
        ret = inet_pton(PF_INET, ipStr, &ipv4);

        ip.bytes[10] = 0xff;
        ip.bytes[11] = 0xff;
        memcpy(ip.bytes + 12, &ipv4, 4);
    }
    switch (ret) {
        case 0:
            LogError("Unparsable IP address: %s", ipStr);
            memset(ip.bytes, 0, sizeof(ip.bytes));
            return ip;
        case 1:
            // success
            return ip;
            break;
        case -1:
            LogError("Error while parsing IP address %s: %s", ipStr, strerror(errno));
            memset(ip.bytes, 0, sizeof(ip.bytes));
            return ip;
            break;
    }

    // unreached
    memset(ip.bytes, 0, 16);
    return ip;
}  // End of ip128_2_bin