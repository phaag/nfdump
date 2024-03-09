/*
 *  Copyright (c) 2023, Peter Haag
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

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "config.h"

#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif

#include "ipconv.h"
#include "util.h"

static int lookup_host(const char *hostname, ipStack_t *ipStack);

int parseIP(const char *src, ipStack_t *ipStack, int lookup) {
    char *alpha = "abcdefghijklmnopqrstuvwxzyABCDEFGHIJKLMNOPQRSTUVWXZY";

    int af = 0;
    // check for IPv6 address
    if (strchr(src, ':') != NULL) {
        af = PF_INET6;
        // check for alpha chars -> hostname -> lookup
    } else if (strpbrk(src, alpha)) {
        af = 0;
        if (lookup == STRICT_IP)
            return -1;
        else
            return lookup_host(src, ipStack);
        // it's IPv4
    } else
        af = PF_INET;

    int numIP = 0;
    switch (af) {
        case PF_INET: {
            uint32_t v4addr = 0;
            int ret = inet_pton(PF_INET, src, &v4addr);
            if (ret > 0) {
                numIP = 1;
                ipStack[0].af = af;
                ipStack[0].ipaddr[0] = 0;
                ipStack[0].ipaddr[1] = ntohl(v4addr);
            } else {
                return ret;
            }
        } break;
        case PF_INET6: {
            uint64_t dst[2];
            int ret = inet_pton(PF_INET6, src, dst);
            if (ret > 0) {
                numIP = 1;
                ipStack[0].af = af;
                ipStack[0].ipaddr[0] = ntohll(dst[0]);
                ipStack[0].ipaddr[1] = ntohll(dst[1]);
            } else {
                return ret;
            }
        } break;
    }
    return numIP;
}

static int lookup_host(const char *hostname, ipStack_t *ipStack) {
    struct addrinfo hints, *res, *r;
    int errcode, len;
    char addrstr[128];
    char reverse[256];

    printf("Resolving %s ...\n", hostname);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;

    errcode = getaddrinfo(hostname, NULL, &hints, &res);
    if (errcode != 0) {
        fprintf(stderr, "Failed to resolve IP address for %s: %s\n", hostname, gai_strerror(errno));
        return 0;
    }

    // count the number of records found
    uint32_t numIP = 0;

    // remember res for later free()
    r = res;

    void *ptr;
    while (res) {
        if (numIP >= MAXHOSTS) {
            fprintf(stderr, "Too man IP addresses in DNS response\n");
            return numIP;
        }
        switch (res->ai_family) {
            case PF_INET:
                ptr = &(((struct sockaddr_in *)res->ai_addr)->sin_addr);
                ipStack[numIP].af = PF_INET;
                ipStack[numIP].ipaddr[0] = 0;
                ipStack[numIP].ipaddr[1] = ntohl(*(uint32_t *)ptr) & 0xffffffffLL;
                len = sizeof(struct sockaddr_in);
                break;
            case AF_INET6:
                ptr = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
                ipStack[numIP].af = PF_INET6;
                ipStack[numIP].ipaddr[0] = ntohll(((uint64_t *)ptr)[0]);
                ipStack[numIP].ipaddr[1] = ntohll(((uint64_t *)ptr)[1]);
                len = sizeof(struct sockaddr_in6);
                break;
            default: {
                // not handled
                res = res->ai_next;
                continue;
            }
        }
        inet_ntop(res->ai_family, ptr, addrstr, 100);
        addrstr[99] = '\0';
        if ((errcode = getnameinfo(res->ai_addr, len, reverse, sizeof(reverse), NULL, 0, 0)) != 0) {
            snprintf(reverse, sizeof(reverse) - 1, "<reverse lookup failed>");
            // fprintf(stderr, "Failed to reverse lookup %s: %s\n", addrstr, gai_strerror(errcode));
        }

        dbg_printf("IPv%d address: %s (%s)\n", res->ai_family == PF_INET6 ? 6 : 4, addrstr, reverse);
        res = res->ai_next;
        numIP++;
    }

    freeaddrinfo(r);
    return numIP;

}  // End of lookup_host

int set_nameserver(char *ns) {
    struct hostent *host;

    res_init();
    host = gethostbyname(ns);
    if (host == NULL) {
        (void)fprintf(stderr, "Can not resolv nameserver %s: %s\n", ns, hstrerror(h_errno));
        return 0;
    }
    (void)memcpy((void *)&_res.nsaddr_list[0].sin_addr, (void *)host->h_addr_list[0], (size_t)host->h_length);
    _res.nscount = 1;
    return 1;

}  // End of set_nameserver

uint64_t Str2Mac(char *macStr) {
    uint8_t values[6];
    if (sscanf(macStr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &values[0], &values[1], &values[2], &values[3], &values[4], &values[5]) != 6) {
        return 0;
    }

    uint64_t macVal = 0;
    for (int i = 0; i < 6; i++) {
        macVal = macVal << 8 | values[i];
    }

    return macVal;
}

#ifdef MAIN

static void checkHost(char *s) {
    ipStack_t ipStack[MAXHOSTS];

    int numIP = parse_ip(s, ipStack, ALLOW_LOOKUP);
    if (numIP < 0)
        printf("Lookup: %s, ret: %d: %s\n", s, numIP, strerror(errno));
    else
        printf("Lookup: %s, numIP: %u\n", s, numIP);

    for (int i = 0; i < numIP; i++) {
        printf("%d: af: %u, 0x%llx 0x%llx\n", i + 1, ipStack[i].af, ipStack[i].ipaddr[0], ipStack[i].ipaddr[1]);
    }
    printf("\n");
}

int main(int argc, char **argv) {
    checkHost("1.2.3.4");
    checkHost("1.2.3.400");
    checkHost("1.2.3.4.5");
    checkHost("0.2.3.4");

    checkHost("2001:620:0:ff::5c");
    checkHost("::ffff:1.2.3.4");

    checkHost("www.google.ch");
    checkHost("www.cnn.ch");
    checkHost("unresovled");
}
#endif