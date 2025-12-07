/*
 *  Copyright (c) 2009-2024, Peter Haag
 *  Copyright (c) 2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
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

static int is_ipv4_mapped(const struct in6_addr *a6) {
    /* First 80 bits must be zero, next 16 bits must be 0xffff */
    static const uint8_t prefix[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};
    return (memcmp(a6->s6_addr, prefix, 12) == 0);
}

static int GetClientIP(const struct sockaddr_storage *ss, ip_addr_t *ip, int *family) {
    union {
        const struct sockaddr_storage *ss;
        const struct sockaddr_in *sa_in;
        const struct sockaddr_in6 *sa_in6;
    } u;
    u.ss = ss;

    *family = ss->ss_family;
    switch (ss->ss_family) {
        case PF_INET: {
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN
            if (ss->ss_len != sizeof(struct sockaddr_in)) {
                // malformed struct
                LogError("Malformed IPv4 socket struct in '%s', line '%d'", __FILE__, __LINE__);
                return NULL;
            }
#endif
            ip->V6[0] = 0;
            ip->V6[1] = 0;
            ip->V4 = ntohl(u.sa_in->sin_addr.s_addr);
        } break;
        case PF_INET6: {
            uint64_t *ip_ptr = (uint64_t *)u.sa_in6->sin6_addr.s6_addr;

#ifdef HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN
            if (ss->ss_len != sizeof(struct sockaddr_in6)) {
                // malformed struct
                LogError("Malformed IPv6 socket struct in '%s', line '%d'", __FILE__, __LINE__);
                return ip;
            }
#endif
            if (is_ipv4_mapped(&u.sa_in6->sin6_addr)) {
                // if listen on dual stack, check, if client was IPv4 client
                dbg_printf("IPv4 mapped IP address\n");
                *family = PF_INET;
                ip->V6[0] = 0;
                ip->V6[1] = 0;
                uint8_t *ipv4 = (uint8_t *)u.sa_in6->sin6_addr.s6_addr + 12;
                ip->V4 = ntohl(*((uint32_t *)ipv4));
            } else {
                ip->V6[0] = ntohll(ip_ptr[0]);
                ip->V6[1] = ntohll(ip_ptr[1]);
            }

        } break;
        default:
            // keep compiler happy
            *family = 0;
            ip->V6[0] = 0;
            ip->V6[1] = 0;

            LogError("Unknown sa family: %d in '%s', line '%d'", ss->ss_family, __FILE__, __LINE__);
            return 0;
    }

    return 1;
}  // End of GetClientIP

static char *GetClientIPstring(struct sockaddr_storage *ss) {
    static char as[128];
    as[0] = '\0';

    union {
        struct sockaddr_storage *ss;
        struct sockaddr_in *sa_in;
        struct sockaddr_in6 *sa_in6;
    } u;
    u.ss = ss;

    int family = ss->ss_family;
    void *ptr = NULL;
    switch (ss->ss_family) {
        case PF_INET: {
            ptr = &u.sa_in->sin_addr;
        } break;
        case PF_INET6: {
            ptr = &u.sa_in6->sin6_addr;
            if (is_ipv4_mapped(&u.sa_in6->sin6_addr)) {
                family = PF_INET;
                ptr = &(u.sa_in6->sin6_addr.s6_addr[12]);
            }
        } break;
        default:
            snprintf(as, sizeof(as) - 1, "Unknown sa family: %d", ss->ss_family);
            return as;
    }

    inet_ntop(family, ptr, as, sizeof(as));
    return as;

}  // End of GetClientIPstring

static inline FlowSource_t *GetFlowSource(struct sockaddr_storage *ss) {
    ip_addr_t ip = {0};
    int family = 0;
    if (GetClientIP(ss, &ip, &family) == 0) return NULL;

    dbg_printf("Flow Source IP: %s\n", GetClientIPstring(ss));

    FlowSource_t *fs = FlowSource;
    while (fs) {
        if (ip.V6[0] == fs->ip.V6[0] && ip.V6[1] == fs->ip.V6[1]) {
            return fs;
        }

        // if we match any source, store the current IP address - works as faster cache next time
        // and identifies the current source by IP
        if (fs->any_source) {
            fs->ip = ip;
            fs->sa_family = family;
            return fs;
        }
        fs = fs->next;
    }

    LogError("Unknown flow source: '%s'", GetClientIPstring(ss));

    return NULL;

}  // End of GetFlowSource
