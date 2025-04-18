/*
 *  Copyright (c) 2009-2022, Peter Haag
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

#include "send_net.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "util.h"

/* local function prototypes */
static int isMulticast(struct sockaddr_storage *addr);

static int joinGroup(int sockfd, int loopBack, int mcastTTL, struct sockaddr_storage *addr);

static int setSourceAddress(int sockfd, const char *srcaddr, int family, int socktype);


int setSourceAddress(int sockfd, const char *shostname, int family, int socktype) {
    struct addrinfo shints, *sres;
    int error;

    memset(&shints, 0, sizeof(struct addrinfo));
    shints.ai_family = family;
    shints.ai_socktype = socktype;
    error = getaddrinfo(shostname, "0", &shints, &sres);
    if (error) {
        LogError("getaddrinfo(%s) error: %s", shostname, gai_strerror(error));
        return -1;
    }
    printf("Hacemos el bind(%s)\n", shostname);
    if (bind(sockfd, sres->ai_addr, sres->ai_addrlen) < 0) {
        LogError("bind(%s) error: %s", shostname, strerror(errno));
        return -1;
    }
    freeaddrinfo(sres);
    return 0;
}

/* function definitions */
int Unicast_send_socket(const char *shostname, const char *dhostname, const char *sendport, int family, unsigned int wmem_size, struct sockaddr_storage *saddr, struct sockaddr_storage *daddr, int *addrlen) {
    struct addrinfo hints, *res, *ressave;
    int error, sockfd;
    unsigned int wmem_actual;
    socklen_t optlen;

    if (!dhostname || !sendport) {
        LogError("hostname and listen port required!");
        return -1;
    }

    // create socket
    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_family = family;
    hints.ai_socktype = SOCK_DGRAM;

    error = getaddrinfo(dhostname, sendport, &hints, &res);
    if (error) {
        LogError("getaddrinfo(%s) error: %s", dhostname, gai_strerror(error));
        return -1;
    }

    ressave = res;
    sockfd = -1;
    while (res) {
        sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sockfd < 0) {
            LogError("socket() error: could not open the requested socket: %s", strerror(errno));
        } else {
            // socket call was successful
            if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
                // unsuccessful connect :(
                LogError("connect() error: could not open the requested socket: %s", strerror(errno));
                close(sockfd);
                sockfd = -1;
            } else {
                // connect successful - we are done
                close(sockfd);
                // ok - we need now an unconnected socket
                sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
                break;
            }
        }
        res = res->ai_next;
    }

    if (sockfd < 0) {
        freeaddrinfo(ressave);
        return -1;
    }

    if (shostname != NULL ) {
        if (setSourceAddress(sockfd, shostname, family, SOCK_DGRAM) == -1) {
            freeaddrinfo(ressave);
            return -1;
        }
    }
    *addrlen = res->ai_addrlen;
    memcpy(daddr, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(ressave);

    // Set socket write buffer. Need to be root!
    if (wmem_size > 0) {
        if (geteuid() == 0) {
            setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &wmem_size, sizeof(wmem_size));

            // check what was set (e.g. linux 2.4.20 sets twice of what was requested)
            getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &wmem_actual, &optlen);

            if (wmem_size != wmem_actual) {
                printf("Warning: Socket write buffer size requested: %u set: %u\n", wmem_size, wmem_actual);
            }
        } else {
            printf("Warning: Socket buffer size can only be changed by root!\n");
        }
    }

    return sockfd;

}  // End of Unicast_send_socket

int Multicast_send_socket(const char *shostname, const char *dhostname, const char *listenport, int family, unsigned int wmem_size, struct sockaddr_storage *saddr, struct sockaddr_storage *daddr,
                          int *addrlen) {
    struct addrinfo hints, *res, *ressave;
    int error, sockfd;

    if (!listenport || !dhostname) {
        fprintf(stderr, "hostname and listen port required!\n");
        LogError("hostname and listen port required!");
        return -1;
    }

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_DGRAM;

    error = getaddrinfo(dhostname, listenport, &hints, &res);

    if (error) {
        fprintf(stderr, "getaddrinfo error:: [%s]\n", gai_strerror(error));
        LogError("getaddrinfo error:: [%s]", gai_strerror(error));
        return -1;
    }

    /*
       Try open socket with each address getaddrinfo returned,
       until we get a valid listening socket.
    */
    sockfd = -1;
    ressave = res;
    while (res) {
        sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sockfd < 0) {
            res = res->ai_next;
            continue;
        }
        // we found a valid socket and are done in this loop
        break;
    }

    
    if (sockfd < 0) {
        // nothing found - bye bye
        fprintf(stderr, "Could not create a socket for [%s:%s]\n", dhostname, listenport);
        LogError("Could not create a socket for [%s:%s]", dhostname, listenport);
        freeaddrinfo(ressave);
        return -1;
    }

    if (isMulticast((struct sockaddr_storage *)res->ai_addr) < 0) {
        fprintf(stderr, "Not a multicast address [%s]\n", dhostname);
        LogError("Not a multicast address [%s]", dhostname);
        freeaddrinfo(ressave);
        return -1;
    }

    close(sockfd);
    sockfd = socket(res->ai_family, SOCK_DGRAM, 0);

    if (shostname != NULL) {
        if (setSourceAddress(sockfd, shostname, family, SOCK_DGRAM) == -1) {
            freeaddrinfo(ressave);
            return -1;
        }
    }
    *addrlen = res->ai_addrlen;
    memcpy(daddr, res->ai_addr, res->ai_addrlen);

    if (joinGroup(sockfd, 1, 1, (struct sockaddr_storage *)res->ai_addr) < 0) {
        close(sockfd);
        freeaddrinfo(ressave);
        return -1;
    }

    freeaddrinfo(ressave);

    return sockfd;

} /* End of Multicast_send_socket */

static int joinGroup(int sockfd, int loopBack, int mcastTTL, struct sockaddr_storage *addr) {
    int ret, err;

    ret = -1;

    switch (addr->ss_family) {
        case AF_INET: {
            struct ip_mreq mreq;

            mreq.imr_multiaddr.s_addr = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
            mreq.imr_interface.s_addr = INADDR_ANY;

            err = setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const void *)&mreq, sizeof(mreq));
            if (err) {
                fprintf(stderr, "setsockopt IP_ADD_MEMBERSHIP: %s\n", strerror(errno));
                LogError("setsockopt IP_ADD_MEMBERSHIP: %s", strerror(errno));
                break;
            }
            ret = 0;
        } break;

        case AF_INET6: {
            struct ipv6_mreq mreq6;

            memcpy(&mreq6.ipv6mr_multiaddr, &(((struct sockaddr_in6 *)addr)->sin6_addr), sizeof(struct in6_addr));
            mreq6.ipv6mr_interface = 0;

            err = setsockopt(sockfd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6, sizeof(mreq6));
            if (err) {
                fprintf(stderr, "setsockopt IPV6_JOIN_GROUP: %s\n", strerror(errno));
                LogError("setsockopt IPV6_JOIN_GROUP: %s", strerror(errno));
                break;
            }
            ret = 0;
        } break;

        default:;
    }

    return ret;
} /* joinGroup */

static int isMulticast(struct sockaddr_storage *addr) {
    int ret;

    ret = -1;
    switch (addr->ss_family) {
        case AF_INET: {
            struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
            ret = IN_MULTICAST(ntohl(addr4->sin_addr.s_addr));
        } break;

        case AF_INET6: {
            struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
            ret = IN6_IS_ADDR_MULTICAST(&addr6->sin6_addr);
        } break;
        default:;
    }

    return ret;
} /* End of isMulticast */
