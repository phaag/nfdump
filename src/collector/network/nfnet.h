/*
 *  Copyright (c) 2009-2026, Peter Haag
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

#ifndef _NFNET_H
#define _NFNET_H 1

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

/* Definitions */

typedef struct PacketCtx_s {
    struct msghdr msg;
    struct iovec iov;
    struct sockaddr_storage sender;
    char control[CMSG_SPACE(sizeof(struct timeval))];
    ssize_t bufferLen;
    _Alignas(16) uint8_t buffer[];
} PacketCtx_t;

#define UDP_PACKET_SIZE 1472

/* input buffer size, to read data from the network */
#define NETWORK_INPUT_BUFF_SIZE 65536  // Maximum UDP message size

/* Function prototypes */

int Unicast_receive_sockets(const char *bindhost, const char *listenport, int family, unsigned sockbuflen, int socks[2]);

int Multicast_receive_socket(const char *hostname, const char *listenport, int family, unsigned sockbuflen);

int Unicast_send_socket(const char *hostname, const char *listenport, int family, unsigned int wmem_size, struct sockaddr_storage *addr,
                        socklen_t *addrlen);

int Multicast_send_socket(const char *hostname, const char *listenport, int family, unsigned int wmem_size, struct sockaddr_storage *addr,
                          socklen_t *addrlen);

PacketCtx_t *init_packet_ctx(size_t buf_size);

int Raw_send_socket(int sockbuflen);

int LookupHost(char *hostname, char *port, struct sockaddr_in *addr);

#endif  //_NFNET_H
