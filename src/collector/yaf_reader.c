/*
 *  Copyright (c) 2025-2026, Peter Haag
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "config.h"
#include "netflow/ipfix.h"
#include "util.h"
#include "yaf_reader.h"

static int yafFd = -1;
static struct sockaddr_storage yafSock;

// Setup YAF reader
int setup_yaf(const char *fname) {
    struct stat fileStat = {0};

    int fd = open(fname, O_RDONLY);
    if (fd < 0) {
        LogError("open(%s) failed: %s", fname, strerror(errno));
        return 0;
    }

    if (fstat(fd, &fileStat) < 0) {
        LogError("fstat(%s) failed: %s", fname, strerror(errno));
        close(fd);
        return 0;
    }

    if (fileStat.st_size < sizeof(ipfix_header_t)) {
        LogError("File %s too small to contain IPFIX header", fname);
        close(fd);
        return 0;
    }

    yafFd = fd;

    /* Fake localhost sender */
    struct sockaddr_in *in = (struct sockaddr_in *)&yafSock;
    memset(in, 0, sizeof(*in));
    in->sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &in->sin_addr);
    in->sin_port = 0;

    return 1;
}  // End of setup_yaf

// Safe read
static inline ssize_t read_full(int fd, void *buf, size_t len) {
    uint8_t *p = buf;
    size_t total = 0;

    while (total < len) {
        ssize_t r = read(fd, p + total, len - total);
        if (r == 0) return total;  // EOF
        if (r < 0) {
            if (errno == EINTR) continue;
            // otherwise error
            LogError("read() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return -1;
        }
        total += r;
    }
    return total;
}  // End of read_full

// Read next IPFIX record from YAF file
ssize_t NextYafRecord(void *buffer, size_t buffer_size, struct sockaddr_storage *sock, socklen_t *size, struct timeval *tv) {
    if (yafFd < 0) return -1;

    // set timestamp
    tv->tv_sec = time(NULL);
    tv->tv_usec = 0;

    /* Return fake sender */
    memcpy(sock, &yafSock, sizeof(yafSock));
    *size = sizeof(struct sockaddr_in);

    ipfix_header_t *ipfix_header = buffer;

    /* Read header */
    ssize_t r = read_full(yafFd, ipfix_header, sizeof(ipfix_header_t));
    if (r == 0) {
        // EOF
        close(yafFd);
        yafFd = -1;
        return -2;
    }
    if (r < 0) {
        return -1;
    }
    if (r != sizeof(*ipfix_header)) {
        LogError("Reading yaf file: short read - incomplete IPFIX header");
        return -1;
    }

    uint16_t version = ntohs(ipfix_header->Version);
    uint16_t length = ntohs(ipfix_header->Length);

    if (version != 10 || length < sizeof(ipfix_header_t)) {
        LogError("Reading yaf file: invalid IPFIX header");
        return -1;
    }

    if (length > buffer_size) {
        LogError("Reading yaf file: IPFIX message length %u exceeds buffer size %zu", length, buffer_size);
        return -1;
    }

    /* Read body */
    uint8_t *body = (uint8_t *)buffer + sizeof(*ipfix_header);
    size_t body_len = length - sizeof(*ipfix_header);

    r = read_full(yafFd, body, body_len);
    if (r < 0) {
        LogError("Reading yaf file: read body failed: %s", strerror(errno));
        return -1;
    }
    if ((size_t)r != body_len) {
        LogError("Reading yaf file: short read: incomplete IPFIX message");
        return -1;
    }

    return length;
}  // End of NextYafRecord