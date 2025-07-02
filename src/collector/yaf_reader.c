/*
 *  Copyright (c) 2025, Peter Haag
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

static int yafFd = 0;

/*
 * Function prototypes
 */

// set filter if requested
// live device

int setup_yaf(char *fname) {
    struct stat fileStat = {0};
    int fd = open(fname, O_RDONLY);
    if (fd < 0) {
        LogError("open() failed for %s in %s line %d: %s", fname, __FILE__, __LINE__, strerror(errno));
        return 0;
    }
    int ret = fstat(fd, &fileStat);
    if (ret < 0) {
        LogError("fstat() failed for %s in %s line %d: %s", fname, __FILE__, __LINE__, strerror(errno));
        return 0;
    }
    if (fileStat.st_size < sizeof(ipfix_header_t)) {
        LogError("File %s is not a valid yaf (ipfix) file", fname);
        return 0;
    }

    yafFd = fd;
    return 1;
} /* End of setup_pcap_offline */

ssize_t NextYafRecord(int fill1, void *buffer, size_t buffer_size, int fill2, struct sockaddr *sock, socklen_t *size) {
    if (yafFd == 0) return -1;

    // fake localhost receiver
    struct sockaddr_in *in_sock = (struct sockaddr_in *)sock;
    in_sock->sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &(in_sock->sin_addr));
    in_sock->sin_port = 0;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
    in_sock->sin_len = sizeof(struct sockaddr_in);
#endif

    ipfix_header_t *ipfix_header = (ipfix_header_t *)buffer;
    uint8_t *data = buffer + sizeof(ipfix_header_t);

    ssize_t readBytes = read(yafFd, ipfix_header, sizeof(ipfix_header_t));
    if (readBytes != sizeof(ipfix_header_t)) {
        if (readBytes < 0) {
            // error
            LogError("read() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return readBytes;
        } else if (readBytes == 0) {
            // EOF
            close(yafFd);
            yafFd = 0;
            return -2;
        } else {
            // not enough data for header
            LogError("Short read - incomplete ipfix header while reading yaf (ipfix) file");
            return -1;
        }
    }

    uint16_t version = ntohs(ipfix_header->Version);
    uint16_t length = ntohs(ipfix_header->Length);

    if (version != 10 || length < sizeof(ipfix_header_t)) {
        LogError("Invalid read - not a valid ipfix header while reading yaf (ipfix) file");
        return -1;
    }
    readBytes = read(yafFd, data, length - sizeof(ipfix_header_t));

    // valid read - return
    if (readBytes == (length - sizeof(ipfix_header_t)))
        return length;
    else if (readBytes < 0) {
        // error
        LogError("read() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return readBytes;
    } else if (readBytes == 0) {
        // EOF - should not happen
        close(yafFd);
        yafFd = 0;
        LogError("Unexpected EOF - incomplete ipfix packet while reading yaf (ipfix) file");
        return -1;
    } else {
        // not enough data for packet
        LogError("Short read - incomplete ipfix packet while reading yaf (ipfix) file");
        return -1;
    }

}  // End of NextYafRecord