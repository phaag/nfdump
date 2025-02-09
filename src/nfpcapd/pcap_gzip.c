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

#include "pcap_gzip.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "util.h"
#include "zlib.h"

#define BUFLEN 16384

typedef struct readerArgs {
    gzFile in;
    FILE *out;
} readerArgs_t;

static void *gzipReader(void *arg);

// check for zlib header and setup
FILE *zlib_stream(char *pcap_file) {
    // in case we need support other compression methodes - check for methode
    /*
        FILE *zFile = fopen(pcap_file, "rb");
        if (!zFile) {
            LogError("fopen() failed: %s", strerror(errno));
            return NULL;
        }
        uint8_t signature[8];
        size_t numObj = fread(signature, sizeof(signature), 1, zFile);
        if (numObj < 1) {
            fclose(zFile);
            return NULL;
        }

        // check for gzip header bytes
        if (signature[0] != 0x1f || signature[1] != 0x8b) {
            fclose(zFile);
            return NULL;
        }
    */

    gzFile zFile = gzopen(pcap_file, "rb");
    if (zFile == NULL) {
        LogError("gzopen() failed: %s", strerror(errno));
        return NULL;
    }

    readerArgs_t *readerArgs = malloc(sizeof(readerArgs_t));
    if (!readerArgs) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        gzclose(zFile);
        return NULL;
    }

    // connect uncompress thread and pcap reader with a binary pipe
    int fd[2];
    pipe(fd);

    // read from gzip file, write to pipe
    readerArgs->in = zFile;
    readerArgs->out = fdopen(fd[1], "wb");

    // resulting pcap stream
    FILE *fpcap = fdopen(fd[0], "rb");

    if (!readerArgs->out || !fpcap) {
        LogError("fdopen() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        gzclose(zFile);
        return NULL;
    }

    pthread_t tid;
    int err = pthread_create(&tid, NULL, gzipReader, (void *)readerArgs);
    if (err) {
        LogError("pthread_create() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        gzclose(zFile);
        return NULL;
    }

    return fpcap;
}  // End of zlib_stream

__attribute__((noreturn)) static void *gzipReader(void *arg) {
    readerArgs_t *readerArgs = (readerArgs_t *)arg;
    gzFile in = readerArgs->in;
    FILE *out = readerArgs->out;

    for (;;) {
        char buf[BUFLEN];
        int err;
        int len = gzread(in, buf, sizeof(buf));
        if (len < 0) {
            LogError("gzread() error in %s line %d: %s", __FILE__, __LINE__, gzerror(in, &err));
            gzclose(in);
            fclose(out);
            pthread_exit(NULL);
        }
        if (len == 0) break;

        if ((int)fwrite(buf, 1, (unsigned)len, out) != len) {
            LogError("write() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        }
    }

    if (fclose(out)) LogError("fclose() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
    if (gzclose(in) != Z_OK) LogError("gzclose() error in %s line %d", __FILE__, __LINE__);

    pthread_exit(NULL);
}  // end of gzipReader