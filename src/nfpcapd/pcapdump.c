/*
 *  Copyright (c) 2022-2026, Peter Haag
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

#include "pcapdump.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "flist.h"
#include "logging.h"
#include "packet_pcap.h"
#include "queue.h"
#include "util.h"

#define PCAP_TMP "pcap.current"
#define MAXBUFFERS 8

/*
 * Function prototypes
 */
static int OpenDumpFile(const char *fileName, int snaplen, int linktype);

static int AppendDumpFile(const char *fileName, int snaplen, int linkType);

static int CloseDumpFile(flushParam_t *param, time_t t_start);

static int appendPcap(flushParam_t *flushParam, const char *existFile, const char *appendFile);

static int PreserveFailedDumpFile(const char *dumpFile, const char *dateFile);

/*
 * Functions
 */

static int OpenDumpFile(const char *fileName, int snaplen, int linktype) {
    dbg_printf("OpenDumpFile()\n");
    int fd = open(fileName, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        LogError("open() failed for file '%s': %s", fileName, strerror(errno));
        return -1;
    }

    struct pcap_file_header hdr;

    hdr.magic = 0xa1b2c3d4; /* little-endian pcap */
    hdr.version_major = PCAP_VERSION_MAJOR;
    hdr.version_minor = PCAP_VERSION_MINOR;
    hdr.thiszone = 0; /* GMT */
    hdr.sigfigs = 0;
    hdr.snaplen = snaplen;
    hdr.linktype = linktype;

    ssize_t written = write(fd, &hdr, sizeof(hdr));
    if (written != sizeof(hdr)) {
        close(fd);
        return -1;
    }

    return fd;
}  // End of OpenDumpFile

static int AppendDumpFile(const char *fileName, int snaplen, int linkType) {
    int fd = open(fileName, O_RDWR);
    if (fd < 0) {
        LogError("open() failed for file '%s': %s", fileName, strerror(errno));
        return -1;
    }

    struct pcap_file_header hdr;

    ssize_t n = read(fd, &hdr, sizeof(hdr));
    if (n != sizeof(hdr)) {
        LogError("read() failed for file '%s': %s", fileName, strerror(errno));
        close(fd);
        return -1;
    }

    // Check magic number
    if (hdr.magic != 0xa1b2c3d4) {
        LogError("%s() wrong pcap magic for file: %s", __func__, fileName);
        close(fd);
        return -1;
    }

    // Sanity check
    if (hdr.version_major != PCAP_VERSION_MAJOR || hdr.version_minor != PCAP_VERSION_MINOR) {
        LogError("%s() major/minor (%u/%u) version missmatch for file: %s", __func__, hdr.version_major, hdr.version_minor, fileName);
        close(fd);
        return -1;
    }

    // Verify compatibility
    if ((int)hdr.snaplen != snaplen || (int)hdr.linktype != linkType) {
        LogError("%s() snaplen/linktype (%u/%u) version missmatch for file: %s", __func__, hdr.version_major, hdr.version_minor, fileName);
        close(fd);
        return -1;
    }

    // Seek to end for appending packets
    if (lseek(fd, 0, SEEK_END) == (off_t)-1) {
        LogError("lseek() failed for file '%s': %s", fileName, strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}  // End of AppendDumpFile

static int CloseDumpFile(flushParam_t *flushParam, time_t t_start) {
    struct tm tmBuff = {0};
    struct tm *now = localtime_r(&t_start, &tmBuff);
    char fmt[16];
    strftime(fmt, sizeof(fmt), flushParam->extensionFormat, now);

    if (flushParam->pfd == 0) return 1;

    close(flushParam->pfd);
    flushParam->pfd = 0;

    dbg_printf("CloseDumpFile()\n");
    char datefile[MAXPATHLEN];
    int pos = SetupPath(now, flushParam->archivedir, flushParam->subdir_index, datefile);
    char *p = datefile + (ptrdiff_t)pos;

    snprintf(p, MAXPATHLEN - pos - 1, "pcapd.%s", fmt);

    int fileStat = TestPath(datefile, S_IFREG);
    if (fileStat == PATH_NOTEXISTS) {
        // file does not exist
        dbg_printf("CloseDumpFile() %s -> %s\n", flushParam->dumpFile, datefile);
        int err = rename(flushParam->dumpFile, datefile);
        if (err) {
            LogError("rename() failed: %s", strerror(errno));
        }
    } else if (fileStat == PATH_OK) {
        // file exists - append pcap
        dbg_printf("CloseDumpFile() append %s -> %s\n", flushParam->dumpFile, datefile);
        if (!appendPcap(flushParam, datefile, flushParam->dumpFile)) {
            LogError("Failed to append pcapfile '%s' to '%s'", flushParam->dumpFile, datefile);
            PreserveFailedDumpFile(flushParam->dumpFile, datefile);
            return -1;
        }
        if (unlink(flushParam->dumpFile) < 0) {
            LogError("unlink() failed for temporary pcapfile '%s': %s", flushParam->dumpFile, strerror(errno));
            return -1;
        }
    } else {
        LogError("CloseDumpFile() TestPath() failed: %d", fileStat);
        return -1;
    }

    return 0;

}  // End of CloseDumpFile

/*
 * A failed append must not leave the temporary capture at dumpFile: the next
 * rotation opens that fixed path with O_TRUNC. Preserve it beside the archive
 * instead, using the process ID and a sequence number to avoid collisions.
 */
static int PreserveFailedDumpFile(const char *dumpFile, const char *dateFile) {
    static uint32_t failedDumpSequence = 0;
    char failedFile[MAXPATHLEN];

    for (uint32_t attempt = 0; attempt < 1000; attempt++) {
        uint32_t sequence = failedDumpSequence++;
        int len = snprintf(failedFile, sizeof(failedFile), "%s.append-failed.%ld.%u", dateFile, (long)getpid(), sequence);
        if (len < 0 || (size_t)len >= sizeof(failedFile)) {
            LogError("Failed-pcap filename is too long for '%s'", dateFile);
            return 0;
        }
        if (TestPath(failedFile, S_IFREG) == PATH_NOTEXISTS) {
            if (rename(dumpFile, failedFile) == 0) {
                LogError("Preserved unappended pcapfile as '%s'", failedFile);
                return 1;
            }
            LogError("rename() failed while preserving '%s': %s", dumpFile, strerror(errno));
            return 0;
        }
    }

    LogError("Unable to find a unique filename to preserve '%s'", dumpFile);
    return 0;
}  // End of PreserveFailedDumpFile

static int appendPcap(flushParam_t *flushParam, const char *existFile, const char *appendFile) {
    // open existing file in append mode
    int infd = AppendDumpFile(existFile, flushParam->snaplen, flushParam->linkType);
    if (infd < 0) {
        return 0;
    }

    // open new appendFile
    int outfd = open(appendFile, O_RDONLY);
    if (outfd < 0) {
        LogError("open() failed for file '%s': %s", appendFile, strerror(errno));
        close(infd);
        return 0;
    }

    // skip file header
    struct pcap_file_header hdr;
    ssize_t n = read(outfd, &hdr, sizeof(hdr));
    if (n != sizeof(hdr)) {
        LogError("read() failed for file '%s': %s", appendFile, strerror(errno));
        close(infd);
        close(outfd);
        return 0;
    }

    uint8_t buf[128 * 1024];
    while ((n = read(outfd, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(infd, buf + off, n - off);
            if (w <= 0) {
                LogError("write() failed for file '%s': %s", existFile, w < 0 ? strerror(errno) : "short write");
                close(infd);
                close(outfd);
                return 0;
            }
            off += w;
        }
    }

    // n == 0 => EOF
    if (n < 0) {
        LogError("read() failed for file '%s': %s", existFile, strerror(errno));
    }

    close(infd);
    close(outfd);

    return n == 0;
}  // End of appendPcap

int InitFlushParam(flushParam_t *flushParam) {
    flushParam->bufferQueue = queue_init(MAXBUFFERS);
    flushParam->flushQueue = queue_init(MAXBUFFERS);
    if (!flushParam->bufferQueue || !flushParam->flushQueue) {
        LogError("Init buffer queues failed");
        return -1;
    }
    for (int i = 0; i < MAXBUFFERS; i++) {
        packetBuffer_t *packetBuffer = malloc(sizeof(packetBuffer_t) + 1048576);
        if (!packetBuffer) {
            LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return -1;
        }
        packetBuffer->bufferSize = 0;
        packetBuffer->timeStamp = 0;
        packetBuffer->rotate = 0;
        queue_push(flushParam->bufferQueue, (void *)packetBuffer);
    }

    flushParam->dumpFile = malloc(PATH_MAX);
    if (!flushParam->dumpFile) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return -1;
    }

    return 0;

}  // End of InitBufferQueues

void __attribute__((noreturn)) * flush_thread(void *args) {
    flushParam_t *flushParam = (flushParam_t *)args;

    snprintf(flushParam->dumpFile, MAXPATHLEN, "%s/%s-%i", flushParam->archivedir, PCAP_TMP, getpid());
    flushParam->dumpFile[MAXPATHLEN - 1] = '\0';

    while (1) {
        packetBuffer_t *packetBuffer = queue_pop(flushParam->flushQueue);
        if (packetBuffer == QUEUE_CLOSED) {
            break;
        }
        dbg_printf("flush_thread() next buffer: %zu\n", packetBuffer->bufferSize);
        time_t timeStamp = packetBuffer->timeStamp;
        int rotate = packetBuffer->rotate;

        if (packetBuffer->bufferSize) {
            if (flushParam->pfd == 0) {
                int fd = OpenDumpFile(flushParam->dumpFile, flushParam->snaplen, flushParam->linkType);
                if (fd < 0) {
                    LogError("flush_thread() - failed to open dump file");
                } else {
                    flushParam->pfd = fd;
                }
            }
            if (flushParam->pfd) {
                dbg_printf("flush_thread() flush buffer\n");
                if (write(flushParam->pfd, packetBuffer->buffer, packetBuffer->bufferSize) <= 0) {
                    LogError("write() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                }
            }
        }

        packetBuffer->bufferSize = 0;
        packetBuffer->timeStamp = 0;
        packetBuffer->rotate = 0;
        queue_push(flushParam->bufferQueue, packetBuffer);

        if (rotate) {
            // rotate file
            dbg_printf("flush_thread() CloseDumpFile\n");
            if (CloseDumpFile(flushParam, timeStamp) < 0) {
                LogError("flush_thread() - failed to close dump file");
            }
        }
    }

    pthread_exit("ok");
    /* NOTREACHED */

}  // End of flush_thread
