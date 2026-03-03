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

/* legacy code for NfSen */

#include "nfstatfile.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "bookkeeper.h"
#include "expire.h"
#include "logging.h"
#include "util.h"

static int SetFileLock(int fd) {
    struct flock fl;

    fl.l_type = F_WRLCK;    /* F_RDLCK, F_WRLCK, F_UNLCK    */
    fl.l_whence = SEEK_SET; /* SEEK_SET, SEEK_CUR, SEEK_END */
    fl.l_start = 0;         /* Offset from l_whence         */
    fl.l_len = 0;           /* length, 0 = to EOF           */
    fl.l_pid = getpid();    /* our PID                      */

    return fcntl(fd, F_SETLKW, &fl); /* F_GETLK, F_SETLK, F_SETLKW */

}  // End of SetFileLock

static int ReleaseFileLock(int fd) {
    struct flock fl;

    fl.l_type = F_UNLCK;    /* F_RDLCK, F_WRLCK, F_UNLCK    */
    fl.l_whence = SEEK_SET; /* SEEK_SET, SEEK_CUR, SEEK_END */
    fl.l_start = 0;         /* Offset from l_whence         */
    fl.l_len = 0;           /* length, 0 = to EOF           */
    fl.l_pid = getpid();    /* our PID                      */

    return fcntl(fd, F_SETLK, &fl); /* set the region to unlocked */

}  // End of SetFileLock

int WriteStatInfo(channel_t *channel) {
    char stat_file[MAXPATHLEN];
    snprintf(stat_file, sizeof(stat_file), "%s/%s", channel->datadir, ".nfstat");

    bookkeeper_t bookkeeper;
    book_get(channel->book_handle, &bookkeeper);

    int fd = open(stat_file, O_RDWR | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0) {
        LogError("open() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    int err = SetFileLock(fd);
    if (err != 0) {
        LogError("ioctl(F_WRLCK) error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        close(fd);
        return 0;
    }

    if (ftruncate(fd, 0) < 0) {
        LogError("ftruncate() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        ReleaseFileLock(fd);
        close(fd);
        return 0;
    }

    char line[256];
    int len = snprintf(line, sizeof(line), "first=%llu\n", (unsigned long long)bookkeeper.first);
    if (write(fd, line, len) < 0) {
        LogError("write() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
    }
    len = snprintf(line, sizeof(line), "last=%llu\n", (unsigned long long)bookkeeper.last);
    if (write(fd, line, len) < 0) {
        LogError("write() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
    }
    len = snprintf(line, sizeof(line), "size=%llu\n", (unsigned long long)bookkeeper.filesize);
    if (write(fd, line, len) < 0) {
        LogError("write() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
    }
    len = snprintf(line, sizeof(line), "maxsize=%llu\n", (unsigned long long)bookkeeper.max_filesize);
    if (write(fd, line, len) < 0) {
        LogError("write() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
    }
    len = snprintf(line, sizeof(line), "numfiles=%llu\n", (unsigned long long)bookkeeper.numfiles);
    if (write(fd, line, len) < 0) {
        LogError("write() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
    }
    len = snprintf(line, sizeof(line), "lifetime=%llu\n", (unsigned long long)bookkeeper.max_lifetime);
    if (write(fd, line, len) < 0) {
        LogError("write() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
    }
    len = snprintf(line, sizeof(line), "watermark=%llu\n", (unsigned long long)bookkeeper.watermark);
    if (write(fd, line, len) < 0) {
        LogError("write() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
    }
    len = snprintf(line, sizeof(line), "status=%llu\n", (unsigned long long)bookkeeper.dirty);
    if (write(fd, line, len) < 0) {
        LogError("write() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
    }

    ReleaseFileLock(fd);
    close(fd);

    return 1;

}  // End of WriteStatInfo