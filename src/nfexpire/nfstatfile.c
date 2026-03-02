/*
 *  Copyright (c) 2009-2025, Peter Haag
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

typedef struct {
    double factor;
    const char *unit;
} ScaleStep;

static const ScaleStep SIZE_STEPS[] = {
    {1099511627776.0, "TB"},  // 1024^4
    {1073741824.0, "GB"},     // 1024^3
    {1048576.0, "MB"},        // 1024^2
    {1024.0, "KB"},           // 1024^1
    {1.0, "B"},               // 1024^0
    {0.0, NULL}               // Sentinel
};

static const ScaleStep TIME_STEPS[] = {
    {604800.0, "weeks"},  // weeks
    {86400.0, "days"},    // days
    {3600.0, "hours"},    // hours
    {60.0, "min"},        // minutes
    {1.0, "sec"},         // seconds
    {0.0, NULL}           // Sentinel
};

// Internal helper to handle the formatting logic
static char *FormatScaled(char *buf, size_t len, uint64_t v, const ScaleStep *steps) {
    double f = (double)v;

    for (int i = 0; steps[i].unit != NULL; ++i) {
        if (f >= steps[i].factor) {
            if (steps[i].factor > 1.0) {
                snprintf(buf, len, "%llu = %.1f %s", (unsigned long long)v, f / steps[i].factor, steps[i].unit);
            } else {
                snprintf(buf, len, "%llu %s", (unsigned long long)v, steps[i].unit);
            }
            return buf;
        }
    }

    // Fix 3: Handle the 0 case specifically
    snprintf(buf, len, "0 %s", steps[4].unit);  // Usually "B" or "sec"
    return buf;
}  // End of FormatScaled

// Thread-safe versions requiring a buffer
char *ScaleValue(char *buf, size_t len, uint64_t v) { return FormatScaled(buf, len, v, SIZE_STEPS); }

char *ScaleTime(char *buf, size_t len, uint64_t v) { return FormatScaled(buf, len, v, TIME_STEPS); }

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

/*
void PrintDirStat(dirstat_t *dirstat) {
    struct tm ts_buf;
    struct tm *ts;
    time_t t;
    char string[32];

    t = dirstat->first;
    ts = localtime_r(&t, &ts_buf);
    strftime(string, 31, "%Y-%m-%d %H:%M:%S", ts);
    string[31] = '\0';
    printf("First:     %s\n", string);

    t = dirstat->last;
    ts = localtime_r(&t, &ts_buf);
    strftime(string, 31, "%Y-%m-%d %H:%M:%S", ts);
    string[31] = '\0';
    printf("Last:      %s\n", string);

    printf("Lifetime:  %s\n", ScaleTime(dirstat->last - dirstat->first));

    printf("Numfiles:  %llu\n", (unsigned long long)dirstat->numfiles);
    printf("Filesize:  %s\n", ScaleValue(dirstat->filesize));

    if (dirstat->max_size)
    printf("Max Size:  %s\n", ScaleValue(dirstat->max_size));
    else
    printf("Max Size:  <none>\n");

    if (dirstat->max_lifetime)
    printf("Max Life:  %s\n", ScaleTime(dirstat->max_lifetime));
    else
    printf("Max Life:  <none>\n");

    printf("Watermark: %llu%%\n", (unsigned long long)dirstat->low_water);

    switch (dirstat->status) {
        case STATFILE_OK:
        printf("Status:    OK\n");
        break;
        case FORCE_REBUILD:
        printf("Status:    Force rebuild\n");
        break;
        default:
        printf("Status:    Unexpected: %llu\n", (unsigned long long)dirstat->status);
        break;
    }
}  // End of PrintDirStat
*/
