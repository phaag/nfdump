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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef SYSLOG_NAMES
#define SYSLOG_NAMES 1
#endif

#include <stdarg.h>
#include <syslog.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "util.h"

/* Global vars */

static int verbose = 0;

/* Function prototypes */
static int check_number(char *s, int len);

static int ParseTime(char *s, time_t *t_start);

static int use_syslog = 0;

#ifdef sun
struct _code {
    char *c_name;
    int c_val;
} facilitynames[] = {{"auth", LOG_AUTH},     {"cron", LOG_CRON},     {"daemon", LOG_DAEMON}, {"kern", LOG_KERN},
                     {"lpr", LOG_LPR},       {"mail", LOG_MAIL},     {"news", LOG_NEWS},     {"security", LOG_AUTH}, /* DEPRECATED */
                     {"syslog", LOG_SYSLOG}, {"user", LOG_USER},     {"uucp", LOG_UUCP},     {"local0", LOG_LOCAL0},
                     {"local1", LOG_LOCAL1}, {"local2", LOG_LOCAL2}, {"local3", LOG_LOCAL3}, {"local4", LOG_LOCAL4},
                     {"local5", LOG_LOCAL5}, {"local6", LOG_LOCAL6}, {"local7", LOG_LOCAL7}, {NULL, -1}};
#endif

/* Functions */

double t(void) {
    static double t0;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    double h = t0;
    t0 = tv.tv_sec + tv.tv_usec / 1000000.0;
    return t0 - h;
}  // End of t

/*
** usleep(3) implemented with select.
*/
void xsleep(suseconds_t usec) {
    struct timeval tv;

    tv.tv_sec = 0;
    tv.tv_usec = usec;

    select(0, NULL, NULL, NULL, &tv);
}

// Check cmd line argument length
// exit on failure
void CheckArgLen(char *arg, size_t len) {
    size_t i = 0;
    while (arg[i] != '\0' && i < len) i++;
    if (i > len) {
        fprintf(stderr, "Input string error. Length > %zu\n", len);
        exit(EXIT_FAILURE);
        // unreached
    }
}  // End of CheckArgLen

/*
 * test for file or directory
 * returns:
 * -1 error
 *  0 does not exists
 *  1 exists, but wrong type
 *  2 exists, ok
 */
int TestPath(char *path, unsigned type) {
    struct stat fstat;

    if (!path) {
        LogError("NULL file name in %s line %d", __FILE__, __LINE__);
        return -1;
    }

    if (strlen(path) >= MAXPATHLEN) {
        LogError("MAXPATHLEN error in %s line %d", __FILE__, __LINE__);
        return -1;
    }

    if (stat(path, &fstat)) {
        if (errno == ENOENT) {
            return 0;
        } else {
            LogError("stat(%s) error in %s line %d: %s", path, __FILE__, __LINE__, strerror(errno));
            return -1;
        }
    }

    if (type) {
        if (!(fstat.st_mode & type)) {
            return 1;
        } else {
            return 2;
        }
    } else if (S_ISREG(fstat.st_mode) || S_ISDIR(fstat.st_mode)) {
        return 2;
    } else {
        LogError("Not a file or directory: %s", path);
        return -1;
    }

    /* NOTREACHED */
}  // End of TestPath

/*
 * check for existing file or directory
 * returns:
 *  0 does not exists or error
 *  1 exists
 */
int CheckPath(char *path, unsigned type) {
    int ret = TestPath(path, type);
    switch (ret) {
        case 0:
            LogError("path does not exist: %s", path);
            break;
        case 1:
            if (type && type == S_IFREG)
                LogError("not a regular file: %s", path);
            else if (type && type == S_IFDIR)
                LogError("not a directory: %s", path);
            else
                LogError("path is not a file or directory: %s", path);
            break;
    }
    return ret == 2 ? 1 : 0;
}  // End of CheckPath

void EndLog() {
    if (use_syslog) closelog();
}  // End of CloseLog

int InitLog(int want_syslog, char *name, char *facility, int verbose_log) {
    int i;
    char *logname;

    verbose = verbose_log;
    if (!want_syslog) {
        if (verbose) {
            LogInfo("Verbose log level: %u", verbose);
        }
        return 1;
    }

    if (!facility || strlen(facility) > 32) {
        fprintf(stderr, "Invalid syslog facility name '%s'!\n", facility);
        return 0;
    }

    i = 0;
    while (facilitynames[i].c_name && strcasecmp(facilitynames[i].c_name, facility) != 0) {
        i++;
    }

    if (facilitynames[i].c_name == NULL) {
        fprintf(stderr, "Invalid syslog facility name '%s'!\n", facility);
        return 0;
    }

    if ((logname = strrchr(name, '/')) != 0) {
        logname++;
    } else {
        logname = name;
    }
    openlog(logname, LOG_CONS | LOG_PID, facilitynames[i].c_val);
    use_syslog = 1;

    return 1;

}  // End of InitLog

/*
 * some modules are needed for daemon code as well as normal stdio code
 * therefore a generic LogError is defined, which maps in this case
 * to stderr
 */
void LogError(char *format, ...) {
    va_list var_args;
    char string[512];

    if (use_syslog) {
        va_start(var_args, format);
        vsnprintf(string, 511, format, var_args);
        va_end(var_args);
        syslog(LOG_ERR, "%s", string);
        dbg_printf("%s\n", string);
    } else {
        va_start(var_args, format);
        vsnprintf(string, 511, format, var_args);
        fprintf(stderr, "%s\n", string);
        va_end(var_args);
    }

}  // End of LogError

void LogInfo(char *format, ...) {
    va_list var_args;
    char string[512];

    if (use_syslog) {
        va_start(var_args, format);
        vsnprintf(string, 511, format, var_args);
        va_end(var_args);
        syslog(LOG_INFO, "%s", string);
        dbg_printf("%s\n", string);
    } else if (verbose) {
        va_start(var_args, format);
        vsnprintf(string, 511, format, var_args);
        fprintf(stderr, "%s\n", string);
        va_end(var_args);
    }

}  // End of LogInfo

void LogVerbose(char *format, ...) {
    va_list var_args;
    char string[512];

    if (verbose > 1) {
        va_start(var_args, format);
        vsnprintf(string, 511, format, var_args);
        fprintf(stderr, "%s\n", string);
        va_end(var_args);
    }

}  // End of LogVerbose

static int check_number(char *s, int len) {
    size_t l = strlen(s);

    for (int i = 0; i < l; i++) {
        if (s[i] < '0' || s[i] > '9') {
            LogError("Time format error at '%s': unexpected character: '%c'.\n", s, s[i]);
            return 0;
        }
    }

    if (l != len) {
        LogError("Time format error: '%s' unexpected.\n", s);
        return 0;
    }
    return 1;

}  // End of check_number

static int ParseTime(char *s, time_t *t_start) {
    struct tm ts;
    int i;
    char *p, *q;

    /* A time string may look like:
     * yyyy/MM/dd.hh:mm:ss
     */

    memset((void *)&ts, 0, sizeof(ts));
    ts.tm_isdst = -1;

    p = s;

    // parse year
    q = strchr(p, '/');
    if (q) {
        *q++ = 0;
    }
    if (!check_number(p, 4)) return 0;
    i = atoi(p);
    if (i > 2038 || i < 1970) {
        LogError("Year out of range: '%i'\n", i);
        *t_start = 0;
        return 0;
    }
    ts.tm_year = i - 1900;
    if (!q) {
        ts.tm_mday = 1;
        *t_start = mktime(&ts);
        return 1;
    }

    // parse month
    p = q;
    q = strchr(p, '/');
    if (q) *q++ = 0;
    if (!check_number(p, 2)) return 0;
    i = atoi(p);
    if (i < 1 || i > 12) {
        LogError("Month out of range: '%i'\n", i);
        *t_start = 0;
        return 0;
    }
    ts.tm_mon = i - 1;
    if (!q) {
        ts.tm_mday = 1;
        *t_start = mktime(&ts);
        return 1;
    }

    // Parse day
    p = q;
    q = strchr(p, '.');
    if (q) *q++ = 0;
    if (!check_number(p, 2)) return 0;
    i = atoi(p);
    if (i < 1 || i > 31) {
        LogError("Day out of range: '%i'\n", i);
        *t_start = 0;
        return 0;
    }
    ts.tm_mday = i;
    if (!q) {
        *t_start = mktime(&ts);
        return 1;
    }

    // Parse hour
    p = q;
    q = strchr(p, ':');
    if (q) *q++ = 0;
    if (!check_number(p, 2)) return 0;
    i = atoi(p);
    if (i < 0 || i > 23) {
        LogError("Hour out of range: '%i'\n", i);
        *t_start = 0;
        return 0;
    }
    ts.tm_hour = i;
    if (!q) {
        *t_start = mktime(&ts);
        return 1;
    }

    // Parse minute
    p = q;
    q = strchr(p, ':');
    if (q) *q++ = 0;
    if (!check_number(p, 2)) return 0;
    i = atoi(p);
    if (i < 0 || i > 59) {
        LogError("Minute out of range: '%i'\n", i);
        *t_start = 0;
        return 0;
    }
    ts.tm_min = i;
    if (!q) {
        *t_start = mktime(&ts);
        return 1;
    }

    // Parse second
    p = q;
    if (!check_number(p, 2)) return 0;
    i = atoi(p);
    if (i < 0 || i > 59) {
        LogError("Seconds out of range: '%i'\n", i);
        *t_start = 0;
        return 0;
    }
    ts.tm_sec = i;
    *t_start = mktime(&ts);
    return 1;

}  // End of ParseTime

timeWindow_t *ScanTimeFrame(char *tstring) {
    timeWindow_t *timeWindow;
    char *p;

    if (!tstring) {
        return NULL;
    }

    timeWindow = calloc(1, sizeof(timeWindow_t));
    if (!timeWindow) {
        LogError("calloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    // check for delta time window
    if (tstring[0] == '-' || tstring[0] == '+') {
        if (strlen(tstring) > 10) {
            LogError("Time string too long: %s", tstring);
            free(timeWindow);
            return NULL;
        }
        char *invalid = NULL;
        errno = 0;
        long sec = strtol(tstring, &invalid, 10);
        if (sec == 0 && errno != 0) {
            LogError("Invald time string %s: %s", tstring, strerror(errno));
            free(timeWindow);
            return NULL;
        }
        if (invalid && strlen(invalid) > 0) {
            LogError("Invald time string %s at %c", tstring, *invalid);
            free(timeWindow);
            return NULL;
        }
        if (sec == 0) {
            LogError("Ignore time string: %s", tstring, *invalid, strerror(errno));
            free(timeWindow);
            return NULL;
        }
        if (sec < 0) {
            timeWindow->last = abs((int)sec);
        } else {
            timeWindow->first = sec;
        }
    } else {
        if (strlen(tstring) < 4) {
            LogError("Time string format error '%s'\n", tstring);
            return NULL;
        }

        if ((p = strchr(tstring, '-')) == NULL) {
            ParseTime(tstring, &timeWindow->first);
        } else {
            *p++ = 0;
            ParseTime(tstring, &timeWindow->first);
            ParseTime(p, &timeWindow->last);
        }
    }

    return timeWindow;

}  // End of ScanTimeFrame

char *TimeString(time_t start, time_t end) {
    static char datestr[255];
    char t1[64], t2[64];
    struct tm *tbuff;

    if (start) {
        tbuff = localtime(&start);
        if (!tbuff) {
            perror("Error time convert");
            exit(250);
        }
        strftime(t1, 63, "%Y-%m-%d %H:%M:%S", tbuff);

        tbuff = localtime(&end);
        if (!tbuff) {
            perror("Error time convert");
            exit(250);
        }
        strftime(t2, 63, "%Y-%m-%d %H:%M:%S", tbuff);

        snprintf(datestr, 254, "%s - %s", t1, t2);
    } else {
        snprintf(datestr, 254, "Time Window unknown");
    }
    datestr[254] = 0;
    return datestr;
}

char *UNIX2ISO(time_t t) {
    struct tm *when;
    static char timestring[32];

    when = localtime(&t);
    when->tm_isdst = -1;
    snprintf(timestring, 31, "%4i%02i%02i%02i%02i%02i", when->tm_year + 1900, when->tm_mon + 1, when->tm_mday, when->tm_hour, when->tm_min,
             when->tm_sec);
    timestring[31] = '\0';

    return timestring;

}  // End of UNIX2ISO

time_t ISO2UNIX(char *timestring) {
    char c, *p;
    struct tm when;
    time_t t;

    // let localtime fill in all default fields such as summer time, TZ etc.
    t = time(NULL);
    localtime_r(&t, &when);
    when.tm_sec = 0;
    when.tm_wday = 0;
    when.tm_yday = 0;
    when.tm_isdst = -1;

    size_t len = strlen(timestring);
    if (len != 12 && len != 14) {
        LogError("Wrong time format '%s'\n", timestring);
        return 0;
    }
    // 2019 05 05 12 00 (10)
    // year
    p = timestring;
    c = p[4];
    p[4] = '\0';
    when.tm_year = atoi(p) - 1900;
    p[4] = c;

    // month
    p += 4;
    c = p[2];
    p[2] = '\0';
    when.tm_mon = atoi(p) - 1;
    p[2] = c;

    // day
    p += 2;
    c = p[2];
    p[2] = '\0';
    when.tm_mday = atoi(p);
    p[2] = c;

    // hour
    p += 2;
    c = p[2];
    p[2] = '\0';
    when.tm_hour = atoi(p);
    p[2] = c;

    // minute
    p += 2;
    c = p[2];
    p[2] = '\0';
    when.tm_min = atoi(p);
    p[2] = c;

    if (len == 14) {
        p += 2;
        when.tm_sec = atoi(p);
    }

    t = mktime(&when);
    if (t == -1) {
        LogError("Failed to convert string '%s'\n", timestring);
        return 0;
    } else {
        // printf("%s %s", timestring, ctime(&t));
        return t;
    }

}  // End of ISO2UNIX

long getTick(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    long theTick = ts.tv_nsec / 1000000;
    theTick += ts.tv_sec * 1000;
    return theTick;
}

char *DurationString(double duration) {
    static char s[128];
    int days = duration / 86400;
    int sum = 86400 * days;
    int hours = (duration - sum) / 3600;
    sum += 3600 * hours;
    int min = (duration - sum) / 60;
    double sec = duration - sum - 60 * min;
    if (days == 0)
        snprintf(s, 128, "    %02d:%02d:%06.3f", hours, min, sec);
    else
        snprintf(s, 128, "%2dd %02d:%02d:%06.3f", days, hours, min, sec);
    s[127] = '\0';
    return s;
}  // End of DurationString

void InitStringlist(stringlist_t *list, int block_size) {
    list->list = NULL;
    list->num_strings = 0;
    list->max_index = 0;
    list->block_size = block_size;

}  // End of InitStringlist

void InsertString(stringlist_t *list, char *string) {
    if (!list->list) {
        list->max_index = list->block_size;
        list->num_strings = 0;
        list->list = (char **)malloc(list->max_index * sizeof(char *));
        if (!list->list) {
            LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
            exit(250);
        }
    }
    list->list[list->num_strings++] = string ? strdup(string) : NULL;

    if (list->num_strings == list->max_index) {
        list->max_index += list->block_size;
        list->list = (char **)realloc(list->list, list->max_index * sizeof(char *));
        if (!list->list) {
            LogError("realloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
            exit(250);
        }
    }

}  // End of InsertString

void format_number(uint64_t num, char *s, int plain, int fixed_width) {
    double f = num;

    if (plain) {
        snprintf(s, 31, "%llu", (long long unsigned)num);
    } else {
        if (f >= _1TB) {
            if (fixed_width)
                snprintf(s, NUMBER_STRING_SIZE - 1, "%5.1f T", f / _1TB);
            else
                snprintf(s, NUMBER_STRING_SIZE - 1, "%.1f T", f / _1TB);
        } else if (f >= _1GB) {
            if (fixed_width)
                snprintf(s, NUMBER_STRING_SIZE - 1, "%5.1f G", f / _1GB);
            else
                snprintf(s, NUMBER_STRING_SIZE - 1, "%.1f G", f / _1GB);
        } else if (f >= _1MB) {
            if (fixed_width)
                snprintf(s, NUMBER_STRING_SIZE - 1, "%5.1f M", f / _1MB);
            else
                snprintf(s, NUMBER_STRING_SIZE - 1, "%.1f M", f / _1MB);
        } else {
            if (fixed_width)
                snprintf(s, NUMBER_STRING_SIZE - 1, "%4.0f", f);
            else
                snprintf(s, NUMBER_STRING_SIZE - 1, "%.0f", f);
        }
        s[NUMBER_STRING_SIZE - 1] = '\0';
    }

}  // End of format_number

void inet_ntop_mask(uint32_t ipv4, int mask, char *s, socklen_t sSize) {
    if (mask) {
        ipv4 &= 0xffffffffL << (32 - mask);
        ipv4 = htonl(ipv4);
        inet_ntop(AF_INET, &ipv4, s, sSize);
    } else {
        s[0] = '\0';
    }

}  // End of inet_ntop_mask

void inet6_ntop_mask(uint64_t ipv6[2], int mask, char *s, socklen_t sSize) {
    uint64_t ip[2];

    ip[0] = ipv6[0];
    ip[1] = ipv6[1];
    if (mask) {
        if (mask <= 64) {
            ip[0] = ip[0] & (0xffffffffffffffffLL << (64 - mask));
            ip[1] = 0;
        } else {
            ip[1] = ip[1] & (0xffffffffffffffffLL << (128 - mask));
        }
        ip[0] = htonll(ip[0]);
        ip[1] = htonll(ip[1]);
        inet_ntop(AF_INET6, ip, s, sSize);

    } else {
        s[0] = '\0';
    }
}  // End of inet_ntop_mask

// Copyright (c) 2008-2009 Bjoern Hoehrmann <bjoern@hoehrmann.de>
// See http://bjoern.hoehrmann.de/utf-8/decoder/dfa/ for details.

static const uint8_t utf8d[] = {
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 00..1f
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 20..3f
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 40..5f
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 60..7f
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,  // 80..9f
    7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,  // a0..bf
    8,   8,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,  // c0..df
    0xa, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x4, 0x3, 0x3,                                                  // e0..ef
    0xb, 0x6, 0x6, 0x6, 0x5, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8,                                                  // f0..ff
    0x0, 0x1, 0x2, 0x3, 0x5, 0x8, 0x7, 0x1, 0x1, 0x1, 0x4, 0x6, 0x1, 0x1, 0x1, 0x1,                                                  // s0..s0
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1,  // s1..s2
    1,   2,   1,   1,   1,   1,   1,   2,   1,   2,   1,   1,   1,   1,   1,   1,   1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1,  // s3..s4
    1,   2,   1,   1,   1,   1,   1,   1,   1,   2,   1,   1,   1,   1,   1,   1,   1, 1, 1, 1, 1, 1, 1, 3, 1, 3, 1, 1, 1, 1, 1, 1,  // s5..s6
    1,   3,   1,   1,   1,   1,   1,   3,   1,   3,   1,   1,   1,   1,   1,   1,   1, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // s7..s8
};

uint32_t decode(uint32_t *state, uint32_t *codep, uint32_t byte) {
    uint32_t type = utf8d[byte];

    *codep = (*state != UTF8_ACCEPT) ? (byte & 0x3fu) | (*codep << 6) : (0xff >> type) & (byte);

    *state = utf8d[256 + *state * 16 + type];
    return *state;
}

uint32_t validate_utf8(uint32_t *state, char *str, size_t len) {
    size_t i;
    uint32_t type;

    for (i = 0; i < len; i++) {
        // We don't care about the codepoint, so this is
        // a simplified version of the decode function.
        type = utf8d[(uint8_t)str[i]];
        *state = utf8d[256 + (*state) * 16 + type];

        if (*state == UTF8_REJECT) break;
    }

    return *state;
}
