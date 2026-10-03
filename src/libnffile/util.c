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

#include "util.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
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

#include "logging.h"

typedef struct scal_steps_s {
    double factor;
    const char *scale;
} scale_steps_t;

// factor table for biinary counting
static const scale_steps_t bin_scale_steps[] = {
    {1099511627776.0, "T"},  // 1024^4
    {1073741824.0, "G"},     // 1024^3
    {1048576.0, "M"},        // 1024^2
    {1024.0, "K"},           // 1024^1
    {1.0, ""},               // 1024^0
    {0.0, NULL}              // Sentinel
};

// factor table for SI counting
static const scale_steps_t si_scale_steps[] = {{1000000000000.0, "T"},  // 1000^4
                                               {1000000000.0, "G"},     // 1000^3
                                               {1000000.0, "M"},        // 1000^2
                                               {1000.0, "k"},           // 1000^1
                                               {1.0, ""},               // 1000^0 Base (no unit)
                                               {0.0, NULL}};            // Sentinel

/* Functions */

double t(void) {
    static double t0;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    double h = t0;
    t0 = ts.tv_sec + ts.tv_nsec / 1000000000.0;
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
    if (arg == NULL) {
        fprintf(stderr, "Input string error. Expected argument\n");
        exit(EXIT_FAILURE);
    }
    size_t i = 0;
    while (arg[i] != '\0' && i < len) i++;
    if (i > len) {
        fprintf(stderr, "Input string error. Length > %zu\n", len);
        exit(EXIT_FAILURE);
        // unreached
    }
}  // End of CheckArgLen

// Strictly parse a cli integer argument, e.g. the optarg of a getopt() option.
//
// Unlike atoi(), which silently maps any garbage input ("abc", "5abc", "")
// to 0 and has undefined behaviour on overflow, this requires the entire
// string to be a valid, in-range integer. On success returns 1 and stores
// the result in *value. On failure returns 0, logs an error naming optName
// and the offending argument, and leaves *value untouched.
int ParseInt(const char *argument, const char *optName, int min, int max, int *value) {
    if (argument == NULL || *argument == '\0') {
        LogError("Option %s needs a numeric argument", optName);
        return 0;
    }

    errno = 0;
    char *end = NULL;
    long parsed = strtol(argument, &end, 10);
    if (errno == ERANGE || end == argument || *end != '\0' || parsed < min || parsed > max) {
        LogError("Option %s: invalid number '%s' - expected an integer between %d and %d", optName, argument, min, max);
        return 0;
    }

    *value = (int)parsed;
    return 1;
}  // End of ParseInt

/*
 * test for file or directory
 * returns:
 * -1 error
 *  0 does not exists
 *  1 exists, but wrong type
 *  2 exists, ok
 */
int TestPath(const char *path, unsigned type) {
    if (!path) {
        LogError("NULL file name in %s line %d", __FILE__, __LINE__);
        return -1;
    }

    if (strlen(path) >= MAXPATHLEN) {
        LogError("MAXPATHLEN error in %s line %d", __FILE__, __LINE__);
        return -1;
    }

    struct stat fstat;
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
int CheckPath(const char *path, unsigned type) {
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

typedef struct dateTime_s {
    int year;
    int month;
    int day;
    int hour;
    int minute;
    int second;
    int millis;
} dateTime_t;

static int ParseDecimal(const char *s, size_t offset, size_t len, int *value) {
    int number = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[offset + i];
        if (!isdigit(c)) return 0;
        number = 10 * number + c - '0';
    }
    *value = number;
    return 1;
}  // End of ParseDecimal

static int IsLeapYear(int year) { return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0; }

static int DaysInMonth(int year, int month) {
    static const uint8_t days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (month < 1 || month > 12) return 0;
    return month == 2 && IsLeapYear(year) ? 29 : days[month - 1];
}  // End of DaysInMonth

static int ValidDateTime(const dateTime_t *dateTime) {
    return dateTime->year >= 1970 && dateTime->year <= 2038 && dateTime->month >= 1 && dateTime->month <= 12 && dateTime->day >= 1 &&
           dateTime->day <= DaysInMonth(dateTime->year, dateTime->month) && dateTime->hour >= 0 && dateTime->hour <= 23 && dateTime->minute >= 0 &&
           dateTime->minute <= 59 && dateTime->second >= 0 && dateTime->second <= 59 && dateTime->millis >= 0 && dateTime->millis <= 999;
}  // End of ValidDateTime

static int ParseISOTime(const char *s, dateTime_t *dateTime) {
    size_t len = strlen(s);
    if (len != 4 && len != 7 && len != 10 && len != 13 && len != 16 && len != 19 && len != 23) return 0;
    if ((len >= 7 && s[4] != '-') || (len >= 10 && s[7] != '-') || (len >= 13 && s[10] != 'T') || (len >= 16 && s[13] != ':') ||
        (len >= 19 && s[16] != ':') || (len == 23 && s[19] != '.'))
        return 0;

    *dateTime = (dateTime_t){.month = 1, .day = 1};
    if (!ParseDecimal(s, 0, 4, &dateTime->year)) return 0;
    if (len >= 7 && !ParseDecimal(s, 5, 2, &dateTime->month)) return 0;
    if (len >= 10 && !ParseDecimal(s, 8, 2, &dateTime->day)) return 0;
    if (len >= 13 && !ParseDecimal(s, 11, 2, &dateTime->hour)) return 0;
    if (len >= 16 && !ParseDecimal(s, 14, 2, &dateTime->minute)) return 0;
    if (len >= 19 && !ParseDecimal(s, 17, 2, &dateTime->second)) return 0;
    if (len == 23 && !ParseDecimal(s, 20, 3, &dateTime->millis)) return 0;
    return ValidDateTime(dateTime);
}  // End of ParseISOTime

static int ParseCompactTime(const char *s, dateTime_t *dateTime) {
    size_t len = strlen(s);
    int hasSeconds = len == 14;
    int hasZone = len == 17 && (s[12] == '+' || s[12] == '-');
    if (len != 12 && !hasSeconds && !hasZone) return 0;

    *dateTime = (dateTime_t){0};
    if (!ParseDecimal(s, 0, 4, &dateTime->year) || !ParseDecimal(s, 4, 2, &dateTime->month) || !ParseDecimal(s, 6, 2, &dateTime->day) ||
        !ParseDecimal(s, 8, 2, &dateTime->hour) || !ParseDecimal(s, 10, 2, &dateTime->minute))
        return 0;
    if (hasSeconds && !ParseDecimal(s, 12, 2, &dateTime->second)) return 0;
    if (hasZone) {
        int zoneHour, zoneMinute;
        if (!ParseDecimal(s, 13, 2, &zoneHour) || !ParseDecimal(s, 15, 2, &zoneMinute) || zoneHour > 23 || zoneMinute > 59) return 0;
    }
    return ValidDateTime(dateTime);
}  // End of ParseCompactTime

static int DateTimeToMsec(const dateTime_t *dateTime, uint64_t *msec) {
    struct tm when = {
        .tm_sec = dateTime->second,
        .tm_min = dateTime->minute,
        .tm_hour = dateTime->hour,
        .tm_mday = dateTime->day,
        .tm_mon = dateTime->month - 1,
        .tm_year = dateTime->year - 1900,
        .tm_isdst = -1,
    };
    time_t timestamp = mktime(&when);
    if (timestamp < 0) return 0;
    *msec = 1000ULL * (uint64_t)timestamp + (uint64_t)dateTime->millis;
    return 1;
}  // End of DateTimeToMsec

static int DateTimeToTimeslotKey(const dateTime_t *dateTime, char key[TIMESLOT_KEY_SIZE]) {
    int len = snprintf(key, TIMESLOT_KEY_SIZE, "%04d%02d%02d%02d%02d%02d%03d", dateTime->year, dateTime->month, dateTime->day, dateTime->hour,
                       dateTime->minute, dateTime->second, dateTime->millis);
    return len == TIMESLOT_KEY_LENGTH;
}  // End of DateTimeToTimeslotKey

static int MsecToDateTime(uint64_t msec, dateTime_t *dateTime) {
    time_t seconds = (time_t)(msec / 1000);
    struct tm when;
    if (!localtime_r(&seconds, &when)) return 0;
    *dateTime = (dateTime_t){
        .year = when.tm_year + 1900,
        .month = when.tm_mon + 1,
        .day = when.tm_mday,
        .hour = when.tm_hour,
        .minute = when.tm_min,
        .second = when.tm_sec,
        .millis = (int)(msec % 1000),
    };
    return 1;
}  // End of MsecToDateTime

// Parse an ISO 8601 timestamp used by -t and the first/last seen filters.
int ParseTime8601(const char *s, uint64_t *msec, char key[TIMESLOT_KEY_SIZE]) {
    if (!s || !msec) return 0;
    dateTime_t dateTime;
    if (!ParseISOTime(s, &dateTime) || !DateTimeToMsec(&dateTime, msec)) return 0;
    return !key || DateTimeToTimeslotKey(&dateTime, key);
}  // End of ParseTime8601

// Convert a collector filename timestamp to a fixed-width local wall-clock key.
// A trailing numeric timezone is validated but is intentionally not part of the
// key: -t selects the timestamp text encoded in the filename.
int CompactTimeToTimeslotKey(const char *timestring, char key[TIMESLOT_KEY_SIZE]) {
    if (!timestring || !key) return 0;
    dateTime_t dateTime;
    return ParseCompactTime(timestring, &dateTime) && DateTimeToTimeslotKey(&dateTime, key);
}  // End of CompactTimeToTimeslotKey

char *msec2Str(uint64_t msec, char *output_buffer, size_t buffer_size) {
    if (msec == 0) {
        snprintf(output_buffer, buffer_size, "0000-00-00 00:00:00.000");
        return output_buffer;
    }
    dateTime_t dateTime;
    if (!MsecToDateTime(msec, &dateTime)) {
        snprintf(output_buffer, buffer_size, "0000-00-00 00:00:00.000");
        return output_buffer;
    }
    snprintf(output_buffer, buffer_size, "%04d-%02d-%02d %02d:%02d:%02d.%03d", dateTime.year, dateTime.month, dateTime.day, dateTime.hour,
             dateTime.minute, dateTime.second, dateTime.millis);
    return output_buffer;

}  // End of msec2Str

static void LogTimeWindowFormatError(const char *tstring) {
    LogError("Time window format error '%s'. Expected for example: 2026-09-24T12:00:05-2026-09-24T13:00:50, 2026-09-24T12:00-, or -2026-09-24T13:00",
             tstring ? tstring : "NullString");
}  // End of LogTimeWindowFormatError

timeWindow_t *ScanTimeFrame(const char *tstring) {
    if (!tstring || *tstring == '\0') {
        LogTimeWindowFormatError(tstring);
        return NULL;
    }

    timeWindow_t *timeWindow = calloc(1, sizeof(timeWindow_t));
    if (!timeWindow) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    // A single timestamp is an open-ended lower bound. For a range, try each
    // dash as its separator; ParseTime8601() is the sole endpoint validator.
    if (!ParseTime8601(tstring, &timeWindow->msecFirst, timeWindow->firstKey)) {
        timeWindow->msecFirst = 0;
        timeWindow->firstKey[0] = '\0';
        char *window = strdup(tstring);
        if (!window) {
            LogError("strdup() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            free(timeWindow);
            return NULL;
        }

        int validWindow = 0;
        for (char *separator = strchr(window, '-'); separator; separator = strchr(separator + 1, '-')) {
            *separator = '\0';
            uint64_t first = 0, last = 0;
            char firstKey[TIMESLOT_KEY_SIZE] = {0};
            char lastKey[TIMESLOT_KEY_SIZE] = {0};
            int firstOK = separator == window || ParseTime8601(window, &first, firstKey);
            int lastOK = separator[1] == '\0' || ParseTime8601(separator + 1, &last, lastKey);
            *separator = '-';
            if (firstOK && lastOK && (separator != window || separator[1] != '\0')) {
                timeWindow->msecFirst = first;
                timeWindow->msecLast = last;
                memcpy(timeWindow->firstKey, firstKey, sizeof(firstKey));
                memcpy(timeWindow->lastKey, lastKey, sizeof(lastKey));
                validWindow = 1;
                break;
            }
        }
        free(window);
        if (!validWindow) {
            LogTimeWindowFormatError(tstring);
            free(timeWindow);
            return NULL;
        }
    }

    if (timeWindow->firstKey[0] == '\0' && timeWindow->lastKey[0] == '\0') {
        LogError("Time window needs a start or end time");
        free(timeWindow);
        return NULL;
    }
    if (timeWindow->firstKey[0] && timeWindow->lastKey[0] && strcmp(timeWindow->firstKey, timeWindow->lastKey) > 0) {
        LogError("Time window start is later than end");
        free(timeWindow);
        return NULL;
    }

#ifdef DEVEL
    if (timeWindow->firstKey[0]) {
        printf("TimeWindow first: %s\n", UNIX2ISO((time_t)(timeWindow->msecFirst / 1000)));
    }
    if (timeWindow->lastKey[0]) {
        printf("TimeWindow last: %s\n", UNIX2ISO((time_t)(timeWindow->msecLast / 1000)));
    }
#endif

    return timeWindow;

}  // End of ScanTimeFrame

char *TimeString(uint64_t msecStart, uint64_t msecEnd) {
    static char datestr[255];

    if (msecStart) {
        char first[32], last[32];
        msec2Str(msecStart, first, sizeof(first));
        msec2Str(msecEnd, last, sizeof(last));
        snprintf(datestr, sizeof(datestr), "%s - %s", first, last);
    } else {
        snprintf(datestr, sizeof(datestr), "Time Window unknown");
    }
    return datestr;
}

char *UNIX2ISO(time_t t) {
    static char timestring[32];

    dateTime_t dateTime;
    if (t < 0 || !MsecToDateTime(1000ULL * (uint64_t)t, &dateTime)) {
        timestring[0] = '\0';
        return timestring;
    }
    snprintf(timestring, sizeof(timestring), "%04d%02d%02d%02d%02d%02d", dateTime.year, dateTime.month, dateTime.day, dateTime.hour, dateTime.minute,
             dateTime.second);

    return timestring;

}  // End of UNIX2ISO

// Convert a compact collector timestamp YYYYMMDDhhmm[ss] to local Unix time.
time_t ISO2UNIX(const char *timestring) {
    if (!timestring) {
        LogError("NULL time string");
        return (time_t)-1;
    }

    size_t len = strlen(timestring);
    if (len != 12 && len != 14) {
        LogError("Wrong time format '%s'", timestring);
        return (time_t)-1;
    }

    dateTime_t dateTime;
    uint64_t msec;
    if (!ParseCompactTime(timestring, &dateTime) || !DateTimeToMsec(&dateTime, &msec)) {
        LogError("Invalid compact time string '%s'", timestring);
        return (time_t)-1;
    }
    return (time_t)(msec / 1000);
}  // End of ISO2UNIX

long getTick(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    long theTick = ts.tv_nsec / 1000000;
    theTick += ts.tv_sec * 1000;
    return theTick;
}

// convert duration in msec into literal string
char *ScaleDuration(char *string, size_t len, uint64_t duration, int plain, int width) {
    if (duration == 0) {
        snprintf(string, len, "%*s", width, "00:00:00.000");
    } else if (plain) {
        snprintf(string, len, "%*.3f", width, (double)duration / 1000.0);
    } else {
        int msec = duration % 1000;
        duration /= 1000;
        int days = duration / 86400;
        int sum = 86400 * days;
        int hours = (duration - sum) / 3600;
        sum += 3600 * hours;
        int min = (duration - sum) / 60;
        sum += 60 * min;
        int sec = duration - sum;
        if (days == 0)
            snprintf(string, len, "%s%02d:%02d:%02d.%03d", width ? "    " : "", hours, min, sec, msec);
        else
            snprintf(string, len, "%2dd %02d:%02d:%02d.%03d", days, hours, min, sec, msec);
    }
    string[len - 1] = '\0';
    return string;
}  // End of ScaleDuration

void InsertString(stringlist_t *sl, const char *s) {
    if (sl->num_strings == sl->capacity) {
        sl->capacity = sl->capacity ? sl->capacity * 2 : 16;
        sl->list = (char **)realloc(sl->list, sl->capacity * sizeof(char *));
        if (!sl->list) {
            LogError("realloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    if (s) {
        sl->list[sl->num_strings++] = strdup(s);
    } else {
        /* allow explicit NULL sentinel */
        sl->list[sl->num_strings++] = NULL;
    }
}  // // End of InsertString

void ClearStringList(stringlist_t *sl) {
    if (sl->list) free(sl->list);
    memset(sl, 0, sizeof(stringlist_t));
}  // End of ClearStringList

void FreeStringList(stringlist_t *sl) {
    if (sl == NULL) return;
    ClearStringList(sl);
    free(sl);
}  // End of ClearStringList

// Internal helper to handle the formatting logic
static char *FormatNumber(char *string, size_t len, const scale_steps_t *scale, uint64_t num, int plain, int width) {
    double f = (double)num;

    if (plain) {
        snprintf(string, len, "%*llu", width, (long long unsigned)num);
        return string;
    }
    for (int i = 0; scale[i].scale != NULL; ++i) {
        if (f >= scale[i].factor) {
            // Skip k/K scaling for values < 10000 (print 4-digit numbers as-is)
            if (scale[i].factor < 10000.0 && scale[i].factor > 1.0 && num < 10000) {
                continue;
            }
            if (scale[i].factor > 1.0) {
                snprintf(string, len, "%*.1f%s", width, f / scale[i].factor, scale[i].scale);
            } else {
                snprintf(string, len, "%*llu", width + 1, (unsigned long long)num);
            }
            return string;
        }
    }

    // just in case ..
    snprintf(string, len, "%*llu", width + 1, 0ULL);
    return string;
}  // End of FormatNumber

char *ScaleByteValue(char *string, size_t len, uint64_t value, int plain, int width) {
    //
    return FormatNumber(string, len, si_scale_steps, value, plain, width);
}  // End of ScaleByteValue

char *ScaleCountValue(char *string, size_t len, uint64_t value, int plain, int width) {
    //
    return FormatNumber(string, len, bin_scale_steps, value, plain, width);
}  // End of ScaleCountValue

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

/*
uint32_t utfDecode(uint32_t *state, uint32_t *codep, uint32_t byte) {
    uint32_t type = utf8d[byte];

    *codep = (*state != UTF8_ACCEPT) ? (byte & 0x3fu) | (*codep << 6) : (0xff >> type) & (byte);

    *state = utf8d[256 + *state * 16 + type];
    return *state;
}
*/

uint32_t validate_utf8(uint32_t *state, char *str, size_t len) {
    size_t i;
    uint32_t type;

    for (i = 0; i < len; i++) {
        // We don't care about the codepoint, so this is
        // a simplified version of the utfDecode function.
        type = utf8d[(uint8_t)str[i]];
        *state = utf8d[256 + (*state) * 16 + type];

        if (*state == UTF8_REJECT) break;
    }

    return *state;
}

/*
 * converts a uint8_t array ( e.g. md5 or sha256 ) to a readable string
 * hexstring mus be big enough (2 * len) to hold the final string
 */
char *HexString(uint8_t *hex, size_t len, char *hexString) {
    unsigned i, j = 0;
    for (i = 0, j = 0; i < len; i++) {
        uint8_t ln = hex[i] & 0xF;
        uint8_t hn = (hex[i] >> 4) & 0xF;
        hexString[j++] = hn <= 9 ? hn + '0' : hn + 'a' - 10;
        hexString[j++] = ln <= 9 ? ln + '0' : ln + 'a' - 10;
    }
    hexString[j] = '\0';

    return hexString;
}  // End of HexString

void DumpHex(FILE *stream, const void *data, size_t size) {
    unsigned char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    uint32_t addr = 0;
    fprintf(stream, "%08x ", addr);
    for (i = 0; i < size; ++i) {
        fprintf(stream, "%02X ", ((unsigned char *)data)[i]);
        if (((unsigned char *)data)[i] >= ' ' && ((unsigned char *)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char *)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            fprintf(stream, " ");
            if ((i + 1) % 16 == 0) {
                addr += 16;
                fprintf(stream, "|  %s \n%08x ", ascii, addr);
            } else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    fprintf(stream, " ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    fprintf(stream, "   ");
                }
                fprintf(stream, "|  %s \n", ascii);
            }
        }
    }
}  // End of DumpHex
