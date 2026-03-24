/*
 *  Copyright (c) 2026, Peter Haag
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

#ifndef SYSLOG_NAMES
#define SYSLOG_NAMES 1
#endif

#include "logging.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "config.h"

#ifdef DEVEL
#include <assert.h>
#define dbg_printf(...) printf(__VA_ARGS__)
#else
#define dbg_printf(...) /* printf(__VA_ARGS__) */
#endif

/* Global vars */
static unsigned verbose = 1;
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

int ParseVerbose(int verbose, const char *arg) {
    if (verbose >= 0) {
        printf("Verbose log level already set to %d\n", verbose);
        return -2;
    }
    if (verbose < 0) verbose = 0;

    if (arg == NULL) {
        printf("Verbose argument requires a number\n");
        return -2;
    }
    // handle -v...
    size_t len = strlen(arg);
    if (len != 1) {
        printf("Invalid verbose level: %s\n", arg);
        return -2;
    }

    char c = arg[0];
    if (!isdigit(c)) {
        printf("Invalid verbose level: %s\n", arg);
        return -2;
    }

    verbose = atoi(arg);
    if (verbose < 0 || verbose > MAXVERBOSE) {
        printf("Verbose log level allowed between 0..%d\n", MAXVERBOSE);
        return -2;
    }

    return verbose;
}  // End of ParseVerbose

void EndLog(void) {
    if (use_syslog) closelog();
}  // End of EndLog

int InitLog(unsigned want_syslog, const char *name, char *facility, int verbose_log) {
    int i;

#ifdef DEVEL
    verbose_log = MAXVERBOSE;
    want_syslog = NOSYSLOG;
#endif

    // if not set - defaults to 1
    if (verbose_log < 0) verbose_log = 1;

    verbose = verbose_log;
    if (want_syslog == NOSYSLOG) {
        use_syslog = 0;
        if (verbose) {
            LogInfo("Verbose log level: %u", verbose);
        }
        return 1;
    }

    if (!facility || strlen(facility) > 32) {
        fprintf(stdout, "Invalid syslog facility name '%s'!\n", facility);
        return 0;
    }

    i = 0;
    while (facilitynames[i].c_name && strcasecmp(facilitynames[i].c_name, facility) != 0) {
        i++;
    }

    if (facilitynames[i].c_name == NULL) {
        fprintf(stdout, "Invalid syslog facility name '%s'!\n", facility);
        return 0;
    }

    const char *logname;
    if ((logname = strrchr(name, '/')) != 0) {
        logname++;
    } else {
        logname = name;
    }
    openlog(logname, LOG_CONS | LOG_PID, facilitynames[i].c_val);
    use_syslog = 1;

    if (verbose) {
        LogInfo("Verbose log level: %u", verbose);
    }

    return 1;

}  // End of InitLog

/*
 * some modules are needed for daemon code as well as normal stdio code
 * therefore a generic LogError is defined, which maps in this case
 * to stdout
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
        fprintf(stdout, "%s\n", string);
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
        fprintf(stdout, "%s\n", string);
        va_end(var_args);
    }

}  // End of LogInfo

void LogVerbose(char *format, ...) {
    va_list var_args;
    char string[512];
    if (verbose > 1) {
        if (use_syslog) {
            va_start(var_args, format);
            vsnprintf(string, 511, format, var_args);
            va_end(var_args);
            syslog(LOG_INFO, "%s", string);
            dbg_printf("%s\n", string);
        } else {
            va_start(var_args, format);
            vsnprintf(string, 511, format, var_args);
            fprintf(stdout, "%s\n", string);
            va_end(var_args);
        }
    }

}  // End of LogVerbose
