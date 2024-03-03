/*
 *  Copyright (c) 2009-2024, Peter Haag
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

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include "bookkeeper.h"
#include "config.h"
#include "nfstatfile.h"

#ifdef HAVE_FTS_H
#include <fts.h>
#else
#include "fts_compat.h"
#define fts_children fts_children_compat
#define fts_close fts_close_compat
#define fts_open fts_open_compat
#define fts_read fts_read_compat
#define fts_set fts_set_compat
#endif

#include "collector.h"
#include "expire.h"
#include "launch.h"
#include "nfdump.h"
#include "nffile.h"
#include "privsep.h"
#include "util.h"

typedef struct launcher_message_s {
    time_t timeslot;
    uint32_t lenFilename;
    uint32_t lenFlowdir;
    uint32_t lenIsotime;
    uint32_t lenIdent;
    uint32_t lenAlign;
} launcher_message_t;

typedef struct launcher_args_s {
    time_t timeslot;
    char *filename;
    char *flowdir;
    char *isotime;
    char *ident;
} launcher_args_t;

static int done = 0;
static int child_exit = 0;
static pthread_t killtid = 0;

static void SignalHandler(int signal);

static char *cmd_expand(char *launch_process, launcher_args_t *launcher_args);

static void cmd_parse(char *buf, char **args);

static void cmd_execute(char **args);

static void processMessage(message_t *message, launcher_args_t *launcher_args);

static void launcher(messageQueue_t *messageQueue, char *launch_process, int expire);

static void do_expire(char *datadir);

#define MAXARGS 256
#define MAXCMDLEN 4096

static void SignalHandler(int signal) {
    switch (signal) {
        case SIGTERM:
            done = 1;
            pthread_kill(killtid, SIGINT);
            break;
        case SIGCHLD:
            child_exit++;
            break;
    }

} /* End of IntHandler */

/*
 * Expand % placeholders in command string
 * expand the memory needed in the command string and replace placeholders
 * prevent endless expansion
 */
static char *cmd_expand(char *launch_process, launcher_args_t *launcher_args) {
    char *q = strdup(launch_process);
    if (!q) {
        LogError("strdup() error in %s:%i: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    int i = 0;
    while (q[i]) {
        char *s, tmp[16];
        if ((q[i] == '%') && q[i + 1]) {
            // replace the %x var
            switch (q[i + 1]) {
                case 'd':
                    s = launcher_args->flowdir;
                    break;
                case 'f':
                    s = launcher_args->filename;
                    break;
                case 't':
                    s = launcher_args->isotime;
                    break;
                case 'u':
                    snprintf(tmp, 16, "%lli", (long long)launcher_args->timeslot);
                    tmp[15] = 0;
                    s = tmp;
                    break;
                case 'i':
                    s = launcher_args->ident;
                    break;
                default:
                    LogError("Unknown format token '%%%c'", q[i + 1]);
                    s = NULL;
            }
            if (s) {
                q = (char *)realloc(q, strlen(q) + strlen(s));
                if (!q) {
                    LogError("realloc() error in %s:%i: %s", __FILE__, __LINE__, strerror(errno));
                    return NULL;
                }
                // sanity check
                if (strlen(q) > MAXCMDLEN) {
                    LogError("command expand error in %s:%i: cmd line too long", __FILE__, __LINE__);
                    return NULL;
                }
                memmove(&q[i] + strlen(s), &q[i + 2], strlen(&q[i + 2]) + 1);  // include trailing '0' in memmove
                memcpy(&q[i], s, strlen(s));
            }
        }
        i++;
    }

    return q;

}  // End of cmd_expand

/*
 * split the command in buf into individual arguments.
 */
static void cmd_parse(char *buf, char **args) {
    int i, argnum;

    i = argnum = 0;
    while ((i < MAXCMDLEN) && (buf[i] != 0)) {
        /*
         * Strip whitespace.  Use nulls, so
         * that the previous argument is terminated
         * automatically.
         */
        while ((i < MAXCMDLEN) && ((buf[i] == ' ') || (buf[i] == '\t'))) buf[i++] = 0;

        /*
         * Save the argument.
         */
        if (argnum < MAXARGS) args[argnum++] = &(buf[i]);

        /*
         * Skip over the argument.
         */
        while ((i < MAXCMDLEN) && ((buf[i] != 0) && (buf[i] != ' ') && (buf[i] != '\t'))) i++;
    }

    if (argnum < MAXARGS) args[argnum] = NULL;

    if ((i >= MAXCMDLEN) || (argnum >= MAXARGS)) {
        // for safety reason, disable the command
        args[0] = NULL;
        LogError("Launcher: Unable to parse command: '%s'", buf);
    }

}  // End of cmd_parse

/*
 * cmd_execute
 * spawn a child process and execute the program.
 */
static void cmd_execute(char **args) {
    int pid;

    // Get a child process.
    if ((pid = fork()) < 0) {
        LogError("Can't fork: %s", strerror(errno));
        return;
    }

    if (pid == 0) {
        // child process
        execvp(*args, args);
        LogError("Can't execvp: %s: %s", args[0], strerror(errno));
        _exit(1);
    }

    // parent process

}  // End of cmd_execute

static void do_expire(char *datadir) {
    bookkeeper_t *books;
    dirstat_t *dirstat, oldstat;
    int ret, bookkeeper_stat, do_rescan;

    LogInfo("Run expire on '%s'", datadir);

    do_rescan = 0;
    ret = ReadStatInfo(datadir, &dirstat, CREATE_AND_LOCK);
    switch (ret) {
        case STATFILE_OK:
            break;
        case ERR_NOSTATFILE:
            dirstat->low_water = 95;
        case FORCE_REBUILD:
            LogInfo("Force rebuild stat record");
            do_rescan = 1;
            break;
        case ERR_FAIL:
            LogError("expire failed: can't read stat record");
            return;
            /* not reached */
            break;
        default:
            LogError("expire failed: unexpected return code %i reading stat record", ret);
            return;
            /* not reached */
    }

    bookkeeper_stat = AccessBookkeeper(&books, datadir);
    if (do_rescan) {
        RescanDir(datadir, dirstat);
        if (bookkeeper_stat == BOOKKEEPER_OK) {
            ClearBooks(books, NULL);
            // release the books below
        }
    }

    if (bookkeeper_stat == BOOKKEEPER_OK) {
        bookkeeper_t tmp_books;
        ClearBooks(books, &tmp_books);
        UpdateDirStat(dirstat, &tmp_books);
        ReleaseBookkeeper(books, DETACH_ONLY);
    } else {
        LogError("Error %i: can't access book keeping records", ret);
    }

    LogInfo("Limits: Filesize %s, Lifetime %s, Watermark: %llu%%\n", dirstat->max_size ? ScaleValue(dirstat->max_size) : "<none>",
            dirstat->max_lifetime ? ScaleTime(dirstat->max_lifetime) : "<none>", (unsigned long long)dirstat->low_water);

    LogInfo("Current size: %s, Current lifetime: %s, Number of files: %llu", ScaleValue(dirstat->filesize), ScaleTime(dirstat->last - dirstat->first),
            (unsigned long long)dirstat->numfiles);

    oldstat = *dirstat;
    if (dirstat->max_size || dirstat->max_lifetime) ExpireDir(datadir, dirstat, dirstat->max_size, dirstat->max_lifetime, 0);
    WriteStatInfo(dirstat);

    if ((oldstat.numfiles - dirstat->numfiles) > 0) {
        LogInfo("expire completed");
        LogInfo("   expired files: %llu", (unsigned long long)(oldstat.numfiles - dirstat->numfiles));
        LogInfo("   expired time slot: %s", ScaleTime(dirstat->first - oldstat.first));
        LogInfo("   expired file size: %s", ScaleValue(oldstat.filesize - dirstat->filesize));
        LogInfo("New size: %s, New lifetime: %s, Number of files: %llu", ScaleValue(dirstat->filesize), ScaleTime(dirstat->last - dirstat->first),
                (unsigned long long)dirstat->numfiles);
    } else {
        LogInfo("expire completed - nothing to expire.");
    }
    ReleaseStatInfo(dirstat);

}  // End of do_expire

void processMessage(message_t *message, launcher_args_t *launcher_args) {
    void *p = message;
    p += sizeof(message_t);

    memset(launcher_args, 0, sizeof(launcher_args_t));

    launcher_message_t *lm = (launcher_message_t *)p;
    size_t len = sizeof(message_t) + sizeof(launcher_message_t);
    len += lm->lenFilename + lm->lenFlowdir + lm->lenIsotime + lm->lenIdent + lm->lenAlign;

    if (message->length < len) {
        LogError("Message size error: Expected: %zu, have: %u\n", len, message->length);
        return;
    }

    p += sizeof(launcher_message_t);

    launcher_args->timeslot = lm->timeslot;
    launcher_args->filename = p;
    launcher_args->filename[lm->lenFilename - 1] = '\0';
    p += lm->lenFilename;

    launcher_args->flowdir = p;
    launcher_args->flowdir[lm->lenFlowdir - 1] = '\0';
    p += lm->lenFlowdir;

    launcher_args->isotime = p;
    launcher_args->isotime[lm->lenIsotime - 1] = '\0';
    p += lm->lenIsotime;

    launcher_args->ident = p;
    launcher_args->ident[lm->lenIdent - 1] = '\0';
    p += lm->lenIdent;

}  // End of processMessage

static void launcher(messageQueue_t *messageQueue, char *launch_process, int expire) {
    while (!done) {
        message_t *message = getMessage(messageQueue);
        if (message == (message_t *)-1) {
            done = 1;
            return;
        }

        LogVerbose("Launcher: process next message");
        launcher_args_t launcher_args;
        processMessage(message, &launcher_args);

        // may be NULL, if we only expire data files
        if (launch_process) {
            char *cmd = NULL;

            // check valid command expansion
            cmd = cmd_expand(launch_process, &launcher_args);
            if (cmd == NULL) {
                LogError("Launcher: ident: %s, Unable to expand command: '%s'", launcher_args.ident, launch_process);
                done = 1;
                return;
            }
            LogVerbose("Launcher: ident: %s run command: '%s'", launcher_args.ident, cmd);

            // prepare args array
            char *args[MAXARGS];
            cmd_parse(cmd, args);
            if (args[0]) cmd_execute(args);

            free(cmd);
        }
        if (expire) do_expire(launcher_args.flowdir);

        if (child_exit) {
            LogVerbose("%d child process(es) terminated", child_exit);
            int stat;
            pid_t pid;
            while ((pid = waitpid(-1, &stat, WNOHANG)) > 0) {
                if (WIFEXITED(stat)) {
                    LogVerbose("launcher child %i exit status: %i", pid, WEXITSTATUS(stat));
                }
                if (WIFSIGNALED(stat)) {
                    LogError("launcher child %i died due to signal %i", pid, WTERMSIG(stat));
                }

                child_exit--;
            }
            child_exit = 0;
        }
    }

    // we are done
    LogInfo("Launcher: Terminating.");

}  // End of launcher

#define AddVector(v, s, l)         \
    v[i].iov_base = s;             \
    l = strlen(v[i].iov_base) + 1; \
    v[i++].iov_len = l;

int SendLauncherMessage(int pfd, time_t t_start, char *subdir, char *fmt, char *datadir, char *ident) {
    char fname[MAXPATHLEN];
    if (subdir) {
        snprintf(fname, MAXPATHLEN - 1, "%s/nfcapd.%s", subdir, fmt);
    } else {
        snprintf(fname, MAXPATHLEN - 1, "nfcapd.%s", fmt);
    }
    fname[MAXPATHLEN - 1] = '\0';

    dbg_printf("Launcher arguments: Time: %ld, t: %s, f: %s, d: %s, i: %s\n", t_start, fmt, fname, datadir, ident);

    message_t message;
    message.type = PRIVMSG_LAUNCH;

    launcher_message_t launcher_message;
    launcher_message.timeslot = t_start;

    struct iovec vector[8];

    int i = 0;
    vector[i].iov_base = &message;
    vector[i++].iov_len = sizeof(message);

    vector[i].iov_base = &launcher_message;
    vector[i++].iov_len = sizeof(launcher_message);

    size_t argLen = 0;
    size_t len = sizeof(message_t) + sizeof(launcher_message);

    AddVector(vector, fname, argLen);
    launcher_message.lenFilename = argLen;
    len += argLen;

    AddVector(vector, datadir, argLen);
    launcher_message.lenFlowdir = argLen;
    len += argLen;

    AddVector(vector, fmt, argLen);
    launcher_message.lenIsotime = argLen;
    len += argLen;

    AddVector(vector, ident, argLen);
    launcher_message.lenIdent = argLen;
    len += argLen;

    size_t align = len & 0x3;
    if (align) {
        launcher_message.lenAlign = 4 - align;
        len += launcher_message.lenAlign;
        vector[i].iov_base = &align;
        vector[i++].iov_len = launcher_message.lenAlign;
    } else {
        launcher_message.lenAlign = 0;
    }

    message.length = len;
    ssize_t ret = writev(pfd, vector, i);
    if (ret < 0) {
        LogError("Failed to send launcher message: %s", strerror(errno));
    }
    return ret;
}

int StartupLauncher(char *launch_process, int expire) {
    LogInfo("StartupLauncher(): %s, expire: %d", launch_process, expire);

    messageQueue_t *messageQueue = NewMessageQueue();
    if (!messageQueue) return 0;

    /* Signal handling */
    struct sigaction act;
    memset((void *)&act, 0, sizeof(struct sigaction));
    act.sa_handler = SignalHandler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGCHLD, &act, NULL);

    thread_arg_t thread_arg = {0};
    thread_arg.messageFunc = pushMessageFunc;
    thread_arg.extraArg = (void *)messageQueue;
    pthread_t tid;
    int err = pthread_create(&killtid, NULL, pipeReader, (void *)&thread_arg);
    if (err) {
        LogError("pthread_create() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }
    tid = killtid;

    launcher(messageQueue, launch_process, expire);
    err = pthread_join(tid, NULL);
    if (err) {
        LogError("pthread_join() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
    }

    LogVerbose("End StartupLauncher()");
    return 1;
}  // End of StartupLauncher
