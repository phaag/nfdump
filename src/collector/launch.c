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

#include <errno.h>
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
#include <sys/wait.h>
#include <unistd.h>

#include "bookkeeper.h"
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
#include "util.h"

#define DEVEL 1

static int done, launch, child_exit;

static void SignalHandler(int signal);

static char *cmd_expand(srecord_t *InfoRecord, char *ident, char *datadir, char *process);

static void cmd_parse(char *buf, char **args);

static void cmd_execute(char **args);

static void do_expire(char *datadir);

#define MAXARGS 256
#define MAXCMDLEN 4096

static void SignalHandler(int signal) {
    switch (signal) {
        case SIGTERM:
            // in case the process will not terminate, we
            // kill the process directly after the 2nd TERM signal
            if (done > 1) exit(234);
            done++;
            break;
        case SIGHUP:
            launch = 1;
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
static char *cmd_expand(srecord_t *InfoRecord, char *ident, char *datadir, char *process) {
    char *q, *s, tmp[16];
    int i;

    q = strdup(process);
    if (!q) {
        LogError("strdup() error in %s:%i: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }
    i = 0;

    while (q[i]) {
        if ((q[i] == '%') && q[i + 1]) {
            // replace the %x var
            switch (q[i + 1]) {
                case 'd':
                    s = datadir;
                    break;
                case 'f':
                    s = InfoRecord->fname;
                    break;
                case 't':
                    s = InfoRecord->tstring;
                    break;
                case 'u':
                    snprintf(tmp, 16, "%lli", (long long)InfoRecord->tstamp);
                    tmp[15] = 0;
                    s = tmp;
                    break;
                case 'i':
                    s = ident;
                    break;
                default:
                    LogError("Unknown format token '%%%c'", q[i + 1]);
                    s = NULL;
            }
            if (s) {
                q = realloc(q, strlen(q) + strlen(s));
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
    LogInfo("Launcher: fork child.");
    if ((pid = fork()) < 0) {
        LogError("Can't fork: %s", strerror(errno));
        return;
    }

    if (pid == 0) {  // we are the child
        execvp(*args, args);
        LogError("Can't execvp: %s: %s", args[0], strerror(errno));
        _exit(1);
    }

    // we are the parent
    LogInfo("Launcher: child exec done.");
    /* empty */

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

void launcher(void *commbuff, FlowSource_t *FlowSource, char *process, int expire) {
    FlowSource_t *fs;
    struct sigaction act;
    char *args[MAXARGS];
    int pid, stat;
    srecord_t *InfoRecord;

    InfoRecord = (srecord_t *)commbuff;

    LogInfo("Launcher: Startup. auto-expire %s", expire ? "enabled" : "off");
    done = launch = child_exit = 0;

    // process may be NULL, if we only expire data files
    if (process) {
        char *cmd = NULL;
        srecord_t TestRecord;
        // check for valid command expansion
        strncpy(TestRecord.fname, "test", MAXPATHLEN - 1);
        TestRecord.fname[MAXPATHLEN - 1] = 0;
        strncpy(TestRecord.tstring, "20190711084500", MAXTIMESTRING - 1);
        TestRecord.tstring[MAXTIMESTRING - 1] = 0;
        TestRecord.tstamp = 1;

        // checkk valid command expansion
        fs = FlowSource;
        cmd = cmd_expand(&TestRecord, fs->Ident, fs->datadir, process);
        if (cmd == NULL) {
            LogError("Launcher: ident: %s, Unable to expand command: '%s'", fs->Ident, process);
            exit(255);
        }
        free(cmd);
    }

    /* Signal handling */
    memset((void *)&act, 0, sizeof(struct sigaction));
    act.sa_handler = SignalHandler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    sigaction(SIGCHLD, &act, NULL);  // child process terminated
    sigaction(SIGTERM, &act, NULL);  // we are done
    sigaction(SIGINT, &act, NULL);   // we are done
    sigaction(SIGHUP, &act, NULL);   // run command

    while (!done) {
        // sleep until we get signaled
        dbg_printf("Launcher: Sleeping");
        select(0, NULL, NULL, NULL, NULL);
        dbg_printf("Launcher: Wakeup");
        if (launch) {  // SIGHUP
            launch = 0;

            if (process) {
                char *cmd = NULL;

                fs = FlowSource;
                while (fs) {
                    // Expand % placeholders
                    cmd = cmd_expand(InfoRecord, fs->Ident, fs->datadir, process);
                    if (cmd == NULL) {
                        LogError("Launcher: ident: %s, Unable to expand command: '%s'", fs->Ident, process);
                        continue;
                    }
                    dbg_printf("Launcher: ident: %s run command: '%s'", fs->Ident, cmd);

                    // prepare args array
                    cmd_parse(cmd, args);
                    if (args[0]) cmd_execute(args);

                    // do not flood the system with new processes
                    sleep(1);
                    // else cmd_parse already reported the error
                    free(cmd);
                    fs = fs->next;
                }
            }

            fs = FlowSource;
            while (fs) {
                if (expire) do_expire(fs->datadir);
                fs = fs->next;
            }
        }
        if (child_exit) {
            LogInfo("launcher child exit %d children.", child_exit);
            while ((pid = waitpid(-1, &stat, WNOHANG)) > 0) {
                if (WIFEXITED(stat)) {
                    LogInfo("launcher child %i exit status: %i", pid, WEXITSTATUS(stat));
                }
                if (WIFSIGNALED(stat)) {
                    LogError("launcher child %i died due to signal %i", pid, WTERMSIG(stat));
                }

                child_exit--;
            }
            LogInfo("launcher waiting children done. %d children", child_exit);
            child_exit = 0;
        }
        if (done) {
            LogInfo("Launcher: Terminating.");
        }
    }

    waitpid(-1, &stat, 0);

    // we are done
    LogInfo("Launcher: exit.");

}  // End of launcher
