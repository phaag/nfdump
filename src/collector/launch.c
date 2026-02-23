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

#include "launch.h"

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
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
#include "collector.h"
#include "config.h"
#include "expire.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfstatfile.h"
#include "privsep.h"
#include "util.h"

typedef struct launcher_msg_s {
    uint16_t type;    // message type
    uint16_t length;  // total message size including header
    time_t timeslot;  // rotation time

    uint32_t offFilename;  // offset from start of message_data
    uint32_t offFlowdir;   // flow directory
    uint32_t offISOtime;   // iso time string of current slot
    uint32_t offIdent;     // Ident

    char message_data[];  // compact string blob
} launcher_msg_t;

typedef struct launcher_args_s {
    time_t timeslot;
    char *filename;
    char *flowdir;
    char *isotime;
    char *ident;
} launcher_args_t;

extern char **environ;

static void do_expire(char *datadir);

static char *cmd_expand(const char *cmd, const launcher_msg_t *msg);

static char **cmd_parse(char *cmd);

static void cmd_execute(char **args);

static void launch(const char *command, launcher_msg_t *msg);

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

    LogInfo("Limits: Filesize %s, Lifetime %s, Watermark: %llu%%", dirstat->max_size ? ScaleValue(dirstat->max_size) : "<none>",
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

/*
 * Expand % placeholders in command string
 * command = 'path/to/command arg1 %t arg2 -f %f -i %i'
 */
static char *cmd_expand(const char *cmd, const launcher_msg_t *msg) {
    if (!cmd || !msg) return NULL;

    // Extract strings from message
    const char *fname = msg->message_data + msg->offFilename;
    const char *flowdir = msg->message_data + msg->offFlowdir;
    const char *isotime = msg->message_data + msg->offISOtime;
    const char *ident = msg->message_data + msg->offIdent;

    char timeslot_buf[32];
    snprintf(timeslot_buf, sizeof(timeslot_buf), "%ld", (long)msg->timeslot);

    // Expand placeholders
    size_t out_cap = strlen(cmd) + 128;
    char *out = malloc(out_cap);
    if (!out) return NULL;

    size_t out_len = 0;

    for (const char *p = cmd; *p; p++) {
        if (*p != '%') {
            // literal char
            if (out_len + 2 > out_cap) {
                out_cap *= 2;
                void *tmp = realloc(out, out_cap);
                if (!tmp) {
                    free(out);
                    LogError("realloc() failed in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                    return NULL;
                }
                out = tmp;
            }
            out[out_len++] = *p;
            continue;
        }

        // '%' placeholder
        p++;
        const char *rep = NULL;

        switch (*p) {
            case '%':
                rep = "%";
                break;
            case 'f':
                rep = fname;
                break;
            case 'd':
                rep = flowdir;
                break;
            case 't':
                rep = isotime;
                break;
            case 'u':
                rep = timeslot_buf;
                break;
            case 'i':
                rep = ident;
                break;
            default:
                // Unknown placeholder → treat literally
                if (out_len + 2 > out_cap) {
                    out_cap *= 2;
                    void *tmp = realloc(out, out_cap);
                    if (!tmp) {
                        free(out);
                        LogError("realloc() failed in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                        return NULL;
                    }
                    out = tmp;
                }
                out[out_len++] = '%';
                out[out_len++] = *p;
                continue;
        }

        if (rep) {
            size_t rlen = strlen(rep);
            if (out_len + rlen + 1 > out_cap) {
                while (out_len + rlen + 1 > out_cap) out_cap *= 2;
                void *tmp = realloc(out, out_cap);
                if (!tmp) {
                    free(out);
                    LogError("realloc() failed in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                    return NULL;
                }
                out = tmp;
            }
            memcpy(out + out_len, rep, rlen);
            out_len += rlen;
        }
    }

    out[out_len] = '\0';

    return out;

}  // End of cmd_expand

// split the expandd command line into individual arguments
static char **cmd_parse(char *cmd) {
    // count tokens in expanded string
    size_t ntokens = 0;

    int in_token = 0;
    for (char *s = cmd; *s; s++) {
        if (isspace((unsigned char)*s)) {
            in_token = 0;
        } else if (!in_token) {
            in_token = 1;
            ntokens++;
        }
    }

    // allocate argv with exact size
    char **argv = calloc(ntokens + 1, sizeof(char *));
    if (!argv) {
        free(cmd);
        LogError("calloc() failed in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    // tokenize expanded string
    size_t argc = 0;
    char *saveptr = NULL;
    char *tok = strtok_r(cmd, " \t\r\n", &saveptr);

    while (tok) {
        argv[argc] = strdup(tok);
        if (!argv[argc]) {
            // cleanup
            for (size_t i = 0; i < argc; i++) free(argv[i]);
            free(argv);
            free(cmd);
            return NULL;
        }
        argc++;
        tok = strtok_r(NULL, " \t\r\n", &saveptr);
    }

    argv[argc] = NULL;

    // expanded buffer no longer needed
    free(cmd);

    return argv;

}  // End of cmd_parse

static void cmd_execute(char **args) {
    if (!args || !args[0]) {
        LogError("cmd_execute: no command specified");
        return;
    }

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);

    sigset_t empty;
    sigemptyset(&empty);
    posix_spawnattr_setsigmask(&attr, &empty);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK);

    pid_t pid;
    int rc = posix_spawn(&pid, args[0], NULL, &attr, args, environ);

    posix_spawnattr_destroy(&attr);

    if (rc != 0) {
        LogError("posix_spawn(%s) failed: %s", args[0], strerror(rc));
        return;
    }

    LogVerbose("Launched command '%s' with pid %d", args[0], (int)pid);

}  // End of cmd_execute

static void launch(const char *command, launcher_msg_t *msg) {
    char *expanded = cmd_expand(command, msg);
    if (expanded == NULL) {
        LogError("launch process: Cannot expand command");
        return;
    }

    char **argv = cmd_parse(expanded);
    if (argv == NULL) {
        LogError("launch process: Cannot parse command");
        return;
    }

    cmd_execute(argv);

    for (size_t i = 0; argv[i]; i++) free(argv[i]);
    free(argv);

}  // End of launch

int SendLauncherMessage(queue_t *msgQueue, time_t t_start, const char *ISOtime, const char *fname, const char *datadir, const char *ident) {
    uint32_t lenFilename = strlen(fname) + 1;
    uint32_t lenFlowdir = strlen(datadir) + 1;
    uint32_t lenISOtime = strlen(ISOtime) + 1;
    uint32_t lenIdent = strlen(ident) + 1;

    uint32_t blob_size = lenFilename + lenFlowdir + lenISOtime + lenIdent;
    uint32_t msg_size = sizeof(launcher_msg_t) + blob_size;

    launcher_msg_t *msg = malloc(msg_size);
    if (!msg) {
        LogError("malloc() failed in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    msg->type = PRIVMSG_LAUNCH;
    msg->length = msg_size;
    msg->timeslot = t_start;

    // compute offsets
    msg->offFilename = 0;
    msg->offFlowdir = msg->offFilename + lenFilename;
    msg->offISOtime = msg->offFlowdir + lenFlowdir;
    msg->offIdent = msg->offISOtime + lenISOtime;

    // fill compact blob
    char *p = msg->message_data;
    memcpy(p + msg->offFilename, fname, lenFilename);
    memcpy(p + msg->offFlowdir, datadir, lenFlowdir);
    memcpy(p + msg->offISOtime, ISOtime, lenISOtime);
    memcpy(p + msg->offIdent, ident, lenIdent);

    // push to queue
    if (queue_try_push(msgQueue, msg) != NULL) {
        LogError("Failed to push launcher message");
        free(msg);
        return 0;
    }

    LogVerbose("Launcher message queued: ident=%s file=%s", ident, fname);
    return 1;
}  // End of SendLauncherMessage

static void *child_reaper_thread(void *arg) {
    (void)arg;

    for (;;) {
        int status;
        pid_t pid = waitpid(-1, &status, 0);  // block until ANY child exits

        if (pid < 0) {
            if (errno == EINTR) continue;  // interrupted by signal, retry
            if (errno == ECHILD) break;    // no more children
            LogError("waitpid failed: %s", strerror(errno));
            continue;
        }

        if (WIFEXITED(status)) {
            int code = WEXITSTATUS(status);
            if (code != 0)
                LogError("Launcher child %d exited with status %d", pid, code);
            else
                LogVerbose("Launcher child %d exited successfully", pid);
        } else if (WIFSIGNALED(status)) {
            LogError("Launcher child %d terminated by signal %d", pid, WTERMSIG(status));
        }
    }

    return NULL;
}  // End of child_reaper_thread

static void *launcher_thread_main(void *arg) {
    launcher_ctx_t *launcher_ctx = (launcher_ctx_t *)arg;

    dbg_printf("Startup %s()\n", __func__);
    while (!atomic_load(&launcher_ctx->done)) {
        launcher_msg_t *msg = queue_pop(launcher_ctx->msgQueue);
        if (msg == QUEUE_CLOSED) {
            // msg cannot get NULL, but handle it anyway
            atomic_store(&launcher_ctx->done, 1);
            break;
        }

        if (msg->type == PRIVMSG_LAUNCH) {
            LogVerbose("Launcher: process next message");
            launch(launcher_ctx->cmd_template, msg);
        } else {
            LogError("Skip unknow msg: %u", msg->type);
        }

        free(msg);
    }

    dbg_printf("Exit %s()\n", __func__);
    return NULL;
}  // End of launcher_thread_main

launcher_ctx_t *LauncherInit(char *command) {
    dbg_printf("%s() Start\n", __func__);
    launcher_ctx_t *launcher_ctx = calloc(1, sizeof(launcher_ctx_t));
    if (!launcher_ctx) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    atomic_store(&launcher_ctx->done, 0);
    launcher_ctx->cmd_template = command;
    launcher_ctx->msgQueue = queue_init(1024);

    return launcher_ctx;
}  // End of LauncherInit

pthread_t LauncherStart(launcher_ctx_t *launcher_ctx) {
    if (!launcher_ctx) return 0;

    dbg_printf("%s() Start\n", __func__);
    pthread_t tid;
    int err = pthread_create(&tid, NULL, launcher_thread_main, (void *)launcher_ctx);
    if (err) {
        LogError("pthread_create(repeater) failed: %s", strerror(err));
        return 0;
    }
    launcher_ctx->tid = tid;

    pthread_create(&tid, NULL, child_reaper_thread, NULL);
    pthread_detach(tid);

    return tid;

}  // End of LauncherStart

void LauncherShutdown(launcher_ctx_t *launcher_ctx) {
    if (!launcher_ctx) return;

    dbg_printf("%s() Start\n", __func__);
    atomic_store(&launcher_ctx->done, 1);
    queue_close(launcher_ctx->msgQueue);
    if (launcher_ctx->tid) {
        pthread_join(launcher_ctx->tid, NULL);
    }
    queue_free(launcher_ctx->msgQueue);
    free(launcher_ctx->cmd_template);
    free(launcher_ctx);

}  // End of LauncherShutdown
