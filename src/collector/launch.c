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
#include <fcntl.h>
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
#include <unistd.h>

#include "collector.h"
#include "config.h"
#include "logging.h"
#include "nfdump.h"
#include "util.h"

#define LAUNCH_EXEC 1

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

static char *cmd_expand(const char *cmd, const launcher_msg_t *msg);

static char **cmd_parse(char *cmd);

static int cmd_execute(char **args);

static int launch(const char *command, launcher_msg_t *msg);

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

    dbg_printf("%s() args: t_start: %s, ISOtime: %s, filename: %s, datadir: %s, ident: %s", __func__, timeslot_buf, isotime, fname, flowdir, ident);

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
            // Quote the substituted value to prevent argument splitting
            // wrap in double quotes and escape any embedded double quotes as \".
            // cmd_parse handles the quoting, so adjacent quoted sections merge correctly
            // even if the user has already wrapped the placeholder in quotes.
            size_t rlen = strlen(rep);
            // worst case: every char becomes \" (2 bytes) + 2 surrounding quotes + '\0'
            size_t needed = out_len + 2 + rlen * 2 + 1;
            if (needed > out_cap) {
                while (needed > out_cap) out_cap *= 2;
                void *tmp = realloc(out, out_cap);
                if (!tmp) {
                    free(out);
                    LogError("realloc() failed in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                    return NULL;
                }
                out = tmp;
            }
            out[out_len++] = '"';
            for (const char *r = rep; *r; r++) {
                if (*r == '"') out[out_len++] = '\\';
                out[out_len++] = *r;
            }
            out[out_len++] = '"';
        }
    }

    out[out_len] = '\0';

    dbg_printf("%s() template: %s\n", __func__, cmd);
    dbg_printf("%s() expanded: %s\n", __func__, out);

    return out;

}  // End of cmd_expand

// Append one character to the token buffer, growing it if necessary.
// Returns 1 on success, 0 on allocation failure.
static int tok_append(char **buf, size_t *len, size_t *cap, char c) {
    if (*len + 2 > *cap) {
        *cap *= 2;
        char *tmp = realloc(*buf, *cap);
        if (!tmp) return 0;
        *buf = tmp;
    }
    (*buf)[(*len)++] = c;
    return 1;
}

// Append one argument to argv, growing it if necessary.
// Returns 1 on success, 0 on allocation failure.
static int argv_append(char ***argv, size_t *argc, size_t *cap, char *tok) {
    if (*argc + 2 > *cap) {
        *cap *= 2;
        char **tmp = realloc(*argv, *cap * sizeof(char *));
        if (!tmp) return 0;
        *argv = tmp;
    }
    (*argv)[(*argc)++] = tok;
    return 1;
}

// split the expanded command line into individual arguments, respecting "..." and '...' quoting
static char **cmd_parse(char *cmd) {
    if (!cmd) return NULL;

    size_t argv_cap = 16;
    char **argv = calloc(argv_cap, sizeof(char *));
    if (!argv) {
        free(cmd);
        LogError("calloc() failed in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    size_t tok_cap = 64;
    char *tok_buf = malloc(tok_cap);
    if (!tok_buf) {
        free(argv);
        free(cmd);
        LogError("malloc() failed in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    size_t argc = 0;
    const char *p = cmd;
    int ok = 1;

    while (*p && ok) {
        // skip unquoted whitespace between tokens
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;

        // accumulate one token, handling quoted sections
        size_t tok_len = 0;
        while (*p && !isspace((unsigned char)*p) && ok) {
            if (*p == '"' || *p == '\'') {
                // quoted section: copy contents until matching closing quote
                char q = *p++;
                while (*p && *p != q && ok) {
                    ok = tok_append(&tok_buf, &tok_len, &tok_cap, *p++);
                }
                if (*p == q) p++;  // consume closing quote
            } else {
                // unquoted character
                ok = tok_append(&tok_buf, &tok_len, &tok_cap, *p++);
            }
        }
        if (!ok) break;

        tok_buf[tok_len] = '\0';

        char *arg = strdup(tok_buf);
        if (!arg || !argv_append(&argv, &argc, &argv_cap, arg)) {
            free(arg);
            ok = 0;
            break;
        }
    }

    free(tok_buf);
    free(cmd);

    if (!ok) {
        LogError("memory allocation failed in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        for (size_t i = 0; i < argc; i++) free(argv[i]);
        free(argv);
        return NULL;
    }

    argv[argc] = NULL;

#ifdef DEVEL
    printf("%s() final argv[%zu] vector\n", __func__, argc);
    for (int i = 0; i < (int)argc; i++) {
        printf(" [%d] %s\n", i, argv[i]);
    }
#endif

    return argv;

}  // End of cmd_parse

static int cmd_execute(char **args);  // forward decl

/*
 * Build a sanitised child environment by stripping loader-hijacking and
 * interpreter-path variables.  We use a blocklist of known-
 * dangerous prefixes while passing everything else through unchanged.
 */
static const char *const dangerous_env_prefixes[] = {
    "LD_PRELOAD=",
    "LD_LIBRARY_PATH=",
    "LD_AUDIT=",
    "LD_DEBUG=",
    "LD_BIND_NOW=",
    "DYLD_INSERT_LIBRARIES=",
    "DYLD_LIBRARY_PATH=",
    "DYLD_FRAMEWORK_PATH=",
    "PYTHONPATH=",
    "PYTHONSTARTUP=",
    "PERL5LIB=",
    "PERLLIB=",
    "PERL5OPT=",
    "RUBYLIB=",
    "RUBYOPT=",
    "NODE_PATH=",
    "JAVA_TOOL_OPTIONS=",
    "JVM_OPTS=",
    "_JAVA_OPTIONS=",
    "IFS=",
    "CDPATH=",
    "BASH_ENV=",
    "ENV=",
    NULL,
};

static char **build_safe_env(void) {
    size_t count = 0;
    for (char **e = environ; *e; e++) {
        int block = 0;
        for (int i = 0; dangerous_env_prefixes[i]; i++) {
            if (strncmp(*e, dangerous_env_prefixes[i], strlen(dangerous_env_prefixes[i])) == 0) {
                block = 1;
                break;
            }
        }
        if (!block) count++;
    }

    char **out = calloc(count + 1, sizeof(char *));
    if (!out) return NULL;

    size_t idx = 0;
    for (char **e = environ; *e; e++) {
        int block = 0;
        for (int i = 0; dangerous_env_prefixes[i]; i++) {
            if (strncmp(*e, dangerous_env_prefixes[i], strlen(dangerous_env_prefixes[i])) == 0) {
                block = 1;
                LogVerbose("Launcher: stripped environment variable: %.32s", *e);
                break;
            }
        }
        if (!block) {
            out[idx] = strdup(*e);
            if (!out[idx]) {
                for (size_t j = 0; j < idx; j++) free(out[j]);
                free(out);
                return NULL;
            }
            idx++;
        }
    }
    out[idx] = NULL;
    return out;
}  // End of build_safe_env

static int cmd_execute(char **args) {
    if (!args || !args[0]) {
        LogError("cmd_execute: no command specified");
        return 0;
    }

    // warn when the command is not an absolute path
    if (args[0][0] != '/') {
        LogInfo("Launcher: command '%s' is not an absolute path — resolved via PATH", args[0]);
    }

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);

    sigset_t empty;
    sigemptyset(&empty);
    posix_spawnattr_setsigmask(&attr, &empty);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK);

    // Concern 1: close all file descriptors above stderr in the child process
    posix_spawn_file_actions_t factions;
    posix_spawn_file_actions_init(&factions);
    int maxfd = (int)sysconf(_SC_OPEN_MAX);
    if (maxfd <= 0 || maxfd > 4096) maxfd = 4096;
    for (int fd = STDERR_FILENO + 1; fd < maxfd; fd++) {
        if (fcntl(fd, F_GETFD) != -1)  // only close fds that are actually open
            posix_spawn_file_actions_addclose(&factions, fd);
    }

    // build a sanitised child environment
    char **safe_env = build_safe_env();

    dbg_printf("Run command %s\n", args[0]);
    dbg(for (char **e = safe_env ? safe_env : environ; *e; e++) printf("ENV: %s\n", *e));

    pid_t pid;
    int rc = posix_spawnp(&pid, args[0], &factions, &attr, args, safe_env ? safe_env : environ);

    posix_spawnattr_destroy(&attr);
    posix_spawn_file_actions_destroy(&factions);
    if (safe_env) {
        for (char **e = safe_env; *e; e++) free(*e);
        free(safe_env);
    }

    if (rc != 0) {
        LogError("posix_spawn(%s) failed: %s", args[0], strerror(rc));
        return 0;
    }

    LogVerbose("Launched command '%s' with pid %d", args[0], (int)pid);
    return 1;

}  // End of cmd_execute

static int launch(const char *command, launcher_msg_t *msg) {
    char *expanded = cmd_expand(command, msg);
    if (expanded == NULL) {
        LogError("launch process: Cannot expand command");
        return 0;
    }

    char **argv = cmd_parse(expanded);
    if (argv == NULL) {
        LogError("launch process: Cannot parse command");
        return 0;
    }

    int err = cmd_execute(argv);

    for (size_t i = 0; argv[i]; i++) free(argv[i]);
    free(argv);

    return err;
}  // End of launch

int SendLauncherMessage(queue_t *msgQueue, time_t t_start, const char *ISOtime, const char *fname, const char *datadir, const char *ident) {
    uint32_t lenFilename = strlen(fname) + 1;
    uint32_t lenFlowdir = strlen(datadir) + 1;
    uint32_t lenISOtime = strlen(ISOtime) + 1;
    uint32_t lenIdent = strlen(ident) + 1;

    uint32_t blob_size = lenFilename + lenFlowdir + lenISOtime + lenIdent;
    uint32_t msg_size = sizeof(launcher_msg_t) + blob_size;

    dbg_printf("%s() args: t_start: %ld, ISOtime: %s, filename: %s, datadir: %s, ident: %s\n", __func__, t_start, ISOtime, fname, datadir, ident);

    launcher_msg_t *msg = malloc(msg_size);
    if (!msg) {
        LogError("malloc() failed in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return -1;
    }

    msg->type = LAUNCH_EXEC;
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
        return -1;
    }

    LogVerbose("Launcher message queued: ident=%s file=%s", ident, fname);
    return 1;
}  // End of SendLauncherMessage

static void *child_reaper_thread(void *arg) {
    launcher_ctx_t *launcher_ctx = (launcher_ctx_t *)arg;

    dbg_printf("Startup %s()\n", __func__);
    for (;;) {
        int status;
        pid_t pid = waitpid(-1, &status, WNOHANG);

        if (pid > 0) {
            dbg_printf("%s() reaped pid: %d\n", __func__, pid);
            if (WIFEXITED(status)) {
                int code = WEXITSTATUS(status);
                if (code != 0)
                    LogError("Launcher child %d exited with status %d", pid, code);
                else
                    LogVerbose("Launcher child %d exited successfully", pid);
            } else if (WIFSIGNALED(status)) {
                LogError("Launcher child %d terminated by signal %d", pid, WTERMSIG(status));
            }
            // immediately try to reap the next child
            continue;
        }

        if (pid < 0 && errno != EINTR && errno != ECHILD) {
            LogError("waitpid failed: %s", strerror(errno));
        }

        // Exit when done and no children remain
        if (atomic_load(&launcher_ctx->done) && (pid < 0 && errno == ECHILD)) break;

        // No child ready yet — sleep 100 ms before polling again
        struct timespec ts = {0, 100000000L};
        nanosleep(&ts, NULL);
    }

    dbg_printf("Exit %s()\n", __func__);
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

        if (msg->type == LAUNCH_EXEC) {
            LogVerbose("Launcher: process next message");
            int err = 0;
            if (launcher_ctx->cmd_expire) err += launch(launcher_ctx->cmd_expire, msg);
            if (launcher_ctx->cmd_template) err += launch(launcher_ctx->cmd_template, msg);
            (void)err;
        }

        free(msg);
    }

    dbg_printf("Exit %s()\n", __func__);
    return NULL;
}  // End of launcher_thread_main

launcher_ctx_t *LauncherInit(char *command, int expire) {
    dbg_printf("%s() Start\n", __func__);
    launcher_ctx_t *launcher_ctx = calloc(1, sizeof(launcher_ctx_t));
    if (!launcher_ctx) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    atomic_store(&launcher_ctx->done, 0);
    launcher_ctx->cmd_template = command;
    launcher_ctx->msgQueue = queue_init(1024);
    if (expire) {
        size_t len = strlen(INSTALL_PREFIX) + strlen("/bin/nfexpire -e %d") + 1;
        launcher_ctx->cmd_expire = malloc(len);
        if (!launcher_ctx->cmd_expire) {
            LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return NULL;
        }
        snprintf(launcher_ctx->cmd_expire, len, "%s%s", INSTALL_PREFIX, "/bin/nfexpire -e %d");
        dbg_printf("nfexpire expanded to %s\n", launcher_ctx->cmd_expire);
    }
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
    launcher_ctx->ltid = tid;

    err = pthread_create(&tid, NULL, child_reaper_thread, (void *)launcher_ctx);
    if (err) {
        LogError("pthread_create(reaper) failed: %s", strerror(err));
        // shut down the already-started launcher thread cleanly
        atomic_store(&launcher_ctx->done, 1);
        queue_close(launcher_ctx->msgQueue);
        pthread_join(launcher_ctx->ltid, NULL);
        launcher_ctx->ltid = 0;
        return 0;
    }
    launcher_ctx->rtid = tid;

    return launcher_ctx->ltid;

}  // End of LauncherStart

void LauncherShutdown(launcher_ctx_t *launcher_ctx) {
    if (!launcher_ctx) return;

    dbg_printf("%s() Start\n", __func__);
    atomic_store(&launcher_ctx->done, 1);
    queue_close(launcher_ctx->msgQueue);
    // wait for launcher thread
    if (launcher_ctx->ltid) {
        pthread_join(launcher_ctx->ltid, NULL);
    }
    // wait for reaper thread
    if (launcher_ctx->rtid) {
        pthread_join(launcher_ctx->rtid, NULL);
    }
    queue_free(launcher_ctx->msgQueue);
    if (launcher_ctx->cmd_template) free(launcher_ctx->cmd_template);
    if (launcher_ctx->cmd_expire) free(launcher_ctx->cmd_expire);
    free(launcher_ctx);

}  // End of LauncherShutdown
