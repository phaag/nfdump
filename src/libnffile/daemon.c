/*
 *  Copyright (c) 2023, Peter Haag
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

#include "daemon.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
// some linux are picky
#define __USE_GNU
#include <unistd.h>

#include "util.h"

void daemonize(void) {
    int fd;
    switch (fork()) {
        case 0:
            // child
            break;
        case -1:
            // error
            LogError("fork() error: %s", strerror(errno));
            exit(EXIT_SUCCESS);
            break;
        default:
            // parent
            _exit(EXIT_SUCCESS);
    }

    if (setsid() < 0) {
        LogError("setsid() error: %s", strerror(errno));
        exit(EXIT_SUCCESS);
    }

    // Double fork
    switch (fork()) {
        case 0:
            // child
            break;
        case -1:
            // error
            LogError("fork() error: %s", strerror(errno));
            exit(EXIT_FAILURE);
            break;
        default:
            // parent
            _exit(EXIT_SUCCESS);
    }

    fd = open("/dev/null", O_RDONLY);
    if (fd != 0) {
        dup2(fd, 0);
        close(fd);
    }
    fd = open("/dev/null", O_WRONLY);
    if (fd != 1) {
        dup2(fd, 1);
        close(fd);
    }
    fd = open("/dev/null", O_WRONLY);
    if (fd != 2) {
        dup2(fd, 2);
        close(fd);
    }

}  // End of daemonize

int RunAsRoot(void) {
    uid_t myuid = getuid();
    return myuid == 0;
}  // end of RunAsRoot

void SetPriv(char *userid, char *groupid) {
    struct passwd *pw_entry;
    struct group *gr_entry;
    uid_t newuid, newgid;
    int err;

    if (userid == 0 && groupid == 0) return;

    newuid = newgid = 0;
    if (RunAsRoot() == 0) {
        LogError("Process not started as root - can not change uid/gid");
        exit(EXIT_FAILURE);
    }

    if (userid) {
        pw_entry = getpwnam(userid);
        newuid = pw_entry ? pw_entry->pw_uid : atol(userid);

        if (newuid == 0) {
            LogError("Invalid user '%s'", userid);
            exit(EXIT_FAILURE);
        }
    }

    if (groupid) {
        gr_entry = getgrnam(groupid);
        newgid = gr_entry ? gr_entry->gr_gid : atol(groupid);

        if (newgid == 0) {
            LogError("Invalid group '%s'", groupid);
            exit(EXIT_FAILURE);
        }

        if (setgroups(1, &newgid) == -1 || setresgid(newgid, newgid, newgid) == -1) {
            LogError("Can't set group id %ld for group '%s': %s", (long)newgid, groupid, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    if (newuid) {
        err = setresuid(newuid, newuid, newuid);
        if (err) {
            LogError("Can't set user id %ld for user '%s': %s", (long)newuid, userid, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

}  // End of SetPriv