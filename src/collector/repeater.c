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

#include "repeater.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nfnet.h"
#include "privsep.h"
#include "util.h"

static int done = 1;
static int child_exit = 0;
static pthread_t reader_tid;

static void SignalHandler(int signal) {
    switch (signal) {
        case SIGTERM:
            done = 1;
            break;
        case SIGCHLD:
            child_exit++;
            break;
    }

} /* End of IntHandler */

static void RepeaterMessageFunc(message_t *message, void *extraArg) {
    repeater_t *repeater = (repeater_t *)extraArg;

    if (message->type == PRIVMSG_REPEAT) {
        dbg_printf("Repeater process message: type: %d, length: %d\n", message->type, message->length);

        void *in_buff = (void *)message + sizeof(message_t);
        size_t cnt = message->length - sizeof(message_t);
        int i = 0;
        while (repeater[i].hostname && (i < MAX_REPEATERS)) {
            ssize_t len;
            len = sendto(repeater[i].sockfd, in_buff, cnt, 0, (struct sockaddr *)&(repeater[i].addr), repeater[i].addrlen);
            if (len < 0) {
                LogError("sendto(): %d: %s %s", i, repeater[i].hostname, strerror(errno));
            } else {
                dbg_printf("Repeated: %zd\n", len);
            }
            i++;
        }
    }
}

int StartupRepeater(repeater_t *repeater, int bufflen, char *userid, char *groupid) {
    LogInfo("StartupRepeater: userid: %s, groupid: %s", userid ? userid : "default", groupid ? groupid : "default");

    int i = 0;
    while (repeater[i].hostname && (i < MAX_REPEATERS)) {
        repeater[i].sockfd =
            Unicast_send_socket(repeater[i].hostname, repeater[i].port, repeater[i].family, bufflen, &repeater[i].addr, &repeater[i].addrlen);
        if (repeater[i].sockfd <= 0) exit(EXIT_FAILURE);
        LogVerbose("Replay flows to host: %s port: %s", repeater[i].hostname, repeater[i].port);
        i++;
    }

    /* Signal handling */
    struct sigaction act;
    memset((void *)&act, 0, sizeof(struct sigaction));
    act.sa_handler = SignalHandler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGCHLD, &act, NULL);

    thread_arg_t thread_arg = {0};
    thread_arg.messageFunc = RepeaterMessageFunc;
    thread_arg.extraArg = repeater;
    pthread_t tid;
    int err = pthread_create(&reader_tid, NULL, pipeReader, (void *)&thread_arg);
    if (err) {
        LogError("pthread_create() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }
    tid = reader_tid;

    err = pthread_join(tid, NULL);
    if (err) {
        LogError("pthread_join() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
    }

    LogVerbose("End StartupRepeater()");
    return 1;

}  // End of StartupRepeater