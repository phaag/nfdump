/*
 *  Copyright (c) 2024-2025, Peter Haag
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

#include "privsep.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "util.h"

#define MAXMSGSIZE 65535

static int done = 0;

static void IntHandler(int signal) {
    switch (signal) {
        case SIGINT:
            done = 1;
            break;
        default:
            // ignore everything we don't know
            break;
    }
}  // End of IntHandler

messageQueue_t *NewMessageQueue(void) {
    messageQueue_t *messageQueue = (messageQueue_t *)calloc(1, sizeof(messageQueue_t));
    if (!messageQueue) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }
    int err = 0;
    err += pthread_mutex_init(&messageQueue->mutex, NULL);
    err += pthread_cond_init(&messageQueue->cond, NULL);
    if (err) {
        LogError("pthread_mutex_init() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        free(messageQueue);
        return NULL;
    }
    messageQueue->length = 0;
    return messageQueue;

}  // End of NewMessageQueue

void pushMessage(messageQueue_t *messageQueue, message_t *message) {
    messageList_t *listElement = (messageList_t *)malloc(sizeof(messageList_t));
    if (!listElement) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return;
    }
    listElement->message = (message_t *)malloc(message->length);
    if (!listElement->message) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return;
    }
    memcpy(listElement->message, message, message->length);
    listElement->next = NULL;

    pthread_mutex_lock(&(messageQueue->mutex));
    if (messageQueue->tail) {
        // messageQ already contains records, append to last element
        messageQueue->tail->next = listElement;
    } else {
        // messageQ ist empty
        messageQueue->head = listElement;
        // signal reader thread, there is a new record
        pthread_cond_signal(&(messageQueue->cond));
    }
    messageQueue->tail = listElement;
    messageQueue->length++;
    pthread_mutex_unlock(&(messageQueue->mutex));

}  // End of pushMessage

message_t *getMessage(messageQueue_t *messageQueue) {
    pthread_mutex_lock(&(messageQueue->mutex));
    while (messageQueue->head == NULL && done == 0) {
        // messageQ ist empty
        pthread_cond_wait(&(messageQueue->cond), &(messageQueue->mutex));
    }

    if (done) {
        pthread_mutex_unlock(&(messageQueue->mutex));
        return (message_t *)-1;
    }

    messageList_t *listElement = messageQueue->head;
    message_t *message = listElement->message;

    messageQueue->head = listElement->next;
    messageQueue->length--;
    if (messageQueue->head == NULL) messageQueue->tail = NULL;
    pthread_mutex_unlock(&(messageQueue->mutex));

    free(listElement);
    return message;

}  // End of getMessage

void pushMessageFunc(message_t *message, void *extraArg) {
    // simple wrapper for pushMessage
    pushMessage((messageQueue_t *)extraArg, message);
}  // End of pushMessageFunc

__attribute__((noreturn)) void *pipeReader(void *arg) {
    dbg_printf("pipeReader() enter\n");

    thread_arg_t *thread_arg = (thread_arg_t *)arg;

    char *buffer = (char *)malloc(MAXMSGSIZE);
    int fd = STDIN_FILENO;

    struct sigaction act;
    /* Signal handling */
    memset((void *)&act, 0, sizeof(struct sigaction));
    act.sa_handler = IntHandler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    sigaction(SIGINT, &act, NULL);

#ifdef DEVEL
    int mcnt = 0;
#endif
    size_t bufferOffset = 0;
    while (!done) {
        ssize_t nbytes = read(fd, buffer + bufferOffset, MAXMSGSIZE - bufferOffset);
        if (nbytes > 0) {
            nbytes += bufferOffset;
            bufferOffset = 0;
            dbg_printf("Received message %d: size: %zd\n", ++mcnt, nbytes);
            void *p = buffer;
            void *eod = buffer + nbytes;
            while (p < eod) {
                // check for full message header
                if (nbytes < sizeof(message_t)) {
                    dbg_printf("Short read: available: %zu\n", nbytes);
                    // shift the partly message header at the beginning of the buffer and continue reading data
                    if ((void *)buffer != p) memmove(buffer, p, nbytes);
                    bufferOffset = nbytes;
                    p = eod;
                    continue;
                    // short read
                }

                // check for valid message length
                message_t *message = (message_t *)p;
                if (message->length == 0) {
                    LogError("Zero size pipe message: flush all data: %zu", nbytes);
                    p = eod;
                    continue;
                }

                // check for enough message data
                if (nbytes < message->length) {
                    dbg_printf("Short read: message size: %u, available: %zu\n", message->length, nbytes);
                    // shift the partly message at the beginning of the buffer and continue reading data
                    if ((void *)buffer != p) memmove(buffer, p, nbytes);
                    bufferOffset = nbytes;
                    p = eod;
                    continue;
                    // short read
                }

                dbg_printf("%d, Message type: %d, length: %u\n", mcnt, message->type, message->length);
                switch (message->type) {
                    case PRIVMSG_FLUSH:
                        dbg_printf("FlushMessage received\n");
                        break;
                    case PRIVMSG_LAUNCH:
                    case PRIVMSG_REPEAT:
                        thread_arg->messageFunc(message, thread_arg->extraArg);
                        break;
                    case PRIVMSG_EXIT:
                        done = 1;
                        // make sure the pipeReader() get known the done signal
                        // push exit message
                        thread_arg->messageFunc(message, thread_arg->extraArg);
                        break;
                    default:
                        LogError("pipeReader() received unknown message type: %u", message->type);
                }

                // advance message pointer, calculate remaining bytes
                nbytes -= message->length;
                p += message->length;
            }
        } else {
            bufferOffset = 0;
            if (nbytes == 0) {
                // EOF - pipe broken?
                done = 1;
                LogError("read() error pipe closed");
            } else {
                if (errno != EINTR) LogError("read() error pipe: %zd %s", nbytes, strerror(errno));
            }
        }
    }
    dbg_printf("pipeReader() pthread_exit\n");
    pthread_exit(NULL);

    /* UNREACHED */
}  // End of pipereader

int PrivsepFork(int argc, char **argv, pid_t *child_pid, char *privname) {
    *child_pid = 0;

    int pfd[2] = {0};

    if (pipe(pfd) == -1) {
        LogError("pipe() error: %s in '%s', line '%d'", strerror(errno), __FILE__, __LINE__);
        exit(1);
    }

    if ((*child_pid = fork()) == -1) {
        LogError("fork() error: %s in '%s', line '%d'", strerror(errno), __FILE__, __LINE__);
        exit(1);
    }

    if (*child_pid == 0) {
        // child
        close(pfd[1]);
        close(0);
        dup(pfd[0]);
        int i;
        char **privargv = (char **)calloc(argc + 3, sizeof(char *));
        if (!privargv) {
            LogError("PrivsepFork: Panic! calloc(): %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            exit(255);
        }
        privargv[0] = argv[0];
        for (i = 1; i < argc; i++) privargv[i] = argv[i];
        privargv[i++] = "privsep";
        privargv[i++] = privname;
        privargv[i++] = NULL;
        execvp(privargv[0], privargv);
        LogError("execvp() privsep '%s' failed: %s", privargv[0], strerror(errno));
        _exit(errno);
    }

    // parent
    close(pfd[0]);
    LogVerbose("Privsep child %s forked: %d", privname, *child_pid);
    return pfd[1];
}