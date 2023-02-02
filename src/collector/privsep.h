/*
 *  Copyright (c) 2022, Peter Haag
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

#ifndef _PRIVSEP_H
#define _PRIVSEP_H 1

#include <pthread.h>
#include <stdint.h>
#include <unistd.h>

typedef struct message_s {
    uint16_t type;
    uint16_t length;
} message_t;

typedef struct messageList {
    struct messageList *next;
    message_t *message;
} messageList_t;

typedef struct messageQueue_s {
    messageList_t *head;
    messageList_t *tail;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    uint32_t length;
} messageQueue_t;

#define PRIVMSG_NULL 0
#define PRIVMSG_LAUNCH 1
#define PRIVMSG_REPEAT 2
#define PRIVMSG_EXIT 0xFFFF
#define PRIVMSG_FLUSH 0xFFFE

typedef void (*messageFunc_t)(message_t *, void *);

typedef struct thread_arg_s {
    messageFunc_t messageFunc;
    void *extraArg;
} thread_arg_t;

void *pipeReader(void *arg);

messageQueue_t *NewMessageQueue(void);

void pushMessage(messageQueue_t *messageQueue, message_t *message);

void pushMessageFunc(message_t *message, void *extraArg);

message_t *getMessage(messageQueue_t *messageQueue);

int PrivsepFork(int argc, char **argv, pid_t *child_pid, char *privname);

#endif