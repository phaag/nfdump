/*
 *  Copyright (c) 2009-2023, Peter Haag
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

#ifndef _BOOKKEEPER_H
#define _BOOKKEEPER_H 1

#include <stdint.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define BOOK_MAGIC 0x4E46424B /* "NFBK" */
#define BOOK_VERSION 1

#define STAT_BLOCK_SIZE 512ULL

typedef struct {
    uint32_t magic;
    uint32_t version;

    pid_t nfcapd_pid;
    uint64_t sequence;

    time_t first;
    time_t last;

    uint64_t numfiles;
    uint64_t filesize;

    uint64_t max_filesize;
    uint64_t max_lifetime;

} bookkeeper_t;

_Static_assert(sizeof(bookkeeper_t) % 8 == 0, "Unexpected struct layout");

#define BOOK_FAILED ((book_handle_t *)-1)
#define BOOK_EXISTS ((book_handle_t *)-2)
#define BOOK_NOT_EXISTS ((book_handle_t *)-3)

typedef struct {
    int fd;
    bookkeeper_t *bookkeeper;
} book_handle_t;

book_handle_t *book_open(const char *flowdir, pid_t pid);

void book_close(book_handle_t *book_handle);

book_handle_t *book_attach(const char *flowdir);

void book_update(book_handle_t *book_handle, time_t when, uint64_t size);

void book_set_limits(book_handle_t *book_handle, time_t lifetime, uint64_t maxsize);

void book_clear(book_handle_t *book_handle, bookkeeper_t *bookkeeper);

uint64_t book_sequence(book_handle_t *book_handle);

void book_print(book_handle_t *book_handle);

#endif  //_BOOKKEEPER_H
