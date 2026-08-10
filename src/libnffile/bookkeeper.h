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

#define STAT_BLOCK_SIZE 512ULL

typedef struct {
// file header
#define BOOK_MAGIC 0x4E46424B  // "NFBK"
    uint32_t magic;            // identify this file
#define BOOK_VERSION 2
    uint32_t version;       // version of this file
                            // collector
    pid_t nfcapd_pid;       // nfcapd process, if a collector is running
    pid_t expire_pid;       // nfexpire process currently scanning/modifying this
                            // directory, 0 if idle - see book_claim_expire()
    uint64_t sequence;      // book sequence
                            // timestamps
    time_t first;           // timestamp of first file
    time_t last;            // timestamp of last file
                            // sum
    uint64_t numfiles;      // total number of files
    uint64_t filesize;      // total file size in disk blocks
                            // limits
    uint64_t max_filesize;  // maximum file size
    time_t max_lifetime;    // maximum livetime in s
    uint32_t watermark;     // low water mark, if expiring files
    uint32_t dirty;         // dirty flag
} bookkeeper_t;

_Static_assert(sizeof(bookkeeper_t) % 8 == 0, "Unexpected struct layout");

// book_open()/book_attach() report success/failure through this status
// code, never through the returned handle - *out is only ever valid,
// dereferenceable memory when the return value is BOOK_OK, and is left
// NULL on every error path. Keeping the status and the payload in two
// separate values (instead of overloading the handle pointer with magic
// sentinel addresses) means there is nothing plausible to mistakenly
// dereference or test as a bare boolean on failure.
typedef enum {
    BOOK_OK = 0,
    BOOK_ERR_NOT_EXISTS,  // book_attach: no bookkeeper file present yet
    BOOK_ERR_EXISTS,      // book_open: another live collector already owns this bookkeeper
    BOOK_ERR_FAILED       // I/O, allocation, version or size error
} book_status_t;

typedef struct {
    int fd;
    bookkeeper_t *bookkeeper;
} book_handle_t;

enum {
    BOOK_LIMIT_LIFETIME = 1U << 0,
    BOOK_LIMIT_MAXSIZE = 1U << 1,
    BOOK_LIMIT_WATERMARK = 1U << 2,
};

book_status_t book_open(const char *flowdir, pid_t pid, book_handle_t **out);

void book_close(book_handle_t *book_handle);

book_status_t book_attach(const char *flowdir, book_handle_t **out);

void book_update(book_handle_t *book_handle, time_t when, uint64_t size);

void book_set_limits(book_handle_t *book_handle, time_t lifetime, uint64_t maxsize, uint32_t watermark, uint32_t set_mask);

void book_get(book_handle_t *book_handle, bookkeeper_t *bookkeeper);

int book_set(book_handle_t *book_handle, bookkeeper_t *bookkeeper);

int book_expire(book_handle_t *book_handle, time_t first, uint32_t expired_files, uint64_t expired_size);

uint64_t book_sequence(book_handle_t *book_handle);

void book_mark_dirty(book_handle_t *book_handle);

int book_is_dirty(book_handle_t *book_handle);

// nfexpire: claim exclusive right to scan/modify this directory's files and
// book, so two concurrent nfexpire processes on the same directory never
// race on the same files or bookkeeper. Mirrors book_open()'s single-
// collector enforcement. Returns BOOK_OK once claimed (including when the
// caller already holds it, or the previous holder is no longer alive);
// BOOK_ERR_EXISTS if another live nfexpire process holds it - *holder, if
// non-NULL, then receives that process' pid; BOOK_ERR_FAILED on error.
book_status_t book_claim_expire(book_handle_t *book_handle, pid_t pid, pid_t *holder);

// Release a lock claimed by book_claim_expire(). No-op if not held.
void book_release_expire(book_handle_t *book_handle);

#endif  //_BOOKKEEPER_H
