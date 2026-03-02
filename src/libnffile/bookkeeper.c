/*
 *  Copyright (c) 2026, Peter Haag
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

#include "bookkeeper.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "logging.h"
#include "util.h"

static int book_lock(int fd) {
    struct flock fl = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 0};
    while (fcntl(fd, F_SETLKW, &fl) == -1) {
        if (errno != EINTR) {
            LogError("fcntl() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return -1;
        }
    }
    return 0;
}  // End of book_lock

static int book_unlock(int fd) {
    struct flock fl = {.l_type = F_UNLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 0};
    return fcntl(fd, F_SETLK, &fl);
}  // End of book_unlock

// open the book from th collector
book_handle_t *book_open(const char *flowdir, pid_t pid) {
    char path[PATH_MAX];

    snprintf(path, sizeof(path), "%s/.nfcapd.book", flowdir);

    book_handle_t *book_handle = calloc(1, sizeof(book_handle_t));
    if (!book_handle) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return BOOK_FAILED;
    }

    book_handle->fd = open(path, O_RDWR | O_CREAT, 0644);
    if (book_handle->fd < 0) {
        free(book_handle);
        LogError("open() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return BOOK_FAILED;
    }

    if (book_lock(book_handle->fd) < 0) {
        close(book_handle->fd);
        free(book_handle);
        return BOOK_FAILED;
    }

    struct stat st;
    fstat(book_handle->fd, &st);
    if (st.st_size != sizeof(bookkeeper_t)) {
        // new file or corrupt file
        if (ftruncate(book_handle->fd, sizeof(bookkeeper_t)) < 0) {
            book_unlock(book_handle->fd);
            close(book_handle->fd);
            free(book_handle);
            LogError("ftruncate() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return BOOK_FAILED;
        }
    }

    book_handle->bookkeeper = mmap(NULL, sizeof(bookkeeper_t), PROT_READ | PROT_WRITE, MAP_SHARED, book_handle->fd, 0);

    if (book_handle->bookkeeper == MAP_FAILED) {
        book_unlock(book_handle->fd);
        close(book_handle->fd);
        free(book_handle);
        LogError("mmap() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return BOOK_FAILED;
    }

    if (book_handle->bookkeeper->magic != BOOK_MAGIC) {
        // new file - initialise bookkeeper
        memset(book_handle->bookkeeper, 0, sizeof(bookkeeper_t));
        book_handle->bookkeeper->magic = BOOK_MAGIC;
        book_handle->bookkeeper->version = BOOK_VERSION;
    }

    if (book_handle->bookkeeper->version != BOOK_VERSION) {
        LogError("Found unknown version for bookkeeper: %u", book_handle->bookkeeper->version);
        munmap(book_handle->bookkeeper, sizeof(bookkeeper_t));
        book_unlock(book_handle->fd);
        close(book_handle->fd);
        free(book_handle);
        return BOOK_FAILED;
    }

    // enforce single collector
    if (book_handle->bookkeeper->nfcapd_pid > 0) {
        if (kill(book_handle->bookkeeper->nfcapd_pid, 0) == 0 || errno == EPERM) {
            LogError("Another collector with pid %i is already running, and configured for '%s'", book_handle->bookkeeper->nfcapd_pid, flowdir);
            book_unlock(book_handle->fd);
            munmap(book_handle->bookkeeper, sizeof(bookkeeper_t));
            close(book_handle->fd);
            free(book_handle);
            return BOOK_EXISTS;
        }
    }

    book_handle->bookkeeper->nfcapd_pid = pid;
    book_handle->bookkeeper->sequence++;

    msync(book_handle->bookkeeper, sizeof(bookkeeper_t), MS_SYNC);
    book_unlock(book_handle->fd);

    return book_handle;
}  // End of book_open

void book_close(book_handle_t *book_handle) {
    if (!book_handle) return;

    if (book_handle->bookkeeper) munmap(book_handle->bookkeeper, sizeof(bookkeeper_t));
    if (book_handle->fd >= 0) close(book_handle->fd);
    free(book_handle);
}  // End of book_close

// access the book from nfexpire
book_handle_t *book_attach(const char *flowdir) {
    char path[PATH_MAX];

    snprintf(path, sizeof(path), "%s/.nfcapd.book", flowdir);

    book_handle_t *book_handle = calloc(1, sizeof(book_handle_t));
    if (!book_handle) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return BOOK_FAILED;
    }

    book_handle->fd = open(path, O_RDWR);
    if (book_handle->fd < 0) {
        if (errno != ENOENT) LogError("open() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        free(book_handle);
        return BOOK_NOT_EXISTS;
    }

    struct stat st;
    if (fstat(book_handle->fd, &st) < 0 || st.st_size != sizeof(bookkeeper_t)) {
        LogError("File size error of nfbook file");
        close(book_handle->fd);
        free(book_handle);
        return BOOK_FAILED;
    }

    book_handle->bookkeeper = mmap(NULL, sizeof(bookkeeper_t), PROT_READ | PROT_WRITE, MAP_SHARED, book_handle->fd, 0);

    if (book_handle->bookkeeper == MAP_FAILED) {
        close(book_handle->fd);
        free(book_handle);
        LogError("mmap() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return BOOK_FAILED;
    }

    if (book_handle->bookkeeper->magic != BOOK_MAGIC) {
        LogError("File %s is not a valid nfbook file", path);
        munmap(book_handle->bookkeeper, sizeof(bookkeeper_t));
        close(book_handle->fd);
        free(book_handle);
        return BOOK_FAILED;
    }

    if (book_handle->bookkeeper->version != BOOK_VERSION) {
        LogError("Found unknown version for bookkeeper: %u", book_handle->bookkeeper->version);
        munmap(book_handle->bookkeeper, sizeof(bookkeeper_t));
        close(book_handle->fd);
        free(book_handle);
        return BOOK_FAILED;
    }

    return book_handle;
}  // End of book_attach

// collector rotate cycle
void book_update(book_handle_t *book_handle, time_t when, uint64_t size) {
    book_lock(book_handle->fd);

    if (book_handle->bookkeeper->first == 0) book_handle->bookkeeper->first = when;

    book_handle->bookkeeper->last = when;
    book_handle->bookkeeper->numfiles++;
    book_handle->bookkeeper->filesize += size;
    book_handle->bookkeeper->sequence++;

    msync(book_handle->bookkeeper, sizeof(bookkeeper_t), MS_ASYNC);

    book_unlock(book_handle->fd);
}  // End of book_update

// nfexpire set parameters
void book_set_limits(book_handle_t *book_handle, time_t lifetime, uint64_t maxsize, uint32_t watermark) {
    book_lock(book_handle->fd);

    if (lifetime) book_handle->bookkeeper->max_lifetime = lifetime;
    if (maxsize) book_handle->bookkeeper->max_filesize = maxsize;
    if (watermark) book_handle->bookkeeper->sequence++;

    msync(book_handle->bookkeeper, sizeof(bookkeeper_t), MS_ASYNC);

    book_unlock(book_handle->fd);
}  // End of book_set_limits

// return current book - no changes - no sequence update
void book_get(book_handle_t *book_handle, bookkeeper_t *bookkeeper) {
    book_lock(book_handle->fd);

    if (bookkeeper) memcpy(bookkeeper, book_handle->bookkeeper, sizeof(bookkeeper_t));

    book_unlock(book_handle->fd);

}  // End of book_get

// set new bookkeeper record, if both sequence numbers are identical
int book_set(book_handle_t *book_handle, bookkeeper_t *bookkeeper) {
    if (bookkeeper == NULL) return 0;
    book_lock(book_handle->fd);

    int ok = 0;
    if (book_handle->bookkeeper->sequence == bookkeeper->sequence) {
        memcpy(book_handle->bookkeeper, bookkeeper, sizeof(bookkeeper_t));
        book_handle->bookkeeper->sequence++;
        msync(book_handle->bookkeeper, sizeof(bookkeeper_t), MS_SYNC);
        ok = 1;
    }

    book_unlock(book_handle->fd);

    return ok;
}  // End of book_set

// nfexpire removes old files, nfcapd potentially adds new files
// they do not interfer - therefor update cummulativ
int book_expire(book_handle_t *book_handle, time_t first, uint32_t expired_files, uint64_t expired_size) {
    book_lock(book_handle->fd);

    bookkeeper_t *bookkeeper = book_handle->bookkeeper;
    // check for error condition
    int ok = 0;
    if (first < bookkeeper->first || expired_files > bookkeeper->numfiles || expired_size > bookkeeper->filesize) {
        ok = 0;
    } else {
        bookkeeper->first = first;
        bookkeeper->numfiles -= expired_files;
        bookkeeper->filesize -= expired_size;
        ok = 1;
    }
    book_unlock(book_handle->fd);
    return ok;

}  // End of book_expire

// for sequence check
uint64_t book_sequence(book_handle_t *book_handle) {
    uint64_t seq;

    book_lock(book_handle->fd);
    seq = book_handle->bookkeeper->sequence;
    book_unlock(book_handle->fd);

    return seq;
}  // End of book_sequence
