/*
 *  Copyright (c) 2009-2020, Peter Haag
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

#ifndef _EXPIRE_H
#define _EXPIRE_H 1

#include <stdint.h>
#include <sys/types.h>

#include "config.h"

#ifdef HAVE_FTS_H
#include <fts.h>
#else
#include "fts_compat.h"
#endif

#include "bookkeeper.h"

typedef struct channel_s {
    struct channel_s *next;
    char *datadir;               // channel directory
    book_handle_t *book_handle;  // handle to books
    int dirfd;                   // reference to open channel dir
    uint64_t expired_size;       // expired size of file blocks
    uint64_t expired_files;      // expired files
    time_t expired_time;         // time span expired
} channel_t;

int ParseSizeDef(const char *s, uint64_t *value);

int ParseTimeDef(const char *s, time_t *value);

int RescanDir(const channel_t *channel);

int ExpireDir(channel_t *channel, uint64_t maxsize, time_t maxlife, uint32_t low_water, time_t runtime, int dryrun);

int ExpireProfile(const char *profile, channel_t *channel, uint64_t maxsize, time_t maxlife, uint32_t low_water, uint32_t runtime, int dryrun);

#endif  //_EXPIRE_H
