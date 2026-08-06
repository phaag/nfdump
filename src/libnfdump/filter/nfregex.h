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

/*
 * nfregex - thin wrapper around PCRE2
 *
 * Design:
 *  - CompileRegex() is called once per 'payload regex' filter term, at
 *    filter-compile time. The returned program is immutable afterwards.
 *  - MatchRegex() is called from the bytecode hot path, potentially by many
 *    filter-worker threads concurrently, all sharing the same compiled
 *    program (see FilterEngine_t / FilterCloneEngine() - prog[] and its aux
 *    pointers are shared read-only across all clones). Each engine has its
 *    own RegexMatchContext_t, which owns reusable PCRE2 match scratch space.
 *    This keeps mutable state thread-local and avoids allocator traffic in
 *    the record-processing path.
 *  - Subject data is matched by explicit length, never by strlen(): payloads
 *    are arbitrary binary data and may contain embedded NUL bytes.
 *  - If nfdump was built without PCRE2 (HAVE_PCRE2 undefined), CompileRegex()
 *    always fails - a filter using 'payload regex' then fails to compile
 *    instead of silently matching with a different/weaker engine.
 */

#ifndef NFREGEX_H_
#define NFREGEX_H_

#include <stddef.h>
#include <stdint.h>

typedef struct RegexMatchContext_s RegexMatchContext_t;

/*
 * Compiles pattern with the given modifier letters (any of "mis", see
 * nfdump.1) into an opaque, immutable program.
 *
 * Returns the compiled program on success, or NULL on failure - including
 * when nfdump was built without PCRE2. On failure, a human readable message
 * is written to errBuf (if given).
 */
void *CompileRegex(const char *pattern, const char *mods, char *errBuf, size_t errBufLen);

/*
 * Matches length bytes at data (which may contain embedded NUL bytes)
 * against program. Returns 1 on match, 0 otherwise. Safe to call
 * concurrently from multiple threads with the same program.
 */
int MatchRegex(const void *program, const char *data, uint32_t length, RegexMatchContext_t *context);

// Creates/releases reusable, per-engine match scratch space.
RegexMatchContext_t *CreateRegexMatchContext(void);
void FreeRegexMatchContext(RegexMatchContext_t *context);

// Releases a program created by CompileRegex().
void FreeRegex(void *program);

// Returns 1 if nfdump was built with PCRE2 support, 0 otherwise.
int HasRegexSupport(void);

#endif  // NFREGEX_H_
