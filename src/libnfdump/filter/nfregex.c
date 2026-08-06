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

#include "nfregex.h"

#include "config.h"

#ifdef HAVE_PCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

#include <stdio.h>
#include <stdlib.h>

struct RegexMatchContext_s {
    unsigned char unused;
#ifdef HAVE_PCRE2
    pcre2_match_data *matchData;
#endif
};

int HasRegexSupport(void) {
#ifdef HAVE_PCRE2
    return 1;
#else
    return 0;
#endif
}  // End of HasRegexSupport

void *CompileRegex(const char *pattern, const char *mods, char *errBuf, size_t errBufLen) {
#ifndef HAVE_PCRE2
    (void)pattern;
    (void)mods;
    if (errBuf && errBufLen) snprintf(errBuf, errBufLen, "nfdump was built without PCRE2 - 'payload regex' is not available");
    return NULL;
#else
    if (!pattern) return NULL;

    /* Payloads are arbitrary bytes. Do not let a pattern switch the matcher
     * into UTF/UCP mode, because an invalid byte sequence would then turn a
     * regular byte match into a UTF validation error. ANYCRLF preserves the
     * old engine's treatment of both CR and LF as line endings; DOLLAR_ENDONLY
     * preserves its default '$' behaviour. The latter is ignored for /m. */
    uint32_t options = PCRE2_NEVER_UTF | PCRE2_NEVER_UCP | PCRE2_DOLLAR_ENDONLY;
    for (const char *m = mods; m && *m; m++) {
        switch (*m) {
            case 'i':
                options |= PCRE2_CASELESS;
                break;
            case 'm':
                options |= PCRE2_MULTILINE;
                break;
            case 's':
                options |= PCRE2_DOTALL;
                break;
            default:
                if (errBuf && errBufLen) snprintf(errBuf, errBufLen, "invalid regex modifier '%c' - valid modifiers are 'm', 'i', 's'", *m);
                return NULL;
        }
    }

    pcre2_compile_context *compileContext = pcre2_compile_context_create(NULL);
    if (!compileContext || pcre2_set_newline(compileContext, PCRE2_NEWLINE_ANYCRLF) != 0) {
        if (errBuf && errBufLen) snprintf(errBuf, errBufLen, "failed to create PCRE2 compile context");
        if (compileContext) pcre2_compile_context_free(compileContext);
        return NULL;
    }

    int errCode;
    PCRE2_SIZE errOffset;
    pcre2_code *code = pcre2_compile((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED, options, &errCode, &errOffset, compileContext);
    pcre2_compile_context_free(compileContext);
    if (!code) {
        if (errBuf && errBufLen) {
            PCRE2_UCHAR pcreErr[120];
            pcre2_get_error_message(errCode, pcreErr, sizeof(pcreErr));
            snprintf(errBuf, errBufLen, "%s at offset %zu", (char *)pcreErr, (size_t)errOffset);
        }
        return NULL;
    }

    // Best-effort JIT compile for speed. If the platform/PCRE2 build has no
    // JIT support, this simply fails and pcre2_match() below transparently
    // uses the portable interpreter instead - no fallback logic needed here.
    pcre2_jit_compile(code, PCRE2_JIT_COMPLETE);

    return (void *)code;
#endif
}  // End of CompileRegex

RegexMatchContext_t *CreateRegexMatchContext(void) {
    RegexMatchContext_t *context = calloc(1, sizeof(*context));
    if (!context) return NULL;
#ifdef HAVE_PCRE2
    /* The filter VM reports only a boolean, so one ovector pair for the
     * overall match is sufficient. PCRE2 still handles internal captures and
     * backreferences correctly. */
    context->matchData = pcre2_match_data_create(1, NULL);
    if (!context->matchData) {
        free(context);
        return NULL;
    }
#endif
    return context;
}  // End of CreateRegexMatchContext

void FreeRegexMatchContext(RegexMatchContext_t *context) {
    if (!context) return;
#ifdef HAVE_PCRE2
    pcre2_match_data_free(context->matchData);
#endif
    free(context);
}  // End of FreeRegexMatchContext

int MatchRegex(const void *program, const char *data, uint32_t length, RegexMatchContext_t *context) {
#ifndef HAVE_PCRE2
    (void)program;
    (void)data;
    (void)length;
    (void)context;
    return 0;
#else
    if (!program || !context || !context->matchData) return 0;

    int rc = pcre2_match((const pcre2_code *)program, (PCRE2_SPTR)data, (PCRE2_SIZE)length, 0, 0, context->matchData, NULL);
    // rc >= 0 signals a match (0 means the match succeeded but the capture
    // vector was too small to hold every subexpression - the overall match,
    // which is all MatchRegex() reports, is still valid).
    return rc >= 0;
#endif
}  // End of MatchRegex

void FreeRegex(void *program) {
#ifdef HAVE_PCRE2
    if (program) pcre2_code_free((pcre2_code *)program);
#else
    (void)program;
#endif
}  // End of FreeRegex
