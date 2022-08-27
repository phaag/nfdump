/*
 * Copyright (c) 2012-2013 Arvīds Kokins
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to the
 * following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
 * FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

#ifndef SG_REGEX_H_
#define SG_REGEX_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#define RXSUCCESS 0
#define RXEINMOD -1 /* invalid modifier */
#define RXEPART -2  /* partial (sub-)expression */
#define RXEUNEXP -3 /* unexpected character */
#define RXERANGE -4 /* invalid range (min > max) */
#define RXELIMIT -5 /* too many digits */
#define RXEEMPTY -6 /* expression is effectively empty */
#define RXENOREF -7 /* the specified backreference cannot be used here */

#define RX_ALLMODS "mis"

#ifndef RX_STRLENGTHFUNC
#define RX_STRLENGTHFUNC(str) strlen(str)
#endif

typedef void* (*srx_MemFunc)(void* /* userdata */, void* /* ptr */, size_t /* size */
);

#ifdef RX_NEED_DEFAULT_MEMFUNC
static void* srx_DefaultMemFunc(void* userdata, void* ptr, size_t size) {
    (void)userdata;
    if (size) return realloc(ptr, size);
    free(ptr);
    return NULL;
}
#endif

typedef char rxChar;
typedef unsigned char rxUChar;
typedef struct _srx_Context srx_Context;

srx_Context* srx_CreateExt(const rxChar* str, size_t strsize, const rxChar* mods, int* errnpos, srx_MemFunc memfn, void* memctx);
#define srx_Create(str, mods) srx_CreateExt(str, RX_STRLENGTHFUNC(str), mods, NULL, NULL, NULL)
void srx_Destroy(srx_Context* R);
void srx_DumpToFile(srx_Context* R, FILE* fp);
#define srx_DumpToStdout(R) srx_DumpToFile(R, stdout)

int srx_MatchExt(srx_Context* R, const rxChar* str, size_t size, size_t offset);
#define srx_Match(R, str, off) srx_MatchExt(R, str, RX_STRLENGTHFUNC(str), off)
int srx_GetCaptureCount(srx_Context* R);
int srx_GetCaptured(srx_Context* R, int which, size_t* pbeg, size_t* pend);
int srx_GetCapturedPtrs(srx_Context* R, int which, const rxChar** pbeg, const rxChar** pend);

rxChar* srx_ReplaceExt(srx_Context* R, const rxChar* str, size_t strsize, const rxChar* rep, size_t repsize, size_t* outsize);
#define srx_Replace(R, str, rep) srx_ReplaceExt(R, str, RX_STRLENGTHFUNC(str), rep, RX_STRLENGTHFUNC(rep), NULL)
void srx_FreeReplaced(srx_Context* R, rxChar* repstr);

#ifdef __cplusplus
}
#endif

#endif /* SG_REGEX_H_ */
