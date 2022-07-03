/*
 *  Copyright (c) 2019-2021, Peter Haag
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

#ifndef _OUTPUT_UTIL_H
#define _OUTPUT_UTIL_H 1

#include <stdbool.h>
#include <stdio.h>

typedef void (*printer_t)(FILE *, void *, int);
typedef void (*func_prolog_t)(bool quiet);
typedef void (*func_epilog_t)(bool quiet);

enum { MODE_PLAIN = 0, MODE_PIPE, MODE_JSON, MODE_CSV };
typedef struct outputParams_s {
    bool printPlain;
    bool doTag;
    bool quiet;
    int mode;
    int topN;
} outputParams_t;

typedef struct printmap_s {
    char *printmode;            // name of the output format
    printer_t func_record;      // prints the record
    func_prolog_t func_prolog;  // prints the output prolog
    func_epilog_t func_epilog;  // prints the output epilog
    char *Format;               // output format definition
} printmap_t;

char *ProtoString(uint8_t protoNum, uint32_t plainNumbers);

int ProtoNum(char *protoString);

char *FlagsString(uint16_t flags);

char *biFlowString(uint8_t biFlow);

char *FlowEndString(uint8_t biFlow);

void CondenseV6(char *s);

char *FwEventString(int event);

char *EventString(int event);

char *EventXString(int xevent);

void DumpHex(FILE *stream, const void *data, size_t size);

#endif  // _OUTPUT_UTIL_H
