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

#ifndef _OUTPUT_H
#define _OUTPUT_H 1

#include <stdbool.h>
#include <stdio.h>

#include "nfdump.h"

typedef void (*RecordPrinter_t)(FILE *, recordHandle_t *, int);
typedef void (*PrologPrinter_t)(void);
typedef void (*EpilogPrinter_t)(void);

enum { MODE_PLAIN = 0, MODE_JSON, MODE_CSV };
typedef struct outputParams_s {
    bool printPlain;
    bool doTag;
    bool quiet;
    bool hasGeoDB;
    int mode;
    int topN;
} outputParams_t;

typedef struct printmap_s {
    char *printmode;              // name of the output format
    RecordPrinter_t func_record;  // prints the record
    PrologPrinter_t func_prolog;  // prints the output prolog
    PrologPrinter_t func_epilog;  // prints the output epilog
    char *Format;                 // output format definition
} printmap_t;

void AddFormat(char *name, char *fmtString);

RecordPrinter_t SetupOutputMode(char *print_format, outputParams_t *outputParams);

void PrintProlog(outputParams_t *outputParams);

void PrintEpilog(outputParams_t *outputParams);

#endif