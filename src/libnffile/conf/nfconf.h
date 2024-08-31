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

#ifndef _NFCONF_H
#define _NFCONF_H 1

#include <stdint.h>
#include <stdio.h>

#define NOCONF "none"

typedef enum { OPTDEFAULT, OPTSET } optFlags;
typedef struct option_s {
    char *name;
    union {
        int valBool;
        int64_t valInt64;
        uint64_t valUint64;
        char *valString;
    };
    optFlags flags;
} option_t;

int ConfOpen(char *filename, char *section);

int ConfGetFormatEntry(char *format, char **key, char **value);

int ConfGetExporter(char **ident, char **ip, char **flowdir);

char *ConfGetString(char *key);

int ConfGetValue(char *key);

int ConfGetInt64(option_t *optionList, char *key, uint64_t *valOnt64);

int ConfSetInt64(option_t *optionList, char *key, uint64_t valInt64);

int ConfGetUint64(option_t *optionList, char *key, uint64_t *valUint64);

int ConfSetUint64(option_t *optionList, char *key, uint64_t valUint64);

int SetNameserver(char *ns);

int scanOptions(option_t *optionList, char *options);

void ConfInventory(char *confFile);

int OptSetBool(option_t *optionList, char *name, int valBool);

int OptGetBool(option_t *optionList, char *name, int *valBool);

#endif