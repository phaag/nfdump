/*
 *  Copyright (c) 2022-2026, Peter Haag
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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define NOCONF "none"

/* Value type tag for option_t.  CONF_BOOL = 0 so zero-initialised entries
 * (the common case for bool defaults) need no explicit .type field.        */
typedef enum { CONF_BOOL = 0, CONF_INT64, CONF_UINT64, CONF_STRING } confType_t;

typedef struct option_s {
    const char *key;
    confType_t type;
    union {
        bool valBool;
        int64_t valInt64;
        uint64_t valUint64;
        char *valString;
    };
} option_t;

/* Open the config file.  defaultConf is a NULL-key-sentinel-terminated array
 * of per-program defaults consulted last (lowest priority); pass NULL if the
 * program has no defaults.                                                   */
int ConfOpen(char *filename, char *section, option_t *defaultConf);

/* Store a runtime CLI override (-x key=value).                              */
int ConfSetOverride(const char *confString);

int ConfGetFormatEntry(char *format, char **key, char **value);

int ConfGetExporter(char **ident, char **ip, char **flowdir);

/* Getters — priority: CLI override > config file > program defaults.
 * ConfGetString() returns a heap-allocated string; caller must free().      */
char *ConfGetString(const char *key);

int64_t ConfGetValue(const char *key);

bool ConfGetBool(const char *key);

void ConfInventory(const char *confFile);

// scan option string
int scanOptions(option_t *optionList, char *options);

#endif
