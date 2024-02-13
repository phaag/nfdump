/*
 *  Copyright (c) 2024, Peter Haag
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
 *   * Neither the name of SWITCH nor the names of its contributors may be
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

#ifndef _JA3_H
#define _JA3_H 1

#include <stdint.h>
#include <sys/types.h>

#include "config.h"

typedef struct uint16Array_s {
    uint32_t numElements;
    uint16_t *array;
} uint16Array_t;

typedef struct ja3_s {
    uint16_t version;
#define CLIENTja3 0
#define SERVERja3s 1
    uint16_t type;
    uint16Array_t cipherSuites;
    uint16Array_t extensions;
    uint16Array_t ellipticCurves;
    uint16Array_t ellipticCurvesPF;
    char sniName[256];
    char *ja3String;
    uint32_t md5Hash[4];
} ja3_t;

char *ja3HashString(ja3_t *ja3);

void ja3Print(ja3_t *ja3);

void ja3Free(ja3_t *ja3);

ja3_t *ja3Process(uint8_t *data, size_t len);

#endif
