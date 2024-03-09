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

#ifndef _jA4S_H
#define _jA4S_H 1

#include <stdint.h>
#include <sys/types.h>

#include "ssl/ssl.h"

/*
       + ------ Protocol, TCP = "I" QUIC= "q"
       | + ---- TLS version, 1.2 = "12", 1.3 = "13"
       | | + -- Number of Extensions
       | | | +- ALPN Chosen (00 if no ALPN)
       | | | |    +-  Cipher Suite Chosen
       | | | |    |
       | | | |    |            +- Truncated SHA256 hash of the Extensions, in the order they appear
       | | | |    |            |
  JA45=t120400_C030_4e8089608790
       ja4s_a  ja4s_b ja4s_c


*/
typedef struct ja4s_s {
    char a[8];   // max 7 chars + '\0'
    char b[8];   // max 4 chars + '\0'
    char c[14];  // max 12 chars + '\0'
} ja4s_t;

ja4s_t *ja4sProcess(ssl_t *ssl, uint8_t proto);

char *ja4sString(ja4s_t *ja4s, char *buff);

void ja4sPrint(ja4s_t *ja4s);

void ja4sFree(ja4s_t *ja4s);
#endif
