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

#ifndef _jA4_H
#define _jA4_H 1

#include <stdint.h>
#include <sys/types.h>

#include "ssl/ssl.h"

/*

example fingerprint:
t13d1516h2_8daaf6152771_b186095e22b6

(QUIC=”q” or TCP=”t”)
(2 character TLS version)
(SNI=”d” defined or SNI=”i” no SNI defined)
(2 character count of ciphers)
(2 character count of extensions)
(first and last characters of first ALPN extension value)
_
(sha256 hash of the list of cipher hex codes sorted in hex order, truncated to 12 characters)
_
(sha256 hash of (the list of extension hex codes sorted in hex order)_(the list of signature algorithms), truncated to 12 characters)

*/

enum { TYPE_JA4 = 1, TYPE_JA4S };

// ex. t13d1516h2_8daaf6152771_b186095e22bb
typedef struct ja4_s {
    uint8_t type;
    char string[];
} ja4_t;
#define OFFja4String offsetof(ja4_t, string)
#define SIZEja4String 36

int ja4Check(char *ja4String);

char *ja4Process(ssl_t *ssl, uint8_t proto, char *buff);

#endif
