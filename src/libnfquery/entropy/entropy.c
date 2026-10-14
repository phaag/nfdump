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

#include "entropy.h"

#include <math.h>
#include <pthread.h>
#include <string.h>

/*
 * Shannon entropy H = log2(n) - (1/n) * sum(c * log2(c)) over the byte counts c.
 * c * log2(c) comes from a table for counts up to ENTROPY_TABLE, so no log2()
 * per distinct byte. The 256 bin sum runs in 4 accumulators to break the
 * floating point dependency chain.
 */
#define ENTROPY_TABLE 4096
// from this length, count into 4 interleaved histograms: runs of the same
// byte (padding) would otherwise serialise on one counter
#define ENTROPY_MULTIHIST 512

static float clogc[ENTROPY_TABLE + 1];
static pthread_once_t clogcOnce = PTHREAD_ONCE_INIT;

static void InitEntropyTable(void) {
    clogc[0] = 0.0f;
    for (int c = 1; c <= ENTROPY_TABLE; c++) clogc[c] = (float)(c * log2((double)c));
}  // End of InitEntropyTable

static inline double CLogC(uint32_t c) { return c <= ENTROPY_TABLE ? clogc[c] : c * log2((double)c); }

uint32_t PayloadEntropy(const uint8_t *data, uint32_t len) {
    if (data == NULL || len == 0) return 0;
    pthread_once(&clogcOnce, InitEntropyTable);

    double s[4] = {0};
    if (len < ENTROPY_MULTIHIST) {
        uint32_t hist[256];
        memset(hist, 0, sizeof(hist));
        for (uint32_t i = 0; i < len; i++) hist[data[i]]++;
        for (int b = 0; b < 256; b += 4) {
            for (int k = 0; k < 4; k++) s[k] += CLogC(hist[b + k]);
        }
    } else {
        uint32_t hist[4][256];
        memset(hist, 0, sizeof(hist));
        uint32_t i = 0;
        for (; i + 4 <= len; i += 4) {
            hist[0][data[i]]++;
            hist[1][data[i + 1]]++;
            hist[2][data[i + 2]]++;
            hist[3][data[i + 3]]++;
        }
        for (; i < len; i++) hist[0][data[i]]++;
        for (int b = 0; b < 256; b += 4) {
            for (int k = 0; k < 4; k++) s[k] += CLogC(hist[0][b + k] + hist[1][b + k] + hist[2][b + k] + hist[3][b + k]);
        }
    }

    double h = log2((double)len) - (s[0] + s[1] + s[2] + s[3]) / (double)len;
    return h <= 0.0 ? 0 : (uint32_t)(h * 1000.0 + 0.5);
}  // End of PayloadEntropy
