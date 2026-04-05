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

#ifndef _NFFILEV2_H
#define _NFFILEV2_H 1

/*
 * output buffer max size, before writing data to the file
 * used to cache flows before writing to disk. size: tradeoff between
 * size and time to flush to disk. Do not delay collector with long I/O
 */
#define ONEMB 1048576
#define WRITE_BUFFSIZE (2 * ONEMB)
/*
 * use this buffer size to allocate memory for the output buffer
 * data other than flow records, such as histograms, may be larger than
BUFFSIZE and have potentially more time to flush to disk
 */
#define BUFFSIZE (5 * ONEMB)

/* if the output buffer reaches this limit, it gets flushed. This means,
 * that 0.5MB input data may produce max 1MB data in output buffer, otherwise
 * a buffer overflow may occur, and data does not get processed correctly.
 * However, every Process_vx function checks buffer boundaries.
 */

#define MAXRECORDSIZE 1024

/*
 * In file layout format 1: After the file header an
 * implicit stat record follows, which contains the statistics
 * information about all netflow records in this file.
 */

#define DATA_BLOCK_MESSAGE 0x0100

typedef struct dataBlockV2_s dataBlockV2_t;

int VerifyFileV2(const char *filename, int verbose);

#endif