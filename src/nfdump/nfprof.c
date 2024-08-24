/*
 *  Copyright (c) 2009-2021, Peter Haag
 *  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
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

#include "nfprof.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>

#include "config.h"
#include "util.h"

/*
 * Initialize profiling.
 *
 */
int nfprof_start(nfprof_t *profile_data) {
    memset((void *)profile_data, 0, sizeof(nfprof_t));
    return gettimeofday(&profile_data->tstart, (struct timezone *)NULL) == 0 ? 1 : 0;

}  // End of nfprof_start

/*
 * Finish profiling.
 *
 */
int nfprof_end(nfprof_t *profile_data, uint64_t numflows) {
    int ret;

    if ((ret = gettimeofday(&profile_data->tend, (struct timezone *)NULL)) == -1) return 1;

    if ((ret = getrusage(RUSAGE_SELF, &profile_data->used)) == -1) return 1;

    profile_data->numflows = numflows;

    return 0;

}  // End of nfprof_end

/*
 * Dump nfprof contents to std
 *
 */
void nfprof_print(nfprof_t *profile_data, FILE *std) {
    struct timeval tv;

    gettimeofday(&tv, NULL);

    double tsys = profile_data->used.ru_stime.tv_sec + profile_data->used.ru_stime.tv_usec / 1000000.0;
    double tuser = profile_data->used.ru_utime.tv_sec + profile_data->used.ru_utime.tv_usec / 1000000.0;

    double tstart = profile_data->tstart.tv_sec + profile_data->tstart.tv_usec / 1000000.0;
    double tend = profile_data->tend.tv_sec + profile_data->tend.tv_usec / 1000000.0;
    double tstop = tv.tv_sec + tv.tv_usec / 1000000.0;

    double fps;
    if (tstart == tend)
        // acctually should never happen, but catch it anyway
        fps = 0;
    else
        fps = (double)profile_data->numflows / (tend - tstart);

    fprintf(std, "Sys: %.4fs User: %.4fs Wall: %.4fs flows/second: %-.1f Runtime: %.4fs\n", tsys, tuser, tend - tstart, fps, tstop - tstart);

#ifdef DEVEL
    fprintf(std, "\n");
    fprintf(std, "Max RSS: %ld\n", profile_data->used.ru_maxrss);
    /*
            fprintf(std, "integral shared text memory size: %ld\n", profile_data->used.ru_ixrss);
            fprintf(std, "integral unshared data size: %ld\n", profile_data->used.ru_idrss);
            fprintf(std, "integral unshared stack size: %ld\n", profile_data->used.ru_isrss);
    */
    fprintf(std, "page reclaims: %ld\n", profile_data->used.ru_minflt);
    fprintf(std, "page faults: %ld\n", profile_data->used.ru_majflt);
    fprintf(std, "swaps: %ld\n", profile_data->used.ru_nswap);
/*
        fprintf(std, "block input operations: %ld\n", profile_data->used.ru_inblock);
        fprintf(std, "block output operations: %ld\n", profile_data->used.ru_oublock);
*/
#endif

}  // End of nfprof_print
