/*
 *  Copyright (c) 2014, Peter Haag
 *  Copyright (c) 2009, Peter Haag
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
 *  $Author: haag $
 *
 *  $Id: nfprof.c 39 2009-11-25 08:11:15Z haag $
 *
 *  $LastChangedRevision: 39 $
 *	
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <strings.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <sys/time.h>
#include <sys/resource.h>
#include "nfprof.h"

/*
 * Initialize profiling.
 * 
 */
int nfprof_start(nfprof_t *profile_data) {

	bzero (profile_data, sizeof(nfprof_t));
	return gettimeofday(&profile_data->tstart, (struct timezone*)NULL) == 0 ? 1 : 0;

} // End of nfprof_start

/*
 * Finish profiling.
 * 
 */
int nfprof_end(nfprof_t *profile_data, uint64_t numflows) {
int ret;

	if ((ret = gettimeofday(&profile_data->tend, (struct timezone*)NULL)) == -1)
		return 1;

	if ((ret = getrusage(RUSAGE_SELF, &profile_data->used)) == -1)
		return 1;

	profile_data->numflows = numflows;

	return 0;

} // End of nfprof_end

/*
 * Dump nfprof contents to std
 * 
 */
void  nfprof_print(nfprof_t *profile_data, FILE *std) {
u_long usec, sec;
double fps, allsecs;

	usec = profile_data->used.ru_utime.tv_usec + profile_data->used.ru_stime.tv_usec;
	sec = profile_data->used.ru_utime.tv_sec + profile_data->used.ru_stime.tv_sec;

	if (usec > 1000000)
		usec -= 1000000, ++sec;

	
	allsecs = (double)sec + ((double)usec/1000000);
	if ( allsecs == 0.0 ) 
		fps = 0;
	else
		fps = (double)profile_data->numflows / ((double)sec + ((double)usec/1000000));

	fprintf(std, "Sys: %lu.%-3.3lus flows/second: %-10.1f ", sec, usec/1000, fps);

	if (profile_data->tend.tv_usec < profile_data->tstart.tv_usec) 
		profile_data->tend.tv_usec += 1000000, --profile_data->tend.tv_sec;

	usec = profile_data->tend.tv_usec - profile_data->tstart.tv_usec;
	sec = profile_data->tend.tv_sec - profile_data->tstart.tv_sec;

	if ( usec == 0 && sec == 0 ) 
		// acctually should never happen, but catch it anyway
		fps = 0;
	else
		fps = (double)profile_data->numflows / ((double)sec + ((double)usec/1000000));

	fprintf(std, "Wall: %lu.%-3.3lus flows/second: %-10.1f\n", sec, usec/1000, fps);
/*
	fprintf(std, "\n");
	fprintf(std, "integral max resident set size: %u\n", profile_data->used.ru_maxrss);
	fprintf(std, "integral shared text memory size: %u\n", profile_data->used.ru_ixrss);
	fprintf(std, "integral unshared data size: %u\n", profile_data->used.ru_idrss);
	fprintf(std, "integral unshared stack size: %u\n", profile_data->used.ru_isrss);
	fprintf(std, "page reclaims: %u\n", profile_data->used.ru_minflt);
	fprintf(std, "page faults: %u\n", profile_data->used.ru_majflt);
	fprintf(std, "swaps: %u\n", profile_data->used.ru_nswap);
	fprintf(std, "block input operations: %u\n", profile_data->used.ru_inblock);
	fprintf(std, "block output operations: %u\n", profile_data->used.ru_oublock);
*/

} // End of nfprof_print

