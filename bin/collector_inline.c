/*
 *  Copyright (c) 2014, Peter Haag
 *  Copyright (c) 2009, Peter Haag
 *  Copyright (c) 2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
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
 *  $Id: collector_inline.c 37 2009-11-10 08:40:30Z haag $
 *
 *  $LastChangedRevision: 37 $
 *	
 */

static inline FlowSource_t *GetFlowSource(struct sockaddr_storage *ss) {
FlowSource_t	*fs;
void			*ptr;
ip_addr_t		ip;
char			as[100];

    union {
        struct sockaddr_storage	*ss;
        struct sockaddr			*sa;
        struct sockaddr_in		*sa_in;
        struct sockaddr_in6		*sa_in6;
    } u;
    u.ss = ss;

	switch (ss->ss_family) {
		case PF_INET: {
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN
			if (ss->ss_len != sizeof(struct sockaddr_in) ) {
				// malformed struct
				LogError("Malformed IPv4 socket struct in '%s', line '%d'", __FILE__, __LINE__ );
				return NULL;
			}
#endif
			ip.v6[0] = 0;
			ip.v6[1] = 0;
			ip.v4 = ntohl(u.sa_in->sin_addr.s_addr);
			ptr 	   = &u.sa_in->sin_addr;
			} break;
		case PF_INET6: {
			uint64_t *ip_ptr = (uint64_t *)u.sa_in6->sin6_addr.s6_addr;
			
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN
			if (ss->ss_len != sizeof(struct sockaddr_in6) ) {
				// malformed struct
				LogError("Malformed IPv6 socket struct in '%s', line '%d'", __FILE__, __LINE__ );
				return NULL;
			}
#endif
			// ptr = &((struct sockaddr_in6 *)sa)->sin6_addr;
			ip.v6[0] = ntohll(ip_ptr[0]);
			ip.v6[1] = ntohll(ip_ptr[1]);
			ptr = &u.sa_in6->sin6_addr;
			} break;
		default:
			// keep compiler happy
			ip.v6[0] = 0;
			ip.v6[1] = 0;
			ptr   = NULL;

			LogError("Unknown sa fanily: %d in '%s', line '%d'", ss->ss_family, __FILE__, __LINE__ );
			return NULL;
	}

#ifdef DEVEL
	inet_ntop(ss->ss_family, ptr, as, sizeof(as));
	as[99] = '\0';
	printf("Flow Source IP: %s\n", as);
#endif

	fs = FlowSource;
	while ( fs ) {
		if ( ip.v6[0] ==  fs->ip.v6[0] && ip.v6[1] == fs->ip.v6[1] )
			return fs; 

		// if we match any source, store the current IP address - works as faster cache next time
		// and identifies the current source by IP
		if ( fs->any_source ) {
			fs->ip = ip;
			fs->sa_family = ss->ss_family;
			return fs;
		}
		fs = fs->next;
	}

	if ( ptr ) {
		inet_ntop (ss->ss_family, ptr, as, 100);
	} else 
		strncpy(as, "<unknown>", 99);

	as[99] = '\0';
	LogError("Unknown flow source: '%s'" , as);

	return NULL;

} // End of GetFlowSource



