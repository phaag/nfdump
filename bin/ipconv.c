/*
 *  Copyright (c) 2014, Peter Haag
 *  Copyright (c) 2009, Peter Haag
 *  Copyright (c) 2008-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
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
 * Copyright (c) 1996 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 *
 *  $Author: haag $
 *
 *  $Id: ipconv.c 39 2009-11-25 08:11:15Z haag $
 *
 *  $LastChangedRevision: 39 $
 *  
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nffile.h"
#include "util.h"
#include "ipconv.h"


static int	parse_ipv4(const char *src, uint32_t *dst, int *bytes);
static int	parse_ipv6(const char *src, uint64_t *dst, int *bytes);
static int lookup_host(const char *hostname, uint64_t *iplist, uint32_t *num_ip );

int parse_ip(int *af, const char *src, uint64_t *dst, int *bytes, int lookup, uint32_t *num_ip ) {
char *alpha = "abcdefghijklmnopqrstuvwxzyABCDEFGHIJKLMNOPQRSTUVWXZY";
uint32_t	v4addr;
int ret;

	// check for IPv6 address
	if ( strchr(src, ':') != NULL ) {
		*af = PF_INET6;
	// check for alpha chars -> hostname -> lookup
	} else if ( strpbrk(src, alpha)) {
		*af = 0;
		if ( lookup == STRICT_IP )
			return -1;
		else
			return lookup_host(src, dst, num_ip );
	// it's IPv4
	} else
		*af = PF_INET;

	*num_ip = 1;
	switch (*af) {
	case AF_INET:
		ret =  (parse_ipv4(src, &v4addr, bytes));
		dst[0] = 0;
		dst[1] = ntohl(v4addr) & 0xffffffffLL ;
		return ret;
		break;
	case AF_INET6:
		ret =  (parse_ipv6(src, dst, bytes));
		dst[0] = ntohll(dst[0]);
		dst[1] = ntohll(dst[1]);
		return ret;
		break;
	}
	/* NOTREACHED */

	return 0;
}

static int parse_ipv4(const char *src, uint32_t *dst, int *bytes) {
static const char digits[] = "0123456789";
int saw_digit, ch;
uint8_t  tmp[4], *tp;

	saw_digit = 0;
	*bytes = 0;
	*(tp = tmp) = 0;
	memset(tmp, 0, sizeof(tmp));
	while ((ch = *src++) != '\0') {
		const char *pch;

		if ((pch = strchr(digits, ch)) != NULL) {
			unsigned int new = *tp * 10 + (pch - digits);

			if (new > 255)
				return (0);
			if (! saw_digit) {
				if (++(*bytes) > 4)
					return (0);
				saw_digit = 1;
			}
			*tp = new;
		} else if (ch == '.' && saw_digit) {
			if (*bytes == 4)
				return (0);
			*++tp = 0;
			saw_digit = 0;
			if ( !(*src) )
				return 0;
		} else
			return (0);
	}

	memcpy(dst, tmp, sizeof(tmp));
	return (1);
}

static int parse_ipv6(const char *src, uint64_t *dst, int *bytes) {
static const char xdigits_l[] = "0123456789abcdef",
		  xdigits_u[] = "0123456789ABCDEF";
uint8_t tmp[16], *tp, *endp, *colonp;
const char *xdigits, *curtok;
int ch, saw_xdigit;
u_int val;

	memset((tp = tmp), '\0', sizeof(tmp));
	endp = tp + sizeof(tmp);
	colonp = NULL;
	/* Leading :: requires some special handling. */
	if (*src == ':')
		if (*++src != ':')
			return (0);
	curtok = src;
	saw_xdigit = 0;
	val = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;

		if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL)
			pch = strchr((xdigits = xdigits_u), ch);
		if (pch != NULL) {
			val <<= 4;
			val |= (pch - xdigits);
			if (val > 0xffff)
				return (0);
			saw_xdigit = 1;
			continue;
		}
		if (ch == ':') {
			curtok = src;
			if (!saw_xdigit) {
				if (colonp)
					return (0);
				colonp = tp;
				continue;
			} else if (*src == '\0') {
				return (0);
			}
			if (tp + sizeof(uint16_t) > endp)
				return (0);
			*tp++ = (u_char) (val >> 8) & 0xff;
			*tp++ = (u_char) val & 0xff;
			saw_xdigit = 0;
			val = 0;
			continue;
		}
		if (ch == '.' && ((tp + 4) <= endp) &&
		    parse_ipv4(curtok, (uint32_t *)tp, bytes) > 0) {
			tp += 4;
			saw_xdigit = 0;
			break;	/* '\0' was seen by parse_ipv4(). */
		}
		return (0);
	}
	if (saw_xdigit) {
		if (tp + sizeof(uint16_t) > endp)
			return (0);
		*tp++ = (u_char) (val >> 8) & 0xff;
		*tp++ = (u_char) val & 0xff;
	}
	if (colonp != NULL) {
		/*
		 * Since some memmove()'s erroneously fail to handle
		 * overlapping regions, we'll do the shift by hand.
		 */
		const int n = tp - colonp;
		int i;

		for (i = 1; i <= n; i++) {
			endp[- i] = colonp[n - i];
			colonp[n - i] = 0;
		}
		tp = endp;
	}
	*bytes = 16 - ( endp - tp );
		
	memcpy(dst, tmp, sizeof(tmp));
	return (1);
}

static int lookup_host(const char *hostname, uint64_t *iplist, uint32_t *num_ip ) {
struct addrinfo hints, *res, *r;
int 		errcode, i, len;
char 		addrstr[128];
char 		reverse[256];
void 		*ptr;

	printf("Resolving %s ...\n", hostname);

	memset (&hints, 0, sizeof (hints));
	hints.ai_family 	= PF_UNSPEC;
	hints.ai_socktype 	= SOCK_STREAM;
	hints.ai_flags 		|= AI_CANONNAME;

	errcode = getaddrinfo (hostname, NULL, &hints, &res);
	if (errcode != 0) {
		fprintf(stderr, "Failed to resolve IP address for %s: %s\n", hostname, gai_strerror(errno));
		return 0;
	}

	// count the number of records found
	*num_ip = 0;

	// remember res for later free()
	r = res;

	i = 0;
	while (res) {
		if ( *num_ip >= MAXHOSTS ) {
			printf ("Too man IP addresses in DNS response\n");
			return 1;
		}
		switch (res->ai_family) {
        	case PF_INET:  
				ptr = &(((struct sockaddr_in *) res->ai_addr)->sin_addr);
				iplist[i++] = 0;
				iplist[i++] = ntohl(*(uint32_t *)ptr) & 0xffffffffLL ;
				len = sizeof(struct sockaddr_in);
				break;
			case AF_INET6:
				ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
				iplist[i++] = ntohll(((uint64_t *)ptr)[0]);
				iplist[i++] = ntohll(((uint64_t *)ptr)[1]);
				len = sizeof(struct sockaddr_in6);
				break;
			default: {
				// not handled
				res = res->ai_next;
				continue;
			}
		}
		inet_ntop (res->ai_family, ptr, addrstr, 100);
		addrstr[99] = '\0';
		if ( (errcode = getnameinfo(res->ai_addr, len, reverse, sizeof(reverse), NULL,0,0)) != 0 ) {
			snprintf(reverse, sizeof(reverse)-1, "<reverse lookup failed>");
			// fprintf(stderr, "Failed to reverse lookup %s: %s\n", addrstr, gai_strerror(errcode));
    	}

		printf ("IPv%d address: %s (%s)\n", res->ai_family == PF_INET6 ? 6 : 4, addrstr, reverse );
		res = res->ai_next;
		(*num_ip)++;
    }
	
	freeaddrinfo(r);
	return 1;

} // End of lookup_host

int set_nameserver(char *ns) {
struct hostent *host;

	res_init();
	host = gethostbyname(ns);
	if (host == NULL) {
		(void) fprintf(stderr,"Can not resolv nameserver %s: %s\n", ns, hstrerror(h_errno));
		return 0;
	}
	(void) memcpy((void *)&_res.nsaddr_list[0].sin_addr, (void *)host->h_addr_list[0], (size_t)host->h_length);
	_res.nscount = 1;
	return 1;

} // End of set_nameserver


/*
int main( int argc, char **argv ) {

char	*s, t[64];
uint64_t	anyaddr[2];
uint32_t	 num_ip;
int af, ret, bytes;

	
	s = argv[1];
	if (argc == 3 && !set_nameserver(argv[2]) )
			return 0;

	lookup_host(s, &num_ip);
	return 0;

	ret = parse_ip(&af, s, anyaddr, &bytes);
	if ( ret != 1 ) {
		printf("Parse failed!\n");
		return 0;
	}

	if ( af == PF_INET ) 
		inet_ntop(af, &(((uint32_t *)anyaddr)[3]), t, 64);
	else
		inet_ntop(af, anyaddr, t, 64);

	printf("Convert back: %s => %s %i bytes\n", s, t, bytes);

}

*/

