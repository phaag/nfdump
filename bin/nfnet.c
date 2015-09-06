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
 *  $Id: nfnet.c 39 2009-11-25 08:11:15Z haag $
 *
 *  $LastChangedRevision: 39 $
 *	
 *
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/in.h>
#include <string.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "util.h"
#include "nfnet.h"

/* at least this number of byytes required, if we change the socket buffer */
#define Min_SOCKBUFF_LEN 65536

const int LISTEN_QUEUE = 128;

/* local function prototypes */
static int isMulticast(struct sockaddr_storage *addr);

static int joinGroup(int sockfd, int loopBack, int mcastTTL, struct sockaddr_storage *addr);

/* function definitions */

int Unicast_receive_socket(const char *bindhost, const char *listenport, int family, int sockbuflen ) {
struct addrinfo hints, *res, *ressave;
socklen_t   	optlen;
int 			error, p, sockfd;


	if ( !listenport ) {
        fprintf(stderr, "listen port required!\n");
        LogError("listen port required!");
		return -1;
	}

	// if nothing specified on command line, prefer IPv4 over IPv6, for compatibility
	if ( bindhost == NULL && family == AF_UNSPEC ) 
		family = AF_INET;

    memset(&hints, 0, sizeof(struct addrinfo));

    /*
       AI_PASSIVE flag: we use the resulting address to bind
       to a socket for accepting incoming connections. 
       So, when the hostname==NULL, getaddrinfo function will 
       return one entry per allowed protocol family containing 
       the unspecified address for that family.
    */

    hints.ai_flags    = AI_PASSIVE;
    hints.ai_family   = family;
    hints.ai_socktype = SOCK_DGRAM; 
    
    error = getaddrinfo(bindhost, listenport, &hints, &res);
	if (error) {
        fprintf(stderr, "getaddrinfo error: [%s]\n", gai_strerror(error));
        LogError("getaddrinfo error: [%s]", gai_strerror(error));
        return -1;
    }

    /* 
       Try open socket with each address getaddrinfo returned, 
       until we get a valid listening socket. 
    */
    ressave = res;
    sockfd  = -1;
    while ( res ) {
		// we listen only on IPv4 or IPv6
		if ( res->ai_family != AF_INET && res->ai_family != AF_INET6 )
			continue;

        sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol); 

        if ( !( sockfd < 0 ) ) {
			// socket call was successfull

            if (bind(sockfd, res->ai_addr, res->ai_addrlen) == 0) {
				if ( res->ai_family == AF_INET ) 
        			LogInfo("Bound to IPv4 host/IP: %s, Port: %s", 
						bindhost == NULL ? "any" : bindhost, listenport);
				if ( res->ai_family == AF_INET6 ) 
        			LogInfo("Bound to IPv6 host/IP: %s, Port: %s", 
						bindhost == NULL ? "any" : bindhost, listenport);

				// we are done
                break;
			}

			// bind was unsuccessful :(
            close(sockfd);
            sockfd = -1;
        }
        res = res->ai_next;
    }
    
    if (sockfd < 0) {
        freeaddrinfo(ressave);
        fprintf(stderr, "Could not open the requested socket: %s\n", strerror (errno));
        LogError("Receive socket error: could not open the requested socket", strerror (errno));
        return -1;
    }

    listen(sockfd, LISTEN_QUEUE); 

    freeaddrinfo(ressave);

	if ( sockbuflen ) {
		if ( sockbuflen < Min_SOCKBUFF_LEN ) {
			sockbuflen = Min_SOCKBUFF_LEN;
			LogInfo("I want at least %i bytes as socket buffer", sockbuflen);
		}
		optlen = sizeof(p);
		getsockopt(sockfd,SOL_SOCKET,SO_RCVBUF,&p,&optlen);
		LogInfo("Standard setsockopt, SO_RCVBUF is %i Requested length is %i bytes",p, sockbuflen);
		if ((setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &sockbuflen, sizeof(sockbuflen)) != 0) ) {
			fprintf (stderr, "setsockopt(SO_RCVBUF,%d): %s\n", sockbuflen, strerror (errno));
			LogError("setsockopt(SO_RCVBUF,%d): %s", sockbuflen, strerror (errno));
			close(sockfd);
			return -1;
		} else {
			getsockopt(sockfd,SOL_SOCKET,SO_RCVBUF,&p,&optlen);
			LogInfo("System set setsockopt, SO_RCVBUF to %d bytes", p);
		}
	} 

    return sockfd;

}  /* End of Unicast_receive_socket */

int Unicast_send_socket (const char *hostname, const char *sendport, int family, 
		unsigned int wmem_size, struct sockaddr_storage *addr, int *addrlen) {
struct addrinfo hints, *res, *ressave;
int n, sockfd;
unsigned int wmem_actual;
socklen_t optlen;

	if ( !hostname || !sendport ) {
        fprintf(stderr, "hostname and listen port required!\n");
        LogError("hostname and listen port required!");
		return -1;
	}

	// create socket
    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_family   = family;
    hints.ai_socktype = SOCK_DGRAM; 
    
    n = getaddrinfo(hostname, sendport, &hints, &res);

    if ( n < 0 ) {
        fprintf(stderr, "getaddrinfo error: [%s]\n", strerror(errno));
        return -1;
    }

    ressave = res;
    sockfd  = -1;
    while (res) {
        sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

        if ( !(sockfd < 0) ) {
			// socket call was successsful
            if (connect(sockfd, res->ai_addr, res->ai_addrlen) == 0) {
				// connect successful - we are done
            	close(sockfd);
				// ok - we need now an unconnected socket
        		sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
                break;
            }
			// unsuccessful connect :(
            close(sockfd);
            sockfd = -1;
        }
        res=res->ai_next;
    }

    if (sockfd < 0) {
        freeaddrinfo(ressave);
        fprintf(stderr, "Send socket error: could not open the requested socket: %s\n", strerror (errno));
        LogError("Send socket error: could not open the requested socket: %s", strerror (errno));
        return -1;
    }

	*addrlen = res->ai_addrlen;
	memcpy(addr, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(ressave);
  
	// Set socket write buffer. Need to be root!
	if ( wmem_size > 0 ) {
		if ( geteuid() == 0 ) {
			setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &wmem_size, sizeof(wmem_size));
	
			// check what was set (e.g. linux 2.4.20 sets twice of what was requested)
			getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &wmem_actual, &optlen);
	
			if (wmem_size != wmem_actual) {
				printf("Warning: Socket write buffer size requested: %u set: %u\n",
			 	wmem_size, wmem_actual);
			} 
		} else {
			printf("Warning: Socket buffer size can only be changed by root!\n");
		}
	}

    return sockfd;

} // End of Unicast_send_socket


int Multicast_receive_socket (const char *hostname, const char *listenport, int family, int sockbuflen ) {
struct addrinfo hints, *res, *ressave;
socklen_t   	optlen;
int p, error, sockfd;

	if ( !listenport ) {
        fprintf(stderr, "listen port required!\n");
        LogError("listen port required!");
		return -1;
	}

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family 	= family;
    hints.ai_socktype	= SOCK_DGRAM;

    error = getaddrinfo(hostname, listenport, &hints, &res);

    if ( error ) {
        fprintf(stderr, "getaddrinfo error:: [%s]\n", gai_strerror(error));
        LogError("getaddrinfo error:: [%s]", gai_strerror(error));
        return -1;
    }


    /* 
       Try open socket with each address getaddrinfo returned, 
       until we get a valid listening socket. 
    */

    sockfd	= -1;
    ressave = res;
    while (res) {
        sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if ( sockfd < 0 ) {
        	res=res->ai_next;
			continue;
		}

		// we found a valid socket and are done in this loop
		break;
	}

	if ( sockfd < 0 ) {
		// nothing found - bye bye
		fprintf(stderr, "Could not create a socket for [%s:%s]\n", hostname, listenport);
        LogError("Could not create a socket for [%s:%s]", hostname, listenport);
		freeaddrinfo(ressave);
		return -1;
	}


	if ( isMulticast((struct sockaddr_storage *)res->ai_addr) < 0 ) {
		fprintf(stderr, "Not a multicast address [%s]\n", hostname);
        LogError("Not a multicast address [%s]", hostname);
		freeaddrinfo(ressave);
		return -1;
	}

	close(sockfd);


	sockfd = socket(res->ai_family, SOCK_DGRAM, 0);
	if (bind(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
		fprintf(stderr, "bind: %s\n", strerror (errno));
        LogError("bind: %s", strerror (errno));
		close(sockfd);
		freeaddrinfo(ressave);
		return -1;
	}

	if (joinGroup(sockfd, 1 , 1, (struct sockaddr_storage *)res->ai_addr) <0) {
		close(sockfd);
		freeaddrinfo(ressave);
		return -1;
	}

	if ( res->ai_family == AF_INET ) 
   		LogInfo("Joined IPv4 multicast group: %s Port: %s", hostname, listenport);
	if ( res->ai_family == AF_INET6 ) 
   		LogInfo( "Joined IPv6 multicat group: %s Port: %s", hostname, listenport);


    freeaddrinfo(ressave);

	if ( sockbuflen ) {
		if ( sockbuflen < Min_SOCKBUFF_LEN ) {
			sockbuflen = Min_SOCKBUFF_LEN;
			LogInfo("I want at least %i bytes as socket buffer", sockbuflen);
		}
		optlen = sizeof(p);
		getsockopt(sockfd,SOL_SOCKET,SO_RCVBUF,&p,&optlen);
		LogInfo("Standard setsockopt, SO_RCVBUF is %i Requested length is %i bytes",p, sockbuflen);
		if ((setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &sockbuflen, sizeof(sockbuflen)) != 0) ) {
			fprintf (stderr, "setsockopt(SO_RCVBUF,%d): %s\n", sockbuflen, strerror (errno));
			LogError("setsockopt(SO_RCVBUF,%d): %s", sockbuflen, strerror (errno));
			close(sockfd);
			return -1;
		} else {
			getsockopt(sockfd,SOL_SOCKET,SO_RCVBUF,&p,&optlen);
			LogInfo("System set setsockopt, SO_RCVBUF to %d bytes", p);
		}
	} 

    return sockfd;

} /* End of Multicast_receive_socket */

int Multicast_send_socket (const char *hostname, const char *listenport, int family, 
		unsigned int wmem_size, struct sockaddr_storage *addr, int *addrlen) {
struct addrinfo hints, *res, *ressave;
int error, sockfd;

	if ( !listenport || !hostname ) {
        fprintf(stderr, "hostname and listen port required!\n");
        LogError("hostname and listen port required!");
		return -1;
	}

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family 	= family;
    hints.ai_socktype 	= SOCK_DGRAM;

    error = getaddrinfo(hostname, listenport, &hints, &res);

    if ( error ) {
        fprintf(stderr, "getaddrinfo error:: [%s]\n", gai_strerror(error));
        LogError("getaddrinfo error:: [%s]", gai_strerror(error));
        return -1;
    }


    /* 
       Try open socket with each address getaddrinfo returned, 
       until we get a valid listening socket. 
    */

    sockfd=-1;
    ressave = res;
    while (res) {
        sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if ( sockfd < 0 ) {
        	res=res->ai_next;
			continue;
		}

		// we found a valid socket and are done in this loop
		break;
	}

	if ( sockfd < 0 ) {
		// nothing found - bye bye
		fprintf(stderr, "Could not create a socket for [%s:%s]\n", hostname, listenport);
        LogError("Could not create a socket for [%s:%s]", hostname, listenport);
		freeaddrinfo(ressave);
		return -1;
	}

	if ( isMulticast((struct sockaddr_storage *)res->ai_addr) < 0 ) {
		fprintf(stderr, "Not a multicast address [%s]\n", hostname);
        LogError("Not a multicast address [%s]", hostname);
		freeaddrinfo(ressave);
		return -1;
	}

	close(sockfd);
	sockfd = socket(res->ai_family, SOCK_DGRAM, 0);

	*addrlen = res->ai_addrlen;
	memcpy(addr, res->ai_addr, res->ai_addrlen);

/*
     ((struct sockaddr_in *)addr)->sin_family=AF_INET;
     addr.sin_addr.s_addr=inet_addr(HELLO_GROUP);
     addr.sin_port=htons(HELLO_PORT);
*/

	if (joinGroup(sockfd, 1 , 1, (struct sockaddr_storage *)res->ai_addr) <0) {
		close(sockfd);
		freeaddrinfo(ressave);
		return -1;
	}

    freeaddrinfo(ressave);

/*
	message = "hello world\n";
     printf("Send %lu bytes, Message: %s\n", strlen(message)+1, message);
     while (1) {
      ret = sendto(sockfd,message,strlen(message)+1,0,(struct sockaddr *) addr, *addrlen);
      if ( ret != strlen(message)+1 ) {
           perror("sendto");
           exit(1);
      }
		printf("sleep\n");
      sleep(1);
     }
exit(255);
*/
    return sockfd;

} /* End of Multicast_send_socket */

static int joinGroup(int sockfd, int loopBack, int mcastTTL, struct sockaddr_storage *addr) {
int ret, err;

	ret=-1;

	switch (addr->ss_family) {
		case AF_INET: {
			struct ip_mreq	  mreq;

			mreq.imr_multiaddr.s_addr = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
			mreq.imr_interface.s_addr = INADDR_ANY;

			err = setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const void *)&mreq, sizeof(mreq));
			if ( err ) {
				fprintf(stderr, "setsockopt IP_ADD_MEMBERSHIP: %s\n", strerror (errno));
        		LogError("setsockopt IP_ADD_MEMBERSHIP: %s", strerror (errno));
				break;
			}
			ret = 0;
/*
			// These two setsockopt may fail because not implemented on every OS, but harmless
			err = setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_LOOP, &loopBack, sizeof(loopBack));
			if ( err ) {
				fprintf(stderr, "setsockopt IP_MULTICAST_LOOP: %s\n", strerror (errno));
        		LogError("setsockopt IP_MULTICAST_LOOP: %s", strerror (errno));
			}

			err = setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &mcastTTL, sizeof(mcastTTL));
			if ( err ) {
				fprintf(stderr, "setsockopt IP_MULTICAST_LOOP: %s\n", strerror (errno));
        		LogError("setsockopt IP_MULTICAST_LOOP: %s", strerror (errno));
			}
*/
		} break;

		case AF_INET6: {
			struct ipv6_mreq	mreq6;

			memcpy(&mreq6.ipv6mr_multiaddr, &(((struct sockaddr_in6 *)addr)->sin6_addr), sizeof(struct in6_addr));
			mreq6.ipv6mr_interface= 0;

			err = setsockopt(sockfd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6, sizeof(mreq6));
			if ( err ) {
				fprintf(stderr, "setsockopt IPV6_JOIN_GROUP: %s\n", strerror (errno));
        		LogError("setsockopt IPV6_JOIN_GROUP: %s", strerror (errno));
				break;
			}
			ret = 0;
/*
			// These two setsockopt may fail because not implemented on every OS, but harmless
			err = setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loopBack, sizeof(loopBack));
			if ( err ) {
				fprintf(stderr, "setsockopt IPV6_MULTICAST_LOOP: %s\n", strerror (errno));
        		LogError("setsockopt IPV6_MULTICAST_LOOP: %s", strerror (errno));
			}

			err = setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &mcastTTL, sizeof(mcastTTL));
			if ( err ) {
				fprintf(stderr, "setsockopt IPV6_MULTICAST_HOPS: %s\n", strerror (errno));
        		LogError("setsockopt IPV6_MULTICAST_HOPS: %s", strerror (errno));
			}
*/
		} break;

		default:
			;
	}

	return ret;
} /* joinGroup */


static int isMulticast(struct sockaddr_storage *addr) {
int ret;

	ret = -1;
	switch (addr->ss_family) {
		case AF_INET: {
				struct sockaddr_in *addr4=(struct sockaddr_in *)addr;
				ret = IN_MULTICAST(ntohl(addr4->sin_addr.s_addr));
			} 
			break;

		case AF_INET6: {
				struct sockaddr_in6 *addr6=(struct sockaddr_in6 *)addr;
				ret = IN6_IS_ADDR_MULTICAST(&addr6->sin6_addr);
			}
			break;
		default:
		   ;
	}

	return ret;
} /* End of isMulticast */


