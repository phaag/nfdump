/*
 *  Copyright (c) 2021, Peter Haag
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

#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include "util.h"
#include "ja3.h"
#include "md5.h"

// array handling 

#define arrayMask 0x1F

#define NewArray(a) {a.numElements=0; a.array=NULL;}

#define AppendArray(a, v) if ((a.numElements & arrayMask) == 0 ) { \
	a.array = realloc(a.array, sizeof(uint16_t) * (a.numElements + (arrayMask+1))); \
		if ( !a.array ) { \
			fprintf(stderr, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno)); \
			exit(255); \
		} \
	} \
	a.array[a.numElements++] = (v);

#define FreeArray(a) if (a.numElements && a.array) { \
	free(a.array); \
	a.numElements = 0; \
	a.array = NULL; \
}

#define LenArray(a) a.numElements

static int ja3ParseExtensions(ja3_t *ja3, uint8_t *data, size_t len);

static int ja3ParseClientHandshake(ja3_t *ja3, uint8_t *data, size_t len);

static char *ja3Hash(ja3_t *ja3);

static int checkGREASE(uint16_t val);

/*
 * grease_table = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
 *              0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
 *              0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
 *              0xcaca, 0xdada, 0xeaea, 0xfafa};
 */
static int checkGREASE(uint16_t val) {

	if ((val & 0x0f0f) != 0x0a0a) {
		return 0;
	} else {
		uint8_t *p = (uint8_t *)&val;
		return p[0] == p[1] ? 1 : 0;
	}
	// not reached

} // End of checkGrease

#define CheckSize(s, n) { if ((n)>(s)) { \
	return 0;}\
	dbg_printf("Size left: %zu, check for: %u\n", (s), (n));\
	(s) -= (n);\
}

#define CheckStringSize(s, l) { if ((s) < (l)) { \
	LogError("sLen error in %s line %d: %s\n", __FILE__, __LINE__, ""); \
abort(); \
	return NULL; \
	} else { \
		(s) -= (l); \
	} \
}

char *ja3Hash(ja3_t *ja3) {

	size_t sLen = 6 * (1+1 + LenArray(ja3->cipherSuites)+1 + LenArray(ja3->extensions)+1
						 + LenArray(ja3->ellipticCurves)+1 + LenArray(ja3->ellipticCurvesPF)+1) +1; // +1 '\0'

	ja3->ja3String = calloc(1, sLen);
	if ( !ja3->ja3String ) {
		LogError("calloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
		return NULL;
	}
	char *s = ja3->ja3String;
	snprintf(s, sLen, "%u,", ja3->version);
	size_t len = strlen(s);
	s += len;
	sLen = sLen - 1 - len;
	for (int i=0; i<LenArray(ja3->cipherSuites); i++ ) {
		len = snprintf(s, sLen, "%u-", ja3->cipherSuites.array[i]);
		s += len;
		CheckStringSize(sLen, len);
	}
	if (LenArray(ja3->cipherSuites)) --s;
	*s++ = ',';

	for (int i=0; i<LenArray(ja3->extensions); i++ ) {
		len = snprintf(s, sLen, "%u-", ja3->extensions.array[i]);
		s += len;
		CheckStringSize(sLen, len);
	}
	if (LenArray(ja3->extensions)) --s;

	// SERVERja3s stops here
	if ( ja3->type == CLIENTja3 ) {
		// CLIENTja3
		*s++ = ',';

		for (int i=0; i<LenArray(ja3->ellipticCurves); i++ ) {
			len = snprintf(s, sLen, "%u-", ja3->ellipticCurves.array[i]);
			s += len;
			CheckStringSize(sLen, len);
		}
		if (LenArray(ja3->ellipticCurves)) --s;
		*s++ = ',';

		for (int i=0; i<LenArray(ja3->ellipticCurvesPF); i++ ) {
			len = snprintf(s, sLen, "%u-", ja3->ellipticCurvesPF.array[i]);
			s += len;
			CheckStringSize(sLen, len);
		}
		if (LenArray(ja3->ellipticCurvesPF)) --s;
	}

	if ( sLen == 0 ) {
		LogError("sLen error in %s line %d: %s\n", __FILE__, __LINE__, "Size == 0");
		return NULL;
	}

	*s++ = '\0';
	md5_hash((uint8_t *)ja3->ja3String, strlen(ja3->ja3String), ja3->md5Hash);

	return ja3->ja3String;

} // End of ja3Hash
	
static int ja3ParseExtensions(ja3_t *ja3, uint8_t *data, size_t len) {

	if ( len == 0 ) {
		LogError("%s handshake error: extension length: 0", __FUNCTION__);
		return 0;
	}
	size_t size_left = len;
	int index = 0;
	
	NewArray(ja3->extensions);
	NewArray(ja3->ellipticCurves);
	NewArray(ja3->ellipticCurvesPF);
	while (size_left >=4 ) {
		uint16_t exType = data[index]<<8 | data[index+1];
		index += 2;
		uint16_t exLen  = data[index]<<8 | data[index+1];
		CheckSize(size_left, exLen+4);
		index += 2;

		if ( checkGREASE(exType) == 0 ) {
			dbg_printf("Found extension type: %u, len: %u\n", exType, exLen);
			AppendArray(ja3->extensions, exType);
		}

		switch (exType) {
			case 0: { // server_name
				// skip sniListLength = data[index]<<8 | data[index+1];
				index += 2;
				// skip type = data[index];
				index++;
				uint16_t sniLen = data[index]<<8 | data[index+1];
				index += 2;
				if ((sniLen + 5) > exLen || sniLen > 255 ) {
					LogError("%s handshake extension length error", __FUNCTION__);
					return 0;
				}
				memcpy(ja3->sniName, data+index, sniLen);
				index += sniLen;
				ja3->sniName[sniLen] = '\0';
				dbg_printf("Found sni name: %s\n", ja3->sniName);
				} break;
			case 10: { // supported_groups
				uint16_t ecsLen = data[index]<<8 | data[index+1];
				if ((ecsLen+2) > exLen) {
					LogError("%s handshake error: ecsLen: %u, exLen: %u", __FUNCTION__, ecsLen, exLen);
					return 0;
				}
				index += 2;
				for (int i=0; i<(ecsLen>>1); i++) {
					uint16_t curve = data[index]<<8 | data[index+1];
					index += 2;
					AppendArray(ja3->ellipticCurves, curve);
					dbg_printf("Found curve: 0x%x\n", curve);
				}
				} break;
			case 11: { // ec_point_formats groups
				uint8_t ecspLen = data[index];
				if ((ecspLen+1) > exLen) {
					LogError("%s handshake error: ecspLen: %u, exLen: %u", __FUNCTION__, ecspLen, exLen);
					return 0;
				}
				index++;
				for (int i=0; i<ecspLen; i++) {
					uint8_t curvePF = data[index];
					index++;
					AppendArray(ja3->ellipticCurvesPF, curvePF);
					dbg_printf("Found curvePF: 0x%x\n", curvePF);
				}
				} break;
			default:
				index += exLen;
		}
	}
	dbg_printf("End extension. size: %zu\n", size_left);

	return 1;

} // End of ja3ParseExtensions

static int ja3ParseClientHandshake(ja3_t *ja3, uint8_t *data, size_t len) {

	// version(2) random(32) sessionIDLen(1)
	size_t size_left = len;
	int index = 0;
	CheckSize(size_left, 35);

	uint16_t version = data[index]<<8 | data[index+1];
	ja3->version = version;

	if ( data[index] != 3 || data[index+1] > 4 ) {
		LogError("%s handshake error: version 0x%xnot supported", __FUNCTION__, version);
		return 0;
	}
	index += 34;
	uint8_t sessionIDLen = data[index++];
	if ( sessionIDLen > 32 ) {
		LogError("%s handshake error: sessionIDLen %u > 32", __FUNCTION__, sessionIDLen);
		return 0;
	}

	// sessionIDLen + cipherSuiteHeaderLen(2)
	CheckSize(size_left, sessionIDLen+2);
	index += sessionIDLen;
	uint16_t cipherSuiteHeaderLen = data[index]<<8 | data[index+1];
	index += 2;

	// cipherSuiteHeaderLen + compressionMethodes(1)
	CheckSize(size_left, cipherSuiteHeaderLen+1);
	int numCiphers = cipherSuiteHeaderLen >> 1;
	if ( numCiphers == 0 ) {
		LogError("%s handshake error: Number of Ciphers: 0", __FUNCTION__);
		return 0;
	}

	NewArray(ja3->cipherSuites);
	uint8_t *p = (uint8_t *)(data + index);
	for (int i = 0; i < numCiphers; i++) {
		uint16_t cipher = p[i<<1]<<8 | p[(i<<1)+1];
		if ( checkGREASE(cipher) == 0 ) {
			AppendArray(ja3->cipherSuites, cipher);
		}
		index += 2;
	}

	uint8_t compressionMethodes = data[index++];

	// skip compression methodes
	index += compressionMethodes;

	// compressionMethodes extensionLength(2)
	CheckSize(size_left, compressionMethodes+2);

	uint16_t extensionLength = data[index]<<8 | data[index+1];
	index += 2;
	CheckSize(size_left, extensionLength);

	return ja3ParseExtensions(ja3, data+index, extensionLength);

} // End of ja3ParseClientHandshake

static int ja3ParseServerHandshake(ja3_t *ja3, uint8_t *data, size_t len) {

	// version(2) random(32) sessionIDLen(1)
	size_t size_left = len;
	int index = 0;
	CheckSize(size_left, 35);

	uint16_t version = data[index]<<8 | data[index+1];
	ja3->version = version;

	if ( data[index] != 3 || data[index+1] > 4 ) {
		LogError("%s handshake error: version 0x%xnot supported", __FUNCTION__, version);
		return 0;
	}
	index += 34;
	uint8_t sessionIDLen = data[index++];
	if ( sessionIDLen > 32 ) {
		LogError("%s handshake error: sessionIDLen %u > 32", __FUNCTION__, sessionIDLen);
		return 0;
	}

	// sessionIDLen + cipherSuite (2) + compression(1) + extensionLength(2)
	CheckSize(size_left, sessionIDLen+5);
	index += sessionIDLen;
	uint16_t cipherSuite = data[index]<<8 | data[index+1];
	index += 2;

	NewArray(ja3->cipherSuites);
	AppendArray(ja3->cipherSuites, cipherSuite);

	// skip compression = data[index];
	index++;

	uint16_t extensionLength = data[index]<<8 | data[index+1];
	index += 2;
	CheckSize(size_left, extensionLength);

	size_left = extensionLength;
	NewArray(ja3->extensions);
	while (size_left >=4 ) {
		uint16_t exType = data[index]<<8 | data[index+1];
		index += 2;
		uint16_t exLen  = data[index]<<8 | data[index+1];
		CheckSize(size_left, exLen+4);
		index += 2;

		if ( checkGREASE(exType) == 0 ) {
			dbg_printf("Found extension type: %u, len: %u\n", exType, exLen);
			AppendArray(ja3->extensions, exType);
		}
		index += exLen;
	}
	dbg_printf("End extension. size: %zu\n", size_left);

	return 1;

} // End of ja3ParseServerHandshake

void ja3Print(ja3_t *ja3) {

	if ( ja3->type == CLIENTja3 ) 
		printf("ja3 client record for %s:\n", ja3->sniName);
	else
		printf("ja3 server record\n");

	printf("version   : %u\n", ja3->version);
	printf("ciphers   :");
	for (int i=0; i<LenArray(ja3->cipherSuites); i++ ) {
		printf(" %u", ja3->cipherSuites.array[i]);
	}
	printf("\nextensions:");
	for (int i=0; i<LenArray(ja3->extensions); i++ ) {
		printf(" %u", ja3->extensions.array[i]);
	}
	printf("\n");

	if ( ja3->type == CLIENTja3 ) {
		printf("curves    :");
		for (int i=0; i<LenArray(ja3->ellipticCurves); i++ ) {
			printf(" %u", ja3->ellipticCurves.array[i]);
		}
		printf("\ncurves PF :");
		for (int i=0; i<LenArray(ja3->ellipticCurvesPF); i++ ) {
			printf(" %u", ja3->ellipticCurvesPF.array[i]);
		}
		printf("\n");
	}

	if ( ja3->ja3String ) 
		printf("string    : %s\n", ja3->ja3String);

	uint8_t *u8 = (uint8_t *)ja3->md5Hash;
	char out[33];

	int i,j;
    for (i=0, j=0; i<16; i++, j+=2 ) {
        uint8_t ln = u8[i] & 0xF;
        uint8_t hn = (u8[i] >> 4)  & 0xF;
        out[j+1] = ln <= 9 ? ln + '0' : ln + 'a' - 10;
        out[j]   = hn <= 9 ? hn + '0' : hn + 'a' - 10;
    }
	out[32] = '\0';

	if ( ja3->type == CLIENTja3 ) 
		printf("ja3 hash  : %s\n\n", out);
	else
		printf("ja3s hash : %s\n\n", out);

} // End of ja3Print

void ja3Free(ja3_t *ja3) {

	FreeArray(ja3->cipherSuites);
	FreeArray(ja3->extensions);
	FreeArray(ja3->ellipticCurves);
	FreeArray(ja3->ellipticCurvesPF);

	if ( ja3->ja3String ) 
		free(ja3->ja3String);

	free(ja3);

} // End of ja3Free

ja3_t *ja3Process(uint8_t *data, size_t len) {

	dbg_printf("\nja3Process new packet. size: %zu\n", len); 
	// Check for
	// - ssl header length (5)
	// - message type/length (4)
	// - and handshake content type (22)
	if (len < 9 || data[0] != 22) {
		dbg_printf("Not an ssl handshake packet\n");
		return NULL;
	}

	// skip tlsVersion = data[1]<<8 | data[2];
	if ( data[1] != 3 && data[2] >4 ) {  // major version and SSL 3.0 - TLS1.3
		dbg_printf("Not an SSL 3.0 - TLS 1.3 \n");
		return NULL;
	}

	uint16_t sslLength = data[3]<<8 | data[4];
	if ( (sslLength + 5) > len ) {
		dbg_printf("Short ssl packet -  size: %zu, sslLength: %u\n", len, sslLength);
		return NULL;
	}

	uint8_t  messageType = data[5];
	uint32_t messageLength = data[6]<< 16 | data[7]<< 8 | data[8];

	dbg_printf("Message type: %u, length: %u\n", messageType, messageLength);
	len -= 9;
	if (messageLength > len) {
		dbg_printf("Message length error: %u > %zu\n", messageLength, len);
		return NULL;
	}

	ja3_t *ja3 = calloc(1, sizeof(ja3_t));
	if ( !ja3 ) {
		LogError("calloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
		return NULL;
	}

	int ok = 0;
	switch (messageType) {
		case 1: // ClientHello
			ja3->type = CLIENTja3;
			ok = ja3ParseClientHandshake(ja3, data+9, messageLength);
			if ( ok ) ja3Hash(ja3);
			break;
		case 2: // ServerHello
			ja3->type = SERVERja3s;
			ok = ja3ParseServerHandshake(ja3, data+9, messageLength);
			if ( ok ) ja3Hash(ja3);
			break;
		default:
			dbg_printf("ja3 process: Message type not ClientHello or ServerHello: %u\n", messageType);
			ja3Free(ja3);
			return NULL;
	}

	if ( !ok ) {
		ja3Free(ja3);
		return NULL;
	}

	dbg_printf("ja3 process message: %u, Length: %u\n", messageType, messageLength);
	// ja3Print(ja3);

	return ja3;

} // End of ja3Process


