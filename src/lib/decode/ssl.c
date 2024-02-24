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

#include "ssl.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "stream.h"
#include "util.h"

// array handling

static int sslParseExtensions(ssl_t *ssl, BytesStream_t sslStream, uint16_t length);

static int sslParseClientHandshake(ssl_t *ssl, BytesStream_t sslStream, uint32_t messageLength);

static int sslParseServerHandshake(ssl_t *ssl, BytesStream_t sslStream, uint32_t messageLength);

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

}  // End of checkGrease

#define CheckSize(s, n)                                          \
    {                                                            \
        if ((n) > (s)) {                                         \
            return 0;                                            \
        }                                                        \
        dbg_printf("Size left: %zu, check for: %u\n", (s), (n)); \
        (s) -= (n);                                              \
    }

#define CheckStringSize(s, l)                                                   \
    {                                                                           \
        if ((s) < (l)) {                                                        \
            LogError("sLen error in %s line %d: %s\n", __FILE__, __LINE__, ""); \
            abort();                                                            \
            return NULL;                                                        \
        } else {                                                                \
            (s) -= (l);                                                         \
        }                                                                       \
    }

static int sslParseExtensions(ssl_t *ssl, BytesStream_t sslStream, uint16_t length) {
    if (length == 0) {
        LogError("%s() extension length is 0", __FUNCTION__);
        return 0;
    }

    int extensionLength = length;
    NewArray(ssl->extensions);
    NewArray(ssl->ellipticCurves);
    NewArray(ssl->ellipticCurvesPF);
    while (extensionLength >= 4) {
        uint16_t exType, exLength;
        ByteStream_GET_u16(sslStream, exType);
        ByteStream_GET_u16(sslStream, exLength);

        if (checkGREASE(exType)) {
            extensionLength -= (4 + exLength);
            continue;
        }

        if (exLength > ByteStream_AVAILABLE(sslStream)) {
            LogError("%s():%d extension length error", __FUNCTION__, __LINE__);
            return 0;
        }

        dbg_printf("Found extension type: %u, len: %u\n", exType, exLength);
        AppendArray(ssl->extensions, exType);

        switch (exType) {
            case 0: {  // sni name
                uint16_t sniLen;
                ByteStream_GET_u16(sslStream, sniLen);

                if (sniLen > ByteStream_AVAILABLE(sslStream) || sniLen > 255) {
                    LogError("%s():%d sni extension length error", __FUNCTION__, __LINE__);
                    return 0;
                }

                ByteStream_GET_X(sslStream, ssl->sniName, sniLen);
                ssl->sniName[sniLen] = '\0';
                dbg_printf("Found sni name: %s\n", ssl->sniName);
            } break;
            case 10: {  // Elliptic curves
                uint16_t ecsLen;
                ByteStream_GET_u16(sslStream, ecsLen);

                if (ecsLen > ByteStream_AVAILABLE(sslStream)) {
                    LogError("%s():%d ecs extension length error", __FUNCTION__, __LINE__);
                    return 0;
                }

                for (int i = 0; i < (ecsLen >> 1); i++) {
                    uint16_t curve;
                    ByteStream_GET_u16(sslStream, curve);
                    AppendArray(ssl->ellipticCurves, curve);
                    dbg_printf("Found curve: 0x%x\n", curve);
                }
            } break;
            case 11: {  // Elliptic curve point formats uncompressed
                uint8_t ecspLen;
                ByteStream_GET_u8(sslStream, ecspLen);

                if (ecspLen > ByteStream_AVAILABLE(sslStream)) {
                    LogError("%s():%d ecsp extension length error", __FUNCTION__, __LINE__);
                    return 0;
                }

                for (int i = 0; i < ecspLen; i++) {
                    uint8_t curvePF;
                    ByteStream_GET_u8(sslStream, curvePF);
                    AppendArray(ssl->ellipticCurvesPF, curvePF);
                    dbg_printf("Found curvePF: 0x%x\n", curvePF);
                }
            } break;
        }
        extensionLength -= (4 + exLength);
    }
    dbg_printf("End extension. size: %zu\n", size_left);

    return 1;

}  // End of sslParseExtensions

static int sslParseClientHandshake(ssl_t *ssl, BytesStream_t sslStream, uint32_t messageLength) {
    // version(2) random(32) sessionIDLen(1) = 35 bytes
    if (ByteStream_AVAILABLE(sslStream) < 35) return 0;

    uint16_t version;
    ByteStream_GET_u16(sslStream, version);  // client hello protocol version
    ByteStream_SKIP(sslStream, 32);          // random init bytes

    ssl->protocolVersion = version;
    switch (version) {
        case 0x3000:
        case 0x3001:
        case 0x3002:
        case 0x3003:
            break;
        default:
            LogError("%s(): Not an SSL 3.0 - TLS 1.3 protocol", __FUNCTION__);
            dbg_printf("Client handshake: Not an SSL 3.0 - TLS 1.3 protocol\n");
            return 0;
    }

    uint8_t sessionIDLen;
    ByteStream_GET_u8(sslStream, sessionIDLen);  // session ID length (followed by session ID if non-zero)

    // sessionIDLen + cipherSuiteHeaderLen(2)
    if (ByteStream_AVAILABLE(sslStream) < (sessionIDLen + 2)) return 0;
    if (sessionIDLen) ByteStream_SKIP(sslStream, sessionIDLen);

    uint16_t cipherSuiteHeaderLen;
    ByteStream_GET_u8(sslStream, cipherSuiteHeaderLen);  // Cipher suites length

    // cipherSuiteHeaderLen + compressionMethodes(1)
    if (ByteStream_AVAILABLE(sslStream) < (cipherSuiteHeaderLen + 1)) return 0;

    int numCiphers = cipherSuiteHeaderLen >> 1;
    if (numCiphers == 0) {
        LogError("%s(): Number of ciphers is 0", __FUNCTION__);
        return 0;
    }

    NewArray(ssl->cipherSuites);
    for (int i = 0; i < numCiphers; i++) {
        uint16_t cipher;
        ByteStream_GET_u16(sslStream, cipher);  // get next cipher

        if (checkGREASE(cipher) == 0) {
            AppendArray(ssl->cipherSuites, cipher);
        }
    }

    uint8_t compressionMethodes;
    ByteStream_GET_u8(sslStream, compressionMethodes);  // number of compression methods to follow

    // compressionMethodes extensionLength(2)
    if (ByteStream_AVAILABLE(sslStream) < (compressionMethodes + 2)) return 0;

    uint16_t extensionLength;
    ByteStream_GET_u16(sslStream, extensionLength);  // length of extensions

    if (ByteStream_AVAILABLE(sslStream) < (extensionLength)) return 0;

    return sslParseExtensions(ssl, sslStream, extensionLength);

}  // End of sslParseClientHandshake

static int sslParseServerHandshake(ssl_t *ssl, BytesStream_t sslStream, uint32_t messageLength) {
    // version(2) random(32) sessionIDLen(1) = 35 bytes
    if (ByteStream_AVAILABLE(sslStream) < 35) return 0;

    uint16_t version;
    ByteStream_GET_u16(sslStream, version);  // client hello protocol version
    ByteStream_SKIP(sslStream, 32);          // random init bytes

    ssl->protocolVersion = version;
    switch (version) {
        case 0x3000:
        case 0x3001:
        case 0x3002:
        case 0x3003:
            break;
        default:
            LogError("%s():%d Not an SSL 3.0 - TLS 1.3 protocol", __FUNCTION__, __LINE__);
            dbg_printf("Client handshake: Not an SSL 3.0 - TLS 1.3 protocol\n");
            return 0;
    }

    uint8_t sessionIDLen;
    ByteStream_GET_u8(sslStream, sessionIDLen);  // session ID length (followed by session ID if non-zero)

    // sessionIDLen + cipherSuite (2) + compression(1) + extensionLength(2)
    if (ByteStream_AVAILABLE(sslStream) < (sessionIDLen + 5)) return 0;
    if (sessionIDLen) ByteStream_SKIP(sslStream, sessionIDLen);

    uint16_t cipherSuite;
    ByteStream_GET_u16(sslStream, cipherSuite);  // Cipher suite

    NewArray(ssl->cipherSuites);
    AppendArray(ssl->cipherSuites, cipherSuite);

    // skip compression
    ByteStream_SKIP(sslStream, 1);

    uint16_t extensionLength;
    ByteStream_GET_u16(sslStream, extensionLength);  // extension length

    if (ByteStream_AVAILABLE(sslStream) < extensionLength) return 0;

    NewArray(ssl->extensions);

    int sizeLeft = extensionLength;
    while (sizeLeft >= 4) {
        uint16_t exType, exLength;
        ByteStream_GET_u16(sslStream, exType);
        ByteStream_GET_u16(sslStream, exLength);

        if (checkGREASE(exType)) {
            extensionLength -= (4 + exLength);
            continue;
        }

        dbg_printf("Found extension type: %u, len: %u\n", exType, exLength);
        AppendArray(ssl->extensions, exType);
    }
    dbg_printf("End extension. size: %d\n", sizeLeft);

    return 1;

}  // End of sslParseServerHandshake

void sslPrint(ssl_t *ssl) {
    if (ssl->type == CLIENTssl)
        printf("ssl client record for %s:\n", ssl->sniName);
    else
        printf("ssl server record\n");

    printf("TLS      : %u\n", ssl->tlsVersion);
    printf("Protocol : %u\n", ssl->protocolVersion);
    printf("ciphers  : ");
    for (int i = 0; i < LenArray(ssl->cipherSuites); i++) {
        printf(" %u", ssl->cipherSuites.array[i]);
    }
    printf("\nextensions:");
    for (int i = 0; i < LenArray(ssl->extensions); i++) {
        printf(" %u", ssl->extensions.array[i]);
    }
    printf("\n");

    if (ssl->type == CLIENTssl) {
        printf("curves    :");
        for (int i = 0; i < LenArray(ssl->ellipticCurves); i++) {
            printf(" %u", ssl->ellipticCurves.array[i]);
        }
        printf("\ncurves PF :");
        for (int i = 0; i < LenArray(ssl->ellipticCurvesPF); i++) {
            printf(" %u", ssl->ellipticCurvesPF.array[i]);
        }
        printf("\n");
    }

}  // End of sslPrint

void sslFree(ssl_t *ssl) {
    FreeArray(ssl->cipherSuites);
    FreeArray(ssl->extensions);
    FreeArray(ssl->ellipticCurves);
    FreeArray(ssl->ellipticCurvesPF);

    free(ssl);

}  // End of sslFree

ssl_t *sslProcess(uint8_t *data, size_t len) {
    dbg_printf("\nsslProcess new packet. size: %zu\n", len);
    // Check for
    // - ssl header length (5)
    // - message type/length (4)
    // - and handshake content type (22)
    if (len < 9 || data[0] != 22) {
        dbg_printf("Not an ssl handshake packet\n");
        return NULL;
    }

    ByteStream_INIT(sslStream, data, len);
    ByteStream_SKIP(sslStream, 1);  // 0x22 data[0]

    uint16_t sslVersion;
    ByteStream_GET_u16(sslStream, sslVersion);
    switch (sslVersion) {
        case 0x3000:
        case 0x3001:
        case 0x3002:
        case 0x3003:
            break;
        default:
            dbg_printf("Not an SSL 3.0 - TLS 1.3 connection\n");
            return NULL;
    }

    uint16_t contentLength;
    ByteStream_GET_u16(sslStream, contentLength);

    if (contentLength > ByteStream_AVAILABLE(sslStream)) {
        dbg_printf("Short ssl packet -  have: %zu, need contentLength: %u\n", len, contentLength);
        return NULL;
    }

    uint8_t messageType;
    uint32_t messageLength;
    ByteStream_GET_u8(sslStream, messageType);
    ByteStream_GET_u24(sslStream, messageLength);

    dbg_printf("Message type: %u, length: %u\n", messageType, messageLength);
    if (messageLength > ByteStream_AVAILABLE(sslStream)) {
        dbg_printf("Message length error: %u > %zu\n", messageLength, len);
        return NULL;
    }

    ssl_t *ssl = calloc(1, sizeof(ssl_t));
    if (!ssl) {
        LogError("calloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }
    ssl->tlsVersion = sslVersion;

    int ok = 0;
    switch (messageType) {
        case 1:  // ClientHello
            ssl->type = CLIENTssl;
            ok = sslParseClientHandshake(ssl, sslStream, messageLength);
            break;
        case 2:  // ServerHello
            ssl->type = SERVERssls;
            ok = sslParseServerHandshake(ssl, sslStream, messageLength);
            break;
        default:
            dbg_printf("ssl process: Message type not ClientHello or ServerHello: %u\n", messageType);
            sslFree(ssl);
            return NULL;
    }

    if (!ok) {
        sslFree(ssl);
        return NULL;
    }

    dbg_printf("ssl process message: %u, Length: %u\n", messageType, messageLength);
    // sslPrint(ssl);

    return ssl;

}  // End of sslProcess
