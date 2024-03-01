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

static int sslParseExtensions(ssl_t *ssl, BytesStream_t sslStream, uint16_t length) {
    dbg_printf("Parse extensions: %x\n", length);
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
        dbg_printf("Ex Type: %x, Length: %x\n", exType, exLength);
        if (checkGREASE(exType)) {
            extensionLength -= (4 + exLength);
            continue;
        }

        if (exLength > ByteStream_AVAILABLE(sslStream)) {
            LogError("%s():%d extension length error", __FUNCTION__, __LINE__);
            return 0;
        }

        AppendArray(ssl->extensions, exType);

        switch (exType) {
            case 0: {  // sni name
                uint16_t sniListLength;
                ByteStream_GET_u16(sslStream, sniListLength);

                // skip server name type 1
                ByteStream_SKIP(sslStream, 1);

                uint16_t sniLen;
                ByteStream_GET_u16(sslStream, sniLen);

                if (sniLen > ByteStream_AVAILABLE(sslStream) || sniLen > 255) {
                    LogError("%s():%d sni extension length error", __FUNCTION__, __LINE__);
                    return 0;
                }

                ByteStream_GET_X(sslStream, ssl->sniName, sniLen);
                ssl->sniName[sniLen] = '\0';
                dbg_printf("Found sni name: %s\n", ssl->sniName);

                if ((sniLen + 3) < sniListLength) {
                    // should not happen as only one host_type suported
                    size_t skipBytes = sniListLength - sniLen - 3;
                    ByteStream_SKIP(sslStream, skipBytes);
                }
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
            default:
                if (exLength) ByteStream_SKIP(sslStream, exLength);
        }
        extensionLength -= (4 + exLength);
    }
    dbg_printf("End extension. size: %d\n", extensionLength);

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
        case 0x0200:  // SSL 2.0
        case 0x0300:  // SSL 3.0
        case 0x0301:  // TLS 1.1
        case 0x0302:  // TLS 1.2
        case 0x0303:  // TLS 1.3
            break;
        default:
            LogError("%s():%d Not an SSL 3.0 - TLS 1.3 protocol", __FUNCTION__, __LINE__);
            dbg_printf("Client handshake: Not an SSL 3.0 - TLS 1.3 protocol\n");
            return 0;
    }

    uint8_t sessionIDLen;
    ByteStream_GET_u8(sslStream, sessionIDLen);  // session ID length (followed by session ID if non-zero)

    // sessionIDLen + cipherSuiteHeaderLen(2)
    if (ByteStream_AVAILABLE(sslStream) < (sessionIDLen + 2)) return 0;
    if (sessionIDLen) ByteStream_SKIP(sslStream, sessionIDLen);

    uint16_t cipherSuiteHeaderLen;
    ByteStream_GET_u16(sslStream, cipherSuiteHeaderLen);  // Cipher suites length

    // cipherSuiteHeaderLen + compressionMethodes(1)
    if (ByteStream_AVAILABLE(sslStream) < (cipherSuiteHeaderLen + 1)) return 0;

    int numCiphers = cipherSuiteHeaderLen >> 1;
    if (numCiphers == 0) {
        LogError("%s():%d Number of ciphers is 0", __FUNCTION__, __LINE__);
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
    if (compressionMethodes) ByteStream_SKIP(sslStream, compressionMethodes);

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
        case 0x0200:  // SSL 2.0
        case 0x0300:  // SSL 3.0
        case 0x0301:  // TLS 1.1
        case 0x0302:  // TLS 1.2
        case 0x0303:  // TLS 1.3
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

        sizeLeft -= (4 + exLength);
        if (checkGREASE(exType)) {
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

    printf("TLS        : 0x%x\n", ssl->tlsVersion);
    printf("Protocol   : 0x%x\n", ssl->protocolVersion);
    printf("ciphers    : ");
    for (int i = 0; i < LenArray(ssl->cipherSuites); i++) {
        printf("0x%x ", ssl->cipherSuites.array[i]);
    }
    printf("\nextensions :");
    for (int i = 0; i < LenArray(ssl->extensions); i++) {
        printf(" 0x%x", ssl->extensions.array[i]);
    }
    printf("\n");

    if (ssl->sniName[0]) {
        printf("SNI name   : %s\n", ssl->sniName);
    }

    if (ssl->type == CLIENTssl) {
        printf("curves     :");
        for (int i = 0; i < LenArray(ssl->ellipticCurves); i++) {
            printf(" 0x%x", ssl->ellipticCurves.array[i]);
        }
        printf("\ncurves PF  :");
        for (int i = 0; i < LenArray(ssl->ellipticCurvesPF); i++) {
            printf(" 0x%x", ssl->ellipticCurvesPF.array[i]);
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

ssl_t *sslProcess(const uint8_t *data, size_t len) {
    dbg_printf("\nsslProcess new packet. size: %zu\n", len);
    // Check for ssl record
    // - TLS header length (5)
    // - message type/length (4)
    //
    // TLS Record header
    // 0--------8-------16-------24-------32-------40
    // | type   |     version     |     length      | TLS Record header
    // +--------+--------+--------+--------+--------+
    //
    // type:
    // Record Type Values       dec      hex
    // -------------------------------------
    // CHANGE_CIPHER_SPEC        20     0x14
    // ALERT                     21     0x15
    // HANDSHAKE                 22     0x16
    // APPLICATION_DATA          23     0x17
    //
    // version:
    // Version Values            dec     hex
    // -------------------------------------
    // SSL 3.0                   3,0  0x0300
    // TLS 1.0                   3,1  0x0301
    // TLS 1.1                   3,2  0x0302
    // TLS 1.2                   3,3  0x0303
    //
    // record type (1 byte)

    // - and handshake content type (22)
    if (len < 9 || data[0] != 0x16) {
        dbg_printf("Not a TLS handshake record: 0x%x\n", data[0]);
        return NULL;
    }

    ByteStream_INIT(sslStream, data, len);
    ByteStream_SKIP(sslStream, 1);  // 0x22 data[0]

    uint16_t sslVersion;
    ByteStream_GET_u16(sslStream, sslVersion);
    switch (sslVersion) {
        case 0x0200:  // SSL 2.0
        case 0x0300:  // SSL 3.0
        case 0x0301:  // TLS 1.1
        case 0x0302:  // TLS 1.2
        case 0x0303:  // TLS 1.3
            break;
        default:
            dbg_printf("SSL version: 0x%x not SSL 3.0 - TLS 1.3 connection\n", sslVersion);
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

    ssl_t *ssl = (ssl_t *)calloc(1, sizeof(ssl_t));
    if (!ssl) {
        LogError("calloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }
    ssl->tlsVersion = sslVersion;

    int ok = 0;
    switch (messageType) {
        case 0:  // hello_request(0)
            break;
        case 1:  // client_hello(1)
            ssl->type = CLIENTssl;
            ok = sslParseClientHandshake(ssl, sslStream, messageLength);
            break;
        case 2:  // server_hello(2),
            ssl->type = SERVERssls;
            ok = sslParseServerHandshake(ssl, sslStream, messageLength);
            break;
        case 11:  // certificate(11)
        case 12:  // server_key_exchange (12),
        case 13:  //  certificate_request(13)
        case 14:  //  server_hello_done(14),
        case 15:  // certificate_verify(15)
        case 16:  // client_key_exchange(16)
        case 20:  // finished(20),
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

#ifdef MAIN
void sslTest(void) {
    const uint8_t clientHello[] = {
        0x16, 0x03, 0x01, 0x00, 0xc8, 0x01, 0x00, 0x00, 0xc4, 0x03, 0x03, 0xec, 0x12, 0xdd, 0x17, 0x64, 0xa4, 0x39, 0xfd, 0x7e, 0x8c, 0x85, 0x46,
        0xb8, 0x4d, 0x1e, 0xa0, 0x6e, 0xb3, 0xd7, 0xa0, 0x51, 0xf0, 0x3c, 0xb8, 0x17, 0x47, 0x0d, 0x4c, 0x54, 0xc5, 0xdf, 0x72, 0x00, 0x00, 0x1c,
        0xea, 0xea, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00,
        0x2f, 0x00, 0x35, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x7f, 0xda, 0xda, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00,
        0x14, 0x00, 0x00, 0x11, 0x77, 0x77, 0x77, 0x2e, 0x77, 0x69, 0x6b, 0x69, 0x70, 0x65, 0x64, 0x69, 0x61, 0x2e, 0x6f, 0x72, 0x67, 0x00, 0x17,
        0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05,
        0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x10, 0x00,
        0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x75, 0x50, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x02,
        0x01, 0x00, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x1a, 0x1a, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x1a, 0x1a, 0x00, 0x01, 0x00};

    const uint8_t tls12[] = {
        0x16, 0x03,                                      // ..X.....
        0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03,  // ........
        0x03, 0xec, 0xb2, 0x69, 0x1a, 0xdd, 0xb2, 0xbf,  // ...i....
        0x6c, 0x59, 0x9c, 0x7a, 0xaa, 0xe2, 0x3d, 0xe5,  // lY.z..=.
        0xf4, 0x25, 0x61, 0xcc, 0x04, 0xeb, 0x41, 0x02,  // .%a...A.
        0x9a, 0xcc, 0x6f, 0xc0, 0x50, 0xa1, 0x6a, 0xc1,  // ..o.P.j.
        0xd2, 0x20, 0x46, 0xf8, 0x61, 0x7b, 0x58, 0x0a,  // . F.a{X.
        0xc9, 0x35, 0x8e, 0x2a, 0xa4, 0x4e, 0x30, 0x6d,  // .5.*.N0m
        0x52, 0x46, 0x6b, 0xcc, 0x98, 0x9c, 0x87, 0xc8,  // RFk.....
        0xca, 0x64, 0x30, 0x9f, 0x5f, 0xaf, 0x50, 0xba,  // .d0._.P.
        0x7b, 0x4d, 0x00, 0x22, 0x13, 0x01, 0x13, 0x03,  // {M."....
        0x13, 0x02, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9,  // ...+./..
        0xcc, 0xa8, 0xc0, 0x2c, 0xc0, 0x30, 0xc0, 0x0a,  // ...,.0..
        0xc0, 0x09, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c,  // ........
        0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0x01, 0x00,  // .../.5..
        0x01, 0x91, 0x00, 0x00, 0x00, 0x21, 0x00, 0x1f,  // .....!..
        0x00, 0x00, 0x1c, 0x63, 0x6f, 0x6e, 0x74, 0x69,  // ...conti
        0x6c, 0x65, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69,  // le.servi
        0x63, 0x65, 0x73, 0x2e, 0x6d, 0x6f, 0x7a, 0x69,  // ces.mozi
        0x6c, 0x6c, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x00,  // lla.com.
        0x17, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00,  // ........
        0x00, 0x0a, 0x00, 0x0e, 0x00, 0x0c, 0x00, 0x1d,  // ........
        0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00,  // ........
        0x01, 0x01, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,  // ........
        0x00, 0x23, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e,  // .#......
        0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74,  // ...h2.ht
        0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x00, 0x05,  // tp/1.1..
        0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,  // ........
        0x22, 0x00, 0x0a, 0x00, 0x08, 0x04, 0x03, 0x05,  // ".......
        0x03, 0x06, 0x03, 0x02, 0x03, 0x00, 0x33, 0x00,  // ......3.
        0x6b, 0x00, 0x69, 0x00, 0x1d, 0x00, 0x20, 0x89,  // k.i... .
        0x09, 0x85, 0x8f, 0xbe, 0xb6, 0xed, 0x2f, 0x12,  // ....../.
        0x48, 0xba, 0x5b, 0x9e, 0x29, 0x78, 0xbe, 0xad,  // H.[.)x..
        0x0e, 0x84, 0x01, 0x10, 0x19, 0x2c, 0x61, 0xda,  // .....,a.
        0xed, 0x00, 0x96, 0x79, 0x8b, 0x18, 0x44, 0x00,  // ...y..D.
        0x17, 0x00, 0x41, 0x04, 0x4d, 0x18, 0x3d, 0x91,  // ..A.M.=.
        0xf5, 0xee, 0xd3, 0x57, 0x91, 0xfa, 0x98, 0x24,  // ...W...$
        0x64, 0xe3, 0xb0, 0x21, 0x4a, 0xaa, 0x5f, 0x5d,  // d..!J._]
        0x1b, 0x78, 0x61, 0x6d, 0x9b, 0x9f, 0xbe, 0xbc,  // .xam....
        0x22, 0xd1, 0x1f, 0x53, 0x5b, 0x2f, 0x94, 0xc6,  // "..S[/..
        0x86, 0x14, 0x31, 0x36, 0xaa, 0x79, 0x5e, 0x6e,  // ..16.y^n
        0x5a, 0x87, 0x5d, 0x6c, 0x08, 0x06, 0x4a, 0xd5,  // Z.]l..J.
        0xb7, 0x6d, 0x44, 0xca, 0xad, 0x76, 0x6e, 0x24,  // .mD..vn$
        0x83, 0x01, 0x27, 0x48, 0x00, 0x2b, 0x00, 0x05,  // ..'H.+..
        0x04, 0x03, 0x04, 0x03, 0x03, 0x00, 0x0d, 0x00,  // ........
        0x18, 0x00, 0x16, 0x04, 0x03, 0x05, 0x03, 0x06,  // ........
        0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04,  // ........
        0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x03, 0x02,  // ........
        0x01, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00,  // ..-.....
        0x1c, 0x00, 0x02, 0x40, 0x01, 0x00, 0x15, 0x00,  // ...@....
        0x7a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // z.......
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // ........
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // ........
        0x00, 0x00, 0x00                                 // ...
    };
    /*
    [JA4: t13d1715h2_5b57614c22b0_3d5424432f57]
    JA4_r:
    t13d1715h2_002f,0035,009c,009d,1301,1302,1303,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0015,0017,001c,0022,0023,002b,002d,0033,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201]

    JA3 Fullstring:
    771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0]
    [JA3: 579ccef312d18482fc42e2b822ca2430]
    */
    // size_t len = sizeof(clientHello);
    size_t len = sizeof(tls12);

    ssl_t *ssl = sslProcess(tls12, len);
    if (ssl)
        sslPrint(ssl);
    else
        printf("Failed to parse ssl\n");
}

int main(int argc, char **argv) {
    sslTest();
    return 0;
}

#endif