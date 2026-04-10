/*
 *  Copyright (c) 2024-2026, Peter Haag
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

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "filter/filter.h"
#include "id.h"
#include "ja3/ja3.h"
#include "ja4/ja4.h"
#include "logging.h"
#include "nfdump.h"
#include "nfxV4.h"
#include "output_short.h"
#include "ssl/ssl.h"
#include "userio.h"
#include "util.h"

/* MapV4RecordHandle - inline copy from nffile_inline.c to avoid V3 dependencies */

// Fix lazy exporters, sending both - IPv4 and IPv6 addresses in the same record
static inline void ResolveMultipleIPrecords(recordHandle_t *handle, uint64_t flowCount) {
    dbg_printf("ResolveMultipleIPrecords\n");
    EXlayer2_t *EXlayer2 = (EXlayer2_t *)handle->extensionList[EXlayer2ID];
    uint32_t skipID = 0;
    if (EXlayer2) {
        switch (EXlayer2->ipVersion) {
            case 0: {
                uint64_t *ipv4SrcDst = (uint64_t *)handle->extensionList[EXipv4FlowID];
                if (*ipv4SrcDst == 0) {
                    skipID = EXipv4FlowID;
                } else {
                    skipID = EXipv6FlowID;
                }
            } break;
            case 4:
                skipID = EXipv6FlowID;
                break;
            case 6:
                skipID = EXipv4FlowID;
                break;
            default:
                LogError("Mapping record: %" PRIu64 "  - Error - unknown IP version: %d", flowCount, EXlayer2->ipVersion);
        }
    } else {
        uint64_t *ipv4SrcDst = (uint64_t *)handle->extensionList[EXipv4FlowID];
        if (*ipv4SrcDst == 0) {
            skipID = EXipv4FlowID;
        } else {
            skipID = EXipv6FlowID;
        }
    }
    if (skipID) {
        handle->extensionList[skipID] = NULL;
    }
}

static inline int MapV4RecordHandle(recordHandle_t *handle, recordHeaderV4_t *recordHeaderV4, uint64_t flowCount) {
    *handle = (recordHandle_t){.recordHeaderV4 = recordHeaderV4, .numElements = recordHeaderV4->numExtensions, .flowCount = flowCount};

    uint8_t *eor = (uint8_t *)recordHeaderV4 + recordHeaderV4->size;
    uint8_t *recordBase = (uint8_t *)recordHeaderV4;

    uint16_t *offset = (uint16_t *)(recordBase + sizeof(recordHeaderV4_t));

    uint64_t bitMap = recordHeaderV4->extBitmap;
    while (bitMap) {
        uint32_t extID = __builtin_ctzll(bitMap);
        bitMap &= bitMap - 1;

        uint8_t *extension = recordBase + *offset++;

        if (extension > eor) {
            LogError("MapV4RecordHandle: extension %d offset out of bounds", extID);
            return 0;
        }

        if (extID < MAXEXTENSIONS) {
            handle->extensionList[extID] = extension;
        } else {
            LogError("Mapping record: %" PRIu64 " - Skip unknown extension Type: %u", flowCount, extID);
        }
    }

    handle->extensionList[EXheader] = (void *)recordHeaderV4;
    handle->extensionList[EXlocal] = (void *)handle;

    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)handle->extensionList[EXgenericFlowID];
    if (genericFlow && genericFlow->msecFirst == 0) {
        EXnselCommon_t *nselCommon = (EXnselCommon_t *)handle->extensionList[EXnselCommonID];
        if (nselCommon) {
            genericFlow->msecFirst = nselCommon->msecEvent;
        }
    }

    // NOTE: For testing purposes, we DON'T call ResolveMultipleIPrecords()
    // because we want to test both IPv4 and IPv6 extensions independently
    // using DisableExtension()/EnableExtension()

    return 1;
}

/* record buffer for building V4 records */
#define RECBUF_SIZE 8192

/*
 * Build a V4 record with fixed-size extensions.
 * Variable-length extensions (payload, nbar, pfinfo, etc.) require special handling.
 */
static uint16_t BuildV4Record(uint8_t *buf, const uint32_t *extIDs, uint32_t numExt) {
    memset(buf, 0, RECBUF_SIZE);
    recordHeaderV4_t *h = AddV4Header(buf);

    // set all bitmap bits first
    for (uint32_t i = 0; i < numExt; i++) {
        BitMapSet(h->extBitmap, extIDs[i]);
    }
    h->numExtensions = numExt;

    // compute offset past offset table (8-byte aligned)
    uint16_t nextOffset = (uint16_t)ALIGN8(sizeof(recordHeaderV4_t) + numExt * sizeof(uint16_t));
    h->size = nextOffset;

    // add extensions in ascending ID order (matching bitmap rank order)
    for (uint32_t i = 0; i < numExt; i++) {
        uint32_t extID = extIDs[i];
        uint32_t extSize = extensionTable[extID].size;
        if (extSize == VARLENGTH) {
            fprintf(stderr, "BuildV4Record: variable-length extension %u not supported\n", extID);
            return 0;
        }

        uint32_t slot = __builtin_popcountll(h->extBitmap & ((1ULL << extID) - 1));
        uint16_t *offsets = V4OffsetTable(h);
        offsets[slot] = nextOffset;

        memset(buf + nextOffset, 0, extSize);
        nextOffset += (uint16_t)extSize;
        h->size += (uint16_t)extSize;
    }

    return h->size;
}

/*
 * Build a V4 record with a variable-length payload extension.
 * payloadLen: size of payload data to reserve (will be 8-byte aligned internally)
 */
static uint16_t BuildV4RecordWithPayload(uint8_t *buf, const uint32_t *extIDs, uint32_t numExt, uint32_t payloadLen) {
    memset(buf, 0, RECBUF_SIZE);
    recordHeaderV4_t *h = AddV4Header(buf);

    // set all bitmap bits
    for (uint32_t i = 0; i < numExt; i++) {
        BitMapSet(h->extBitmap, extIDs[i]);
    }
    h->numExtensions = numExt;

    // compute offset past offset table
    uint16_t nextOffset = (uint16_t)ALIGN8(sizeof(recordHeaderV4_t) + numExt * sizeof(uint16_t));
    h->size = nextOffset;

    // add extensions
    for (uint32_t i = 0; i < numExt; i++) {
        uint32_t extID = extIDs[i];
        uint32_t extSize = extensionTable[extID].size;

        // Handle variable-length payload extension
        if (extID == EXinPayloadID || extID == EXoutPayloadID) {
            extSize = (uint32_t)ALIGN8(sizeof(EXinPayload_t) + payloadLen);
        } else if (extSize == VARLENGTH) {
            fprintf(stderr, "BuildV4RecordWithPayload: unsupported variable-length extension %u\n", extID);
            return 0;
        }

        uint32_t slot = __builtin_popcountll(h->extBitmap & ((1ULL << extID) - 1));
        uint16_t *offsets = V4OffsetTable(h);
        offsets[slot] = nextOffset;

        memset(buf + nextOffset, 0, extSize);

        // Set payload size field
        if (extID == EXinPayloadID || extID == EXoutPayloadID) {
            EXinPayload_t *p = (EXinPayload_t *)(buf + nextOffset);
            p->size = payloadLen;
        }

        nextOffset += (uint16_t)extSize;
        h->size += (uint16_t)extSize;
    }

    return h->size;
}

static void DumpRecord(recordHandle_t *recordHandle) {
    recordHeaderV4_t *h = recordHandle->recordHeaderV4;
    printf("V4 Record - Extensions: %u, Size: %u, Bitmap: 0x%016" PRIx64 "\n", h->numExtensions, h->size, h->extBitmap);

    uint16_t *offset = V4OffsetTable(h);
    printf("OffsetTable: \n");
    uint64_t bitMap = h->extBitmap;
    while (bitMap) {
        uint32_t extID = __builtin_ctzll(bitMap);
        bitMap &= bitMap - 1;
        printf(" extID: %u, offset: %u\n", extID, *offset++);
    }
    printf("Record dump:\n");
    DumpHex(stdout, (void *)h, h->size);
    printf("Flow Count: %" PRIu64 "\n", recordHandle->flowCount);
    payloadHandle_t *payloadHandle = recordHandle->extensionList[EXinPayloadHandle];
    if (payloadHandle) {
        ssl_t *ssl = payloadHandle->ssl;
        if (ssl) {
            printf("SSL version : %c.%c\n", ssl->tlsCharVersion[0], ssl->tlsCharVersion[1]);
            printf("SSL SNI     : %s\n", ssl->sniName);
        }
        char *s = payloadHandle->ja3;
        printf("Ja3: %s\n", s != NULL ? s : "no ja3");
        ja4_t *ja4 = payloadHandle->ja4;
        if (ja4) {
            switch (ja4->type) {
                case TYPE_JA4:
                    printf("Ja4: %s\n", ja4->string);
                    break;
                case TYPE_JA4S:
                    printf("Ja4s: %s\n", ja4->string);
                    break;
                default:
                    printf("Unknown Ja4: %s\n", ja4->string);
            }
        } else {
            printf("Ja4: no ja4\n");
        }
    } else {
        printf("no payload\n");
    }

    printf("Geo: ");
    DumpHex(stdout, (void *)recordHandle->geo, sizeof(recordHandle->geo));
}

static void CheckFilter(char *filter, recordHandle_t *recordHandle, int expect) {
    void *engine = CompileFilter(filter);
    if (!engine) {
        printf("*** Compile %s failed\n", filter);
        if (expect != -1)
            exit(255);
        else
            return;
    } else {
        printf("Compiled ok: %s\n", filter);
    }
    FilterSetParam(engine, NULL, NOGEODB);
    int ret = FilterRecord(engine, recordHandle);
    if (ret != expect) {
        printf("*** Filter failed for %s\n", filter);
        printf("*** Expected %d, result: %d\n", expect, ret);
        DumpEngine(engine);
        DumpRecord(recordHandle);
        exit(255);
    }
    DisposeFilter(engine);
}

/*
 * V4 Extension Enable/Disable Mechanism
 *
 * Unlike V3 where extensions were added incrementally with PushExtension(),
 * V4 records have a fixed layout with all extensions defined upfront.
 *
 * To test filters with/without specific extensions:
 * 1. Build a "maximal" record containing all needed extensions
 * 2. MapV4RecordHandle() populates extensionList[] with pointers
 * 3. To "disable" an extension: save and NULL the extensionList pointer
 * 4. To "enable" an extension: restore the saved pointer
 *
 * This approach is cleaner than V3's DisableExtension/EnableExtension
 * which manipulated element headers.
 */

/* Saved extension pointers for enable/disable mechanism */
static void *savedExtensions[MAXEXTENSIONS];

static void DisableExtension(recordHandle_t *handle, uint32_t extID) {
    if (extID < MAXEXTENSIONS) {
        savedExtensions[extID] = handle->extensionList[extID];
        handle->extensionList[extID] = NULL;
        dbg_printf("Disabled extension %u\n", extID);
    }
}

static void EnableExtension(recordHandle_t *handle, uint32_t extID) {
    if (extID < MAXEXTENSIONS && savedExtensions[extID]) {
        handle->extensionList[extID] = savedExtensions[extID];
        dbg_printf("Enabled extension %u\n", extID);
    }
}

static void runTest(void) {
    // Allocate buffer for V4 record - large enough for all extensions
    uint8_t *recBuf = malloc(RECBUF_SIZE);
    if (!recBuf) {
        perror("malloc() failed:");
        exit(255);
    }

    recordHandle_t *recordHandle = (recordHandle_t *)calloc(1, sizeof(recordHandle_t));
    if (!recordHandle) {
        perror("calloc() failed:");
        exit(255);
    }

    memset(savedExtensions, 0, sizeof(savedExtensions));

    // ================================================================
    // Phase 1: Empty record - header only
    // ================================================================
    BuildV4Record(recBuf, NULL, 0);
    recordHeaderV4_t *h = (recordHeaderV4_t *)recBuf;
    MapV4RecordHandle(recordHandle, h, 1);

    CheckFilter("count 1", recordHandle, 1);
    CheckFilter("count 2", recordHandle, 0);
    CheckFilter("count > 2", recordHandle, 0);

    // no extension
    CheckFilter("any", recordHandle, 1);

    // Record header fields
    h->engineType = 3;
    h->engineID = 8;
    CheckFilter("engine-type 4", recordHandle, 0);
    CheckFilter("engine-type 3", recordHandle, 1);
    CheckFilter("engine type 3", recordHandle, 1);
    CheckFilter("engine-id 9", recordHandle, 0);
    CheckFilter("engine-id 8", recordHandle, 1);
    CheckFilter("engine id 8", recordHandle, 1);
    h->exporterID = 12345;
    CheckFilter("exporter id 12345", recordHandle, 1);
    CheckFilter("exporter id 8", recordHandle, 0);

    // non existing extension
    CheckFilter("src port 80", recordHandle, 0);

    // ================================================================
    // Phase 2: Add EXgenericFlow
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID};
        BuildV4Record(recBuf, ext, 1);
        h = (recordHeaderV4_t *)recBuf;
        h->exporterID = 12345;
        h->engineType = 3;
        h->engineID = 8;
        MapV4RecordHandle(recordHandle, h, 1);

        EXgenericFlow_t *genericFlow = GetExtension(h, EXgenericFlow);

        genericFlow->srcPort = 80;
        CheckFilter("src port 80", recordHandle, 1);
        CheckFilter("not src port 80", recordHandle, 0);
        CheckFilter("src port 81", recordHandle, 0);
        CheckFilter("src port 79", recordHandle, 0);

        genericFlow->srcPort = 0x1122;
        genericFlow->dstPort = 80;
        CheckFilter("src port 0x1122", recordHandle, 1);
        CheckFilter("not src port 80", recordHandle, 1);
        CheckFilter("dst port 80", recordHandle, 1);
        CheckFilter("dst port > 79", recordHandle, 1);
        CheckFilter("dst port > 80", recordHandle, 0);
        CheckFilter("dst port < 80", recordHandle, 0);
        CheckFilter("port > 79 and port < 81", recordHandle, 1);

        genericFlow->srcPort = 1234;
        genericFlow->dstPort = 80;
        genericFlow->proto = 17;

        CheckFilter("proto 17", recordHandle, 1);
        CheckFilter("proto tcp", recordHandle, 0);
        CheckFilter("proto udp", recordHandle, 1);
        CheckFilter("proto foobar", recordHandle, -1);

        CheckFilter("src port 1234", recordHandle, 1);
        CheckFilter("dst port 80", recordHandle, 1);
        CheckFilter("dst port 80 or src port 1234", recordHandle, 1);
        CheckFilter("dst port 81 or src port 1234", recordHandle, 1);
        CheckFilter("dst port 80 or src port 1235", recordHandle, 1);
        CheckFilter("dst port 81 or src port 1235", recordHandle, 0);
        CheckFilter("dst port 80 and src port 1234", recordHandle, 1);
        CheckFilter("dst port 81 and src port 1234", recordHandle, 0);
        // test against non existing extension
        CheckFilter("dst port 80 or mpls label2 32", recordHandle, 1);
        CheckFilter("dst port 81 or mpls label2 32", recordHandle, 0);
        CheckFilter("dst port 80 and mpls label2 32", recordHandle, 0);

        genericFlow->proto = 1;
        CheckFilter("icmp-type 3", recordHandle, 0);
        genericFlow->icmpType = 3;
        CheckFilter("icmp-type 3", recordHandle, 1);
        CheckFilter("icmp type 3", recordHandle, 1);
        CheckFilter("icmp-code 8", recordHandle, 0);
        genericFlow->icmpCode = 8;
        CheckFilter("icmp-code 8", recordHandle, 1);
        CheckFilter("icmp code 8", recordHandle, 1);

        genericFlow->inPackets = 100;
        CheckFilter("packets 100", recordHandle, 1);
        CheckFilter("packets 1", recordHandle, 0);
        CheckFilter("packets > 1", recordHandle, 1);
        CheckFilter("packets < 101", recordHandle, 1);

        CheckFilter("bytes 200", recordHandle, 0);
        genericFlow->inBytes = 200;
        CheckFilter("bytes 200", recordHandle, 1);
        CheckFilter("bytes 2", recordHandle, 0);
        CheckFilter("bytes > 2", recordHandle, 1);
        CheckFilter("bytes < 201", recordHandle, 1);

        CheckFilter("duration > 0", recordHandle, 0);
        genericFlow->msecLast = time(0) * 1000;
        genericFlow->msecFirst = genericFlow->msecLast - (10 * 1000);
        CheckFilter("duration > 1", recordHandle, 1);
        CheckFilter("duration >= 10000", recordHandle, 1);
        CheckFilter("duration >= 10001", recordHandle, 0);

        genericFlow->inPackets = 100;
        CheckFilter("pps > 1", recordHandle, 1);
        CheckFilter("pps 10", recordHandle, 1);
        CheckFilter("pps > 10", recordHandle, 0);

        genericFlow->inBytes = 200;
        CheckFilter("bps > 2", recordHandle, 1);
        CheckFilter("bps 160", recordHandle, 1);
        CheckFilter("bps > 160", recordHandle, 0);

        CheckFilter("bpp 2", recordHandle, 1);
        CheckFilter("bpp > 2", recordHandle, 0);

        // Test with time 2024-07-11T09:15:10.010
        genericFlow->msecFirst = ParseTime8601("2024-07-11T09:15:10.010");
        CheckFilter("first seen 2024-07-11T09:15:10.010", recordHandle, 1);
        CheckFilter("first seen > 2024-07-11T09:15:10.010", recordHandle, 0);
        CheckFilter("first seen > 2024-07-11T09:15:10.009", recordHandle, 1);
        CheckFilter("first seen > 2024-07-10T09:15:10.010", recordHandle, 1);
        CheckFilter("first seen < 2024-07-11T09:15:10.011", recordHandle, 1);
        CheckFilter("first seen < 2024-07-11T09:15:10.010", recordHandle, 0);
        CheckFilter("first seen < 2024-07-10T09:15:10.010", recordHandle, 0);

        genericFlow->msecLast = ParseTime8601("2024-07-11T09:15:10.010");
        genericFlow->msecFirst = 0;
        CheckFilter("last seen 2024-07-11T09:15:10.010", recordHandle, 1);
        CheckFilter("last seen > 2024-07-11T09:15:10.010", recordHandle, 0);
        CheckFilter("last seen > 2024-07-11T09:15:10.009", recordHandle, 1);
        CheckFilter("last seen > 2024-07-10T09:15:10.010", recordHandle, 1);
        CheckFilter("last seen < 2024-07-11T09:15:10.011", recordHandle, 1);
        CheckFilter("last seen < 2024-07-11T09:15:10.010", recordHandle, 0);
        CheckFilter("last seen < 2024-07-10T09:15:10.010", recordHandle, 0);

        genericFlow->proto = IPPROTO_TCP;
        genericFlow->tcpFlags = 1;  // FIN
        CheckFilter("flags F", recordHandle, 1);
        CheckFilter("flags S", recordHandle, 0);
        CheckFilter("flags R", recordHandle, 0);
        CheckFilter("flags P", recordHandle, 0);
        CheckFilter("flags A", recordHandle, 0);
        CheckFilter("flags U", recordHandle, 0);
        CheckFilter("flags X", recordHandle, 0);

        genericFlow->tcpFlags = 2;  // SYN
        CheckFilter("flags S", recordHandle, 1);
        genericFlow->tcpFlags = 4;  // RST
        CheckFilter("flags R", recordHandle, 1);
        genericFlow->tcpFlags = 8;  // PUSH
        CheckFilter("flags P", recordHandle, 1);
        genericFlow->tcpFlags = 16;  // ACK
        CheckFilter("flags A", recordHandle, 1);
        genericFlow->tcpFlags = 32;  // URG
        CheckFilter("flags U", recordHandle, 1);
        genericFlow->tcpFlags = 63;  // Xmas
        CheckFilter("flags X", recordHandle, 1);

        CheckFilter("flags S", recordHandle, 1);
        CheckFilter("flags RF", recordHandle, 1);
        genericFlow->tcpFlags = 16;
        CheckFilter("not flags RF", recordHandle, 1);

        genericFlow->tcpFlags = 63;
        CheckFilter("flags =S", recordHandle, 0);
        genericFlow->tcpFlags = 2;
        CheckFilter("flags =S", recordHandle, 1);
        genericFlow->tcpFlags = 18;
        CheckFilter("flags =SA", recordHandle, 1);

        genericFlow->tcpFlags = 3;  // flags SF
        CheckFilter("flags SF", recordHandle, 1);
        CheckFilter("flags 3", recordHandle, 1);
        CheckFilter("flags SF and not flags AR", recordHandle, 1);
        CheckFilter("flags SF", recordHandle, 1);
        genericFlow->tcpFlags = 7;
        CheckFilter("flags R", recordHandle, 1);
        CheckFilter("flags P", recordHandle, 0);
        CheckFilter("flags A", recordHandle, 0);

        CheckFilter("flags = 7", recordHandle, 1);
        CheckFilter("flags > 7", recordHandle, 0);
        CheckFilter("flags > 6", recordHandle, 1);
        CheckFilter("flags < 7", recordHandle, 0);
        CheckFilter("flags < 8", recordHandle, 1);

        genericFlow->srcTos = 10;
        CheckFilter("src tos 10", recordHandle, 1);
        CheckFilter("src tos 11", recordHandle, 0);
        CheckFilter("src tos 9", recordHandle, 0);
        CheckFilter("src tos > 9", recordHandle, 1);
        CheckFilter("src tos < 11", recordHandle, 1);

        genericFlow->fwdStatus = 25;
        CheckFilter("fwdstat 25", recordHandle, 1);
        CheckFilter("fwdstat DbadTTL", recordHandle, 1);
        CheckFilter("fwdstat 24", recordHandle, 0);
        CheckFilter("fwdstat 26", recordHandle, 0);
    }

    // ================================================================
    // Phase 3: Add EXipv4Flow and EXipv6Flow
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXipv6FlowID};
        BuildV4Record(recBuf, ext, 3);
        h = (recordHeaderV4_t *)recBuf;
        h->exporterID = 12345;

        // Get extension pointers BEFORE MapV4RecordHandle
        // Set a dummy IPv4 address to prevent ResolveMultipleIPrecords from
        // NULLing the IPv4 extension (it checks if ipv4SrcDst == 0)
        EXipv4Flow_t *ipv4 = GetExtension(h, EXipv4Flow);
        EXipv6Flow_t *ipv6 = GetExtension(h, EXipv6Flow);
        uint32_t dummyV4 = 0;
        inet_pton(PF_INET, "127.0.0.1", &dummyV4);
        ipv4->srcAddr = ntohl(dummyV4);

        MapV4RecordHandle(recordHandle, h, 1);

        EXgenericFlow_t *genericFlow = GetExtension(h, EXgenericFlow);
        (void)genericFlow;  // suppress unused variable warning

        // Start with IPv4 only (disable IPv6)
        DisableExtension(recordHandle, EXipv6FlowID);
        CheckFilter("ipv4", recordHandle, 1);
        CheckFilter("ipv6", recordHandle, 0);

        // Reset IPv4 and test with real addresses
        ipv4->srcAddr = 0;
        uint32_t v4 = 0;
        inet_pton(PF_INET, "1.2.3.4", &v4);
        ipv4->srcAddr = ntohl(v4);
        CheckFilter("src ip 1.2.3.4", recordHandle, 1);
        CheckFilter("dst ip 1.2.3.4", recordHandle, 0);
        CheckFilter("ip 1.2.3.4", recordHandle, 1);
        ipv4->dstAddr = ipv4->srcAddr;
        ipv4->srcAddr = 0;
        CheckFilter("src ip 1.2.3.4", recordHandle, 0);
        CheckFilter("dst ip 1.2.3.4", recordHandle, 1);
        CheckFilter("ip 1.2.3.4", recordHandle, 1);
        ipv4->srcAddr = 0;
        ipv4->dstAddr = 0;

        // Enable IPv6
        EnableExtension(recordHandle, EXipv6FlowID);
        CheckFilter("ipv6", recordHandle, 1);

        // EXipv6FlowID
        uint64_t v6[2];
        inet_pton(PF_INET6, "2001:620:0:ff::5c", v6);
        ipv6->srcAddr[0] = ntohll(v6[0]);
        ipv6->srcAddr[1] = ntohll(v6[1]);
        CheckFilter("src ip 2001:620:0:ff::5c", recordHandle, 1);
        CheckFilter("ip 2001:620:0:ff::5c", recordHandle, 1);
        CheckFilter("dst ip 2001:620:0:ff::5c", recordHandle, 0);
        ipv6->dstAddr[0] = ipv6->srcAddr[0];
        ipv6->dstAddr[1] = ipv6->srcAddr[1];
        CheckFilter("dst ip 2001:620:0:ff::5c", recordHandle, 1);
        ipv6->srcAddr[0] = 0;
        ipv6->srcAddr[1] = 0;
        CheckFilter("ip 2001:620:0:ff::5c", recordHandle, 1);
        CheckFilter("src ip 2001:620:0:ff::5c", recordHandle, 0);
    }

    // ================================================================
    // Phase 4: Add AS extensions
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXipv6FlowID, EXasInfoID};
        BuildV4Record(recBuf, ext, 4);
        h = (recordHeaderV4_t *)recBuf;
        h->exporterID = 12345;
        MapV4RecordHandle(recordHandle, h, 1);

        EXasInfo_t *asInfo = GetExtension(h, EXasInfo);

        CheckFilter("src as 65535", recordHandle, 0);
        asInfo->srcAS = 65535;
        CheckFilter("src as 65535", recordHandle, 1);
        CheckFilter("as 65535", recordHandle, 1);
        CheckFilter("dst as 65535", recordHandle, 0);
        asInfo->dstAS = 65535;
        asInfo->srcAS = 0;
        CheckFilter("dst as 65535", recordHandle, 1);
        CheckFilter("as 65535", recordHandle, 1);
        CheckFilter("src as 65535", recordHandle, 0);
        CheckFilter("as > 65000", recordHandle, 1);
    }

    // ================================================================
    // Phase 5: Add interface and flow misc
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXinterfaceID, EXflowMiscID};
        BuildV4Record(recBuf, ext, 4);
        h = (recordHeaderV4_t *)recBuf;
        h->exporterID = 12345;
        MapV4RecordHandle(recordHandle, h, 1);

        EXinterface_t *iface = GetExtension(h, EXinterface);
        EXflowMisc_t *flowMisc = GetExtension(h, EXflowMisc);

        iface->input = 5;
        CheckFilter("in if 5", recordHandle, 1);
        CheckFilter("in if 6", recordHandle, 0);
        CheckFilter("out if 6", recordHandle, 0);
        iface->output = 6;
        CheckFilter("out if 6", recordHandle, 1);

        flowMisc->srcMask = 11;
        flowMisc->dstMask = 13;
        CheckFilter("src mask 11", recordHandle, 1);
        CheckFilter("src mask 12", recordHandle, 0);
        CheckFilter("mask 11", recordHandle, 1);
        CheckFilter("dst mask 13", recordHandle, 1);
        CheckFilter("dst mask 14", recordHandle, 0);
        CheckFilter("mask 13", recordHandle, 1);
        CheckFilter("mask 11", recordHandle, 1);

        flowMisc->direction = 1;
        CheckFilter("flowdir 1", recordHandle, 1);
        CheckFilter("flowdir 0", recordHandle, 0);
        CheckFilter("flowdir egress", recordHandle, 1);
        CheckFilter("flowdir ingress", recordHandle, 0);
    }

    // ================================================================
    // Phase 6: Add counter flow
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXinterfaceID, EXflowMiscID, EXcntFlowID};
        BuildV4Record(recBuf, ext, 5);
        h = (recordHeaderV4_t *)recBuf;
        MapV4RecordHandle(recordHandle, h, 1);

        EXcntFlow_t *cntFlow = GetExtension(h, EXcntFlow);

        cntFlow->flows = 10;
        CheckFilter("flows 10", recordHandle, 1);
        CheckFilter("flows > 10", recordHandle, 0);
        CheckFilter("flows < 10", recordHandle, 0);
        cntFlow->outPackets = 1234;
        CheckFilter("out packets 1234", recordHandle, 1);
        CheckFilter("out packets > 1234", recordHandle, 0);
        CheckFilter("out packets < 1234", recordHandle, 0);
        cntFlow->outBytes = 5678;
        CheckFilter("out bytes 5678", recordHandle, 1);
        CheckFilter("out bytes > 5678", recordHandle, 0);
        CheckFilter("out bytes < 5678", recordHandle, 0);
    }

    // ================================================================
    // Phase 7: Add VLAN and layer2
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXvLanID, EXlayer2ID};
        BuildV4Record(recBuf, ext, 4);
        h = (recordHeaderV4_t *)recBuf;
        MapV4RecordHandle(recordHandle, h, 1);

        EXvLan_t *vlan = GetExtension(h, EXvLan);
        EXlayer2_t *layer2 = GetExtension(h, EXlayer2);

        vlan->srcVlan = 1001;
        vlan->dstVlan = 2002;
        CheckFilter("src vlan 2002", recordHandle, 0);
        CheckFilter("dst vlan 2002", recordHandle, 1);
        CheckFilter("vlan 2002", recordHandle, 1);
        CheckFilter("vlan 1001", recordHandle, 1);
        CheckFilter("dst vlan 1001", recordHandle, 0);
        CheckFilter("src vlan 1001", recordHandle, 1);

        layer2->vlanID = 3003;
        layer2->postVlanID = 4004;
        layer2->customerVlanId = 5005;
        layer2->postCustomerVlanId = 6006;
        layer2->etherType = 0x0600;

        CheckFilter("src vlan 1001", recordHandle, 1);
        CheckFilter("src vlan 3003", recordHandle, 1);
        CheckFilter("dst vlan 2002", recordHandle, 1);
        CheckFilter("dst vlan 4004", recordHandle, 1);
        CheckFilter("vlan 3003", recordHandle, 1);
        CheckFilter("vlan 4004", recordHandle, 1);
        CheckFilter("ethertype 0x0600", recordHandle, 1);
        CheckFilter("ethertype 600", recordHandle, 0);
    }

    // ================================================================
    // Phase 8: Add next hop and BGP next hop (IPv4)
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXasRoutingV4ID};
        BuildV4Record(recBuf, ext, 3);
        h = (recordHeaderV4_t *)recBuf;
        MapV4RecordHandle(recordHandle, h, 1);

        EXasRoutingV4_t *routingV4 = GetExtension(h, EXasRoutingV4);

        uint32_t v4 = 0;
        inet_pton(PF_INET, "1.2.3.4", &v4);
        routingV4->nextHop = ntohl(v4);
        CheckFilter("next ip 1.1.1.1", recordHandle, 0);
        CheckFilter("next ip 1.2.3.4", recordHandle, 1);

        inet_pton(PF_INET, "22.33.44.55", &v4);
        routingV4->bgpNextHop = ntohl(v4);
        CheckFilter("bgp next ip 1.2.3.4", recordHandle, 0);
        CheckFilter("bgp next ip 22.33.44.55", recordHandle, 1);
    }

    // ================================================================
    // Phase 9: Add next hop (IPv6)
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv6FlowID, EXasRoutingV6ID};
        BuildV4Record(recBuf, ext, 3);
        h = (recordHeaderV4_t *)recBuf;
        MapV4RecordHandle(recordHandle, h, 1);

        EXasRoutingV6_t *routingV6 = GetExtension(h, EXasRoutingV6);

        uint64_t v6[2];
        inet_pton(PF_INET6, "2002:620:0:ff::52", v6);
        routingV6->nextHop[0] = ntohll(v6[0]);
        routingV6->nextHop[1] = ntohll(v6[1]);
        CheckFilter("next ip 2001:620:0:ff::5c", recordHandle, 0);
        CheckFilter("next ip 2002:620:0:ff::52", recordHandle, 1);

        inet_pton(PF_INET6, "fe80::2110:abcd:1235:ffff", v6);
        routingV6->bgpNextHop[0] = ntohll(v6[0]);
        routingV6->bgpNextHop[1] = ntohll(v6[1]);
        CheckFilter("bgp next ip 2002:620:0:ff::52", recordHandle, 0);
        CheckFilter("bgp next ip fe80::2110:abcd:1235:ffff", recordHandle, 1);
    }

    // ================================================================
    // Phase 10: Add router IP received
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXipReceivedV4ID, EXipReceivedV6ID};
        BuildV4Record(recBuf, ext, 4);
        h = (recordHeaderV4_t *)recBuf;
        MapV4RecordHandle(recordHandle, h, 1);

        EXipReceivedV4_t *receivedV4 = GetExtension(h, EXipReceivedV4);
        EXipReceivedV6_t *receivedV6 = GetExtension(h, EXipReceivedV6);

        uint32_t v4 = 0;
        inet_pton(PF_INET, "192.168.100.1", &v4);
        receivedV4->ip = ntohl(v4);
        CheckFilter("router ip 22.33.44.55", recordHandle, 0);
        CheckFilter("router ip 192.168.100.1", recordHandle, 1);
        CheckFilter("exporter ip 192.168.100.1", recordHandle, 1);

        uint64_t v6[2];
        inet_pton(PF_INET6, "fe80::2110:abcd:1235:1234", v6);
        receivedV6->ip[0] = ntohll(v6[0]);
        receivedV6->ip[1] = ntohll(v6[1]);
        CheckFilter("router ip fe80::2110:abcd:1235:ffff", recordHandle, 0);
        CheckFilter("router ip fe80::2110:abcd:1235:1234", recordHandle, 1);
        CheckFilter("exporter ip fe80::2110:abcd:1235:1234", recordHandle, 1);
    }

    // ================================================================
    // Phase 11: IP lists
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXipv6FlowID, EXasInfoID};
        BuildV4Record(recBuf, ext, 4);
        h = (recordHeaderV4_t *)recBuf;
        MapV4RecordHandle(recordHandle, h, 1);

        EXgenericFlow_t *genericFlow = GetExtension(h, EXgenericFlow);
        EXipv4Flow_t *ipv4 = GetExtension(h, EXipv4Flow);
        EXipv6Flow_t *ipv6 = GetExtension(h, EXipv6Flow);
        EXasInfo_t *asInfo = GetExtension(h, EXasInfo);

        uint32_t v4 = 0;
        uint64_t v6[2];

        // IPv4 list tests - disable IPv6
        DisableExtension(recordHandle, EXipv6FlowID);
        inet_pton(PF_INET, "192.168.169.170", &v4);
        ipv4->srcAddr = ntohl(v4);
        inet_pton(PF_INET, "172.16.17.18", &v4);
        ipv4->dstAddr = ntohl(v4);
        CheckFilter("src ip in [8.8.8.8 2.2.2.2 192.168.169.170]", recordHandle, 1);
        CheckFilter("ip in [8.8.8.8 2.2.2.2 192.168.169.170]", recordHandle, 1);
        CheckFilter("dst ip 172.16.17.18", recordHandle, 1);
        CheckFilter("dst ip in [8.8.8.8 2.2.2.2 192.168.169.170]", recordHandle, 0);
        CheckFilter("dst ip in [8.8.8.8 2.2.2.2 192.168.169.171 172.16.17.18]", recordHandle, 1);
        CheckFilter("src ip in [192.168.169.0/24]", recordHandle, 1);
        CheckFilter("src ip in [8.8.8.8 192.168.169.0/24]", recordHandle, 1);
        CheckFilter("ip in [8.8.8.8 2.2.2.2 192.168.169.171]", recordHandle, 0);
        CheckFilter("dst ip in [8.8.8.8 2.2.2.2 192.168.169.171]", recordHandle, 0);
        CheckFilter("src ip in [8.8.8.8 2.2.2.2 192.168.169.171]", recordHandle, 0);

        // IPv6 list tests - enable IPv6, disable IPv4
        EnableExtension(recordHandle, EXipv6FlowID);
        DisableExtension(recordHandle, EXipv4FlowID);
        inet_pton(PF_INET6, "fe80::2110:abcd:1234:5678", v6);
        ipv6->srcAddr[0] = ntohll(v6[0]);
        ipv6->srcAddr[1] = ntohll(v6[1]);
        ipv6->dstAddr[0] = 0;
        ipv6->dstAddr[1] = 0;
        CheckFilter("src ip fe80::2110:abcd:1234:5678", recordHandle, 1);
        CheckFilter("src ip in [fe80::2110:abcd:1234:5678]", recordHandle, 1);
        CheckFilter("src ip in [8.8.8.8 2.2.2.2 192.168.169.171]", recordHandle, 0);

        CheckFilter("src ip in [8.8.8.8 2.2.2.2 192.168.169.171 fe80::2110:abcd:1234:5678]", recordHandle, 1);
        inet_pton(PF_INET6, "2001:620:0:ff::5c", v6);
        ipv6->dstAddr[0] = ntohll(v6[0]);
        ipv6->dstAddr[1] = ntohll(v6[1]);
        CheckFilter("src ip in [fe80::/16]", recordHandle, 1);
        CheckFilter("src ip in [1.1.1.1 fe80::/16]", recordHandle, 1);
        CheckFilter("ip in [8.8.8.8 2.2.2.2 192.168.169.171 fe80::2110:abcd:1234:5678]", recordHandle, 1);
        CheckFilter("dst ip in [8.8.8.8 2.2.2.2 192.168.169.171 fe80::2110:abcd:1234:5678]", recordHandle, 0);
        CheckFilter("dst ip in [8.8.8.8 2.2.2.2 192.168.169.171 fe80::2110:abcd:1234:5678 2001:620:0:ff::5c]", recordHandle, 1);

        // port lists
        genericFlow->srcPort = 44331;
        genericFlow->dstPort = 80;
        CheckFilter("src port in [80 443 143 25]", recordHandle, 0);
        CheckFilter("dst port in [80 443 143 25]", recordHandle, 1);
        CheckFilter("port in [80 443 143 25]", recordHandle, 1);
        CheckFilter("port in [44331, 443 143 25]", recordHandle, 1);
        CheckFilter("src port in [44331 443 143 25]", recordHandle, 1);
        CheckFilter("dst port in [44331 443 143 25]", recordHandle, 0);

        // AS lists
        asInfo->srcAS = 65535;
        asInfo->dstAS = 330;
        CheckFilter("src as in [330 55443 44332]", recordHandle, 0);
        CheckFilter("dst as in [330 55443 44332]", recordHandle, 1);
        CheckFilter("as in [330 55443 44332]", recordHandle, 1);
        CheckFilter("as in [65535, 55443 44332]", recordHandle, 1);
        CheckFilter("src as in [65535, 55443 44332]", recordHandle, 1);
        CheckFilter("dst as in [65535, 55443 44332]", recordHandle, 0);
    }

    // ================================================================
    // Phase 12: MPLS labels
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXmplsID};
        BuildV4Record(recBuf, ext, 3);
        h = (recordHeaderV4_t *)recBuf;
        MapV4RecordHandle(recordHandle, h, 1);

        EXmpls_t *mpls = GetExtension(h, EXmpls);

        for (int i = 0; i < 10; i++) {
            mpls->label[i] = (30 + i) << 4;  // init label
        }
        // simulate an end of stack label
        mpls->label[4] = (34 << 4) + 1;

        CheckFilter("mpls label2 32", recordHandle, 1);
        CheckFilter("mpls label2 > 31", recordHandle, 1);
        CheckFilter("mpls label2 > 32", recordHandle, 0);
        CheckFilter("mpls label4 > 33", recordHandle, 1);
        CheckFilter("mpls label4 34", recordHandle, 1);

        CheckFilter("mpls eos 34", recordHandle, 1);
        CheckFilter("mpls eos 33", recordHandle, 0);

        for (int i = 0; i < 10; i++) {
            mpls->label[i] = mpls->label[i] | ((i & 0x7) << 1);  // init exp bits
        }

        CheckFilter("mpls exp3 3", recordHandle, 1);
        CheckFilter("mpls exp3 > 2", recordHandle, 1);
        CheckFilter("mpls exp3 > 4", recordHandle, 0);
        CheckFilter("mpls exp7 > 6", recordHandle, 1);
        CheckFilter("mpls exp7 7", recordHandle, 1);

        CheckFilter("mpls any 34", recordHandle, 1);
        CheckFilter("mpls any 33", recordHandle, 1);
        CheckFilter("mpls any 330", recordHandle, 0);
    }

    // ================================================================
    // Phase 13: MAC addresses
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXinMacAddrID, EXoutMacAddrID};
        BuildV4Record(recBuf, ext, 4);
        h = (recordHeaderV4_t *)recBuf;
        MapV4RecordHandle(recordHandle, h, 1);

        EXinMacAddr_t *inMac = GetExtension(h, EXinMacAddr);
        EXoutMacAddr_t *outMac = GetExtension(h, EXoutMacAddr);

        inMac->inSrcMac = 0x0a5056c00001LL;
        outMac->inDstMac = 0x0b5056c00001LL;
        outMac->outSrcMac = 0x0c5056c00001LL;
        inMac->outDstMac = 0x0d5056c00001LL;

        CheckFilter("in src mac 0a:50:56:c0:00:01", recordHandle, 1);
        CheckFilter("in src mac 0a:50:56:c0:00:02", recordHandle, 0);
        CheckFilter("in dst mac 0b:50:56:c0:00:01", recordHandle, 1);
        CheckFilter("in dst mac 0b:50:56:c0:00:02", recordHandle, 0);
        CheckFilter("out src mac 0c:50:56:c0:00:01", recordHandle, 1);
        CheckFilter("out src mac 0c:50:56:c0:00:02", recordHandle, 0);
        CheckFilter("out dst mac 0d:50:56:c0:00:01", recordHandle, 1);
        CheckFilter("out dst mac 0d:50:56:c0:00:02", recordHandle, 0);

        CheckFilter("in mac 0a:50:56:c0:00:01", recordHandle, 1);
        CheckFilter("in mac 0b:50:56:c0:00:01", recordHandle, 1);
        CheckFilter("in mac 0c:50:56:c0:00:01", recordHandle, 0);
        CheckFilter("in mac 0d:50:56:c0:00:01", recordHandle, 0);

        CheckFilter("out mac 0c:50:56:c0:00:01", recordHandle, 1);
        CheckFilter("out mac 0d:50:56:c0:00:01", recordHandle, 1);
        CheckFilter("out mac 0a:50:56:c0:00:01", recordHandle, 0);
        CheckFilter("out mac 0b:50:56:c0:00:01", recordHandle, 0);

        CheckFilter("mac 0a:50:56:c0:00:01", recordHandle, 1);
        CheckFilter("mac 0b:50:56:c0:00:01", recordHandle, 1);
        CheckFilter("mac 0c:50:56:c0:00:01", recordHandle, 1);
        CheckFilter("mac 0d:50:56:c0:00:01", recordHandle, 1);
    }

    // ================================================================
    // Phase 14: Latency
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXlatencyID};
        BuildV4Record(recBuf, ext, 3);
        h = (recordHeaderV4_t *)recBuf;
        MapV4RecordHandle(recordHandle, h, 1);

        EXlatency_t *latency = GetExtension(h, EXlatency);

        latency->msecClientNwDelay = 11;
        latency->msecServerNwDelay = 22;
        latency->msecApplLatency = 33;

        CheckFilter("client latency 11", recordHandle, 1);
        CheckFilter("server latency 22", recordHandle, 1);
        CheckFilter("client latency 12", recordHandle, 0);
        CheckFilter("server latency 23", recordHandle, 0);
        CheckFilter("client latency < 11", recordHandle, 0);
        CheckFilter("client latency > 11", recordHandle, 0);
    }

    // ================================================================
    // Phase 15: NSEL/ASA events
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXnselCommonID};
        BuildV4Record(recBuf, ext, 3);
        h = (recordHeaderV4_t *)recBuf;
        MapV4RecordHandle(recordHandle, h, 1);

        EXnselCommon_t *nselCommon = GetExtension(h, EXnselCommon);

        nselCommon->fwEvent = NSEL_EVENT_IGNORE;
        CheckFilter("asa event ignore", recordHandle, 1);
        CheckFilter("asa event create", recordHandle, 0);
        nselCommon->fwEvent = NSEL_EVENT_CREATE;
        CheckFilter("asa event create", recordHandle, 1);
        nselCommon->fwEvent = NSEL_EVENT_DELETE;
        CheckFilter("asa event delete", recordHandle, 1);
        nselCommon->fwEvent = NSEL_EVENT_DENIED;
        CheckFilter("asa event denied", recordHandle, 1);
        CheckFilter("asa event create", recordHandle, 0);
        CheckFilter("asa event 3", recordHandle, 1);
        CheckFilter("asa event > 2", recordHandle, 1);
        CheckFilter("asa event > 3", recordHandle, 0);

        nselCommon->fwXevent = NSEL_XEVENT_IACL;
        CheckFilter("asa denied ingress", recordHandle, 1);
        CheckFilter("asa denied egress", recordHandle, 0);
        nselCommon->fwXevent = NSEL_XEVENT_EACL;
        CheckFilter("asa denied egress", recordHandle, 1);
        nselCommon->fwXevent = NSEL_XEVENT_DENIED;
        CheckFilter("asa denied access", recordHandle, 1);
        nselCommon->fwXevent = NSEL_XEVENT_NOSYN;
        CheckFilter("asa denied nosyn", recordHandle, 1);
        CheckFilter("asa denied ingress", recordHandle, 0);

        CheckFilter("asa xevent 1004", recordHandle, 1);
        CheckFilter("asa xevent < 1004", recordHandle, 0);
        CheckFilter("asa xevent > 1004", recordHandle, 0);

        // NAT event
        nselCommon->natEvent = 0;
        CheckFilter("nat event invalid", recordHandle, 1);
        CheckFilter("nat event add", recordHandle, 0);

        nselCommon->natEvent = 10;
        CheckFilter("nat event add64bib", recordHandle, 1);
        CheckFilter("nat event add", recordHandle, 0);
        CheckFilter("nat event 10", recordHandle, 1);
        CheckFilter("nat event > 9", recordHandle, 1);
        CheckFilter("nat event > 10", recordHandle, 0);
    }

    // ================================================================
    // Phase 16: NAT translate addresses
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXnatXlateV4ID, EXnatXlateV6ID};
        BuildV4Record(recBuf, ext, 4);
        h = (recordHeaderV4_t *)recBuf;
        MapV4RecordHandle(recordHandle, h, 1);

        EXnatXlateV4_t *natXlateIPv4 = GetExtension(h, EXnatXlateV4);
        EXnatXlateV6_t *natXlateIPv6 = GetExtension(h, EXnatXlateV6);

        uint32_t v4 = 0;
        inet_pton(PF_INET, "172.32.7.16", &v4);
        natXlateIPv4->xlateSrcAddr = ntohl(v4);
        inet_pton(PF_INET, "10.10.10.11", &v4);
        natXlateIPv4->xlateDstAddr = ntohl(v4);

        CheckFilter("src nat ip 172.32.7.16", recordHandle, 1);
        CheckFilter("src nat ip 172.32.7.15", recordHandle, 0);
        CheckFilter("dst nat ip 10.10.10.11", recordHandle, 1);
        CheckFilter("dst nat ip 10.10.10.12", recordHandle, 0);
        CheckFilter("nat ip 172.32.7.16", recordHandle, 1);
        CheckFilter("nat ip 10.10.10.11", recordHandle, 1);
        CheckFilter("nat ip 172.32.7.15", recordHandle, 0);
        CheckFilter("nat ip 10.10.10.12", recordHandle, 0);
        CheckFilter("src nat net 172.32.7.0/24", recordHandle, 1);
        CheckFilter("src nat net 172.32.8.0/24", recordHandle, 0);
        CheckFilter("dst nat net 10.10.10.0/24", recordHandle, 1);
        CheckFilter("dst nat net 10.10.11.0/24", recordHandle, 0);
        CheckFilter("nat net 172.32.7.0/24", recordHandle, 1);
        CheckFilter("nat net 10.10.10.0/24", recordHandle, 1);
        CheckFilter("nat ip in [10.10.10.10]", recordHandle, 0);

        uint64_t v6[2];
        inet_pton(PF_INET6, "fe80::2110:abcd:1235:ffff", v6);
        natXlateIPv6->xlateSrcAddr[0] = ntohll(v6[0]);
        natXlateIPv6->xlateSrcAddr[1] = ntohll(v6[1]);

        CheckFilter("src nat ip fe80::2110:abcd:1235:ffff", recordHandle, 1);
        CheckFilter("src nat ip fe80::2110:abcd:1235:fffe", recordHandle, 0);
    }

    // ================================================================
    // Phase 17: Net/prefix notation
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXipv6FlowID};
        BuildV4Record(recBuf, ext, 3);
        h = (recordHeaderV4_t *)recBuf;
        MapV4RecordHandle(recordHandle, h, 1);

        EXipv4Flow_t *ipv4 = GetExtension(h, EXipv4Flow);
        EXipv6Flow_t *ipv6 = GetExtension(h, EXipv6Flow);

        uint32_t v4 = 0;
        uint64_t v6[2];

        // IPv4 net tests - disable IPv6
        DisableExtension(recordHandle, EXipv6FlowID);
        inet_pton(PF_INET, "192.168.169.170", &v4);
        ipv4->srcAddr = ntohl(v4);
        inet_pton(PF_INET, "172.16.18.19", &v4);
        ipv4->dstAddr = ntohl(v4);
        CheckFilter("src net 192.168.169.0 255.255.255.0", recordHandle, 1);
        CheckFilter("src net 192.168.168.0 255.255.255.0", recordHandle, 0);
        CheckFilter("src net 192.168.169.0/24", recordHandle, 1);
        CheckFilter("src net 192.168.168.0/24", recordHandle, 0);
        CheckFilter("dst net 172.16.18.0/24", recordHandle, 1);
        CheckFilter("net 192.168.169.0/24", recordHandle, 1);
        CheckFilter("net 172.16.18.0/24", recordHandle, 1);

        // IPv6 net tests
        EnableExtension(recordHandle, EXipv6FlowID);
        DisableExtension(recordHandle, EXipv4FlowID);
        inet_pton(PF_INET6, "2001:620:0:ff::5c", v6);
        ipv6->srcAddr[0] = ntohll(v6[0]);
        ipv6->srcAddr[1] = ntohll(v6[1]);
        CheckFilter("src net 2001::/16", recordHandle, 1);
        CheckFilter("net 2001::/16", recordHandle, 1);
    }

    // ================================================================
    // Phase 18: NAT port translation
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXnatXlatePortID};
        BuildV4Record(recBuf, ext, 3);
        h = (recordHeaderV4_t *)recBuf;
        MapV4RecordHandle(recordHandle, h, 1);

        EXnatXlatePort_t *natXlatePort = GetExtension(h, EXnatXlatePort);

        natXlatePort->xlateSrcPort = 45123;
        natXlatePort->xlateDstPort = 59321;
        CheckFilter("src nat port 45123", recordHandle, 1);
        CheckFilter("dst nat port 59321", recordHandle, 1);
        CheckFilter("nat port 45123", recordHandle, 1);
        CheckFilter("nat port 59321", recordHandle, 1);
        CheckFilter("nat port > 59321", recordHandle, 0);

        CheckFilter("nat port in [59321 80 443]", recordHandle, 1);
        CheckFilter("nat port in [45123 80 443]", recordHandle, 1);
        CheckFilter("nat port in [143 80 443]", recordHandle, 0);
    }

    // ================================================================
    // Phase 19: NSEL ACL
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXnselAclID};
        BuildV4Record(recBuf, ext, 3);
        h = (recordHeaderV4_t *)recBuf;
        MapV4RecordHandle(recordHandle, h, 1);

        EXnselAcl_t *nselAcl = GetExtension(h, EXnselAcl);

        nselAcl->ingressAcl[0] = 100;
        nselAcl->ingressAcl[1] = 110;
        nselAcl->ingressAcl[2] = 120;
        nselAcl->egressAcl[0] = 200;
        nselAcl->egressAcl[1] = 210;
        nselAcl->egressAcl[2] = 220;

        CheckFilter("ingress acl 100", recordHandle, 1);
        CheckFilter("ingress acl 110", recordHandle, 1);
        CheckFilter("ingress acl 120", recordHandle, 1);
        CheckFilter("egress acl 200", recordHandle, 1);
        CheckFilter("egress acl 210", recordHandle, 1);
        CheckFilter("egress acl 220", recordHandle, 1);
        CheckFilter("ingress acl 200", recordHandle, 0);
        CheckFilter("egress acl 100", recordHandle, 0);

        CheckFilter("ingress acl > 100", recordHandle, 1);
        CheckFilter("ingress acl > 200", recordHandle, 0);
        CheckFilter("egress acl < 300", recordHandle, 1);
        CheckFilter("egress acl < 100", recordHandle, 0);
    }

    // ================================================================
    // Phase 20: NSEL User
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXnselUserID};
        BuildV4Record(recBuf, ext, 3);
        h = (recordHeaderV4_t *)recBuf;
        MapV4RecordHandle(recordHandle, h, 1);

        EXnselUser_t *nselUser = GetExtension(h, EXnselUser);

        strcpy(nselUser->username, "The nsel user");
        CheckFilter("asa user invalid", recordHandle, 0);
        CheckFilter("asa user 'The nsel user'", recordHandle, 1);
    }

    // ================================================================
    // Phase 21: NAT port block
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXnatPortBlockID};
        BuildV4Record(recBuf, ext, 3);
        h = (recordHeaderV4_t *)recBuf;
        MapV4RecordHandle(recordHandle, h, 1);

        EXgenericFlow_t *genericFlow = GetExtension(h, EXgenericFlow);
        EXnatPortBlock_t *natPortBlock = GetExtension(h, EXnatPortBlock);

        natPortBlock->blockStart = 1111;
        natPortBlock->blockEnd = 2222;
        natPortBlock->blockStep = 3333;
        natPortBlock->blockSize = 4444;

        CheckFilter("nat pblock start 1111", recordHandle, 1);
        CheckFilter("nat pblock start 2222", recordHandle, 0);

        CheckFilter("nat pblock end 2222", recordHandle, 1);
        CheckFilter("nat pblock end 3333", recordHandle, 0);

        CheckFilter("nat pblock step 3333", recordHandle, 1);
        CheckFilter("nat pblock step 4444", recordHandle, 0);

        CheckFilter("nat pblock size 4444", recordHandle, 1);
        CheckFilter("nat pblock size 5555", recordHandle, 0);

        genericFlow->srcPort = 1234;
        genericFlow->dstPort = 80;
        CheckFilter("src port in nat pblock", recordHandle, 1);
        genericFlow->srcPort = 1024;
        CheckFilter("src port in nat pblock", recordHandle, 0);
        CheckFilter("dst port in nat pblock", recordHandle, 0);
        genericFlow->srcPort = 1234;
        CheckFilter("port in nat pblock", recordHandle, 1);
        genericFlow->dstPort = 2121;
        CheckFilter("dst port in nat pblock", recordHandle, 1);
        CheckFilter("port in nat pblock", recordHandle, 1);
    }

    // ================================================================
    // Phase 22: Payload content
    // ================================================================
    {
        char *payloadString = "GET /index.html HTTP/1.1\r\n";
        uint32_t payloadLen = strlen(payloadString) + 1;
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXinPayloadID};
        BuildV4RecordWithPayload(recBuf, ext, 3, payloadLen);
        h = (recordHeaderV4_t *)recBuf;
        MapV4RecordHandle(recordHandle, h, 1);

        EXinPayload_t *payload = GetExtension(h, EXinPayload);
        strcpy((char *)payload->payload, payloadString);

        CheckFilter("payload content 'GET /index'", recordHandle, 1);
        CheckFilter("payload content index", recordHandle, 1);
        CheckFilter("payload content 'POST'", recordHandle, 0);

        CheckFilter("payload regex 'GET'", recordHandle, 1);
        CheckFilter("payload regex '(GET|POST)'", recordHandle, 1);
        CheckFilter("payload regex 'HT{1,3}P/[0-9].[0-9]'", recordHandle, 1);
        CheckFilter("payload regex \"HT{1,3}P/[0-9].[0-9]\"", recordHandle, 1);
        CheckFilter("payload regex 'QT{1,3}P/[0-9].[0-9]'", recordHandle, 0);
        CheckFilter("payload regex 'gET'i", recordHandle, 1);
        h->exporterID = 12345;
        CheckFilter("exporter sysid 12345", recordHandle, 1);
        CheckFilter("payload regex 'gET'i and exporter sysid 12345", recordHandle, 1);
    }

    // ================================================================
    // Phase 23: Tunnel addresses
    // ================================================================
    {
        // IPv4 tunnel test
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXtunnelV4ID};
        BuildV4Record(recBuf, ext, 3);
        h = (recordHeaderV4_t *)recBuf;
        MapV4RecordHandle(recordHandle, h, 1);

        EXtunnelV4_t *tunV4 = GetExtension(h, EXtunnelV4);

        uint32_t v4 = 0;

        inet_pton(PF_INET, "192.168.170.170", &v4);
        tunV4->srcAddr = ntohl(v4);

        inet_pton(PF_INET, "172.16.19.20", &v4);
        tunV4->dstAddr = ntohl(v4);

        CheckFilter("src tun ip 192.168.170.170", recordHandle, 1);
        CheckFilter("src tun ip 192.168.170.169", recordHandle, 0);
        CheckFilter("dst tun ip 172.16.19.20", recordHandle, 1);
        CheckFilter("dst tun ip 172.16.19.19", recordHandle, 0);

        CheckFilter("tun ip 172.16.19.20", recordHandle, 1);
        CheckFilter("tun ip 192.168.170.170", recordHandle, 1);
        CheckFilter("tun ip 192.168.170.169", recordHandle, 0);
        CheckFilter("tun ip 172.16.19.19", recordHandle, 0);

        tunV4->proto = IPPROTO_IPIP;
        CheckFilter("tun proto ipip", recordHandle, 1);
        CheckFilter("tun proto 4", recordHandle, 1);
        CheckFilter("tun proto 5", recordHandle, 0);

        CheckFilter("tun ip in [172.16.19.20]", recordHandle, 1);
        CheckFilter("tun ip in [192.168.170.170]", recordHandle, 1);
    }

    // ================================================================
    // Phase 23b: IPv6 Tunnel addresses
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXtunnelV6ID};
        BuildV4Record(recBuf, ext, 3);
        h = (recordHeaderV4_t *)recBuf;
        MapV4RecordHandle(recordHandle, h, 1);

        EXtunnelV6_t *tunV6 = GetExtension(h, EXtunnelV6);

        uint64_t v6[2];

        // IPv6 tunnel addresses
        inet_pton(PF_INET6, "fe80::2110:abcd:1235:ffff", v6);
        tunV6->srcAddr[0] = ntohll(v6[0]);
        tunV6->srcAddr[1] = ntohll(v6[1]);
        inet_pton(PF_INET6, "fe80::2110:abcd:1235:fffe", v6);
        tunV6->dstAddr[0] = ntohll(v6[0]);
        tunV6->dstAddr[1] = ntohll(v6[1]);

        CheckFilter("src tun ip fe80::2110:abcd:1235:ffff", recordHandle, 1);
        CheckFilter("src tun ip fe80::2110:abcd:1235:fffe", recordHandle, 0);
        CheckFilter("tun ip fe80::2110:abcd:1235:ffff", recordHandle, 1);

        CheckFilter("dst tun ip fe80::2110:abcd:1235:fffe", recordHandle, 1);
        CheckFilter("dst tun ip fe80::2110:abcd:1235:fffc", recordHandle, 0);
        CheckFilter("tun ip fe80::2110:abcd:1235:fffe", recordHandle, 1);

        tunV6->proto = IPPROTO_IPIP;
        CheckFilter("tun proto ipip", recordHandle, 1);
        CheckFilter("tun proto 4", recordHandle, 1);
        CheckFilter("tun proto 5", recordHandle, 0);
    }

    // ================================================================
    // Phase 24: SSL/TLS and JA3/JA4
    // ================================================================
    {
        char *payloadString = "dummy payload";
        uint32_t payloadLen = strlen(payloadString) + 1;
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXinPayloadID};
        BuildV4RecordWithPayload(recBuf, ext, 3, payloadLen);
        h = (recordHeaderV4_t *)recBuf;
        MapV4RecordHandle(recordHandle, h, 1);

        CheckFilter("payload ssl defined", recordHandle, 0);
        ssl_t ssl = {.type = CLIENTssl, .sniName = "example.com", .protocolVersion = 0x0303, .tlsCharVersion[0] = '1', .tlsCharVersion[1] = '2'};
        payloadHandle_t payloadHandle = {.ssl = &ssl};
        recordHandle->extensionList[EXinPayloadHandle] = &payloadHandle;
        CheckFilter("payload ssl defined", recordHandle, 1);
        CheckFilter("payload tls version 1.2", recordHandle, 1);
        CheckFilter("payload tls version 1.3", recordHandle, 0);
        CheckFilter("payload ssl sni example", recordHandle, 1);
        CheckFilter("payload ssl sni nonexist", recordHandle, 0);
        payloadHandle.ssl = NULL;
        CheckFilter("payload ssl sni example", recordHandle, 0);

        // ja3
        payloadHandle.ja3 = "123456789abcdef0123456789abcdef0";
        CheckFilter("payload ja3 123456789abcdef0123456789abcdef0", recordHandle, 1);
        CheckFilter("payload ja3 123456789abcdef0123456789abcdef1", recordHandle, 0);
        CheckFilter("payload ja3 023456789abcdef0123456789abcdef0", recordHandle, 0);
        CheckFilter("payload ja3 defined", recordHandle, 1);
        payloadHandle.ja3 = NULL;
        CheckFilter("payload ja3 defined", recordHandle, 0);

        // ja4
        ja4_t *ja4 = malloc(sizeof(ja4_t) + SIZEja4String + 1);
        if (ja4 == NULL) {
            LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            exit(255);
        }
        ja4->type = TYPE_JA4;
        strcpy(ja4->string, "t13d1516h2_8daaf6152771_b186095e22b6");
        payloadHandle.ja4 = ja4;
        CheckFilter("payload ja4 t13d1516h2_8daaf6152771_b186095e22b6", recordHandle, 1);
        CheckFilter("payload ja4 q13d1516h2_8daaf6152771_b186095e22b6", recordHandle, 0);
        CheckFilter("payload ja4 t13d1516h2_8daaf6152771_ccc6095e22b6", recordHandle, 0);
        CheckFilter("payload ja4 defined", recordHandle, 1);
        payloadHandle.ja4 = NULL;
        CheckFilter("payload ja4 defined", recordHandle, 0);

#ifdef BUILD_JA4
        // ja4s
        ja4->type = TYPE_JA4S;
        payloadHandle.ja4 = ja4;
        strcpy(ja4->string, "t120400_C030_4e8089608790");
        CheckFilter("payload ja4s t120400_C030_4e8089608790", recordHandle, 1);
        CheckFilter("payload ja4s q120400_C030_4e8089608790", recordHandle, 0);
        CheckFilter("payload ja4s t120400_C030_cccc89608790", recordHandle, 0);
        CheckFilter("payload ja4 defined", recordHandle, 1);
        payloadHandle.ja4 = NULL;
        CheckFilter("payload ja4 defined", recordHandle, 0);
#endif
        recordHandle->extensionList[EXinPayloadHandle] = NULL;
        free(ja4);
    }

    // ================================================================
    // Phase 25: Geo location (local extension)
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID};
        BuildV4Record(recBuf, ext, 2);
        h = (recordHeaderV4_t *)recBuf;
        MapV4RecordHandle(recordHandle, h, 1);

        char *ptr = (char *)recordHandle;
        ptr[OFFgeoSrcIP] = 'C';
        ptr[OFFgeoSrcIP + 1] = 'H';

        ptr[OFFgeoDstIP] = 'D';
        ptr[OFFgeoDstIP + 1] = 'E';

        ptr[OFFgeoSrcNatIP] = 'U';
        ptr[OFFgeoSrcNatIP + 1] = 'S';

        ptr[OFFgeoDstNatIP] = 'A';
        ptr[OFFgeoDstNatIP + 1] = 'T';

        CheckFilter("src geo CH", recordHandle, 1);
        CheckFilter("src geo CD", recordHandle, 0);
        CheckFilter("geo CH", recordHandle, 1);
        CheckFilter("geo DE", recordHandle, 1);
        CheckFilter("geo CD", recordHandle, 0);

        CheckFilter("dst geo AB", recordHandle, 0);
        CheckFilter("dst geo DE", recordHandle, 1);
        CheckFilter("dst geo de", recordHandle, 1);

        CheckFilter("src nat geo US", recordHandle, 1);
        CheckFilter("dst nat geo AT", recordHandle, 1);
        CheckFilter("dst nat geo DE", recordHandle, 0);
        CheckFilter("nat geo US", recordHandle, 1);
        CheckFilter("nat geo AT", recordHandle, 1);
    }

    // ================================================================
    // Phase 26: Observation
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXobservationID};
        BuildV4Record(recBuf, ext, 3);
        h = (recordHeaderV4_t *)recBuf;
        MapV4RecordHandle(recordHandle, h, 1);

        EXobservation_t *observation = GetExtension(h, EXobservation);

        observation->pointID = 0xabcabcabc;
        observation->domainID = 0xcabc;

        CheckFilter("observation domain id 0xcabc", recordHandle, 1);
        CheckFilter("observation domain id 12345", recordHandle, 0);

        CheckFilter("observation point id 0xabcabcabc", recordHandle, 1);
        CheckFilter("observation point id 12345", recordHandle, 0);
    }

    // ================================================================
    // Phase 27: VRF
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXvrfID};
        BuildV4Record(recBuf, ext, 3);
        h = (recordHeaderV4_t *)recBuf;
        MapV4RecordHandle(recordHandle, h, 1);

        EXvrf_t *vrf = GetExtension(h, EXvrf);

        vrf->ingressVrf = 0xAAAA;
        vrf->egressVrf = 0xBBBB;
        CheckFilter("ingress vrf 0xAAAA", recordHandle, 1);
        CheckFilter("ingress vrf 100", recordHandle, 0);

        CheckFilter("egress vrf 0xBBBB", recordHandle, 1);
        CheckFilter("egress vrf 0xAAAA", recordHandle, 0);
    }

    // ================================================================
    // Phase 28: IP Info (TTL)
    // ================================================================
    {
        uint32_t ext[] = {EXgenericFlowID, EXipv4FlowID, EXipInfoID};
        BuildV4Record(recBuf, ext, 3);
        h = (recordHeaderV4_t *)recBuf;
        MapV4RecordHandle(recordHandle, h, 1);

        EXipInfo_t *ipInfo = GetExtension(h, EXipInfo);

        ipInfo->minTTL = 36;
        ipInfo->maxTTL = 48;
        ipInfo->fragmentFlags = flagDF;
        CheckFilter("min ttl 36", recordHandle, 1);
        CheckFilter("min ttl > 30", recordHandle, 1);
        CheckFilter("min ttl < 37", recordHandle, 1);
        CheckFilter("min ttl 64", recordHandle, 0);
        CheckFilter("min ttl < 30", recordHandle, 0);

        CheckFilter("max ttl 48", recordHandle, 1);
        CheckFilter("max ttl > 40", recordHandle, 1);
        CheckFilter("max ttl < 50", recordHandle, 1);
        CheckFilter("max ttl 64", recordHandle, 0);
        CheckFilter("max ttl < 30", recordHandle, 0);
        CheckFilter("max ttl 48", recordHandle, 1);

        CheckFilter("ttl 36", recordHandle, 1);
        CheckFilter("ttl 48", recordHandle, 1);
        CheckFilter("ttl > 40", recordHandle, 1);
        CheckFilter("ttl < 50", recordHandle, 1);
        CheckFilter("ttl 64", recordHandle, 0);
        CheckFilter("ttl < 30", recordHandle, 0);

        CheckFilter("ttl equal", recordHandle, 0);
        CheckFilter("not ttl equal", recordHandle, 1);
        ipInfo->maxTTL = 36;
        CheckFilter("ttl equal", recordHandle, 1);
        CheckFilter("not ttl equal", recordHandle, 0);
    }

    free(recBuf);
    free(recordHandle);
    printf("DONE.\n");
}  // End of runTest

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    runTest();
    return 0;
}
