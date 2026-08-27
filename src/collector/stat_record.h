/*
 *  Copyright (c) 2026, Peter Haag
 *  All rights reserved.
 */

/*
 * Record-derived stat_record accounting shared by the file post-filter and
 * the native-UDP receiver.  Both consumers see final V4 records, so keeping
 * this in one place prevents their packet/byte/aggregate-flow semantics from
 * drifting apart.
 */

#ifndef _COLLECTOR_STAT_RECORD_H
#define _COLLECTOR_STAT_RECORD_H 1

#include <netinet/in.h>
#include <stdint.h>

#include "nffileV3/nffileV3.h"
#include "nfxV4.h"

static inline void UpdateRecordStat(stat_record_t *stat, const EXgenericFlow_t *genericFlow, const EXcntFlow_t *cntFlow) {
    if (!genericFlow) return;

    uint64_t inPackets = genericFlow->inPackets;
    uint64_t inBytes = genericFlow->inBytes;
    uint64_t outPackets = cntFlow ? cntFlow->outPackets : 0;
    uint64_t outBytes = cntFlow ? cntFlow->outBytes : 0;
    uint64_t flows = (cntFlow && cntFlow->flows) ? cntFlow->flows : 1;

    switch (genericFlow->proto) {
        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6:
            stat->numflows_icmp += flows;
            stat->numpackets_icmp += inPackets + outPackets;
            stat->numbytes_icmp += inBytes + outBytes;
            break;
        case IPPROTO_TCP:
            stat->numflows_tcp += flows;
            stat->numpackets_tcp += inPackets + outPackets;
            stat->numbytes_tcp += inBytes + outBytes;
            break;
        case IPPROTO_UDP:
            stat->numflows_udp += flows;
            stat->numpackets_udp += inPackets + outPackets;
            stat->numbytes_udp += inBytes + outBytes;
            break;
        default:
            stat->numflows_other += flows;
            stat->numpackets_other += inPackets + outPackets;
            stat->numbytes_other += inBytes + outBytes;
    }
    stat->numflows += flows;
    stat->numpackets += inPackets + outPackets;
    stat->numbytes += inBytes + outBytes;

    if (stat->msecFirstSeen == 0 || genericFlow->msecFirst < stat->msecFirstSeen) stat->msecFirstSeen = genericFlow->msecFirst;
    if (genericFlow->msecLast > stat->msecLastSeen) stat->msecLastSeen = genericFlow->msecLast;
}

#endif  // _COLLECTOR_STAT_RECORD_H
