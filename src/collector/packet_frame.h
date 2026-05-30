/*
 *  Copyright (c) 2026, Peter Haag
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

/*
 * packet_frame.h
 *
 * Decoder for IPFIX IE #315 dataLinkFrameSection.
 *
 * Called from ipfix.c after PipelineRun() stores the raw captured frame into
 * EXpacketFrame.  The decoder overwrites the current v4 flow record in-place
 * with a fully-decoded flow record built from the frame's L2/L3/L4/tunnel
 * headers and payload — mirroring what nfpcapd produces from live pcap.
 *
 * Designed for debugging / inline-monitoring use.  Supports:
 *   Ethernet (IPFIX linkType 1 / DLT_EN10MB)
 *   Raw IPv4  (IPFIX linkType 11)
 *   Raw IPv6  (IPFIX linkType 12)
 *
 * VLAN stacking, MPLS, PPPoE, GRE, ERSPAN, IP-in-IP tunnels, fragmentation
 * reassembly is NOT performed (fragments are decoded as partial records).
 * All layers are safe against truncated/malformed frames via cursor bounds.
 */

#ifndef _PACKET_FRAME_H
#define _PACKET_FRAME_H 1

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <sys/types.h>

#include "flowsource.h"
#include "nfxV4.h"

/*
 * IPFIX dataLinkFrameType (#408) values per IANA registry
 * (same numbering as pcap DLT_ for Ethernet and raw IP)
 */
#define DATALINK_ETHERNET 1  /* IPFIX linkType = 1  → IEEE 802.3 Ethernet */
#define DATALINK_RAW_IPV4 11 /* IPFIX linkType = 11 → Raw IPv4 */
#define DATALINK_RAW_IPV6 12 /* IPFIX linkType = 12 → Raw IPv6 */

/*
 * DecodePacketFrame()
 *
 * Decodes the raw frame stored in EXpacketFrame and overwrites the v4 record
 * at outBuff with a fully-populated flow record.
 *
 * Parameters:
 *   outBuff       – pointer to start of the current v4 record in the data
 *                   block.  Will be overwritten from byte 0.
 *   buffAvail     – bytes available from outBuff to end of data block.
 *   frameData     – pointer to raw frame bytes (copied from EXpacketFrame
 *                   before the caller overwrites the output buffer).
 *   frameLen      – number of valid bytes in frameData.
 *   linkType      – IPFIX dataLinkFrameType (#408): 1=Ethernet, 11=IPv4,
 *                   12=IPv6.
 *   origFrameSize – original captured frame size from EXpacketMeta.frameSize
 *                   (used to detect truncation).
 *   msecReceived  – millisecond receive timestamp from the IPFIX header.
 *   exporterSysID – exporter system ID for the record header.
 *   fs            – flow source (for statistics update and exporter IP).
 *
 * Returns:
 *   > 0  : size of the new record written into outBuff (caller adds to
 *           rawSize / numRecords).
 *   0    : frame could not be decoded (unknown/unsupported link type,
 *          truncated before IP header, etc.). Caller should discard the
 *          record and not advance rawSize.
 */
int DecodePacketFrame(void *outBuff, size_t buffAvail, const uint8_t *frameData, uint32_t frameLen, uint16_t linkType, uint16_t origFrameSize,
                      uint64_t msecReceived, uint16_t exporterSysID, FlowSource_t *fs);

#endif /* _PACKET_FRAME_H */
