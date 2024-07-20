/*
 *  Copyright (c) 2022, Peter Haag
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

#ifndef _ID_H
#define _ID_H 1

// Legacy records
#define CommonRecordV0Type 1
#define ExtensionMapType 2
#define PortHistogramType 3
#define BppHistogramType 4
#define LegacyRecordType1 5
#define LegacyRecordType2 6

// exporter/sampler types
#define ExporterInfoRecordType 7
#define ExporterStatRecordType 8

// legacy sampler
#define SamplerLegacyRecordType 9

// new extended Common Record as intermediate solution to overcome 255 exporters
// requires moderate changes till 1.7
#define CommonRecordType 10

// Identifier for new V3Record
#define V3Record 11

// record type definition
#define NbarRecordType 12
#define IfNameRecordType 13
#define VrfNameRecordType 14

#define SamplerRecordType 15

#define MaxRecordID 15

// array record types
// maxmind
#define LocalInfoElementID 1
#define IPV4treeElementID 2
#define IPV6treeElementID 3
#define ASV4treeElementID 4
#define ASV6treeElementID 5
#define ASOrgtreeElementID 7
// tor
#define TorTreeElementID 6

#endif