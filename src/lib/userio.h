/*
 *  Copyright (c) 2023, Peter Haag
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

#ifndef _USERIO_H
#define _USERIO_H 1

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

// events
#ifdef JUNOS
// Juniper uses a differet mapping of events
// https://www.juniper.net/documentation/us/en/software/junos/flow-monitoring/topics/concept/services-logging-flowmonitoring-format-nat-events.html

#define JUNOS_EVENT_IGNORE 0
#define JUNOS_NAT44_CREATE 1
#define JUNOS_NAT44_DELETE 2
#define JUNOS_NAT_EXHAUSTED 3
#define JUNOS_NAT64_CREATE 4
#define JUNOS_NAT64_DELETE 5
#define JUNOS_NAT44_BIN_CREATE 6
#define JUNOS_NAT44_BIN_DELETE 7
#define JUNOS_NAT64_BIN_CREATE 8
#define JUNOS_NAT64BIN_DELETE 9
#define JUNOS_NATPORTS_EHAUSTED 10
#define JUNOS_NAT_QUOTA_EXCEEDED 11
#define JUNOS_NAT_ADDR_CREATE 12
#define JUNOS_NAT_ADDR_DELETE 13
#define JUNOS_NAT_PBLOCK_ALLOC 14
#define JUNOS_NAT_PBLOCK_RELEASE 15
#define JUNOS_NAT_PBLOCK_ACTIVE 16

#else
// https://www.cisco.com/c/en/us/td/docs/security/asa/special/netflow/asa_netflow.html

#define NSEL_EVENT_IGNORE 0LL
#define NSEL_EVENT_CREATE 1LL
#define NSEL_EVENT_DELETE 2LL
#define NSEL_EVENT_DENIED 3LL
#define NSEL_EVENT_ALERT 4LL
#define NSEL_EVENT_UPDATE 5LL
#endif

// extended events
#define NSEL_XEVENT_IGNORE 0
#define NSEL_XEVENT_IACL 1001
#define NSEL_XEVENT_EACL 1002
#define NSEL_XEVENT_DENIED 1003
#define NSEL_XEVENT_NOSYN 1004

// Max number of nat events
#define MAX_NAT_EVENTS 19

#define SHORTNAME 0
#define LONGNAME 1

int ProtoNum(char *protoString);

char *ProtoString(uint8_t protoNum, uint32_t plainNumbers);

void Protoinfo(char *protoString);

int fwdStatusNum(char *fwdString);

void fwdStatusInfo(void);

int fwEventID(char *event);

char *fwEventString(int event);

int fwXEventID(char *event);

char *fwXEventString(int xeventID);

int natEventNum(char *natString);

char *natEventString(int event, int longName);

void natEventInfo(void);

int IsMD5(char *string);

const char *pfAction(int action);

int pfActionNr(char *action);

void pfListActions(void);

const char *pfReason(int reason);

int pfReasonNr(char *reason);

void pfListReasons(void);

#endif