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

#include "userio.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *protoList[] = {
    "0",      // 0  masked out - no protocol info - set to '0'
    "ICMP",   // 1  Internet Control Message
    "IGMP",   // 2  Internet Group Management
    "GGP",    // 3  Gateway-to-Gateway
    "IPIP",   // 4  IP in IP (encapsulation)
    "ST",     // 5  Stream
    "TCP",    // 6  Transmission Control
    "CBT",    // 7  CBT
    "EGP",    // 8  Exterior Gateway Protocol
    "IGP",    // 9  any private interior gateway (used by Cisco for their IGRP)
    "BBN",    // 10 BBN RCC Monitoring
    "NVPII",  // 11 Network Voice Protocol
    "PUP",    // 12 PUP
    "ARGUS",  // 13 ARGUS
    "ENCOM",  // 14 EMCON
    "XNET",   // 15 Cross Net Debugger
    "CHAOS",  // 16 Chaos
    "UDP",    // 17 User Datagram
    "MUX",    // 18 Multiplexing
    "DCN",    // 19 DCN Measurement Subsystems
    "HMP",    // 20 Host Monitoring
    "PRM",    // 21 Packet Radio Measurement
    "XNS",    // 22 XEROX NS IDP
    "Trnk1",  // 23 Trunk-1
    "Trnk2",  // 24 Trunk-2
    "Leaf1",  // 25 Leaf-1
    "Leaf2",  // 26 Leaf-2
    "RDP",    // 27 Reliable Data Protocol
    "IRTP",   // 28 Internet Reliable Transaction
    "ISO-4",  // 29 ISO Transport Protocol Class 4
    "NETBK",  // 30 Bulk Data Transfer Protocol
    "MFESP",  // 31 MFE Network Services Protocol
    "MEINP",  // 32 MERIT Internodal Protocol
    "DCCP",   // 33 Datagram Congestion Control Protocol
    "3PC",    // 34 Third Party Connect Protocol
    "IDPR",   // 35 Inter-Domain Policy Routing Protocol
    "XTP",    // 36 XTP
    "DDP",    // 37 Datagram Delivery Protocol
    "IDPR",   // 38 IDPR Control Message Transport Proto
    "TP++",   // 39 TP++ Transport Protocol
    "IL",     // 40 IL Transport Protocol
    "IPv6",   // 41 IPv6
    "SDRP",   // 42 Source Demand Routing Protocol
    "Rte6",   // 43 Routing Header for IPv6
    "Frag6",  // 44 Fragment Header for IPv6
    "IDRP",   // 45 Inter-Domain Routing Protocol
    "RSVP",   // 46 Reservation Protocol
    "GRE",    // 47 General Routing Encapsulation
    "MHRP",   // 48 Mobile Host Routing Protocol
    "BNA",    // 49 BNA
    "ESP",    // 50 Encap Security Payload
    "AH",     // 51 Authentication Header
    "INLSP",  // 52 Integrated Net Layer Security  TUBA
    "SWIPE",  // 53 IP with Encryption
    "NARP",   // 54 NBMA Address Resolution Protocol
    "MOBIL",  // 55 IP Mobility
    "TLSP",   // 56 Transport Layer Security Protocol
    "SKIP",   // 57 SKIP
    "ICMP6",  // 58 ICMP for IPv6
    "NOHE6",  // 59 No Next Header for IPv6
    "OPTS6",  // 60 Destination Options for IPv6
    "HOST",   // 61 any host internal protocol
    "CFTP",   // 62 CFTP
    "NET",    // 63 any local network
    "SATNT",  // 64 SATNET and Backroom EXPAK
    "KLAN",   // 65 Kryptolan
    "RVD",    // 66 MIT Remote Virtual Disk Protocol
    "IPPC",   // 67 Internet Pluribus Packet Core
    "FS",     // 68 any distributed file system
    "SATM",   // 69 SATNET Monitoring
    "VISA",   // 70 VISA Protocol
    "IPCV",   // 71 Internet Packet Core Utility
    "CPNX",   // 72 Computer Protocol Network Executive
    "CPHB",   // 73 Computer Protocol Heart Beat
    "WSN",    // 74 Wang Span Network
    "PVP",    // 75 Packet Video Protocol
    "BSATM",  // 76 Backroom SATNET Monitoring
    "SUNND",  // 77 SUN ND PROTOCOL-Temporary
    "WBMON",  // 78 WIDEBAND Monitoring
    "WBEXP",  // 79 WIDEBAND EXPAK
    "ISOIP",  // 80 ISO Internet Protocol
    "VMTP",   // 81 VMTP
    "SVMTP",  // 82 SECURE-VMTP
    "VINES",  // 83 VINES
    "TTP",    // 84 TTP
    "NSIGP",  // 85 NSFNET-IGP
    "DGP",    // 86 Dissimilar Gateway Protocol
    "TCF",    // 87 TCF
    "EIGRP",  // 88 EIGRP
    "OSPF",   // 89 OSPFIGP
    "S-RPC",  // 90 Sprite RPC Protocol
    "LARP",   // 91 Locus Address Resolution Protocol
    "MTP",    // 92 Multicast Transport Protocol
    "AX.25",  // 93 AX.25 Frames
    "OS",     // 94 KA9Q NOS compatible IP over IP tunneling
    "MICP",   // 95 Mobile Internetworking Control Protocol
    "SCCSP",  // 96 Semaphore Communications Sec. Protocol
    "ETHIP",  // 97 Ethernet-within-IP Encapsulation
    "ENCAP",  // 98 Encapsulation Header
    "99",     // 99 any private encryption scheme
    "GMTP",   // 100    GMTP
    "IFMP",   // 101    Ipsilon Flow Management Protocol
    "PNNI",   // 102    PNNI over IP
    "PIM",    // 103    Protocol Independent Multicast
    "ARIS",   // 104    ARIS
    "SCPS",   // 105    SCPS
    "QNX",    // 106    QNX
    "A/N",    // 107    Active Networks
    "IPcmp",  // 108    IP Payload Compression Protocol
    "SNP",    // 109    Sitara Networks Protocol
    "CpqPP",  // 110    Compaq Peer Protocol
    "IPXIP",  // 111    IPX in IP
    "VRRP",   // 112    Virtual Router Redundancy Protocol
    "PGM",    // 113    PGM Reliable Transport Protocol
    "0hop",   // 114    any 0-hop protocol
    "L2TP",   // 115    Layer Two Tunneling Protocol
    "DDX",    // 116    D-II Data Exchange (DDX)
    "IATP",   // 117    Interactive Agent Transfer Protocol
    "STP",    // 118    Schedule Transfer Protocol
    "SRP",    // 119    SpectraLink Radio Protocol
    "UTI",    // 120    UTI
    "SMP",    // 121    Simple Message Protocol
    "SM",     // 122    SM
    "PTP",    // 123    Performance Transparency Protocol
    "ISIS4",  // 124    ISIS over IPv4
    "FIRE",   // 125    FIRE
    "CRTP",   // 126    Combat Radio Transport Protocol
    "CRUDP",  // 127    Combat Radio User Datagram
    "128",    // 128    SSCOPMCE
    "IPLT",   // 129    IPLP
    "SPS",    // 130    Secure Packet Shield
    "PIPE",   // 131    Private IP Encapsulation within IP
    "SCTP",   // 132    Stream Control Transmission Protocol
    "FC",     // 133    Fibre Channel
    "134",    // 134    RSVP-E2E-IGNORE
    "MHEAD",  // 135    Mobility Header
    "UDP-L",  // 136    UDPLite
    "MPLS",   // 137    MPLS-in-IP
    NULL      // End of list
};
#define NUMPROTOS 138

static struct fwdStatus_def_s {
    uint32_t id;
    char *name;
    char *description;
} fwdStatusList[] = {{0, "Ukwn", "Unknown"},
                     {1, "Forw", "Normal forwarding"},
                     {2, "Frag", "Fragmented"},
                     {16, "Drop", "Drop"},
                     {17, "DaclD", "Drop ACL deny"},
                     {18, "Daclp", "Drop ACL drop"},
                     {19, "Noroute", "Unroutable"},
                     {20, "Dadj", "Drop Adjacency"},
                     {21, "Dfrag", "Drop Fragmentation & DF set"},
                     {22, "Dbadh", "Drop Bad header checksum"},
                     {23, "Dbadtlen", "Drop Bad total Length"},
                     {24, "Dbadhlen", "Drop Bad Header Length"},
                     {25, "DbadTTL", "Drop bad TTL"},
                     {26, "Dpolicy", "Drop Policer"},
                     {27, "Dwred", "Drop WRED"},
                     {28, "Drpf", "Drop RPF"},
                     {29, "Dforus", "Drop For us"},
                     {30, "DbadOf", "Drop Bad output interface"},
                     {31, "Dhw", "Drop Hardware"},
                     {128, "Term", "Terminate"},
                     {129, "Tadj", "Terminate Punt Adjacency"},
                     {130, "TincAdj", "Terminate Incomplete Adjacency"},
                     {131, "Tforus", "Terminate For us"},
                     {0, NULL, NULL}};

static struct fwEvent_s {
    int id;
    char *eventName;
} fwEventList[] = {
#ifdef JUNOS
    /* Juniper has its own event table */
    {JUNOS_EVENT_IGNORE, "IGNORE"},
    {JUNOS_NAT44_CREATE, "CREATE"},
    {JUNOS_NAT44_DELETE, "DELETE"},
    {JUNOS_NAT_EXHAUSTED, "EXHAUSTED"},
    {JUNOS_NAT64_CREATE, "CREATE"},
    {JUNOS_NAT64_DELETE, "DELETE"},
    {JUNOS_NAT44_BIN_CREATE, "CREATE"},
    {JUNOS_NAT44_BIN_DELETE, "DELETE"},
    {JUNOS_NAT64_BIN_CREATE, "CREATE"},
    {JUNOS_NAT64BIN_DELETE, "DELETE"},
    {JUNOS_NATPORTS_EHAUSTED, "EXHAUSTED"},
    {JUNOS_NAT_QUOTA_EXCEEDED, "QUOTA EXCEEDED"},
    {JUNOS_NAT_ADDR_CREATE, "CREATE"},
    {JUNOS_NAT_ADDR_DELETE, "DELETE"},
    {JUNOS_NAT_PBLOCK_ALLOC, "NAT PORT ALLOC"},
    {JUNOS_NAT_PBLOCK_RELEASE, "NAT PORT RELEASE"},
    {JUNOS_NAT_PBLOCK_ACTIVE, "NAT PORT ACTIVE"},
#else
    {NSEL_EVENT_IGNORE, "IGNORE"},
    {NSEL_EVENT_CREATE, "CREATE"},
    {NSEL_EVENT_DELETE, "DELETE"},
    {NSEL_EVENT_DENIED, "DENIED"},
    {NSEL_EVENT_ALERT, "ALERT"},
    {NSEL_EVENT_UPDATE, "UPDATE"},
#endif
    {0, NULL}};

static struct fwXEvent_s {
    int id;
    char *eventName;
} fwXEventList[] = {{NSEL_XEVENT_IGNORE, "IGNORE"}, {NSEL_XEVENT_IACL, "I-ACL"},
                    {NSEL_XEVENT_IACL, "ingress"},  {NSEL_XEVENT_EACL, "E-ACL"},
                    {NSEL_XEVENT_EACL, "egress"},   {NSEL_XEVENT_DENIED, "DENY"},
                    {NSEL_XEVENT_DENIED, "access"}, {NSEL_XEVENT_DENIED, "interface"},
                    {NSEL_XEVENT_NOSYN, "NOSYN"},   {0, NULL}};

// RFC 8158, section 4.3, "Definition of NAT events"
/*
          +-------+------------------------------------+
          | Value | Event Name                         |
          +-------+------------------------------------+
          | 0     | Reserved                           |
          | 1     | NAT translation create (Historic)  |
          | 2     | NAT translation delete (Historic)  |
          | 3     | NAT Addresses exhausted            |
          | 4     | NAT44 session create               |
          | 5     | NAT44 session delete               |
          | 6     | NAT64 session create               |
          | 7     | NAT64 session delete               |
          | 8     | NAT44 BIB create                   |
          | 9     | NAT44 BIB delete                   |
          | 10    | NAT64 BIB create                   |
          | 11    | NAT64 BIB delete                   |
          | 12    | NAT ports exhausted                |
          | 13    | Quota Exceeded                     |
          | 14    | Address binding create             |
          | 15    | Address binding delete             |
          | 16    | Port block allocation              |
          | 17    | Port block de-allocation           |
          | 18    | Threshold Reached                  |
          +-------+------------------------------------+
*/

static struct natEvent_s {
    char *sname;
    char *lname;
} natEvents[MAX_NAT_EVENTS] = {{"INVALID", "INVALID"},
                               {"ADD", "NAT translation create"},
                               {"DELETE", "NAT translation delete"},
                               {"EXHAUST", "NAT Addresses exhausted"},
                               {"ADD44", "NAT44 session create"},
                               {"DEL44", "NAT44 session delete"},
                               {"ADD64", "NAT64 session create"},
                               {"DEL64", "NAT64 session delete"},
                               {"ADD44BIB", "NAT44 BIB create"},
                               {"DEL44BIB", "NAT44 BIB delete"},
                               {"ADD64BIB", "NAT64 BIB create"},
                               {"DEL64BIB", "NAT64 BIB delete"},
                               {"PEXHAUST", "NAT ports exhausted"},
                               {"QUOTAEXH", "Quota Exceeded"},
                               {"ADDADDR", "Address binding create"},
                               {"DELADDR", "Address binding delete"},
                               {"ADDPBLK", "Port block allocation"},
                               {"DELPBLK", "Port block de-allocation"},
                               {"THRESHLD", "Threshold Reached"}};

// definitions for OpenBSD pflog
const char *pf_actions[] = {"pass",  "block",    "scrub", "noscrub", "nat",    "nonat", "binat", "nobinat", "rdr",
                            "nordr", "synblock", "defer", "match",   "divert", "rt",    "afrt",  NULL};

const char *pf_reasons[] = {"match",         "bad-offset", "fragment",  "short",       "normalize",      "memory)",
                            "bad-timestamp", "congestion", "ip-option", "proto-cksum", "state-mismatch", "state-insert",
                            "state-limit",   "src-limit",  "synproxy",  "translate",   "no-route",       NULL};

int ProtoNum(char *protoString) {
    int len = strlen(protoString);
    if (len >= 6) return -1;

    int i = 0;
    while (protoList[i] != NULL && strncasecmp(protoString, protoList[i], len) != 0) i++;
    return protoList[i] != NULL ? i : -1;
}  // End of ProtoNum

char *ProtoString(uint8_t protoNum, uint32_t plainNumbers) {
    static char s[16];

    if (protoNum >= NUMPROTOS || plainNumbers) {
        snprintf(s, 15, "%-5i", protoNum);
        s[15] = '\0';
        return s;
    } else {
        return protoList[protoNum];
    }

}  // End of ProtoString

void Protoinfo(char *protoString) {
    printf("Valid protocols:\n");

    int i = 0;
    while (protoList[i] != NULL) {
        printf("%3d: %s\n", i, protoList[i]);
        i++;
    }

}  // End of ProtoInfo

int fwdStatusNum(char *fwdString) {
    int len = strlen(fwdString);
    if (len >= 16) return -1;

    for (int i = 0; fwdStatusList[i].name != NULL; i++) {
        if (strcasecmp(fwdString, fwdStatusList[i].name) == 0) {
            return fwdStatusList[i].id;
        }
    }

    return -1;
}  // End of fwdStatusNum

void fwdStatusInfo(void) {
    printf("Recognized forward status strings:\n");
    for (int i = 0; fwdStatusList[i].name != NULL; i++) {
        printf("%s  %s\n", fwdStatusList[i].name, fwdStatusList[i].description);
    }
}  // End of fwdStatusNum

int fwEventID(char *event) {
    int i = 0;
    while (fwEventList[i].eventName) {
        if (strcasecmp(event, fwEventList[i].eventName) == 0) {
            return fwEventList[i].id;
        }
        i++;
    }
    return -1;
}  // End of fwEventID

char *fwEventString(int event) {
    int i = 0;
    while (fwEventList[i].eventName) {
        if (event == fwEventList[i].id) {
            return fwEventList[i].eventName;
        }
        i++;
    }

    // unknow event string
    static char s[16];
    snprintf(s, 15, "%u-Unknw", event);
    s[15] = '\0';
    return s;
}  // End of fwEventID

int fwXEventID(char *event) {
    int i = 0;
    while (fwXEventList[i].eventName) {
        if (strcasecmp(event, fwXEventList[i].eventName) == 0) {
            return fwXEventList[i].id;
        }
        i++;
    }
    return -1;
}  // End of fwXEventID

char *fwXEventString(int xeventID) {
    int i = 0;
    while (fwXEventList[i].eventName) {
        if (fwXEventList[i].id == xeventID) {
            return fwXEventList[i].eventName;
        }
        i++;
    }

    // unknow event string
    static char s[16];
    snprintf(s, 15, "%u", xeventID);
    s[15] = '\0';
    return s;

}  // End of fwXEventString

int natEventNum(char *natString) {
    int len = strlen(natString);
    if (len >= 16) return -1;

    for (int i = 0; i < MAX_NAT_EVENTS; i++) {
        if (strcasecmp(natEvents[i].sname, natString) == 0) {
            return i;
        }
    }

    return -1;
}  // End of natEventNum

char *natEventString(int event, int longName) {
    if (event >= MAX_NAT_EVENTS) {
        // unknow event string
        static char s[32] = {0};
        snprintf(s, 31, "%u-Unknown", event);
        return s;
    }
    return longName ? natEvents[event].lname : natEvents[event].sname;

}  // End of natEventString

void natEventInfo(void) {
    printf("Valid NAT events:\n");
    for (int i = 1; i < MAX_NAT_EVENTS; i++) {
        printf("%s for %s\n", natEvents[i].sname, natEvents[i].lname);
    }

}  // End of natEventInfo

int IsMD5(char *string) {
    int i = 0;
    for (i = 0; i < 32; i++) {
        char c = string[i];
        if (c == '\0' || !isxdigit(c)) return 0;
    }
    return string[i] == '\0';

}  // End of IsMD5

const char *pfAction(int action) {
    const char *a = "<undef>";
    if (action >= 0 && action <= 15) a = pf_actions[action];
    return a;
}  // End of pfAction

int pfActionNr(char *action) {
    int i = 0;
    while (pf_actions[i] && strcasecmp(pf_actions[i], action) != 0) i++;
    return pf_actions[i] != NULL ? i : -1;
}  // End of pfActionNr

void pfListActions(void) {
    int i = 0;
    while (pf_actions[i]) {
        printf("%s ", pf_actions[i++]);
    }
    printf("\n");
}  // End of pfListActions

const char *pfReason(int reason) {
    const char *r = "<undef>";
    if (reason >= 0 && reason <= 16) r = pf_reasons[reason];
    return r;
}  // End of pfReason

int pfReasonNr(char *reason) {
    int i = 0;
    while (pf_reasons[i] && strcasecmp(pf_reasons[i], reason) != 0) i++;
    return pf_reasons[i] != NULL ? i : -1;
}  // End of pfReasonNr

void pfListReasons(void) {
    int i = 0;
    while (pf_reasons[i]) {
        printf("%s ", pf_reasons[i++]);
    }
    printf("\n");
}  // End of pfListReasons