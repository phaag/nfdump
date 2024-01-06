/*
 *  Copyright (c) 2019-2023, Peter Haag
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

#include "output_util.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "config.h"
#include "nfdump.h"
#include "nffile.h"

#define NumProtos 138
static char *protoList[NumProtos] = {
    "0",      // 0 	masked out - no protocol info - set to '0'
    "ICMP",   // 1 	Internet Control Message
    "IGMP",   // 2	Internet Group Management
    "GGP",    // 3	Gateway-to-Gateway
    "IPIP",   // 4	IP in IP (encapsulation)
    "ST",     // 5	Stream
    "TCP",    // 6	Transmission Control
    "CBT",    // 7	CBT
    "EGP",    // 8	Exterior Gateway Protocol
    "IGP",    // 9	any private interior gateway (used by Cisco for their IGRP)
    "BBN",    // 10	BBN RCC Monitoring
    "NVPII",  // 11	Network Voice Protocol
    "PUP",    // 12	PUP
    "ARGUS",  // 13	ARGUS
    "ENCOM",  // 14	EMCON
    "XNET",   // 15	Cross Net Debugger
    "CHAOS",  // 16	Chaos
    "UDP",    // 17	User Datagram
    "MUX",    // 18	Multiplexing
    "DCN",    // 19	DCN Measurement Subsystems
    "HMP",    // 20	Host Monitoring
    "PRM",    // 21	Packet Radio Measurement
    "XNS",    // 22	XEROX NS IDP
    "Trnk1",  // 23	Trunk-1
    "Trnk2",  // 24	Trunk-2
    "Leaf1",  // 25	Leaf-1
    "Leaf2",  // 26	Leaf-2
    "RDP",    // 27	Reliable Data Protocol
    "IRTP",   // 28	Internet Reliable Transaction
    "ISO-4",  // 29	ISO Transport Protocol Class 4
    "NETBK",  // 30	Bulk Data Transfer Protocol
    "MFESP",  // 31	MFE Network Services Protocol
    "MEINP",  // 32	MERIT Internodal Protocol
    "DCCP",   // 33	Datagram Congestion Control Protocol
    "3PC",    // 34	Third Party Connect Protocol
    "IDPR",   // 35	Inter-Domain Policy Routing Protocol
    "XTP",    // 36	XTP
    "DDP",    // 37	Datagram Delivery Protocol
    "IDPR",   // 38	IDPR Control Message Transport Proto
    "TP++",   // 39	TP++ Transport Protocol
    "IL",     // 40	IL Transport Protocol
    "IPv6",   // 41	IPv6
    "SDRP",   // 42	Source Demand Routing Protocol
    "Rte6",   // 43	Routing Header for IPv6
    "Frag6",  // 44	Fragment Header for IPv6
    "IDRP",   // 45	Inter-Domain Routing Protocol
    "RSVP",   // 46	Reservation Protocol
    "GRE",    // 47	General Routing Encapsulation
    "MHRP",   // 48	Mobile Host Routing Protocol
    "BNA",    // 49	BNA
    "ESP",    // 50	Encap Security Payload
    "AH",     // 51	Authentication Header
    "INLSP",  // 52	Integrated Net Layer Security  TUBA
    "SWIPE",  // 53	IP with Encryption
    "NARP",   // 54	NBMA Address Resolution Protocol
    "MOBIL",  // 55	IP Mobility
    "TLSP",   // 56	Transport Layer Security Protocol
    "SKIP",   // 57	SKIP
    "ICMP6",  // 58	ICMP for IPv6
    "NOHE6",  // 59	No Next Header for IPv6
    "OPTS6",  // 60	Destination Options for IPv6
    "HOST",   // 61	any host internal protocol
    "CFTP",   // 62	CFTP
    "NET",    // 63	any local network
    "SATNT",  // 64	SATNET and Backroom EXPAK
    "KLAN",   // 65	Kryptolan
    "RVD",    // 66	MIT Remote Virtual Disk Protocol
    "IPPC",   // 67	Internet Pluribus Packet Core
    "FS",     // 68	any distributed file system
    "SATM",   // 69	SATNET Monitoring
    "VISA",   // 70	VISA Protocol
    "IPCV",   // 71	Internet Packet Core Utility
    "CPNX",   // 72	Computer Protocol Network Executive
    "CPHB",   // 73	Computer Protocol Heart Beat
    "WSN",    // 74	Wang Span Network
    "PVP",    // 75	Packet Video Protocol
    "BSATM",  // 76	Backroom SATNET Monitoring
    "SUNND",  // 77	SUN ND PROTOCOL-Temporary
    "WBMON",  // 78	WIDEBAND Monitoring
    "WBEXP",  // 79	WIDEBAND EXPAK
    "ISOIP",  // 80	ISO Internet Protocol
    "VMTP",   // 81	VMTP
    "SVMTP",  // 82	SECURE-VMTP
    "VINES",  // 83	VINES
    "TTP",    // 84	TTP
    "NSIGP",  // 85	NSFNET-IGP
    "DGP",    // 86	Dissimilar Gateway Protocol
    "TCF",    // 87	TCF
    "EIGRP",  // 88	EIGRP
    "OSPF",   // 89	OSPFIGP
    "S-RPC",  // 90	Sprite RPC Protocol
    "LARP",   // 91	Locus Address Resolution Protocol
    "MTP",    // 92	Multicast Transport Protocol
    "AX.25",  // 93	AX.25 Frames
    "OS",     // 94	KA9Q NOS compatible IP over IP tunneling
    "MICP",   // 95	Mobile Internetworking Control Protocol
    "SCCSP",  // 96	Semaphore Communications Sec. Protocol
    "ETHIP",  // 97	Ethernet-within-IP Encapsulation
    "ENCAP",  // 98	Encapsulation Header
    "99",     // 99	any private encryption scheme
    "GMTP",   // 100	GMTP
    "IFMP",   // 101	Ipsilon Flow Management Protocol
    "PNNI",   // 102	PNNI over IP
    "PIM",    // 103	Protocol Independent Multicast
    "ARIS",   // 104	ARIS
    "SCPS",   // 105	SCPS
    "QNX",    // 106	QNX
    "A/N",    // 107	Active Networks
    "IPcmp",  // 108	IP Payload Compression Protocol
    "SNP",    // 109	Sitara Networks Protocol
    "CpqPP",  // 110	Compaq Peer Protocol
    "IPXIP",  // 111	IPX in IP
    "VRRP",   // 112	Virtual Router Redundancy Protocol
    "PGM",    // 113	PGM Reliable Transport Protocol
    "0hop",   // 114	any 0-hop protocol
    "L2TP",   // 115	Layer Two Tunneling Protocol
    "DDX",    // 116	D-II Data Exchange (DDX)
    "IATP",   // 117	Interactive Agent Transfer Protocol
    "STP",    // 118	Schedule Transfer Protocol
    "SRP",    // 119	SpectraLink Radio Protocol
    "UTI",    // 120	UTI
    "SMP",    // 121	Simple Message Protocol
    "SM",     // 122	SM
    "PTP",    // 123	Performance Transparency Protocol
    "ISIS4",  // 124	ISIS over IPv4
    "FIRE",   // 125	FIRE
    "CRTP",   // 126	Combat Radio Transport Protocol
    "CRUDP",  // 127	Combat Radio User Datagram
    "128",    // 128	SSCOPMCE
    "IPLT",   // 129	IPLP
    "SPS",    // 130	Secure Packet Shield
    "PIPE",   // 131	Private IP Encapsulation within IP
    "SCTP",   // 132	Stream Control Transmission Protocol
    "FC",     // 133	Fibre Channel
    "134",    // 134	RSVP-E2E-IGNORE
    "MHEAD",  // 135	Mobility Header
    "UDP-L",  // 136	UDPLite
    "MPLS"    // 137	MPLS-in-IP
};

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

#define MAX_EVENTS 19
static struct event_flags_s {
    char *sname;
    char *lname;
} event_flags[MAX_EVENTS] = {{"INVALID", "INVALID"},
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

char *ProtoString(uint8_t protoNum, uint32_t plainNumbers) {
    static char s[16];

    if (protoNum >= NumProtos || plainNumbers) {
        snprintf(s, 15, "%-5i", protoNum);
        s[15] = '\0';
        return s;
    } else {
        return protoList[protoNum];
    }

}  // End of ProtoString

int ProtoNum(char *protoString) {
    int len;

    if ((len = strlen(protoString)) >= 6) return -1;

    for (int i = 0; i < NumProtos; i++) {
        if (strncasecmp(protoString, protoList[i], len) == 0 && (strlen(protoList[i]) == len)) return i;
    }

    return -1;

}  // End of ProtoNum

char *FlagsString(uint16_t flags) {
    static char string[16];

    string[0] = flags & 128 ? 'C' : '.';  // Congestion window reduced -  CWR
    string[1] = flags & 64 ? 'E' : '.';   // ECN-Echo
    string[2] = flags & 32 ? 'U' : '.';   // Urgent
    string[3] = flags & 16 ? 'A' : '.';   // Ack
    string[4] = flags & 8 ? 'P' : '.';    // Push
    string[5] = flags & 4 ? 'R' : '.';    // Reset
    string[6] = flags & 2 ? 'S' : '.';    // Syn
    string[7] = flags & 1 ? 'F' : '.';    // Fin
    string[8] = '\0';

    return string;
}  // End of FlagsString

char *biFlowString(uint8_t biFlow) {
    switch (biFlow) {
        case 0:
            return "";
            break;
        case 1:
            return "initiator";
            break;
        case 2:
            return "reverseInitiator";
            break;
        case 3:
            return "perimeter";
            break;
    }

    return "undef";

}  // End of biFlowString

char *FlowEndString(uint8_t endReason) {
    switch (endReason) {
        case 0:
            return "";
            break;
        case 1:
            return "idle timeout";
            break;
        case 2:
            return "active timeout";
            break;
        case 3:
            return "end of Flow detected";
            break;
        case 4:
            return "forced end";
            break;
        case 5:
            return "lack of resources";
            break;
    }

    return "undef";

}  // End of FlowEndString

char *FwEventString(int event) {
    switch (event) {
#ifdef JUNOS
        case 0:
            return "IGNORE";
            break;
        case 1:
        case 4:
        case 6:
        case 8:
        case 12:
            return "CREATE";
            break;
        case 2:
        case 5:
        case 7:
        case 9:
        case 13:
            return "DELETE";
            break;
        case 3:
        case 10:
            return "EXHAUSTED";
            break;
        case 11:
            return "QUOTA EXCEED";
            break;
        case 14:
            return "NAT PORT ALLOC";
            break;
        case 15:
            return "NAT PORT RELEASE";
            break;
        case 16:
            return "NAT PORT ACTIVE";
            break;
#else
        case 0:
            return "IGNORE";
            break;
        case 1:
            return "CREATE";
            break;
        case 2:
            return "DELETE";
            break;
        case 3:
            return "DENIED";
            break;
        case 4:
            return "ALERT";
            break;
        case 5:
            return "UPDATE";
            break;
#endif
        default:
            return "UNKNOWN";
    }

}  // End of FwEventString

char *EventString(int event, int longName) {
    if (event >= MAX_EVENTS) {
        event = 0;
    }
    return longName ? event_flags[event].lname : event_flags[event].sname;

}  // End of EventString

char *EventXString(int xevent) {
    static char s[16];

    switch (xevent) {
        case 0:
            return "Ignore";
            break;
        case 1001:
            return "I-ACL";
            break;
        case 1002:
            return "E-ACL";
            break;
        case 1003:
            return "Adap";
            break;
        case 1004:
            return "No Syn";
            break;
        default:
            snprintf(s, 15, "%u", xevent);
            s[15] = '\0';
            return s;
    }

    // not reached
}  // End of EventXString

// definitions for OpenBSD pflog
const char *pf_actions[] = {"pass",  "block",    "scrub", "noscrub", "nat",    "nonat", "binat", "nobinat", "rdr",
                            "nordr", "synblock", "defer", "match",   "divert", "rt",    "afrt",  NULL};

const char *pf_reasons[] = {"match",         "bad-offset", "fragment",  "short",       "normalize",      "memory)",
                            "bad-timestamp", "congestion", "ip-option", "proto-cksum", "state-mismatch", "state-insert",
                            "state-limit",   "src-limit",  "synproxy",  "translate",   "no-route",       NULL};

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