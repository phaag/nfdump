/*************************************************************************
 *
 * Copyright 2010 by Sean Conner.  All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or (at your
 * option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, see <http://www.gnu.org/licenses/>.
 *
 **************************************************************************/

/*************************************************************************
 *
 * Definitions for all things related to the DNS protocol (and not to the
 * network transport thereof---that's for another episode).
 *
 * I've scoured the Internet and I think I've located every DNS RR type that
 * exists.  And for the majority of them, I've made an in-memory
 * representation of said record for easy access to the contents (for when I
 * do get around to decoding them from their wire representation).  For
 * records that I do not decode (and you'll need to check codec.c to see
 * which ones aren't being decoded) you'll get back a dns_x_t, which has the
 * common portion of the RR decoded (which includes the ID, type, class and
 * TTL) plus the remainder of the raw packet.
 *
 * My eventual intent is to decode those records that I can find definitions
 * for, and decipher the sometimes dry and dense RFCs that describe said RRs.
 * I'm well on my way with support for about half the known records (which
 * includes the ones most likely to be found in 99% of all zone files).
 *
 * This file assumes C99.  You must include the following files before
 * including this one:
 *
 * #include <stdbool.h>
 * #include <stdint.h>
 * #include <stddef.h>
 * #incldue <arpa/inet.h>
 *
 ***************************************************************************/

#ifndef I_52281206_2176_5917_BC9C_574D81892362
#define I_52281206_2176_5917_BC9C_574D81892362

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>

#ifndef __GNUC__
#define __attribute__(x)
#endif

#include "dns.h"

/****************************************************************************
 * Buffers passed to these routines should be declared as one of these two
 * types with one of the given sizes below, depending upon what the buffer is
 * being used for.  This is to ensure things work out fine and don't blow up
 * (like a segfault).  The 4K size *should* be okay for UDP packets, but if
 * you are worried, 8K is more than enough to handle responses from UDP.
 * Larger sizes may be required for TCP.
 *
 * A declaration would looke something like:
 *
 *       dns_packet_t  query_packet    [DNS_BUFFER_UDP];
 *       dns_decoded_t decoded_response[DNS_DECODEBUF_4K];
 *
 * Alternatively, you can do this:
 *
 *       dns_packet_t  *pquery_packet;
 *       dns_decoded_t *pdecoded_response;
 *
 *       pquery_packet     = malloc(MAX_DNS_QUERY_SIZE);
 *       pdecoded_response = malloc(4192);
 *
 *************************************************************************/

typedef uintptr_t dns_packet_t;
typedef uintptr_t dns_decoded_t;

#define DNS_BUFFER_UDP (512uL / sizeof(dns_packet_t))
#define DNS_BUFFER_UDP_MAX (1492uL / sizeof(dns_packet_t))
#define DNS_DECODEBUF_4K (4096uL / sizeof(dns_decoded_t))
#define DNS_DECODEBUF_8K (16384uL / sizeof(dns_decoded_t))
#define DNS_DECODEBUF_16k (16384uL / sizeof(dns_decoded_t))

/************************************************************************
 * Various upper limits in the DNS protocol
 ************************************************************************/

#define MAX_DNS_QUERY_SIZE 512
#define MAX_DOMAIN_SEGMENT 64
#define MAX_DOMAIN_LABEL 64
#define MAX_STRING_LEN 256
#define MAX_UDP_PACKET_SIZE 1492

/***************************************************************************
 * I've specified where each RR, Class and error codes are defined.  Also,
 * for the RRs, I've marked if I have decode support as well as experimental
 * and obsolete information as follows:
 *
 *       +       Encoding/Decoding support
 *       O       Obsolete
 *       E       Experimental
 *
 * https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
 ***************************************************************************/

typedef enum dns_type {
    RR_A = 1,           /* IPv4 Address                      + RFC-1035 */
    RR_NS = 2,          /* Name server                       + RFC-1035 */
    RR_MD = 3,          /* Mail Destination                 O+ RFC-1035 */
    RR_MF = 4,          /* Mail Forwarder                   O+ RFC-1035 */
    RR_CNAME = 5,       /* Canonical name                    + RFC-1035 */
    RR_SOA = 6,         /* Start of Authority                + RFC-1035 */
    RR_MB = 7,          /* Mailbox                          E+ RFC-1035 */
    RR_MG = 8,          /* Mailgroup                        E+ RFC-1035 */
    RR_MR = 9,          /* Mailrename                       E+ RFC-1035 */
    RR_NULL = 10,       /* NULL resource                    E+ RFC-1035 */
    RR_WKS = 11,        /* Well Known Service                + RFC-1035 */
    RR_PTR = 12,        /* Pointer                           + RFC-1035 */
    RR_HINFO = 13,      /* Host Info                         + RFC-1035 */
    RR_MINFO = 14,      /* Mailbox/mail list info            + RFC-1035 */
    RR_MX = 15,         /* Mail Exchange                     + RFC-1035 */
    RR_TXT = 16,        /* Text                              + RFC-1035 */
    RR_RP = 17,         /* Responsible Person                + RFC-1183 */
    RR_AFSDB = 18,      /* Andrew File System DB             + RFC-1183 RFC-5864 */
    RR_X25 = 19,        /* X.25 address, route binding       + RFC-1183 */
    RR_ISDN = 20,       /* ISDN address, route binding       + RFC-1183 */
    RR_RT = 21,         /* Route Through                     + RFC-1183 */
    RR_NSAP = 22,       /* Network Service Access Proto      + RFC-1348 RFC-1706 */
    RR_NSAP_PTR = 23,   /* NSAP Pointer                      + RFC-1348 */
    RR_SIG = 24,        /* Signature                           RFC-2065 RFC-2535 RFC-3755 RFC-4034 */
    RR_KEY = 25,        /* Key                                 RFC-2065 RFC-2535 RFC-3755 RFC-4034 */
    RR_PX = 26,         /* X.400 mail mapping                + RFC-2163 */
    RR_GPOS = 27,       /* Geographical position            O+ RFC-1712 */
    RR_AAAA = 28,       /* IPv6 Address                      + RFC-1886 RFC-3596 */
    RR_LOC = 29,        /* Location                          + RFC-1876 */
    RR_NXT = 30,        /* Next RR                             RFC-2065 RFC-2535 RFC-3755 */
    RR_EID = 31,        /* Endpoint Identifier                          */
    RR_NIMLOC = 32,     /* Nimrod Locator                               */
    RR_SRV = 33,        /* Service                           + RFC-2782 */
    RR_ATMA = 34,       /* ATM Address                                  */
    RR_NAPTR = 35,      /* Naming Authority Pointer          + RFC-2168 RFC-2915 RFC-3403 */
    RR_KX = 36,         /* Key Exchange                        RFC-2230 */
    RR_CERT = 37,       /* Certification                       RFC-4398 */
    RR_A6 = 38,         /* IPv6 Address                      O RFC-2874 RFC-3658 */
    RR_DNAME = 39,      /* Non-terminal DNAME (IPv6)           RFC-2672 */
    RR_SINK = 40,       /* Kitchen sink                                 */
    RR_OPT = 41,        /* EDNS0 option (meta-RR)            + RFC-2671 RFC-3225 RFC-6891 */
    RR_APL = 42,        /* Address Prefix List                 RFC-3123 */
    RR_DS = 43,         /* Delegation Signer                   RFC-3658 RFC-4034 */
    RR_SSHFP = 44,      /* SSH Key Fingerprint                 RFC-4255 */
    RR_ISECKEY = 45,    /* IP Security Key                     RFC-4025 */
    RR_RRSIG = 46,      /* Resource Record Signature           RFC-3755 RFC-4034 */
    RR_NSEC = 47,       /* Next Security Record                RFC-3755 RFC-4034 */
    RR_DNSKEY = 48,     /* DNS Security Key                    RFC-3755 RFC-4034 */
    RR_DHCID = 49,      /* DHCID                               RFC-4701 */
    RR_NSEC3 = 50,      /* NSEC3                               RFC-5155 */
    RR_NSEC3PARAM = 51, /* NSEC3PARAM                          RFC-5155 */
    RR_TLSA = 52,       /* TLSA                                RFC-6698 */
    RR_SMIMEA = 53,     /* S/MIME cert association             RFC-8162 */
    RR_HIP = 55,        /* Host Identity Protocol              RFC-5205 */
    RR_NINFO = 56,      /* NINFO                                        */
    RR_RKEY = 57,       /* RKEY                                         */
    RR_TALINK = 58,     /* Trust Anchor Link                            */
    RR_CDS = 59,        /* Child DS                            RFC-7344 */
    RR_CDNSKEY = 60,    /* DNSKEY the Child wants reflected    RFC-7344 */
    RR_OPENPGPKEY = 61, /* OpenPGP key                         RFC-7929 */
    RR_CSYNC = 62,      /* Child-to-Parent Synchronization     RFC-7477 */
    RR_ZONEMD = 63,     /* Message Digest Over Zone Data       RFC-8976 */
    RR_SVCB = 64,       /* Service Binding                              */
    RR_HTTPS = 65,      /* HTTPS Binding (really?)                      */
    RR_SPF = 99,        /* Sender Policy Framework          O+ RFC-4408 RFC-7208 */
    RR_UINFO = 100,     /* IANA Reserved                                */
    RR_UID = 101,       /* IANA Reserved                                */
    RR_GID = 102,       /* IANA Reserved                                */
    RR_UNSPEC = 103,    /* IANA Reserved                                */
    RR_NID = 104,       /* Node Identifier                     RFC-6742 */
    RR_L32 = 105,       /* 32-bit Locator value                RFC-6742 */
    RR_L64 = 106,       /* 64-bit Locator value                RFC-6742 */
    RR_LP = 107,        /* Name of ILNP subnetwork             RFC-6742 */
    RR_EUI48 = 108,     /* EUI-48 address                      RFC-7043 */
    RR_EUI64 = 109,     /* EUI-64 address                      RFC-7043 */

    /* Query types, >= 128 */

    RR_TKEY = 249,     /* Transaction Key                     RFC-2930 */
    RR_TSIG = 250,     /* Transaction Signature               RFC-2845 */
    RR_IXFR = 251,     /* Incremental zone transfer           RFC-1995 */
    RR_AXFR = 252,     /* Transfer of zone                    RFC-1035 RFC-5936 */
    RR_MAILB = 253,    /* Mailbox related records             RFC-1035 */
    RR_MAILA = 254,    /* Mail agent RRs (obsolete)        O  RFC-1035 */
    RR_ANY = 255,      /* All records                         RFC-1035 RFC-6895 RFC-8482 */
    RR_URI = 256,      /* Universal Resource Indicator        RFC-7553 */
    RR_CAA = 257,      /* Certification Authority Restriction RFC-8659 */
    RR_AVC = 258,      /* Application Visibility and Control           */
    RR_DOA = 259,      /* Digital Object Architecture                  */
    RR_AMTRELAY = 260, /* Automatic Multicast Tunneling Relay RFC-8777 */

    RR_TA = 32768,  /* DNSSEC Trust Authories                       */
    RR_DLV = 32769, /* DNSSEC Lookaside Validation      O  RFC-8749 RFC-4431 */

    RR_PRIVATE = 65280, /* Private usage                       RFC-2929 */
    RR_UNKNOWN = 65535, /* Unknown record type                 RFC-6895 */
} dns_type_t;

typedef enum edns0_type {
    EDNS0RR_NSID = 3 /* Name Server ID                     + RFC-5001 */
} edns0_type_t;

typedef enum dns_class {
    CLASS_IN = 1,          /* Internet             RFC-1035 */
    CLASS_CS = 2,          /* CSNET (obsolete)     RFC-1035 */
    CLASS_CH = 3,          /* CHAOS                RFC-1035 */
    CLASS_HS = 4,          /* Hesiod               RFC-1035 */
    CLASS_NONE = 254,      /*                      RFC-2136 */
    CLASS_ANY = 255,       /* All classes          RFC-1035 */
    CLASS_PRIVATE = 65280, /* Private use          RFC-2929 */
    CLASS_UNKNOWN = 65535, /* Unknown class        RFC-2929 */
} dns_class_t;

typedef enum dns_op {
    OP_QUERY = 0, /* RFC-1035 */
    OP_IQUERY = 1,
    /* RFC-1035 RFC-3425 */ /* Obsolete */
    OP_STATUS = 2,          /* RFC-1035 */
    OP_NOTIFY = 4,          /* RFC-1996 */
    OP_UPDATE = 5,          /* RFC-2136 */
    OP_UNKNOWN = 1          /* Since OP_IQUERY is obsolete */
} dns_op_t;

typedef enum dns_rcode {
    RCODE_OKAY = 0,            /* RFC-1035 */
    RCODE_FORMAT_ERROR = 1,    /* RFC-1035 */
    RCODE_SERVER_FAILURE = 2,  /* RFC-1035 */
    RCODE_NAME_ERROR = 3,      /* RFC-1035 */
    RCODE_NOT_IMPLEMENTED = 4, /* RFC-1035 */
    RCODE_REFUSED = 5,         /* RFC-1035 */
    RCODE_YXDOMAIN = 6,        /* RFC-2136 */
    RCODE_YXRRSET = 7,         /* RFC-2136 */
    RCODE_NXRRSET = 8,         /* RFC-2136 */
    RCODE_NOTAUTH = 9,         /* RFC-2136 */
    RCODE_NOTZONE = 10,        /* RFC-2136 */
    RCODE_BADVERS = 16,        /* RFC-2671 */
    RCODE_BADSIG = 16,         /* RFC-2845 */
    RCODE_BADKEY = 17,         /* RFC-2845 */
    RCODE_BADTIME = 18,        /* RFC-2845 */
    RCODE_BADMODE = 19,        /* RFC-2845 */
    RCODE_BADNAME = 20,        /* RFC-2930 */
    RCODE_BADALG = 21,         /* RFC-2930 */
    RCODE_BADTRUC = 22,        /* RFC-4635 */
    RCODE_BADCOOKIE = 23,      /* RFC-7873 */
    RCODE_PRIVATE = 3841,      /* RFC-2929 */

    RCODE_NO_MEMORY,
    RCODE_BAD_STRING,
} dns_rcode_t;

typedef enum edns0_label {
    EDNS0_ELT = 0x01, /* RFC-2673 (experimental RFC-3363) */
    EDNS0_RSVP = 0x3F /* RFC-2671 */
} edns0_label_t;

typedef uint32_t TTL;

typedef struct dns_question_t /* RFC-1035 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
} dns_question_t;

typedef struct dns_generic_t /* RFC-1035 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
} dns_generic_t;

typedef struct dns_a_t /* RFC-1035 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    in_addr_t address;
} dns_a_t;

typedef struct dns_ns_t /* RFC-1035 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    char const *nsdname;
} dns_ns_t;

typedef struct dns_md_t /* RFC-1035 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    char const *madname;
} dns_md_t;

typedef struct dns_mf_t /* RFC-1035 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    char const *madname;
} dns_mf_t;

typedef struct dns_cname_t /* RFC-1035 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    char const *cname;
} dns_cname_t;

typedef struct dns_soa_t /* RFC-1035 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    char const *mname;
    char const *rname;
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t minimum;
} dns_soa_t;

typedef struct dns_mb_t /* RFC-1035 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    char const *madname;
} dns_mb_t;

typedef struct dns_mg_t /* RFC-1035 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    char const *mgmname;
} dns_mg_t;

typedef struct dns_mr_t /* RFC-1035 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    char const *newname;
} dns_mr_t;

typedef struct dns_null_t /* RFC-1035 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    size_t size;
    uint8_t *data;
} dns_null_t;

typedef struct dns_wks_t /* RFC-1035 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    in_addr_t address;
    int protocol;
    size_t numbits; /* <= 16384 */
    uint8_t *bits;
} dns_wks_t;

typedef struct dns_ptr_t /* RFC-1035 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    char const *ptr;
} dns_ptr_t;

typedef struct dns_hinfo_t /* RFC-1035 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    char const *cpu;
    char const *os;
} dns_hinfo_t;

typedef struct dns_minfo_t /* RFC-1035 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    char const *rmailbx;
    char const *emailbx;
} dns_minfo_t;

typedef struct dns_mx_t /* RFC-1035 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    int preference;
    char const *exchange;
} dns_mx_t;

typedef struct dns_txt_t /* RFC-1035 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    size_t len;
    char const *text;
} dns_txt_t;

typedef struct dns_rp_t /* RFC-1183 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    char const *mbox;
    char const *domain;
} dns_rp_t;

typedef struct dns_afsdb_t /* RFC-1183 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    int subtype;
    char const *hostname;
} dns_afsdb_t;

typedef struct dns_x25_t /* RFC-1183 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    size_t size;
    char const *psdnaddress;
} dns_x25_t;

typedef struct dns_isdn_t /* RFC-1183 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    char const *isdnaddress;
    char const *sa;
} dns_isdn_t;

typedef struct dns_rt_t /* RFC-1183 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    int preference;
    char const *host;
} dns_rt_t;

typedef struct dns_nsap_t /* RFC-1348 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    char const *length;
    char const *nsapaddress;
} dns_nsap_t;

typedef struct dns_nsap_ptr_t /* RFC-1348 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    char const *owner;
} dns_nsap_ptr_t;

typedef enum dnskey_algorithm /* RFC-2065 */
{ DNSKEYA_RSAMD5 = 1,
  DNSKEYA_DH = 2,         /* RFC-2535 */
  DNSKEYA_DSA = 3,        /* RFC-2535 */
  DNSKEYA_ECC = 4,        /* RFC-2535 */
  DNSKEYA_RSASHA1 = 5,    /* RFC-3110 */
  DNSKEYA_INDIRECT = 252, /* RFC-2535 */
  DNSKEYA_PRIVATEDNS = 253,
  DNSKEYA_PRIVATEOID = 254,
  DNSKEYA_RSVP = 255 } dnskey_algorithm;

typedef struct dns_sig_t /* RFC-2065 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    dns_type_t covered;
    dnskey_algorithm algorithm;
    int labels;
    TTL originttl;
    unsigned long sigexpire;
    unsigned long timesigned;
    uint16_t keyfootprint;
    char const *signer;
    size_t sigsize;
    uint8_t *signature;
} dns_sig_t;

typedef enum dnskey_protocol /* RFC-2535 */
{ DNSKEYP_NONE = 0,
  DNSKEYP_TLS = 1,
  DNSKEYP_EMAIL = 2,
  DNSKEYP_DNSSEC = 3,
  DNSKEYP_IPSEC = 4,
  DNSKEYP_ALL = 255 } dnskey_protocol;

typedef union dnskey_key /* RFC-2065 */
{
    struct {
        size_t expsize;
        uint8_t *exponent;
        size_t modsize;
        uint8_t *modulus;
    } md5;

    struct {
        size_t size;
        uint8_t *data;
    } unknown;
} dnskey_key;

typedef struct dns_key_t /* RFC-2065 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    struct {
        bool authentication;
        bool confidential;
        bool experimental;
        bool user;
        bool zone;
        bool host;
        bool ipsec;
        bool email; /* not in RFC-2535 */
    } flags;
    int signatory;
    dnskey_protocol protocol;
    dnskey_algorithm algorithm;
    dnskey_key key;
} dns_key_t;

typedef struct dns_px_t /* RFC-2163 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    char const *map822;
    char const *mapx400;
} dns_px_t;

typedef struct dnsgpos_angle /* RFC-1712 , RFC1876 */
{
    int deg;
    int min;
    int sec;
    int frac;
    bool nw; /* Northern or Western Hemisphere */
} dnsgpos_angle;

typedef struct dns_gpos_t /* RFC-1712 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    dnsgpos_angle longitude;
    dnsgpos_angle latitude;
    double altitude;
} dns_gpos_t;

typedef struct dns_aaaa_t /* RFC-1886 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    struct in6_addr address;
} dns_aaaa_t;

typedef struct dns_loc_t /* RFC-1876 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    int version;
    unsigned long long size;      /* plese see RFC-1876 for a discussion  */
    unsigned long long horiz_pre; /* of these fields                      */
    unsigned long long vert_pre;
    dnsgpos_angle latitude;
    dnsgpos_angle longitude;
    long altitude;
} dns_loc_t;

typedef struct dns_nxt_t /* RFC-2065 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    char const *next;
    size_t numbits;
    uint8_t *bitmap;
} dns_nxt_t;

typedef struct dns_eid_t /* (unknown) */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    size_t size;
    uint8_t *rawdata;
} dns_eid_t;

typedef struct dns_nimloc_t /* (unknown) */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    size_t size;
    uint8_t *rawdata;
} dns_nimloc_t;

typedef struct dns_srv_t /* RFC-2782 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    int priority;
    int weight;
    int port;
    char const *target;
} dns_srv_t;

typedef struct dns_atm_t /* (unknown) */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    size_t size;
    uint8_t *rawdata;
} dns_atm_t;

typedef struct dns_naptr_t /* RFC-2915 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    int order;
    int preference;
    char const *flags;
    char const *services;
    char const *regexp;
    char const *replacement;
} dns_naptr_t;

typedef struct dns_kx_t /* (unknown) */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    size_t size;
    uint8_t *rawdata;
} dns_kx_t;

typedef struct dns_cert_t /* (unknown) */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    size_t size;
    uint8_t *rawdata;
} dns_cert_t;

typedef struct dns_a6_t /* RFC-2874 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    size_t mask;
    struct in6_addr address;
    char const *prefixname;
} dns_a6_t;

typedef struct dns_dname_t /* RFC-2672 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    size_t size;
    uint8_t *rawdata;
} dns_dname_t;

typedef struct dns_sink_t /* (unknown) */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    size_t size;
    uint8_t *rawdata;
} dns_sink_t;

typedef struct edns0_opt_t /* RFC-2671 */
{
    edns0_type_t code; /* 0 <= code <= UINT16_MAX */
    size_t len;        /* 0 <= len  <= UINT16_MAX */
    uint8_t *data;     /* encoded per RFC specification */
} edns0_opt_t;

typedef struct dns_edns0opt_t /* RFC-2671 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class; /* not applicable --- set to CLASS_UNKNOWN */
    TTL ttl;           /* not applicable --- set to 0 */
    size_t udp_payload;
    int version;
    bool fdo; /* RFC-3225 */
    int fug;
    unsigned int z; /* should be zero */
    size_t numopts;
    edns0_opt_t *opts;
} dns_edns0opt_t;

typedef struct dnsapl_record /* RFC-3123 */
{
    int addressfamily;
    int prefix;
    size_t afdlength;
    uint8_t *afdpart;
    bool negate;
} dnsapl_record;

typedef struct dns_apl_t /* RFC-3123 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    size_t numrecs;
    dnsapl_record *recs;
} dns_apl_t;

typedef enum dnsds_digest /* RFC-3658 */
{ DNSDS_SHA1 = 1 } dnsds_digest;

typedef struct dns_ds_t /* RFC-3658 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    dnskey_protocol keytag;
    dnskey_algorithm algorithm;
    dnsds_digest digest;
    size_t digestlen;
    uint8_t *digestdata;
} dns_ds_t;

typedef struct dns_rrsig_t /* RFC-4034 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    dns_type_t covered;
    dnskey_algorithm algorithm;
    int labels;
    TTL originttl;
    unsigned long sigexpire;
    unsigned long timesigned;
    uint16_t keyfootprint;
    char const *signer;
    size_t sigsize;
    uint8_t *signature;
} dns_rrsig_t;

typedef struct dns_nsec_t /* RFC-4034 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    char const *next;
    size_t numbits;
    uint8_t *bitmap;
} dns_nsec_t;

typedef struct dns_dnskey_t /* RFC-4034 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    bool zonekey;
    bool sep;
    dnskey_protocol protocol; /* must be DNSKEYP_DNSSEC */
    dnskey_algorithm algorithm;
    size_t keysize;
    uint8_t *key;
} dns_dnskey_t;

typedef struct dns_sshfp_t /* RFC-4255 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    dnskey_algorithm algorithm;
    dnsds_digest fptype;
    size_t fpsize;
    uint8_t *fingerprint;
} dns_sshfp_t;

typedef struct dns_spf_t /* RFC-4408 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    size_t len;
    char const *text;
} dns_spf_t;

typedef struct dns_tsig_t /* RFC-2845 */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl; /* must be 0 */
    char const *algorithm;
    uint64_t timesigned;
    unsigned int fudge;
    size_t MACsize;
    uint8_t *MAC;
    int id;
    int error;
    size_t lenother;
    uint8_t *other;
} dns_tsig_t;

typedef struct dns_x_t /* CATCH-ALL */
{
    char const *name;
    dns_type_t type;
    dns_class_t class;
    TTL ttl;
    size_t size;
    uint8_t *rawdata;
} dns_x_t;

typedef union dns_answer_t {
    dns_generic_t generic;
    dns_x_t x;
    dns_a_t a;
    dns_ns_t ns;
    dns_md_t md;
    dns_mf_t mf;
    dns_cname_t cname;
    dns_soa_t soa;
    dns_mb_t mb;
    dns_mg_t mg;
    dns_mr_t mr;
    dns_null_t null;
    dns_wks_t wks;
    dns_ptr_t ptr;
    dns_hinfo_t hinfo;
    dns_minfo_t minfo;
    dns_mx_t mx;
    dns_txt_t txt;
    dns_rp_t rp;
    dns_afsdb_t afsdb;
    dns_x25_t x25;
    dns_isdn_t isdn;
    dns_rt_t rt;
    dns_nsap_t nsap;
    dns_nsap_ptr_t nsap_ptr;
    dns_sig_t sig;
    dns_key_t key;
    dns_px_t px;
    dns_gpos_t gpos;
    dns_aaaa_t aaaa;
    dns_loc_t loc;
    dns_nxt_t nxt;
    dns_eid_t eid;
    dns_nimloc_t nimloc;
    dns_srv_t srv;
    dns_atm_t atm;
    dns_naptr_t naptr;
    dns_kx_t kx;
    dns_cert_t cert;
    dns_a6_t a6;
    dns_dname_t dname;
    dns_sink_t sink;
    dns_edns0opt_t opt;
    dns_apl_t apl;
    dns_ds_t ds;
    dns_rrsig_t rrsig;
    dns_nsec_t nsec;
    dns_dnskey_t dnskey;
    dns_spf_t spf;
    dns_tsig_t tsig;
} dns_answer_t;

/**********************************************************************/

extern dns_rcode_t dns_encode(dns_packet_t *, size_t *, const dns_query_t *) __attribute__((nothrow, nonnull));
extern dns_rcode_t dns_decode(dns_decoded_t *, size_t *, const dns_packet_t *, size_t) __attribute__((nothrow, nonnull(1, 2, 3)));

#endif
