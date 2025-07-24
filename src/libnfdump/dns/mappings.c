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

/***********************************************************************
 *
 * Implementation of mapping values to strings, or strings to values.
 *
 * This code is written to C99.
 *
 ************************************************************************/

#include "mappings.h"

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "dns/dns.h"

/*******************************************************************
 *
 * The following structure is used to map strings to values.  The arrays
 * defined by this structure *MUST* be sorted by the strings in ascending
 * order.
 *
 *********************************************************************/

struct string_int_map {
    char const *const text;
    int const value;
};

/************************************************************************/

static struct int_string_map const cm_dns_rcode[] = {
    {RCODE_OKAY, "No error"},
    {RCODE_FORMAT_ERROR, "Format error"},
    {RCODE_SERVER_FAILURE, "Server failure"},
    {RCODE_NAME_ERROR, "Non-existant domain"},
    {RCODE_NOT_IMPLEMENTED, "Not implemented"},
    {RCODE_REFUSED, "Query refused"},
    {RCODE_YXDOMAIN, "Name exists when it should not"},
    {RCODE_YXRRSET, "RRset exists when it should not"},
    {RCODE_NXRRSET, "RRset does not exist"},
    {RCODE_NOTAUTH, "Server not authoritative"},
    {RCODE_NOTZONE, "Zone not in zone section"},
    {RCODE_BADVERS, "Bad OPT version/TSIG failed"},
    {RCODE_BADKEY, "Key not recognized"},
    {RCODE_BADTIME, "Signature out of time window"},
    {RCODE_BADMODE, "Bad TKEY mode"},
    {RCODE_BADNAME, "Duplicate key name"},
    {RCODE_BADALG, "Algorithm not supported"},
    {RCODE_BADTRUC, "Bad truncation"},
    {RCODE_BADCOOKIE, "Bad/missing server cookie"},
    {RCODE_NO_MEMORY, "No memory"},
    {RCODE_BAD_STRING, "Bad sring"},
};

#define RCODE_COUNT (sizeof(cm_dns_rcode) / sizeof(struct int_string_map))

struct int_string_map const c_dns_rcode_enum[] = {
    {RCODE_OKAY, "OKAY"},
    {RCODE_FORMAT_ERROR, "FORMAT_ERROR"},
    {RCODE_SERVER_FAILURE, "SERVER_FAILURE"},
    {RCODE_NAME_ERROR, "NAME_ERROR"},
    {RCODE_NOT_IMPLEMENTED, "NOT_IMPLEMENTED"},
    {RCODE_REFUSED, "REFUSED"},
    {RCODE_YXDOMAIN, "YXDOMAIN"},
    {RCODE_YXRRSET, "YXRRSET"},
    {RCODE_NXRRSET, "NXRRSET"},
    {RCODE_NOTAUTH, "NOTAUTH"},
    {RCODE_NOTZONE, "NOTZONE"},
    {RCODE_BADVERS, "BADVERS"},
    {RCODE_BADKEY, "BADKEY"},
    {RCODE_BADTIME, "BADTIME"},
    {RCODE_BADMODE, "BADMODE"},
    {RCODE_BADNAME, "BADNAME"},
    {RCODE_BADALG, "BADALG"},
    {RCODE_BADTRUC, "BADTRUNC"},
    {RCODE_BADCOOKIE, "BADCOOKIE"},
    {RCODE_NO_MEMORY, "NO_MEMORY"},
    {RCODE_BAD_STRING, "BAD_STRING"},
    {0, NULL},
};

static struct string_int_map const cm_dns_rcode_is[] = {
    {"BADALG", RCODE_BADALG},
    {"BADCOOKIE", RCODE_BADCOOKIE},
    {"BADKEY", RCODE_BADKEY},
    {"BADMODE", RCODE_BADMODE},
    {"BADNAME", RCODE_BADNAME},
    {"BADTIME", RCODE_BADTIME},
    {"BADTRUNC", RCODE_BADTRUC},
    {"BADVERS", RCODE_BADVERS},
    {"BAD_STRING", RCODE_BAD_STRING},
    {"FORMAT_ERROR", RCODE_FORMAT_ERROR},
    {"NAME_ERROR", RCODE_NAME_ERROR},
    {"NOTAUTH", RCODE_NOTAUTH},
    {"NOTZONE", RCODE_NOTZONE},
    {"NOT_IMPLEMENTED", RCODE_NOT_IMPLEMENTED},
    {"NO_MEMORY", RCODE_NO_MEMORY},
    {"NXRRSET", RCODE_NXRRSET},
    {"OKAY", RCODE_OKAY},
    {"REFUSED", RCODE_REFUSED},
    {"SERVER_FAILURE", RCODE_SERVER_FAILURE},
    {"YXDOMAIN", RCODE_YXDOMAIN},
    {"YXRRSET", RCODE_YXRRSET},
};

static struct int_string_map const cm_dns_type[] = {
    {RR_A, "A"},
    {RR_NS, "NS"},
    {RR_MD, "MD"},
    {RR_MF, "MF"},
    {RR_CNAME, "CNAME"},
    {RR_SOA, "SOA"},
    {RR_MB, "MB"},
    {RR_MG, "MG"},
    {RR_MR, "MR"},
    {RR_NULL, "NULL"},
    {RR_WKS, "WKS"},
    {RR_PTR, "PTR"},
    {RR_HINFO, "HINFO"},
    {RR_MINFO, "MINFO"},
    {RR_MX, "MX"},
    {RR_TXT, "TXT"},
    {RR_RP, "RP"},
    {RR_AFSDB, "AFSDB"},
    {RR_X25, "X25"},
    {RR_ISDN, "ISDN"},
    {RR_RT, "RT"},
    {RR_NSAP, "NSAP"},
    {RR_NSAP_PTR, "NSAP-PTR"},
    {RR_SIG, "SIG"},
    {RR_KEY, "KEY"},
    {RR_PX, "PX"},
    {RR_GPOS, "GPOS"},
    {RR_AAAA, "AAAA"},
    {RR_LOC, "LOC"},
    {RR_NXT, "NXT"},
    {RR_EID, "EID"},
    {RR_NIMLOC, "NIMLOC"},
    {RR_SRV, "SRV"},
    {RR_ATMA, "ATMA"},
    {RR_NAPTR, "NAPTR"},
    {RR_KX, "KX"},
    {RR_CERT, "CERT"},
    {RR_A6, "A6"},
    {RR_DNAME, "DNAME"},
    {RR_SINK, "SINK"},
    {RR_OPT, "OPT"},
    {RR_APL, "APL"},
    {RR_DS, "DS"},
    {RR_SSHFP, "SSHFP"},
    {RR_ISECKEY, "ISECKEY"},
    {RR_RRSIG, "RRSIG"},
    {RR_NSEC, "NSEC"},
    {RR_DNSKEY, "DNSKEY"},
    {RR_DHCID, "DHCID"},
    {RR_NSEC3, "NSEC3"},
    {RR_NSEC3PARAM, "NSEC3PARAM"},
    {RR_TLSA, "TLSA"},
    {RR_SMIMEA, "SMIMEA"},
    {RR_HIP, "HIP"},
    {RR_NINFO, "NINFO"},
    {RR_RKEY, "RKEY"},
    {RR_TALINK, "TALINK"},
    {RR_CDS, "CDS"},
    {RR_CDNSKEY, "CDNSKEY"},
    {RR_OPENPGPKEY, "OPENPGPKEY"},
    {RR_CSYNC, "CSYNC"},
    {RR_ZONEMD, "ZONEMD"},
    {RR_HTTPS, "HTTPS"},
    {RR_SPF, "SPF"},
    {RR_UINFO, "UINFO"},
    {RR_UID, "UID"},
    {RR_GID, "GID"},
    {RR_UNSPEC, "UNSPEC"},
    {RR_NID, "NID"},
    {RR_L32, "L32"},
    {RR_L64, "L64"},
    {RR_LP, "LP"},
    {RR_EUI48, "EUI48"},
    {RR_EUI64, "EUI64"},
    {RR_TKEY, "TKEY"},
    {RR_TSIG, "TSIG"},
    {RR_IXFR, "IXFR"},
    {RR_AXFR, "AXFR"},
    {RR_MAILB, "MAILB"},
    {RR_MAILA, "MAILA"},
    {RR_ANY, "ANY"},
    {RR_URI, "URI"},
    {RR_CAA, "CAA"},
    {RR_AVC, "AVC"},
    {RR_DOA, "DOA"},
    {RR_AMTRELAY, "AMTRELAY"},
    {RR_TA, "TA"},
    {RR_DLV, "DLV"},
    {RR_PRIVATE, "PRIVATE"},
    {RR_UNKNOWN, "UNKNOWN"},
};

#define TYPE_COUNT (sizeof(cm_dns_type) / sizeof(struct int_string_map))

static struct string_int_map const cm_dns_type_is[] = {
    {"A", RR_A},
    {"A6", RR_A6},
    {"AAAA", RR_AAAA},
    {"AFSDB", RR_AFSDB},
    {"AMTRELAY", RR_AMTRELAY},
    {"ANY", RR_ANY},
    {"APL", RR_APL},
    {"ATMA", RR_ATMA},
    {"AVC", RR_AVC},
    {"AXFR", RR_AXFR},
    {"CAA", RR_CAA},
    {"CDNSKEY", RR_CDNSKEY},
    {"CDS", RR_CDS},
    {"CERT", RR_CERT},
    {"CNAME", RR_CNAME},
    {"CSYNC", RR_CSYNC},
    {"DHCID", RR_DHCID},
    {"DLV", RR_DLV},
    {"DNAME", RR_DNAME},
    {"DNSKEY", RR_DNSKEY},
    {"DOA", RR_DOA},
    {"DS", RR_DS},
    {"EID", RR_EID},
    {"EUI48", RR_EUI48},
    {"EUI64", RR_EUI64},
    {"GID", RR_GID},
    {"GPOS", RR_GPOS},
    {"HINFO", RR_HINFO},
    {"HIP", RR_HIP},
    {"HTTPS", RR_HTTPS},
    {"ISDN", RR_ISDN},
    {"ISECKEY", RR_ISECKEY},
    {"IXFR", RR_IXFR},
    {"KEY", RR_KEY},
    {"KX", RR_KX},
    {"L32", RR_L32},
    {"L64", RR_L64},
    {"LOC", RR_LOC},
    {"LP", RR_LP},
    {"MAILA", RR_MAILA},
    {"MAILB", RR_MAILB},
    {"MB", RR_MB},
    {"MD", RR_MD},
    {"MF", RR_MF},
    {"MG", RR_MG},
    {"MINFO", RR_MINFO},
    {"MR", RR_MR},
    {"MX", RR_MX},
    {"NAPTR", RR_NAPTR},
    {"NID", RR_NID},
    {"NIMLOC", RR_NIMLOC},
    {"NINFO", RR_NINFO},
    {"NS", RR_NS},
    {"NSAP", RR_NSAP},
    {"NSAP-PTR", RR_NSAP_PTR},
    {"NSEC", RR_NSEC},
    {"NSEC3", RR_NSEC3},
    {"NSEC3PARAM", RR_NSEC3PARAM},
    {"NULL", RR_NULL},
    {"NXT", RR_NXT},
    {"OPENPGPKEY", RR_OPENPGPKEY},
    {"OPT", RR_OPT},
    {"PRIVATE", RR_PRIVATE},
    {"PTR", RR_PTR},
    {"PX", RR_PX},
    {"RKEY", RR_RKEY},
    {"RP", RR_RP},
    {"RRSIG", RR_RRSIG},
    {"RT", RR_RT},
    {"SIG", RR_SIG},
    {"SINK", RR_SINK},
    {"SMIMEA", RR_SMIMEA},
    {"SOA", RR_SOA},
    {"SPF", RR_SPF},
    {"SRV", RR_SRV},
    {"SSHFP", RR_SSHFP},
    {"TA", RR_TA},
    {"TALINK", RR_TALINK},
    {"TKEY", RR_TKEY},
    {"TLSA", RR_TLSA},
    {"TSIG", RR_TSIG},
    {"TXT", RR_TXT},
    {"UID", RR_UID},
    {"UINFO", RR_UINFO},
    {"UNKNOWN", RR_UNKNOWN},
    {"UNSPEC", RR_UNSPEC},
    {"URI", RR_URI},
    {"WKS", RR_WKS},
    {"X25", RR_X25},
    {"ZONEMD", RR_ZONEMD},
};

static struct int_string_map const cm_dns_class[] = {
    {CLASS_IN, "IN"},     {CLASS_CS, "CS"},   {CLASS_CH, "CH"},           {CLASS_HS, "HS"},
    {CLASS_NONE, "NONE"}, {CLASS_ANY, "ANY"}, {CLASS_PRIVATE, "PRIVATE"}, {CLASS_UNKNOWN, "UNKNOWN"},
};

#define CLASS_COUNT (sizeof(cm_dns_class) / sizeof(struct int_string_map))

static struct string_int_map const cm_dns_class_is[] = {
    {"ANY", CLASS_ANY}, {"CH", CLASS_CH},     {"CS", CLASS_CS},           {"HS", CLASS_HS},
    {"IN", CLASS_IN},   {"NONE", CLASS_NONE}, {"PRIVATE", CLASS_PRIVATE}, {"UNKNOWN", CLASS_UNKNOWN},
};

static struct int_string_map const cm_dns_op[] = {
    {OP_QUERY, "QUERY"}, {OP_UNKNOWN, "UKNOWN"}, {OP_STATUS, "STATUS"}, {OP_NOTIFY, "NOTIFY"}, {OP_UPDATE, "UPDATE"},
};

#define OP_COUNT (sizeof(cm_dns_op) / sizeof(struct int_string_map))

static struct string_int_map const cm_dns_op_is[] = {
    {"NOTIFY", OP_NOTIFY}, {"QUERY", OP_QUERY}, {"STATUS", OP_STATUS}, {"UNKNOWN", OP_UNKNOWN}, {"UPDATE", OP_UPDATE},
};

/*************************************************************************/

static int intstr_cmp(void const *needle, void const *haystack) {
    struct int_string_map const *pism = haystack;
    int const *pi = needle;

    assert(needle != NULL);
    assert(haystack != NULL);

    return *pi - pism->value;
}

/*********************************************************************/

static int strint_cmp(void const *needle, void const *haystack) {
    struct string_int_map const *psim = haystack;
    char const *key = needle;

    assert(needle != NULL);
    assert(haystack != NULL);

    return strcmp(key, psim->text);
}

/**********************************************************************/

static char const *itosdef(int v, struct int_string_map const *pitab, size_t itabcnt, char const *def) {
    struct int_string_map *pism;

    assert(v >= 0);
    assert(pitab != NULL);
    assert(itabcnt > 0);
    assert(def != NULL);

    pism = bsearch(&v, pitab, itabcnt, sizeof(struct int_string_map), intstr_cmp);
    if (pism)
        return pism->text;
    else
        return def;
}

/********************************************************************/

static int stoidef(char const *tag, struct string_int_map const *pstab, size_t stabcnt, int def) {
    struct string_int_map *psim;
    size_t len = strlen(tag) + 1;
    char buffer[16];
    size_t max = len > 15 ? 15 : len;

    memset(buffer, 0, sizeof(buffer));

    for (size_t i = 0; i < max; i++) buffer[i] = toupper(tag[i]);

    psim = bsearch(buffer, pstab, stabcnt, sizeof(struct string_int_map), strint_cmp);
    if (psim)
        return psim->value;
    else
        return def;
}

/*******************************************************************/

char const *dns_rcode_enum(dns_rcode_t r) { return itosdef(r, c_dns_rcode_enum, RCODE_COUNT, "X-UNKN"); }

/*******************************************************************/

char const *dns_rcode_text(dns_rcode_t r) { return itosdef(r, cm_dns_rcode, RCODE_COUNT, "Unknown error"); }

/*********************************************************************/

char const *dns_type_text(dns_type_t t) { return itosdef(t, cm_dns_type, TYPE_COUNT, "X-UNKN"); }

/**********************************************************************/

char const *dns_class_text(dns_class_t c) { return itosdef(c, cm_dns_class, CLASS_COUNT, "X-UNKN"); }

/*******************************************************************/

char const *dns_op_text(dns_op_t o) { return itosdef(o, cm_dns_op, OP_COUNT, "X-UNKNOWN"); }

/********************************************************************/

dns_rcode_t dns_rcode_value(char const *tag) { return stoidef(tag, cm_dns_rcode_is, RCODE_COUNT, RCODE_NOT_IMPLEMENTED); }

/********************************************************************/

dns_type_t dns_type_value(char const *tag) { return stoidef(tag, cm_dns_type_is, TYPE_COUNT, RR_UNKNOWN); }

/*********************************************************************/

dns_class_t dns_class_value(char const *tag) { return stoidef(tag, cm_dns_class_is, CLASS_COUNT, CLASS_UNKNOWN); }

/**********************************************************************/

dns_op_t dns_op_value(char const *tag) { return stoidef(tag, cm_dns_op_is, OP_COUNT, OP_UNKNOWN); }

/**********************************************************************/
