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

/**********************************************************************
 *
 * DNS record output functions used by sample application.
 *
 * It was factored out so it could be called from client applications.
 *
 ***************************************************************************/

#include "output_dns.h"

#include <assert.h>
#include <ctype.h>
#include <stdio.h>

#include "dns/dns.h"
#include "dns/mappings.h"
#include "util.h"

/************************************************************************/

/************************************************************************/

static void dns_print_header(FILE *stream, const dns_query_t *presult) {
    fprintf(stream, "DNS Header : Queries: %zu, Answers: %zu, Nameservers: %zu, Additional: %zu, Authoritative: %s\n", presult->qdcount,
            presult->ancount, presult->nscount, presult->arcount, presult->aa ? "true" : "false");
    fprintf(stream, "DNS header : Truncated: %s, Recursion desired: %s, Recursion available: %s\n", presult->tc ? "true" : "false",
            presult->rd ? "true" : "false", presult->ra ? "true" : "false");
    fprintf(stream, "DNS header : Authentic data: %s, Checking disabled: %s, Result: %s\n", presult->ad ? "true" : "false",
            presult->cd ? "true" : "false", dns_rcode_text(presult->rcode));
}  // End of dns_print_header

/************************************************************************/

static void dns_print_question(FILE *stream, dns_question_t *pquest, size_t cnt) {
    dbg_assert(cnt > 0 && pquest != NULL);

    for (size_t i = 0; i < cnt; i++) {
        fprintf(stream, "DNS Query  : %2zd: %s %s %s\n", i, pquest[i].name, dns_class_text(pquest[i].class), dns_type_text(pquest[i].type));
    }
}  // End of dns_print_question

/***********************************************************************/

static void dns_print_answer(FILE *stream, char const *tag, dns_answer_t *pans, size_t cnt) {
    char ipaddr[INET6_ADDRSTRLEN];

    dbg_assert(tag != NULL);
    dbg_assert(cnt > 0 && pans != NULL);

    for (size_t i = 0; i < cnt; i++) {
        fprintf(stream, "%s : %2zd: ", tag, i);
        if (pans[i].generic.type != RR_OPT) {
            fprintf(stream, "%s ttl: %lu, %s %s: ", pans[i].generic.name, (unsigned long)pans[i].generic.ttl, dns_class_text(pans[i].generic.class),
                    dns_type_text(pans[i].generic.type));
        } else
            fprintf(stream, "OPT RR: ");

        switch (pans[i].generic.type) {
            case RR_NS:
                fprintf(stream, "%s", pans[i].ns.nsdname);
                break;
            case RR_A:
                inet_ntop(AF_INET, &pans[i].a.address, ipaddr, sizeof(ipaddr));
                fprintf(stream, "%s", ipaddr);
                break;
            case RR_AAAA:
                inet_ntop(AF_INET6, &pans[i].aaaa.address, ipaddr, sizeof(ipaddr));
                fprintf(stream, "%s", ipaddr);
                break;
            case RR_CNAME:
                fprintf(stream, "%s", pans[i].cname.cname);
                break;
            case RR_MX:
                fprintf(stream, "%5d %s", pans[i].mx.preference, pans[i].mx.exchange);
                break;
            case RR_PTR:
                fprintf(stream, "%s", pans[i].ptr.ptr);
                break;
            case RR_HINFO:
                fprintf(stream, "\"%s\" \"%s\"", pans[i].hinfo.cpu, pans[i].hinfo.os);
                break;
            case RR_MINFO:
                fprintf(stream, "(%s, %s)", pans[i].minfo.rmailbx, pans[i].minfo.emailbx);
                break;
            case RR_SPF:
            case RR_TXT:
                fprintf(stream, "\"%s\"", pans[i].txt.text);
                break;
            case RR_SOA:
                fprintf(stream, "%s %s (%lu %lu %lu %lu %lu)", pans[i].soa.mname, pans[i].soa.rname, (unsigned long)pans[i].soa.serial,
                        (unsigned long)pans[i].soa.refresh, (unsigned long)pans[i].soa.retry, (unsigned long)pans[i].soa.expire,
                        (unsigned long)pans[i].soa.minimum);
                break;
            case RR_NAPTR:
                fprintf(stream, "order: %d, pref: %d (flags: %s, services: %s, regex: %s, replace: %s)", pans[i].naptr.order,
                        pans[i].naptr.preference, pans[i].naptr.flags, pans[i].naptr.services, pans[i].naptr.regexp, pans[i].naptr.replacement);
                break;
            case RR_LOC:
                fprintf(stream, "lat: %d %d %d %s, long: %d %d %d %s, alt: %ld, size: %llu, hPrec: %llu, vPrec: %llu)", pans[i].loc.latitude.deg,
                        pans[i].loc.latitude.min, pans[i].loc.latitude.sec, pans[i].loc.latitude.nw ? "N" : "S", pans[i].loc.longitude.deg,
                        pans[i].loc.longitude.min, pans[i].loc.longitude.sec, pans[i].loc.longitude.nw ? "W" : "E", pans[i].loc.altitude,
                        pans[i].loc.size, pans[i].loc.horiz_pre, pans[i].loc.vert_pre);
                break;
            case RR_SRV:
                fprintf(stream, "priority: %d, weight: %d, port: %d, target: %s", pans[i].srv.priority, pans[i].srv.weight, pans[i].srv.port,
                        pans[i].srv.target);
                break;
            case RR_OPT:
                fprintf(stream, "payload = %lu, DO = %s, #opts = %lu\n", (unsigned long)pans[i].opt.udp_payload, pans[i].opt.fdo ? "true" : "false",
                        (unsigned long)pans[i].opt.numopts);
                break;

            default:
                fprintf(stream, "<data>");
                break;
        }
        fprintf(stream, "\n");
    }
}  // End of dns_print_answer

/**********************************************************************/

void dns_print_result(FILE *stream, const dns_query_t *presult) {
    if (presult == NULL) return;
    dns_print_header(stream, presult);
    dns_print_question(stream, presult->questions, presult->qdcount);
    dns_print_answer(stream, "DNS Answer", presult->answers, presult->ancount);
    dns_print_answer(stream, "DNS Nameserver", presult->nameservers, presult->nscount);
    dns_print_answer(stream, "DNS Additional", presult->additional, presult->arcount);
}  // End of dns_print_result