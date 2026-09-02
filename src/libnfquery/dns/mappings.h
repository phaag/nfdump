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

/**************************************************************************
 *
 * Useful routines to convert error codes, RR, Class and Opcode values into
 * strings, and strings into their equivilent RR, Class or Opcode values.
 *
 * This file assumes C99.  You must include the following files before
 * including this one:
 *
 * #include "dns.h"
 *
 **************************************************************************/

#ifndef I_E2A4214D_2476_5EA3_92C1_9E450F8F349E
#define I_E2A4214D_2476_5EA3_92C1_9E450F8F349E

#include "codec.h"

#ifndef __GNUC__
#define __attribute__(x)
#endif

struct int_string_map {
    int const value;
    char const *const text;
};

extern struct int_string_map const c_dns_rcode_enum[];

extern char const *dns_rcode_enum(dns_rcode_t) __attribute__((pure, nothrow));
extern char const *dns_rcode_text(dns_rcode_t) __attribute__((pure, nothrow));
extern char const *dns_type_text(dns_type_t) __attribute__((pure, nothrow));
extern char const *dns_class_text(dns_class_t) __attribute__((pure, nothrow));
extern char const *dns_op_text(dns_op_t) __attribute__((pure, nothrow));

extern dns_rcode_t dns_rcode_value(char const *) __attribute__((pure, nothrow, nonnull));
extern dns_type_t dns_type_value(char const *) __attribute__((pure, nothrow, nonnull));
extern dns_class_t dns_class_value(char const *) __attribute__((pure, nothrow, nonnull));
extern dns_op_t dns_op_value(char const *) __attribute__((pure, nothrow, nonnull));

#endif
