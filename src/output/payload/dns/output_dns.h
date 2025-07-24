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

#ifndef _OUTPUT_DNS_H
#define _OUTPUT_DNS_H

#include <stdio.h>

#include "dns/codec.h"

void dns_print_result(FILE *stream, const dns_query_t *presult);

#endif
