#!/bin/sh
#  This file is part of the nfdump project.
#
#  Copyright (c) 2026, Peter Haag
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#
#   * Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions and the following disclaimer in the documentation
#     and/or other materials provided with the distribution.
#   * Neither the name of Peter Haag nor the names of its contributors may be
#     used to endorse or promote products derived from this software without
#     specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#  POSSIBILITY OF SUCH DAMAGE.
#
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/testsetup.sh"

echo ""
echo "── nfdump read / write / sort ───────────────────────────────────────────"

# raw output matches reference
if nfdump -r dummy_flows.nf -q -o raw >"$WORKDIR/raw.txt" 2>/dev/null \
   && diff -u "$WORKDIR/raw.txt" "$SCRIPT_DIR/ref_raw.txt" >/dev/null 2>&1; then
    pass "raw_output"
else
    fail "raw_output"
fi

# lzo compress + read back — output must match uncompressed reference
if nfdump -r dummy_flows.nf -q -z=lzo -w "$WORKDIR/lzo.nf" >/dev/null 2>&1 \
   && nfdump -v check -r "$WORKDIR/lzo.nf" >/dev/null 2>&1 \
   && nfdump -r "$WORKDIR/lzo.nf" -q -o raw >"$WORKDIR/lzo.txt" 2>/dev/null \
   && diff -u "$WORKDIR/lzo.txt" "$SCRIPT_DIR/ref_raw.txt" >/dev/null 2>&1; then
    pass "lzo_compress_read"
else
    fail "lzo_compress_read"
fi

# tstart sort order (uses the lzo-compressed file from the previous test)
if nfdump -r "$WORKDIR/lzo.nf" -q -O tstart -o raw \
          >"$WORKDIR/tstart_sort.txt" 2>/dev/null \
   && diff -u "$WORKDIR/tstart_sort.txt" "$SCRIPT_DIR/ref_tstart_sort.txt" >/dev/null 2>&1; then
    pass "tstart_sort"
else
    fail "tstart_sort"
fi

# write descending (tstart) sorted table, change ident, compare output
if nfdump -r dummy_flows.nf -O tstart -z=lzo -w "$WORKDIR/descending_sort.nf" >/dev/null 2>&1 \
   && nfdump -v check -r "$WORKDIR/descending_sort.nf" >/dev/null 2>&1 \
   && nfdump -r "$WORKDIR/descending_sort.nf" -i TestFlows >/dev/null 2>&1 \
   && nfdump -q -r "$WORKDIR/descending_sort.nf" -o raw \
             >"$WORKDIR/descending_sort.txt" 2>/dev/null \
   && diff -u "$WORKDIR/descending_sort.txt" "$SCRIPT_DIR/ref_descending_sort.txt" \
             >/dev/null 2>&1; then
    pass "descending_sort_ident"
else
    fail "descending_sort_ident"
fi

# bytes sort + lz4 compress; round-trip output must match unsorted bytes reference
if nfdump -r dummy_flows.nf -q -O bytes -o raw >"$WORKDIR/bytes_sort.txt" 2>/dev/null \
   && nfdump -r dummy_flows.nf -O bytes -z=lz4 -w "$WORKDIR/bytes_sort.nf" >/dev/null 2>&1 \
   && nfdump -v check -r "$WORKDIR/bytes_sort.nf" >/dev/null 2>&1 \
   && nfdump -r "$WORKDIR/bytes_sort.nf" -i TestFlows >/dev/null 2>&1 \
   && diff -u "$WORKDIR/bytes_sort.txt" "$SCRIPT_DIR/ref_bytes_sort.txt" >/dev/null 2>&1; then
    pass "bytes_sort_lz4"
else
    fail "bytes_sort_lz4"
fi

summary
