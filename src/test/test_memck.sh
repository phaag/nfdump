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
echo "── memory guard checks ──────────────────────────────────────────────────"

mkdir -p "$WORKDIR/memck"
export MALLOC_OPTIONS=CFGJS
export MallocGuardEdges=1
export MallocStackLogging=1
export MallocStackLoggingDirectory="$WORKDIR/memck"
export MallocScribble=1
export MallocErrorAbort=1
export MallocCorruptionAbort=1

if nfdump -r dummy_flows.nf 'host 172.16.2.66' >/dev/null 2>&1; then
    pass "memck_filter"
else
    fail "memck_filter"
fi
if nfdump -r dummy_flows.nf -s ip 'host 172.16.2.66' >/dev/null 2>&1; then
    pass "memck_stats_ip"
else
    fail "memck_stats_ip"
fi
if nfdump -r dummy_flows.nf -s record 'host 172.16.2.66' >/dev/null 2>&1; then
    pass "memck_stats_record"
else
    fail "memck_stats_record"
fi
if nfdump -r dummy_flows.nf -w "$WORKDIR/memck_filter.nf" \
          'host 172.16.2.66' >/dev/null 2>&1; then
    pass "memck_write_filter"
else
    fail "memck_write_filter"
fi
if nfdump -r dummy_flows.nf -O tstart -w "$WORKDIR/memck_sort.nf" \
          'host 172.16.2.66' >/dev/null 2>&1; then
    pass "memck_write_sort"
else
    fail "memck_write_sort"
fi

unset MALLOC_OPTIONS MallocGuardEdges MallocStackLogging MallocStackLoggingDirectory \
      MallocScribble MallocErrorAbort MallocCorruptionAbort

summary
