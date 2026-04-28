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

# ── nfdump read/write/sort/compress tests ─────────────────────────────────────
echo ""
echo "── nfdump read / write / sort / compress ────────────────────────────────"

# 1. raw output matches reference
if nfdump -r dummy_flows.nf -q -o raw >"$WORKDIR/test.1.out" 2>/dev/null \
   && diff -u "$WORKDIR/test.1.out" "$SCRIPT_DIR/nftest.1.out" >/dev/null 2>&1; then
    pass "raw_output"
else
    fail "raw_output"
fi

# 2. lzo compress + read back
if nfdump -r dummy_flows.nf -q -z=lzo -w "$WORKDIR/test.2.flows.nf" >/dev/null 2>&1 \
   && nfdump -v check -r "$WORKDIR/test.2.flows.nf" >/dev/null 2>&1 \
   && nfdump -r "$WORKDIR/test.2.flows.nf" -q -o raw >"$WORKDIR/test.2.out" 2>/dev/null \
   && diff -u "$WORKDIR/test.2.out" "$SCRIPT_DIR/nftest.1.out" >/dev/null 2>&1; then
    pass "lzo_compress_read"
else
    fail "lzo_compress_read"
fi

# 3. tstart sort order (depends on test.2.flows.nf)
if nfdump -r "$WORKDIR/test.2.flows.nf" -q -O tstart -o raw \
          >"$WORKDIR/test.3.out" 2>/dev/null \
   && diff -u "$WORKDIR/test.3.out" "$SCRIPT_DIR/nftest.2.out" >/dev/null 2>&1; then
    pass "tstart_sort"
else
    fail "tstart_sort"
fi

# 4. write descending sorted table + change ident
if nfdump -r dummy_flows.nf -O tstart -z=lzo -w "$WORKDIR/test.4.flows.nf" >/dev/null 2>&1 \
   && nfdump -v check -r "$WORKDIR/test.4.flows.nf" >/dev/null 2>&1 \
   && nfdump -r "$WORKDIR/test.4.flows.nf" -i TestFlows >/dev/null 2>&1 \
   && nfdump -q -r "$WORKDIR/test.4.flows.nf" -o raw >"$WORKDIR/test.4.out" 2>/dev/null \
   && diff -u "$WORKDIR/test.4.out" "$SCRIPT_DIR/nftest.4.out" >/dev/null 2>&1; then
    pass "descending_sort_ident"
else
    fail "descending_sort_ident"
fi

# 5. bytes sort + lz4 compress
if nfdump -r dummy_flows.nf -q -O bytes -o raw >"$WORKDIR/test.5.out" 2>/dev/null \
   && nfdump -r dummy_flows.nf -O bytes -z=lz4 -w "$WORKDIR/test.5.flows.nf" >/dev/null 2>&1 \
   && nfdump -v check -r "$WORKDIR/test.5.flows.nf" >/dev/null 2>&1 \
   && nfdump -r "$WORKDIR/test.5.flows.nf" -i TestFlows >/dev/null 2>&1 \
   && nfdump -r "$WORKDIR/test.5.flows.nf" -q -o raw >"$WORKDIR/test.5-2.out" 2>/dev/null \
   && diff -u "$WORKDIR/test.5.out" "$SCRIPT_DIR/nftest.5.out" >/dev/null 2>&1; then
    pass "bytes_sort_lz4"
else
    fail "bytes_sort_lz4"
fi

# ── live collection (nfcapd + nfreplay) ───────────────────────────────────────
echo ""
echo "── live collection ──────────────────────────────────────────────────────"

cp dummy_flows.nf first.nf
if nfdump -r dummy_flows.nf -w second.nf 2>/dev/null \
    && ./test_append first.nf second.nf; then
        pass "RenameAppend"
    else
        fail "RenameAppend"
fi

COLLECT_FILE=""
if [ ! -x "$NFREPLAY_BIN" ]; then
    skip "live_collect: nfreplay not available"
else
    COLLECT_DIR="$WORKDIR/collect"
    mkdir -p "$COLLECT_DIR"
    nfcapd -p 65530 -w "$COLLECT_DIR" -D \
           -P "$COLLECT_DIR/pidfile" -I TestIdent -z=lz4 >/dev/null 2>&1
    sleep 1
    nfreplay -r dummy_flows.nf -v9 -H 127.0.0.1 -p 65530 >/dev/null 2>&1
    sleep 1
    kill -TERM "$(cat "$COLLECT_DIR/pidfile" 2>/dev/null)" 2>/dev/null || true
    sleep 1

    if [ -f "$COLLECT_DIR/pidfile" ]; then
        fail "live_collect: nfcapd did not terminate"
    else
        COLLECT_FILE=$(ls "$COLLECT_DIR"/nfcapd.* 2>/dev/null | head -1)
        if [ -z "$COLLECT_FILE" ]; then
            fail "live_collect: no output file created"
        else
            nfdump -r dummy_flows.nf -q -o extended -6 'packets > 0' \
                   >"$WORKDIR/ref.6.out" 2>/dev/null
            nfdump -v check -r "$COLLECT_FILE" >/dev/null 2>&1
            nfdump -r "$COLLECT_FILE" -q -o extended -6 >"$WORKDIR/test.6.out" 2>/dev/null
            nfexpire -l "$COLLECT_DIR" >/dev/null 2>&1
            if diff "$WORKDIR/ref.6.out" "$WORKDIR/test.6.out" >/dev/null 2>&1; then
                pass "live_collect"
            else
                fail "live_collect: output differs from reference"
            fi
        fi
    fi
fi

# ── AppendRename ──────────────────────────────────────────────────────────────
echo ""
echo "── AppendRename ─────────────────────────────────────────────────────────"

if [ ! -x "$NFREPLAY_BIN" ]; then
    skip "append_rename: nfreplay not available"
else
    APPEND_DIR="$WORKDIR/append"
    mkdir -p "$APPEND_DIR"

    # Cycle 1
    nfcapd -p 65531 -w "$APPEND_DIR" -D \
           -P "$APPEND_DIR/pidfile" -I TestIdent -t 3600 -z=lz4 >/dev/null 2>&1
    sleep 1
    nfreplay -r dummy_flows.nf -v9 -H 127.0.0.1 -p 65531 >/dev/null 2>&1
    sleep 1
    kill -TERM "$(cat "$APPEND_DIR/pidfile" 2>/dev/null)" 2>/dev/null || true
    sleep 1

    # Cycle 2
    nfcapd -p 65531 -w "$APPEND_DIR" -D \
           -P "$APPEND_DIR/pidfile" -I TestIdent -t 3600 -z=lz4 >/dev/null 2>&1
    sleep 1
    nfreplay -r dummy_flows.nf -v9 -H 127.0.0.1 -p 65531 >/dev/null 2>&1
    sleep 1
    kill -TERM "$(cat "$APPEND_DIR/pidfile" 2>/dev/null)" 2>/dev/null || true
    sleep 1

    if [ -f "$APPEND_DIR/pidfile" ]; then
        fail "append_rename: nfcapd did not terminate on second cycle"
    elif nfdump -X -v check -r "$APPEND_DIR"/nfcapd.* >/dev/null 2>&1; then
        pass "append_rename"
    else
        fail "append_rename: file check failed after two cycles"
    fi
fi

# ── memory guard checks ───────────────────────────────────────────────────────
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
if nfdump -r dummy_flows.nf -w "$WORKDIR/test.7.flows.nf" \
          'host 172.16.2.66' >/dev/null 2>&1; then
    pass "memck_write_filter"
else
    fail "memck_write_filter"
fi
if nfdump -r dummy_flows.nf -O tstart -w "$WORKDIR/test.8.flows.nf" \
          'host 172.16.2.66' >/dev/null 2>&1; then
    pass "memck_write_sort"
else
    fail "memck_write_sort"
fi

unset MALLOC_OPTIONS MallocGuardEdges MallocStackLogging MallocStackLoggingDirectory \
      MallocScribble MallocErrorAbort MallocCorruptionAbort

# ── nfanon ────────────────────────────────────────────────────────────────────
echo ""
echo "── nfanon ───────────────────────────────────────────────────────────────"

if nfanon -K abcdefghijklmnopqrstuvwxyz012345 \
          -r dummy_flows.nf -w "$WORKDIR/test.9.flows.nf" >/dev/null 2>&1 \
   && nfdump -q -r "$WORKDIR/test.9.flows.nf" -o raw >/dev/null 2>&1; then
    pass "nfanon"
else
    fail "nfanon"
fi

# ── ChangeIdent ───────────────────────────────────────────────────────────────
echo ""
echo "── ChangeIdent ──────────────────────────────────────────────────────────"

# Use the AppendRename output file if available.
APPEND_FILE=$(ls "$WORKDIR/append"/nfcapd.* 2>/dev/null | head -1)
if [ -n "$APPEND_FILE" ] && [ -f "$APPEND_FILE" ]; then
    if nfdump -r "$APPEND_FILE" -i NewIdent >/dev/null 2>&1; then
        pass "change_ident"
    else
        fail "change_ident"
    fi
else
    skip "change_ident: no AppendRename file available"
fi

summary
