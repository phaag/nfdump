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
echo "── live collection (nfcapd + nfreplay) ──────────────────────────────────"

if [ ! -x "$NFREPLAY_BIN" ]; then
    skip "live_collect: nfreplay not available"
    skip "live_collect_ident: nfreplay not available"
    summary
    exit 0
fi

BASE_PORT=$(( 49300 + $$ % 16000 ))
COLLECT_DIR="$WORKDIR/collect"
mkdir -p "$COLLECT_DIR"

nfcapd -p "$BASE_PORT" -4 -w "$COLLECT_DIR" -D \
       -P "$COLLECT_DIR/pidfile" -I TestIdent -z=lz4 >/dev/null 2>&1
sleep 1
if [ ! -s "$COLLECT_DIR/pidfile" ]; then
    skip "live_collect: local UDP listener unavailable"
    skip "live_collect_ident: local UDP listener unavailable"
    summary
    exit 0
fi
nfreplay -r dummy_flows.nf -v9 -H 127.0.0.1 -p "$BASE_PORT" >/dev/null 2>&1
sleep 1
kill -TERM "$(cat "$COLLECT_DIR/pidfile" 2>/dev/null)" 2>/dev/null || true
sleep 1

if [ -f "$COLLECT_DIR/pidfile" ]; then
    fail "live_collect: nfcapd did not terminate"
    skip "live_collect_ident: preceding test failed"
else
    COLLECT_FILE=$(ls "$COLLECT_DIR"/nfcapd.* 2>/dev/null | head -1)
    if [ -z "$COLLECT_FILE" ]; then
        fail "live_collect: no output file created"
        skip "live_collect_ident: no output file"
    else
        # Collected output must reproduce the same flow identity and
        # counters as the source file. Duration/pps/bps are deliberately
        # excluded from this comparison: NetFlow v9's NSEL/ASA event fields
        # (used by some dummy_flows.nf records) make netflow_v9.c legitimately
        # collapse msecLast to msecFirst and flag the record as a
        # point-in-time EVENT rather than a duration-spanning flow - correct
        # NSEL semantics, not a replay/collection defect - so a record with
        # those fields has a real, expected duration mismatch against the
        # source file that never went through that decode path.
        FMT='fmt:%ts %pr %sap -> %dap %flg %pkt %byt %fl'
        nfdump -r dummy_flows.nf -q -o "$FMT" -6 'packets > 0' \
               >"$WORKDIR/collect_ref.txt" 2>/dev/null
        nfdump -v check -r "$COLLECT_FILE" >/dev/null 2>&1
        nfdump -r "$COLLECT_FILE" -q -o "$FMT" -6 \
               >"$WORKDIR/collect.txt" 2>/dev/null
        nfexpire -l "$COLLECT_DIR" >/dev/null 2>&1
        if diff "$WORKDIR/collect_ref.txt" "$WORKDIR/collect.txt" >/dev/null 2>&1; then
            pass "live_collect"
        else
            fail "live_collect: output differs from reference"
        fi

        # ChangeIdent on the collected file
        if nfdump -r "$COLLECT_FILE" -i NewIdent >/dev/null 2>&1; then
            pass "live_collect_ident"
        else
            fail "live_collect_ident"
        fi
    fi
fi

summary
