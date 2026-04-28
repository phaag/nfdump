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
echo "── RenameAppendV3 ───────────────────────────────────────────────────────"

# Verify that the test_append binary exists
if [ ! -x "$SCRIPT_DIR/test_append" ]; then
    skip "rename_append_unit: test_append binary not built"
    skip "rename_append_dir:  test_append binary not built"
    summary
    exit 0
fi

# Unit test: append two flow files using test_append, verify nfdump -v check
APPEND_UNIT="$WORKDIR/append_unit"
mkdir -p "$APPEND_UNIT"
cp dummy_flows.nf "$APPEND_UNIT/first.nf"
if nfdump -r dummy_flows.nf -w "$APPEND_UNIT/second.nf" >/dev/null 2>&1 \
   && "$SCRIPT_DIR/test_append" "$APPEND_UNIT/second.nf" "$APPEND_UNIT/first.nf" \
      >/dev/null 2>&1 \
   && nfdump -v check -r "$APPEND_UNIT/first.nf" >/dev/null 2>&1; then
    pass "rename_append_unit"
else
    fail "rename_append_unit"
fi

# Live test: two consecutive nfcapd cycles into the same output directory.
# The second cycle must AppendRename the in-progress file from cycle 1.
# Requires nfreplay; skip gracefully if not available.
if [ ! -x "$NFREPLAY_BIN" ]; then
    skip "rename_append_live: nfreplay not available"
else
    APPEND_LIVE="$WORKDIR/append_live"
    mkdir -p "$APPEND_LIVE"
    BASE_PORT=$(( 49200 + $$ % 16000 ))

    # Cycle 1
    nfcapd -p "$BASE_PORT" -4 -w "$APPEND_LIVE" -D \
           -P "$APPEND_LIVE/pidfile" -I TestIdent -t 3600 -z=lz4 >/dev/null 2>&1
    sleep 1
    nfreplay -r dummy_flows.nf -v9 -H 127.0.0.1 -p "$BASE_PORT" >/dev/null 2>&1
    sleep 1
    kill -TERM "$(cat "$APPEND_LIVE/pidfile" 2>/dev/null)" 2>/dev/null || true
    sleep 1

    # Cycle 2
    nfcapd -p "$BASE_PORT" -4 -w "$APPEND_LIVE" -D \
           -P "$APPEND_LIVE/pidfile" -I TestIdent -t 3600 -z=lz4 >/dev/null 2>&1
    sleep 1
    nfreplay -r dummy_flows.nf -v9 -H 127.0.0.1 -p "$BASE_PORT" >/dev/null 2>&1
    sleep 1
    kill -TERM "$(cat "$APPEND_LIVE/pidfile" 2>/dev/null)" 2>/dev/null || true
    sleep 1

    if [ -f "$APPEND_LIVE/pidfile" ]; then
        fail "rename_append_live: nfcapd did not terminate on second cycle"
    elif nfdump -X -v check -r "$APPEND_LIVE"/nfcapd.* >/dev/null 2>&1; then
        pass "rename_append_live"
    else
        fail "rename_append_live: file check failed after two cycles"
    fi
fi

summary
