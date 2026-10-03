#!/bin/sh
#  This file is part of the nfdump project.
#
#  Copyright (c) 2023, Peter Haag
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
# Common test setup — source this file near the top of every test script:
#
#   SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
#   . "$SCRIPT_DIR/testsetup.sh"
#
# SCRIPT_DIR must be set by the sourcing script before sourcing this file.
# After sourcing, the following are available:
#
#   BINDIR, TESTDATA                — directory paths
#   MAXMIND_TESTDATA                — test/maxmind/ fixture directory
#   NFCAPD_BIN, SFCAPD_BIN,         — collector binary paths
#   NFDUMP_BIN, SFLOWGEN_BIN,       — tool and fixture-generator binary paths
#   NFREPLAY_BIN, NFEXPIRE_BIN, NFMETA_BIN,
#   NFANON_BIN, GEOLOOKUP_BIN
#   nfcapd(), nfdump(), nfreplay(), — wrapper functions (-G none pre-applied
#   nfexpire(), nfanon(),             to nfdump; all others pass-through)
#   geolookup()
#   PASS, FAIL, SKIP                — counters (initialised to 0)
#   pass(), fail(), skip()          — increment counter and print test result
#   WORKDIR                         — private temp directory (auto-removed)
#   cleanup()                       — kill stray daemons + rm WORKDIR
#   summary()                       — print result table; exits 1 if FAIL > 0

TZ=Europe/Zurich
export TZ

# ── locate binaries and test data ─────────────────────────────────────────────
: "${BINDIR:=$SCRIPT_DIR/..}"
# test data for nfcapd tests lives two levels up under test/nfcapd/
TESTDATA=$(cd "$SCRIPT_DIR/../../test/nfcapd" 2>/dev/null && pwd)
# CSV fixtures for the maxmind geoDB tests live under test/maxmind/
MAXMIND_TESTDATA=$(cd "$SCRIPT_DIR/../../test/maxmind" 2>/dev/null && pwd)

NFCAPD_BIN="$BINDIR/nfcapd/nfcapd"
SFCAPD_BIN="$BINDIR/sflow/sfcapd"
NFDUMP_BIN="$BINDIR/nfdump/nfdump"
SFLOWGEN_BIN="$BINDIR/test/sflowgen"
NFREPLAY_BIN="$BINDIR/nfreplay/nfreplay"
NFEXPIRE_BIN="$BINDIR/nfexpire/nfexpire"
NFANON_BIN="$BINDIR/nfanon/nfanon"
NFMETA_BIN="$BINDIR/nfmeta/nfmeta"
GEOLOOKUP_BIN="$BINDIR/maxmind/geolookup"

# Wrapper functions — callers never need to worry about path quoting or
# the -G none flag that suppresses geo-lookup during tests.
nfcapd()  { "$NFCAPD_BIN"  "$@"; }
nfdump()  { "$NFDUMP_BIN"  -G none "$@"; }
nfreplay(){ "$NFREPLAY_BIN" "$@"; }
nfexpire(){ "$NFEXPIRE_BIN" "$@"; }
nfanon()  { "$NFANON_BIN"  "$@"; }
geolookup(){ "$GEOLOOKUP_BIN" "$@"; }

# wait_start PIDFILE [SECONDS]
# Wait until a daemon started with -D has written its pidfile (default 10s).
# nfcapd and sfcapd bind their listening socket before the pidfile is written,
# so a daemon accepts data once the pidfile exists. Returns 1 on timeout.
wait_start() {
    _ws_max=$(( ${2:-10} * 10 ))
    _ws_i=0
    while [ ! -s "$1" ] && [ "$_ws_i" -lt "$_ws_max" ]; do
        sleep 0.1
        _ws_i=$((_ws_i + 1))
    done
    [ -s "$1" ]
}

# ── pass / fail / skip accounting ─────────────────────────────────────────────
PASS=0; FAIL=0; SKIP=0

pass() { PASS=$((PASS+1)); printf "  PASS  %s\n" "$1"; }
fail() { FAIL=$((FAIL+1)); printf "  FAIL  %s\n" "$1"; }
skip() { SKIP=$((SKIP+1)); printf "  SKIP  %s\n" "$1"; }

# ── temporary workspace ────────────────────────────────────────────────────────
WORKDIR=$(mktemp -d /tmp/nftest.XXXXXX)

cleanup() {
    # Terminate any stray nfcapd daemons started by this script.
    for pf in "$WORKDIR"/*/pidfile; do
        [ -f "$pf" ] || continue
        kill "$(cat "$pf")" 2>/dev/null || true
        i=0; while [ -f "$pf" ] && [ "$i" -lt 3 ]; do sleep 1; i=$((i+1)); done
    done
    rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM HUP

# ── summary ────────────────────────────────────────────────────────────────────
# Print the final pass/fail/skip table. Returns 1 if any tests failed, 77 if
# all tests were skipped (automake reports SKIP), 0 otherwise.
# Call as the last statement in every test script.
summary() {
    echo ""
    echo "========================================================================="
    printf "  Results:  %d passed  |  %d failed  |  %d skipped\n" \
           "$PASS" "$FAIL" "$SKIP"
    echo "========================================================================="
    echo ""
    [ "$FAIL" -eq 0 ] || return 1
    # nothing could be tested: report the whole test as skipped (automake: 77)
    if [ "$PASS" -eq 0 ] && [ "$SKIP" -gt 0 ]; then return 77; fi
    return 0
}

# add_index_block <in> <out> - append a reserved BLOCK_TYPE_INDEX block to an
# unencrypted nffile V3 without directory checksum. Requires python3.
add_index_block() {
    python3 - "$1" "$2" <<'PYEOF'
import struct, sys
data = open(sys.argv[1], 'rb').read()
HDR = '<HHIQHHIIIQQ'                      # fileHeaderV3_t, 48 bytes
hdr = list(struct.unpack_from(HDR, data, 0))
offDir = hdr[9]
magic, num = struct.unpack_from('<II', data, offDir)
entries = [struct.unpack_from('<IIQ', data, offDir + 8 + 16 * i) for i in range(num)]
ftr = struct.unpack_from('<IIQQ32s', data, len(data) - 56)
if ftr[3] != 0 or any(ftr[4]):
    sys.exit("file has a directory checksum or MAC - not supported")
payload = b'NFINDEX0' * 2
# BLOCKHEADER: type 8 = BLOCK_TYPE_INDEX, discSize, rawSize, NOT_COMPRESSED, NOT_ENCRYPTED, checksum
block = struct.pack('<IIIHHQ', 8, 24 + len(payload), 24 + len(payload), 1, 0, 0) + payload
out = bytearray(data[:offDir])
entries.append((8, len(block), len(out)))
out += block
newOff = len(out)
out += struct.pack('<II', magic, len(entries)) + b''.join(struct.pack('<IIQ', *e) for e in entries)
out += struct.pack('<IIQQ32s', ftr[0], len(out) - newOff, newOff, 0, bytes(32))
hdr[8], hdr[9] = len(out) - newOff - 56, newOff
out[0:48] = struct.pack(HDR, *hdr)
open(sys.argv[2], 'wb').write(out)
PYEOF
}

# index_blocks <file> - number of index blocks reported by nfdump -v check
index_blocks() { nfdump -v check -r "$1" 2>/dev/null | sed -n 's/^ *Index blocks *: *\([0-9]*\).*/\1/p'; }
