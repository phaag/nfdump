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
#   NFCAPD_BIN, NFDUMP_BIN,         — binary paths
#   NFREPLAY_BIN, NFEXPIRE_BIN,
#   NFANON_BIN
#   nfcapd(), nfdump(), nfreplay(), — wrapper functions (-G none pre-applied
#   nfexpire(), nfanon()              to nfdump; all others pass-through)
#   PASS, FAIL, SKIP                — counters (initialised to 0)
#   pass(), fail(), skip()          — increment counter and print test result
#   WORKDIR                         — private temp directory (auto-removed)
#   cleanup()                       — kill stray daemons + rm WORKDIR
#   summary()                       — print result table; exits 1 if FAIL > 0

TZ=Europe/Zurich
export TZ

# ── locate binaries and test data ─────────────────────────────────────────────
BINDIR="$SCRIPT_DIR/.."
# test data for nfcapd tests lives two levels up under test/nfcapd/
TESTDATA=$(cd "$SCRIPT_DIR/../../test/nfcapd" 2>/dev/null && pwd)

NFCAPD_BIN="$BINDIR/nfcapd/nfcapd"
NFDUMP_BIN="$BINDIR/nfdump/nfdump"
NFREPLAY_BIN="$BINDIR/nfreplay/nfreplay"
NFEXPIRE_BIN="$BINDIR/nfexpire/nfexpire"
NFANON_BIN="$BINDIR/nfanon/nfanon"

# Wrapper functions — callers never need to worry about path quoting or
# the -G none flag that suppresses geo-lookup during tests.
nfcapd()  { "$NFCAPD_BIN"  "$@"; }
nfdump()  { "$NFDUMP_BIN"  -G none "$@"; }
nfreplay(){ "$NFREPLAY_BIN" "$@"; }
nfexpire(){ "$NFEXPIRE_BIN" "$@"; }
nfanon()  { "$NFANON_BIN"  "$@"; }

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
# Print the final pass/fail/skip table and exit with 1 if any tests failed.
# Call as the last statement in every test script.
summary() {
    echo ""
    echo "========================================================================="
    printf "  Results:  %d passed  |  %d failed  |  %d skipped\n" \
           "$PASS" "$FAIL" "$SKIP"
    echo "========================================================================="
    echo ""
    [ "$FAIL" -eq 0 ]
}
