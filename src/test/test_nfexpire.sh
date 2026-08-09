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
# nfexpire regression test suite.
# Tests: rescan bookkeeping, -u limit persistence (incl. watermark), dry-run
#        and real size-triggered FIFO expiry, lifetime-triggered expiry,
#        concurrent-collector safety, profile (-p) lockstep expiry, basic
#        CLI validation.
#
# Fixture files are plain copies of dummy_flows.nf renamed to
# nfcapd.<timestamp> - nfexpire only cares about the filename pattern and
# on-disk size (st_blocks*512), never the file's content.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/testsetup.sh"

echo ""
echo "── nfexpire ─────────────────────────────────────────────────────────────"

EXPBASE="$WORKDIR/expire"
mkdir -p "$EXPBASE"

# st_blocks*512 of a file - matches nfexpire's own disk-usage accounting
# exactly (RescanDir/ExpireDir both use fts_statp->st_blocks * 512ULL).
# st_blocks is always in 512-byte units per POSIX, independent of the
# filesystem's actual block size, so this is portable.
file_disk_bytes() {
    blocks=$(stat -f%b "$1" 2>/dev/null || stat -c%b "$1" 2>/dev/null)
    echo $((blocks * 512))
}

# make_files <dir> <timestamp> [<timestamp> ...]
# Populate <dir> with one nfcapd.<timestamp> file per argument.
make_files() {
    dir="$1"
    shift
    for ts in "$@"; do
        cp dummy_flows.nf "$dir/nfcapd.$ts"
    done
}

# get_stat_field <nfexpire -l output> <field prefix>
# Field separator is exactly ": " (colon + one space) - NOT ": *", which
# would also split on the bare colons inside "First"/"Last" time values
# (e.g. "00:00:00" has no space after its colons, so it survives intact).
get_stat_field() {
    printf '%s\n' "$1" | awk -F': ' -v pat="^$2" '$0 ~ pat {print $2}'
}

ONE_FILE_BYTES=$(file_disk_bytes dummy_flows.nf)

# ---------------------------------------------------------------------------
# 1. Rescan populates correct bookkeeping from pre-existing files
# ---------------------------------------------------------------------------
D1="$EXPBASE/1_rescan"
mkdir -p "$D1"
make_files "$D1" 202601010000 202601010005 202601010010

nfexpire -r "$D1" >"$WORKDIR/1_rescan.log" 2>&1
STAT=$(nfexpire -l "$D1" 2>&1)
NUMFILES=$(get_stat_field "$STAT" "Number of files")
FSIZE=$(get_stat_field "$STAT" "Total file size")
FIRST=$(get_stat_field "$STAT" "First")
LAST=$(get_stat_field "$STAT" "Last")
EXPECT_SIZE=$((ONE_FILE_BYTES * 3))

if [ "$NUMFILES" = "3" ] && [ "$FSIZE" = "$EXPECT_SIZE" ] \
   && [ "$FIRST" = "2026-01-01 00:00:00" ] && [ "$LAST" = "2026-01-01 00:10:00" ]; then
    pass "nfexpire_rescan"
else
    fail "nfexpire_rescan: numfiles=$NUMFILES size=$FSIZE(want $EXPECT_SIZE) first='$FIRST' last='$LAST'"
fi

# ---------------------------------------------------------------------------
# 2. -u persists size, lifetime AND watermark - direct regression test for
#    the watermark bug (book_set_limits() used to bump ->sequence instead of
#    storing ->watermark, so this field silently stayed 0 forever).
# ---------------------------------------------------------------------------
D2="$EXPBASE/2_limits"
mkdir -p "$D2"
make_files "$D2" 202601010000
nfexpire -r "$D2" >/dev/null 2>&1

nfexpire -u "$D2" -s 100k -t 30d -w 50 >"$WORKDIR/2_update.log" 2>&1
STAT=$(nfexpire -l "$D2" 2>&1)
MAXSIZE=$(get_stat_field "$STAT" "Max file size")
MAXLIFE=$(get_stat_field "$STAT" "Max life time")
WATERMARK=$(get_stat_field "$STAT" "Watermark")

if [ "$MAXSIZE" = "102400" ] && [ "$MAXLIFE" = "2592000" ] && [ "$WATERMARK" = "50" ]; then
    pass "nfexpire_update_limits"
else
    fail "nfexpire_update_limits: maxsize=$MAXSIZE maxlife=$MAXLIFE watermark=$WATERMARK (want 102400/2592000/50)"
fi

# ---------------------------------------------------------------------------
# 3. Dry-run reports without deleting anything
# ---------------------------------------------------------------------------
D3="$EXPBASE/3_dryrun"
mkdir -p "$D3"
make_files "$D3" 202601010000 202601010005 202601010010 202601010015 202601010020 202601010025
nfexpire -r "$D3" >/dev/null 2>&1
LIMIT=$((ONE_FILE_BYTES * 4))
nfexpire -u "$D3" -s "$LIMIT" -w 50 >/dev/null 2>&1

DRYOUT=$(nfexpire -e "$D3" -n 2>&1)
REMAINING=$(ls "$D3"/nfcapd.* 2>/dev/null | wc -l | tr -d ' ')

if [ "$REMAINING" = "6" ] && printf '%s' "$DRYOUT" | grep -q "Would delete file.*202601010000"; then
    pass "nfexpire_dryrun"
else
    fail "nfexpire_dryrun: remaining=$REMAINING (want 6, nothing deleted); output: $DRYOUT"
fi

# ---------------------------------------------------------------------------
# 4. Real size-triggered expiry: FIFO oldest-first, stops at the watermark
#    target. 6 files, maxsize=4x, watermark=50% -> target=2x -> the 4 oldest
#    are deleted, the 2 newest survive (hand-verified arithmetic, see the
#    review notes: current_size must drop to <= target before a file is kept).
# ---------------------------------------------------------------------------
D4="$EXPBASE/4_expire_size"
mkdir -p "$D4"
make_files "$D4" 202601010000 202601010005 202601010010 202601010015 202601010020 202601010025
nfexpire -r "$D4" >/dev/null 2>&1
LIMIT=$((ONE_FILE_BYTES * 4))
nfexpire -u "$D4" -s "$LIMIT" -w 50 >/dev/null 2>&1

nfexpire -e "$D4" >"$WORKDIR/4_expire.log" 2>&1
REMAINING=$(ls "$D4"/nfcapd.* 2>/dev/null | sort)
REMAINING_COUNT=$(printf '%s\n' "$REMAINING" | grep -c .)
OLDEST_GONE=1
[ -e "$D4/nfcapd.202601010000" ] && OLDEST_GONE=0
[ -e "$D4/nfcapd.202601010015" ] && OLDEST_GONE=0
NEWEST_KEPT=1
[ -e "$D4/nfcapd.202601010020" ] || NEWEST_KEPT=0
[ -e "$D4/nfcapd.202601010025" ] || NEWEST_KEPT=0

if [ "$REMAINING_COUNT" = "2" ] && [ "$OLDEST_GONE" = "1" ] && [ "$NEWEST_KEPT" = "1" ]; then
    pass "nfexpire_expire_size_fifo"
else
    fail "nfexpire_expire_size_fifo: remaining=$REMAINING_COUNT files=[$REMAINING]"
fi

# ---------------------------------------------------------------------------
# 5. Real lifetime-triggered expiry: same 6 files 5 minutes apart (span
#    1500s). maxlife=10M (600s), watermark=50% -> timeLimit = last - 300s
#    = :20 -> files strictly older than :20 are deleted, :20 and :25 survive.
# ---------------------------------------------------------------------------
D5="$EXPBASE/5_expire_life"
mkdir -p "$D5"
make_files "$D5" 202601010000 202601010005 202601010010 202601010015 202601010020 202601010025
nfexpire -r "$D5" >/dev/null 2>&1
nfexpire -u "$D5" -t 10M -w 50 >/dev/null 2>&1

nfexpire -e "$D5" >"$WORKDIR/5_expire_life.log" 2>&1
REMAINING_COUNT=$(ls "$D5"/nfcapd.* 2>/dev/null | grep -c .)
OLDEST_GONE=1
[ -e "$D5/nfcapd.202601010015" ] && OLDEST_GONE=0
NEWEST_KEPT=1
[ -e "$D5/nfcapd.202601010020" ] || NEWEST_KEPT=0
[ -e "$D5/nfcapd.202601010025" ] || NEWEST_KEPT=0

if [ "$REMAINING_COUNT" = "2" ] && [ "$OLDEST_GONE" = "1" ] && [ "$NEWEST_KEPT" = "1" ]; then
    pass "nfexpire_expire_lifetime"
else
    fail "nfexpire_expire_lifetime: remaining=$REMAINING_COUNT (want 2, keeping :20 and :25 only)"
fi

# ---------------------------------------------------------------------------
# 6. Concurrent-collector safety - direct regression test for the
#    BOOK_NOT_EXISTS crash: nfexpire used to segfault (and silently clobber
#    the registered collector pid) whenever it touched a directory a live
#    nfcapd owned. Requires nfreplay/live listener support like test_collect.sh.
# ---------------------------------------------------------------------------
if [ ! -x "$NFCAPD_BIN" ]; then
    skip "nfexpire_live_collector: nfcapd not available"
else
    D6="$WORKDIR/6_live"
    mkdir -p "$D6"
    BASE_PORT=$(( 49500 + $$ % 16000 ))

    nfcapd -p "$BASE_PORT" -4 -w "$D6" -D -P "$D6/pidfile" -I livetest >/dev/null 2>&1
    sleep 1

    if [ ! -f "$D6/pidfile" ]; then
        skip "nfexpire_live_collector: nfcapd did not start"
    else
        COLLECTOR_PID=$(cat "$D6/pidfile")
        BEFORE=$(nfexpire -l "$D6" 2>&1 | head -1)

        nfexpire -l "$D6" >"$WORKDIR/6_live_l.log" 2>&1
        RC_L=$?
        nfexpire -e "$D6" -s 1 -w 50 -n >"$WORKDIR/6_live_e.log" 2>&1
        RC_E=$?

        AFTER=$(nfexpire -l "$D6" 2>&1 | head -1)
        STILL_ALIVE=0
        kill -0 "$COLLECTOR_PID" 2>/dev/null && STILL_ALIVE=1

        kill -TERM "$COLLECTOR_PID" 2>/dev/null || true
        i=0
        while [ -f "$D6/pidfile" ] && [ "$i" -lt 3 ]; do
            sleep 1
            i=$((i + 1))
        done

        if [ "$RC_L" -eq 0 ] && [ "$RC_E" -eq 0 ] && [ "$STILL_ALIVE" = "1" ] \
           && [ "$BEFORE" = "$AFTER" ] && printf '%s' "$BEFORE" | grep -q "$COLLECTOR_PID"; then
            pass "nfexpire_live_collector"
        else
            fail "nfexpire_live_collector: rc_l=$RC_L rc_e=$RC_E alive=$STILL_ALIVE before='$BEFORE' after='$AFTER'"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# 7. Profile mode (-p): lockstep expiry across multiple channel directories.
#    This is the code path (ExpireProfile) that had a real use-after-free
#    crash (WriteStatInfo() was called after book_close() freed the handle
#    it reads) - exercise it for basic correctness/crash safety.
#
#    Note: -p does not support -u at all ("nfexpire cannot update profile
#    parameters") and ExpireProfile() has no fallback to bookkeeper-stored
#    limits the way ExpireDir() does - -s/-t/-w must be given directly on
#    the -e command line every time. That is how NfSen itself always drove
#    this legacy mode, so it is a design characteristic, not a bug.
# ---------------------------------------------------------------------------
D7="$EXPBASE/7_profile"
mkdir -p "$D7/chanA" "$D7/chanB"
make_files "$D7/chanA" 202601010000 202601010005 202601010010
make_files "$D7/chanB" 202601010000 202601010005 202601010010

nfexpire -p -r "$D7" >"$WORKDIR/7_rescan.log" 2>&1
LIMIT=$((ONE_FILE_BYTES * 2))
nfexpire -p -e "$D7" -s "$LIMIT" -w 50 >"$WORKDIR/7_expire.log" 2>&1
RC_P=$?

A_REMAIN=$(ls "$D7/chanA"/nfcapd.* 2>/dev/null | grep -c .)
B_REMAIN=$(ls "$D7/chanB"/nfcapd.* 2>/dev/null | grep -c .)

if [ "$RC_P" -eq 0 ] && [ "$A_REMAIN" = "$B_REMAIN" ] && [ "$A_REMAIN" -lt 3 ]; then
    pass "nfexpire_profile_lockstep"
else
    fail "nfexpire_profile_lockstep: rc=$RC_P chanA=$A_REMAIN chanB=$B_REMAIN (want equal counts, some expired)"
fi

# ---------------------------------------------------------------------------
# 8. Basic CLI sanity
# ---------------------------------------------------------------------------
if nfexpire -h >"$WORKDIR/8_help.log" 2>&1; then
    if grep -q '\-e datadir' "$WORKDIR/8_help.log" && grep -q '\-w watermark' "$WORKDIR/8_help.log"; then
        pass "nfexpire_help"
    else
        fail "nfexpire_help: usage text missing expected options"
    fi
else
    fail "nfexpire_help: -h exited non-zero"
fi

D8="$EXPBASE/8_badarg"
mkdir -p "$D8"
if nfexpire -u "$D8" -w 150 >/dev/null 2>&1; then
    fail "nfexpire_bad_watermark: -w 150 should have been rejected"
else
    pass "nfexpire_bad_watermark"
fi

summary
