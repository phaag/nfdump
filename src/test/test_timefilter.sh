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
echo "── time window filter ───────────────────────────────────────────────────"

# A filter with a time range skips entire files, whose stat record time window
# cannot match, before any data block is read. These tests verify that the
# results are identical to reading all flows, and that files are skipped.

NFGEN2="$BINDIR/test/nfgen2"
nfmeta() { "$NFMETA_BIN" "$@" </dev/null; }

if [ ! -x "$NFGEN2" ] || [ ! -x "$NFMETA_BIN" ]; then
    skip "time window filter: nfgen2 or nfmeta not built"
    summary
    exit $?
fi

# flows <nfdump args> - sorted csv flows without header
flows() {
    nfdump -q -o csv "$@" </dev/null 2>/dev/null | grep '^[0-9]' | sort
}

# same_flows <file1> <file2> - identical flow lists
same_flows() { cmp -s "$1" "$2"; }

# 6 files in 5 minute slots, starting 2024-01-01 01:00 local time (TZ is
# Europe/Zurich, see testsetup.sh). Each file holds 3000 flows over 30s.
# Mixed file formats: nfdump 1.8.x, legacy 1.7.x, and legacy 1.7.x without
# a stat record, which must never be skipped.
TFDIR="$WORKDIR/timefilter"
SRC="$WORKDIR/timefilter_src"
mkdir -p "$TFDIR" "$SRC"
T0=1704067200
ok=1
for i in 0 1 2 3 4 5; do
    t=$((T0 + i * 300))
    name="nfcapd.2024010101$(printf '%02d' $((i * 5)))"
    case "$i" in
        0 | 2 | 4)
            "$NFGEN2" -w "$SRC/$name" -z lz4 -n 3000 -b 1000 -t "$t" >/dev/null 2>&1 \
                && nfmeta -r "$SRC/$name" -w "$TFDIR/$name" >/dev/null 2>&1 || ok=0
            ;;
        1) "$NFGEN2" -w "$TFDIR/$name" -z lz4 -n 3000 -b 1000 -t "$t" >/dev/null 2>&1 || ok=0 ;;
        3) "$NFGEN2" -w "$TFDIR/$name" -z lzo -n 3000 -b 1000 -t "$t" >/dev/null 2>&1 || ok=0 ;;
        5) "$NFGEN2" -w "$TFDIR/$name" -z lz4 -n 3000 -b 1000 -t "$t" -A >/dev/null 2>&1 || ok=0 ;;
    esac
done
flows -R "$TFDIR" >"$WORKDIR/all.csv"
if [ "$ok" -eq 1 ] && [ "$(wc -l <"$WORKDIR/all.csv")" -eq 18000 ]; then
    pass "timefilter_setup"
else
    fail "timefilter_setup"
fi

# expected <awk condition> - flows from all.csv matching the condition.
# csv column 1 is firstSeen as 'YYYY-MM-DD HH:MM:SS.mmm', compared as string,
# so bounds are given with msec.
expected() {
    awk -F, "$1" "$WORKDIR/all.csv"
}

# check <name> <filter> <awk condition>
check() {
    flows -R "$TFDIR" "$2" >"$WORKDIR/got.csv"
    expected "$3" >"$WORKDIR/exp.csv"
    if same_flows "$WORKDIR/got.csv" "$WORKDIR/exp.csv"; then
        pass "$1"
    else
        fail "$1 (got $(wc -l <"$WORKDIR/got.csv" | tr -d ' '), expected $(wc -l <"$WORKDIR/exp.csv" | tr -d ' '))"
    fi
}

# window within one current format file
check "timefilter_window_v3_file" \
    'first seen > 2024-01-01T01:09:59 and first seen < 2024-01-01T01:11:00' \
    '$1 > "2024-01-01 01:09:59.000" && $1 < "2024-01-01 01:11:00.000"'

# window within one legacy 1.7.x file
check "timefilter_window_legacy_file" \
    'first seen > 2024-01-01T01:14:59 and first seen < 2024-01-01T01:16:00' \
    '$1 > "2024-01-01 01:14:59.000" && $1 < "2024-01-01 01:16:00.000"'

# window spanning parts of two files
check "timefilter_window_two_files" \
    'first seen > 2024-01-01T01:00:20 and first seen < 2024-01-01T01:05:10' \
    '$1 > "2024-01-01 01:00:20.000" && $1 < "2024-01-01 01:05:10.000"'

# window between files matches nothing
check "timefilter_window_gap" \
    'first seen > 2024-01-01T01:06:00 and first seen < 2024-01-01T01:09:00' \
    '0'

# a legacy file without stat record is never skipped
check "timefilter_file_without_stat_kept" \
    'first seen > 2024-01-01T01:24:59 and first seen < 2024-01-01T01:26:00' \
    '$1 > "2024-01-01 01:24:59.000" && $1 < "2024-01-01 01:26:00.000"'

# last seen: all flows last 1s
check "timefilter_last_seen" \
    'last seen < 2024-01-01T01:05:05' \
    '$1 < "2024-01-01 01:05:04.000"'

# -t is a compatibility alias for strict first/last-seen predicates. It is
# combined with an ordinary filter and limits the time span in the summary.
flows -R "$TFDIR" -t '2024/01/01.01:09:59-2024/01/01.01:11:00' >"$WORKDIR/got.csv"
expected '$1 > "2024-01-01 01:09:59.000" && $1 < "2024-01-01 01:11:00.000"' >"$WORKDIR/exp.csv"
if same_flows "$WORKDIR/got.csv" "$WORKDIR/exp.csv"; then
    pass "timefilter_legacy_t_window"
else
    fail "timefilter_legacy_t_window"
fi

flows -R "$TFDIR" -t '2024/01/01.01:24:59' >"$WORKDIR/got.csv"
flows -R "$TFDIR" 'first seen > 2024-01-01T01:24:59' >"$WORKDIR/exp.csv"
if same_flows "$WORKDIR/got.csv" "$WORKDIR/exp.csv"; then
    pass "timefilter_legacy_t_open_end"
else
    fail "timefilter_legacy_t_open_end"
fi

flows -R "$TFDIR" -t '2024/01/01.01:09:59-2024/01/01.01:16:00' 'proto tcp' >"$WORKDIR/got.csv"
flows -R "$TFDIR" 'first seen > 2024-01-01T01:09:59 and last seen < 2024-01-01T01:16:00 and proto tcp' >"$WORKDIR/exp.csv"
if same_flows "$WORKDIR/got.csv" "$WORKDIR/exp.csv"; then
    pass "timefilter_legacy_t_combined_filter"
else
    fail "timefilter_legacy_t_combined_filter"
fi

echo 'proto tcp' >"$WORKDIR/timefilter.txt"
flows -R "$TFDIR" -t '2024/01/01.01:09:59-2024/01/01.01:16:00' -f "$WORKDIR/timefilter.txt" >"$WORKDIR/got.csv"
if same_flows "$WORKDIR/got.csv" "$WORKDIR/exp.csv"; then
    pass "timefilter_legacy_t_combined_filter_file"
else
    fail "timefilter_legacy_t_combined_filter_file"
fi

summary_window=$(nfdump -R "$TFDIR" -t '2024/01/01.01:10:05-2024/01/01.01:15:20' -o null 2>/dev/null |
    sed -n 's/^Time window: \([^,]*\), Duration:.*/\1/p')
if [ "$summary_window" = '2024-01-01 01:10:05.000 - 2024-01-01 01:15:20.000' ]; then
    pass "timefilter_legacy_t_summary_window"
else
    fail "timefilter_legacy_t_summary_window: got '$summary_window'"
fi

# an OR with a non-time condition has no time constraint - no file is skipped
check "timefilter_or_not_skipped" \
    'first seen > 2024-01-01T01:24:00 or src ip 10.0.0.1' \
    '$1 > "2024-01-01 01:24:00.000" || $4 == "10.0.0.1"'

# Files are skipped by their stat record only: a file whose stat record claims
# the next day is skipped for a window matching its flows, which proves that
# its data blocks are not read. Without a time filter, its flows are there.
LIEDIR="$WORKDIR/timefilter_stat"
mkdir -p "$LIEDIR"
"$NFGEN2" -w "$LIEDIR/nfcapd.202401010100" -z lz4 -n 3000 -t "$T0" -S 86400 >/dev/null 2>&1
if [ "$(flows -R "$LIEDIR" | wc -l)" -eq 3000 ] \
   && [ "$(flows -R "$LIEDIR" 'first seen > 2024-01-01T00:59:59 and first seen < 2024-01-01T01:01:00' | wc -l)" -eq 0 ]; then
    pass "timefilter_skips_file_by_stat_record"
else
    fail "timefilter_skips_file_by_stat_record"
fi

# nfmeta computes the stat record from the flows it writes. A merged file must
# cover all input flows, including those of a legacy file without stat record,
# so the file is not wrongly skipped.
if nfmeta -r "$TFDIR" -w "$WORKDIR/merged.nf" >/dev/null 2>&1 \
   && nfdump -I -r "$WORKDIR/merged.nf" </dev/null 2>/dev/null | grep -q '^Flows: 18000$' \
   && nfdump -I -r "$WORKDIR/merged.nf" </dev/null 2>/dev/null | grep -q "^First: $T0\$" \
   && nfdump -I -r "$WORKDIR/merged.nf" </dev/null 2>/dev/null | grep -q "^Last: $((T0 + 5 * 300 + 30))\$" \
   && [ "$(flows -r "$WORKDIR/merged.nf" 'first seen > 2024-01-01T01:24:59 and first seen < 2024-01-01T01:26:00' | wc -l)" -eq 3000 ]; then
    pass "timefilter_nfmeta_merged_stat_window"
else
    fail "timefilter_nfmeta_merged_stat_window"
fi

# in place, the stat record of a legacy file without stat record is created
cp "$TFDIR/nfcapd.202401010125" "$WORKDIR/nostat.nf"
if nfmeta -r "$WORKDIR/nostat.nf" >/dev/null 2>&1 \
   && nfdump -I -r "$WORKDIR/nostat.nf" </dev/null 2>/dev/null | grep -q '^Flows: 3000$' \
   && nfdump -I -r "$WORKDIR/nostat.nf" </dev/null 2>/dev/null | grep -q "^First: $((T0 + 5 * 300))\$"; then
    pass "timefilter_nfmeta_creates_stat_record"
else
    fail "timefilter_nfmeta_creates_stat_record"
fi

summary
