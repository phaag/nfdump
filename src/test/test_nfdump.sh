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

# -x accepts TOML boolean spelling as well as 0/1.  Ensure it enables the
# block checksums, not merely a successful checksum verification of absent ones.
if nfdump -x xxhash=true -r dummy_flows.nf -q -z=lz4 -w "$WORKDIR/xxhash.nf" >/dev/null 2>&1 \
   && out=$(nfdump -v check-verbose -r "$WORKDIR/xxhash.nf" 2>&1) \
   && echo "$out" | grep -Eq 'checksum: 0x[1-9a-fA-F]'; then
    pass "xxhash_cli_true"
else
    fail "xxhash_cli_true"
fi

# Hash-only verification must verify all stored checksums without decoding
# blocks. A file without checksums must not be reported as verified.
if out=$(nfdump -v hash -r "$WORKDIR/xxhash.nf" 2>&1) \
   && echo "$out" | grep -q 'XXH3 checksums: OK'; then
    pass "verify_hash"
else
    fail "verify_hash"
fi

if nfdump -v hash -r dummy_flows.nf >/dev/null 2>&1; then
    fail "verify_hash_missing: unexpectedly exited 0"
else
    pass "verify_hash_missing"
fi

if out=$(nfdump -v check -r dummy_flows.nf 2>&1) \
   && echo "$out" | grep -q 'Checksums       : not available'; then
    pass "verify_check_checksum_unavailable"
else
    fail "verify_check_checksum_unavailable"
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

# All record-count expectations below are pinned to the fixed content of
# dummy_flows.nf (42 raw records: 30 tcp, 8 udp, 2 icmp, plus 2 non-flow
# ident/exporter records). If dummy_flows.nf is ever regenerated, these
# counts need re-deriving from a `nfdump -r dummy_flows.nf -o line` dump.

echo ""
echo "── filtering ─────────────────────────────────────────────────────────"

# single-protocol filters partition the raw records
tcp_n=$(nfdump -r dummy_flows.nf -q -o line 'proto tcp' 2>/dev/null | wc -l | tr -d ' ')
[ "$tcp_n" = "30" ] && pass "filter_proto_tcp" || fail "filter_proto_tcp: got $tcp_n, expected 30"

udp_n=$(nfdump -r dummy_flows.nf -q -o line 'proto udp' 2>/dev/null | wc -l | tr -d ' ')
[ "$udp_n" = "8" ] && pass "filter_proto_udp" || fail "filter_proto_udp: got $udp_n, expected 8"

icmp_n=$(nfdump -r dummy_flows.nf -q -o line 'proto icmp' 2>/dev/null | wc -l | tr -d ' ')
[ "$icmp_n" = "2" ] && pass "filter_proto_icmp" || fail "filter_proto_icmp: got $icmp_n, expected 2"

# a filter matching nothing must report so and still exit 0
if out=$(nfdump -r dummy_flows.nf -o line 'src ip 240.0.0.1' 2>&1) \
   && echo "$out" | grep -q "No matching flows"; then
    pass "filter_no_match"
else
    fail "filter_no_match"
fi

# malformed filter syntax must fail to compile and exit non-zero, not crash
if nfdump -r dummy_flows.nf -o line 'proto tcp and and' >/dev/null 2>&1; then
    fail "filter_syntax_error: unexpectedly succeeded"
else
    pass "filter_syntax_error"
fi

# -f <filterfile> must apply the same as the equivalent inline filter
echo "proto tcp" >"$WORKDIR/filter.txt"
filef_n=$(nfdump -r dummy_flows.nf -q -f "$WORKDIR/filter.txt" -o line 2>/dev/null | wc -l | tr -d ' ')
[ "$filef_n" = "30" ] && pass "filter_from_file" || fail "filter_from_file: got $filef_n, expected 30"

echo ""
echo "── aggregation ───────────────────────────────────────────────────────"

# -a: default 5-tuple aggregation collapses repeated flows
a_n=$(nfdump -r dummy_flows.nf -q -a 2>/dev/null | wc -l | tr -d ' ')
[ "$a_n" = "38" ] && pass "aggregate_default" || fail "aggregate_default: got $a_n, expected 38"

# -A srcip: aggregate by a single custom key
A_n=$(nfdump -r dummy_flows.nf -q -A srcip 2>/dev/null | wc -l | tr -d ' ')
[ "$A_n" = "36" ] && pass "aggregate_custom_srcip" || fail "aggregate_custom_srcip: got $A_n, expected 36"

# -A srcip4/24: aggregate by a subnet, collapsing further than by host
subnet_n=$(nfdump -r dummy_flows.nf -q -A srcip4/24 2>/dev/null | wc -l | tr -d ' ')
[ "$subnet_n" = "21" ] && pass "aggregate_subnet" || fail "aggregate_subnet: got $subnet_n, expected 21"

# -b / -B: bidirectional aggregation (own vs. guessed direction)
b_n=$(nfdump -r dummy_flows.nf -q -b 2>/dev/null | wc -l | tr -d ' ')
[ "$b_n" = "36" ] && pass "aggregate_bidir" || fail "aggregate_bidir: got $b_n, expected 36"

B_n=$(nfdump -r dummy_flows.nf -q -B 2>/dev/null | wc -l | tr -d ' ')
[ "$B_n" = "36" ] && pass "aggregate_bidir_guess" || fail "aggregate_bidir_guess: got $B_n, expected 36"

echo ""
echo "── statistics ────────────────────────────────────────────────────────"

# -s <elem>/<order> -n <N>: top-N statistics output is truncated correctly
stat_n=$(nfdump -r dummy_flows.nf -q -s srcip/bytes -n 3 2>/dev/null | wc -l | tr -d ' ')
[ "$stat_n" = "3" ] && pass "stat_topn" || fail "stat_topn: got $stat_n, expected 3"

# an unknown statistics element must be rejected, not silently ignored
if nfdump -r dummy_flows.nf -q -s bogus_element >/dev/null 2>&1; then
    fail "stat_invalid_element: unexpectedly succeeded"
else
    pass "stat_invalid_element"
fi

# regression: -s eacl (NSEL/ASA egress ACL) is implemented and must work ...
if nfdump -r dummy_flows.nf -q -s eacl >/dev/null 2>&1; then
    pass "stat_eacl_valid"
else
    fail "stat_eacl_valid"
fi

# ... while -s iace (egress ACE) was removed from nfdump.1 as never-implemented
# (nfstat.c keeps it #define'd out) - must still be rejected, not silently
# accepted, so the man page fix stays honest.
if nfdump -r dummy_flows.nf -q -s iace >/dev/null 2>&1; then
    fail "stat_iace_invalid: unexpectedly succeeded"
else
    pass "stat_iace_invalid"
fi

echo ""
echo "── output formats ────────────────────────────────────────────────────"

# -o csv:<fmt>: header line + one line per record
csv_n=$(nfdump -r dummy_flows.nf -q -c 3 -o "csv:%sa,%da,%pr" 2>/dev/null | wc -l | tr -d ' ')
[ "$csv_n" = "4" ] && pass "output_csv" || fail "output_csv: got $csv_n lines, expected 4"

# -o fmt:<fmt>: custom token format, one line per record, no header
fmt_n=$(nfdump -r dummy_flows.nf -q -c 3 -o "fmt:%sa -> %da" 2>/dev/null | wc -l | tr -d ' ')
[ "$fmt_n" = "3" ] && pass "output_custom_fmt" || fail "output_custom_fmt: got $fmt_n lines, expected 3"

if command -v python3 >/dev/null 2>&1; then
    # -o json: a single well-formed JSON array
    if nfdump -r dummy_flows.nf -q -c 5 -o json >"$WORKDIR/out.json" 2>/dev/null \
       && python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$WORKDIR/out.json" 2>/dev/null; then
        pass "output_json_valid"
    else
        fail "output_json_valid"
    fi

    # -o ndjson: one well-formed JSON object per line
    if nfdump -r dummy_flows.nf -q -c 5 -o ndjson >"$WORKDIR/out.ndjson" 2>/dev/null \
       && [ -s "$WORKDIR/out.ndjson" ] \
       && while IFS= read -r jline; do
              python3 -c "import json,sys; json.loads(sys.argv[1])" "$jline" || exit 1
          done <"$WORKDIR/out.ndjson"; then
        pass "output_ndjson_valid"
    else
        fail "output_ndjson_valid"
    fi
else
    skip "output_json_valid: python3 not available"
    skip "output_ndjson_valid: python3 not available"
fi

echo ""
echo "── limits & postfilter ───────────────────────────────────────────────"

# -c <num>: hard cap on the number of records read
c_n=$(nfdump -r dummy_flows.nf -q -c 5 -o line 2>/dev/null | wc -l | tr -d ' ')
[ "$c_n" = "5" ] && pass "limit_records" || fail "limit_records: got $c_n, expected 5"

# -n 0: explicitly unlimited top-N
n0_n=$(nfdump -r dummy_flows.nf -q -s srcip/bytes -n 0 2>/dev/null | wc -l | tr -d ' ')
[ "$n0_n" = "35" ] && pass "limit_topn_unlimited" || fail "limit_topn_unlimited: got $n0_n, expected 35"

# -P <expr>: post-filter narrows the flow-record output of an aggregation
p_n=$(nfdump -r dummy_flows.nf -q -a -P 'bytes > 100000' -o line 2>/dev/null | wc -l | tr -d ' ')
[ "$p_n" = "9" ] && pass "postfilter_aggregated" || fail "postfilter_aggregated: got $p_n, expected 9"

# -P also applies to a plain -O sort (it goes through the same flow-record
# result-set path as -a/-A/-b/-B; see nflowcache.c's PrintSortList()).
o_n=$(nfdump -r dummy_flows.nf -q -O tstart -P 'bytes > 100000' -o line 2>/dev/null | wc -l | tr -d ' ')
[ "$o_n" = "9" ] && pass "postfilter_sorted" || fail "postfilter_sorted: got $o_n, expected 9"

# -P must also apply to aggregated -w output.  The exported data and its
# stats block must describe exactly the accepted post-filter records, and a
# derived aggregate file must not carry source exporter metadata.
postfilter_file="$WORKDIR/postfilter_aggregated.nf"
if nfdump -r dummy_flows.nf -q -a -P 'bytes > 100000' -w "$postfilter_file" >/dev/null 2>&1 \
   && nfdump -v check -r "$postfilter_file" >/dev/null 2>&1; then
    # The aggregation debug banner is emitted on stdout, so count only data
    # rows from a deliberately narrow output format.
    postfilter_print_n=$(nfdump -r dummy_flows.nf -q -a -P 'bytes > 100000' -o 'fmt:%pr' 2>/dev/null | grep -c '^TCP')
    postfilter_export_n=$(nfdump -r "$postfilter_file" -q -o 'fmt:%pr' 2>/dev/null | grep -c '^TCP')
    postfilter_file_stats=$(nfdump -r "$postfilter_file" -I 2>/dev/null | \
        awk '/^(Flows|Packets|Bytes|First|Last):/ { values = values (values ? " " : "") $2 } END { print values }')
    # Fixed values for the eight aggregate records that pass the post-filter.
    # Packets/bytes include both directions, as does UpdateRawStat().
    if [ "$postfilter_export_n" = "$postfilter_print_n" ] \
       && [ "$postfilter_file_stats" = "17 2563 49504821 1562833808 1562833840" ] \
       && nfdump -E "$postfilter_file" 2>/dev/null | grep -q "No Exporter records found"; then
        pass "postfilter_aggregated_export"
    else
        fail "postfilter_aggregated_export: printed=$postfilter_print_n exported=$postfilter_export_n file_stats='$postfilter_file_stats'"
    fi
else
    fail "postfilter_aggregated_export: failed to write or verify output"
fi

# When -P rejects every aggregate, ExportFlowTable reports no accepted record
# and the caller removes the otherwise empty output file.
postfilter_empty="$WORKDIR/postfilter_empty.nf"
if nfdump -r dummy_flows.nf -q -a -P 'proto 255' -w "$postfilter_empty" >/dev/null 2>&1 \
   && [ ! -e "$postfilter_empty" ]; then
    pass "postfilter_aggregated_export_empty"
else
    fail "postfilter_aggregated_export_empty"
fi

# By design, -P has no effect without -a/-A/-b/-B/-O: a plain read prints
# each matching record as it streams in and never builds the flow-record
# result set -P filters, so -P is silently a no-op there (the man page
# says so explicitly) - not a hidden truncation bug.
plain_n=$(nfdump -r dummy_flows.nf -q -P 'bytes > 100000' -o line 2>/dev/null | wc -l | tr -d ' ')
[ "$plain_n" = "42" ] && pass "postfilter_plain_read_noop" || fail "postfilter_plain_read_noop: got $plain_n, expected 42"

# By design, -P likewise does not apply to -s statistics output (a
# different, non-flow record type) - confirm it stays a documented no-op
# rather than silently reappearing as a partial/inconsistent filter.
s_all_n=$(nfdump -r dummy_flows.nf -q -s srcip 2>/dev/null | wc -l | tr -d ' ')
s_filtered_n=$(nfdump -r dummy_flows.nf -q -s srcip -P 'bytes > 100000' 2>/dev/null | wc -l | tr -d ' ')
[ "$s_filtered_n" = "$s_all_n" ] && pass "postfilter_statistics_noop" || fail "postfilter_statistics_noop: -P unexpectedly changed -s output ($s_all_n -> $s_filtered_n)"

echo ""
echo "── multi-file reading ────────────────────────────────────────────────"

# -R dir/file1:file2 - a range of files read in one pass
mkdir -p "$WORKDIR/rdir"
cp dummy_flows.nf "$WORKDIR/rdir/nfcapd.202001010000"
cp dummy_flows.nf "$WORKDIR/rdir/nfcapd.202001010005"
R_n=$(nfdump -R "$WORKDIR/rdir/nfcapd.202001010000:nfcapd.202001010005" -q -o line 2>/dev/null | wc -l | tr -d ' ')
[ "$R_n" = "84" ] && pass "multifile_R_range" || fail "multifile_R_range: got $R_n, expected 84"

# -M dir1:dir2 - the same filename read from multiple directories
mkdir -p "$WORKDIR/mdir1" "$WORKDIR/mdir2"
cp dummy_flows.nf "$WORKDIR/mdir1/nfcapd.202001010000"
cp dummy_flows.nf "$WORKDIR/mdir2/nfcapd.202001010000"
M_n=$(nfdump -M "$WORKDIR/mdir1:mdir2" -r nfcapd.202001010000 -q -o line 2>/dev/null | wc -l | tr -d ' ')
[ "$M_n" = "84" ] && pass "multidir_M" || fail "multidir_M: got $M_n, expected 84"

echo ""
echo "── verify & repair (-v) ──────────────────────────────────────────────"

if nfdump -v check -r dummy_flows.nf >/dev/null 2>&1; then
    pass "verify_check_valid"
else
    fail "verify_check_valid"
fi

if out=$(nfdump -v check-verbose -r dummy_flows.nf 2>&1) \
   && echo "$out" | grep -q "Checksums       : not available"; then
    pass "verify_check_verbose_valid"
else
    fail "verify_check_verbose_valid"
fi

# repair on an already-healthy file must succeed and must not alter its data
cp dummy_flows.nf "$WORKDIR/repair.nf"
if nfdump -v repair -r "$WORKDIR/repair.nf" >/dev/null 2>&1 \
   && nfdump -r "$WORKDIR/repair.nf" -q -o raw >"$WORKDIR/repair.txt" 2>/dev/null \
   && diff -u "$WORKDIR/repair.txt" "$SCRIPT_DIR/ref_raw.txt" >/dev/null 2>&1; then
    pass "verify_repair_preserves_data"
else
    fail "verify_repair_preserves_data"
fi

# regression: an unknown -v mode used to fall through to exit(EXIT_SUCCESS)
if nfdump -v bogus -r dummy_flows.nf >/dev/null 2>&1; then
    fail "verify_bogus_mode: unexpectedly exited 0"
else
    pass "verify_bogus_mode"
fi

if nfdump -v check -r "$WORKDIR/no-such-file.nf" >/dev/null 2>&1; then
    fail "verify_check_missing_file: unexpectedly exited 0"
else
    pass "verify_check_missing_file"
fi

echo ""
echo "── regression: exit codes & error handling ──────────────────────────"

# -c 0 / -c garbage: previously atoi()-based, silently fell back to "no limit"
if nfdump -r dummy_flows.nf -c 0 >/dev/null 2>&1; then
    fail "regress_c_zero: unexpectedly exited 0"
else
    pass "regress_c_zero"
fi

if nfdump -r dummy_flows.nf -c abc >/dev/null 2>&1; then
    fail "regress_c_garbage: unexpectedly exited 0"
else
    pass "regress_c_garbage"
fi

# -n -1: negative top-N must be rejected
if nfdump -r dummy_flows.nf -n -1 >/dev/null 2>&1; then
    fail "regress_n_negative: unexpectedly exited 0"
else
    pass "regress_n_negative"
fi

# -l out of its documented 1..4 range
if nfdump -r dummy_flows.nf -l 9 >/dev/null 2>&1; then
    fail "regress_l_out_of_range: unexpectedly exited 0"
else
    pass "regress_l_out_of_range"
fi

# -f with a non-existent filter file used to exit(255); now a plain
# EXIT_FAILURE like every other bad-argument case.
if nfdump -f "$WORKDIR/no-such-filterfile.txt" -r dummy_flows.nf >/dev/null 2>&1; then
    fail "regress_f_bad_path: unexpectedly exited 0"
else
    pass "regress_f_bad_path"
fi

# a missing -r input file must be a clean, non-zero exit
if nfdump -r "$WORKDIR/no-such-file.nf" >/dev/null 2>&1; then
    fail "regress_missing_input_file: unexpectedly exited 0"
else
    pass "regress_missing_input_file"
fi

# regression: ChangeIdent()'s failure return value used to be discarded,
# reporting EXIT_SUCCESS even when the ident change failed.
if [ "$(id -u)" != "0" ]; then
    cp dummy_flows.nf "$WORKDIR/readonly.nf"
    chmod 0444 "$WORKDIR/readonly.nf"
    if nfdump -r "$WORKDIR/readonly.nf" -i NewIdent >/dev/null 2>&1; then
        fail "regress_changeident_failure: unexpectedly exited 0"
    else
        pass "regress_changeident_failure"
    fi
    chmod 0644 "$WORKDIR/readonly.nf"
else
    skip "regress_changeident_failure: running as root"
fi

summary
