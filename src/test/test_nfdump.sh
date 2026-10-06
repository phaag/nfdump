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
[ "$a_n" = "37" ] && pass "aggregate_default" || fail "aggregate_default: got $a_n, expected 37"

# -A srcip: aggregate by a single custom key
A_n=$(nfdump -r dummy_flows.nf -q -A srcip 2>/dev/null | wc -l | tr -d ' ')
[ "$A_n" = "36" ] && pass "aggregate_custom_srcip" || fail "aggregate_custom_srcip: got $A_n, expected 36"

# -A srcip4/24: aggregate by a subnet, collapsing further than by host
subnet_n=$(nfdump -r dummy_flows.nf -q -A srcip4/24 2>/dev/null | wc -l | tr -d ' ')
[ "$subnet_n" = "21" ] && pass "aggregate_subnet" || fail "aggregate_subnet: got $subnet_n, expected 21"

# -b / -B: bidirectional aggregation (own vs. guessed direction)
b_n=$(nfdump -r dummy_flows.nf -q -b 2>/dev/null | wc -l | tr -d ' ')
[ "$b_n" = "35" ] && pass "aggregate_bidir" || fail "aggregate_bidir: got $b_n, expected 35"

B_n=$(nfdump -r dummy_flows.nf -q -B 2>/dev/null | wc -l | tr -d ' ')
[ "$B_n" = "35" ] && pass "aggregate_bidir_guess" || fail "aggregate_bidir_guess: got $B_n, expected 35"

# Records without an IPv4 or IPv6 extension use an AF_UNSPEC key. They must
# retain their ports, print the missing addresses as 0, and emit no diagnostic.
if unspecified=$(nfdump -r dummy_flows.nf -q -N -n 0 -s record/flows 'not ipv4 and not ipv6' 2>&1) \
   && printf '%s\n' "$unspecified" | grep -Eq '0:12345[[:space:]]+->[[:space:]]+0:443' \
   && ! printf '%s\n' "$unspecified" | grep -q 'ipv4Flow:'; then
    pass "aggregate_unspecified_address"
else
    fail "aggregate_unspecified_address: output='$unspecified'"
fi

if unspecified=$(nfdump -r dummy_flows.nf -q -N -n 0 -b 'not ipv4 and not ipv6' 2>&1) \
   && printf '%s\n' "$unspecified" | grep -Eq '0:12345[[:space:]]+<->[[:space:]]+0:443' \
   && ! printf '%s\n' "$unspecified" | grep -q 'ipv4Flow:'; then
    pass "aggregate_unspecified_address_bidir"
else
    fail "aggregate_unspecified_address_bidir: output='$unspecified'"
fi

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
[ "$p_n" = "8" ] && pass "postfilter_aggregated" || fail "postfilter_aggregated: got $p_n, expected 8"

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
    # Count only data rows from a deliberately narrow output format.
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

# ── custom aggregation context ────────────────────────────────────────────────
# -A keeps a compact record per group. Ports and flags imply proto in the key,
# srcnet/dstnet keep the exporter's masks; the labels must survive aggregation.
aggr_csv() { nfdump -G none -q -r dummy_flows.nf -O bytes -o csv -A "$@" 2>/dev/null; }

if aggr_csv flags | grep -q '^[^,]*,[^,]*,6,\.\.\.A' \
   && aggr_csv flags | head -1 | grep -q ',proto,flags,'; then
    pass "aggr_flags_proto_label"
else
    fail "aggr_flags_proto_label"
fi

if aggr_csv dstport | grep -q '^[^,]*,[^,]*,1,8\.0,' \
   && aggr_csv dstport | grep -q '^[^,]*,[^,]*,17,53,'; then
    pass "aggr_dstport_proto_icmp"
else
    fail "aggr_dstport_proto_icmp"
fi

if [ "$(aggr_csv dstport,proto | head -1 | cut -d, -f3-4)" = "dstPort,proto" ] \
   && [ "$(aggr_csv proto,dstport | head -1 | cut -d, -f3-4)" = "proto,dstPort" ]; then
    pass "aggr_explicit_proto_not_duplicated"
else
    fail "aggr_explicit_proto_not_duplicated"
fi

if aggr_csv srcnet | grep -q ',172\.20\.0\.0/16,' \
   && aggr_csv dstnet | grep -q '/24,' \
   && aggr_csv srcnet | grep -q ',2001:db8:100::/48,'; then
    pass "aggr_net_mask_label"
else
    fail "aggr_net_mask_label"
fi

rm -f "$WORKDIR/srcnet_aggr.nf"
if nfdump -G none -q -r dummy_flows.nf -A srcnet -w "$WORKDIR/srcnet_aggr.nf" >/dev/null 2>&1 \
   && nfdump -G none -q -r "$WORKDIR/srcnet_aggr.nf" -o "csv:%sn,%byt" 2>/dev/null | grep -q '^172\.20\.0\.0/16,'; then
    pass "aggr_net_mask_exported"
else
    fail "aggr_net_mask_exported"
fi

# ── statistics in CSV ──────────────────────────────────────────────────────────
# Every element type must be formatted in -s ... -o csv; a missing type printed
# an uninitialised value.
stat_csv_bad=""
for s in flags event nat cl odid iacl mpls1 srcasn; do
    val=$(nfdump -q -G none -r dummy_flows.nf -s "$s" -n 1 -o csv 2>/dev/null | sed -n 2p | cut -d, -f5)
    if [ -z "$val" ] || printf '%s' "$val" | LC_ALL=C grep -q '[^[:print:]]'; then
        stat_csv_bad="$stat_csv_bad $s"
    fi
done
if [ -z "$stat_csv_bad" ] \
   && [ "$(nfdump -q -G none -r dummy_flows.nf -s flags -n 1 -o csv 2>/dev/null | sed -n 2p | cut -d, -f5)" = "...AP.SF" ]; then
    pass "stat_csv_element_values"
else
    fail "stat_csv_element_values (bad:$stat_csv_bad)"
fi

# ── legacy V2 records with merged V4 extensions ──────────────────────────────
# A V2 IP next hop and BGP next hop are merged into one V4 EXasRouting extension,
# NSEL and NAT common into one EXnselCommon. Both contributors must survive in
# either order; a duplicate V2 extension keeps the first one.
make_v2_merge() {
    python3 - "$1" <<'PYEOF'
import struct, sys, ipaddress
p = struct.pack
MSEC = 1791194400000
def v4(s): return p('<I', int(ipaddress.ip_address(s)))
def v6(s):
    n = int(ipaddress.ip_address(s)); return p('<QQ', n >> 64, n & ((1 << 64) - 1))
def generic(port): return p('<QQQQQHHBBBB', MSEC, MSEC + 1000, MSEC + 2000, 10, 1000, port, 443, 6, 18, 0, 0)
def ext(i, b): return p('<HH', i, len(b) + 4) + b
def record(port, es):
    data = b''.join(ext(i, generic(port) if i == 1 else b) for i, b in es)
    return p('<HHHBBHBB', 11, 12 + len(data), len(es), 0, 0, 0, 0, 10) + data
f4 = (2, v4('192.0.2.10') + v4('198.51.100.20'))
f6 = (3, v6('2001:db8:1::10') + v6('2001:db8:2::20'))
bgp4, ip4 = (8, v4('192.0.2.254')), (10, v4('198.51.100.254'))
bgp6, ip6 = (9, v6('2001:db8:3::fe')), (11, v6('2001:db8:4::fe'))
mac1 = (15, p('<QQQQ', 0x010203040506, 0x111213141516, 0x212223242526, 0x313233343536))
mac2 = (15, p('<QQQQ', 0x414243444546, 0x515253545556, 0x616263646566, 0x717273747576))
nsel = (19, p('<QIHBB', MSEC + 3333, 0x12345678, 123, 1, 0))
nat = (25, p('<QIBBH', MSEC + 4444, 0x23456789, 1, 0, 0))
recs = [(11000, [(1, b''), f4, bgp4, ip4]), (11001, [(1, b''), f4, ip4, bgp4]),
        (11002, [(1, b''), f6, bgp6, ip6]), (11003, [(1, b''), f6, ip6, bgp6]),
        (11004, [(1, b''), f4, nsel, nat]), (11005, [(1, b''), f4, nat, nsel]),
        (11006, [(1, b''), f4, mac1, mac2])]
body = b''.join(record(port, es) for port, es in recs)
n = len(recs)
# V2 file: header, one data block of V3 records, appendix with ident and stat record
ident = b'v2-merge\0'
identrec = p('<HH', 0x8001, len(ident) + 4) + ident
stats = p('<18Q', n, 1000 * n, 10 * n, n, 0, 0, 0, 1000 * n, 0, 0, 0, 10 * n, 0, 0, 0, MSEC, MSEC + 1000, 0)
appendix = p('<IIHH', 2, len(identrec) + 148, 3, 0) + identrec + p('<HH', 0x8002, 148) + stats
header = p('<HHIqBBHIqII', 0xa50c, 2, 0x01070a00, MSEC // 1000, 0, 0, 1, 4, 40 + 12 + len(body), 1048576, 1)
open(sys.argv[1], 'wb').write(header + p('<IIHH', n, len(body), 3, 0) + body + appendix)
PYEOF
}

if command -v python3 >/dev/null 2>&1 && make_v2_merge "$WORKDIR/v2merge.nf"; then
    v2csv() { nfdump -q -6 -G none -W 1 -r "$WORKDIR/v2merge.nf" -o "csv:$1" "src port $2" 2>/dev/null | tail -n +2; }
    if [ "$(v2csv '%nh,%nhb' 11000)" = "198.51.100.254,192.0.2.254" ] \
       && [ "$(v2csv '%nh,%nhb' 11001)" = "198.51.100.254,192.0.2.254" ] \
       && [ "$(v2csv '%nh,%nhb' 11002)" = "2001:db8:4::fe,2001:db8:3::fe" ] \
       && [ "$(v2csv '%nh,%nhb' 11003)" = "2001:db8:4::fe,2001:db8:3::fe" ]; then
        pass "v2_merged_next_hops"
    else
        fail "v2_merged_next_hops"
    fi

    # NSEL and NAT fields both kept; event time: first non-zero contributor
    v2json() { nfdump -q -G none -W 1 -r "$WORKDIR/v2merge.nf" -o ndjson "src port $1" 2>/dev/null; }
    if v2json 11004 | grep -q '"connect_id":305419896' && v2json 11004 | grep -q '"nat_pool_id":591751049' \
       && v2json 11005 | grep -q '"connect_id":305419896' && v2json 11005 | grep -q '"nat_pool_id":591751049' \
       && v2json 11004 | grep -q '"t_event":"[^"]*:03.333"' && v2json 11005 | grep -q '"t_event":"[^"]*:04.444"'; then
        pass "v2_merged_nsel_nat"
    else
        fail "v2_merged_nsel_nat"
    fi

    if [ "$(v2csv '%ismc,%odmc,%idmc,%osmc' 11006)" = "01:02:03:04:05:06,11:12:13:14:15:16,21:22:23:24:25:26,31:32:33:34:35:36" ]; then
        pass "v2_duplicate_extension_first_wins"
    else
        fail "v2_duplicate_extension_first_wins"
    fi
else
    skip "v2_merged_next_hops: python3 not available"
    skip "v2_merged_nsel_nat: python3 not available"
    skip "v2_duplicate_extension_first_wins: python3 not available"
fi

# ── reserved index block ──────────────────────────────────────────────────────
# BLOCK_TYPE_INDEX is reserved for a future block index. Current readers must
# skip it silently, and tools which rewrite blocks must drop it, as its block
# offsets would be stale. add_index_block and index_blocks are defined in
# testsetup.sh.

if command -v python3 >/dev/null 2>&1 && add_index_block dummy_flows.nf "$WORKDIR/index.nf"; then
    if nfdump -v check -r "$WORKDIR/index.nf" >/dev/null 2>&1 && [ "$(index_blocks "$WORKDIR/index.nf")" = "1" ]; then
        pass "index_block_checked"
    else
        fail "index_block_checked"
    fi

    nfdump -q -r dummy_flows.nf -o csv >"$WORKDIR/index_ref.csv" 2>/dev/null
    if nfdump -q -r "$WORKDIR/index.nf" -o csv >"$WORKDIR/index_got.csv" 2>"$WORKDIR/index_err.txt" \
       && [ ! -s "$WORKDIR/index_err.txt" ] \
       && [ -s "$WORKDIR/index_got.csv" ] && cmp -s "$WORKDIR/index_ref.csv" "$WORKDIR/index_got.csv"; then
        pass "index_block_skipped_by_reader"
    else
        fail "index_block_skipped_by_reader"
    fi

    if nfdump -r "$WORKDIR/index.nf" -w "$WORKDIR/index_copy.nf" >/dev/null 2>&1 \
       && [ -z "$(index_blocks "$WORKDIR/index_copy.nf")" ]; then
        pass "index_block_dropped_by_rewrite"
    else
        fail "index_block_dropped_by_rewrite"
    fi

    cp "$WORKDIR/index.nf" "$WORKDIR/index_repair.nf"
    if nfdump -r "$WORKDIR/index_repair.nf" -v repair >/dev/null 2>&1 \
       && nfdump -v check -r "$WORKDIR/index_repair.nf" >/dev/null 2>&1 \
       && [ -z "$(index_blocks "$WORKDIR/index_repair.nf")" ] \
       && nfdump -q -r "$WORKDIR/index_repair.nf" -o csv 2>/dev/null | cmp -s "$WORKDIR/index_ref.csv" -; then
        pass "index_block_dropped_by_repair"
    else
        fail "index_block_dropped_by_repair"
    fi
else
    skip "index_block_checked: python3 not available"
    skip "index_block_skipped_by_reader: python3 not available"
    skip "index_block_dropped_by_rewrite: python3 not available"
    skip "index_block_dropped_by_repair: python3 not available"
fi

summary
