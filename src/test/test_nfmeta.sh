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
echo "── nfmeta ───────────────────────────────────────────────────────────────"

# nfmeta never reads from the terminal in these tests: stdin is /dev/null, so
# an unexpected passphrase prompt fails instead of hanging the test suite.
nfmeta() { "$NFMETA_BIN" "$@" </dev/null; }

NFGEN2="$SCRIPT_DIR/nfgen2"

# ── helpers ────────────────────────────────────────────────────────────────────

# check_value <file> <label> [nfdump args]
# Print the value of a 'label : value' line from nfdump -v check-verbose.
check_value() {
    _file="$1"; _label="$2"; shift 2
    nfdump -v check-verbose -r "$_file" "$@" </dev/null 2>/dev/null \
        | sed -n "s/^ *$_label *: *//p" | head -1
}

# compression <file> [nfdump args] - e.g. "lz4 compressed", "not compressed"
compression() { _file="$1"; shift; check_value "$_file" Compression "$@"; }

# is_layout_v3 <file> - true if the file uses the nfdump 1.8.x file layout
is_layout_v3() {
    [ "$(od -An -tx1 -N4 "$1" | tr -d ' \n')" = "0ca50300" ]
}

# has_bloom <file> [nfdump args]
# True if the file verifies and every flow block carries bloom metadata.
has_bloom() {
    _file="$1"; shift
    _bloom=$(check_value "$_file" "Bloom metadata" "$@")
    case "$_bloom" in
        "present ("*)
            _n=$(echo "$_bloom" | sed 's/^present (\([0-9]*\)\/\([0-9]*\).*/\1/')
            _m=$(echo "$_bloom" | sed 's/^present (\([0-9]*\)\/\([0-9]*\).*/\2/')
            [ -n "$_n" ] && [ "$_n" -gt 0 ] && [ "$_n" = "$_m" ]
            ;;
        *) return 1 ;;
    esac
}

# flow_blocks <file> [nfdump args] - number of flow blocks
flow_blocks() { _file="$1"; shift; check_value "$_file" "Flow blocks" "$@" | sed 's/ .*//'; }

# flows <file> [nfdump args] - sorted csv dump of all flows. nfmeta workers may
# reorder blocks, so flow content is compared independent of order.
flows() {
    _file="$1"; shift
    nfdump -q -r "$_file" "$@" -o csv </dev/null 2>/dev/null | sort
}

# same_flows <file1> <file2> [nfdump args] - identical, non-empty flow content
same_flows() {
    _f1="$1"; _f2="$2"; shift 2
    flows "$_f1" "$@" >"$WORKDIR/flows1.csv"
    flows "$_f2" "$@" >"$WORKDIR/flows2.csv"
    [ -s "$WORKDIR/flows1.csv" ] && cmp -s "$WORKDIR/flows1.csv" "$WORKDIR/flows2.csv"
}

# count <file> <filter> [nfdump args] - number of flows matching filter
count() {
    _file="$1"; _filter="$2"; shift 2
    nfdump -q -r "$_file" "$@" -o csv "$_filter" </dev/null 2>/dev/null | grep -c '^[0-9]'
}

# blocks_skipped <file> <filter> - block-filter skips reported by nfdump
blocks_skipped() {
    _file="$1"; _filter="$2"
    nfdump -r "$_file" -o null "$_filter" </dev/null 2>/dev/null \
        | sed -n 's/.*Blocks skipped: \([0-9][0-9]*\).*/\1/p'
}

if [ ! -x "$NFMETA_BIN" ]; then
    skip "nfmeta: binary not built"
    summary
    exit $?
fi
if [ ! -x "$NFGEN2" ]; then
    skip "nfmeta: nfgen2 binary not built"
    summary
    exit $?
fi

# ── legacy nfdump 1.7.x files ──────────────────────────────────────────────────

# Generate legacy V2 files with every compression nfgen2 supports.
V2DIR="$WORKDIR/v2"
mkdir -p "$V2DIR"
for z in none lzo lz4; do
    if "$NFGEN2" -w "$V2DIR/orig_$z.nf" -z "$z" -n 1000 -b 400 >/dev/null 2>&1 \
       && ! is_layout_v3 "$V2DIR/orig_$z.nf" \
       && [ "$(count "$V2DIR/orig_$z.nf" 'any')" -eq 1000 ]; then
        pass "nfgen2_legacy_file_$z"
    else
        fail "nfgen2_legacy_file_$z"
    fi
done

# In place: a legacy file is converted to the 1.8.x layout, keeps its
# compression, ident, stat record and flows, and gets bloom metadata.
for z in none lzo lz4; do
    case "$z" in
        none) expect="not compressed" ;;
        *)    expect="$z compressed" ;;
    esac
    f="$V2DIR/inplace_$z.nf"
    cp "$V2DIR/orig_$z.nf" "$f"
    if nfmeta -r "$f" >/dev/null 2>&1 \
       && is_layout_v3 "$f" \
       && [ "$(compression "$f")" = "$expect" ] \
       && has_bloom "$f" \
       && same_flows "$V2DIR/orig_$z.nf" "$f" \
       && nfdump -I -r "$f" </dev/null 2>/dev/null | grep -q '^Ident: nfgen2$' \
       && nfdump -I -r "$f" </dev/null 2>/dev/null | grep -q '^Flows: 1000$' \
       && [ -z "$(ls "$V2DIR" | grep "^inplace_$z\.nf\.")" ]; then
        pass "nfmeta_v2_inplace_keeps_$z"
    else
        fail "nfmeta_v2_inplace_keeps_$z (compression: '$(compression "$f")')"
    fi
done

# -w without -z inherits the compression of the legacy input file.
if nfmeta -r "$V2DIR/orig_lzo.nf" -w "$V2DIR/write_lzo.nf" >/dev/null 2>&1 \
   && is_layout_v3 "$V2DIR/write_lzo.nf" \
   && [ "$(compression "$V2DIR/write_lzo.nf")" = "lzo compressed" ] \
   && has_bloom "$V2DIR/write_lzo.nf" \
   && same_flows "$V2DIR/orig_lzo.nf" "$V2DIR/write_lzo.nf"; then
    pass "nfmeta_v2_write_inherits_compression"
else
    fail "nfmeta_v2_write_inherits_compression"
fi

# ── -z for -w output files ─────────────────────────────────────────────────────

ZLIST="none lzo lz4"
[ "$TEST_BZIP2" = "yes" ] && ZLIST="$ZLIST bz2"
[ "$TEST_ZSTD" = "yes" ] && ZLIST="$ZLIST zstd"
for z in $ZLIST; do
    case "$z" in
        none) expect="not compressed" ;;
        *)    expect="$z compressed" ;;
    esac
    out="$V2DIR/write_z_$z.nf"
    if nfmeta -r "$V2DIR/orig_lz4.nf" -w "$out" -z="$z" >/dev/null 2>&1 \
       && [ "$(compression "$out")" = "$expect" ] \
       && has_bloom "$out" \
       && same_flows "$V2DIR/orig_lz4.nf" "$out"; then
        pass "nfmeta_write_z_$z"
    else
        fail "nfmeta_write_z_$z (compression: '$(compression "$out")')"
    fi
done

# -z with a level
if [ "$TEST_ZSTD" = "yes" ]; then
    if nfmeta -r "$V2DIR/orig_none.nf" -w "$V2DIR/write_zstd3.nf" -z=zstd:3 >/dev/null 2>&1 \
       && [ "$(compression "$V2DIR/write_zstd3.nf")" = "zstd compressed" ] \
       && same_flows "$V2DIR/orig_none.nf" "$V2DIR/write_zstd3.nf"; then
        pass "nfmeta_write_z_zstd_level"
    else
        fail "nfmeta_write_z_zstd_level"
    fi
fi

# -z without an argument selects lzo, as in nfdump
if nfmeta -r "$V2DIR/orig_lz4.nf" -w "$V2DIR/write_z_default.nf" -z >/dev/null 2>&1 \
   && [ "$(compression "$V2DIR/write_z_default.nf")" = "lzo compressed" ]; then
    pass "nfmeta_write_z_default_lzo"
else
    fail "nfmeta_write_z_default_lzo"
fi

# -z is rejected without -w: in-place updates keep each file's compression.
cp "$V2DIR/orig_lz4.nf" "$V2DIR/z_inplace.nf"
if ! nfmeta -r "$V2DIR/z_inplace.nf" -z=zstd >/dev/null 2>&1 \
   && cmp -s "$V2DIR/orig_lz4.nf" "$V2DIR/z_inplace.nf"; then
    pass "nfmeta_z_requires_w"
else
    fail "nfmeta_z_requires_w"
fi

# invalid, out of range or repeated -z options are rejected
if ! nfmeta -r "$V2DIR/orig_lz4.nf" -w "$V2DIR/bad.nf" -z=foo >/dev/null 2>&1 \
   && ! nfmeta -r "$V2DIR/orig_lz4.nf" -w "$V2DIR/bad.nf" -z=lz4:9999 >/dev/null 2>&1 \
   && ! nfmeta -r "$V2DIR/orig_lz4.nf" -w "$V2DIR/bad.nf" -z=lz4 -z=lzo >/dev/null 2>&1 \
   && [ ! -e "$V2DIR/bad.nf" ]; then
    pass "nfmeta_z_rejects_invalid"
else
    fail "nfmeta_z_rejects_invalid"
fi

# ── nfdump 1.8.x files ─────────────────────────────────────────────────────────

V3DIR="$WORKDIR/v3"
mkdir -p "$V3DIR"
for z in $ZLIST; do
    case "$z" in
        none) expect="not compressed" ;;
        *)    expect="$z compressed" ;;
    esac
    orig="$V3DIR/orig_$z.nf"
    f="$V3DIR/inplace_$z.nf"
    if nfdump -r dummy_flows.nf -z="$z" -w "$orig" >/dev/null 2>&1 \
       && cp "$orig" "$f" \
       && nfmeta -r "$f" >/dev/null 2>&1 \
       && [ "$(compression "$f")" = "$expect" ] \
       && has_bloom "$f" \
       && same_flows "$orig" "$f"; then
        pass "nfmeta_v3_inplace_keeps_$z"
    else
        fail "nfmeta_v3_inplace_keeps_$z (compression: '$(compression "$f")')"
    fi
done

# Running nfmeta again replaces the existing metadata and changes nothing else.
f="$V3DIR/inplace_lz4.nf"
blocks=$(flow_blocks "$f")
if nfmeta -r "$f" >/dev/null 2>&1 \
   && [ "$(compression "$f")" = "lz4 compressed" ] \
   && has_bloom "$f" \
   && [ "$(flow_blocks "$f")" = "$blocks" ] \
   && same_flows "$V3DIR/orig_lz4.nf" "$f"; then
    pass "nfmeta_rerun_replaces_metadata"
else
    fail "nfmeta_rerun_replaces_metadata"
fi

# ── bloom metadata ─────────────────────────────────────────────────────────────

# Filters on an enriched file return the same flows as on the original file.
# Bloom filters may skip blocks, but must never reject a matching one.
f="$V2DIR/inplace_lz4.nf"
ok=1
for filter in 'src ip 10.0.1.4' 'dst ip 172.16.0.7' 'ip 2001:db8::7' 'dst ip 2001:db8:1::3e7' \
              'ip 192.0.2.1' 'ip 2001:db8:ffff::1' 'net 10.0.2.0/24' \
              'src ip 192.0.2.1 or proto tcp' \
              'src ip 2001:db8::3 or proto tcp' \
              'first seen < 2025-01-01 and (src ip 192.0.2.1 or proto tcp)' \
              'first seen > 2030-01-01 or proto tcp' \
              'first seen > 2030-01-01 or src ip 10.0.0.1' \
              '(first seen > 2030-01-01 and src ip 192.0.2.1) or proto tcp' \
              'first seen > 2030-01-01 and src ip 10.0.0.1' \
              'src ip 10.0.0.1 or src ip 10.0.0.2' \
              'src ip 2001:db8::3 or src ip 2001:db8::7' \
              'not src ip 10.0.0.1' 'not src ip 2001:db8::3' \
              'src ip in [192.0.2.1 10.0.0.0/24]' \
              'first seen > 2024-01-01T01:00:05' 'last seen < 2024-01-01T01:00:02'; do
    c1=$(count "$V2DIR/orig_lz4.nf" "$filter")
    c2=$(count "$f" "$filter")
    if [ "$c1" != "$c2" ]; then
        echo "        filter '$filter': original $c1, enriched $c2"
        ok=0
    fi
done
# sanity: known matches and non-matches
[ "$(count "$f" 'src ip 10.0.1.4')" -eq 1 ] || ok=0
[ "$(count "$f" 'ip 2001:db8::7')" -eq 1 ] || ok=0
[ "$(count "$f" 'ip 192.0.2.1')" -eq 0 ] || ok=0
if [ "$ok" -eq 1 ]; then
    pass "nfmeta_bloom_filters_match_original"
else
    fail "nfmeta_bloom_filters_match_original"
fi

# Prove that metadata pruning is active, while an accepting ordinary-filter
# branch still keeps every block. A false time branch combined with an exact IP
# must fall through to the Bloom decision instead of skipping the whole file.
if [ "$(blocks_skipped "$V2DIR/orig_lz4.nf" 'src ip 192.0.2.1')" -eq 0 ] \
   && [ "$(blocks_skipped "$f" 'src ip 192.0.2.1')" -gt 0 ] \
   && [ "$(blocks_skipped "$f" 'src ip 192.0.2.1 or proto tcp')" -eq 0 ] \
   && [ "$(count "$f" 'first seen > 2030-01-01 or src ip 10.0.0.1')" -eq 1 ] \
   && [ "$(blocks_skipped "$f" 'first seen > 2030-01-01 or src ip 10.0.0.1')" -gt 0 ]; then
    pass "nfmeta_block_filter_control_flow"
else
    fail "nfmeta_block_filter_control_flow"
fi

# Filter workers may finish blocks out of order. Their completion stream must
# nevertheless reproduce source order, including zero-match block tombstones
# and early termination through -c.
if nfdump -q -r "$f" -x threads.workers=1 -o csv 'proto tcp or src ip 10.0.0.1' >"$WORKDIR/order1.csv" \
   && nfdump -q -r "$f" -x threads.workers=4 -o csv 'proto tcp or src ip 10.0.0.1' >"$WORKDIR/order4.csv" \
   && cmp -s "$WORKDIR/order1.csv" "$WORKDIR/order4.csv" \
   && nfdump -q -r "$f" -x threads.workers=1 -o csv 'src port 1424' >"$WORKDIR/tombstone1.csv" \
   && nfdump -q -r "$f" -x threads.workers=4 -o csv 'src port 1424' >"$WORKDIR/tombstone4.csv" \
   && cmp -s "$WORKDIR/tombstone1.csv" "$WORKDIR/tombstone4.csv" \
   && nfdump -q -r "$f" -x threads.workers=1 -c 73 -o csv 'proto tcp' >"$WORKDIR/limit1.csv" \
   && nfdump -q -r "$f" -x threads.workers=4 -c 73 -o csv 'proto tcp' >"$WORKDIR/limit4.csv" \
   && cmp -s "$WORKDIR/limit1.csv" "$WORKDIR/limit4.csv"; then
    pass "nfdump_filter_workers_preserve_order"
else
    fail "nfdump_filter_workers_preserve_order"
fi

# An unreadable data block is skipped: all other blocks are still delivered,
# the failure is reported by a non-zero exit, and nfmeta does not replace the
# original file in place. The test file is uncompressed, so the number of
# records of a flow block is readable in its header at offset 24. The
# encryption field at offset 14 is set to an unknown type to make the block
# unreadable.
"$NFGEN2" -w "$V2DIR/multi.v2" -z lz4 -n 150000 -b 5000 >/dev/null 2>&1
nfdump -r "$V2DIR/multi.v2" -z=none -w "$V2DIR/multi.nf" >/dev/null 2>&1
off=$(nfdump -v check-verbose -r "$V2DIR/multi.nf" </dev/null 2>/dev/null \
        | sed -n 's/^Checkblock: type: 1, offset: \([0-9]*\).*/\1/p' | sed -n 2p)
if [ -n "$off" ]; then
    lost=$(od -An -tu4 -j $((off + 24)) -N4 "$V2DIR/multi.nf" | tr -d ' ')
    cp "$V2DIR/multi.nf" "$V2DIR/badblock.nf"
    printf '\167\167' | dd of="$V2DIR/badblock.nf" bs=1 seek=$((off + 14)) conv=notrunc 2>/dev/null
    # data lines only: the read error message is printed as well
    flows "$V2DIR/multi.nf" | grep '^[0-9]' >"$WORKDIR/intact.csv"
    flows "$V2DIR/badblock.nf" -x threads.readers=4 | grep '^[0-9]' >"$WORKDIR/badblock.csv"
    cp "$V2DIR/badblock.nf" "$V2DIR/badblock_inplace.nf"
    if ! nfdump -q -r "$V2DIR/badblock.nf" -o csv >/dev/null 2>&1 \
       && [ "$(wc -l <"$WORKDIR/badblock.csv")" -eq $(($(wc -l <"$WORKDIR/intact.csv") - lost)) ] \
       && [ -z "$(comm -13 "$WORKDIR/intact.csv" "$WORKDIR/badblock.csv")" ] \
       && ! nfmeta -r "$V2DIR/badblock_inplace.nf" >/dev/null 2>&1 \
       && cmp -s "$V2DIR/badblock.nf" "$V2DIR/badblock_inplace.nf" \
       && [ -z "$(ls "$V2DIR" | grep '^badblock_inplace\.nf\.')" ] \
       && nfdump -q -r "$V2DIR/multi.nf" -o csv >/dev/null 2>&1; then
        pass "nfdump_skips_unreadable_block"
    else
        fail "nfdump_skips_unreadable_block"
    fi
else
    fail "nfdump_skips_unreadable_block (no multi-block test file)"
fi

# With more workers than input blocks, idle workers must not write empty
# blocks that only hold bloom metadata.
"$NFGEN2" -w "$V2DIR/one_block.nf" -z lz4 -n 500 -b 500 >/dev/null 2>&1
if nfmeta -r "$V2DIR/one_block.nf" -w "$V2DIR/one_block_meta.nf" -x threads.workers=4 >/dev/null 2>&1 \
   && [ "$(flow_blocks "$V2DIR/one_block_meta.nf")" = "1" ] \
   && has_bloom "$V2DIR/one_block_meta.nf" \
   && same_flows "$V2DIR/one_block.nf" "$V2DIR/one_block_meta.nf"; then
    pass "nfmeta_no_empty_blocks"
else
    fail "nfmeta_no_empty_blocks (flow blocks: '$(flow_blocks "$V2DIR/one_block_meta.nf")')"
fi

# ── directories ────────────────────────────────────────────────────────────────

# In place over a directory with mixed legacy and current files.
DIRIN="$WORKDIR/dir_inplace"
mkdir -p "$DIRIN"
cp "$V2DIR/orig_lzo.nf" "$DIRIN/nfcapd.202401010000"
cp "$V3DIR/orig_lz4.nf" "$DIRIN/nfcapd.202401010005"
if nfmeta -r "$DIRIN" >/dev/null 2>&1 \
   && [ "$(compression "$DIRIN/nfcapd.202401010000")" = "lzo compressed" ] \
   && [ "$(compression "$DIRIN/nfcapd.202401010005")" = "lz4 compressed" ] \
   && has_bloom "$DIRIN/nfcapd.202401010000" \
   && has_bloom "$DIRIN/nfcapd.202401010005" \
   && [ "$(ls "$DIRIN" | wc -l | tr -d ' ')" -eq 2 ]; then
    pass "nfmeta_directory_inplace"
else
    fail "nfmeta_directory_inplace"
fi

# A directory with -w produces one merged output file.
if nfmeta -r "$DIRIN" -w "$WORKDIR/dir_merged.nf" >/dev/null 2>&1 \
   && has_bloom "$WORKDIR/dir_merged.nf" \
   && [ "$(count "$WORKDIR/dir_merged.nf" 'any')" -eq \
        "$(( $(count "$V2DIR/orig_lzo.nf" 'any') + $(count "$V3DIR/orig_lz4.nf" 'any') ))" ]; then
    pass "nfmeta_directory_write_merged"
else
    fail "nfmeta_directory_write_merged"
fi

# ── encrypted files ────────────────────────────────────────────────────────────

# -K requires libsodium, detected via 'CRYPTO' in nfdump -V as in
# test_crypto_nfcapd.sh.
if "$NFDUMP_BIN" -V 2>&1 | grep -q 'CRYPTO'; then
    ENCDIR="$WORKDIR/enc"
    mkdir -p "$ENCDIR"
    nfdump -r "$V2DIR/orig_lz4.nf" -z=lz4 -K=metapass -w "$ENCDIR/orig.nf" >/dev/null 2>&1

    # Without -K an encrypted file is rejected, not prompted for, and never
    # replaced by an unencrypted one.
    cp "$ENCDIR/orig.nf" "$ENCDIR/nokey.nf"
    if [ "$(check_value "$ENCDIR/orig.nf" Encrypted -K=metapass)" = "yes" ] \
       && ! nfmeta -r "$ENCDIR/nokey.nf" >/dev/null 2>&1 \
       && cmp -s "$ENCDIR/orig.nf" "$ENCDIR/nokey.nf" \
       && [ "$(ls "$ENCDIR" | wc -l | tr -d ' ')" -eq 2 ]; then
        pass "nfmeta_encrypted_requires_key"
    else
        fail "nfmeta_encrypted_requires_key"
    fi

    # A wrong passphrase fails and leaves the file untouched.
    cp "$ENCDIR/orig.nf" "$ENCDIR/wrongkey.nf"
    if ! nfmeta -K=wrongpass -r "$ENCDIR/wrongkey.nf" >/dev/null 2>&1 \
       && cmp -s "$ENCDIR/orig.nf" "$ENCDIR/wrongkey.nf"; then
        pass "nfmeta_encrypted_wrong_key"
    else
        fail "nfmeta_encrypted_wrong_key"
    fi

    # In place with -K: enriched, re-encrypted, compression preserved.
    f="$ENCDIR/inplace.nf"
    cp "$ENCDIR/orig.nf" "$f"
    if nfmeta -K=metapass -r "$f" >/dev/null 2>&1 \
       && [ "$(check_value "$f" Encrypted -K=metapass)" = "yes" ] \
       && [ "$(compression "$f" -K=metapass)" = "lz4 compressed" ] \
       && has_bloom "$f" -K=metapass \
       && same_flows "$V2DIR/orig_lz4.nf" "$f" -K=metapass \
       && ! nfdump -q -r "$f" -K=wrongpass -o csv >/dev/null 2>&1; then
        pass "nfmeta_encrypted_inplace_reencrypted"
    else
        fail "nfmeta_encrypted_inplace_reencrypted"
    fi

    # The key file form works the same way.
    keyfile="$ENCDIR/meta.key"
    f="$ENCDIR/inplace_keyfile.nf"
    cp "$ENCDIR/orig.nf" "$f"
    if (umask 077 && printf '%s\n' metapass >"$keyfile") \
       && nfmeta -K@"$keyfile" -r "$f" >/dev/null 2>&1 \
       && [ "$(check_value "$f" Encrypted -K=metapass)" = "yes" ] \
       && has_bloom "$f" -K=metapass \
       && same_flows "$V2DIR/orig_lz4.nf" "$f" -K=metapass; then
        pass "nfmeta_encrypted_keyfile"
    else
        fail "nfmeta_encrypted_keyfile"
    fi

    # -w with -K encrypts the output, also for unencrypted legacy input, and
    # honours -z.
    out="$ENCDIR/write_lzo.nf"
    if nfmeta -K=metapass -r "$V2DIR/orig_none.nf" -w "$out" -z=lzo >/dev/null 2>&1 \
       && [ "$(check_value "$out" Encrypted -K=metapass)" = "yes" ] \
       && [ "$(compression "$out" -K=metapass)" = "lzo compressed" ] \
       && has_bloom "$out" -K=metapass \
       && same_flows "$V2DIR/orig_none.nf" "$out" -K=metapass; then
        pass "nfmeta_encrypted_write"
    else
        fail "nfmeta_encrypted_write"
    fi

    # Unencrypted files updated in place stay unencrypted with -K.
    f="$ENCDIR/plain.nf"
    cp "$V3DIR/orig_lz4.nf" "$f"
    if nfmeta -K=metapass -r "$f" >/dev/null 2>&1 \
       && [ "$(check_value "$f" Encrypted)" = "no" ] \
       && has_bloom "$f" \
       && same_flows "$V3DIR/orig_lz4.nf" "$f"; then
        pass "nfmeta_plain_inplace_stays_plain"
    else
        fail "nfmeta_plain_inplace_stays_plain"
    fi
else
    skip "nfmeta_encrypted: nfdump built without libsodium"
fi

summary
