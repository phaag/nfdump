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
# Exercises the maxmind geoDB code end to end via the geolookup(1) tool:
#   - building an nfdump geoDB from MaxMind CSV files (mmcreate.c)
#   - the CSV parser's handling of quoted/comma-containing fields and of
#     rows with missing optional fields (empty country/city/time_zone)
#   - correctness of geo/timezone/AS lookups against known-good CSV input
#     (mmhash.c, maxmind.c)
#   - the nffileV3 master DB <-> mmap'd .flat cache round trip, including
#     loading the .flat file directly, and that both give identical results
#   - CLI argument and stdin "whois paste" parsing (geolookup.c)
#   - the .flat file bounds-check added to guard against a truncated or
#     corrupted cache file being loaded (regression test)
#
# Test data lives in test/maxmind/:
#   GeoIP2-City-CSV_Example/    official MaxMind example CSVs (small, fixed
#                               content - counts and values below are exact)
#   GeoLite2-ASN-CSV_Example/   hand-crafted ASN CSVs (see its README.txt) -
#                               MaxMind does not ship an ASN example bundle

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/testsetup.sh"

echo ""
echo "── maxmind geoDB ────────────────────────────────────────────────────────"

if [ -z "$MAXMIND_TESTDATA" ] || [ ! -d "$MAXMIND_TESTDATA/GeoIP2-City-CSV_Example" ]; then
    skip "maxmind_csv_fixtures_missing"
    summary
    exit $?
fi
if [ ! -x "$GEOLOOKUP_BIN" ]; then
    skip "geolookup_binary_missing"
    summary
    exit $?
fi

CITY="$MAXMIND_TESTDATA/GeoIP2-City-CSV_Example"
ASN="$MAXMIND_TESTDATA/GeoLite2-ASN-CSV_Example"

# ── stage a combined CSV directory ─────────────────────────────────────────
# LoadMaps() reads every *.csv in one flat directory and picks files by
# filename substring. The City example ships location files for 8 locales,
# all matching "-City-Locations-", and LoadMaps has no way to prefer one -
# it just keeps the last one readdir() happens to return. Stage only the
# "en" locale explicitly so results are deterministic, alongside the v4/v6
# city blocks and the crafted ASN blocks.
CSVDIR="$WORKDIR/csv"
mkdir -p "$CSVDIR"
ln -s "$CITY/GeoIP2-City-Locations-en.csv" "$CSVDIR/GeoIP2-City-Locations-en.csv"
ln -s "$CITY/GeoIP2-City-Blocks-IPv4.csv" "$CSVDIR/GeoIP2-City-Blocks-IPv4.csv"
ln -s "$CITY/GeoIP2-City-Blocks-IPv6.csv" "$CSVDIR/GeoIP2-City-Blocks-IPv6.csv"
ln -s "$ASN/GeoLite2-ASN-Blocks-IPv4.csv" "$CSVDIR/GeoLite2-ASN-Blocks-IPv4.csv"
ln -s "$ASN/GeoLite2-ASN-Blocks-IPv6.csv" "$CSVDIR/GeoLite2-ASN-Blocks-IPv6.csv"

DB="$WORKDIR/test.nf"

# ── 1. build the DB from CSV and verify exact row counts ──────────────────
# The example CSVs have fixed, known content, so exact counts catch both
# under-parsing (rows silently dropped) and over-parsing (e.g. a quoted
# comma splitting one row into two).
BUILD_LOG="$WORKDIR/build.log"
if geolookup -d "$CSVDIR" -w "$DB" >"$BUILD_LOG" 2>&1; then
    if grep -q "Loaded 57 location records" "$BUILD_LOG" \
       && grep -q "Loaded 18 entries into IPV4 tree" "$BUILD_LOG" \
       && grep -q "Loaded 230 entries into IPV6 tree" "$BUILD_LOG" \
       && grep -q "Loaded 7 entries into ASV4 tree" "$BUILD_LOG" \
       && grep -q "Loaded 3 entries into ASV6 tree" "$BUILD_LOG" \
       && [ -s "$DB" ]; then
        pass "build_db_row_counts"
    else
        fail "build_db_row_counts"
        cat "$BUILD_LOG"
    fi
else
    fail "build_db_exit_status"
    cat "$BUILD_LOG"
fi

# ── 2. malformed CSV header is rejected, DB build keeps going ─────────────
# checkFile() validates the header field-by-field; a mismatch fails that one
# table (0 records loaded) without aborting the whole build. Verify both the
# error is reported and the affected table really is empty, not silently
# populated with misaligned data.
BADDIR="$WORKDIR/badcsv"
mkdir -p "$BADDIR"
sed 's/city_name/CITY/' "$CITY/GeoIP2-City-Locations-en.csv" >"$BADDIR/GeoIP2-City-Locations-en.csv"
ln -s "$CITY/GeoIP2-City-Blocks-IPv4.csv" "$BADDIR/GeoIP2-City-Blocks-IPv4.csv"
BADDB="$WORKDIR/bad.nf"
BAD_LOG="$WORKDIR/bad_build.log"
geolookup -d "$BADDIR" -w "$BADDB" >"$BAD_LOG" 2>&1
# checkFile() fails before loadLocalMap() ever reaches its "Loaded N location
# records" line, so there is no such line to look for here - only the error
# and the fact that loadLocalMap() bailed out. The next check (below) proves
# the location table really did end up empty.
if grep -q "Field check failed" "$BAD_LOG" && grep -q "loadLocalMap.*failed" "$BAD_LOG"; then
    pass "malformed_csv_header_rejected"
else
    fail "malformed_csv_header_rejected"
    cat "$BAD_LOG"
fi
# the (still valid) IPv4 blocks table loaded fine, but its geoname_id now
# has no matching location row - must report "no information", not crash
# or return a bogus join.
if geolookup -G "$BADDB" 2.2.3.1 2>&1 | grep -q "no information"; then
    pass "malformed_csv_location_join_miss"
else
    fail "malformed_csv_location_join_miss"
fi

# ── 3. lookup correctness against known CSV content ────────────────────────
# One IP per interesting case:
#   2.2.3.1         plain match, AS org with no embedded punctuation
#   81.2.69.145     second City block sharing a geoname_id with others
#   149.101.100.1   AS org name with an embedded comma inside quotes
#   2.3.3.1         geoname row with empty country/city/time_zone fields
#                   (continent-only row) - exercises the city fallback chain
#   2001:218::1     IPv6, city falls back to country name ("Japan")
#   214.1.1.1       block row with empty geoname_id AND empty
#                   registered_country_geoname_id - no match at all
TESTIPS="2.2.3.1 81.2.69.145 149.101.100.1 2.3.3.1 2001:218::1 214.1.1.1"

SLOW_OUT="$WORKDIR/slow.out"
geolookup -G "$DB" $TESTIPS >"$SLOW_OUT" 2>&1

check_lookup() {
    # $1 = test name, remaining args = substrings that must all appear
    name="$1"
    shift
    ok=1
    for needle in "$@"; do
        grep -qF -- "$needle" "$SLOW_OUT" || ok=0
    done
    if [ "$ok" = 1 ]; then pass "$name"; else fail "$name"; fi
}

check_lookup "lookup_basic"          "5089" "Sky UK Limited" "EU/GB/Boxford" "-1.2500" "51.7500" "TZ: Europe/London"
check_lookup "lookup_shared_geoname" "29049" "Aire Networks" "EU/GB/London" "-0.0931" "51.5142" "TZ: Europe/London"
check_lookup "lookup_quoted_comma_org" "7018" "AT&T Services, Inc." "NA/US/United States" "-97.8220" "37.7510" "TZ: America/Chicago"
check_lookup "lookup_empty_fields_fallback" "3320" "Deutsche Telekom AG" "EU//unknown"
check_lookup "lookup_ipv6_city_fallback" "2497" "Internet Initiative Japan Inc." "AS/JP/Japan" "139.7531" "35.6854" "TZ: Asia/Tokyo"
check_lookup "lookup_no_match"        "214.1.1.1" "no information" "TZ: -"

if [ "$ok" != 1 ]; then cat "$SLOW_OUT"; fi

# ── 4. AS-only lookup mode (as<number>) ─────────────────────────────────────
if geolookup -G "$DB" as7018 2>&1 | grep -qF "AT&T Services, Inc."; then
    pass "as_lookup_mode"
else
    fail "as_lookup_mode"
fi

# ── 5. stdin "whois paste" mode ─────────────────────────────────────────────
# geolookup with no IP arguments reads stdin, splits on space/'(' and looks
# up any tokens that parse as a valid IPv4/IPv6 address.
STDIN_OUT=$(printf 'flow from 2.2.3.1 (edge1) to 81.2.69.145 (core1)\n' | geolookup -G "$DB" 2>&1)
if echo "$STDIN_OUT" | grep -qF "Sky UK Limited" && echo "$STDIN_OUT" | grep -qF "Aire Networks"; then
    pass "stdin_whois_paste"
else
    fail "stdin_whois_paste"
fi

# ── 6. flat cache: slow path (build+write) == fast path (mmap) == direct .flat
# First -G load has no .flat yet, decompresses the nffileV3 master and writes
# one (mmhash.c: LoadMaxMind's slow path + WriteFlatCache). All three loading
# strategies must produce byte-identical lookup output.
FLAT="$DB.flat"
rm -f "$FLAT"
geolookup -G "$DB" $TESTIPS >"$WORKDIR/pass1.out" 2>&1
if [ -s "$FLAT" ]; then
    pass "flat_cache_created"
else
    fail "flat_cache_created"
fi

geolookup -G "$DB" $TESTIPS >"$WORKDIR/pass2.out" 2>&1        # fast path: mmap via master path
geolookup -G "$FLAT" $TESTIPS >"$WORKDIR/pass3.out" 2>&1      # fast path: .flat given directly

if diff -q "$WORKDIR/pass1.out" "$WORKDIR/pass2.out" >/dev/null 2>&1 \
   && diff -q "$WORKDIR/pass1.out" "$WORKDIR/pass3.out" >/dev/null 2>&1; then
    pass "flat_cache_matches_slow_path"
else
    fail "flat_cache_matches_slow_path"
    diff "$WORKDIR/pass1.out" "$WORKDIR/pass2.out"
    diff "$WORKDIR/pass1.out" "$WORKDIR/pass3.out"
fi

# ── 7. corrupted .flat file is rejected, not trusted ────────────────────────
# Regression test for the LoadFlatCache() bounds check: a truncated cache
# file must be cleanly rejected (and must not crash), never silently read
# out of bounds. See mmhash.c LoadFlatCache()'s CHECK_SEC.
TRUNCATED="$WORKDIR/truncated.flat"
cp "$FLAT" "$TRUNCATED"
origSize=$(wc -c <"$FLAT" | tr -d ' ')
if ! truncate -s $((origSize / 100)) "$TRUNCATED" 2>/dev/null; then
    # no truncate(1) available - fall back to copying just the first 1%
    dd if="$FLAT" of="$TRUNCATED" bs=1 count=$((origSize / 100)) 2>/dev/null
fi

TRUNC_LOG="$WORKDIR/truncated.log"
geolookup -G "$TRUNCATED" 8.8.8.8 >"$TRUNC_LOG" 2>&1
rc=$?
# must fail cleanly (rc 1 from exit(EXIT_FAILURE)), not die from a signal
# (rc >= 128) such as a SIGSEGV from an out-of-bounds mmap access.
if [ "$rc" -ge 1 ] && [ "$rc" -lt 128 ] && grep -qi "exceeds file size\|cannot load flat file" "$TRUNC_LOG"; then
    pass "truncated_flat_cache_rejected"
else
    fail "truncated_flat_cache_rejected"
    echo "exit code: $rc"
    cat "$TRUNC_LOG"
fi

summary
