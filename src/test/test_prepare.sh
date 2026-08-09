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
echo "── prepare test data ────────────────────────────────────────────────────"

# generate dummy_flows.nf used by all subsequent test scripts
rm -f dummy_flows.nf
if ./nfgen4 >/dev/null 2>&1; then
    pass "nfgen4"
else
    fail "nfgen4"
fi

# verify the generated file is well-formed
if nfdump -v check -r dummy_flows.nf >/dev/null 2>&1; then
    pass "nffile_check"
else
    fail "nffile_check"
fi

# The checker must inspect decoded V4 records, not only the block directory.
# nfgen4's first flow block starts at the fixed V3 header (48 bytes); its
# third record's two-byte size field is at byte 154. Zero it without touching
# the block or directory headers and expect the deep check to reject the file.
badfile="$WORKDIR/invalid-v4-record.nf"
cp dummy_flows.nf "$badfile"
if printf '\000\000' | dd of="$badfile" bs=1 seek=154 conv=notrunc 2>/dev/null \
   && ! nfdump -v check -r "$badfile" >/dev/null 2>&1; then
    pass "nffile_check_rejects_invalid_v4_record"
else
    fail "nffile_check_rejects_invalid_v4_record"
fi

# A mismatched extension count leaves the generic V4 record framing intact.
# The quick check accepts it, while check-verbose must inspect the extension
# directory and reject it. The field belongs to nfgen4's third V4 record.
detailfile="$WORKDIR/invalid-v4-directory.nf"
cp dummy_flows.nf "$detailfile"
if printf '\000\000' | dd of="$detailfile" bs=1 seek=156 conv=notrunc 2>/dev/null \
   && nfdump -v check -r "$detailfile" >/dev/null 2>&1 \
   && ! nfdump -v check-verbose -r "$detailfile" >/dev/null 2>&1; then
    pass "nffile_check_verbose_validates_v4_directory"
else
    fail "nffile_check_verbose_validates_v4_directory"
fi

# verify the flow content matches the reference output
if nfdump -r dummy_flows.nf -q -o raw >"$WORKDIR/raw.txt" 2>/dev/null \
   && diff -u "$WORKDIR/raw.txt" "$SCRIPT_DIR/ref_raw.txt" >/dev/null 2>&1; then
    pass "raw_output_reference"
else
    fail "raw_output_reference"
fi

summary
