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
echo "── nfanon ───────────────────────────────────────────────────────────────"

# -W accepts only a complete, non-negative integer.
if ! "$NFANON_BIN" -W invalid >/dev/null 2>&1; then
    pass "nfanon_rejects_invalid_core_limit"
else
    fail "nfanon_rejects_invalid_core_limit"
fi

# anonymise a flow file and verify the result is readable
if "$NFANON_BIN" -A abcdefghijklmnopqrstuvwxyz012345 \
          -r dummy_flows.nf -w "$WORKDIR/anon.nf" >/dev/null 2>&1 \
   && "$NFDUMP_BIN" -v check -r "$WORKDIR/anon.nf" >/dev/null 2>&1 \
   && "$NFDUMP_BIN" -q -r "$WORKDIR/anon.nf" -o raw >/dev/null 2>&1; then
    pass "nfanon_write_read"
else
    fail "nfanon_write_read"
fi

# A directory and -w produce one aggregate output file, not one overwritten
# output per source file.
multi_input="$WORKDIR/nfanon-multi-input"
if mkdir "$multi_input" \
   && cp dummy_flows.nf "$multi_input/flows-a.nf" \
   && cp dummy_flows.nf "$multi_input/flows-b.nf" \
   && "$NFANON_BIN" -A abcdefghijklmnopqrstuvwxyz012345 \
          -r "$multi_input" -w "$WORKDIR/anon-all.nf" >/dev/null 2>&1 \
   && "$NFDUMP_BIN" -v check -r "$WORKDIR/anon-all.nf" >/dev/null 2>&1 \
   && "$NFDUMP_BIN" -q -r dummy_flows.nf -o raw >"$WORKDIR/original.raw" \
   && "$NFDUMP_BIN" -q -r "$WORKDIR/anon-all.nf" -o raw >"$WORKDIR/anon-all.raw" \
   && [ "$(wc -l < "$WORKDIR/anon-all.raw")" -eq "$((2 * $(wc -l < "$WORKDIR/original.raw")))" ]; then
    pass "nfanon_directory_single_output"
else
    fail "nfanon_directory_single_output"
fi

# Without -w each input file is replaced in place, including when -r names a
# directory. The temporary replacement files must not remain behind.
inplace_input="$WORKDIR/nfanon-inplace-input"
if mkdir "$inplace_input" \
   && cp dummy_flows.nf "$inplace_input/flows-a.nf" \
   && cp dummy_flows.nf "$inplace_input/flows-b.nf" \
   && "$NFANON_BIN" -A abcdefghijklmnopqrstuvwxyz012345 -r "$inplace_input" >/dev/null 2>&1 \
   && "$NFDUMP_BIN" -v check -r "$inplace_input/flows-a.nf" >/dev/null 2>&1 \
   && "$NFDUMP_BIN" -v check -r "$inplace_input/flows-b.nf" >/dev/null 2>&1 \
   && [ ! -e "$inplace_input/flows-a.nf-tmp" ] \
   && [ ! -e "$inplace_input/flows-b.nf-tmp" ]; then
    pass "nfanon_directory_inplace_output"
else
    fail "nfanon_directory_inplace_output"
fi

# Bloom filters contain hashes of the original addresses. nfanon must remove
# them after anonymization and instruct the user to rebuild them with nfmeta.
if "$NFMETA_BIN" -r dummy_flows.nf -w "$WORKDIR/indexed.nf" -v 1 >/dev/null 2>&1 \
   && "$NFDUMP_BIN" -v check -r "$WORKDIR/indexed.nf" >/dev/null 2>&1 \
   && cp "$WORKDIR/indexed.nf" "$WORKDIR/invalid-bloom.nf" \
   && printf '\000\040' | dd of="$WORKDIR/invalid-bloom.nf" bs=1 seek=106 conv=notrunc 2>/dev/null \
   && ! "$NFDUMP_BIN" -v check -r "$WORKDIR/invalid-bloom.nf" >/dev/null 2>&1 \
   && "$NFANON_BIN" -A abcdefghijklmnopqrstuvwxyz012345 \
          -r "$WORKDIR/indexed.nf" -w "$WORKDIR/no_bloom.nf" -W 1 -v 1 >"$WORKDIR/nfanon-bloom.log" 2>&1 \
   && grep -q 'Removed IP bloom-filter metadata.*nfmeta' "$WORKDIR/nfanon-bloom.log" \
   && "$NFDUMP_BIN" -v check -r "$WORKDIR/no_bloom.nf" >/dev/null 2>&1 \
   && "$NFMETA_BIN" -r "$WORKDIR/no_bloom.nf" -w "$WORKDIR/reindexed.nf" -v 1 >/dev/null 2>&1; then
    pass "nfanon_removes_bloom_metadata"
else
    fail "nfanon_removes_bloom_metadata"
fi

# -K (backend file encryption) requires nfanon and nfdump both built with
# libsodium; detected the same way as test_crypto_nfcapd.sh, via 'CRYPTO' in
# their -V output. Without it, -K is rejected at option-parsing time, so
# these three tests would fail rather than exercise anything -K-specific.
if "$NFANON_BIN" -V 2>&1 | grep -q 'CRYPTO' && "$NFDUMP_BIN" -V 2>&1 | grep -q 'CRYPTO'; then

    # -K on read+write: nfanon can process a backend-encrypted input file and
    # produce a backend-encrypted output, using the same convention as nfdump
    # (-K covers both directions with one passphrase). -A (CryptoPAn key) and
    # -K (encryption passphrase) are independent options.
    if "$NFDUMP_BIN" -q -r dummy_flows.nf -z=lz4 -K=anonpass -w "$WORKDIR/enc_src.nf" >/dev/null 2>&1 \
       && "$NFANON_BIN" -A abcdefghijklmnopqrstuvwxyz012345 -K=anonpass \
              -r "$WORKDIR/enc_src.nf" -w "$WORKDIR/enc_anon.nf" >/dev/null 2>&1 \
       && "$NFDUMP_BIN" -v check -r "$WORKDIR/enc_anon.nf" -K=anonpass >/dev/null 2>&1 \
       && "$NFDUMP_BIN" -q -r "$WORKDIR/enc_anon.nf" -K=anonpass -o raw >/dev/null 2>&1; then
        pass "nfanon_encrypted_round_trip"
    else
        fail "nfanon_encrypted_round_trip"
    fi

    # regression: a wrong -K passphrase must fail cleanly (non-zero exit), not
    # silently report success.
    if "$NFANON_BIN" -A abcdefghijklmnopqrstuvwxyz012345 -K=wrongpass \
              -r "$WORKDIR/enc_src.nf" -w "$WORKDIR/enc_wrong.nf" </dev/null >/dev/null 2>&1; then
        fail "nfanon_wrong_passphrase_rejected: unexpectedly exited 0"
    else
        pass "nfanon_wrong_passphrase_rejected"
    fi

    # regression: no -K at all on an encrypted input, in a non-interactive
    # context (no controlling terminal to prompt on), must fail cleanly rather
    # than silently reporting "Processed 0 files" with exit 0.
    if "$NFANON_BIN" -A abcdefghijklmnopqrstuvwxyz012345 \
              -r "$WORKDIR/enc_src.nf" -w "$WORKDIR/enc_none.nf" </dev/null >/dev/null 2>&1; then
        fail "nfanon_missing_passphrase_rejected: unexpectedly exited 0"
    else
        pass "nfanon_missing_passphrase_rejected"
    fi
else
    skip "nfanon_encrypted_round_trip: libsodium not compiled in"
    skip "nfanon_wrong_passphrase_rejected: libsodium not compiled in"
    skip "nfanon_missing_passphrase_rejected: libsodium not compiled in"
fi

summary
