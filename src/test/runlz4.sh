#!/bin/sh
#  This file is part of the nfdump project.
#
#  Copyright (c) 2023-2024, Peter Haag
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
echo "── lz4 compression ────────────────────────────────────────────────────"

cp dummy_flows.nf "$WORKDIR/flows.nf"

if nfdump -J=lz4 -r "$WORKDIR/flows.nf" >/dev/null 2>&1 \
   && nfdump -v check -r "$WORKDIR/flows.nf" >/dev/null 2>&1; then
    pass "lz4"
else
    fail "lz4"
fi

if nfdump -J=none -r "$WORKDIR/flows.nf" >/dev/null 2>&1 \
   && nfdump -v check -r "$WORKDIR/flows.nf" >/dev/null 2>&1; then
    pass "none"
else
    fail "none"
fi

if nfdump -J=lz4:5 -r "$WORKDIR/flows.nf" >/dev/null 2>&1 \
   && nfdump -v check -r "$WORKDIR/flows.nf" >/dev/null 2>&1; then
    pass "lz4:5"
else
    fail "lz4:5"
fi

if nfdump -J=none -r "$WORKDIR/flows.nf" >/dev/null 2>&1 \
   && nfdump -v check -r "$WORKDIR/flows.nf" >/dev/null 2>&1; then
    pass "none_2"
else
    fail "none_2"
fi

if nfdump -J=lz4:9 -r "$WORKDIR/flows.nf" >/dev/null 2>&1 \
   && nfdump -v check -r "$WORKDIR/flows.nf" >/dev/null 2>&1; then
    pass "lz4:9"
else
    fail "lz4:9"
fi

if nfdump -J=none -r "$WORKDIR/flows.nf" >/dev/null 2>&1 \
   && nfdump -v check -r "$WORKDIR/flows.nf" >/dev/null 2>&1; then
    pass "none_3"
else
    fail "none_3"
fi

summary
