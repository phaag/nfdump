#!/bin/sh
#
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
# sfcapd smoke tests: one deterministic sFlow v5 PCAP decode and daemon shutdown.

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/testsetup.sh"

echo ""
echo "── sfcapd smoke tests ─────────────────────────────────────────────────"

if [ ! -x "$SFCAPD_BIN" ] || [ ! -x "$SFLOWGEN_BIN" ]; then
    skip "sflow_pcap_decode: sfcapd or sflowgen not available"
    skip "sflow_sigterm: sfcapd or sflowgen not available"
    summary
    exit 0
fi

PCAP="$WORKDIR/sflow-v5.pcap"
OFFLINE_DIR="$WORKDIR/sflow-pcap"
mkdir -p "$OFFLINE_DIR"

if ! "$SFLOWGEN_BIN" "$PCAP"; then
    fail "sflow_pcap_decode: could not create fixture"
elif ! "$SFCAPD_BIN" -f "$PCAP" -w "$OFFLINE_DIR" -I sflow-smoke -t 2 -v 0 >"$WORKDIR/sfcapd-pcap.log" 2>&1; then
    fail "sflow_pcap_decode: sfcapd failed"
else
    FLOW_FILE=$(ls "$OFFLINE_DIR"/nfcapd.* 2>/dev/null | head -1)
    if [ -z "$FLOW_FILE" ]; then
        fail "sflow_pcap_decode: no output file created"
    elif ! nfdump -v check -r "$FLOW_FILE" >"$WORKDIR/sfcapd-check.log" 2>&1; then
        fail "sflow_pcap_decode: output file validation failed"
    else
        FLOW=$(nfdump -r "$FLOW_FILE" -q -o csv 2>/dev/null | sed -n '2p')
        EXPECTED='2023-11-14 23:13:20.000,0.000,6,203.0.113.10,12345,198.51.100.20,443,1000,128000,1'
        if [ "$FLOW" = "$EXPECTED" ]; then
            pass "sflow_pcap_decode"
        else
            fail "sflow_pcap_decode: unexpected flow [$FLOW]"
        fi
    fi
fi

LIVE_DIR="$WORKDIR/sflow-live"
PIDFILE="$LIVE_DIR/pidfile"
mkdir -p "$LIVE_DIR"
PORT=$(( 49500 + $$ % 16000 ))

"$SFCAPD_BIN" -4 -p "$PORT" -w "$LIVE_DIR" -D -P "$PIDFILE" -t 2 -v 0 >"$WORKDIR/sfcapd-live.log" 2>&1
i=0
while [ ! -s "$PIDFILE" ] && [ "$i" -lt 3 ]; do
    sleep 1
    i=$((i + 1))
done

if [ ! -s "$PIDFILE" ]; then
    fail "sflow_sigterm: daemon did not start"
else
    kill -TERM "$(cat "$PIDFILE")" 2>/dev/null || true
    i=0
    while [ -f "$PIDFILE" ] && [ "$i" -lt 3 ]; do
        sleep 1
        i=$((i + 1))
    done
    if [ -f "$PIDFILE" ]; then
        fail "sflow_sigterm: daemon did not terminate"
    else
        pass "sflow_sigterm"
    fi
fi

summary
