#!/bin/sh
#  This file is part of the nfdump project.
#
#  Copyright (c) 2023, Peter Haag
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

set -e
TZ=Europe/Zurich
export TZ

# prevent any default goelookup for testing
NFDUMP="../nfdump/nfdump -G none"
NFCAPD="../nfcapd/nfcapd"
NFREPLAY="../nfreplay/nfreplay"

$NFDUMP -r dummy_flows.nf -q -o raw >test.1.out
diff -u test.1.out nftest.1.out

# read/write compressed flow test
$NFDUMP -r dummy_flows.nf -q -z=lzo -w test.2.flows.nf
$NFDUMP -v test.2.flows.nf >/dev/null

$NFDUMP -r test.2.flows.nf -q -o raw >test.2.out
diff -u test.2.out nftest.1.out

# test tstart sort order
$NFDUMP -r test.2.flows.nf -q -O tstart -o raw >test.3.out
diff -u test.3.out nftest.2.out

# test write descending sorted flow table
$NFDUMP -r dummy_flows.nf -O tstart -z=lzo -w test.4.flows.nf
$NFDUMP -v test.4.flows.nf >/dev/null
$NFDUMP -q -r test.4.flows.nf -o raw >test.4.out
diff -u test.4.out nftest.4.out

# test write ascending sorted flow table
$NFDUMP -r dummy_flows.nf -q -O bytes -o raw >test.5.out
$NFDUMP -r dummy_flows.nf -O bytes -z=lz4 -w test.5.flows.nf
$NFDUMP -v test.5.flows.nf >/dev/null
$NFDUMP -r test.5.flows.nf -q -o raw >test.5-2.out
diff -u test.5.out test.5-2.out

# create testdir dir for flow replay
if [ -d testdir ]; then
	rm -f testdir/*
	rmdir testdir
fi
mkdir testdir

# Test flow collection
# Start nfcapd on localhost and replay flows
echo
echo -n Starting nfcapd ...
$NFCAPD -p 65530 -w testdir -D -P testdir/pidfile -I TestIdent -z=lz4
sleep 1
echo done.
echo -n Replay flows ...
$NFREPLAY -r dummy_flows.nf -v9 -H 127.0.0.1 -p 65530
echo done.
sleep 1

echo -n Terminate nfcapd ...
kill -TERM $(cat testdir/pidfile)
sleep 1
echo done.

if [ -f testdir/pidfile ]; then
	echo nfcapd does not terminate
	exit
fi

$NFDUMP -r dummy_flows.nf -q -o extended -6 'packets > 0' >test.6-1.out
$NFDUMP -r testdir/nfcapd.* -q -o extended -6 >test.6-2.out

diff test.6-1.out test.6-2.out

# Test propper AppendRename
# Start nfcapd on localhost and replay flows
rm -f testdir/nfcapd.*
echo
echo -n Starting nfcapd ...
$NFCAPD -p 65530 -w testdir -D -P testdir/pidfile -I TestIdent -t 3600 -z=lz4
sleep 1
echo done.
echo -n Replay flows ...
$NFREPLAY -r dummy_flows.nf -v9 -H 127.0.0.1 -p 65530
echo done.
sleep 1

echo -n Terminate nfcapd ...
kill -TERM $(cat testdir/pidfile)
sleep 1
echo done.

echo -n Starting nfcapd ...
$NFCAPD -p 65530 -w testdir -D -P testdir/pidfile -I TestIdent -t 3600 -z=lz4
sleep 1
echo done.
echo -n Replay flows ...
$NFREPLAY -r dummy_flows.nf -v9 -H 127.0.0.1 -p 65530
echo done.
sleep 1

echo -n Terminate nfcapd ...
kill -TERM $(cat testdir/pidfile)
sleep 1
echo done.

if [ -f testdir/pidfile ]; then
	echo nfcapd does not terminate
	exit
fi

$NFDUMP -X -v testdir/nfcapd.* >/dev/null

mkdir memck.$$
# OpenBSD
export MALLOC_OPTIONS=AFGJS
# MacOSX
export MallocGuardEdges=1
export MallocStackLogging=1
export MallocStackLoggingDirectory=memck.$$
export MallocScribble=1
export MallocErrorAbort=1
export MallocCorruptionAbort=1
$NFDUMP -r dummy_flows.nf 'host 172.16.2.66'
$NFDUMP -r dummy_flows.nf -s ip 'host 172.16.2.66'
$NFDUMP -r dummy_flows.nf -s record 'host 172.16.2.66'
$NFDUMP -r dummy_flows.nf -w test.7.flows.nf 'host 172.16.2.66'
$NFDUMP -r dummy_flows.nf -O tstart -w test.8.flows.nf 'host 172.16.2.66'
../nfanon/nfanon -K abcdefghijklmnopqrstuvwxyz012345 -r dummy_flows.nf -w test.9.flows.nf
$NFDUMP -q -r test.9.flows.nf -o raw >test.9.out
$NFDUMP -r testdir/nfcapd.* -i NewIdent
rm -f testdir/nfcapd.* test*.out test*.flows.nf dummy_flows.nf
[ -d testdir ] && rmdir testdir
[ -d memck.$$ ] && rm -rf memck.$$

echo All tests successful. || rm -rf memck.$$
