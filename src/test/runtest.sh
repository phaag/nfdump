#!/bin/sh
#  This file is part of the nfdump project.
#
#  Copyright (c) 2009-2020, Peter Haag
#  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
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
#   * Neither the name of SWITCH nor the names of its contributors may be 
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
TZ=MET
export TZ

# Check for correct output
rm -f test.*
./nfgen 

# verify test
../nfdump -v test.flows.nf

# read test
rm -f test1.out
../nfdump -r test.flows.nf -q -o raw  > test.1.out
diff -u test.1.out nftest.1.out

# compression tests
../nfdump -J 0 -r test.flows.nf && ../nfdump -v test.flows.nf > /dev/null
../nfdump -J 1 -r test.flows.nf && ../nfdump -v test.flows.nf > /dev/null
../nfdump -J 2 -r test.flows.nf && ../nfdump -v test.flows.nf > /dev/null
../nfdump -J 3 -r test.flows.nf && ../nfdump -v test.flows.nf > /dev/null
../nfdump -J 2 -r test.flows.nf && ../nfdump -v test.flows.nf > /dev/null
../nfdump -J 1 -r test.flows.nf && ../nfdump -v test.flows.nf > /dev/null
../nfdump -J 0 -r test.flows.nf && ../nfdump -v test.flows.nf > /dev/null

rm -f test.1.out
../nfdump -r test.flows.nf -q -o raw  > test.1.out
diff -u test.1.out nftest.1.out

# read/write compressed flow test
../nfdump -r test.flows.nf -q -z -w  test.2.flows.nf
../nfdump -v test.2.flows.nf > /dev/null

../nfdump -r test.2.flows.nf -q -o raw > test.2.out
diff -u test.2.out nftest.1.out

# test tstart sort order
../nfdump -r test.2.flows.nf -q -O tstart -o raw > test.3.out
diff -u test.3.out nftest.2.out

# test write descending sorted flow table
../nfdump -r test.flows.nf -O tstart -z -w test.4.flows.nf
../nfdump -v test.4.flows.nf > /dev/null
../nfdump -q -r test.4.flows.nf -o raw > test.4.out
diff -u test.4.out nftest.1.out

# test write ascending sorted flow table
../nfdump -r test.flows.nf -q -O bytes -o raw > test.5.out
../nfdump -r test.flows.nf -O bytes -z -w test.5.flows.nf
../nfdump -v test.5.flows.nf > /dev/null
../nfdump -r test.5.flows.nf -q -o raw | grep -v RecordCount > test.5-2.out
diff -u test.5.out test.5-2.out

# create testdir dir for flow replay
if [ -d testdir ]; then
	rm -f testdir/*
	rmdir testdir
fi
mkdir testdir

# Start nfcapd on localhost and replay flows
echo
echo -n Starting nfcapd ...
../nfcapd -p 65530 -l testdir -D -P testdir/pidfile
sleep 1
echo done.
echo -n Replay flows ...
../nfreplay -r test.flows.nf -v9 -H 127.0.0.1 -p 65530
echo done.
sleep 1 

echo -n Terminate nfcapd ...
kill -TERM `cat testdir/pidfile`;
sleep 1
echo done.

if [ -f testdir/pidfile ]; then
	echo nfcapd does not terminate
	exit
fi

../nfdump -r test.flows.nf -q -o extended -6 'packets > 0' > test.6-1.out
../nfdump -r testdir/nfcapd.* -q -o extended -6 > test.6-2.out

diff test.6-1.out test.6-2.out

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
../nfdump -r test.flows.nf 'host 172.16.2.66'
../nfdump -r test.flows.nf -s ip 'host 172.16.2.66'
../nfdump -r test.flows.nf -s record 'host 172.16.2.66'
../nfdump -r test.flows.nf -w test.7.flows.nf 'host 172.16.2.66'
../nfdump -r test.flows.nf -O tstart -w test.8.flows.nf 'host 172.16.2.66'
../nfanon -K abcdefghijklmnopqrstuvwxyz012345 -r test.flows.nf -w test.9.flows.nf
../nfdump -q -r test.9.flows.nf -o raw > test.9.out
rm -f testdir/nfcapd.* test*.out test*.flows.nf
[ -d testdir ] && rmdir testdir
[ -d memck.$$ ] && rm -rf  memck.$$

echo All tests successful. || rm -rf memck.$$
