#!/bin/sh
#  This file is part of the nfdump project.
#
#  Copyright (c) 2004, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
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
#  $Author: haag $
#
#  $Id: test.sh 56 2010-02-08 13:37:55Z haag $
#
#  $LastChangedRevision: 56 $
#  
# 

set -e
TZ=MET
export TZ

# Check for correct output
./nfgen | ./nfdump -q -o raw  > test1.out
diff -u test1.out nfdump.test.out

# compressed flow test
./nfgen | ./nfdump -z -q -w  test.flows
./nfdump -q -r test.flows -o raw > test2.out
diff -u test2.out nfdump.test.out

./nfdump -q -r test.flows -O tstart -o raw > test3.out
diff -u test3.out nfdump.test.out

./nfdump -r test.flows -O tstart -z -w test2.flows
./nfdump -q -r test2.flows -o raw > test4.out
diff -u test4.out nfdump.test.out

# uncompressed flow test
rm -f test.flows test2.out
./nfgen | ./nfdump -q -w  test.flows
./nfdump -q -r test.flows -o raw > test2.out
diff -u test2.out nfdump.test.out

rm -r test1.out test2.out

# create tmp dir for flow replay
if [ -d tmp ]; then
	rm -f tmp/*
	rmdir tmp
fi
mkdir tmp

# Start nfcapd on localhost and replay flows
echo
echo -n Starting nfcapd ...
./nfcapd -p 65530 -T '*' -l tmp -D -P tmp/pidfile
sleep 1
echo done.
echo -n Replay flows ...
./nfreplay -r test.flows -v9 -H 127.0.0.1 -p 65530
echo done.
sleep 1 

echo -n Terminate nfcapd ...
kill -TERM `cat tmp/pidfile`;
sleep 1
echo done.

if [ -f tmp/pidfile ]; then
	echo nfcapd does not terminate
	exit
fi

# supress 'received at' as this is always different
./nfdump -r tmp/nfcapd.* -q -o raw | grep -v 'received at' > test5.out
# nfdump 1.6.5 always uses 64 bits. therefore we have a predictable diff
# so diff the diff
diff test5.out nfdump.test.out > test5.diff || true
diff test5.diff nfdump.test.diff

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
./nfdump -r test.flows 'host  172.16.14.18'
./nfdump -r test.flows -s ip 'host  172.16.14.18'
./nfdump -r test.flows -s record 'host  172.16.14.18'
./nfdump -r test.flows -w test-2.flows 'host  172.16.14.18'
./nfdump -r test.flows -O tstart -w test-2.flows 'host  172.16.14.18'
./nfanon -K abcdefghijklmnopqrstuvwxyz012345 -r test.flows -w anon.flows
rm -f tmp/nfcapd.* test*.out test*.flows
[ -d tmp ] && rmdir tmp
[ -d memck.$$ ] && rm -rf  memck.$$


echo All tests successful. || rm -rf memck.$$
