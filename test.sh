#!/bin/sh

NFDUMP=nfdump

rm -f out1
$NFDUMP -Gnone -q -r ../flow-archive/single.nf -o line > out1
$NFDUMP -Gnone -q -r ../flow-archive/single.nf -o long >> out1
$NFDUMP -Gnone -q -r ../flow-archive/single.nf -o extended >> out1
$NFDUMP -Gnone -q -r ../flow-archive/bidir.nf -o biline >> out1
$NFDUMP -Gnone -q -r ../flow-archive/bidir.nf -o bilong >> out1
$NFDUMP -Gnone -q -r ../flow-archive/bidir.nf -o raw >> out1

diff -ru test1.txt out1
