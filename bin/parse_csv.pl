#!/usr/bin/perl
#
#  Copyright (c) 2009, Peter Haag
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
#   * The names of its contributors must not be used to endorse or promote 
#     products derived from this software without specific prior written permission.
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
#  $Id: parse_csv.pl 33 2009-09-30 08:30:37Z haag $
#
#  $LastChangedRevision: 33 $
#   

use strict;
use warnings;


my $need_tags 	= 1;
my $in_block 	= 0;
my $in_summary 	= 0;
my $block_no 	= 0;
my $line_no 	= 0;

my @data_blocks;
my %summary;
my @tags;

# 
# The cvs output format consists of one or more output blocks and one summary block.
# Each output block starts with a cvs index line followed by the cvs record lines. 
# The index lines describes the order, how each following record is composed.
#
# Example:
# Index line:   ts,te,td,sa,da,sp,dp,pr,...
# Record line:  2004-07-11 10:30:00,2004-07-11 10:30:10,10.010,172.16.1.66,192.168.170.100,1024,25,TCP,..
#
# All records are in ASCII readable form. Numbers are not scaled, so each line can easly 
# be parsed.
#
# Below you find the list off all indices, defined by nfdump 1.6. The perl script 
# automatically parses a cvs output format and stores the record into a data stucture
# which can be used for further processing. This type of representation is very flexible
# as the leading cvs index line describes the following block. This makes the format also 
# compatible with furture versions of nfdump.
#
# Indices used in nfdump 1.6
# ts,te,td	time records: t-start, t-end, duration
# sa,da		src dst address
# sp,dp		src, dst port
# pr		protocol
# flg		flags
# fwd		forwarding status
# stos		src tos
# ipkt,ibyt	input packets/bytes
# opkt,obyt	output packets, bytes
# in,out	input/output interface SNMP number
# sas,das	src, dst AS
# smk,dmk	src, dst mask
# dtos		dst tos
# dir		direction
# nh,nhb	nethop IP address, bgp next hop IP
# svln,dvln	src, dst vlan id
# ismc,odmc	input src, output dst MAC
# idmc,osmc	input dst, output src MAC
# mpls1,mpls2,mpls3,mpls4,mpls5,mpls6,mpls7,mpls8,mpls9,mpls10 MPLS label 1-10
# cl,sl,al  client server application latency (nprobe)
# ra		router IP
# eng		router engine type/id
# exid		exporter SysID
#
# usage: ./nfdump -r ... -o csv | ./parse_csv.pl
#


# Start parsing the cvs blocks
while (<>) {
	chomp;
	if ( $_ =~ /^$/ ) { # empty line
		$block_no++;
		$line_no	= 0;
		$need_tags 	= 1;
		next;
	}
	if ( $_ =~ /^Summary/ ) {
		$in_summary = 1;
		$need_tags 	= 1;
		$in_block 	= 0;
		next;
	}

	if ( $need_tags ) {
		@tags = split /,/, $_;
		$need_tags = 0;
		$in_block = 1;
		next;
	}

	if ( $in_summary ) {
		my @vals = split /,/, $_;
		@summary{@tags} = @vals;
	} elsif ( $in_block ) {
		my @vals = split /,/, $_;
		my %a;
		@a{@tags} = @vals;
		$data_blocks[$block_no][$line_no++] = \%a;
		next;
	}
}

# Everything parsed
# Insert your code here.
#
# As an example, for post processing print each record.

for (my $i=0; $i<=$block_no; $i++ ) {
	my $lines =	$data_blocks[$i];

	print "Start of output block\n";
	foreach my $line ( @$lines ) {

		print "
Start          : $$line{'ts'}
End            : $$line{'te'}
Duration       : $$line{'td'}
Src Addr       : $$line{'sa'}
Dst Addr       : $$line{'da'}
Src Port       : $$line{'sp'}
Dst Port       : $$line{'dp'}
Protocol       : $$line{'pr'}
Flags          : $$line{'flg'}
FWD Status     : $$line{'fwd'}
Direction      : $$line{'dir'}
Src TOS        : $$line{'stos'}
Dst TOS        : $$line{'dtos'}
Input IF       : $$line{'in'}
Output IF      : $$line{'out'}
Src VLAN       : $$line{'svln'}
Dst VLAN       : $$line{'dvln'}
Next Hop IP    : $$line{'nh'}
BGP Next IP    : $$line{'nhb'}
Src AS         : $$line{'sas'}
Dst AS         : $$line{'das'}
Src Mask       : $$line{'smk'}
Dst Mask       : $$line{'dmk'}
Input Pack     : $$line{'ipkt'}
Output Pack    : $$line{'opkt'}
Input Bytes    : $$line{'ibyt'}
Output Bytes   : $$line{'obyt'}
In Src MAC     : $$line{'ismc'}
Out Dst MAC    : $$line{'odmc'}
In Dst MAC     : $$line{'idmc'}
Out Src MAC    : $$line{'osmc'}
MPLS 1         : $$line{'mpls1'}
MPLS 2         : $$line{'mpls2'}
MPLS 3         : $$line{'mpls3'}
MPLS 4         : $$line{'mpls4'}
MPLS 5         : $$line{'mpls5'}
MPLS 6         : $$line{'mpls6'}
MPLS 7         : $$line{'mpls7'}
MPLS 8         : $$line{'mpls8'}
MPLS 8         : $$line{'mpls8'}
MPLS 10        : $$line{'mpls10'}
Client latency : $$line{'cl'}
Server latency : $$line{'sl'}
Appl.  latency : $$line{'al'}
Router IP      : $$line{'ra'}
Engine type/id : $$line{'eng'}
Exporter SysID : $$line{'exid'}
\n";
	}
	print "\n";
}

#
# Summary lines
print "\nSummary:\n";
print "Number of Flows   : $summary{'flows'}\n";
print "Number of Packets : $summary{'packets'}\n";
print "Number of Bytes   : $summary{'bytes'}\n";
print "Average pps       : $summary{'avg_pps'}\n";
print "Average bps       : $summary{'avg_bps'}\n";
print "Average bpp       : $summary{'avg_bpp'}\n";

# To view the raw records for debugging purpose, uncomment the lines below
# use Data::Dumper;
# print Dumper(@data_blocks);
# print Dumper(%summary);
