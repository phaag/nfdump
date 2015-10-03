#!/usr/bin/perl
#
#  Copyright (c) 2004, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#
#   * Redistributions of source code must retain the above copyright notice,
#	 this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright notice,
#	 this list of conditions and the following disclaimer in the documentation
#	 and/or other materials provided with the distribution.
#   * Neither the name of SWITCH nor the names of its contributors may be
#	 used to endorse or promote products derived from this software without
#	 specific prior written permission.
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
#  $Id: PortTracker.pm 67 2010-09-09 05:56:05Z haag $
#
#  $LastChangedRevision: 67 $

# Demo plugin for NfSen
#
# This plugin demonstrates the use of plugins

package PortTracker;

use strict;
use NfSen;
use NfConf;

#
# The plugin may send any messages to syslog
# Do not initialize syslog, as this is done by 
# the main process nfsen-run
use Sys::Syslog;
  
our $VERSION = 130;

our %cmd_lookup = (
	'get-portgraph'	=> \&GetPortGraph,
	'get-topN'	 	=> \&GetTopN,
);

my ( $nftrack, $PROFILEDATADIR );

my $PORTSDBDIR = "/data/ports-db";

my $EODATA  = ".\n";

# colours used in graphs
# if more than 12 graphs are drawn ( does this really make sense ? ) 
# the same colours are used again
my @colour = ( 
	'#ff0000', '#ff8000', '#ffff00', '#80ff00', '#00ff00',
	'#00ff80', '#00ffff', '#0080ff', '#0000ff', '#8000ff',
	'#ff00ff', '#ff0080'
);


sub GetTopN {
    my $socket  = shift;
    my $opts    = shift;

	my $interval;
	if ( !exists $$opts{'interval'} ) {
		$interval = 1;
	} else {
		$interval = $$opts{'interval'};
	}
	print $socket ".Get topN ports\n";

	my $statfile = $interval == 24 ? 'portstat24.txt' : 'portstat.txt';
	print $socket ".topN ports $PORTSDBDIR/$statfile\n";
	if ( !open STAT, "$PORTSDBDIR/$statfile" ) {
		print $socket $EODATA;
		print $socket "ERR Open statfile '$PORTSDBDIR/$statfile': $!\n";
		return;
	}

	print $socket ".topN read ports\n";
	while ( <STAT> ) {
		chomp;
		print $socket "_topN=$_\n";
	}
	print $socket $EODATA;
	print $socket "OK Command completed\n",
		
} # End of GetPortGraph

sub GetPortGraph {
    my $socket  = shift;
    my $opts    = shift;

	# get all arguments:
	# Example:
	# proto typw  logscale light tstart     tend       topN              track_list
	# tcp   flows 0        0     1116495000 1116581400 '22 445 135 1433' '80 143'
	if ( !exists $$opts{'arg'} ) {
		print $socket $EODATA;
		print $socket "ERR Missing Arguments.\n";
	}
	my $ARGS = $$opts{'arg'};
	my $proto 		= shift @$ARGS;	# 'tcp' or 'udp'
	my $type  		= shift @$ARGS;	# 'flows', 'packets' or 'bytes'
	my $logscale	= shift @$ARGS;	# 0 or 1
	my $stacked		= shift @$ARGS;	# 0 or 1
	my $light 		= shift @$ARGS;	# 0 or 1
	my $tstart		= shift @$ARGS;	# start time - UNIX format
	my $tend		= shift @$ARGS;	# end time - UNIX format
	my $topN		= shift @$ARGS;	# TopN port list: string: ' ' separated port list
	my $track_list	= shift @$ARGS;	# Static track port list: string: ' ' separated port list
	my $skip_list	= shift @$ARGS;	# Static skip port list: string: ' ' separated port list

	if ( !defined $proto || !defined $type || !defined $logscale || !defined $stacked ||
		 !defined $light || !defined $tstart || !defined $tend || !defined $topN || 
		 !defined $track_list || !defined $skip_list ) {
		print $socket $EODATA;
		print $socket "ERR Argument Error.\n";
		return;
	}
	my @skipPorts = split '-', $skip_list;

	my @topN = split '-', $topN;
	my @track_list = split '-', $track_list;

	# remove the common ports in both lists from the dynamic topN list
	my %_tmp;
	@_tmp{@track_list} = @track_list;
	delete @_tmp{@topN};
	@track_list = sort keys %_tmp;

	# %_tmp = ();
	# @_tmp{@topN} = @topN;
	# delete @_tmp{@skipPorts};
	# @topN = keys %_tmp;

	%_tmp = ();
	my @_tmp;
	@_tmp{@skipPorts} = @skipPorts;
	foreach my $port ( @topN ) {
		push @_tmp, $port unless exists $_tmp{$port};
	}
	@topN = @_tmp;

	my $datestr = scalar localtime($tstart) . " - " . scalar localtime($tend);
	my $title   = uc($proto) . " " . ucfirst($type);

	my @DEFS = ();

	# Compile rrd args
	my @rrdargs = ();
	push @rrdargs, "-";	# output graphics to stdout
	
	foreach my $port ( @topN, @track_list ) {
		# assemble filename
		my $fileident = $port >> 10;
		my $rrdfile	= "$PORTSDBDIR/${proto}-${type}-$fileident.rrd";
		# which ident in this rrd file
		my $ident	=  $port & 1023;	# 0x0000001111111111 mask
		push @rrdargs, "DEF:Port${port}=$rrdfile:p${ident}:AVERAGE";
	}

	push @rrdargs, "--start",  "$tstart";
	push @rrdargs, "--end",    "$tend";
	push @rrdargs, "--title",  "$datestr - $title" unless $light;
	push @rrdargs, "--vertical-label", "$title"  unless $light;
	
	# lin or log graph?
	push @rrdargs, "--logarithmic" if $logscale;

	if ( $light ) {
		push @rrdargs, "-w";
		push @rrdargs, "288";
		push @rrdargs, "-h";
		push @rrdargs, "150";
		push @rrdargs, "--no-legend";	# no legend in small pictures
	} else {
		push @rrdargs, "-w";
		push @rrdargs, "576";
		push @rrdargs, "-h";
		push @rrdargs, "300";
	}


	my $i=0;
	my $area_set = 0;
	my $n = scalar @topN;
	push @rrdargs, "COMMENT:Top $n Ports\\n";
	if ( $stacked && scalar @topN ) {
		my $port = shift @topN;
		push @rrdargs, "AREA:Port${port}$colour[$i]:Port ${port}";
		$i++;
		$area_set = 1;
		foreach my $port ( @topN ) {
	 		push @rrdargs, "STACK:Port${port}$colour[$i]:Port ${port}";
	 		$i++;
		}

	} else {
		foreach my $port ( @topN ) {
			push @rrdargs, "LINE1:Port${port}$colour[$i]:Port ${port}";
			$i++;
		}
	}
	
	if ( scalar @track_list) {
		push @rrdargs, "COMMENT:\\n";
		push @rrdargs, "COMMENT:\\n";
		push @rrdargs, "COMMENT:Tracked Ports\\n";
	}
	if ( $stacked && scalar @track_list) {
		if ( !$area_set ) {
			my $port = shift @track_list;
			push @rrdargs, "AREA:Port${port}$colour[$i]:Port ${port}";
			$i++;
		}
		foreach my $port ( @track_list ) {
			push @rrdargs, "STACK:Port${port}$colour[$i]:Port ${port}";
			$i++;
		}
		
	} else {
		foreach my $port ( @track_list ) {
			push @rrdargs, "LINE2:Port${port}$colour[$i]:Port ${port}";
			$i++;
		}
	}
	if ( scalar @skipPorts) {
		push @rrdargs, "COMMENT:\\n";
		push @rrdargs, "COMMENT:\\n";
		my $portlist = join ',', @skipPorts;
		push @rrdargs, "COMMENT:Skipped Ports $portlist\\n";
	}
	my ($averages,$xsize,$ysize) = RRDs::graph( @rrdargs );
		
	if (my $ERROR = RRDs::error) {
		print "ERROR: $ERROR\n";
	} 

} # End of GenPortGraph


sub nftrack_execute {
	my $command = shift;

	syslog('debug', $command);

	my $ret = system($command);
	if ( $ret == - 1 ) {
		syslog('err', "Failed to execute nftrack: $!\n");
	} elsif ($ret & 127) {
		syslog('err', "nftrack died with signal %d, %s coredump\n", ($ret & 127),  ($ret & 128) ? 'with' : 'without');
	} else {
		syslog('debug', "nftrack exited with value %d\n", $ret >> 8);
	}

} # End of nftrack_execute

#
# Periodic function
#   input:  hash reference including the items:
#           'profile'       profile name
#           'profilegroup'  profile group
#           'timeslot'      time of slot to process: Format yyyymmddHHMM e.g. 200503031200
sub run {
    my $argref       = shift;

    my $profile      = $$argref{'profile'};
    my $profilegroup = $$argref{'profilegroup'};
    my $timeslot     = $$argref{'timeslot'};

	syslog('debug', "PortTracker run: Profile: $profile, Time: $timeslot");

	my %profileinfo	 = NfProfile::ReadProfile($profile);
	my $netflow_sources = "$PROFILEDATADIR/$profile/$profileinfo{'sourcelist'}";

	# 
	# process all sources of this profile at once
	my $command = "$nftrack -M $netflow_sources -r nfcapd.$timeslot -d $PORTSDBDIR -A -t $timeslot -s -p -w $PORTSDBDIR/portstat.txt";
	nftrack_execute($command);

	$command = "$nftrack -d $PORTSDBDIR -S -p -w $PORTSDBDIR/portstat24.txt";
	nftrack_execute($command);

	#
	# Process the output and notify the duty team

	syslog('debug', "PortTracker run: Done.");

} # End of run

sub Init {
	syslog("info", "PortTracker: Init");

	# Init some vars
	$nftrack  = "$NfConf::PREFIX/nftrack";
	$PROFILEDATADIR = "$NfConf::PROFILEDATADIR";

	return 1;
}

sub Cleanup {
	syslog("info", "PortTracker Cleanup");
	# not used here
}

1;
