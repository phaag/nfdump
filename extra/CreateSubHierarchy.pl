#!/usr/bin/perl
#
#
#   Sample script to clean old data.
#   Run this script each hour to cleanup old files to make room for
#   new data. When max_size_spool is reached the oldest files are
#   deleted down to high_water.
#
#   Copyright (c) 2004, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
#   All rights reserved.
#   
#   Redistribution and use in source and binary forms, with or without 
#   modification, are permitted provided that the following conditions are met:
#   
#    * Redistributions of source code must retain the above copyright notice, 
#      this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice, 
#      this list of conditions and the following disclaimer in the documentation 
#      and/or other materials provided with the distribution.
#    * Neither the name of SWITCH nor the names of its contributors may be 
#      used to endorse or promote products derived from this software without 
#      specific prior written permission.
#   
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
#   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
#   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
#   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
#   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
#   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
#   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
#   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
#   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
#   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
#   POSSIBILITY OF SUCH DAMAGE.
#   
#   $Author: peter $
#
#   $Id: CreateSubHierarchy.pl 77 2006-06-14 14:52:25Z peter $
#
#   $LastChangedRevision: 77 $
#
use strict;
use warnings;
use POSIX qw(strftime);
use Time::Local;
use Getopt::Std;

our(    
    $opt_l,     # Data directory
    $opt_S,     # Sub hierarchy format. Correspondes to -S to nfcapd. See nfcapd(1)
);

getopts('l:S:');

my $subdir_format;

my @subdir_formats = (
    "",
    "%Y/%m/%d",
    "%Y/%m/%d/%H",
    "%Y/%W/%u",
    "%Y/%W/%u/%H",
    "%Y/%j",
    "%Y/%j/%H",
    "%F",
    "%F/%H"
);

sub usage {
	print "$0 [options]\n",
		  " -l datadir	Data directory\n",
		  " -S <num>	Sub hierarchy format. Correspondes to -S to nfcapd. See nfcapd(1)\n",
	"\n";
	exit(0);
}

sub ISO2UNIX {
    my $isotime = shift;

    $isotime =~ s/\-//g;    # allow '-' to structur time string

    # 2004 02 13 12 45 /
    my $sec = 0;
    my ( $year, $mon, $mday, $hour, $min ) = $isotime =~ /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})/;
    $mon--;

    # round down to nearest 5 min slot
    my $diff = $min % 5;
	if ( $diff ) {
		$min -= $diff;
	}

	my $unixtime = Time::Local::timelocal($sec,$min,$hour,$mday,$mon,$year);

	return $unixtime;

} # End of ISO2UNIX

if ( !defined $opt_l || !defined $opt_S ) {
	usage();
}

my $data_dir = $opt_l;
if ( !defined $subdir_formats[$opt_S] ) {
	die "Unknown format number $opt_S";
}
$subdir_format = $subdir_formats[$opt_S];

opendir DIR, "$data_dir" || die "Can't open current directory: $!\n";
$| = 1;
print "Reorganizing data files ... ";
while ( my $entry = readdir DIR ) {
	next if $entry =~ /^\./;
	next unless -f "$data_dir/$entry";
	next unless $entry =~ /nfcapd\.(\d{12})$/;
	my $date = $1;
	my $unix_time = ISO2UNIX($date);
	my $sub_path = strftime $subdir_format, localtime($unix_time);
	if ( !-d "$data_dir/$sub_path" ) {
		print "Need to create '$data_dir/$sub_path'\n";
		my @dirlist = split '\/', $sub_path;
		my $all_dirs = undef;
		foreach my $dir ( @dirlist ) {
			$all_dirs = defined $all_dirs ? "$all_dirs/$dir" : $dir;
			if ( !-d "$data_dir/$all_dirs" ) {
				mkdir "$data_dir/$all_dirs" || die "Can't create subdir '$data_dir/$all_dirs'\n";
			}
		}
	}
	rename "$data_dir/$entry", "$data_dir/$sub_path/$entry" || die "Can't move file: $!\n";

}
print "done.\n";
