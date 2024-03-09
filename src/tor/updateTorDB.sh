#!/bin/sh

# Script to update nfdump toDB.

# Where to put local download data
TMPDIR="/tmp/tor_raw_data.$$"

# Use the nfdump tor DB environment variable NFTORDB if set
# or put the default name it in current directory
NFTORDB=${NFTORDB:="./tordb.nf"}

# Fetch all tor files from the last n months.
# Days do not matter only full months are taken.
# The current month counts also as full month
# This default value may be overwritten on the command line
NUM_MONTHS=6

# Tor exit node URL
EXIT_URL="https://collector.torproject.org/archive/exit-lists"

# Usage info
usage () {
  echo "Usage : $1 [num]"
  echo 'Fetch tor exit node list from last [num] months and create the nfdump tor lookup DB.'
  echo '[num] is optional and defaults to 6 months'
  exit
}

# Fetch the tor files
fetch_files() {
    n=$(($1 -1 ))
    current_year=$(date +"%Y")
    current_month=$(date +"%m")
    for i in $(seq $n 0); do
        month=$(($current_month - $i))
        year=$current_year
        if [ $month -le 0 ]; then
            month=$(($month + 12))
            year=$(($current_year - 1))
        fi
        if [ $month -lt 10 ]; then
			month="0${month}"
		fi
		/bin/echo -n "Fetch exit-list-$year-$month.tar.xz: .. "
		wget -q "${EXIT_URL}/exit-list-$year-$month.tar.xz"
		if [ $? -eq 0 -a -f exit-list-$year-$month.tar.xz ]; then
			tar Jxf exit-list-$year-$month.tar.xz
			rm exit-list-$year-$month.tar.xz
			/bin/echo OK.
		else
			/bin/echo failed.
		fi
    done
}

## 
# Main starts here
##

if [ $# -gt 1 ]; then
    usage $0
fi

# Only accept numbers
if [ $# -eq 1 ]; then
	case $1 in
    	''|*[!0-9]*)
			echo "Argument not a positive number"
			usage $0
			;;
    	*) 
			NUM_MONTHS=$1
			;;
	esac
fi

if [ $NUM_MONTHS -le 0 -o $NUM_MONTHS -gt 24 ]; then
	echo "Number of months: $NUM_MONTHS out of 1..24"
	exit
fi

echo "Get tor node exit list for the last $NUM_MONTHS months"

# tmp data dir
cur=`pwd`
test -d $TMPDIR && rm -rf $TMPDIR
mkdir $TMPDIR

cd $TMPDIR
fetch_files $NUM_MONTHS
cd $cur

echo Building nfdump tordb: $NFTORDB
#torlookup -d $TMPDIR -w $NFTORDB && rm -rf $TMPDIR
torlookup -d $TMPDIR -w $NFTORDB
echo Done.
