#!/bin/sh
#

# Get your license key from maxmind.com
# - Signup for a free account
# - This account gives you access to the GeoLite2 files
# - On the web page, in your account, create the license key
LICENSE=YOURLICENSEKEY

# language: the location information is avalable in many languages
# available languages:
# check the files in the GeoLite2-City-CSV folder:
# GeoLite2-City-Locations-xx.csv with xx language:  de, fr, ru, en, ja, zh-CN, es, pt-BR.
LANG=en

# cleanup old directories
rm -rf GeoLite2-ASN-CSV_* GeoLite2-City-CSV_*

# get the permalink from the maxmind download page
# If you have a maxmind paid account, replace the URLs below
wget -O GeoLite2-ASN-CSV.zip "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN-CSV&license_key=${LICENSE}&suffix=zip"
if [ $? -ne 0 ]; then
  echo "### Maxmind DB download error ###"
  echo "DB Download failed. Check your license keys or download URLs."
  exit
fi

wget -O GeoLite2-City-CSV.zip "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City-CSV&license_key=${LICENSE}&suffix=zip"
if [ $? -ne 0 ]; then
  echo "### Maxmind DB download error ###"
  echo "DB Download failed. Check your license keys or download URLs."
  exit
fi

unzip GeoLite2-ASN-CSV.zip
unzip GeoLite2-City-CSV.zip

# use IPv4 and IPv6 mmdb files to read and convert into nfdump format.
set -x
mkdir mmdb
mv GeoLite2-ASN-CSV*/GeoLite2-ASN-Blocks-IPv[46].csv mmdb
mv GeoLite2-City-CSV*/GeoLite2-City-Blocks-IPv[46].csv mmdb
mv GeoLite2-City-CSV*/GeoLite2-City-Locations-${LANG}.csv mmdb

# create nfdump format db file
./geolookup -d mmdb -w mmdb.nf
rm -rf GeoLite2-ASN-CSV_* GeoLite2-City-CSV_* mmdb

# test lookup
./geolookup -G mmdb.nf 8.8.8.8
