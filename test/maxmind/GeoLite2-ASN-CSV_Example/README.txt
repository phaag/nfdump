These GeoLite2-ASN-Blocks-IPv4.csv / GeoLite2-ASN-Blocks-IPv6.csv files are
hand-crafted test fixtures, NOT official MaxMind data or MaxMind copyrighted
content - MaxMind does not publish an ASN example CSV bundle alongside its
GeoIP2-City-CSV_Example / GeoIP2-Country-CSV_Example downloads.

They follow the real GeoLite2-ASN-Blocks-IPv4.csv/-IPv6.csv column format
("network,autonomous_system_number,autonomous_system_organization") and use
real-world AS number/organization pairings for realism, but the network
prefixes are deliberately chosen to align with networks already present in
../GeoIP2-City-CSV_Example/, so a single test IP can be used to exercise
combined geo + timezone + AS lookups in one assertion. A couple of entries
(AT&T, CenturyLink) deliberately keep an embedded comma inside the quoted
org name, to exercise the CSV parser's handling of quoted fields.

Used by src/test/test_maxmind.sh.
