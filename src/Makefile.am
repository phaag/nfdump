
bin_PROGRAMS = nfcapd nfdump nfreplay nfexpire nfanon
check_PROGRAMS = nfreader

EXTRA_DIST = applybits_inline.c nffile_inline.c nffile_compat.c collector_inline.c 
EXTRA_DIST += inline.c memhandle.c nfdump_inline.c heapsort_inline.c 

if MAXMIND
bin_PROGRAMS += geolookup
endif

AM_CPPFLAGS = -Ilib $(DEPS_CFLAGS)
AM_LDFLAGS  = -Llib

LDADD = $(DEPS_LIBS)


#Add extra debug info for gdb
AM_CFLAGS = -ggdb 

exporter = exporter.c exporter.h
nbar = nbar.c nbar.h

output =  output_raw.h output_raw.c 
output += output_json.c output_json.h output_csv.c output_csv.h output_pipe.c output_pipe.h
output += output_fmt.c output_fmt.h content_dns.c content_dns.h ja3.h ja3.c md5.h md5.c

nfprof = nfprof.c nfprof.h
nfnet = nfnet.c nfnet.h
anon = panonymizer.c panonymizer.h rijndael.c rijndael.h
collector = collector.c collector.h
nfv1 = netflow_v1.c netflow_v1.h
nfv5v7 = netflow_v5_v7.c netflow_v5_v7.h
nfv9 = netflow_v9.c netflow_v9.h fnf.h
nfpcapd = netflow_pcapd.c netflow_pcapd.h
ipfix = ipfix.c ipfix.h fnf.h
nfstatfile = nfstatfile.c nfstatfile.h
nflowcache = nflowcache.c nflowcache.h memhandle.h 
bookkeeper = bookkeeper.c bookkeeper.h
expire= expire.c expire.h
launch = launch.c launch.h
maxmind = maxmind.c maxmind.h

nfdump_SOURCES = nfdump.c nfdump.h nfstat.c nfstat.h khash.h blocksort.h blocksort.c  \
	$(exporter) $(output) $(nbar) $(maxmind) $(nflowcache) $(nfprof)
nfdump_LDADD = lib/libnfdump.la

nfreplay_SOURCES = nfreplay.c $(nfprof) \
	$(nfnet) $(collector) $(nfv1) $(nfv9) $(nfv5v7) $(ipfix)
nfreplay_LDADD = lib/libnfdump.la

nfcapd_SOURCES = nfcapd.c \
	$(nfstatfile) $(launch) \
	$(nfnet) $(collector) $(nfv1) $(nfv5v7) $(nfv9) $(ipfix) $(nfpcapd) $(bookkeeper) $(expire)
nfcapd_LDADD = lib/libnfdump.la
nfcapd_LDFLAGS = -Llib

if READPCAP
nfcapd_CFLAGS = -DPCAP
nfcapd_SOURCES += pcap_reader.c pcap_reader.h
nfcapd_LDADD += -lpcap 
endif


nfreader_SOURCES = nfreader.c 
nfreader_LDADD = lib/libnfdump.la

nfanon_SOURCES = nfanon.c $(anon)
nfanon_LDADD = lib/libnfdump.la

nfexpire_SOURCES = nfexpire.c \
	$(bookkeeper) $(expire) $(nfstatfile)
nfexpire_LDADD = lib/libnfdump.la @FTS_OBJ@

if MAXMIND
geolookup_SOURCES = geolookup.c $(maxmind)
geolookup_LDADD = lib/libnfdump.la 
endif

check_DIST = inline.c collector_inline.c nffile_inline.c nfdump_inline.c heapsort_inline.c applybits_inline.c 
check_DIST += parse_csv.pl AddExtension.txt
CLEANFILES = $(check_PROGRAMS) *.gch
