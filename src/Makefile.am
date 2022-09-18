
bin_PROGRAMS = nfcapd nfdump nfreplay nfexpire nfanon
check_PROGRAMS = nfreader

EXTRA_DIST = applybits_inline.c nffile_inline.c nffile_compat.c collector_inline.c 
EXTRA_DIST += inline.c memhandle.c nfdump_inline.c heapsort_inline.c 

if MAXMIND
bin_PROGRAMS += geolookup
endif

AM_CFLAGS = -ggdb 
AM_CPPFLAGS = -Ilib -Ioutput -Iconf -Inetflow $(DEPS_CFLAGS)
AM_LDFLAGS  = -Llib 


exporter = exporter.c exporter.h
nbar = nbar.c nbar.h

nfprof = nfprof.c nfprof.h
nfnet = nfnet.c nfnet.h
anon = panonymizer.c panonymizer.h rijndael.c rijndael.h
collector = collector.c collector.h
nfpcapd = netflow_pcapd.c netflow_pcapd.h
nfstatfile = nfstatfile.c nfstatfile.h
nflowcache = nflowcache.c nflowcache.h memhandle.h 
bookkeeper = bookkeeper.c bookkeeper.h
expire= expire.c expire.h
metric=metric.c metric.h
launch = launch.c launch.h
maxmind = maxmind.c maxmind.h

nfdump_SOURCES = nfdump.c nfdump.h nfstat.c nfstat.h khash.h blocksort.h blocksort.c  \
	$(exporter) $(nbar) $(maxmind) $(nflowcache) $(nfprof)
nfdump_LDADD = lib/libnfdump.la output/liboutput.a conf/libconf.a

nfreplay_SOURCES = nfreplay.c $(nfprof) \
	$(nfnet) $(collector) $(metric)
nfreplay_LDADD = lib/libnfdump.la netflow/libnetflow.a -lm

nfcapd_SOURCES = nfcapd.c \
	$(nfstatfile) $(launch) \
	$(nfnet) $(collector) $(nfpcapd) $(bookkeeper) $(expire) $(metric)
nfcapd_LDADD = lib/libnfdump.la netflow/libnetflow.a -lm
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
