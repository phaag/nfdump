
bin_PROGRAMS = nfcapd nfdump nfexpire 

EXTRA_DIST = applybits_inline.c nffile_inline.c nffile_compat.c collector_inline.c 
EXTRA_DIST += inline.c memhandle.c nfdump_inline.c heapsort_inline.c 

AM_CFLAGS = -ggdb 
AM_CPPFLAGS = -Iinclude -Ilib -Ioutput -Iconf -Inetflow -Imaxmind $(DEPS_CFLAGS)
AM_LDFLAGS  = -Llib 

exporter = exporter.c exporter.h
nbar = nbar.c nbar.h
nfprof = nfprof.c nfprof.h
nfnet = nfnet.c nfnet.h
collector = collector.c collector.h
nfpcapd = netflow_pcapd.c netflow_pcapd.h
nfstatfile = nfstatfile.c nfstatfile.h
nflowcache = nflowcache.c nflowcache.h memhandle.h 
bookkeeper = bookkeeper.c bookkeeper.h
expire= expire.c expire.h
metric=metric.c metric.h
launch = launch.c launch.h

nfdump_SOURCES = nfdump.c nfdump.h nfstat.c nfstat.h khash.h blocksort.h blocksort.c  \
	$(exporter) $(nbar) $(nflowcache) $(nfprof)
nfdump_LDADD = lib/libnfdump.la output/liboutput.a conf/libconf.a maxmind/libmaxmind.a

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

nfexpire_SOURCES = nfexpire.c \
	$(bookkeeper) $(expire) $(nfstatfile)
nfexpire_LDADD = lib/libnfdump.la @FTS_OBJ@

check_DIST = inline.c collector_inline.c nffile_inline.c nfdump_inline.c heapsort_inline.c applybits_inline.c 

CLEANFILES = $(check_PROGRAMS) *.gch
