
bin_PROGRAMS = nfcapd nfdump nfexpire 

EXTRA_DIST = applybits_inline.c nffile_inline.c nffile_compat.c collector_inline.c 
EXTRA_DIST += inline.c memhandle.c nfdump_inline.c heapsort_inline.c 

AM_CFLAGS = -ggdb 
AM_CPPFLAGS = -Iinclude -Ilib -Ioutput -Iconf -Inetflow -Imaxmind -Icollector $(DEPS_CFLAGS)
AM_LDFLAGS  = -Llib 

exporter = exporter.c exporter.h
nbar = nbar.c nbar.h
nfprof = nfprof.c nfprof.h
nfpcapd = netflow_pcapd.c netflow_pcapd.h
nflowcache = nflowcache.c nflowcache.h memhandle.h 
expire= expire.c expire.h
launch = launch.c launch.h

nfdump_SOURCES = nfdump.c nfdump.h nfstat.c nfstat.h khash.h blocksort.h blocksort.c  \
	$(exporter) $(nbar) $(nflowcache) $(nfprof)
nfdump_LDADD = lib/libnfdump.la output/liboutput.a conf/libconf.a maxmind/libmaxmind.a

nfcapd_SOURCES = nfcapd.c \
	$(launch) $(nfpcapd) $(expire)
nfcapd_LDADD = collector/libcollector.a lib/libnfdump.la netflow/libnetflow.a -lm
nfcapd_LDFLAGS = -Llib

if READPCAP
nfcapd_CFLAGS = -DPCAP
nfcapd_LDADD += -lpcap 
endif

nfexpire_SOURCES = nfexpire.c \
	$(expire) 
nfexpire_LDADD = lib/libnfdump.la collector/libcollector.a @FTS_OBJ@

check_DIST = inline.c collector_inline.c nffile_inline.c nfdump_inline.c heapsort_inline.c applybits_inline.c 

CLEANFILES = $(check_PROGRAMS) *.gch
