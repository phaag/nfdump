
bin_PROGRAMS = nfcapd nfexpire 

AM_CFLAGS = -ggdb 
AM_CPPFLAGS = -Iinclude -Ilib -Iinline -Ioutput -Iconf -Inetflow -Imaxmind -Icollector $(DEPS_CFLAGS)
AM_LDFLAGS  = -Llib 

nfpcapd = netflow_pcapd.c netflow_pcapd.h
expire= expire.c expire.h
launch = launch.c launch.h

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
