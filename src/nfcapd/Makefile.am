
bin_PROGRAMS = nfcapd 

AM_CFLAGS = -ggdb 
AM_CPPFLAGS = -I../include -I../lib -I../inline -I../netflow -I../collector -I../conf $(DEPS_CFLAGS)
AM_LDFLAGS  = -Llib 

nfpcapd = netflow_pcapd.c

nfcapd_SOURCES = nfcapd.c \
	$(nfpcapd) 
nfcapd_LDADD = ../netflow/libnetflow.a ../lib/libnfdump.la ../collector/libcollector.a
nfcapd_LDADD += ../conf/libconf.a -lm
nfcapd_LDFLAGS = -L../lib

if READPCAP
nfcapd_CFLAGS = -DPCAP
nfcapd_LDADD += -lpcap 
endif

check_DIST = inline.c collector_inline.c nffile_inline.c nfdump_inline.c heapsort_inline.c applybits_inline.c 

CLEANFILES = $(check_PROGRAMS) *.gch
