
bin_PROGRAMS = nfcapd 

AM_CFLAGS = -ggdb 
AM_CPPFLAGS = -I../include -I../lib -I../inline -I../netflow -I../collector $(DEPS_CFLAGS)
AM_LDFLAGS  = -Llib 

nfpcapd = netflow_pcapd.c

nfcapd_SOURCES = nfcapd.c \
	$(nfpcapd) 
nfcapd_LDADD = ../lib/libnfdump.la ../collector/libcollector.a  ../netflow/libnetflow.a -lm
nfcapd_LDFLAGS = -L../lib

if READPCAP
nfcapd_CFLAGS = -DPCAP
nfcapd_LDADD += -lpcap 
endif

check_DIST = inline.c collector_inline.c nffile_inline.c nfdump_inline.c heapsort_inline.c applybits_inline.c 

CLEANFILES = $(check_PROGRAMS) *.gch
