
bin_PROGRAMS = nfcapd 

AM_CFLAGS = -ggdb 
AM_CPPFLAGS = -I../include -I../libnffile -I../inline -I../netflow -I../collector $(DEPS_CFLAGS)

nfcapd_SOURCES = nfcapd.c 
nfcapd_LDADD = ../netflow/libnetflow.a ../collector/libcollector.a -lnffile  -lm
nfcapd_LDFLAGS = -L../libnffile

if READPCAP
nfcapd_CFLAGS = -DPCAP
nfcapd_LDADD += -lpcap 
endif

check_DIST = inline.c collector_inline.c nffile_inline.c nfdump_inline.c 

CLEANFILES = $(check_PROGRAMS) *.gch
