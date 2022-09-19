
AM_CPPFLAGS = -I.. -I../include -I../lib $(DEPS_CFLAGS)

EXTRA_DIST = collector_inline.c 

noinst_LIBRARIES = libcollector.a

libcollector_a_SOURCES = bookkeeper.c bookkeeper.h collector.c collector.h \
	nfnet.h nfnet.c nfstatfile.c nfstatfile.h metric.c metric.h

if READPCAP
libcollector_a_SOURCES += pcap_reader.c pcap_reader.h
endif

CLEANFILES = *.gch

