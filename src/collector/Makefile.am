
AM_CPPFLAGS = -I.. -I../include -I../lib -I../inline -I../conf $(DEPS_CFLAGS)

EXTRA_DIST = collector_inline.c 

noinst_LIBRARIES = libcollector.a

libcollector_a_SOURCES = bookkeeper.c bookkeeper.h launch.h launch.c \
	collector.c collector.h nfnet.h nfnet.c nfstatfile.c nfstatfile.h \
	expire.c expire.h metric.c metric.h

if READPCAP
libcollector_a_SOURCES += pcap_reader.c pcap_reader.h
endif

CLEANFILES = *.gch

