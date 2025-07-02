
AM_CPPFLAGS = -I.. -I../include -I../libnffile -I../inline $(DEPS_CFLAGS) -D_BSD_SOURCE -D_DEFAULT_SOURCE

EXTRA_DIST = collector_inline.c 

noinst_LIBRARIES = libcollector.a

libcollector_a_SOURCES = privsep.c privsep.h repeater.c repeater.h \
	launch.h launch.c bookkeeper.c bookkeeper.h \
	collector.c collector.h nfnet.h nfnet.c nfstatfile.c nfstatfile.h \
	yaf_reader.c yaf_reader.h expire.c expire.h metric.c metric.h

if READPCAP
libcollector_a_SOURCES += pcap_reader.c pcap_reader.h
endif

CLEANFILES = *.gch

