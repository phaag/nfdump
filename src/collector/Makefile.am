
AM_CPPFLAGS = -I.. -I../include -I../libnffile -I../inline $(DEPS_CFLAGS) -D_BSD_SOURCE -D_DEFAULT_SOURCE

noinst_LIBRARIES = libcollector.a

libcollector_a_SOURCES = ip128.c ip128.h repeater.c repeater.h \
	backend.c backend.h launch.h launch.c  \
	flowsource.c flowsource.h collector.c collector.h nfnet.h nfnet.c \
	yaf_reader.c yaf_reader.h  metric.c metric.h

if ENABLE_READPCAP
libcollector_a_SOURCES += pcap_reader.c pcap_reader.h
endif

CLEANFILES = *.gch

