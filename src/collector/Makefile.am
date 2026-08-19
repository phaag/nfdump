
AM_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/src/include -I$(top_srcdir)/src/libnffile -I$(top_srcdir)/src/inline -I$(top_srcdir)/src/netflow $(DEPS_CFLAGS) -D_BSD_SOURCE -D_DEFAULT_SOURCE
AM_CPPFLAGS += $(LZ4_CFLAGS)

if HAVE_LIBSODIUM
AM_CPPFLAGS += $(LIBSODIUM_CFLAGS)
endif

noinst_LIBRARIES = libcollector.a

libcollector_a_SOURCES = \
	process/daemon.c process/daemon.h \
	process/pidfile.c process/pidfile.h \
	network/nfnet.c network/nfnet.h \
	network/nfd_udp_crypto.c network/nfd_udp_crypto.h \
	network/repeater.c network/repeater.h \
	reader/yaf_reader.c reader/yaf_reader.h \
	backend/backend.h \
	backend/nffile_backend.c backend/nffile_backend.h \
	backend/remote_backend.c backend/remote_backend.h \
	ip128.c \
	launch.h launch.c \
	flowsource.c flowsource.h \
	collector.c collector.h \
	metric.c metric.h \
	packet_frame.c packet_frame.h

EXTRA_DIST = collector_run_inline.c

if ENABLE_READPCAP
libcollector_a_SOURCES += reader/pcap_reader.c reader/pcap_reader.h
endif

CLEANFILES = *.gch
