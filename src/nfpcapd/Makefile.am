
bin_PROGRAMS = nfpcapd

nfpcapd_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/src/include -I$(top_srcdir)/src/libnffile -I$(top_srcdir)/src/libnfquery -I$(top_srcdir)/src/inline -I$(top_srcdir)/src/collector -I$(top_srcdir)/src/netflow $(DEPS_CFLAGS)

flowdump = flowdump.c flowdump.h
pcapdump = pcapdump.c pcapdump.h
pcaproc = pcaproc.c pcaproc.h nflog.h pflog.h flowhash.c flowhash.h ip_frag.c ip_frag.h

nfpcapd_SOURCES = nfpcapd.c packet_pcap.c packet_pcap_file.c packet_pcap.h
nfpcapd_SOURCES += $(pcaproc) $(pcapdump) $(flowdump)
nfpcapd_CFLAGS = -D_BSD_SOURCE -D_DEFAULT_SOURCE
nfpcapd_CPPFLAGS += $(PCAP_CFLAGS) $(ZLIB_CFLAGS)
# -lnffilter: the minimal plain-element filter engine (-F), not the full
# -lnfquery - see src/libnfquery/Makefile.am.
nfpcapd_LDADD = ../netflow/libnetflow.a ../collector/libcollector.a -lnffilter -lnffile  -lpcap -lm
nfpcapd_LDADD += $(PCAP_LIBS) $(ZLIB_LIBS)
nfpcapd_LDADD += $(LZ4_LIBS) $(ZSTD_LIBS) $(BZ2_LIBS)
nfpcapd_LDFLAGS = -L$(top_builddir)/src/libnfquery -L$(top_builddir)/src/libnffile

if HAVE_LIBSODIUM
nfpcapd_CPPFLAGS += $(LIBSODIUM_CFLAGS)
nfpcapd_LDADD += $(LIBSODIUM_LIBS)
endif

if HAVE_ZLIB
nfpcapd_SOURCES += pcap_gzip.c pcap_gzip.h
endif

if BSDBPF
nfpcapd_SOURCES += packet_bpf.c
nfpcapd_CPPFLAGS += -DUSE_BPFSOCKET
endif
if TPACKETV3
nfpcapd_SOURCES += packet_linux.c
nfpcapd_CPPFLAGS += -DUSE_TPACKETV3
endif

CLEANFILES = *.gch
