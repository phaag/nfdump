
bin_PROGRAMS = nfcapd 

nfcapd_SOURCES = nfcapd.c
nfcapd_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/src/include -I$(top_srcdir)/src/libnffile -I$(top_srcdir)/src/libnfquery -I$(top_srcdir)/src/inline -I$(top_srcdir)/src/netflow -I$(top_srcdir)/src/collector

# -lnffilter: the minimal plain-element filter engine (-F), not the full
# -lnfquery - see src/libnfquery/Makefile.am. Pulls in no MaxMind/Tor/DNS/SSL/
# JA3/JA4 code.
nfcapd_LDADD = ../netflow/libnetflow.a ../collector/libcollector.a -lnffilter -lnffile  -lm
nfcapd_LDADD += $(LZ4_LIBS) $(ZSTD_LIBS) $(BZ2_LIBS)
nfcapd_LDFLAGS = -L$(top_builddir)/src/libnfquery -L$(top_builddir)/src/libnffile

nfcapd_CFLAGS = $(PTHREAD_CFLAGS)
nfcapd_LDADD  += $(PTHREAD_LIBS)

if HAVE_LIBSODIUM
nfcapd_CPPFLAGS += $(LIBSODIUM_CFLAGS)
nfcapd_LDADD += $(LIBSODIUM_LIBS)
endif

if ENABLE_READPCAP
nfcapd_CPPFLAGS += $(PCAP_CFLAGS)
nfcapd_LDADD += $(PCAP_LIBS)
endif

CLEANFILES = $(bin_PROGRAMS) *.gch
