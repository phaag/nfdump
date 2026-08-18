
bin_PROGRAMS = nfcapd 

nfcapd_SOURCES = nfcapd.c 
nfcapd_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/src/include -I$(top_srcdir)/src/libnffile -I$(top_srcdir)/src/inline -I$(top_srcdir)/src/netflow -I$(top_srcdir)/src/collector

nfcapd_LDADD = ../netflow/libnetflow.a ../collector/libcollector.a -lnffile  -lm
nfcapd_LDADD += $(LZ4_LIBS) $(ZSTD_LIBS) $(BZ2_LIBS)
nfcapd_LDFLAGS = -L../libnffile

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
