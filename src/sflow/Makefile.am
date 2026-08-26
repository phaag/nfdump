
bin_PROGRAMS = sfcapd

sfcapd_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/src/include -I$(top_srcdir)/src/libnffile -I$(top_srcdir)/src/libnfdump -I$(top_srcdir)/src/inline -I$(top_srcdir)/src/netflow -I$(top_srcdir)/src/collector $(DEPS_CFLAGS)

sfcapd_SOURCES = sfcapd.c
sfcapd_SOURCES += sflow_nfdump.c sflow_nfdump.h sflow.h sflow_v2v4.h sflow_decode.c sflow_decode.h

# -lnffilter: the minimal plain-element filter engine (-F), not the full
# -lnfdump - see src/libnfdump/Makefile.am.
sfcapd_LDADD = ../netflow/libnetflow.a ../collector/libcollector.a -lnffilter -lnffile  -lm
sfcapd_LDADD += $(LZ4_LIBS) $(ZSTD_LIBS) $(BZ2_LIBS)
sfcapd_LDFLAGS = -L../libnfdump -L../libnffile

sfcapd_CFLAGS = $(PTHREAD_CFLAGS)
sfcapd_LDADD  += $(PTHREAD_LIBS)

if HAVE_LIBSODIUM
sfcapd_CPPFLAGS += $(LIBSODIUM_CFLAGS)
sfcapd_LDADD += $(LIBSODIUM_LIBS)
endif

if ENABLE_READPCAP
sfcapd_CPPFLAGS += $(PCAP_CFLAGS)
sfcapd_LDADD += $(PCAP_LIBS)
endif

CLEANFILES = $(bin_PROGRAMS) *.gch
