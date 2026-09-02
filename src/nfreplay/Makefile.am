
bin_PROGRAMS = nfreplay

AM_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/src/include -I$(top_srcdir)/src/libnfquery -I$(top_srcdir)/src/libnffile -I$(top_srcdir)/src/inline -I$(top_srcdir)/src/collector -I$(top_srcdir)/src/netflow $(DEPS_CFLAGS)

LDADD = $(DEPS_LIBS)

replay = send_v5.c send_v5.h send_v9_ipfix.c send_v9_ipfix.h send_net.h send_net.c

nfreplay_SOURCES = nfreplay.c $(replay)
nfreplay_LDADD = -lnfquery ../netflow/libnetflow.a ../collector/libcollector.a -lnffile
nfreplay_LDADD += $(PCRE2_LIBS) $(LZ4_LIBS) $(ZSTD_LIBS) $(BZ2_LIBS)
nfreplay_LDFLAGS = -L$(top_builddir)/src/libnfquery -L$(top_builddir)/src/libnffile
nfreplay_CPPFLAGS = $(AM_CPPFLAGS)
if HAVE_LIBSODIUM
nfreplay_CPPFLAGS += $(LIBSODIUM_CFLAGS)
nfreplay_LDADD += $(LIBSODIUM_LIBS)
endif
CLEANFILES = *.gch
