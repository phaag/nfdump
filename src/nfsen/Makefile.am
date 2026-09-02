
AM_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/src/include -I$(top_srcdir)/src/libnffile -I$(top_srcdir)/src/nfexpire -I$(top_srcdir)/src/collector
AM_CPPFLAGS += -I$(top_srcdir)/src/libnfquery -I$(top_srcdir)/src/libnfquery/maxmind -I$(top_srcdir)/src/libnfquery/tor -I$(top_srcdir)/src/inline
AM_CPPFLAGS += $(RRD_CFLAGS)

bin_PROGRAMS = nfprofile nftrack

nfstatfile = ../nfexpire/nfstatfile.c ../nfexpire/nfstatfile.h

nfprofile_SOURCES = nfprofile.c profile.c profile.h $(nfstatfile) 
nfprofile_LDADD = -lnfquery -lnffile $(RRD_LIBS)
nfprofile_LDADD += $(PCRE2_LIBS) $(LZ4_LIBS) $(ZSTD_LIBS) $(BZ2_LIBS) $(LIBSODIUM_LIBS)
nfprofile_LDFLAGS = -L$(top_builddir)/src/libnfquery -L$(top_builddir)/src/libnffile

nftrack_SOURCES = nftrack.c nftrack_rrd.c nftrack_rrd.h nftrack_stat.c nftrack_stat.h
nftrack_LDADD = -lnfquery -lnffile $(RRD_LIBS)
nftrack_LDADD += $(PCRE2_LIBS) $(LZ4_LIBS) $(ZSTD_LIBS) $(BZ2_LIBS) $(LIBSODIUM_LIBS)
nftrack_LDFLAGS = -L$(top_builddir)/src/libnfquery -L$(top_builddir)/src/libnffile

CLEANFILES = $(bin_PROGRAMS) *.gch
