
bin_PROGRAMS = nfexpire

AM_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/src/include -I$(top_srcdir)/src/libnffile $(DEPS_CFLAGS)

LDADD = $(DEPS_LIBS)

nfexpire_SOURCES = nfexpire.c expire.c expire.h nfstatfile.c nfstatfile.h 
nfexpire_LDADD = -lnffile
nfexpire_LDADD += $(LZ4_LIBS) $(ZSTD_LIBS) $(BZ2_LIBS) $(LIBSODIUM_LIBS)
nfexpire_LDFLAGS = -L../libnffile
CLEANFILES = *.gch
