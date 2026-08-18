
EXTRA_PROGRAMS = nfreader

AM_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/src/include -I$(top_srcdir)/src/libnffile -I$(top_srcdir)/src/inline $(DEPS_CFLAGS)

LDADD = $(DEPS_LIBS)

nfreader_SOURCES = nfreader.c 
nfreader_LDADD = -lnffile
nfreader_LDADD += $(LZ4_LIBS) $(ZSTD_LIBS) $(BZ2_LIBS) $(LIBSODIUM_LIBS)
nfreader_LDFLAGS = -L../libnffile

CLEANFILES = *.gch
