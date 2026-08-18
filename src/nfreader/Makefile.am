
EXTRA_PROGRAMS = nfreader

AM_CPPFLAGS = -I.. -I../include -I../libnffile -I../inline $(DEPS_CFLAGS)

LDADD = $(DEPS_LIBS)

nfreader_SOURCES = nfreader.c 
nfreader_LDADD = -lnffile
nfreader_LDADD += $(LZ4_LIBS) $(ZSTD_LIBS) $(BZ2_LIBS) $(LIBSODIUM_LIBS)
nfreader_LDFLAGS = -L../libnffile

CLEANFILES = *.gch
