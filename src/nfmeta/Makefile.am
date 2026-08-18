
bin_PROGRAMS = nfmeta

nfmeta_SOURCES = nfmeta.c 

nfmeta_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/src/include -I$(top_srcdir)/src/libnffile -I$(top_srcdir)/src/libnffile/conf -I$(top_srcdir)/src/inline $(DEPS_CFLAGS)
nfmeta_CFLAGS = $(PTHREAD_CFLAGS)

nfmeta_LDADD = -lnffile $(PTHREAD_LIBS)
nfmeta_LDADD += $(LZ4_LIBS) $(ZSTD_LIBS) $(BZ2_LIBS) $(LIBSODIUM_LIBS)
nfmeta_LDFLAGS = -L../libnffile

CLEANFILES = *.gch
