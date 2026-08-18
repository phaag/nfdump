
bin_PROGRAMS = nfanon

nfanon_SOURCES = nfanon.c panonymizer.c panonymizer.h rijndael.c rijndael.h

nfanon_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/src/include -I$(top_srcdir)/src/libnffile -I$(top_srcdir)/src/libnffile/conf -I$(top_srcdir)/src/inline $(DEPS_CFLAGS)
nfanon_CFLAGS = $(PTHREAD_CFLAGS)

nfanon_LDADD = -lnffile $(PTHREAD_LIBS)
nfanon_LDADD += $(LZ4_LIBS) $(ZSTD_LIBS) $(BZ2_LIBS) $(LIBSODIUM_LIBS)
nfanon_LDFLAGS = -L../libnffile

CLEANFILES = *.gch
