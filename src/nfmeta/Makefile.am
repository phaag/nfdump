
bin_PROGRAMS = nfmeta

nfmeta_SOURCES = nfmeta.c 

nfmeta_CPPFLAGS = -I.. -I../include -I../libnffile -I../libnffile/conf -I../inline $(DEPS_CFLAGS)
nfmeta_CFLAGS = $(PTHREAD_CFLAGS)

nfmeta_LDADD = -lnffile $(PTHREAD_LIBS)
nfmeta_LDFLAGS = -L../libnffile

CLEANFILES = *.gch
