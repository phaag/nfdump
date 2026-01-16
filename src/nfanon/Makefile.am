
bin_PROGRAMS = nfanon

nfanon_SOURCES = nfanon.c panonymizer.c panonymizer.h rijndael.c rijndael.h

nfanon_CPPFLAGS = -I.. -I../include -I../libnffile -I../libnffile/conf -I../inline $(DEPS_CFLAGS)
nfanon_CFLAGS = $(PTHREAD_CFLAGS)

nfanon_LDADD = -lnffile $(PTHREAD_LIBS)
nfanon_LDFLAGS = -L../libnffile

CLEANFILES = *.gch
