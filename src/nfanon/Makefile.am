
bin_PROGRAMS = nfanon

AM_CPPFLAGS = -I.. -I../include -I../libnffile -I../inline $(DEPS_CFLAGS)

LDADD = $(DEPS_LIBS)

anon = panonymizer.c panonymizer.h rijndael.c rijndael.h

nfanon_SOURCES = nfanon.c $(anon)
nfanon_LDADD = -lnffile
nfanon_LDFLAGS = -L../libnffile

CLEANFILES = *.gch
