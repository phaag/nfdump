
bin_PROGRAMS = nfanon

AM_CPPFLAGS = -I$(srcdir)/.. -I$(srcdir)/../include -I$(srcdir)/../libnffile -I$(srcdir)/../inline $(DEPS_CFLAGS)

LDADD = $(DEPS_LIBS)

anon = panonymizer.c panonymizer.h rijndael.c rijndael.h

nfanon_SOURCES = nfanon.c $(anon)
nfanon_LDADD = -lnffile
nfanon_LDFLAGS = -L../libnffile

CLEANFILES = *.gch
