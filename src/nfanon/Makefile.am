
bin_PROGRAMS = nfanon

AM_CPPFLAGS = -I.. -I../include -I../lib -I../inline $(DEPS_CFLAGS)
AM_LDFLAGS  = -L../lib

LDADD = $(DEPS_LIBS)

anon = panonymizer.c panonymizer.h rijndael.c rijndael.h

nfanon_SOURCES = nfanon.c $(anon)
nfanon_LDADD = ../lib/libnfdump.la ../maxmind/libmaxmind.a

CLEANFILES = *.gch
