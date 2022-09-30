
bin_PROGRAMS = nfexpire

AM_CPPFLAGS = -I.. -I../include -I../lib -I../collector $(DEPS_CFLAGS)
AM_LDFLAGS  = -L../lib

LDADD = $(DEPS_LIBS)

nfexpire_SOURCES = nfexpire.c 
nfexpire_LDADD = ../lib/libnfdump.la ../collector/libcollector.a

CLEANFILES = *.gch
