
bin_PROGRAMS = nfexpire

AM_CPPFLAGS = -I.. -I../include -I../libnffile -I../collector $(DEPS_CFLAGS)

LDADD = $(DEPS_LIBS)

nfexpire_SOURCES = nfexpire.c 
nfexpire_LDADD = ../collector/libcollector.a -lnffile
nfexpire_LDFLAGS = -L../libnffile
CLEANFILES = *.gch
