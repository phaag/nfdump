
bin_PROGRAMS = nfexpire

AM_CPPFLAGS = -I$(srcdir)/.. -I$(srcdir)/../include -I$(srcdir)/../libnffile -I$(srcdir)/../collector $(DEPS_CFLAGS)

LDADD = $(DEPS_LIBS)

nfexpire_SOURCES = nfexpire.c 
nfexpire_LDADD = ../collector/libcollector.a -lnffile
nfexpire_LDFLAGS = -L../libnffile
CLEANFILES = *.gch
