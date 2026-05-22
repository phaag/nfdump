
bin_PROGRAMS = nfexpire

AM_CPPFLAGS = -I.. -I../include -I../libnffile $(DEPS_CFLAGS)

LDADD = $(DEPS_LIBS)

nfexpire_SOURCES = nfexpire.c expire.c expire.h nfstatfile.c nfstatfile.h 
nfexpire_LDADD = -lnffile
nfexpire_LDFLAGS = -L../libnffile
CLEANFILES = *.gch
