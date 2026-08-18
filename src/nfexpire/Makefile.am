
bin_PROGRAMS = nfexpire

AM_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/src/include -I$(top_srcdir)/src/libnffile -I$(top_srcdir)/src/collector $(DEPS_CFLAGS)

LDADD = $(DEPS_LIBS)

nfexpire_SOURCES = nfexpire.c 
nfexpire_LDADD = ../collector/libcollector.a -lnffile
nfexpire_LDFLAGS = -L../libnffile
CLEANFILES = *.gch
