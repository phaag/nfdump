
EXTRA_PROGRAMS = nfreader

AM_CPPFLAGS = -I$(srcdir)/.. -I$(srcdir)/../include -I$(srcdir)/../libnffile -I$(srcdir)/../inline $(DEPS_CFLAGS)

LDADD = $(DEPS_LIBS)

nfreader_SOURCES = nfreader.c 
nfreader_LDADD = -lnffile
nfreader_LDFLAGS = -L../libnffile

CLEANFILES = *.gch
