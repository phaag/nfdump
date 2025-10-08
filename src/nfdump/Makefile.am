
bin_PROGRAMS = nfdump

AM_CPPFLAGS = -I$(srcdir)/.. -I$(srcdir)/compat_1_6_x -I$(srcdir)/../include -I$(srcdir)/../libnffile -I$(srcdir)/../libnfdump -I$(srcdir)/../output -I$(srcdir)/../tor -I$(srcdir)/../netflow -I$(srcdir)/../collector -I$(srcdir)/../inline $(DEPS_CFLAGS)
AM_LDFLAGS  = -L../libnfdump -L../libnffile

EXTRA_DIST = memhandle.c

LDADD = $(DEPS_LIBS)

nflowcache = nflowcache.c nflowcache.h memhandle.h
nfstat = nfstat.h nfstat.c
sort = blocksort.h blocksort.c 
nfprof = nfprof.h nfprof.c
exporter = exporter.c
nbar = nbar.c 
ifvrf = ifvrf.c 
compat = compat_1_6_x/nfx.h compat_1_6_x/nfx.c compat_1_6_x/convert.c

nfdump_SOURCES = nfdump.c spin_lock.h \
	$(exporter) $(nbar) $(ifvrf) $(nfstat) $(nflowcache) $(nfprof) $(sort) $(compat)
nfdump_LDADD = ../output/liboutput.a  -lnfdump  -lnffile
nfdump_LDFLAGS = -L../libnfdump -L../libnffile

CLEANFILES = *.gch
