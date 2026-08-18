
bin_PROGRAMS = nfdump

nfdump_CPPFLAGS = -I$(top_srcdir)/src -I$(srcdir)/compat_1_6_x -I$(top_srcdir)/src/include -I$(top_srcdir)/src/libnffile -I$(top_srcdir)/src/libnfdump -I$(top_srcdir)/src/output -I$(top_srcdir)/src/tor -I$(top_srcdir)/src/netflow -I$(top_srcdir)/src/collector -I$(top_srcdir)/src/inline $(DEPS_CFLAGS)
nfdump_CFLAGS = $(PTHREAD_CFLAGS)

nflowcache = nflowcache.c nflowcache.h memhandle.h
nfstat = nfstat.h nfstat.c
sort = blocksort.h blocksort.c 
nfprof = nfprof.h nfprof.c
exporter = exporter.c
nbar = nbar.c 
ifvrf = ifvrf.c 
compat = compat_1_6_x/nfx.h compat_1_6_x/nfx.c compat_1_6_x/convert.c compat_1_6_x/nfdump_1_6_x.h

nfdump_SOURCES = nfdump.c spin_lock.h \
	$(exporter) $(nbar) $(ifvrf) $(nfstat) $(nflowcache) $(nfprof) $(sort) $(compat)

nfdump_LDADD = ../output/liboutput.a  -lnfdump  -lnffile $(PTHREAD_LIBS)
nfdump_LDFLAGS  = -L../libnfdump -L../libnffile

EXTRA_DIST = memhandle.c

CLEANFILES = *.gch
