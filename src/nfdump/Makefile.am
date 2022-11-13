
bin_PROGRAMS = nfdump

AM_CPPFLAGS = -I.. -I../include -I../lib -I../output -I../maxmind -I../netflow -I../collector -I../conf -I../inline $(DEPS_CFLAGS)
AM_LDFLAGS  = -L../lib

EXTRA_DIST = nffile_compat.c memhandle.c heapsort_inline.c 

LDADD = $(DEPS_LIBS)

nflowcache = nflowcache.c nflowcache.h memhandle.h
nfstat = nfstat.h nfstat.c
sort = blocksort.h blocksort.c 
nfprof = nfprof.h nfprof.c
exporter = exporter.c
nbar = nbar.c 
ifvrf = ifvrf.c 

nfdump_SOURCES = nfdump.c spin_lock.h \
	$(exporter) $(nbar) $(ifvrf) $(nfstat) $(nflowcache) $(nfprof) $(sort)
nfdump_LDADD = ../lib/libnfdump.la ../output/liboutput.a ../conf/libconf.a ../maxmind/libmaxmind.a

CLEANFILES = *.gch
