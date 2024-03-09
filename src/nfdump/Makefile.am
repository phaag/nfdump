
bin_PROGRAMS = nfdump

AM_CPPFLAGS = -I.. -Icompat_1_6_x -I../include -I../lib -I../output -I../maxmind -I../tor -I../netflow -I../collector -I../lib/conf -I../lib/filter -I../decode -I../inline $(DEPS_CFLAGS)
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
compat = compat_1_6_x/nfx.h compat_1_6_x/nfx.c

nfdump_SOURCES = nfdump.c spin_lock.h \
	$(exporter) $(nbar) $(ifvrf) $(nfstat) $(nflowcache) $(nfprof) $(sort) $(compat)
nfdump_LDADD = ../output/liboutput.a  ../lib/libnfdump.la ../maxmind/libmaxmind.a  ../tor/libtorlookup.a ../decode/libnfdecode.a

CLEANFILES = *.gch
