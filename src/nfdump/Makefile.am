
bin_PROGRAMS = nfdump

AM_CPPFLAGS = -I.. -Icompat_1_6_x -I../include -I../libnffile -I../libnfdump -I../output -I../tor -I../netflow -I../collector -I../inline $(DEPS_CFLAGS)
AM_LDFLAGS  = -L../libnfdump -L../libnffile

EXTRA_DIST = nffile_compat.c memhandle.c heapsort_inline.c 

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
