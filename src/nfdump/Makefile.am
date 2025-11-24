
bin_PROGRAMS = nfdump

nfdump_CPPFLAGS = -I.. -Icompat_1_6_x -I../include -I../libnffile -I../libnfdump -I../output -I../tor -I../netflow -I../collector -I../inline $(DEPS_CFLAGS)
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
