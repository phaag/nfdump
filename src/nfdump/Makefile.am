
bin_PROGRAMS = nfdump

nfdump_CPPFLAGS = -I.. -Icompat_1_7_x -I../include -I../libnffile -I../libnfdump -I../output -I../tor -I../netflow -I../collector -I../inline $(DEPS_CFLAGS)
nfdump_CFLAGS = $(PTHREAD_CFLAGS)

nflowcache = nflowcache.c nflowcache.h memhandle.h
nfstat = nfstat.h nfstat.c
sort = blocksort.h blocksort.c 
nfprof = nfprof.h nfprof.c
exporter = exporter.c
nbar = nbar.c 
ifvrf = ifvrf.c 

nfdump_SOURCES = nfdump.c spin_lock.h \
	$(exporter) $(nbar) $(ifvrf) $(nfstat) $(nflowcache) $(nfprof) $(sort) 

nfdump_LDADD = ../output/liboutput.a  -lnfdump  -lnffile $(MATH_LIBS) $(PTHREAD_LIBS)
nfdump_LDADD += $(PCRE2_LIBS) $(LZ4_LIBS) $(ZSTD_LIBS) $(BZ2_LIBS)
nfdump_LDFLAGS  = -L../libnfdump -L../libnffile

if HAVE_LIBSODIUM
nfdump_CPPFLAGS += $(LIBSODIUM_CFLAGS)
nfdump_LDADD += $(LIBSODIUM_LIBS)
endif

EXTRA_DIST = memhandle.c

CLEANFILES = *.gch
