
bin_PROGRAMS = nfdump

nfdump_CPPFLAGS = -I$(top_srcdir)/src -I$(srcdir)/compat_1_7_x -I$(top_srcdir)/src/include -I$(top_srcdir)/src/libnffile -I$(top_srcdir)/src/libnfquery -I$(top_srcdir)/src/output -I$(top_srcdir)/src/tor -I$(top_srcdir)/src/netflow -I$(top_srcdir)/src/collector -I$(top_srcdir)/src/inline $(DEPS_CFLAGS)
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

nfdump_LDADD = ../output/liboutput.a  -lnfquery  -lnffile $(MATH_LIBS) $(PTHREAD_LIBS)
nfdump_LDADD += $(PCRE2_LIBS) $(LZ4_LIBS) $(ZSTD_LIBS) $(BZ2_LIBS)
nfdump_LDFLAGS  = -L$(top_builddir)/src/libnfquery -L$(top_builddir)/src/libnffile

if HAVE_LIBSODIUM
nfdump_CPPFLAGS += $(LIBSODIUM_CFLAGS)
nfdump_LDADD += $(LIBSODIUM_LIBS)
endif

EXTRA_DIST = memhandle.c

CLEANFILES = *.gch
