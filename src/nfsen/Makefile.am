
AM_CPPFLAGS = -I.. -I../include -I../lib $(DEPS_CFLAGS)
AM_LDFLAGS  = -L../lib

bin_PROGRAMS = 

if NFPROFILE
bin_PROGRAMS += nfprofile
endif

if NFTRACK
bin_PROGRAMS += nftrack
endif

nfstatfile = ../nfstatfile.c ../nfstatfile.h
exporter = ../exporter.c ../exporter.h

nfprofile_SOURCES = nfprofile.c profile.c profile.h $(nfstatfile) $(exporter)
nfprofile_LDADD = ../lib/libnfdump.la -lrrd 

nftrack_SOURCES = nftrack.c nftrack_rrd.c nftrack_rrd.h \
	nftrack_stat.c nftrack_stat.h 
nftrack_LDADD = ../lib/libnfdump.la -lrrd


