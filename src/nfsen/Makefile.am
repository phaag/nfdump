
AM_CPPFLAGS = -I.. -I../include -I../lib -I../inline -I../collector $(DEPS_CFLAGS)
AM_LDFLAGS  = -L../lib

bin_PROGRAMS = 

if NFPROFILE
bin_PROGRAMS += nfprofile
endif

if NFTRACK
bin_PROGRAMS += nftrack
endif

nfstatfile = ../collector/nfstatfile.c ../collector/nfstatfile.h
exporter = ../nfdump/exporter.c 

nfprofile_SOURCES = nfprofile.c profile.c profile.h $(nfstatfile) $(exporter)
nfprofile_LDADD = ../lib/libnfdump.la -lrrd 

nftrack_SOURCES = nftrack.c nftrack_rrd.c nftrack_rrd.h \
	nftrack_stat.c nftrack_stat.h 
nftrack_LDADD = ../lib/libnfdump.la -lrrd


