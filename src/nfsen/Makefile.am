
AM_CPPFLAGS = -I.. -I../include -I../libnffile -I../libnfdump -I../inline -I../collector 
AM_CPPFLAGS += -I../libnffile/conf -I../libnfdump/maxmind -I../libnfdump/tor $(DEPS_CFLAGS)

bin_PROGRAMS = 

if NFPROFILE
bin_PROGRAMS += nfprofile
endif

if NFTRACK
bin_PROGRAMS += nftrack
endif

nfstatfile = ../collector/nfstatfile.c ../collector/nfstatfile.h

nfprofile_SOURCES = nfprofile.c profile.c profile.h $(nfstatfile) 
nfprofile_LDADD = -lnfdump -lnffile -lrrd
nfprofile_LDFLAGS = -L../libnfdump -L../libnffile

nftrack_SOURCES = nftrack.c nftrack_rrd.c nftrack_rrd.h \
	nftrack_stat.c nftrack_stat.h 
nftrack_LDADD = -lnfdump -lnffile -lrrd
nftrack_LDFLAGS = -L../libnfdump -L../libnffile
