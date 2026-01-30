
AM_CPPFLAGS = -I.. -I../include -I../libnffile -I../collector/
AM_CPPFLAGS += -I../libnfdump -I../libnfdump/maxmind -I../libnfdump/tor -I../inline 
AM_CPPFLAGS += $(RRD_CFLAGS)

bin_PROGRAMS = nfprofile nftrack

nfstatfile = ../collector/nfstatfile.c ../collector/nfstatfile.h

nfprofile_SOURCES = nfprofile.c profile.c profile.h $(nfstatfile) 
nfprofile_LDADD = -lnfdump -lnffile $(RRD_LIBS)
nfprofile_LDFLAGS = -L../libnfdump -L../libnffile

nftrack_SOURCES = nftrack.c nftrack_rrd.c nftrack_rrd.h nftrack_stat.c nftrack_stat.h 
nftrack_LDADD = -lnfdump -lnffile $(RRD_LIBS)
nftrack_LDFLAGS = -L../libnfdump -L../libnffile

CLEANFILES = $(bin_PROGRAMS) *.gch