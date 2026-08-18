
AM_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/src/include -I$(top_srcdir)/src/libnffile -I$(top_srcdir)/src/collector
AM_CPPFLAGS += -I$(top_srcdir)/src/libnfdump -I$(top_srcdir)/src/libnfdump/maxmind -I$(top_srcdir)/src/libnfdump/tor -I$(top_srcdir)/src/inline
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
