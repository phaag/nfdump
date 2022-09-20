
AM_CPPFLAGS = -I.. -I../include -I../lib -I../conf -I../inline $(DEPS_CFLAGS)

noinst_LIBRARIES = libmaxmind.a

if MAXMIND
bin_PROGRAMS = geolookup
endif

libmaxmind_a_SOURCES = maxmind.c maxmind.h

if MAXMIND
geolookup_SOURCES = geolookup.c 
geolookup_LDADD = ../lib/libnfdump.la ../conf/libconf.a libmaxmind.a
endif

CLEANFILES = *.gch
