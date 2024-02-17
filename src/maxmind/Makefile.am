
AM_CPPFLAGS = -I.. -I../include -I../lib -I../lib/conf  -I../lib/filter -I../inline $(DEPS_CFLAGS)

noinst_LIBRARIES = libmaxmind.a

if MAXMIND
bin_PROGRAMS = geolookup
bin_SCRIPTS = updateGeoDB.sh
endif

libmaxmind_a_SOURCES = maxmind.c maxmind.h

if MAXMIND
geolookup_SOURCES = geolookup.c 
geolookup_LDADD = ../lib/libnfdump.la libmaxmind.a
endif

CLEANFILES = *.gch

EXTRA_DIST = updateGeoDB.sh
