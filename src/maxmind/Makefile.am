
AM_CPPFLAGS = -I.. -I../include -I../libnffile   -I../lib/filter -I../inline $(DEPS_CFLAGS)

noinst_LIBRARIES = libmaxmind.a

if MAXMIND
bin_PROGRAMS = geolookup
bin_SCRIPTS = updateGeoDB.sh
endif

libmaxmind_a_SOURCES = mmhash.c mmhash.h maxmind.c maxmind.h

if MAXMIND
geolookup_SOURCES = geolookup.c mmcreate.c mmcreate.h
geolookup_LDADD = libmaxmind.a ../libnffile/libnffile.la  
endif

CLEANFILES = *.gch

EXTRA_DIST = updateGeoDB.sh
