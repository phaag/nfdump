
AM_CPPFLAGS = -I.. -I../include -I../lib -I../lib/conf -I../inline $(DEPS_CFLAGS)

noinst_LIBRARIES = libtorlookup.a

if TORLOOKUP
bin_PROGRAMS = torlookup
bin_SCRIPTS = updateTorDB.sh
endif

libtorlookup_a_SOURCES = tor.c tor.h

if TORLOOKUP
torlookup_SOURCES = torlookup.c 
torlookup_LDADD = ../lib/libnfdump.la libtorlookup.a ../maxmind/libmaxmind.a ../decode/libnfdecode.a
endif

CLEANFILES = *.gch
