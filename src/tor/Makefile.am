
AM_CPPFLAGS = -I.. -I../include -I../libnffile -I../inline $(DEPS_CFLAGS)

noinst_LIBRARIES = libtorlookup.a

if TORLOOKUP
bin_PROGRAMS = torlookup
bin_SCRIPTS = updateTorDB.sh
endif

libtorlookup_a_SOURCES = tor.c tor.h

if TORLOOKUP
torlookup_SOURCES = torlookup.c 
torlookup_LDADD = libtorlookup.a -lnffile
torlookup_LDFLAGS = -L../libnffile  
endif

CLEANFILES = *.gch
