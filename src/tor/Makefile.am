
AM_CPPFLAGS = -I.. -I../include -I../libnfdump -I../libnffile -I../inline $(DEPS_CFLAGS)

if TORLOOKUP
bin_PROGRAMS = torlookup
bin_SCRIPTS = updateTorDB.sh

torlookup_SOURCES = torlookup.c 
torlookup_LDADD = -lnfdump -lnffile
torlookup_LDFLAGS = -L../libnfdump -L../libnffile  
endif

CLEANFILES = *.gch
