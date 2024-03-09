
AM_CPPFLAGS = -I.. -I../include -I../libnfdump -I../libnffile  -I../inline $(DEPS_CFLAGS)

if MAXMIND
bin_PROGRAMS = geolookup
bin_SCRIPTS = updateGeoDB.sh

geolookup_SOURCES = geolookup.c mmcreate.c mmcreate.h
geolookup_LDADD = -lnfdump -lnffile
geolookup_LDFLAGS = -L../libnfdump -L../libnffile
endif

CLEANFILES = *.gch

EXTRA_DIST = updateGeoDB.sh
