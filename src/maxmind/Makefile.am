
bin_PROGRAMS = geolookup
bin_SCRIPTS = updateGeoDB.sh

geolookup_CPPFLAGS = -I.. -I../include -I../libnfdump -I../libnffile  -I../inline $(DEPS_CFLAGS)

geolookup_SOURCES = geolookup.c mmcreate.c mmcreate.h

geolookup_LDADD = -lnfdump -lnffile
geolookup_LDFLAGS = -L../libnfdump -L../libnffile

CLEANFILES = *.gch

EXTRA_DIST = updateGeoDB.sh
