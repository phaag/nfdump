
AM_CPPFLAGS = -I$(srcdir)/.. -I$(srcdir)/../include -I$(srcdir)/../libnfdump -I$(srcdir)/../libnffile  -I$(srcdir)/../inline $(DEPS_CFLAGS)

if MAXMIND
bin_PROGRAMS = geolookup
bin_SCRIPTS = updateGeoDB.sh

geolookup_SOURCES = geolookup.c mmcreate.c mmcreate.h
geolookup_LDADD = -lnfdump -lnffile
geolookup_LDFLAGS = -L../libnfdump -L../libnffile
endif

CLEANFILES = *.gch

EXTRA_DIST = updateGeoDB.sh
