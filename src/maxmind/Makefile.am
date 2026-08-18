
bin_PROGRAMS = geolookup
bin_SCRIPTS = updateGeoDB.sh

geolookup_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/src/include -I$(top_srcdir)/src/libnfdump -I$(top_srcdir)/src/libnffile -I$(top_srcdir)/src/inline $(DEPS_CFLAGS)

geolookup_SOURCES = geolookup.c mmcreate.c mmcreate.h

geolookup_LDADD = -lnfdump -lnffile
geolookup_LDFLAGS = -L../libnfdump -L../libnffile

CLEANFILES = *.gch

EXTRA_DIST = updateGeoDB.sh
