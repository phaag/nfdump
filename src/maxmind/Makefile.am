
bin_PROGRAMS = geolookup
bin_SCRIPTS = updateGeoDB.sh

geolookup_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/src/include -I$(top_srcdir)/src/libnfquery -I$(top_srcdir)/src/libnffile -I$(top_srcdir)/src/inline $(DEPS_CFLAGS)

geolookup_SOURCES = geolookup.c mmcreate.c mmcreate.h

geolookup_LDADD = -lnfquery -lnffile
geolookup_LDADD += $(PCRE2_LIBS) $(LZ4_LIBS) $(ZSTD_LIBS) $(BZ2_LIBS) $(LIBSODIUM_LIBS)
geolookup_LDFLAGS = -L$(top_builddir)/src/libnfquery -L$(top_builddir)/src/libnffile

CLEANFILES = *.gch

EXTRA_DIST = updateGeoDB.sh
