
AM_CPPFLAGS = -I.. -I../include -I../lib $(DEPS_CFLAGS) -DCONFIGDIR=\"$(sysconfdir)\"

nfconfdir=$(sysconfdir)
nfconf_DATA = nfdump.conf.dist

EXTRA_DIST = nfdump.conf.dist

noinst_LIBRARIES = libconf.a

libconf_a_SOURCES = nfconf.c nfconf.h toml.c toml.h

CLEANFILES = *.gch
