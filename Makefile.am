ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src/lib src/output src/conf src/netflow . src src/test

if SFLOW
SUBDIRS += src/sflow
endif

if FT2NFDUMP
SUBDIRS += src/ft2nfdump
endif

if BUILDNFPCAPD
SUBDIRS += src/nfpcapd
endif

if NFPROFILE
SUBDIRS += src/nfsen
endif

SUBDIRS += man doc

EXTRA_DIST = CreateSubHierarchy.pl LICENSE BSD-license.txt extra/PortTracker.pm extra/nfdump.spec bootstrap
