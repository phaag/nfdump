
SUBDIRS = src/lib . src src/test man doc 

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

EXTRA_DIST = CreateSubHierarchy.pl LICENSE BSD-license.txt extra/PortTracker.pm extra/nfdump.spec bootstrap
