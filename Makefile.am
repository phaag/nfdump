ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src/lib src/output src/netflow src/collector src/decode src/maxmind src/nfdump src/nfcapd  
SUBDIRS += src/nfanon src/nfexpire src/nfreplay . src src/test src/nfreader src/inline src/include

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

EXTRA_DIST = extra/CreateSubHierarchy.pl LICENSE BSD-license.txt extra/PortTracker.pm extra/nfdump.spec bootstrap
