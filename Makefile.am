ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src/libnffile src/libnfquery src/libnfdump src/output src/netflow src/collector src/maxmind src/tor
SUBDIRS += src/nfdump src/nfcapd  
SUBDIRS += src/nfanon src/nfexpire src/nfreplay . src src/inline src/include

SUBDIRS += src/sflow
SUBDIRS += src/nfmeta

if BUILD_FT2NFDUMP
SUBDIRS += src/ft2nfdump
endif

if BUILD_NFPCAPD
SUBDIRS += src/nfpcapd
endif

if BUILD_NFPROFILE
SUBDIRS += src/nfsen
endif

# The tests run every program: build all programs before src/test.
# Otherwise 'make check' on a clean tree tests programs not built yet.
SUBDIRS += src/test

SUBDIRS += man doc

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = nfdump.pc

EXTRA_DIST = LICENSE BSD-license.txt bootstrap nfdump.pc.in
EXTRA_DIST += extra/CreateSubHierarchy.pl extra/PortTracker.pm extra/nfdump.spec 
