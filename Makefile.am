ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src/libnffile src/libnfdump src/output src/netflow src/collector src/maxmind src/tor
SUBDIRS += src/nfdump src/nfcapd  
SUBDIRS += src/nfanon src/nfexpire src/nfreplay . src src/test src/nfreader src/inline src/include

SUBDIRS += src/sflow

if BUILD_FT2NFDUMP
SUBDIRS += src/ft2nfdump
endif

if BUILD_NFPCAPD
SUBDIRS += src/nfpcapd
endif

if BUILD_NFPROFILE
SUBDIRS += src/nfsen
endif

SUBDIRS += man doc

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = nfdump.pc

EXTRA_DIST = LICENSE BSD-license.txt bootstrap nfdump.pc.in
EXTRA_DIST += extra/CreateSubHierarchy.pl extra/PortTracker.pm extra/nfdump.spec 
