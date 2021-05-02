
bin_PROGRAMS = nfpcapd

AM_CPPFLAGS = -I.. -I../lib $(DEPS_CFLAGS)
AM_LDFLAGS  = -L../lib

LDADD = $(DEPS_LIBS)

collector = ../collector.c ../collector.h
nfstatfile = ../nfstatfile.c ../nfstatfile.h
bookkeeper = ../bookkeeper.c ../bookkeeper.h
expire= ../expire.c ../expire.h
pcapdump = pcapdump.c pcapdump.h 
flowdump = flowdump.c flowdump.h
pcaproc = pcaproc.c pcaproc.h flowtree.c flowtree.h ipfrag.c ipfrag.h

nfpcapd_SOURCES = nfpcapd.c packet_pcap.c packet_pcap.h \
	$(pcaproc) $(pcapdump) $(flowdump) \
	$(nfstatfile) \
	$(nfnet) $(collector) $(bookkeeper) $(expire)
nfpcapd_LDADD = ../lib/libnfdump.la
if BSDBPF
nfpcapd_SOURCES += packet_bpf.c
AM_CPPFLAGS += -DUSE_BPFSOCKET
endif
if TPACKETV3
nfpcapd_SOURCES += packet_linux.c
AM_CPPFLAGS += -DUSE_TPACKETV3
endif

bin_PROGRAMS += nfpcapd
nfpcapd_CFLAGS = -D_BSD_SOURCE -D_DEFAULT_SOURCE
nfpcapd_LDADD += -lpcap 

CLEANFILES = *.gch
