
bin_PROGRAMS = nfpcapd

AM_CPPFLAGS = -I.. -I../include -I../lib -I../inline -I../collector -I../conf $(DEPS_CFLAGS)
AM_LDFLAGS  = -L../lib

LDADD = $(DEPS_LIBS)

pcapdump = pcapdump.c pcapdump.h 
flowdump = flowdump.c flowdump.h
flowsend = flowsend.c flowsend.h
pcaproc = pcaproc.c pcaproc.h flowtree.c flowtree.h 

nfpcapd_SOURCES = nfpcapd.c packet_pcap.c packet_pcap.h \
	$(pcaproc) $(pcapdump) $(flowdump) $(flowsend)
nfpcapd_LDADD = ../lib/libnfdump.la ../collector/libcollector.a ../conf/libconf.a -lm
if BSDBPF
nfpcapd_SOURCES += packet_bpf.c
AM_CPPFLAGS += -DUSE_BPFSOCKET
endif
if TPACKETV3
nfpcapd_SOURCES += packet_linux.c
AM_CPPFLAGS += -DUSE_TPACKETV3
endif
if HAVEPCAPAPPEND
AM_CPPFLAGS += -DHAVEPCAPAPPEND
endif

bin_PROGRAMS += nfpcapd
nfpcapd_CFLAGS = -D_BSD_SOURCE -D_DEFAULT_SOURCE
nfpcapd_LDADD += -lpcap 

CLEANFILES = *.gch
