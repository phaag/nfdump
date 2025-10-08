
bin_PROGRAMS = nfpcapd

AM_CPPFLAGS = -I$(srcdir)/.. -I$(srcdir)/../include -I$(srcdir)/../libnffile -I$(srcdir)/../inline -I$(srcdir)/../collector -I$(srcdir)/../netflow $(DEPS_CFLAGS)
#AM_LDFLAGS  = -L../lib

LDADD = $(DEPS_LIBS)

pcapdump = pcapdump.c pcapdump.h 
flowdump = flowdump.c flowdump.h
flowsend = flowsend.c flowsend.h
pcaproc = pcaproc.c pcaproc.h nflog.h pflog.h flowtree.c flowtree.h ip_frag.c ip_frag.h

nfpcapd_SOURCES = nfpcapd.c packet_pcap.c packet_pcap.h 
nfpcapd_SOURCES += $(pcaproc) $(pcapdump) $(flowdump) $(flowsend)
nfpcapd_CFLAGS = -D_BSD_SOURCE -D_DEFAULT_SOURCE
nfpcapd_LDADD = ../collector/libcollector.a -lnffile  -lpcap -lm
nfpcapd_LDFLAGS = -L../libnffile

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

if HAVEZLIB 
AM_CPPFLAGS += -DHAVEZLIB
nfpcapd_SOURCES += pcap_gzip.c pcap_gzip.h
nfpcapd_LDADD += -lz
endif

CLEANFILES = *.gch
