
bin_PROGRAMS = nfpcapd

nfpcapd_CPPFLAGS = -I.. -I../include -I../libnffile -I../inline -I../collector -I../netflow $(DEPS_CFLAGS)

flowdump = flowdump.c flowdump.h
flowsend = flowsend.c flowsend.h
pcapdump = pcapdump.c pcapdump.h 
pcaproc = pcaproc.c pcaproc.h nflog.h pflog.h flowhash.c flowhash.h ip_frag.c ip_frag.h

nfpcapd_SOURCES = nfpcapd.c packet_pcap.c packet_pcap_file.c packet_pcap.h 
nfpcapd_SOURCES += $(pcaproc) $(pcapdump) $(flowdump) $(flowsend) 
nfpcapd_CFLAGS = -D_BSD_SOURCE -D_DEFAULT_SOURCE
nfpcapd_CPPFLAGS += $(PCAP_CFLAGS) $(ZLIB_CFLAGS)
nfpcapd_LDADD = ../collector/libcollector.a -lnffile  -lpcap -lm
nfpcapd_LDADD += $(PCAP_LIBS) $(ZLIB_LIBS)
nfpcapd_LDFLAGS = -L../libnffile

if HAVE_ZLIB
nfpcapd_SOURCES += pcap_gzip.c pcap_gzip.h
endif

if BSDBPF
nfpcapd_SOURCES += packet_bpf.c
nfpcapd_CPPFLAGS += -DUSE_BPFSOCKET
endif
if TPACKETV3
nfpcapd_SOURCES += packet_linux.c
nfpcapd_CPPFLAGS += -DUSE_TPACKETV3
endif

CLEANFILES = *.gch
