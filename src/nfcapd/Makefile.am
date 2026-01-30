
bin_PROGRAMS = nfcapd 

nfcapd_SOURCES = nfcapd.c 
nfcapd_CPPFLAGS = -I../include -I../libnffile -I../inline -I../netflow -I../collector 

nfcapd_LDADD = ../netflow/libnetflow.a ../collector/libcollector.a -lnffile  -lm
nfcapd_LDFLAGS = -L../libnffile

nfcapd_CFLAGS = $(PTHREAD_CFLAGS)
nfcapd_LDADD  += $(PTHREAD_LIBS)

if ENABLE_READPCAP
nfcapd_CPPFLAGS += $(PCAP_CFLAGS)
nfcapd_LDADD += $(PCAP_LIBS)
endif

CLEANFILES = $(bin_PROGRAMS) *.gch
