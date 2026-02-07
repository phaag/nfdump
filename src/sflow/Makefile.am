
bin_PROGRAMS = sfcapd

sfcapd_CPPFLAGS = -I.. -I../include -I../libnffile -I../libnfdump -I../inline -I../collector $(DEPS_CFLAGS)

sfcapd_SOURCES = sfcapd.c 
sfcapd_SOURCES += sflow_nfdump.c sflow_nfdump.h sflow.h sflow_v2v4.h sflow_process.c  sflow_process.h

sfcapd_LDADD = ../collector/libcollector.a -lnfdump -lnffile  -lm
sfcapd_LDFLAGS = -L../libnffile -L../libnfdump

sfcapd_CFLAGS = $(PTHREAD_CFLAGS)
sfcapd_LDADD  += $(PTHREAD_LIBS)

if ENABLE_READPCAP
sfcapd_CPPFLAGS += $(PCAP_CFLAGS)
sfcapd_LDADD += $(PCAP_LIBS)
endif

CLEANFILES = $(bin_PROGRAMS) *.gch
