
bin_PROGRAMS = sfcapd

AM_CPPFLAGS = -I.. -I../include -I../lib -I../collector $(DEPS_CFLAGS)
AM_LDFLAGS  = -L../lib

expire= ../expire.c ../expire.h
launch = ../launch.c ../launch.h
nfnet = ../nfnet.c ../nfnet.h

sfcapd_SOURCES = sfcapd.c sflow_nfdump.c sflow_nfdump.h sflow.h sflow_v2v4.h sflow_process.c  sflow_process.h\
	$(launch) $(nfnet) $(expire) 
sfcapd_LDADD = ../lib/libnfdump.la ../collector/libcollector.a -lm

if READPCAP
sfcapd_CFLAGS = -DPCAP
sfcapd_SOURCES += ../pcap_reader.c ../pcap_reader.h
sfcapd_LDADD += -lpcap
endif

CLEANFILES = *.gch
