
bin_PROGRAMS = sfcapd

AM_CPPFLAGS = -I.. -I../lib $(DEPS_CFLAGS)
AM_LDFLAGS  = -L../lib

collector = ../collector.c ../collector.h
nfstatfile = ../nfstatfile.c ../nfstatfile.h
bookkeeper = ../bookkeeper.c ../bookkeeper.h
expire= ../expire.c ../expire.h
launch = ../launch.c ../launch.h
nfnet = ../nfnet.c ../nfnet.h
metric = ../metric.c ../metric.h

sfcapd_SOURCES = sfcapd.c sflow_nfdump.c sflow_nfdump.h sflow.h sflow_v2v4.h sflow_process.c  sflow_process.h\
	$(nfstatfile) $(launch) \
	$(nfnet) $(collector) $(bookkeeper) $(expire) $(metric)
sfcapd_LDADD = ../lib/libnfdump.la

if READPCAP
sfcapd_CFLAGS = -DPCAP
sfcapd_SOURCES += ../pcap_reader.c ../pcap_reader.h
sfcapd_LDADD += -lpcap
endif

CLEANFILES = *.gch
