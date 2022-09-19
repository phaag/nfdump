
bin_PROGRAMS = sfcapd

AM_CPPFLAGS = -I.. -I../include -I../lib -I../inline -I../collector $(DEPS_CFLAGS)
AM_LDFLAGS  = -L../lib

expire= ../expire.c ../expire.h
launch = ../launch.c ../launch.h

sfcapd_SOURCES = sfcapd.c sflow_nfdump.c sflow_nfdump.h sflow.h sflow_v2v4.h sflow_process.c  sflow_process.h\
	$(launch) $(expire) 
sfcapd_LDADD = ../lib/libnfdump.la ../collector/libcollector.a -lm

if READPCAP
sfcapd_CFLAGS = -DPCAP
sfcapd_LDADD += -lpcap
endif

CLEANFILES = *.gch
