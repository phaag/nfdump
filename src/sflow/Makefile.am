
bin_PROGRAMS = sfcapd

AM_CPPFLAGS = -I.. -I../include -I../libnffile -I../inline -I../collector $(DEPS_CFLAGS)

sflow = sflow_nfdump.c sflow_nfdump.h sflow.h sflow_v2v4.h sflow_process.c  sflow_process.h
sfcapd_SOURCES = sfcapd.c \
	$(sflow) $(launch) 
sfcapd_LDADD = ../collector/libcollector.a -lnffile  -lm
sfcapd_LDFLAGS = -L../libnffile 

if READPCAP
sfcapd_CFLAGS = -DPCAP
sfcapd_LDADD += -lpcap
endif

CLEANFILES = *.gch
