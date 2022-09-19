
bin_PROGRAMS = nfreplay

AM_CPPFLAGS = -I.. -I../lib $(DEPS_CFLAGS)
AM_LDFLAGS  = -L../lib

LDADD = $(DEPS_LIBS)

replay = send_v5.c send_v5.h send_v9.c send_v9.h ../nfet.h ../nfnet.c

nfreplay_SOURCES = nfreplay.c $(replay)
nfreplay_LDADD = ../lib/libnfdump.la

CLEANFILES = *.gch
