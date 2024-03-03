
bin_PROGRAMS = nfreplay

AM_CPPFLAGS = -I.. -I../include -I../lib -I../lib/filter -I../inline -I../collector -I../netflow $(DEPS_CFLAGS)
AM_LDFLAGS  = -L../lib

LDADD = $(DEPS_LIBS)

replay = send_v5.c send_v5.h send_v9.c send_v9.h send_net.h send_net.c

nfreplay_SOURCES = nfreplay.c $(replay)
nfreplay_LDADD = ../lib/libnfdump.la ../maxmind/libmaxmind.a ../decode/libnfdecode.a

CLEANFILES = *.gch
