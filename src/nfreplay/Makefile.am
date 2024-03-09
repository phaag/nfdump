
bin_PROGRAMS = nfreplay

AM_CPPFLAGS = -I.. -I../include -I../libnfdump -I../libnffile -I../inline -I../collector -I../netflow $(DEPS_CFLAGS)

LDADD = $(DEPS_LIBS)

replay = send_v5.c send_v5.h send_v9.c send_v9.h send_net.h send_net.c

nfreplay_SOURCES = nfreplay.c $(replay)
nfreplay_LDADD = -lnfdump -lnffile
nfreplay_LDFLAGS = -L../libnfdump -L../libnffile
CLEANFILES = *.gch
