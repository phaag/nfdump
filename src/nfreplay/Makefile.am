
bin_PROGRAMS = nfreplay

AM_CPPFLAGS = -I$(srcdir)/.. -I$(srcdir)/../include -I$(srcdir)/../libnfdump -I$(srcdir)/../libnffile -I$(srcdir)/../inline -I$(srcdir)/../collector -I$(srcdir)/../netflow $(DEPS_CFLAGS)

LDADD = $(DEPS_LIBS)

replay = send_v5.c send_v5.h send_v9.c send_v9.h send_net.h send_net.c

nfreplay_SOURCES = nfreplay.c $(replay)
nfreplay_LDADD = -lnfdump -lnffile
nfreplay_LDFLAGS = -L../libnfdump -L../libnffile
CLEANFILES = *.gch
