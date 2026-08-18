
bin_PROGRAMS = nfreplay

AM_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/src/include -I$(top_srcdir)/src/libnfdump -I$(top_srcdir)/src/libnffile -I$(top_srcdir)/src/inline -I$(top_srcdir)/src/collector -I$(top_srcdir)/src/netflow $(DEPS_CFLAGS)

LDADD = $(DEPS_LIBS)

replay = send_v5.c send_v5.h send_v9.c send_v9.h send_net.h send_net.c

nfreplay_SOURCES = nfreplay.c $(replay)
nfreplay_LDADD = -lnfdump -lnffile
nfreplay_LDFLAGS = -L../libnfdump -L../libnffile
CLEANFILES = *.gch
