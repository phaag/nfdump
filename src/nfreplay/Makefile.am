
bin_PROGRAMS = nfreplay

AM_CPPFLAGS = -I.. -I../include -I../libnfdump -I../libnffile -I../inline -I../collector -I../netflow $(DEPS_CFLAGS)

LDADD = $(DEPS_LIBS)

replay = send_v5.c send_v5.h send_v9_ipfix.c send_v9_ipfix.h send_net.h send_net.c

nfreplay_SOURCES = nfreplay.c $(replay)
nfreplay_LDADD = -lnfdump ../netflow/libnetflow.a -lnffile
nfreplay_LDFLAGS = -L../libnfdump -L../libnffile
if HAVE_LIBSODIUM
nfreplay_CPPFLAGS = $(AM_CPPFLAGS) $(LIBSODIUM_CFLAGS)
nfreplay_LDADD += $(LIBSODIUM_LIBS)
endif
CLEANFILES = *.gch
