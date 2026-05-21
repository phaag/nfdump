
AM_CPPFLAGS = -I.. -I../libnffile -I../include -I../collector -I../inline $(DEPS_CFLAGS)

if HAVE_LIBSODIUM
AM_CPPFLAGS += $(LIBSODIUM_CFLAGS)
endif

noinst_LIBRARIES = libnetflow.a

libnetflow_a_SOURCES = fnf.h netflow_v1.c netflow_v1.h netflow_v5_v7.c netflow_v5_v7.h netflow_v9.c netflow_v9.h ipfix.c ipfix.h nfd_raw.c nfd_raw.h nfd_udp_crypto.c nfd_udp_crypto.h

CLEANFILES = *.gch