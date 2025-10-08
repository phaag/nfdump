
AM_CPPFLAGS = -I$(srcdir)/.. -I$(srcdir)/../libnffile -I$(srcdir)/../include -I$(srcdir)/../collector -I$(srcdir)/../inline $(DEPS_CFLAGS)

noinst_LIBRARIES = libnetflow.a

libnetflow_a_SOURCES = fnf.h netflow_v1.c netflow_v1.h netflow_v5_v7.c netflow_v5_v7.h netflow_v9.c netflow_v9.h ipfix.c ipfix.h nfd_raw.c nfd_raw.h

CLEANFILES = *.gch