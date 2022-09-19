
AM_CPPFLAGS = -I.. -I../lib -I../include -I../collector -I../nfdump -I../inline $(DEPS_CFLAGS)

noinst_LIBRARIES = libnetflow.a

libnetflow_a_SOURCES = fnf.h netflow_v1.c netflow_v1.h netflow_v5_v7.c netflow_v5_v7.h netflow_v9.c netflow_v9.h ipfix.c ipfix.h

CLEANFILES = *.gch