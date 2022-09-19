
check_PROGRAMS = nfreader

AM_CPPFLAGS = -I.. -I../include -I../lib -I../inline $(DEPS_CFLAGS)
AM_LDFLAGS  = -L../lib

LDADD = $(DEPS_LIBS)

nfreader_SOURCES = nfreader.c 
nfreader_LDADD = ../lib/libnfdump.la

CLEANFILES = *.gch
