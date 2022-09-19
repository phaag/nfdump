
check_PROGRAMS = nftest nfgen
TESTS = nftest runtest.sh

AM_CPPFLAGS = -I.. -I../include -I../lib -I../inline -I../netflow -I../collector $(DEPS_CFLAGS)
AM_CFLAGS = -ggdb
AM_LDFLAGS  = -L../lib

LDADD = $(DEPS_LIBS)

nfgen_SOURCES = nfgen.c
nfgen_LDADD = ../lib/libnfdump.la

nftest_SOURCES = nftest.c 
nftest_LDADD = ../lib/libnfdump.la
nftest_DEPENDENCIES = nfgen

EXTRA_DIST = runtest.sh nftest.1.out nftest.2.out 
CLEANFILES = $(check_PROGRAMS) test.flows.nf *.gch 