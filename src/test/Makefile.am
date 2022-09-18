
check_PROGRAMS = nftest nfgen
TESTS = nftest runtest.sh

AM_CPPFLAGS = -I.. -I../lib -I../netflow $(DEPS_CFLAGS)
AM_CFLAGS = -ggdb
AM_LDFLAGS  = -L../lib

LDADD = $(DEPS_LIBS)

nfgen_SOURCES = nfgen.c
nfgen_LDADD = ../lib/libnfdump.la

nftest_SOURCES = nftest.c 
nftest_LDADD = ../lib/libnfdump.la
nftest_DEPENDENCIES = nfgen


check_DIST = runtest.sh nfdump.test.out nfdump.test.diff
CLEANFILES = $(check_PROGRAMS) test.flows.nf *.gch 