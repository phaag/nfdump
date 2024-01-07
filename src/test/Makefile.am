
check_PROGRAMS = nftest nfgen
TESTS = nftest runprepare.sh runlzo.sh runlz4.sh

if HAVE_BZIP2
TEST_BZIP2=yes
TESTS += runbz2.sh
endif

if HAVE_ZSTD
TEST_ZSTD=yes
TESTS += runzstd.sh
endif

TESTS += runtest.sh

AM_TESTS_ENVIRONMENT = \
## Set enabled compression
TEST_BZIP2="$(TEST_BZIP2)"; export TEST_BZIP2 \
TEST_ZSTD="$(TEST_ZSTD)"; export TEST_ZSTD \
;

AM_CPPFLAGS = -I.. -I../include -I../lib -I../lib/filter -I../inline -I../netflow -I../collector $(DEPS_CFLAGS)
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