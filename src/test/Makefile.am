
check_PROGRAMS = nftest nfgen
TESTS = nftest runprepare.sh runlzo.sh runlz4.sh

if HAVE_BZ2
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

AM_CPPFLAGS = -I.. -I../include -I../libnfdump -I../libnffile -I../inline -I../netflow -I../collector $(DEPS_CFLAGS)
AM_CFLAGS = -ggdb
AM_LDFLAGS  = -L../lib

LDADD = $(DEPS_LIBS)

nfgen_SOURCES = nfgen.c
nfgen_LDADD = -lnffile
nfgen_LDFLAGS = -L../libnffile

nftest_SOURCES = nftest.c 
nftest_LDADD = -lnfdump -lnffile 
nftest_LDFLAGS = -L../libnfdump -L../libnffile
nftest_DEPENDENCIES = nfgen

EXTRA_DIST = runprepare.sh runtest.sh runbz2.sh runlz4.sh runlzo.sh runzstd.sh
EXTRA_DIST += nftest.1.out nftest.2.out nftest.4.out
CLEANFILES = $(check_PROGRAMS) test.flows.nf *.gch 
