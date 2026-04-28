
check_PROGRAMS = nftest nfgen4 test_append
TESTS = nftest test_prepare.sh test_compress_lzo.sh test_compress_lz4.sh
TESTS += test_append.sh test_nfdump.sh test_collect.sh test_memck.sh test_nfanon.sh

if HAVE_BZ2
TEST_BZIP2=yes
TESTS += test_compress_bz2.sh
endif

if HAVE_ZSTD
TEST_ZSTD=yes
TESTS += test_compress_zstd.sh
endif

if ENABLE_READPCAP
TESTS += test_nfcapd.sh
endif

AM_TESTS_ENVIRONMENT = \
## Set enabled compression
TEST_BZIP2="$(TEST_BZIP2)"; export TEST_BZIP2 \
TEST_ZSTD="$(TEST_ZSTD)"; export TEST_ZSTD \
;

AM_CPPFLAGS = -I.. -I../include -I../libnfdump -I../libnffile -I../inline -I../netflow -I../collector $(DEPS_CFLAGS)
AM_CFLAGS = -ggdb
AM_LDFLAGS  = -L../lib

LDADD = $(DEPS_LIBS)

nfgen4_SOURCES = nfgen4.c
nfgen4_LDADD = -lnffile
nfgen4_LDFLAGS = -L../libnffile

nftest_SOURCES = nftest.c 
nftest_LDADD = -lnfdump -lnffile 
nftest_LDFLAGS = -L../libnfdump -L../libnffile
nftest_DEPENDENCIES = nfgen4

test_append_SOURCES = test_append.c
test_append_LDADD = -lnffile
test_append_LDFLAGS = -L../libnffile

EXTRA_DIST = testsetup.sh \
             test_prepare.sh test_nfdump.sh test_collect.sh test_memck.sh test_nfanon.sh \
             test_append.sh test_nfcapd.sh \
             test_compress_lzo.sh test_compress_lz4.sh test_compress_bz2.sh test_compress_zstd.sh
EXTRA_DIST += ref_raw.txt ref_tstart_sort.txt ref_descending_sort.txt ref_bytes_sort.txt
CLEANFILES = $(check_PROGRAMS) test.flows.nf *.gch 
