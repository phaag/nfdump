
check_PROGRAMS = nftest nfgen4 test_append
TESTS = nftest test_prepare.sh test_compress_lzo.sh test_compress_lz4.sh
TESTS += test_append.sh test_nfdump.sh test_collect.sh test_memck.sh test_nfanon.sh
TESTS += test_maxmind.sh test_nfexpire.sh

if HAVE_LIBSODIUM
TESTS += test_crypto_nfcapd.sh
endif

if HAVE_BZ2
TEST_BZIP2=yes
TESTS += test_compress_bz2.sh
endif

if HAVE_ZSTD
TEST_ZSTD=yes
TESTS += test_compress_zstd.sh
endif

if ENABLE_READPCAP
check_PROGRAMS += sflowgen
TESTS += test_nfcapd.sh test_sfcapd.sh
endif

AM_TESTS_ENVIRONMENT = \
BINDIR="$(abs_builddir)/.."; export BINDIR; \
## Set enabled compression
TEST_BZIP2="$(TEST_BZIP2)"; export TEST_BZIP2 \
TEST_ZSTD="$(TEST_ZSTD)"; export TEST_ZSTD \
;

AM_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/src/include -I$(top_srcdir)/src/libnfdump -I$(top_srcdir)/src/libnffile -I$(top_srcdir)/src/inline -I$(top_srcdir)/src/netflow -I$(top_srcdir)/src/collector $(DEPS_CFLAGS)
AM_CFLAGS = -ggdb
AM_LDFLAGS  = -L../lib

LDADD = $(DEPS_LIBS)

NFFILE_TRANSITIVE_LIBS = $(LZ4_LIBS) $(ZSTD_LIBS) $(BZ2_LIBS) $(LIBSODIUM_LIBS)
NFDUMP_TRANSITIVE_LIBS = $(PCRE2_LIBS) $(NFFILE_TRANSITIVE_LIBS)

nfgen4_SOURCES = nfgen4.c
nfgen4_LDADD = -lnffile $(NFFILE_TRANSITIVE_LIBS)
nfgen4_LDFLAGS = -L../libnffile

nftest_SOURCES = nftest.c
nftest_LDADD = -lnfdump -lnffile $(NFDUMP_TRANSITIVE_LIBS)
nftest_LDFLAGS = -L../libnfdump -L../libnffile
nftest_DEPENDENCIES = nfgen4

test_append_SOURCES = test_append.c
test_append_LDADD = -lnffile $(NFFILE_TRANSITIVE_LIBS)
test_append_LDFLAGS = -L../libnffile

sflowgen_SOURCES = sflowgen.c
sflowgen_LDFLAGS =

EXTRA_DIST = testsetup.sh \
             test_prepare.sh test_nfdump.sh test_collect.sh test_memck.sh test_nfanon.sh \
             test_append.sh test_nfcapd.sh test_crypto_nfcapd.sh test_maxmind.sh test_nfexpire.sh \
             test_compress_lzo.sh test_compress_lz4.sh test_compress_bz2.sh test_compress_zstd.sh test_sfcapd.sh \
             sflowgen.c
EXTRA_DIST += ref_raw.txt ref_tstart_sort.txt ref_descending_sort.txt ref_bytes_sort.txt
CLEANFILES = $(check_PROGRAMS) test.flows.nf dummy_flows.nf *.gch
