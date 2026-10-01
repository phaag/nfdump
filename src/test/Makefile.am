
check_PROGRAMS = nftest nfgen4 nfgen2 test_append test_rotation
TESTS = nftest test_prepare.sh test_compress_lzo.sh test_compress_lz4.sh
TESTS += test_append.sh test_nfdump.sh test_collect.sh test_memck.sh test_nfanon.sh
TESTS += test_maxmind.sh test_nfexpire.sh test_nfmeta.sh test_timefilter.sh
TESTS += test_rotation

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

AM_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/src/include -I$(top_srcdir)/src/libnfquery -I$(top_srcdir)/src/libnffile -I$(top_srcdir)/src/inline -I$(top_srcdir)/src/netflow -I$(top_srcdir)/src/collector $(DEPS_CFLAGS)
AM_CFLAGS = -ggdb

LDADD = $(DEPS_LIBS)

# Link the libraries of this build tree by their .la files. With -L<dir> -l<lib>
# libtool silently falls back to an installed library of the same name.
NFFILE_LA = $(top_builddir)/src/libnffile/libnffile.la
NFQUERY_LA = $(top_builddir)/src/libnfquery/libnfquery.la

NFFILE_TRANSITIVE_LIBS = $(LZ4_LIBS) $(ZSTD_LIBS) $(BZ2_LIBS) $(LIBSODIUM_LIBS)
NFDUMP_TRANSITIVE_LIBS = $(PCRE2_LIBS) $(NFFILE_TRANSITIVE_LIBS)

nfgen4_SOURCES = nfgen4.c
nfgen4_LDADD = $(NFFILE_LA) $(NFFILE_TRANSITIVE_LIBS)

nfgen2_SOURCES = nfgen2.c
nfgen2_CFLAGS = $(AM_CFLAGS) $(LZ4_CFLAGS)
nfgen2_LDADD = $(NFFILE_LA) $(NFFILE_TRANSITIVE_LIBS)

nftest_SOURCES = nftest.c
nftest_LDADD = $(NFQUERY_LA) $(NFFILE_LA) $(NFDUMP_TRANSITIVE_LIBS)
nftest_DEPENDENCIES = nfgen4 $(NFQUERY_LA) $(NFFILE_LA)

test_append_SOURCES = test_append.c
test_append_LDADD = $(NFFILE_LA) $(NFFILE_TRANSITIVE_LIBS)

test_rotation_SOURCES = test_rotation.c
test_rotation_LDADD = $(NFFILE_LA) $(NFFILE_TRANSITIVE_LIBS)

sflowgen_SOURCES = sflowgen.c
sflowgen_LDFLAGS =

EXTRA_DIST = testsetup.sh \
             test_prepare.sh test_nfdump.sh test_collect.sh test_memck.sh test_nfanon.sh \
             test_append.sh test_nfcapd.sh test_crypto_nfcapd.sh test_maxmind.sh test_nfexpire.sh test_nfmeta.sh test_timefilter.sh \
             test_compress_lzo.sh test_compress_lz4.sh test_compress_bz2.sh test_compress_zstd.sh test_sfcapd.sh \
             sflowgen.c
EXTRA_DIST += ref_raw.txt ref_tstart_sort.txt ref_descending_sort.txt ref_bytes_sort.txt
CLEANFILES = $(check_PROGRAMS) test.flows.nf dummy_flows.nf *.gch

if BUILD_NFPROFILE
TESTS += test_nfprofile.sh
endif
EXTRA_DIST += test_nfprofile.sh test_nfprofile.py
