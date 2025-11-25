
AC_PREREQ([2.71])
AC_INIT([nfdump], [1.7.7], [peter@people.ops-trust.net])

AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([subdir-objects])
AC_CANONICAL_HOST
PKG_PROG_PKG_CONFIG

# --- debugging option for development ---
AC_ARG_ENABLE([devel], [AS_HELP_STRING([--enable-devel], [Enable developer/debug mode (implies --disable-shared)])],
  [enable_devel=$enableval],
  [enable_devel=no])

# --- early set our CFLAGS if not given by user
AS_IF([test -z "$CFLAGS"], [
	AS_IF([test "x$enable_devel" = "xyes"], [CFLAGS="-g -O0"], [CFLAGS="-g -O3"])
])

# --- Prefer clang over gcc ---
AC_PROG_CC([clang gcc])

# --- Require C17 ---
AX_CHECK_C17

# --- add pre-process DEVEL option to include development code
AS_IF([test x$enable_devel = xyes], [
    AC_MSG_NOTICE([developer mode enabled])
		AX_APPEND_FLAG([-DDEVEL],[CFLAGS])
		# --- check for address sanitizer ---
		AX_CHECK_COMPILE_FLAG([-fno-omit-frame-pointer -fsanitize=address],[
			AX_APPEND_FLAG([-fno-omit-frame-pointer -fsanitize=address],[CFLAGS])
		])
		enable_shared=no
])

# --- Add compiler flags
AX_APPEND_FLAG([-Wall],[CFLAGS])
AX_APPEND_FLAG([-Wstrict-prototypes],[CFLAGS])
AX_APPEND_FLAG([-Wmissing-prototypes],[CFLAGS])
AX_APPEND_FLAG([-Wmissing-declarations],[CFLAGS])
AX_APPEND_FLAG([-Wmissing-noreturn],[CFLAGS])
AX_APPEND_FLAG([-fno-strict-aliasing],[CFLAGS])

LT_INIT

# --- LEX/YACC/BISON ---
AC_PROG_LEX(noyywrap)
AC_PROG_YACC
AS_IF([test "$YACC" = ""], [AC_MSG_ERROR([YACC/Bison is required])])
AS_IF([test "$LEX" = ""], [AC_MSG_ERROR([LEX is required])])

# --- Feature flags ---
AC_ARG_ENABLE(ftconv, AS_HELP_STRING([--enable-ftconv],[Enable ft2nfdump flow-tools converter]), enable_ftconv=yes, enable_ftconv=no)
AC_ARG_ENABLE([jnat], AS_HELP_STRING([--enable-jnat],[Enable Junos NAT event logging]), enable_jnat=yes, enable_jnat=no)
AC_ARG_ENABLE([nfprofile], AS_HELP_STRING([--enable-nfprofile],[Enable nfprofile]), enable_nfprofile=yes, enable_nfprofile=no)
AC_ARG_ENABLE([readpcap], AS_HELP_STRING([--enable-readpcap],[Enable reading of pcap file for nfcapd/sfcapd]), enable_readpcap=yes, enable_readpcap=no)
AC_ARG_ENABLE([nfpcapd], AS_HELP_STRING([--enable-nfpcapd],[Enable nfpcapd pcap to netflow collector]), enable_nfpcapd=yes, enable_nfpcapd=no)
AC_ARG_ENABLE([ja4], AS_HELP_STRING([--enable-ja4],[Build with ja4+ fingerprinting code; https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE]), enable_ja4=yes, enable_ja4=no)

AM_CONDITIONAL([BUILD_FT2NFDUMP], [test x$enable_ftconv = xyes])
AM_CONDITIONAL([BUILD_NFPCAPD], [test x$enable_nfpcapd = xyes])
AM_CONDITIONAL([BUILD_NFPROFILE], [test x$enable_nfprofile = xyes])
AM_CONDITIONAL([ENABLE_READPCAP], [test x$enable_readpcap = xyes])
AM_CONDITIONAL([ENABLE_JNAT], [test x$enable_jnat = xyes])
AM_CONDITIONAL([DEVEL_MODE], [test x$enable_devel = xyes])
AM_CONDITIONAL([ENABLE_JA4], [test x$enable_ja4 = xyes])
AS_IF([test x$enable_ja4 = xyes], [
	AC_DEFINE([BUILD_JA4], [1], ["Has $3 installed"])
])

# --- check for big/little endian ---
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <stdint.h>
#include <stdio.h>
]], [[
uint16_t x = 1;
char *c = (char*)&x;
#if *c
#error "Little endian"
#endif
]])],
[AC_DEFINE([WORDS_BIGENDIAN], [1], [Define if big endian])])

# --- Check to see if -latomic is needed for atomic built-ins.
AX_CHECK_ATOMIC
LIBS="$LIBS $LIBATOMIC"

# --- Check to see if -pthread is needed 
AX_PTHREAD([],AC_MSG_ERROR([No valid pthread configuration found]))
LIBS="$LIBS $PTHREAD_LIBS"
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"

# --- Required system headers or definitions ---
AC_CHECK_DECLS([htonll], [have_htonll=yes], [have_htonll=no], [[#include <arpa/inet.h>]])
AS_IF([test "x$have_htonll" = xyes],
	[AC_DEFINE([HAVE_HTONLL], [1], [Define if the system provides htonll()])]
)

# --- all around fts
AC_CHECK_HEADERS(stdio_ext.h)
AC_HEADER_DIRENT
AC_CHECK_HEADERS([fts.h], [have_fts_h=yes], [have_fts_h=no])
AM_CONDITIONAL([NO_FTS], [test x$have_fts_h = xno])
AC_SUBST([NO_FTS])

AC_CHECK_TYPES([union semun],
  [AC_DEFINE([HAVE_SEMUN], [1],[Define if sys/sem.h defines union semun])],
    [],
    [[
      #include <sys/types.h>
      #include <sys/ipc.h>
      #include <sys/sem.h>
    ]]
)

AC_CHECK_FUNCS(fpurge __fpurge)

AC_CHECK_SIZEOF(void *)

AC_CHECK_HEADERS(pcap-bpf.h net/bpf.h net/ethernet.h net/ethertypes.h net/if_pflog.h)

# --- lz4 ---
AC_ARG_WITH([lz4], AS_HELP_STRING([--with-lz4=PATH],[Path to liblz4]), ,with_lz4="")
AS_IF([test "x$with_lz4" = "xno"], [
	# --- disable library search
	HAVE_LZ4=no
	AM_CONDITIONAL([HAVE_LZ4], [false])
	AC_MSG_WARN([Disabled lz4 system library])
], [
	AX_FIND_LIBRARY([LZ4], [lz4.h], [lz4], [$with_lz4], [/usr /usr/local /opt/local])
])
AS_IF([test x$HAVE_LZ4 = xyes], [which_lz4="system library"], which_lz4="embedded")

# --- zstd ---
AC_ARG_WITH([zstd], AS_HELP_STRING([--with-zstd=PATH],[Path to libzstd]), ,with_zstd="")
AS_IF([test "x$with_zstd" = "xno"], [
	# --- disable library search
	HAVE_ZSTD=no
	AM_CONDITIONAL([HAVE_ZSTD], [false])
	AC_MSG_WARN([Disabled zstd compression])
], [
	AX_FIND_LIBRARY([ZSTD], [zstd.h], [zstd], [$with_zstd], [/usr /usr/local /opt/local])
])

# --- bz2 ---
AC_ARG_WITH([bz2], AS_HELP_STRING([--with-bz2=PATH],[Path to libbz2]), ,with_bz2="")
AS_IF([test "x$with_bz2" = "xno"], [
	# --- disable library search
	HAVE_BZ2=no
	AM_CONDITIONAL([HAVE_BZ2], [false])
	AC_MSG_WARN([Disabled bz2 compression])
], [
	AX_FIND_LIBRARY([BZ2], [bzlib.h], [bz2], [$with_bz2], [/usr /usr/local])
])

# --- libpcap  ---
AC_ARG_WITH([pcap], AS_HELP_STRING([--with-pcap=PATH],[Path to libpcap]), ,with_pcap="")
AS_IF([test x$enable_readpcap = xyes || test x$enable_nfpcapd = xyes], [
AX_FIND_LIBRARY([PCAP], [pcap.h], [pcap], [$with_pcap], [/usr /usr/local /opt/local])
	AS_IF([test "x$PCAP_LIBS" = "x"], [AC_MSG_ERROR([libpcap required])])
	# --- check if pcap library provides pcap_dump_open_append() ---
	AC_CHECK_LIB([pcap], [pcap_dump_open_append],
  	[have_pcap_append=yes],
  	[have_pcap_append=no]
	)
	AS_IF([test "x$have_pcap_append" = "xyes"], [
  	AC_DEFINE([HAVE_PCAP_APPEND], [1], [Define if pcap_dump_open_append() is available])
	])
	AM_CONDITIONAL([HAVE_PCAP_APPEND], [test "x$have_pcap_append" = "xyes"])
], [
	AM_CONDITIONAL([HAVE_PCAP], [false])
	AM_CONDITIONAL([HAVE_PCAP_APPEND], [false])
])

# --- zlib for nfpcapd and ftconv ---
AC_ARG_WITH([zlib], AS_HELP_STRING([--with-zlib=PATH],[Path to libz]), ,with_zlib="")
AS_IF([test x$enable_nfpcapd = xyes || test x$enable_ftconv = xyes], [
	AX_FIND_LIBRARY([ZLIB], [zlib.h], [z], [$with_zlib], [/usr /usr/local /opt/local])
	AS_IF([test "x$ZLIB_LIBS" = "x"], [
		readzpcap="no"
	], [ readzpcap="yes"
		])
], [
	AM_CONDITIONAL([HAVE_ZLIB], [false])
])

# --- ft2conv flow-tools converter ---
AC_ARG_WITH([ft], AS_HELP_STRING([--with-ft=PATH],[Path to libft]), ,with_ft="")
AS_IF([test x$enable_ftconv = xyes], [
	AX_FIND_LIBRARY([FT], [ftlib.h], [ft], [$with_ft], [/usr /usr/local /opt/local])
	AS_IF([test "x$FT_LIBS" = "x"], [
		AC_MSG_ERROR([required libft not found for ft2conv. use --with-ft=<path>])
	])
	AS_IF([test "x$ZLIB_LIBS" = "x"], [
		AC_MSG_ERROR([required zlib not found for libft])
	])
], [
	AM_CONDITIONAL([HAVE_FT], [false])
])

# --- nfpcapd build options: Berkely BSD socket or TPACKET_V3, or plain pcap library
AM_COND_IF([BUILD_NFPCAPD],
	[ AC_CHECK_HEADERS([net/bpf.h],
		[AM_CONDITIONAL(BSDBPF, true) AM_CONDITIONAL(TPACKETV3, false) AM_CONDITIONAL(PLAINPCAP, false)],
		[AC_CHECK_DECL([TPACKET_V3],
			[AM_CONDITIONAL(TPACKETV3, true) AM_CONDITIONAL(BSDBPF, false) AM_CONDITIONAL(PLAINPCAP, false)],
			[AM_CONDITIONAL(PLAINPCAP, true) AM_CONDITIONAL(BSDBPF, false) AM_CONDITIONAL(TPACKETV3, false)],
			[[ #include <sys/socket.h>
           	   #include <linux/if_packet.h>]])]
	)],
		[AM_CONDITIONAL(BSDBPF, false) AM_CONDITIONAL(TPACKETV3, false) AM_CONDITIONAL(PLAINPCAP, false)],
)

AC_ARG_WITH([rrd], AS_HELP_STRING([--with-rrd=PATH],[Path to librrd]), ,with_rrd="")
AM_COND_IF([BUILD_NFPROFILE], [
	AX_FIND_LIBRARY([RRD], [rrd.h], [rrd], [$with_rrd], [/usr /usr/local /opt/local])
	AS_IF([test "x$RRD_LIBS" = "x"], [
		AC_MSG_ERROR([required librrd not found for nfprofile. use --with-rrd=<path>])
	])
	AX_RRD_CONSTCHAR
], [
	AM_CONDITIONAL([HAVE_RRD], [false])
	AM_CONDITIONAL([RRDCONSTCHAR], [false])
])

AM_CONDITIONAL([HAVE_DOXYGEN], [false])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
	Makefile
	src/Makefile
	src/inline/Makefile
	src/include/Makefile
	src/libnffile/Makefile
	src/libnfdump/Makefile
	src/output/Makefile
	src/netflow/Makefile
	src/collector/Makefile
	src/nfdump/Makefile
	src/nfcapd/Makefile
	src/sflow/Makefile
	src/nfpcapd/Makefile
	src/nfexpire/Makefile 
	src/nfanon/Makefile
	src/nfreplay/Makefile
	src/nfreader/Makefile 
	src/maxmind/Makefile
	src/tor/Makefile
	src/ft2nfdump/Makefile
	src/nfsen/Makefile
	src/test/Makefile
	man/Makefile
	doc/Makefile
	nfdump.pc
])

AC_OUTPUT

echo ""
echo "----------------------------------"
echo " Build Settings for ${PACKAGE_TARNAME} v${PACKAGE_VERSION}"
echo "----------------------------------"
echo "  host type          = $host_os"
echo "  install dir        = $prefix"
echo "  CC                 = $CC"
echo "  CFLAGS             = $CFLAGS"
echo "  CPPFLAGS           = $CPPFLAGS"
echo "  LDFLAGS            = $LDFLAGS"
echo "  LIBS               = $LIBS $LZ4_LIBS $ZSTD_LIBS $BZ2_LIBS $RRD_LIBS $FT_LIBS"
echo "  Which lz4 code     = $which_lz4"
echo "  Enable libbz2      = $HAVE_BZ2"
echo "  Enable libzstd     = $HAVE_ZSTD"
echo "  Enable ja4         = $enable_ja4"
echo "  Enable read pcap   = $enable_readpcap"
echo "  Build nfpcapd      = $enable_nfpcapd - with gzip pcap-reader: $readzpcap"
echo "  Build nfprofile    = $enable_nfprofile"
echo "  Build ft2nfdump    = $enable_ftconv"
echo "----------------------------------"
echo ""
echo " You can run ./make now." 
echo ""
if test "x$enable_ja4" = "xyes"; then
echo "* Ja4 code enabled."
echo "* JA4: TLS Client Fingerprinting is open-source, BSD 3-Clause"
echo "* All other JA4+ additions are licensed under the FoxIO License 1.1"
echo "* See https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE"
echo "* as well as the license FAQ:"
echo "* https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md"
fi
echo ""
echo "* Many thanks for using nfdump tools"
echo "* See https://github.com/phaag/nfdump/issues"
echo "* For bug open a ticket or send a bug report to peter@people.ops-trust.net"
