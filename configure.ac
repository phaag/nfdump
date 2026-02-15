
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
		AX_APPEND_FLAG([-Wextra], [CFLAGS])
		#AX_APPEND_FLAG([-Wsign-conversion], [CFLAGS])
		#AX_APPEND_FLAG([-fsanitize=undefined], [CFLAGS])
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
AC_ARG_ENABLE([native], [AS_HELP_STRING([--enable-native], [Use -march=native if supported for running on local system])], [enable_native=$enableval], [enable_native=no])
AC_ARG_ENABLE([lto], AS_HELP_STRING([--enable-lto], [Enable link-time optimization (LTO) if supported]), [enable_lto=$enableval], [enable_lto=no])


AM_CONDITIONAL([BUILD_FT2NFDUMP], [test x$enable_ftconv = xyes])
AM_CONDITIONAL([BUILD_NFPCAPD], [test x$enable_nfpcapd = xyes])
AM_CONDITIONAL([BUILD_NFPROFILE], [test x$enable_nfprofile = xyes])
AM_CONDITIONAL([ENABLE_READPCAP], [test x$enable_readpcap = xyes])
AM_CONDITIONAL([ENABLE_JNAT], [test x$enable_jnat = xyes])
AM_CONDITIONAL([DEVEL_MODE], [test x$enable_devel = xyes])
AM_CONDITIONAL([ENABLE_JA4], [test x$enable_ja4 = xyes])
AS_IF([test x$enable_ja4 = xyes], [
	AC_DEFINE([BUILD_JA4], [1], ["Enable a4 code"])
])
AS_IF([test x$enable_readpcap = xyes], [
	AC_DEFINE([ENABLE_READPCAP], [1], ["Enable read pcap code in collectors"])
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

# Initialize the native CFLAG variable
NATIVE_CFLAGS=""

# append -march=native for optimised vector code unless disabled
AS_IF([test x$enable_native != xno], [
		AX_CHECK_COMPILE_FLAG([-march=native], [
			AX_APPEND_FLAG([-march=native],[CFLAGS])
		])
])

AS_IF([test "x$enable_lto" = "xyes"], [
  AC_MSG_CHECKING([whether the compiler supports -flto])
  AX_CHECK_COMPILE_FLAG([-flto], [have_lto_cc=yes], [have_lto_cc=no])

  AC_MSG_CHECKING([whether the linker supports -flto])
  AX_CHECK_LINK_FLAG([-flto], [have_lto_ld=yes], [have_lto_ld=no])

  AS_IF([test "x$have_lto_cc" = "xyes" -a "x$have_lto_ld" = "xyes"], [
      AC_MSG_NOTICE([LTO enabled])
      AX_APPEND_FLAG([-flto], [CFLAGS])
      AX_APPEND_FLAG([-flto], [LDFLAGS])
  ], [
      AC_MSG_WARN([LTO requested but not supported by compiler or linker])
  ])
])

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

AC_CHECK_FUNCS([fpurge __fpurge])

# --- check for arc4random
dnl Initialize EXTRA_LIBS
RAND_LIBS=""
AC_CHECK_FUNCS([arc4random])

# --- If not found, try libbsd
AS_IF([test "x$ac_cv_func_arc4random" != "xyes"], [
    AC_CHECK_LIB([bsd], [arc4random],
        [
            RAND_LIBS="$RAND_LIBS -lbsd"
            AC_DEFINE([HAVE_ARC4RANDOM], [1], [Define if arc4random() is available])
						AC_DEFINE([HAVE_LIBBSD], [1], [Define if arc4random() comes from libbsd])
        ], [ AC_MSG_ERROR([required function arc4random() not found - try to install libbsd])])
])
AC_SUBST([RAND_LIBS])

AC_CHECK_SIZEOF(void *)

AC_CHECK_HEADERS(pcap-bpf.h net/bpf.h net/ethernet.h net/ethertypes.h net/if_pflog.h)


# --- lz4 ---
AX_CHECK_LIB_GENERIC([LZ4], [lz4.h], [lz4],
  [AC_MSG_NOTICE([Found LZ4])],
  [AC_MSG_WARN([LZ4 not found; using embedded version])]
)
AS_IF([test x$HAVE_LZ4 = xyes], [which_lz4="system library"], which_lz4="embedded")

# --- zstd ---
AX_CHECK_LIB_GENERIC([ZSTD], [zstd.h], [zstd],
  [AC_MSG_NOTICE([Found ZSTD])],
  [AC_MSG_WARN([ZSTD not found; disabling zstd])]
)

# --- bz2 ---
AX_CHECK_LIB_GENERIC([BZ2], [bzlib.h], [bz2],
  [AC_MSG_NOTICE([Found BZ2])],
  [AC_MSG_WARN([Bzip2 not found; disabling bz2])]
)

# --- zlib, if we need it later  ---
AX_CHECK_LIB_GENERIC([ZLIB], [zlib.h], [z],
  [AC_MSG_NOTICE([Found zlib])],
  []
)


# --- libpcap  ---
AS_IF([test x$enable_readpcap = xyes || test x$enable_nfpcapd = xyes], [

  AX_CHECK_LIB_GENERIC([PCAP], [pcap.h], [pcap],
    [
      # --- temporarily inject PCAP flags for the symbol check
      save_CPPFLAGS="$CPPFLAGS"
      save_LDFLAGS="$LDFLAGS"
      CPPFLAGS="$CPPFLAGS $PCAP_CFLAGS"
      LDFLAGS="$LDFLAGS $PCAP_LIBS"

      AC_CHECK_LIB([pcap], [pcap_dump_open_append], [
  			AM_CONDITIONAL([HAVE_PCAP_APPEND], [true])
        AC_DEFINE([HAVE_PCAP_APPEND], [1],
          [Define if pcap_dump_open_append() exists])
      ], [
  			AM_CONDITIONAL([HAVE_PCAP_APPEND], [false])
			])

      CPPFLAGS="$save_CPPFLAGS"
      LDFLAGS="$save_LDFLAGS"
    ],
    [
      AC_MSG_ERROR([required libpcap not found. Try --with-pcap=path-to-libpcap])
  		AM_CONDITIONAL([HAVE_PCAP_APPEND], [false])
    ]
  )
], [
  AM_CONDITIONAL([HAVE_PCAP], [false])
  AM_CONDITIONAL([HAVE_PCAP_APPEND], [false])
])

# --- optional zlib for nfpcapd ---
AS_IF([test x$enable_nfpcapd = xyes], [
	AS_IF([test "x$ZLIB_LIBS" = "x"], [
		readzpcap="no"
	], [
		readzpcap="yes"
	])
])

# --- ft2conv flow-tools converter ---
AS_IF([test x$enable_ftconv = xyes], [
	# --- requires zlib ---
	AS_IF([test "x$ZLIB_LIBS" = "x"], [
		AC_MSG_ERROR([required zlib for libft not found. Try --with-zlib=path-to-libz])
	])
  AX_CHECK_LIB_GENERIC([FT], [ftlib.h], [ft],
    [AC_MSG_NOTICE([Found libft])],
    [AC_MSG_ERROR([required libft for ft2nfdump not found. Try --with-ft=path-to-libft])]
  )
], [AM_CONDITIONAL([HAVE_FT], [false])] )

# --- nfpcapd build options: Berkely BSD socket or TPACKET_V3, or plain pcap library
AM_COND_IF([BUILD_NFPCAPD],
	[ AC_CHECK_HEADERS([net/bpf.h],
		[AC_DEFINE([USE_BPFSOCKET], [1], [Use BSD BPF for packet collection])
		 AM_CONDITIONAL(BSDBPF, true) AM_CONDITIONAL(TPACKETV3, false) AM_CONDITIONAL(PLAINPCAP, false)],
		[AC_CHECK_DECL([TPACKET_V3],
			[ AC_DEFINE([USE_TPACKETV3], [1], [Use Linux TPACKETV3 for packet collection])
				AM_CONDITIONAL(TPACKETV3, true) AM_CONDITIONAL(BSDBPF, false) AM_CONDITIONAL(PLAINPCAP, false)],
			[AM_CONDITIONAL(PLAINPCAP, true) AM_CONDITIONAL(BSDBPF, false) AM_CONDITIONAL(TPACKETV3, false)],
			[[ #include <sys/socket.h>
           	   #include <linux/if_packet.h>]])]
	)],
		[AM_CONDITIONAL(BSDBPF, false) AM_CONDITIONAL(TPACKETV3, false) AM_CONDITIONAL(PLAINPCAP, false)],
)

AS_IF([test x$enable_nfprofile = xyes], [
	# --- check for rrd library
  AX_CHECK_LIB_GENERIC([RRD], [rrd.h], [rrd],
    [AX_RRD_CONSTCHAR],

    [ AM_CONDITIONAL([RRDCONSTCHAR], [false])
      AC_MSG_ERROR([required librrd for nfprofile not found. Try --with-rrd=path-to-librrd])
    ]
  )

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
