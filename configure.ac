#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_REVISION($Revision: 244 $)dnl 
AC_INIT([nfdump],[1.7.0],[peter@people.ops-trust.net])

AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([subdir-objects])

AC_CONFIG_MACRO_DIR([m4])

if test "x$CFLAGS" = "x"; then
    CFLAGS="-g -O3"
fi 

# Checks for programs.
AC_PROG_CC([clang gcc])
AX_CHECK_C11
AX_APPEND_FLAG([-Wall], [CFLAGS])
AX_APPEND_FLAG([-Wstrict-prototypes], [CFLAGS])
AX_APPEND_FLAG([-Wmissing-prototypes], [CFLAGS])
AX_APPEND_FLAG([-Wmissing-declarations], [CFLAGS])
AX_APPEND_FLAG([-Wmissing-noreturn], [CFLAGS])
AX_APPEND_FLAG([-fno-strict-aliasing], [CFLAGS])

LT_INIT


dnl
dnl Check to see if -latomic is need for GCC atomic built-ins.
AC_DEFUN([OVS_CHECK_ATOMIC_LIBS],
[AC_SEARCH_LIBS([__atomic_load_8], [atomic], [ATOMIC_LIBS=-latomic])])


AC_ARG_ENABLE(devel,
[  --enable-devel       compile debug and development code into nfdump; default is NO])

# Which way is better?
if test "${enable_devel}" = "yes" ; then
	CFLAGS="$CFLAGS -DDEVEL"
fi

AC_ARG_ENABLE(nsel,
[  --enable-nsel           compile nfdump, to read and process ASA/NSEL/NEL event data; default is NO])

if test "${enable_nsel}" = "yes" ; then
	CFLAGS="$CFLAGS -DNSEL"
fi

AC_ARG_ENABLE(jnat,
[  --enable-jnat           compile nfdump, to read and process Junos NAT event logging; default is NO])

if test "${enable_jnat}" = "yes" ; then
	CFLAGS="$CFLAGS -DNSEL -DJUNOS"
fi

if test "${enable_nsel}" = "yes" -a "${enable_jnat}" = "yes"; then
	AC_MSG_ERROR(You can use only one of --enable-nsel or --enable-jnat. CISCO and Juniper are not compatible.)
fi

AC_ARG_ENABLE(nel,
[  --enable-nel            (depricated) compile nfdump, to read and process NAT/NSEL/NEL event data; default is NO])

if test "${enable_nel}" = "yes" ; then
	CFLAGS="$CFLAGS -DNSEL"
fi

AC_ARG_ENABLE(fixtimebug,
[  --enable-fixtimebug       enable code for swap time bug of some v5 exporters; default is NO])

if test "${enable_fixtimebug}" = "yes" ; then
	CFLAGS="$CFLAGS -DFIXTIMEBUG"
fi

AC_PROG_YACC
AC_PROG_LEX(noyywrap)
which $LEX > /dev/null 2>&1
if test $? = 1; then
	AC_MSG_ERROR(No lex or flex found on system)
fi
AC_PROG_INSTALL

if test "x$ac_cv_prog_LEX" = "xflex"; then
	LFLAGS=-i
fi

# Check if we need to build the flow-tools converter
# FIXME? This should use flow-tools-dev if possible, not local sources.. 
AC_ARG_WITH(ftpath,
[  --with-ftpath=PATH      Expect flow-tool sources in PATH; default /usr/local/flow-tools/],
if test "x$with_ftpath" = "xyes" ; then
	WHERE_FTPATH="/usr/local/flow-tools/"
else
	WHERE_FTPATH=$with_ftpath
fi
,
WHERE_FTPATH="/usr/local/flow-tools/"
)

AC_ARG_WITH(rrdpath,
[  --with-rrdpath=PATH      Expect RRD installed in PATH; default /usr/local],
if test "x$with_rrdpath" = "xyes" ; then
	CPPFLAGS="${CPPFLAGS} -I/usr/local/include"
	LDFLAGS="${LDFLAGS} -L/usr/local/lib"
else
	CPPFLAGS="${CPPFLAGS} -I${with_rrdpath}/include"
	LDFLAGS="${LDFLAGS} -L${with_rrdpath}/lib"
fi
,
)

AC_ARG_WITH(pcappath,
[  --with-pcappath=PATH      Expect libpcap installed in PATH; default /usr/local],
if test "x$with_pcappath" = "xyes" ; then
	CPPFLAGS="${CPPFLAGS} -I/usr/local/include"
	LDFLAGS="${LDFLAGS} -L/usr/local/lib"
else
	CPPFLAGS="${CPPFLAGS} -I${with_pcappath}/include"
	LDFLAGS="${LDFLAGS} -L${with_pcappath}/lib"
fi
,
)

#Tidz up? esp not using in source dist flow-tools
AC_ARG_ENABLE(ftconv,
[  --enable-ftconv         Build the flow-tools to nfdump converter; default is NO],
AC_CHECK_LIB(z, zlibVersion,,
AC_MSG_ERROR(Link with "-lz" failed! (Need zlib >= 1.0.2))
)
if test -d "$WHERE_FTPATH"; then
	if test ! -f "$WHERE_FTPATH/include/ftlib.h"; then
		AC_MSG_ERROR(ftlib.h file not found in flow-tools directory '$WHERE_FTPATH'. Use --with-ftpath=PATH)
	fi
	if test -f "$WHERE_FTPATH/lib/libft.a" -o -f "$WHERE_FTPATH/lib64/libft.a" -o -f "$WHERE_FTPATH/lib/libft.so" -o -f "$WHERE_FTPATH/lib64/libft.so"; then
		FT_INCLUDES="-I$WHERE_FTPATH/include -I$WHERE_FTPATH/lib"
		FT_LDFLAGS="-L$WHERE_FTPATH/lib"
	else
		AC_MSG_ERROR(libft.a not found in flow-tools directory '$WHERE_FTPATH'. Build flow tools first)
	fi
else
	AC_MSG_ERROR(flow-tools directory '$WHERE_FTPATH' does not exists. Use --with-ftpath=PATH)
fi
AM_CONDITIONAL(FT2NFDUMP, true)
,
AM_CONDITIONAL(FT2NFDUMP, false)
)

AC_ARG_ENABLE(maxmind,
[  --enable-maxmind        Build geolookup for MaxMind GeoDB; default is NO],
AM_CONDITIONAL(MAXMIND, true)
,
AM_CONDITIONAL(MAXMIND, false)
)


#Needs tidy
AC_ARG_ENABLE(nfprofile,
[  --enable-nfprofile      Build nfprofile used by NfSen; default is NO],
[ 
	AC_CHECK_LIB(rrd, rrd_update,[
cat >>config.h <<_ACEOF
#define HAVE_LIBRRD 1
_ACEOF
RRD_LIBS="-lrrd"
AC_SUBST(RRD_LIBS)
]
, AC_MSG_ERROR(Can not link librrd. Please specify --with-rrdpath=.. configure failed! ))
	AC_CHECK_HEADERS([rrd.h])
	if test "$ac_cv_header_rrd_h" = yes; then
		AM_CONDITIONAL(NFPROFILE, true)
	else
		AC_MSG_ERROR(Required rrd.h header file not found!)
	fi
	AC_RUN_IFELSE(
		[ AC_LANG_PROGRAM(
			[[
				#include <stdio.h>
				#include <rrd.h>
			]],
            [[ 
				rrd_value_t d; 
			]])
		],, AC_MSG_ERROR(Can not load rrd library. Not in loader search path! ))

]
,
AM_CONDITIONAL(NFPROFILE, false)
)

AC_ARG_ENABLE(influxdb, [AS_HELP_STRING([--enable-influxdb], [enable stats to influxdb (default is no)])], [
   influxdb=${enableval} ], [influxdb=no])
AS_IF([test "x$influxdb" = xyes], [ 
	PKG_CHECK_MODULES([curl], [libcurl],,
	    [AC_MSG_ERROR([No pkg-config for libcurl])])
	AC_SUBST(CURL_CFLAGS)
	AC_SUBST(CURL_LIBS)
	#CFLAGS="${CFLAGS} ${CURL_CFLAGS}"
	#LIBS="${LIBS} ${LIBS_CFLAGS}"
	
	AC_CHECK_LIB([curl], [curl_easy_init],,[AC_MSG_ERROR([libcurl required!])])
	AC_CHECK_LIB([curl], [curl_easy_escape],,[AC_MSG_ERROR([libcurl required!])])
	AC_CHECK_LIB([curl], [curl_easy_setopt],,[AC_MSG_ERROR([libcurl required!])])
	AC_CHECK_LIB([curl], [curl_easy_cleanup],,[AC_MSG_ERROR([libcurl required!])])
	AC_CHECK_LIB([curl], [curl_free],,[AC_MSG_ERROR([libcurl required!])])
	
	AC_DEFINE_UNQUOTED(HAVE_INFLUXDB, 1, [enable stats to influxdb])
	AM_CONDITIONAL(INFLXDB, true)
], 
AM_CONDITIONAL(INFLXDB, false)
)

AC_ARG_ENABLE(nftrack,
[  --enable-nftrack      Build nftrack used by PortTracker; default is NO],
[ 
	AC_CHECK_LIB(rrd, rrd_update,[
cat >>config.h <<_ACEOF
#define HAVE_LIBRRD 1
_ACEOF
RRD_LIBS="-lrrd"
AC_SUBST(RRD_LIBS)
]
, AC_MSG_ERROR(Can not link librrd. Please specify --with-rrdpath=.. configure failed! ))
	AC_CHECK_HEADERS([rrd.h])
	if test "$ac_cv_header_rrd_h" = yes; then
		AM_CONDITIONAL(NFTRACK, true)
	else
		AC_MSG_ERROR(Required rrd.h header file not found!)
	fi
	AC_RUN_IFELSE(
		[ AC_LANG_PROGRAM(
			[[
				#include <stdio.h>
				#include <rrd.h>
			]],
            [[ 
				rrd_value_t d; 
			]])
		],, AC_MSG_ERROR(Can not load rrd library. Not in loader search path! ))

]
,
AM_CONDITIONAL(NFTRACK, false)
)

AC_ARG_ENABLE(sflow,
[  --enable-sflow          Build sflow collector sfcpad; default is NO])
AM_CONDITIONAL(SFLOW, test "$enable_sflow" = yes)

AC_ARG_ENABLE(readpcap,
[  --enable-readpcap       Build nfcapd collector to read from pcap file instead of network data; default is NO])
AM_CONDITIONAL(READPCAP, test "$enable_readpcap" = yes)

AC_ARG_ENABLE(nfpcapd,
[  --enable-nfpcapd       Build nfpcapd collector to create netflow data from interface or pcap data; default is NO],
[ 
	AC_CHECK_LIB(pcap, pcap_create,[
cat >>config.h <<_ACEOF
#define HAVE_LIBPCAP 1
_ACEOF
PCAP_LIBS="-lpcap"
AC_SUBST(PCAP_LIBS)
]
, AC_MSG_ERROR(Can not link libpcap. Please specify --with-pcappath=.. configure failed! ))
	AC_CHECK_HEADERS([pcap.h])
	if test "$ac_cv_header_pcap_h" = yes; then
		AM_CONDITIONAL(BUILDNFPCAPD, true)
	else
		AC_MSG_ERROR(Required pcap.h header file not found!)
	fi
	AC_RUN_IFELSE(
		[ AC_LANG_PROGRAM(
			[[
				#include <stdio.h>
				#include <pcap.h>
			]],
            [[ 
				struct pcap_pkthdr p; 
			]])
		],, AC_MSG_ERROR(Can not load pcap library. Not in loader search path! ))

]
,
AM_CONDITIONAL(BUILDNFPCAPD, false)
)

## Check for BSD socket or TPACKET_V3
AM_COND_IF([BUILDNFPCAPD],
	[AC_CHECK_HEADERS([net/bpf.h],
		[AM_CONDITIONAL(BSDBPF, true) AM_CONDITIONAL(TPACKETV3, false) AM_CONDITIONAL(PLAINPCAP, false)],
		[AC_CHECK_DECL([TPACKET_V3],
			[AM_CONDITIONAL(TPACKETV3, true) AM_CONDITIONAL(BSDBPF, false) AM_CONDITIONAL(PLAINPCAP, false)],
			[AM_CONDITIONAL(PLAINPCAP, true) AM_CONDITIONAL(BSDBPF, false) AM_CONDITIONAL(TPACKETV3, false)],
			[[ #include <sys/socket.h>
           	   #include <linux/if_packet.h>]])]
	)],
		[AM_CONDITIONAL(BSDBPF, false) AM_CONDITIONAL(TPACKETV3, false) AM_CONDITIONAL(PLAINPCAP, false)],
)

OVS_CHECK_ATOMIC_LIBS
AX_PTHREAD([],AC_MSG_ERROR(No valid pthread configuration found))

LIBS="$PTHREAD_LIBS $LIBS"
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
CC="$PTHREAD_CC"

# Check for structures
AC_CHECK_MEMBER([struct sockaddr.sa_len],
 AC_DEFINE(HAVE_SOCKADDR_SA_LEN, 1, define if socket address structures have length fields),,[
#include <sys/types.h>
#include <sys/socket.h>])

AC_CHECK_MEMBERS([struct sockaddr_storage.ss_family,
		  struct sockaddr_storage.__ss_family,
		  struct sockaddr_storage.ss_len,
		  struct sockaddr_storage.__ss_len,
		  struct sockaddr.sa_len], [], [], [
#include <sys/types.h>
#include <sys/socket.h>
])

#AC_SUBST(opt_objects)
AC_SUBST(FT_INCLUDES)
AC_SUBST(FT_LDFLAGS)
AC_SUBST(LFLAGS)


# Checks for libraries.
AC_CHECK_FUNCS(gethostbyname,,[AC_CHECK_LIB(nsl,gethostbyname,,[AC_CHECK_LIB(socket,gethostbyname)])])
AC_CHECK_FUNCS(setsockopt,,[AC_CHECK_LIB(socket,setsockopt)])

dnl checks for fpurge or __fpurge
AC_CHECK_FUNCS(fpurge __fpurge)

AC_MSG_CHECKING([if htonll is defined])

dnl # Check for htonll
AC_LINK_IFELSE(
  [AC_LANG_PROGRAM(
     [[
        #include <arpa/inet.h>
     ]],
     [[
       return htonll(0);
     ]]
  )],
  [
    AC_MSG_RESULT(yes)
    AC_DEFINE(HAVE_HTONLL, 1, [Define to 1 if the function (or macro) htonll exists.])
  ],
  [
    AC_MSG_RESULT(no)
  ]
)

# Checks for header files.
AC_HEADER_DIRENT
# Autoupdate added the next two lines to ensure that your configure
# script's behavior did not change.  They are probably safe to remove.
AC_CHECK_INCLUDES_DEFAULT
AC_PROG_EGREP

AC_CHECK_HEADERS(stdio_ext.h)
AC_CHECK_HEADERS([nameser8_compat.h])
AC_CHECK_HEADERS([features.h arpa/inet.h fcntl.h netinet/in.h fts.h stdint.h stdlib.h stddef.h string.h sys/socket.h syslog.h unistd.h iso/limits_iso.h])
AC_CHECK_HEADERS(pcap-bpf.h net/bpf.h net/ethernet.h net/ethertypes.h)

AC_CHECK_HEADERS(sys/types.h netinet/in.h arpa/nameser.h arpa/nameser_compat.h netdb.h resolv.h netinet/in_systm.h,
                 [], [],
[[#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>   /* inet_ functions / structs */
#endif
#ifdef HAVE_ARPA_NAMESER_H
#  include <arpa/nameser.h> /* DNS HEADER struct */
#endif
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif]])


AC_CHECK_HEADERS([bzlib.h])
if test "$ac_cv_header_bzlib_h" = no; then
	AC_MSG_ERROR(Required bzlib.h header file not found!)
fi

if test "$ac_cv_header_fts_h" != yes; then
	FTS_OBJ=fts_compat.o
  AM_CONDITIONAL(NEEDFTSCOMPAT, true)
else 
  AM_CONDITIONAL(NEEDFTSCOMPAT, false)
fi


# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_SIZEOF(void *)

AC_C_CONST
AC_C_INLINE
AC_C_BIGENDIAN

AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_STRUCT_TM
AC_HEADER_STDBOOL

# Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_REALLOC
AC_FUNC_STAT
AC_FUNC_STRFTIME
AC_CHECK_FUNCS(inet_ntoa socket strchr strdup strerror strrchr strstr scandir)

dnl The res_search may be in libsocket as well, and if it is
dnl make sure to check for dn_skipname in libresolv, or if res_search
dnl is in neither of these libs, still check for dn_skipname in libresolv
AC_CHECK_LIB(socket, res_search, [
 AC_CHECK_LIB(resolv, dn_skipname)
 AC_CHECK_LIB(resolv, __dn_skipname)
 LIBS="$LIBS -lsocket"
 AC_DEFINE(HAVE_LIBSOCKET,1,[ ]) ], [
 AC_CHECK_LIB(resolv, res_search, [
  LIBS="$LIBS -lresolv"
  AC_DEFINE(HAVE_LIBRESOLV,1,[ ]) 
 ], [
  AC_CHECK_LIB(resolv, dn_skipname)
  AC_CHECK_LIB(resolv, __dn_skipname)
 ]) 
])

AC_CHECK_LIB(bz2, BZ2_bzCompressInit, [
 LIBS="$LIBS -lbz2"
 ], [])

# lzo compression requirements
AC_CHECK_TYPE(ptrdiff_t, long)
AC_TYPE_SIZE_T
AC_CHECK_SIZEOF(short)
AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(long)
AC_CHECK_SIZEOF(long long)
AC_CHECK_SIZEOF(__int64)
AC_CHECK_SIZEOF(void *)
AC_CHECK_SIZEOF(size_t)
AC_CHECK_SIZEOF(time_t)
AC_CHECK_SIZEOF(ptrdiff_t)
AC_C_CONST
AC_CHECK_FUNCS(memcmp memcpy memmove memset)

AC_MSG_CHECKING([for union semun])
AC_CACHE_VAL(ac_cv_struct_semun,
	[
		AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
			#include <sys/types.h>
	 		#include <sys/ipc.h>
			#include <sys/sem.h>;
		]], [[
			union semun semdat;
		]])],[ac_cv_struct_semun=yes],[ac_cv_struct_semun=no
		])
	]
)

AC_MSG_RESULT($ac_cv_struct_semun)
if test "$ac_cv_struct_semun" = "yes"; then
	AC_DEFINE(HAVE_SEMUN, 1, [Define if sys/sem.h defines struct semun])
fi

AC_MSG_CHECKING(for the %z format string in printf())
AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <stdio.h>
#include <sys/types.h>

int main() {
int 	i;
size_t	s;
char	string[16];

	s = 12345;
	i = snprintf(string,16,"%zu", s);

	return i == 5 ? 0 : 1;
}
]])],[
	AC_MSG_RESULT(yes)
	AC_DEFINE([HAVE_SIZE_T_Z_FORMAT], [1],
                                      [Define to 1 if you have a printf() that supports the %z format string.])
],[
	AC_MSG_RESULT(no)
],[
	AC_MSG_RESULT(no)

])

AC_PATH_PROG([DOXYGEN], [doxygen], [])
AM_CONDITIONAL([HAVE_DOXYGEN], [test -n "$DOXYGEN"])
AM_COND_IF([HAVE_DOXYGEN], AC_CONFIG_FILES([doc/Doxyfile]))
AC_CONFIG_FILES([doc/Makefile])
AC_OUTPUT

AC_CONFIG_FILES([Makefile src/lib/Makefile src/Makefile src/test/Makefile
	src/output/Makefile src/conf/Makefile src/netflow/Makefile src/collector/Makefile
	src/maxmind/Makefile src/nfdump/Makefile src/nfcapd/Makefile src/nfexpire/Makefile 
	src/nfanon/Makefile src/nfreplay/Makefile src/nfreader/Makefile 
	src/inline/Makefile src/include/Makefile man/Makefile ])


if test "x$enable_ftconv" = "xyes"; then
    AC_CONFIG_FILES([src/ft2nfdump/Makefile])
fi

if test "x$enable_sflow" = "xyes"; then
    AC_CONFIG_FILES([src/sflow/Makefile])
fi

if test "x$enable_nfpcapd" = "xyes"; then
    AC_CONFIG_FILES([src/nfpcapd/Makefile])
fi

if test "x$enable_nfprofile" = "xyes"; then
    AC_CONFIG_FILES([src/nfsen/Makefile])
fi

AC_OUTPUT

echo ""
echo "----------------------------------"
echo " Build Settings for ${PACKAGE_TARNAME} v${PACKAGE_VERSION}"
echo "----------------------------------"
echo "  host type            = $host_os"
echo "  install dir          = $prefix"
echo "  CC                   = $CC"
echo "  CFLAGS               = $AM_CFLAGS $CFLAGS"
echo "  CPPFLAGS             = $AM_CPPFLAGS $CPPFLAGS"
echo "  LDFLAGS              = $AM_LDFLAGS $LDFLAGS"
echo "  LIBS                 = $LIBS"
echo "  Build geolookup      = $enable_maxmind"
echo "  Build sflow          = $enable_sflow"
echo "  Build nfpcapd        = $enable_nfpcapd"
echo "  Build flowtools conv = $enable_ftconv"
echo "  Build nfprofile      = $enable_nfprofile"
echo "----------------------------------"
echo ""
echo " You can run ./make now." 
echo ""
echo "* Many thanks for using nfdump tools"
echo "* See https://github.com/phaag/nfdump/issues"
echo "* For bug open a ticket or send a bug report to peter@people.ops-trust.net"
