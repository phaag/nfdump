#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_REVISION($Revision: 243 $)dnl 
AC_INIT(nfdump, 1.6.13, phaag@users.sourceforge.net)
# $Date: 2014-11-16 14:10:20 +0100 (Sun, 16 Nov 2014) $
#AC_CONFIG_SRCDIR([grammar.y])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE([subdir-objects])
 
# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

dnl get the flags
CFLAGS="${CFLAGS=}"
if test $ac_cv_prog_gcc = yes -a "x$CFLAGS" = "x-g -O2"; then
	CFLAGS="-g -O2 -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wmissing-noreturn -fno-strict-aliasing"
fi

AC_ARG_ENABLE(devel,
[  --enable-devel       compile debug and development code into nfdump; default is NO])

# Which way is better?
if test "${enable_devel}" = "yes" ; then
	CFLAGS="$CFLAGS -DDEVEL"
cat >>config.h <<_ACEOF
#define dbg_printf(...) printf(__VA_ARGS__)
_ACEOF
else
cat >>config.h <<_ACEOF
#define dbg_printf(...) /* printf(__VA_ARGS__) */
_ACEOF
fi

AC_ARG_ENABLE(compat15,
[  --enable-compat15       compile nfdump, to read nfdump data files created with nfdump 1.5.x; default is NO])

if test "${enable_compat15}" = "yes" ; then
	CFLAGS="$CFLAGS -DCOMPAT15"
fi

AC_ARG_ENABLE(nsel,
[  --enable-nsel           compile nfdump, to read and process ASA/NSEL/NEL event data; default is NO])

if test "${enable_nsel}" = "yes" ; then
	CFLAGS="$CFLAGS -DNSEL"
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
AC_PROG_LEX
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
	if test ! -f "$WHERE_FTPATH/lib/libft.a"; then
		AC_MSG_ERROR(libft.a not found in flow-tools directory '$WHERE_FTPATH'. Build flow tools first)
	fi
	FT_INCLUDES="-I$WHERE_FTPATH/include -I$WHERE_FTPATH/lib"
	FT_LDFLAGS="-L$WHERE_FTPATH/lib"
else
	AC_MSG_ERROR(flow-tools directory '$WHERE_FTPATH' does not exists. Use --with-ftpath=PATH)
fi
AM_CONDITIONAL(FT2NFDUMP, true)
,
AM_CONDITIONAL(FT2NFDUMP, false)
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
[  --enable-nfpcapd       Build nfpcapd collector to create netflow data from interface or pcap data; default is NO])
AM_CONDITIONAL(BUILDNFPCAPD, test "$enable_nfpcapd" = yes)

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
AC_HEADER_STDC
AC_CHECK_HEADERS([nameser8_compat.h])
AC_CHECK_HEADERS([features.h arpa/inet.h fcntl.h netinet/in.h fts.h stdint.h stdlib.h stddef.h string.h sys/socket.h syslog.h unistd.h iso/limits_iso.h])
AC_CHECK_HEADERS(pcap-bpf.h net/bpf.h)

AC_CHECK_HEADERS(sys/types.h netinet/in.h arpa/nameser.h arpa/nameser_compat.h netdb.h resolv.h,
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


if test "$ac_cv_header_fts_h" != yes; then
	FTS_OBJ=fts_compat.o
fi
AC_SUBST(FTS_OBJ)


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
AC_CHECK_SIZEOF(ptrdiff_t)
AC_C_CONST
AC_CHECK_FUNCS(memcmp memcpy memmove memset)

AC_MSG_CHECKING([for union semun])
AC_CACHE_VAL(ac_cv_struct_semun,
	[
		AC_TRY_COMPILE(
		[
			#include <sys/types.h>
	 		#include <sys/ipc.h>
			#include <sys/sem.h>;
		],
		[
			union semun semdat;
		],
		ac_cv_struct_semun=yes, ac_cv_struct_semun=no
		)
	]
)

AC_MSG_RESULT($ac_cv_struct_semun)
if test "$ac_cv_struct_semun" = "yes"; then
	AC_DEFINE(HAVE_SEMUN, 1, [Define if sys/sem.h defines struct semun])
fi

AC_MSG_CHECKING(for the %z format string in printf())
AC_TRY_RUN([
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
],
[
	AC_MSG_RESULT(yes)
	AC_DEFINE([HAVE_SIZE_T_Z_FORMAT], [1],
                                      [Define to 1 if you have a printf() that supports the %z format string.])
],
[
	AC_MSG_RESULT(no)
],
[
	AC_MSG_RESULT(no)
]
)

#AC_CONFIG_FILES([Makefile])
AC_OUTPUT(Makefile bin/Makefile man/Makefile)

echo ""
echo "* Many thanks for using nfdump tools"
echo "* You may want to subscribe to the nfdump-discuss and/or"
echo "* nfsen-discuss mailing list:"
echo "* http://lists.sourceforge.net/lists/listinfo/nfdump-discuss"
echo "* http://lists.sourceforge.net/lists/listinfo/nfsen-discuss"
echo "* Please send bug reports back to me: phaag@users.sourceforge.net"
echo "* or to one of the lists."

