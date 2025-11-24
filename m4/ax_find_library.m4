# AX_FIND_LIBRARY(MODULE, HEADER, LIBNAME, PREFIX, [SEARCH_PATHS])
#
# MODULE       = prefix for variable names (e.g. LZ4)
# HEADER       = header file (e.g. lz4.h)
# LIBNAME      = library base name without "lib" (e.g. lz4)
# PREFIX       = user-supplied path or empty
# SEARCH_PATHS = optional list of fallback prefixes
#
# Produces:
#   HAVE_MODULE
#   MODULE_CFLAGS
#   MODULE_LIBS
# + AM_CONDITIONAL(HAVE_MODULE)
# + AC_DEFINE([HAVE_MODULE], [1], ["Has LIBNAME installed"]

AC_DEFUN([AX_FIND_LIBRARY],
[
  dnl --- MODULE = $1, HEADER=$2, LIBNAME=$3, PREFIX=$4, SEARCHPATHS=$5 ---
  dnl --- fallback paths if $5 is empty ---
  m4_if([$5], [], [SEARCHPATHS="/usr /usr/local /opt/local"], [SEARCHPATHS="$5"])

  dnl --- initialize ---
  HAVE_$1=no
  $1_CFLAGS=""
  $1_LIBS=""

  dnl --- user-supplied prefix ---
  AS_IF([test -n "$4"], [
    AC_MSG_CHECKING([for $2 in $4/include])
    AS_IF([test -f "$4/include/$2"], [
      AC_MSG_RESULT([found])
      AC_MSG_CHECKING([for lib$3 in $4/lib])
      AS_IF([ls "$4/lib/lib$3".* >/dev/null 2>&1], [
        AC_MSG_RESULT([found])
        HAVE_$1=yes
        $1_CFLAGS="-I$4/include"
        $1_LIBS="-L$4/lib -l$3"
        AC_DEFINE([HAVE_$1], [1], ["Has $3 installed"])
      ], [AC_MSG_ERROR([lib$3 not found in $4/lib])])
    ], [AC_MSG_ERROR([$2 not found in $4/include])])
  ], [
    dnl --- try pkg-config ---
    PKG_CHECK_MODULES([$1],[lib$3],[
      HAVE_$1=yes
      AC_DEFINE([HAVE_$1], [1], ["Has $3 installed"])
      ],[ HAVE_$1=no ])

    AS_IF([test x$HAVE_$1 = xno], [
      dnl --- fallback search paths ---
      for d in $SEARCHPATHS; do
        AC_MSG_CHECKING([for $2 in $d/include])
        if test -f "$d/include/$2"; then
          AC_MSG_RESULT([found])
          AC_MSG_CHECKING([for lib$3 in $d/lib])
          if ls "$d/lib/lib$3".* >/dev/null 2>&1; then
            AC_MSG_RESULT([found])
            AC_MSG_NOTICE([found valid $2 and lib$3])
            HAVE_$1=yes
            $1_CFLAGS="-I$d/include"
            $1_LIBS="-L$d/lib -l$3"
            AC_DEFINE([HAVE_$1], [1], ["Has $3 installed"])
            break
          else
            AC_MSG_RESULT([no])
          fi
        else
          AC_MSG_RESULT([no])
        fi
      done
    ])
  ])

  AC_SUBST([$1_CFLAGS])
  AC_SUBST([$1_LIBS])
  AM_CONDITIONAL([HAVE_$1], [test x$HAVE_$1 = xyes])
])

