idnl ----------------------------------------------------------------------
dnl AX_RRD_CONSTCHAR.M4
dnl Detect whether rrd_update() expects const char ** in the installed RRD library
dnl Usage: AX_RRD_CONSTCHAR
dnl ----------------------------------------------------------------------

AC_DEFUN([AX_RRD_CONSTCHAR],
[
  AC_MSG_CHECKING([for RRD library const char ** API])

  dnl Save CFLAGS and add -Werror to turn warnings into errors
  save_CFLAGS="$CFLAGS"
  CFLAGS="$CFLAGS -Werror"

  AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM(
      [[#include <rrd.h>]],
      [[
        char *args[] = { "file.rrd" };
        rrd_update(1, args);
        return 0;
      ]]
    )],
    [have_rrd_constchar=no],
    [have_rrd_constchar=yes]
  )

  CFLAGS="$save_CFLAGS"

  AC_MSG_RESULT([$have_rrd_constchar])

  if test "x$have_rrd_constchar" = "xyes"; then
    AC_DEFINE([RRDCONSTCHAR], [1],
              [Define if rrd_update() expects const char **])
  fi

  AM_CONDITIONAL([RRDCONSTCHAR], [test "x$have_rrd_constchar" = "xyes"])
])

