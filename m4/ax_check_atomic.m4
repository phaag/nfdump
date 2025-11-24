dnl ------------------------------------------------------------
dnl Check whether linking atomic builtins requires -latomic
dnl Sets LIBATOMIC to "-latomic" or ""
dnl Defines HAVE_LIBATOMIC if needed
dnl ------------------------------------------------------------
AC_DEFUN([AX_CHECK_ATOMIC], [
  AC_MSG_CHECKING([whether atomic builtins require -latomic])

  AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([#include <stdint.h>],
      [[uint64_t v = 0; __atomic_fetch_add(&v, 1, __ATOMIC_SEQ_CST);]])],
    [need_latomic=no],
    [need_latomic=yes]
  )

  if test "x$need_latomic" = "xyes"; then
    AC_SEARCH_LIBS([__atomic_fetch_add_8], [atomic],
      [LIBATOMIC="-latomic"; AC_DEFINE([HAVE_LIBATOMIC], 1,
        [Define if libatomic is required])],
      [LIBATOMIC=""]
    )
  else
    LIBATOMIC=""
  fi

  AC_MSG_RESULT([$LIBATOMIC])
  AC_SUBST([LIBATOMIC])
])

