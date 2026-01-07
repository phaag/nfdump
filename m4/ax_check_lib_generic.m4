dnl AX_CHECK_LIB_GENERIC(TAG, HEADER, LIBNAME, ACTION-IF-FOUND, ACTION-IF-NOT-FOUND)
dnl   TAG       - identifier (e.g. LZ4) used for HAVE_TAG, TAG_CFLAGS, TAG_LIBS
dnl   HEADER    - header file to check (e.g. lz4.h)
dnl   LIBNAME   - library name without -l (e.g. lz4)
dnl   ACTION-IF-FOUND     - shell/m4 code to run if library is found
dnl   ACTION-IF-NOT-FOUND - shell/m4 code to run if library is not found

AC_DEFUN([AX_CHECK_LIB_GENERIC],
[
  m4_pushdef([tag_lc], m4_tolower([$1]))

  AC_ARG_WITH([tag_lc],
    AS_HELP_STRING([--with-]tag_lc[=PATH], [Path to lib$3 (default: auto)]),
    [],
    [with_[]tag_lc=auto]
  )

  HAVE_$1=no
  $1_CFLAGS=""
  $1_LIBS=""

  dnl 1. User-supplied path
  AS_IF([test "x$with_[]tag_lc" != "xauto" -a "x$with_[]tag_lc" != "xno"], [
    $1_CFLAGS="-I$with_[]tag_lc/include"
    $1_LIBS="-L$with_[]tag_lc/lib -l$3"
    HAVE_$1=yes
  ])

  dnl 2. pkg-config
  AS_IF([test "x$HAVE_$1" = "xno"], [
    PKG_CHECK_MODULES([$1], [lib$3], [
      HAVE_$1=yes
    ], [
      HAVE_$1=no
    ])
  ])

  dnl 3. Manual fallback
  AS_IF([test "x$HAVE_$1" = "xno"], [

    save_CPPFLAGS="$CPPFLAGS"
    save_LDFLAGS="$LDFLAGS"

    AS_IF([test "x$with_[]tag_lc" != "xauto" -a "x$with_[]tag_lc" != "xno"], [
      CPPFLAGS="$CPPFLAGS -I$with_[]tag_lc/include"
      LDFLAGS="$LDFLAGS -L$with_[]tag_lc/lib"
    ])

    AC_CHECK_HEADER([$2], [
      AC_CHECK_LIB([$3], [main], [
        HAVE_$1=yes
        $1_CFLAGS="$CPPFLAGS"
        $1_LIBS="$LDFLAGS -l$3"
      ])
    ])

    CPPFLAGS="$save_CPPFLAGS"
    LDFLAGS="$save_LDFLAGS"
  ])

  dnl 4. Emit config.h define if found
  AS_IF([test "x$HAVE_$1" = "xyes"], [
    AC_DEFINE([HAVE_$1], [1], [Define if lib$3 is available])
  ])

  dnl 5. Run user-supplied blocks
  AS_IF([test "x$HAVE_$1" = "xyes"], [$4], [$5])

  dnl 6. Export variables
  AC_SUBST([$1_CFLAGS])
  AC_SUBST([$1_LIBS])
  AM_CONDITIONAL([HAVE_$1], [test "x$HAVE_$1" = "xyes"])

  m4_popdef([tag_lc])
])
