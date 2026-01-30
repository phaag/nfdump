AC_DEFUN([AX_CHECK_C17], [

  for flag in -std=gnu17 -std=c17 -std=gnu11 -std=c11; do
    AX_CHECK_COMPILE_FLAG([$flag],
      [ AX_APPEND_FLAG([$flag])
       ac_cv_c_std_flag=$flag
       break])
  done

  test -n "$ac_cv_c_std_flag" ||
    AC_MSG_ERROR([C compiler does not support at least C11!])
])
