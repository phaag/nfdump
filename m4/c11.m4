AC_DEFUN([AX_CHECK_C11],
[AX_CHECK_COMPILE_FLAG([-std=gnu11],
    [AX_APPEND_FLAG([-std=gnu11])],
    [AX_CHECK_COMPILE_FLAG([-std=c11],
        [AX_APPEND_FLAG([-std=c11])],
        [AX_CHECK_COMPILE_FLAG([-std=c99],
            [AX_APPEND_FLAG([-std=c99])],
            [AC_MSG_ERROR([C compiled does not support at least C99!])])
        ])
    ])
])
