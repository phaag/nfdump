BEGIN {
D["PACKAGE_NAME"]=" \"nfdump\""
D["PACKAGE_TARNAME"]=" \"nfdump\""
D["PACKAGE_VERSION"]=" \"1.7.0\""
D["PACKAGE_STRING"]=" \"nfdump 1.7.0\""
D["PACKAGE_BUGREPORT"]=" \"peter@people.ops-trust.net\""
D["PACKAGE_URL"]=" \"\""
D["PACKAGE"]=" \"nfdump\""
D["VERSION"]=" \"1.7.0\""
D["HAVE_STDIO_H"]=" 1"
D["HAVE_STDLIB_H"]=" 1"
D["HAVE_STRING_H"]=" 1"
D["HAVE_INTTYPES_H"]=" 1"
D["HAVE_STDINT_H"]=" 1"
D["HAVE_STRINGS_H"]=" 1"
D["HAVE_SYS_STAT_H"]=" 1"
D["HAVE_SYS_TYPES_H"]=" 1"
D["HAVE_UNISTD_H"]=" 1"
D["HAVE_SYS_TIME_H"]=" 1"
D["STDC_HEADERS"]=" 1"
D["HAVE_DLFCN_H"]=" 1"
D["LT_OBJDIR"]=" \".libs/\""
D["YYTEXT_POINTER"]=" 1"
D["HAVE_PTHREAD_PRIO_INHERIT"]=" 1"
D["HAVE_PTHREAD"]=" 1"
D["HAVE_SOCKADDR_SA_LEN"]=" 1"
D["HAVE_STRUCT_SOCKADDR_STORAGE_SS_FAMILY"]=" 1"
D["HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN"]=" 1"
D["HAVE_STRUCT_SOCKADDR_SA_LEN"]=" 1"
D["HAVE_GETHOSTBYNAME"]=" 1"
D["HAVE_SETSOCKOPT"]=" 1"
D["HAVE_FPURGE"]=" 1"
D["HAVE_HTONLL"]=" 1"
D["HAVE_DIRENT_H"]=" 1"
D["HAVE_ARPA_INET_H"]=" 1"
D["HAVE_FCNTL_H"]=" 1"
D["HAVE_NETINET_IN_H"]=" 1"
D["HAVE_FTS_H"]=" 1"
D["HAVE_STDINT_H"]=" 1"
D["HAVE_STDLIB_H"]=" 1"
D["HAVE_STDDEF_H"]=" 1"
D["HAVE_STRING_H"]=" 1"
D["HAVE_SYS_SOCKET_H"]=" 1"
D["HAVE_SYSLOG_H"]=" 1"
D["HAVE_UNISTD_H"]=" 1"
D["HAVE_PCAP_BPF_H"]=" 1"
D["HAVE_NET_BPF_H"]=" 1"
D["HAVE_NET_ETHERNET_H"]=" 1"
D["HAVE_SYS_TYPES_H"]=" 1"
D["HAVE_NETINET_IN_H"]=" 1"
D["HAVE_ARPA_NAMESER_H"]=" 1"
D["HAVE_ARPA_NAMESER_COMPAT_H"]=" 1"
D["HAVE_NETDB_H"]=" 1"
D["HAVE_RESOLV_H"]=" 1"
D["HAVE_NETINET_IN_SYSTM_H"]=" 1"
D["HAVE_BZLIB_H"]=" 1"
D["SIZEOF_VOID_P"]=" 8"
D["HAVE__BOOL"]=" 1"
D["HAVE_STDBOOL_H"]=" 1"
D["HAVE_FORK"]=" 1"
D["HAVE_VFORK"]=" 1"
D["HAVE_ALARM"]=" 1"
D["HAVE_WORKING_VFORK"]=" 1"
D["HAVE_WORKING_FORK"]=" 1"
D["HAVE_MALLOC"]=" 1"
D["HAVE_REALLOC"]=" 1"
D["HAVE_STRFTIME"]=" 1"
D["HAVE_INET_NTOA"]=" 1"
D["HAVE_SOCKET"]=" 1"
D["HAVE_STRCHR"]=" 1"
D["HAVE_STRDUP"]=" 1"
D["HAVE_STRERROR"]=" 1"
D["HAVE_STRRCHR"]=" 1"
D["HAVE_STRSTR"]=" 1"
D["HAVE_SCANDIR"]=" 1"
D["HAVE_LIBRESOLV"]=" 1"
D["SIZEOF_SHORT"]=" 2"
D["SIZEOF_INT"]=" 4"
D["SIZEOF_LONG"]=" 8"
D["SIZEOF_LONG_LONG"]=" 8"
D["SIZEOF___INT64"]=" 0"
D["SIZEOF_VOID_P"]=" 8"
D["SIZEOF_SIZE_T"]=" 8"
D["SIZEOF_TIME_T"]=" 8"
D["SIZEOF_PTRDIFF_T"]=" 8"
D["HAVE_MEMCMP"]=" 1"
D["HAVE_MEMCPY"]=" 1"
D["HAVE_MEMMOVE"]=" 1"
D["HAVE_MEMSET"]=" 1"
D["HAVE_SEMUN"]=" 1"
D["HAVE_SIZE_T_Z_FORMAT"]=" 1"
  for (key in D) D_is_set[key] = 1
  FS = ""
}
/^[\t ]*#[\t ]*(define|undef)[\t ]+[_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ][_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789]*([\t (]|$)/ {
  line = $ 0
  split(line, arg, " ")
  if (arg[1] == "#") {
    defundef = arg[2]
    mac1 = arg[3]
  } else {
    defundef = substr(arg[1], 2)
    mac1 = arg[2]
  }
  split(mac1, mac2, "(") #)
  macro = mac2[1]
  prefix = substr(line, 1, index(line, defundef) - 1)
  if (D_is_set[macro]) {
    # Preserve the white space surrounding the "#".
    print prefix "define", macro P[macro] D[macro]
    next
  } else {
    # Replace #undef with comments.  This is necessary, for example,
    # in the case of _POSIX_SOURCE, which is predefined and required
    # on some systems where configure will not decide to define it.
    if (defundef == "undef") {
      print "/*", prefix defundef, macro, "*/"
      next
    }
  }
}
{ print }
