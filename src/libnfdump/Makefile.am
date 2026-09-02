# Public, stable read-only flow reader ABI.  All nffile layout, codec,
# crypto and record-mapping details remain private to this small facade.
AM_CPPFLAGS = -I$(srcdir) -I$(top_srcdir)/src -I$(top_srcdir)/src/include -I$(top_srcdir)/src/inline -I$(top_srcdir)/src/libnffile -I$(top_srcdir)/src/libnffile/nffileV3

lib_LTLIBRARIES = libnfdump.la
libnfdump_la_SOURCES = nfdump.h nfdump_abi.c
libnfdump_la_LIBADD = ../libnffile/libnffile.la
# libnfdump is the only supported external C ABI.  Export no nffile internals.
libnfdump_la_LDFLAGS = -release @VERSION@ -export-symbols-regex '^nfdump_'

include_HEADERS = nfdump.h
