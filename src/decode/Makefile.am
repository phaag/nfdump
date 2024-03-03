
AM_CPPFLAGS = -I.. -I../include -I../inline -I../lib -Issl $(DEPS_CFLAGS)
AM_CFLAGS = -ggdb 

LDADD =  $(DEPS_LIBS)


# libnfdecode sources
decode  = dns/dns.c dns/dns.h
decode += ssl/ssl.c ssl/ssl.h ja3/ja3.c ja3/ja3.h ja4/ja4.c ja4/ja4.h
decode += digest/md5.c digest/md5.h digest/sha256.c digest/sha256.h

if JA4
decode += ja4/ja4s.c ja4/ja4s.h
endif

noinst_LIBRARIES = libnfdecode.a

libnfdecode_a_SOURCES = $(decode)