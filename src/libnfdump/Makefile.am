
BUILT_SOURCES = filter/grammar.h
AM_YFLAGS = -d

AM_CPPFLAGS = -I.. -I../include -I../inline -I../libnffile -Idecode -Isgregex $(DEPS_CFLAGS)
AM_CFLAGS = -ggdb 

LDADD =  $(DEPS_LIBS)

# libnfdump sources
filter = filter/grammar.y filter/scanner.l filter/filter.c filter/filter.h filter/ipconv.c filter/ipconv.h ../include/rbtree.h
regex = sgregex/sgregex.c sgregex/sgregex.h
decode  = dns/codec.c dns/codec.h dns/dns.c dns/dns.h dns/mappings.c dns/mappings.h
decode += ssl/ssl.c ssl/ssl.h ja3/ja3.c ja3/ja3.h ja4/ja4.c ja4/ja4.h
if JA4
decode += ja4/ja4s.c
endif
digest  = digest/md5.c digest/md5.h digest/sha256.c digest/sha256.h
maxmind = maxmind/maxmind.c maxmind/maxmind.h maxmind/mmhash.c maxmind/mmhash.h
tor = tor/tor.c tor/tor.h 

lib_LTLIBRARIES = libnfdump.la
libnfdump_la_SOURCES = $(filter) $(maxmind) $(tor) $(regex) $(decode) $(digest) ../libnffile/vcs_track.h
libnfdump_la_LDFLAGS = -release @VERSION@
 
CLEANFILES = filter/lex.yy.c filter/grammar.c filter/grammar.h filter/scanner.c filter/scanner.h *.gch
