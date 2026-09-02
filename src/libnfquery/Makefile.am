
BUILT_SOURCES = filter/grammar.h
AM_YFLAGS = -d

AM_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/src/include -I$(top_srcdir)/src/inline -I$(top_srcdir)/src/libnffile

# libnfquery sources
#
# 'core' is the plain-element filter engine: the bytecode compiler/interpreter,
# IP/CIDR/list parsing, and the time+bloom block pre-filter. It has no
# dependency beyond libnffile.
# It is built twice: once here as part of the full-featured libnfquery.la
# (with -DNFFILTER_FULL, enabling MaxMind/Tor/DNS/SSL/JA3/JA4/regex lookups),
# and once as the standalone libnffilter.la below, for consumers (the
# collectors) that only want plain-field filtering with none of that pulled
# in. See filter/filter.c and filter/grammar.y's "#ifdef NFFILTER_FULL"
# guards for the exact boundary.
core = filter/grammar.y filter/scanner.l filter/filter.c filter/filter.h filter/filter_int.h filter/block_filter.c ../include/rbtree.h filter/ipconv.c filter/ipconv.h
regex = filter/nfregex.c filter/nfregex.h
digest  = digest/md5.c digest/md5.h digest/sha256.c digest/sha256.h
maxmind = maxmind/maxmind.c maxmind/maxmind.h maxmind/mmhash.c maxmind/mmhash.h
tor = tor/tor.c tor/tor.h
decode  = dns/codec.c dns/codec.h dns/dns.c dns/dns.h dns/mappings.c dns/mappings.h
decode += ssl/ssl.c ssl/ssl.h ja3/ja3.c ja3/ja3.h ja4/ja4.c ja4/ja4.h

if ENABLE_JA4
decode += ja4/ja4s.c
endif


lib_LTLIBRARIES = libnfquery.la libnffilter.la

libnfquery_la_CPPFLAGS = $(AM_CPPFLAGS) -DNFFILTER_FULL $(PCRE2_CFLAGS)
libnfquery_la_SOURCES = $(core) $(maxmind) $(tor) $(regex) $(decode) $(digest) ../libnffile/vcs_track.h
libnfquery_la_LDFLAGS = -release @VERSION@
libnfquery_la_LIBADD = ../libnffile/libnffile.la $(LIBATOMIC) $(PCRE2_LIBS)

# Minimal filter-only library: plain V4 field/extension comparisons only.
# No MaxMind, Tor, DNS, SSL, JA3, JA4, or regex - those keywords are rejected
# by CompileFilter() at compile time in this build (see NFFILTER_FULL guards).
# Do not compile nfregex or link PCRE2 here: that would make the advertised
# dependency boundary ineffective.
libnffilter_la_CPPFLAGS = $(AM_CPPFLAGS)
libnffilter_la_SOURCES = $(core) ../libnffile/vcs_track.h
libnffilter_la_LDFLAGS = -release @VERSION@
libnffilter_la_LIBADD = ../libnffile/libnffile.la $(LIBATOMIC)

CLEANFILES = filter/lex.yy.c filter/grammar.c filter/grammar.h filter/scanner.c filter/scanner.h *.gch
