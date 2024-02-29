
BUILT_SOURCES = filter/grammar.h vcs_track.h
AM_YFLAGS = -d

AM_CPPFLAGS = -I.. -I../include -I../inline -Iconf -Idecode -I../maxmind -Isgregex -Icompress $(DEPS_CFLAGS)
AM_CFLAGS = -ggdb 

LDADD =  $(DEPS_LIBS)

# libnfdump sources
util = util.c util.h
pidfile = pidfile.c pidfile.h
compress = compress/minilzo.c compress/minilzo.h compress/lzoconf.h compress/lzodefs.h 
if LZ4EMBEDDED
compress += compress/lz4.c compress/lz4.h compress/lz4hc.c compress/lz4hc.h
endif
nffile = nffile.c nffile.h nffileV2.h queue.c queue.h nfxV3.h nfxV3.c id.h
conf = conf/nfconf.c conf/nfconf.h conf/toml.c conf/toml.h

if NEEDFTSCOMPAT
nflist = flist.c flist.h fts_compat.c fts_compat.h
else 
nflist = flist.c flist.h
endif
filter = filter/grammar.y filter/scanner.l filter/filter.c filter/filter.h filter/ipconv.c filter/ipconv.h rbtree.h
output = userio.c userio.h output_short.c output_short.h
regex = sgregex/sgregex.c sgregex/sgregex.h
daemon = daemon.c daemon.h 
version = version.c version.h
decode = decode/content_dns.c decode/content_dns.h decode/ssl.c decode/ssl.h decode/ja3.c decode/ja3.h decode/md5.c decode/md5.h decode/sha256.c decode/sha256.h

vcs_track.h: Makefile
	./gen_version.sh

lib_LTLIBRARIES = libnfdump.la
libnfdump_la_SOURCES = $(conf) $(util) $(pidfile) $(compress) $(nffile) $(nflist) $(filter) $(decode) $(output) $(regex) $(daemon) $(version) vcs_track.h
libnfdump_la_LDFLAGS = -release @VERSION@
 

EXTRA_DIST = gen_version.sh conf/nfdump.conf.dist

nfconfdir=$(sysconfdir)
nfconf_DATA = conf/nfdump.conf.dist

CLEANFILES = filter/lex.yy.c filter/grammar.c filter/grammar.h filter/scanner.c filter/scanner.h vcs_track.h *.gch
