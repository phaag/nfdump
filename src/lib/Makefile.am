
BUILT_SOURCES = grammar.h vcs_track.h
AM_YFLAGS = -d

AM_CPPFLAGS = -I.. -I../include -I../inline -I../conf $(DEPS_CFLAGS)
AM_CFLAGS = -ggdb 

LDADD = $(DEPS_LIBS)

# libnfdump sources
util = util.c util.h
pidfile = pidfile.c pidfile.h
compress = minilzo.c minilzo.h lzoconf.h lzodefs.h lz4.c lz4.h lz4hc.c lz4hc.h
nffile = nffile.c nffile.h nffileV2.h queue.c queue.h nfx.c nfx.h nfxV3.h nfxV3.c id.h

if NEEDFTSCOMPAT
nflist = flist.c flist.h fts_compat.c fts_compat.h
else 
nflist = flist.c flist.h
endif
filter = grammar.y scanner.l nftree.c nftree.h ipconv.c ipconv.h rbtree.h filter.h
output = output_util.c output_util.h output_short.c output_short.h
regex = sgregex/sgregex.c sgregex/sgregex.h
daemon = daemon.c daemon.h 
version = version.c version.h

vcs_track.h: Makefile
	./gen_version.sh

lib_LTLIBRARIES = libnfdump.la
libnfdump_la_SOURCES = $(util) $(pidfile) $(compress) $(nffile) $(nflist) $(filter) $(output) $(regex) $(daemon) $(version) vcs_track.h
libnfdump_la_LDFLAGS = -release @VERSION@

EXTRA_DIST = gen_version.sh

CLEANFILES = lex.yy.c grammar.c grammar.h scanner.c scanner.h vcs_track.h *.gch
