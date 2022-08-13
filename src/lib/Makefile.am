
BUILT_SOURCES = grammar.h
AM_YFLAGS = -d

AM_CPPFLAGS = -I.. $(DEPS_CFLAGS)
AM_CFLAGS = -ggdb 

LDADD = $(DEPS_LIBS)

# libnfdump sources
util = util.c util.h
pidfile = pidfile.c pidfile.h
filelzo = minilzo.c minilzo.h lzoconf.h lzodefs.h lz4.c lz4.h
nffile = nffile.c nffile.h nffileV2.h queue.c queue.h nfx.c nfx.h nfxV3.h nfxV3.c
nflist = flist.c flist.h fts_compat.c fts_compat.h
filter = grammar.y scanner.l nftree.c nftree.h ipconv.c ipconv.h rbtree.h klist.h filter.h
output = output_util.c output_util.h output_short.c output_short.h
regex = cregex/compile.c cregex/parse.c cregex/vm.c 

lib_LTLIBRARIES = libnfdump.la
libnfdump_la_SOURCES = $(util) $(pidfile) $(filelzo) $(nffile) $(nflist) $(filter) $(output) $(regex)
libnfdump_la_LDFLAGS = -release @VERSION@

CLEANFILES = lex.yy.c grammar.c grammar.h scanner.c scanner.h *.gch
