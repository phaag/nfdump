BUILT_SOURCES = vcs_track.h

AM_CPPFLAGS = -I.. -I../include -I../inline -Iconf -Icompress -DSYSCONFDIR='"$(sysconfdir)"'

# libnffile sources
util = util.c util.h
pidfile = pidfile.c pidfile.h
compress = compress/minilzo.c compress/minilzo.h compress/lzoconf.h compress/lzodefs.h 
if HAVE_LZ4
else
compress += compress/lz4.c compress/lz4.h compress/lz4hc.c compress/lz4hc.h
endif
nffile = nffile.c nffile.h nffileV2.h queue.c queue.h nfxV3.h nfxV3.c id.h
conf = conf/nfconf.c conf/nfconf.h conf/toml.c conf/toml.h
nflist = flist.c flist.h

if NO_FTS
nflist += fts_compat.c fts_compat.h
endif

ip128 = ip128.c ip128.h
output = userio.c userio.h output_short.c output_short.h
daemon = daemon.c daemon.h 
version = version.c version.h
barrier = barrier.c barrier.h

vcs_track.h: Makefile
	./gen_version.sh @PACKAGE_VERSION@

lib_LTLIBRARIES = libnffile.la
libnffile_la_SOURCES = $(ip128) $(conf) $(util) $(pidfile) $(compress) $(nffile) $(nflist) $(filter) $(output) $(regex) $(daemon) $(barrier) $(version) vcs_track.h
libnffile_la_CFLAGS = $(LZ4_CFLAGS) $(ZSTD_CFLAGS) $(BZ2_CFLAGS)
libnffile_la_LIBADD = $(LZ4_LIBS) $(ZSTD_LIBS) $(BZ2_LIBS) $(LIBATOMIC)
libnffile_la_LDFLAGS = -release @VERSION@
 
EXTRA_DIST = gen_version.sh conf/nfdump.conf.dist

nfconfdir=$(sysconfdir)
nfconf_DATA = conf/nfdump.conf.dist

CLEANFILES = vcs_track.h *.gch
