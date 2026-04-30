BUILT_SOURCES = vcs_track.h

AM_CPPFLAGS = -I.. -I../include -I../inline -I../nfdump/compat_1_6_x -I../nfdump/compat_1_7_x  -Iconf -Icompress -InffileV3 -DSYSCONFDIR='"$(sysconfdir)"'

# libnffile sources
logging = logging.c logging.h
util = util.c util.h
pidfile = pidfile.c pidfile.h
compress = compress/nfcompress.c compress/nfcompress.h compress/minilzo.c compress/minilzo.h compress/lzoconf.h compress/lzodefs.h 
if HAVE_LZ4
else
compress += compress/lz4.c compress/lz4.h compress/lz4hc.c compress/lz4hc.h
endif
nffileV3 = nffileV3/nffileV3.c nffileV3/nffileV3.h nffileV3/nfcheck.c nffileV3/nfcheck.h
nffileV3 += nffileV3/nfread.h nffileV3/nfread.c nffileV3/nfwrite.h nffileV3/nfwrite.c
if HAVE_LIBSODIUM
nffileV3 += nffileV3/nfcrypto.c nffileV3/nfcrypto.h
endif
nffileV2 = nffileV2/nffileV2.c nffileV2/nffileV2.h nffileV2/uncompress.c nffileV2/uncompress.h
nfxV4 = queue.c queue.h nfxV4.h nfxV4.c id.h
nfxV3 = nffileV2/nfxV3.h nffileV2/nfxV3.c
convert = nffileV3/nfconvert.h nffileV3/nfconvert.c
conf = conf/nfconf.c conf/nfconf.h conf/toml.c conf/toml.h
nflist = flist.c flist.h

if NO_FTS
nflist += fts_compat.c fts_compat.h
endif

output = userio.c userio.h output_short.c output_short.h
daemon = daemon.c daemon.h 
version = version.c version.h
barrier = barrier.c barrier.h
bookkeeper = bookkeeper.c bookkeeper.h

vcs_track.h: Makefile
	./gen_version.sh @PACKAGE_VERSION@

lib_LTLIBRARIES = libnffile.la
libnffile_la_SOURCES = $(conf) $(logging) $(util) $(pidfile) $(compress) $(nffileV3) $(nffileV2) $(nfxV4) $(nfxV3) $(convert) $(nflist) $(filter) $(output) $(regex) $(daemon) $(barrier) $(bookkeeper) $(version) vcs_track.h
libnffile_la_CFLAGS = $(LZ4_CFLAGS) $(ZSTD_CFLAGS) $(BZ2_CFLAGS) $(LIBSODIUM_CFLAGS)
libnffile_la_LIBADD = $(LZ4_LIBS) $(ZSTD_LIBS) $(BZ2_LIBS) $(LIBSODIUM_LIBS) $(LIBATOMIC) $(RAND_LIBS)
libnffile_la_LDFLAGS = -release @VERSION@
 
EXTRA_DIST = gen_version.sh conf/nfdump.conf.dist

nfconfdir=$(sysconfdir)
nfconf_DATA = conf/nfdump.conf.dist

CLEANFILES = vcs_track.h *.gch
