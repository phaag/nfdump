BUILT_SOURCES = vcs_track.h

AM_CPPFLAGS = -I.. -I../include -I../inline -Iconf -Icompress $(DEPS_CFLAGS)
AM_CFLAGS = -ggdb 

LDADD =  $(DEPS_LIBS)

# libnffile sources
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
output = userio.c userio.h output_short.c output_short.h
daemon = daemon.c daemon.h 
version = version.c version.h
barrier = barrier.c barrier.h

vcs_track.h: Makefile
	./gen_version.sh

lib_LTLIBRARIES = libnffile.la
libnffile_la_SOURCES = $(conf) $(util) $(pidfile) $(compress) $(nffile) $(nflist) $(filter) $(output) $(regex) $(daemon) $(barrier) $(version) vcs_track.h
libnffile_la_LDFLAGS = -release @VERSION@
 
EXTRA_DIST = gen_version.sh conf/nfdump.conf.dist

nfconfdir=$(sysconfdir)
nfconf_DATA = conf/nfdump.conf.dist

CLEANFILES = vcs_track.h *.gch
