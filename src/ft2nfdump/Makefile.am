
bin_PROGRAMS = ft2nfdump

ft2nfdump_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/src/include -I$(top_srcdir)/src/libnffile -I$(top_srcdir)/src/inline $(DEPS_CFLAGS)
ft2nfdump_CFLAGS = $(FT_CFLAGS)

ft2nfdump_SOURCES = ft2nfdump.c 
ft2nfdump_LDADD = -lnffile 
ft2nfdump_LDFLAGS = -L$(top_builddir)/src/libnffile

ft2nfdump_LDADD += $(FT_LIBS) -lz
ft2nfdump_LDADD += $(LZ4_LIBS) $(ZSTD_LIBS) $(BZ2_LIBS) $(LIBSODIUM_LIBS)

CLEANFILES = *.gch
