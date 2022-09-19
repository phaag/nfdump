
AM_CPPFLAGS = -I.. -I../include -I../lib $(DEPS_CFLAGS)
AM_LDFLAGS  = -L../lib

bin_PROGRAMS = ft2nfdump

ft2nfdump_SOURCES = ft2nfdump.c 
ft2nfdump_CFLAGS = @FT_INCLUDES@
ft2nfdump_LDADD = ../lib/libnfdump.la -lft -lz
ft2nfdump_LDADD += @FT_LDFLAGS@

