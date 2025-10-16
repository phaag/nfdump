
AM_CPPFLAGS = -I$(srcdir)/.. -I$(srcdir)/../include -I$(srcdir)/../libnffile -I$(srcdir)/../inline $(DEPS_CFLAGS)
#AM_LDFLAGS  = -L../lib

bin_PROGRAMS = ft2nfdump

ft2nfdump_SOURCES = ft2nfdump.c 
ft2nfdump_CFLAGS = @FT_INCLUDES@
ft2nfdump_LDADD = ../libnffile/libnffile.la -lft -lz
ft2nfdump_LDADD += @FT_LDFLAGS@

