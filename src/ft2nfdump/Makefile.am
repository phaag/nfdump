
bin_PROGRAMS = ft2nfdump

ft2nfdump_CPPFLAGS = -I.. -I../include -I../libnffile -I../inline $(DEPS_CFLAGS)
ft2nfdump_CFLAGS = $(FT_CFLAGS)

ft2nfdump_SOURCES = ft2nfdump.c 
ft2nfdump_LDADD = -lnffile 
ft2nfdump_LDFLAGS = -L../libnffile 

ft2nfdump_LDADD += $(FT_LIBS) -lz

CLEANFILES = *.gch