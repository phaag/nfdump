
bin_PROGRAMS = torlookup
bin_SCRIPTS = updateTorDB.sh

torlookup_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/src/include -I$(top_srcdir)/src/libnfdump -I$(top_srcdir)/src/libnffile -I$(top_srcdir)/src/inline

torlookup_SOURCES = torlookup.c 
torlookup_LDADD = -lnfdump -lnffile 
torlookup_LDFLAGS = -L../libnfdump -L../libnffile  

EXTRA_DIST = updateTorDB.sh

CLEANFILES =  $(bin_PROGRAMS) *.gch
