
bin_PROGRAMS = torlookup
bin_SCRIPTS = updateTorDB.sh

torlookup_CPPFLAGS = -I.. -I../include -I../libnfdump -I../libnffile -I../inline

torlookup_SOURCES = torlookup.c 
torlookup_LDADD = -lnfdump -lnffile 
torlookup_LDFLAGS = -L../libnfdump -L../libnffile  

EXTRA_DIST = updateTorDB.sh

CLEANFILES =  $(bin_PROGRAMS) *.gch
