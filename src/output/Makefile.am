
AM_CPPFLAGS = -I$(srcdir)/.. -I$(srcdir)/../include -I$(srcdir)/../libnffile -I$(srcdir)/../libnfdump -I$(srcdir)/../inline $(DEPS_CFLAGS)

noinst_LIBRARIES = liboutput.a

liboutput_a_SOURCES = output.c output.h \
	output_util.c output_util.h  output_raw.c output_raw.h \
	output_csv.c output_csv.h output_csv_fast.c \
	output_fmt.c output_fmt.h \
	output_json.c output_json.h output_ndjson.c output_ndjson.h \
	payload/dns/output_dns.c payload/dns/output_dns.h

EXTRA_DIST = itoa.c

CLEANFILES = *.gch

