
AM_CPPFLAGS = -I.. -I../include -I../lib -I../lib/conf -I../maxmind -I../inline $(DEPS_CFLAGS)

noinst_LIBRARIES = liboutput.a

liboutput_a_SOURCES = content_dns.c content_dns.h \
	ja3.c ja3.h md5.c md5.h \
	output.c output.h output_util.c output_util.h  output_csv.c output_csv.h \
	output_fmt.c output_fmt.h output_json.c output_json.h \
	output_raw.c output_raw.h

CLEANFILES = *.gch

