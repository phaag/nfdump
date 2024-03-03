
AM_CPPFLAGS = -I.. -I../include -I../lib -I../decode -I../lib/conf  -I../maxmind -I../inline $(DEPS_CFLAGS)

noinst_LIBRARIES = liboutput.a

liboutput_a_SOURCES = output.c output.h \
	output_util.c output_util.h  output_csv.c output_csv.h \
	output_fmt.c output_fmt.h output_json.c output_json.h \
	output_raw.c output_raw.h

CLEANFILES = *.gch

