
AM_CPPFLAGS = -I.. -I../include -I../libnffile -I../libnfdump -I../inline $(DEPS_CFLAGS)

noinst_LIBRARIES = liboutput.a

liboutput_a_SOURCES = output.c output.h \
	output_util.c output_util.h  output_raw.c output_raw.h \
	output_csv.c output_csv.h output_csv_fast.c \
	output_fmt.c output_fmt.h \
	output_json.c output_json.h output_ndjson.c output_ndjson.h

EXTRA_DIST = itoa.c

CLEANFILES = *.gch

