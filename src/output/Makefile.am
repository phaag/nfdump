
liboutput_a_CPPFLAGS = -I.. -I../include -I../libnffile -I../libnfdump -I../inline -I../collector $(DEPS_CFLAGS)

noinst_LIBRARIES = liboutput.a

# output_raw.c uses log2() — declare the math library dependency so programs
# linking liboutput.a know to add $(MATH_LIBS) to their LDADD.
liboutput_a_LIBADD = $(MATH_LIBS)

liboutput_a_SOURCES = output.c output.h \
	output_util.c output_util.h  output_raw.c output_raw.h \
	output_csv.c output_csv.h output_csv_fast.c \
	output_fmt.c output_fmt.h \
	output_json.c output_json.h output_ndjson.c output_ndjson.h \
	payload/dns/output_dns.c payload/dns/output_dns.h

EXTRA_DIST = itoa.c

CLEANFILES = *.gch

