#if HAVE_DOXYGEN

directory = $(top_srcdir)/doc

$(directory)/html: Doxyfile
	$(DOXYGEN) Doxyfile

all-local: $(directory)/html

clean-local:
	rm -rf $(directory)/html
	rm -rf $(directory)/man
	rm -rf $(directory)/xml

#endif
