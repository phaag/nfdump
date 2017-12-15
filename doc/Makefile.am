directory = $(top_srcdir)/doc

if HAVE_DOXYGEN

doxygen-build.stamp: Doxyfile
	$(DOXYGEN) Doxyfile
	touch $@

else

doxygen-build.stamp:
	@echo "*** Doxygen not found. Documentation will not be build."
	touch $@

endif

all-local: doxygen-build.stamp

clean-local:
	rm -f doxygen-build.stamp
	rm -rf html
	rm -rf man
	rm -rf xml

