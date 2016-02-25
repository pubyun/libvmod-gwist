AM_CPPFLAGS = @VMOD_INCLUDES@ -Wall -Werror

vmoddir = @VMOD_DIR@
vmod_LTLIBRARIES = libvmod_gwist.la

libvmod_gwist_la_LDFLAGS = -module -export-dynamic -avoid-version -shared

libvmod_gwist_la_SOURCES = \
	vmod_gwist.c

nodist_libvmod_gwist_la_SOURCES = \
	vcc_if.c \
	vcc_if.h

vmod_gwist.lo: vcc_if.c vcc_if.h

vcc_if.c: vcc_if.h

vcc_if.h: @VMODTOOL@ $(top_srcdir)/src/vmod_gwist.vcc
	@VMODTOOL@ $(top_srcdir)/src/vmod_gwist.vcc

VMOD_TESTS = $(top_srcdir)/src/tests/*.vtc
.PHONY: $(VMOD_TESTS)

$(top_srcdir)/src/tests/*.vtc: libvmod_gwist.la
	@VARNISHTEST@ -Dvarnishd=@VARNISHD@ -Dvmod_topbuild=$(abs_top_builddir) $@

check: $(VMOD_TESTS)

EXTRA_DIST = \
	vmod_gwist.vcc \
	$(VMOD_TESTS)

CLEANFILES = \
	$(builddir)/vcc_if.c \
	$(builddir)/vcc_if.h \
	$(builddir)/vmod_gwist.rst \
	$(builddir)/vmod_gwist.man.rst
