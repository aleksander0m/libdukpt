
lib_LTLIBRARIES = libdukpt.la

libdukpt_la_CPPFLAGS = \
	-I$(top_builddir) \
	$(OPENSSL_CFLAGS) \
	$(NULL)

libdukpt_la_SOURCES = \
	dukpt.h dukpt.c \
	$(NULL)

include_HEADERS = \
	dukpt.h \
	$(NULL)

libdukpt_la_LDFLAGS = \
	$(OPENSSL_LIBS) \
	$(NULL)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = dukpt.pc

EXTRA_DIST = \
	dukpt.h.in \
	$(NULL)
