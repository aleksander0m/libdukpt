
noinst_PROGRAMS =

# Unit tests only built if libcheck is available
if HAVE_CHECK

noinst_PROGRAMS += dukpt-test

dukpt_test_SOURCES  = dukpt-test.c
dukpt_test_CPPFLAGS = -I$(top_srcdir)/src/ $(CHECK_CFLAGS)
dukpt_test_LDADD    = $(top_builddir)/src/libdukpt.la
dukpt_test_LDFLAGS  = $(CHECK_LIBS)

endif # HAVE_CHECK

TESTS = $(noinst_PROGRAMS)
