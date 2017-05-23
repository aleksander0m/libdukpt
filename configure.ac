dnl Process this file with autoconf to produce a configure script.
AC_PREREQ([2.68])

dnl The dukpt version number
m4_define([dukpt_major_version], [1])
m4_define([dukpt_minor_version], [3])
m4_define([dukpt_micro_version], [0])
m4_define([dukpt_version],
          [dukpt_major_version.dukpt_minor_version.dukpt_micro_version])

AC_INIT([libdukpt], [dukpt_version], [aleksander@aleksander.es])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.11 foreign no-define no-dist-gzip dist-xz tar-ustar -Wno-portability])
AM_MAINTAINER_MODE([enable])

dnl Support silent build rules. Disable
dnl by either passing --disable-silent-rules to configure or passing V=1
dnl to make
AM_SILENT_RULES([yes])

dnl Required programs
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
PKG_PROG_PKG_CONFIG

dnl Initialize libtool
LT_PREREQ([2.2])
LT_INIT

dnl Specific warnings to always use
LIBDUKPT_COMPILER_WARNINGS

dnl Version stuff
DUKPT_MAJOR_VERSION=dukpt_major_version
DUKPT_MINOR_VERSION=dukpt_minor_version
DUKPT_MICRO_VERSION=dukpt_micro_version
DUKPT_VERSION=dukpt_version
AC_SUBST(DUKPT_MAJOR_VERSION)
AC_SUBST(DUKPT_MINOR_VERSION)
AC_SUBST(DUKPT_MICRO_VERSION)
AC_SUBST(DUKPT_VERSION)

dnl Require openssl
PKG_CHECK_MODULES(OPENSSL, [openssl])
AC_SUBST(OPENSSL_CFLAGS)
AC_SUBST(OPENSSL_LIBS)

dnl libcheck required for unit test support
PKG_CHECK_MODULES([CHECK], [check >= 0.9.4], [have_check=yes], [have_check=no])
AM_CONDITIONAL(HAVE_CHECK, test "$have_check" = "yes")
AC_SUBST(CHECK_CFLAGS)
AC_SUBST(CHECK_LIBS)

dnl Documentation
GTK_DOC_CHECK(1.0)

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 src/dukpt.h
                 src/dukpt.pc
                 test/Makefile
                 doc/Makefile
                 doc/reference/Makefile
                 doc/reference/version.xml])
AC_OUTPUT

echo "
    libdukpt $VERSION
    ==============================================

    Build:
      compiler:             ${CC}
      cflags:               ${CFLAGS}
      ldflags:              ${LDFLAGS}
      maintainer mode:      ${USE_MAINTAINER_MODE}
      library unit tests:   ${have_check}
      documentation:        ${enable_gtk_doc}
"
