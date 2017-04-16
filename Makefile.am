
SUBDIRS = . src test doc

DISTCHECK_CONFIGURE_FLAGS = \
	--enable-more-warnings=error     \
	--enable-gtk-doc                 \
	CFLAGS="-O2 -D_FORTIFY_SOURCE=2" \
	$(NULL)

ACLOCAL_AMFLAGS = -I m4
