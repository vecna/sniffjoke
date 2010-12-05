#! /bin/sh

libtoolize --automake --copy --force\
&& aclocal \
&& autoheader --force\
&& automake --copy --add-missing --force-missing\
&& autoconf --force \
&& exit

echo "autogen.sh FAIL - check by hand"
