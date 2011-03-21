#! /bin/sh

libtoolize --force --copy\
&& aclocal --force\
&& autoheader --force\
&& automake --copy --add-missing --force-missing\
&& autoconf --force \
&& exit

echo "autogen.sh FAIL - check by hand"
