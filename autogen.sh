#! /bin/sh

libtoolize --ltdl --force \
&& aclocal \
&& autoheader \
&& automake --add-missing \
&& autoconf \
&& exit

echo "autogen.sh FAIL - check by hand"
