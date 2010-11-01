#! /bin/sh

aclocal \
&& automake --add-missing \
&& autoconf \
&& libtoolize --ltdl --force && exit

echo "autogen.sh FAIL - check by hand"
