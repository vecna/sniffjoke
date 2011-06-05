#!/bin/sh

# whe know the name, but I prefer is passed, because of the paths...

WPATH=$1

if [ ! -d $WPATH ]; then
    echo "Error, first (and only) argument is not a directory!"
    exit
fi

if [ ! -e "$WPATH/sniffjoke-autotest" ]; then
    echo "Error! $WPATH/sniffjoke-autotest don'e exist!"
    exit
fi

if [ ! -e "$WPATH/unusable-sj-autotest.sh" ]; then
    echo "Error! $WPATH/unusable-sj-autotest.sh don'e exist!"
    exit
fi

rm -f $WPATH/sniffjoke-autotest
ln -s unusable-sj-autotest.sh $WPATH/sniffjoke-autotest
