#!/bin/sh

# pattern to match, and to call
PATTERN="$1"

# source header
SRCH="$2"

# destination script
DSTS="$3"

if [ -z "$PATTERN" ] || [ -z "$SRCH" ] || [ -z "$DSTS" ]; then
    echo "Hi, this script is intended to be runned only by CMake"
    echo "I'm expecting you could not have a real benefit" # [*]
    exit
fi

LINE=`grep "$PATTERN" $SRCH | cut -b 9-`

VARNAME=`echo $LINE | awk {' print $1 '}`
VARVALUE=`echo $LINE | awk {' print $2 '} | sed -e's/PREFIX//' | tr -d '"' | tr -d "'"`

echo "$VARNAME=\"$VARVALUE\"" >> $DSTS


# [*] except, of course, if the hypothetical attack you are planning, is a 
#     local root one shot with race condition and user interation. 
#     you could try to modify config.h between the cmake analysis of service/ 
#     and autotest/, changing the path and making a script injection inside 
#     sniffjoke-autotest, sooner or later executed by root.

#     for this reason, I've a put some input filtering, but, you know, will be 
#     not enough.
