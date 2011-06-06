#!/bin/sh

# pattern to match, and to call
PATTERN1="$1"
PATTERN2="$2"
PATTERN3="$3"
PATTERN4="$4"

# source header
SRCH="$5"

# scripts path
WHEREPATH="$6"
SOURCE="unusable-sj-autotest.sh"
DEST="sniffjoke-autotest"

if [ -z "$PATTERN1" ] || [ -z "$PATTERN2" ] || [ -z "$PATTERN3" ] || [ -z "$PATTERN4" ] ||  [ -z "$SRCH" ] || [ -z "$WHEREPATH" ]; then
    echo "Hi, this script is intended to be runned only by CMake"
    echo "I'm expecting you could not have a real benefit" # [*]
    exit
fi

if [ ! -e $WHEREPATH/$SOURCE ] || [ ! -e $WHEREPATH/$DEST ]; then
    echo "fatal error: $WHEREPATH/$SOURCE does not exist or $WHEREPATH/$DEST do not."
    echo "Installation will not work"
    exit
fi

# grep the line number where the vars to filter out exist
CLEANPATTERN1=`echo $PATTERN1 | tr "_" " " | tr -d [:space:]`
STARTLINEPOS=`grep -n "tofilterout_"$CLEANPATTERN1 $WHEREPATH/$SOURCE | head -1 | sed -e's/:.*//'`

CLEANPATTERN4=`echo $PATTERN4 | tr "_" " " | tr -d [:space:]`
ENDLINEPOS=`grep -n "tofilterout_"$CLEANPATTERN4 $WHEREPATH/$SOURCE | head -1 | sed -e's/:.*//'`

# we need the entire length of the source file, in order to copy correctly in the new one
SRCLINELEN=`wc -l < $WHEREPATH/$SOURCE`

# the section before the line should be copyed, as the section after
before_line=$(($STARTLINEPOS -1))
after_line=$(($SRCLINELEN - $ENDLINEPOS))

# echo "working with: $before_line, $after_line"
# ----------- file generation follow:

head -"$before_line" $WHEREPATH/$SOURCE > $WHEREPATH/$DEST.tmp

DATALINE=`grep "$PATTERN1" $SRCH | cut -b 9-`
VARNAME=`echo $DATALINE | awk {' print $1 '}`
VARVALUE=`echo $DATALINE | awk {' print $2 '} | sed -e's/PREFIX//' | tr -d '"' | tr -d "'"`
echo "$VARNAME=\"$VARVALUE\"" >> $WHEREPATH/$DEST.tmp

DATALINE=`grep "$PATTERN2" $SRCH | cut -b 9-`
VARNAME=`echo $DATALINE | awk {' print $1 '}`
VARVALUE=`echo $DATALINE | awk {' print $2 '} | sed -e's/PREFIX//' | tr -d '"' | tr -d "'"`
echo "$VARNAME=\"$VARVALUE\"" >> $WHEREPATH/$DEST.tmp

DATALINE=`grep "$PATTERN3" $SRCH | cut -b 9-`
VARNAME=`echo $DATALINE | awk {' print $1 '}`
VARVALUE=`echo $DATALINE | awk {' print $2 '} | sed -e's/PREFIX//' | tr -d '"' | tr -d "'"`
echo "$VARNAME=\"$VARVALUE\"" >> $WHEREPATH/$DEST.tmp

DATALINE=`grep "$PATTERN4" $SRCH | cut -b 9-`
VARNAME=`echo $DATALINE | awk {' print $1 '}`
VARVALUE=`echo $DATALINE | awk {' print $2 '} | sed -e's/PREFIX//' | tr -d '"' | tr -d "'"`
echo "$VARNAME=\"$VARVALUE\"" >> $WHEREPATH/$DEST.tmp

tail -"$after_line" $WHEREPATH/$SOURCE >> $WHEREPATH/$DEST.tmp
# ----------- end of file generation

# remind: for a debug, comment this mv is the best way
mv $WHEREPATH/$DEST.tmp $WHEREPATH/$DEST
chmod +x $WHEREPATH/$DEST

# [*] except, of course, if the hypothetical attack you are planning, is a 
#     local root one shot with race condition and user interation. 
#     you could try to modify config.h between the cmake analysis of service/ 
#     and autotest/, changing the path and making a script injection inside 
#     sniffjoke-autotest, sooner or later executed by root.

#     for this reason, I've a put some input filtering, but, you know, will be 
#     not enough.
