#!/bin/sh

# pattern to match, and to call
PATTERN="$1"
CLEANPATTERN=`echo $PATTERN | tr "_" " " | tr -d [:space:]`

# source header
SRCH="$2"

# source script
DSTS="$3"

# grep the line number where the vars to filter out exist
LINEPOS=`grep -n "tofilterout_"$CLEANPATTERN $DSTS | head -1 | sed -e's/:.*//'`

# if the destination, sniffjoke-autotest is a symbolic link, mean that
# we are on the first execution of this install script
if [ -L $DSTS ]; then
    TEMPNAME=$DSTS.$RANDOM.$RANDOM
    echo "found to be a symbolic link $DSTS, copying its contents"
    cp $DSTS $TEMPNAME
    echo "removing the symlink..."
    rm -f $DSTS
    echo "preparing the sniffjoke-autotest script"
    mv $TEMPNAME $DSTS
else
    if [ -z "$LINEPOS" ]; then
        UNUSABLE_NAME="unusable-sj-autotest.sh"
        echo "Not a symbolic link $DSTS, (this is not the first installation!) looking for the original"
        DIRNAME=`dirname $DSTS`
        if [ -e $DIRNAME/$UNUSABLE_NAME ]; then
            echo "found: copying as base for the sniffjoke-autotest setup..."
            cp $DIRNAME/$UNUSABLE_NAME $DSTS
            LINEPOS=`grep -n "tofilterout_"$CLEANPATTERN $DSTS | head -1 | sed -e's/:.*//'`
        else
            echo "Error in generation: Installation aborted, clean sniffjoke directory, somethins is goes wrong!"
            exit
        fi
    else
        echo "setup is going well..."
    fi
fi

if [ -z "$PATTERN" ] || [ -z "$SRCH" ] || [ -z "$DSTS" ]; then
    echo "Hi, this script is intended to be runned only by CMake"
    echo "I'm expecting you could not have a real benefit" # [*]
    exit
fi

# grep from config.h and cut off the #define
LINE=`grep "$PATTERN" $SRCH | cut -b 9-`

# we need the entire length of the source file, in order to copy correctly in the new one
LINELEN=`wc -l < $DSTS`

# extracting the system dependent value
VARNAME=`echo $LINE | awk {' print $1 '}`
VARVALUE=`echo $LINE | awk {' print $2 '} | sed -e's/PREFIX//' | tr -d '"' | tr -d "'"`

# the section before the line should be copyed, as the section after
before_line=$(($LINEPOS -1))
after_line=$(($LINELEN - $LINEPOS))

head -"$before_line" $DSTS > $DSTS.$LINEPOS
echo "$VARNAME=\"$VARVALUE\"" >> $DSTS.$LINEPOS
tail -"$after_line" $DSTS >> $DSTS.$LINEPOS

# remind: for a debug, comment this mv is the best way
mv $DSTS.$LINEPOS $DSTS
chmod +x $DSTS

# [*] except, of course, if the hypothetical attack you are planning, is a 
#     local root one shot with race condition and user interation. 
#     you could try to modify config.h between the cmake analysis of service/ 
#     and autotest/, changing the path and making a script injection inside 
#     sniffjoke-autotest, sooner or later executed by root.

#     for this reason, I've a put some input filtering, but, you know, will be 
#     not enough.
