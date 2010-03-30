#!/usr/local/bin/python

# This script builds a SWIG1.3 distribution.
# Usage : mkdist.py dirname 

import sys
import string

try:
   dirname = sys.argv[1]
except:
   print "Usage: mkdist.py directory"
   sys.exit(0)

# If directory exists, remove it
import os
print "Removing ", dirname
os.system("rm -rf "+dirname)

# Do a CVS export on the directory name

print "Checking out SWILL"
os.system("cvs export -D now -d "+dirname+ " SWILL")

# Go build the system

os.system("cd "+dirname+"; autoconf")
os.system("tar -cf "+string.lower(dirname)+".tar "+dirname)
os.system("gzip "+string.lower(dirname)+".tar")

