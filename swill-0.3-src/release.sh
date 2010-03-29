#
# $Id: release.sh,v 1.1 2007/11/15 17:24:44 gonzalodiethelm Exp $
#
# Script to generate a release of SWILL. Called with one argument it
# will generate a .zip and a .tgz file with the proper release:
#
# ./release.sh 1.5
#

if [ $# -ne 1 ]
then
  echo "Usage: $0 name" 1>&2
  exit 0
fi

name=$1
fils=/tmp/files.txt

rm -f swill-${name}.zip
rm -f swill-${name}.tgz

# Generate PDF files from PS files, to ease the pain in Win32.
pushd Paper >/dev/null
ps2pdf swillsc.ps swillsc.pdf
popd >/dev/null

make clean

find . -type f -print |
  egrep -v '(Talk|CVS|autom4te\.cache)/|/(config\..*|swill-win32\..*|win32\.sh|make\.log|oo|ee|.*\.(cvsignore|zip|tgz))$|~' |
  sort > $fils

zip -9 swill-tmp.zip `cat $fils` >/dev/null
rm -f $fils

mkdir SWILL-${name}
pushd SWILL-${name} >/dev/null
unzip ../swill-tmp.zip
popd >/dev/null
rm -f swill-tmp.zip

zip -9r swill-${name}.zip SWILL-${name}
tar zcvf swill-${name}.tgz SWILL-${name}

ls -l swill-${name}.*
rm -fr SWILL-${name}

echo "Release ${name} done"
