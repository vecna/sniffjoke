#!/bin/sh -x

USERID=`id -u`
if [ $USERID != "0" ]; then
	echo "- Error, only root should run $0"
	exit;
fi

echo "+ Starting SniffJoke hacks test"
echo "* Stopping running sniffjoke"
../sniffjoke quit

generate_hacking_option()
{
	if [ $x -eq 1 ]
	then
		HACKOPT="YNNNNNNNNNNN"; return;
	fi

	if [ $x -eq 12 ]
	then
		HACKOPT="NNNNNNNNNNNY"; return;
	fi

	defaultopt="NNNNNNNNNNNN";
	before=$(($x - 1))
	first=`echo $defaultopt | cut -b -$before`
	after=$(($x + 1))
	second=`echo $defaultopt | cut -b $after-`
	HACKOPT=`echo $first"Y"$second`
}

i=`seq 1 12`
for x in $i; do
	rm -rf tmpdir.$x
	mkdir tmpdir.$x
	cd tmpdir.$x
	for y in `seq 1 5`; do echo -n "$x $y " >> generated-1.$x; done
	for y in `seq 1 5`; do echo -n "$x $y " >> generated-2.$x; done
	md5sum generated-1.$x > generated-1.$x.md5sum
	md5sum generated-2.$x > generated-2.$x.md5sum
	generate_hacking_option
	echo "+ Starting sniffjoke in the $x instance"
	../../sniffjoke --force --debug 6 --hacking $HACKOPT
	sleep 1
	if [ ! -e "/tmp/sniffjoke/sniffjoke_service" ]; then 
		echo "- Bad, on instance $x sniffjoke IS NOT running!"; exit;
	fi
	../../sniffjoke clear
	../../sniffjoke set 80 80 heavy 
	../../sniffjoke start
	curl -d "sparedata=`cat generated-1.$x`" http://www.delirandom.net/sniffjoke_test/post_echo.php > received-1.$x
	curl -d "sparedata=`cat generated-2.$x`" http://www.delirandom.net/sniffjoke_test/post_echo.php > received-2.$x
	../../sniffjoke quit
	cd ..
done
