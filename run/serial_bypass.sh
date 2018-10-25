#!/bin/sh

while [ 1 ]; do
	brctl addbr bridge0
	brctl addif bridge0 ens32
	brctl addif bridge0 ens33
	brctl bridge0 down
        ulimit -c 0

    ./sapp > /dev/null
	brctl bridge0 up
	echo program crashed, restart at `date +"%w %Y/%m/%d, %H:%M:%S"` >> RESTART.lo
    #sleep 10
done
