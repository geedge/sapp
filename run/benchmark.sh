#!/bin/sh
for i in {1..223}
do
	echo "-------- process $i files --------"  >> bench.log
	#tcpdump -r /tmp/fraglist.leak.pcap net $i.0.0.0/8 -s0 -w /tmp/fraglist.leak.pcap.net.$i
	ln -sf /tmp/fraglist.leak.pcap.net.$i dumpfile
	./memchk.sh.full	
	cat valgrind.log | grep definitely >> bench.log
done
