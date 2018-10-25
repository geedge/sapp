#!/bin/sh
filename=$1
cat $filename |sort >$filename.sort
cat $filename.sort |grep tcpstream >$filename.tcp
cat $filename.sort |grep tcpallstream >$filename.tcpall
cat $filename.sort |grep udpallstream >$filename.udp
echo $filename tcpallstreamnum=`cat $filename.tcpall|wc -l`
echo $filename tcpstreamnum=`cat $filename.tcp|wc -l`
echo $filename udpstreamnum=`cat $filename.udp|wc -l`
cat $filename.tcpall |awk {'print $10'}|awk -F',' '{sum+=$1 } END {print "tcppktnum=" sum }'
cat $filename.udp |awk {'print $10'}|awk -F',' '{sum+=$1 } END {print "udppktnum=" sum }'
cat $filename.tcpall |awk {'print $10'}|awk -F'=' '{sum+=$2 } END {print "tcppayload=" sum }'
cat $filename.udp |awk {'print $10'}|awk -F'=' '{sum+=$2 } END {print "udppayload=" sum }'


