#!/bin/sh
filename=$1
cat $filename |sort >$filename.sort
cat $filename.sort |grep tcpstream >$filename.tcp
cat $filename.sort |grep tcpallstream >$filename.tcpall
cat $filename.sort |grep udpstream >$filename.udp
echo $filename tcpallstreamnum=`cat $filename.tcpall|wc -l`
echo $filename tcpstreamnum=`cat $filename.tcp|wc -l`
echo $filename udpstreamnum=`cat $filename.udp|wc -l`

#./start
#echo program crashed, reboot at `date +"%w %Y/%m/%d, %H:%M:%S"` >> REBOOT.log
#reboot


