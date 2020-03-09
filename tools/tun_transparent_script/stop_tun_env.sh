#!/bin/sh

RAW_DEFAULT_GW_IP=""

if [[ $RAW_DEFAULT_GW_IP == "" ]] ; then
        TRACE_RES=$(traceroute -n -m 1 8.8.8.8 2>&1 | grep -v "traceroute to")
        NET_ERR="unreachable"

        echo "$TRACE_RES"
        tmp_res=$(echo $TRACE_RES | grep "Network is unreachable")
        if [[ $tmp_res != "" ]] ; then
            echo "error! can't found default gateway!"
            exit 1
        else
            RAW_DEFAULT_GW_IP=$(echo $TRACE_RES | awk '{ print $2}')
            echo "bingo! default gateway is $RAW_DEFAULT_GW_IP!"
        fi

fi

killall -9 sapp eth_tun_bridge
route del default
route add default gw $RAW_DEFAULT_GW_IP
iptables -F
iptables -t nat -F
