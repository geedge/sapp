#!/bin/sh
PHY_DEVICE="ens33"
TUN_PPP_DEVICE="tun0"
TUN_INTERNET_DEVICE="tun1"
RAW_DEFAULT_GW_IP="192.168.31.1"
PHY_IP4_ADDR=$(ifconfig $PHY_DEVICE | grep "inet " | awk '{ print $2}')
USER_IP_NETWORK_FILE="./user_ip_route.ini"

./stop_tun_env.sh

set_all_user_ip_route(){

cat $USER_IP_NETWORK_FILE |while read line
do
    echo $line
        cur_user_ip_route_flags=`route -n  | grep $line | awk {'print $4'}`
        echo "current user ip route flag is: $cur_user_ip_route_flags"

        if [[ $cur_user_ip_route_flags == "U" ]] ; then
                echo "cur user connection directly, don't need gateway!"
	else
                echo "cur user connection is UG,  need gateway!"
    		route add -net $line/24 gw $RAW_DEFAULT_GW_IP
        fi
done

}

save_user_ip_route_to_file(){
	ret=`cat $USER_IP_NETWORK_FILE | grep $1`
	if [[ $? != 0 ]] ; then
		echo "not found $1 in file '$USER_IP_NETWORK_FILE'"
		echo $1 >> $USER_IP_NETWORK_FILE
	else
		echo "$1 already in file '$USER_IP_NETWORK_FILE'"
	fi
}

show_all_current_users_ip(){
	cur_all_users_ip_list=`who | grep -v tty | grep pts | awk -F "[()]" {'print $2'} | sort | uniq`
	#echo "cur_all_users_ip_list is: $cur_all_users_ip_list"

	for ip in $cur_all_users_ip_list
	do
		echo "current user ip is: $ip"
        	cur_user_network=`echo $ip | awk -F "." {'print $1"."$2"."$3"."0'}`
        	echo "current user ip network is: $cur_user_network"
		save_user_ip_route_to_file $cur_user_network
	done
}

update_cur_user_route(){
	cur_user=`whoami`
	echo "current user name is: $cur_user"

	cur_user_ip=`who | grep $cur_user | grep -v tty | grep pts | head -n 1 | awk -F "[()]" {'print $2'}`

	if [[ $cur_user_ip == "" ]] ; then
	    echo "Error! cant get current user ip address!"
	    exit
	fi
	echo "current user ip is: $cur_user_ip"

	cur_user_network=`echo $cur_user_ip | awk -F "." {'print $1"."$2"."$3"."0'}`
	echo "current user ip network is: $cur_user_network"

	cur_user_ip_route_flags=`route -n  | grep $cur_user_network | awk {'print $4'}`
	echo "current user ip route flag is: $cur_user_ip_route_flags"

	if [[ $cur_user_ip_route_flags == "U" ]] ; then
		echo "cur user connection directly, don't need gateway!"
		return
	fi

	cur_user_ip_gateway=`route -n  | grep $cur_user_network | awk {'print $2'}`
	echo "current user ip gateway is: $cur_user_ip_gateway"

}


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

PHY_DEVICE_MAC=`ifconfig $PHY_DEVICE | grep "ether" | awk {'print $2'}`
if [[ $PHY_DEVICE_MAC == "" ]] ; then
    echo "get local device $PHY_DEVICE error!"
    exit 1
fi

RAW_DEFAULT_GW_MAC=$(arp -an | grep "($RAW_DEFAULT_GW_IP)" | awk {'print $4'})
if [[ $RAW_DEFAULT_GW_MAC == "" ]] ; then
    echo "get default gateway '$RAW_DEFAULT_GW_IP' mac error!"
    exit 1
fi
echo "default gateway MAC is: $RAW_DEFAULT_GW_MAC"

ethtool -K $PHY_DEVICE tso off
ethtool -K $PHY_DEVICE gso off
ethtool -K $PHY_DEVICE gro off

killall -9 sapp sapp_tun_bridge_user
> sysinfo.log

ulimit -c unlimited

#nohup ./sapp > /dev/null &
#nohup ./sapp > /tmp/sapp.log &
./r2

sapp_rcv_pkt_num=""
while [[ $sapp_rcv_pkt_num == "" ]]
do
    sapp_rcv_pkt_num=`tail -n 20 sysinfo.log | grep IPv4`
    echo "sapp initializing, wait a moment...."
    sleep 1
done

#show_all_current_users_ip
#set_all_user_ip_route

ifconfig $TUN_PPP_DEVICE 192.168.1.1/24 up
ifconfig $TUN_INTERNET_DEVICE up

./bridge_r2 $PHY_DEVICE  $TUN_INTERNET_DEVICE  $RAW_DEFAULT_GW_MAC 
#nohup ./sapp_tun_bridge_user $PHY_DEVICE $TUN_INTERNET_DEVICE $RAW_DEFAULT_GW_MAC > /dev/null &
#nohup ./sapp_tun_bridge_user $PHY_DEVICE $TUN_INTERNET_DEVICE $RAW_DEFAULT_GW_MAC > /tmp/bridge.log &

#route add -net 223.90.112.0/20 gw 172.17.239.253
#route add -net 121.71.0.0/16 gw 172.17.239.253

###route del default
##route add default gw 192.168.31.1
ip rule del table 200
ip rule add from 10.0.0.0/8 table 200
ip route add default via 192.168.1.2 table 200

#route add -net 121.71.90.0/24 gw 172.17.239.253
echo "1" > /proc/sys/net/ipv4/ip_forward
iptables -F
iptables -t nat -F
iptables -A FORWARD -p tcp --syn -s 10.0.0.0/24 -j TCPMSS --set-mss 1300
#iptables -t mangle -A PREROUTING -m ttl --ttl-gt 1 -j TTL --ttl-set 13 -i tun0

#ifconfig $PHY_DEVICE:2 169.254.254.254/24 up
#arp -s 169.254.254.254 00:11:22:33:44:55

#iptables -t mangle -A PREROUTING -j TTL --ttl-set 100 -i ppp0 
iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -j SNAT --to-source $PHY_IP4_ADDR -o $TUN_PPP_DEVICE
#iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -j SNAT --to-source 169.254.254.254 -o $TUN_PPP_DEVICE

iptables -I INPUT -p tcp -s 119.253.39.18 -j ACCEPT
iptables -A INPUT -p tcp -m multiport ! --dport 22,1723 -d $PHY_IP4_ADDR -j DROP

#iptables -I INPUT ! -p ip -d $PHY_IP4_ADDR -j DROP

#### NFQUEUE
#kmodule=`insmod ./sapp_tun_bridge_kmodule.ko devip=\"$PHY_IP4_ADDR\" devmac=\"$PHY_DEVICE_MAC\"`
#if [[ $? != 0 ]] ; then
    #echo "insmod sapp_tun_bridge_kmodule.ko error!"
    #./stop_tun_env.sh
    #exit 1
#fi

#iptables -A INPUT -p tcp -m tcp ! --dport 22 -j NFQUEUE
#iptables -A INPUT -p udp -m udp -j NFQUEUE
##iptables -A INPUT -p gre -j NFQUEUE
#iptables -A INPUT -p icmp -j NFQUEUE

#iptables -A INPUT -p icmp --icmp-type 8 -s 0/0 -j DROP

#cp pptp_etc/pptpd.conf /etc/pptpd.conf
#cp pptp_etc/options.pptpd  /etc/ppp/options.pptpd
#cp pptp_etc/chap-secrets /etc/ppp/chap-secrets
#systemctl restart pptpd

