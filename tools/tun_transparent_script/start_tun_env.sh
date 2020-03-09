#!/bin/sh
PHY_DEVICE="eth0"
TUN_PPP_DEVICE="tun0"
TUN_INTERNET_DEVICE="tun1"
RAW_DEFAULT_GW_IP=""
PHY_IP4_ADDR=$(ifconfig $PHY_DEVICE | grep "inet " | awk '{ print $2}')
USER_IP_NETWORK_FILE="/home/mesasoft/sapp_run/user_ip_route.ini"

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
		echo "not found $1 in file '/tmp/user_ip_network'"
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

RAW_DEFAULT_GW_MAC=$(arp -an | grep "($RAW_DEFAULT_GW_IP)" | awk {'print $4'})
echo "default gateway MAC is: $RAW_DEFAULT_GW_MAC"

ethtool -K $PHY_DEVICE tso off
ethtool -K $PHY_DEVICE gso off
ethtool -K $PHY_DEVICE gro off

killall -9 sapp 
killall -9 sapp eth_tun_bridge
nohup ./sapp > /dev/null &
echo "sapp starting..."
sleep 5
nohup ./eth_tun_bridge $PHY_DEVICE $TUN_INTERNET_DEVICE $RAW_DEFAULT_GW_MAC > /dev/null &

ifconfig $TUN_PPP_DEVICE 192.168.1.1/24 up


show_all_current_users_ip
set_all_user_ip_route

#route add -net 223.90.112.0/20 gw 172.17.239.253
#route add -net 121.71.0.0/16 gw 172.17.239.253

route del default
route add default gw 192.168.1.2

#route add -net 121.71.90.0/24 gw 172.17.239.253
echo "1" > /proc/sys/net/ipv4/ip_forward
iptables -F
iptables -t nat -F
iptables -A FORWARD -p tcp --syn -s 10.0.0.0/24 -j TCPMSS --set-mss 1300
#iptables -t mangle -A PREROUTING -m ttl --ttl-gt 1 -j TTL --ttl-set 13 -i tun0

iptables -t mangle -A PREROUTING -j TTL --ttl-set 100 -i ppp0 
iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -j SNAT --to-source $PHY_IP4_ADDR -o $TUN_PPP_DEVICE


#iptables -A INPUT -p icmp --icmp-type 8 -s 0/0 -j DROP

cp pptp_etc/pptpd.conf /etc/pptpd.conf
cp pptp_etc/options.pptpd  /etc/ppp/options.pptpd
cp pptp_etc/chap-secrets /etc/ppp/chap-secrets
systemctl restart pptpd
