#!/bin/sh
PHY_DEVICE="eth0"
TUN_PPP_DEVICE="tun0"
TUN_INTERNET_DEVICE="tun1"
RAW_DEFAULT_GW_IP="172.17.239.253"
PHY_IP4_ADDR=$(ifconfig $PHY_DEVICE | grep "inet " | awk '{ print $2}')


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
#ifconfig ens33 mtu 1500

killall -9 sapp 
killall -9 sapp eth_tun_bridge
nohup ./sapp > /dev/null &
echo "sapp starting..."
sleep 5
nohup ./eth_tun_bridge $PHY_DEVICE $TUN_INTERNET_DEVICE $RAW_DEFAULT_GW_MAC > /dev/null &

ifconfig $TUN_PPP_DEVICE 192.168.1.1/24 up
route add -net 223.90.126.0/24 gw 172.17.239.253
route add -net 121.71.90.0/24 gw 172.17.239.253
route add -net 100.100.30.0/24 gw 172.17.239.253
route add -net 100.100.2.0/24 gw 172.17.239.253
route add -net 114.252.36.0/24 gw 172.17.239.253
route del default
route add default gw 192.168.1.2
#route add -net 121.71.90.0/24 gw 172.17.239.253
echo "1" > /proc/sys/net/ipv4/ip_forward
iptables -F
iptables -t nat -F
iptables -A FORWARD -p tcp --syn -s 10.0.0.0/24 -j TCPMSS --set-mss 1300
#iptables -t mangle -A PREROUTING -m ttl --ttl-gt 1 -j TTL --ttl-set 13 -i tun0
#iptables -t mangle -A PREROUTING -j TTL --ttl-set 100 -i ppp0 
iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -j SNAT --to-source $PHY_IP4_ADDR -o $TUN_PPP_DEVICE


#iptables -A INPUT -p icmp --icmp-type 8 -s 0/0 -j DROP

cp pptp_etc/pptpd.conf /etc/pptpd.conf
cp pptp_etc/options.pptpd  /etc/ppp/options.pptpd
cp pptp_etc/chap-secrets /etc/ppp/chap-secrets
systemctl restart pptpd
