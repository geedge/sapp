#!/bin/sh

#rmmod sapp_tun_bridge_kmodule
#route del default
#route add default gw 192.168.31.1
iptables -F
iptables -t nat -F
ip rule del table 200
killall -9 r3 sapp bridge_r3 sapp_tun_bridge_user
