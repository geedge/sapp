#!/bin/sh

killall -9 sapp eth_tun_bridge
route del default
route add default gw 172.17.239.253
