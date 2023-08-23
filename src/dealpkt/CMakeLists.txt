cmake_minimum_required(VERSION 2.8...3.10)

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/include/private)
include_directories(${CMAKE_SOURCE_DIR}/include/public)
include_directories(${CMAKE_SOURCE_DIR}/include/support)
include_directories(${CMAKE_SOURCE_DIR}/src/support/dablooms/src)
include_directories(${MESA_SDK_PREFIX}/include)
include_directories(${MESA_SDK_PREFIX}/include/MESA)


if(OPT_IOMODE_MARSIO)
	include_directories(${MARSIO_SDK_PREFIX}/include)
endif()

add_definitions(-D_DEFAULT_SOURCE -D_DEFAULT_SOURCE -D__DEFAULT_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H)
add_definitions(-DPLATFORM_NSDPF_PAPP=1)
add_definitions(-fPIC)

add_library(dealpkt STATIC callapp.c deal_ipv4.c deal_mpls.c deal_tcp.c  hash.c plug_support.c
deal_arp.c       deal_ipv6.c        deal_ppp.c    deal_teredo.c  ip_reassembly.c   
deal_ethernet.c  deal_pppoe.c  deal_udp.c     stream_manage.c
deal_gre.c       deal_l2tp.c        deal_pptp.c   deal_vlan.c     
deal_icmp.c      deal_mac_in_mac.c  deal_proxy.c  g_device.c      
deal_gprs_tunnel.c deal_vxlan.c duplicate_pkt_distinguish.c)
