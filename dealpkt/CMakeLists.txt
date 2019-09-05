cmake_minimum_required(VERSION 2.8)

include_directories(${MESA_SDK_PREFIX}/include)
include_directories(${MESA_SDK_PREFIX}/include/MESA)
include_directories(${CMAKE_SOURCE_DIR}/packet_io)
include_directories(${CMAKE_SOURCE_DIR}/project)
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/include/net)
include_directories(${CMAKE_SOURCE_DIR}/include/stream_inc)
include_directories(${CMAKE_SOURCE_DIR}/include/support)
include_directories(${CMAKE_SOURCE_DIR}/dealpkt)

if(CAPTURE_MODE MATCHES "MARSIO")
    include_directories(${MARSIO_SDK_PREFIX}/include)
endif()

add_definitions(-D_BSD_SOURCE -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H)
add_definitions(-DPLATFORM_NSDPF_PAPP=1)

add_library(dealpkt STATIC callapp.c deal_ipv4.c deal_mpls.c deal_tcp.c  hash.c plug_support.c
deal_arp.c       deal_ipv6.c        deal_ppp.c    deal_teredo.c  ip_reassembly.c       stream_addr_inet.c
deal_ethernet.c  deal_isakmp.c      deal_pppoe.c  deal_udp.c     linux_kernel_jhash.c  stream_manage.c
deal_gre.c       deal_l2tp.c        deal_pptp.c   deal_vlan.c    MESA_stream_hash.c    synflood_detect.c
deal_icmp.c      deal_mac_in_mac.c  deal_proxy.c  g_device.c     net_common.c
deal_gprs_tunnel.c)
