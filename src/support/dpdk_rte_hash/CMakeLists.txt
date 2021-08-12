cmake_minimum_required(VERSION 2.8)

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/include/private)
include_directories(${CMAKE_SOURCE_DIR}/include/public)

include_directories(${CMAKE_SOURCE_DIR}/src/support/dpdk_rte_hash)
include_directories(${CMAKE_SOURCE_DIR}/src/support/dpdk_rte_hash/generic)

#set(CMAKE_C_FLAGS "-DLINK_MODE_DYNAMIC=1")
set(CMAKE_C_FLAGS "-std=c99")

add_definitions(-D_BSD_SOURCE -D_GNU_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H)

add_library(dpdk_ip_hash STATIC dpdk_hash_crc.c)
