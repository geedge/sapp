cmake_minimum_required(VERSION 2.8...3.10)

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/include/private)
include_directories(${CMAKE_SOURCE_DIR}/include/public)
include_directories(${CMAKE_SOURCE_DIR}/include/support)
include_directories(/opt/MESA/include/MESA)
include_directories(/opt/MESA/include/)

add_definitions(-D_DEFAULT_SOURCE -D_GNU_SOURCE -D__DEFAULT_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H -fPIC)

add_library(cpu_limit STATIC  cpu_limit.c)
