cmake_minimum_required(VERSION 2.8...3.10)

#include_directories(${CMAKE_SOURCE_DIR}/packet_io)
#include_directories(${CMAKE_SOURCE_DIR}/project)
#include_directories(${CMAKE_SOURCE_DIR}/include)
#include_directories(${CMAKE_SOURCE_DIR}/include/support)
#include_directories(${CMAKE_SOURCE_DIR}/dealpkt)

add_definitions(-D_DEFAULT_SOURCE -D_DEFAULT_SOURCE -D__DEFAULT_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H)
add_definitions(-fPIC)

add_library(MESA_sleep STATIC  mesa_sleep_nowatchBGT.c)
