cmake_minimum_required(VERSION 2.8)

#include_directories(${CMAKE_SOURCE_DIR}/packet_io)
#include_directories(${CMAKE_SOURCE_DIR}/project)
#include_directories(${CMAKE_SOURCE_DIR}/include)
#include_directories(${CMAKE_SOURCE_DIR}/include/support)
#include_directories(${CMAKE_SOURCE_DIR}/dealpkt)

add_definitions(-D_BSD_SOURCE -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H)

add_library(dictator2 STATIC  dictator.cpp dictator_debuger.cpp
    D_internal/D_kernel_list.cpp D_internal/list_common.cpp
    D_internal/MESA_hash_v2.cpp D_internal/MESA_list_v2.cpp)
