cmake_minimum_required(VERSION 2.8...3.10)

include_directories(${MESA_SDK_PREFIX}/include)
include_directories(${MESA_SDK_PREFIX}/include/MESA)
#include_directories(${CMAKE_SOURCE_DIR}/packet_io)
#include_directories(${CMAKE_SOURCE_DIR}/project)
#include_directories(${CMAKE_SOURCE_DIR}/include)
#include_directories(${CMAKE_SOURCE_DIR}/include/support)
#include_directories(${CMAKE_SOURCE_DIR}/dealpkt)

add_definitions(${MEM_POOL_DEFINITIONS} -D_DEFAULT_SOURCE -D_DEFAULT_SOURCE -D__DEFAULT_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H)
add_library(dictator2 STATIC  dictator.cpp dictator_debuger.cpp
    D_internal/D_kernel_list.cpp D_internal/list_common.cpp
    D_internal/MESA_hash_v2.cpp D_internal/MESA_list_v2.cpp)

add_library(dictator2_debug STATIC  dictator.cpp dictator_debuger.cpp
    D_internal/D_kernel_list.cpp D_internal/list_common.cpp
    D_internal/MESA_hash_v2.cpp D_internal/MESA_list_v2.cpp)
target_compile_definitions(dictator2_debug PRIVATE "-DDICTATOR_DEBUG")