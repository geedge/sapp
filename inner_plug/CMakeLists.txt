cmake_minimum_required(VERSION 2.8)

include_directories(${CMAKE_SOURCE_DIR}/packet_io)
#include_directories(${CMAKE_SOURCE_DIR}/project)
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/include/net)
include_directories(${CMAKE_SOURCE_DIR}/include/support)
include_directories(${CMAKE_SOURCE_DIR}/dealpkt)

add_definitions(-D_BSD_SOURCE -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H)

add_definitions(-fPIC)
add_library(sapp_assistant SHARED sapp_assistant.cpp)
add_library(gdev_assistant SHARED gdev_assistant.c)

install(TARGETS sapp_assistant DESTINATION ${MESA_SDK_PREFIX}/lib/)
install(TARGETS gdev_assistant DESTINATION ${MESA_SDK_PREFIX}/lib/)
